import json
import subprocess
import socket
import threading
import time
import unittest
from unittest.mock import patch

from reolink_protect_events import connector
from reolink_protect_events.native import NativeAdapter


class ConnectorContract(unittest.TestCase):
    def setUp(self):
        self.config={'cameraIds':['a'*24], 'protectUserId':'a'*36, 'hashPaths':['/etc/nginx/nginx.conf']}

    def test_adapter_transaction_can_cross_transport(self):
        row={'eventId':'b'*24,'cameraId':'a'*24,'start':1792351000000,'end':None,
             'classes':['person'],'provenance':{'adapter':'reolink-protect-events','seq':1}}
        sql,_=NativeAdapter().build_interval_sql(row)
        self.assertEqual(connector.validate_sql(sql),sql)

    def test_shell_meta_and_database_commands_rejected(self):
        for sql in ['SELECT 1;', 'BEGIN; \\! id\n COMMIT;', 'BEGIN; COPY t TO PROGRAM \'id\'; COMMIT;',
                    'BEGIN; DROP TABLE events; COMMIT;']:
            with self.subTest(sql=sql),self.assertRaises(connector.ConnectorError):
                connector.validate_sql(sql)

    def test_retired_event_has_fixed_code(self):
        response=subprocess.CompletedProcess([],1,'','ERROR reolink-protect-events:retired secret')
        with patch.object(connector,'installed_version',return_value='7.3.70'),patch.object(connector.subprocess,'run',return_value=response):
            with self.assertRaises(connector.ConnectorError)as error:
                connector.execute_sql('BEGIN; SELECT 1; COMMIT;')
        self.assertEqual(error.exception.code,'event_retired')
        self.assertNotIn('secret',str(error.exception))

    def test_api_cannot_write_other_settings_or_cameras(self):
        for request in [{'method':'PATCH','path':'/api/cameras/'+'a'*24,'body':{'name':'x'}},
                        {'method':'PATCH','path':'/api/cameras/'+'b'*24,'body':{'thirdPartyCameraInfo':{'forceTcp':True}}},
                        {'method':'GET','path':'https://other/api/bootstrap'},
                        {'method':'GET','path':'/api/ws/livestream?camera='+'b'*24}]:
            with self.subTest(request=request),self.assertRaises(connector.ConnectorError):
                connector.api_request(self.config,request)

    def test_hashes_cannot_read_arbitrary_path(self):
        with self.assertRaises(connector.ConnectorError):
            connector.file_hashes(self.config,{'paths':['/root/.ssh/id_ed25519']})

    def test_version_pin_is_required(self):
        with patch.object(connector.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'7.4.0','')):
            with self.assertRaises(connector.ConnectorError)as error:connector.installed_version()
        self.assertEqual(error.exception.code,'connector_protect_version_changed')

    def test_body_deadline_is_total_even_when_peer_keeps_sending(self):
        first,second=socket.socketpair();stop=threading.Event()
        def drip():
            try:
                while not stop.wait(0.01):second.sendall(b'x')
            except OSError:pass
        writer=threading.Thread(target=drip,daemon=True);writer.start()
        began=time.monotonic();wrapped=connector.DeadlineSocket(first,began+0.08)
        buffered=wrapped.makefile('rb')
        try:
            with self.assertRaises(TimeoutError):buffered.read(100)
            self.assertLess(time.monotonic()-began,0.5)
        finally:
            stop.set();buffered.close();wrapped.close();second.close();writer.join(1)

    def test_buffered_response_can_finish_after_connection_close(self):
        first,second=socket.socketpair();wrapped=connector.DeadlineSocket(first,time.monotonic()+1)
        buffered=wrapped.makefile('rb');wrapped.close()
        try:
            second.sendall(b'body');second.shutdown(socket.SHUT_WR)
            self.assertEqual(buffered.read(),b'body')
        finally:
            buffered.close();second.close()


if __name__=='__main__':unittest.main()
