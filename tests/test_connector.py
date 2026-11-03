import json
import subprocess
import socket
import threading
import time
import stat
import types
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

    def test_readonly_native_scope_can_read_media_and_camera_but_never_patch(self):
        native='6ad623df037f3f03e402c6b4'
        self.config['readOnlyCameraIds']=[native]
        for path in ('/api/cameras/'+native,'/api/ws/livestream?camera='+native+'&channel=3',
                     '/api/tcp/livestream?camera='+native+'&channel=0'):
            with self.subTest(path=path),patch.object(connector,'DeadlineHTTPSConnection')as connection:
                response=connection.return_value.getresponse.return_value.__enter__.return_value
                response.status=200;response.read.return_value=b'{}'
                self.assertEqual(connector.api_request(self.config,{'path':path}),{})
        with patch.object(connector,'DeadlineHTTPSConnection')as connection, \
                patch.object(connector,'installed_version')as version:
            with self.assertRaisesRegex(connector.ConnectorError,'connector_api_write_scope'):
                connector.api_request(self.config,{'method':'PATCH','path':'/api/cameras/'+native,
                  'body':{'thirdPartyCameraInfo':{'forceTcp':True}}})
            connection.assert_not_called();version.assert_not_called()

    def test_readonly_config_is_optional_separate_and_bounded_to_one_camera(self):
        value={'cameraIds':['%024x'%n for n in range(210,216)],'protectUserId':'a'*36}
        class ConfigPath:
            def lstat(self):return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)
            def read_text(self):return json.dumps(value)
        self.assertEqual(connector.load_config(ConfigPath()),value)
        value['readOnlyCameraIds']=['f'*24]
        self.assertEqual(connector.load_config(ConfigPath())['readOnlyCameraIds'],['f'*24])
        for invalid in ([value['cameraIds'][0]],['f'*24,'e'*24],['f'*24]*2,['invalid'],[None],'f'*24,None):
            value['readOnlyCameraIds']=invalid
            with self.subTest(invalid=invalid),self.assertRaisesRegex(connector.ConnectorError,'connector_readonly_camera_scope'):
                connector.load_config(ConfigPath())

    def test_hashes_cannot_read_arbitrary_path(self):
        with self.assertRaises(connector.ConnectorError):
            connector.file_hashes(self.config,{'paths':['/root/.ssh/id_ed25519']})

    def test_package_metadata_accepts_new_versions_and_rejects_ambiguous_values(self):
        for version in ('7.3.74','8.0.0','1:8.0.0~rc1+build.2-1'):
            with self.subTest(version=version),patch.object(connector.subprocess,'run',
                    return_value=subprocess.CompletedProcess([],0,version,'')):
                self.assertEqual(connector.installed_version(),version)
        for version,code in (('',0),('unknown',0),('7.3.74\nsecret',0),('7.3.74;id',0),('7'*65,0),('7.3.74',1)):
            with self.subTest(version=version),patch.object(connector.subprocess,'run',
                    return_value=subprocess.CompletedProcess([],code,version,'')):
                self.assertIsNone(connector.installed_version())

    def test_sql_function_does_not_depend_on_package_metadata(self):
        response=subprocess.CompletedProcess([],0,'[]','')
        with patch.object(connector,'installed_version',side_effect=AssertionError('metadata must not gate SQL')), \
                patch.object(connector.subprocess,'run',return_value=response):
            self.assertEqual(connector.execute_sql('BEGIN READ ONLY; SELECT 1; ROLLBACK;'),'[]')

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
