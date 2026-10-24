"""Loopback failures exercise the independently deployed API's actual IO."""
import concurrent.futures
import http.client
import importlib.util
from pathlib import Path
import socket
import threading
import time
import unittest
import tempfile
import json
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'services/frigate-api/api_proxy.py'


def module():
    spec=importlib.util.spec_from_file_location('api_resilience_fixture',PATH)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    value.TOKEN='synthetic-api-token'
    return value


class ApiResilience(unittest.TestCase):
    def test_body_and_header_dribble_share_absolute_backend_deadline(self):
        for headers in (False,True):
            with self.subTest(headers=headers):
                api=module();api.BACKEND_SECONDS=.18
                listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(1)
                api.BACKEND='http://127.0.0.1:'+str(listener.getsockname()[1]);stop=threading.Event()
                def peer():
                    try:
                        conn,_=listener.accept()
                        with conn:
                            conn.settimeout(1);data=b''
                            while b'\r\n\r\n'not in data:data+=conn.recv(4096)
                            body=b'{"pad":"'+b'x'*80+b'"}'
                            reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
                            if not headers:
                                head,body=reply.split(b'\r\n\r\n',1);conn.sendall(head+b'\r\n\r\n');reply=body
                            for byte in reply:
                                conn.sendall(bytes([byte]))
                                if stop.wait(.025):break
                    except OSError:pass
                thread=threading.Thread(target=peer,daemon=True);thread.start();began=time.monotonic()
                try:
                    with self.assertRaises(TimeoutError):api.backend('/api/stats')
                    self.assertLess(time.monotonic()-began,.6)
                finally:
                    stop.set();listener.close();thread.join(2)
                self.assertFalse(thread.is_alive())

    def serve(self,api):
        server=api.BoundedHTTPServer(('127.0.0.1',0),api.Handler)
        thread=threading.Thread(target=lambda:server.serve_forever(.02),daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(2)))
        return server

    def get(self,server,path='/livez'):
        client=http.client.HTTPConnection(*server.server_address,timeout=2)
        try:
            client.request('GET',path,headers={'Authorization':'Bearer synthetic-api-token'})
            reply=client.getresponse();return reply.status,reply.read()
        finally:client.close()

    def test_incomplete_client_headers_do_not_block_other_clients(self):
        api=module();api.REQUEST_SECONDS=.22;server=self.serve(api)
        slow=socket.create_connection(server.server_address);stop=threading.Event()
        def drip():
            try:
                for byte in b'GET /livez HTTP/1.1\r\nAuthorization: Bearer synthetic-api-token\r\n\r\n':
                    slow.sendall(bytes([byte]))
                    if stop.wait(.03):break
            except OSError:pass
        thread=threading.Thread(target=drip,daemon=True);thread.start()
        try:
            self.assertEqual(self.get(server)[0],200)
            time.sleep(.3)
            self.assertEqual(self.get(server)[0],200)
        finally:
            stop.set();slow.close();thread.join(1)

    def test_backend_budget_respects_time_already_spent_on_request(self):
        api=module();observed=[]
        def bounded(*args,**kwargs):observed.append(kwargs['timeout']);return 200,b'{}'
        with patch.object(api,'get_bytes',side_effect=bounded):
            api.backend('/api/stats',time.monotonic()+.1)
        self.assertGreater(observed[0],0);self.assertLessEqual(observed[0],.1)
        with self.assertRaises(TimeoutError):api.backend('/api/stats',time.monotonic()-1)

    def test_parallel_requests_are_bounded_and_capacity_recovers(self):
        api=module();api.REQUEST_SECONDS=2;server=self.serve(api)
        lock=threading.Lock();active=0;peak=0
        def backend(path,deadline=None):
            nonlocal active,peak
            with lock:active+=1;peak=max(peak,active)
            try:time.sleep(.2);return {'cameras':{},'detectors':{},'service':{}}
            finally:
                with lock:active-=1
        def query(_):
            try:return self.get(server,'/health')[0]
            except (OSError,http.client.HTTPException):return 0
        with patch.object(api,'backend',side_effect=backend):
            with concurrent.futures.ThreadPoolExecutor(max_workers=12)as pool:list(pool.map(query,range(12)))
        self.assertLessEqual(peak,api.WORKERS);self.assertEqual(active,0)
        self.assertEqual(self.get(server)[0],200)

    def test_wedged_accept_loop_requests_process_restart(self):
        api=module();called=[];server=api.BoundedHTTPServer(('127.0.0.1',0),api.Handler,exit_process=called.append)
        self.addCleanup(server.server_close)
        server._loop_last=time.monotonic()-31
        class Once:
            def wait(self,_):return False
        server._watch_stop=Once()
        server._watch_loop();self.assertEqual(called,[70])
        server._watch_stop=threading.Event()

    def test_independent_status_projects_only_public_fields_and_stale_fails_closed(self):
        api=module()
        with tempfile.TemporaryDirectory()as folder:
            api.STATUS_DIR=Path(folder)
            value={'schemaVersion':1,'atMs':1000,'completedAtMs':1000,'state':'healthy',
                   'actionRequired':False,'alerts':[],'privateUnexpectedField':'do-not-forward'}
            for name in ['events','monitor']:(api.STATUS_DIR/(name+'.json')).write_text(json.dumps(value))
            result=api.status_view(2000)
            self.assertFalse(result['actionRequired'])
            self.assertNotIn('privateUnexpectedField',json.dumps(result))
            result=api.status_view(500000)
            self.assertTrue(result['actionRequired'])
            self.assertEqual(len(result['alerts']),2)
            value['alerts']=[{'code':'recovery_requires_review','actionRequired':True}]
            (api.STATUS_DIR/'monitor.json').write_text(json.dumps(value))
            self.assertTrue(api.status_view(2000)['actionRequired'])

    def test_status_only_peer_cannot_read_event_or_backend_routes(self):
        api=module();server=self.serve(api)
        with patch.object(api,'STATUS_ONLY',{'127.0.0.1'}):
            self.assertEqual(self.get(server,'/health')[0],403)
            self.assertEqual(self.get(server,'/resilience')[0],200)


if __name__=='__main__':unittest.main()
