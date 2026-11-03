"""Real loopback peers exercise total deadlines, overload and reclamation."""
import contextlib
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import threading
import time
import unittest
import urllib.request
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('deadline_controls_worker',Path(__file__).resolve().parents[1]/'services/controls/worker.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)


@contextlib.contextmanager
def backend(parts,interval):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(1)
    stopped=threading.Event()
    def serve():
        try:
            conn,_=listener.accept()
            with conn:
                conn.settimeout(1);raw=b''
                while b'\r\n\r\n'not in raw:raw+=conn.recv(4096)
                for part in parts:
                    if stopped.wait(interval):break
                    conn.sendall(part)
        except OSError:pass
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:yield 'http://127.0.0.1:'+str(listener.getsockname()[1])+'/control'
    finally:
        stopped.set();listener.close();thread.join(1)


class DeadlineTests(unittest.TestCase):
    def test_dribbling_response_headers_have_total_deadline(self):
        with backend([bytes([b])for b in b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'],.03)as url:
            start=time.monotonic()
            with self.assertRaises((w.ControlError,OSError,http.client.HTTPException)):
                with w.backend_reply(urllib.request.Request(url),.15)as(reply,deadline):w.read_body(reply,deadline)
            self.assertLess(time.monotonic()-start,.7)

    def test_dribbling_response_body_has_total_deadline_even_with_connection_close(self):
        body=b'{"schemaVersion":1,"values":{}}'
        head=b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'
        with backend([head]+[bytes([b])for b in body],.025)as url:
            start=time.monotonic()
            with self.assertRaises((w.ControlError,OSError,http.client.HTTPException)):
                with w.backend_reply(urllib.request.Request(url),.18)as(reply,deadline):w.read_body(reply,deadline)
            self.assertLess(time.monotonic()-start,.7)

    def test_fast_json_succeeds_and_response_size_is_bounded(self):
        for body,limit,passes in [(b'{"ok":true}',100,True),(b'x'*300,100,False)]:
            head=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'
            with self.subTest(limit=limit,passes=passes),backend([head+body],0)as url:
                with w.backend_reply(urllib.request.Request(url),1)as(reply,deadline):
                    if passes:self.assertEqual(w.read_body(reply,deadline,limit),body)
                    else:
                        with self.assertRaises(w.ControlError):w.read_body(reply,deadline,limit)

    def test_complete_connection_close_json_does_not_reuse_closed_socket(self):
        body=json.dumps({'schemaVersion':1,'values':{'description':'x'*22700}}).encode()
        head=b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'
        with backend([head+body],0)as url:
            with w.backend_reply(urllib.request.Request(url),1)as(reply,deadline):
                self.assertTrue(reply.will_close)
                self.assertEqual(w.read_body(reply,deadline),body)

    def test_truncated_connection_close_response_is_rejected(self):
        body=b'{"schemaVersion":1,"values":{}}'
        head=b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)+10).encode()+b'\r\n\r\n'
        with backend([head+body],0)as url:
            with w.backend_reply(urllib.request.Request(url),1)as(reply,deadline):
                with self.assertRaises(w.ControlError)as error:w.read_body(reply,deadline)
                self.assertEqual(error.exception.code,'camera_control_truncated_response')

    def test_complete_chunked_connection_close_response_succeeds(self):
        body=b'{"schemaVersion":1,"values":{}}'
        head=b'HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n'
        framed=format(len(body),'x').encode()+b'\r\n'+body+b'\r\n0\r\n\r\n'
        with backend([head+framed],0)as url:
            with w.backend_reply(urllib.request.Request(url),1)as(reply,deadline):
                self.assertEqual(w.read_body(reply,deadline),body)

    def test_truncated_chunked_response_is_rejected(self):
        head=b'HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n'
        with backend([head+b'20\r\n{}\r\n'],0)as url:
            with w.backend_reply(urllib.request.Request(url),1)as(reply,deadline):
                with self.assertRaises((w.ControlError,http.client.HTTPException,OSError)):
                    w.read_body(reply,deadline)

    def test_incoming_stalls_are_bounded_and_handler_slots_reclaimed(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    if self.request.recv(1):self.request.sendall(b'ok')
                except OSError:pass
        class Server(w.BoundedThreadingMixIn,socketserver.TCPServer):
            max_handlers=2;request_seconds=.5
        with Server(('127.0.0.1',0),Echo)as server:
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
            clients=[]
            try:
                for _ in range(2):
                    c=socket.create_connection(server.server_address,timeout=1);clients.append(c)
                time.sleep(.04)
                with socket.create_connection(server.server_address,timeout=1)as rejected:
                    self.assertIn(b'503 Service Unavailable',rejected.recv(1024))
                for c in clients:self.assertEqual(c.recv(1),b'')
                limit=time.monotonic()+1
                while server.deadlines and time.monotonic()<limit:time.sleep(.01)
                self.assertFalse(server.deadlines)
                with socket.create_connection(server.server_address,timeout=1)as healthy:
                    healthy.sendall(b'x');self.assertEqual(healthy.recv(2),b'ok')
            finally:
                for c in clients:c.close()
                server.shutdown();thread.join(1)

    def test_audio_progress_requires_complete_bounded_adts_frame(self):
        frame=bytes([0xff,0xf1,0x60,0x40,0x01,0x3f,0xfc,0x12,0x34])
        p=w.AdtsProgress();self.assertEqual(p.feed(frame[:4]),0);self.assertEqual(p.feed(frame[4:]),1)
        self.assertEqual(p.feed(frame*10),10)
        with self.assertRaises(w.ControlError):p.feed(b'badheader')

    def test_watchdog_is_not_a_background_thread(self):
        # Notification is only sent from the server's event-loop callback.
        class Server(w.BoundedThreadingMixIn,socketserver.TCPServer):pass
        with Server(('127.0.0.1',0),socketserver.BaseRequestHandler)as server:
            with patch.dict(w.os.environ,{'NOTIFY_SOCKET':'/fixture','WATCHDOG_USEC':'1000000','WATCHDOG_PID':str(w.os.getpid())}),patch.object(w.socket,'AF_UNIX',1,create=True),patch.object(w.socket,'socket')as notify:
                server.service_actions()
                notify.return_value.__enter__.return_value.sendto.assert_called_once_with(b'WATCHDOG=1','/fixture')
                self.assertFalse(any(t.name.startswith('controls-watchdog')for t in threading.enumerate()))


if __name__=='__main__':unittest.main()
