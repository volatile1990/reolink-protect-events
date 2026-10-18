"""Regression fixtures for bounded connector HTTP and EOF/backpressure paths."""
import http.client
from types import SimpleNamespace
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch

from reolink_protect_events import connector


class ConnectorReliabilityTests(unittest.TestCase):
    def test_dribbling_body_uses_one_total_http_deadline(self):
        listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
        listener.settimeout(3); port = listener.getsockname()[1]
        done = threading.Event()
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        request.extend(connection.recv(1))
                    body = b'{"padding":"' + b"x" * 70 + b'"}'
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
                    for value in body:
                        connection.sendall(bytes((value,)))
                        if done.wait(0.015): break
            except OSError:
                pass
            finally:
                done.set()
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        # Exercise the connector's real request/body wrapper over local plaintext
        # HTTP; TLS identity is independently covered by the remote stream tests.
        def plain(_host, _port, timeout, context):
            return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        cfg = {"cameraIds": ["a" * 24], "protectUserId": "fixture-owner"}
        began = time.monotonic()
        try:
            with patch.object(connector, "DeadlineHTTPSConnection", side_effect=plain):
                with self.assertRaises(TimeoutError):
                    connector.api_request(cfg, {"path": "/api/bootstrap", "timeout": 0.2})
            self.assertLess(time.monotonic() - began, 0.9)
        finally:
            done.set(); listener.close(); thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_upstream_eof_drains_only_nonblocking_writes_and_keeps_deadline(self):
        for stalled in (False, True):
            with self.subTest(stalled=stalled):
                clock = [0]
                stream = Mock()
                stream.recv.side_effect = [b"tail", b""]
                writes = []
                class Selector:
                    def __init__(self): self.entries = {}; self.calls = 0
                    def get_map(self): return self.entries
                    def register(self, file, events, data):
                        self.entries[file] = SimpleNamespace(fileobj=file, data=data)
                    def unregister(self, file): del self.entries[file]
                    def select(self, timeout):
                        self.calls += 1
                        if self.calls > 6: raise AssertionError("EOF must terminate within the bounded loop")
                        if stalled: clock[0] += 40
                        if self.calls <= 2:
                            return [(self.entries[stream], connector.selectors.EVENT_READ)]
                        if stalled: return []
                        return [(self.entries[1], connector.selectors.EVENT_WRITE)]
                    def close(self): pass
                def write(fd, data):
                    self.assertEqual(fd, 1)
                    chunk = bytes(data[:2]); writes.append(chunk)
                    return len(chunk)
                stdout = Mock()
                stdout.buffer.write.side_effect = AssertionError("blocking flush is forbidden")
                with patch.object(connector.socket, "create_connection", return_value=stream), \
                     patch.object(connector.selectors, "DefaultSelector", side_effect=Selector), \
                     patch.object(connector.os, "set_blocking") as blocking, \
                     patch.object(connector.os, "write", side_effect=write), \
                     patch.object(connector.time, "monotonic", side_effect=lambda: clock[0]), \
                     patch.object(connector.sys, "stdout", stdout):
                    if stalled:
                        with self.assertRaises(connector.ConnectorError) as error:
                            connector.relay(7443)
                        self.assertEqual(error.exception.code, "connector_stream_deadline")
                    else:
                        connector.relay(7443)
                    self.assertNotIn(((1, True), {}), blocking.call_args_list)
                    stdout.buffer.write.assert_not_called()
                self.assertEqual(b"".join(writes), b"" if stalled else b"tail")
                stream.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
