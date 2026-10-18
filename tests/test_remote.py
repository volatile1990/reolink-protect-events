"""Offline connector contracts; SSH is replaced by mocks or local child pipes."""
import datetime
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from unittest.mock import patch

from reolink_protect_events.remote import RPC_COMMAND, RemoteError, open_socket, rpc, settings


def config():
    return {"protectRemote": {"sshAlias": "udm-protect", "rpcCommand": RPC_COMMAND,
                              "snapshotPort": 17080, "dsPort": 17448, "apiPort": 17443}}


def completed(value, code=0):
    return subprocess.CompletedProcess([], code, json.dumps(value), "")


class RpcTests(unittest.TestCase):
    def test_local_mode_has_no_remote_configuration(self):
        self.assertIsNone(settings({}))
        with patch("reolink_protect_events.remote.subprocess.run") as run:
            with self.assertRaises(RemoteError):
                rpc({}, "version")
            run.assert_not_called()

    def test_alias_command_and_port_validation_precedes_process_creation(self):
        invalid = []
        for alias in ("-oProxyCommand=bad", "root@udm", "udm;echo", "udm\nother", "udm host", "x" * 129):
            item = config(); item["protectRemote"]["sshAlias"] = alias; invalid.append(item)
        for port in (True, 0, 65536, "17080"):
            item = config(); item["protectRemote"]["snapshotPort"] = port; invalid.append(item)
        item = config(); item["protectRemote"]["rpcCommand"] += "; bad"; invalid.append(item)
        invalid.append({"protectRemote": None})
        with patch("reolink_protect_events.remote.subprocess.run") as run:
            for item in invalid:
                with self.subTest(item=item), self.assertRaises(RemoteError):
                    rpc(item, "version")
            run.assert_not_called()

    def test_sql_stays_in_stdin_and_ssh_requires_pinned_alias_trust(self):
        sql = "SELECT 'synthetic-private-payload';"
        with patch("reolink_protect_events.remote.subprocess.run", return_value=completed({"ok": True, "result": "row\n"})) as run:
            self.assertEqual(rpc(config(), "sql", {"sql": sql}, timeout=17), "row\n")
        args, kwargs = run.call_args
        self.assertEqual(args[0][-2:], ["udm-protect", RPC_COMMAND])
        self.assertIn("-T", args[0]); self.assertIn("-oBatchMode=yes", args[0])
        self.assertIn("-oStrictHostKeyChecking=yes", args[0])
        self.assertNotIn(sql, " ".join(args[0]))
        self.assertEqual(json.loads(kwargs["input"]), {"action": "sql", "sql": sql})
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 17)

    def test_transport_timeout_is_sanitized_and_never_retried(self):
        private = "synthetic-secret-body"
        failure = subprocess.TimeoutExpired([private], 1, output=private, stderr=private)
        with patch("reolink_protect_events.remote.subprocess.run", side_effect=failure) as run:
            with self.assertRaises(RemoteError) as caught:
                rpc(config(), "sql", {"sql": private}, timeout=1)
            self.assertEqual(run.call_count, 1)
        self.assertEqual(caught.exception.code, "protect_remote_rpc_timeout")
        self.assertNotIn(private, "".join(traceback.format_exception(caught.exception)))

    def test_process_creation_failure_and_nonzero_success_output_are_not_success(self):
        for outcome in (OSError("synthetic-secret-detail"), completed({"ok": True, "result": "private"}, 255)):
            with self.subTest(outcome=type(outcome).__name__):
                with patch("reolink_protect_events.remote.subprocess.run", **(
                        {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome})):
                    with self.assertRaises(RemoteError) as caught:
                        rpc(config(), "version")
                self.assertEqual(str(caught.exception), "protect_remote_transport_failed")

    def test_invalid_envelopes_never_leak_remote_text(self):
        values = [[], {"ok": 1, "result": "private"}, {"ok": True}, {"result": "private"},
                  {"ok": False, "errorCode": "synthetic-secret", "error": "synthetic-secret"}]
        for value in values:
            with self.subTest(value=value), patch("reolink_protect_events.remote.subprocess.run", return_value=completed(value)):
                with self.assertRaises(RemoteError) as caught:
                    rpc(config(), "version")
                self.assertNotIn("synthetic-secret", str(caught.exception))
                self.assertIsNone(caught.exception.remote_code)
        with patch("reolink_protect_events.remote.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "not-json-private", "")):
            with self.assertRaisesRegex(RemoteError, "^protect_remote_response_invalid$"):
                rpc(config(), "version")

    def test_only_known_retired_semantics_cross_the_error_boundary(self):
        with patch("reolink_protect_events.remote.subprocess.run", return_value=completed({"ok": False, "errorCode": "event_retired"})):
            with self.assertRaises(RemoteError) as caught:
                rpc(config(), "sql", {"sql": "SELECT 1;"})
        self.assertEqual(caught.exception.remote_code, "event_retired")

    def test_action_payload_and_timeout_validation(self):
        with patch("reolink_protect_events.remote.subprocess.run") as run:
            for action, payload in (("sql\nversion", {}), ("version", {"action": "sql"}),
                                    ("version", []), ("sql", {"sql": object()})):
                with self.subTest(action=action), self.assertRaises(RemoteError):
                    rpc(config(), action, payload)
            for timeout in (True, -1, 0, float("inf"), float("nan"), 301):
                with self.subTest(timeout=timeout), self.assertRaises(RemoteError):
                    rpc(config(), "version", timeout=timeout)
            run.assert_not_called()

    def test_rpc_size_limits_are_fixed_errors(self):
        with patch("reolink_protect_events.remote._MAX_RPC_BYTES", 64):
            with self.assertRaisesRegex(RemoteError, "^protect_remote_request_limit$"):
                rpc(config(), "sql", {"sql": "x" * 100})
            with patch("reolink_protect_events.remote.subprocess.run", return_value=completed({"ok": True, "result": "x" * 100})):
                with self.assertRaisesRegex(RemoteError, "^protect_remote_response_limit$"):
                    rpc(config(), "version")


ECHO_CHILD = "import os\nwhile True:\n b=os.read(0,65536)\n if not b:break\n os.write(1,b)\n"


class StreamTests(unittest.TestCase):
    def child(self, code):
        original = subprocess.Popen
        self.processes = []
        self.commands = []
        def start(args, **kwargs):
            self.commands.append(args)
            process = original([sys.executable, "-u", "-c", code], **kwargs)
            self.processes.append(process)
            return process
        return patch("reolink_protect_events.remote.subprocess.Popen", side_effect=start)

    def test_binary_stream_roundtrip_context_close_reaps_child_and_pumps(self):
        payload = bytes(range(256)) * 24
        with self.child(ECHO_CHILD):
            with open_socket(config(), 7448, 3) as stream:
                stream.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    received.extend(stream.recv(len(payload) - len(received)))
                self.assertEqual(bytes(received), payload)
                stream.settimeout(1)
                self.assertEqual(stream.gettimeout(), 1)
            stream.close()
        self.assertEqual(self.commands[0][-1], "stream:7448")
        self.assertIsNotNone(self.processes[0].poll())
        self.assertTrue(all(not thread.is_alive() for thread in stream._threads))

    def test_read_timeout_is_a_socket_timeout_and_close_cancels_blocked_pumps(self):
        with self.child("import time;time.sleep(60)"):
            with open_socket(config(), 7443, 0.05) as stream:
                with self.assertRaises(socket.timeout):
                    stream.recv(1)
        self.assertIsNotNone(self.processes[0].poll())
        self.assertTrue(all(not thread.is_alive() for thread in stream._threads))

    def test_invalid_stream_scope_never_starts_ssh(self):
        with patch("reolink_protect_events.remote.subprocess.Popen") as start:
            for port in (True, 22, 1023, 65536, "7443"):
                with self.subTest(port=port), self.assertRaises(RemoteError):
                    open_socket(config(), port, 1)
            with self.assertRaises(RemoteError):
                open_socket(config(), 7443, 1, tls="yes")
            start.assert_not_called()

    def test_close_cancels_backpressure_without_leaking_a_writer_thread(self):
        with self.child("import time;time.sleep(60)"):
            stream = open_socket(config(), 7443, 0.05)
            stream._socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            stream._peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            try:
                try:
                    stream.sendall(b"x" * (4 * 1024 * 1024))
                except socket.timeout:
                    pass  # Platforms differ in how much loopback data they queue.
            finally:
                began = time.monotonic()
                stream.close()
        self.assertLess(time.monotonic() - began, 2.5)
        self.assertIsNotNone(self.processes[0].poll())
        self.assertTrue(all(not thread.is_alive() for thread in stream._threads))

    def test_failed_process_creation_closes_both_local_socket_ends(self):
        pair = socket.socketpair()
        with patch("reolink_protect_events.remote.socket.socketpair", return_value=pair), \
             patch("reolink_protect_events.remote.subprocess.Popen", side_effect=OSError("synthetic-private-detail")):
            with self.assertRaisesRegex(RemoteError, "^protect_remote_stream_failed$"):
                open_socket(config(), 7443, 1)
        self.assertTrue(all(endpoint.fileno() == -1 for endpoint in pair))

    def test_failed_tls_setup_is_sanitized_and_reaps_child(self):
        with self.child(ECHO_CHILD):
            with self.assertRaisesRegex(RemoteError, "^protect_remote_tls_failed$"):
                open_socket(config(), 7443, 2, tls=True)
        self.assertIsNotNone(self.processes[0].poll())

    def test_tls_is_terminated_locally_over_opaque_child_stdio(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest("cryptography is needed only to generate this temporary offline TLS fixture")
        # Ephemeral test material stays in a temporary directory, never Git or logs.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline-protect-fixture")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as folder:
            cert_path, key_path = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(5)
            port = listener.getsockname()[1]
            failures = []
            def server():
                try:
                    raw, _ = listener.accept(); raw.settimeout(3)
                    with context.wrap_socket(raw, server_side=True) as secure:
                        self.assertEqual(secure.recv(5), b"hello")
                        secure.sendall(b"local-tls")
                except Exception as error:
                    failures.append(type(error).__name__)
            thread = threading.Thread(target=server, daemon=True); thread.start()
            child = ("import os,socket,threading\n"
                     "s=socket.create_connection(('127.0.0.1',%d),timeout=5)\ns.settimeout(None)\n"
                     "def send():\n"
                     " try:\n"
                     "  while True:\n"
                     "   b=os.read(0,65536)\n"
                     "   if not b:break\n"
                     "   s.sendall(b)\n"
                     " finally:\n  s.shutdown(socket.SHUT_WR)\n"
                     "threading.Thread(target=send,daemon=True).start()\n"
                     "while True:\n"
                     " b=s.recv(65536)\n"
                     " if not b:break\n"
                     " os.write(1,b)\n") % port
            try:
                with self.child(child):
                    with open_socket(config(), 7443, 4, tls=True) as stream:
                        self.assertIsInstance(stream._socket, ssl.SSLSocket)
                        stream.sendall(b"hello")
                        self.assertEqual(stream.recv(32), b"local-tls")
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])
                self.assertIsNotNone(self.processes[0].poll())
            finally:
                listener.close()


if __name__ == "__main__":
    unittest.main()
