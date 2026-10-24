"""A silent control loop must recover; camera loss must not kill the relay."""
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'services/frigate-api/sidecar_watchdog.py'


def module():
    spec = importlib.util.spec_from_file_location('relay_watchdog_fixture', PATH)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class ClockStop:
    def __init__(self, steps=100):
        self.now = 0
        self.steps = steps

    def wait(self, duration):
        self.now += duration
        self.steps -= 1
        return self.steps <= 0


class Child:
    pid = 100001

    def __init__(self, code=None):
        self.code = code
        self.waited = []

    def poll(self):
        return self.code

    def wait(self, timeout):
        self.waited.append(timeout)
        self.code = 0
        return self.code


class RelayWatchdog(unittest.TestCase):
    def test_healthy_control_survives_indefinite_source_loss(self):
        watch = module(); stop = ClockStop(1000); child = Child(); probes = []
        with patch.object(watch.os, 'killpg', create=True) as kill:
            code = watch.supervise(['relay'], 'local', grace=60, stop=stop,
                popen=lambda *a, **k: child, clock=lambda: stop.now,
                check=lambda *a: probes.append(stop.now) or True)
        self.assertEqual(code, 0)
        self.assertGreater(len(probes), 900)
        self.assertGreaterEqual(probes[0], 60)
        kill.assert_called_once_with(child.pid, signal.SIGTERM)

    def test_only_consecutive_control_failures_restart_owned_child(self):
        watch = module(); stop = ClockStop(); child = Child()
        results = iter([False, False, True, False, False, False])
        with patch.object(watch.os, 'killpg', create=True) as kill:
            code = watch.supervise(['relay'], 'local', grace=0, interval=10,
                stop=stop, popen=lambda *a, **k: child, clock=lambda: stop.now,
                check=lambda *a: next(results))
        self.assertEqual(code, 70)
        self.assertEqual(stop.now, 60)
        kill.assert_called_once_with(child.pid, signal.SIGTERM)
        self.assertEqual(child.waited, [5])

    def test_child_exit_is_propagated_without_signalling_unrelated_process(self):
        watch = module(); child = Child(17)
        with patch.object(watch.os, 'killpg', create=True) as kill:
            code = watch.supervise(['relay'], 'local', stop=ClockStop(),
                popen=lambda *a, **k: child, check=lambda *a: self.fail('probe after child exit'))
        self.assertEqual(code, 17)
        kill.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'owned Unix process group')
    def test_real_child_is_reaped_after_unresponsive_probe(self):
        watch = module(); children = []
        def start(*args, **kwargs):
            child = subprocess.Popen(*args, **kwargs); children.append(child); return child
        began = time.monotonic()
        code = watch.supervise([sys.executable, '-c', 'import time; time.sleep(120)'],
            'local', grace=0, interval=.02, failures=2, popen=start, check=lambda *a: False)
        self.assertEqual(code, 70)
        self.assertLess(time.monotonic() - began, 2)
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ProcessLookupError): os.kill(children[0].pid, 0)

    @unittest.skipUnless(os.name == 'posix', 'owned Unix process group')
    def test_real_shutdown_reaps_child(self):
        watch = module(); children = []; stop = threading.Event()
        def start(*args, **kwargs):
            child = subprocess.Popen(*args, **kwargs); children.append(child); stop.set(); return child
        self.assertEqual(watch.supervise([sys.executable, '-c', 'import time; time.sleep(120)'],
            'local', interval=.02, stop=stop, popen=start), 0)
        self.assertIsNotNone(children[0].poll())

    def test_real_slow_control_response_has_total_deadline(self):
        watch = module(); listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(1)
        stop = threading.Event()
        def peer():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(1); conn.recv(4096)
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n')
                    for byte in b'{"version":"1.9.14","camera":"offline"}':
                        conn.sendall(bytes([byte]))
                        if stop.wait(.03): break
            except OSError: pass
        thread = threading.Thread(target=peer, daemon=True); thread.start(); began = time.monotonic()
        try:
            self.assertFalse(watch.probe('http://127.0.0.1:' + str(listener.getsockname()[1]) + '/api', .18))
            self.assertLess(time.monotonic() - began, .7)
        finally:
            stop.set(); listener.close(); thread.join(2)
        self.assertFalse(thread.is_alive())


if __name__ == '__main__': unittest.main()
