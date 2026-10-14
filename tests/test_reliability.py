"""Regression and fault tests against real journals/files and loopback sockets."""
import copy
import base64
import datetime
import importlib.util
import json
import io
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from reolink_protect_events.feature_rollback import recover_legacy_state, resume_rollback
from reolink_protect_events.features import FeaturePatch, UI_ORIGINAL, sha256
from reolink_protect_events.http_deadline import get_bytes
from reolink_protect_events.native import NativeError
from reolink_protect_events.runtime import Journal, Runtime
from reolink_protect_events.updates import DsUpdateClient, DsUpdateError
from test_runtime_delivery import FakeClient, FakeNative, config, response, source, START, CAMERA
from test_updates import MockDs


class JournalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.j = Journal(Path(self.folder.name) / 'journal.sqlite3')
        self.addCleanup(self.j.db.close)

    def ingest(self, events, state=None):
        batch = response(events)
        if state is not None:
            batch['source'] = state
        self.j.ingest(config()['bridges'][0], batch)

    def test_backward_clock_does_not_shorten_known_activity_or_block_later_sequences(self):
        self.ingest([source(1), source(2, 60000), source(3, 30000), source(4, -1000), source(5, 40000, ())])
        event = self.j.pending()[0]
        self.assertGreaterEqual(event['end'], START + 60000)
        self.assertEqual(self.j.cursor(CAMERA)['seq'], 5)
        self.assertTrue(event['provenance']['sourceClockRegressed'])
        self.assertTrue(event['provenance']['endIsTimeoutEstimate'])
        self.assertEqual(event['provenance']['lastSourceEvent']['timestampUtc'], source(5, 40000, ())['timestampUtc'])
        self.assertEqual(self.j.health()['counters']['sourceClockRegressions'], 3)

    def test_empty_replay_reports_reconnect_without_inventing_source_event(self):
        self.ingest([source(1)], {'connectionEpoch': 0, 'connected': True})
        self.j.ingest(config()['bridges'][0], {'instanceId': 'a' * 32, 'oldestSeq': 1,
            'currentSeq': 1, 'events': [], 'source': {'connectionEpoch': 1, 'connected': True}})
        self.assertIsNotNone(self.j.pending()[0]['end'])
        self.assertEqual(self.j.pending()[0]['provenance']['closureReason'], 'source_reconnect')
        self.assertEqual(self.j.health()['sourceRows'], 1)
        self.assertEqual(self.j.cursor(CAMERA)['epoch'], 1)

    def test_source_state_boundary_is_applied_after_replay_and_old_bridges_work(self):
        self.ingest([source(1)], {'connectionEpoch': 1, 'connected': False})
        self.assertEqual(self.j.pending()[0]['provenance']['closureReason'], 'source_disconnect')
        self.ingest([source(2, 1000)])
        self.assertEqual(self.j.health()['sourceRows'], 2)
        self.assertEqual(len(self.j.pending()), 2)

    def test_invalid_source_state_is_atomic(self):
        with self.assertRaises(ValueError):
            self.ingest([source(1)], {'connectionEpoch': True, 'connected': True})
        self.assertEqual(self.j.health()['sourceRows'], 0)

    def test_partial_durable_replay_does_not_apply_current_epoch_or_timeout_too_early(self):
        batch = response([source(1), source(2, 1000)])
        batch.update(currentSeq=4, source={'connectionEpoch': 1, 'connected': False})
        self.j.ingest(config()['bridges'][0], batch)
        self.assertEqual(self.j.cursor(CAMERA)['epoch'], 0)
        self.j.expire(START + 1000000, {CAMERA})
        self.assertEqual(self.j.health()['openIntervals'], 1)
        batch = response([source(3, 2000), source(4, 3000)])
        batch.update(source={'connectionEpoch': 1, 'connected': False})
        self.j.ingest(config()['bridges'][0], batch)
        self.assertEqual(len(self.j.pending()), 1)
        self.assertEqual(self.j.health()['openIntervals'], 0)
        self.assertEqual(self.j.cursor(CAMERA)['seq'], 4)

    def test_empty_expired_replay_advances_floor_and_counts_loss_only_once(self):
        self.ingest([source(1)])
        batch = {'instanceId': 'a' * 32, 'oldestSeq': 11, 'currentSeq': 10, 'events': [],
                 'source': {'connectionEpoch': 2, 'connected': False}}
        for _ in range(2):
            self.j.ingest(config()['bridges'][0], batch)
        self.assertEqual(self.j.cursor(CAMERA), {'instance': 'a' * 32, 'seq': 10, 'epoch': 2})
        self.assertEqual(self.j.health()['counters']['replayGaps'], 1)
        self.assertEqual(self.j.health()['counters']['replayLostPushes'], 9)
        self.assertEqual(self.j.health()['sourceRows'], 1)
        self.assertEqual(self.j.health()['openIntervals'], 0)

    def test_media_backoff_reason_survives_restart_and_explicit_retry_keeps_delivery(self):
        self.ingest([source(1)])
        eid = self.j.pending()[0]['eventId']
        self.j.acknowledge(eid, 1, 'delivered')
        self.j.acknowledge(eid, 1, 'notified')
        now = START + 50000
        for offset in (0, 20000, 50000):
            self.j.media_attempt(eid, now + offset, False, 'timeout')
        path = self.j.path
        self.j.db.close()
        self.j = Journal(path)
        self.addCleanup(self.j.db.close)
        self.assertEqual(self.j.health()['thumbnailErrorReasons'], {'timeout': 1})
        self.assertEqual(self.j.pending_media(now + 50001), [])
        self.assertEqual(self.j.retry_media([eid]), 1)
        self.assertEqual(len(self.j.pending_media(now + 50001)), 1)
        row = self.j.db.execute('SELECT delivered_revision,notified_revision FROM intervals WHERE id=?', (eid,)).fetchone()
        self.assertEqual(row, (1, 1))
        self.j.media_attempt(eid, now + 50001, True)
        self.assertEqual(self.j.retry_media([eid]), 0)
        self.assertEqual(self.j.health()['thumbnailErrorReasons'], {})

    def test_legacy_media_schema_is_upgraded_without_resetting_sources_or_outbox(self):
        self.ingest([source(1)])
        eid = self.j.pending()[0]['eventId']
        self.j.db.executescript('ALTER TABLE media RENAME TO upgraded_media; '
            'CREATE TABLE media(event_id TEXT PRIMARY KEY,attempts INTEGER NOT NULL DEFAULT 0,last_attempt INTEGER NOT NULL DEFAULT 0,done INTEGER NOT NULL DEFAULT 0); '
            'INSERT INTO media SELECT event_id,attempts,last_attempt,done FROM upgraded_media; DROP TABLE upgraded_media;')
        path = self.j.path
        self.j.db.close()
        self.j = Journal(path)
        self.addCleanup(self.j.db.close)
        self.assertEqual(self.j.pending()[0]['eventId'], eid)
        self.assertEqual(self.j.cursor(CAMERA)['seq'], 1)
        self.assertEqual(self.j.health()['sourceRows'], 1)
        self.assertIn('next_attempt', {row[1] for row in self.j.db.execute('PRAGMA table_info(media)')})

    def test_partial_indexes_used_for_open_and_pending_work(self):
        plan = self.j.db.execute('EXPLAIN QUERY PLAN SELECT id FROM intervals WHERE camera=? AND end IS NULL', (CAMERA,)).fetchall()
        self.assertTrue(any('intervals_open' in row[3] for row in plan))
        plan = self.j.db.execute('EXPLAIN QUERY PLAN SELECT id FROM intervals WHERE delivered_revision<revision OR notified_revision<revision ORDER BY start').fetchall()
        self.assertTrue(any('intervals_pending' in row[3] for row in plan))

    def test_second_connection_never_acknowledges_a_later_collector_revision(self):
        self.ingest([source(1)])
        second = Journal(self.j.path)
        try:
            interval = second.pending()[0]
            self.ingest([source(2, 5000, ())])
            second.acknowledge(interval['eventId'], 1, 'delivered')
            second.acknowledge(interval['eventId'], 1, 'notified')
            self.assertEqual(self.j.pending()[0]['revision'], 2)
            self.assertEqual(self.j.pending()[0]['deliveredRevision'], 1)
        finally:
            second.db.close()


class RollbackRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.vendor = ('const ' + UI_ORIGINAL + ';').encode()
        self.targets = [root / 'swai.js', root / 'swai-version.js']
        for target in self.targets:
            target.write_bytes(self.vendor)
        self.patch = FeaturePatch(version_reader=lambda: '7.3.70', ui_paths=self.targets, ui_hash=sha256(self.vendor))
        manifest = self.patch.apply(['1' * 24], root / 'backups')
        self.state = {'state': 'applied', 'uiManifest': manifest, 'cameraManifest': 'synthetic-camera.json'}
        self.persisted = []

    def persist(self, state):
        self.persisted.append(copy.deepcopy(state))

    def test_database_failure_after_ui_restore_can_resume_after_process_restart(self):
        def fail(_):
            raise NativeError('database offline')
        with self.assertRaises(NativeError):
            resume_rollback(self.state, self.persist, self.patch, types.SimpleNamespace(rollback=fail), lambda: None)
        self.assertTrue(all(target.read_bytes() == self.vendor for target in self.targets))
        restarted_state = copy.deepcopy(self.persisted[-1])
        calls = []
        resume_rollback(restarted_state, self.persist, self.patch,
                        types.SimpleNamespace(rollback=calls.append), lambda: self.fail('preflight must not require applied UI again'))
        self.assertEqual(calls, ['synthetic-camera.json'])
        self.assertEqual(restarted_state['rollbackPhase'], 'complete')

    def test_crash_after_ui_write_before_phase_save_is_idempotent(self):
        state = dict(self.state, rollbackPhase='ui', state='rolling_back')
        self.patch.rollback(state['uiManifest'])
        calls = []
        resume_rollback(state, self.persist, self.patch, types.SimpleNamespace(rollback=calls.append), lambda: None)
        self.assertEqual(state['state'], 'rolled_back')
        self.assertEqual(len(calls), 1)

    def test_controls_or_user_drift_after_partial_rollback_stops_camera_restore(self):
        state = dict(self.state, rollbackPhase='cameras', state='rolling_back')
        self.patch.rollback(state['uiManifest'])
        self.targets[0].write_bytes(self.vendor + b'new unrelated layer')
        calls = []
        with self.assertRaises(Exception):
            resume_rollback(state, self.persist, self.patch, types.SimpleNamespace(rollback=calls.append), lambda: None)
        self.assertEqual(calls, [])

    def test_preflight_rejection_does_not_start_rollback(self):
        def reject():
            raise ValueError('controls dependency')
        with self.assertRaises(ValueError):
            resume_rollback(self.state, self.persist, self.patch, None, reject)
        self.assertEqual(self.persisted, [])
        self.assertTrue(all(target.read_bytes() != self.vendor for target in self.targets))

    def test_partial_rollback_from_old_release_is_recoverable_without_relaxing_hashes(self):
        self.patch.rollback(self.state['uiManifest'])
        legacy = recover_legacy_state(self.state, json.loads(Path(self.state['uiManifest']).read_text()))
        self.assertNotIn('rollbackPhase', self.state)
        calls = []
        resume_rollback(legacy, self.persist, self.patch, types.SimpleNamespace(rollback=calls.append),
                        lambda: self.fail('legacy UI is already restored'))
        self.assertEqual(calls, ['synthetic-camera.json'])
        self.assertEqual(legacy['state'], 'rolled_back')


class TcpFixture:
    def __init__(self, response, delay=0, body_delay=0):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.response, self.delay = response, delay
        self.body_delay = body_delay
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        connection = None
        try:
            connection, _ = self.listener.accept()
            connection.settimeout(2)
            data = b''
            while b'\r\n\r\n' not in data:
                data += connection.recv(4096)
            if self.body_delay:
                headers, body = self.response.split(b'\r\n\r\n', 1)
                connection.sendall(headers + b'\r\n\r\n')
                time.sleep(self.body_delay)
                connection.sendall(body)
            elif self.delay:
                for byte in self.response:
                    connection.sendall(bytes([byte]))
                    time.sleep(self.delay)
            else:
                connection.sendall(self.response)
        except (OSError, TimeoutError):
            pass
        finally:
            if connection is not None:
                connection.close()
            self.listener.close()
            self.done.set()


class DeadlineTests(unittest.TestCase):
    def test_close_delimited_response_does_not_close_socket_before_delayed_body(self):
        for headers in (b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close', b'HTTP/1.0 200 OK'):
            fixture = TcpFixture(headers + b'\r\n\r\nabc', body_delay=0.05)
            try:
                self.assertEqual(get_bytes('http://127.0.0.1:' + str(fixture.port) + '/', timeout=1), (200, b'abc'))
            finally:
                self.assertTrue(fixture.done.wait(2))

    def test_http_connection_close_body_is_retained_and_limits_redirects_are_enforced(self):
        for response_, expected in ((b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc', b'abc'),
                                    (b'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/elsewhere\r\nContent-Length: 0\r\n\r\n', None),
                                    (b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd', None)):
            fixture = TcpFixture(response_)
            try:
                if expected is None:
                    with self.assertRaises(ValueError):
                        get_bytes('http://127.0.0.1:' + str(fixture.port) + '/', timeout=1, limit=3)
                else:
                    self.assertEqual(get_bytes('http://127.0.0.1:' + str(fixture.port) + '/', timeout=1, limit=3), (200, expected))
            finally:
                self.assertTrue(fixture.done.wait(2))

    def test_http_dribbling_headers_hit_total_deadline(self):
        fixture = TcpFixture(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', delay=0.04)
        began = time.monotonic()
        with self.assertRaises(TimeoutError):
            get_bytes('http://127.0.0.1:' + str(fixture.port) + '/', timeout=0.2)
        self.assertLess(time.monotonic() - began, 0.7)
        self.assertTrue(fixture.done.wait(2))

    def test_ds_dribbling_upgrade_hits_total_deadline(self):
        def behavior(mock, connection, accept):
            try:
                for byte in b'HTTP/1.1 101 Switching Protocols\r\n':
                    connection.sendall(bytes([byte]))
                    time.sleep(0.04)
            except OSError:
                pass
        server = MockDs(behavior)
        began = time.monotonic()
        with self.assertRaises(DsUpdateError):
            DsUpdateClient('AABBCCDDEEFF', port=server.port, timeout=0.2).connect()
        self.assertLess(time.monotonic() - began, 0.7)
        server.finish()

    def test_http_dribbling_body_hits_same_total_deadline(self):
        fixture = TcpFixture(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n' + b'x' * 100, delay=0.005)
        began = time.monotonic()
        with self.assertRaises(TimeoutError):
            get_bytes('http://127.0.0.1:' + str(fixture.port) + '/', timeout=0.25)
        self.assertLess(time.monotonic() - began, 0.7)
        self.assertTrue(fixture.done.wait(2))


class CollectorIsolationTests(unittest.TestCase):
    def test_close_releases_owner_journal_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Runtime(config(), folder, capture_only=True)
            runtime.close()
            runtime.close()
            with self.assertRaises(sqlite3.ProgrammingError):
                runtime.journal.health()

    def test_stop_during_schema_recovery_does_not_start_ds_handshakes(self):
        entered, release = threading.Event(), threading.Event()
        native = FakeNative()
        def guard():
            entered.set();release.wait(2)
        native.guard_schema = guard
        with tempfile.TemporaryDirectory() as folder:
            runtime = Runtime(config(), folder)
            try:
                with patch('reolink_protect_events.native.NativeAdapter', return_value=native), \
                     patch('reolink_protect_events.updates.DsUpdateClient') as clients:
                    runtime._start_native_worker()
                    self.assertTrue(entered.wait(2))
                    runtime._stop.set()
                    release.set()
                    runtime.close()
                    clients.assert_not_called()
                    self.assertFalse(runtime._native_thread.is_alive())
            finally:
                release.set();runtime.close()

    def test_blocked_native_schema_does_not_stop_capture_and_pool_is_reused(self):
        folder = tempfile.TemporaryDirectory()
        runtime = Runtime(config(), folder.name)
        entered, release = threading.Event(), threading.Event()
        native, client = FakeNative(), FakeClient()
        thread_ids = []
        def guard():
            thread_ids.append(threading.get_ident())
            entered.set()
            release.wait(3)
        native.guard_schema = guard
        try:
            with patch('reolink_protect_events.native.NativeAdapter', return_value=native), \
                 patch('reolink_protect_events.updates.DsUpdateClient', return_value=client), \
                 patch('reolink_protect_events.runtime.fetch_bridge', return_value=response([source(1)])), \
                 patch('reolink_protect_events.runtime.recording_thumbnail', side_effect=TimeoutError):
                runtime._start_native_worker()
                self.assertTrue(entered.wait(2))
                began = time.monotonic()
                runtime.once()
                self.assertLess(time.monotonic() - began, 0.7)
                self.assertEqual(runtime.journal.health()['sourceRows'], 1)
                self.assertEqual(runtime.journal.health()['pending'], 1)
                pool = runtime._pool
                runtime.once()
                self.assertIs(runtime._pool, pool)
                release.set()
                deadline = time.monotonic() + 2
                while runtime.journal.health()['pending'] and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(runtime.journal.health()['pending'], 0)
                self.assertTrue(all(identity != threading.get_ident() for identity in thread_ids))
                runtime.close()
                self.assertFalse(runtime._native_thread.is_alive())
        finally:
            release.set()
            runtime.close()
            runtime.journal.db.close()
            folder.cleanup()

    def test_restart_refetch_stays_in_parallel_network_workers(self):
        cfg = config([dict(config()['bridges'][0], cameraId=str(i) * 24, host='192.168.30.' + str(210 + i)) for i in range(1, 4)])
        with tempfile.TemporaryDirectory() as folder:
            runtime = Runtime(cfg, folder, capture_only=True)
            try:
                for bridge in cfg['bridges']:
                    runtime.journal.ingest(bridge, response([source(1)]))
                ids = []
                def fetch(bridge, after):
                    ids.append(threading.get_ident())
                    time.sleep(0.06)
                    batch = response([source(1)])
                    batch['instanceId'] = 'b' * 32
                    return batch
                with patch('reolink_protect_events.runtime.fetch_bridge', side_effect=fetch):
                    began = time.monotonic()
                    runtime.once()
                    self.assertLess(time.monotonic() - began, 0.3)
                self.assertEqual(len(ids), 6)
                self.assertNotIn(threading.get_ident(), ids)
            finally:
                runtime.close()
                runtime.journal.db.close()


class DeploymentHealthTests(unittest.TestCase):
    def test_stale_health_is_not_healthy_even_when_service_is_active(self):
        spec = importlib.util.spec_from_file_location('health_tool', Path(__file__).resolve().parents[1] / 'tools/deploy.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        env = {}
        exec(module.REMOTE.split('os.umask(0o077)')[0], env)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'config.json').write_text('{}')
            (root / 'health.json').write_text(json.dumps({'atMs': int(time.time() * 1000) - 60000, 'healthy': True}))
            env.update(root=root, run=lambda args: 'active')
            self.assertFalse(env['health']()['health']['healthy'])


class RetryToolTests(unittest.TestCase):
    def test_plan_and_apply_execute_real_journal_logic_with_complete_scope_preflight(self):
        project = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('retry_tool_test', project / 'tools/retry_thumbnails.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cfg_path, db_path = root / 'config.json', root / 'journal.sqlite3'
            cfg_path.write_text(json.dumps(config()))
            journal = Journal(db_path)
            try:
                journal.ingest(config()['bridges'][0], response([source(1)]))
                eid = journal.pending()[0]['eventId']
                journal.acknowledge(eid, 1, 'delivered')
                journal.acknowledge(eid, 1, 'notified')
                journal.media_attempt(eid, START, False, 'timeout')
                code = tool.REMOTE.replace("root=pathlib.Path('/data/reolink-protect-events')", 'root=pathlib.Path(' + repr(folder) + ')')
                code = code.replace('secure(config);secure(database)', 'pass')
                original_stat = Path.stat
                def private_stat(path, *args, **kwargs):
                    value = original_stat(path, *args, **kwargs)
                    if path in (cfg_path, db_path):
                        fields = list(value); fields[0] = 0o100600
                        return os.stat_result(fields)
                    return value
                def run(mode, ids):
                    sources = {name: base64.b64encode((project / 'reolink_protect_events' / (name + '.py')).read_bytes()).decode()
                               for name in ('http_deadline', 'runtime')}
                    previous_umask = os.umask(0o077)
                    try:
                        with patch.dict(sys.modules), patch.object(os, 'geteuid', return_value=0, create=True), \
                             patch.object(Path, 'stat', private_stat), patch('sys.stdout', new_callable=io.StringIO) as output:
                            exec(code, {'mode': mode, 'event_ids': ids, 'sources': sources})
                            return json.loads(output.getvalue())
                    finally:
                        os.umask(previous_umask)
                self.assertEqual(run('plan', [eid])['resetAttempts'], 0)
                self.assertEqual(journal.db.execute('SELECT attempts FROM media').fetchone()[0], 1)
                with self.assertRaises(ValueError):
                    run('apply', [eid, 'f' * 24])
                self.assertEqual(journal.db.execute('SELECT attempts FROM media').fetchone()[0], 1)
                self.assertEqual(run('apply', [eid])['resetAttempts'], 1)
                self.assertEqual(journal.db.execute('SELECT attempts FROM media').fetchone()[0], 0)
                self.assertEqual(journal.db.execute('SELECT delivered_revision,notified_revision FROM intervals').fetchone(), (1, 1))
            finally:
                journal.db.close()


if __name__ == '__main__':
    unittest.main()
