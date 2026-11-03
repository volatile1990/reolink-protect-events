"""Keep durable delivery truthful while eliminating idle/history-sized work."""
import concurrent.futures
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from reolink_protect_events.runtime import Journal, Runtime


CAMERA = '111111111111111111111111'
INSTANCE = 'a' * 32
NOW = 1791586997512
CONFIG = {'bridges': [{'cameraId': CAMERA, 'host': '192.168.30.214',
    'username': 'fixture-user', 'password': 'fixture-password'}],
    'protectVersion': '7.3.70', 'protectUserId': 'fixture-owner', 'dsProxyPort': 7448}


class RuntimeCpuTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.runtime = Runtime(CONFIG, self.root, background_native=False)
        self.addCleanup(self.runtime.close)
        self.journal = self.runtime.journal

    def interval(self, identifier, *, start=NOW - 5000, end=None, revision=1,
                 delivered=0, notified=0, hidden=False, media=True):
        with self.journal.db:
            self.journal.db.execute('INSERT INTO intervals(id,camera,class,start,end,last_seen,provenance,revision,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (identifier, CAMERA, 'person', start, end, start, '{}', revision, delivered, notified))
            if hidden:
                self.journal.db.execute('INSERT INTO visual_group_members VALUES(?)', (identifier,))
            if media:
                self.journal.db.execute('INSERT INTO media(event_id) VALUES(?)', (identifier,))

    def group(self, identifier, *, start=NOW - 5000, end=None, revision=1,
              delivered=0, notified=0, manual=False):
        with self.journal.db:
            self.journal.db.execute('INSERT INTO visual_groups(id,camera,start,end,last_seen,provenance,revision,delivered_revision,notified_revision,classes) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (identifier, CAMERA, start, end, start, '{}', revision, delivered, notified, '["person","vehicle"]'))
            self.journal.db.execute('INSERT INTO media(event_id) VALUES(?)', (identifier,))
            if manual:
                self.journal.db.execute('INSERT INTO visual_group_manual VALUES(?,?,?,?)',
                    (identifier, identifier + '-operation', '[]', 'fixture-digest'))

    def test_health_is_fresh_and_matches_publication_view_with_hidden_and_manual_rows(self):
        self.interval('pending-open')
        self.interval('pending-close', end=NOW - 2000, revision=2, delivered=1, notified=1)
        self.interval('hidden', hidden=True, start=NOW - 9000)
        self.interval('done', end=NOW - 2000, delivered=1, notified=1)
        self.group('automatic', start=NOW - 3000)
        self.group('manual', start=NOW - 10000, manual=True, revision=2, delivered=2, notified=1)
        with self.journal.db:
            self.journal.db.execute("UPDATE media SET attempts=20,error_reason='snapshot_timeout' WHERE event_id='pending-close'")
            self.journal.db.execute("UPDATE media SET done=1 WHERE event_id='done'")
            self.journal.db.execute("INSERT INTO delivery_failures VALUES('pending-open',1,?)", (NOW + 2000,))
        with patch('reolink_protect_events.runtime.time.time', return_value=NOW / 1000):
            before = self.journal.db.total_changes
            health = self.journal.health()
            self.assertEqual(before, self.journal.db.total_changes)
            expected = self.journal.db.execute('SELECT COUNT(*),MIN(start) FROM publication_intervals WHERE delivered_revision<revision OR notified_revision<revision').fetchone()
            self.assertEqual((health['pending'], health['oldestPendingStartMs']), expected)
            self.assertEqual(health['oldestPendingAgeMs'], NOW - expected[1])
            self.assertEqual(health['openIntervals'], self.journal.db.execute('SELECT COUNT(*) FROM publication_intervals WHERE end IS NULL').fetchone()[0])
            self.assertEqual(health['pending'], 4)
            self.assertEqual(health['openIntervals'], 3)
            self.assertEqual(health['pendingThumbnails'], 3)
            self.assertEqual(health['failedThumbnails'], 1)
            self.assertEqual(health['thumbnailErrorReasons'], {'snapshot_timeout': 1})
            self.assertEqual(health['retryIntervals'], 1)
        # A separate connection commits after the first read: no cached health.
        writer = Journal(self.journal.path)
        try:
            with writer.db:
                writer.db.execute("UPDATE intervals SET delivered_revision=revision,notified_revision=revision,end=? WHERE id='pending-open'", (NOW,))
            fresh = self.journal.health()
            self.assertEqual(fresh['pending'], 3)
            self.assertEqual(fresh['openIntervals'], 2)
        finally:
            writer.close()

    def test_pending_branch_projection_matches_view_order_classes_and_retry_filter(self):
        self.interval('legacy', start=NOW - 7000)
        self.interval('hidden', hidden=True, start=NOW - 10000)
        self.group('manual', start=NOW - 5000, manual=True)
        self.group('retry', start=NOW - 9000)
        with self.journal.db:
            self.journal.db.execute("INSERT INTO delivery_failures VALUES('retry',1,?)", (NOW + 1,))
        # This fixture deliberately constructs view membership directly. The
        # real enrollment/transaction boundary has separate two-connection tests.
        with patch('reolink_protect_events.runtime.time.time', return_value=NOW / 1000), \
             patch.object(self.journal.visual_groups, 'sync'):
            rows = self.journal.pending()
            reference = self.journal.db.execute('SELECT i.id,i.classes FROM publication_intervals i LEFT JOIN delivery_failures f ON f.event_id=i.id WHERE (i.delivered_revision<i.revision OR i.notified_revision<i.revision) AND COALESCE(f.next_attempt,0)<=? ORDER BY i.start LIMIT 16', (NOW,)).fetchall()
        self.assertEqual([r['eventId'] for r in rows], [r[0] for r in reference])
        self.assertEqual([r['classes'] for r in rows], [['person'], ['person', 'vehicle']])
        self.assertNotIn('hidden', [r['eventId'] for r in rows])

    def test_repeated_empty_bridge_pages_do_not_write_cursors_with_or_without_fusion(self):
        for fusion in (False, True):
            with self.subTest(fusion=fusion):
                journal = Journal(self.root / ('fusion' if fusion else 'plain') / 'journal.sqlite3')
                try:
                    if fusion:
                        journal.enable_fusion([CAMERA], {'staleSeconds': 120, 'finalizeSeconds': 4, 'historySeconds': 300})
                    page = {'instanceId': INSTANCE, 'oldestSeq': 1, 'currentSeq': 0, 'events': []}
                    journal.ingest({'cameraId': CAMERA}, page)
                    before = journal.db.total_changes
                    journal.ingest({'cameraId': CAMERA}, page)
                    self.assertEqual(journal.db.total_changes, before)
                    # NULL -> epoch is genuine state and must still persist.
                    page['source'] = {'connectionEpoch': 0, 'connected': True}
                    journal.ingest({'cameraId': CAMERA}, page)
                    self.assertEqual(journal.cursor(CAMERA)['epoch'], 0)
                    self.assertGreater(journal.db.total_changes, before)
                    before = journal.db.total_changes
                    journal.ingest({'cameraId': CAMERA}, page)
                    self.assertEqual(journal.db.total_changes, before)
                    page['instanceId'] = 'b' * 32
                    journal.ingest({'cameraId': CAMERA}, page)
                    self.assertEqual(journal.cursor(CAMERA), {'instance': 'b' * 32, 'seq': 0, 'epoch': 0})
                    self.assertEqual(journal.db.execute('PRAGMA synchronous').fetchone()[0], 2)
                finally:
                    journal.close()

    def test_idle_retry_and_strict_thumbnail_due_times_bound_wait(self):
        self.assertEqual(self.journal.outbox_wait_seconds(NOW), 1)
        self.interval('retry', media=False)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW), 0.1)
        with self.journal.db:
            self.journal.db.execute("INSERT INTO delivery_failures VALUES('retry',1,?)", (NOW + 250,))
        self.assertEqual(self.journal.outbox_wait_seconds(NOW), 0.25)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 250), 0.1)
        self.journal.acknowledge('retry', 1, 'delivered')
        self.journal.acknowledge('retry', 1, 'notified')
        self.interval('thumbnail', start=NOW, delivered=1, notified=1)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 1001), 0.5)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 1501), 0.1)
        self.journal.media_attempt('thumbnail', NOW + 1501, False)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 16001), 0.501)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 16001, include_media=False), 1)
        self.journal.media_attempt('thumbnail', NOW + 16002, True)
        self.assertEqual(self.journal.outbox_wait_seconds(NOW + 16002), 1)

    def test_commit_signal_follows_commit_and_unchanged_cursor_does_not_wake(self):
        page = {'instanceId': INSTANCE, 'oldestSeq': 1, 'currentSeq': 0, 'events': []}
        seen = []
        def committed_signal():
            seen.append(self.journal.db.in_transaction)
        self.runtime._native_wake.set = committed_signal
        self.runtime._commit_and_wake(self.journal.ingest, {'cameraId': CAMERA}, page)
        self.assertEqual(seen, [False])
        self.runtime._commit_and_wake(self.journal.ingest, {'cameraId': CAMERA}, page)
        self.assertEqual(seen, [False])
        def rolled_back():
            with self.journal.db:
                self.journal.count('rolledBack')
                raise ValueError('fixture rollback')
        with self.assertRaises(ValueError):
            self.runtime._commit_and_wake(rolled_back)
        self.assertEqual(self.journal.counter('rolledBack'), 0)
        self.assertEqual(seen, [False])

    def test_worker_cannot_lose_commit_signal_between_select_and_wait(self):
        parent = self.runtime
        observed = []
        class Wake:
            signalled = False
            def clear(self):
                self.signalled = False
            def set(self):
                self.signalled = True
            def wait(self, timeout):
                observed.append((self.signalled, timeout))
                if not self.signalled or len(observed) > 2:
                    parent._stop.set()
        parent._native_wake = Wake()
        calls = []
        def deliver():
            calls.append('select')
            if len(calls) == 1:
                # Emulate a collector commit after the worker's SELECT. The
                # next wait MUST return immediately and perform another pass.
                parent._native_wake.set()
        worker = SimpleNamespace(check_native=lambda: None, deliver=deliver,
            deliver_media=lambda _: None, native_ready=True, native_error=None,
            native=SimpleNamespace(protect_version='7.3.74'),
            _native_wait_seconds=lambda: 1.0, _media_future=None, _media_pool=None,
            clients={}, journal=SimpleNamespace(counter=lambda _: 0, close=lambda: None))
        with patch('reolink_protect_events.runtime.Runtime', return_value=worker):
            parent._native_loop()
        self.assertEqual(calls, ['select', 'select'])
        self.assertEqual(observed, [(True, 1.0), (False, 1.0)])
        self.assertTrue(parent._native_state['nativeReady'])
        self.assertEqual(parent._native_state['protectVersion'], '7.3.74')

    def test_thumbnail_future_completion_and_stop_wake_idle_worker(self):
        self.runtime.config = dict(CONFIG, thumbnailSelection={'mode': 'automatic'})
        self.runtime.native_ready = True
        self.interval('thumbnail', delivered=1, notified=1)
        future = concurrent.futures.Future()
        pool = Mock()
        pool.submit.return_value = future
        self.runtime._media_pool = pool
        self.runtime.deliver_media(NOW)
        self.assertIs(self.runtime._media_future, future)
        self.assertFalse(self.runtime._native_wake.is_set())
        future.set_result(None)
        self.assertTrue(self.runtime._native_wake.is_set())
        self.runtime._native_wake.clear()
        self.runtime.request_stop()
        self.assertTrue(self.runtime._native_wake.is_set())
        self.assertTrue(self.runtime._stop.is_set())

    def test_native_check_deadline_and_unavailable_native_do_not_scan_outbox(self):
        with patch('reolink_protect_events.runtime.time.time', return_value=NOW / 1000), \
             patch.object(self.journal, 'outbox_wait_seconds', return_value=0.25) as wait:
            self.runtime.native_ready = True
            self.runtime.last_native_check = NOW
            self.assertEqual(self.runtime._native_wait_seconds(), 0.25)
            self.runtime.last_native_check = NOW - 60000
            self.assertEqual(self.runtime._native_wait_seconds(), 0.1)
            wait.reset_mock()
            self.runtime.native_ready = False
            self.runtime.last_native_check = NOW
            self.assertEqual(self.runtime._native_wait_seconds(), 1)
            wait.assert_not_called()

    def test_pending_health_work_is_bounded_by_open_outbox_not_closed_history(self):
        # Count SQLite VM operations, not wall time: this is a deterministic
        # complexity contract on a real database with a large delivered history.
        with self.journal.db:
            self.journal.db.executemany('INSERT INTO intervals(id,camera,class,start,end,last_seen,provenance,revision,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,?,?,?)',
                [(str(i), CAMERA, 'person', i, i + 1, i, '{}', 1, 1, 1) for i in range(5000)])
        self.interval('pending')
        def operations(query):
            steps = [0]
            def progress():
                steps[0] += 1
                return 0
            self.journal.db.set_progress_handler(progress, 1)
            try:
                result = self.journal.db.execute(query).fetchall()
            finally:
                self.journal.db.set_progress_handler(None, 0)
            return result, steps[0]
        counted, count_steps = operations('SELECT COUNT(*) FROM publication_intervals WHERE delivered_revision<revision OR notified_revision<revision')
        oldest, oldest_steps = operations('SELECT MIN(start) FROM publication_intervals WHERE delivered_revision<revision OR notified_revision<revision')
        branch = self.journal._publications_sql('COUNT(*) AS n,MIN(i.start) AS oldest', '(i.delivered_revision<i.revision OR i.notified_revision<i.revision)')
        optimized, new_steps = operations('SELECT SUM(n),MIN(oldest) FROM (' + branch + ')')
        self.assertEqual(optimized, [(counted[0][0], oldest[0][0])])
        self.assertLess(new_steps, count_steps + oldest_steps)
        # The read must remain independent of delivered, closed history size.
        with self.journal.db:
            self.journal.db.execute("DELETE FROM intervals WHERE id<>'pending'")
        same, short_steps = operations('SELECT SUM(n),MIN(oldest) FROM (' + branch + ')')
        self.assertEqual(same, optimized)
        self.assertLessEqual(new_steps, short_steps + 10)


if __name__ == '__main__':
    unittest.main()
