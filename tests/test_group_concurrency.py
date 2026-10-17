"""Real SQLite poller/outbox races must never publish an eligible legacy row."""
import datetime
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from reolink_protect_events.runtime import Journal
from reolink_protect_events.visual_groups import VisualGroups


CAMERA = '111111111111111111111111'


class PublicationConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='visual-group-concurrency-')
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'journal.sqlite3'
        self.reader = Journal(self.path)
        self.addCleanup(self.reader.close)
        self.reader.visual_groups = VisualGroups(self.reader, [CAMERA], {'enabled': True, 'maxSpanSeconds': 120})
        at = self.reader.visual_groups.activation_ms + 1
        stamp = datetime.datetime.fromtimestamp(at / 1000, datetime.timezone.utc).isoformat()
        self.response = {'instanceId': 'a' * 32, 'currentSeq': 1, 'oldestSeq': 1,
                         'source': {'connectionEpoch': 1, 'connected': True},
                         'events': [{'seq': 1, 'timestampUtc': stamp, 'classes': ['person'],
                                     'rawAiTypes': [], 'source': {'connectionEpoch': 1}}]}

    def writer(self, ready, begin, blocked, release, committed, observed):
        journal = None
        try:
            # The collector owns and closes its separate connection on this
            # thread, exactly as the production poller/outbox ownership requires.
            journal = Journal(self.path)
            journal.db.execute('PRAGMA busy_timeout=50')
            ready.set()
            if not begin.wait(3):
                raise RuntimeError('writer_start_timeout')
            try:
                journal.ingest({'cameraId': CAMERA}, self.response)
            except sqlite3.OperationalError as error:
                if 'locked' not in str(error).lower():
                    raise
                blocked.set()
                if not release.wait(3):
                    raise RuntimeError('writer_release_timeout')
                journal.ingest({'cameraId': CAMERA}, self.response)
            observed['sourceId'] = journal.db.execute('SELECT id FROM intervals').fetchone()[0]
            committed.set()
        except Exception as error:
            observed['error'] = type(error).__name__
            ready.set()
        finally:
            if journal is not None:
                journal.close()

    def test_poller_commit_between_enrollment_and_outbox_select_is_excluded_until_next_snapshot(self):
        ready, begin, blocked, release, committed = (threading.Event() for _ in range(5))
        observed = {}
        thread = threading.Thread(target=self.writer, args=(ready, begin, blocked, release, committed, observed))
        thread.start()
        self.assertTrue(ready.wait(3), 'poller connection did not initialize')
        trace_seen = []

        def trace(statement):
            if 'FROM publication_intervals i LEFT JOIN delivery_failures' in statement and not trace_seen:
                # A trace callback runs immediately before the actual outbox
                # SELECT. The writer attempts a genuine ingest at that boundary.
                begin.set()
                trace_seen.append({'transaction': self.reader.db.in_transaction,
                                   'blocked': blocked.wait(2), 'committed': committed.is_set()})

        self.reader.db.set_trace_callback(trace)
        try:
            first = self.reader.pending()
        finally:
            self.reader.db.set_trace_callback(None)
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive(), 'collector failed to finish after snapshot released its lock')
        self.assertNotIn('error', observed)
        self.assertEqual(trace_seen, [{'transaction': True, 'blocked': True, 'committed': False}])
        self.assertEqual(first, [])
        self.assertTrue(committed.is_set())
        second = self.reader.pending()
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0]['classes'], ['person'])
        self.assertEqual(second[0]['provenance']['visualGroupVersion'], 1)
        self.assertNotEqual(second[0]['eventId'], observed['sourceId'])

    def test_already_committed_source_is_enrolled_before_outbox_snapshot(self):
        ready, begin, blocked, release, committed = (threading.Event() for _ in range(5))
        observed = {}
        begin.set()
        release.set()
        thread = threading.Thread(target=self.writer, args=(ready, begin, blocked, release, committed, observed))
        thread.start()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertNotIn('error', observed)
        self.assertTrue(committed.is_set())
        # Ensure an immediate, millisecond-resolution source timestamp is now
        # observed; Event.wait is bounded and does not substitute for locking.
        deadline = time.monotonic() + 1
        while int(time.time() * 1000) <= self.reader.visual_groups.activation_ms + 1:
            if time.monotonic() >= deadline:
                self.fail('source timestamp did not become current')
            threading.Event().wait(0.001)
        row, = self.reader.pending()
        self.assertEqual(row['classes'], ['person'])
        self.assertEqual(row['provenance']['visualGroupVersion'], 1)
        self.assertNotEqual(row['eventId'], observed['sourceId'])


if __name__ == '__main__':
    unittest.main()
