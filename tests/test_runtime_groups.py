"""Exercise multi-type delivery and media through the actual durable runtime."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.runtime import Runtime, grouping_settings, validate_config
from test_runtime_delivery import CAMERA, START, FakeClient, FakeNative, config, response, source


class GroupedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name)
        self.now = START
        self.clock = patch('reolink_protect_events.runtime.time.time', side_effect=lambda: self.now / 1000)
        self.clock.start()
        self.cfg = config()
        self.cfg['eventGrouping'] = {'enabled': True, 'maxSpanSeconds': 120}
        self.runtime = Runtime(self.cfg, self.path, background_native=False)
        self.native, self.client = FakeNative(), FakeClient()
        self.attach()

    def attach(self):
        self.runtime.native, self.runtime.clients, self.runtime.native_ready = self.native, {CAMERA: self.client}, True

    def tearDown(self):
        self.runtime.close()
        self.clock.stop()
        self.folder.cleanup()

    def ingest(self, seq, offset, classes):
        self.now = START + offset
        self.runtime.journal.ingest(self.cfg['bridges'][0], response([source(seq, offset, classes)]))

    def test_delivery_expands_same_live_event_and_keeps_source_intervals(self):
        self.ingest(1, 0, ('vehicle',))
        self.runtime.deliver()
        event_id = next(iter(self.native.rows))
        self.ingest(2, 4000, ('vehicle', 'person'))
        self.runtime.deliver()
        self.assertEqual(list(self.native.rows), [event_id])
        self.assertEqual(self.native.rows[event_id]['smartDetectTypes'], ['person', 'vehicle'])
        self.assertEqual(self.client.sent[-1][0], 'update')
        latest = self.native.calls[-1][0]
        self.assertEqual(latest['provenance']['classIntervals']['person'][0]['start'], START + 4000)
        self.assertEqual(latest['provenance']['classIntervals']['vehicle'][0]['start'], START)
        self.assertEqual(self.runtime.journal.db.execute('SELECT COUNT(*) FROM intervals').fetchone()[0], 2)
        self.assertEqual(self.runtime.journal.health()['pending'], 0)

    def test_group_media_routes_acknowledgements_and_pins_preview_across_restart(self):
        self.ingest(1, 0, ('vehicle', 'person'))
        self.runtime.deliver()
        event_id = next(iter(self.native.rows))
        self.now += 20000
        media = self.runtime.journal.pending_media(self.now)
        self.assertEqual([row['eventId'] for row in media], [event_id])
        self.assertEqual(media[0]['classes'], ['person', 'vehicle'])
        selection = {'mode': 'automatic', 'timestamp': START + 1000, 'sha256': 'a' * 64}
        self.runtime.journal.media_selection(event_id, selection)
        self.runtime.close()
        self.runtime = Runtime(self.cfg, self.path, background_native=False)
        self.attach()
        self.runtime.journal.pending()
        current = self.runtime.journal.media_interval(event_id)
        self.assertEqual(current['provenance']['thumbnailSelection'], selection)
        self.assertEqual(current['classes'], ['person', 'vehicle'])
        self.runtime.journal.media_attempt(event_id, self.now, True)
        self.assertEqual(self.runtime.journal.health()['pendingThumbnails'], 0)

    def test_native_commit_retry_reuses_group_identity(self):
        self.ingest(1, 0, ('person', 'vehicle'))
        first = self.runtime.journal.pending()[0]
        self.native.fail.add(first['eventId'])
        self.runtime.deliver()
        self.assertEqual(self.runtime.journal.health()['retryIntervals'], 1)
        self.native.fail.clear()
        self.now += 10000
        self.runtime.deliver()
        self.assertEqual(list(self.native.rows), [first['eventId']])
        self.assertEqual(self.runtime.journal.health()['pending'], 0)
        self.assertEqual(self.runtime.journal.health()['retryIntervals'], 0)

    def test_disabled_enrollment_still_finishes_existing_group(self):
        self.ingest(1, 0, ('vehicle',))
        self.runtime.deliver()
        event_id = next(iter(self.native.rows))
        self.runtime.close()
        disabled = copy.deepcopy(self.cfg)
        disabled['eventGrouping']['enabled'] = False
        self.runtime = Runtime(disabled, self.path, background_native=False)
        self.attach()
        self.ingest(2, 2000, ())
        self.now += 10000
        self.runtime.deliver()
        self.assertEqual(list(self.native.rows), [event_id])
        self.assertIsNotNone(self.native.rows[event_id]['end'])

    def test_audio_and_new_visual_events_stay_distinct(self):
        self.ingest(1, 0, ('vehicle', 'person', 'speak'))
        values = self.runtime.journal.pending()
        self.assertEqual(sorted(row['classes'] for row in values), [['person', 'vehicle'], ['speak']])

    def test_manual_old_sources_and_media_survive_until_group_is_acknowledged(self):
        journal = self.runtime.journal
        past = START - 40 * 86400000
        ids = ['1' * 24, '2' * 24]
        with journal.db:
            for identifier, kind in zip(ids, ('vehicle', 'person')):
                journal.db.execute('INSERT INTO intervals(id,camera,class,start,end,last_seen,provenance,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,1,1)',
                    (identifier, CAMERA, kind, past, past + 10000, past + 10000, '{}'))
                journal.db.execute('INSERT INTO media(event_id,done) VALUES(?,1)', (identifier,))
            journal.db.execute('INSERT INTO visual_groups(id,camera,start,end,last_seen,provenance,classes,revision,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,2,1,1)',
                (ids[0], CAMERA, past, past + 10000, past + 10000, '{}', '["person","vehicle"]'))
            journal.db.execute('INSERT INTO visual_group_manual VALUES(?,?,?,?)',
                (ids[0], 'fixture-operation', json.dumps(ids), 'a' * 64))
            for identifier in ids:
                journal.db.execute('INSERT INTO visual_group_members VALUES(?)', (identifier,))
                journal.db.execute('INSERT INTO visual_group_segments VALUES(?,?)', (ids[0], identifier))
        journal.prune(START)
        self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM intervals').fetchone()[0], 2)
        self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM media').fetchone()[0], 2)
        journal.acknowledge(ids[0], 2, 'delivered')
        journal.acknowledge(ids[0], 2, 'notified')
        journal.prune(START)
        for table in ('intervals', 'media', 'visual_groups', 'visual_group_manual', 'visual_group_members'):
            self.assertEqual(journal.db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0, table)


class GroupingConfigTests(unittest.TestCase):
    def test_default_and_explicit_bounds(self):
        self.assertEqual(grouping_settings({}), {'enabled': False, 'maxSpanSeconds': 120})
        for value in (None, {}, {'enabled': True}, {'enabled': False, 'maxSpanSeconds': 300}):
            cfg = config()
            cfg['eventGrouping'] = value
            validate_config(cfg)

    def test_malformed_grouping_cannot_start_runtime(self):
        for value in (True, [], {'enabled': 1}, {'maxSpanSeconds': True}, {'maxSpanSeconds': 0},
                      {'maxSpanSeconds': 301}, {'unbounded': True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cfg = config()
                cfg['eventGrouping'] = value
                validate_config(cfg)
