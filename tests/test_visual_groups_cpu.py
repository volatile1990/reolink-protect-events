"""Progress shortcut parity against the immutable, pre-optimization algorithm."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.runtime import Journal
from reolink_protect_events import visual_groups as candidate


FIXTURE = Path(__file__).parent / 'fixtures' / 'visual_groups_f52ce8f.py'
ORACLE_SHA256 = '9b657b2861fa5bf197b2acc00ab45a31d7cbb0cdf4561541bf9398c93f586c11'
spec = importlib.util.spec_from_file_location('visual_groups_frozen_f52ce8f', FIXTURE)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
START = 1792168300000
CAMERA = '1' * 24
OTHER = '2' * 24
PUBLIC_TABLES = ('intervals', 'visual_groups', 'visual_group_members',
                 'visual_group_segments', 'visual_group_manual', 'media')


class VisualGroupCpuTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.journals, self.groups = [], []
        for name, cls in [('oracle', oracle.VisualGroups), ('candidate', candidate.VisualGroups)]:
            journal = Journal(Path(self.folder.name) / (name + '.sqlite3'))
            self.addCleanup(journal.close)
            with patch.object(candidate.time, 'time', return_value=START / 1000):
                groups = cls(journal, (CAMERA, OTHER), {'enabled': True, 'maxSpanSeconds': 120})
            self.journals.append(journal)
            self.groups.append(groups)

    def execute(self, sql, values=()):
        for journal in self.journals:
            with journal.db:
                journal.db.execute(sql, values)

    def add(self, identifier, start, end, *, camera=CAMERA, label='person', meta=None):
        raw = json.dumps(dict({'identityStart': START + start, 'sourceTypes': ['reolink'],
                               'source': 'reolink-camera-ai'}, **(meta or {})))
        self.execute('INSERT INTO intervals(id,camera,class,start,end,last_seen,instance,epoch,provenance) '
                     'VALUES(?,?,?,?,?,?,?,?,?)', (identifier, camera, label, START + start,
                     None if end is None else START + end, START + (start if end is None else end),
                     'fixture', 1, raw))
        self.execute('INSERT INTO media(event_id) VALUES(?)', (identifier,))

    def snapshot(self, journal):
        return {table: journal.db.execute('SELECT * FROM ' + table +
                (' ORDER BY 1,2' if table == 'visual_group_segments' else ' ORDER BY 1')).fetchall()
                for table in PUBLIC_TABLES}

    def sync(self, offset):
        for groups in self.groups:
            groups.sync(START + offset)
        self.assertEqual(self.snapshot(self.journals[0]), self.snapshot(self.journals[1]))

    def seed(self, count=12):
        for index in range(count):
            self.add('source-' + str(index), index * 15000, index * 15000 + 5000)
        self.add('live', count * 15000, None)
        self.sync(count * 15000 + 1000)
        return count * 15000

    def test_oracle_is_exact_f52_source(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), ORACLE_SHA256)

    def test_pure_progress_skips_full_store_and_json_history(self):
        now = self.seed()
        statements = []
        self.journals[1].db.set_trace_callback(statements.append)
        with patch.object(self.groups[1], '_store', side_effect=AssertionError('historical store')):
            for tick in range(1, 5):
                self.execute("UPDATE intervals SET last_seen=? WHERE id='live'", (START + now + tick * 2000,))
                self.sync(now + tick * 2000)
        self.assertFalse(any('i.provenance' in sql for sql in statements))
        self.assertTrue(self.groups[1]._progress_cache)

    def test_progress_decrease_old_closed_source_and_acknowledgement_parity(self):
        now = self.seed()
        for value in (900000, 1000, 950000):
            self.execute("UPDATE intervals SET last_seen=? WHERE id='source-0'", (START + value,))
            self.sync(now + 3000)
        self.execute('UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision')
        self.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='live'")
        self.sync(now + 4000)

    def test_late_correction_provenance_and_cross_camera_move_use_full_path(self):
        now = self.seed()
        for sql, values in [
            ("UPDATE intervals SET end=? WHERE id='source-0'", (START + 18000,)),
            ("UPDATE intervals SET provenance=? WHERE id='source-1'", (json.dumps({'identityStart': START + 15000,
               'sourceTypes': ['frigate'], 'classificationDetails': {'animalType': ['cat']}}),)),
            ("UPDATE intervals SET camera=?,class='animal' WHERE id='source-2'", (OTHER,)),
            ("UPDATE intervals SET instance='second',epoch=2,last_seen=last_seen+1 WHERE id='live'", ())]:
            with patch.object(self.groups[1], '_store', wraps=self.groups[1]._store) as store:
                self.execute(sql, values)
                self.sync(now + 5000)
            if 'instance=' not in sql:
                self.assertGreater(store.call_count, 0)

    def test_future_start_and_cap_use_original_algorithm(self):
        self.add('vehicle', 0, None, label='vehicle')
        self.add('future', 130000, 140000)
        self.sync(1000)
        self.execute("UPDATE intervals SET last_seen=? WHERE id='vehicle'", (START + 120000,))
        with patch.object(self.groups[1], '_store', wraps=self.groups[1]._store) as store:
            self.sync(120000)
        self.assertGreater(store.call_count, 0)
        self.sync(135000)
        self.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='vehicle'", (START + 180000, START + 180000))
        self.sync(200000)

    def test_second_connection_and_new_grouper_restart(self):
        now = self.seed()
        others = [sqlite3.connect(j.path) for j in self.journals]
        try:
            for tick in range(1, 4):
                for db in others:
                    with db:
                        db.execute("UPDATE intervals SET last_seen=? WHERE id='live'", (START + now + tick * 1000,))
                self.sync(now + tick * 1000)
            for index, cls in enumerate((oracle.VisualGroups, candidate.VisualGroups)):
                self.groups[index] = cls(self.journals[index], (CAMERA, OTHER), {'enabled': True})
            self.sync(now + 6000)
        finally:
            for db in others:
                db.close()

    def test_savepoint_and_transaction_rollback_without_manual_invalidation(self):
        now = self.seed()
        for prefix, rollback in [('SAVEPOINT trial', 'ROLLBACK TO trial'), ('BEGIN IMMEDIATE', 'ROLLBACK')]:
            for journal, groups in zip(self.journals, self.groups):
                journal.db.execute(prefix)
                journal.db.execute("UPDATE intervals SET last_seen=last_seen+7000 WHERE id='live'")
                groups.sync(START + now + 7000)
                journal.db.execute(rollback)
                if prefix.startswith('SAVEPOINT'):
                    journal.db.execute('RELEASE trial')
            self.execute("UPDATE intervals SET last_seen=last_seen+1000 WHERE id='live'")
            self.sync(now + 2000)
        self.execute("UPDATE intervals SET class='vehicle' WHERE id='source-0'")
        self.sync(now + 3000)

    def test_shape_tracking_table_or_row_removal_repairs_conservatively(self):
        now = self.seed()
        for statement in ('DELETE FROM visual_group_shape_changes', 'DROP TABLE visual_group_shape_changes'):
            with self.journals[1].db:
                self.journals[1].db.execute(statement)
            self.sync(now + 4000)
            self.execute("UPDATE intervals SET last_seen=last_seen+1000 WHERE id='live'")
            self.sync(now + 5000)

    def test_cache_budget_falls_back_without_changing_publication(self):
        with patch.object(candidate, 'PROGRESS_CACHE_MAX_ITEMS', 3), patch.object(candidate, 'PROGRESS_CACHE_MAX_CHARACTERS', 12):
            now = self.seed()
            self.assertEqual(self.groups[1]._progress_cache, {})
            self.execute("UPDATE intervals SET last_seen=last_seen+1000 WHERE id='live'")
            self.sync(now + 3000)

    def test_cache_limit_applies_across_cameras(self):
        with patch.object(candidate, 'PROGRESS_CACHE_MAX_ITEMS', 35):
            for camera in (CAMERA, OTHER):
                for index in range(8):
                    self.add(camera + '-' + str(index), index * 15000, index * 15000 + 5000, camera=camera)
            self.sync(140000)
            self.assertLessEqual(sum(value['items'] for value in self.groups[1]._progress_cache.values()), 35)
            self.assertEqual(len(self.groups[1]._progress_cache), 1)
            self.execute('UPDATE intervals SET last_seen=last_seen+1')
            self.sync(140001)

    def test_published_disconnected_members_do_not_use_progress_shortcut(self):
        self.add('vehicle', 0, None, label='vehicle')
        self.add('person', 50000, None)
        self.sync(60000)
        self.execute('UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision')
        self.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='vehicle'", (START + 10000, START + 10000))
        self.sync(70000)
        self.assertNotIn(CAMERA, self.groups[1]._progress_cache)
        self.execute("UPDATE intervals SET last_seen=? WHERE id='person'", (START + 71000,))
        with patch.object(self.groups[1], '_store', wraps=self.groups[1]._store) as store:
            self.sync(71000)
        self.assertGreater(store.call_count, 0)

    def test_raw_fusion_range_change_and_manual_membership(self):
        self.execute('CREATE TABLE fusion_inputs(camera TEXT,class TEXT,start INTEGER,end INTEGER)')
        self.execute('INSERT INTO fusion_inputs VALUES(?,?,?,?)', (CAMERA, 'person', START, START + 10000))
        self.add('union', 0, None, meta={'sourceUnionVersion': 1})
        self.sync(20000)
        self.execute('UPDATE fusion_inputs SET end=?', (START + 15000,))
        self.sync(22000)
        self.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='union'")
        self.sync(23000)
        for journal in self.journals:
            identifier = journal.db.execute('SELECT id FROM visual_groups ORDER BY start LIMIT 1').fetchone()[0]
            with journal.db:
                journal.db.execute('INSERT INTO visual_group_manual VALUES(?,?,?,?)', (identifier, 'manual-fixture', '[]', 'fixture'))
        self.sync(24000)
        self.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='union'")
        self.sync(25000)

    def test_randomized_late_history_and_progress_matches_frozen_oracle(self):
        now = self.seed(20)
        rng = random.Random(25102026)
        for step in range(90):
            identifier = 'source-' + str(rng.randrange(20))
            action = rng.randrange(5)
            if action < 2:
                self.execute('UPDATE intervals SET last_seen=last_seen+? WHERE id=?', (rng.randrange(1, 5000), identifier))
            elif action == 2:
                self.execute('UPDATE intervals SET end=end+?,revision=revision+1 WHERE id=?', (rng.randrange(1, 8000), identifier))
            elif action == 3:
                self.execute('UPDATE intervals SET class=? WHERE id=?', (rng.choice(('person', 'vehicle', 'animal')), identifier))
            else:
                self.execute('UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision')
            self.sync(now + 1000 + step * 100)

    def test_mixed_open_closed_withdrawn_and_deleted_sources_progress_parity(self):
        rng = random.Random(20261025)
        self.add('initial', 0, None)
        self.sync(1000)
        identifiers = ['initial']
        now = 1000
        for step in range(160):
            now += 1100
            action = rng.randrange(7)
            identifier = rng.choice(identifiers)
            if action == 0:
                identifier = 'new-' + str(step)
                start = rng.randrange(max(1, now - 30000), now)
                end = None if rng.randrange(3) == 0 else start + rng.randrange(1, 20000)
                self.add(identifier, start, end, label=rng.choice(('person', 'vehicle', 'animal')))
                identifiers.append(identifier)
            elif action <= 2:
                self.execute('UPDATE intervals SET last_seen=? WHERE id=?', (START + now, identifier))
            elif action == 3:
                self.execute('UPDATE intervals SET end=?,last_seen=?,revision=revision+1 WHERE id=?',
                             (START + now, START + now, identifier))
            elif action == 4:
                self.execute('UPDATE intervals SET class=? WHERE id=?',
                             (rng.choice(('person', 'vehicle', 'animal', 'speak')), identifier))
            elif action == 5:
                self.execute('DELETE FROM intervals WHERE id=?', (identifier,))
            else:
                self.execute('UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision')
            with self.subTest(step=step, action=action, identifier=identifier):
                self.sync(now)
            # Exercise pure progress immediately after every kind of repair,
            # including histories whose sticky class no longer has a source.
            self.execute('UPDATE intervals SET last_seen=last_seen+1 WHERE id=?', (rng.choice(identifiers),))
            self.sync(now + 1)

    def test_sticky_marker_can_settle_after_new_continuous_coverage(self):
        # Seed 17 restores continuous source coverage across an already sticky
        # publication partition. The legacy algorithm removes its transient
        # sticky marker on the following progress pass: it is not a fixed point.
        factory = random.Random
        with patch.object(random, 'Random', side_effect=lambda ignored: factory(17)):
            self.test_mixed_open_closed_withdrawn_and_deleted_sources_progress_parity()

    def test_withdrawn_open_class_settles_while_other_class_progresses(self):
        factory = random.Random
        with patch.object(random, 'Random', side_effect=lambda ignored: factory(25)):
            self.test_mixed_open_closed_withdrawn_and_deleted_sources_progress_parity()

    def test_deleted_source_retained_link_can_reenter_metadata_on_next_pass(self):
        factory = random.Random
        with patch.object(random, 'Random', side_effect=lambda ignored: factory(28)):
            self.test_mixed_open_closed_withdrawn_and_deleted_sources_progress_parity()


if __name__ == '__main__':
    unittest.main()
