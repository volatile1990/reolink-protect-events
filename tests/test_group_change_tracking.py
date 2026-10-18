"""Durable grouping invalidation across idle commits, DDL and rollback."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.runtime import Journal
from reolink_protect_events.visual_groups import VisualGroups


NOW = 1792168300000
CAMERA = "1" * 24


class GroupChangeTrackingTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="group-change-tracking-")
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "journal.sqlite3"
        self.j = Journal(self.path)
        self.addCleanup(self.j.close)
        with patch("reolink_protect_events.visual_groups.time.time", return_value=NOW / 1000):
            self.g = self.j.visual_groups = VisualGroups(self.j, [CAMERA], {"enabled": True})
        self.add("first", "vehicle")
        self.g.sync(NOW + 20000)

    def add(self, name, label="person", db=None):
        db = db or self.j.db
        db.execute("INSERT INTO intervals(id,camera,class,start,end,last_seen,provenance) VALUES(?,?,?,?,?,?,?)",
                   (name, CAMERA, label, NOW + 1, NOW + 10000, NOW + 10000,
                    json.dumps({"identityStart": NOW + 1, "sourceTypes": ["reolink"]})))
        db.commit()

    def rows(self):
        return self.j.db.execute("SELECT id,classes,provenance,revision FROM visual_groups ORDER BY id").fetchall()

    def test_same_connection_cursor_counter_media_commits_skip_historical_scan(self):
        expected = self.rows()
        with patch.object(self.g, "_sync", wraps=self.g._sync) as sync:
            for n in range(20):
                with self.j.db:
                    self.j.count("sourceEvents")
                    self.j.db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?,?,?)", (CAMERA, "a" * 32, n, 1))
                    self.j.db.execute("UPDATE media SET last_attempt=?", (n,))
                self.g.sync(NOW + 20001 + n)
            self.assertEqual(sync.call_count, 0)
        self.assertEqual(self.rows(), expected)

    def test_foreign_cursor_counter_media_commits_skip_historical_scan(self):
        other = sqlite3.connect(self.path)
        self.addCleanup(other.close)
        with patch.object(self.g, "_sync", wraps=self.g._sync) as sync:
            for n in range(10):
                with other:
                    other.execute("INSERT OR REPLACE INTO counters VALUES('noise',?)", (n,))
                    other.execute("INSERT OR REPLACE INTO cursors VALUES(?,?,?,?)", (CAMERA, "b" * 32, n, 1))
                    other.execute("UPDATE media SET done=done")
                self.g.sync(NOW + 20001 + n)
            self.assertEqual(sync.call_count, 0)

    def test_foreign_input_commit_is_enrolled_on_next_same_time_pass(self):
        other = sqlite3.connect(self.path)
        self.addCleanup(other.close)
        self.add("person", db=other)
        self.g.sync(NOW + 20000)
        self.assertEqual(json.loads(self.rows()[0][1]), ["person", "vehicle"])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_members").fetchone()[0], 2)

    def test_delivery_only_ack_does_not_recompute_group_shape(self):
        with self.j.db:
            self.j.db.execute("UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision")
        with patch.object(self.g, "_sync", wraps=self.g._sync) as sync:
            self.g.sync(NOW + 20001)
            self.assertEqual(sync.call_count, 0)

    def test_input_provenance_only_mutation_recomputes_same_time_projection(self):
        with self.j.db:
            raw = json.loads(self.j.db.execute("SELECT provenance FROM intervals WHERE id='first'").fetchone()[0])
            raw["sourceTypes"] = ["frigate", "reolink"]
            self.j.db.execute("UPDATE intervals SET provenance=? WHERE id='first'", (json.dumps(raw),))
        self.g.sync(NOW + 20000)
        self.assertEqual(json.loads(self.rows()[0][2])["sourceTypes"], ["frigate", "reolink"])

    def test_transaction_rollback_rebuilds_rolled_back_outputs_without_caller_invalidate(self):
        with self.j.db:
            self.j.db.execute("DELETE FROM visual_groups")
        self.j.db.execute("BEGIN IMMEDIATE")
        self.g.sync(NOW + 20000)
        self.assertEqual(len(self.rows()), 1)
        self.j.db.rollback()
        self.assertEqual(self.rows(), [])
        self.g.sync(NOW + 20000)
        self.assertEqual(len(self.rows()), 1)

    def test_savepoint_rollback_and_repeated_writes_cannot_reuse_cached_generation(self):
        self.j.db.execute("BEGIN IMMEDIATE")
        self.j.db.execute("SAVEPOINT candidate")
        self.j.db.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='first'")
        self.g.sync(NOW + 20000)
        discarded = self.g._input_token
        self.j.db.execute("ROLLBACK TO candidate")
        self.j.db.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertNotEqual(self.g._input_token, discarded)
        self.j.db.execute("RELEASE candidate")
        self.j.db.commit()
        cached = self.rows()
        self.g.sync(NOW + 20000)
        self.assertEqual(self.rows(), cached)

    def test_dropped_replaced_trigger_is_repaired_before_following_input_change(self):
        name = "visual_group_change_intervals_update"
        with self.j.db:
            self.j.db.execute("DROP TRIGGER " + name)
            self.j.db.execute("CREATE TRIGGER " + name + " AFTER UPDATE ON intervals BEGIN SELECT 1; END")
            self.j.db.execute("UPDATE intervals SET class='animal' WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertIn("animal", json.loads(self.rows()[0][1]))
        actual = self.j.db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
        self.assertIn("randomblob(16)", actual)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET class='person' WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertIn("person", json.loads(self.rows()[0][1]))

    def test_rolled_back_schema_cookie_reuse_still_detects_missing_trigger(self):
        name = "visual_group_change_intervals_update"
        self.j.db.execute("BEGIN IMMEDIATE")
        self.j.db.execute("DROP TRIGGER " + name)
        self.g.sync(NOW + 20000)  # Reinstalls (+2 cookie), cached inside transaction.
        cached_cookie = self.g._tracking_signature[0]
        self.j.db.rollback()
        with self.j.db:
            self.j.db.execute("DROP TRIGGER " + name)
            self.j.db.execute("CREATE TABLE unrelated_fixture(value INTEGER)")
        self.assertEqual(self.j.db.execute("PRAGMA schema_version").fetchone()[0], cached_cookie)
        self.g.sync(NOW + 20000)
        self.assertIsNotNone(self.j.db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone())
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET class='animal' WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertIn("animal", json.loads(self.rows()[0][1]))

    def test_tracking_row_or_table_removal_is_recovered_without_stale_cache(self):
        for sql in ("DELETE FROM visual_group_changes", "DROP TABLE visual_group_changes"):
            with self.subTest(sql=sql):
                with self.j.db:
                    self.j.db.execute(sql)
                self.g.sync(NOW + 20000)
                self.assertEqual(len(self.g._input_token), 16)
                self.assertEqual(len(self.rows()), 1)

    def test_optional_fusion_table_appearing_after_cache_receives_all_three_triggers(self):
        with self.j.db:
            self.j.db.execute("CREATE TABLE fusion_inputs(camera TEXT,class TEXT,start INTEGER,end INTEGER)")
        self.g.sync(NOW + 20000)
        names = {r[0] for r in self.j.db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'visual_group_change_fusion_inputs_%'")}
        self.assertEqual(len(names), 3)
        token = self.g._input_token
        with self.j.db:
            self.j.db.execute("INSERT INTO fusion_inputs VALUES(?,?,?,?)", (CAMERA, "vehicle", NOW, NOW + 5000))
        self.assertNotEqual(token, self.g._change_token())

    def test_due_time_still_runs_without_database_mutation(self):
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=NULL WHERE id='first'")
        self.g.sync(NOW + 1000)
        self.assertIsNone(self.j.db.execute("SELECT end FROM visual_groups").fetchone()[0])
        self.g.sync(NOW + 121000)
        self.assertEqual(self.j.db.execute("SELECT end FROM visual_groups").fetchone()[0], NOW + 120001)

    def test_one_camera_update_never_rebuilds_an_unrelated_camera_history(self):
        other_camera = "2" * 24
        self.g.cameras.add(other_camera)
        self.add("second", "person")
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET camera=? WHERE id='second'", (other_camera,))
        self.g.sync(NOW + 20000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET last_seen=last_seen+1,revision=revision+1 WHERE id='first'")
        with patch.object(self.g, "_ranges", wraps=self.g._ranges) as ranges:
            self.g.sync(NOW + 20000)
        self.assertGreater(ranges.call_count, 0)
        self.assertEqual({call.args[0][1] for call in ranges.call_args_list}, {CAMERA})

    def test_noop_interval_and_nonmember_audio_updates_skip_grouping(self):
        self.add("audio", "sound")
        self.g.sync(NOW + 20000)
        with patch.object(self.g, "_sync", wraps=self.g._sync) as sync:
            with self.j.db:
                self.j.db.execute("UPDATE intervals SET last_seen=last_seen WHERE id='first'")
                self.j.db.execute("UPDATE intervals SET last_seen=last_seen+100,revision=revision+1 WHERE id='audio'")
            self.g.sync(NOW + 20000)
            self.assertEqual(sync.call_count, 0)

    def test_member_reclassified_as_audio_still_invalidates_its_camera(self):
        token = self.g._camera_tokens[CAMERA]
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET class='sound' WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertNotEqual(token, self.g._camera_tokens[CAMERA])

    def test_interval_move_invalidates_both_old_and_new_camera(self):
        other_camera = "2" * 24
        before = dict(self.g._camera_tokens)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET camera=? WHERE id='first'", (other_camera,))
        actual = dict(self.j.db.execute("SELECT camera,token FROM visual_group_camera_changes"))
        self.assertNotEqual(actual[CAMERA], before[CAMERA])
        self.assertIn(other_camera, actual)

    def test_orphan_manual_marker_resolves_camera_through_member_segments(self):
        with self.j.db:
            self.j.db.execute("INSERT INTO visual_group_segments VALUES('orphan','first')")
        self.g.sync(NOW + 20000)
        before = dict(self.g._camera_tokens)
        with self.j.db:
            self.j.db.execute("INSERT INTO visual_group_manual VALUES('orphan','operation','[]','fixture')")
        actual = dict(self.j.db.execute("SELECT camera,token FROM visual_group_camera_changes"))
        self.assertNotEqual(actual[CAMERA], before[CAMERA])
        self.assertEqual(actual.get('*'), before.get('*'))

    def test_unresolvable_manual_reference_uses_full_recompute_fallback(self):
        with self.j.db:
            self.j.db.execute("INSERT INTO visual_group_manual VALUES('unknown','operation','[]','fixture')")
        with patch.object(self.g, "_sync", wraps=self.g._sync) as sync:
            self.g.sync(NOW + 20000)
        self.assertTrue(sync.call_args.kwargs['force'])

    def test_camera_tracking_table_drop_repairs_before_next_projection(self):
        with self.j.db:
            self.j.db.execute("DROP TABLE visual_group_camera_changes")
        self.g.sync(NOW + 20000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET last_seen=last_seen+1 WHERE id='first'")
        self.g.sync(NOW + 20000)
        self.assertIn(CAMERA, self.g._camera_tokens)

    def test_source_upsert_and_replace_conflict_policies_preserve_tracking(self):
        for statement in (
            "INSERT INTO intervals(id,camera,class,start,end,last_seen,provenance) VALUES('first',?,'vehicle',?,?,?,'{}') ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
            "INSERT OR REPLACE INTO intervals(id,camera,class,start,end,last_seen,provenance) VALUES('first',?,'vehicle',?,?,?,'{}')",
        ):
            with self.subTest(statement=statement):
                previous = self.g._camera_tokens[CAMERA]
                with self.j.db:
                    self.j.db.execute(statement, (CAMERA, NOW + 1, NOW + 10000, NOW + 10001))
                self.g.sync(NOW + 20000)
                self.assertNotEqual(previous, self.g._camera_tokens[CAMERA])
        previous = self.g._camera_tokens[CAMERA]
        with self.j.db:
            self.j.db.execute("INSERT OR IGNORE INTO intervals(id,camera,class) VALUES('first',?,'person')", (CAMERA,))
        self.g.sync(NOW + 20000)
        self.assertEqual(previous, self.g._camera_tokens[CAMERA])

    def test_exact_trigger_restore_after_ddl_rollback_cannot_hide_source_change(self):
        name = 'visual_group_change_intervals_update'
        original = self.j.db.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()[0]
        self.j.db.execute('BEGIN IMMEDIATE')
        self.j.db.execute('DROP TRIGGER ' + name)
        self.g.sync(NOW + 20000)
        cached = self.g._tracking_signature
        repaired_marker = self.g._camera_tokens['*']
        self.j.db.rollback()
        with self.j.db:
            self.j.db.execute('DROP TRIGGER ' + name)
            self.j.db.execute("UPDATE intervals SET class='animal' WHERE id='first'")
            self.j.db.execute(original)
        self.assertEqual(cached, self.g._schema_signature())
        self.g.sync(NOW + 20000)
        self.assertIn('animal', json.loads(self.rows()[0][1]))
        self.assertNotEqual(repaired_marker, self.g._camera_tokens['*'])

    def test_foreign_exact_trigger_restore_after_ddl_rollback_cannot_hide_change(self):
        name = 'visual_group_change_intervals_update'
        original = self.j.db.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()[0]
        self.j.db.execute('BEGIN IMMEDIATE')
        self.j.db.execute('DROP TRIGGER ' + name)
        self.g.sync(NOW + 20000)
        cached = self.g._tracking_signature
        self.j.db.rollback()
        other = sqlite3.connect(self.path)
        self.addCleanup(other.close)
        with other:
            other.execute('DROP TRIGGER ' + name)
            other.execute("UPDATE intervals SET class='animal' WHERE id='first'")
            other.execute(original)
        self.assertEqual(cached, self.g._schema_signature())
        self.g.sync(NOW + 20000)
        self.assertIn('animal', json.loads(self.rows()[0][1]))

    def test_committed_schema_repair_keeps_unrelated_commit_fast_path(self):
        with self.j.db:
            self.j.db.execute('DROP TRIGGER visual_group_change_intervals_update')
        self.j.pending()
        self.assertIn('*', self.g._camera_tokens)
        with patch.object(self.g, '_sync', wraps=self.g._sync) as sync:
            with self.j.db:
                self.j.count('unrelated_after_confirmed_commit')
            self.j.pending()
        self.assertEqual(sync.call_count, 0)

    def test_schema_rollback_with_other_camera_tracked_write_still_repairs_first_camera(self):
        other_camera = '2' * 24
        self.g.cameras.add(other_camera)
        self.add('second')
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET camera=? WHERE id='second'", (other_camera,))
        self.g.sync(NOW + 20000)
        name = 'visual_group_change_intervals_update'
        original = self.j.db.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()[0]
        self.j.db.execute('BEGIN IMMEDIATE')
        self.j.db.execute('DROP TRIGGER ' + name)
        self.g.sync(NOW + 20000)
        cached = self.g._tracking_signature
        self.j.db.rollback()
        with self.j.db:
            self.j.db.execute('DROP TRIGGER ' + name)
            self.j.db.execute("UPDATE intervals SET class='animal' WHERE id='first'")
            self.j.db.execute(original)
            self.j.db.execute("UPDATE intervals SET last_seen=last_seen+1,revision=revision+1 WHERE id='second'")
        self.assertEqual(cached, self.g._schema_signature())
        self.g.sync(NOW + 20000)
        self.assertIn('animal', json.loads(self.j.db.execute('SELECT classes FROM visual_groups WHERE camera=?', (CAMERA,)).fetchone()[0]))


if __name__ == "__main__":
    unittest.main()
