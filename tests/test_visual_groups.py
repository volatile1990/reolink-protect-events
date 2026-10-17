"""Real SQLite contracts for additive, bounded visual publication groups."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.runtime import Journal
from reolink_protect_events.visual_groups import VisualGroups


START = 1792168300000
CAMERA = "111111111111111111111111"
OTHER = "222222222222222222222222"


class VisualGroupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "journal.sqlite3"
        self.j = Journal(self.path)
        self.addCleanup(lambda: self.j.close())
        self.groups = self.open_groups()

    def open_groups(self, enabled=True, span=120, cameras=(CAMERA,)):
        with patch("reolink_protect_events.visual_groups.time.time", return_value=START / 1000):
            return VisualGroups(self.j, cameras, {"enabled": enabled, "maxSpanSeconds": span})

    def add(self, identifier, label="person", start=0, end=10000, camera=CAMERA, delivered=0, notified=0, meta=None):
        provenance = {"identityStart": START + start, "sourceUnionVersion": 1,
                      "sourceTypes": ["frigate"], "source": "frigate-object-detection"}
        provenance.update(meta or {})
        with self.j.db:
            self.j.db.execute("INSERT INTO intervals(id,camera,class,start,end,last_seen,instance,epoch,provenance,delivered_revision,notified_revision) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                              (identifier, camera, label, START + start, None if end is None else START + end,
                               START + (end if end is not None else start), "fixture", 0, json.dumps(provenance), delivered, notified))
            self.j.db.execute("INSERT INTO media(event_id) VALUES(?)", (identifier,))

    def sync(self, offset=30000):
        self.groups.sync(START + offset)
        return self.rows()

    def rows(self):
        rows = self.j.db.execute("SELECT id,start,end,classes,provenance,revision,delivered_revision,notified_revision "
                                 "FROM visual_groups ORDER BY start,id").fetchall()
        return [{"id": r[0], "start": r[1], "end": r[2], "classes": json.loads(r[3]),
                 "provenance": json.loads(r[4]), "revision": r[5], "delivered": r[6], "notified": r[7]} for r in rows]

    def publication(self):
        return self.j.db.execute("SELECT id,class,classes FROM publication_intervals ORDER BY start,id").fetchall()

    def manual_snapshot(self):
        """Simulate the exact, separately authorized historical-operation write."""
        self.add("old-vehicle", "vehicle", -120000, -50000, delivered=1, notified=1)
        self.add("old-person", "person", -116000, -60000, delivered=1, notified=1,
                 meta={"sourceTypes": ["frigate", "reolink"]})
        members = ["old-person", "old-vehicle"]
        meta = {"sourceUnionVersion": 1, "visualGroupVersion": 1,
                "identityStart": START - 120000, "groupIdentityStart": START - 120000,
                "activationMs": START - 120000, "groupMaxSpanMs": 120000,
                "sourceTypes": ["frigate", "reolink"], "classIntervalsComplete": True,
                "classIntervals": {"person": [{"start": START - 116000, "end": START - 60000}],
                                   "vehicle": [{"start": START - 120000, "end": START - 50000}]},
                "manualHistoricalMerge": {"operationId": "fixture-explicit-two-event-merge",
                                          "memberIntervalIds": members},
                "thumbnailSelection": {"selectedAtMs": START - 119000, "policy": "fixture"}}
        encoded = json.dumps(meta, indent=1)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.j.db:
            self.j.db.execute("INSERT INTO visual_groups(id,camera,start,end,last_seen,provenance,classes,revision,delivered_revision,notified_revision) "
                              "VALUES(?,?,?,?,?,?,?,2,1,1)", ("old-vehicle", CAMERA, START - 120000, START - 50000,
                                                           START - 49000, encoded, '["person","vehicle"]'))
            self.j.db.executemany("INSERT INTO visual_group_members(interval_id) VALUES(?)", [(member,) for member in members])
            self.j.db.executemany("INSERT INTO visual_group_segments VALUES(?,?)", [("old-vehicle", member) for member in members])
            self.j.db.execute("INSERT INTO visual_group_manual VALUES(?,?,?,?)",
                              ("old-vehicle", "fixture-explicit-two-event-merge", json.dumps(members), digest))
        return "old-vehicle"

    def test_parcel_person_car_one_group_with_exact_class_times_and_originals(self):
        self.add("car", "vehicle", 14445, 81785)
        self.add("courier", "person", 18586, 71380)
        original = self.j.db.execute("SELECT * FROM intervals ORDER BY id").fetchall()
        group, = self.sync(100000)
        self.assertEqual((group["start"], group["end"]), (START + 14445, START + 81785))
        self.assertEqual(group["classes"], ["person", "vehicle"])
        self.assertEqual(group["provenance"]["classIntervals"], {
            "person": [{"start": START + 18586, "end": START + 71380}],
            "vehicle": [{"start": START + 14445, "end": START + 81785}]})
        self.assertEqual(self.j.db.execute("SELECT * FROM intervals ORDER BY id").fetchall(), original)
        self.assertEqual(self.publication(), [(group["id"], "visual", '["person","vehicle"]')])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM media").fetchone()[0], 3)
        self.assertTrue(group["provenance"]["classIntervalsComplete"])
        self.assertFalse(group["provenance"]["objectIdentityMatched"])

    def test_cameras_audio_and_touching_or_nearby_times_do_not_join(self):
        self.add("person", start=0, end=1000)
        self.add("car", "vehicle", start=1000, end=2000)
        self.add("animal", "animal", start=2001, end=3000)
        self.add("audio", "speak", start=0, end=3000)
        self.add("other", "person", start=0, end=3000, camera=OTHER)
        values = self.sync()
        self.assertEqual(len(values), 3)
        self.assertEqual([value["classes"] for value in values], [["person"], ["vehicle"], ["animal"]])
        legacy = {r[0] for r in self.publication() if r[2] is None}
        self.assertEqual(legacy, {"audio", "other"})
        self.groups = self.open_groups(cameras=(CAMERA, OTHER))
        self.assertEqual(len(self.sync()), 4)

    def test_live_publication_type_expansion_clear_and_restart_preserve_identity(self):
        self.add("car", "vehicle", 0, None)
        first, = self.sync(1000)
        self.assertIsNone(first["end"])
        with self.j.db:
            self.j.db.execute("UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision WHERE id=?", (first["id"],))
            self.j.db.execute("INSERT INTO delivery_failures VALUES(?,2,?)", (first["id"], START + 5000))
            selection = {"selectedAtMs": START + 500, "policy": "fixture"}
            meta = first["provenance"]
            meta["thumbnailSelection"] = selection
            self.j.db.execute("UPDATE visual_groups SET provenance=? WHERE id=?", (json.dumps(meta), first["id"]))
        self.add("person", "person", 500, 4000)
        second, = self.sync(5000)
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["classes"], ["person", "vehicle"])
        self.assertEqual(second["delivered"], 1)
        self.assertEqual(second["notified"], 1)
        self.assertEqual(second["revision"], 2)
        self.assertEqual(second["provenance"]["thumbnailSelection"], selection)
        self.assertEqual(self.j.db.execute("SELECT attempts FROM delivery_failures WHERE event_id=?", (first["id"],)).fetchone()[0], 2)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='car'", (START + 6000, START + 6000))
        third, = self.sync(10000)
        self.assertEqual(third["end"], START + 6000)
        self.assertEqual(third["provenance"]["classIntervals"]["vehicle"], [{"start": START, "end": START + 6000}])
        self.j.close()
        self.j = Journal(self.path)
        self.groups = self.open_groups()
        restarted, = self.sync(15000)
        self.assertEqual(restarted, third)
        self.assertEqual(self.groups.activation_ms, START)

    def test_open_long_car_defers_unconfirmed_continuation_and_later_person_stays_truthful(self):
        self.add("parked", "vehicle", 0, None)
        self.add("courier", "person", 130000, 140000)
        values = self.sync(250000)
        self.assertEqual([(r["start"] - START, None if r["end"] is None else r["end"] - START)
                          for r in values], [(0, 120000), (130000, 140000)])
        self.assertEqual([r["classes"] for r in values], [["vehicle"], ["person"]])
        for row in values[:1]:
            self.assertEqual(row["provenance"]["administrativePartitionReason"], "max_span")
            self.assertEqual(row["provenance"]["closureReason"], "administrative_partition")
        self.assertIsNone(self.j.db.execute("SELECT end FROM intervals WHERE id='parked'").fetchone()[0])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_members").fetchone()[0], 2)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_segments WHERE interval_id='parked'").fetchone()[0], 1)
        before = [(r["id"], r["revision"]) for r in values]
        self.assertEqual([(r["id"], r["revision"]) for r in self.sync(250001)], before)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='parked'", (START + 180000, START + 180000))
        confirmed = self.sync(260000)
        person = next(row for row in confirmed if row["id"] == values[1]["id"])
        self.assertEqual(person["classes"], ["person", "vehicle"])
        self.assertEqual(person["provenance"]["classIntervals"]["vehicle"], [{"start": START + 130000, "end": START + 180000}])

    def test_late_bridge_keeps_both_published_ids_and_exact_adjacent_partitions(self):
        self.add("early", "person", 0, 10000)
        self.add("late", "vehicle", 20000, 30000)
        original = self.sync(40000)
        with self.j.db:
            self.j.db.execute("UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision")
        self.add("connector", "animal", 5000, 25000)
        values = self.sync(50000)
        self.assertEqual([row["id"] for row in values], [row["id"] for row in original])
        self.assertEqual([(r["start"] - START, r["end"] - START) for r in values], [(0, 20000), (20000, 30000)])
        self.assertEqual(values[0]["classes"], ["animal", "person"])
        self.assertEqual(values[1]["classes"], ["animal", "vehicle"])
        self.assertEqual(values[0]["provenance"]["classIntervals"]["animal"], [{"start": START + 5000, "end": START + 20000}])
        self.assertEqual(values[1]["provenance"]["classIntervals"]["animal"], [{"start": START + 20000, "end": START + 25000}])
        self.assertTrue(all(r["revision"] == 2 for r in values))
        self.assertEqual(self.sync(60000), values)

    def test_activation_never_rewrites_older_published_or_partial_history(self):
        self.add("old", start=-2000, end=5000)
        self.add("published", "vehicle", start=0, end=10000, delivered=1, notified=1)
        self.add("partial", "animal", start=0, end=10000, delivered=1)
        self.add("old-identity", start=1000, end=2000, meta={"identityStart": START - 5000})
        self.add("fresh", "person", start=1000, end=5000)
        values = self.sync()
        self.assertEqual(len(values), 1)
        self.assertEqual({r[0] for r in self.publication() if r[2] is None}, {"old", "published", "partial", "old-identity"})
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM intervals").fetchone()[0], 5)

    def test_disabled_finishes_enrolled_members_but_never_enrolls_new_sources(self):
        self.add("active", "person", 0, None)
        first, = self.sync(1000)
        self.groups = self.open_groups(enabled=False)
        self.add("new", "vehicle", 500, 5000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='active'", (START + 6000, START + 6000))
        second, = self.sync(10000)
        self.assertEqual((second["id"], second["end"]), (first["id"], START + 6000))
        self.assertEqual(second["classes"], ["person"])
        self.assertIn(("new", "vehicle", None), self.publication())
        self.groups = self.open_groups()
        self.assertEqual(self.groups.activation_ms, START)
        expanded, = self.sync(12000)
        self.assertEqual((expanded["id"], expanded["classes"]), (first["id"], ["person", "vehicle"]))

    def test_full_fusion_coverage_not_diagnostic_limit_or_finalize_hold(self):
        self.add("union", "person", 0, None, meta={"sourceIntervals": [{"start": START, "end": START + 1000}]})
        with self.j.db:
            self.j.db.execute("CREATE TABLE fusion_inputs(camera TEXT,class TEXT,start INTEGER,end INTEGER)")
            self.j.db.executemany("INSERT INTO fusion_inputs VALUES(?,?,?,?)", [(CAMERA, "person", START + offset, START + offset + 1000)
                                                                             for offset in range(0, 20000, 1000)])
        group, = self.sync(25000)
        self.assertEqual(group["end"], START + 20000)
        self.assertEqual(group["provenance"]["classIntervals"]["person"], [{"start": START, "end": START + 20000}])

    def test_finalize_hold_cannot_adopt_disjoint_raw_input_before_its_fusion_output(self):
        self.add("reolink-union", "person", 0, None,
                 meta={"sourceTypes": ["reolink"], "source": "reolink-camera-ai"})
        with self.j.db:
            self.j.db.execute("CREATE TABLE fusion_inputs(camera TEXT,class TEXT,start INTEGER,end INTEGER)")
            self.j.db.executemany("INSERT INTO fusion_inputs VALUES(?,?,?,?)", [
                (CAMERA, "person", START, START + 1000),
                (CAMERA, "person", START + 2000, START + 3000)])
        first, = self.sync(5000)
        self.assertEqual((first["start"], first["end"]), (START, START + 1000))
        self.assertEqual(first["provenance"]["sourceTypes"], ["reolink"])
        self.add("frigate-union", "person", 2000, 3000)
        values = self.sync(6000)
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0], first)
        self.assertEqual((values[1]["start"], values[1]["end"]), (START + 2000, START + 3000))
        self.assertEqual(values[1]["provenance"]["sourceTypes"], ["frigate"])

    def test_published_closed_class_evidence_is_not_retracted(self):
        self.add("person", "person", 0, 10000)
        self.add("car", "vehicle", 5000, 20000)
        before, = self.sync()
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET start=? WHERE id='person'", (START + 9000,))
        after, = self.sync(40000)
        self.assertEqual(after["classes"], before["classes"])
        self.assertEqual(after["provenance"]["classIntervals"], before["provenance"]["classIntervals"])

    def test_prune_requires_whole_completed_membership_component_and_media(self):
        self.add("car", "vehicle", 0, 250000)
        rows = self.sync(300000)
        with self.j.db:
            self.j.db.execute("UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision")
            self.j.db.execute("UPDATE media SET done=1 WHERE event_id IN (SELECT id FROM visual_groups)")
        rows = self.rows()
        self.groups.prune(START + 200000)
        self.assertEqual(self.rows(), rows)
        self.groups.prune(START + 400000)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM intervals").fetchone()[0], 0)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_members").fetchone()[0], 0)
        self.assertEqual(self.sync(500000), [])

    def test_prune_terminal_thumbnail_failure_but_retains_retryable_media(self):
        self.add("source", "person", 0, 1000)
        group, = self.sync(5000)
        with self.j.db:
            self.j.db.execute("UPDATE visual_groups SET delivered_revision=revision,notified_revision=revision")
            self.j.db.execute("UPDATE media SET done=0,attempts=19 WHERE event_id=?", (group["id"],))
        self.groups.prune(START + 10000)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_members").fetchone()[0], 1)
        with self.j.db:
            self.j.db.execute("UPDATE media SET attempts=20 WHERE event_id=?", (group["id"],))
        self.groups.prune(START + 10000)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM intervals").fetchone()[0], 0)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM media").fetchone()[0], 0)

    def test_late_earlier_history_reuses_single_identity_and_bounded_true_start(self):
        self.add("first", "person", 5000, 15000)
        before, = self.sync()
        self.add("earlier", "vehicle", 1000, 10000)
        after, = self.sync(40000)
        self.assertEqual(after["id"], before["id"])
        self.assertEqual(after["start"], START + 1000)
        self.assertEqual(after["provenance"]["identityStart"], START + 5000)
        self.assertEqual(self.sync(50000), [after])

    def test_source_clears_then_later_activity_cannot_reopen_past_group(self):
        self.add("active", "person", 0, None)
        old, = self.sync(5000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='active'", (START + 10000, START + 10000))
        ended, = self.sync(15000)
        self.assertEqual(ended["end"], START + 10000)
        self.add("later", "vehicle", 200000, 210000)
        values = self.sync(1000000)
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0]["id"], old["id"])
        self.assertEqual(values[0]["end"], START + 10000)

    def test_person_arriving_exactly_now_expands_still_active_vehicle(self):
        self.add("car", "vehicle", 0, None)
        old, = self.sync(1000)
        self.add("person", "person", 4000, None)
        expanded, = self.sync(4000)
        self.assertEqual(expanded["id"], old["id"])
        self.assertEqual(expanded["classes"], ["person", "vehicle"])

    def test_withdrawn_open_class_retains_finite_published_evidence(self):
        self.add("changing", "person", 0, None)
        old, = self.sync(5000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET class='vehicle' WHERE id='changing'")
        expanded, = self.sync(10000)
        self.assertEqual(expanded["id"], old["id"])
        self.assertEqual(expanded["classes"], ["person", "vehicle"])
        self.assertEqual(expanded["provenance"]["classIntervals"]["person"], [{"start": START, "end": START + 5000}])
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='changing'", (START + 15000, START + 15000))
        closed, = self.sync(1000000)
        self.assertEqual(closed["end"], START + 15000)

    def test_delayed_genuine_clear_corrects_cap_without_phantom_continuation(self):
        self.add("long", "vehicle", 0, None)
        initial, = self.sync(1000)
        capped, = self.sync(126000)
        self.assertEqual(capped["id"], initial["id"])
        self.assertEqual(capped["end"], START + 120000)
        with self.j.db:
            self.j.db.execute("UPDATE intervals SET end=?,last_seen=? WHERE id='long'", (START + 117000, START + 117000))
        corrected, = self.sync(130000)
        self.assertEqual(corrected["id"], initial["id"])
        self.assertEqual(corrected["end"], START + 117000)
        self.assertEqual(corrected["provenance"]["classIntervals"]["vehicle"], [{"start": START, "end": START + 117000}])
        self.assertNotIn("administrativePartitionReason", corrected["provenance"])
        self.assertEqual(self.sync(1000000), [corrected])

    def test_cache_observes_other_connection_changes_and_skips_unchanged_work(self):
        self.add("first", "vehicle", 0, None)
        before, = self.sync(1000)
        with patch.object(self.groups, "_ranges", wraps=self.groups._ranges) as ranges:
            self.sync(2000)
            self.assertEqual(ranges.call_count, 0)
            other = Journal(self.path)
            try:
                with other.db:
                    other.db.execute("INSERT INTO intervals(id,camera,class,start,end,last_seen,instance,epoch,provenance) "
                                     "VALUES('other-source',?,'person',?,?,?,'fixture',0,?)",
                                     (CAMERA, START + 500, START + 5000, START + 5000,
                                      json.dumps({"identityStart": START + 500, "sourceTypes": ["reolink"]})))
                    other.db.execute("INSERT INTO media(event_id) VALUES('other-source')")
                expanded, = self.sync(6000)
                self.assertGreater(ranges.call_count, 0)
                self.assertEqual(expanded["id"], before["id"])
                self.assertEqual(expanded["classes"], ["person", "vehicle"])
                count = ranges.call_count
                with other.db:
                    other.db.execute("UPDATE visual_groups SET delivered_revision=revision")
                self.sync(7000)
                self.assertEqual(ranges.call_count, count)
            finally:
                other.close()

    def test_outer_outbox_claim_transaction_is_not_committed_and_rollback_invalidates(self):
        self.add("claimed", "person", 0, 10000)
        self.j.db.execute("BEGIN IMMEDIATE")
        self.groups.sync(START + 20000)
        self.assertTrue(self.j.db.in_transaction)
        self.assertEqual(len(self.rows()), 1)
        self.j.db.rollback()
        self.groups.invalidate()
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_members").fetchone()[0], 0)
        self.assertEqual(len(self.sync(30000)), 1)

    def test_activation_bootstrap_and_configuration_validation(self):
        self.assertEqual(self.groups.activation_ms, START)
        with patch("reolink_protect_events.visual_groups.time.time", return_value=(START + 500000) / 1000):
            self.assertEqual(VisualGroups(self.j, (CAMERA,), {"enabled": True}).activation_ms, START)
        for options in ({"enabled": 1}, {"enabled": True, "maxSpanSeconds": 29},
                        {"enabled": True, "maxSpanSeconds": 301}, {"enabled": True, "maxSpanSeconds": True}):
            with self.assertRaises(ValueError):
                VisualGroups(self.j, (CAMERA,), options)

    def test_explicit_manual_history_is_immutable_across_ack_restart_and_automatic_sync(self):
        identifier = self.manual_snapshot()
        original_sources = self.j.db.execute("SELECT * FROM intervals ORDER BY id").fetchall()
        original_media = self.j.db.execute("SELECT * FROM media ORDER BY event_id").fetchall()
        self.j.acknowledge(identifier, 2, "delivered")
        self.j.acknowledge(identifier, 2, "notified")
        snapshot = self.j.db.execute("SELECT * FROM visual_groups WHERE id=?", (identifier,)).fetchone()
        manual = self.j.db.execute("SELECT * FROM visual_group_manual WHERE group_id=?", (identifier,)).fetchone()
        self.sync()
        self.assertEqual(self.groups._camera_signatures, {})
        self.assertEqual(self.j.db.execute("SELECT * FROM visual_groups WHERE id=?", (identifier,)).fetchone(), snapshot)
        self.j.close()
        self.j = Journal(self.path)
        self.groups = self.open_groups(cameras=(CAMERA, OTHER))
        self.sync(40000)
        self.assertEqual(self.groups.activation_ms, START)
        self.assertEqual(self.j.db.execute("SELECT * FROM visual_groups WHERE id=?", (identifier,)).fetchone(), snapshot)
        self.assertEqual(self.j.db.execute("SELECT * FROM visual_group_manual WHERE group_id=?", (identifier,)).fetchone(), manual)
        self.assertEqual(self.j.db.execute("SELECT * FROM intervals ORDER BY id").fetchall(), original_sources)
        self.assertEqual(self.j.db.execute("SELECT * FROM media ORDER BY event_id").fetchall(), original_media)
        self.assertEqual(self.publication(), [(identifier, "visual", '["person","vehicle"]')])
        self.add("fresh-other-camera", "person", 1000, 5000, camera=OTHER)
        self.sync(50000)
        self.assertEqual(self.j.db.execute("SELECT * FROM visual_groups WHERE id=?", (identifier,)).fetchone(), snapshot)
        self.assertEqual(len(self.publication()), 2)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_groups WHERE camera=?", (OTHER,)).fetchone()[0], 1)

    def test_manual_snapshot_prunes_its_marker_only_after_safe_group_and_media_completion(self):
        identifier = self.manual_snapshot()
        self.groups.prune(START + 10000)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_manual").fetchone()[0], 1)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM intervals").fetchone()[0], 2)
        self.j.acknowledge(identifier, 2, "delivered")
        self.j.acknowledge(identifier, 2, "notified")
        self.groups.prune(START + 10000)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM visual_group_manual").fetchone()[0], 1)
        with self.j.db:
            self.j.db.execute("UPDATE media SET done=1 WHERE event_id=?", (identifier,))
        self.groups.prune(START + 10000)
        for table in ("visual_groups", "visual_group_manual", "visual_group_members", "visual_group_segments", "intervals", "media"):
            self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0], 0, table)


if __name__ == "__main__":
    unittest.main()
