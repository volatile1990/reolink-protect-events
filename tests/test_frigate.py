"""Real SQLite recovery and bounded HTTP polling contracts, no live events."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

from reolink_protect_events.frigate import event as normalize, poll, settings
from reolink_protect_events.runtime import Journal, Runtime, validate_config
from reolink_protect_events.native import native_id
from test_runtime import CAMERA as BRIDGE, START, event, response
from test_runtime_delivery import config, bridge
from test_native import adapter


CAMERA = BRIDGE["cameraId"]


def options():
    value = config()
    value["frigate"] = {"url": "http://192.0.2.1:18799", "bearerToken": "fixture-never-a-real-token-12345",
                        "cameraMap": {"front": CAMERA}}
    return settings(value)


def item(identifier="track-1", start=0, end=None, label="person", false_positive=False):
    return {"id": identifier, "camera": "front", "label": label, "data": {"type": "object"},
            "start_time": (START + start) / 1000,
            "end_time": None if end is None else (START + end) / 1000,
            "false_positive": false_positive, "top_score": 0.87}


def batch(items, at=30000, cursor=None):
    return {"events": [normalize(value, "front", START + at) for value in items],
            "atMs": START + at, "cursor": START + at if cursor is None else cursor,
            "missingIds": [], "initial": False, "requests": 2, "backlogMs": 0}


class FusionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "journal.sqlite3"
        self.j = Journal(self.path)
        self.addCleanup(self.j.close)
        self.j.enable_fusion([CAMERA], options())

    def sync(self, at=30000):
        self.j.fusion.sync(START + at)
        return self.j.pending()

    def test_two_sources_overlap_one_interval_clear_is_independent(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"]), event(2, 5000)]))
        self.j.fusion.frigate(CAMERA, batch([item(start=2000)]))
        values = self.sync()
        self.assertEqual(len(values), 1)
        self.assertIsNone(values[0]["end"])
        self.assertEqual(values[0]["provenance"]["sourceTypes"], ["frigate", "reolink"])
        self.j.fusion.frigate(CAMERA, batch([item(start=2000, end=10000)], at=40000))
        values = self.sync(40000)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["start"], START)
        self.assertEqual(values[0]["end"], START + 10000)

    def test_frigate_only_real_classes_no_motion_or_false_positive(self):
        self.j.ingest(BRIDGE, response([event(1, motion=True)]))
        self.j.fusion.frigate(CAMERA, batch([item(label="motion"), item("false", label="person", false_positive=True), item("car", label="car", end=8000)]))
        values = self.sync()
        self.assertEqual([value["classes"] for value in values], [["vehicle"]])
        self.assertEqual(values[0]["provenance"]["classificationOrigin"], "external-model")
        self.assertEqual(values[0]["provenance"]["source"], "frigate-object-detection")

    def test_distinct_classes_and_time_gaps_remain_distinct(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"]), event(2, 1000)]))
        self.j.fusion.frigate(CAMERA, batch([item("car", label="car", end=2000), item("later", start=3000, end=4000)]))
        values = self.sync()
        self.assertEqual(len(values), 3)
        self.assertEqual(sorted(value["classes"][0] for value in values), ["person", "person", "vehicle"])

    def test_epoch_boundary_closes_only_reolink(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"])]))
        self.j.fusion.frigate(CAMERA, batch([item(start=1000)]))
        self.sync()
        value = response([], newest=1)
        value["source"] = {"connected": False, "connectionEpoch": 1}
        self.j.ingest(BRIDGE, value)
        self.assertIsNone(self.sync()[0]["end"])
        self.assertEqual(self.j.cursor(CAMERA)["epoch"], 1)

    def test_crash_replay_does_not_duplicate_inputs_or_native_identity(self):
        source = response([event(1, classes=["person"]), event(2, 3000)])
        snapshot = batch([item(start=1000, end=4000)])
        self.j.ingest(BRIDGE, source)
        self.j.fusion.frigate(CAMERA, snapshot)
        first = self.sync()[0]
        self.j.acknowledge(first["eventId"], first["revision"], "delivered")
        self.j.acknowledge(first["eventId"], first["revision"], "notified")
        self.j.close()
        self.j = Journal(self.path)
        self.addCleanup(self.j.close)
        self.j.enable_fusion([CAMERA], options())
        self.assertEqual(self.j.fusion.poll_state(CAMERA)[0], snapshot["cursor"])
        self.j.ingest(BRIDGE, source)
        self.j.fusion.frigate(CAMERA, snapshot)
        self.sync()
        self.assertEqual(self.j.pending(), [])
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM intervals").fetchone()[0], 1)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM fusion_inputs").fetchone()[0], 2)

    def test_crash_before_frigate_commit_rolls_back_events_and_cursor_together(self):
        class Crash(BaseException):
            pass
        snapshot = batch([item(end=4000)])
        with patch.object(self.j, "count", side_effect=Crash()):
            with self.assertRaises(Crash):
                self.j.fusion.frigate(CAMERA, snapshot)
        self.assertEqual(self.j.fusion.poll_state(CAMERA)[0], None)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM fusion_inputs").fetchone()[0], 0)
        self.j.fusion.frigate(CAMERA, snapshot)
        self.assertEqual(len(self.sync()), 1)

    def test_activation_preserves_existing_open_legacy_id_and_other_camera(self):
        # Simulate enabling after the original collector has already delivered.
        self.j.fusion = None
        self.j.db.execute("DELETE FROM fusion_cameras")
        self.j.ingest(BRIDGE, response([event(1, classes=["person"])]))
        old = self.j.pending()[0]
        self.j.acknowledge(old["eventId"], 1, "delivered")
        self.j.acknowledge(old["eventId"], 1, "notified")
        self.j.enable_fusion([CAMERA], options())
        self.j.fusion.frigate(CAMERA, batch([item(start=1000)]))
        self.j.ingest(BRIDGE, response([event(2, 2000, classes=["person"]), event(3, 5000)]))
        values = self.sync()
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["eventId"], old["eventId"])
        self.assertEqual(values[0]["deliveredRevision"], 1)
        other = dict(BRIDGE, cameraId="2" * 24)
        self.j.ingest(other, response([event(1, classes=["animal"])]))
        self.assertEqual(self.j.db.execute("SELECT instance FROM intervals WHERE camera=?", (other["cameraId"],)).fetchone()[0], "a" * 32)

    def test_disable_legacy_capture_reenable_adopts_new_interval_without_loop(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"]), event(2, 1000)]))
        self.sync()
        self.j.fusion = None
        self.j.ingest(BRIDGE, response([event(3, 5000, classes=["person"])]))
        legacy = self.j.db.execute("SELECT id FROM intervals WHERE camera=? AND end IS NULL", (CAMERA,)).fetchone()[0]
        self.j.enable_fusion([CAMERA], options())
        self.j.ingest(BRIDGE, response([event(4, 7000)]))
        self.sync()
        self.assertEqual(self.j.db.execute("SELECT end FROM intervals WHERE id=?", (legacy,)).fetchone()[0], START + 7000)
        self.assertEqual(self.j.cursor(CAMERA)["seq"], 4)
        self.assertEqual(self.j.db.execute("SELECT COUNT(*) FROM fusion_inputs WHERE source_id LIKE 'legacy:%'").fetchone()[0], 0)

    def test_reenable_replays_disabled_clear_without_reopening_or_extending(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"])]))
        old = self.sync()[0]
        self.j.fusion = None
        self.j.ingest(BRIDGE, response([event(2, 3000)]))
        self.j.enable_fusion([CAMERA], options())
        self.j.fusion.frigate(CAMERA, batch([item("unrelated", start=20000, end=25000)]))
        self.sync(30000)
        old_end = self.j.db.execute("SELECT end FROM intervals WHERE id=?", (old["eventId"],)).fetchone()[0]
        self.assertEqual(old_end, START + 3000)
        self.assertEqual(self.j.db.execute("SELECT seq FROM fusion_bridge WHERE camera=?", (CAMERA,)).fetchone()[0], 2)
        self.assertEqual(self.j.db.execute("SELECT end FROM fusion_inputs WHERE source='reolink'").fetchone()[0], START + 3000)

    def test_reenable_reconciles_disconnect_without_new_push(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"])]))
        old = self.sync()[0]
        self.j.fusion = None
        source = response([], newest=1)
        source["source"] = {"connected": False, "connectionEpoch": 0}
        self.j.ingest(BRIDGE, source)
        old_end = self.j.db.execute("SELECT end FROM intervals WHERE id=?", (old["eventId"],)).fetchone()[0]
        self.j.enable_fusion([CAMERA], options())
        self.sync(180000)
        self.assertEqual(self.j.db.execute("SELECT end FROM fusion_inputs WHERE source='reolink'").fetchone()[0], old_end)

    def test_source_updates_keep_pinned_recorded_thumbnail(self):
        self.j.fusion.frigate(CAMERA, batch([item()]))
        value = self.sync()[0]
        pin = {"timestamp": START + 1000, "automaticSelected": True, "candidateCount": 4}
        self.j.media_selection(value["eventId"], pin)
        self.j.fusion.frigate(CAMERA, batch([item(end=10000)], at=40000))
        newer = self.sync(40000)[0]
        self.assertEqual(newer["provenance"]["thumbnailSelection"], pin)

    def test_configuration_disable_closes_only_external_source_with_new_binary(self):
        from reolink_protect_events.fusion import Fusion
        self.j.fusion.frigate(CAMERA, batch([item()]))
        old = self.sync()[0]
        with patch("reolink_protect_events.fusion.time.time", return_value=(START + 40000) / 1000):
            Fusion.deactivate_unmapped(self.j)
        newer = self.j.db.execute("SELECT end,provenance FROM intervals WHERE id=?", (old["eventId"],)).fetchone()
        self.assertEqual(newer[0], START + 40000)
        self.assertEqual(json.loads(newer[1])["sourceTypes"], ["frigate"])
        self.assertEqual(self.j.db.execute("SELECT enabled FROM fusion_cameras").fetchone()[0], 0)

    def test_expiry_is_per_source_and_missing_active_ids_are_bounded(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"])]))
        self.j.fusion.frigate(CAMERA, batch([item()], at=60000))
        self.sync(60000)
        self.j.expire(START + 125000)
        self.assertIsNone(self.sync(125000)[0]["end"])
        self.j.expire(START + 185000)
        value = self.sync(185000)[0]
        self.assertEqual(value["end"], START + 180000)
        self.assertTrue(value["provenance"]["endIsTimeoutEstimate"])
        self.assertEqual(self.j.fusion.poll_state(CAMERA)[1], [])

    def test_late_earlier_start_keeps_stable_graph_identity(self):
        self.j.ingest(BRIDGE, response([event(1, 5000, classes=["person"]), event(2, 10000)]))
        first = self.sync()[0]
        self.j.fusion.frigate(CAMERA, batch([item(start=0, end=15000)]))
        newer = self.sync()[0]
        self.assertEqual(first["eventId"], newer["eventId"])
        self.assertEqual(newer["start"], START)
        self.assertEqual(newer["end"], START + 15000)
        self.assertEqual(newer["provenance"]["identityStart"], START + 5000)
        first_sql, _ = adapter().build_interval_sql(first)
        newer_sql, native = adapter().build_interval_sql(newer)
        oid = native_id("object", START + 5000, first["eventId"] + ":person")
        self.assertIn(oid.encode().hex(), first_sql)
        self.assertIn(oid.encode().hex(), newer_sql)
        self.assertIn('start=EXCLUDED.start,"end"=EXCLUDED."end"', newer_sql)
        self.assertEqual(native["metadata"]["reolinkProtectEvents"]["classificationOrigin"], "mixed")

    def test_late_history_joining_two_delivered_ids_keeps_nonoverlap_partitions(self):
        self.j.ingest(BRIDGE, response([event(1, classes=["person"]), event(2, 1000), event(3, 3000, classes=["person"]), event(4, 4000)]))
        old = self.sync()
        self.assertEqual(len(old), 2)
        self.j.fusion.frigate(CAMERA, batch([item(start=500, end=3500)]))
        values = sorted(self.sync(), key=lambda value: value["start"])
        self.assertEqual({value["eventId"] for value in values}, {value["eventId"] for value in old})
        self.assertEqual(values[0]["end"], values[1]["start"])
        self.assertEqual(values[1]["end"], START + 4000)

    def test_transitive_late_overlap_preserves_full_old_component_start(self):
        self.j.ingest(BRIDGE, response([event(1, 100, classes=["person"]), event(2, 200)]))
        self.j.fusion.frigate(CAMERA, batch([item("a", start=180, end=300)]))
        first = self.sync()[0]
        self.j.fusion.frigate(CAMERA, batch([item("b", start=290, end=400)]))
        newer = self.sync()[0]
        self.assertEqual(newer["eventId"], first["eventId"])
        self.assertEqual((newer["start"], newer["end"]), (START + 100, START + 400))
        self.assertEqual(newer["provenance"]["sourceIntervalCount"], 3)

    def test_finalization_waits_without_inventing_source_end(self):
        self.j.fusion.frigate(CAMERA, batch([item(end=10000)], at=11000))
        self.assertIsNone(self.sync(11000)[0]["end"])
        self.assertEqual(self.sync(15000)[0]["end"], START + 10000)


class FrigateHttpTests(unittest.TestCase):
    def test_actual_018_nullable_columns_use_real_nested_object_score(self):
        value = item()
        value.update(top_score=None, false_positive=None,
                     data={"type": "object", "score": 0.82421875, "top_score": 0.84375, "max_severity": "alert"})
        parsed = normalize(value, "front", START + 60000)
        self.assertEqual(parsed["class"], "person")
        self.assertEqual(parsed["topScore"], 0.84375)
        self.assertIsNone(parsed["falsePositive"])
        self.assertEqual(parsed["acceptanceBasis"], "object_data_with_nullable_legacy_flag")
        value["false_positive"] = True
        self.assertIsNone(normalize(value, "front", START + 60000)["class"])
        value["false_positive"] = False
        self.assertEqual(normalize(value, "front", START + 60000)["class"], "person")

    def test_nullable_flag_never_substitutes_for_actual_object_data(self):
        for data in ({}, {"type": "motion", "top_score": 0.9}, {"type": "manual", "top_score": 0.9},
                     {"type": "object"}, {"type": "object", "top_score": None},
                     {"type": "object", "top_score": True}, {"type": "object", "top_score": float("nan")}):
            value = item(false_positive=None)
            value["data"] = data
            with self.assertRaises(ValueError):
                normalize(value, "front", START + 60000)
        value = item()
        del value["false_positive"]
        with self.assertRaises(ValueError):
            normalize(value, "front", START + 60000)

    def fake(self, values, requests, absent=()):
        def get(url, headers, **kwargs):
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query)
            requests.append((url, headers))
            self.assertEqual(headers["Authorization"], "Bearer " + options()["bearerToken"])
            self.assertLessEqual(kwargs["timeout"], 4)
            if parsed.path == "/health":
                return 200, b'{"healthy":true}'
            if parsed.path.startswith("/api/events/"):
                identifier = urllib.parse.unquote(parsed.path.split("/")[-1])
                value = next((value for value in values if value["id"] == identifier), None)
                return (404, b"{}") if value is None or identifier in absent else (200, json.dumps(value).encode())
            selected = list(values)
            if "in_progress" in query:
                selected = [value for value in selected if value["end_time"] is None]
            else:
                after, before = float(query["after"][0]), float(query["before"][0])
                selected = [value for value in selected if after < value["start_time"] < before]
            return 200, json.dumps(sorted(selected, key=lambda value: value["start_time"], reverse=True)[:200]).encode()
        return get

    def test_full_pages_are_split_with_boundary_overlap_and_exact_ids(self):
        values = [item("track-" + str(index), start=index * 100, end=index * 100 + 50) for index in range(400)]
        requests = []
        with patch("reolink_protect_events.frigate.get_bytes", side_effect=self.fake(values, requests)):
            result = poll(options(), "front", START, [], START + 60000)
        self.assertEqual({value["id"] for value in result["events"]}, {value["id"] for value in values})
        self.assertEqual(result["cursor"], START + 60000)
        self.assertGreater(len(requests), 2)

    def test_same_timestamp_saturation_raises_without_cursor_result(self):
        values = [item("track-" + str(index), end=100) for index in range(201)]
        with patch("reolink_protect_events.frigate.get_bytes", side_effect=self.fake(values, [])):
            with self.assertRaises((ValueError, TimeoutError)):
                poll(options(), "front", START, [], START + 60000)

    def test_long_active_and_saved_closed_event_are_refreshed_outside_window(self):
        values = [item("long", start=-500000), item("closed", start=-500000, end=10000)]
        with patch("reolink_protect_events.frigate.get_bytes", side_effect=self.fake(values, [])):
            result = poll(options(), "front", START, ["closed"], START + 60000)
        self.assertEqual({value["id"] for value in result["events"]}, {"long", "closed"})

    def test_malformed_remote_payload_fails_entire_batch(self):
        for mutation in ({"false_positive": None}, {"start_time": float("nan")}, {"camera": "wrong"}, {"end_time": 1}, {"id": "../../other"}):
            value = item(end=10000)
            value.update(mutation)
            def get(url, *_args, **_kwargs):
                return (200, b'{"healthy":true}') if urllib.parse.urlsplit(url).path == "/health" else (200, json.dumps([value]).encode())
            with patch("reolink_protect_events.frigate.get_bytes", side_effect=get):
                with self.assertRaises(ValueError):
                    poll(options(), "front", START, [], START + 60000)

    def test_unhealthy_detector_never_admits_history_or_advances_cursor(self):
        for health in ({"healthy": False}, {"healthy": "true"}, {}):
            with patch("reolink_protect_events.frigate.get_bytes", return_value=(200, json.dumps(health).encode())) as get:
                with self.assertRaisesRegex(ValueError, "frigate_detector_unhealthy"):
                    poll(options(), "front", START, [], START + 60000)
                self.assertEqual(get.call_count, 1)

    def test_optional_config_does_not_change_legacy_and_rejects_secret_url(self):
        self.assertIsNone(settings(config()))
        for change in ({"url": "http://user:password@192.0.2.1"}, {"bearerToken": "x\r\nAuthorization: bad"}, {"cameraMap": {"front": "2" * 24}}):
            value = config()
            value["frigate"] = dict(options(), **change)
            with self.assertRaises(ValueError):
                validate_config(value)


class RuntimeFusionTests(unittest.TestCase):
    def test_poll_failure_keeps_bridge_capture_and_saved_frigate_watermark(self):
        value = config()
        value["frigate"] = options()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Runtime(value, directory, capture_only=True)
            try:
                with patch("reolink_protect_events.runtime.fetch_bridge", return_value=response([event(1, classes=["person"])])), \
                     patch("reolink_protect_events.frigate.poll", side_effect=TimeoutError("secret must not appear")):
                    runtime.once()
                    for future in runtime._frigate_jobs:
                        try:
                            future.result()
                        except TimeoutError:
                            pass
                    runtime.once()
                health = json.loads((Path(directory) / "health.json").read_text())
                self.assertFalse(health["frigateHealthy"])
                self.assertEqual(health["frigate"][CAMERA]["errorType"], "TimeoutError")
                self.assertEqual(runtime.journal.cursor(CAMERA)["seq"], 1)
                self.assertEqual(runtime.journal.fusion.poll_state(CAMERA)[0], None)
                self.assertNotIn("secret must not appear", json.dumps(health))
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
