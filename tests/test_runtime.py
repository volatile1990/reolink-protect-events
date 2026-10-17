import datetime
import json
from pathlib import Path
import tempfile
import unittest
from reolink_protect_events.runtime import Journal, source_classes, timestamp_ms


CAMERA = {"cameraId": "111111111111111111111111", "host": "192.168.30.214"}
INSTANCE = "a" * 32
START = 1791586947512


def event(seq, offset=0, classes=(), raw=(), motion=False, epoch=0):
    return {"seq": seq, "timestampUtc": datetime.datetime.fromtimestamp((START + offset) / 1000, datetime.timezone.utc).isoformat(),
            "isActive": motion, "motion": motion, "classes": list(classes), "rawAiTypes": list(raw),
            "sourceStatus": "MD" if motion else "none", "source": {"connectionEpoch": epoch, "profile": "main", "channel": 0}, "zones": []}


def response(events, instance=INSTANCE, oldest=1, newest=None):
    return {"instanceId": instance, "oldestSeq": oldest, "currentSeq": newest if newest is not None else max(e["seq"] for e in events), "events": events}


class JournalTests(unittest.TestCase):
    def test_single_counter_read_uses_index_without_aggregating_source_or_publication_history(self):
        self.assertEqual(self.journal.counter('nativeImportErrors'),0)
        with self.journal.db:self.journal.count('nativeImportErrors',12)
        queries=[];self.journal.db.set_trace_callback(queries.append)
        self.assertEqual(self.journal.counter('nativeImportErrors'),12)
        self.journal.db.set_trace_callback(None)
        self.assertEqual(len(queries),1)
        self.assertNotIn('publication_intervals',queries[0]);self.assertNotIn('sources',queries[0])
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "journal.sqlite3"
        self.journal = Journal(self.path)

    def tearDown(self):
        self.journal.db.close()
        self.folder.cleanup()

    def test_motion_never_creates_classification(self):
        self.journal.ingest(CAMERA, response([event(1, motion=True), event(2, 2000)]))
        self.assertEqual(self.journal.pending(), [])
        self.assertEqual(self.journal.health()["sourceRows"], 2)

    def test_ai_only_person_duplicate_replay_and_restart(self):
        payload = response([event(1, classes=["person"], raw=["people"])])
        self.journal.ingest(CAMERA, payload)
        first = self.journal.pending()[0]
        self.journal.acknowledge(first["eventId"], 1, "delivered")
        self.journal.acknowledge(first["eventId"], 1, "notified")
        self.journal.db.close()
        self.journal = Journal(self.path)
        self.journal.ingest(CAMERA, payload)
        self.assertEqual(self.journal.pending(), [])
        self.assertEqual(self.journal.health()["sourceRows"], 1)
        self.assertEqual(self.journal.health()["openIntervals"], 1)

    def test_repeated_class_then_clear_uses_source_times(self):
        self.journal.ingest(CAMERA, response([event(1, classes=["animal"]), event(2, 3000, classes=["animal"]), event(3, 6000)]))
        pending = self.journal.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["end"], START + 6000)
        self.assertEqual(pending[0]["provenance"]["closureReason"], "camera_clear")
        self.assertFalse(pending[0]["provenance"]["classificationInferred"])

    def test_multiple_classes_have_separate_truthful_intervals(self):
        self.journal.ingest(CAMERA, response([event(1, classes=["person", "vehicle"]), event(2, 5000, classes=["vehicle"])]))
        values = {p["classes"][0]: p for p in self.journal.pending()}
        self.assertEqual(set(values), {"person", "vehicle"})
        self.assertEqual(values["person"]["end"], START + 5000)
        self.assertIsNone(values["vehicle"]["end"])

    def test_stale_and_epoch_do_not_merge_detections(self):
        self.journal.ingest(CAMERA, response([event(1, classes=["person"]), event(2, 130000, classes=["person"])]))
        self.assertEqual(len(self.journal.pending()), 2)
        self.assertEqual(self.journal.pending()[0]["end"], START + 120000)
        self.journal.ingest(CAMERA, response([event(3, 135000, classes=["person"], epoch=1)], oldest=1))
        self.assertEqual(len(self.journal.pending()), 3)

    def test_restart_closes_old_without_fabricated_source_event(self):
        self.journal.ingest(CAMERA, response([event(1, classes=["person"])]))
        self.journal.ingest(CAMERA, response([event(1, 10000, classes=["person"])], instance="b" * 32))
        self.assertEqual(self.journal.health()["sourceRows"], 2)
        self.assertEqual(len(self.journal.pending()), 2)
        self.assertEqual(self.journal.pending()[0]["provenance"]["closureReason"], "bridge_restart")

    def test_invalid_batch_cannot_advance_cursor(self):
        malformed = event(2, 3000)
        malformed["timestampUtc"] = "invalid"
        with self.assertRaises(ValueError):
            self.journal.ingest(CAMERA, response([event(1, classes=["person"]), malformed]))
        self.assertEqual(self.journal.cursor(CAMERA["cameraId"])["seq"], 0)
        self.assertEqual(self.journal.health()["sourceRows"], 0)

    def test_replay_gap_visible_and_first_available_detection_preserved(self):
        self.journal.ingest(CAMERA, response([event(300, classes=["vehicle"])], oldest=300))
        self.assertEqual(self.journal.health()["counters"]["replayGaps"], 1)
        self.assertEqual(self.journal.pending()[0]["classes"], ["vehicle"])

    def test_unsupported_classes_do_not_become_people(self):
        self.assertEqual(source_classes(event(1, raw=["face", "visitor", "motion", "true", "package"])), set())
        self.assertEqual(source_classes(event(1, raw=["people", "dog_cat", "car"])), {"person", "animal", "vehicle"})

    def test_reolink_baby_cry_aliases_keep_audio_separate_from_objects(self):
        for label in ("cry", "baby_cry", "babycry", " CRY "):
            self.assertEqual(source_classes(event(1, raw=[label])), {"babyCry"})
        self.assertEqual(source_classes(event(1, raw=["crying", "smoke", "bark"])), set())
        self.journal.ingest(CAMERA, response([
            event(1, classes=["person"], raw=["cry"]),
            event(2, 3000, classes=["person"]),
            event(3, 6000)]))
        values = {p["classes"][0]: p for p in self.journal.pending()}
        self.assertEqual(set(values), {"person", "babyCry"})
        self.assertEqual(values["babyCry"]["end"], START + 3000)
        self.assertEqual(values["person"]["end"], START + 6000)

    def test_dotnet_timestamp_preserves_millisecond(self):
        self.assertEqual(timestamp_ms("2026-10-09T23:02:27.5128436+00:00"), START)
        with self.assertRaises(ValueError):
            timestamp_ms("2026-10-09T23:02:27.512")


if __name__ == "__main__":
    unittest.main()
