"""Future-only Reolink class filtering with genuine durable source replay."""
import json
from pathlib import Path
import tempfile
import unittest

from reolink_protect_events.runtime import (
    CLASSES, Journal, Runtime, reolink_class_settings, source_classes, validate_config,
)
from test_frigate import options
from test_runtime import CAMERA, START, event, response
from test_runtime_delivery import config


class ReolinkClassPolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def runtime(self, allowed):
        value = config()
        value["reolinkClasses"] = allowed
        runtime = Runtime(value, self.root, background_native=False)
        self.addCleanup(runtime.journal.close)
        return runtime

    def test_legacy_default_keeps_audio_and_pure_normalizer_unchanged(self):
        self.assertEqual(reolink_class_settings(config()), CLASSES)
        journal = Journal(self.root / "legacy.sqlite3")
        self.addCleanup(journal.close)
        original = event(1, classes=["person"], raw=["cry"])
        self.assertEqual(source_classes(original), {"person", "babyCry"})
        journal.ingest(CAMERA, response([original, event(2, 2000)]))
        self.assertEqual({row["classes"][0] for row in journal.pending()}, {"person", "babyCry"})

    def test_runtime_filters_mixed_pushes_but_preserves_raw_clear_and_cursor(self):
        journal = self.runtime(["person", "animal", "vehicle"]).journal
        messages = [event(1, classes=["person"], raw=["cry"]),
                    event(2, 2000, raw=["cry"]), event(3, 3000, raw=["cry"])]
        journal.ingest(CAMERA, response(messages))
        values = journal.pending()
        self.assertEqual([row["classes"] for row in values], [["person"]])
        self.assertEqual(values[0]["end"], START + 2000)
        self.assertEqual(values[0]["provenance"]["closureReason"], "camera_clear")
        self.assertEqual([json.loads(row[0]) for row in journal.db.execute(
            "SELECT payload FROM sources ORDER BY seq")], messages)
        self.assertEqual(journal.cursor(CAMERA["cameraId"])["seq"], 3)
        self.assertEqual(journal.counter("sourceEvents"), 3)

    def test_filter_does_not_rewrite_closed_history_or_acknowledgements(self):
        path = self.root / "journal.sqlite3"
        legacy = Journal(path)
        legacy.ingest(CAMERA, response([event(1, raw=["cry"]), event(2, 1000)]))
        old = legacy.pending()[0]
        legacy.acknowledge(old["eventId"], old["revision"], "delivered")
        legacy.acknowledge(old["eventId"], old["revision"], "notified")
        before = legacy.db.execute("SELECT * FROM intervals WHERE id=?", (old["eventId"],)).fetchone()
        legacy.close()
        journal = self.runtime(["person", "animal", "vehicle"]).journal
        journal.ingest(CAMERA, response([event(3, 3000, classes=["person"], raw=["cry"]), event(4, 4000)]))
        after = journal.db.execute("SELECT * FROM intervals WHERE id=?", (old["eventId"],)).fetchone()
        self.assertEqual(after, before)
        self.assertEqual([row["classes"] for row in journal.pending()], [["person"]])
        self.assertEqual(journal.health()["sourceRows"], 4)

    def test_fusion_reenable_replay_cannot_resurrect_filtered_audio(self):
        journal = self.runtime(["person", "animal", "vehicle"]).journal
        journal.enable_fusion([CAMERA["cameraId"]], options())
        journal.fusion = None  # The genuine collector continues while unmapped.
        journal.ingest(CAMERA, response([event(1, classes=["person"], raw=["cry"]), event(2, 2000)]))
        journal.enable_fusion([CAMERA["cameraId"]], options())
        journal.fusion.sync(START + 30000)
        self.assertEqual({row[0] for row in journal.db.execute(
            "SELECT class FROM fusion_inputs WHERE source='reolink'")}, {"person"})
        self.assertEqual({row["classes"][0] for row in journal.pending()}, {"person"})
        self.assertEqual(journal.cursor(CAMERA["cameraId"])["seq"], 2)

    def test_configuration_requires_unique_supported_string_list(self):
        for allowed in ([], ["person"], ["person", "animal", "vehicle"], sorted(CLASSES)):
            value = config()
            value["reolinkClasses"] = allowed
            self.assertIs(validate_config(value), value)
            self.assertEqual(reolink_class_settings(value), frozenset(allowed))
        for invalid in (None, True, "person", {}, ["person", "person"], ["motion"], [1], [["person"]]):
            value = config()
            value["reolinkClasses"] = invalid
            with self.assertRaisesRegex(ValueError, "invalid_reolink_classes"):
                validate_config(value)
