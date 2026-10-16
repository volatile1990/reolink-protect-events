import json
from pathlib import Path
import tempfile
import unittest

from reolink_protect_events.features import (CameraFeatures, FeatureError, FeaturePatch,
    INTEGRATION_ZONE, UI_ORIGINAL, SCOPE_ORIGINAL, camera_ids, patched_bytes, sha256)


IDS = ["0123456789abcdef01234567", "1123456789abcdef01234567"]


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.ui = self.root / "swai.js"
        self.ui_alias = self.root / "swai-7.3.26.js"
        self.service = self.root / "service.js"
        self.ui_original = ("const " + UI_ORIGINAL + ";").encode()
        self.service_original = ("const scopes={" + SCOPE_ORIGINAL + ",scope_other:e=>!e.isThirdPartyCamera};").encode()
        for path in (self.ui, self.ui_alias):
            path.write_bytes(self.ui_original)
        self.service.write_bytes(self.service_original)
        self.patch = FeaturePatch(version_reader=lambda: "7.3.70",
            ui_paths=[self.ui, self.ui_alias], service_path=self.service,
            ui_hash=sha256(self.ui_original), service_hash=sha256(self.service_original))

    def tearDown(self):
        self.directory.cleanup()

    def test_narrow_selector_preserves_original_and_requires_enabled_identity(self):
        patched = patched_bytes(self.ui_original, IDS, "ui").decode()
        self.assertIn("!a||!!r.has(e.nvrMac)", patched)
        self.assertIn("!e.isThirdPartyCamera||!!e.isPairedWithAiPort||(", patched)
        self.assertIn(json.dumps(IDS, separators=(",", ":")) + ".includes(e.id)&&e.featureFlags.hasSmartDetect", patched)
        self.assertNotIn("hasFullFeatureSet", patched)

    def test_default_does_not_touch_backend_and_full_rollback(self):
        manifest = self.patch.apply(IDS, self.root / "backups")
        self.assertNotEqual(self.ui.read_bytes(), self.ui_original)
        self.assertEqual(self.ui.read_bytes(), self.ui_alias.read_bytes())
        self.assertEqual(self.service.read_bytes(), self.service_original)
        parsed = json.loads(Path(manifest).read_text())
        self.assertEqual(parsed["state"], "applied")
        self.assertEqual(len(parsed["files"]), 2)
        self.assertEqual(self.patch.rollback(manifest), {"state": "rolled_back", "files": 2})
        self.assertEqual(self.ui.read_bytes(), self.ui_original)
        self.assertEqual(self.ui_alias.read_bytes(), self.ui_original)

    def test_optional_alarm_scope_only_selected_camera_models(self):
        manifest = self.patch.apply(IDS, self.root / "backups", include_alarm_scope=True)
        patched = self.service.read_text()
        self.assertIn(".includes(e.pk)&&e.featureFlags.hasSmartDetect", patched)
        self.assertIn("scope_other:e=>!e.isThirdPartyCamera", patched)
        self.patch.rollback(manifest)
        self.assertEqual(self.service.read_bytes(), self.service_original)

    def test_refuses_package_upgrade_modified_hash_and_ambiguous_anchor(self):
        self.patch.version_reader = lambda: "7.3.71"
        with self.assertRaises(FeatureError):
            self.patch.plan(IDS)
        self.patch.version_reader = lambda: "7.3.70"
        self.ui.write_bytes(self.ui_original + b"changed")
        with self.assertRaises(FeatureError):
            self.patch.plan(IDS)
        with self.assertRaises(FeatureError):
            patched_bytes(self.ui_original * 2, IDS, "ui")

    def test_rollback_never_overwrites_intervening_change(self):
        manifest = self.patch.apply(IDS, self.root / "backups")
        self.ui_alias.write_bytes(b"later package update")
        with self.assertRaises(FeatureError):
            self.patch.rollback(manifest)
        # Rollback preflights every target before restoring any target.
        self.assertNotEqual(self.ui.read_bytes(), self.ui_original)
        self.assertEqual(self.ui_alias.read_bytes(), b"later package update")

    def test_invalid_identity_and_manifest_paths_fail(self):
        for ids in ([], IDS + [IDS[0]], ["not-an-id"], ["a\"].includes(e.id)||true"]):
            with self.assertRaises(ValueError):
                camera_ids(ids)
        manifest = Path(self.patch.apply(IDS, self.root / "backups"))
        parsed = json.loads(manifest.read_text())
        parsed["files"][0]["backup"] = "../../swai.js"
        manifest.write_text(json.dumps(parsed))
        with self.assertRaises(FeatureError):
            self.patch.rollback(manifest)


class FakeAdapter:
    def __init__(self):
        self.guarded = 0
        self.calls = []
        self.rows = [{"id": identity, "isThirdPartyCamera": True, "isPairedWithAiPort": False,
            "featureFlags": {"hasMotionDetection": True, "smartDetectTypes": [], "hasMic": False},
            "smartDetectSettings": {"objectTypes": [], "audioTypes": [], "autoTrackingWithZoom": True},
            "smartDetectZones": []} for identity in IDS]
        self.schema = [{"column": name, "type": type_} for name, type_ in {
            "featureFlags": "json", "smartDetectSettings": "json", "smartDetectZones": "json",
            "isThirdPartyCamera": "bool", "isPairedWithAiPort": "bool"}.items()]

    def guard_schema(self):
        self.guarded += 1

    def execute(self, sql):
        self.calls.append(sql)
        if "information_schema.columns" in sql:
            return json.dumps(self.schema)
        if "FROM cameras WHERE id IN" in sql:
            return json.dumps(self.rows)
        return json.dumps({"configuredCameras": len(self.rows)})


class CameraFeatureTests(unittest.TestCase):
    def test_audio_features_are_explicit_per_camera_and_preserve_native_settings(self):
        adapter = FakeAdapter()
        adapter.rows[0]["featureFlags"]["smartDetectAudioTypes"] = ["alrmSpeak"]
        adapter.rows[1]["featureFlags"]["smartDetectAudioTypes"] = ["alrmBark"]
        selected = {IDS[0]: ["alrmBabyCry", "alrmBabyCry", "alrmGlassBreak"]}
        tool = CameraFeatures(adapter)
        plan = tool.plan(IDS, audio_types_by_camera=selected)
        self.assertEqual(plan["audioTypesByCamera"], {IDS[0]: ["alrmBabyCry", "alrmGlassBreak"]})
        for row in plan["cameras"]:
            self.assertFalse(row["configured"]["featureFlags"]["hasMic"])
            self.assertEqual(row["configured"]["smartDetectSettings"], row["original"]["smartDetectSettings"])
        self.assertEqual(plan["cameras"][0]["configured"]["featureFlags"]["smartDetectAudioTypes"], ["alrmBabyCry", "alrmGlassBreak"])
        self.assertEqual(plan["cameras"][1]["configured"]["featureFlags"]["smartDetectAudioTypes"], ["alrmBark"])
        self.assertEqual(tool.public_plan(plan)["audioTypesByCamera"], plan["audioTypesByCamera"])
        self.assertNotIn('"smartDetectSettings"=', tool._sql(plan))
        self.assertEqual(adapter.rows[0]["featureFlags"]["smartDetectAudioTypes"], ["alrmSpeak"])
        cleared = tool.plan(IDS, audio_types_by_camera={IDS[0]: []})
        self.assertEqual(cleared["cameras"][0]["configured"]["featureFlags"]["smartDetectAudioTypes"], [])

    def test_audio_capabilities_reject_wrong_camera_or_internal_source_names(self):
        for supplied in ({"ffffffffffffffffffffffff": ["alrmBabyCry"]},
                         {IDS[0]: ["babyCry"]}, {IDS[0]: ["alrmBurglar"]},
                         {IDS[0]: "alrmBark"}, {IDS[0]: [None]}, []):
            adapter = FakeAdapter()
            with self.subTest(supplied=supplied), self.assertRaises(ValueError):
                CameraFeatures(adapter).plan(IDS, audio_types_by_camera=supplied)
            self.assertEqual(adapter.calls, [])

    def test_truthful_zone_and_narrow_field_changes(self):
        adapter = FakeAdapter()
        tool = CameraFeatures(adapter)
        plan = tool.plan(IDS)
        configured = plan["cameras"][0]["configured"]
        self.assertEqual(configured["featureFlags"]["smartDetectTypes"], ["person", "vehicle", "animal"])
        self.assertTrue(configured["featureFlags"]["hasSmartDetect"])
        self.assertTrue(configured["featureFlags"]["hasMotionDetection"])
        self.assertFalse(configured["featureFlags"]["hasMic"])
        self.assertEqual(configured["smartDetectSettings"]["objectTypes"], [])
        self.assertTrue(configured["smartDetectSettings"]["autoTrackingWithZoom"])
        self.assertEqual(configured["smartDetectSettings"]["audioTypes"], [])
        self.assertEqual(configured["smartDetectZones"], [INTEGRATION_ZONE])
        self.assertEqual(INTEGRATION_ZONE["points"], [[0, 0], [1, 0], [1, 1], [0, 1]])
        self.assertEqual(adapter.rows[0]["smartDetectZones"], [])
        sql = tool._sql(plan)
        self.assertIn("GET DIAGNOSTICS n = ROW_COUNT", sql)
        self.assertIn('"isThirdPartyCamera"=true AND "isPairedWithAiPort"=false', sql)
        self.assertIn('"featureFlags"::jsonb=', sql)
        self.assertNotIn('"recordingSettings"=', sql)
        self.assertNotIn('"smartDetectSettings"=', sql)
        self.assertNotIn('"thirdPartyCameraInfo"', sql)

    def test_refuse_existing_custom_zone_or_paired_camera_or_schema_change(self):
        for mutation in ("custom_zone", "paired", "schema"):
            adapter = FakeAdapter()
            if mutation == "custom_zone":
                adapter.rows[0]["smartDetectZones"] = [{"id": 1, "name": "user perimeter"}]
            elif mutation == "paired":
                adapter.rows[0]["isPairedWithAiPort"] = True
            else:
                adapter.schema[0]["type"] = "text"
            with self.subTest(mutation=mutation), self.assertRaises(FeatureError):
                CameraFeatures(adapter).plan(IDS)

    def test_backup_retains_native_settings_but_rollback_changes_two_fields(self):
        adapter = FakeAdapter()
        tool = CameraFeatures(adapter)
        with tempfile.TemporaryDirectory() as root:
            result = tool.apply(IDS, root)
            path = Path(result["manifest"])
            manifest = json.loads(path.read_text(encoding="utf8"))
            self.assertEqual(manifest["state"], "applied")
            self.assertEqual(set(manifest["cameras"][0]["original"]),
                             {"featureFlags", "smartDetectSettings", "smartDetectZones"})
            result = tool.rollback(path)
            self.assertEqual(result["cameras"], 2)
            self.assertEqual(json.loads(path.read_text())["state"], "rolled_back")
            self.assertGreaterEqual(adapter.guarded, 2)
            self.assertIn("Camera feature precondition changed", adapter.calls[-1])
            self.assertNotIn('"smartDetectSettings"=', adapter.calls[-1])

    def test_legacy_manifest_ignored_native_settings_never_overwritten(self):
        tool = CameraFeatures(FakeAdapter())
        plan = tool.plan(IDS)
        plan["cameras"][0]["configured"]["smartDetectSettings"]["objectTypes"] = ["person", "vehicle", "animal"]
        self.assertNotIn('"smartDetectSettings"=', tool._sql(plan))
        self.assertNotIn('"smartDetectSettings"=', tool._sql(plan, restore=True))


if __name__ == "__main__":
    unittest.main()
