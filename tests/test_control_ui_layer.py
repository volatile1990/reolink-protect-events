import ast
import copy
import importlib.util
from pathlib import Path
import unittest

from reolink_protect_events.control_ui_layer import OwnedLayerError, rollback_dependency, verified_controls_layer, user_modified_zone_fields

ROOT = Path(__file__).resolve().parents[2]
from reolink_protect_events import controls_ui_guard as controls
IDS = ["0123456789abcdef01234567", "1123456789abcdef01234567"]


class OwnedControlsLayerTests(unittest.TestCase):
    def setUp(self):
        self.vendor = ("const " + controls.EVENT_GATE + ";let settings=[" + controls.ANCHOR + "{}:null]").encode()
        self.vendor_hash = controls.digest(self.vendor)
        self.native = self.vendor.replace(controls.EVENT_GATE.encode(), controls.event_gate(IDS).encode())
        self.current = controls.patched_bytes(self.native, IDS, runtime=b"window.syntheticControls = true;", ui_hash=self.vendor_hash)
        self.item = {"path": "/vendor/swai.js", "afterSha256": controls.digest(self.native)}
        self.manifest = {"version": "7.3.70", "state": "applied", "cameraBaseline": {"version": "7.3.70", "cameraIds": IDS},
            "files": [{"path": "/vendor/swai.js", "beforeSha256": controls.digest(self.native),
                "afterSha256": controls.digest(self.current), "absentBefore": False}]}

    def unpatch(self, current, ids, **options):
        return controls.unpatched_bytes(current, ids, ui_hash=self.vendor_hash, **options)

    def verify(self, *, current=None, item=None, manifest=None, backup=None):
        return verified_controls_layer(self.current if current is None else current, self.item if item is None else item,
            IDS, self.manifest if manifest is None else manifest, self.native if backup is None else backup, self.unpatch)

    def test_exact_applied_manifest_layer_is_reversibly_owned(self):
        result = self.verify()
        self.assertEqual(result["owner"], "reolink-protect-controls")
        self.assertTrue(result["verified"] and result["reversible"])
        self.assertEqual(result["nativeFeaturesSha256"], controls.digest(self.native))
        self.assertEqual(self.unpatch(self.current, IDS, expected_sha256=controls.digest(self.current)), self.native)

    def test_unrecorded_hash_drift_or_camera_scope_never_accepted(self):
        for modified in [self.current + b"drift", self.current.replace(b"syntheticControls", b"otherRuntime")]:
            with self.assertRaises(OwnedLayerError): self.verify(current=modified)
        for mutate in [lambda m: m.update(state="prepared"), lambda m: m.update(version="7.3.71"),
                lambda m: m["cameraBaseline"].update(cameraIds=IDS[:1]), lambda m: m["files"][0].update(absentBefore=True),
                lambda m: m["files"].append(copy.deepcopy(m["files"][0]))]:
            manifest = copy.deepcopy(self.manifest); mutate(manifest)
            with self.assertRaises(OwnedLayerError): self.verify(manifest=manifest)

    def test_backup_and_native_layer_integrity_both_required(self):
        with self.assertRaises(OwnedLayerError): self.verify(backup=self.native + b"changed")
        item = dict(self.item, afterSha256=controls.digest(self.vendor))
        with self.assertRaises(OwnedLayerError): self.verify(item=item)
        altered = self.current.replace(b"let settings", b"let changed")
        manifest = copy.deepcopy(self.manifest); manifest["files"][0]["afterSha256"] = controls.digest(altered)
        with self.assertRaisesRegex(OwnedLayerError, "owned_controls_unpatch_failed"):
            self.verify(current=altered, manifest=manifest)

    def test_marker_or_insertion_tampering_rejected_even_at_recorded_hash(self):
        for altered in [self.current.replace(controls.PREFIX_END, b"bad end"),
                self.current.replace(controls.insertion(IDS).encode(), controls.insertion(IDS[:1]).encode()),
                self.current + controls.PREFIX_BEGIN]:
            with self.assertRaises(controls.PatchError):
                self.unpatch(altered, IDS, expected_sha256=controls.digest(altered))

    def test_dependency_guard_precedes_any_live_restore_or_sql(self):
        rollback_dependency([])
        with self.assertRaisesRegex(OwnedLayerError, "feature_rollback_controls_dependency"):
            rollback_dependency([self.verify()])
        path = Path(__file__).resolve().parents[1] / "tools/enable_features.py"
        spec = importlib.util.spec_from_file_location("feature_enable_ui_guard_test", path)
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        ast.parse(helper.REMOTE)
        rollback = helper.REMOTE.split("if mode=='rollback':", 1)[1]
        self.assertLess(rollback.index("rollback_dependency(ui_status(state))"), rollback.index("resume_rollback("))

    def test_actual_vendor_bytes_keep_native_feature_gate_through_controls_layer(self):
        asset = ROOT / "audit-protect-frontend-swai-7.3.26.js"
        if not asset.exists(): self.skipTest("Audited UI unavailable")
        vendor = asset.read_bytes()
        self.assertEqual(controls.digest(vendor), controls.UI_HASH)
        native = vendor.replace(controls.EVENT_GATE.encode(), controls.event_gate(IDS).encode())
        current = controls.patched_bytes(native, IDS, runtime=b"window.oldReviewedRuntime = true;")
        self.assertEqual(controls.unpatched_bytes(current, IDS, expected_sha256=controls.digest(current)), native)

    def test_status_reports_valid_user_zone_fields_without_altering_manifest(self):
        expected = [{"id": 1, "points": [[0, 0], [1, 0], [1, 1], [0, 1]], "objectTypes": ["person", "vehicle", "animal"],
                     "sensitivity": 50, "mergeId": "reolink-protect-events-primary", "isTriggerLightEnabled": False}]
        actual = copy.deepcopy(expected); actual[0].update(sensitivity=53, mergeId=None)
        original = copy.deepcopy(expected)
        result = user_modified_zone_fields(expected, actual)
        self.assertEqual(result["fields"], ["mergeId", "sensitivity"])
        self.assertEqual(result["sensitivity"], {"manifest": 50, "current": 53})
        self.assertTrue(result["originalManifestPreserved"] and result["rollbackCASPreserved"])
        self.assertEqual(expected, original)
        for mutate in [lambda z: z[0].update(id=2), lambda z: z[0].update(points=[[0, 0], [0.5, 1]]),
                lambda z: z[0].update(objectTypes=["face"]), lambda z: z[0].update(isTriggerLightEnabled=True),
                lambda z: z[0].update(sensitivity=True), lambda z: z[0].update(sensitivity=100.1),
                lambda z: z[0].update(sensitivity=-1), lambda z: z[0].update(mergeId="unverified-string"),
                lambda z: z.append(copy.deepcopy(z[0]))]:
            modified = copy.deepcopy(actual); mutate(modified)
            with self.assertRaises(OwnedLayerError): user_modified_zone_fields(expected, modified)

    def test_mutating_modes_still_reject_user_zone_drift_before_restore(self):
        path = Path(__file__).resolve().parents[1] / "tools/enable_features.py"
        spec = importlib.util.spec_from_file_location("feature_mutation_guard_test", path)
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        apply_existing = helper.REMOTE.split("if mode=='apply':", 1)[1].split("cameras.plan(ids)", 1)[0]
        self.assertIn("if result['userModifiedZoneFields']:raise RuntimeError('feature_camera_fields_changed')", apply_existing)
        rollback = helper.REMOTE.split("if mode=='rollback':", 1)[1]
        self.assertLess(rollback.index("if status(state)['userModifiedZoneFields']:raise"), rollback.index("resume_rollback("))


if __name__ == "__main__": unittest.main()
