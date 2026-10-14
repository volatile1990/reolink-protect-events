"""Pure ownership guard for Controls above the native camera-feature UI patch."""
import hashlib
import re


class OwnedLayerError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise OwnedLayerError(code)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def verified_controls_layer(current, feature_item, ids, manifest, backup, unpatch):
    """Caller supplies a root-private, path-scoped manifest and backup bytes.

    A matching hash alone is insufficient: reversing the controls insertion must
    reproduce the exact native-features file and its protected backup.
    """
    need(manifest.get("version") == "7.3.70" and manifest.get("state") == "applied", "owned_controls_manifest_not_applied")
    selected = sorted(ids)
    need(selected and len(selected) == len(set(selected)) and
         all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{24}", value) for value in selected), "owned_controls_camera_scope_invalid")
    baseline = manifest.get("cameraBaseline", {})
    need(baseline.get("version") == "7.3.70" and baseline.get("cameraIds") == selected, "owned_controls_camera_scope_changed")
    files = manifest.get("files")
    need(isinstance(files, list) and len(files) <= 8 and len({item.get("path") for item in files}) == len(files), "owned_controls_manifest_files_invalid")
    matched = [item for item in files if item.get("path") == feature_item.get("path")]
    need(len(matched) == 1, "owned_controls_ui_target_missing")
    item = matched[0]
    need(item.get("beforeSha256") == feature_item.get("afterSha256") and item.get("absentBefore") is False,
         "owned_controls_native_base_changed")
    need(sha(current) == item.get("afterSha256") and sha(backup) == item.get("beforeSha256"), "owned_controls_digest_changed")
    try:
        restored = unpatch(current, selected, expected_sha256=item["afterSha256"], feature_camera_ids=selected)
    except Exception:
        raise OwnedLayerError("owned_controls_unpatch_failed") from None
    need(restored == backup and sha(restored) == feature_item["afterSha256"], "owned_controls_native_base_changed")
    return {"owner": "reolink-protect-controls", "verified": True, "reversible": True,
            "nativeFeaturesSha256": feature_item["afterSha256"], "controlsSha256": item["afterSha256"]}


def rollback_dependency(layers):
    if layers:
        raise OwnedLayerError("feature_rollback_controls_dependency")


def user_modified_zone_fields(expected, current):
    """Status-only tolerance for editable sensitivity and nullable merge metadata.

    Every identity, polygon, class and other setting remains an exact comparison.
    Mutation callers continue to require the original complete CAS comparison.
    """
    need(isinstance(expected, list) and isinstance(current, list) and len(expected) == len(current) == 1 and
         isinstance(expected[0], dict) and isinstance(current[0], dict), "feature_camera_fields_changed")
    before, actual = expected[0], current[0]
    keys = set(before) | set(actual)
    changed = {key for key in keys if before.get(key) != actual.get(key) or (key in before) != (key in actual)}
    need(changed and changed <= {"sensitivity", "mergeId"}, "feature_camera_fields_changed")
    if "sensitivity" in changed:
        need(type(actual.get("sensitivity")) is int and 0 <= actual["sensitivity"] <= 100, "feature_camera_fields_changed")
    if "mergeId" in changed:
        value = actual.get("mergeId")
        # The audited UI serializes absent merge metadata as mergeId ?? null.
        # Generated identifiers are accepted only in the standard UUID/ObjectId forms.
        need(value is None or isinstance(value, str) and bool(re.fullmatch(
            r"(?:[a-f0-9]{24}|[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})", value)),
            "feature_camera_fields_changed")
    result = {"zoneId": before.get("id"), "fields": sorted(changed), "originalManifestPreserved": True,
              "rollbackCASPreserved": True}
    if "sensitivity" in changed: result["sensitivity"] = {"manifest": before.get("sensitivity"), "current": actual["sensitivity"]}
    if "mergeId" in changed: result["mergeIdPresent"] = "mergeId" in actual
    return result
