"""Narrow, reversible UI gate patch for the inspected Protect 7.3.70 build.

Find Anything excludes unpaired third-party cameras even when native detection
data and camera feature flags exist. This patch admits only explicitly selected
camera identities with hasSmartDetect set. It does not advertise full features,
AI Port pairing, facial recognition, LPR, boxes, or line crossing. Native person,
vehicle and animal alarm scopes already honor hasSmartDetect + smartDetectZones;
the broader all-UI-camera alarm scope patch is optional and disabled by default.

Database flags are a separate, coordinated operation: the running Protect model
does not reload them from a genericModelUpdate notification. Restart Protect
once after persistence + this patch, then verify API/bootstrap and health sync.
Native AI settings and the UniFi smart-detection user agreement stay unchanged:
classification events originate in Reolink and enter through the adapter.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


VERSION = "7.3.70"
UI_ROOT = "/usr/share/unifi-protect/app/node_modules/@ubnt/unifi-protect-ui-internal/dist"
SERVICE = "/usr/share/unifi-protect/app/service.js"
UI_HASH = "0ffb0344d673a7f6e04703e1ae6695b77d65d07ba16886cb06956e2581e5cff4"
SERVICE_HASH = "b2dbea8740a201826b66d427e26cc428651751fcf1c4bda6de9b26765e558c16"
UI_ORIGINAL = "qq=(e,a,r)=>(!a||!!r.has(e.nvrMac))&&(!e.isThirdPartyCamera||!!e.isPairedWithAiPort)"
SCOPE_ORIGINAL = "scope_all_ui_cameras:e=>(0,t.deviceNotDeleted)(e)&&e.isAdopted&&(0,s.isCamera)(e)&&!e.isThirdPartyCamera"


class FeatureError(RuntimeError):
    pass


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def _version():
    try:
        result = subprocess.run(["dpkg-query", "--show", "--showformat=${Version}", "unifi-protect"],
                                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding="utf-8", timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        raise FeatureError("Cannot read the installed Protect version") from None
    if result.returncode:
        raise FeatureError("Cannot read the installed Protect version")
    return result.stdout.strip()


def camera_ids(ids):
    if not isinstance(ids, (list, tuple)) or not ids or len(ids) > 64:
        raise ValueError("Explicit camera identities are required")
    if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value) for value in ids):
        raise ValueError("Invalid camera identity")
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate camera identities")
    return sorted(ids)


def patched_bytes(original, ids, kind):
    selected = json.dumps(camera_ids(ids), separators=(",", ":"))
    if kind == "ui":
        before = UI_ORIGINAL
        after = before[:-1] + "||(" + selected + ".includes(e.id)&&e.featureFlags.hasSmartDetect))"
    elif kind == "all_ui_alarm_scope":
        before = SCOPE_ORIGINAL
        after = before.rsplit("&&!e.isThirdPartyCamera", 1)[0] + "&&(!e.isThirdPartyCamera||(" + selected + ".includes(e.pk)&&e.featureFlags.hasSmartDetect))"
    else:
        raise ValueError("Unknown feature patch")
    before, after = before.encode("ascii"), after.encode("ascii")
    if original.count(before) != 1:
        raise FeatureError("The inspected feature gate anchor is absent or ambiguous")
    return original.replace(before, after, 1)


DETECTION_CLASSES = ["person", "vehicle", "animal"]
INTEGRATION_ZONE = {"id": 1, "name": "Reolink-Kamera-KI (gesamtes Bild)",
    "color": "#AB46BC", "sensitivity": 50, "points": [[0, 0], [1, 0], [1, 1], [0, 1]],
    "objectTypes": DETECTION_CLASSES, "isTriggerLightEnabled": False, "source": "unifi-protect",
    "triggerAccessTypes": [], "enableAccessLPOnlyMode": False,
    "mergeId": "reolink-protect-events-primary"}
_CAMERA_FIELDS = ("featureFlags", "smartDetectZones")
_BACKUP_CAMERA_FIELDS = ("featureFlags", "smartDetectSettings", "smartDetectZones")


class CameraFeatures:
    """Version-guarded, compare-and-swap changes to two camera JSON fields.

    Full-frame coordinates [0,1] match shipped createDefaultSmartDetectZones.
    The integration rule indicates a camera AI detection anywhere in its image;
    the adapter never claims Reolink supplied a spatial coordinate or crossing.
    Existing custom zones are refused because source events cannot satisfy them.
    Native smartDetectSettings are backed up for historical context and never
    changed. No UniFi AI agreement, stream, recording, pairing or access change.
    """

    def __init__(self, adapter):
        self.adapter = adapter

    def _read(self, ids):
        from .native import _read_json_output, sql_text
        selected = camera_ids(ids)
        self.adapter.guard_schema()
        result = _read_json_output(self.adapter.execute(
            "SELECT json_agg(json_build_object('column',column_name,'type',udt_name) ORDER BY column_name) "
            "FROM information_schema.columns WHERE table_schema='public' AND table_name='cameras' "
            "AND column_name IN ('featureFlags','smartDetectSettings','smartDetectZones','isThirdPartyCamera','isPairedWithAiPort');"))
        expected = {"featureFlags": "json", "smartDetectSettings": "json", "smartDetectZones": "json",
                    "isThirdPartyCamera": "bool", "isPairedWithAiPort": "bool"}
        if not isinstance(result, list) or {row.get("column"): row.get("type") for row in result} != expected:
            raise FeatureError("Camera feature schema differs from the inspected Protect schema")
        fields = ",".join("'%s',\"%s\"" % (field, field) for field in _BACKUP_CAMERA_FIELDS)
        rows = _read_json_output(self.adapter.execute(
            "SELECT COALESCE(json_agg(data ORDER BY data->>'id'),'[]'::json) FROM (SELECT "
            "json_build_object('id',id,'isThirdPartyCamera',\"isThirdPartyCamera\",'isPairedWithAiPort',\"isPairedWithAiPort\",%s) AS data "
            "FROM cameras WHERE id IN (%s)) selected;" % (fields, ",".join(sql_text(value) for value in selected))))
        if not isinstance(rows, list) or sorted(row.get("id", "") for row in rows) != selected:
            raise FeatureError("Selected cameras do not all exist")
        for row in rows:
            if row.get("isThirdPartyCamera") is not True or row.get("isPairedWithAiPort") is not False:
                raise FeatureError("Only unpaired third-party cameras may receive adapter feature flags")
            if not isinstance(row.get("featureFlags"), dict) or not isinstance(row.get("smartDetectSettings"), dict) or not isinstance(row.get("smartDetectZones"), list):
                raise FeatureError("Invalid persisted camera feature representation")
        return rows

    def plan(self, ids):
        rows = self._read(ids)
        result = {"schemaVersion": 1, "protectVersion": VERSION, "cameraIds": camera_ids(ids),
                  "state": "prepared", "cameras": []}
        for row in rows:
            original = {field: row[field] for field in _BACKUP_CAMERA_FIELDS}
            desired = json.loads(json.dumps(original))
            zones = original["smartDetectZones"]
            if zones and zones != [INTEGRATION_ZONE]:
                raise FeatureError("Existing camera zones cannot be replaced by a non-spatial source integration")
            desired["featureFlags"].update(hasSmartDetect=True, smartDetectTypes=DETECTION_CLASSES)
            desired["smartDetectZones"] = [INTEGRATION_ZONE]
            result["cameras"].append({"id": row["id"], "original": original, "configured": desired})
        result["managedFields"] = list(_CAMERA_FIELDS)
        result["nativeRecognitionSettingsPreserved"] = True
        result["userAgreementUnchanged"] = True
        return result

    @staticmethod
    def public_plan(plan):
        return {"protectVersion": VERSION, "cameraIds": plan["cameraIds"], "fields": list(_CAMERA_FIELDS),
                "hasSmartDetect": True, "smartDetectTypes": DETECTION_CLASSES,
                "zone": INTEGRATION_ZONE, "restartRequired": True,
                "nativeRecognitionSettingsPreserved": True, "userAgreementUnchanged": True}

    @staticmethod
    def _sql(plan, restore=False):
        from .native import sql_text
        selected = camera_ids(plan["cameraIds"])
        if plan.get("schemaVersion") != 1 or plan.get("protectVersion") != VERSION:
            raise FeatureError("Unknown camera feature manifest version")
        if sorted(row.get("id", "") for row in plan["cameras"]) != selected:
            raise FeatureError("Camera feature manifest identities differ")
        lines = ["BEGIN;", "SET LOCAL statement_timeout='10s';", "SET LOCAL lock_timeout='2s';",
                 "SELECT pg_advisory_xact_lock(hashtextextended('reolink-protect-events:features',0));",
                 "DO $rpe_features$ DECLARE n integer; BEGIN"]
        for row in plan["cameras"]:
            previous, target = (row["configured"], row["original"]) if restore else (row["original"], row["configured"])
            if not set(_CAMERA_FIELDS).issubset(previous) or not set(_CAMERA_FIELDS).issubset(target) or (
                    not set(previous).issubset(_BACKUP_CAMERA_FIELDS) or not set(target).issubset(_BACKUP_CAMERA_FIELDS)):
                raise FeatureError("Camera feature manifest contains unexpected fields")
            def value(item):
                return sql_text(json.dumps(item, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            set_values = ",".join('"%s"=%s::json' % (field, value(target[field])) for field in _CAMERA_FIELDS)
            # Legacy manifests also back up native smartDetectSettings. That
            # field is deliberately excluded from every write and rollback.
            # Permit original/configured per managed field; other changes fail.
            comparisons = " AND ".join('(\"%s\"::jsonb=%s::jsonb OR \"%s\"::jsonb=%s::jsonb)'
                % (field, value(previous[field]), field, value(target[field])) for field in _CAMERA_FIELDS)
            lines.append("UPDATE cameras SET %s,\"updatedAt\"=CURRENT_TIMESTAMP WHERE id=%s AND \"isThirdPartyCamera\"=true AND \"isPairedWithAiPort\"=false AND (%s);\n"
                         "GET DIAGNOSTICS n = ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'Camera feature precondition changed'; END IF;"
                         % (set_values, sql_text(row["id"]), comparisons))
        lines.extend(["END $rpe_features$;", "SELECT json_build_object('configuredCameras',%d);" % len(selected), "COMMIT;"])
        return "\n".join(lines)

    def apply(self, ids, backup_dir):
        from .native import _read_json_output
        plan = self.plan(ids)
        root = Path(backup_dir)
        if root.is_symlink():
            raise FeatureError("Backup directory must not be a symlink")
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        path = root / ("cameras-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + os.urandom(4).hex() + ".json")
        _atomic_write(path, json.dumps(plan, ensure_ascii=False, indent=2).encode("utf-8"), 0o600)
        result = _read_json_output(self.adapter.execute(self._sql(plan)))
        if result != {"configuredCameras": len(plan["cameraIds"])}:
            raise FeatureError("Camera configuration returned an unexpected result; reconcile the saved manifest")
        plan["state"] = "applied"
        _atomic_write(path, json.dumps(plan, ensure_ascii=False, indent=2).encode("utf-8"), 0o600)
        return {"manifest": str(path.resolve()), "configuredCameras": len(plan["cameraIds"]), "restartRequired": True}

    def rollback(self, manifest_path):
        from .native import _read_json_output
        path = Path(manifest_path)
        plan = json.loads(path.read_text(encoding="utf-8"))
        self._read(plan["cameraIds"])
        result = _read_json_output(self.adapter.execute(self._sql(plan, restore=True)))
        if result != {"configuredCameras": len(plan["cameraIds"])}:
            raise FeatureError("Camera rollback returned an unexpected result")
        plan["state"] = "rolled_back"
        _atomic_write(path, json.dumps(plan, ensure_ascii=False, indent=2).encode("utf-8"), 0o600)
        return {"state": "rolled_back", "cameras": len(plan["cameraIds"]), "restartRequired": True}


def configure_cameras(adapter, ids, backup_dir):
    return CameraFeatures(adapter).apply(ids, backup_dir)


def _atomic_write(path, content, mode, uid=None, gid=None):
    path = Path(path)
    descriptor, name = tempfile.mkstemp(prefix=".reolink-protect-events-", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.chmod(temporary, mode)
            if uid is not None and hasattr(os, "chown"):
                os.chown(temporary, uid, gid)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


class FeaturePatch:
    def __init__(self, version_reader=None, ui_paths=None, service_path=SERVICE,
                 ui_hash=UI_HASH, service_hash=SERVICE_HASH):
        self.version_reader = version_reader or _version
        self.ui_paths = [Path(value) for value in (ui_paths or [UI_ROOT + "/swai-7.3.26.js", UI_ROOT + "/swai.js"])]
        self.service_path = Path(service_path)
        self.expected = {"ui": ui_hash, "all_ui_alarm_scope": service_hash}

    def guard_version(self):
        if self.version_reader() != VERSION:
            raise FeatureError("Only the inspected Protect 7.3.70 package is supported")

    def plan(self, ids, include_alarm_scope=False):
        self.guard_version()
        selected = camera_ids(ids)
        files = [(path, "ui") for path in self.ui_paths]
        if include_alarm_scope:
            files.append((self.service_path, "all_ui_alarm_scope"))
        plan = []
        for path, kind in files:
            if path.is_symlink() or not path.is_file():
                raise FeatureError("Protect patch target must be a regular, non-symlink file")
            content = path.read_bytes()
            before = sha256(content)
            if before != self.expected[kind]:
                raise FeatureError("Protect file differs from the inspected package hash")
            patched = patched_bytes(content, selected, kind)
            info = path.stat()
            plan.append({"path": str(path.resolve()), "kind": kind, "beforeSha256": before,
                         "afterSha256": sha256(patched), "beforeBytes": len(content),
                         "afterBytes": len(patched), "mode": stat.S_IMODE(info.st_mode),
                         "uid": getattr(info, "st_uid", None), "gid": getattr(info, "st_gid", None),
                         "original": content, "patched": patched})
        return plan

    @staticmethod
    def public_plan(plan):
        return [{key: value for key, value in item.items() if key not in ("original", "patched")}
                for item in plan]

    def apply(self, ids, backup_dir, include_alarm_scope=False):
        plan = self.plan(ids, include_alarm_scope)
        root = Path(backup_dir)
        if root.is_symlink():
            raise FeatureError("Backup directory must not be a symlink")
        root = root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        folder = root / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + os.urandom(4).hex())
        folder.mkdir(mode=0o700)
        manifest = {"schemaVersion": 1, "protectVersion": VERSION, "cameraIds": camera_ids(ids),
                    "files": self.public_plan(plan), "state": "prepared"}
        for index, item in enumerate(plan):
            backup = folder / (str(index) + ".original")
            _atomic_write(backup, item["original"], 0o600)
            manifest["files"][index]["backup"] = backup.name
        manifest_path = folder / "manifest.json"
        _atomic_write(manifest_path, json.dumps(manifest, indent=2).encode(), 0o600)
        written = []
        try:
            for item in plan:
                # Close the time between preflight and replacement without
                # overwriting an intervening Protect update or other patch.
                if sha256(Path(item["path"]).read_bytes()) != item["beforeSha256"]:
                    raise FeatureError("Protect patch target changed after preflight")
                _atomic_write(item["path"], item["patched"], item["mode"], item["uid"], item["gid"])
                written.append(item)
            manifest["state"] = "applied"
            _atomic_write(manifest_path, json.dumps(manifest, indent=2).encode(), 0o600)
        except Exception:
            for item in reversed(written):
                if sha256(Path(item["path"]).read_bytes()) == item["afterSha256"]:
                    _atomic_write(item["path"], item["original"], item["mode"], item["uid"], item["gid"])
            raise
        return str(manifest_path)

    def rollback(self, manifest_path):
        self.guard_version()
        path = Path(manifest_path).resolve()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("schemaVersion") != 1 or manifest.get("protectVersion") != VERSION:
            raise FeatureError("Unknown patch manifest format or Protect version")
        allowed = {str(item.resolve()) for item in self.ui_paths + [self.service_path]}
        prepared = []
        for item in manifest["files"]:
            target = Path(item["path"])
            backup = (path.parent / item["backup"]).resolve()
            if str(target.resolve()) not in allowed or backup.parent != path.parent or target.is_symlink():
                raise FeatureError("Patch manifest target or backup is outside the allowed paths")
            original = backup.read_bytes()
            if sha256(original) != item["beforeSha256"] or item["beforeSha256"] != self.expected[item["kind"]]:
                raise FeatureError("Patch backup differs from the inspected package")
            current_hash = sha256(target.read_bytes())
            if current_hash not in (item["beforeSha256"], item["afterSha256"]):
                raise FeatureError("Protect file changed; rollback must not overwrite it")
            prepared.append((item, original))
        for item, original in prepared:
            _atomic_write(item["path"], original, item["mode"], item["uid"], item["gid"])
        manifest["state"] = "rolled_back"
        _atomic_write(path, json.dumps(manifest, indent=2).encode(), 0o600)
        return {"state": "rolled_back", "files": len(prepared)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inspect", "apply", "rollback", "camera-plan", "configure-cameras", "rollback-cameras"))
    parser.add_argument("--camera", action="append", default=[])
    parser.add_argument("--backup-dir", default="/data/reolink-protect-events/feature-backups")
    parser.add_argument("--manifest")
    parser.add_argument("--include-all-ui-alarm-scope", action="store_true")
    args = parser.parse_args()
    if args.action in ("camera-plan", "configure-cameras", "rollback-cameras"):
        from .native import NativeAdapter
        cameras = CameraFeatures(NativeAdapter())
        if args.action == "camera-plan":
            result = cameras.public_plan(cameras.plan(args.camera))
        elif args.action == "configure-cameras":
            result = cameras.apply(args.camera, args.backup_dir)
        else:
            if not args.manifest:
                parser.error("rollback-cameras requires --manifest")
            result = cameras.rollback(args.manifest)
        print(json.dumps(result, ensure_ascii=False))
        return
    patch = FeaturePatch()
    if args.action == "inspect":
        result = {"protectVersion": VERSION, "files": patch.public_plan(patch.plan(args.camera, args.include_all_ui_alarm_scope))}
    elif args.action == "apply":
        result = {"manifest": patch.apply(args.camera, args.backup_dir, args.include_all_ui_alarm_scope),
                  "restartRequired": True}
    else:
        if not args.manifest:
            parser.error("rollback requires --manifest")
        result = patch.rollback(args.manifest)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
