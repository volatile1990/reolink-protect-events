"""Truthful native event persistence for the inspected Protect 7.3.70 schema.

This is a private, version-pinned PostgreSQL integration. It writes camera
classification intervals, never inferred confidence, boxes, embeddings or tracks.
The caller owns source authentication, interval lifecycle and DS notifications.
"""

import hashlib
import json
import re
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Optional


SUPPORTED_PROTECT_VERSION = "7.3.70"
OWNER = "reolink-protect-events"
CLASSES = frozenset(("person", "vehicle", "animal"))
_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SECRET_KEYS = frozenset(("password", "passwd", "secret", "token", "authorization",
                          "apikey", "privatekey", "credentials", "supervisortoken"))


class NativeError(RuntimeError):
    """An operation failed without including SQL, snapshots or credentials."""


class SchemaError(NativeError):
    """The installed version/schema does not match the supported contract."""


class RetiredEventError(NativeError):
    """Protect removed/tombstoned a previously delivered event; do not retry it."""


def _identifier(value, name):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid " + name)
    return value


def _millis(value, name, optional=False):
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**53:
        raise ValueError(name + " must be a positive integer Unix timestamp in milliseconds")
    return value


def _safe_provenance(value, depth=0):
    if depth > 8:
        raise ValueError("Provenance is too deeply nested")
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("Invalid provenance key")
            normalized = re.sub(r"[^a-z]", "", key.lower())
            if normalized in _SECRET_KEYS or normalized.endswith("password") or normalized.endswith("token"):
                raise ValueError("Provenance must not contain access credentials")
            result[key] = _safe_provenance(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError("Provenance collection is too large")
        return [_safe_provenance(item, depth + 1) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, str) and ("\x00" in value or len(value) > 8192):
            raise ValueError("Invalid provenance text")
        # allow_nan=False validates finite numbers when the full object is encoded.
        return value
    raise ValueError("Provenance must contain JSON values")


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def sql_text(value):
    """A UTF-8 SQL expression, safe regardless of quote/backslash settings.

    Data is hex-encoded rather than shell-escaped or interpolated into a DO body.
    It cannot close a SQL quote or the fixed dollar-quoted procedural body.
    """
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("SQL text must be a NUL-free string")
    return "convert_from(decode('" + value.encode("utf-8").hex() + "','hex'),'UTF8')"


def _sql_json(value, kind="json"):
    if kind not in ("json", "jsonb"):
        raise ValueError("Invalid JSON database type")
    return sql_text(_json(value)) + "::" + kind


def native_id(namespace, timestamp_ms, key):
    """Stable ObjectId-shaped ID, timestamp ordered, without random retries."""
    seconds = _millis(timestamp_ms, "timestamp") // 1000
    if seconds > 0xffffffff:
        raise ValueError("Timestamp exceeds the native ID timestamp range")
    digest = hashlib.sha256((OWNER + ":" + namespace + ":" + key).encode("utf-8")).hexdigest()
    return "%08x%s" % (seconds, digest[:16])


def _jpeg_size(content):
    if not isinstance(content, bytes) or len(content) > 2 * 1024 * 1024:
        raise ValueError("Thumbnail must be JPEG bytes of at most 2 MiB")
    if not content.startswith(b"\xff\xd8") or not content.endswith(b"\xff\xd9"):
        raise ValueError("Thumbnail is not a complete JPEG")
    offset = 2
    while offset < len(content) - 2:
        if content[offset] != 0xff:
            break
        while offset < len(content) and content[offset] == 0xff:
            offset += 1
        if offset >= len(content):
            break
        marker = content[offset]
        offset += 1
        if marker in (0x01, 0xd8) or 0xd0 <= marker <= 0xd7:
            continue
        if marker in (0xd9, 0xda) or offset + 2 > len(content):
            break
        length = int.from_bytes(content[offset:offset + 2], "big")
        if length < 2 or offset + length > len(content):
            break
        if marker in (0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf):
            if length < 8:
                break
            height = int.from_bytes(content[offset + 3:offset + 5], "big")
            width = int.from_bytes(content[offset + 5:offset + 7], "big")
            if 0 < width <= 16384 and 0 < height <= 16384:
                return width, height
            break
        offset += length
    raise ValueError("Thumbnail JPEG has no valid dimensions")


@dataclass(frozen=True)
class Thumbnail:
    content: bytes
    timestamp: int
    width: Optional[int] = None
    height: Optional[int] = None

    def dimensions(self):
        _millis(self.timestamp, "thumbnail timestamp")
        width, height = _jpeg_size(self.content)
        if self.width is not None and self.width != width or self.height is not None and self.height != height:
            raise ValueError("Thumbnail dimensions do not match the supplied JPEG")
        return width, height


_REQUIRED_COLUMNS = {
    "events": {"id": "varchar", "type": "varchar", "start": "int8", "end": "int8",
               "cameraId": "varchar", "smartDetectTypes": "json", "metadata": "json",
               "score": "int8", "createdAt": "timestamptz", "updatedAt": "timestamptz",
               "locked": "bool", "thumbnailId": "varchar", "thumbnailFullfovId": "varchar",
               "deletedAt": "timestamptz"},
    "smartDetectObjects": {"id": "varchar", "eventId": "varchar", "cameraId": "varchar",
                           "type": "varchar", "attributes": "json", "metadata": "jsonb",
                           "detectedAt": "int8", "thumbnailId": "varchar",
                           "createdAt": "timestamptz", "updatedAt": "timestamptz"},
    "smartDetectTracks": {"id": "varchar", "eventId": "varchar", "cameraId": "varchar",
                          "payload": "json", "createdAt": "timestamptz", "updatedAt": "timestamptz"},
    "labels": {"id": "varchar", "lid": "int8", "name": "varchar", "lastSeen": "int8",
               "createdAt": "timestamptz", "updatedAt": "timestamptz"},
    "detectionLabels": {"id": "varchar", "eventId": "varchar", "objectId": "varchar",
                        "labels": "_int4", "createdAt": "timestamptz", "updatedAt": "timestamptz"},
    "thumbnails": {"id": "varchar", "eventId": "varchar", "cameraId": "varchar",
                   "content": "bytea", "width": "int8", "height": "int8", "timestamp": "int8",
                   "isFullfov": "bool", "locked": "bool", "createdAt": "timestamptz", "updatedAt": "timestamptz"},
    "cameras": {"id": "varchar"},
}


def _read_json_output(output):
    if not isinstance(output, str):
        raise NativeError("Database executor must return text")
    for line in reversed(output.splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    raise NativeError("Database returned no JSON result")


class NativeAdapter:
    def __init__(self, protect_version=SUPPORTED_PROTECT_VERSION, execute=None,
                 psql_command=None, version_reader=None, timeout=15, guard_interval=60):
        if protect_version != SUPPORTED_PROTECT_VERSION:
            raise SchemaError("Only Protect " + SUPPORTED_PROTECT_VERSION + " is supported")
        self.protect_version = protect_version
        self.timeout = timeout
        self.guard_interval = guard_interval
        self.psql_command = list(psql_command or ["runuser", "-u", "postgres", "--", "psql",
                "-h", "/run/postgresql", "-p", "5433", "-d", "unifi-protect", "-w",
                "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
        self.execute = execute or self._execute
        self.version_reader = version_reader or self._installed_version
        self._guarded_at = None

    def _execute(self, sql):
        try:
            result = subprocess.run(self.psql_command, input=sql, encoding="utf-8",
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout,
                    check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NativeError("Protect database process failed or timed out") from None
        if result.returncode != 0:
            # Only match our fixed SQL error marker. Never expose arbitrary
            # stderr, PL/pgSQL context, SQL values or PostgreSQL diagnostics.
            if "reolink-protect-events:retired" in result.stderr:
                raise RetiredEventError("Previously delivered event was retired by Protect")
            raise NativeError("Protect database operation failed (exit %d)" % result.returncode)
        return result.stdout

    def _installed_version(self):
        try:
            result = subprocess.run(["dpkg-query", "--show", "--showformat=${Version}", "unifi-protect"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
                    timeout=5, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise SchemaError("Cannot verify the installed Protect version") from None
        if result.returncode:
            raise SchemaError("Cannot verify the installed Protect version")
        return result.stdout.strip()

    def guard_schema(self):
        if self.version_reader() != SUPPORTED_PROTECT_VERSION:
            raise SchemaError("Installed Protect version changed; native writes are disabled")
        tables = ",".join(sql_text(name) for name in sorted(_REQUIRED_COLUMNS))
        query = """BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT json_build_object('database',current_database(),'columns',
 COALESCE((SELECT json_agg(json_build_object('table',table_name,'column',column_name,'type',udt_name))
 FROM information_schema.columns WHERE table_schema='public' AND table_name IN (%s)),'[]'::json),
 'indexes',COALESCE((SELECT json_agg(json_build_object('table',tablename,'name',indexname,'definition',indexdef))
 FROM pg_indexes WHERE schemaname='public' AND tablename IN (%s)),'[]'::json));
ROLLBACK;
""" % (tables, tables)
        data = _read_json_output(self.execute(query))
        if not isinstance(data, dict) or data.get("database") != "unifi-protect":
            raise SchemaError("Unexpected Protect database")
        columns = {(item.get("table"), item.get("column")): item.get("type") for item in data.get("columns", [])}
        missing = [(table, column) for table, expected in _REQUIRED_COLUMNS.items()
                   for column, kind in expected.items() if columns.get((table, column)) != kind]
        if missing:
            raise SchemaError("Protect database column contract changed")
        # pg_get_indexdef quotes mixed-case names, but ordinary labels_name_key
        # is normally unquoted. Verify semantics, not the cosmetic quoting.
        definitions = {(item.get("table"), item.get("name")):
            re.sub(r"\s+", " ", item.get("definition", "").replace('"', '').lower()).strip()
            for item in data.get("indexes", [])}
        required_indexes = {
            ("labels", "labels_name_key"):
                "create unique index labels_name_key on public.labels using btree (name)",
            ("detectionLabels", "detectionLabels_eventId_index_unique"):
                "create unique index detectionlabels_eventid_index_unique on public.detectionlabels using btree (eventid) where (objectid is null)",
            ("detectionLabels", "detectionLabels_eventId_objectId_index_unique"):
                "create unique index detectionlabels_eventid_objectid_index_unique on public.detectionlabels using btree (eventid, objectid) where (objectid is not null)",
        }
        if any(definitions.get(key) != expected for key, expected in required_indexes.items()):
            raise SchemaError("Protect database index contract changed")
        self._guarded_at = time.monotonic()
        return {"protectVersion": SUPPORTED_PROTECT_VERSION, "database": "unifi-protect",
                "schemaVerified": True}

    def _ensure_guard(self):
        if self._guarded_at is None or time.monotonic() - self._guarded_at >= self.guard_interval:
            self.guard_schema()

    def build_interval_sql(self, interval, thumbnail=None):
        """Validate input and build one atomic idempotent transaction (no I/O)."""
        if not isinstance(interval, Mapping):
            raise ValueError("Interval must be an object")
        event_id = _identifier(interval.get("eventId"), "eventId")
        camera_id = _identifier(interval.get("cameraId"), "cameraId")
        start = _millis(interval.get("start"), "start")
        end = _millis(interval.get("end"), "end", optional=True)
        if end is not None and end < start:
            raise ValueError("Event end precedes its start")
        delivered_revision = interval.get("deliveredRevision", 0)
        require_existing = interval.get("requireExisting", False)
        if type(delivered_revision) is not int or delivered_revision < 0 or type(require_existing) is not bool:
            raise ValueError("Invalid interval delivery state")
        require_existing = require_existing or delivered_revision > 0
        classes = interval.get("classes")
        if not isinstance(classes, (list, tuple)) or not classes or any(item not in CLASSES for item in classes):
            raise ValueError("Interval requires real person, vehicle or animal classes")
        classes = sorted(set(classes))
        provenance = _safe_provenance(interval.get("provenance", {}))
        if not isinstance(provenance, dict) or not provenance:
            raise ValueError("Source provenance is required")
        if len(_json(provenance).encode("utf-8")) > 32768:
            raise ValueError("Provenance exceeds 32 KiB")
        if isinstance(thumbnail, Mapping):
            thumbnail = Thumbnail(**thumbnail)
        if thumbnail is not None and not isinstance(thumbnail, Thumbnail):
            raise ValueError("Invalid thumbnail")
        metadata = {"source": "reolink-camera-ai", "reolinkProtectEvents": {
            "owner": OWNER, "schemaVersion": 1, "classificationOrigin": "camera",
            "confidenceAvailable": False, "spatialTrackAvailable": False,
            "adapterVirtualZone": True, "sourceZoneIds": [],
            "provenance": provenance},
            # Zone 1 is an integration rule covering this camera, not an object box.
            "zonesStatus": {"1": {"status": "enter" if end is None else "leave"}},
            "loiterStatus": {}, "linesStatus": {},
            "detectedThumbnails": []}
        event = {"id": event_id, "modelKey": "event", "type": "smartDetectZone",
                 "camera": camera_id, "start": start, "end": end, "score": None,
                 "smartDetectTypes": classes, "metadata": metadata,
                 "thumbnail": "e-" + event_id, "thumbnailFullfov": None,
                 "heatmap": "e-" + event_id}
        eid, cid = sql_text(event_id), sql_text(camera_id)
        owner_predicate = "metadata::jsonb->'reolinkProtectEvents'->>'owner'=" + sql_text(OWNER)
        class_sql = _sql_json(classes)
        objects = {kind: native_id("object", start, event_id + ":" + kind) for kind in classes}
        tid = native_id("track", start, event_id)
        thumb_id = None
        preview_id = None
        lines = ["BEGIN;", "SET LOCAL statement_timeout = '10s';",
                 "SET LOCAL lock_timeout = '2s';",
                 "SELECT pg_advisory_xact_lock(hashtextextended(%s,0));" % sql_text(OWNER + ":" + event_id),
                 "DO $rpe$ BEGIN\n IF NOT EXISTS (SELECT 1 FROM cameras WHERE id=%s) THEN RAISE EXCEPTION 'Unknown event camera'; END IF;\n"
                 # The row lock also protects against a concurrent vendor
                 # retention DELETE between this check and the upsert.
                 " PERFORM id FROM events WHERE id=%s FOR UPDATE;\n"
                 " IF %s AND NOT EXISTS (SELECT 1 FROM events WHERE id=%s AND \"deletedAt\" IS NULL) THEN RAISE EXCEPTION USING MESSAGE='reolink-protect-events:retired',ERRCODE='P0002'; END IF;\n"
                 " IF EXISTS (SELECT 1 FROM events WHERE id=%s AND (NOT COALESCE(%s,false) OR type IS DISTINCT FROM 'smartDetectZone' OR \"cameraId\" IS DISTINCT FROM %s OR start IS DISTINCT FROM %d OR \"smartDetectTypes\"::jsonb IS DISTINCT FROM %s::jsonb OR \"deletedAt\" IS NOT NULL)) THEN RAISE EXCEPTION 'Integration event identity collision'; END IF;\n END $rpe$;"
                 % (cid, eid, "true" if require_existing else "false", eid, eid, owner_predicate, cid, start, class_sql)]
        if thumbnail:
            width, height = thumbnail.dimensions()
            thumb_id = native_id("thumbnail", start, event_id)
            preview_id = native_id("preview-thumbnail", start, event_id)
            event["thumbnailFullfov"] = thumb_id
            sid = sql_text(thumb_id)
            lines.append("INSERT INTO thumbnails (id,\"cameraId\",\"eventId\",width,height,timestamp,content,\"isFullfov\",locked,\"createdAt\",\"updatedAt\")\n"
                "VALUES (%s,%s,NULL,%d,%d,%d,decode('%s','hex'),true,false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\n"
                "ON CONFLICT (id) DO NOTHING;" % (sid, cid, width, height, thumbnail.timestamp, thumbnail.content.hex()))
            # Protect's default timeline route selects isFullfov=false OR NULL;
            # its full-FoV route selects true. NULL uses the existing default
            # preview branch without claiming a measured object crop. Both
            # variants contain the genuine recorded full-frame JPEG.
            lines.append("INSERT INTO thumbnails (id,\"cameraId\",\"eventId\",width,height,timestamp,content,\"isFullfov\",locked,\"createdAt\",\"updatedAt\")\n"
                "VALUES (%s,%s,NULL,%d,%d,%d,decode('%s','hex'),NULL,false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\n"
                "ON CONFLICT (id) DO NOTHING;" % (sql_text(preview_id), cid, width, height, thumbnail.timestamp, thumbnail.content.hex()))
            metadata["detectedThumbnails"] = [{"objectId": objects[kind], "clockBestWall": thumbnail.timestamp,
                "type": kind, "croppedId": thumb_id, "attributes": {"objectType": kind, "zone": [1], "adapterVirtualZone": True}}
                for kind in classes]
        # Retain the first thumbnail and a closed end on retries; never reopen a
        # finished interval, unlock an operator's favorite, or reset deletedAt.
        end_sql = "NULL" if end is None else str(end)
        thumb_sql = "NULL" if thumb_id is None else sql_text(thumb_id)
        preview_sql = "NULL" if preview_id is None else sql_text(preview_id)
        lines.append("INSERT INTO events (id,type,start,\"end\",\"cameraId\",score,\"smartDetectTypes\",metadata,locked,\"thumbnailId\",\"thumbnailFullfovId\",\"createdAt\",\"updatedAt\")\n"
            "VALUES (%s,'smartDetectZone',%d,%s,%s,NULL,%s,%s,false,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\n"
            "ON CONFLICT (id) DO UPDATE SET \"end\"=CASE WHEN EXCLUDED.\"end\" IS NULL THEN events.\"end\" ELSE GREATEST(events.\"end\",EXCLUDED.\"end\") END,\n"
            "metadata=((events.metadata::jsonb || EXCLUDED.metadata::jsonb) || jsonb_build_object('detectedThumbnails',CASE WHEN jsonb_array_length(COALESCE(events.metadata::jsonb->'detectedThumbnails','[]'::jsonb))>0 THEN events.metadata::jsonb->'detectedThumbnails' ELSE EXCLUDED.metadata::jsonb->'detectedThumbnails' END,'zonesStatus',jsonb_build_object('1',jsonb_build_object('status',CASE WHEN events.\"end\" IS NOT NULL OR EXCLUDED.\"end\" IS NOT NULL THEN 'leave' ELSE 'enter' END))))::json,\n"
            "\"thumbnailId\"=CASE WHEN events.\"thumbnailId\" IS NULL OR (events.\"thumbnailId\"=events.\"thumbnailFullfovId\" AND events.\"thumbnailId\"=EXCLUDED.\"thumbnailFullfovId\") THEN EXCLUDED.\"thumbnailId\" ELSE events.\"thumbnailId\" END,\"thumbnailFullfovId\"=COALESCE(events.\"thumbnailFullfovId\",EXCLUDED.\"thumbnailFullfovId\"),\"updatedAt\"=CURRENT_TIMESTAMP;"
            % (eid, start, end_sql, cid, class_sql, _sql_json(metadata), preview_sql, thumb_sql))
        if thumb_id:
            for variant_id in (thumb_id, preview_id):
                lines.append("UPDATE thumbnails SET \"eventId\"=%s WHERE id=%s AND \"cameraId\"=%s AND (\"eventId\" IS NULL OR \"eventId\"=%s);"
                             % (eid, sql_text(variant_id), cid, eid))
        label_names = ["eventType:smartDetectZone", "camera:" + camera_id, "zone:" + camera_id + ":1"]
        label_names += ["smartDetectType:" + kind for kind in classes]
        for name in label_names:
            lid = native_id("label", 1000, name)
            lines.append("INSERT INTO labels (id,name,\"lastSeen\",\"createdAt\",\"updatedAt\") VALUES (%s,%s,%d,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\n"
                "ON CONFLICT (name) DO UPDATE SET \"lastSeen\"=GREATEST(labels.\"lastSeen\",EXCLUDED.\"lastSeen\"),\"updatedAt\"=CURRENT_TIMESTAMP;"
                % (sql_text(lid), sql_text(name), end or start))
        for kind, object_id in objects.items():
            attributes = {"objectType": kind, "zone": [1], "adapterVirtualZone": True}
            object_meta = {"reolinkProtectEvents": {"owner": OWNER, "classificationOrigin": "camera",
                                                   "confidenceAvailable": False, "spatialTrackAvailable": False,
                                                   "adapterVirtualZone": True, "sourceZoneIds": []}}
            lines.append("INSERT INTO \"smartDetectObjects\" (id,\"eventId\",\"cameraId\",type,attributes,metadata,\"detectedAt\",\"thumbnailId\",\"createdAt\",\"updatedAt\")\n"
                "VALUES (%s,%s,%s,%s,%s,%s,%d,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\n"
                "ON CONFLICT (id) DO UPDATE SET \"thumbnailId\"=COALESCE(\"smartDetectObjects\".\"thumbnailId\",EXCLUDED.\"thumbnailId\"),\"updatedAt\"=CURRENT_TIMESTAMP\n"
                "WHERE \"smartDetectObjects\".\"eventId\"=EXCLUDED.\"eventId\" AND \"smartDetectObjects\".\"cameraId\"=EXCLUDED.\"cameraId\" AND \"smartDetectObjects\".type=EXCLUDED.type;"
                % (sql_text(object_id), eid, cid, sql_text(kind), _sql_json(attributes), _sql_json(object_meta, "jsonb"), start, thumb_sql))
        lines.append("INSERT INTO \"smartDetectTracks\" (id,\"eventId\",\"cameraId\",payload,\"createdAt\",\"updatedAt\") VALUES (%s,%s,%s,'[]'::json,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (id) DO NOTHING;"
                     % (sql_text(tid), eid, cid))
        def detection_label(object_id, names):
            key = event_id + ":" + (object_id or "event")
            label_id = native_id("detection-label", start, key)
            array_sql = "ARRAY(SELECT lid::integer FROM labels WHERE name IN (%s) ORDER BY lid)" % ",".join(sql_text(n) for n in names)
            object_sql = sql_text(object_id) if object_id else "NULL"
            target = '("eventId","objectId") WHERE "objectId" IS NOT NULL' if object_id else '("eventId") WHERE "objectId" IS NULL'
            return "INSERT INTO \"detectionLabels\" (id,\"eventId\",\"objectId\",labels,\"createdAt\",\"updatedAt\") VALUES (%s,%s,%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)\nON CONFLICT %s DO UPDATE SET labels=EXCLUDED.labels,\"updatedAt\"=CURRENT_TIMESTAMP;" % (sql_text(label_id), eid, object_sql, array_sql, target)
        lines.append(detection_label(None, label_names))
        for kind, oid in objects.items():
            names = [name for name in label_names if not name.startswith("smartDetectType:")]
            lines.append(detection_label(oid, names + ["smartDetectType:" + kind]))
        lines.append("SELECT json_build_object('id',id,'modelKey','event','type',type,'camera',\"cameraId\",'start',start,'end',\"end\",'score',score,'smartDetectTypes',\"smartDetectTypes\",'metadata',metadata,'thumbnail','e-'||id,'thumbnailFullfov',\"thumbnailFullfovId\",'heatmap','e-'||id) FROM events WHERE id=%s;" % eid)
        lines.append("COMMIT;")
        return "\n".join(lines) + "\n", event

    def upsert_interval(self, interval, thumbnail=None):
        sql, _ = self.build_interval_sql(interval, thumbnail)
        self._ensure_guard()
        event = _read_json_output(self.execute(sql))
        if not isinstance(event, dict) or event.get("id") != interval["eventId"]:
            raise NativeError("Native event persistence returned an unexpected identity")
        return event

    def preview_repair_candidates(self, limit=128):
        """List live owned events missing the default thumbnail variant."""
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("Invalid preview repair limit")
        self._ensure_guard()
        sql = """BEGIN READ ONLY;
SET LOCAL statement_timeout='10s';
SELECT COALESCE(jsonb_agg(jsonb_build_object('eventId',r.id,'cameraId',r."cameraId",
 'start',r.start,'fullfovId',r."thumbnailFullfovId")),'[]'::jsonb) FROM (
 SELECT e.id,e."cameraId",e.start,e."thumbnailFullfovId" FROM events e
 JOIN thumbnails f ON f.id=e."thumbnailFullfovId" AND f."eventId"=e.id AND f."cameraId"=e."cameraId"
 WHERE e.metadata::jsonb->'reolinkProtectEvents'->>'owner'=%s
 AND e.type='smartDetectZone' AND e."deletedAt" IS NULL AND f."isFullfov" IS TRUE
 AND octet_length(f.content) BETWEEN 1 AND 2097152
 AND (e."thumbnailId" IS NULL OR e."thumbnailId"=e."thumbnailFullfovId")
 AND NOT EXISTS (SELECT 1 FROM thumbnails p WHERE p."eventId"=e.id
  AND (p."isFullfov" IS NULL OR p."isFullfov" IS FALSE) AND p.content IS NOT NULL)
 ORDER BY e.start LIMIT %d) r;
ROLLBACK;
""" % (sql_text(OWNER), limit)
        result = _read_json_output(self.execute(sql))
        if not isinstance(result, list):
            raise NativeError("Unexpected preview repair plan")
        return result

    def build_preview_repair_sql(self, candidate):
        """Copy existing real bytes without changing the detection graph."""
        eid = sql_text(_identifier(candidate.get("eventId"), "eventId"))
        cid = sql_text(_identifier(candidate.get("cameraId"), "cameraId"))
        start = _millis(candidate.get("start"), "start")
        fid = sql_text(_identifier(candidate.get("fullfovId"), "fullfovId"))
        pid = sql_text(native_id("preview-thumbnail", start, candidate["eventId"]))
        owner = sql_text(OWNER)
        return """BEGIN;
SET LOCAL statement_timeout='10s';
SET LOCAL lock_timeout='2s';
SELECT pg_advisory_xact_lock(hashtextextended(%s,0));
WITH eligible AS (
 SELECT e.id,e."cameraId",e.locked FROM events e
 WHERE e.id=%s AND e."cameraId"=%s AND e.start=%d AND e."thumbnailFullfovId"=%s
 AND e.type='smartDetectZone' AND e."deletedAt" IS NULL
 AND e.metadata::jsonb->'reolinkProtectEvents'->>'owner'=%s
 AND (e."thumbnailId" IS NULL OR e."thumbnailId"=e."thumbnailFullfovId")
 FOR UPDATE OF e
), inserted AS (
 INSERT INTO thumbnails (id,"cameraId","eventId",width,height,timestamp,content,"isFullfov",locked,"createdAt","updatedAt")
 SELECT %s,e."cameraId",e.id,f.width,f.height,f.timestamp,f.content,NULL,(e.locked OR f.locked),CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
 FROM eligible e JOIN thumbnails f ON f.id=%s AND f."eventId"=e.id AND f."cameraId"=e."cameraId"
 WHERE f."isFullfov" IS TRUE AND octet_length(f.content) BETWEEN 1 AND 2097152
 ON CONFLICT (id) DO NOTHING RETURNING "eventId"
)
UPDATE events e SET "thumbnailId"=%s,"updatedAt"=CURRENT_TIMESTAMP
 WHERE e.id IN (SELECT "eventId" FROM inserted);
SELECT json_build_object('id',e.id,'modelKey','event','type',e.type,'camera',e."cameraId",
 'start',e.start,'end',e."end",'score',e.score,'smartDetectTypes',e."smartDetectTypes",'metadata',e.metadata,
 'thumbnail','e-'||e.id,'thumbnailFullfov',e."thumbnailFullfovId",'heatmap','e-'||e.id)
 FROM events e WHERE e.id=%s AND e."cameraId"=%s AND e.start=%d AND e."deletedAt" IS NULL
 AND e.metadata::jsonb->'reolinkProtectEvents'->>'owner'=%s AND e."thumbnailId"=%s
 AND EXISTS (SELECT 1 FROM thumbnails p WHERE p.id=%s AND p."eventId"=e.id
  AND p."cameraId"=e."cameraId" AND (p."isFullfov" IS NULL OR p."isFullfov" IS FALSE));
COMMIT;
""" % (sql_text(OWNER + ":" + candidate["eventId"]), eid, cid, start, fid, owner,
       pid, fid, pid, eid, cid, start, owner, pid, pid)

    def repair_preview_thumbnail(self, candidate):
        sql = self.build_preview_repair_sql(candidate)
        self._ensure_guard()
        output = self.execute(sql)
        # A concurrent retention removal or operator thumbnail change can make
        # the guarded UPDATE/SELECT empty. Nothing may resurrect that event.
        try:
            event = _read_json_output(output)
        except NativeError:
            if output.strip() == "":
                return None
            raise
        if not isinstance(event, dict) or event.get("id") != candidate["eventId"]:
            raise NativeError("Unexpected repaired preview identity")
        return event

    def delete_owned_event(self, event_id):
        """Remove one integration-owned graph for canary rollback, never video."""
        event_id = _identifier(event_id, "eventId")
        self._ensure_guard()
        eid = sql_text(event_id)
        sql = """BEGIN;
SET LOCAL statement_timeout='10s';
SET LOCAL lock_timeout='2s';
SELECT pg_advisory_xact_lock(hashtextextended(%s,0));
DELETE FROM thumbnails WHERE "eventId"=%s AND EXISTS (SELECT 1 FROM events WHERE id=%s AND metadata::jsonb->'reolinkProtectEvents'->>'owner'=%s);
WITH deleted AS (DELETE FROM events WHERE id=%s AND metadata::jsonb->'reolinkProtectEvents'->>'owner'=%s RETURNING id)
SELECT json_build_object('deleted',count(*)) FROM deleted;
COMMIT;
""" % (sql_text(OWNER + ":" + event_id), eid, eid, sql_text(OWNER), eid, sql_text(OWNER))
        return _read_json_output(self.execute(sql))
