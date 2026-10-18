"""Durable source journal and idempotent detection interval outbox (Python 3.9)."""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from .http_deadline import get_bytes

OBJECT_CLASSES = frozenset(("person", "vehicle", "animal"))
AUDIO_CLASSES = frozenset(("babyCry", "bark", "speak", "glassBreak", "siren", "carHorn", "smoke"))
CLASSES = OBJECT_CLASSES | AUDIO_CLASSES
RAW_CLASSES = {"people": "person", "person": "person", "human": "person", "pedestrian": "person",
               "car": "vehicle", "vehicle": "vehicle", "dog_cat": "animal", "dogcat": "animal",
               "animal": "animal", "pet": "animal", "dog": "animal", "cat": "animal",
               "cry": "babyCry", "baby_cry": "babyCry", "babycry": "babyCry"}


def timestamp_ms(value):
    if not isinstance(value, str):
        raise ValueError("invalid_source_timestamp")
    normalized = re.sub(r"([Tt ]\d{2}:\d{2}:\d{2})\.(\d+)",
                        lambda m: m[1] + "." + m[2][:6].ljust(6, "0"), value)
    parsed = datetime.datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("source_timestamp_requires_timezone")
    return int(parsed.timestamp() * 1000)


def source_classes(event):
    """No motion-to-person fallback, face inference, or local image inference."""
    declared = event.get("classes", [])
    raw = event.get("rawAiTypes", [])
    if not isinstance(declared, list) or not isinstance(raw, list):
        raise ValueError("invalid_source_classes")
    # Bridge classes are the authoritative normalized camera-AI fields. A raw
    # recognized AI field also works when motion is false (AI-only camera push).
    return set(x for x in declared if isinstance(x, str) and x in CLASSES) | {
        RAW_CLASSES[x.strip().lower()] for x in raw if isinstance(x, str) and x.strip().lower() in RAW_CLASSES}


def grouping_settings(config):
    """Explicit opt-in, bounded visual presentation; audio stays independent."""
    value = config.get("eventGrouping")
    if value is None:
        return {"enabled": False, "maxSpanSeconds": 120}
    if not isinstance(value, dict) or set(value) - {"enabled", "maxSpanSeconds"}:
        raise ValueError("invalid_event_grouping")
    enabled, span = value.get("enabled", False), value.get("maxSpanSeconds", 120)
    if type(enabled) is not bool or type(span) is not int or not 30 <= span <= 300:
        raise ValueError("invalid_event_grouping")
    return {"enabled": enabled, "maxSpanSeconds": span}


def validate_config(config):
    if not isinstance(config, dict) or not isinstance(config.get("bridges"), list) or not config["bridges"]:
        raise ValueError("invalid_config")
    identities = set()
    hosts = set()
    for bridge in config["bridges"]:
        if not isinstance(bridge, dict) or not re.fullmatch(r"[a-f0-9]{24}", bridge.get("cameraId", "")):
            raise ValueError("invalid_camera_id")
        if bridge["cameraId"] in identities or bridge.get("host") in hosts:
            raise ValueError("duplicate_camera")
        identities.add(bridge["cameraId"])
        hosts.add(bridge.get("host"))
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", bridge.get("host", "")):
            raise ValueError("invalid_bridge_host")
        for field in ("username", "password"):
            if not isinstance(bridge.get(field), str) or not bridge[field] or any(c in bridge[field] for c in "\r\n\0"):
                raise ValueError("invalid_bridge_credentials")
        if ":" in bridge["username"]:
            raise ValueError("invalid_bridge_username")
    stale = config.get("bridgeEventStaleSeconds", 120)
    if type(stale) is not int or not 5 <= stale <= 600:
        raise ValueError("invalid_stale_seconds")
    if config.get("protectVersion", "7.3.70") != "7.3.70":
        raise ValueError("unsupported_protect_version")
    from .thumbnails import settings
    settings(config)
    from .frigate import settings as frigate_settings
    frigate_settings(config)
    grouping_settings(config)
    from .remote import settings as remote_settings
    remote_settings(config)
    return config


def fetch_bridge(bridge, after):
    token = base64.b64encode((bridge["username"] + ":" + bridge["password"]).encode()).decode()
    status, data = get_bytes("http://" + bridge["host"] + ":8080/events?after=" + str(after) + "&limit=256",
                             {"Authorization": "Basic " + token}, timeout=4, limit=512000)
    if status != 200:
        raise ValueError("bridge_http_status")
    return json.loads(data)


def atomic_json(path, value):
    temporary = Path(str(path) + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, ensure_ascii=False)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def recording_thumbnail(config, interval):
    """Select genuine recorded snapshots; preserve the original event timestamp."""
    from .native import Thumbnail
    from .thumbnails import settings, select_recorded
    from .remote import settings as remote_settings
    remote = remote_settings(config)
    snapshot_port = remote["snapshotPort"] if remote is not None else 7080
    headers = {"X-UserId": config["protectUserId"], "X-UserRole": "owner", "X-UserPermissionMask": "64",
               "X-UserPermissions": "65535", "X-Internal-Use": "true"}
    def recorded(timestamp, timeout):
        path = "/api/cameras/" + interval["cameraId"] + "/snapshot?ts=" + str(timestamp)
        status, content = get_bytes("http://127.0.0.1:" + str(snapshot_port) + path,
                                    headers, timeout=timeout, limit=2097152)
        if status != 200:
            raise ValueError("recording_http_" + str(status))
        thumbnail = Thumbnail(content, timestamp)
        thumbnail.dimensions()
        return thumbnail
    options = settings(config)
    return select_recorded(interval, options, recorded) if options["mode"] == "automatic" else recorded(interval["start"], 5)


class Journal:
    def __init__(self, path, stale_seconds=120):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=10)
        os.chmod(path, 0o600)
        self.stale_ms = stale_seconds * 1000
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS cursors(camera TEXT PRIMARY KEY,instance TEXT,seq INTEGER NOT NULL DEFAULT 0,epoch INTEGER);
        CREATE TABLE IF NOT EXISTS sources(camera TEXT,instance TEXT,seq INTEGER,at INTEGER,payload TEXT,
          PRIMARY KEY(camera,instance,seq));
        CREATE TABLE IF NOT EXISTS intervals(id TEXT PRIMARY KEY,camera TEXT,class TEXT,start INTEGER,end INTEGER,
          last_seen INTEGER,instance TEXT,epoch INTEGER,provenance TEXT,revision INTEGER NOT NULL DEFAULT 1,
          delivered_revision INTEGER NOT NULL DEFAULT 0,notified_revision INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS media(event_id TEXT PRIMARY KEY,attempts INTEGER NOT NULL DEFAULT 0,
          last_attempt INTEGER NOT NULL DEFAULT 0,done INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS delivery_failures(event_id TEXT PRIMARY KEY,attempts INTEGER NOT NULL,next_attempt INTEGER NOT NULL);
        """)

        # Additive migration preserves every existing cursor, interval and outbox.
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(media)")}
        for name, definition in (("next_attempt", "INTEGER NOT NULL DEFAULT 0"), ("error_reason", "TEXT"),
                                 ("selection", "TEXT")):
            if name not in columns:
                self.db.execute("ALTER TABLE media ADD COLUMN " + name + " " + definition)
        self.db.executescript("""
        CREATE INDEX IF NOT EXISTS intervals_open ON intervals(camera,last_seen) WHERE end IS NULL;
        CREATE INDEX IF NOT EXISTS intervals_pending ON intervals(start) WHERE delivered_revision<revision OR notified_revision<revision;
        CREATE INDEX IF NOT EXISTS sources_at ON sources(at);
        CREATE INDEX IF NOT EXISTS media_pending ON media(next_attempt,last_attempt) WHERE done=0 AND attempts<20;
        """)
        self.fusion = None
        from .visual_groups import VisualGroups
        self.visual_groups = VisualGroups(self, (), {"enabled": False, "maxSpanSeconds": 120})

    def enable_fusion(self, cameras, options):
        from .fusion import Fusion
        self.fusion = Fusion(self, cameras, options)

    def close(self):
        self.db.close()  # sqlite3.close is idempotent; still enforces owner-thread use.

    def cursor(self, camera):
        row = self.db.execute("SELECT instance,seq,epoch FROM cursors WHERE camera=?", (camera,)).fetchone()
        return dict(zip(("instance", "seq", "epoch"), row)) if row else {"instance": None, "seq": 0, "epoch": None}

    def count(self, name, amount=1):
        self.db.execute("INSERT INTO counters VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (name, amount))

    def counter(self, name):
        """Read one indexed counter without aggregating the publication history."""
        row = self.db.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()
        return row[0] if row else 0

    def _close(self, row, at, reason, source=None):
        event_id, start, last_seen, provenance = row
        meta = json.loads(provenance)
        meta["closureReason"] = reason
        meta["endIsTimeoutEstimate"] = reason != "camera_clear" or at > last_seen + self.stale_ms or at < last_seen
        meta["endBasis"] = "camera_clear_received_utc" if not meta["endIsTimeoutEstimate"] else "source_stale_or_connection_boundary"
        if source is not None:
            meta["lastSourceEvent"] = source
        end = max(start + 1, last_seen, min(at, last_seen + self.stale_ms))
        self.db.execute("UPDATE intervals SET end=?,provenance=?,revision=revision+1 WHERE id=? AND end IS NULL",
                        (end, json.dumps(meta), event_id))

    def _close_camera(self, camera, at, reason):
        for row in self.db.execute("SELECT id,start,last_seen,provenance FROM intervals WHERE camera=? AND end IS NULL", (camera,)).fetchall():
            self._close(row, at, reason)

    def ingest(self, bridge, response):
        camera = bridge["cameraId"]
        instance = response.get("instanceId")
        newest, oldest = response.get("currentSeq"), response.get("oldestSeq")
        events = response.get("events")
        source_state = response.get("source")
        if source_state is not None and (not isinstance(source_state, dict) or
                type(source_state.get("connectionEpoch")) is not int or source_state["connectionEpoch"] < 0 or
                type(source_state.get("connected")) is not bool):
            raise ValueError("invalid_bridge_source_state")
        if not isinstance(instance, str) or not re.fullmatch(r"[a-f0-9]{32}", instance):
            raise ValueError("invalid_bridge_instance")
        if type(newest) is not int or type(oldest) is not int or newest < 0 or not 1 <= oldest <= newest + 1:
            raise ValueError("invalid_bridge_cursor")
        if not isinstance(events, list) or len(events) > 256:
            raise ValueError("invalid_bridge_events")
        # Validate before applying any cursor so malformed data cannot silently
        # skip real detections. Persist original precision and source metadata.
        validated = []
        prior_seq = -1
        for event in events:
            sequence = event.get("seq") if isinstance(event, dict) else None
            if type(sequence) is not int or not oldest <= sequence <= newest or sequence <= prior_seq:
                raise ValueError("invalid_source_sequence")
            at = timestamp_ms(event.get("timestampUtc"))
            if not 0 < at < 0xffffffff * 1000:
                raise ValueError("invalid_source_timestamp_range")
            if at > int(time.time() * 1000) + 300000:
                raise ValueError("future_source_timestamp")
            epoch = event.get("source", {}).get("connectionEpoch")
            if type(epoch) is not int or epoch < 0:
                raise ValueError("invalid_source_epoch")
            validated.append((sequence, at, epoch, event, source_classes(event)))
            prior_seq = sequence
        if self.fusion is not None and camera in self.fusion.cameras:
            self.fusion.reolink(bridge, response, validated)
            return
        with self.db:
            current = self.cursor(camera)
            if current["instance"] != instance:
                self._close_camera(camera, int(time.time() * 1000), "bridge_restart")
                current = {"instance": instance, "seq": 0, "epoch": None}
            if oldest > current["seq"] + 1:
                self.count("replayGaps")
                self.count("replayLostPushes", oldest - current["seq"] - 1)
                self._close_camera(camera, int(time.time() * 1000), "replay_gap")
                # The source explicitly proves these sequences are gone. Advance
                # only to its retention floor, never across an ordinary partial
                # page. An entirely expired replay may therefore be empty.
                current["seq"] = oldest - 1
            for sequence, at, epoch, event, classes in validated:
                if sequence <= current["seq"]:
                    continue
                if current["epoch"] is not None and current["epoch"] != epoch:
                    self._close_camera(camera, at, "source_reconnect")
                self.db.execute("INSERT OR IGNORE INTO sources VALUES(?,?,?,?,?)",
                                (camera, instance, sequence, at, json.dumps(event)))
                active = self.db.execute("SELECT id,class,start,last_seen,provenance FROM intervals WHERE camera=? AND end IS NULL", (camera,)).fetchall()
                active_classes = set()
                regressed = False
                for event_id, label, start, last_seen, provenance in active:
                    if at < last_seen:
                        regressed = True
                        meta = json.loads(provenance)
                        meta["sourceClockRegressed"] = True
                        meta["lastClockRegressionSource"] = event
                        self.db.execute("UPDATE intervals SET provenance=? WHERE id=?", (json.dumps(meta), event_id))
                        provenance = json.dumps(meta)
                    if label not in classes:
                        self._close((event_id, start, last_seen, provenance), at, "camera_clear", event)
                    elif at - last_seen >= self.stale_ms:
                        self._close((event_id, start, last_seen, provenance), last_seen + self.stale_ms, "source_stale")
                    else:
                        self.db.execute("UPDATE intervals SET last_seen=MAX(last_seen,?) WHERE id=?", (at, event_id))
                        active_classes.add(label)
                if regressed:
                    self.count("sourceClockRegressions")
                for label in sorted(classes - active_classes):
                    identity = camera + ":" + instance + ":" + str(epoch) + ":" + str(sequence) + ":" + label
                    event_id = "%08x%s" % (at // 1000, hashlib.sha256(identity.encode()).hexdigest()[:16])
                    provenance = {"adapter": "reolink-protect-events", "source": "reolink-camera-ai",
                        "bridgeInstanceId": instance, "sourceSequence": sequence, "connectionEpoch": epoch,
                        "firstSourceEvent": event, "classificationInferred": False,
                        "timeBasis": "bridge_received_utc", "spatialDataAvailable": False}
                    self.db.execute("INSERT OR IGNORE INTO intervals(id,camera,class,start,last_seen,instance,epoch,provenance) VALUES(?,?,?,?,?,?,?,?)",
                                    (event_id, camera, label, at, at, instance, epoch, json.dumps(provenance)))
                    self.db.execute("INSERT OR IGNORE INTO media(event_id) VALUES(?)", (event_id,))
                    self.count("classifiedIntervals")
                self.count("sourceEvents")
                current.update(seq=sequence, epoch=epoch)
            # Current source state is evaluated AFTER replay: old epoch pushes
            # still carry their real classifications, then the boundary closes
            # them even when the new connection has not pushed another event.
            if source_state is not None and current["seq"] == newest:
                epoch = source_state["connectionEpoch"]
                if current["epoch"] is not None and (epoch != current["epoch"] or not source_state["connected"]):
                    self._close_camera(camera, int(time.time() * 1000),
                                       "source_disconnect" if not source_state["connected"] else "source_reconnect")
                current["epoch"] = epoch
            self.db.execute("INSERT INTO cursors VALUES(?,?,?,?) ON CONFLICT(camera) DO UPDATE SET instance=excluded.instance,seq=excluded.seq,epoch=excluded.epoch",
                            (camera, instance, current["seq"], current["epoch"]))

    def expire(self, now_ms, replaying_cameras=()):
        with self.db:
            for row in self.db.execute("SELECT id,start,last_seen,provenance,camera FROM intervals WHERE end IS NULL AND last_seen+?<=?", (self.stale_ms, now_ms)).fetchall():
                if row[4] not in replaying_cameras and not (self.fusion is not None and row[4] in self.fusion.cameras):
                    self._close(row[:4], row[2] + self.stale_ms, "source_stale")
        if self.fusion is not None:
            self.fusion.expire(now_ms, replaying_cameras)

    def pending(self):
        # The native outbox owns a separate SQLite connection. Enroll before its
        # SELECT under the SAME writer lock: a newly committed source must not
        # race between enrollment and this publication snapshot as a legacy row.
        try:
            with self.db:
                if not self.db.in_transaction:
                    self.db.execute("BEGIN IMMEDIATE")
                self.visual_groups.sync(int(time.time() * 1000))
                rows = self.db.execute("SELECT i.id,i.camera,i.class,i.start,i.end,i.provenance,i.revision,i.delivered_revision,i.notified_revision,i.classes FROM publication_intervals i LEFT JOIN delivery_failures f ON f.event_id=i.id WHERE (i.delivered_revision<i.revision OR i.notified_revision<i.revision) AND COALESCE(f.next_attempt,0)<=? ORDER BY i.start LIMIT 16", (int(time.time() * 1000),)).fetchall()
        except Exception:
            self.visual_groups.invalidate()
            raise
        return [{"eventId": r[0], "cameraId": r[1], "classes": json.loads(r[9]) if r[9] else [r[2]], "start": r[3], "end": r[4],
                 "provenance": json.loads(r[5]), "revision": r[6], "deliveredRevision": r[7], "notifiedRevision": r[8]} for r in rows]

    def publication_table(self, event_id):
        return "visual_groups" if self.db.execute("SELECT 1 FROM visual_groups WHERE id=?", (event_id,)).fetchone() else "intervals"

    def acknowledge(self, event_id, revision, stage):
        if stage not in ("delivered", "notified"):
            raise ValueError("invalid_delivery_stage")
        with self.db:
            self.db.execute("UPDATE " + self.publication_table(event_id) + " SET " + stage + "_revision=MAX(" + stage + "_revision,?) WHERE id=?", (revision, event_id))
            if stage == "notified":
                self.db.execute("DELETE FROM delivery_failures WHERE event_id=?", (event_id,))

    def delivery_failed(self, event_id, now_ms):
        with self.db:
            row = self.db.execute("SELECT attempts FROM delivery_failures WHERE event_id=?", (event_id,)).fetchone()
            attempts = (row[0] if row else 0) + 1
            retry = now_ms + min(300000, 1000 * 2 ** min(attempts, 8))
            self.db.execute("INSERT INTO delivery_failures VALUES(?,?,?) ON CONFLICT(event_id) DO UPDATE SET attempts=excluded.attempts,next_attempt=excluded.next_attempt", (event_id, attempts, retry))

    @staticmethod
    def _media_publications_sql(columns, predicate, *, include_classes=False):
        """Join media to each publication branch without materializing its view.

        CROSS JOIN keeps filtered media as the driver on the console's SQLite.
        Keep the view's UNION ALL and membership predicate exactly: hidden
        sources are excluded, while every group (including manual ones) stays.
        All SQL fragments are fixed internal strings, never external values.
        """
        branches = []
        for table in ("intervals", "visual_groups"):
            selected = columns
            if include_classes:
                selected += "," + ("NULL" if table == "intervals" else "i.classes") + " AS classes"
            # i.id=m.event_id below. Use the driving media key so SQLite can
            # reject hidden members before its interval primary-key lookup.
            membership = " AND NOT EXISTS(SELECT 1 FROM visual_group_members member WHERE member.interval_id=m.event_id)" if table == "intervals" else ""
            branches.append("SELECT " + selected + " FROM media m CROSS JOIN " + table +
                            " i ON i.id=m.event_id WHERE " + predicate + membership)
        return " UNION ALL ".join(branches)

    def _media_publication_count(self, predicate):
        query = self._media_publications_sql("COUNT(*) AS n", predicate)
        return self.db.execute("SELECT SUM(n) FROM (" + query + ")").fetchone()[0]

    def health(self):
        counters = dict(self.db.execute("SELECT name,value FROM counters"))
        oldest = self.db.execute("SELECT MIN(start) FROM publication_intervals WHERE delivered_revision<revision OR notified_revision<revision").fetchone()[0]
        return {"counters": counters,
                "lastNativeDeliveryMs": counters.get("lastNativeDeliveryMs"),
                "oldestPendingStartMs": oldest,
                "oldestPendingAgeMs": max(0, int(time.time() * 1000) - oldest) if oldest is not None else 0,
                "pending": self.db.execute("SELECT COUNT(*) FROM publication_intervals WHERE delivered_revision<revision OR notified_revision<revision").fetchone()[0],
                "openIntervals": self.db.execute("SELECT COUNT(*) FROM publication_intervals WHERE end IS NULL").fetchone()[0],
                "pendingThumbnails": self._media_publication_count("m.done=0 AND m.attempts<20"),
                "failedThumbnails": self._media_publication_count("m.done=0 AND m.attempts>=20"),
                "retryIntervals": self.db.execute("SELECT COUNT(*) FROM delivery_failures").fetchone()[0],
                "sourceRows": self.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
                "thumbnailErrorReasons": dict(self.db.execute("SELECT COALESCE(error_reason,'unknown'),COUNT(*) FROM (" +
                    self._media_publications_sql("m.error_reason AS error_reason", "m.done=0 AND m.error_reason IS NOT NULL") +
                    ") GROUP BY error_reason")),
                "visualGroups": self.db.execute("SELECT COUNT(*) FROM visual_groups").fetchone()[0]}

    def pending_media(self, now_ms):
        query = self._media_publications_sql("i.id,i.camera,i.class,i.start,i.end,i.provenance,i.delivered_revision",
            "m.done=0 AND m.attempts<20 AND m.next_attempt<=? AND m.last_attempt<? AND i.start<? AND i.delivered_revision=i.revision",
            include_classes=True)
        rows = self.db.execute(query + " ORDER BY start LIMIT 1",
                               (now_ms, now_ms - 15000, now_ms - 1500) * 2).fetchall()
        return [{"eventId": r[0], "cameraId": r[1], "classes": json.loads(r[7]) if r[7] else [r[2]], "start": r[3], "end": r[4], "provenance": json.loads(r[5]), "deliveredRevision": r[6]} for r in rows]

    def media_attempt(self, event_id, now_ms, success, error_reason=None):
        with self.db:
            attempts = self.db.execute("SELECT attempts FROM media WHERE event_id=?", (event_id,)).fetchone()
            attempts = attempts[0] if attempts else 0
            delay = min(3600000, 15000 * 2 ** min(attempts, 8))
            self.db.execute("UPDATE media SET attempts=attempts+1,last_attempt=?,done=?,next_attempt=?,error_reason=? WHERE event_id=?",
                            (now_ms, int(success), 0 if success else now_ms + delay, None if success else error_reason or "unknown", event_id))

    def defer_media(self, event_id, ready_at):
        with self.db:
            self.db.execute("UPDATE media SET next_attempt=? WHERE event_id=? AND done=0", (ready_at, event_id))

    def media_interval(self, event_id):
        row = self.db.execute("SELECT id,camera,class,start,end,provenance,delivered_revision,revision,classes FROM publication_intervals WHERE id=?", (event_id,)).fetchone()
        return {"eventId": row[0], "cameraId": row[1], "classes": json.loads(row[8]) if row[8] else [row[2]], "start": row[3], "end": row[4],
                "provenance": json.loads(row[5]), "deliveredRevision": row[6], "revision": row[7]} if row else None

    def media_selection(self, event_id, selection):
        # Preserve source/classification fields. Pin before the native write so
        # a crash after its commit cannot silently choose another sample time.
        with self.db:
            table = self.publication_table(event_id)
            row = self.db.execute("SELECT provenance FROM " + table + " WHERE id=?", (event_id,)).fetchone()
            if row:
                provenance = json.loads(row[0])
                provenance.setdefault("thumbnailSelection", selection)
                self.db.execute("UPDATE " + table + " SET provenance=? WHERE id=?", (json.dumps(provenance), event_id))
                self.db.execute("UPDATE media SET selection=? WHERE event_id=?", (json.dumps(provenance["thumbnailSelection"]), event_id))
                return provenance["thumbnailSelection"]
        return selection

    def retry_media(self, event_ids):
        """Explicitly reopen failed attempts; never reset interval delivery state."""
        if not event_ids or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value) for value in event_ids):
            raise ValueError("explicit_valid_event_ids_required")
        with self.db:
            changed = 0
            for event_id in set(event_ids):
                changed += self.db.execute("UPDATE media SET attempts=0,last_attempt=0,next_attempt=0,error_reason=NULL WHERE event_id=? AND done=0", (event_id,)).rowcount
        return changed

    def prune(self, now_ms, days=30):
        """The journal is separate from Protect retention; never resurrect delivered rows."""
        cutoff = now_ms - days * 86400000
        self.visual_groups.prune(cutoff)
        with self.db:
            self.db.execute("DELETE FROM sources WHERE at<?", (cutoff,))
            self.db.execute("DELETE FROM intervals WHERE end<? AND delivered_revision=revision AND notified_revision=revision AND id NOT IN (SELECT interval_id FROM visual_group_members)", (cutoff,))
            self.db.execute("DELETE FROM media WHERE event_id NOT IN (SELECT id FROM intervals UNION ALL SELECT id FROM visual_groups)")
            self.db.execute("DELETE FROM delivery_failures WHERE event_id NOT IN (SELECT id FROM intervals UNION ALL SELECT id FROM visual_groups)")
        if self.fusion is not None:
            self.fusion.prune(cutoff)
        self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")


class Runtime:
    def __init__(self, config, root, capture_only=False, background_native=True):
        self.config = validate_config(config)
        self.root = Path(root)
        self.journal = Journal(self.root / "journal.sqlite3", config.get("bridgeEventStaleSeconds", 120))
        from .frigate import settings as frigate_settings
        self.frigate_config = frigate_settings(config)
        if self.frigate_config is not None:
            self.journal.enable_fusion(self.frigate_config["cameraMap"].values(), self.frigate_config)
        from .fusion import Fusion
        Fusion.deactivate_unmapped(self.journal, self.frigate_config["cameraMap"].values() if self.frigate_config is not None else ())
        from .visual_groups import VisualGroups
        self.journal.visual_groups = VisualGroups(self.journal,
            [bridge["cameraId"] for bridge in config["bridges"]], grouping_settings(config))
        self.frigate_health = {}
        self._frigate_last_poll = {}
        self.capture_only = capture_only
        self.bridge_health = {}
        self.native = None
        self.clients = {}
        self.running = True
        self.last_prune = 0
        self.import_errors = 0
        self.native_ready = False
        self.native_error = None
        self.last_native_check = 0
        self.background_native = background_native
        self._pool = None
        self._frigate_pool = None
        self._frigate_jobs = {}
        self._media_pool = None
        self._media_future = None
        self._media_event_id = None
        self._native_thread = None
        self._stop = threading.Event()
        self._native_state = {}
        self._state_lock = threading.Lock()
        self.last_poll_duration_ms = 0
        self._closed = False

    def initialize_native(self):
        from .native import adapter_for_config
        from .remote import settings as remote_settings
        from .updates import DsUpdateClient
        for client in self.clients.values():
            client.close()
        self.clients = {}
        self.native = adapter_for_config(self.config)
        self.native.guard_schema()
        remote = remote_settings(self.config)
        ds_port = remote["dsPort"] if remote is not None else self.config["dsProxyPort"]
        for bridge in self.config["bridges"]:
            if self._stop.is_set():
                return
            self.clients[bridge["cameraId"]] = DsUpdateClient(bridge["mac"], port=ds_port)
            self.clients[bridge["cameraId"]].connect()
        self.native_ready = True

    def check_native(self):
        if self._stop.is_set():
            return
        now_ms = int(time.time() * 1000)
        delay = 60000 if self.native_ready else 10000
        if now_ms - self.last_native_check < delay:
            return
        self.last_native_check = now_ms
        try:
            expected = {b["cameraId"] for b in self.config["bridges"]}
            if self.native is None or set(self.clients) != expected:
                self.initialize_native()
            else:
                self.native.guard_schema()
                for client in self.clients.values():
                    if self._stop.is_set():
                        return
                    client.connect()
                self.native_ready = True
            self.native_error = None
        except Exception as error:
            self.native_ready = False
            self.native_error = type(error).__name__

    def poll_one(self, bridge):
        cursor = self.journal.cursor(bridge["cameraId"])
        return self._poll_network(bridge, cursor)[0]

    def _poll_network(self, bridge, cursor):
        if self._stop.is_set():
            raise concurrent.futures.CancelledError()
        began = time.monotonic()
        response = fetch_bridge(bridge, cursor["seq"])
        if response.get("instanceId") != cursor["instance"] and cursor["seq"] and not self._stop.is_set():
            response = fetch_bridge(bridge, 0)
        return response, round((time.monotonic() - began) * 1000, 2)

    def deliver(self):
        from .native import RetiredEventError
        if self.capture_only or not self.native_ready:
            return
        began = time.monotonic()
        for interval in self.journal.pending():
            if self._stop.is_set():
                break
            if time.monotonic() - began > 2:
                break
            try:
                event = self.native.upsert_interval(interval)
                if interval["deliveredRevision"] < interval["revision"]:
                    self.journal.acknowledge(interval["eventId"], interval["revision"], "delivered")
                if self._stop.is_set():
                    break
                # Repeated DB writes are idempotent. The WS delivery is at-least-
                # once around a crash; deterministic event IDs prevent duplicate
                # stored detections, but downstream custom alarm actions may repeat.
                client = self.clients[interval["cameraId"]]
                if interval["notifiedRevision"] == 0:
                    start_event = json.loads(json.dumps(event))
                    start_event["end"] = None
                    if start_event.get("type") != "smartAudioDetect":
                        start_event["metadata"]["zonesStatus"]["1"]["status"] = "enter"
                    client.send_event("add", start_event)
                    if event["end"] is not None:
                        client.send_event("update", event)
                else:
                    client.send_event("update", event)
                self.journal.acknowledge(interval["eventId"], interval["revision"], "notified")
                with self.journal.db:
                    self.journal.db.execute("INSERT INTO counters VALUES('lastNativeDeliveryMs',?) ON CONFLICT(name) DO UPDATE SET value=MAX(value,excluded.value)", (int(time.time() * 1000),))
            except RetiredEventError:
                self.journal.acknowledge(interval["eventId"], interval["revision"], "delivered")
                self.journal.acknowledge(interval["eventId"], interval["revision"], "notified")
                self.journal.media_attempt(interval["eventId"], int(time.time() * 1000), True)
                with self.journal.db:
                    self.journal.count("retiredEvents")
            except Exception as error:
                self.import_errors += 1
                with self.journal.db:
                    self.journal.count("nativeImportErrors")
                self.journal.delivery_failed(interval["eventId"], int(time.time() * 1000))
                # Exception messages and urllib headers can expose credentials.
                print(json.dumps({"error": "native_delivery_failed", "errorType": type(error).__name__}), flush=True)
                continue

    def deliver_media(self, now_ms):
        from .native import RetiredEventError
        from .thumbnails import settings, candidate_times, ThumbnailDeferred, ThumbnailExpired
        if self.capture_only or not self.native_ready:
            return
        future = None
        options = settings(self.config)
        if options["mode"] == "automatic":
            if self._media_future is not None:
                if not self._media_future.done():
                    return
                future = self._media_future
                interval = self.journal.media_interval(self._media_event_id)
                self._media_future = self._media_event_id = None
                if interval is None or interval["deliveredRevision"] != interval["revision"]:
                    return
                intervals = [interval]
            else:
                intervals = self.journal.pending_media(now_ms)
                if not intervals:
                    return
                interval = intervals[0]
                try:
                    candidate_times(interval, options, now_ms)
                except ThumbnailDeferred as deferred:
                    self.journal.defer_media(interval["eventId"], deferred.ready_at)
                    return
                except ThumbnailExpired:
                    self.journal.media_attempt(interval["eventId"], now_ms, True)
                    with self.journal.db:
                        self.journal.count("expiredThumbnailWindows")
                    return
                if self._media_pool is None:
                    self._media_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="recorded-thumbnail")
                self._media_event_id = interval["eventId"]
                self._media_future = self._media_pool.submit(recording_thumbnail, self.config, interval)
                return
        else:
            intervals = self.journal.pending_media(now_ms)
        for interval in intervals:
            if self._stop.is_set():
                break
            success = False
            error_reason = None
            stage = "snapshot"
            try:
                thumbnail = future.result() if future is not None else recording_thumbnail(self.config, interval)
                if self._stop.is_set():
                    break
                # A real clear can shorten an open interval while pixels load.
                # Discard an out-of-interval candidate and resample the new bound.
                if thumbnail.timestamp < interval["start"] or (interval["end"] is not None and thumbnail.timestamp > interval["end"]):
                    with self.journal.db:
                        self.journal.count("thumbnailWindowChanged")
                    continue
                selection = getattr(thumbnail, "selection", None)
                if selection:
                    selection = self.journal.media_selection(interval["eventId"], selection)
                    interval = dict(interval, provenance=dict(interval["provenance"], thumbnailSelection=selection))
                stage = "database"
                event = self.native.upsert_interval(interval, thumbnail)
                if selection:
                    with self.journal.db:
                        self.journal.count("automaticallySelectedThumbnails" if selection["automaticSelected"] else "fallbackThumbnails")
                if self._stop.is_set():
                    break
                stage = "notification"
                self.clients[interval["cameraId"]].send_event("update", event)
                success = True
            except RetiredEventError:
                success = True
                with self.journal.db:
                    self.journal.count("retiredMedia")
            except ThumbnailDeferred as deferred:
                self.journal.defer_media(interval["eventId"], deferred.ready_at)
                continue
            except ThumbnailExpired:
                success = True
                with self.journal.db:
                    self.journal.count("expiredThumbnailWindows")
            except Exception as error:
                # Fixed reason vocabulary; never persist arbitrary messages or headers.
                status = re.fullmatch(r"recording_http_([1-5][0-9]{2})", str(error)) if stage == "snapshot" else None
                error_reason = "snapshot_http_" + status[1] if status else stage + ("_timeout" if isinstance(error, TimeoutError) else "_failed")
            self.journal.media_attempt(interval["eventId"], now_ms, success, error_reason)

    def _native_loop(self):
        # Construct and close the connection on its owner thread. No Python
        # SQLite connection, DS client or native adapter crosses thread ownership.
        worker = None
        try:
            worker = Runtime(self.config, self.root, background_native=False)
            worker._stop = self._stop
            while not self._stop.is_set():
                began = time.monotonic()
                worker.check_native()
                if self._stop.is_set():
                    break
                worker.deliver()
                if self._stop.is_set():
                    break
                worker.deliver_media(int(time.time() * 1000))
                with self._state_lock:
                    self._native_state = {"atMs": int(time.time() * 1000), "nativeReady": worker.native_ready,
                        "nativeError": worker.native_error, "nativeDurationMs": round((time.monotonic() - began) * 1000, 2),
                        "importErrors": worker.journal.counter("nativeImportErrors")}
                self._stop.wait(0.1)
        except Exception as error:
            with self._state_lock:
                self._native_state = {"atMs": int(time.time() * 1000), "nativeReady": False,
                                      "nativeError": type(error).__name__, "workerStopped": True}
        finally:
            if worker is not None:
                if worker._media_pool is not None:
                    worker._media_pool.shutdown(wait=True, cancel_futures=True)
                for client in worker.clients.values():
                    client.close()
                worker.journal.close()

    def _start_native_worker(self):
        if not self.capture_only and self.background_native and self._native_thread is None:
            self._native_thread = threading.Thread(target=self._native_loop, name="protect-native-outbox", daemon=True)
            self._native_thread.start()

    def once(self):
        # Cursor reads occur on this thread because SQLite connections are not
        # shared across worker threads. Workers only perform network requests.
        began = time.monotonic()
        if self._native_thread is not None and not self._native_thread.is_alive() and not self._stop.is_set():
            self._native_thread = None
            self._start_native_worker()
        if self._pool is None:
            self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(self.config["bridges"])), thread_name_prefix="bridge-fetch")
        pool = self._pool
        frigate_jobs = self._frigate_jobs
        if self.frigate_config is not None:
            from .frigate import poll as frigate_poll
            if self._frigate_pool is None:
                self._frigate_pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(self.frigate_config["cameraMap"])), thread_name_prefix="frigate-fetch")
            for name, camera in self.frigate_config["cameraMap"].items():
                if camera in frigate_jobs.values() or time.monotonic() - self._frigate_last_poll.get(camera, -1000000) < self.frigate_config["pollSeconds"]:
                    continue
                cursor, active_ids = self.journal.fusion.poll_state(camera)
                frigate_jobs[self._frigate_pool.submit(frigate_poll, self.frigate_config, name, cursor, active_ids)] = camera
                self._frigate_last_poll[camera] = time.monotonic()
        if pool is not None:
            jobs = {}
            for bridge in self.config["bridges"]:
                cursor = self.journal.cursor(bridge["cameraId"])
                jobs[pool.submit(self._poll_network, bridge, cursor)] = bridge
            for job in concurrent.futures.as_completed(jobs):
                bridge = jobs[job]
                health = self.bridge_health.setdefault(bridge["cameraId"], {"consecutiveErrors": 0})
                try:
                    response, fetch_duration = job.result()
                    self.journal.ingest(bridge, response)
                    sequence = self.journal.cursor(bridge["cameraId"])["seq"]
                    health.update(lastSuccessMs=int(time.time() * 1000), consecutiveErrors=0,
                                  pollDurationMs=fetch_duration,
                                  sourceCurrentSeq=response.get("currentSeq"), journalCursor=sequence,
                                  sourceBacklog=max(0, response["currentSeq"] - sequence),
                                  replayHeadroom=max(0, sequence - response["oldestSeq"] + 1))
                    health.pop("errorType", None)
                except Exception as error:
                    health["consecutiveErrors"] += 1
                    health["errorType"] = type(error).__name__
        # Slow or failed Frigate HTTP calls must not delay the next Reolink
        # capture pass. Only consume completed, bounded network jobs here.
        for job in [job for job in frigate_jobs if job.done()]:
            camera = frigate_jobs.pop(job)
            health = self.frigate_health.setdefault(camera, {"consecutiveErrors": 0})
            try:
                response = job.result()
                self.journal.fusion.frigate(camera, response)
                health.update(lastSuccessMs=int(time.time() * 1000), consecutiveErrors=0,
                              cursorMs=response["cursor"], backlogMs=response["backlogMs"], requests=response["requests"],
                              historyCompleteness="no_sequence_or_retention_floor_proof")
                health.pop("errorType", None)
            except Exception as error:
                health["consecutiveErrors"] += 1
                health["errorType"] = type(error).__name__
        now_ms = int(time.time() * 1000)
        self.last_poll_duration_ms = round((time.monotonic() - began) * 1000, 2)
        replaying = {camera for camera, value in self.bridge_health.items() if value["consecutiveErrors"] == 0 and value.get("sourceBacklog", 0) > 0}
        self.journal.expire(now_ms, replaying)
        if self.journal.fusion is not None:
            self.journal.fusion.sync(now_ms)
        self.journal.visual_groups.sync(now_ms)
        if self._native_thread is None:
            if not self.capture_only:
                self.check_native()
            self.deliver()
            self.deliver_media(now_ms)
        if now_ms - self.last_prune > 3600000:
            self.journal.prune(now_ms)
            self.last_prune = now_ms
        health = self.journal.health()
        health.update(atMs=now_ms, mode="capture" if self.capture_only else "native", bridges=self.bridge_health,
                      importErrors=self.import_errors, nativeReady=self.native_ready, nativeError=self.native_error,
                      protectVersion=self.config.get("protectVersion", "7.3.70"), pollDurationMs=self.last_poll_duration_ms)
        if self._native_thread is not None:
            with self._state_lock:
                native_state = dict(self._native_state)
            health.update({key: value for key, value in native_state.items() if key != "atMs"})
            health["nativeWorkerAgeMs"] = max(0, now_ms - native_state.get("atMs", 0))
            health["nativeReady"] = health.get("nativeReady", False) and health["nativeWorkerAgeMs"] <= 60000 and not native_state.get("workerStopped", False)
        health["healthy"] = len(self.bridge_health) == len(self.config["bridges"]) and all(
            v.get("lastSuccessMs", 0) >= now_ms - 30000 and v["consecutiveErrors"] == 0 for v in self.bridge_health.values())
        if not self.capture_only:
            health["healthy"] = health["healthy"] and health["pending"] == 0 and health["nativeReady"]
        health["captureHealthy"] = len(self.bridge_health) == len(self.config["bridges"]) and all(
            v.get("lastSuccessMs", 0) >= now_ms - 30000 and v["consecutiveErrors"] == 0 for v in self.bridge_health.values())
        if self.frigate_config is not None:
            health["frigate"] = self.frigate_health
            health["frigateHealthy"] = len(self.frigate_health) == len(self.frigate_config["cameraMap"]) and all(
                value.get("lastSuccessMs", 0) >= now_ms - 30000 and value["consecutiveErrors"] == 0
                for value in self.frigate_health.values())
            health["healthy"] = health["healthy"] and health["frigateHealthy"]
            health["captureHealthy"] = health["captureHealthy"] and health["frigateHealthy"]
        atomic_json(self.root / "health.json", health)

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.request_stop())
        signal.signal(signal.SIGINT, lambda *_: self.request_stop())
        self._start_native_worker()
        try:
            while self.running:
                began = time.monotonic()
                self.once()
                time.sleep(max(0.1, 1 - (time.monotonic() - began)))
        finally:
            self.close()

    def request_stop(self):
        self.running = False
        self._stop.set()

    def close(self):
        if self._closed:
            return
        self.request_stop()
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
            self._pool = None
        if self._frigate_pool is not None:
            self._frigate_pool.shutdown(wait=True, cancel_futures=True)
            self._frigate_pool = None
        if self._media_pool is not None:
            self._media_pool.shutdown(wait=True, cancel_futures=True)
            self._media_pool = None
        if self._native_thread is not None:
            self._native_thread.join(timeout=30)
        for client in self.clients.values():
            client.close()
        self.journal.close()
        self._closed = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--capture-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    Runtime(json.loads(Path(args.config).read_text()), args.root, args.capture_only).run()


if __name__ == "__main__":
    main()
