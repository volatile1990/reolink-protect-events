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
import ssl
import time
import urllib.error
import urllib.request

CLASSES = frozenset(("person", "vehicle", "animal"))
RAW_CLASSES = {"people": "person", "person": "person", "human": "person", "pedestrian": "person",
               "car": "vehicle", "vehicle": "vehicle", "dog_cat": "animal", "dogcat": "animal",
               "animal": "animal", "pet": "animal", "dog": "animal", "cat": "animal"}


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
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("http_redirect_rejected")


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))


def fetch_bridge(bridge, after):
    request = urllib.request.Request("http://" + bridge["host"] + ":8080/events?after=" + str(after) + "&limit=256")
    token = base64.b64encode((bridge["username"] + ":" + bridge["password"]).encode()).decode()
    request.add_header("Authorization", "Basic " + token)
    with opener().open(request, timeout=4) as response:
        data = response.read(512001)
        if len(data) > 512000:
            raise ValueError("oversized_bridge_response")
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
    """Ask Protect for the recorded frame at the original source timestamp."""
    from .native import Thumbnail
    headers = {"X-UserId": config["protectUserId"], "X-UserRole": "owner", "X-UserPermissionMask": "64",
               "X-UserPermissions": "65535", "X-Internal-Use": "true"}
    path = "/api/cameras/" + interval["cameraId"] + "/snapshot?ts=" + str(interval["start"])
    with opener().open(urllib.request.Request("http://127.0.0.1:7080" + path, headers=headers), timeout=5) as response:
        content = response.read(2097153)
        if response.status != 200 or len(content) > 2097152:
            raise ValueError("invalid_recording_thumbnail")
    thumbnail = Thumbnail(content, interval["start"])
    thumbnail.dimensions()
    return thumbnail


class Journal:
    def __init__(self, path, stale_seconds=120):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
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

    def cursor(self, camera):
        row = self.db.execute("SELECT instance,seq,epoch FROM cursors WHERE camera=?", (camera,)).fetchone()
        return dict(zip(("instance", "seq", "epoch"), row)) if row else {"instance": None, "seq": 0, "epoch": None}

    def count(self, name, amount=1):
        self.db.execute("INSERT INTO counters VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value", (name, amount))

    def _close(self, row, at, reason, source=None):
        event_id, start, last_seen, provenance = row
        meta = json.loads(provenance)
        meta["closureReason"] = reason
        meta["endIsTimeoutEstimate"] = reason != "camera_clear" or at > last_seen + self.stale_ms
        meta["endBasis"] = "camera_clear_received_utc" if not meta["endIsTimeoutEstimate"] else "source_stale_or_connection_boundary"
        if source is not None:
            meta["lastSourceEvent"] = source
        end = max(start + 1, min(at, last_seen + self.stale_ms))
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
            if at > int(time.time() * 1000) + 300000:
                raise ValueError("future_source_timestamp")
            epoch = event.get("source", {}).get("connectionEpoch")
            if type(epoch) is not int or epoch < 0:
                raise ValueError("invalid_source_epoch")
            validated.append((sequence, at, epoch, event, source_classes(event)))
            prior_seq = sequence
        with self.db:
            current = self.cursor(camera)
            if current["instance"] != instance:
                self._close_camera(camera, int(time.time() * 1000), "bridge_restart")
                current = {"instance": instance, "seq": 0, "epoch": None}
            if oldest > current["seq"] + 1:
                self.count("replayGaps")
                self._close_camera(camera, int(time.time() * 1000), "replay_gap")
            for sequence, at, epoch, event, classes in validated:
                if sequence <= current["seq"]:
                    continue
                if current["epoch"] is not None and current["epoch"] != epoch:
                    self._close_camera(camera, at, "source_reconnect")
                self.db.execute("INSERT OR IGNORE INTO sources VALUES(?,?,?,?,?)",
                                (camera, instance, sequence, at, json.dumps(event)))
                active = self.db.execute("SELECT id,class,start,last_seen,provenance FROM intervals WHERE camera=? AND end IS NULL", (camera,)).fetchall()
                active_classes = set()
                for event_id, label, start, last_seen, provenance in active:
                    if at < start:
                        raise ValueError("nonmonotonic_source_timestamp")
                    if label not in classes:
                        self._close((event_id, start, last_seen, provenance), at, "camera_clear", event)
                    elif at - last_seen >= self.stale_ms:
                        self._close((event_id, start, last_seen, provenance), last_seen + self.stale_ms, "source_stale")
                    else:
                        self.db.execute("UPDATE intervals SET last_seen=? WHERE id=?", (at, event_id))
                        active_classes.add(label)
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
            self.db.execute("INSERT INTO cursors VALUES(?,?,?,?) ON CONFLICT(camera) DO UPDATE SET instance=excluded.instance,seq=excluded.seq,epoch=excluded.epoch",
                            (camera, instance, current["seq"], current["epoch"]))

    def expire(self, now_ms):
        with self.db:
            for row in self.db.execute("SELECT id,start,last_seen,provenance FROM intervals WHERE end IS NULL AND last_seen+?<=?", (self.stale_ms, now_ms)).fetchall():
                self._close(row, row[2] + self.stale_ms, "source_stale")

    def pending(self):
        rows = self.db.execute("SELECT i.id,i.camera,i.class,i.start,i.end,i.provenance,i.revision,i.delivered_revision,i.notified_revision FROM intervals i LEFT JOIN delivery_failures f ON f.event_id=i.id WHERE (i.delivered_revision<i.revision OR i.notified_revision<i.revision) AND COALESCE(f.next_attempt,0)<=? ORDER BY i.start LIMIT 16", (int(time.time() * 1000),)).fetchall()
        return [{"eventId": r[0], "cameraId": r[1], "classes": [r[2]], "start": r[3], "end": r[4],
                 "provenance": json.loads(r[5]), "revision": r[6], "deliveredRevision": r[7], "notifiedRevision": r[8]} for r in rows]

    def acknowledge(self, event_id, revision, stage):
        if stage not in ("delivered", "notified"):
            raise ValueError("invalid_delivery_stage")
        with self.db:
            self.db.execute("UPDATE intervals SET " + stage + "_revision=MAX(" + stage + "_revision,?) WHERE id=?", (revision, event_id))
            if stage == "notified":
                self.db.execute("DELETE FROM delivery_failures WHERE event_id=?", (event_id,))

    def delivery_failed(self, event_id, now_ms):
        with self.db:
            row = self.db.execute("SELECT attempts FROM delivery_failures WHERE event_id=?", (event_id,)).fetchone()
            attempts = (row[0] if row else 0) + 1
            retry = now_ms + min(300000, 1000 * 2 ** min(attempts, 8))
            self.db.execute("INSERT INTO delivery_failures VALUES(?,?,?) ON CONFLICT(event_id) DO UPDATE SET attempts=excluded.attempts,next_attempt=excluded.next_attempt", (event_id, attempts, retry))

    def health(self):
        return {"counters": dict(self.db.execute("SELECT name,value FROM counters")),
                "pending": self.db.execute("SELECT COUNT(*) FROM intervals WHERE delivered_revision<revision OR notified_revision<revision").fetchone()[0],
                "openIntervals": self.db.execute("SELECT COUNT(*) FROM intervals WHERE end IS NULL").fetchone()[0],
                "pendingThumbnails": self.db.execute("SELECT COUNT(*) FROM media WHERE done=0 AND attempts<20").fetchone()[0],
                "failedThumbnails": self.db.execute("SELECT COUNT(*) FROM media WHERE done=0 AND attempts>=20").fetchone()[0],
                "retryIntervals": self.db.execute("SELECT COUNT(*) FROM delivery_failures").fetchone()[0],
                "sourceRows": self.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]}

    def pending_media(self, now_ms):
        rows = self.db.execute("SELECT i.id,i.camera,i.class,i.start,i.end,i.provenance,i.delivered_revision FROM media m JOIN intervals i ON i.id=m.event_id WHERE m.done=0 AND m.attempts<20 AND m.last_attempt<? AND i.start<? AND i.delivered_revision=i.revision ORDER BY i.start LIMIT 4",
                               (now_ms - 15000, now_ms - 1500)).fetchall()[:1]
        return [{"eventId": r[0], "cameraId": r[1], "classes": [r[2]], "start": r[3], "end": r[4], "provenance": json.loads(r[5]), "deliveredRevision": r[6]} for r in rows]

    def media_attempt(self, event_id, now_ms, success):
        with self.db:
            self.db.execute("UPDATE media SET attempts=attempts+1,last_attempt=?,done=? WHERE event_id=?", (now_ms, int(success), event_id))

    def prune(self, now_ms, days=30):
        """The journal is separate from Protect retention; never resurrect delivered rows."""
        cutoff = now_ms - days * 86400000
        with self.db:
            self.db.execute("DELETE FROM sources WHERE at<?", (cutoff,))
            self.db.execute("DELETE FROM intervals WHERE end<? AND delivered_revision=revision AND notified_revision=revision", (cutoff,))
            self.db.execute("DELETE FROM media WHERE event_id NOT IN (SELECT id FROM intervals)")
            self.db.execute("DELETE FROM delivery_failures WHERE event_id NOT IN (SELECT id FROM intervals)")
        self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")


class Runtime:
    def __init__(self, config, root, capture_only=False):
        self.config = validate_config(config)
        self.root = Path(root)
        self.journal = Journal(self.root / "journal.sqlite3", config.get("bridgeEventStaleSeconds", 120))
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

    def initialize_native(self):
        from .native import NativeAdapter
        from .updates import DsUpdateClient
        for client in self.clients.values():
            client.close()
        self.clients = {}
        self.native = NativeAdapter(protect_version=self.config.get("protectVersion", "7.3.70"))
        self.native.guard_schema()
        for bridge in self.config["bridges"]:
            self.clients[bridge["cameraId"]] = DsUpdateClient(bridge["mac"], port=self.config["dsProxyPort"])
            self.clients[bridge["cameraId"]].connect()
        self.native_ready = True

    def check_native(self):
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
                    client.connect()
                self.native_ready = True
            self.native_error = None
        except Exception as error:
            self.native_ready = False
            self.native_error = type(error).__name__

    def poll_one(self, bridge):
        cursor = self.journal.cursor(bridge["cameraId"])
        response = fetch_bridge(bridge, cursor["seq"])
        if response.get("instanceId") != cursor["instance"] and cursor["seq"]:
            response = fetch_bridge(bridge, 0)
        return response

    def deliver(self):
        from .native import RetiredEventError
        if self.capture_only or not self.native_ready:
            return
        began = time.monotonic()
        for interval in self.journal.pending():
            if time.monotonic() - began > 2:
                break
            try:
                event = self.native.upsert_interval(interval)
                if interval["deliveredRevision"] < interval["revision"]:
                    self.journal.acknowledge(interval["eventId"], interval["revision"], "delivered")
                # Repeated DB writes are idempotent. The WS delivery is at-least-
                # once around a crash; deterministic event IDs prevent duplicate
                # stored detections, but downstream custom alarm actions may repeat.
                client = self.clients[interval["cameraId"]]
                if interval["notifiedRevision"] == 0:
                    start_event = json.loads(json.dumps(event))
                    start_event["end"] = None
                    start_event["metadata"]["zonesStatus"]["1"]["status"] = "enter"
                    client.send_event("add", start_event)
                    if event["end"] is not None:
                        client.send_event("update", event)
                else:
                    client.send_event("update", event)
                self.journal.acknowledge(interval["eventId"], interval["revision"], "notified")
            except RetiredEventError:
                self.journal.acknowledge(interval["eventId"], interval["revision"], "delivered")
                self.journal.acknowledge(interval["eventId"], interval["revision"], "notified")
                self.journal.media_attempt(interval["eventId"], int(time.time() * 1000), True)
                with self.journal.db:
                    self.journal.count("retiredEvents")
            except Exception as error:
                self.import_errors += 1
                self.journal.delivery_failed(interval["eventId"], int(time.time() * 1000))
                # Exception messages and urllib headers can expose credentials.
                print(json.dumps({"error": "native_delivery_failed", "errorType": type(error).__name__}), flush=True)
                continue

    def deliver_media(self, now_ms):
        from .native import RetiredEventError
        if self.capture_only or not self.native_ready:
            return
        for interval in self.journal.pending_media(now_ms):
            success = False
            try:
                thumbnail = recording_thumbnail(self.config, interval)
                event = self.native.upsert_interval(interval, thumbnail)
                self.clients[interval["cameraId"]].send_event("update", event)
                success = True
            except RetiredEventError:
                success = True
                with self.journal.db:
                    self.journal.count("retiredMedia")
            except Exception:
                pass
            self.journal.media_attempt(interval["eventId"], now_ms, success)

    def once(self):
        # Cursor reads occur on this thread because SQLite connections are not
        # shared across worker threads. Workers only perform network requests.
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(self.config["bridges"]))) as pool:
            jobs = {}
            for bridge in self.config["bridges"]:
                cursor = self.journal.cursor(bridge["cameraId"])
                jobs[pool.submit(fetch_bridge, bridge, cursor["seq"])] = (bridge, cursor)
            for job in concurrent.futures.as_completed(jobs):
                bridge, cursor = jobs[job]
                health = self.bridge_health.setdefault(bridge["cameraId"], {"consecutiveErrors": 0})
                try:
                    response = job.result()
                    if response.get("instanceId") != cursor["instance"] and cursor["seq"]:
                        response = fetch_bridge(bridge, 0)
                    self.journal.ingest(bridge, response)
                    health.update(lastSuccessMs=int(time.time() * 1000), consecutiveErrors=0)
                except Exception as error:
                    health["consecutiveErrors"] += 1
                    health["errorType"] = type(error).__name__
        now_ms = int(time.time() * 1000)
        self.journal.expire(now_ms)
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
                      protectVersion=self.config.get("protectVersion", "7.3.70"))
        health["healthy"] = len(self.bridge_health) == len(self.config["bridges"]) and all(
            v.get("lastSuccessMs", 0) >= now_ms - 30000 and v["consecutiveErrors"] == 0 for v in self.bridge_health.values())
        if not self.capture_only:
            health["healthy"] = health["healthy"] and health["pending"] == 0 and self.native_ready
        atomic_json(self.root / "health.json", health)

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        while self.running:
            began = time.monotonic()
            self.once()
            time.sleep(max(0.1, 1 - (time.monotonic() - began)))


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
