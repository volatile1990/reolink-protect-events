"""Optional camera/class time union, retaining independent source lifecycles.

Additional tables are additive. The six original bridge cursors/source payloads
remain compatible with the previous collector. No cross-source object identity
or spatial association is inferred.
"""
import hashlib
import json
import time

from .frigate import classification_details
from .runtime import AUDIO_CLASSES


class Fusion:
    def __init__(self, journal, cameras, options):
        self.journal, self.db, self.cameras, self.options = journal, journal.db, set(cameras), options
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS fusion_cameras(camera TEXT PRIMARY KEY,enabled_at INTEGER);
        CREATE TABLE IF NOT EXISTS fusion_inputs(camera TEXT,source TEXT,source_id TEXT,class TEXT,
          start INTEGER,end INTEGER,last_seen INTEGER,instance TEXT,epoch INTEGER,provenance TEXT,
          PRIMARY KEY(camera,source,source_id,class));
        CREATE INDEX IF NOT EXISTS fusion_inputs_open ON fusion_inputs(camera,source,class) WHERE end IS NULL;
        CREATE INDEX IF NOT EXISTS fusion_inputs_end ON fusion_inputs(camera,class,end);
        CREATE TABLE IF NOT EXISTS fusion_frigate(camera TEXT,source_id TEXT,payload TEXT,end INTEGER,
          last_seen INTEGER,PRIMARY KEY(camera,source_id));
        CREATE TABLE IF NOT EXISTS fusion_poll(camera TEXT PRIMARY KEY,cursor INTEGER,last_success INTEGER);
        CREATE TABLE IF NOT EXISTS fusion_bridge(camera TEXT PRIMARY KEY,instance TEXT,seq INTEGER,epoch INTEGER);
        CREATE TABLE IF NOT EXISTS fusion_dirty(camera TEXT,class TEXT,since INTEGER,PRIMARY KEY(camera,class));
        """)
        if "enabled" not in {row[1] for row in self.db.execute("PRAGMA table_info(fusion_cameras)")}:
            self.db.execute("ALTER TABLE fusion_cameras ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        with self.db:
            for camera in self.cameras:
                saved = self.db.execute("SELECT instance,seq,epoch FROM fusion_bridge WHERE camera=?", (camera,)).fetchone()
                self.db.execute("INSERT INTO fusion_cameras(camera,enabled_at,enabled) VALUES(?,?,1) ON CONFLICT(camera) DO UPDATE SET enabled=1", (camera, int(time.time() * 1000)))
                # Preserve existing Protect identities, source journal, outbox
                # acknowledgements and every old interval when enabling fusion.
                for row in self.db.execute("SELECT id,class,start,end,last_seen,instance,epoch,provenance FROM intervals WHERE camera=?", (camera,)).fetchall():
                    identifier, label, start, end, seen, instance, epoch, raw = row
                    meta = json.loads(raw)
                    if meta.get("sourceUnionVersion") == 1:
                        # Outputs of an earlier union run are NOT a new camera
                        # source. Real legacy intervals created while disabled
                        # must still be adopted on EVERY re-enable.
                        if end is not None and meta.get("closureReason") in ("camera_clear", "source_disconnect", "source_reconnect", "source_stale", "bridge_restart", "replay_gap"):
                            # Legacy collection while disabled can close an
                            # existing union output without adding a push (e.g.
                            # a disconnect). Reconcile that genuine boundary.
                            for active in self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND source='reolink' AND class=? AND end IS NULL AND start<=?", (camera, label, end)).fetchall():
                                self._close(active, end, meta["closureReason"])
                        continue
                    meta.update(sourceUnionVersion=1, identityStart=start, sourceTypes=["reolink"],
                                mergePolicy="camera_class_time_union", objectIdentityMatched=False,
                                source="reolink-camera-ai", classificationOrigin="camera")
                    if saved is None:
                        self.db.execute("INSERT OR IGNORE INTO fusion_inputs VALUES(?,?,?,?,?,?,?,?,?,?)",
                                        (camera, "reolink", "legacy:" + identifier, label, start, end, seen, instance, epoch, raw))
                    else:
                        self.dirty(camera, label, start)
                    self.db.execute("UPDATE intervals SET provenance=? WHERE id=?", (json.dumps(meta), identifier))
                current = self.journal.cursor(camera)
                if saved is None:
                    self.db.execute("INSERT INTO fusion_bridge VALUES(?,?,?,?)", (camera, current["instance"], current["seq"], current["epoch"]))
                elif (current["instance"], current["seq"], current["epoch"]) != saved:
                    # The independent watermark catches genuine pushes already
                    # consumed by a legacy collector during a disabled period.
                    from .runtime import source_classes, timestamp_ms
                    rows = self.db.execute("SELECT seq,payload FROM sources WHERE camera=? AND instance=? AND seq>? ORDER BY seq", (camera, current["instance"], saved[1] if saved[0] == current["instance"] else 0)).fetchall()
                    events = [json.loads(row[1]) for row in rows]
                    validated = [(row[0], timestamp_ms(item["timestampUtc"]), item["source"]["connectionEpoch"], item, source_classes(item)) for row, item in zip(rows, events)]
                    replay = {"instanceId": current["instance"], "oldestSeq": rows[0][0] if rows else current["seq"] + 1,
                              "currentSeq": current["seq"], "events": events}
                    if current["epoch"] is not None:
                        replay["source"] = {"connectionEpoch": current["epoch"], "connected": True}
                    self.reolink({"cameraId": camera}, replay, validated)

    @staticmethod
    def deactivate_unmapped(journal, keep=()):
        """Close only disabled external sources once, using the union-aware code."""
        if not journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='fusion_cameras'").fetchone():
            return
        columns = {row[1] for row in journal.db.execute("PRAGMA table_info(fusion_cameras)")}
        query = "SELECT camera FROM fusion_cameras" + (" WHERE enabled=1" if "enabled" in columns else "")
        cameras = {row[0] for row in journal.db.execute(query)} - set(keep)
        if not cameras:
            return
        options = {"staleSeconds": 120, "finalizeSeconds": 4, "historySeconds": 300}
        disabled = Fusion(journal, cameras, options)
        now = int(time.time() * 1000)
        with journal.db:
            for camera in cameras:
                disabled.close_source(camera, "frigate", now, "source_disabled")
                journal.db.execute("UPDATE fusion_cameras SET enabled=0 WHERE camera=?", (camera,))
        disabled.sync(now + options["finalizeSeconds"] * 1000)

    def dirty(self, camera, label, at):
        self.db.execute("INSERT INTO fusion_dirty VALUES(?,?,?) ON CONFLICT(camera,class) DO UPDATE SET since=MIN(since,excluded.since)", (camera, label, at))

    def _close(self, row, at, reason):
        camera, source, identifier, label, start, seen, raw = row
        meta = json.loads(raw)
        ttl = self.journal.stale_ms if source == "reolink" else self.options["staleSeconds"] * 1000
        end = max(start + 1, seen, min(at, seen + ttl))
        meta.update(closureReason=reason, endIsTimeoutEstimate=reason not in ("camera_clear", "frigate_end"))
        self.db.execute("UPDATE fusion_inputs SET end=?,provenance=? WHERE camera=? AND source=? AND source_id=? AND class=?",
                        (end, json.dumps(meta), camera, source, identifier, label))
        self.dirty(camera, label, start)

    def close_source(self, camera, source, at, reason):
        rows = self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND source=? AND end IS NULL", (camera, source)).fetchall()
        for row in rows:
            self._close(row, at, reason)

    def reolink(self, bridge, response, validated):
        """Consume a validated bridge page using the original durable cursor."""
        camera, instance = bridge["cameraId"], response["instanceId"]
        saved = self.db.execute("SELECT instance,seq,epoch FROM fusion_bridge WHERE camera=?", (camera,)).fetchone()
        current = dict(zip(("instance", "seq", "epoch"), saved)) if saved else self.journal.cursor(camera)
        now = int(time.time() * 1000)
        with self.db:
            if current["instance"] != instance:
                self.close_source(camera, "reolink", now, "bridge_restart")
                current = {"instance": instance, "seq": 0, "epoch": None}
            if response["oldestSeq"] > current["seq"] + 1:
                self.journal.count("replayGaps")
                self.journal.count("replayLostPushes", response["oldestSeq"] - current["seq"] - 1)
                self.close_source(camera, "reolink", now, "replay_gap")
                current["seq"] = response["oldestSeq"] - 1
            for sequence, at, epoch, event, classes in validated:
                if sequence <= current["seq"]:
                    continue
                if current["epoch"] is not None and current["epoch"] != epoch:
                    self.close_source(camera, "reolink", at, "source_reconnect")
                self.db.execute("INSERT OR IGNORE INTO sources VALUES(?,?,?,?,?)", (camera, instance, sequence, at, json.dumps(event)))
                active = set()
                for row in self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND source='reolink' AND end IS NULL", (camera,)).fetchall():
                    label, start, seen = row[3:6]
                    if at < seen:
                        self.journal.count("sourceClockRegressions")
                    if label not in classes:
                        self._close(row, at, "camera_clear")
                    elif at - seen >= self.journal.stale_ms:
                        self._close(row, seen + self.journal.stale_ms, "source_stale")
                    else:
                        self.db.execute("UPDATE fusion_inputs SET last_seen=MAX(last_seen,?) WHERE camera=? AND source='reolink' AND source_id=? AND class=?", (at, camera, row[2], label))
                        active.add(label)
                for label in sorted(classes - active):
                    key = instance + ":" + str(epoch) + ":" + str(sequence)
                    meta = {"source": "reolink-camera-ai", "firstSourceEvent": event, "classificationInferred": False,
                            "timeBasis": "bridge_received_utc", "endIsTimeoutEstimate": False}
                    self.db.execute("INSERT OR IGNORE INTO fusion_inputs VALUES(?,?,?,?,?,NULL,?,?,?,?)",
                                    (camera, "reolink", key, label, at, at, instance, epoch, json.dumps(meta)))
                    self.dirty(camera, label, at)
                self.journal.count("sourceEvents")
                current.update(seq=sequence, epoch=epoch)
            state = response.get("source")
            if state is not None and current["seq"] == response["currentSeq"]:
                if current["epoch"] is not None and (state["connectionEpoch"] != current["epoch"] or not state["connected"]):
                    self.close_source(camera, "reolink", now, "source_disconnect" if not state["connected"] else "source_reconnect")
                current["epoch"] = state["connectionEpoch"]
            self.db.execute("INSERT INTO cursors VALUES(?,?,?,?) ON CONFLICT(camera) DO UPDATE SET instance=excluded.instance,seq=excluded.seq,epoch=excluded.epoch", (camera, instance, current["seq"], current["epoch"]))
            self.db.execute("INSERT INTO fusion_bridge VALUES(?,?,?,?) ON CONFLICT(camera) DO UPDATE SET instance=excluded.instance,seq=excluded.seq,epoch=excluded.epoch", (camera, instance, current["seq"], current["epoch"]))

    def poll_state(self, camera):
        row = self.db.execute("SELECT cursor FROM fusion_poll WHERE camera=?", (camera,)).fetchone()
        ids = [row[0] for row in self.db.execute("SELECT source_id FROM fusion_frigate WHERE camera=? AND end IS NULL", (camera,))]
        return (row[0] if row else None), ids

    def frigate(self, camera, batch):
        """Commit normalized snapshots and completed-window watermark atomically."""
        at = batch["atMs"]
        with self.db:
            previous = self.db.execute("SELECT cursor,last_success FROM fusion_poll WHERE camera=?", (camera,)).fetchone()
            if previous and at - previous[1] > self.options["historySeconds"] * 1000:
                # HTTP history cannot prove its retention floor. Report the
                # uncertainty; never invent a zero-loss sequence guarantee.
                self.journal.count("frigatePossibleHistoryGaps")
            for item in batch["events"]:
                old = self.db.execute("SELECT payload FROM fusion_frigate WHERE camera=? AND source_id=?", (camera, item["id"])).fetchone()
                raw = json.dumps(item, sort_keys=True)
                self.db.execute("INSERT INTO fusion_frigate VALUES(?,?,?,?,?) ON CONFLICT(camera,source_id) DO UPDATE SET payload=excluded.payload,end=excluded.end,last_seen=excluded.last_seen",
                                (camera, item["id"], raw, item["end"], at))
                if item["class"] is None:
                    # A later source correction is not a new detection. Retain
                    # its previous genuine interval, close its active state and
                    # record why it stopped contributing to the union.
                    for row in self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND source='frigate' AND source_id=? AND end IS NULL", (camera, item["id"])).fetchall():
                        self._close(row, at, "frigate_classification_withdrawn")
                    continue
                meta = {"source": "frigate-audio-detection" if item["type"] == "audio" else "frigate-object-detection",
                        "sourceEventId": item["id"], "sourceLabel": item["label"],
                        "topScore": item["topScore"], "falsePositive": item["falsePositive"],
                        "acceptanceBasis": item["acceptanceBasis"], "classificationInferred": True,
                        "timeBasis": "frigate_event_utc", "endIsTimeoutEstimate": False,
                        "closureReason": "frigate_end" if item["end"] is not None else None}
                for row in self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND source='frigate' AND source_id=? AND class<>? AND end IS NULL", (camera, item["id"], item["class"])).fetchall():
                    self._close(row, at, "frigate_classification_changed")
                prior = self.db.execute("SELECT start,end FROM fusion_inputs WHERE camera=? AND source='frigate' AND source_id=? AND class=?", (camera, item["id"], item["class"])).fetchone()
                self.db.execute("INSERT INTO fusion_inputs VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(camera,source,source_id,class) DO UPDATE SET start=excluded.start,end=excluded.end,last_seen=excluded.last_seen,provenance=excluded.provenance",
                                (camera, "frigate", item["id"], item["class"], item["start"], item["end"], at, "frigate-http", 0, json.dumps(meta)))
                if old is None or old[0] != raw or prior != (item["start"], item["end"]):
                    self.dirty(camera, item["class"], item["start"])
            for identifier in batch["missingIds"]:
                # An absent event could be retention/deletion; a 404 is not a
                # fabricated clear. Its last genuine activity expires by TTL.
                self.journal.count("frigateMissingActiveEvents")
            self.db.execute("INSERT INTO fusion_poll VALUES(?,?,?) ON CONFLICT(camera) DO UPDATE SET cursor=excluded.cursor,last_success=excluded.last_success", (camera, batch["cursor"], at))
            self.journal.count("frigatePolls")

    def expire(self, now, replaying=()):
        with self.db:
            for camera in self.cameras:
                for row in self.db.execute("SELECT camera,source,source_id,class,start,last_seen,provenance FROM fusion_inputs WHERE camera=? AND end IS NULL", (camera,)).fetchall():
                    if row[1] == "reolink" and camera in replaying:
                        continue
                    ttl = self.journal.stale_ms if row[1] == "reolink" else self.options["staleSeconds"] * 1000
                    if now >= row[5] + ttl:
                        self._close(row, row[5] + ttl, "source_stale")
            # Expire missing known active IDs too, so deletion cannot create an
            # unbounded per-poll work list. Source intervals preserve their data.
            self.db.execute("UPDATE fusion_frigate SET end=last_seen+? WHERE end IS NULL AND last_seen+?<=?",
                            (self.options["staleSeconds"] * 1000, self.options["staleSeconds"] * 1000, now))

    def sync(self, now):
        """Build connected time components. Existing delivered IDs stay stable.

        If delayed history joins TWO already-published events, retain adjacent
        partitions at their existing start times. Coverage is the exact union
        without duplicate overlapping events; no vendor history is deleted.
        """
        with self.db:
            dirty = self.db.execute("SELECT camera,class,since FROM fusion_dirty").fetchall()
            for camera, label, since in dirty:
                # Expand backwards through the FULL connected history. A new
                # B[290,400] can overlap A[180,300] which overlaps a previously
                # imported R[100,200]. Cutting at 290 would discard R's genuine
                # 100..180 coverage and move the native event start forwards.
                while True:
                    candidates = [since]
                    for table in ("fusion_inputs", "intervals"):
                        row = self.db.execute("SELECT MIN(start) FROM " + table + " WHERE camera=? AND class=? AND (end IS NULL OR end>=?)", (camera, label, since)).fetchone()
                        if row[0] is not None:
                            candidates.append(row[0])
                    earlier = min(candidates)
                    if earlier == since:
                        break
                    since = earlier
                inputs = self.db.execute("SELECT source,source_id,start,end,provenance,last_seen FROM fusion_inputs WHERE camera=? AND class=? AND (end IS NULL OR end>=?) ORDER BY start,source,source_id", (camera, label, since)).fetchall()
                components = []
                for item in inputs:
                    start, end = item[2:4]
                    if not components or (components[-1][1] is not None and start > components[-1][1]):
                        components.append([start, end, [item]])
                    else:
                        current = components[-1]
                        current[1] = None if current[1] is None or end is None else max(current[1], end)
                        current[2].append(item)
                rows = self.db.execute("SELECT id,start,end,provenance FROM intervals WHERE camera=? AND class=? AND (end IS NULL OR end>=?) ORDER BY start,id", (camera, label, since)).fetchall()
                used = set()
                deferred = None
                for start, end, members in components:
                    matches = [row for row in rows if row[0] not in used and (end is None or row[1] <= end) and (row[2] is None or row[2] >= start)]
                    if not matches:
                        key = camera + ":" + label + ":" + ":".join((members[0][0], members[0][1]))
                        identifier = "%08x%s" % (start // 1000, hashlib.sha256(key.encode()).hexdigest()[:16])
                        matches = [(identifier, start, None, json.dumps({"identityStart": start}))]
                    if len(matches) > 1:
                        self.journal.count("lateUnionPartitions")
                    for index, row in enumerate(matches):
                        identifier, old_start, old_end, raw = row
                        used.add(identifier)
                        left = start if index == 0 else old_start
                        right = matches[index + 1][1] if index + 1 < len(matches) else end
                        relevant = [item for item in members if (right is None or item[2] <= right) and (item[3] is None or item[3] >= left)]
                        sources = sorted({item[0] for item in relevant})
                        audio = label in AUDIO_CLASSES
                        meta = {"adapter": "reolink-protect-events", "sourceUnionVersion": 1,
                            "identityStart": json.loads(raw).get("identityStart", old_start),
                            "source": "reolink-and-frigate" if len(sources) > 1 else ("frigate-audio-detection" if audio else "frigate-object-detection") if sources == ["frigate"] else "reolink-camera-ai",
                            "classificationOrigin": "mixed" if len(sources) > 1 else "external-model" if sources == ["frigate"] else "camera",
                            "classificationInferred": "frigate" in sources, "spatialDataAvailable": False,
                            "mergePolicy": "camera_class_time_union", "objectIdentityMatched": False,
                            "timeBasis": "source_interval_union", "sourceTypes": sources,
                            "sourceIntervalCount": len(relevant), "latePartition": len(matches) > 1,
                            "sourceIntervals": [{"source": item[0], "id": item[1], "start": item[2], "end": item[3],
                                "details": json.loads(item[4])} for item in relevant[:16]],
                            "endIsTimeoutEstimate": any(json.loads(item[4]).get("endIsTimeoutEstimate", False) for item in relevant)}
                        # The bounded diagnostic sourceIntervals list is not a
                        # classification limit. Preserve all genuine subtype
                        # evidence across the full connected component, even
                        # when its first occurrence is after the 16th input.
                        detail_values = {}
                        if not audio:
                            for item in relevant:
                                details = json.loads(item[4])
                                if item[0] == "frigate":
                                    for key, values in classification_details(details.get("sourceLabel")).items():
                                        detail_values.setdefault(key, set()).update(values)
                        if detail_values:
                            meta["classificationDetails"] = {key: sorted(values) for key, values in sorted(detail_values.items())}
                        prior_meta = json.loads(raw)
                        if isinstance(prior_meta.get("thumbnailSelection"), dict):
                            # Preserve the exact chosen recorded pixels across
                            # source/score/end updates and media retry boundaries.
                            meta["thumbnailSelection"] = prior_meta["thumbnailSelection"]
                        if right is not None and right > now - self.options["finalizeSeconds"] * 1000:
                            # One source may clear milliseconds before the next
                            # poll discovers the other. Keep the native event
                            # open briefly, without inventing source activity.
                            right = None
                            deferred = start if deferred is None else min(deferred, start)
                        encoded = json.dumps(meta)
                        existing = self.db.execute("SELECT start,end,provenance FROM intervals WHERE id=?", (identifier,)).fetchone()
                        if existing is None:
                            self.db.execute("INSERT INTO intervals(id,camera,class,start,end,last_seen,instance,epoch,provenance) VALUES(?,?,?,?,?,?,?,?,?)",
                                (identifier, camera, label, left, right, max(item[5] for item in relevant), "source-union", 0, encoded))
                            self.db.execute("INSERT OR IGNORE INTO media(event_id) VALUES(?)", (identifier,))
                            self.journal.count("classifiedIntervals")
                        elif existing != (left, right, encoded):
                            self.db.execute("UPDATE intervals SET start=?,end=?,last_seen=?,provenance=?,revision=revision+1 WHERE id=?", (left, right, max(item[5] for item in relevant), encoded, identifier))
                self.db.execute("DELETE FROM fusion_dirty WHERE camera=? AND class=?", (camera, label))
                if deferred is not None:
                    self.dirty(camera, label, deferred)

    def prune(self, cutoff):
        with self.db:
            self.db.execute("DELETE FROM fusion_inputs WHERE end<?", (cutoff,))
            self.db.execute("DELETE FROM fusion_frigate WHERE end<?", (cutoff,))
