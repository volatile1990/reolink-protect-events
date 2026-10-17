"""Additive publication groups for simultaneous visual detections.

The per-class source intervals remain the authoritative journal. Enrollment is
permanent, starts only at activation, and never adopts a published legacy row.
Administrative span partitions are publication boundaries, never camera clears.
Once published, a group's bounded member association survives later genuine
source finalization. Its class coverage may contain honest gaps; those gaps are
never filled with invented camera activity.
"""
import hashlib
import json
import time


VISUAL_CLASSES = frozenset(("person", "vehicle", "animal"))
MANUAL_GROUP_SCHEMA_VERSION = 1

# Explicit historical snapshots are owned by their bounded administrative
# operation. A source shared with an ordinary group remains in the ordinary
# lifecycle; an exclusively manual source must never be clipped by activation
# or reconsidered by the automatic grouper.
_AUTOMATIC_MEMBER = """NOT (
  EXISTS(SELECT 1 FROM visual_group_segments s JOIN visual_group_manual m ON m.group_id=s.group_id
         WHERE s.interval_id=i.id)
  AND NOT EXISTS(SELECT 1 FROM visual_group_segments s LEFT JOIN visual_group_manual m ON m.group_id=s.group_id
                 WHERE s.interval_id=i.id AND m.group_id IS NULL))"""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _merge(ranges):
    """Normalize genuine class coverage; touching ranges have continuous union."""
    result = []
    for start, end in sorted(ranges, key=lambda item: item[0]):
        if end is not None and end <= start:
            continue
        if not result or (result[-1][1] is not None and start > result[-1][1]):
            result.append([start, end])
        else:
            result[-1][1] = None if end is None or result[-1][1] is None else max(result[-1][1], end)
    return result


def _clip(ranges, left, right):
    result = []
    for start, end in ranges:
        start = max(left, start)
        end = right if end is None else end if right is None else min(end, right)
        if end is None or start < end:
            result.append((start, end))
    return _merge(result)


class VisualGroups:
    def __init__(self, journal, cameras, options):
        self.journal, self.db = journal, journal.db
        self.cameras = set(cameras)
        self.enabled = options.get("enabled", False)
        span = options.get("maxSpanSeconds", 120)
        if type(self.enabled) is not bool or type(span) is not int or not 30 <= span <= 300:
            raise ValueError("invalid_visual_group_options")
        self.max_span_ms = span * 1000
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS visual_group_state(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS visual_groups(id TEXT PRIMARY KEY,camera TEXT,class TEXT NOT NULL DEFAULT 'visual',
          start INTEGER NOT NULL,end INTEGER,last_seen INTEGER NOT NULL,provenance TEXT NOT NULL,
          revision INTEGER NOT NULL DEFAULT 1,delivered_revision INTEGER NOT NULL DEFAULT 0,
          notified_revision INTEGER NOT NULL DEFAULT 0,classes TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS visual_group_members(interval_id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS visual_group_segments(group_id TEXT NOT NULL,interval_id TEXT NOT NULL,
          PRIMARY KEY(group_id,interval_id));
        CREATE TABLE IF NOT EXISTS visual_group_manual(group_id TEXT PRIMARY KEY,operation_id TEXT UNIQUE,
          source_ids TEXT,digest TEXT);
        CREATE INDEX IF NOT EXISTS visual_groups_camera ON visual_groups(camera,start);
        CREATE INDEX IF NOT EXISTS visual_group_segments_interval ON visual_group_segments(interval_id);
        CREATE VIEW IF NOT EXISTS publication_intervals AS
          SELECT i.id,i.camera,i.class,i.start,i.end,i.last_seen,i.provenance,i.revision,
            i.delivered_revision,i.notified_revision,NULL AS classes
          FROM intervals i WHERE NOT EXISTS
            (SELECT 1 FROM visual_group_members m WHERE m.interval_id=i.id)
          UNION ALL
          SELECT id,camera,class,start,end,last_seen,provenance,revision,
            delivered_revision,notified_revision,classes FROM visual_groups;
        """)
        with self.db:
            if self.enabled:
                self.db.execute("INSERT OR IGNORE INTO visual_group_state VALUES('activationMs',?)", (int(time.time() * 1000),))
        row = self.db.execute("SELECT value FROM visual_group_state WHERE key='activationMs'").fetchone()
        self.activation_ms = row[0] if row else None
        self.invalidate()

    def invalidate(self):
        """Forget optimization state after a surrounding transaction rolls back."""
        self._camera_signatures = {}
        self._next_due = {}
        self._data_version = None
        self._total_changes = None

    def _ranges(self, row, meta):
        """Use full fusion inputs, rather than its bounded diagnostic list.

        This also removes the fusion finalization hold from class activity.
        A publication event may be open while its genuine class ranges ended.
        """
        identifier, camera, label, start, end = row[:5]
        if meta.get("sourceUnionVersion") == 1 and self.db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='fusion_inputs'").fetchone():
            rows = self.db.execute("SELECT start,end FROM fusion_inputs WHERE camera=? AND class=? "
                                   "AND (? IS NULL OR start<?) AND (end IS NULL OR end>?)",
                                   (camera, label, end, end, start)).fetchall()
            if rows:
                # The raw source commit precedes Fusion.sync. An output held
                # open for finalization must not adopt a later disjoint raw
                # component which has no output/provenance of its own yet.
                # Its actual start also anchors late-history partitions within
                # a larger connected source union.
                connected = [value for value in _merge(rows)
                             if value[0] <= start and (value[1] is None or start < value[1])]
                return _clip(connected, start, end)
        return [(start, end)]

    def sync(self, now):
        """Atomically enroll, group, and revise the publication outbox.

        BEGIN IMMEDIATE serializes the poller and native worker's independent
        SQLite connections before either decides which rows are still legacy.
        """
        data_version = self.db.execute("PRAGMA data_version").fetchone()[0]
        if (data_version == self._data_version and self.db.total_changes == self._total_changes
                and all(now < due for due in self._next_due.values())):
            return
        try:
            if self.db.in_transaction:
                # Journal.pending owns an atomic claim spanning grouping and
                # its view SELECT. Never commit the caller's transaction.
                self._sync(now)
            else:
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    self._sync(now)
        except BaseException:
            self.invalidate()
            raise
        self._data_version = data_version
        self._total_changes = self.db.total_changes

    def _sync(self, now):
        if not self.enabled and not self.db.execute("SELECT 1 FROM visual_group_members LIMIT 1").fetchone():
            return
        if self.enabled and self.activation_ms is not None:
            rows = self.db.execute("SELECT id,camera,class,start,provenance FROM intervals "
                                   "WHERE delivered_revision=0 AND notified_revision=0 AND class IN ('person','vehicle','animal') "
                                   "AND (end IS NULL OR end>=?) AND camera IN (" + ",".join("?" for _ in self.cameras) + ") "
                                   "AND id NOT IN (SELECT interval_id FROM visual_group_members)",
                                   (self.activation_ms, *sorted(self.cameras))).fetchall() if self.cameras else []
            for identifier, camera, label, start, raw in rows:
                identity = json.loads(raw).get("identityStart", start)
                if camera in self.cameras and type(identity) is int and identity >= self.activation_ms:
                    self.db.execute("INSERT OR IGNORE INTO visual_group_members VALUES(?)", (identifier,))
        signatures = {}
        for row in self.db.execute("SELECT i.id,i.camera,i.class,i.start,i.end,i.last_seen,i.revision "
                                   "FROM intervals i JOIN visual_group_members m ON m.interval_id=i.id "
                                   "WHERE " + _AUTOMATIC_MEMBER + " ORDER BY i.id"):
            signatures.setdefault(row[1], []).append(row)
        signatures = {camera: tuple(values) for camera, values in signatures.items()}
        dirty = {camera for camera in set(signatures) | set(self._camera_signatures)
                 if signatures.get(camera) != self._camera_signatures.get(camera)}
        dirty.update(camera for camera, due in self._next_due.items() if now >= due)
        self._camera_signatures = signatures
        if not dirty:
            return
        marks = ",".join("?" for _ in dirty)
        parameters = tuple(sorted(dirty))
        rows = self.db.execute("SELECT i.id,i.camera,i.class,i.start,i.end,i.last_seen,i.provenance "
                               "FROM intervals i JOIN visual_group_members m ON m.interval_id=i.id "
                               "WHERE i.camera IN (" + marks + ") AND " + _AUTOMATIC_MEMBER + " ORDER BY i.start,i.id", parameters).fetchall()
        sources = {}
        for row in rows:
            meta = json.loads(row[6])
            ranges = self._ranges(row, meta)
            sources[row[0]] = {"row": row, "meta": meta,
                               "ranges": _clip(ranges, self.activation_ms, None)}
        old_rows = self.db.execute("SELECT g.id,g.camera,g.start,g.end,g.last_seen,g.provenance,g.classes,g.delivered_revision,g.notified_revision FROM visual_groups g "
                                   "WHERE g.camera IN (" + marks + ") AND NOT EXISTS "
                                   "(SELECT 1 FROM visual_group_manual m WHERE m.group_id=g.id) ORDER BY g.start,g.id", parameters).fetchall()
        old = {row[0]: {"row": row, "meta": json.loads(row[5])} for row in old_rows}
        links = {}
        for group, identifier in self.db.execute("SELECT s.group_id,s.interval_id FROM visual_group_segments s "
                                                 "JOIN visual_groups g ON g.id=s.group_id WHERE g.camera IN (" + marks + ") "
                                                 "AND NOT EXISTS(SELECT 1 FROM visual_group_manual m WHERE m.group_id=g.id)", parameters):
            links.setdefault(group, set()).add(identifier)
        groups_by_source = {}
        for group, identifiers in links.items():
            for identifier in identifiers:
                groups_by_source.setdefault(identifier, set()).add(group)
        by_camera = {}
        for identifier, source in sources.items():
            for start, end in source["ranges"]:
                if start <= now:
                    by_camera.setdefault(source["row"][1], []).append((start, end, identifier, source["row"][2]))
        # Published evidence is monotonic even if a later upstream correction
        # retracts its class or bounds. Preserve it explicitly, without inventing
        # activity in newly uncovered time.
        sticky_by_camera = {}
        for identifier, group in old.items():
            for label, ranges in group["meta"].get("classIntervals", {}).items():
                for value in ranges:
                    # An open bound expresses current source state, not an
                    # immutable assertion that the class stayed active forever.
                    # Let the authoritative source supply its eventual clear.
                    known_class = any(source_id in sources and sources[source_id]["row"][2] == label
                                      and sources[source_id]["ranges"] for source_id in links.get(identifier, ()))
                    if value["end"] is not None and not (known_class and group["meta"].get("administrativePartitionReason")):
                        by_camera.setdefault(group["row"][1], []).append((value["start"], value["end"], "@" + identifier, label))
                    elif value["end"] is None and not known_class:
                        # A withdrawn/reclassified source must not erase a
                        # previously published type. Keep only the finite past
                        # already observed, never the old unbounded state.
                        end = max(value["start"] + 1, group["row"][4])
                        by_camera.setdefault(group["row"][1], []).append((value["start"], end, "@" + identifier, label))
        for identifier, group in old.items():
            if not (group["row"][7] or group["row"][8]):
                continue
            left = group["row"][2]
            right = left + group["meta"]["groupMaxSpanMs"]
            coverage, open_member = [], False
            for member in links.get(identifier, ()):
                source = sources.get(member)
                if source is None:
                    continue
                for start, end in source["ranges"]:
                    if end is None and start < left:
                        continue
                    clipped = _clip([(start, end)], left, right)
                    if clipped:
                        coverage.extend(clipped)
                        open_member = open_member or end is None
            if len(_merge(coverage)) > 1:
                # This is a connectivity constraint for an already published
                # presentation, not a class interval. A delayed real clear can
                # reveal that two members never overlapped. Re-splitting that
                # publication would withdraw a native class and collide with
                # its monotonic class contract. Retain its bounded identity and
                # member association while keeping each real class time exact.
                sticky_by_camera.setdefault(group["row"][1], []).append((
                    identifier, links.get(identifier, set()) | {"@" + identifier},
                    (min(value[0] for value in coverage), None if open_member else max(value[1] for value in coverage),
                     "!published-gap:" + identifier, None)))
        for camera, spans in by_camera.items():
            components = []
            for span in sorted(spans, key=lambda value: (value[0], value[2], value[3])):
                start, end = span[:2]
                observed_end = max(start + 1, now + 1) if end is None else end
                # Strict positive overlap. A merely adjacent delivery is a new
                # component; there is no proximity or object identity heuristic.
                if not components or start >= components[-1][1]:
                    components.append([start, observed_end, [span]])
                else:
                    components[-1][1] = max(components[-1][1], observed_end)
                    components[-1][2].append(span)
            # Join only components containing already-pinned members. A broad
            # synthetic time envelope would wrongly absorb a new third source
            # located solely in the newly revealed gap.
            parents = list(range(len(components)))
            def representative(index):
                while parents[index] != index:
                    parents[index] = parents[parents[index]]
                    index = parents[index]
                return index
            component_members = [{value[2] for value in component[2]} for component in components]
            sticky_indexes = []
            for group_id, pinned, marker in sticky_by_camera.get(camera, ()):
                indexes = [index for index, identifiers in enumerate(component_members) if identifiers & pinned]
                if indexes:
                    for index in indexes[1:]:
                        parents[representative(index)] = representative(indexes[0])
                    sticky_indexes.append((indexes[0], marker))
            combined = {}
            for index, component in enumerate(components):
                target = combined.setdefault(representative(index), [component[0], component[1], []])
                target[0], target[1] = min(target[0], component[0]), max(target[1], component[1])
                target[2].extend(component[2])
            for index, marker in sticky_indexes:
                combined[representative(index)][2].append(marker)
            components = sorted(combined.values(), key=lambda value: value[0])
            for start, observed_end, members in components:
                existing_ids = {value[2][1:] for value in members if value[2].startswith("@")}
                member_ids = {value[2] for value in members if not value[2].startswith("@")}
                related = set().union(*(groups_by_source.get(identifier, set()) for identifier in member_ids)) if member_ids else set()
                existing_ids.update(identifier for identifier in related for group in (old[identifier],)
                                    if group["row"][1] == camera and group["row"][2] < observed_end
                                    and (group["row"][3] is None or group["row"][3] > start)
                                    )
                existing = sorted((old[identifier] for identifier in existing_ids), key=lambda value: (value["row"][2], value["row"][0]))
                anchors = {value["row"][2]: value for value in existing}
                if len(existing) == 1 and start < existing[0]["row"][2]:
                    prior = existing[0]
                    width = prior["meta"].get("groupMaxSpanMs", self.max_span_ms)
                    identity = prior["meta"].get("groupIdentityStart", prior["row"][2])
                    if identity < start + width:
                        # One stable identity can absorb earlier overlapping
                        # history. Multiple existing identities instead retain
                        # their publication partition boundaries.
                        anchors = {start: prior}
                left = start
                while left < observed_end:
                    prior = anchors.get(left)
                    span_ms = prior["meta"].get("groupMaxSpanMs", self.max_span_ms) if prior else self.max_span_ms
                    later = [point for point in anchors if point > left]
                    boundary = min(left + span_ms, min(later) if later else left + span_ms)
                    capped = boundary < observed_end or (boundary == observed_end and any(value[1] is None for value in members))
                    right = boundary if capped else None if any(value[1] is None for value in members) else observed_end
                    stored = self._store(camera, left, right, members, prior, old, links, sources, span_ms,
                                         "max_span" if capped and boundary == left + span_ms else "late_history_partition" if capped else None, now)
                    if capped and not stored:
                        # Skip arbitrary hours of unconfirmed inherited-open
                        # activity directly to the next genuine source start.
                        future = [value[0] for value in members if value[0] >= boundary]
                        future.extend(point for point in anchors if point >= boundary)
                        left = min(future) if future else observed_end
                    else:
                        left = boundary if capped else observed_end
        for camera in dirty:
            due = [source["row"][3] for source in sources.values()
                   if source["row"][1] == camera and source["row"][3] > now]
            for start, raw in self.db.execute("SELECT g.start,g.provenance FROM visual_groups g WHERE g.camera=? AND g.end IS NULL "
                                              "AND NOT EXISTS(SELECT 1 FROM visual_group_manual m WHERE m.group_id=g.id)", (camera,)):
                due.append(start + json.loads(raw)["groupMaxSpanMs"])
            if due:
                self._next_due[camera] = min(due)
            else:
                self._next_due.pop(camera, None)

    def _store(self, camera, left, right, spans, prior, old, links, sources, span_ms, partition, now):
        coverage, identifiers, prior_groups = {}, set(), set()
        included_open = False
        for start, end, identifier, label in spans:
            if label is None:
                continue
            # An old still-open object does not prove a new continuation after
            # the presentation cap. A real end, or a newly starting source,
            # supplies that evidence. This avoids phantom continuation events
            # when the detector reports an earlier genuine clear late.
            if end is None and start < left:
                continue
            clipped = _clip([(start, end)], left, right)
            if not clipped:
                continue
            coverage.setdefault(label, []).extend(clipped)
            included_open = included_open or end is None
            if identifier.startswith("@"):
                prior_groups.add(identifier[1:])
                identifiers.update(links.get(identifier[1:], ()))
            else:
                identifiers.add(identifier)
        if not coverage:
            return False
        left = min(value[0] for ranges in coverage.values() for value in ranges)
        if not included_open:
            actual_end = max(value[1] for ranges in coverage.values() for value in ranges)
            if right is None or actual_end < right:
                right, partition = actual_end, None
        identifier = prior["row"][0] if prior else "%08x%s" % (
            left // 1000, hashlib.sha256(("visual:" + camera + ":" + str(left)).encode()).hexdigest()[:16])
        previous = prior["meta"] if prior else {}
        classes = sorted(coverage)
        source_types, details, diagnostic = set(), {}, []
        last_seen = left
        estimated = False
        for source_id in sorted(identifiers):
            source = sources.get(source_id)
            if source is None:
                continue
            row, meta = source["row"], source["meta"]
            last_seen = max(last_seen, row[5])
            source_types.update(meta.get("sourceTypes", ["frigate" if meta.get("source", "").startswith("frigate") else "reolink"]))
            estimated = estimated or meta.get("endIsTimeoutEstimate", False)
            for key, values in meta.get("classificationDetails", {}).items():
                details.setdefault(key, set()).update(values)
            original = meta.get("sourceIntervals", [{"source": "frigate" if meta.get("sourceTypes") == ["frigate"] else "reolink",
                                 "id": source_id, "start": row[3], "end": row[4], "details": meta}])
            for value in original:
                detail = value.get("details", {})
                diagnostic.append({"source": value.get("source"), "id": value.get("id"),
                                   "start": value.get("start"), "end": value.get("end"),
                                   "details": {key: detail[key] for key in
                                               ("sourceLabel", "topScore", "closureReason", "endIsTimeoutEstimate", "classificationInferred")
                                               if key in detail}})
        for prior_id in prior_groups:
            meta = old[prior_id]["meta"]
            source_types.update(meta.get("sourceTypes", ()))
            for key, values in meta.get("classificationDetails", {}).items():
                details.setdefault(key, set()).update(values)
        if right is None:
            last_seen = max(last_seen, now)
        types = sorted(source_types)
        meta = {"adapter": "reolink-protect-events", "sourceUnionVersion": 1, "visualGroupVersion": 1,
                "identityStart": previous.get("identityStart", left),
                "groupIdentityStart": previous.get("groupIdentityStart", left),
                "activationMs": previous.get("activationMs", self.activation_ms), "groupMaxSpanMs": span_ms,
                "classIntervalsComplete": True,
                "classIntervals": {label: [{"start": start, "end": end} for start, end in _merge(coverage[label])]
                                   for label in classes},
                "mergePolicy": "camera_visual_positive_overlap", "objectIdentityMatched": False,
                "spatialDataAvailable": False, "timeBasis": "source_interval_union", "sourceTypes": types,
                "source": "reolink-and-frigate" if len(types) > 1 else "frigate-object-detection" if types == ["frigate"] else "reolink-camera-ai",
                "classificationOrigin": "mixed" if len(types) > 1 else "external-model" if types == ["frigate"] else "camera",
                "classificationInferred": "frigate" in types, "sourceIntervalCount": len(diagnostic),
                "sourceIntervals": diagnostic[:16], "memberIntervalIds": sorted(identifiers),
                "endIsTimeoutEstimate": bool(estimated)}
        if details:
            allowed = {"vehicleType" if label == "vehicle" else "animalType" for label in classes if label in ("vehicle", "animal")}
            filtered = {key: sorted(values) for key, values in sorted(details.items()) if key in allowed}
            if filtered:
                meta["classificationDetails"] = filtered
        if partition:
            meta.update(administrativePartitionReason=partition, closureReason="administrative_partition")
        if any(label is None and marker_id == "!published-gap:" + identifier
               and _clip([(start, end)], left, right) for start, end, marker_id, label in spans):
            meta.update(publishedGroupSticky=True, stickyGroupingReason="source_finalization_gap")
        if isinstance(previous.get("thumbnailSelection"), dict):
            meta["thumbnailSelection"] = previous["thumbnailSelection"]
        encoded, encoded_classes = _json(meta), _json(classes)
        current = self.db.execute("SELECT start,end,provenance,classes,last_seen FROM visual_groups WHERE id=?", (identifier,)).fetchone()
        if current is None:
            self.db.execute("INSERT INTO visual_groups(id,camera,start,end,last_seen,provenance,classes) VALUES(?,?,?,?,?,?,?)",
                            (identifier, camera, left, right, last_seen, encoded, encoded_classes))
            self.db.execute("INSERT OR IGNORE INTO media(event_id) VALUES(?)", (identifier,))
        elif current[:4] != (left, right, encoded, encoded_classes):
            self.db.execute("UPDATE visual_groups SET start=?,end=?,last_seen=?,provenance=?,classes=?,revision=revision+1 WHERE id=?",
                            (left, right, last_seen, encoded, encoded_classes, identifier))
        elif last_seen > current[4]:
            self.db.execute("UPDATE visual_groups SET last_seen=MAX(last_seen,?) WHERE id=?", (last_seen, identifier))
        for source_id in identifiers:
            self.db.execute("INSERT OR IGNORE INTO visual_group_segments VALUES(?,?)", (identifier, source_id))
        return True

    def prune(self, cutoff):
        """Prune only complete, acknowledged membership components.

        A long or pending source keeps its old partitions, so subsequent updates
        cannot regenerate already-pruned publication history.
        """
        with self.db:
            candidates = {row[0] for row in self.db.execute("SELECT g.id FROM visual_groups g JOIN media m ON m.event_id=g.id "
                         "WHERE g.end<? AND g.delivered_revision=g.revision AND g.notified_revision=g.revision AND (m.done=1 OR m.attempts>=20) "
                         "AND NOT EXISTS(SELECT 1 FROM delivery_failures f WHERE f.event_id=g.id)", (cutoff,))}
            edges = list(self.db.execute("SELECT group_id,interval_id FROM visual_group_segments"))
            source_ends = dict(self.db.execute("SELECT id,end FROM intervals WHERE id IN (SELECT interval_id FROM visual_group_members)"))
            while True:
                safe_sources = {identifier for identifier, end in source_ends.items() if end is not None and end < cutoff
                                and any(member == identifier for group, member in edges)
                                and all(group in candidates for group, member in edges if member == identifier)}
                safe_groups = {group for group in candidates if all(member in safe_sources for owner, member in edges if owner == group)}
                if safe_groups == candidates:
                    break
                candidates = safe_groups
            for group in candidates:
                self.db.execute("DELETE FROM visual_group_manual WHERE group_id=?", (group,))
                self.db.execute("DELETE FROM visual_groups WHERE id=?", (group,))
                self.db.execute("DELETE FROM media WHERE event_id=?", (group,))
                self.db.execute("DELETE FROM visual_group_segments WHERE group_id=?", (group,))
            for identifier in safe_sources:
                self.db.execute("DELETE FROM visual_group_members WHERE interval_id=?", (identifier,))
                self.db.execute("DELETE FROM intervals WHERE id=?", (identifier,))
                self.db.execute("DELETE FROM media WHERE event_id=?", (identifier,))
                self.db.execute("DELETE FROM delivery_failures WHERE event_id=?", (identifier,))
