"""Offline publication/media contracts, including the SQLite 3.34 query shape."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.native import Thumbnail
from reolink_protect_events.runtime import Journal, Runtime
from tests.test_runtime_delivery import FakeClient, FakeNative, JPEG, config


NOW = 1792273000000
CAMERA = "1" * 24


class ObservedConnection(sqlite3.Connection):
    collect = False

    def execute(self, sql, parameters=()):
        if self.collect:
            self.observed.append((sql, parameters))
        return super().execute(sql, parameters)


class JournalMediaQueryContracts(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "journal.sqlite3"
        self.journal = Journal(self.path)
        self.journal.db.close()
        self.journal.db = sqlite3.connect(str(self.path), factory=ObservedConnection)
        self.journal.db.observed = []
        self.journal.visual_groups.db = self.journal.db
        self.db = self.journal.db

    def tearDown(self):
        self.journal.close()
        self.folder.cleanup()

    def add(self, kind, number, *, start=None, label="person", revision=2,
            delivered=2, notified=0, attempts=0, done=0, next_attempt=0,
            last_attempt=0, error=None, manual=False, media=True):
        identifier = "%024x" % number
        start = NOW - 30000 if start is None else start
        classes = ["vehicle", "person"] if kind == "group" else [label]
        provenance = {"synthetic": kind, "marker": number,
            "thumbnailSelection": {"mode": "automatic", "timestamp": start + 500,
                                   "sha256": "a" * 64}}
        encoded = json.dumps(provenance)
        with self.db:
            if kind == "group":
                self.db.execute("""INSERT INTO visual_groups(id,camera,start,end,last_seen,provenance,
                    classes,revision,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (identifier, CAMERA, start, start + 1000, start + 1000, encoded,
                     json.dumps(classes), revision, delivered, notified))
                if manual:
                    self.db.execute("INSERT INTO visual_group_manual VALUES(?,?,?,?)",
                        (identifier, "synthetic-operation-" + str(number), json.dumps([identifier]), "b" * 64))
            else:
                self.db.execute("""INSERT INTO intervals(id,camera,class,start,end,last_seen,
                    provenance,revision,delivered_revision,notified_revision) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (identifier, CAMERA, label, start, start + 1000, start + 1000,
                     encoded, revision, delivered, notified))
            if media:
                self.db.execute("""INSERT OR REPLACE INTO media(event_id,attempts,last_attempt,done,
                    next_attempt,error_reason) VALUES(?,?,?,?,?,?)""",
                    (identifier, attempts, last_attempt, done, next_attempt, error))
        return {"eventId": identifier, "cameraId": CAMERA, "classes": classes,
                "start": start, "end": start + 1000, "provenance": provenance,
                "deliveredRevision": delivered}

    def clear(self):
        with self.db:
            for table in ("visual_group_manual", "visual_group_segments", "visual_group_members",
                          "visual_groups", "intervals", "media"):
                self.db.execute("DELETE FROM " + table)

    def snapshot(self):
        return {table: self.db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()
                for table in ("intervals", "visual_groups", "media", "visual_group_members",
                              "visual_group_segments", "visual_group_manual")}

    def test_ready_window_retry_and_revision_boundaries_for_both_publication_types(self):
        cases = [
            ({}, True), ({"done": 1}, False), ({"attempts": 19}, True),
            ({"attempts": 20}, False), ({"next_attempt": NOW}, True),
            ({"next_attempt": NOW + 1}, False), ({"last_attempt": NOW - 15000}, False),
            ({"last_attempt": NOW - 15001}, True), ({"start": NOW - 1500}, False),
            ({"start": NOW - 1501}, True), ({"revision": 3, "delivered": 2}, False),
            ({"revision": 3, "delivered": 3, "notified": 0}, True),
        ]
        for kind in ("legacy", "group"):
            for values, allowed in cases:
                with self.subTest(kind=kind, values=values):
                    self.clear()
                    expected = self.add(kind, 1, **values)
                    self.assertEqual(self.journal.pending_media(NOW), [expected] if allowed else [])

    def test_hidden_old_and_blocked_rows_do_not_starve_group_audio_or_legacy(self):
        hidden = self.add("legacy", 1, start=NOW - 100000)
        with self.db:
            self.db.execute("INSERT INTO visual_group_members VALUES(?)", (hidden["eventId"],))
        self.add("legacy", 2, start=NOW - 90000, delivered=1)
        self.add("group", 3, start=NOW - 80000, next_attempt=NOW + 1)
        self.add("legacy", 4, start=NOW - 70000, attempts=20)
        group = self.add("group", 5, start=NOW - 60000)
        audio = self.add("legacy", 6, start=NOW - 50000, label="speak")
        legacy = self.add("legacy", 7, start=NOW - 40000)
        for expected in (group, audio, legacy):
            self.assertEqual(self.journal.pending_media(NOW), [expected])
            with self.db:
                self.db.execute("UPDATE media SET done=1 WHERE event_id=?", (expected["eventId"],))
        self.assertEqual(self.journal.pending_media(NOW), [])

    def test_manual_group_sharing_hidden_source_identity_uses_group_snapshot_once(self):
        source = self.add("legacy", 20, label="animal")
        with self.db:
            self.db.execute("INSERT INTO visual_group_members VALUES(?)", (source["eventId"],))
        group = self.add("group", 20, manual=True)
        with self.db:
            self.db.execute("INSERT INTO visual_group_segments VALUES(?,?)",
                            (group["eventId"], source["eventId"]))
        self.assertEqual(self.journal.pending_media(NOW), [group])
        health = self.journal.health()
        self.assertEqual(health["pendingThumbnails"], 1)
        self.assertEqual(health["failedThumbnails"], 0)
        self.assertEqual(group["provenance"]["thumbnailSelection"],
                         self.journal.pending_media(NOW)[0]["provenance"]["thumbnailSelection"])

    def test_same_start_keeps_single_oldest_candidate_without_new_tie_contract(self):
        legacy = self.add("legacy", 30)
        group = self.add("group", 31)
        self.add("legacy", 32, start=NOW - 20000)
        actual = self.journal.pending_media(NOW)
        self.assertEqual(len(actual), 1)
        self.assertIn(actual[0], (legacy, group))

    def test_retired_manual_group_media_is_terminal_and_does_not_resurrect_source(self):
        source = self.add("legacy", 35, label="animal")
        with self.db:
            self.db.execute("INSERT INTO visual_group_members VALUES(?)", (source["eventId"],))
        group = self.add("group", 35, manual=True)
        runtime = Runtime(config(), self.path.parent, background_native=False)
        native, client = FakeNative(), FakeClient()
        native.retired.add(group["eventId"])
        runtime.native, runtime.native_ready, runtime.clients = native, True, {CAMERA: client}
        try:
            frame = Thumbnail(JPEG, group["start"])
            with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=frame) as snapshot:
                runtime.deliver_media(NOW)
                runtime.deliver_media(NOW + 15001)
            self.assertEqual(snapshot.call_count, 1)
            self.assertEqual(snapshot.call_args.args[1]["classes"], group["classes"])
            self.assertEqual(self.db.execute("SELECT done,attempts FROM media WHERE event_id=?",
                                           (group["eventId"],)).fetchone(), (1, 1))
            self.assertEqual(runtime.journal.health()["counters"]["retiredMedia"], 1)
            self.assertEqual(runtime.journal.pending_media(NOW + 15001), [])
            self.assertEqual(native.rows, {})
            self.assertEqual(client.sent, [])
        finally:
            runtime.close()

    def test_health_media_aggregates_match_publication_contract_and_do_not_count_orphans(self):
        self.add("legacy", 40, attempts=19, error="snapshot_timeout")
        self.add("legacy", 41, label="babyCry")
        self.add("legacy", 42, attempts=20, error="snapshot_http_404")
        self.add("group", 43, attempts=2, delivered=1, error="snapshot_timeout")
        self.add("group", 44, attempts=30, error="", manual=True)
        self.add("group", 45, done=1, error="completed-must-not-count")
        hidden = self.add("legacy", 46, attempts=30, error="hidden-must-not-count")
        self.add("legacy", 47, media=False)
        with self.db:
            self.db.execute("INSERT INTO visual_group_members VALUES(?)", (hidden["eventId"],))
            self.db.execute("INSERT INTO media(event_id,error_reason) VALUES(?,?)",
                            ("f" * 24, "orphan-must-not-count"))
        before = self.snapshot()
        changes = self.db.total_changes
        actual = self.journal.health()
        self.journal.pending_media(NOW)
        self.assertEqual(actual["pendingThumbnails"], 3)
        self.assertEqual(actual["failedThumbnails"], 2)
        self.assertEqual(actual["thumbnailErrorReasons"],
                         {"snapshot_timeout": 2, "snapshot_http_404": 1, "": 1})
        # The existing view remains an independent contract oracle for the
        # optimized direct-table queries, including hidden/manual membership.
        pending = self.db.execute("""SELECT COUNT(*) FROM media m JOIN publication_intervals p
            ON p.id=m.event_id WHERE m.done=0 AND m.attempts<20""").fetchone()[0]
        failed = self.db.execute("""SELECT COUNT(*) FROM media m JOIN publication_intervals p
            ON p.id=m.event_id WHERE m.done=0 AND m.attempts>=20""").fetchone()[0]
        errors = dict(self.db.execute("""SELECT COALESCE(m.error_reason,'unknown'),COUNT(*) FROM media m
            JOIN publication_intervals p ON p.id=m.event_id
            WHERE m.done=0 AND m.error_reason IS NOT NULL GROUP BY m.error_reason"""))
        self.assertEqual((actual["pendingThumbnails"], actual["failedThumbnails"], actual["thumbnailErrorReasons"]),
                         (pending, failed, errors))
        self.assertEqual(self.db.total_changes, changes)
        self.assertEqual(self.snapshot(), before)

    def test_media_read_plans_never_materialize_publication_history(self):
        # This guards the demonstrated SQLite 3.34.1 regression without wall
        # clock thresholds or assertions about the implementation's SQL text.
        for number in range(100, 140):
            row = self.add("legacy", number, done=1)
            if number % 2:
                with self.db:
                    self.db.execute("INSERT INTO visual_group_members VALUES(?)", (row["eventId"],))
        self.add("group", 150, manual=True)
        self.db.observed = []
        self.db.collect = True
        try:
            self.journal.pending_media(NOW)
            self.journal.health()
        finally:
            self.db.collect = False
        statements = [(sql, params) for sql, params in self.db.observed
                      if sql.lstrip().upper().startswith("SELECT") and "media" in sql.lower()]
        self.assertGreaterEqual(len(statements), 4)
        for sql, params in statements:
            plan = self.db.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
            with self.subTest(sqlite=sqlite3.sqlite_version, plan=plan):
                self.assertFalse(any("MATERIALIZE" in row[3].upper() for row in plan), plan)


if __name__ == "__main__":
    unittest.main()
