"""Fault-injected tests for durable delivery boundaries, not live infrastructure."""
import copy
import datetime
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.native import NativeError, RetiredEventError, SchemaError, Thumbnail
from reolink_protect_events.runtime import Runtime


START = 1791586947512
INSTANCE = "a" * 32
CAMERA = "111111111111111111111111"
CAMERA_TWO = "222222222222222222222222"
CAMERA_THREE = "333333333333333333333333"
JPEG = bytes.fromhex("ffd8ffc00011080018002003011100021100031100ffda0008010100003f0000ffd9")


def bridge(camera=CAMERA, host="192.168.30.214"):
    return {"cameraId": camera, "host": host, "username": "fixture-user",
            "password": "fixture-password", "mac": "001122334455"}


def config(bridges=None):
    return {"bridges": bridges or [bridge()], "protectVersion": "7.3.70",
            "protectUserId": "fixture-owner", "dsProxyPort": 7448,
            "bridgeEventStaleSeconds": 120}


def source(sequence, offset=0, classes=("person",)):
    return {"seq": sequence, "timestampUtc": datetime.datetime.fromtimestamp(
        (START + offset) / 1000, datetime.timezone.utc).isoformat(),
        "classes": list(classes), "rawAiTypes": [], "motion": False,
        "source": {"connectionEpoch": 0}, "zones": []}


def response(events):
    return {"instanceId": INSTANCE, "oldestSeq": 1,
            "currentSeq": max(event["seq"] for event in events), "events": events}


class SimulatedProcessCrash(BaseException):
    """Bypass the Runtime's expected Exception handler like a process exit."""


class FakeNative:
    """An idempotent persistent boundary with injectable pre/postcommit faults."""
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.fail = set()
        self.retired = set()
        self.crash_after_commit = False
        self.schema_error = None

    def guard_schema(self):
        if self.schema_error:
            raise self.schema_error
        return {"schemaVerified": True}

    def upsert_interval(self, interval, thumbnail=None):
        self.calls.append((copy.deepcopy(interval), thumbnail))
        event_id = interval["eventId"]
        if event_id in self.retired:
            raise RetiredEventError("removed by retention")
        if event_id in self.fail:
            raise NativeError("private source details must never enter logs")
        # The real adapter's SQL tests cover its graph. Here the identity and
        # persisted representation define the cross-process outbox boundary.
        end = interval["end"]
        old = self.rows.get(event_id)
        if old and old["end"] is not None:
            end = max(old["end"], end or old["end"])
        event = {"id": event_id, "modelKey": "event", "type": "smartDetectZone",
                 "camera": interval["cameraId"], "start": interval["start"], "end": end,
                 "score": None, "smartDetectTypes": list(interval["classes"]),
                 "metadata": {"zonesStatus": {"1": {"status": "enter" if end is None else "leave"}},
                              "detectedThumbnails": copy.deepcopy((old or {}).get("metadata", {}).get("detectedThumbnails", []))}}
        if thumbnail and not event["metadata"]["detectedThumbnails"]:
            event["metadata"]["detectedThumbnails"] = [{"croppedId": "truthful-fixture-frame",
                                                         "type": interval["classes"][0]}]
        self.rows[event_id] = copy.deepcopy(event)
        if self.crash_after_commit:
            self.crash_after_commit = False
            raise SimulatedProcessCrash()
        return event


class FakeClient:
    def __init__(self):
        self.sent = []
        self.fail_action = None
        self.crash_action = None
        self.closed = False
        self.connected = False

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True
        self.connected = False

    def send_event(self, action, event):
        if action == self.crash_action:
            self.crash_action = None
            raise SimulatedProcessCrash()
        if action == self.fail_action:
            raise ConnectionError("private websocket details")
        self.sent.append((action, copy.deepcopy(event)))


class RuntimeDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name)
        self.cfg = config()
        self.now_ms = START + 50000
        self.clock = patch("reolink_protect_events.runtime.time.time", side_effect=lambda: self.now_ms / 1000)
        self.monotonic = patch("reolink_protect_events.runtime.time.monotonic", return_value=10)
        self.clock.start()
        self.monotonic.start()
        self.runtime = Runtime(self.cfg, self.path)
        self.native = FakeNative()
        self.client = FakeClient()
        self.attach()

    def tearDown(self):
        self.runtime.journal.db.close()
        self.monotonic.stop()
        self.clock.stop()
        self.folder.cleanup()

    def attach(self):
        self.runtime.native = self.native
        self.runtime.clients = {CAMERA: self.client}
        self.runtime.native_ready = True

    def restart(self):
        self.runtime.journal.db.close()
        self.runtime = Runtime(self.cfg, self.path)
        self.attach()

    def ingest(self, events, item=None):
        self.runtime.journal.ingest(item or self.cfg["bridges"][0], response(events))
        return self.runtime.journal.pending()

    def row(self, event_id):
        names = ("revision", "delivered", "notified", "end")
        row = self.runtime.journal.db.execute(
            "SELECT revision,delivered_revision,notified_revision,end FROM intervals WHERE id=?", (event_id,)).fetchone()
        return dict(zip(names, row))

    def media(self, event_id):
        return self.runtime.journal.db.execute("SELECT attempts,last_attempt,done FROM media WHERE event_id=?", (event_id,)).fetchone()

    def test_open_then_real_clear_notifies_add_then_update_once(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.runtime.deliver()
        self.ingest([source(2, 6000, classes=())])
        self.runtime.deliver()
        self.runtime.deliver()
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])
        self.assertIsNone(self.client.sent[0][1]["end"])
        self.assertEqual(self.client.sent[1][1]["end"], START + 6000)
        self.assertEqual(self.row(event_id), {"revision": 2, "delivered": 2, "notified": 2, "end": START + 6000})
        provenance = json.loads(self.runtime.journal.db.execute(
            "SELECT provenance FROM intervals WHERE id=?", (event_id,)).fetchone()[0])
        self.assertFalse(provenance["endIsTimeoutEstimate"])
        self.assertEqual(provenance["endBasis"], "camera_clear_received_utc")

    def test_source_timeout_closes_once_and_explicitly_marks_estimated_end(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.runtime.deliver()
        self.now_ms = START + 120001
        self.runtime.journal.expire(self.now_ms)
        self.runtime.journal.expire(self.now_ms + 1000)
        self.runtime.deliver()
        self.assertEqual(self.row(event_id), {"revision": 2, "delivered": 2, "notified": 2, "end": START + 120000})
        provenance = json.loads(self.runtime.journal.db.execute(
            "SELECT provenance FROM intervals WHERE id=?", (event_id,)).fetchone()[0])
        self.assertTrue(provenance["endIsTimeoutEstimate"])
        self.assertEqual(provenance["closureReason"], "source_stale")
        self.assertNotIn("lastSourceEvent", provenance)
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])

    def test_initial_closed_replay_has_enter_then_leave_without_mutating_persistence(self):
        event_id = self.ingest([source(1), source(2, 6000, classes=())])[0]["eventId"]
        self.runtime.deliver()
        added, closed = [event for _, event in self.client.sent]
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])
        self.assertIsNone(added["end"])
        self.assertEqual(added["metadata"]["zonesStatus"]["1"]["status"], "enter")
        self.assertEqual(closed["end"], START + 6000)
        self.assertEqual(self.native.rows[event_id]["metadata"]["zonesStatus"]["1"]["status"], "leave")

    def test_database_failure_backs_off_one_poison_interval_and_delivers_another(self):
        first = self.ingest([source(1, classes=("person", "vehicle"))])
        bad, good = first[0]["eventId"], first[1]["eventId"]
        self.native.fail.add(bad)
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.runtime.deliver()
        self.assertNotIn("private source", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["errorType"], "NativeError")
        self.assertEqual(self.row(bad)["delivered"], 0)
        self.assertEqual(self.row(good)["notified"], 1)
        calls = len(self.native.calls)
        self.runtime.deliver()
        self.assertEqual(len(self.native.calls), calls)
        self.now_ms += 2001
        self.native.fail.clear()
        self.runtime.deliver()
        self.assertEqual(self.runtime.journal.health()["pending"], 0)
        self.assertEqual(self.runtime.journal.health()["retryIntervals"], 0)

    def test_crash_after_database_commit_reuses_same_identity_after_restart(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.native.crash_after_commit = True
        with self.assertRaises(SimulatedProcessCrash):
            self.runtime.deliver()
        self.assertEqual(self.row(event_id)["delivered"], 0)
        self.assertEqual(len(self.native.rows), 1)
        self.restart()
        self.runtime.deliver()
        self.assertEqual(len(self.native.rows), 1)
        self.assertEqual([item[0]["eventId"] for item in self.native.calls], [event_id, event_id])
        self.assertEqual(self.row(event_id)["notified"], 1)

    def test_crash_after_delivery_ack_preserves_existing_requirement_and_notification(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.client.crash_action = "add"
        with self.assertRaises(SimulatedProcessCrash):
            self.runtime.deliver()
        self.assertEqual((self.row(event_id)["delivered"], self.row(event_id)["notified"]), (1, 0))
        self.restart()
        self.runtime.deliver()
        self.assertEqual(self.native.calls[-1][0]["deliveredRevision"], 1)
        self.assertEqual(self.row(event_id)["notified"], 1)
        self.assertEqual([action for action, _ in self.client.sent], ["add"])

    def test_closed_ws_failure_retries_add_then_update_with_documented_at_least_once(self):
        event_id = self.ingest([source(1), source(2, 6000, classes=())])[0]["eventId"]
        self.client.fail_action = "update"
        with patch("sys.stdout", new_callable=io.StringIO):
            self.runtime.deliver()
        self.assertEqual((self.row(event_id)["delivered"], self.row(event_id)["notified"]), (2, 0))
        self.assertEqual([action for action, _ in self.client.sent], ["add"])
        self.restart()
        self.now_ms += 2001
        self.client.fail_action = None
        self.runtime.deliver()
        self.assertEqual([action for action, _ in self.client.sent], ["add", "add", "update"])
        self.assertEqual(self.row(event_id)["notified"], 2)
        self.assertEqual(len(self.native.rows), 1)

    def test_retired_event_is_terminal_and_does_not_block_other_intervals(self):
        pending = self.ingest([source(1, classes=("person", "vehicle"))])
        retired, other = pending[0]["eventId"], pending[1]["eventId"]
        self.runtime.journal.acknowledge(retired, 1, "delivered")
        self.native.retired.add(retired)
        self.runtime.deliver()
        self.assertEqual(self.row(retired)["notified"], 1)
        self.assertEqual(self.row(other)["notified"], 1)
        self.assertEqual(self.media(retired)[2], 1)
        self.assertEqual(self.runtime.journal.health()["counters"]["retiredEvents"], 1)
        self.assertEqual(self.runtime.import_errors, 0)
        self.assertNotIn(retired, self.native.rows)
        self.assertEqual([event["id"] for _, event in self.client.sent], [other])

    def test_media_waits_for_persistence_and_retries_transient_recording_failure(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        with patch("reolink_protect_events.runtime.recording_thumbnail") as snapshot:
            self.runtime.deliver_media(self.now_ms)
            snapshot.assert_not_called()
        self.runtime.deliver()
        with patch("reolink_protect_events.runtime.recording_thumbnail", side_effect=TimeoutError):
            self.runtime.deliver_media(self.now_ms)
        self.assertEqual(self.media(event_id), (1, self.now_ms, 0))
        self.assertEqual(self.row(event_id)["notified"], 1)
        frame = Thumbnail(JPEG, START)
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=frame) as snapshot:
            self.runtime.deliver_media(self.now_ms + 1000)
            snapshot.assert_not_called()
            self.runtime.deliver_media(self.now_ms + 15001)
        self.assertEqual(self.media(event_id)[2], 1)
        self.assertEqual(self.native.calls[-1][0]["deliveredRevision"], 1)
        self.assertIs(self.native.calls[-1][1], frame)
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])

    def test_media_ws_failure_keeps_real_thumbnail_for_idempotent_retry(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.runtime.deliver()
        self.client.fail_action = "update"
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=Thumbnail(JPEG, START)):
            self.runtime.deliver_media(self.now_ms)
            self.assertEqual(self.media(event_id)[2], 0)
            self.assertEqual(len(self.native.rows[event_id]["metadata"]["detectedThumbnails"]), 1)
            self.client.fail_action = None
            self.runtime.deliver_media(self.now_ms + 15001)
        self.assertEqual(self.media(event_id)[2], 1)
        self.assertEqual(len(self.native.rows[event_id]["metadata"]["detectedThumbnails"]), 1)
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])

    def test_retired_media_stops_retrying_without_recreating_deleted_event(self):
        event_id = self.ingest([source(1)])[0]["eventId"]
        self.runtime.deliver()
        del self.native.rows[event_id]
        self.native.retired.add(event_id)
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=Thumbnail(JPEG, START)) as snapshot:
            self.runtime.deliver_media(self.now_ms)
            self.runtime.deliver_media(self.now_ms + 15001)
        self.assertEqual(snapshot.call_count, 1)
        self.assertEqual(self.media(event_id)[2], 1)
        self.assertEqual(self.runtime.journal.health()["counters"]["retiredMedia"], 1)
        self.assertNotIn(event_id, self.native.rows)
        self.assertEqual([action for action, _ in self.client.sent], ["add"])

    def test_journal_prune_preserves_unnotified_closed_interval(self):
        event_id = self.ingest([source(1), source(2, 6000, classes=())])[0]["eventId"]
        self.runtime.journal.acknowledge(event_id, 2, "delivered")
        self.runtime.journal.prune(START + 30000, days=0)
        self.assertEqual(self.row(event_id)["notified"], 0)
        self.assertEqual(self.runtime.journal.health()["pending"], 1)
        self.runtime.deliver()
        self.assertEqual(self.row(event_id)["notified"], 2)
        self.runtime.journal.prune(START + 30000, days=0)
        self.assertIsNone(self.runtime.journal.db.execute(
            "SELECT id FROM intervals WHERE id=?", (event_id,)).fetchone())
        self.assertEqual(self.runtime.journal.health()["pendingThumbnails"], 0)
        self.assertIn(event_id, self.native.rows)  # Protect owns its own retention.

    def test_schema_drift_continues_capture_and_disables_all_native_writes(self):
        self.native.schema_error = SchemaError("schema drift")
        with patch("reolink_protect_events.runtime.fetch_bridge", return_value=response([source(1)])), \
             patch("reolink_protect_events.runtime.recording_thumbnail") as snapshot:
            self.runtime.once()
        self.assertFalse(self.runtime.native_ready)
        self.assertEqual(self.runtime.native_error, "SchemaError")
        self.assertEqual(self.native.calls, [])
        snapshot.assert_not_called()
        self.assertEqual(self.runtime.journal.health()["sourceRows"], 1)
        self.assertEqual(self.runtime.journal.health()["pending"], 1)
        health = json.loads((self.path / "health.json").read_text())
        self.assertFalse(health["healthy"])
        self.assertNotIn("fixture-password", json.dumps(health))

    def test_partial_native_initialization_recovers_all_configured_cameras(self):
        self.cfg = config([bridge(), bridge(CAMERA_TWO, "192.168.30.213"),
                           bridge(CAMERA_THREE, "192.168.30.212")])
        self.runtime.config = self.cfg
        self.runtime.native = None
        self.runtime.clients = {}
        self.runtime.native_ready = False
        clients = []
        def make_client(*args, **kwargs):
            item = FakeClient()
            clients.append(item)
            if len(clients) == 2:
                def fail_connect():
                    raise ConnectionError("transient handshake failure")
                item.connect = fail_connect
            return item
        with patch("reolink_protect_events.native.NativeAdapter", return_value=self.native), \
             patch("reolink_protect_events.updates.DsUpdateClient", side_effect=make_client):
            self.runtime.check_native()
            self.assertFalse(self.runtime.native_ready)
            abandoned = list(clients)
            self.now_ms += 10001
            self.runtime.check_native()
        self.assertTrue(self.runtime.native_ready)
        self.assertEqual(set(self.runtime.clients), {CAMERA, CAMERA_TWO, CAMERA_THREE})
        self.assertTrue(all(client.closed for client in abandoned), "partial retry leaked an old DS client")

    def test_collect_deliver_health_and_shutdown_preserve_replay_cursor(self):
        self.runtime.last_native_check = self.now_ms
        self.now_ms = START + 2000
        original_once = self.runtime.once
        def one_iteration():
            original_once()
            self.runtime.running = False
        with patch("reolink_protect_events.runtime.fetch_bridge", return_value=response([source(1)])), \
             patch("reolink_protect_events.runtime.recording_thumbnail", side_effect=TimeoutError), \
             patch("reolink_protect_events.runtime.signal.signal"), \
             patch("reolink_protect_events.runtime.time.sleep"), \
             patch.object(self.runtime, "once", side_effect=one_iteration):
            self.runtime.run()
        self.assertEqual(len(self.native.rows), 1)
        self.assertEqual(self.runtime.journal.health()["pending"], 0)
        self.restart()
        self.assertEqual(self.runtime.journal.cursor(CAMERA)["seq"], 1)
        self.assertEqual(self.runtime.journal.health()["pending"], 0)
        self.assertTrue(json.loads((self.path / "health.json").read_text())["healthy"])


if __name__ == "__main__":
    unittest.main()
