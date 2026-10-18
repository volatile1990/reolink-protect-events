"""Remote transport selection keeps the existing native/outbox contracts."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.native import NativeAdapter, NativeError, RetiredEventError, SchemaError, adapter_for_config
from reolink_protect_events.remote import RemoteError
from reolink_protect_events.runtime import Runtime, recording_thumbnail, validate_config
from test_native import INTERVAL, JPEG, schema_fixture
from test_remote import config as remote_config
from test_runtime_delivery import FakeClient, config, response, source


def configured():
    return dict(config(), **remote_config())


class RemoteNativeTests(unittest.TestCase):
    def setUp(self):
        guard = patch("reolink_protect_events.remote.subprocess.run",
                      side_effect=AssertionError("offline test attempted an external transport"))
        guard.start(); self.addCleanup(guard.stop)

    def test_local_adapter_still_uses_original_executor_and_version_reader(self):
        adapter = adapter_for_config(config())
        self.assertIsInstance(adapter, NativeAdapter)
        self.assertEqual(adapter.execute, adapter._execute)
        self.assertEqual(adapter.version_reader, adapter._installed_version)

    def test_remote_schema_and_transaction_use_rpc_while_sql_graph_stays_identical(self):
        calls = []
        local_sql, expected_event = NativeAdapter().build_interval_sql(INTERVAL)
        def request(cfg, action, payload=None, timeout=15):
            calls.append((action, payload, timeout))
            if action == "version": return "7.3.70"
            if "information_schema.columns" in payload["sql"]: return json.dumps(schema_fixture())
            self.assertEqual(payload["sql"], local_sql)
            return json.dumps(expected_event)
        with patch("reolink_protect_events.remote.rpc", side_effect=request):
            adapter = adapter_for_config(configured())
            self.assertEqual(adapter.upsert_interval(INTERVAL), expected_event)
        self.assertEqual([row[0] for row in calls], ["version", "sql", "sql"])
        self.assertEqual(calls[0][2], 5)

    def test_remote_version_mismatch_prevents_any_database_request(self):
        with patch("reolink_protect_events.remote.rpc", return_value="7.3.71") as request:
            with self.assertRaises(SchemaError):
                adapter_for_config(configured()).upsert_interval(INTERVAL)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[1], "version")

    def test_remote_retired_code_is_terminal_and_other_errors_are_sanitized(self):
        adapter = adapter_for_config(configured())
        for failure, expected in ((RemoteError("protect_remote_rpc_rejected", remote_code="event_retired"), RetiredEventError),
                                  (RemoteError("protect_remote_rpc_timeout"), NativeError)):
            with self.subTest(expected=expected), patch("reolink_protect_events.remote.rpc", side_effect=failure):
                with self.assertRaises(expected):
                    adapter.execute("SELECT 1;")
        for invalid in ({"private": "output"}, None):
            with patch("reolink_protect_events.remote.rpc", return_value=invalid):
                with self.assertRaises(NativeError): adapter.execute("SELECT 1;")
                with self.assertRaises(SchemaError): adapter.version_reader()


class RemoteRuntimeTests(unittest.TestCase):
    def setUp(self):
        guard = patch("reolink_protect_events.remote.subprocess.run",
                      side_effect=AssertionError("offline test attempted an external transport"))
        guard.start(); self.addCleanup(guard.stop)

    def test_bad_remote_config_is_rejected_before_a_journal_is_created(self):
        cfg = configured(); cfg["protectRemote"]["sshAlias"] = "-invalid"
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RemoteError): Runtime(cfg, folder)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_remote_ds_port_overrides_console_port_without_changing_camera_identity(self):
        cfg = configured(); cfg.pop("dsProxyPort")
        client = FakeClient()
        with tempfile.TemporaryDirectory() as folder:
            runtime = Runtime(cfg, folder)
            try:
                with patch("reolink_protect_events.remote.rpc", side_effect=lambda _, action, payload=None, timeout=15:
                           "7.3.70" if action == "version" else json.dumps(schema_fixture())), \
                     patch("reolink_protect_events.updates.DsUpdateClient", return_value=client) as constructor:
                    runtime.initialize_native()
                constructor.assert_called_once_with(cfg["bridges"][0]["mac"], port=17448)
                self.assertTrue(runtime.native_ready)
            finally: runtime.close()
    def test_evidence_reads_local_journal_and_configured_api_forward_without_exporting_media(self):
        from reolink_protect_events.operations.evidence import inspect
        for cfg, port in ((configured(), 17443), (config(), 7443)):
            with self.subTest(port=port), tempfile.TemporaryDirectory() as folder:
                runtime = Runtime(cfg, folder)
                runtime.journal.ingest(cfg["bridges"][0], response([source(1)]))
                interval = runtime.journal.pending()[0]
                event_id = interval["eventId"]
                runtime.journal.acknowledge(event_id, interval["revision"], "delivered")
                with runtime.journal.db:
                    runtime.journal.db.execute("UPDATE media SET done=1,selection=? WHERE event_id=?",
                                              (json.dumps({"automaticSelected": True, "decodedCandidates": 2}), event_id))
                runtime.close()
                health_path = Path(folder) / "health.json"
                health_path.write_text(json.dumps({"healthy": True}), encoding="utf-8")
                os.chmod(health_path, 0o600)
                fake_event = {"camera": interval["cameraId"], "metadata": {
                    "reolinkProtectEvents": {"owner": "reolink-protect-events"}}}
                with patch("reolink_protect_events.operations.evidence.protect_json", return_value=fake_event) as api, \
                     patch("reolink_protect_events.operations.evidence.get_bytes", return_value=(200, JPEG)) as get:
                    result = inspect(cfg, root=folder)
                api.assert_called_once_with(cfg, "/api/events/" + event_id)
                self.assertEqual(get.call_args.args[0], "https://127.0.0.1:" + str(port) + "/api/events/" + event_id + "/thumbnail?isFullfov=true")
                self.assertTrue(result["readOnly"])
                self.assertFalse(result["mediaPersisted"])
                self.assertTrue(result["ok"])
                self.assertTrue(result["automaticThumbnailProven"])
                self.assertEqual(result["automaticThumbnails"][0]["thumbnailBytes"], len(JPEG))
                self.assertNotIn(JPEG.hex(), json.dumps(result))

    def test_snapshot_uses_configured_loopback_forward_and_original_event_timestamp(self):
        cfg = configured()
        with patch("reolink_protect_events.runtime.get_bytes", return_value=(200, JPEG)) as get:
            frame = recording_thumbnail(cfg, INTERVAL)
        url = get.call_args.args[0]
        self.assertEqual(url, "http://127.0.0.1:17080/api/cameras/" + INTERVAL["cameraId"] + "/snapshot?ts=" + str(INTERVAL["start"]))
        self.assertEqual(frame.timestamp, INTERVAL["start"])

    def test_sql_timeout_keeps_journal_pending_and_sends_no_notification(self):
        cfg = configured()
        with tempfile.TemporaryDirectory() as folder:
            runtime = Runtime(cfg, folder)
            try:
                runtime.journal.ingest(cfg["bridges"][0], response([source(1)]))
                client = FakeClient()
                runtime.clients = {cfg["bridges"][0]["cameraId"]: client}
                runtime.native = adapter_for_config(cfg)
                runtime.native_ready = True
                def request(_, action, payload=None, timeout=15):
                    if action == "version": return "7.3.70"
                    if "information_schema.columns" in payload["sql"]: return json.dumps(schema_fixture())
                    raise RemoteError("protect_remote_rpc_timeout")
                with patch("reolink_protect_events.remote.rpc", side_effect=request), patch("builtins.print"):
                    runtime.deliver()
                self.assertEqual(runtime.journal.health()["pending"], 1)
                self.assertEqual(client.sent, [])
                pending = runtime.journal.db.execute("SELECT delivered_revision,notified_revision FROM intervals").fetchone()
                self.assertEqual(pending, (0, 0))
            finally: runtime.close()


if __name__ == "__main__":
    unittest.main()
