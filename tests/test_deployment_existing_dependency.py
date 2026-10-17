"""Fail-closed synthetic contracts for a pinned pre-existing Frigate outage."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from reolink_protect_events.operations import deployment_health
from tests import test_deploy as deploy_tests


NOW = 1792276000000
CAMERAS = ["%024x" % number for number in range(1, 7)]
CONFIG_SHA = "a" * 64
DEPLOYMENT_SHA = "b" * 64
SPECIAL = "events-native-ready-existing-frigate-failure"


def configuration():
    return {"bridges": [{"cameraId": camera, "host": "192.168.30." + str(210 + index)}
                        for index, camera in enumerate(CAMERAS)],
            "frigate": {"cameraMap": {"fixture_" + str(index): camera
                                      for index, camera in enumerate(CAMERAS)}}}


def failed_health(post=False):
    seen = NOW + 500 if post else NOW - 100
    return {"atMs": NOW + 1000 if post else NOW - 100,
            "mode": "native", "healthy": False, "captureHealthy": False,
            "frigateHealthy": False, "nativeReady": True, "nativeError": None,
            "nativeWorkerAgeMs": 50, "pending": 0, "retryIntervals": 0,
            "pendingThumbnails": 0, "failedThumbnails": 0, "thumbnailErrorReasons": {},
            "importErrors": 0, "counters": {"sourceEvents": 100, "nativeImportErrors": 2},
            "bridges": {camera: {"lastSuccessMs": seen, "consecutiveErrors": 0,
                                  "sourceBacklog": 0} for camera in CAMERAS},
            "frigate": {camera: {"lastSuccessMs": NOW - 90000, "consecutiveErrors": 5,
                                  "errorType": "ConnectionRefusedError"} for camera in CAMERAS}}


def contract(cfg, health):
    return {"schemaVersion": 1, "expectedConfigSha256": CONFIG_SHA,
            "expectedDeploymentSha256": DEPLOYMENT_SHA,
            "expectedFailureSha256": deployment_health.failure_fingerprint(cfg, health, now_ms=NOW)}


class ExistingDependencyHealthContracts(unittest.TestCase):
    def setUp(self):
        self.cfg, self.before = configuration(), failed_health()
        self.request = contract(self.cfg, self.before)
        self.baseline = deployment_health.prepare_baseline(self.cfg, self.before, self.request,
            config_sha256=CONFIG_SHA, deployment_sha256=DEPLOYMENT_SHA, now_ms=NOW)

    def test_fingerprint_ignores_normal_poll_progress_but_binds_existing_failure(self):
        later = copy.deepcopy(self.before)
        later["atMs"] += 1000
        later["nativeWorkerAgeMs"] += 10
        later["counters"]["sourceEvents"] += 25
        for row in later["bridges"].values():
            row["lastSuccessMs"] += 1000
        for row in later["frigate"].values():
            row["consecutiveErrors"] += 10
        self.assertEqual(deployment_health.failure_fingerprint(self.cfg, later, now_ms=NOW + 1000),
                         self.request["expectedFailureSha256"])
        later["frigate"][CAMERAS[0]]["lastSuccessMs"] -= 1000
        self.assertNotEqual(deployment_health.failure_fingerprint(self.cfg, later, now_ms=NOW + 1000),
                            self.request["expectedFailureSha256"])

    def test_prebaseline_rejects_stale_new_partial_or_unrelated_failures(self):
        mutations = [
            lambda v: v.update(atMs=NOW - 30001),
            lambda v: v.update(atMs=NOW + 5001),
            lambda v: v.update(nativeReady=False),
            lambda v: v.update(nativeWorkerAgeMs=30001),
            lambda v: v.update(pending=1), lambda v: v.update(retryIntervals=1),
            lambda v: v.update(pendingThumbnails=1), lambda v: v.update(failedThumbnails=1),
            lambda v: v.update(thumbnailErrorReasons={"snapshot_timeout": 1}),
            lambda v: v["bridges"][CAMERAS[0]].update(lastSuccessMs=NOW - 30001),
            lambda v: v["bridges"][CAMERAS[0]].update(sourceBacklog=1),
            lambda v: v["bridges"][CAMERAS[0]].update(consecutiveErrors=1),
            lambda v: v["frigate"].pop(CAMERAS[0]),
            lambda v: v["frigate"][CAMERAS[0]].update(errorType="TimeoutError"),
            lambda v: v["frigate"][CAMERAS[0]].update(consecutiveErrors=0),
            lambda v: v["frigate"][CAMERAS[0]].update(lastSuccessMs=NOW - 30000),
            lambda v: v["frigate"][CAMERAS[0]].pop("lastSuccessMs"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                value = copy.deepcopy(self.before)
                mutate(value)
                with self.assertRaises(RuntimeError):
                    deployment_health.failure_fingerprint(self.cfg, value, now_ms=NOW)

    def test_contract_rejects_hash_schema_scope_and_unknown_field_changes(self):
        changes = [{"schemaVersion": True}, {"schemaVersion": 2}, {"extra": True},
                   {"expectedConfigSha256": "c" * 64}, {"expectedDeploymentSha256": "c" * 64},
                   {"expectedFailureSha256": "c" * 64}, {"expectedFailureSha256": "z" * 64}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                deployment_health.prepare_baseline(self.cfg, self.before, dict(self.request, **change),
                    config_sha256=CONFIG_SHA, deployment_sha256=DEPLOYMENT_SHA, now_ms=NOW)
        for mutate in (lambda cfg: cfg["bridges"].pop(),
                       lambda cfg: cfg["frigate"]["cameraMap"].pop("fixture_0"),
                       lambda cfg: cfg["bridges"][0].update(cameraId=CAMERAS[1])):
            cfg = copy.deepcopy(self.cfg)
            mutate(cfg)
            with self.assertRaises(RuntimeError):
                deployment_health.prepare_baseline(cfg, self.before, self.request,
                    config_sha256=CONFIG_SHA, deployment_sha256=DEPLOYMENT_SHA, now_ms=NOW)

    def test_known_failure_acceptance_preserves_truthful_health_and_allows_restart_state(self):
        for no_prior_success in (False, True):
            with self.subTest(no_prior_success=no_prior_success):
                after = failed_health(post=True)
                after["counters"]["sourceEvents"] += 40
                if no_prior_success:
                    for row in after["frigate"].values():
                        row.pop("lastSuccessMs")
                        row["consecutiveErrors"] = 1
                snapshot = copy.deepcopy(after)
                self.assertEqual(deployment_health.accept(self.cfg, after, self.baseline,
                    started_ms=NOW, now_ms=NOW + 1000), SPECIAL)
                self.assertEqual(after, snapshot)
                self.assertFalse(after["healthy"])

    def test_postbaseline_rejects_new_errors_stale_worker_or_partial_recovery(self):
        mutations = [
            lambda v: v.update(atMs=NOW),
            lambda v: v.update(workerStopped=True),
            lambda v: v.update(nativeWorkerAgeMs=30001),
            lambda v: v.update(importErrors=1),
            lambda v: v.update(pending=1),
            lambda v: v["counters"].update(nativeImportErrors=3),
            lambda v: v["counters"].update(replayGaps=1),
            lambda v: v["bridges"][CAMERAS[0]].update(lastSuccessMs=NOW),
            lambda v: v["frigate"][CAMERAS[0]].update(errorType="URLError"),
            lambda v: v["frigate"][CAMERAS[0]].update(lastSuccessMs=NOW + 500),
            lambda v: v["frigate"][CAMERAS[0]].update(consecutiveErrors=0, errorType=None,
                                                     lastSuccessMs=NOW + 500),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                value = failed_health(post=True)
                mutate(value)
                with self.assertRaises(RuntimeError):
                    deployment_health.accept(self.cfg, value, self.baseline,
                        started_ms=NOW, now_ms=NOW + 1000)

    def test_fully_healthy_recovery_uses_ordinary_acceptance(self):
        value = failed_health(post=True)
        value.update(healthy=True, captureHealthy=True, frigateHealthy=True)
        for row in value["frigate"].values():
            row.update(lastSuccessMs=NOW + 500, consecutiveErrors=0)
            row.pop("errorType")
        self.assertEqual(deployment_health.accept(self.cfg, value, self.baseline,
            started_ms=NOW, now_ms=NOW + 1000), "healthy")
        value["frigate"][CAMERAS[0]]["lastSuccessMs"] = NOW - 30001
        with self.assertRaises(RuntimeError):
            deployment_health.accept(self.cfg, value, self.baseline,
                started_ms=NOW, now_ms=NOW + 1000)


class ExistingDependencyInstallerContracts(unittest.TestCase):
    def setUp(self):
        # Reuse only the existing synthetic installer fixture, not its tests.
        self.fixture = deploy_tests.ScopedInstallerTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installer = self.fixture.installer
        self.fixture.cfg.update(configuration())
        (self.fixture.root / "config.json").write_text(json.dumps(self.fixture.cfg))
        self.before = failed_health()
        self.started = False
        self.post_transform = lambda value: None
        self.command_hook = None
        self.ticks = 0
        patches = [patch.object(self.installer, "health", self.health),
                   patch.object(self.installer.time, "time", return_value=NOW / 1000),
                   patch.object(self.installer.time, "monotonic", side_effect=lambda: self.ticks),
                   patch.object(self.installer.time, "sleep", side_effect=self.sleep)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.fixture.run_hook = self.command

    def sleep(self, _seconds):
        self.ticks += 40  # A failed poll immediately expires the synthetic gate.

    def command(self, args):
        if args == ["systemctl", "start", self.fixture.unit.name]:
            self.started = True
        if self.command_hook:
            self.command_hook(args)

    def health(self):
        value = failed_health(post=True) if self.started else copy.deepcopy(self.before)
        if self.started:
            self.post_transform(value)
        return {"health": value, "monitor": {"active": False, "enabled": False},
                "active": "active", "enabled": "enabled", "configPrivate": True}

    def request(self, **extra):
        failure = {"schemaVersion": 1,
            "expectedConfigSha256": hashlib.sha256((self.fixture.root / "config.json").read_bytes()).hexdigest(),
            "expectedDeploymentSha256": hashlib.sha256((self.fixture.root / "deployment.json").read_bytes()).hexdigest(),
            "expectedFailureSha256": deployment_health.failure_fingerprint(
                self.fixture.cfg, self.before, now_ms=NOW)}
        return self.fixture.request(existingFrigateFailure=failure, **extra)

    def owned_files(self):
        paths = (self.fixture.unit, self.fixture.monitor, self.fixture.root / "config.json",
                 self.fixture.root / "deployment.json", self.fixture.monitor_root / "maintenance.json")
        return {path: path.read_bytes() for path in paths}

    def stopped(self):
        return [call for call in self.fixture.calls
                if isinstance(call, tuple) and call[:2] == ("systemctl", "stop")]

    def test_scoped_acceptance_keeps_false_health_config_monitor_and_lease_truthful(self):
        original = self.owned_files()
        result = self.installer.execute(self.request())
        self.assertTrue(result["ok"])
        self.assertEqual(result["deploymentAcceptance"], SPECIAL)
        self.assertFalse(result["health"]["healthy"])
        self.assertFalse(result["health"]["frigateHealthy"])
        self.assertEqual(self.fixture.monitor_commands(), [])
        for path in (self.fixture.monitor, self.fixture.root / "config.json",
                     self.fixture.monitor_root / "maintenance.json"):
            self.assertEqual(path.read_bytes(), original[path])
        self.assertEqual(self.stopped(), [("systemctl", "stop", self.fixture.unit.name)])

    def test_without_explicit_contract_the_same_outage_still_fails_strict_gate(self):
        original = self.owned_files()
        with self.assertRaisesRegex(RuntimeError, "deployment_health_timeout"):
            self.installer.execute(self.fixture.request())
        self.assertEqual(self.owned_files(), original)
        self.assertEqual(self.fixture.monitor_commands(), [])

    def test_invalid_scope_or_file_hash_is_rejected_before_stopping(self):
        requests = [self.request(eventsOnly=False), self.request(mode="capture"),
                    self.request(updateMonitor=True),
                    self.request(eventGrouping={"enabled": True, "maxSpanSeconds": 120}),
                    self.request(fmp4Startup={"enabled": False})]
        changed = self.request()
        changed["existingFrigateFailure"]["expectedConfigSha256"] = "c" * 64
        requests.append(changed)
        changed = self.request()
        changed["existingFrigateFailure"]["expectedDeploymentSha256"] = "c" * 64
        requests.append(changed)
        original = self.owned_files()
        for request in requests:
            with self.subTest(request_keys=sorted(request)), self.assertRaises(RuntimeError):
                self.installer.execute(request)
            self.assertEqual(self.stopped(), [])
            self.assertEqual(self.owned_files(), original)

    def test_new_postdeployment_error_restores_prior_files_and_keeps_maintenance(self):
        original = self.owned_files()
        self.post_transform = lambda value: value["counters"].update(nativeImportErrors=3)
        with self.assertRaisesRegex(RuntimeError, "deployment_health_timeout"):
            self.installer.execute(self.request())
        self.assertEqual(self.owned_files(), original)
        self.assertEqual(self.fixture.monitor_commands(), [])

    def test_new_error_during_preparation_is_rejected_by_second_server_baseline(self):
        request = self.request()
        original = self.owned_files()

        def mutate(args):
            if args[:3] == ["/usr/bin/python3", "-m", "compileall"]:
                self.before["counters"]["nativeImportErrors"] = 3

        self.command_hook = mutate
        with self.assertRaisesRegex(RuntimeError, "existing_frigate_failure_CAS_mismatch"):
            self.installer.execute(request)
        self.assertEqual(self.stopped(), [])
        self.assertEqual(self.owned_files(), original)

    def test_losing_lease_during_stop_prevents_owned_writes_and_preserves_new_owner(self):
        original = self.owned_files()
        marker = self.fixture.monitor_root / "maintenance.json"
        new_owner = json.dumps({"owner": "f" * 32}).encode()

        def mutate(args):
            if args == ["systemctl", "stop", self.fixture.unit.name]:
                marker.write_bytes(new_owner)

        self.command_hook = mutate
        with self.assertRaisesRegex(RuntimeError, "maintenance"):
            self.installer.execute(self.request())
        self.assertEqual(marker.read_bytes(), new_owner)
        for path in (self.fixture.unit, self.fixture.root / "config.json", self.fixture.root / "deployment.json"):
            self.assertEqual(path.read_bytes(), original[path])

    def test_explicit_rollback_of_scoped_release_requires_owner_and_restores_prior_files(self):
        original = self.owned_files()
        self.assertTrue(self.installer.execute(self.request())["ok"])
        stops = len(self.stopped())
        with self.assertRaisesRegex(RuntimeError, "maintenance"):
            self.installer.execute({"mode": "rollback", "expectedDigest": "b" * 64,
                                    "owner": "f" * 32})
        self.assertEqual(len(self.stopped()), stops)
        result = self.installer.execute({"mode": "rollback", "expectedDigest": "b" * 64,
                                         "owner": self.fixture.owner})
        self.assertTrue(result["ok"])
        self.assertTrue(result["journalPreserved"])
        self.assertEqual(self.owned_files(), original)
        self.assertEqual(self.fixture.monitor_commands(), [])

    def test_fully_healthy_same_release_resume_uses_ordinary_strict_path(self):
        metadata = dict(self.fixture.prior, sha256="b" * 64, eventsOnly=True,
                        updateMonitor=False, activatedAtMs=NOW - 10000)
        (self.fixture.root / "deployment.json").write_text(json.dumps(metadata))
        self.before.update(healthy=True, captureHealthy=True, frigateHealthy=True)
        for row in self.before["frigate"].values():
            row.update(lastSuccessMs=NOW - 100, consecutiveErrors=0)
            row.pop("errorType")
        original = self.owned_files()
        result = self.installer.execute(self.fixture.request())
        self.assertTrue(result["ok"])
        self.assertTrue(result["resumedExistingDeployment"])
        self.assertTrue(result["health"]["healthy"])
        self.assertNotEqual(result.get("deploymentAcceptance"), SPECIAL)
        self.assertEqual(self.owned_files(), original)
        self.assertEqual(self.stopped(), [])

    def test_foreign_edit_during_stop_survives_write_and_rollback_checks(self):
        for target_name in ("unit", "config", "deployment"):
            with self.subTest(target=target_name):
                target = {"unit": self.fixture.unit,
                          "config": self.fixture.root / "config.json",
                          "deployment": self.fixture.root / "deployment.json"}[target_name]
                original = self.owned_files()
                foreign = b"external-owner-change-" + target_name.encode()
                changed = [False]

                def mutate(args):
                    if args == ["systemctl", "stop", self.fixture.unit.name] and not changed[0]:
                        target.write_bytes(foreign)
                        changed[0] = True

                self.command_hook = mutate
                try:
                    with self.assertRaisesRegex(RuntimeError, "drift|CAS"):
                        self.installer.execute(self.request())
                    self.assertEqual(target.read_bytes(), foreign)
                    marker = self.fixture.monitor_root / "maintenance.json"
                    self.assertEqual(marker.read_bytes(), original[marker])
                finally:
                    self.command_hook = None
                    self.started = False
                    self.ticks = 0
                    for path, content in original.items():
                        path.write_bytes(content)


if __name__ == "__main__":
    unittest.main()
