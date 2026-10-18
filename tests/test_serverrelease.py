"""Public-source release determinism, committed provenance and CAS boundaries."""
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_server_release as builder
import serverrelease as release
from reolink_protect_events.operations.heimserver import REQUIRED, verified_bundle


def source_tree(root):
    for member in sorted(REQUIRED | {"events/reolink_protect_events/operations/__init__.py"}):
        source = root / (member[len("events/"):] if member.startswith("events/") else "services/" + member)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"VALUE = 1\r\n" if source.suffix == ".py" else b"'use strict';\r\nmodule.exports = {};\r\n")
    (root / ".gitignore").write_text("artifacts/\nignored_source.py\n", encoding="utf-8")


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name) / "repo"
        self.root.mkdir(); source_tree(self.root)
        self.addCleanup(self.folder.cleanup)

    def test_repeated_builds_and_different_mtimes_have_identical_manifest_and_zip(self):
        first, info = builder.release_bytes(self.root)
        for path in self.root.rglob("*"):
            if path.is_file(): os.utime(path, (1234567890, 1234567890))
        second, again = builder.release_bytes(self.root)
        self.assertEqual(first, second)
        self.assertEqual(info, again)
        manifest, members = verified_bundle(first, info["digest"])
        self.assertEqual(manifest["version"], "2.0.0")
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["members"], sorted(manifest["members"], key=lambda row: row["path"]))
        self.assertEqual(members["controls/worker.py"], b"VALUE = 1\n")
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertTrue(all(row.date_time == (1980, 1, 1, 0, 0, 0) for row in archive.infolist()))

    def test_only_in_repo_public_sources_are_enrolled_and_private_state_is_untouched(self):
        private = self.root / "state/journal.sqlite3"
        private.parent.mkdir(); private.write_bytes(b"synthetic-private-journal")
        conf = self.root / "reolink_protect_events/config.json"
        conf.write_text('{"password":"synthetic-private-configuration"}')
        historical = self.root.parent / "reolink-protect-controls"
        historical.mkdir(); (historical / "worker.py").write_text("historical_source_must_not_be_used")
        data, result = builder.release_bytes(self.root)
        _, members = verified_bundle(data, result["digest"])
        content = b"\n".join(members.values())
        self.assertNotIn(b"synthetic-private", content)
        self.assertNotIn(b"historical_source", content)
        self.assertEqual(private.read_bytes(), b"synthetic-private-journal")
        self.assertEqual(json.loads(conf.read_text())["password"], "synthetic-private-configuration")

    def test_each_canonical_service_change_changes_the_release_digest(self):
        _, old = builder.release_bytes(self.root)
        for relative in builder.ASSETS.values():
            source = self.root / relative
            original = source.read_bytes()
            source.write_bytes(original + (b"# updated\n" if source.suffix == ".py" else b"// updated\n"))
            _, changed = builder.release_bytes(self.root)
            self.assertNotEqual(old["digest"], changed["digest"])
            source.write_bytes(original)

    def test_missing_asset_bad_python_and_private_key_marker_fail_before_output(self):
        output = self.root / "artifacts"
        source = self.root / "services/controls/worker.py"
        for content in (b"def broken(:\n", b"# -----BEGIN OPENSSH PRIVATE KEY-----\n"):
            source.write_bytes(content)
            with self.assertRaises(builder.BuildError): builder.build(self.root, output)
            self.assertFalse(output.exists())
        source.unlink()
        with self.assertRaises(builder.BuildError): builder.build(self.root, output)

    def test_symlinked_service_source_is_refused(self):
        source = self.root / "services/controls/worker.py"
        external = self.root.parent / "external.py"; external.write_text("VALUE = 2\n")
        source.unlink()
        try: source.symlink_to(external)
        except OSError: self.skipTest("symlink creation requires additional Windows privileges")
        with self.assertRaises(builder.BuildError): builder.release_bytes(self.root)

    def test_artifact_is_reusable_but_modified_existing_zip_is_never_overwritten(self):
        output = self.root / "artifacts"
        first = builder.build(self.root, output)
        self.assertEqual(builder.build(self.root, output), first)
        target = Path(first["bundle"]); target.write_bytes(b"changed-public-artifact")
        with self.assertRaisesRegex(builder.BuildError, "server_build_output_changed"):
            builder.build(self.root, output)
        self.assertEqual(target.read_bytes(), b"changed-public-artifact")

    @unittest.skipUnless(shutil.which("git"), "git is needed for committed-source contracts")
    def test_clean_flag_proves_committed_sources_and_rejects_dirty_or_ignored_sources(self):
        def git(*args):
            result = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, check=True)
            return result.stdout.decode().strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(self.root / "no-hooks"),
            "commit", "-qm", "synthetic fixture")
        _, result = builder.release_bytes(self.root, require_clean=True)
        self.assertEqual(result["sourceRevision"], git("rev-parse", "HEAD"))
        source = self.root / "reolink_protect_events/runtime.py"
        original = source.read_bytes(); source.write_bytes(original + b"# changed\n")
        with self.assertRaisesRegex(builder.BuildError, "server_build_requires_clean_commit"):
            builder.release_bytes(self.root, require_clean=True)
        source.write_bytes(original)
        # Hidden from git status, but still an otherwise eligible package member.
        ignored = self.root / "reolink_protect_events/ignored_source.py"
        ignored.write_text("VALUE = 2\n")
        with self.assertRaisesRegex(builder.BuildError, "server_build_source_not_committed"):
            builder.release_bytes(self.root, require_clean=True)


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.bundle = self.root / "public.zip"; self.bundle.write_bytes(b"public-runtime-code")
        self.old, self.new, self.head = "a" * 64, "b" * 64, "c" * 40
        self.current = self.old
        self.calls, self.order = [], []
        self.fail_postcheck = False

    def run_fixture_tests(self, root, node):
        self.order.append("tests")

    def build(self, root, output_dir, require_clean):
        self.order.append("build"); self.assertTrue(require_clean)
        return {"ok": True, "digest": self.new, "sourceRevision": self.head, "bundle": str(self.bundle)}

    def remote(self, request):
        self.calls.append(request); self.order.append(request["mode"])
        if request["mode"] == "stage":
            self.assertEqual(base64.b64decode(request["bundle"]), b"public-runtime-code")
            return {"ok": True, "digest": self.new}
        if request["mode"] == "activate":
            if request["expectedCurrent"] != self.current: return {"ok": False}
            self.current = request["digest"]
        elif request["mode"] == "rollback":
            if request["expectedCurrent"] != self.current: return {"ok": False}
            self.current = self.old
        elif self.fail_postcheck and self.current == self.new and "digest" not in request:
            return {"ok": False}
        return {"ok": True, "deployment": {"digest": self.current}}

    def update(self, **kwargs):
        return release.update(self.root, tests=self.run_fixture_tests, builder=self.build, remote=self.remote,
                              source_revision=lambda *args, **options: (self.head, False), **kwargs)

    def test_order_and_cas_never_send_configuration_or_state_restore_requests(self):
        state = self.root / "journal.sqlite3"; state.write_bytes(b"preserve-journal")
        result = self.update()
        self.assertEqual(self.order, ["tests", "build", "check", "stage", "check", "activate", "check"])
        self.assertEqual(self.calls[-2], {"mode": "activate", "digest": self.new, "expectedCurrent": self.old})
        self.assertTrue(result["activated"])
        self.assertFalse(result["privateConfigsIncluded"])
        self.assertFalse(result["privateStateRestoreRequested"])
        self.assertEqual(state.read_bytes(), b"preserve-journal")
        self.assertTrue(all(set(row) <= {"mode", "digest", "bundle", "expectedCurrent"} for row in self.calls))

    def test_changed_reviewed_identity_stops_before_stage(self):
        with self.assertRaisesRegex(release.ReleaseError, "server_release_current_changed"):
            self.update(expected_current="d" * 64)
        self.assertEqual([row["mode"] for row in self.calls], ["check"])
        self.assertEqual(self.current, self.old)

    def test_failed_tests_or_different_tested_commit_never_touch_server(self):
        def fail(*args, **kwargs): raise release.ReleaseError("server_release_tests_failed")
        with self.assertRaises(release.ReleaseError):
            release.update(self.root, tests=fail, builder=self.build, remote=self.remote,
                           source_revision=lambda *args, **kwargs: (self.head, False))
        self.assertEqual(self.calls, [])
        actual_build = self.build
        def changed(*args, **kwargs): return dict(actual_build(*args, **kwargs), sourceRevision="d" * 40)
        with self.assertRaisesRegex(release.ReleaseError, "tested_revision_changed"):
            release.update(self.root, tests=self.run_fixture_tests, builder=changed, remote=self.remote,
                           source_revision=lambda *args, **kwargs: (self.head, False))
        self.assertEqual(self.calls, [])

    def test_repeating_an_already_installed_digest_is_readonly(self):
        self.current = self.new
        result = self.update()
        self.assertTrue(result["alreadyCurrent"])
        self.assertFalse(result["activated"])
        self.assertEqual(self.calls, [{"mode": "check"}])

    def test_failed_postcheck_uses_only_a_cas_public_code_rollback(self):
        self.fail_postcheck = True
        with self.assertRaisesRegex(release.ReleaseError, "postcheck_failed_rolled_back"):
            self.update()
        self.assertEqual(self.calls[-1], {"mode": "rollback", "expectedCurrent": self.new})
        self.assertEqual(self.current, self.old)

    def test_activation_transport_failure_is_not_blindly_retried_or_rolled_back(self):
        def remote(request):
            if request["mode"] == "activate":
                self.calls.append(request)
                raise TimeoutError("synthetic private detail")
            return self.remote(request)
        with self.assertRaises(TimeoutError):
            release.update(self.root, tests=self.run_fixture_tests, builder=self.build, remote=remote,
                           source_revision=lambda *args, **kwargs: (self.head, False))
        self.assertEqual([row["mode"] for row in self.calls].count("activate"), 1)
        self.assertNotIn("rollback", [row["mode"] for row in self.calls])

    def test_activation_failure_retains_only_safe_restoration_status(self):
        def remote(request):
            if request["mode"] == "activate":
                return {"ok": False, "previousReleaseRestored": True, "manualInspectionRequired": False,
                        "privateConfigPreserved": True, "privateConfigAndStateReplaced": False,
                        "config": "synthetic-private-data", "errorCode": "untrusted-remote-detail"}
            return self.remote(request)
        with self.assertRaises(release.ReleaseError) as caught:
            release.update(self.root, tests=self.run_fixture_tests, builder=self.build, remote=remote,
                           source_revision=lambda *args, **kwargs: (self.head, False))
        self.assertEqual(caught.exception.details, {"previousReleaseRestored": True,
            "manualInspectionRequired": False, "privateConfigPreserved": True,
            "privateConfigAndStateReplaced": False})
        self.assertNotIn("synthetic-private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
