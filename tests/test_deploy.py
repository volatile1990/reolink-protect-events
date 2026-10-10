import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest


class RollbackTests(unittest.TestCase):
    def setUp(self):
        module_path = Path(__file__).resolve().parents[1] / "tools" / "deploy.py"
        spec = importlib.util.spec_from_file_location("deploy_tool", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.env = {}
        exec(module.REMOTE.split("os.umask(0o077)")[0], self.env)
        self.temp = tempfile.TemporaryDirectory(prefix="reolink-deploy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.unit = self.root / "native.service"
        self.backup = self.root / "backups" / "prior"
        self.backup.mkdir(parents=True)
        self.calls = []
        self.env.update(root=self.root, unit=self.unit, service=self.unit.name,
                        secure=lambda path: None, run=self.calls.append,
                        subprocess=types.SimpleNamespace(
                            DEVNULL=None, run=lambda args, **kwargs: self.calls.append(args)))
        for path in (self.unit, self.root / "config.json", self.root / "deployment.json"):
            path.write_bytes(b"new deployment")
        (self.root / "journal.sqlite").write_bytes(b"retained journal")

    def state(self, active=False, enabled=False):
        (self.backup / "service-state.json").write_text(json.dumps(
            {"active": active, "enabled": enabled}))

    def test_first_install_failure_removes_new_unit_and_credentials(self):
        self.state()
        self.env["restore"](self.backup)
        for path in (self.unit, self.root / "config.json", self.root / "deployment.json"):
            self.assertFalse(path.exists())
        self.assertEqual((self.root / "journal.sqlite").read_bytes(), b"retained journal")
        self.assertIn(["systemctl", "disable", self.unit.name], self.calls)
        self.assertNotIn(["systemctl", "start", self.unit.name], self.calls)

    def test_previous_active_enabled_release_is_restored(self):
        self.state(active=True, enabled=True)
        for path in (self.unit, self.root / "config.json", self.root / "deployment.json"):
            (self.backup / path.name).write_bytes(b"previous deployment")
        self.env["restore"](self.backup)
        self.assertEqual(self.unit.read_bytes(), b"previous deployment")
        self.assertIn(["systemctl", "enable", self.unit.name], self.calls)
        self.assertIn(["systemctl", "start", self.unit.name], self.calls)

    def test_previous_inactive_disabled_release_stays_inactive(self):
        self.state()
        (self.backup / self.unit.name).write_bytes(b"previous deployment")
        self.env["restore"](self.backup)
        self.assertTrue(self.unit.exists())
        self.assertNotIn(["systemctl", "start", self.unit.name], self.calls)
        self.assertNotIn(["systemctl", "enable", self.unit.name], self.calls)


if __name__ == "__main__":
    unittest.main()
