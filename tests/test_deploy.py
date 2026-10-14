import importlib.util
import ast
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
                        monitor_unit=self.root / 'monitor.service', monitor_root=self.root / 'monitor',
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


class DeploymentPreparationTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'tools/deploy.py'
        spec = importlib.util.spec_from_file_location('deploy_prepare_tool', path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_embedded_remote_and_complete_stdin_program_compile_before_connection(self):
        ast.parse(self.tool.REMOTE)
        script = "mode='status'\npackage=''\ndigest=''\ntry:\n" + '\n'.join(' ' + line for line in self.tool.REMOTE.splitlines())
        script += "\nexcept Exception:\n raise SystemExit(1)\n"
        compile(script, 'deployment-stdin.py', 'exec')

    def test_upgrade_preserves_active_config_and_first_install_falls_back_to_legacy(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            current, legacy, defaults = root / 'config.json', root / 'legacy.json', root / 'defaults.json'
            bridges = [{'cameraId': '%024x' % index, 'host': '192.168.30.' + str(index + 209),
                        'username': 'fixture-user', 'password': 'fixture-password'} for index in range(1, 7)]
            old = {'bridges': bridges, 'protectUserId': 'fixture-user', 'bridgeEventStaleSeconds': 120}
            active = {**old, 'bridgeEventStaleSeconds': 45, 'dsProxyPort': 7449, 'customSetting': 'preserve-active'}
            legacy.write_text(json.dumps(old));current.write_text(json.dumps(active))
            defaults.write_text(json.dumps({'ports': {'dsProxy': 7448}}))
            def path_factory(value):
                if value == '/data/reolink-bridge-events/config.json': return legacy
                if value == '/usr/share/unifi-protect/app/config/default.json': return defaults
                return Path(value)
            env = {}
            exec(self.tool.REMOTE.split('os.umask(0o077)')[0], env)
            env.update(root=root, secure=lambda path: None,
                       pathlib=types.SimpleNamespace(Path=path_factory),
                       get_bytes=lambda *args, **kwargs: (200, json.dumps({'nvr': {'version': '7.3.70'},
                           'cameras': [dict(row, id=row['cameraId'], mac='0011223344%02x' % index) for index, row in enumerate(bridges)]}).encode()))
            from unittest.mock import patch
            import os
            actual_stat = Path.stat
            def private_stat(path, *args, **kwargs):
                result = actual_stat(path, *args, **kwargs)
                if path in (current, legacy):
                    values = list(result);values[0] = 0o100600
                    return os.stat_result(values)
                return result
            with patch.object(Path, 'stat', private_stat):
                cfg = env['get_config']()
                self.assertEqual(cfg['bridgeEventStaleSeconds'], 45)
                self.assertEqual(cfg['dsProxyPort'], 7449)
                self.assertEqual(cfg['customSetting'], 'preserve-active')
                self.assertEqual(cfg['bridges'][0]['password'], 'fixture-password')
                current.unlink()
                cfg = env['get_config']()
                self.assertEqual(cfg['bridgeEventStaleSeconds'], 120)
                self.assertEqual(cfg['dsProxyPort'], 7448)


if __name__ == "__main__":
    unittest.main()
