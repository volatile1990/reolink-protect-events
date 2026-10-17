import importlib.util
import ast
import base64
import copy
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import types
import unittest
from unittest.mock import patch


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
                        state_of=lambda name: {'active': True, 'enabled': True},
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


class ScopedInstallerTests(unittest.TestCase):
    def setUp(self):
        from reolink_protect_events.operations import installer
        self.installer = installer
        self.temp = tempfile.TemporaryDirectory(prefix='events-only-deploy-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'events'
        self.root.mkdir()
        self.unit = Path(self.temp.name) / 'native.service'
        self.monitor = Path(self.temp.name) / 'monitor.service'
        self.monitor_root = Path(self.temp.name) / 'monitor'
        self.monitor_root.mkdir()
        self.owner = 'a' * 32
        (self.monitor_root / 'maintenance.json').write_text(json.dumps({'owner': self.owner}))
        self.unit.write_bytes(b'previous native unit')
        self.monitor.write_bytes(b'previous monitor unit')
        self.cfg = {'customSetting': 'preserved', 'thumbnailSelection': {'mode': 'fixed', 'custom': 17},
                    'bridges': [{'privateFixture': 'fixture-only'}]}
        (self.root / 'config.json').write_text(json.dumps(self.cfg))
        self.prior = {'sha256': 'prior-digest', 'mode': 'install', 'version': '1.4.0',
                      'release': str(self.root / 'releases' / 'old'), 'backup': str(self.root / 'backups' / 'old')}
        (self.root / 'deployment.json').write_text(json.dumps(self.prior))
        with closing(sqlite3.connect(self.root / 'journal.sqlite3')) as database, database:
            database.execute('CREATE TABLE genuine_source(id INTEGER)')
            database.execute('INSERT INTO genuine_source VALUES(11)')
        module = b'"""Synthetic projection capability fixture."""\n'
        self.manifest = {'version': '1.5.0', 'sourceRevision': 'fixture-revision', 'sourceSha256': 'fixture-source',
                         'members': [{'path': 'reolink_protect_events/visual_groups.py',
                                      'sha256': hashlib.sha256(module).hexdigest()}]}
        self.members = {'reolink_protect_events/visual_groups.py': module,
                        'reolink_protect_events/release.json': json.dumps(self.manifest).encode()}
        self.calls = []
        self.health_monitor = False
        self.run_hook = None
        changes = dict(root=self.root, unit=self.unit, service=self.unit.name,
                       monitor_unit=self.monitor, monitor_root=self.monitor_root,
                       secure=lambda path: None, run=self.run_command,
                       state_of=lambda name: {'active': name == self.unit.name, 'enabled': name == self.unit.name},
                       verified_members=lambda *args: (self.members, self.manifest),
                       get_config=lambda: copy.deepcopy(self.cfg), health=self.health,
                       validate_packaged_config=lambda *args: self.calls.append(('validate', args)))
        self.patches = patch.multiple(installer, **changes)
        self.patches.start()
        self.addCleanup(self.patches.stop)
        proc = patch.object(installer.subprocess, 'run', side_effect=self.process)
        proc.start()
        self.addCleanup(proc.stop)
        uid = patch.object(installer.os, 'geteuid', return_value=0, create=True)
        uid.start()
        self.addCleanup(uid.stop)

    def process(self, args, **kwargs):
        self.calls.append(tuple(args))
        return types.SimpleNamespace(returncode=0)

    def run_command(self, args):
        self.calls.append(tuple(args))
        if self.run_hook:
            self.run_hook(args)
        return 'active'

    def health(self):
        return {'health': {'healthy': True, 'atMs': int(time.time() * 1000) + 1000, 'mode': 'native'},
                'monitor': {'active': self.health_monitor, 'enabled': self.health_monitor}}

    def request(self, **extra):
        return dict({'mode': 'install', 'eventsOnly': True, 'owner': self.owner,
                     'package': base64.b64encode(b'fixture-package').decode(), 'digest': 'b' * 64}, **extra)

    def enroll_group(self):
        with closing(sqlite3.connect(self.root / 'journal.sqlite3')) as database, database:
            database.execute('CREATE TABLE IF NOT EXISTS visual_group_members(id INTEGER)')
            database.execute('INSERT INTO visual_group_members VALUES(22)')

    def enroll_manual_group(self):
        with closing(sqlite3.connect(self.root / 'journal.sqlite3')) as database, database:
            database.execute('CREATE TABLE IF NOT EXISTS visual_group_manual(group_id TEXT PRIMARY KEY)')
            database.execute("INSERT INTO visual_group_manual VALUES('historical-parcel')")

    def set_package_manual_capability(self):
        module = self.members['reolink_protect_events/visual_groups.py'] + b'MANUAL_GROUP_SCHEMA_VERSION = 1\n'
        self.members['reolink_protect_events/visual_groups.py'] = module
        self.manifest['members'][0]['sha256'] = hashlib.sha256(module).hexdigest()
        self.members['reolink_protect_events/release.json'] = json.dumps(self.manifest).encode()

    def rollback_target(self, manual=False):
        release = Path(self.prior['release']) / 'reolink_protect_events'
        release.mkdir(parents=True)
        module = b'"""Verified previous projection runtime."""\n'
        if manual:
            module += b'MANUAL_GROUP_SCHEMA_VERSION = 1\n'
        (release / 'visual_groups.py').write_bytes(module)
        (release / 'release.json').write_text(json.dumps({'members': [
            {'path': 'reolink_protect_events/visual_groups.py', 'sha256': hashlib.sha256(module).hexdigest()}]}))
        target = dict(self.prior, visualGroupCompatible=True, version='1.5.1' if manual else '1.5.0')
        backup = Path(self.prior['backup'])
        backup.mkdir(parents=True)
        (backup / 'deployment.json').write_text(json.dumps(target))
        return target, backup

    def monitor_commands(self):
        return [args for args in self.calls if isinstance(args, tuple) and len(args) > 2
                and args[0] == 'systemctl' and args[-1] == self.monitor.name]

    def test_events_only_preserves_monitor_and_thumbnail_config_and_backs_up_current_journal(self):
        result = self.installer.execute(self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': 120}))
        self.assertTrue(result['ok'])
        self.assertEqual(self.monitor.read_bytes(), b'previous monitor unit')
        self.assertEqual(self.monitor_commands(), [])
        config = json.loads((self.root / 'config.json').read_text())
        self.assertEqual(config.pop('eventGrouping'), {'enabled': True, 'maxSpanSeconds': 120})
        self.assertEqual(config, self.cfg)
        deployed = json.loads((self.root / 'deployment.json').read_text())
        self.assertTrue(deployed['eventsOnly'])
        self.assertTrue(deployed['visualGroupCompatible'])
        backup = Path(deployed['backup'])
        self.assertTrue(json.loads((backup / 'service-state.json').read_text())['eventsOnly'])
        self.assertFalse((backup / self.monitor.name).exists())
        with closing(sqlite3.connect(backup / 'journal.sqlite3')) as database:
            self.assertEqual(database.execute('SELECT id FROM genuine_source').fetchall(), [(11,)])
        validation = next(i for i, call in enumerate(self.calls) if call[0] == 'validate')
        stop = self.calls.index(('systemctl', 'stop', self.unit.name))
        self.assertLess(validation, stop)

    def test_default_install_retains_full_installer_behavior(self):
        self.health_monitor = True
        result = self.installer.execute(self.request(eventsOnly=False))
        self.assertTrue(result['ok'])
        self.assertNotEqual(self.monitor.read_bytes(), b'previous monitor unit')
        self.assertIn(('systemctl', 'start', self.monitor.name), self.monitor_commands())
        config = json.loads((self.root / 'config.json').read_text())
        self.assertEqual(config['thumbnailSelection']['mode'], 'automatic')

    def test_events_only_without_group_request_preserves_config_bytes(self):
        original = json.dumps(self.cfg, indent=3).encode() + b'\n'
        (self.root / 'config.json').write_bytes(original)
        self.assertTrue(self.installer.execute(self.request())['ok'])
        self.assertEqual((self.root / 'config.json').read_bytes(), original)

    def test_events_only_ordinary_failure_restores_prior_release_without_monitor_actions(self):
        starts = []
        def fail_first_start(args):
            if args == ['systemctl', 'start', self.unit.name]:
                starts.append(args)
                if len(starts) == 1:
                    raise RuntimeError('synthetic_start_failure')
        self.run_hook = fail_first_start
        with self.assertRaisesRegex(RuntimeError, 'synthetic_start_failure'):
            self.installer.execute(self.request())
        self.assertEqual(self.unit.read_bytes(), b'previous native unit')
        self.assertEqual(json.loads((self.root / 'config.json').read_text()), self.cfg)
        self.assertEqual(self.monitor.read_bytes(), b'previous monitor unit')
        self.assertEqual(self.monitor_commands(), [])
        with closing(sqlite3.connect(self.root / 'journal.sqlite3')) as database:
            self.assertEqual(database.execute('SELECT id FROM genuine_source').fetchall(), [(11,)])

    def test_failure_after_group_enrollment_retains_new_runtime_and_disables_only_enrollment(self):
        starts = []
        def fail_first_start(args):
            if args == ['systemctl', 'start', self.unit.name]:
                starts.append(args)
                if len(starts) == 1:
                    self.enroll_group()
                    raise RuntimeError('synthetic_start_failure')
        self.run_hook = fail_first_start
        result = self.installer.execute(self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': 90}))
        self.assertFalse(result['ok'])
        self.assertEqual(result['errorCode'], 'legacy_grouping_rollback_blocked')
        self.assertEqual(result['recovery'], {'compatibleRuntimeRetained': True, 'groupEnrollmentDisabled': True,
                                            'journalPreserved': True, 'healthy': True})
        self.assertNotEqual(self.unit.read_bytes(), b'previous native unit')
        config = json.loads((self.root / 'config.json').read_text())
        self.assertEqual(config.pop('eventGrouping'), {'enabled': False, 'maxSpanSeconds': 90})
        self.assertEqual(config, self.cfg)
        self.assertEqual(self.monitor.read_bytes(), b'previous monitor unit')
        self.assertEqual(self.monitor_commands(), [])
        with closing(sqlite3.connect(self.root / 'journal.sqlite3')) as database:
            self.assertEqual(database.execute('SELECT id FROM visual_group_members').fetchall(), [(22,)])

    def test_manual_legacy_rollback_is_rejected_before_service_stop(self):
        self.enroll_group()
        backup = Path(self.prior['backup'])
        backup.mkdir(parents=True)
        (backup / 'deployment.json').write_text(json.dumps(self.prior))
        with self.assertRaisesRegex(RuntimeError, 'legacy_grouping_rollback_blocked'):
            self.installer.execute({'mode': 'rollback', 'expectedDigest': 'prior-digest'})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.unit.read_bytes(), b'previous native unit')

    def test_rollback_enrollment_race_restarts_current_runtime_without_restoring_legacy_files(self):
        backup = Path(self.prior['backup'])
        backup.mkdir(parents=True)
        (backup / 'deployment.json').write_text(json.dumps(self.prior))
        (backup / 'service-state.json').write_text(json.dumps({'active': True, 'enabled': True, 'eventsOnly': True}))
        (backup / self.unit.name).write_bytes(b'legacy rollback target')
        def enroll_at_stop(args):
            if args == ['systemctl', 'stop', self.unit.name]:
                self.enroll_group()
        self.run_hook = enroll_at_stop
        with self.assertRaisesRegex(RuntimeError, 'legacy_grouping_rollback_blocked'):
            self.installer.execute({'mode': 'rollback', 'expectedDigest': 'prior-digest'})
        self.assertEqual(self.unit.read_bytes(), b'previous native unit')
        self.assertEqual(self.monitor_commands(), [])
        self.assertIn(('systemctl', 'start', self.unit.name), self.calls)

    def test_manual_snapshot_blocks_rollback_to_verified_automatic_only_runtime(self):
        self.enroll_manual_group()
        target, backup = self.rollback_target()
        self.assertTrue(self.installer.supports_visual_groups(target))
        self.assertFalse(self.installer.supports_manual_groups(target))
        with self.assertRaisesRegex(RuntimeError, '^legacy_manual_grouping_rollback_blocked$'):
            self.installer.execute({'mode': 'rollback', 'expectedDigest': 'prior-digest'})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.unit.read_bytes(), b'previous native unit')

    def test_manual_snapshot_rollback_requires_manifest_verified_explicit_capability(self):
        self.enroll_manual_group()
        target, backup = self.rollback_target(manual=True)
        self.assertTrue(self.installer.supports_manual_groups(target))
        self.installer.guard_rollback(backup)
        module = Path(target['release']) / 'reolink_protect_events' / 'visual_groups.py'
        module.write_bytes(module.read_bytes() + b'# changed after release verification\n')
        self.assertFalse(self.installer.supports_manual_groups(target))
        with self.assertRaisesRegex(RuntimeError, '^legacy_manual_grouping_rollback_blocked$'):
            self.installer.guard_rollback(backup)

    def test_install_cannot_replace_manual_runtime_with_automatic_only_package(self):
        self.enroll_manual_group()
        with self.assertRaisesRegex(RuntimeError, '^manual_grouping_runtime_missing$'):
            self.installer.execute(self.request())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.unit.read_bytes(), b'previous native unit')

    def test_failure_after_manual_snapshot_retains_manual_compatible_runtime(self):
        self.set_package_manual_capability()
        starts = []
        def fail_first_start(args):
            if args == ['systemctl', 'start', self.unit.name]:
                starts.append(args)
                if len(starts) == 1:
                    self.enroll_manual_group()
                    raise RuntimeError('synthetic_start_failure')
        self.run_hook = fail_first_start
        result = self.installer.execute(self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': 90}))
        self.assertFalse(result['ok'])
        self.assertEqual(result['errorCode'], 'legacy_manual_grouping_rollback_blocked')
        self.assertTrue(result['recovery']['compatibleRuntimeRetained'])
        self.assertTrue(result['recovery']['healthy'])
        deployed = json.loads((self.root / 'deployment.json').read_text())
        self.assertEqual(deployed['recoveryReason'], 'legacy_manual_grouping_rollback_blocked')
        self.assertTrue(self.installer.supports_manual_groups(deployed))
        self.assertFalse(json.loads((self.root / 'config.json').read_text())['eventGrouping']['enabled'])
        self.assertEqual(self.monitor_commands(), [])

    def test_manual_capability_is_a_single_explicit_module_integer(self):
        self.assertTrue(self.installer.manual_group_module(b'MANUAL_GROUP_SCHEMA_VERSION = 1\n'))
        for content in (b'# MANUAL_GROUP_SCHEMA_VERSION = 1\n',
                        b'MANUAL_GROUP_SCHEMA_VERSION = True\n',
                        b'MANUAL_GROUP_SCHEMA_VERSION = 1\nMANUAL_GROUP_SCHEMA_VERSION = 0\n',
                        b'def fixture():\n    MANUAL_GROUP_SCHEMA_VERSION = 1\n'):
            with self.subTest(content=content):
                self.assertFalse(self.installer.manual_group_module(content))

    def test_recovery_never_claims_automatic_only_runtime_can_service_manual_rows(self):
        def fail_after_new_manual_row(args):
            if args == ['systemctl', 'start', self.unit.name]:
                self.enroll_manual_group()
                raise RuntimeError('synthetic_start_failure')
        self.run_hook = fail_after_new_manual_row
        with self.assertRaisesRegex(RuntimeError, '^compatible_manual_recovery_runtime_missing$'):
            self.installer.execute(self.request())
        self.assertEqual(self.monitor_commands(), [])

    def test_events_only_requests_and_grouping_bounds_are_validated_before_staging(self):
        invalid = [self.request(eventsOnly='true'), self.request(eventsOnly=True, mode='capture'),
                   self.request(eventsOnly=False, eventGrouping={'enabled': True, 'maxSpanSeconds': 120}),
                   self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': 29}),
                   self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': 301}),
                   self.request(eventGrouping={'enabled': True, 'maxSpanSeconds': True})]
        for request in invalid:
            with self.subTest(request=request):
                with self.assertRaises(RuntimeError):
                    self.installer.execute(request)
        self.assertEqual(self.calls, [])


class ScopedDeployCliTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('scoped_deploy_tool',
            Path(__file__).resolve().parents[1] / 'tools' / 'deploy.py')
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_grouping_options_are_forwarded_only_on_explicit_events_only_install(self):
        calls = []
        def invoke(*args, **kwargs):
            calls.append(args[2])
            return {'ok': True}
        with patch('sys.argv', ['deploy.py', 'install', '--events-only', '--group-visual-events',
                                '--group-max-span-seconds', '90']), \
             patch.object(self.tool, 'invoke', side_effect=invoke), \
             patch.object(self.tool, 'build_package', return_value=(b'fixture', {'packageSha256': 'fixture'})), \
             patch('builtins.print'):
            self.assertEqual(self.tool.main(), 0)
        request = calls[1]['request']
        self.assertTrue(request['eventsOnly'])
        self.assertEqual(request['eventGrouping'], {'enabled': True, 'maxSpanSeconds': 90})

    def test_grouping_requires_install_events_only_and_valid_span(self):
        for argv in (['install', '--group-visual-events'], ['status', '--events-only'],
                     ['install', '--events-only', '--group-visual-events', '--group-max-span-seconds', '301']):
            with self.subTest(argv=argv), patch('sys.argv', ['deploy.py'] + argv), patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    self.tool.main()

    def test_events_only_failure_retains_owned_maintenance_and_reports_owner(self):
        calls = []
        def invoke(*args, **kwargs):
            calls.append(args[2]['request'])
            return {'ok': len(calls) == 1}
        with patch('sys.argv', ['deploy.py', 'install', '--events-only']), \
             patch.object(self.tool, 'invoke', side_effect=invoke), \
             patch.object(self.tool, 'build_package', return_value=(b'fixture', {'packageSha256': 'fixture'})), \
             patch('builtins.print') as output:
            self.assertEqual(self.tool.main(), 1)
        self.assertEqual(len(calls), 2)
        result = json.loads(output.call_args.args[0])
        self.assertTrue(result['maintenanceRetained'])
        self.assertEqual(result['maintenanceOwner'], calls[0]['owner'])

    def test_healthy_compatible_recovery_releases_maintenance_but_still_reports_failed_install(self):
        calls = []
        def invoke(*args, **kwargs):
            calls.append(args[2]['request'])
            return {'ok': False, 'recovery': {'healthy': True}} if len(calls) == 2 else {'ok': True}
        with patch('sys.argv', ['deploy.py', 'install', '--events-only']), \
             patch.object(self.tool, 'invoke', side_effect=invoke), \
             patch.object(self.tool, 'build_package', return_value=(b'fixture', {'packageSha256': 'fixture'})), \
             patch('builtins.print'):
            self.assertEqual(self.tool.main(), 1)
        self.assertEqual(len(calls), 3)
        self.assertFalse(calls[2]['enable'])


if __name__ == "__main__":
    unittest.main()
