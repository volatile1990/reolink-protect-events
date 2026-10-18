"""Own-release CLI identity and final-commit crash contracts; no host access."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from reolink_protect_events.operations.orchestrator import IPS, Update, UpdateError
from test_operations_orchestrator import FakeBackend


spec = importlib.util.spec_from_file_location('owned_protect_ops',
    Path(__file__).resolve().parents[1] / 'tools/protect_ops.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
IMAGE = 'sha256:' + 'e' * 64
DIGEST = 'd' * 64


def installed_status(digest=DIGEST):
    return {'ok': True, 'deployment': {'sha256': digest}, 'health': {'healthy': True},
            'active': 'active', 'enabled': 'enabled', 'monitor': {'active': True, 'enabled': True}}


def complete_state(status='complete'):
    return {'schemaVersion': 1, 'status': status, 'completed': ['install-events'],
            'maintenanceIntent': False, 'maintenanceActive': False,
            'release': {'imageId': IMAGE},
            'frozen': {'sources': {p: {'sourceSha256': 'a' * 64} for p in ('bridge', 'events')},
                       'eventsManifest': {'packageSha256': DIGEST}},
            'evidence': {'bridge-final-receipt': {'ok': True, 'bridges':
                        [{'ip': ip, 'imageId': IMAGE} for ip in IPS]},
                         'install-events': {'ok': True, 'deployment': {'sha256': DIGEST}}}}


class ReleaseCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / 'receipts'
        self.directory.mkdir()
        self.run = self.directory / ('1' * 32)
        self.run.mkdir()
        self.config = self.root / 'controller.json'
        self.config.write_text(json.dumps({'bridgeRepo': 'synthetic-bridge', 'eventsRepo': 'synthetic-events',
            'connector': 'external-safe-connector', 'stateDirectory': str(self.directory)}))
        self.backend = Mock()
        self.backend.architecture = 'udm'
        self.backend.current_sources.return_value = {p: {'sourceSha256': 'a' * 64} for p in ('bridge', 'events')}
        self.backend.nas.return_value = {'ok': True, 'bridges': [{'ip': ip, 'imageId': IMAGE} for ip in IPS]}
        self.backend.udm.side_effect = lambda request: installed_status() if request['action'] == 'installer' else {'ok': True}

    def tearDown(self):
        self.temporary.cleanup()

    def receipt(self, state):
        (self.run / 'update.json').write_text(json.dumps(state))
        (self.directory / 'latest.json').write_text(json.dumps({'run': self.run.name}))

    def execute(self, updater=None):
        output = io.StringIO()
        with patch.object(controller, 'Backend', return_value=self.backend), \
             patch.object(controller, 'Update', updater or Mock()) as updates, \
             patch('sys.argv', ['protect_ops.py', 'update', '--config', str(self.config)]), \
             redirect_stdout(output):
            code = controller.main()
        return code, json.loads(output.getvalue()), updates

    def test_exact_installed_identities_reuse_receipt_without_deployment(self):
        self.receipt(complete_state())
        code, report, updates = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'already-deployed')
        updates.assert_not_called()
        self.backend.nas.assert_called_once_with({'mode': 'inventory'})
        self.assertEqual(self.backend.udm.call_args_list[0].args[0],
                         {'action': 'installer', 'request': {'mode': 'status'}})
        self.assertEqual(self.backend.udm.call_args_list[1].args[0], {'action': 'health', 'mode': 'quick'})

    def test_clean_host_settings_reach_backend_without_changing_udm_alias(self):
        settings = {'scope': '/srv/cameras/bridges', 'runtimeUid': 1026, 'renderGroup': 992,
                    'restartPolicy': 'unless-stopped', 'maintenanceMode': 'deployment-lock'}
        config = json.loads(self.config.read_text())
        config.update(bridgeSettings=settings, sshAlias='unifi-dream-machine')
        self.config.write_text(json.dumps(config))
        self.receipt(complete_state())
        with patch.object(controller, 'Backend', return_value=self.backend) as constructor, \
             patch('sys.argv', ['protect_ops.py', 'update', '--config', str(self.config)]), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(controller.main(), 0)
        self.assertEqual(constructor.call_args.kwargs['bridge_settings'], settings)
        self.assertEqual(constructor.call_args.kwargs['host'], 'unifi-dream-machine')

    def test_healthy_manual_bridge_rollback_is_drift_and_never_reinstalled(self):
        self.receipt(complete_state())
        self.backend.nas.return_value['bridges'][0]['imageId'] = 'sha256:' + 'f' * 64
        updates = Mock()
        with self.assertRaisesRegex(UpdateError, '^installed_bridge_release_drift$'):
            self.execute(updates)
        updates.assert_not_called()
        self.backend.udm.assert_not_called()
        self.backend.nas.assert_called_once_with({'mode': 'inventory'})

    def test_healthy_manual_events_rollback_is_drift_and_never_reinstalled(self):
        self.receipt(complete_state())
        self.backend.udm.side_effect = lambda _: installed_status('c' * 64)
        updates = Mock()
        with self.assertRaisesRegex(UpdateError, '^installed_events_release_drift$'):
            self.execute(updates)
        updates.assert_not_called()
        self.backend.udm.assert_called_once_with({'action': 'installer', 'request': {'mode': 'status'}})

    def test_duplicate_or_missing_inventory_member_cannot_match(self):
        for rows in ([{'ip': ip, 'imageId': IMAGE} for ip in IPS[:-1]],
                     [{'ip': IPS[0], 'imageId': IMAGE}] * len(IPS)):
            with self.subTest(rows=rows):
                self.receipt(complete_state())
                self.backend.nas.return_value = {'ok': True, 'bridges': rows}
                with self.assertRaisesRegex(UpdateError, '^installed_bridge_release_drift$'):
                    self.execute()

    def test_failed_release_without_marker_starts_fresh_attempt(self):
        self.receipt(complete_state('failed'))
        updater = Mock()
        updater.return_value.run.return_value = {'ok': True, 'status': 'complete'}
        code, report, updates = self.execute(updater)
        self.assertEqual(code, 0)
        self.assertNotEqual(updates.call_args.args[1], self.run)
        self.assertEqual(updates.call_args.kwargs, {'resume': False})
        self.backend.nas.assert_not_called()
        self.backend.udm.assert_not_called()

    def test_running_without_marker_resumes_existing_uuid(self):
        state = complete_state('running')
        state['completed'] = []
        self.receipt(state)
        updater = Mock()
        updater.return_value.state = state
        updater.return_value.run.return_value = {'ok': True, 'status': 'complete'}
        code, report, updates = self.execute(updater)
        self.assertEqual(code, 0)
        self.assertEqual(updates.call_args.args[1], self.run)
        self.assertEqual(updates.call_args.kwargs, {'resume': True})

    def test_running_completed_install_cannot_finalize_a_different_package(self):
        state = complete_state('running')
        self.receipt(state)
        updater = Mock()
        updater.return_value.state = state
        self.backend.udm.side_effect = lambda _: installed_status('c' * 64)
        with self.assertRaisesRegex(UpdateError, '^installed_events_release_drift$'):
            self.execute(updater)
        updater.return_value.run.assert_not_called()

    def test_matching_completed_ids_require_live_service_health(self):
        self.receipt(complete_state())
        status = installed_status()
        status['monitor']['active'] = False
        self.backend.udm.side_effect = lambda _: status
        with self.assertRaisesRegex(UpdateError, '^installed_events_release_unhealthy$'):
            self.execute()

    def test_real_run_crash_after_clear_resumes_commit_without_second_host_install(self):
        class InstalledBackend(FakeBackend):
            def bridges(self):
                rows = super().bridges()
                for row in rows:
                    if row['ip'] in self.applied:
                        row['imageId'] = IMAGE
                return rows

            def nas(self, request):
                if request['mode'] == 'inventory':
                    self.calls.append(('nas', 'inventory', copy.deepcopy(request), self.marker))
                    return {'ok': True, 'bridges': self.bridges()}
                return super().nas(request)

            def udm(self, request, timeout=None):
                value = super().udm(request, timeout)
                if request['action'] == 'installer' and request['request']['mode'] == 'status':
                    value.update(installed_status(self.events_digest))
                return value

        self.run.rmdir()
        backend = InstalledBackend()
        update = Update(backend, self.run)
        original_persist = update.persist

        def crash_before_committed_receipt():
            if update.state['status'] == 'complete':
                raise KeyboardInterrupt('synthetic power loss')
            original_persist()

        update.persist = crash_before_committed_receipt
        with self.assertRaises(KeyboardInterrupt):
            update.run()
        state = json.loads((self.run / 'update.json').read_text())
        self.assertEqual(state['status'], 'running')
        self.assertIs(state['maintenanceActive'], False)
        self.assertIs(state['maintenanceIntent'], False)
        self.assertIsNone(backend.marker)
        before = len(backend.calls)
        self.receipt(state)
        self.backend = backend
        spy = Mock(wraps=Update)
        code, report, updates = self.execute(spy)
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(updates.call_args.args[1], self.run)
        self.assertEqual(updates.call_args.kwargs, {'resume': True})
        after = backend.calls[before:]
        self.assertFalse(any(row[0] == 'nas' and row[1] in ('build', 'apply', 'rollback-all') for row in after))
        self.assertFalse(any(row[0] == 'udm' and row[1]['action'] == 'installer'
                             and row[1]['request']['mode'] in ('install', 'rollback') for row in after))
        self.assertEqual(json.loads((self.run / 'update.json').read_text())['status'], 'complete')
        self.assertIsNone(backend.marker)


if __name__ == '__main__':
    unittest.main()
