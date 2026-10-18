"""Dedicated-host BridgeOnly flow; all host operations are fixtures/mocks."""
import base64
import ast
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

from reolink_protect_events.operations import orchestrator, transport
from reolink_protect_events.operations import decode
from reolink_protect_events.operations.orchestrator import Backend, Update, UpdateError, IPS
from test_operations_orchestrator import FakeBackend
import test_protect_ops as cli_fixture


SERVER_DIGEST = 'b' * 64
MANIFEST_DIGEST = 'c' * 64


def release(digest=SERVER_DIGEST):
    return {'ok': True, 'releaseVerified': True, 'servicesActive': True,
            'runtime': {'nativeSchemaVerified': True},
            'deployment': {'digest': digest, 'manifestSha256': MANIFEST_DIGEST, 'version': '2.0.0'}}


class ServerBackend(FakeBackend):
    architecture = 'heimserver'
    def __init__(self):
        super().__init__(); self.server_digest = SERVER_DIGEST; self.server_unhealthy = False
        self.server_change_after_rollout = False

    def freeze(self, directory):
        result = super().freeze(directory)
        (directory / 'events-package.zip').unlink()
        result['architecture'] = 'heimserver'
        result['eventsManifest'] = {'version': '2.0.0', 'bridgeOnly': True}
        return result

    def server_release(self):
        self.calls.append(('server-release',))
        if self.server_change_after_rollout and len(self.applied) == 6:
            self.server_digest = 'd' * 64
        result = release(self.server_digest)
        if self.server_unhealthy:
            result['servicesActive'] = False; result['ok'] = False
        return result

    def udm(self, request, timeout=None):
        if request['action'] == 'installer' and request['request']['mode'] != 'maintenance':
            raise AssertionError('legacy installer must never run for dedicated-host bridge releases')
        return super().udm(request, timeout)


class ServerBridgeFlowTests(unittest.TestCase):
    def test_all_six_keep_canary_actual_av_and_rollback_contracts_without_events_install(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ServerBackend(); path = Path(directory) / 'run'
            result = Update(backend, path).run()
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['scope'], 'bridge-only')
            self.assertEqual(result['eventsVersion'], '2.0.0')
            self.assertIs(result['serverReleaseChanged'], False)
            self.assertEqual([row[2]['ip'] for row in backend.calls if row[:2] == ('nas', 'apply')], IPS)
            self.assertEqual(len([row for row in backend.calls if row[0] == 'server-release']), 2)
            decodes = [row for row in backend.calls if row[0] == 'decode' and row[1] is not None]
            self.assertEqual([row[1] for row in decodes], [[ip] for ip in IPS])
            self.assertTrue(all(type(row[2]) is int for row in decodes))
            self.assertIsNone(backend.marker)
            state = json.loads((path / 'update.json').read_text())
            self.assertEqual(state['architecture'], 'heimserver')
            self.assertNotIn('installIntent', state)
            self.assertNotIn('install-events', state['completed'])
            self.assertFalse((path / 'events-package.zip').exists())

    def test_canary_failure_restores_only_applied_bridge_prefix_and_keeps_server_release(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ServerBackend(); backend.fail_decode_ip = IPS[0]
            result = Update(backend, Path(directory) / 'run').run()
            self.assertFalse(result['ok']); self.assertEqual(result['status'], 'rolled-back', result)
            self.assertEqual(len([row for row in backend.calls if row[:2] == ('nas', 'apply')]), 1)
            self.assertEqual(len([row for row in backend.calls if row[:2] == ('nas', 'rollback-all')]), 1)
            self.assertEqual(backend.server_digest, SERVER_DIGEST)
            self.assertFalse(backend.applied); self.assertIsNone(backend.marker)

    def test_server_release_drift_stops_commit_and_never_replaces_foreign_server_code(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ServerBackend(); backend.server_change_after_rollout = True
            result = Update(backend, Path(directory) / 'run').run()
            self.assertFalse(result['ok'])
            self.assertEqual(result['errorCode'], 'server_release_changed_during_bridge_update')
            self.assertEqual(result['status'], 'rolled-back', result)
            self.assertFalse(backend.applied)
            self.assertEqual(backend.server_digest, 'd' * 64)

    def test_unhealthy_server_preflight_never_builds_or_opens_maintenance(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = ServerBackend(); backend.server_unhealthy = True
            result = Update(backend, Path(directory) / 'run').run()
            self.assertFalse(result['ok']); self.assertIsNone(backend.marker)
            self.assertFalse(any(row[0] == 'nas' for row in backend.calls))

    def test_current_user_settings_are_pinned_for_this_update_instead_of_historic_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            backend=ServerBackend();dispatch=backend.udm
            def changed(request,timeout=None):
                result=dispatch(request,timeout)
                if request['action']=='compatibility' and backend.applied:
                    result['currentSettingsSha256']='0'*64
                return result
            backend.udm=changed
            result=Update(backend,Path(directory)/'run').run()
            self.assertFalse(result['ok'])
            self.assertEqual(result['errorCode'],'camera_settings_changed_during_update')
            self.assertEqual(result['status'],'rolled-back',result)
            self.assertFalse(backend.applied)

    def test_legacy_transaction_cannot_resume_as_heimserver_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run'; Update(FakeBackend(), path)
            backend = ServerBackend()
            with self.assertRaisesRegex(UpdateError, '^resume_architecture_changed$'):
                Update(backend, path, resume=True)
            self.assertFalse(backend.calls)


class BackendServerRoutingTests(unittest.TestCase):
    def construct(self):
        with patch.object(orchestrator, 'load_module', side_effect=[types.SimpleNamespace(), types.SimpleNamespace(source_bundle=lambda: {})]), \
             patch.object(orchestrator, 'source_bundle', return_value='frozen-public-code'):
            return Backend('bridge', 'events', 'private-heimserver-connector', architecture='heimserver',
                           host='unifi-dream-machine', server_host='heimserver', progress=lambda _: None)

    def test_health_recovery_evidence_and_maintenance_use_server_only(self):
        backend = self.construct()
        requests = [{'action': 'health', 'mode': 'full'}, {'action': 'recover', 'cameraId': 'a' * 24},
                    {'action': 'event-evidence'}, {'action': 'monitor-status'},
                    {'action': 'installer', 'request': {'mode': 'maintenance', 'owner': 'a' * 32, 'enable': True}}]
        with patch.object(orchestrator, 'invoke_server', return_value={'ok': True}) as server, \
             patch.object(orchestrator, 'invoke', return_value={'ok': True}) as udm:
            for request in requests:
                backend.udm(request)
            self.assertEqual(server.call_count, len(requests)); udm.assert_not_called()
            self.assertTrue(all(call.args[1] == 'heimserver' and call.kwargs['sources'] == 'frozen-public-code'
                                for call in server.call_args_list))
            backend.udm({'action': 'compatibility'})
            udm.assert_called_once()
            self.assertEqual(udm.call_args.args[1], 'unifi-dream-machine')

    def test_any_legacy_events_install_mode_is_refused_before_ssh(self):
        backend = self.construct()
        with patch.object(orchestrator, 'invoke_server') as server, patch.object(orchestrator, 'invoke') as udm:
            for mode in ('install', 'capture', 'rollback', 'status'):
                with self.assertRaisesRegex(UpdateError, '^heimserver_events_use_server_release_controller$'):
                    backend.udm({'action': 'installer', 'request': {'mode': mode}})
        server.assert_not_called(); udm.assert_not_called()

    def test_real_decode_discovery_and_export_use_server_profile(self):
        backend = self.construct()
        with patch.object(orchestrator, 'run_full_decodes', return_value={'ok': True}) as decoder:
            backend.decode(ips=[IPS[0]])
        self.assertEqual(decoder.call_args.args, ('heimserver',))
        self.assertEqual(decoder.call_args.kwargs['architecture'], 'heimserver')
        self.assertEqual(decoder.call_args.kwargs['config_path'], decode.SERVER_CONFIG)

    def test_bridge_only_freeze_does_not_build_or_vendor_events_package(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = self.construct(); folder = Path(directory)
            snapshot = {'sourceRevision': '1' * 40, 'sourceSha256': 'a' * 64,
                        'sourceDirty': False, 'sourceFiles': []}
            backend.bridge_manifest = types.SimpleNamespace(source_files=lambda _: [],
                manifest=lambda *_args, **_kwargs: copy.deepcopy(snapshot),
                archive_sources=lambda _files, path, **_: path.write_bytes(b'public bridge code'))
            with patch.object(orchestrator, 'build_package') as package, \
                 patch.object(orchestrator, 'source_snapshot', return_value=copy.deepcopy(snapshot)):
                frozen = backend.freeze(folder)
            package.assert_not_called()
            self.assertEqual(frozen['eventsManifest'], {'bridgeOnly': True})
            self.assertFalse((folder / 'events-package.zip').exists())


class ServerTransportTests(unittest.TestCase):
    def bootstrap(self, request, *, health_error=False):
        sources = {
          'reolink_protect_events/__init__.py': '',
          'reolink_protect_events/operations/__init__.py': '',
          'reolink_protect_events/remote.py': "def settings(c):return c['protectRemote']\n",
          'reolink_protect_events/operations/safety.py':
              "def private_path(p):return p\ndef ensure_root(p):return p\ndef read_json(p):return {'testPath':str(p),'password':'PRIVATE_PASSWORD','protectRemote':{'sshAlias':'udm-protect'}}\n",
          'reolink_protect_events/operations/media_health.py':
              "def run_once(c,**k):raise RuntimeError(c['password'])\n" if health_error else
              "def run_once(c,**k):return {'ok':True,'configPath':c['testPath'],'mode':k['mode']}\n",
          'reolink_protect_events/operations/recovery.py':
              "def rebuild(c,r,cid,**k):return {'ok':True,'root':str(r),'cameraId':cid}\n",
          'reolink_protect_events/operations/evidence.py':
              "def inspect(c,root):return {'ok':True,'root':str(root)}\n",
          'reolink_protect_events/operations/installer.py':
              "monitor_root=None\ndef maintenance(owner,enable):return {'ok':True,'root':str(monitor_root),'enable':enable}\n"}
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for name, source in sources.items():
                archive.writestr(name, source)
        payload = {'sources': base64.b64encode(data.getvalue()).decode(), 'request': request}
        result = subprocess.run([sys.executable, '-c', transport.SERVER_BOOTSTRAP],
                                input=json.dumps(payload), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('PRIVATE_', result.stdout)
        return json.loads(result.stdout)

    def test_fixed_server_config_state_and_owned_marker_paths(self):
        cases = [({'action': 'health'}, 'configPath', '/config/events.json'),
                 ({'action': 'recover', 'cameraId': 'a' * 24}, 'root', '/state/monitor'),
                 ({'action': 'event-evidence'}, 'root', '/state/events'),
                 ({'action': 'installer', 'request': {'mode': 'maintenance', 'owner': 'a' * 32,
                                                      'enable': True}}, 'root', '/state/monitor')]
        for request, key, suffix in cases:
            value = self.bootstrap(request)
            self.assertTrue(value['ok'], value)
            self.assertEqual(value[key].replace('\\', '/'), '/srv/cameras/protect' + suffix)

    def test_local_udm_paths_old_installers_and_raw_errors_are_never_used(self):
        for request in ({'action': 'health', 'configPath': '/data/reolink-protect-events/config.json'},
                        {'action': 'installer', 'request': {'mode': 'install'}},
                        {'action': 'compatibility'}):
            self.assertFalse(self.bootstrap(request)['ok'])
        value = self.bootstrap({'action': 'health'}, health_error=True)
        self.assertEqual(value['errorCode'], 'server_operation_failed')

    def test_transport_is_strict_sudo_pinned_alias_and_suppresses_raw_stderr(self):
        response = subprocess.CompletedProcess([], 0, stdout='{"ok":true}', stderr='PRIVATE_PASSWORD')
        with patch.object(transport.subprocess, 'run', return_value=response) as run:
            value = transport.invoke_server('.', 'heimserver', {'action': 'health'}, sources='public-code')
            self.assertTrue(value['ok'])
            command = run.call_args.args[0]
            self.assertIn('-oStrictHostKeyChecking=yes', command)
            self.assertTrue(command[-1].startswith('sudo -n python3 -B -c '))
            self.assertIs(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
            with self.assertRaisesRegex(ValueError, '^heimserver_ssh_alias_required$'):
                transport.invoke_server('.', 'unifi-dream-machine', {'action': 'health'})
            self.assertEqual(run.call_count, 1)

    def test_migration_marker_selects_only_credential_free_connector_metadata_for_compatibility(self):
        sources = {
            'reolink_protect_events/__init__.py': '',
            'reolink_protect_events/operations/__init__.py': '',
            'reolink_protect_events/operations/safety.py':
                "from pathlib import Path\n_original_exists=Path.exists\n"
                "Path.exists=lambda p:True if p.as_posix()=='/data/reolink-protect-connector/server-architecture.json' else _original_exists(p)\n"
                "def private_path(p):return p\ndef read_json(p):return {'configPath':p.as_posix()}\n",
            'reolink_protect_events/operations/compatibility.py':
                "def assess(c):return {'ok':True,'configPath':c['configPath']}\n"}
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for name, source in sources.items():
                archive.writestr(name, source)
        payload = {'sources': base64.b64encode(data.getvalue()).decode(), 'request': {'action': 'compatibility'}}
        result = subprocess.run([sys.executable, '-c', transport.BOOTSTRAP], input=json.dumps(payload),
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {'ok': True,
            'configPath': '/data/reolink-protect-connector/compatibility.json'})


class ServerDecodeProfileTests(unittest.TestCase):
    def test_profile_requires_server_config_and_pinned_sudo_ssh_before_any_media(self):
        calls = []
        async def read(command, **_kwargs):
            calls.append(command)
            return 2, b'{"ok":false,"errorCode":"decode_new_recording_pending"}', b''
        with patch.object(decode, '_run_bytes', side_effect=read), \
             patch.object(decode, '_executable', return_value=sys.executable), \
             patch.object(decode, '_remote_source', return_value=b'public-helpers') as source:
            report = decode.run_full_decodes('heimserver', config_path=decode.SERVER_CONFIG,
                                             architecture='heimserver', ips=[IPS[0]])
        self.assertEqual(report['errorCode'], 'decode_new_recording_pending')
        self.assertEqual(calls[0][-1], 'sudo -n python3 -B -')
        self.assertEqual(source.call_args.args[0]['architecture'], 'heimserver')
        self.assertEqual(source.call_args.args[0]['configPath'], decode.SERVER_CONFIG)
        for alias, path in (('unifi-dream-machine', decode.SERVER_CONFIG), ('heimserver', decode.DEFAULT_CONFIG)):
            with patch.object(decode, '_run_bytes') as read:
                result = decode.run_full_decodes(alias, config_path=path, architecture='heimserver')
                self.assertFalse(result['ok']); read.assert_not_called()

    def test_native_recording_export_uses_existing_server_snapshot_tunnel(self):
        function = next(node for node in ast.parse(decode._REMOTE_COMMON).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'export')
        now = 1792219340000 + 300000; cid = 'a' * 24
        camera = {'id': cid, 'host': IPS[0], 'stats': {'video': {'recordingEnd': now - 5000,
                  'recordingStart': now - 500000}}}
        config = {'bridges': [{'cameraId': cid, 'host': IPS[0]}]}
        profile = {'cameraId': cid, 'host': IPS[0], 'quality': 'high', 'channel': 0,
                   'startMs': now - 59000, 'endMs': now - 35000}
        from unittest.mock import Mock
        get = Mock(return_value=(200, b'0000ftypVALID_TEST_BYTES'))
        output = io.BytesIO()
        namespace = {'context': lambda: (config, [camera]), 'payload': {'architecture': 'heimserver',
                     'profile': profile, 'notBeforeMs': None}, 'need': decode.need,
                     'qualities': lambda _: [('high', 'recordingEnd', 0)], 'current_source': lambda *_: None,
                     'time': types.SimpleNamespace(time=lambda: now / 1000), 'EXPORT_WINDOW_MS': 24000,
                     'urllib': types.SimpleNamespace(parse=__import__('urllib.parse', fromlist=['parse'])),
                     'remote_settings': lambda _: {'snapshotPort': 17080}, 'get_bytes': get,
                     'owner_headers': lambda _: {}, 'OperationError': decode.OperationError,
                     'sys': types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=output))}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<server-export-fixture>', 'exec'), namespace)
        namespace['export']()
        self.assertTrue(get.call_args.args[0].startswith('http://127.0.0.1:17080/api/video/export?'))
        self.assertEqual(get.call_args.kwargs, {'timeout': 35, 'limit': 67108864})
        self.assertEqual(output.getvalue(), b'0000ftypVALID_TEST_BYTES')


class ServerReleaseCliTests(unittest.TestCase):
    tearDown = cli_fixture.ReleaseCliTests.tearDown
    receipt = cli_fixture.ReleaseCliTests.receipt
    execute = cli_fixture.ReleaseCliTests.execute

    def setUp(self):
        cli_fixture.ReleaseCliTests.setUp(self)
        self.backend.architecture = 'heimserver'
        self.backend.server_release.return_value = release()
        config = json.loads(self.config.read_text())
        config.update(architecture='heimserver', protectSshAlias='unifi-dream-machine', serverSshAlias='heimserver')
        self.config.write_text(json.dumps(config))

    def server_state(self, status='complete'):
        state = cli_fixture.complete_state(status)
        state['architecture'] = 'heimserver'
        state['completed'] = ['bridge-final-receipt', 'server-release-after']
        state['evidence'].pop('install-events')
        state['evidence']['server-release-before'] = release()
        return state

    def test_server_completed_bridge_receipt_ignores_independent_later_events_updates(self):
        self.receipt(self.server_state())
        self.backend.current_sources.return_value['events']['sourceSha256'] = 'e' * 64
        self.backend.server_release.return_value = release('f' * 64)
        code, report, updates = self.execute()
        self.assertEqual(code, 0); self.assertEqual(report['status'], 'already-deployed')
        updates.assert_not_called()
        self.backend.server_release.assert_called_once()
        self.assertFalse(any(call.args[0]['action'] == 'installer' for call in self.backend.udm.call_args_list))

    def test_server_running_receipt_keeps_exact_release_pin_until_bridge_commit(self):
        state = self.server_state('running'); self.receipt(state)
        from unittest.mock import Mock
        updater = Mock(); updater.return_value.state = state
        self.backend.server_release.return_value = release('f' * 64)
        with self.assertRaisesRegex(UpdateError, '^server_release_changed_during_bridge_update$'):
            self.execute(updater)
        updater.return_value.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
