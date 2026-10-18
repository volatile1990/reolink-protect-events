"""Local-only release/CAS fixtures. No SSH, systemd or target devices are used."""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from reolink_protect_events.operations import heimserver as server, installer


OLD = 'a' * 64
NEW = 'b' * 64
OLD_MANIFEST = 'c' * 64
NEW_MANIFEST = 'd' * 64


def package(extra=None, mutate=None, symlink=None):
    files = {name: b'x = 1\n' if name.endswith('.py') else b'module.exports = {};\n'
             for name in sorted(server.REQUIRED)}
    files.update(extra or {})
    members = [{'path': name, 'sha256': server.digest(data), 'bytes': len(data)}
               for name, data in sorted(files.items())]
    value = server.digest(server.canonical(members))
    manifest = {'schemaVersion': 1, 'digest': value, 'members': members}
    if mutate:
        mutate(files, manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('release.json', server.canonical(manifest))
        for name, data in files.items():
            if name == symlink:
                entry = zipfile.ZipInfo(name); entry.create_system = 3
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(entry, data)
            else:
                archive.writestr(name, data)
    return value, output.getvalue()


def metadata(value=OLD, previous=None, manifest=OLD_MANIFEST, at=1000):
    return {'schemaVersion': 1, 'digest': value, 'releasePath': str(server.release_path(value)),
            'version': '2.0.0', 'previousDigest': previous, 'activatedAtMs': at,
            'manifestSha256': manifest}


def units():
    return {name: {'LoadState': 'loaded', 'ActiveState': 'active'}
            for name in (*server.UNITS, server.TUNNEL, server.TARGET)}


class BundleTests(unittest.TestCase):
    def assert_code(self, expected, function, *args):
        with self.assertRaises(server.ServerError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, expected)

    def test_four_component_manifest_and_all_bytes_are_verified(self):
        value, data = package()
        manifest, files = server.verified_bundle(data, value)
        self.assertEqual(set(files), server.REQUIRED | {'release.json'})
        self.assertEqual(manifest['digest'], value)

    def test_private_paths_traversal_extra_files_and_symlinks_fail(self):
        for name in ('config/events.json', '../worker.py', 'events/reolink_protect_events/../secret.py',
                     'events/reolink_protect_events/_vendor/secret.py'):
            value, data = package({name: b'PRIVATE_VALUE'})
            self.assert_code('heimserver_member_invalid', server.verified_bundle, data, value)
        value, data = package(symlink='controls/worker.py')
        self.assert_code('heimserver_bundle_file_type', server.verified_bundle, data, value)
        value, data = package(mutate=lambda files, _manifest: files.update({'extra.txt': b'not declared'}))
        self.assert_code('heimserver_bundle_extra_members', server.verified_bundle, data, value)

    def test_wrong_digest_content_duplicate_identity_and_private_key_fail(self):
        value, data = package()
        self.assert_code('heimserver_manifest_digest_mismatch', server.verified_bundle, data, '0' * 64)
        value, data = package(mutate=lambda files, _manifest: files.update({'controls/worker.py': b'changed'}))
        self.assert_code('heimserver_bundle_size_mismatch', server.verified_bundle, data, value)
        value, data = package({'events/reolink_protect_events/private.py': b'-----BEGIN OPENSSH PRIVATE KEY-----'})
        self.assert_code('heimserver_private_key_forbidden', server.verified_bundle, data, value)
        value, data = package(mutate=lambda _files, manifest: manifest['members'].append(manifest['members'][0]))
        self.assert_code('heimserver_member_invalid', server.verified_bundle, data, value)

    def test_python_syntax_and_exact_schema_are_required(self):
        value, data = package({'events/reolink_protect_events/bad.py': b'def invalid(\n'})
        self.assert_code('heimserver_python_syntax_invalid', server.verified_bundle, data, value)
        value, data = package(mutate=lambda _files, manifest: manifest.update(schemaVersion=True))
        self.assert_code('heimserver_manifest_invalid', server.verified_bundle, data, value)

    def test_archive_duplicates_are_rejected_before_extraction(self):
        value, data = package()
        output = io.BytesIO(data)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(output, 'a') as archive:
                archive.writestr('controls/worker.py', b'x = 1\n')
        self.assert_code('heimserver_bundle_members_invalid', server.verified_bundle, output.getvalue(), value)

    def test_existing_tree_cannot_gain_unmanifested_files(self):
        value, data = package(); _manifest, files = server.verified_bundle(data, value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                path = root / name; path.parent.mkdir(exist_ok=True, parents=True); path.write_bytes(content)
            with patch.object(server, 'secure', side_effect=lambda path, **_kwargs: path):
                self.assertEqual(server.verify_tree(root, value)[0]['digest'], value)
                (root / 'config.json').write_text('{"private":"must not be accepted"}')
                self.assert_code('heimserver_release_extra_file', server.verify_tree, root, value)


class SwitchTests(unittest.TestCase):
    def fixtures(self):
        prior = metadata(); prior_raw = server.canonical(prior)
        candidate = metadata(NEW, OLD, NEW_MANIFEST, 100000); candidate_raw = server.canonical(candidate)
        return prior, prior_raw, candidate, candidate_raw

    def test_cas_drift_and_nonprevious_rollback_fail_before_any_restart(self):
        prior, raw, _candidate, _candidate_raw = self.fixtures()
        with patch.object(server, 'deployment', return_value=(prior, raw)), \
             patch.object(server, 'run') as run, patch.object(server, 'verify_tree') as verify:
            with self.assertRaises(server.ServerError) as caught:
                server.switch(NEW, OLD)
            self.assertEqual(caught.exception.code, 'heimserver_deployment_CAS_failed')
            with self.assertRaises(server.ServerError) as caught:
                server.switch(OLD, NEW, rollback=True)
            self.assertEqual(caught.exception.code, 'heimserver_rollback_target_invalid')
        run.assert_not_called(); verify.assert_not_called()

    def test_success_switches_four_components_and_never_touches_tunnel_or_private_files(self):
        prior, raw, candidate, candidate_raw = self.fixtures()
        with patch.object(server, 'deployment', side_effect=[(prior, raw), (prior, raw), (candidate, candidate_raw)]), \
             patch.object(server, 'verify_tree', side_effect=[({}, OLD_MANIFEST), ({}, NEW_MANIFEST)]), \
             patch.object(server, 'runtime_check', return_value={'nativeSchemaVerified': True}), \
             patch.object(server, 'unit_states', return_value=units()), \
             patch.object(server, 'config_fingerprints', return_value={'events.json': 'safe', 'controls.json': 'safe'}), \
             patch.object(server.time, 'time', return_value=100), \
             patch.object(server, 'set_current') as current, patch.object(server, 'atomic_write') as write, \
             patch.object(server, 'run') as run, patch.object(server, 'ready', return_value=units()):
            result = server.switch(OLD, NEW)
        self.assertTrue(result['ok']); self.assertFalse(result['mediaCycleVerified'])
        current.assert_called_once_with(NEW)
        write.assert_called_once_with(server.ROOT / 'deployment.json', candidate_raw)
        run.assert_called_once_with(['systemctl', 'restart', *server.UNITS], timeout=90)
        self.assertNotIn(server.TUNNEL, run.call_args.args[0])

    def test_fsync_failure_after_symlink_commit_is_detected_and_rolled_back(self):
        prior, raw, _candidate, _candidate_raw = self.fixtures()
        with patch.object(server, 'deployment', side_effect=[(prior, raw), (prior, raw)]), \
             patch.object(server, 'verify_tree', side_effect=[({}, OLD_MANIFEST), ({}, NEW_MANIFEST)]), \
             patch.object(server, 'runtime_check', return_value={}), \
             patch.object(server, 'unit_states', return_value=units()), \
             patch.object(server, 'config_fingerprints', return_value={}), \
             patch.object(server.time, 'time', return_value=100), \
             patch.object(server, 'set_current', side_effect=[OSError('PRIVATE_DIAGNOSTIC'), None]) as current, \
             patch.object(server, 'atomic_write') as write, patch.object(server, 'run'), \
             patch.object(server, 'ready', return_value=units()), \
             patch.object(server, 'read_private', return_value=raw), \
             patch.object(Path, 'is_symlink', return_value=True), \
             patch.object(server.os, 'readlink', return_value=str(server.release_path(NEW))):
            result = server.switch(OLD, NEW)
        self.assertFalse(result['ok']); self.assertTrue(result['previousReleaseRestored'])
        self.assertFalse(result['manualInspectionRequired'])
        self.assertEqual([call.args[0] for call in current.call_args_list], [NEW, OLD])
        write.assert_called_once_with(server.ROOT / 'deployment.json', raw)
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_foreign_postfailure_state_is_never_overwritten(self):
        prior, raw, _candidate, _candidate_raw = self.fixtures()
        with patch.object(server, 'deployment', side_effect=[(prior, raw), (prior, raw)]), \
             patch.object(server, 'verify_tree', side_effect=[({}, OLD_MANIFEST), ({}, NEW_MANIFEST)]), \
             patch.object(server, 'runtime_check', return_value={}), \
             patch.object(server, 'unit_states', return_value=units()), \
             patch.object(server, 'config_fingerprints', return_value={}), \
             patch.object(server.time, 'time', return_value=100), \
             patch.object(server, 'set_current', side_effect=OSError('failure')) as current, \
             patch.object(server, 'atomic_write') as write, patch.object(server, 'run') as run, \
             patch.object(server, 'read_private', return_value=raw), \
             patch.object(Path, 'is_symlink', return_value=True), \
             patch.object(server.os, 'readlink', return_value='/srv/cameras/protect/releases/' + 'e' * 64):
            result = server.switch(OLD, NEW)
        self.assertFalse(result['previousReleaseRestored']); self.assertTrue(result['manualInspectionRequired'])
        current.assert_called_once_with(NEW); write.assert_not_called(); run.assert_not_called()


class LegacyAndCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / 'tools' / 'protect_server.py'
        spec = importlib.util.spec_from_file_location('protect_server_cli_fixture', path)
        cls.cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.cli)

    def test_legacy_marker_and_remote_config_stop_every_mutation_with_fixed_code(self):
        with patch.object(installer.os, 'geteuid', return_value=0, create=True), \
             patch.object(Path, 'exists', return_value=True):
            for mode in ('install', 'capture', 'rollback', 'maintenance'):
                with self.assertRaises(installer.MigratedToHeimserver) as caught:
                    installer.execute({'mode': mode})
                self.assertEqual(caught.exception.code, 'migrated_to_heimserver')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'config.json').write_text('{"protectRemote":{}}')
            with patch.object(installer, 'root', root), patch.object(installer, 'secure'), \
                 patch.object(installer.os, 'geteuid', return_value=0, create=True):
                with self.assertRaises(installer.MigratedToHeimserver):
                    installer.execute({'mode': 'install'})

    def test_legacy_status_remains_readonly(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(installer, 'root', Path(directory)), patch.object(installer, 'secure'), \
             patch.object(installer, 'health', return_value={'health': {'healthy': False}}), \
             patch.object(installer.os, 'geteuid', return_value=0, create=True):
            self.assertTrue(installer.execute({'mode': 'status'})['ok'])

    def test_cli_requires_explicit_cas_and_only_heimserver_alias(self):
        self.assertEqual(self.cli.request_for(self.cli.arguments(['activate', '--digest', NEW,
                          '--expected-current', OLD])), {'mode': 'activate', 'digest': NEW, 'expectedCurrent': OLD})
        with patch.object(server.subprocess, 'run') as run:
            with self.assertRaises(server.ServerError) as caught:
                server.invoke({'mode': 'status'}, host='unifi-dream-machine')
            self.assertEqual(caught.exception.code, 'heimserver_ssh_alias_required')
        run.assert_not_called()

    def test_cli_stage_checks_local_bundle_before_transport(self):
        value, data = package()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public.zip'; path.write_bytes(data)
            args = self.cli.arguments(['stage', '--bundle', str(path), '--digest', value])
            request = self.cli.request_for(args)
            self.assertEqual(base64.b64decode(request['bundle']), data)
            self.assertEqual(request['digest'], value)


if __name__ == '__main__':
    unittest.main()
