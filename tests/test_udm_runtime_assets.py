"""Pinned dependency recovery, conflicts, and safe caller fallback."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / 'services/udm'
for name in ('runtime_assets', 'runtime_contracts'):
    spec = importlib.util.spec_from_file_location('_asset_test_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals()[name] = module
assets, runtime = runtime_assets, runtime_contracts


def metadata(mode=0o644, *, uid=0, links=1, directory=False):
    return SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
                           st_uid=uid, st_gid=0, st_nlink=links, st_dev=1, st_ino=1)


def fixture_manifest():
    sources = {Path(target).name: b'module.exports = {};\n' for target in assets.TARGETS}
    sources[Path(assets.CONNECTOR).name] = b'print("ready")\n'
    manifest = {'schema': 1, 'files': [
        {'target': target, 'source': Path(target).name,
         'sha256': assets.digest(sources[Path(target).name]), 'allowedBefore': []}
        for target in sorted(assets.TARGETS)]}
    return manifest, sources


class MemoryOps:
    def __init__(self, sources, *, targets=None):
        self.sources = dict(sources)
        self.targets = {} if targets is None else dict(targets)
        self.bad_sources, self.bad_targets = set(), set()
        self.writes = []

    def source(self, row):
        if row['source'] in self.bad_sources:
            raise assets.AssetError('asset_unsafe_symlink')
        return self.sources[row['source']]

    def existing(self, target):
        if target in self.bad_targets:
            raise assets.AssetError('asset_unsafe_symlink')
        return (self.targets[target], metadata()) if target in self.targets else None

    def syntax(self, row, data):
        if row['target'] == assets.CONNECTOR:
            try:
                compile(data, row['source'], 'exec')
            except SyntaxError:
                raise assets.AssetError('asset_python_syntax_failed') from None
        elif data.startswith(b'invalid syntax'):
            raise assets.AssetError('asset_javascript_syntax_failed')

    def replace(self, row, data, previous):
        self.targets[row['target']] = data
        self.writes.append(row['target'])


def prepare_memory(manifest, ops, *, apply=True):
    with mock.patch.object(assets, 'read_secure', return_value=(json.dumps(manifest).encode(), metadata(0o600))), \
         mock.patch.object(assets, 'secure_path', side_effect=lambda path, **kwargs: path):
        return assets.prepare(Path('/private/contracts/assets.json'), apply=apply, ops=ops)


def recipe(capability='controls_http', before=b'native()', after=None):
    after = after or b'require("/usr/local/lib/reolink-protect-controls/protect-hook.cjs").handle()'
    enc = lambda value: base64.b64encode(value).decode()
    return runtime.recipes_from_json({'schema': 1, 'recipes': [
        {'id': capability, 'capability': capability, 'target': 'service', 'kind': 'replace',
         'before': enc(before), 'after': enc(after), 'contexts': []}]})[0]


class RuntimeAssetTests(unittest.TestCase):
    def test_all_four_absent_files_restore_then_are_idempotent(self):
        manifest, sources = fixture_manifest()
        ops = MemoryOps(sources)
        first = prepare_memory(manifest, ops)
        self.assertTrue(first['ok'])
        self.assertEqual(set(ops.writes), assets.TARGETS)
        ops.writes.clear()
        second = prepare_memory(manifest, ops)
        self.assertTrue(second['ok'])
        self.assertEqual(ops.writes, [])
        self.assertTrue(all(row['state'] == 'present' for row in second['files']))

    def test_check_does_not_restore_absent_files(self):
        manifest, sources = fixture_manifest()
        ops = MemoryOps(sources)
        result = prepare_memory(manifest, ops, apply=False)
        self.assertTrue(result['backupReady'])
        self.assertFalse(result['ok'])
        self.assertEqual(ops.writes, [])
        self.assertEqual(set(result['runtimeUnavailable']), assets.TARGETS)

    def test_corrupt_source_prevents_all_writes(self):
        manifest, sources = fixture_manifest()
        ops = MemoryOps(sources)
        ops.sources[Path(assets.HOOK).name] = b'corrupted'
        result = prepare_memory(manifest, ops)
        self.assertEqual(result['errors'], ['asset_source_hash_mismatch'])
        self.assertEqual(ops.writes, [])

    def test_foreign_target_prevents_all_writes_and_is_never_overwritten(self):
        manifest, sources = fixture_manifest()
        ops = MemoryOps(sources, targets={assets.HOOK: b'operator change'})
        result = prepare_memory(manifest, ops)
        self.assertEqual(result['errors'], ['asset_target_conflict'])
        self.assertTrue(result['backupReady'])
        self.assertEqual(ops.targets[assets.HOOK], b'operator change')
        self.assertEqual(ops.writes, [])

    def test_exact_declared_owned_old_bytes_may_be_replaced(self):
        manifest, sources = fixture_manifest()
        for row in manifest['files']:
            if row['target'] == assets.HOOK:
                row['allowedBefore'] = [assets.digest(b'old owned hook')]
        ops = MemoryOps(sources, targets={assets.HOOK: b'old owned hook'})
        result = prepare_memory(manifest, ops)
        self.assertTrue(result['ok'])
        self.assertEqual(ops.targets[assets.HOOK], sources[Path(assets.HOOK).name])

    def test_symlink_sources_and_targets_prevent_all_writes(self):
        manifest, sources = fixture_manifest()
        for source in (True, False):
            ops = MemoryOps(sources)
            (ops.bad_sources if source else ops.bad_targets).add(Path(assets.HOOK).name if source else assets.HOOK)
            result = prepare_memory(manifest, ops)
            self.assertFalse(result['ok'])
            self.assertEqual(ops.writes, [])

    def test_syntax_failure_prevents_all_writes_even_when_hash_matches(self):
        manifest, sources = fixture_manifest()
        for target, invalid in ((assets.HOOK, b'invalid syntax!'),
                                (assets.CONNECTOR, b'def broken(:\n')):
            changed = json.loads(json.dumps(manifest))
            bad_sources = dict(sources)
            bad_sources[Path(target).name] = invalid
            for row in changed['files']:
                if row['target'] == target:
                    row['sha256'] = assets.digest(invalid)
            ops = MemoryOps(bad_sources)
            self.assertFalse(prepare_memory(changed, ops)['ok'])
            self.assertEqual(ops.writes, [])

    def test_bad_backups_do_not_hide_valid_installed_runtime(self):
        manifest, sources = fixture_manifest()
        ops = MemoryOps(sources, targets={target: sources[Path(target).name] for target in assets.TARGETS})
        ops.sources[Path(assets.HOOK).name] = b'corrupt backup'
        result = prepare_memory(manifest, ops)
        self.assertFalse(result['backupReady'])
        self.assertEqual(set(result['runtimeReady']), assets.TARGETS)
        item = recipe()
        source = item['after'] + b';'
        candidate, rows = runtime.transform_with_dependencies(source, [item], result)
        self.assertEqual(candidate, source)
        self.assertEqual(rows[0]['state'], 'present')

    def test_existing_callers_with_missing_runtime_are_exactly_reversed(self):
        item = recipe()
        candidate, rows = runtime.transform_with_dependencies(item['after'] + b';unrelated()', [item],
             {'runtimeReady': [], 'runtimeUnavailable': [assets.HOOK]})
        self.assertEqual(candidate, item['before'] + b';unrelated()')
        self.assertEqual(rows[0]['state'], 'dependency_unavailable_removed')

    def test_new_callers_are_not_installed_without_verified_dependencies(self):
        item = recipe()
        for state in ({'runtimeUnavailable': [assets.HOOK]}, {'runtimeUnavailable': []}):
            candidate, rows = runtime.transform_with_dependencies(item['before'], [item], state)
            self.assertEqual(candidate, item['before'])
            self.assertNotEqual(rows[0]['state'], 'applicable')

    def test_invalid_manifest_does_not_reverse_existing_unverified_runtime(self):
        item = recipe()
        candidate, rows = runtime.transform_with_dependencies(item['after'], [item],
             {'runtimeReady': [], 'runtimeUnavailable': [], 'runtimeUnverified': [assets.HOOK]})
        self.assertEqual(candidate, item['after'])
        self.assertEqual(rows[0]['state'], 'dependency_not_verified')

    def test_missing_manifest_with_missing_helper_removes_only_its_owned_caller(self):
        _, sources = fixture_manifest()
        ops = MemoryOps(sources, targets={assets.AAC: sources[Path(assets.AAC).name]})
        with mock.patch.object(assets, 'read_secure', side_effect=FileNotFoundError), \
             mock.patch.object(assets, 'secure_path', side_effect=lambda path, **kwargs: path):
            result = assets.prepare(Path('/private/contracts/assets.json'), apply=True, ops=ops)
        self.assertFalse(result['backupReady'])
        self.assertIn(assets.HOOK, result['runtimeUnavailable'])
        item = recipe()
        candidate, _ = runtime.transform_with_dependencies(item['after'], [item], result)
        self.assertEqual(candidate, item['before'])

    def test_partial_restore_failure_cannot_install_callers_of_missing_dependencies(self):
        manifest, sources = fixture_manifest()
        manifest['files'].sort(key=lambda row: row['target'] != assets.HOOK)
        ops = MemoryOps(sources)
        original_replace = ops.replace
        def fail_after_hook(row, data, previous):
            if ops.writes:
                raise assets.AssetError('asset_test_disk_failure')
            original_replace(row, data, previous)
        ops.replace = fail_after_hook
        result = prepare_memory(manifest, ops)
        self.assertFalse(result['ok'])
        self.assertTrue(result['backupReady'])
        self.assertEqual(result['runtimeReady'], [assets.HOOK])
        control, audio = recipe(), recipe('live_aac', before=b'audio()', after=b'ownedAudio()')
        candidate, rows = runtime.transform_with_dependencies(control['before'] + b';audio()',
                                                              [control, audio], result)
        self.assertEqual(candidate, control['after'] + b';audio()')
        self.assertEqual(rows[1]['state'], 'dependency_unavailable')

    def test_future_unregistered_external_helpers_cannot_be_added(self):
        item = recipe('automatic_input', after=b'require("/usr/local/lib/unknown.cjs")()')
        with self.assertRaisesRegex(runtime.ContractError, 'unregistered_dependency_reference'):
            runtime.transform_with_dependencies(item['before'], [item], {'runtimeReady': []})

    def test_live_aac_needs_both_modules_and_independent_patches_still_apply(self):
        item = recipe('live_aac', after=b'ownedAudio()')
        independent = recipe('event_cleanup', before=b'cleanup()', after=b'ownedCleanup()')
        candidate, rows = runtime.transform_with_dependencies(item['before'] + b';cleanup()', [item, independent],
             {'runtimeReady': [assets.AAC_ALL], 'runtimeUnavailable': [assets.AAC]})
        self.assertEqual(candidate, item['before'] + b';ownedCleanup()')
        self.assertEqual(rows[0]['state'], 'dependency_unavailable')

    def test_ambiguous_existing_callers_are_not_reversed(self):
        item = recipe()
        with self.assertRaisesRegex(runtime.ContractError, 'dependency_owned_reversal_ambiguous'):
            runtime.transform_with_dependencies(item['after'] + item['after'], [item],
                 {'runtimeUnavailable': [assets.HOOK]})

    def test_allowlist_and_manifest_schema_cannot_expand(self):
        original, _ = fixture_manifest()
        for mutate in (lambda v: v['files'][0].update(target='/tmp/execute.py'),
                       lambda v: v['files'][0].update(source='../outside'),
                       lambda v: v['files'][0].update(allowedBefore=[{}]),
                       lambda v: v.update(schema=True),
                       lambda v: v['files'].pop()):
            value = json.loads(json.dumps(original))
            mutate(value)
            with self.assertRaises(assets.AssetError):
                assets.manifest_rows(value)

    def test_metadata_rejects_nonroot_writable_links_and_nonprivate_sources(self):
        for meta in (metadata(uid=1000), metadata(mode=0o666), metadata(links=2),
                     SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_nlink=1)):
            with self.assertRaises(assets.AssetError):
                assets.secure_metadata(meta)
        with self.assertRaises(assets.AssetError):
            assets.secure_metadata(metadata(), private=True)


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0 and shutil.which('node'),
                     'Real root ownership, symlinks, fsync and Node checks require Linux root + node')
class LinuxRuntimeAssetIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-assets-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.contracts = self.root / 'contracts'
        self.contracts.mkdir(mode=0o700)
        self.source = self.contracts / 'assets'
        self.source.mkdir(mode=0o700)
        self.target_root = self.root / 'usr/local/lib'
        self.target_root.mkdir(parents=True)
        self.manifest, sources = fixture_manifest()
        for name, data in sources.items():
            path = self.source / name
            path.write_bytes(data)
            path.chmod(0o600)
        self.manifest_path = self.contracts / 'assets.json'
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.manifest_path.chmod(0o600)
        self.ops = assets.FileOps(self.source, map_target=lambda target: self.target_root /
                                 target.removeprefix('/usr/local/lib/'), node=shutil.which('node'))

    def test_wiped_usr_local_then_stock_vendor_patch_and_idempotence(self):
        item = recipe()
        vendor = self.root / 'service.js'
        vendor.write_bytes(b'function handle(){' + item['before'] + b'}')
        vendor.chmod(0o644)
        raw_recipe = {'schema': 1, 'recipes': [{key: base64.b64encode(value).decode()
                     if key in ('before', 'after') else value for key, value in item.items()}]}
        recipe_path = self.contracts / 'recipes.json'
        recipe_path.write_text(json.dumps(raw_recipe))
        recipe_path.chmod(0o600)
        original_replace = runtime.replace_checked
        def replace(path, old, new, meta):
            self.assertEqual(set(assets.runtime_state(assets.manifest_rows(self.manifest), self.ops)['runtimeReady']), assets.TARGETS)
            original_replace(path, old, new, meta, syntax_check=[shutil.which('node'), '--check'])
        with mock.patch.object(runtime, 'targets', return_value=iter([('service', vendor)])), \
             mock.patch.object(runtime, 'replace_checked', side_effect=replace):
            first = runtime._run(recipe_path, apply=True, asset_prepare=lambda path, apply:
                                 assets.prepare(path, apply=apply, ops=self.ops))
        self.assertTrue(first['ok'], first)
        self.assertIn(item['after'], vendor.read_bytes())
        with mock.patch.object(runtime, 'targets', return_value=iter([('service', vendor)])):
            second = runtime._run(recipe_path, apply=True, asset_prepare=lambda path, apply:
                                  assets.prepare(path, apply=apply, ops=self.ops))
        self.assertTrue(second['ok'], second)
        self.assertFalse(second['files'][0]['changed'])
        self.assertTrue(all(row['state'] == 'present' for row in second['assets']['files']))

    def test_real_source_and_target_symlinks_are_rejected(self):
        path = self.source / Path(assets.HOOK).name
        path.unlink()
        path.symlink_to(self.source / Path(assets.AAC).name)
        result = assets.prepare(self.manifest_path, apply=True, ops=self.ops)
        self.assertEqual(result['errors'], ['asset_unsafe_symlink'])
        self.assertEqual(list(self.target_root.iterdir()), [])
        path.unlink()
        path.write_bytes(b'module.exports = {};\n')
        path.chmod(0o600)
        target_dir = self.target_root / 'reolink-protect-controls'
        target_dir.symlink_to(self.source, target_is_directory=True)
        result = assets.prepare(self.manifest_path, apply=True, ops=self.ops)
        self.assertIn('asset_unsafe_symlink', result['errors'])

    def test_real_corruption_and_foreign_target_are_not_overwritten(self):
        target = self.ops.map_target(assets.CONNECTOR)
        target.write_bytes(b'operator changed connector')
        target.chmod(0o644)
        result = assets.prepare(self.manifest_path, apply=True, ops=self.ops)
        self.assertEqual(result['errors'], ['asset_target_conflict'])
        self.assertEqual(target.read_bytes(), b'operator changed connector')
        self.assertFalse((self.target_root / 'reolink-protect-controls').exists())

    def test_real_source_hardlinks_and_concurrent_target_changes_are_rejected(self):
        source = self.source / Path(assets.HOOK).name
        linked = self.source / 'hardlink.cjs'
        os.link(source, linked)
        result = assets.prepare(self.manifest_path, apply=True, ops=self.ops)
        self.assertEqual(result['errors'], ['asset_unsafe_links'])
        linked.unlink()
        row = next(row for row in self.manifest['files'] if row['target'] == assets.CONNECTOR)
        target = self.ops.map_target(assets.CONNECTOR)
        target.write_bytes(b'concurrent operator change')
        target.chmod(0o644)
        with self.assertRaisesRegex(assets.AssetError, 'asset_concurrent_target_change'):
            self.ops.replace(row, (self.source / row['source']).read_bytes(), None)
        self.assertEqual(target.read_bytes(), b'concurrent operator change')


if __name__ == '__main__':
    unittest.main()
