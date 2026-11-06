"""Recover owned routes after native root/shared Nginx regeneration."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / 'services/udm'
if 'runtime_contracts' not in sys.modules:
    spec = importlib.util.spec_from_file_location('runtime_contracts', HERE / 'runtime_contracts.py')
    runtime = importlib.util.module_from_spec(spec)
    sys.modules['runtime_contracts'] = runtime
    spec.loader.exec_module(runtime)
spec = importlib.util.spec_from_file_location('nginx_recovery_guard', HERE / 'nginx_guard.py')
nginx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nginx)

SYMBOL = '$codex_live_' + nginx.OPERATION + '_args'
OWNED_MAP = ('    ' + nginx.BEGIN + '\n'
             '    map "$request_method|$args" ' + SYMBOL + ' {\n'
             '        default $args;\n'
             '        "~^GET[|](?<owned_capture>example)$" "value";\n'
             '    }\n    ' + nginx.END + '\n').encode()
ROOT = b'''worker_processes auto;
events { worker_connections 512; }
http {
    include /etc/nginx/mime.types;
    map $native_source $native_result { default native; }
    include /data/unifi-core/config/http/site-*.conf;
}
'''
SHARED = b'''server {
 location /proxy/protect/ {
  auth_request /current-vendor-auth;
  proxy_set_header X-Identity $current_vendor_identity;
  proxy_pass http://protect_api_backend/;
 }
 location /unrelated { return 201; }
}
'''
ARCHIVE_MAPS = ('\n    ' + nginx.ARCHIVE_MARKER + '\n'
                '    upstream ' + nginx.ARCHIVE_PREFIX + '_backend { server 127.0.0.1:7712; }\n'
                '    map "$arg_camera|$arg_channel" $' + nginx.ARCHIVE_PREFIX + '_upstream {\n'
                '        default protect_mspWs_backend;\n'
                '        "synthetic|0" ' + nginx.ARCHIVE_PREFIX + '_backend;\n    }\n'
                '    map $request_uri $' + nginx.ARCHIVE_PREFIX + '_uri {\n'
                '        "~^[^?]*(?<owned_archive_query>[?].*)?$" "/playback/$owned_archive_query";\n'
                '    }\n').encode()
FULL_SHARED = SHARED.replace(b' location /unrelated', b''' location /proxy/protect/ws/playback {
  auth_request /current-playback-auth;
  proxy_set_header X-Playback-Identity $current_playback_identity;
  proxy_pass http://protect_mspWs_backend/playback/;
 }
 location /unrelated''')


class MainRecoveryTests(unittest.TestCase):
    def test_regenerated_root_receives_only_owned_map_inside_http(self):
        candidate = nginx.transform_main(ROOT, owned_map=OWNED_MAP)
        self.assertEqual(candidate.replace(b'\n' + OWNED_MAP, b'', 1), ROOT)
        http = next(block for block in nginx.blocks(candidate.decode()) if block['header'] == ['http'])
        own = nginx.own_span(candidate.decode())
        self.assertLess(http['bodyStart'], own[0])
        self.assertLess(own[1], http['bodyEnd'])
        self.assertIn(b'map $native_source $native_result { default native; }', candidate)

    def test_repeated_root_recovery_is_byte_idempotent(self):
        first = nginx.transform_main(ROOT, owned_map=OWNED_MAP)
        self.assertEqual(nginx.transform_main(first, owned_map=OWNED_MAP), first)

    def test_independent_vendor_changes_remain_in_current_root(self):
        changed = ROOT.replace(b'worker_connections 512', b'worker_connections 1024')
        changed = changed.replace(b'default native', b'default current_native')
        candidate = nginx.transform_main(changed, owned_map=OWNED_MAP)
        self.assertEqual(candidate.replace(b'\n' + OWNED_MAP, b'', 1), changed)

    def test_missing_duplicate_nested_or_unbalanced_http_is_refused(self):
        for source in (b'events {}', ROOT + b'http {}', b'foreign { http {} }', ROOT[:-2]):
            with self.subTest(source=source), self.assertRaises(nginx.ContractError):
                nginx.transform_main(source, owned_map=OWNED_MAP)

    def test_existing_owned_map_outside_http_is_refused(self):
        with self.assertRaisesRegex(nginx.ContractError, 'owned_query_map_context_changed'):
            nginx.transform_main(OWNED_MAP + ROOT, owned_map=OWNED_MAP)

    def test_modified_and_duplicate_owned_maps_are_refused(self):
        present = nginx.transform_main(ROOT, owned_map=OWNED_MAP)
        for source in (present.replace(b'"value"', b'"operator-value"'), present + OWNED_MAP):
            with self.subTest(source=source), self.assertRaises(nginx.ContractError):
                nginx.transform_main(source, owned_map=OWNED_MAP)

    def test_foreign_output_symbol_and_regex_capture_are_not_overwritten(self):
        for addition in ('map $args ' + SYMBOL + ' { default foreign; }',
                         'map $args $other { "~(?<owned_capture>.*)" value; }',
                         'log_format custom "$owned_capture";',
                         'log_format custom "' + SYMBOL + '";'):
            source = ROOT.replace(b'http {', b'http {\n' + addition.encode())
            with self.subTest(addition=addition), self.assertRaisesRegex(
                    nginx.ContractError, 'foreign_owned_query_symbol'):
                nginx.transform_main(source, owned_map=OWNED_MAP)

    def test_comment_only_symbol_references_are_not_definitions(self):
        source = ROOT.replace(b'http {', b'http {\n# note ' + SYMBOL.encode() + b' $owned_capture\n')
        candidate = nginx.transform_main(source, owned_map=OWNED_MAP)
        self.assertIn(b'# note ', candidate)

    def test_recipe_cannot_add_another_directive_or_wrong_map_variable(self):
        for recipe in (OWNED_MAP + b'worker_processes 9;\n',
                       OWNED_MAP.replace(SYMBOL.encode(), b'$foreign'),
                       OWNED_MAP.replace(b'    }\n', b'    }\n    map $a $b { default x; }\n')):
            with self.subTest(recipe=recipe), self.assertRaises(nginx.ContractError):
                nginx.transform_main(ROOT, owned_map=recipe)


class TransactionFixture:
    def __init__(self, main=ROOT, shared=SHARED):
        self.path = Path('/private/recipes.json')
        generated = nginx.transform_shared(SHARED).decode()
        span = nginx.own_span(generated)
        encode = lambda value: base64.b64encode(value).decode()
        config = {'nginxOwnedMap': encode(OWNED_MAP),
                  'nginxOwnedRoutes': encode(generated[span[0]:span[1]].encode())}
        self.data = {self.path: json.dumps(config).encode(), nginx.MAIN: main, nginx.SHARED: shared}
        self.meta = SimpleNamespace(st_mode=0o100644, st_uid=0, st_gid=0)
        self.writes = []
        self.commands = []
        self.before_write = None
        self.on_command = None

    def read(self, path, **kwargs):
        return self.data[path], self.meta

    def atomic(self, path, data, meta, *, expected=None):
        if self.before_write:
            self.before_write(path, data)
        nginx.need(self.data[path] == expected, 'concurrent_main_change' if path == nginx.MAIN
                   else 'concurrent_shared_change')
        self.data[path] = data
        self.writes.append((path, data))

    def command(self, args):
        self.commands.append(args)
        return True if not self.on_command else self.on_command(args)

    def run(self, *, apply=True):
        with mock.patch.object(nginx, 'read_secure', side_effect=self.read), \
                mock.patch.object(nginx, 'atomic', side_effect=self.atomic), \
                mock.patch.object(nginx, 'command', side_effect=self.command):
            return nginx.run(self.path, apply=apply)


class NginxRecoveryTransactionTests(unittest.TestCase):
    def test_regenerated_root_and_shared_restore_current_native_auth_together(self):
        fixture = TransactionFixture()
        report = fixture.run()
        self.assertTrue(report['mainChanged'])
        self.assertTrue(report['sharedChanged'])
        self.assertFalse(report['protectRestarted'])
        self.assertEqual(fixture.commands, [['nginx', '-t'], ['nginx', '-s', 'reload']])
        self.assertEqual(fixture.data[nginx.SHARED].count(b'auth_request /current-vendor-auth;'), 4)
        self.assertEqual(fixture.data[nginx.SHARED].count(b'X-Identity $current_vendor_identity;'), 4)
        writes = list(fixture.writes)
        self.assertEqual(fixture.run()['state'], 'present')
        self.assertEqual(writes, fixture.writes)

    def test_check_plans_both_files_without_writes_or_commands(self):
        fixture = TransactionFixture()
        self.assertEqual(fixture.run(apply=False)['state'], 'applicable')
        self.assertEqual(fixture.writes, [])
        self.assertEqual(fixture.commands, [])

    def test_each_file_can_regenerate_independently(self):
        for main, shared, changed in (
                (nginx.transform_main(ROOT, owned_map=OWNED_MAP), SHARED, nginx.SHARED),
                (ROOT, nginx.transform_shared(SHARED), nginx.MAIN)):
            fixture = TransactionFixture(main, shared)
            fixture.run()
            self.assertEqual([path for path, _ in fixture.writes], [changed])

    def test_missing_native_shared_file_prevents_even_root_map_mutation(self):
        fixture = TransactionFixture()
        del fixture.data[nginx.SHARED]
        with self.assertRaises(KeyError):
            fixture.run()
        self.assertEqual(fixture.writes, [])

    def test_foreign_shared_route_prevents_root_map_mutation(self):
        fixture = TransactionFixture(shared=SHARED + b'location = /proxy/protect/ws/livestream { deny all; }')
        with self.assertRaisesRegex(nginx.ContractError, 'foreign_live_route'):
            fixture.run()
        self.assertEqual(fixture.writes, [])

    def test_syntax_failure_rolls_back_both_files(self):
        fixture = TransactionFixture()
        results = iter([False, True, True])
        fixture.on_command = lambda args: next(results)
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_syntax_failed'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], ROOT)
        self.assertEqual(fixture.data[nginx.SHARED], SHARED)
        self.assertEqual([path for path, _ in fixture.writes],
                         [nginx.MAIN, nginx.SHARED, nginx.SHARED, nginx.MAIN])

    def test_reload_failure_rolls_back_both_files(self):
        fixture = TransactionFixture()
        results = iter([True, False, True, True])
        fixture.on_command = lambda args: next(results)
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_reload_failed'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], ROOT)
        self.assertEqual(fixture.data[nginx.SHARED], SHARED)

    def test_exception_after_rename_still_rolls_back_that_file(self):
        fixture = TransactionFixture()
        atomic = fixture.atomic
        failed = [False]
        def fail_after_write(path, data, meta, *, expected=None):
            atomic(path, data, meta, expected=expected)
            if path == nginx.SHARED and not failed[0]:
                failed[0] = True
                raise OSError('simulated directory fsync failure after rename')
        fixture.atomic = fail_after_write
        with self.assertRaisesRegex(OSError, 'simulated directory fsync'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], ROOT)
        self.assertEqual(fixture.data[nginx.SHARED], SHARED)

    def test_drift_between_file_writes_preserves_foreign_content_and_restores_ours(self):
        fixture = TransactionFixture()
        foreign = SHARED + b'# concurrent vendor regeneration\n'
        def change(path, data):
            if path == nginx.SHARED:
                fixture.data[path] = foreign
        fixture.before_write = change
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_rollback_conflict'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], ROOT)
        self.assertEqual(fixture.data[nginx.SHARED], foreign)
        self.assertEqual(fixture.commands, [])

    def test_drift_during_syntax_check_prevents_reload_and_is_not_overwritten(self):
        fixture = TransactionFixture()
        foreign = ROOT + b'# operator change\n'
        def change(args):
            fixture.data[nginx.MAIN] = foreign
            return True
        fixture.on_command = change
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_rollback_conflict'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], foreign)
        self.assertEqual(fixture.data[nginx.SHARED], SHARED)
        self.assertEqual(fixture.commands, [['nginx', '-t']])

    def test_failed_rollback_validation_never_reloads_invalid_configuration(self):
        fixture = TransactionFixture()
        fixture.on_command = lambda args: False
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_rollback_failed'):
            fixture.run()
        self.assertEqual(fixture.commands, [['nginx', '-t'], ['nginx', '-t']])

    def test_atomic_compare_and_swap_rechecks_after_candidate_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nginx.conf'
            path.write_bytes(b'original')
            meta = path.stat()
            with mock.patch.object(nginx.os, 'chown', create=True), \
                    mock.patch.object(nginx, 'read_secure', return_value=(b'foreign', meta)):
                with self.assertRaisesRegex(nginx.ContractError, 'concurrent_shared_change'):
                    nginx.atomic(path, b'candidate', meta, expected=b'original')
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(list(Path(directory).iterdir()), [path])


class ArchiveRecoveryTests(unittest.TestCase):
    def fixture(self, main=ROOT, shared=FULL_SHARED):
        fixture = TransactionFixture(main, shared)
        route, _ = nginx.archive_route_fragment(FULL_SHARED.decode())
        config = json.loads(fixture.data[fixture.path])
        config.update(nginxOwnedArchiveMaps=base64.b64encode(ARCHIVE_MAPS).decode(),
                      nginxOwnedArchiveRoute=base64.b64encode(route).decode())
        fixture.data[fixture.path] = json.dumps(config).encode()
        return fixture

    def test_archive_main_restores_exact_maps_and_upstream_without_native_changes(self):
        candidate = nginx.transform_archive_main(ROOT, owned_maps=ARCHIVE_MAPS)
        self.assertEqual(candidate.replace(ARCHIVE_MAPS, b'', 1), ROOT)
        self.assertEqual(nginx.transform_archive_main(candidate, owned_maps=ARCHIVE_MAPS), candidate)
        self.assertIn(b'server 127.0.0.1:7712;', candidate)

    def test_archive_main_rejects_foreign_symbols_and_modified_own_maps(self):
        present = nginx.transform_archive_main(ROOT, owned_maps=ARCHIVE_MAPS)
        for source in (present.replace(b'7712', b'8888'), present + ARCHIVE_MAPS,
                       ROOT.replace(b'http {', b'http { map $args $' + nginx.ARCHIVE_PREFIX.encode()
                                    + b'_uri { default native; }'),
                       ROOT.replace(b'http {', b'http { log_format custom "${owned_archive_query}";')):
            with self.subTest(source=source), self.assertRaises(nginx.ContractError):
                nginx.transform_archive_main(source, owned_maps=ARCHIVE_MAPS)

    def test_archive_maps_in_wrong_scope_are_refused(self):
        with self.assertRaisesRegex(nginx.ContractError, 'owned_archive_maps_context_changed'):
            nginx.transform_archive_main(ARCHIVE_MAPS + ROOT, owned_maps=ARCHIVE_MAPS)

    def test_full_firmware_reset_recovers_live_and_archive_with_current_auth(self):
        fixture = self.fixture()
        report = fixture.run()
        self.assertTrue(report['archiveConfigured'])
        self.assertEqual(fixture.data[nginx.SHARED].count(b'auth_request /current-playback-auth;'), 2)
        self.assertEqual(fixture.data[nginx.SHARED].count(b'X-Playback-Identity $current_playback_identity;'), 2)
        self.assertEqual(fixture.data[nginx.SHARED].count(b'auth_request /current-vendor-auth;'), 4)
        self.assertEqual(fixture.commands, [['nginx', '-t'], ['nginx', '-s', 'reload']])
        before = dict(fixture.data)
        self.assertEqual(fixture.run()['state'], 'present')
        self.assertEqual(fixture.data, before)

    def test_new_native_playback_auth_is_used_when_shared_regenerates(self):
        changed = FULL_SHARED.replace(b'/current-playback-auth', b'/new-native-playback-auth')
        changed = changed.replace(b'$current_playback_identity', b'$new_playback_identity')
        fixture = self.fixture(shared=changed)
        fixture.run()
        result = fixture.data[nginx.SHARED]
        self.assertEqual(result.count(b'auth_request /new-native-playback-auth;'), 2)
        self.assertEqual(result.count(b'$new_playback_identity;'), 2)
        self.assertNotIn(b'/current-playback-auth', result)

    def test_foreign_archive_exact_prefix_and_regex_routes_are_preserved(self):
        for location in ('= /proxy/protect/ws/playback', '/proxy/protect/ws/',
                         '^~ /proxy/protect/ws/', '~ /proxy/protect/ws/playback'):
            fixture = self.fixture(shared=FULL_SHARED + b'location ' + location.encode() + b' { deny all; }')
            with self.subTest(location=location), self.assertRaises(nginx.ContractError):
                fixture.run()
            self.assertEqual(fixture.writes, [])

    def test_owned_archive_operator_change_is_not_overwritten(self):
        fixture = self.fixture()
        fixture.run()
        fixture.data[nginx.SHARED] = fixture.data[nginx.SHARED].replace(
            ('proxy_pass http://$' + nginx.ARCHIVE_PREFIX + '_upstream').encode(),
            b'proxy_pass http://operator_backend')
        fixture.writes.clear()
        with self.assertRaisesRegex(nginx.ContractError, 'owned_archive_route_contract_changed'):
            fixture.run()
        self.assertEqual(fixture.writes, [])

    def test_full_live_and_archive_recovery_rolls_back_on_syntax_failure(self):
        fixture = self.fixture()
        results = iter([False, True, True])
        fixture.on_command = lambda args: next(results)
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_syntax_failed'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], ROOT)
        self.assertEqual(fixture.data[nginx.SHARED], FULL_SHARED)

    def test_incomplete_archive_recipe_prevents_every_write(self):
        fixture = self.fixture()
        config = json.loads(fixture.data[fixture.path])
        del config['nginxOwnedArchiveRoute']
        fixture.data[fixture.path] = json.dumps(config).encode()
        with self.assertRaisesRegex(nginx.ContractError, 'archive_recipe_incomplete'):
            fixture.run()
        self.assertEqual(fixture.writes, [])

    def test_private_snapshot_extraction_requires_both_existing_ownership_pins(self):
        snapshot = nginx.transform_archive_main(ROOT, owned_maps=ARCHIVE_MAPS)
        route, _ = nginx.archive_route_fragment(FULL_SHARED.decode())
        result = nginx.archive_recipe_fragments(snapshot, FULL_SHARED,
                    maps_sha256=nginx.digest(ARCHIVE_MAPS), route_sha256=nginx.digest(route))
        self.assertEqual(base64.b64decode(result['nginxOwnedArchiveMaps']), ARCHIVE_MAPS)
        self.assertEqual(base64.b64decode(result['nginxOwnedArchiveRoute']), route)
        with self.assertRaisesRegex(nginx.ContractError, 'archive_recipe_source_pin_changed'):
            nginx.archive_recipe_fragments(snapshot, FULL_SHARED,
                    maps_sha256='0' * 64, route_sha256=nginx.digest(route))

    def test_drift_during_reload_is_detected_without_overwriting_foreign_root(self):
        fixture = self.fixture()
        foreign = ROOT + b'# changed during reload\n'
        def command(args):
            if args[-1] == 'reload':
                fixture.data[nginx.MAIN] = foreign
            return True
        fixture.on_command = command
        with self.assertRaisesRegex(nginx.ContractError, 'nginx_rollback_conflict'):
            fixture.run()
        self.assertEqual(fixture.data[nginx.MAIN], foreign)
        self.assertEqual(fixture.data[nginx.SHARED], FULL_SHARED)


if __name__ == '__main__':
    unittest.main()
