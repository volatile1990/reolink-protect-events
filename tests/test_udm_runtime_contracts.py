import base64
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parents[1] / 'services/udm'
for name in ('runtime_contracts', 'nginx_guard'):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
runtime = sys.modules['runtime_contracts']
nginx = sys.modules['nginx_guard']


def recipe(key, before, after, *, capability='controls_http', target='service', contexts=(), kind='replace'):
    enc = lambda value: base64.b64encode(value).decode()
    row = {'id': key, 'capability': capability, 'target': target, 'kind': kind,
           'after': enc(after), 'contexts': [enc(value) for value in contexts]}
    if kind == 'replace':
        row['before'] = enc(before)
    return runtime.recipes_from_json({'schema': 1, 'recipes': [row]})[0]


class RuntimeContractsTests(unittest.TestCase):
    def test_vendor_version_and_unrelated_source_changes_do_not_block(self):
        item = recipe('control', b'function target(){native()}', b'function target(){owned();native()}')
        for version in ('7.3.70', '7.3.74', '8.99.1'):
            source = ('version="' + version + '";unrelatedNewCode();').encode() + item['before']
            candidate, report = runtime.transform(source, [item])
            self.assertEqual(candidate, source.replace(item['before'], item['after']))
            self.assertEqual(report[0]['state'], 'applicable')
            again, report = runtime.transform(candidate, [item])
            self.assertEqual(candidate, again)
            self.assertEqual(report[0]['state'], 'present')

    def test_changed_or_ambiguous_contract_is_left_untouched(self):
        item = recipe('control', b'exact()', b'owned(exact())')
        for source in (b'changed()', b'exact();exact()', b'owned(exact());exact()'):
            candidate, report = runtime.transform(source, [item])
            self.assertEqual(candidate, source)
            self.assertEqual(report[0]['state'], 'contract_changed')

    def test_context_preserves_authentication_boundary(self):
        item = recipe('control', b'handle()', b'ownedHandle()', contexts=(b'authenticateFirst()',))
        source = b'newAuthentication();handle()'
        candidate, report = runtime.transform(source, [item])
        self.assertEqual(candidate, source)
        self.assertEqual(report[0]['state'], 'contract_changed')

    def test_dependent_patch_group_rolls_back_without_blocking_independent_function(self):
        rows = [recipe('resolver', b'resolver()', b'ownedResolver()', capability='automatic_input'),
                recipe('caller', b'caller()', b'ownedCaller()', capability='automatic_input'),
                recipe('control', b'handle()', b'ownedHandle()')]
        source = b'resolver();changedCaller();handle()'
        candidate, report = runtime.transform(source, rows)
        self.assertEqual(candidate, b'resolver();changedCaller();ownedHandle()')
        self.assertIn('contract_changed', [row['state'] for row in report[:2]])
        self.assertEqual(report[-1]['state'], 'applicable')

    def test_prefix_and_panel_are_idempotent_and_cannot_overwrite_foreign_prefix(self):
        prefix = b'/* reolink-protect-controls:v1 begin */\nownedRuntime();\n/* reolink-protect-controls:v1 end */\n'
        rows = [recipe('prefix', b'', prefix, capability='controls_ui', target='ui', kind='prefix'),
                recipe('panel', b'nativePanel()', b'ownedPanel(),nativePanel()', capability='controls_ui', target='ui')]
        source = b'nativePanel()'
        candidate, _ = runtime.transform(source, rows)
        self.assertTrue(candidate.startswith(prefix))
        again, report = runtime.transform(candidate, rows)
        self.assertEqual(candidate, again)
        self.assertTrue(all(row['state'] == 'present' for row in report))
        foreign = prefix.replace(b'ownedRuntime()', b'operatorModifiedRuntime()') + source
        changed, report = runtime.transform(foreign, rows)
        self.assertEqual(changed, foreign)
        self.assertEqual(report[0]['state'], 'contract_changed')

    def test_invalid_recipe_scope_and_fragment_fail(self):
        for change in ({'target': '../../service'}, {'capability': 'execute_shell'}, {'after': '!invalid'},
                       {'kind': 'delete'}, {'id': 'bad/id'}):
            row = {'id': 'control', 'capability': 'controls_http', 'target': 'service', 'kind': 'replace',
                   'before': base64.b64encode(b'before').decode(), 'after': base64.b64encode(b'after').decode()}
            row.update(change)
            with self.assertRaises(runtime.ContractError):
                runtime.recipes_from_json({'schema': 1, 'recipes': [row]})


NATIVE = b'''server {
 location /proxy/protect/ {
  auth_request /unchanged-native-auth;
  proxy_set_header X-Existing-Identity $native_identity;
  proxy_pass http://protect_api_backend/;
 }
 location /unrelated { return 200; }
}
'''


class NginxContractsTests(unittest.TestCase):
    def test_routes_copy_current_native_auth_without_changing_other_locations(self):
        candidate = nginx.transform_shared(NATIVE)
        for route, upstream in nginx.ROUTES.items():
            self.assertIn(('location = ' + route).encode(), candidate)
            self.assertIn(('proxy_pass http://protect_api_backend' + upstream).encode(), candidate)
        self.assertEqual(candidate.count(b'auth_request /unchanged-native-auth;'), 4)
        self.assertEqual(candidate.count(b'proxy_set_header X-Existing-Identity $native_identity;'), 4)
        self.assertIn(b'location /unrelated { return 200; }', candidate)
        self.assertEqual(nginx.transform_shared(candidate), candidate)

    def test_unrelated_vendor_configuration_changes_remain_allowed(self):
        changed = NATIVE.replace(b'return 200;', b'return 201;')
        candidate = nginx.transform_shared(changed)
        self.assertIn(b'return 201;', candidate)
        self.assertEqual(nginx.transform_shared(candidate), candidate)

    def test_native_auth_is_adapted_from_current_vendor_block(self):
        changed = NATIVE.replace(b'/unchanged-native-auth', b'/new-native-auth')
        candidate = nginx.transform_shared(changed)
        self.assertEqual(candidate.count(b'auth_request /new-native-auth;'), 4)
        self.assertNotIn(b'/unchanged-native-auth', candidate)

    def test_foreign_route_and_duplicate_native_location_are_refused(self):
        foreign = NATIVE + b'location = /proxy/protect/ws/livestream { return 403; }'
        for source in (foreign, NATIVE + NATIVE, NATIVE.replace(b'protect_api_backend/', b'unknown_backend/')):
            with self.assertRaises(runtime.ContractError):
                nginx.transform_shared(source)

    def test_more_specific_prefix_and_quoted_locations_cannot_be_bypassed(self):
        for location in ('/proxy/protect/api/', '^~ /proxy/protect/api/',
                         '"/proxy/protect/api/ws/"', "'/proxy/protect/ws/'",
                         '= "/proxy/protect/api/tcp/livestream"'):
            foreign=NATIVE+b'location '+location.encode()+b' { deny all; }'
            with self.subTest(location=location),self.assertRaises(runtime.ContractError):
                nginx.transform_shared(foreign)

    def test_regex_locations_fail_closed_instead_of_assuming_pcre_semantics(self):
        for location in ('~ ^/proxy/protect/api/ws/livestream$', '~* /proxy/protect/(api/)?(ws|tcp)/',
                         '~ "^/proxy/protect/api/"'):
            foreign=NATIVE+b'location '+location.encode()+b' { deny all; }'
            with self.subTest(location=location),self.assertRaises(runtime.ContractError):
                nginx.transform_shared(foreign)

    def test_disjoint_prefix_and_exact_routes_remain_untouched(self):
        foreign=NATIVE+b'location /proxy/protect/api/snapshots/ { deny all; }\nlocation = /proxy/protect/api/ { deny all; }'
        candidate=nginx.transform_shared(foreign)
        self.assertIn(b'location /proxy/protect/api/snapshots/ { deny all; }',candidate)
        self.assertIn(b'location = /proxy/protect/api/ { deny all; }',candidate)

    def test_operator_modified_owned_route_is_not_overwritten(self):
        candidate = nginx.transform_shared(NATIVE)
        # Alter just one owned clone while leaving the native auth block intact.
        changed = candidate.replace(b'auth_request /unchanged-native-auth;', b'auth_request /operator-auth;', 2)
        with self.assertRaises(runtime.ContractError):
            nginx.transform_shared(changed)

    def test_query_map_ignores_unrelated_global_directives(self):
        owned = ('    ' + nginx.BEGIN + '\n    map $request_uri $codex_live_' + nginx.OPERATION +
                 '_args { default $args; }\n    ' + nginx.END + '\n')
        first = 'unrelated before;\n' + owned + 'unrelated after;\n'
        self.assertEqual(nginx.own_map(first), nginx.own_map(first.replace('before', 'changed')))


if __name__ == '__main__':
    unittest.main()
