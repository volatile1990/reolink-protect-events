"""Migrate trusted owned runtime snippets to private version-free recipes.

Run beside runtime_contracts.py on the console. This reads only the existing
root-private manifest and its hash-verified sources. It emits no source, camera
scope, credentials or vendor code to stdout. The new private JSON contains the
same already-owned snippets; it never copies an old complete vendor bundle over
a newly installed package.
"""
import argparse
import ast
import base64
import json
from pathlib import Path
import re

from runtime_contracts import ContractError, digest, need, read_secure, recipes_from_json, secure_path
from nginx_guard import MAIN, SHARED, own_map, own_span, transform_shared

MANIFEST = Path('/data/reolink-protect-recovery/runtime/manifest.json')
CONTROL_BEFORE = b'const a=o=>{if(o)return r(o);super.handle(e,t,r)}'
CONTROL_AFTER = b'const a=o=>{if(o)return r(o);if(require("/usr/local/lib/reolink-protect-controls/protect-hook.cjs").handle(e,t,r,this))return;super.handle(e,t,r)}'
PIPE_BEFORE = b'w.pipe(D),D.pipe(w)'
SCOPE_BEFORE = b'scope_all_ui_cameras:e=>(0,t.deviceNotDeleted)(e)&&e.isAdopted&&(0,s.isCamera)(e)&&!e.isThirdPartyCamera'
SEARCH_BEFORE = b'(e,a,r)=>(!a||!!r.has(e.nvrMac))&&(!e.isThirdPartyCamera||!!e.isPairedWithAiPort)'
UI_ANCHOR = b'(()=>{if(!C||!F)return null;let e=d.featureFlags.hasFisheye'
PREFIX_BEGIN = b'/* reolink-protect-controls:v1 begin */\n'
PREFIX_END = b'\n/* reolink-protect-controls:v1 end */\n'


def encoded(data):
    return base64.b64encode(data).decode('ascii')


def decoded_literal(node):
    need(isinstance(node, ast.Call) and len(node.args) == 1 and isinstance(node.func, ast.Attribute)
         and isinstance(node.func.value, ast.Name) and node.func.value.id == 'base64'
         and node.func.attr == 'b64decode', 'legacy_literal_contract_changed')
    return base64.b64decode(ast.literal_eval(node.args[0]), validate=True)


def prepare(manifest_path=MANIFEST):
    # The established restore manifest is 0644 inside its root-only 0700
    # runtime directory. Its effective access boundary remains root-private.
    need(not manifest_path.parent.stat().st_mode & 0o077, 'legacy_directory_not_private')
    raw, _ = read_secure(manifest_path)
    manifest = json.loads(raw)
    need(manifest.get('schema') == 1 and isinstance(manifest.get('files'), list), 'legacy_manifest_invalid')
    sources = {}
    for row in manifest['files']:
        basename = row.get('source')
        need(isinstance(basename, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', basename)),
             'legacy_source_path_invalid')
        content, _ = read_secure(manifest_path.parent / basename)
        need(digest(content) == row.get('sha256'), 'legacy_source_digest_changed')
        sources[basename] = content
    service = sources['service.js']
    ui = sources['swai.js']
    tree = ast.parse(sources['automatic-quality-guard.py'])
    pair_assignments = [node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'PAIRS' for target in node.targets)]
    need(len(pair_assignments) == 1, 'legacy_automatic_pairs_missing')
    pairs = [(base64.b64decode(a, validate=True), base64.b64decode(b, validate=True))
             for a, b in ast.literal_eval(pair_assignments[0].value)]
    need(len(pairs) == 4 and all(service.count(after) == 1 for _, after in pairs), 'legacy_automatic_sources_changed')
    after = pairs[0][1].decode('utf-8')
    scope_start = after.index('const __codexAutoScope=Object.freeze(') + len('const __codexAutoScope=Object.freeze(')
    scope, _ = json.JSONDecoder().raw_decode(after[scope_start:])
    identities = sorted(row['id'] for row in scope)
    need(0 < len(identities) <= 64 and len(set(identities)) == len(identities)
         and all(re.fullmatch(r'[a-f0-9]{24}', value) for value in identities), 'legacy_camera_scope_invalid')
    selected = json.dumps(identities, separators=(',', ':')).encode('ascii')
    recipes = []

    def add(key, capability, target, before, patched, contexts=(), kind='replace'):
        trusted = service if target == 'service' else ui
        need(trusted.count(patched) == 1, 'legacy_owned_snippet_changed:' + key)
        value = {'id': key, 'capability': capability, 'target': target, 'kind': kind,
                 'after': encoded(patched), 'contexts': [encoded(item) for item in contexts]}
        if kind == 'replace':
            value['before'] = encoded(before)
        recipes.append(value)

    add('controls-http', 'controls_http', 'service', CONTROL_BEFORE, CONTROL_AFTER,
        (b'e.use(this.auth.initialize()),e.use(this.handle)',))
    pipe_after = b'(' + selected + b'.includes(g.pk)&&String(_).toLowerCase()==="ubv"?require("/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat-all.cjs").wireOutgoing(w,D,g.pk,_):w.pipe(D)),D.pipe(w)'
    add('live-aac', 'live_aac', 'service', PIPE_BEFORE, pipe_after,
        (b'if(!(l||(null==o?void 0:o.can("readlive",g))',))
    for index, (before, patched) in enumerate(pairs):
        add('automatic-input-' + str(index), 'automatic_input', 'service', before, patched)
    cleanup = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'detection_cleanup']
    need(len(cleanup) == 1, 'legacy_cleanup_missing')
    assignments = {target.id: node.value for node in cleanup[0].body if isinstance(node, ast.Assign)
                   for target in node.targets if isinstance(target, ast.Name)}
    add('event-cleanup', 'event_cleanup', 'service', decoded_literal(assignments['before']),
        decoded_literal(assignments['after']))
    scope_after = SCOPE_BEFORE.rsplit(b'&&!e.isThirdPartyCamera', 1)[0] + b'&&(!e.isThirdPartyCamera||(' + selected + b'.includes(e.pk)&&e.featureFlags.hasSmartDetect))'
    # The broader alarm-scope patch was optional. Never enable a feature which
    # was absent from the proven operator-owned runtime.
    if service.count(scope_after) == 1:
        add('alarm-scope', 'alarm_scope', 'service', SCOPE_BEFORE, scope_after)
    else:
        need(service.count(SCOPE_BEFORE) == 1, 'legacy_alarm_scope_contract_changed')
    add('event-search', 'event_search', 'ui', SEARCH_BEFORE,
        SEARCH_BEFORE[:-1] + b'||(' + selected + b'.includes(e.id)&&e.featureFlags.hasSmartDetect))')
    need(ui.startswith(PREFIX_BEGIN) and ui.count(PREFIX_BEGIN) == ui.count(PREFIX_END) == 1,
         'legacy_controls_prefix_changed')
    prefix = ui[:ui.index(PREFIX_END) + len(PREFIX_END)]
    insertion = (b'!C||!F||!d.isThirdPartyCamera||!' + selected + b'.includes(d.id)?null:{id:"reolink-controls",defaultIsOpen:!0,header:"Reolink-Kamerafunktionen",children:tT.createElement(window.ReolinkProtectControls.createPanel(tT),{cameraId:d.id,api:d.api})},' + UI_ANCHOR)
    add('controls-ui-prefix', 'controls_ui', 'ui', b'', prefix, (UI_ANCHOR,), kind='prefix')
    add('controls-ui-panel', 'controls_ui', 'ui', UI_ANCHOR, insertion,
        (b'isAdoptedByAccessApp:H,hasFullFeatureSet:W}=d,Y=tT.createElement',))
    result = {'schema': 1, 'sourceManifestSha256': digest(raw), 'recipes': recipes}
    # This one-time migration proves ownership of the existing generated map.
    # Runtime checks subsequently pin only that owned block, never this file.
    main, _ = read_secure(MAIN)
    need(digest(main) == '8e6b5039a16375c112d9a608ef6ba890a2fcc54eded3e13524e4dc30b2a602d4',
         'legacy_owned_nginx_map_unproven')
    result['nginxOwnedMap'] = encoded(own_map(main.decode('utf-8')))
    shared, _ = read_secure(SHARED)
    generated = transform_shared(shared).decode('utf-8')
    span = own_span(generated)
    result['nginxOwnedRoutes'] = encoded(generated[span[0]:span[1]].encode('utf-8'))
    recipes_from_json(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.manifest)
    # The caller must pre-create a private directory; exclusive create avoids
    # replacing a concurrently prepared operator intent.
    import os
    secure_path(args.output.parent, private=True, directory=True)
    need(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', args.output.name)), 'invalid_output_basename')
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, sort_keys=True)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps({'ok': True, 'recipeCount': len(result['recipes']), 'output': str(args.output)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': str(error) if isinstance(error, ContractError) else 'recipe_prepare_failed'}))
        raise SystemExit(1)
