"""Restore owned live/playback routes with their current native auth blocks.

Only the integration's own map/upstream blocks are pinned. A regenerated
root configuration can receive those absent blocks inside its unique HTTP
context; the current native routes and authentication remain authoritative.
Protect's version and complete configuration hashes are not compatibility
gates. No engine restart is performed.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from runtime_contracts import ContractError, digest, fragment, need, read_secure, secure_path

MAIN = Path('/etc/nginx/nginx.conf')
SHARED = Path('/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf')
ROOT = Path('/data/reolink-protect-controls/automatic-quality')
OPERATION = '2024de37468a4eac'
BEGIN = '# BEGIN Eingang native live-start ' + OPERATION
END = '# END Eingang native live-start ' + OPERATION
ROUTES = {'/proxy/protect/api/ws/livestream': '/api/ws/livestream',
          '/proxy/protect/api/tcp/livestream': '/api/tcp/livestream',
          '/proxy/protect/ws/livestream': '/ws/livestream'}
ARCHIVE_OWNER = '7957a02d504c4634'
ARCHIVE_MARKER = '# Scoped native MSP archive canary ' + ARCHIVE_OWNER
ARCHIVE_PREFIX = 'codex_archive_' + ARCHIVE_OWNER
ARCHIVE_ROUTE = '/proxy/protect/ws/playback'


def own_span(text):
    starts = list(re.finditer(r'(?m)^[ \t]*' + re.escape(BEGIN) + r'[ \t]*\n', text))
    ends = list(re.finditer(r'(?m)^[ \t]*' + re.escape(END) + r'[ \t]*(?:\n|$)', text))
    need(len(starts) == len(ends) and len(starts) <= 1, 'owned_route_boundaries_changed')
    if not starts:
        return None
    need(starts[0].start() < ends[0].start(), 'owned_route_boundaries_changed')
    return starts[0].start(), ends[0].end()


def own_map(text):
    span = own_span(text)
    need(span is not None, 'owned_query_map_missing')
    value = text[span[0]:span[1]]
    need(value.count('$codex_live_' + OPERATION + '_args') == 1
         and 'default $args;' in value, 'owned_query_map_contract_changed')
    return value.encode('utf-8')


def blocks(text):
    """Tokenize Nginx braces while ignoring quoted/escaped values and comments."""
    pattern = r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};\#"']+'''
    stack, pending, result = [], [], []
    pending_start = None
    for match in re.finditer(pattern, text):
        value = match.group()
        if value.isspace() or value.startswith('#'):
            continue
        if value == '{':
            stack.append((pending, match.end(), len(stack), pending_start))
            pending = []
            pending_start = None
        elif value == '}':
            need(bool(stack), 'invalid_config_structure')
            header, start, depth, header_start = stack.pop()
            result.append({'header': header, 'bodyStart': start, 'bodyEnd': match.start(),
                           'end': match.end(), 'depth': depth, 'start': header_start})
            pending = []
            pending_start = None
        elif value == ';':
            pending = []
            pending_start = None
        else:
            if not pending:
                pending_start = match.start()
            pending.append(value)
    need(not stack, 'invalid_config_structure')
    return result


def _check_owned_symbols(outside, variables, upstreams=()):
    uncommented = re.sub(r'''\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''',
                         lambda match: '' if match.group().startswith('#') else match.group(),
                         outside, flags=re.VERBOSE)
    for name in variables:
        escaped = re.escape(name)
        need(not re.search(r'\$(?:' + escaped + r'(?![A-Za-z0-9_])|\{' + escaped
                           + r'\})|\(\?(?:P?<' + escaped + r'>|\x27' + escaped + r'\x27)',
                           uncommented), 'foreign_owned_query_symbol')
    for name in upstreams:
        need(not re.search(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'(?![A-Za-z0-9_])',
                           uncommented), 'foreign_owned_archive_upstream')


def transform_main(raw, *, owned_map):
    """Insert only a previously reviewed, absent map into native HTTP scope."""
    text, expected = raw.decode('utf-8'), owned_map.decode('utf-8')
    expected_span = own_span(expected)
    need(expected_span == (0, len(expected)) and own_map(expected) == owned_map,
         'owned_query_map_recipe_changed')
    symbol = 'codex_live_' + OPERATION + '_args'
    expected_blocks = blocks(expected)
    need(len(expected_blocks) == 1 and expected_blocks[0]['depth'] == 0
         and len(expected_blocks[0]['header']) == 3
         and expected_blocks[0]['header'][0] == 'map'
         and expected_blocks[0]['header'][-1] == '$' + symbol,
         'owned_query_map_recipe_changed')
    parsed = blocks(text)
    contexts = [block for block in parsed if block['header'] == ['http']]
    need(len(contexts) == 1 and contexts[0]['depth'] == 0, 'native_http_context_not_unique')
    http = contexts[0]
    span = own_span(text)
    if span:
        need(own_map(text) == owned_map, 'owned_query_map_contract_changed')
        maps = [block for block in parsed if block['header'] == expected_blocks[0]['header']]
        need(len(maps) == 1 and maps[0]['depth'] == 1
             and http['bodyStart'] <= span[0] < maps[0]['bodyStart']
             and maps[0]['end'] <= span[1] <= http['bodyEnd'],
             'owned_query_map_context_changed')
        outside = text[:span[0]] + text[span[1]:]
    else:
        outside = text
    # Named regex captures define global Nginx variables as well. Refuse both
    # foreign definitions and callers of our symbols before inserting a map.
    symbols = {symbol, *re.findall(r'\(\?(?:P?<)([A-Za-z_][A-Za-z0-9_]*)>', expected)}
    _check_owned_symbols(outside, symbols)
    if span:
        return raw
    position = http['bodyStart']
    candidate = text[:position] + '\n' + expected + text[position:]
    need(own_map(candidate) == owned_map, 'owned_query_map_insertion_changed')
    return candidate.encode('utf-8')


def _archive_marker(text):
    found = list(re.finditer(r'(?m)^[ \t]*' + re.escape(ARCHIVE_MARKER) + r'[ \t]*\n', text))
    need(len(found) <= 1, 'owned_archive_boundaries_changed')
    return found[0] if found else None


def archive_map_span(text):
    marker = _archive_marker(text)
    if marker is None:
        return None
    definitions = [block for block in blocks(text) if block['header'] in
                   (['upstream', ARCHIVE_PREFIX + '_backend'],)
                   or (len(block['header']) == 3 and block['header'][0] == 'map'
                       and block['header'][-1] in ('$' + ARCHIVE_PREFIX + '_upstream',
                                                  '$' + ARCHIVE_PREFIX + '_uri'))]
    definitions.sort(key=lambda block: block['start'])
    need(len(definitions) == 3 and definitions[0]['header'] == ['upstream', ARCHIVE_PREFIX + '_backend']
         and definitions[1]['header'][-1] == '$' + ARCHIVE_PREFIX + '_upstream'
         and definitions[2]['header'][-1] == '$' + ARCHIVE_PREFIX + '_uri'
         and len({block['depth'] for block in definitions}) == 1,
         'owned_archive_maps_contract_changed')
    position = marker.end()
    for block in definitions:
        need(block['start'] >= position and not text[position:block['start']].strip(),
             'owned_archive_maps_contract_changed')
        position = block['end']
    start = marker.start() - (1 if marker.start() and text[marker.start() - 1] == '\n' else 0)
    end = position + (1 if text[position:position + 1] == '\n' else 0)
    return start, end


def transform_archive_main(raw, *, owned_maps):
    text, expected = raw.decode('utf-8'), owned_maps.decode('utf-8')
    need(archive_map_span(expected) == (0, len(expected)), 'owned_archive_maps_recipe_changed')
    expected_blocks = blocks(expected)
    need(all(block['depth'] == 0 for block in expected_blocks)
         and len(expected_blocks) == 3, 'owned_archive_maps_recipe_changed')
    contexts = [block for block in blocks(text) if block['header'] == ['http']]
    need(len(contexts) == 1 and contexts[0]['depth'] == 0, 'native_http_context_not_unique')
    http = contexts[0]
    span = archive_map_span(text)
    if span:
        need(text[span[0]:span[1]].encode() == owned_maps, 'owned_archive_maps_contract_changed')
        definitions = [block for block in blocks(text)
                       if span[0] <= block['start'] and block['end'] <= span[1]]
        need(len(definitions) == 3 and all(block['depth'] == 1 for block in definitions)
             and http['bodyStart'] <= span[0] < span[1] <= http['bodyEnd'],
             'owned_archive_maps_context_changed')
        outside = text[:span[0]] + text[span[1]:]
    else:
        outside = text
    symbols = {ARCHIVE_PREFIX + '_upstream', ARCHIVE_PREFIX + '_uri',
               *re.findall(r'\(\?(?:P?<)([A-Za-z_][A-Za-z0-9_]*)>', expected)}
    _check_owned_symbols(outside, symbols, [ARCHIVE_PREFIX + '_backend'])
    if span:
        return raw
    return (text[:http['bodyStart']] + expected + text[http['bodyStart']:]).encode()


def archive_route_span(text):
    marker = _archive_marker(text)
    if marker is None:
        return None
    routes = [block for block in blocks(text) if block['header'] == ['location', '=', ARCHIVE_ROUTE]]
    need(len(routes) == 1 and routes[0]['start'] >= marker.end()
         and not text[marker.end():routes[0]['start']].strip(), 'owned_archive_route_contract_changed')
    start, end = marker.start(), routes[0]['end']
    for _ in range(2):
        if start and text[start - 1] == '\n':
            start -= 1
    if text[end:end + 1] == '\n':
        end += 1
    return start, end


def archive_route_fragment(text):
    parsed = blocks(text)
    native = [block for block in parsed if block['header'] == ['location', ARCHIVE_ROUTE]]
    need(len(native) == 1, 'native_archive_location_not_unique')
    for block in parsed:
        header = block['header']
        if not header or header[0] != 'location' or block is native[0]:
            continue
        if len(header) == 2:
            modifier, location = '', header[1]
        elif len(header) == 3 and header[1] in ('=', '^~', '~', '~*'):
            modifier, location = header[1:]
        else:
            raise ContractError('foreign_location_contract_changed')
        need(modifier not in ('~', '~*'), 'foreign_archive_route')
        if location[:1] in ('"', "'"):
            need(len(location) >= 2 and location[-1] == location[0], 'foreign_location_contract_changed')
            location = location[1:-1]
        location = re.sub(r'\\(.)', r'\1', location)
        need(location.startswith(('/', '@')), 'foreign_location_contract_changed')
        overlap = location == ARCHIVE_ROUTE if modifier == '=' else (
            ARCHIVE_ROUTE.startswith(location) and len(location) > len('/proxy/protect/'))
        need(not overlap, 'foreign_archive_route')
    body = text[native[0]['bodyStart']:native[0]['bodyEnd']]
    old = 'proxy_pass http://protect_mspWs_backend/playback/;'
    need(body.count(old) == 1, 'native_archive_proxy_not_unique')
    proxy = 'proxy_pass http://$' + ARCHIVE_PREFIX + '_upstream$' + ARCHIVE_PREFIX + '_uri;'
    changed = body.replace(old, proxy, 1)
    need(changed.replace(proxy, old, 1) == body, 'native_archive_auth_copy_changed')
    addition = '\n\n' + ARCHIVE_MARKER + '\nlocation = ' + ARCHIVE_ROUTE + ' {' + changed + '}\n'
    return addition.encode(), native[0]['end']


def transform_archive_shared(raw, *, owned_route):
    text = raw.decode('utf-8')
    span = archive_route_span(text)
    source = text[:span[0]] + text[span[1]:] if span else text
    addition, position = archive_route_fragment(source)
    if span:
        existing = text[span[0]:span[1]].encode()
        need(existing in (addition, owned_route), 'owned_archive_route_contract_changed')
        return (text[:span[0]] + addition.decode() + text[span[1]:]).encode()
    return (source[:position] + addition.decode() + source[position:]).encode()


def archive_recipe_fragments(main_snapshot, shared_native_snapshot, *, maps_sha256, route_sha256):
    """One-time extraction from caller-verified private historical snapshots."""
    text = main_snapshot.decode('utf-8')
    span = archive_map_span(text)
    need(span is not None, 'archive_recipe_source_missing')
    maps = text[span[0]:span[1]].encode()
    route, _ = archive_route_fragment(shared_native_snapshot.decode('utf-8'))
    need(digest(maps) == maps_sha256 and digest(route) == route_sha256,
         'archive_recipe_source_pin_changed')
    return {'nginxOwnedArchiveMaps': base64.b64encode(maps).decode('ascii'),
            'nginxOwnedArchiveRoute': base64.b64encode(route).decode('ascii')}


def transform_shared(raw, *, owned_block=None):
    text = raw.decode('utf-8')
    span = own_span(text)
    if span:
        source = text[:span[0]] + text[span[1]:]
    else:
        source = text
    parsed = blocks(source)
    candidates = [block for block in parsed if block['header'] == ['location', '/proxy/protect/']]
    need(len(candidates) == 1, 'native_api_location_not_unique')
    # Exact locations outrank prefix and regex locations. Copying only the
    # broad native API block must never bypass a more specific auth/deny rule.
    # PCRE routing cannot be proved with Python's different regex engine, so
    # an unfamiliar regex location leaves the native configuration untouched.
    for block in parsed:
        header = block['header']
        if not header or header[0] != 'location':
            continue
        if len(header) == 2:
            modifier, location = '', header[1]
        elif len(header) == 3 and header[1] in ('=', '^~', '~', '~*'):
            modifier, location = header[1:]
        else:
            raise ContractError('foreign_location_contract_changed')
        need(modifier not in ('~', '~*'), 'foreign_live_route')
        if location[:1] in ('"', "'"):
            need(len(location) >= 2 and location[-1] == location[0], 'foreign_location_contract_changed')
            location = location[1:-1]
        location = re.sub(r'\\(.)', r'\1', location)
        need(location.startswith(('/', '@')), 'foreign_location_contract_changed')
        overlap = location in ROUTES if modifier == '=' else any(
            route.startswith(location) and len(location) > len('/proxy/protect/') for route in ROUTES)
        need(not overlap, 'foreign_live_route')
    native = candidates[0]
    body = source[native['bodyStart']:native['bodyEnd']]
    matches = list(re.finditer(r'\bproxy_pass\s+http://protect_api_backend/\s*;', body))
    need(len(matches) == 1, 'native_api_proxy_not_unique')
    proxy = matches[0]
    clones = []
    for route, upstream in ROUTES.items():
        replacement = 'proxy_pass http://protect_api_backend' + upstream + '$is_args$codex_live_' + OPERATION + '_args;'
        changed = body[:proxy.start()] + replacement + body[proxy.end():]
        need(changed.replace(replacement, proxy.group(), 1) == body, 'native_auth_copy_changed')
        clones.append('    location = ' + route + ' {' + changed + '}\n')
    addition = '    ' + BEGIN + '\n' + '\n'.join(clones) + '    ' + END + '\n'
    # A currently owned block is replaced only in its original boundary. This
    # avoids adding whitespace on every natural vendor regeneration/check.
    if span:
        existing = text[span[0]:span[1]].encode('utf-8')
        need(existing == addition.encode('utf-8') or existing == owned_block, 'owned_routes_changed')
        candidate = text[:span[0]] + addition + text[span[1]:]
    else:
        candidate = source[:native['end']] + '\n' + addition + source[native['end']:]
    return candidate.encode('utf-8')


def atomic(path, data, meta, *, expected=None):
    fd, temporary = tempfile.mkstemp(prefix='.owned-route-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(meta.st_mode))
        os.chown(temporary, meta.st_uid, meta.st_gid)
        if expected is not None:
            fresh, _ = read_secure(path)
            need(fresh == expected, 'concurrent_main_change' if path == MAIN else 'concurrent_shared_change')
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(args):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=25, check=False).returncode == 0


def run(recipes_path, *, apply=False):
    raw, _ = read_secure(recipes_path, private=True)
    config = json.loads(raw)
    expected = fragment(config['nginxOwnedMap'])
    main, main_meta = read_secure(MAIN)
    main_candidate = transform_main(main, owned_map=expected)
    original, meta = read_secure(SHARED)
    owned_block = fragment(config['nginxOwnedRoutes'])
    candidate = transform_shared(original, owned_block=owned_block)
    archive_fields = ('nginxOwnedArchiveMaps', 'nginxOwnedArchiveRoute')
    configured = [key in config for key in archive_fields]
    need(all(configured) or not any(configured), 'archive_recipe_incomplete')
    if all(configured):
        main_candidate = transform_archive_main(main_candidate, owned_maps=fragment(config[archive_fields[0]]))
        candidate = transform_archive_shared(candidate, owned_route=fragment(config[archive_fields[1]]))
    plans = [(MAIN, main, main_candidate, main_meta), (SHARED, original, candidate, meta)]
    changes = [plan for plan in plans if plan[1] != plan[2]]
    if not changes:
        return {'ok': True, 'state': 'present', 'changed': False, 'protectRestarted': False,
                'archiveConfigured': all(configured)}
    if not apply:
        return {'ok': True, 'state': 'applicable', 'changed': False, 'protectRestarted': False,
                'archiveConfigured': all(configured)}
    for path, before, _, _ in plans:
        fresh, _ = read_secure(path)
        need(fresh == before, 'concurrent_main_change' if path == MAIN else 'concurrent_shared_change')
    written = []
    try:
        for path, before, after, metadata in changes:
            written.append((path, before, after, metadata))
            atomic(path, after, metadata, expected=before)
        need(command(['nginx', '-t']), 'nginx_syntax_failed')
        for path, _, after, _ in plans:
            fresh, _ = read_secure(path)
            need(fresh == after, 'concurrent_main_change' if path == MAIN else 'concurrent_shared_change')
        need(command(['nginx', '-s', 'reload']), 'nginx_reload_failed')
        for path, _, after, _ in plans:
            fresh, _ = read_secure(path)
            need(fresh == after, 'concurrent_main_change' if path == MAIN else 'concurrent_shared_change')
    except Exception:
        rollback_ok = True
        for path, before, after, metadata in reversed(written):
            try:
                fresh, _ = read_secure(path)
                if fresh == after:
                    atomic(path, before, metadata, expected=after)
                else:
                    rollback_ok = rollback_ok and fresh == before
            except Exception:
                rollback_ok = False
        for path, before, _, _ in plans:
            try:
                fresh, _ = read_secure(path)
                rollback_ok = rollback_ok and fresh == before
            except Exception:
                rollback_ok = False
        need(rollback_ok, 'nginx_rollback_conflict')
        need(command(['nginx', '-t']) and command(['nginx', '-s', 'reload']), 'nginx_rollback_failed')
        raise
    return {'ok': True, 'state': 'restored', 'changed': True, 'nginxReloaded': True,
            'protectRestarted': False, 'mainChanged': main != main_candidate,
            'sharedChanged': original != candidate, 'mainSha256': digest(main_candidate),
            'sharedSha256': digest(candidate), 'archiveConfigured': all(configured)}


def watch(recipes_path, *, apply=False, watch_seconds=0):
    """Wait briefly for native generated files without hiding missing recipes."""
    need(0 <= watch_seconds <= 90, 'invalid_watch_duration')
    deadline = time.monotonic() + (watch_seconds if apply else 0)
    passes, restorations = 0, 0
    while True:
        try:
            report = run(recipes_path, apply=apply)
        except FileNotFoundError as error:
            # Native Core creates these files asynchronously after Protect is
            # ready. A missing private recipe/helper or parent directory is a
            # different fault and must not be mislabeled as pending config.
            missing = Path(error.filename) if error.filename is not None else None
            if missing not in (MAIN, SHARED):
                raise
            report = {'ok': False, 'state': 'native_config_pending', 'changed': False,
                      'pendingTarget': 'main' if missing == MAIN else 'shared',
                      'healthBasis': 'functional_probes_required', 'protectRestarted': False}
        except ContractError as error:
            operation_failed = str(error) in ('nginx_syntax_failed', 'nginx_reload_failed',
                'concurrent_main_change', 'concurrent_shared_change', 'nginx_rollback_conflict',
                'nginx_rollback_failed')
            report = {'ok': not operation_failed,
                      'state': 'operation_failed' if operation_failed else 'contract_changed', 'changed': False,
                      'contractDetail': str(error), 'healthBasis': 'functional_probes_required',
                      'protectRestarted': False}
        passes += 1
        restorations += report.get('state') == 'restored'
        if time.monotonic() >= deadline or restorations >= 3:
            return dict(report, passes=passes, restorations=restorations)
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipes', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--watch-seconds', type=int, default=0)
    args = parser.parse_args()
    need(0 <= args.watch_seconds <= 90, 'invalid_watch_duration')
    # Serialize only this owned Nginx mutation, independently of Protect and its
    # native startup. Metadata incompatibility never stops the engine.
    if not args.check:
        import fcntl
        secure_path(ROOT, private=True, directory=True)
    fd = os.open(ROOT / 'nginx-contract.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600) if not args.check else None
    try:
        if fd is not None:
            meta = os.fstat(fd)
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                 and not meta.st_mode & 0o077, 'unsafe_lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(watch(args.recipes, apply=not args.check, watch_seconds=args.watch_seconds)))
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'ok': False, 'state': 'operation_failed', 'protectRestarted': False}))
    # Fail open for native Protect startup; real probes determine camera health.
