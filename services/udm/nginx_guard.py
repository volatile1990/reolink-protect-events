"""Restore narrowly owned live routes by copying the current native auth block.

Only the integration's own query-map block is pinned. Protect's version, service
bundle, unrelated Nginx directives and complete configuration hashes are not
compatibility gates. No engine restart is performed.
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

from runtime_contracts import ContractError, digest, need, read_secure, secure_path

MAIN = Path('/etc/nginx/nginx.conf')
SHARED = Path('/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf')
ROOT = Path('/data/reolink-protect-controls/automatic-quality')
OPERATION = '2024de37468a4eac'
BEGIN = '# BEGIN Eingang native live-start ' + OPERATION
END = '# END Eingang native live-start ' + OPERATION
ROUTES = {'/proxy/protect/api/ws/livestream': '/api/ws/livestream',
          '/proxy/protect/api/tcp/livestream': '/api/tcp/livestream',
          '/proxy/protect/ws/livestream': '/ws/livestream'}


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
    for match in re.finditer(pattern, text):
        value = match.group()
        if value.isspace() or value.startswith('#'):
            continue
        if value == '{':
            stack.append((pending, match.end()))
            pending = []
        elif value == '}':
            need(bool(stack), 'invalid_config_structure')
            header, start = stack.pop()
            result.append({'header': header, 'bodyStart': start, 'bodyEnd': match.start(), 'end': match.end()})
            pending = []
        elif value == ';':
            pending = []
        else:
            pending.append(value)
    need(not stack, 'invalid_config_structure')
    return result


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


def atomic(path, data, meta):
    fd, temporary = tempfile.mkstemp(prefix='.owned-route-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(meta.st_mode))
        os.chown(temporary, meta.st_uid, meta.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(args):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=25, check=False).returncode == 0


def run(recipes_path, *, apply=False):
    raw, _ = read_secure(recipes_path, private=True)
    config = json.loads(raw)
    expected = base64.b64decode(config['nginxOwnedMap'], validate=True)
    main, _ = read_secure(MAIN)
    need(own_map(main.decode('utf-8')) == expected, 'owned_query_map_contract_changed')
    original, meta = read_secure(SHARED)
    owned_block = base64.b64decode(config['nginxOwnedRoutes'], validate=True)
    candidate = transform_shared(original, owned_block=owned_block)
    if original == candidate:
        return {'ok': True, 'state': 'present', 'changed': False, 'protectRestarted': False}
    if not apply:
        return {'ok': True, 'state': 'applicable', 'changed': False, 'protectRestarted': False}
    fresh, _ = read_secure(SHARED)
    need(fresh == original, 'concurrent_shared_change')
    # Recheck the narrow dependency immediately before mutation.
    main, _ = read_secure(MAIN)
    need(own_map(main.decode('utf-8')) == expected, 'owned_query_map_contract_changed')
    atomic(SHARED, candidate, meta)
    try:
        need(command(['nginx', '-t']), 'nginx_syntax_failed')
        fresh, _ = read_secure(SHARED)
        need(fresh == candidate, 'concurrent_shared_change')
        need(command(['nginx', '-s', 'reload']), 'nginx_reload_failed')
    except Exception:
        fresh, _ = read_secure(SHARED)
        if fresh == candidate:
            atomic(SHARED, original, meta)
            command(['nginx', '-t'])
            command(['nginx', '-s', 'reload'])
        raise
    return {'ok': True, 'state': 'restored', 'changed': True, 'nginxReloaded': True,
            'protectRestarted': False, 'sharedSha256': digest(candidate)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipes', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--watch-seconds', type=int, default=0)
    args = parser.parse_args()
    need(0 <= args.watch_seconds <= 90, 'invalid_watch_duration')
    deadline = time.monotonic() + (0 if args.check else args.watch_seconds)
    # Serialize only this owned Nginx mutation, independently of Protect and its
    # native startup. Metadata incompatibility never stops the engine.
    import fcntl
    if not args.check:
        secure_path(ROOT, private=True, directory=True)
    fd = os.open(ROOT / 'nginx-contract.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600) if not args.check else None
    try:
        if fd is not None:
            meta = os.fstat(fd)
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                 and not meta.st_mode & 0o077, 'unsafe_lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        passes, restorations = 0, 0
        while True:
            try:
                report = run(args.recipes, apply=not args.check)
            except ContractError as error:
                operation_failed = str(error) in ('nginx_syntax_failed', 'nginx_reload_failed', 'concurrent_shared_change')
                report = {'ok': not operation_failed,
                          'state': 'operation_failed' if operation_failed else 'contract_changed', 'changed': False,
                          'contractDetail': str(error), 'healthBasis': 'functional_probes_required',
                          'protectRestarted': False}
            passes += 1
            restorations += report.get('state') == 'restored'
            if time.monotonic() >= deadline or restorations >= 3:
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        print(json.dumps(dict(report, passes=passes, restorations=restorations)))
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'ok': False, 'state': 'operation_failed', 'protectRestarted': False}))
    # Fail open for native Protect startup; real probes determine camera health.
