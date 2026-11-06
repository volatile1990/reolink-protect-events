"""Restore owned integration snippets when their actual contracts still match.

Protect version numbers and complete vendor-file digests are not compatibility
gates. Recipes contain exact, previously reviewed local transformations. They
live in a root-private file, separately from this public helper and from vendor
packages. Every replacement is unique, reversible and confined to its declared
target. An unfamiliar contract is left untouched without blocking Protect.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

APP = Path('/usr/share/unifi-protect/app')
SERVICE = APP / 'service.js'
UI = APP / 'node_modules/@ubnt/unifi-protect-ui-internal/dist'
MAX_FILE = 32 * 1024 * 1024
MAX_FRAGMENT = 256 * 1024
CAPABILITIES = frozenset(('controls_http', 'live_aac', 'automatic_input',
    'event_cleanup', 'alarm_scope', 'event_search', 'controls_ui'))
DEPENDENCIES = {
    'controls_http': frozenset(('/usr/local/lib/reolink-protect-controls/protect-hook.cjs',)),
    'live_aac': frozenset(('/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat.cjs',
                           '/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat-all.cjs')),
}


class ContractError(Exception):
    pass


def need(value, code):
    if not value:
        raise ContractError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secure_path(path, *, private=False, directory=False):
    """Retain the existing root ownership and no-symlink access boundary."""
    path = Path(path)
    for item in (path, *path.parents):
        if item.is_symlink():
            need(item == Path('/data') and item.resolve() == Path('/ssd1/.data'), 'unsafe_symlink')
        meta = item.stat()
        vendor_parent = (item in (Path('/usr'), Path('/usr/share'), Path('/etc'))
                         and stat.S_ISDIR(meta.st_mode) and meta.st_gid == 0
                         and stat.S_IMODE(meta.st_mode) == 0o775)
        need(meta.st_uid == 0 and (not meta.st_mode & 0o022 or vendor_parent), 'unsafe_permissions')
    meta = path.stat()
    need(stat.S_ISDIR(meta.st_mode) if directory else
         stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, 'unsafe_file_type')
    need(not private or not meta.st_mode & 0o077, 'private_permissions_required')
    return path


def read_secure(path, *, private=False):
    path = secure_path(path, private=private)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        meta = os.fstat(handle.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == 0
             and not meta.st_mode & 0o022 and meta.st_size <= MAX_FILE, 'unsafe_opened_file')
        data = handle.read(MAX_FILE + 1)
        need(len(data) <= MAX_FILE, 'file_size_limit')
    return data, meta


def fragment(value):
    try:
        result = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        raise ContractError('invalid_recipe_fragment') from None
    need(0 < len(result) <= MAX_FRAGMENT, 'invalid_recipe_fragment')
    return result


def recipes_from_json(value):
    need(isinstance(value, dict) and value.get('schema') == 1, 'invalid_recipe_schema')
    rows = value.get('recipes')
    need(isinstance(rows, list) and 0 < len(rows) <= 32, 'invalid_recipes')
    result = []
    seen = set()
    for row in rows:
        need(isinstance(row, dict) and set(row) <= {'id', 'capability', 'target', 'kind',
             'before', 'after', 'contexts'} and {'id', 'capability', 'target', 'kind', 'after'} <= set(row),
             'invalid_recipe')
        key = row.get('id')
        need(isinstance(key, str) and bool(re.fullmatch(r'[a-z0-9_-]{1,64}', key)) and key not in seen,
             'invalid_recipe_identity')
        seen.add(key)
        need(row.get('capability') in CAPABILITIES and row.get('target') in ('service', 'ui')
             and row.get('kind') in ('replace', 'prefix'), 'invalid_recipe_scope')
        kind = row['kind']
        before = fragment(row.get('before')) if kind == 'replace' else b''
        after = fragment(row['after'])
        need(before != after, 'empty_recipe_change')
        if kind == 'prefix':
            need(row['capability'] == 'controls_ui' and row['target'] == 'ui'
                 and after.startswith(b'/* reolink-protect-controls:v1 begin */\n'),
                 'invalid_owned_prefix')
        contexts = row.get('contexts', [])
        need(isinstance(contexts, list) and len(contexts) <= 16, 'invalid_recipe_contexts')
        result.append(dict(row, before=before, after=after,
                           contexts=[fragment(item) for item in contexts]))
    return result


def _transform_group(data, recipes):
    """Pure plan/apply; unrelated vendor changes do not affect compatibility."""
    need(isinstance(data, bytes) and 0 < len(data) <= MAX_FILE, 'invalid_vendor_file')
    candidate = data
    results = []
    for row in recipes:
        before, after = row['before'], row['after']
        context_valid = all(candidate.count(item) == 1 for item in row['contexts'])
        if row['kind'] == 'prefix':
            if candidate.startswith(after) and candidate.count(after) == 1:
                state = 'present'
            elif (candidate.count(after) == 0 and context_valid
                  and b'/* reolink-protect-controls:v1 begin */' not in candidate
                  and b'/* reolink-protect-controls:v1 end */' not in candidate):
                candidate = after + candidate
                state = 'applicable'
            else:
                state = 'contract_changed'
        elif candidate.count(after) == 1:
            # Check the inverse as well: an accidental duplicate stock anchor
            # must not be mistaken for an owned insertion.
            reversed_data = candidate.replace(after, before, 1)
            state = 'present' if reversed_data.count(before) == 1 and context_valid else 'contract_changed'
        elif candidate.count(after) == 0 and candidate.count(before) == 1 and context_valid:
            changed = candidate.replace(before, after, 1)
            need(changed.replace(after, before, 1) == candidate, 'recipe_not_reversible')
            candidate = changed
            state = 'applicable'
        else:
            state = 'contract_changed'
        results.append({'id': row['id'], 'capability': row['capability'], 'state': state})
    # Dependent snippets form one capability transaction. A missing resolver,
    # for example, must never leave callers of that resolver installed.
    if any(row['state'] == 'contract_changed' for row in results):
        for row in results:
            if row['state'] == 'applicable':
                row['state'] = 'not_applied'
        return data, results
    need(len(candidate) <= MAX_FILE, 'candidate_size_limit')
    return candidate, results


def transform(data, recipes):
    """Keep independent functions working when a different contract changes."""
    candidate, results = data, []
    groups = {}
    for row in recipes:
        groups.setdefault(row['capability'], []).append(row)
    for rows in groups.values():
        candidate, reports = _transform_group(candidate, rows)
        results.extend(reports)
    return candidate, results


def reverse_owned_group(data, recipes):
    """Remove only exact, unique owned callers of unavailable dependencies."""
    candidate = data
    for row in reversed(recipes):
        after, before = row['after'], row['before']
        occurrences = candidate.count(after)
        if not occurrences:
            continue
        need(occurrences == 1 and all(candidate.count(context) == 1 for context in row['contexts']),
             'dependency_owned_reversal_ambiguous')
        if row['kind'] == 'prefix':
            need(candidate.startswith(after), 'dependency_owned_reversal_ambiguous')
            candidate = candidate[len(after):]
        else:
            changed = candidate.replace(after, before, 1)
            need(changed.count(before) == 1, 'dependency_owned_reversal_ambiguous')
            candidate = changed
    return candidate


def transform_with_dependencies(data, recipes, assets):
    """Backup failure must not remove callers whose installed files are valid."""
    ready = set(assets.get('runtimeReady', []))
    unavailable = set(assets.get('runtimeUnavailable', []))
    candidate, results, groups = data, [], {}
    for row in recipes:
        groups.setdefault(row['capability'], []).append(row)
    for capability, rows in groups.items():
        required = set(DEPENDENCIES.get(capability, frozenset()))
        # A future recipe must register every external helper it introduces;
        # a matching JavaScript anchor alone is not proof of that dependency.
        for row in rows:
            references = re.findall(rb'require\(\s*[\'"](/usr/local/lib/[^\'"]+)[\'"]\s*\)', row['after'])
            for reference in references:
                dependency = reference.decode('utf-8')
                need(dependency in set().union(*DEPENDENCIES.values()), 'unregistered_dependency_reference')
                required.add(dependency)
        if required <= ready:
            candidate, reports = _transform_group(candidate, rows)
            results.extend(reports)
            continue
        missing = required & unavailable
        previous = candidate
        if missing:
            candidate = reverse_owned_group(candidate, rows)
        state = ('dependency_unavailable_removed' if candidate != previous else
                 'dependency_unavailable' if missing else 'dependency_not_verified')
        results.extend({'id': row['id'], 'capability': row['capability'], 'state': state}
                       for row in rows)
    return candidate, results


def targets():
    yield 'service', SERVICE
    for path in sorted(UI.glob('swai*.js')):
        if re.fullmatch(r'swai(?:-[A-Za-z0-9_.-]+)?\.js', path.name):
            yield 'ui', path


def replace_checked(path, old, new, meta, *, syntax_check=None):
    """Check the candidate before CAS replacement; never restart the engine."""
    syntax_check = syntax_check or ['/usr/bin/node24', '--check']
    fd, temporary = tempfile.mkstemp(prefix='.owned-contract-', suffix='.js', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(new)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(meta.st_mode))
        os.chown(temporary, meta.st_uid, meta.st_gid)
        result = subprocess.run(syntax_check + [temporary], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
        need(result.returncode == 0, 'candidate_syntax_failed')
        fresh, _ = read_secure(path)
        need(fresh == old, 'concurrent_vendor_change')
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _run(recipe_path, *, apply=False, assets_path=None, asset_prepare=None):
    raw, _ = read_secure(recipe_path, private=True)
    try:
        recipes = recipes_from_json(json.loads(raw))
    except (ValueError, UnicodeError):
        raise ContractError('invalid_recipe_json') from None
    if asset_prepare is None:
        from runtime_assets import prepare as asset_prepare
    assets_path = Path(assets_path) if assets_path is not None else Path(recipe_path).with_name('assets.json')
    need(assets_path.parent == Path(recipe_path).parent and assets_path.name == 'assets.json',
         'invalid_asset_manifest_location')
    assets = asset_prepare(assets_path, apply=apply)
    reports = []
    for kind, path in targets():
        selected = [row for row in recipes if row['target'] == kind]
        if not selected:
            continue
        try:
            old, meta = read_secure(path)
            candidate, rows = transform_with_dependencies(old, selected, assets)
            changed = apply and candidate != old
            if changed:
                replace_checked(path, old, candidate, meta)
            reports.append({'target': str(path), 'changed': changed,
                            'recipes': rows, 'candidateChanged': candidate != old})
        except Exception as error:
            reports.append({'target': str(path), 'changed': False,
                            'operationError': str(error) if isinstance(error, ContractError) else 'operation_failed'})
    # Contract metadata alone is not an operational camera failure. Callers
    # determine health from real API, stream, recording and event probes.
    return {'ok': assets.get('ok') is True and not any('operationError' in row for row in reports), 'schema': 1,
            'protectRestarted': False, 'files': reports,
            'assets': assets, 'healthBasis': 'functional_probes_required', 'recipeSha256': digest(raw)}


def run(recipe_path, *, apply=False, assets_path=None):
    if not apply:
        return _run(recipe_path, apply=False, assets_path=assets_path)
    import fcntl
    parent = secure_path(Path(recipe_path).parent, private=True, directory=True)
    fd = os.open(parent / 'runtime-contract.lock', os.O_RDWR | os.O_CREAT
                 | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
             and not meta.st_mode & 0o077, 'unsafe_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _run(recipe_path, apply=True, assets_path=assets_path)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipes', type=Path, required=True)
    parser.add_argument('--assets', type=Path, help='Pinned assets.json beside the recipes (default).')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        report = run(args.recipes, apply=not args.check, assets_path=args.assets)
    except Exception as error:
        report = {'ok': False, 'operationError': str(error) if isinstance(error, ContractError) else 'guard_failed',
                  'protectRestarted': False}
    print(json.dumps(report, sort_keys=True))
    # A compatibility helper must never prevent the native service starting.


if __name__ == '__main__':
    main()
