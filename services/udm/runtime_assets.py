"""Restore four pinned owned dependencies before installing their callers.

Only the root-private manifest and adjacent assets directory authorize bytes.
Unknown existing files are conflicts, never overwrite candidates. Native vendor
files and service processes are outside this helper's write allowlist.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

CONTROLS = '/usr/local/lib/reolink-protect-controls/'
HOOK = CONTROLS + 'protect-hook.cjs'
AAC = CONTROLS + 'ubv-aac-clock-compat.cjs'
AAC_ALL = CONTROLS + 'ubv-aac-clock-compat-all.cjs'
CONNECTOR = '/usr/local/lib/reolink-protect-connector.py'
TARGETS = frozenset((HOOK, AAC, AAC_ALL, CONNECTOR))
DEPENDENCIES = {'controls_http': frozenset((HOOK,)),
                'live_aac': frozenset((AAC, AAC_ALL))}
MAX_FILE = 4 * 1024 * 1024


class AssetError(Exception):
    pass


def need(value, code):
    if not value:
        raise AssetError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secure_metadata(meta, *, directory=False, private=False):
    need(stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode),
         'asset_unsafe_file_type')
    need(meta.st_uid == 0 and not meta.st_mode & 0o022, 'asset_unsafe_permissions')
    need(directory or meta.st_nlink == 1, 'asset_unsafe_links')
    need(not private or not meta.st_mode & 0o077, 'asset_private_permissions_required')


def secure_path(path, *, private=False, directory=False):
    path = Path(path)
    for item in reversed((path, *path.parents)):
        meta = item.lstat()
        if stat.S_ISLNK(meta.st_mode):
            need(item == Path('/data') and item.resolve() == Path('/ssd1/.data'),
                 'asset_unsafe_symlink')
            meta = item.stat()
        if item != path:
            # Root-owned sticky ancestors are safe for exclusive temp fixtures;
            # real production sources live under /data, targets under /usr.
            sticky = stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & stat.S_ISVTX
            vendor = item in (Path('/usr'), Path('/usr/local'), Path('/usr/local/lib')) and meta.st_uid == 0 and meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o775
            if sticky or vendor:
                continue
        secure_metadata(meta, directory=directory if item == path else True,
                        private=private if item == path else False)
    return path


def read_secure(path, *, private=False):
    path = secure_path(path, private=private)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        meta = os.fstat(handle.fileno())
        secure_metadata(meta, private=private)
        need(meta.st_size <= MAX_FILE, 'asset_file_size_limit')
        data = handle.read(MAX_FILE + 1)
        need(0 < len(data) <= MAX_FILE, 'asset_file_size_limit')
    return data, meta


def manifest_rows(value):
    need(isinstance(value, dict) and set(value) == {'schema', 'files'} and type(value['schema']) is int and value['schema'] == 1,
         'asset_invalid_manifest')
    need(isinstance(value['files'], list) and len(value['files']) == len(TARGETS),
         'asset_invalid_manifest')
    rows, seen = [], set()
    for row in value['files']:
        need(isinstance(row, dict) and set(row) == {'target', 'source', 'sha256', 'allowedBefore'},
             'asset_invalid_row')
        target = row['target']
        need(isinstance(target, str) and target in TARGETS and target not in seen,
             'asset_invalid_target')
        seen.add(target)
        need(row['source'] == Path(target).name, 'asset_invalid_source')
        need(isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'asset_invalid_hash')
        before = row['allowedBefore']
        need(isinstance(before, list) and len(before) <= 16
             and all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h) for h in before)
             and len(set(before)) == len(before),
             'asset_invalid_owned_hashes')
        rows.append(dict(row))
    need(seen == TARGETS, 'asset_incomplete_manifest')
    return rows


class FileOps:
    """All mutation is confined to TARGETS; map_target exists for isolated tests."""
    def __init__(self, source_dir, *, map_target=None, node=None):
        self.source_dir = Path(source_dir)
        self.map_target = map_target or (lambda value: Path(value))
        self.node = node or '/usr/bin/node24'

    def source(self, row):
        secure_path(self.source_dir, private=True, directory=True)
        return read_secure(self.source_dir / row['source'], private=True)[0]

    def existing(self, target):
        path = self.map_target(target)
        try:
            return read_secure(path)
        except FileNotFoundError:
            # A missing approved directory can be reconstructed; an ancestor
            # link or unsafe parent cannot masquerade as an absent leaf.
            current = path.parent
            while not current.exists() and not current.is_symlink():
                current = current.parent
            secure_path(current, directory=True)
            return None

    def syntax(self, row, data):
        if row['target'] == CONNECTOR:
            try:
                compile(data, row['source'], 'exec')
            except (SyntaxError, ValueError, UnicodeError):
                raise AssetError('asset_python_syntax_failed') from None
            return
        result = subprocess.run([self.node, '--input-type=commonjs', '--check'], input=data,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, check=False)
        need(result.returncode == 0, 'asset_javascript_syntax_failed')

    def replace(self, row, data, previous):
        target = row['target']
        need(target in TARGETS, 'asset_invalid_target')
        path = self.map_target(target)
        parent = path.parent
        if not parent.exists():
            # Only the controls directory itself may be created. /usr/local/lib
            # must already be a trusted directory supplied by the host.
            need(target.startswith(CONTROLS) and parent.name == 'reolink-protect-controls',
                 'asset_missing_parent')
            secure_path(parent.parent, directory=True)
            os.mkdir(parent, 0o755)
        secure_path(parent, directory=True)
        fd, name = tempfile.mkstemp(prefix='.owned-asset-', dir=parent)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), 0o644)
                os.fchown(handle.fileno(), 0, 0)
            fresh = self.existing(target)
            need((fresh is None) == (previous is None), 'asset_concurrent_target_change')
            if fresh is not None:
                old_data, old_meta = previous
                fresh_data, fresh_meta = fresh
                need(fresh_data == old_data and (fresh_meta.st_dev, fresh_meta.st_ino,
                     fresh_meta.st_mode, fresh_meta.st_uid, fresh_meta.st_gid) ==
                     (old_meta.st_dev, old_meta.st_ino, old_meta.st_mode, old_meta.st_uid, old_meta.st_gid),
                     'asset_concurrent_target_change')
            os.replace(name, path)
            directory = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            final = self.existing(target)
            need(final is not None and digest(final[0]) == row['sha256']
                 and stat.S_IMODE(final[1].st_mode) == 0o644, 'asset_final_verification_failed')
        finally:
            if os.path.exists(name):
                os.unlink(name)


def runtime_state(rows, ops):
    pins = {row['target']: row['sha256'] for row in rows or []}
    ready, unavailable, unverified = [], [], []
    for target in sorted(TARGETS):
        try:
            found = ops.existing(target)
            if found is None:
                unavailable.append(target)
            elif target not in pins:
                unverified.append(target)
            elif digest(found[0]) == pins[target] and stat.S_IMODE(found[1].st_mode) == 0o644:
                ready.append(target)
            else:
                unavailable.append(target)
        except Exception:
            unavailable.append(target)
    return {'runtimeReady': ready, 'runtimeUnavailable': unavailable,
            'runtimeUnverified': unverified}


def prepare(manifest_path, *, apply=False, ops=None):
    """Assess backup readiness separately from already validated runtime files."""
    manifest_path = Path(manifest_path)
    ops = ops or FileOps(manifest_path.parent / 'assets')
    rows, reports, errors, backup_ready = None, [], [], False
    try:
        secure_path(manifest_path.parent, private=True, directory=True)
        raw, _ = read_secure(manifest_path, private=True)
        try:
            rows = manifest_rows(json.loads(raw))
        except (ValueError, UnicodeError):
            raise AssetError('asset_invalid_manifest_json') from None
        sources, planned = [], []
        # Every source and existing target is validated before the first write.
        for row in rows:
            data = ops.source(row)
            need(digest(data) == row['sha256'], 'asset_source_hash_mismatch')
            ops.syntax(row, data)
            sources.append((row, data))
        backup_ready = True
        for row, data in sources:
            existing = ops.existing(row['target'])
            previous_hash = digest(existing[0]) if existing is not None else None
            need(previous_hash is None or previous_hash == row['sha256']
                 or previous_hash in row['allowedBefore'], 'asset_target_conflict')
            need(existing is None or stat.S_IMODE(existing[1].st_mode) == 0o644,
                 'asset_target_mode_conflict')
            planned.append((row, data, existing))
        for row, data, existing in planned:
            changed = existing is None or digest(existing[0]) != row['sha256']
            if apply and changed:
                ops.replace(row, data, existing)
            reports.append({'target': row['target'], 'state': 'restored' if apply and changed
                            else 'restore_required' if changed else 'present'})
    except Exception as error:
        errors.append(str(error) if isinstance(error, AssetError) else 'asset_operation_failed')
    state = runtime_state(rows, ops)
    return {'ok': not errors and len(state['runtimeReady']) == len(TARGETS),
            'backupReady': backup_ready, 'errors': errors, 'files': reports, **state}
