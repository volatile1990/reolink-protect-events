"""Private paths, immutable scope and fixed diagnostic errors."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from ..remote import RemoteError, settings as remote_settings

HOSTS = frozenset('192.168.30.' + str(i) for i in range(210, 216))
VERSION = '7.3.70'


class OperationError(Exception):
    def __init__(self, code):
        if not isinstance(code, str) or not re.fullmatch(r'[a-z0-9_]{1,96}', code):
            code = 'operation_failed'
        self.code = code
        super().__init__(code)


def need(value, code):
    if not value:
        raise OperationError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def private_path(path, *, directory=False):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink():
            need(item == Path('/data') and item.resolve() == Path('/ssd1/.data'), 'private_path_symlink')
        if item.exists():
            info = item.stat()
            need(info.st_uid in ({os.geteuid()}if item==path else {0,os.geteuid()})
                 if hasattr(os, 'geteuid') else True, 'private_path_owner')
            trusted_sticky_parent=(item!=path and stat.S_ISDIR(info.st_mode)
                                   and info.st_uid==0 and bool(info.st_mode&stat.S_ISVTX))
            need(trusted_sticky_parent or not info.st_mode & 0o002 and not (info.st_mode & 0o020 and info.st_gid != 0)
                 if os.name != 'nt' else True, 'private_path_writable')
    if path.exists():
        info = path.stat()
        need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'private_path_type')
        need(info.st_mode & 0o077 == 0 if os.name != 'nt' else True, 'private_path_not_private')
    return path


def read_json(path, *, limit=1048576):
    path = private_path(path)
    with path.open('rb') as handle:
        value = handle.read(limit + 1)
    need(len(value) <= limit, 'private_json_size_limit')
    try:
        result = json.loads(value)
    except (ValueError, UnicodeError):
        raise OperationError('private_json_invalid') from None
    need(isinstance(result, dict), 'private_json_object_required')
    return result


def ensure_root(root):
    root = private_path(root, directory=True)
    if not root.exists():
        root.mkdir(mode=0o700, parents=False)
    return private_path(root, directory=True)


def write_json(path, value):
    path = Path(path)
    private_path(path)
    private_path(path.parent, directory=True)
    temporary = path.with_name(path.name + '.new')
    private_path(temporary)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(str(temporary), flags, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        if os.name != 'nt':
            os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle, sort_keys=True, separators=(',', ':'), allow_nan=False)
        handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
    os.replace(str(temporary), str(path))


def validate_config(config, *, require_credentials=True):
    need(type(require_credentials) is bool, 'monitor_credentials_mode_invalid')
    need(isinstance(config, dict), 'monitor_config_invalid')
    bridges = config.get('bridges')
    need(isinstance(bridges, list) and len(bridges) == 6, 'monitor_scope_invalid')
    need({row.get('host') for row in bridges if isinstance(row, dict)} == HOSTS, 'monitor_scope_invalid')
    ids = [row.get('cameraId') for row in bridges]
    need(len(set(ids)) == 6 and all(isinstance(i, str) and re.fullmatch(r'[a-f0-9]{24}', i) for i in ids),
         'monitor_camera_identity_invalid')
    if require_credentials:
        for row in bridges:
            user, password = row.get('username'), row.get('password')
            need(isinstance(user, str) and isinstance(password, str) and user and password and ':' not in user
                 and not any(c in user + password for c in '\r\n\0'), 'monitor_bridge_credentials_invalid')
    need(isinstance(config.get('protectUserId'), str) and bool(re.fullmatch(
        r'[A-Za-z0-9-]{1,80}', config['protectUserId'])), 'monitor_protect_identity_invalid')
    try:
        remote_settings(config)
    except RemoteError as error:
        raise OperationError(error.code) from None
    return config


def maintenance(root):
    path = Path(root) / 'maintenance.json'
    # Presence suppresses mutations even if an interrupted coordinator leaves a
    # stale or malformed marker. Removal belongs to the rollout coordinator.
    return path.exists() or path.is_symlink()


def maintenance_blocks(root, owner=None):
    """Default blocks every marker; an exact private lease can own one repair."""
    if owner is None:return maintenance(root)
    need(isinstance(owner,str)and re.fullmatch(r'[a-f0-9]{32}',owner),'maintenance_owner_invalid')
    path=Path(root)/'maintenance.json'
    if not path.exists()or path.is_symlink():return True
    try:value=read_json(path)
    except Exception:return True
    return value.get('owner')!=owner


def error_code(error, fallback='operation_failed'):
    return error.code if isinstance(error, (OperationError, RemoteError)) else fallback
