"""Public-code releases for the dedicated server; private config/state stay put.

The entry point is shipped over pinned SSH stdin, never installed on the UDM.
There is no dependency installation, service-unit editing or database restore.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import time
import uuid
import zipfile


ROOT = Path('/srv/cameras/protect')
VERSION = '2.0.0'
ALIAS = 'heimserver'
UNITS = ('reolink-protect-events.service', 'reolink-protect-media-monitor.service',
         'reolink-protect-controls.service', 'reolink-protect-archive.service')
TUNNEL = 'reolink-protect-ssh.service'
TARGET = 'reolink-protect.target'
HEX = re.compile(r'[a-f0-9]{64}\Z')
MAX_BUNDLE = 32 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
REQUIRED = {'events/reolink_protect_events/__init__.py',
            'events/reolink_protect_events/runtime.py',
            'events/reolink_protect_events/native.py',
            'events/reolink_protect_events/remote.py',
            'events/reolink_protect_events/operations/monitor.py',
            'controls/worker.py', 'archive/proxy.cjs', 'archive/aac-clock.cjs'}


class ServerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise ServerError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def public_member(name):
    if name in {'controls/worker.py', 'archive/proxy.cjs', 'archive/aac-clock.cjs'}:
        return True
    if not isinstance(name, str) or '\\' in name:
        return False
    path = PurePosixPath(name)
    parts = path.parts
    return (not path.is_absolute() and len(parts) >= 3
            and parts[:2] == ('events', 'reolink_protect_events')
            and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', part) for part in parts[2:-1])
            and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.py', parts[-1]) is not None
            and '__pycache__' not in parts and '_vendor' not in parts)


def manifest_members(raw, expected):
    need(len(raw) <= 512 * 1024 and valid_digest(expected), 'heimserver_manifest_invalid')
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ServerError('heimserver_manifest_invalid') from None
    need(isinstance(manifest, dict) and type(manifest.get('schemaVersion')) is int
         and manifest['schemaVersion'] == 1
         and set(manifest) <= {'schemaVersion', 'digest', 'members', 'version'}
         and manifest.get('version', VERSION) == VERSION, 'heimserver_manifest_invalid')
    members = manifest.get('members')
    need(isinstance(members, list) and 8 <= len(members) <= 512, 'heimserver_manifest_invalid')
    names = set(); total = 0
    for row in members:
        need(isinstance(row, dict) and set(row) == {'path', 'sha256', 'bytes'}
             and isinstance(row['path'], str) and public_member(row['path'])
             and row['path'] not in names and valid_digest(row['sha256'])
             and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE,
             'heimserver_member_invalid')
        names.add(row['path']); total += row['bytes']
    need(total <= MAX_BUNDLE and REQUIRED <= names, 'heimserver_member_scope_invalid')
    need(digest(canonical(members)) == expected and manifest.get('digest') == expected,
         'heimserver_manifest_digest_mismatch')
    return manifest


def verified_bundle(data, expected):
    need(isinstance(data, bytes) and len(data) <= MAX_BUNDLE, 'heimserver_bundle_limit')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist(); names = [info.filename for info in infos]
            need(len(names) == len(set(names)) and len(names) <= 513
                 and 'release.json' in names, 'heimserver_bundle_members_invalid')
            info = archive.getinfo('release.json')
            need(info.file_size <= 512 * 1024, 'heimserver_manifest_invalid')
            raw = archive.read(info); manifest = manifest_members(raw, expected)
            expected_rows = {row['path']: row for row in manifest['members']}
            need(set(names) == set(expected_rows) | {'release.json'}, 'heimserver_bundle_extra_members')
            contents = {'release.json': raw}
            for info in infos:
                need(not info.is_dir() and not info.flag_bits & 1
                     and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG),
                     'heimserver_bundle_file_type')
                if info.filename == 'release.json':
                    continue
                row = expected_rows[info.filename]
                need(info.file_size == row['bytes'], 'heimserver_bundle_size_mismatch')
                content = archive.read(info)
                need(digest(content) == row['sha256'], 'heimserver_bundle_hash_mismatch')
                need(not re.search(br'-----BEGIN [A-Z ]*PRIVATE KEY-----', content),
                     'heimserver_private_key_forbidden')
                if info.filename.endswith('.py'):
                    try:
                        ast.parse(content, filename=info.filename)
                    except (ValueError, SyntaxError, UnicodeError):
                        raise ServerError('heimserver_python_syntax_invalid') from None
                contents[info.filename] = content
            return manifest, contents
    except (zipfile.BadZipFile, KeyError, OSError, RuntimeError):
        raise ServerError('heimserver_bundle_invalid') from None


def secure(path, *, private=False, regular=False):
    """Existing parents and the leaf must be root-owned and never symlinked."""
    path = Path(path)
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'heimserver_unsafe_path')
        if item == path:
            need(not private or not info.st_mode & 0o077, 'heimserver_private_path_required')
            need(not regular or stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                 'heimserver_regular_file_required')
    return path


def read_private(path, limit=1024 * 1024):
    secure(path, private=True, regular=True)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'heimserver_private_file_limit')
    return raw


def sync_directory(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path, data):
    secure(path)
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def release_path(value):
    need(valid_digest(value), 'heimserver_digest_invalid')
    return ROOT / 'releases' / value


def verify_tree(path, expected):
    secure(path); need(path.is_dir(), 'heimserver_release_missing')
    manifest_path = secure(path / 'release.json', regular=True)
    need(manifest_path.stat().st_size <= 512 * 1024, 'heimserver_manifest_invalid')
    raw = manifest_path.read_bytes(); manifest = manifest_members(raw, expected)
    rows = {row['path']: row for row in manifest['members']}
    actual = set()
    for parent, directories, files in os.walk(path, followlinks=False):
        for name in directories:
            secure(Path(parent) / name)
        for name in files:
            leaf = secure(Path(parent) / name, regular=True)
            relative = leaf.relative_to(path).as_posix(); actual.add(relative)
            if relative == 'release.json':
                continue
            need(relative in rows, 'heimserver_release_extra_file')
            row = rows[relative]
            need(leaf.stat().st_size == row['bytes'] and digest(leaf.read_bytes()) == row['sha256'],
                 'heimserver_release_changed')
    need(actual == set(rows) | {'release.json'}, 'heimserver_release_members_changed')
    return manifest, digest(raw)


def deployment():
    raw = read_private(ROOT / 'deployment.json')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ServerError('heimserver_deployment_invalid') from None
    need(isinstance(value, dict) and set(value) == {'schemaVersion', 'digest', 'releasePath',
         'version', 'previousDigest', 'activatedAtMs', 'manifestSha256'}
         and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1
         and valid_digest(value.get('digest')) and value.get('version') == VERSION
         and value.get('releasePath') == str(release_path(value['digest']))
         and (value.get('previousDigest') is None or valid_digest(value['previousDigest']))
         and type(value.get('activatedAtMs')) is int and value['activatedAtMs'] > 0
         and valid_digest(value.get('manifestSha256')), 'heimserver_deployment_invalid')
    current = ROOT / 'current'
    need(current.is_symlink() and os.readlink(current) == value['releasePath'],
         'heimserver_current_deployment_mismatch')
    return value, raw


def run(args, timeout=60):
    try:
        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=timeout, text=True)
    except (OSError, subprocess.TimeoutExpired):
        raise ServerError('heimserver_system_command_failed') from None
    need(process.returncode == 0, 'heimserver_system_command_failed')
    return process.stdout


def unit_states():
    result = {}
    for name in (*UNITS, TUNNEL, TARGET):
        text = run(['systemctl', 'show', name, '--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,NRestarts,ExecMainStatus'])
        fields = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        result[name] = {key: fields.get(key) for key in ('LoadState', 'ActiveState', 'SubState',
                            'UnitFileState', 'MainPID', 'NRestarts', 'ExecMainStatus')}
    return result


CHECK_CODE = r'''
import json,pathlib,sys
sys.dont_write_bytecode=True
try:
 sys.path.insert(0,sys.argv[1])
 from reolink_protect_events.remote import settings
 from reolink_protect_events.operations.safety import validate_config
 from reolink_protect_events.native import adapter_for_config
 from reolink_protect_events.operations.http import protect_json
 from reolink_protect_events.operations.protect import selected_cameras
 config=json.loads(pathlib.Path(sys.argv[2]).read_text())
 validate_config(config)
 remote=settings(config)
 if remote is None or remote['sshAlias']!='udm-protect':raise ValueError()
 schema=adapter_for_config(config).guard_schema()
 bootstrap=protect_json(config,'/api/bootstrap',timeout=8)
 cameras=selected_cameras(config,bootstrap)
 if schema.get('schemaVerified') is not True or bootstrap.get('nvr',{}).get('version')!='7.3.70' or len(cameras)!=6:raise ValueError()
 import PIL
 print(json.dumps({'ok':True,'remoteConfigured':True,'nativeSchemaVerified':True,'protectVersion':'7.3.70','cameraCount':6,'pillowVersion':PIL.__version__}))
except Exception:
 print(json.dumps({'ok':False,'errorCode':'heimserver_remote_contract_failed'}))
'''


def runtime_check(path):
    read_private(ROOT / 'config' / 'events.json')
    read_private(ROOT / 'config' / 'controls.json')
    output = run(['/usr/bin/python3', '-I', '-B', '-c', CHECK_CODE,
                  str(path / 'events'), str(ROOT / 'config' / 'events.json')], timeout=45)
    try:
        value = json.loads(output)
    except (ValueError, TypeError):
        raise ServerError('heimserver_remote_contract_failed') from None
    need(isinstance(value, dict) and value.get('ok') is True,
         'heimserver_remote_contract_failed')
    return {key: value[key] for key in ('remoteConfigured', 'nativeSchemaVerified',
            'protectVersion', 'cameraCount', 'pillowVersion')}


def status(*, check=False, candidate=None):
    deployed, _ = deployment()
    chosen = candidate if candidate is not None else deployed['digest']
    manifest, manifest_hash = verify_tree(release_path(chosen), chosen)
    if chosen == deployed['digest']:
        need(manifest_hash == deployed['manifestSha256'], 'heimserver_manifest_deployment_mismatch')
    units = unit_states()
    active = all(row['LoadState'] == 'loaded' and row['ActiveState'] == 'active' for row in units.values())
    result = {'ok': active, 'schemaVersion': 1, 'readOnly': True, 'deployment': deployed,
              'releaseVerified': True, 'memberCount': len(manifest['members']),
              'servicesActive': active, 'units': units,
              'privateConfigAndStateReplaced': False, 'mediaCycleVerified': False}
    if check:
        result['runtime'] = runtime_check(release_path(chosen))
    return result


def stage(data, expected):
    manifest, files = verified_bundle(data, expected)
    releases = secure(ROOT / 'releases')
    need(releases.is_dir(), 'heimserver_releases_root_missing')
    destination = release_path(expected)
    if destination.exists() or destination.is_symlink():
        _, found = verify_tree(destination, expected)
        need(found == digest(files['release.json']), 'heimserver_existing_manifest_changed')
        return {'ok': True, 'digest': expected, 'alreadyStaged': True, 'memberCount': len(manifest['members'])}
    temporary = releases / ('.stage-' + uuid.uuid4().hex)
    temporary.mkdir(mode=0o700)
    for name, content in files.items():
        path = temporary.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
    for name in ('archive/proxy.cjs', 'archive/aac-clock.cjs'):
        run(['/usr/bin/node', '--check', str(temporary / name)], timeout=20)
    verify_tree(temporary, expected)
    for parent, _dirs, _files in os.walk(temporary, topdown=False):
        sync_directory(parent)
    os.rename(temporary, destination); sync_directory(releases)
    return {'ok': True, 'digest': expected, 'alreadyStaged': False,
            'memberCount': len(manifest['members']), 'manifestSha256': digest(files['release.json'])}


def set_current(value):
    target = release_path(value)
    secure(target); need(target.is_dir(), 'heimserver_release_missing')
    temporary = ROOT / ('.current-' + uuid.uuid4().hex)
    os.symlink(str(target), temporary)
    os.replace(temporary, ROOT / 'current'); sync_directory(ROOT)


def config_fingerprints():
    return {name: digest(read_private(ROOT / 'config' / name)) for name in ('events.json', 'controls.json')}


def ready(after_ms, seconds=60):
    """Process and fresh events-health gate; a full monitor cycle is separate."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        units = unit_states()
        if all(row['LoadState'] == 'loaded' and row['ActiveState'] == 'active' for row in units.values()):
            try:
                value = json.loads(read_private(ROOT / 'state' / 'events' / 'health.json'))
                if value.get('mode') == 'native' and value.get('healthy') is True \
                        and type(value.get('atMs')) is int and value['atMs'] >= after_ms:
                    return units
            except (OSError, ValueError):
                pass
        time.sleep(1)
    raise ServerError('heimserver_activation_health_failed')


def switch(expected, target, *, rollback=False):
    need(valid_digest(expected) and valid_digest(target), 'heimserver_digest_invalid')
    prior, prior_raw = deployment()
    need(prior['digest'] == expected, 'heimserver_deployment_CAS_failed')
    if rollback:
        need(prior['previousDigest'] == target, 'heimserver_rollback_target_invalid')
    _, old_manifest = verify_tree(release_path(expected), expected)
    need(old_manifest == prior['manifestSha256'], 'heimserver_manifest_deployment_mismatch')
    _manifest, manifest_hash = verify_tree(release_path(target), target)
    baseline = config_fingerprints()
    runtime = runtime_check(release_path(target))
    need(all(row['LoadState'] == 'loaded' and row['ActiveState'] == 'active'
             for row in unit_states().values()), 'heimserver_services_not_active')
    if expected == target:
        return {'ok': True, 'unchanged': True, 'deployment': prior, 'runtime': runtime}
    began = int(time.time() * 1000)
    candidate = {'schemaVersion': 1, 'digest': target, 'releasePath': str(release_path(target)),
                 'version': VERSION, 'previousDigest': expected, 'activatedAtMs': began,
                 'manifestSha256': manifest_hash}
    candidate_raw = canonical(candidate)
    try:
        # Re-read immediately before switching; no private file is rewritten.
        observed, observed_raw = deployment()
        need(observed_raw == prior_raw and observed['digest'] == expected,
             'heimserver_deployment_CAS_failed')
        set_current(target)
        atomic_write(ROOT / 'deployment.json', candidate_raw)
        run(['systemctl', 'restart', *UNITS], timeout=90)
        units = ready(began)
        need(config_fingerprints() == baseline, 'heimserver_private_config_changed')
        after, after_raw = deployment()
        need(after_raw == candidate_raw, 'heimserver_deployment_CAS_failed')
        return {'ok': True, 'deployment': after, 'units': units, 'runtime': runtime,
                'privateConfigAndStateReplaced': False, 'privateConfigPreserved': True,
                'mediaCycleVerified': False,
                'rollback': rollback}
    except Exception as error:
        restored = False
        # A rename can commit before fsync reports failure. Inspect actual bytes,
        # rather than trusting a boolean assigned after the commit point.
        try:
            current = ROOT / 'current'
            raw = read_private(ROOT / 'deployment.json')
            ours = current.is_symlink() and os.readlink(current) == str(release_path(target)) \
                and raw in (prior_raw, candidate_raw)
            if ours:
                set_current(expected)
                atomic_write(ROOT / 'deployment.json', prior_raw)
                run(['systemctl', 'restart', *UNITS], timeout=90)
                ready(int(time.time() * 1000) - 1000)
                restored = True
        except Exception:
            restored = False
        try:
            configs_preserved = config_fingerprints() == baseline
        except Exception:
            configs_preserved = None
        return {'ok': False, 'errorCode': error.code if isinstance(error, ServerError)
                else 'heimserver_activation_failed', 'previousReleaseRestored': restored,
                'privateConfigAndStateReplaced': False, 'privateConfigPreserved': configs_preserved,
                'manualInspectionRequired': not restored or configs_preserved is not True}


@contextmanager
def mutation_lock():
    import fcntl
    path = secure(ROOT / 'deployment.lock', private=True, regular=True)
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and not info.st_mode & 0o077, 'heimserver_lock_invalid')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ServerError('heimserver_deployment_busy') from None
        yield
    finally:
        os.close(descriptor)


def execute(request):
    need(os.geteuid() == 0, 'heimserver_root_required')
    secure(ROOT); need(ROOT.is_dir(), 'heimserver_root_missing')
    need(isinstance(request, dict), 'heimserver_request_invalid')
    mode = request.get('mode')
    allowed = {'status': {'mode'}, 'check': {'mode', 'digest'},
               'stage': {'mode', 'digest', 'bundle'},
               'activate': {'mode', 'digest', 'expectedCurrent'},
               'rollback': {'mode', 'expectedCurrent'}}
    need(mode in allowed and set(request) <= allowed[mode], 'heimserver_request_invalid')
    if mode in ('status', 'check'):
        return status(check=mode == 'check', candidate=request.get('digest'))
    with mutation_lock():
        if mode == 'stage':
            encoded = request.get('bundle')
            need(isinstance(encoded, str) and len(encoded) <= MAX_BUNDLE * 4 // 3 + 8,
                 'heimserver_bundle_limit')
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                raise ServerError('heimserver_bundle_invalid') from None
            return stage(data, request.get('digest'))
        if mode == 'rollback':
            prior, _raw = deployment()
            return switch(request.get('expectedCurrent'), prior.get('previousDigest'), rollback=True)
        return switch(request.get('expectedCurrent'), request.get('digest'))


BOOTSTRAP = r'''
import json,sys
try:
 raw=sys.stdin.buffer.read(48*1024*1024+1)
 if len(raw)>48*1024*1024:raise ValueError()
 payload=json.loads(raw)
 scope={'__name__':'protect_server_deployment'}
 exec(compile(payload['source'],'<public-server-deployment>','exec'),scope)
 result=scope['execute'](payload['request'])
except Exception as error:
 result={'ok':False,'errorCode':getattr(error,'code','heimserver_operation_failed')}
print(json.dumps(result,separators=(',',':')))
'''


def invoke(request, *, host=ALIAS, timeout=600):
    need(host == ALIAS, 'heimserver_ssh_alias_required')
    payload = json.dumps({'source': Path(__file__).read_text(encoding='utf-8'), 'request': request})
    command = 'sudo -n python3 -B -c ' + shlex.quote(BOOTSTRAP)
    try:
        result = subprocess.run(['ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
                                 '-oConnectTimeout=10', host, command], input=payload,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout)
        need(result.returncode == 0 and len(result.stdout) <= 1024 * 1024,
             'heimserver_transport_failed')
        value = json.loads(result.stdout)
        need(isinstance(value, dict) and type(value.get('ok')) is bool, 'heimserver_transport_failed')
        return value
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise ServerError('heimserver_transport_failed') from None
