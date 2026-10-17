"""Private release installation on the Protect console; never replace its database."""
import ast
import base64
from contextlib import closing
import hashlib
import io
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess
import time
import uuid
import zipfile
from reolink_protect_events.http_deadline import get_bytes

root = pathlib.Path('/data/reolink-protect-events')
unit = pathlib.Path('/etc/systemd/system/reolink-protect-native-events.service')
service = unit.name
monitor_root = pathlib.Path('/data/reolink-protect-monitor')
monitor_unit = pathlib.Path('/etc/systemd/system/reolink-protect-media-monitor.service')


def run(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    if p.returncode:
        raise RuntimeError('system_command_failed')
    return p.stdout.strip()


def secure(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            if item != pathlib.Path('/data') or item.resolve() != pathlib.Path('/ssd1/.data'):
                raise RuntimeError('unsafe_symlink')
        if item.exists():
            s = item.stat()
            if s.st_uid != 0 or s.st_mode & 0o002 or (s.st_mode & 0o020 and s.st_gid != 0):
                raise RuntimeError('unsafe_owner_or_mode')


def write(path, data):
    secure(path)
    tmp = path.with_name(path.name + '.new-' + uuid.uuid4().hex)
    with tmp.open('xb') as f:
        os.chmod(tmp, 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def get_config():
    current = root / 'config.json'
    prior = current if current.exists() or current.is_symlink() else pathlib.Path('/data/reolink-bridge-events/config.json')
    secure(prior)
    if prior.stat().st_mode & 0o077:
        raise RuntimeError('source_config_not_private')
    cfg = json.loads(prior.read_text())
    headers = {'X-UserId': cfg['protectUserId'], 'X-UserRole': 'owner', 'X-UserPermissionMask': '64',
               'X-UserPermissions': '65535', 'X-Internal-Use': 'true', 'Content-Type': 'application/json'}
    status, data = get_bytes('https://127.0.0.1:7443/api/bootstrap', headers, timeout=10, limit=10000000)
    if status != 200:
        raise RuntimeError('bootstrap_http_rejected')
    boot = json.loads(data)
    version = boot.get('nvr', {}).get('version')
    if version != '7.3.70':
        raise RuntimeError('unsupported_protect_version')
    cams = {c['id']: c for c in boot['cameras']}
    if len(cfg['bridges']) != 6 or {b['host'] for b in cfg['bridges']} != {'192.168.30.' + str(i) for i in range(210, 216)}:
        raise RuntimeError('unexpected_bridge_scope')
    for b in cfg['bridges']:
        c = cams[b['cameraId']]
        if c['host'] != b['host']:
            raise RuntimeError('camera_mapping_changed')
        b['mac'] = c['mac']
    cfg['protectVersion'] = version
    if 'dsProxyPort' not in cfg:
        cfg['dsProxyPort'] = json.loads(pathlib.Path('/usr/share/unifi-protect/app/config/default.json').read_text())['ports']['dsProxy']
    if type(cfg['dsProxyPort']) is not int or not 1 <= cfg['dsProxyPort'] <= 65535:
        raise RuntimeError('invalid_ds_proxy_port')
    return cfg


def state_of(name):
    return {key: subprocess.run(['systemctl', verb, '--quiet', name], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=60).returncode == 0
            for key, verb in (('active', 'is-active'), ('enabled', 'is-enabled'))}


def health():
    value = json.loads((root / 'health.json').read_text())
    age = int(time.time() * 1000) - value.get('atMs', 0)
    value['healthAgeMs'] = max(0, age)
    value['fresh'] = -5000 <= age <= 30000
    value['healthy'] = value.get('healthy', False) and value['fresh']
    # Runtime health contains projected counters, never source credentials.
    return {'active': run(['systemctl', 'is-active', service]), 'enabled': run(['systemctl', 'is-enabled', service]),
            'health': value, 'configPrivate': ((root / 'config.json').stat().st_mode & 0o077) == 0,
            'monitor': state_of(monitor_unit.name)}


def backup_state(backup):
    state_path = backup / 'service-state.json'
    return json.loads(state_path.read_text()) if state_path.exists() else {
        'active': (backup / unit.name).exists(), 'enabled': (backup / unit.name).exists()}


def visual_groups_exist():
    journal = root / 'journal.sqlite3'
    if not journal.exists():
        return False
    secure(journal)
    with closing(sqlite3.connect('file:' + str(journal) + '?mode=ro', uri=True, timeout=10)) as database:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='visual_group_members'").fetchone():
            return False
        return database.execute('SELECT 1 FROM visual_group_members LIMIT 1').fetchone() is not None


def manual_visual_groups_exist():
    journal = root / 'journal.sqlite3'
    if not journal.exists():
        return False
    secure(journal)
    with closing(sqlite3.connect('file:' + str(journal) + '?mode=ro', uri=True, timeout=10)) as database:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='visual_group_manual'").fetchone():
            return False
        return database.execute('SELECT 1 FROM visual_group_manual LIMIT 1').fetchone() is not None


def manual_group_module(content):
    # Inspect an explicit module-level capability without executing release code.
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, TypeError):
        return False
    values = [node.value.value if isinstance(node.value, ast.Constant) else None
              for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'MANUAL_GROUP_SCHEMA_VERSION'
                      for target in node.targets)]
    return len(values) == 1 and type(values[0]) is int and values[0] == 1


def supports_visual_groups(deployed):
    # A version label alone does not prove the projection-capable runtime exists.
    release = pathlib.Path(deployed.get('release', ''))
    module = release / 'reolink_protect_events' / 'visual_groups.py'
    if deployed.get('visualGroupCompatible') is not True or release.parent != root / 'releases' or not module.is_file():
        return False
    secure(release)
    secure(module)
    manifest = release / 'reolink_protect_events' / 'release.json'
    secure(manifest)
    if not manifest.is_file():
        return False
    metadata = json.loads(manifest.read_text())
    expected = [entry for entry in metadata.get('members', [])
                if entry.get('path') == 'reolink_protect_events/visual_groups.py']
    return len(expected) == 1 and expected[0].get('sha256') == hashlib.sha256(module.read_bytes()).hexdigest()


def supports_manual_groups(deployed):
    if not supports_visual_groups(deployed):
        return False
    module = pathlib.Path(deployed['release']) / 'reolink_protect_events' / 'visual_groups.py'
    return manual_group_module(module.read_bytes())


def guard_rollback(backup):
    manual = manual_visual_groups_exist()
    if not manual and not visual_groups_exist():
        return
    previous = backup / 'deployment.json'
    target = json.loads(previous.read_text()) if previous.exists() else {}
    if manual and not supports_manual_groups(target):
        raise RuntimeError('legacy_manual_grouping_rollback_blocked')
    if not supports_visual_groups(target):
        raise RuntimeError('legacy_grouping_rollback_blocked')


def validate_packaged_config(release, cfg):
    program = ('import json,sys;sys.path.insert(0,sys.argv[1]);'
               'from reolink_protect_events.runtime import validate_config;'
               'validate_config(json.load(sys.stdin))')
    result = subprocess.run(['/usr/bin/python3', '-c', program, str(release)],
                            input=json.dumps(cfg), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('packaged_configuration_invalid')


def restore(backup):
    secure(backup)
    guard_rollback(backup)
    state = backup_state(backup)
    events_only = state.get('eventsOnly', False)
    states = {service: state}
    if not events_only:
        states[monitor_unit.name] = state.get('monitor', {'active': False, 'enabled': False})
    current_states = {name: state_of(name) for name in states}
    for name in states:
        path = unit if name == service else monitor_unit
        if path.exists() or current_states[name]['active']:
            run(['systemctl', 'stop', name])
    # Enrollment can race the first read while the current worker is running.
    # With that worker stopped, verify again before changing any owned files.
    try:
        guard_rollback(backup)
    except Exception:
        for name, current in current_states.items():
            if current['active']:
                run(['systemctl', 'start', name])
        raise
    for name, previous in states.items():
        if not previous['enabled']:
            subprocess.run(['systemctl', 'disable', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    paths = (unit, root / 'config.json', root / 'deployment.json')
    if not events_only:
        paths += (monitor_unit,)
    for p in paths:
        saved = backup / p.name
        if saved.exists():
            write(p, saved.read_bytes())
        elif p.exists():
            p.unlink()
    run(['systemctl', 'daemon-reload'])
    for name, previous in states.items():
        if previous['enabled'] and (backup / name).exists():
            run(['systemctl', 'enable', name])
        if previous['active'] and (backup / name).exists():
            run(['systemctl', 'start', name])
    # journal.sqlite remains current, including genuine events received during rollout.


def retain_compatible_runtime(backup, release, reason='legacy_grouping_rollback_blocked'):
    """Disable new enrollment when restoring an old binary would lose projection."""
    deployed_path = root / 'deployment.json'
    deployed = json.loads(deployed_path.read_text())
    if not supports_visual_groups(deployed) or deployed.get('release') != str(release):
        raise RuntimeError('compatible_recovery_runtime_missing')
    if manual_visual_groups_exist() and not supports_manual_groups(deployed):
        raise RuntimeError('compatible_manual_recovery_runtime_missing')
    state = backup_state(backup)
    previous_config = backup / 'config.json'
    secure(previous_config)
    cfg = json.loads(previous_config.read_text())
    current_cfg = json.loads((root / 'config.json').read_text())
    cfg['eventGrouping'] = {'enabled': False,
                            'maxSpanSeconds': current_cfg.get('eventGrouping', {}).get('maxSpanSeconds', 120)}
    validate_packaged_config(release, cfg)
    run(['systemctl', 'stop', service])
    write(root / 'config.json', json.dumps(cfg).encode())
    if not state.get('eventsOnly', False):
        prior_monitor = state.get('monitor', {'active': False, 'enabled': False})
        subprocess.run(['systemctl', 'stop', monitor_unit.name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60)
        saved = backup / monitor_unit.name
        if saved.exists():
            write(monitor_unit, saved.read_bytes())
        elif monitor_unit.exists():
            monitor_unit.unlink()
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable' if prior_monitor['enabled'] else 'disable', monitor_unit.name])
        if prior_monitor['active']:
            run(['systemctl', 'start', monitor_unit.name])
    deployed['groupEnrollmentDisabled'] = True
    deployed['recoveryReason'] = reason
    write(deployed_path, json.dumps(deployed).encode())
    restarted_at = int(time.time() * 1000)
    if state['active']:
        run(['systemctl', 'start', service])
    recovered = False
    deadline = time.monotonic() + 35
    while state['active'] and time.monotonic() < deadline:
        try:
            current = health()['health']
            if current.get('atMs', 0) > restarted_at and current.get('mode') == 'native' and current.get('healthy'):
                recovered = True
                break
        except (FileNotFoundError, ValueError, RuntimeError):
            pass
        time.sleep(1)
    return {'compatibleRuntimeRetained': True, 'groupEnrollmentDisabled': True,
            'journalPreserved': True, 'healthy': recovered}


def verified_members(data, digest):
    if len(data) > 16 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('package_digest_mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > 800 or len({i.filename for i in infos}) != len(infos):
            raise RuntimeError('package_inventory_invalid')
        total = 0
        for info in infos:
            name = info.filename
            parts = pathlib.PurePosixPath(name).parts
            if not name.startswith('reolink_protect_events/') or '..' in parts or '\\' in name or ':' in name or '\0' in name or info.is_dir() or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                raise RuntimeError('unsafe_package_member')
            total += info.file_size
            if total > 64 * 1024 * 1024 or info.file_size > 16 * 1024 * 1024:
                raise RuntimeError('package_budget_exceeded')
        manifest_info = z.getinfo('reolink_protect_events/release.json')
        if manifest_info.file_size > 512 * 1024:
            raise RuntimeError('package_manifest_invalid')
        meta = json.loads(z.read('reolink_protect_events/release.json'))
        if meta.get('schemaVersion') != 1 or meta.get('project') != 'reolink-protect-events':
            raise RuntimeError('package_manifest_invalid')
        rows = meta.get('members', [])
        expected = {r['path']: r for r in rows}
        if len(expected) != len(rows) or set(expected) | {'reolink_protect_events/release.json'} != {i.filename for i in infos}:
            raise RuntimeError('package_inventory_invalid')
        result = {}
        total = 0
        for info in infos:
            name = info.filename
            parts = pathlib.PurePosixPath(name).parts
            if not name.startswith('reolink_protect_events/') or '..' in parts or '\\' in name or ':' in name or '\0' in name or info.is_dir() or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                raise RuntimeError('unsafe_package_member')
            total += info.file_size
            if total > 64 * 1024 * 1024 or info.file_size > 16 * 1024 * 1024:
                raise RuntimeError('package_budget_exceeded')
            content = z.read(info)
            if name in expected:
                row = expected[name]
                if len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
                    raise RuntimeError('package_member_changed')
            result[name] = content
    required = {'reolink_protect_events/runtime.py', 'reolink_protect_events/operations/monitor.py',
                'reolink_protect_events/_vendor/integrity.json'}
    if not required <= set(result):
        raise RuntimeError('package_runtime_missing')
    return result, meta


def maintenance(owner, enable):
    if not isinstance(owner, str) or len(owner) != 32 or any(c not in '0123456789abcdef' for c in owner):
        raise RuntimeError('maintenance_owner_invalid')
    secure(monitor_root)
    monitor_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = monitor_root / 'maintenance.json'
    if marker.exists():
        secure(marker)
        current = json.loads(marker.read_text())
        if current.get('owner') != owner:
            raise RuntimeError('maintenance_owned_by_other_rollout')
        if not enable:
            marker.unlink()
    elif enable:
        write(marker, json.dumps({'schemaVersion': 1, 'owner': owner, 'atMs': int(time.time() * 1000)}).encode())
    return {'ok': True, 'maintenance': enable, 'owner': owner}


def unit_text(release, monitoring=False, capture=False):
    module = 'reolink_protect_events.operations.monitor' if monitoring else 'reolink_protect_events.runtime'
    target = monitor_root if monitoring else root
    suffix = ' --allow-repair' if monitoring else (' --capture-only' if capture else '')
    return ('[Unit]\nDescription=Reolink Protect ' + ('media monitor' if monitoring else 'native events') + '\n'
            'After=network-online.target unifi-protect.service\nWants=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n'
            '[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory=' + str(release) + '\n'
            'ExecStart=/usr/bin/python3 -m ' + module + ' --config ' + str(root / 'config.json') + ' --root ' + str(target) + suffix + '\n'
            'Restart=on-failure\nRestartSec=10\nUMask=0077\nProtectSystem=full\nProtectHome=true\nPrivateTmp=true\nTimeoutStopSec=45\n'
            '[Install]\nWantedBy=multi-user.target\n')


os.umask(0o077)


def execute(request):
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    secure(root)
    secure(unit)
    secure(monitor_unit)
    mode = request.get('mode')
    if mode == 'status':
        current = root / 'deployment.json'
        deployed = json.loads(current.read_text()) if current.exists() else {}
        return {'ok': True, 'deployment': {'sha256': deployed.get('sha256'), 'mode': deployed.get('mode')}, **health()}
    if mode == 'maintenance':
        return maintenance(request['owner'], request['enable'])
    if mode == 'rollback':
        meta = json.loads((root / 'deployment.json').read_text())
        if meta.get('sha256') != request.get('expectedDigest'):
            raise RuntimeError('rollback_deployment_drift')
        backup = pathlib.Path(meta['backup'])
        if backup.parent != root / 'backups' or not backup.is_dir():
            raise RuntimeError('unsafe_backup_path')
        restore(backup)
        return {'ok': True, 'restoredBackup': str(backup), 'journalPreserved': True}
    if mode not in ('install', 'capture'):
        raise RuntimeError('installer_mode_invalid')
    events_only = request.get('eventsOnly', False)
    if type(events_only) is not bool or events_only and mode != 'install':
        raise RuntimeError('events_only_mode_invalid')
    grouping = request.get('eventGrouping')
    if grouping is not None and (not events_only or not isinstance(grouping, dict)
            or set(grouping) != {'enabled', 'maxSpanSeconds'} or grouping.get('enabled') is not True
            or type(grouping.get('maxSpanSeconds')) is not int or not 30 <= grouping['maxSpanSeconds'] <= 300):
        raise RuntimeError('event_grouping_request_invalid')
    data = base64.b64decode(request['package'], validate=True)
    digest = request['digest']
    members, manifest = verified_members(data, digest)
    group_compatible = 'reolink_protect_events/visual_groups.py' in members
    if manual_visual_groups_exist() and not manual_group_module(members.get('reolink_protect_events/visual_groups.py', b'')):
        raise RuntimeError('manual_grouping_runtime_missing')
    if grouping is not None and not group_compatible:
        raise RuntimeError('event_grouping_runtime_missing')
    deployed = root / 'deployment.json'
    if deployed.exists():
        previous = json.loads(deployed.read_text())
        same_grouping = grouping is None or json.loads((root / 'config.json').read_text()).get('eventGrouping') == grouping
        if previous.get('sha256') == digest and previous.get('mode') == mode \
                and previous.get('eventsOnly', False) == events_only and same_grouping:
            h = health()
            if h['health']['healthy'] and (events_only or all(h['monitor'].values())):
                return {'ok': True, 'deployment': {k: previous[k] for k in ('sha256', 'mode', 'release', 'version', 'activatedAtMs')},
                        'resumedExistingDeployment': True, **h}
    cfg = get_config()
    original_files = {}
    if events_only:
        current_config = root / 'config.json'
        secure(current_config)
        if not current_config.exists() or cfg != json.loads(current_config.read_text()):
            raise RuntimeError('events_only_configuration_drift')
        for path in (unit, current_config, root / 'deployment.json'):
            secure(path)
            original_files[path] = path.read_bytes() if path.exists() else None
    else:
        cfg['thumbnailSelection'] = {'mode': 'automatic', 'maxCandidates': 4, 'windowSeconds': 6,
                                    'settleSeconds': 3, 'recordingLagMs': 1500, 'historyDays': 30, 'budgetSeconds': 8}
    if grouping is not None:
        cfg['eventGrouping'] = dict(grouping)
    secure(monitor_root)
    monitor_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = monitor_root / 'maintenance.json'
    if not marker.exists() or json.loads(marker.read_text()).get('owner') != request.get('owner'):
        raise RuntimeError('installer_requires_owned_maintenance')
    release = root / 'releases' / digest[:16]
    secure(release)
    release.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, content in members.items():
        p = release / name
        secure(p)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if p.exists() and p.read_bytes() != content:
            raise RuntimeError('existing_release_changed')
        if not p.exists():
            write(p, content)
    # Imports exercise the actual ARM64 native decoder before stopping the current service.
    run(['/usr/bin/python3', '-c', 'import sys;sys.path.insert(0,' + repr(str(release)) + ');from reolink_protect_events.vendor_support import ensure_pillow;ensure_pillow();from PIL import Image;Image.new("L",(8,8)).resize((4,4))'])
    run(['/usr/bin/python3', '-m', 'compileall', '-q', str(release)])
    validate_packaged_config(release, cfg)
    backup = root / 'backups' / (str(int(time.time())) + '-' + uuid.uuid4().hex[:12])
    backup.mkdir(parents=True, mode=0o700)
    state = state_of(service)
    state['monitor'] = state_of(monitor_unit.name)
    state['eventsOnly'] = events_only
    write(backup / 'service-state.json', json.dumps(state).encode())
    paths = (unit, root / 'config.json', root / 'deployment.json')
    if not events_only:
        paths += (monitor_unit,)
    for p in paths:
        if p.exists():
            secure(p)
            shutil.copy2(p, backup / p.name)
    journal = root / 'journal.sqlite3'
    if journal.exists():
        secure(journal)
        deadline = time.monotonic() + 25
        def progress(status, remaining, total):
            if time.monotonic() > deadline:
                raise RuntimeError('journal_backup_deadline')
        with closing(sqlite3.connect('file:' + str(journal) + '?mode=ro', uri=True, timeout=10)) as source:
            with closing(sqlite3.connect(str(backup / 'journal.sqlite3'))) as destination:
                source.backup(destination, pages=256, sleep=0.05, progress=progress)
        os.chmod(backup / 'journal.sqlite3', 0o600)
    if events_only and any((path.read_bytes() if path.exists() else None) != previous
                           for path, previous in original_files.items()):
        raise RuntimeError('events_only_deployment_drift')
    started = int(time.time() * 1000)
    try:
        services = (service,) if events_only else (service, monitor_unit.name)
        for name in services:
            path = unit if name == service else monitor_unit
            if path.exists() or (state if name == service else state['monitor'])['active']:
                run(['systemctl', 'stop', name])
        if not events_only or grouping is not None:
            write(root / 'config.json', json.dumps(cfg).encode())
        write(unit, unit_text(release, capture=mode == 'capture').encode())
        if not events_only:
            write(monitor_unit, unit_text(release, monitoring=True).encode())
        write(root / 'deployment.json', json.dumps({'sha256': digest, 'mode': mode, 'release': str(release),
              'backup': str(backup), 'sourceRevision': manifest['sourceRevision'], 'sourceSha256': manifest['sourceSha256'],
              'version': manifest['version'], 'activatedAtMs': started, 'eventsOnly': events_only,
              'visualGroupCompatible': group_compatible}).encode())
        run(['systemctl', 'daemon-reload'])
        for name in services:
            run(['systemctl', 'enable', name])
            run(['systemctl', 'start', name])
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            try:
                h = health()
                if h['health']['atMs'] > started and h['health']['mode'] == ('capture' if mode == 'capture' else 'native') \
                        and h['health']['healthy'] and (events_only or all(h['monitor'].values())):
                    return {'ok': True, 'deployment': {'sha256': digest, 'mode': mode, 'release': str(release),
                            'version': manifest['version'], 'activatedAtMs': started, 'eventsOnly': events_only,
                            'visualGroupCompatible': group_compatible}, 'journalBackedUp': journal.exists(), **h}
            except (FileNotFoundError, ValueError, RuntimeError):
                pass
            time.sleep(1)
        raise RuntimeError('deployment_health_timeout')
    except Exception:
        try:
            restore(backup)
        except RuntimeError as rollback_error:
            reason = str(rollback_error)
            if reason not in ('legacy_grouping_rollback_blocked', 'legacy_manual_grouping_rollback_blocked'):
                raise
            recovery = retain_compatible_runtime(backup, release, reason)
            return {'ok': False, 'errorCode': reason, 'recovery': recovery}
        raise
