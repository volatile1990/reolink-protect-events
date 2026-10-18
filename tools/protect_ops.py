#!/usr/bin/env python3
"""Test and deploy one's own committed bridge/events code as a single release."""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reolink_protect_events.operations.orchestrator import Backend, Update, UpdateError, IPS, need, save
from reolink_protect_events.operations.locking import process_lock
from reolink_protect_events.operations.heimserver import valid_digest


def verify_installed_release(backend, state):
    """Read-only CAS for a completed installation, including a crash before commit."""
    architecture = getattr(backend, 'architecture', 'udm')
    need(state.get('architecture', 'udm') == architecture, 'receipt_architecture_changed')
    release = state.get('release', {})
    expected_image = release.get('imageId')
    final = state.get('evidence', {}).get('bridge-final-receipt', {})
    saved = final.get('bridges', [])
    need(final.get('ok') is True and isinstance(expected_image, str) and expected_image
         and len(saved) == len(IPS) and {row.get('ip') for row in saved} == set(IPS)
         and all(row.get('imageId') == expected_image for row in saved), 'installed_release_receipt_invalid')
    expected = {row['ip']: row['imageId'] for row in saved}
    inventory = backend.nas({'mode': 'inventory'})
    need(inventory.get('ok') is True, 'installed_bridge_inventory_failed')
    actual = inventory.get('bridges', [])
    need(len(actual) == len(IPS) and {row.get('ip') for row in actual} == set(IPS)
         and {row['ip']: row.get('imageId') for row in actual} == expected, 'installed_bridge_release_drift')
    if architecture == 'heimserver':
        observed = backend.server_release()
        need(observed.get('ok') is True and observed.get('releaseVerified') is True
             and observed.get('servicesActive') is True
             and observed.get('runtime', {}).get('nativeSchemaVerified') is True
             and valid_digest(observed.get('deployment', {}).get('digest'))
             and valid_digest(observed.get('deployment', {}).get('manifestSha256')),
             'installed_server_release_unhealthy')
        if state.get('status') != 'complete':
            pinned = state.get('evidence', {}).get('server-release-before', {}).get('deployment', {})
            need(pinned.get('digest') == observed.get('deployment', {}).get('digest')
                 and pinned.get('manifestSha256') == observed.get('deployment', {}).get('manifestSha256'),
                 'server_release_changed_during_bridge_update')
        return
    digest = state.get('frozen', {}).get('eventsManifest', {}).get('packageSha256')
    installed = state.get('evidence', {}).get('install-events', {}).get('deployment', {})
    need(isinstance(digest, str) and digest and installed.get('sha256') == digest,
         'installed_release_receipt_invalid')
    observed = backend.udm({'action': 'installer', 'request': {'mode': 'status'}})
    need(observed.get('ok') is True, 'installed_events_inventory_failed')
    need(observed.get('deployment', {}).get('sha256') == digest, 'installed_events_release_drift')
    need(observed.get('health', {}).get('healthy') is True and observed.get('active') == 'active'
         and observed.get('enabled') == 'enabled' and observed.get('monitor', {}).get('active') is True
         and observed.get('monitor', {}).get('enabled') is True, 'installed_events_release_unhealthy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('update', 'resume', 'assess', 'status'))
    parser.add_argument('--config', required=True, type=Path, help='Local paths/SSH alias only; no passwords or tokens')
    parser.add_argument('--run', type=Path, help='Exact receipt directory to resume')
    args = parser.parse_args()
    need(not args.config.is_symlink(), 'controller_config_invalid')
    config = json.loads(args.config.read_text(encoding='utf-8'))
    allowed = {'bridgeRepo', 'eventsRepo', 'connector', 'sshAlias', 'ffmpeg', 'ffprobe', 'dependencyCache',
               'stateDirectory', 'bridgeSettings', 'architecture', 'protectSshAlias', 'serverSshAlias'}
    need(set(config) <= allowed and {'bridgeRepo', 'eventsRepo', 'connector', 'stateDirectory'} <= set(config), 'controller_config_invalid')
    architecture = config.get('architecture', 'udm')
    need(architecture in ('udm', 'heimserver'), 'controller_architecture_invalid')
    need('sshAlias' not in config or 'protectSshAlias' not in config
         or config['sshAlias'] == config['protectSshAlias'], 'controller_protect_alias_conflict')
    backend = Backend(config['bridgeRepo'], config['eventsRepo'], config['connector'],
                      host=config.get('protectSshAlias', config.get('sshAlias', 'unifi-dream-machine')),
                      ffmpeg=config.get('ffmpeg'), ffprobe=config.get('ffprobe'), dependency_cache=config.get('dependencyCache'),
                      bridge_settings=config.get('bridgeSettings'), architecture=architecture,
                      server_host=config.get('serverSshAlias', 'heimserver'))
    if args.mode in ('assess', 'status'):
        result = backend.udm({'action': 'compatibility' if args.mode == 'assess' else 'monitor-status'})
        if architecture == 'heimserver':
            server = backend.server_release()
            result = {'ok': result.get('ok') is True and server.get('ok') is True,
                      'architecture': architecture, 'scope': 'bridge-only',
                      'serverRelease': server, 'compatibility' if args.mode == 'assess' else 'monitor': result}
        print(json.dumps(result))
        return 0 if result.get('ok') else 1
    directory = Path(config['stateDirectory']).resolve()
    need(not directory.is_symlink(), 'state_directory_invalid')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = directory / 'active-controller.lock'
    lease = process_lock(lock)
    lease.__enter__()
    try:
        latest = directory / 'latest.json'
        current = backend.current_sources()
        resume = args.mode == 'resume'
        run = args.run
        if args.mode == 'update' and latest.exists():
            prior = json.loads(latest.read_text())
            path = directory / prior['run']
            need(path.parent == directory and len(prior['run']) == 32, 'latest_receipt_invalid')
            previous = json.loads((path / 'update.json').read_text())
            projects = ('bridge',) if architecture == 'heimserver' else ('bridge', 'events')
            same = previous.get('architecture', 'udm') == architecture and all(
                previous.get('frozen', {}).get('sources', {}).get(project, {}).get('sourceSha256') == current[project]['sourceSha256']
                for project in projects)
            if previous['status'] == 'complete' and same:
                verify_installed_release(backend, previous)
                result = backend.udm({'action': 'health', 'mode': 'quick'})
                need(result.get('ok') is True, 'already_deployed_release_unhealthy')
                print(json.dumps({'ok': True, 'status': 'already-deployed', 'receipt': str(path / 'update.json')}))
                return 0
            if previous['status'] == 'running' or (previous['status'] == 'failed'
                    and (previous.get('maintenanceIntent') or previous.get('maintenanceActive'))):
                run, resume = path, True
        if resume:
            need(run is not None and run.resolve().parent == directory, 'resume_run_required')
        else:
            run = directory / uuid.uuid4().hex
        updater = Update(backend, run, resume=resume)
        finished = 'bridge-final-receipt' if architecture == 'heimserver' else 'install-events'
        if resume and updater.state['status'] == 'running' and finished in updater.state['completed']:
            verify_installed_release(backend, updater.state)
            need(backend.udm({'action': 'health', 'mode': 'quick'}).get('ok') is True,
                 'resumed_installed_release_unhealthy')
        save(latest, {'run': run.name})
        result = updater.run()
        print(json.dumps(result))
        return 0 if result.get('ok') else 1
    finally:
        lease.__exit__(None, None, None)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': str(error) if isinstance(error, UpdateError) else 'release_controller_failed',
                          'errorType': type(error).__name__}))
        raise SystemExit(1)
