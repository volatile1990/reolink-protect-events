#!/usr/bin/env python3
"""Deploy an owned Events release; credentials remain on the Protect console."""
import argparse
import base64
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reolink_protect_events.operations import installer
from reolink_protect_events.operations.release import build_package
from reolink_protect_events.operations.transport import invoke

REMOTE = Path(installer.__file__).read_text(encoding='utf-8')


def package():
    return build_package(ROOT)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('capture', 'install', 'status', 'rollback'))
    parser.add_argument('--host', default='unifi-dream-machine')
    parser.add_argument('--dependency-cache', type=Path)
    parser.add_argument('--expected-digest', help='Required current deployment digest for rollback')
    parser.add_argument('--events-only', action='store_true',
                        help='Install only the Events service; preserve the media monitor and thumbnail settings')
    parser.add_argument('--update-monitor', action='store_true',
                        help='With --events-only, also upgrade its owned media-monitor unit; preserve thumbnail configuration')
    parser.add_argument('--fmp4-startup-config', type=Path,
                        help='Public explicit startup flags/nginx pins JSON; requires --update-monitor and current config digest')
    parser.add_argument('--expected-config-sha256')
    parser.add_argument('--expected-deployment-sha256', help='Current deployment.json file digest for an owned monitor upgrade')
    parser.add_argument('--group-visual-events', action='store_true',
                        help='Enable visual event grouping during an Events-only installation')
    parser.add_argument('--group-max-span-seconds', type=int, default=120)
    args = parser.parse_args()
    if args.events_only and args.mode != 'install':
        parser.error('--events-only requires install')
    if args.update_monitor and not args.events_only:
        parser.error('--update-monitor requires --events-only')
    if args.update_monitor and (not args.expected_config_sha256 or not args.expected_deployment_sha256):
        parser.error('--update-monitor requires current configuration and deployment file digests')
    if args.fmp4_startup_config and (not args.update_monitor or not args.expected_config_sha256):
        parser.error('--fmp4-startup-config requires --update-monitor and --expected-config-sha256')
    if args.group_visual_events and not args.events_only:
        parser.error('--group-visual-events requires --events-only')
    if not 30 <= args.group_max_span_seconds <= 300:
        parser.error('--group-max-span-seconds must be between 30 and 300')
    if args.group_max_span_seconds != 120 and not args.group_visual_events:
        parser.error('--group-max-span-seconds requires --group-visual-events')
    owner = uuid.uuid4().hex
    request = {'mode': args.mode}
    if args.mode == 'install':
        request['eventsOnly'] = args.events_only
        request['updateMonitor'] = args.update_monitor
        if args.update_monitor:
            request['expectedConfigSha256'] = args.expected_config_sha256
            request['expectedDeploymentSha256'] = args.expected_deployment_sha256
    if args.fmp4_startup_config:
        request['fmp4Startup'] = json.loads(args.fmp4_startup_config.read_text(encoding='utf-8'))
        request['expectedConfigSha256'] = args.expected_config_sha256
    if args.group_visual_events:
        request['eventGrouping'] = {'enabled': True, 'maxSpanSeconds': args.group_max_span_seconds}
    if args.mode == 'rollback':
        if not args.expected_digest:
            parser.error('Rollback requires the expected current deployment digest')
        request['expectedDigest'] = args.expected_digest
    if args.mode in ('install', 'capture'):
        data, manifest = build_package(ROOT, cache=args.dependency_cache, require_clean=True)
        request.update(package=base64.b64encode(data).decode(), digest=manifest['packageSha256'], owner=owner)
        if not invoke(ROOT, args.host, {'action': 'installer', 'request': {'mode': 'maintenance', 'owner': owner, 'enable': True}}).get('ok'):
            raise RuntimeError('maintenance_failed')
    value = None
    try:
        value = invoke(ROOT, args.host, {'action': 'installer', 'request': request}, timeout=300)
    except Exception as error:
        if not args.events_only:
            raise
        value = {'ok': False, 'errorCode': 'deployment_failed', 'errorType': type(error).__name__}
    finally:
        if args.mode in ('install', 'capture'):
            verified = value is not None and (value.get('ok') is True
                or value.get('recovery', {}).get('healthy') is True)
            if not args.events_only or verified:
                try:
                    released = invoke(ROOT, args.host, {'action': 'installer', 'request': {
                        'mode': 'maintenance', 'owner': owner, 'enable': False}})
                    if args.events_only and not released.get('ok'):
                        raise RuntimeError('maintenance_release_failed')
                except Exception:
                    if not args.events_only:
                        raise
                    value.update(ok=False, errorCode='maintenance_release_failed',
                                 maintenanceRetained=True, maintenanceOwner=owner)
            else:
                value.update(maintenanceRetained=True, maintenanceOwner=owner)
    print(json.dumps(value))
    return 0 if value.get('ok') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': 'deployment_failed', 'errorType': type(error).__name__}))
        raise SystemExit(1)
