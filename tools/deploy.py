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
    args = parser.parse_args()
    owner = uuid.uuid4().hex
    request = {'mode': args.mode}
    if args.mode == 'rollback':
        if not args.expected_digest:
            parser.error('Rollback requires the expected current deployment digest')
        request['expectedDigest'] = args.expected_digest
    if args.mode in ('install', 'capture'):
        data, manifest = build_package(ROOT, cache=args.dependency_cache, require_clean=True)
        request.update(package=base64.b64encode(data).decode(), digest=manifest['packageSha256'], owner=owner)
        if not invoke(ROOT, args.host, {'action': 'installer', 'request': {'mode': 'maintenance', 'owner': owner, 'enable': True}}).get('ok'):
            raise RuntimeError('maintenance_failed')
    try:
        value = invoke(ROOT, args.host, {'action': 'installer', 'request': request}, timeout=300)
    finally:
        if args.mode in ('install', 'capture'):
            invoke(ROOT, args.host, {'action': 'installer', 'request': {'mode': 'maintenance', 'owner': owner, 'enable': False}})
    print(json.dumps(value))
    return 0 if value.get('ok') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': 'deployment_failed', 'errorType': type(error).__name__}))
        raise SystemExit(1)
