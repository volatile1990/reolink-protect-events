#!/usr/bin/env python3
"""Check/stage/activate the public four-component release on the Heimserver."""
import argparse
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reolink_protect_events.operations.heimserver import (
    MAX_BUNDLE, ServerError, invoke, need, valid_digest, verified_bundle)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-alias', default='heimserver', choices=('heimserver',))
    commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('status', help='Read release identity and own unit states')
    check = commands.add_parser('check', help='Also verify the remote Protect version/schema and six-camera mapping')
    check.add_argument('--digest', help='Optionally check a staged release instead of current')
    stage = commands.add_parser('stage', help='Stage a reviewed ZIP containing release.json and public code only')
    stage.add_argument('--bundle', required=True, type=Path)
    stage.add_argument('--digest', required=True)
    activate = commands.add_parser('activate', help='Switch all four own components with compare-and-swap')
    activate.add_argument('--digest', required=True)
    activate.add_argument('--expected-current', required=True)
    rollback = commands.add_parser('rollback', help='Return to previousDigest without restoring private state')
    rollback.add_argument('--expected-current', required=True)
    return parser.parse_args(argv)


def request_for(args):
    request = {'mode': args.mode}
    value = getattr(args, 'digest', None)
    if value is not None:
        need(valid_digest(value), 'heimserver_digest_invalid')
        request['digest'] = value
    expected = getattr(args, 'expected_current', None)
    if expected is not None:
        need(valid_digest(expected), 'heimserver_digest_invalid')
        request['expectedCurrent'] = expected
    if args.mode == 'stage':
        need(not args.bundle.is_symlink() and args.bundle.is_file()
             and args.bundle.stat().st_size <= MAX_BUNDLE, 'heimserver_bundle_invalid')
        data = args.bundle.read_bytes()
        verified_bundle(data, args.digest)
        request['bundle'] = base64.b64encode(data).decode('ascii')
    return request


def main(argv=None):
    args = arguments(argv)
    try:
        request = request_for(args)
        result = invoke(request, host=args.ssh_alias)
    except Exception as error:
        result = {'ok': False, 'errorCode': error.code if isinstance(error, ServerError)
                  else 'heimserver_controller_failed'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
