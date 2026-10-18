#!/usr/bin/env python3
"""Connect local pushes to main with the guarded own-repository release controller."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

MARKER = '# reolink-owned-release-hook-v1'


def hook_text(python, controller, config=None):
    command = ' '.join(shlex.quote(str(p).replace('\\', '/')) for p in (python, controller))
    command += ' update'
    if config is not None:
        command += ' --config ' + shlex.quote(str(config).replace('\\', '/'))
    return ('#!/bin/sh\n' + MARKER + '\ntrigger=0\n'
            'while read local_ref local_oid remote_ref remote_oid; do\n'
            '  if [ "$remote_ref" = refs/heads/main ] && [ "$local_oid" != 0000000000000000000000000000000000000000 ]; then\n'
            '    current=$(git rev-parse HEAD) || exit 1\n'
            '    if [ "$local_oid" != "$current" ]; then echo "Deploy requires the checked-out release commit." >&2; exit 1; fi\n'
            '    trigger=1\n  fi\ndone\n'
            'if [ "$trigger" = 1 ]; then\n  ' + command + '\n  exit $?\nfi\nexit 0\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='Existing private bridge/events path configuration; required for bridge scope')
    parser.add_argument('--scope', choices=('events', 'bridge', 'both'), default='events',
                        help='Events uses serverrelease; bridge keeps its guarded protect_ops controller')
    parser.add_argument('--python', default=sys.executable, type=Path)
    args = parser.parse_args(argv)
    if args.scope in ('bridge', 'both') and args.config is None:
        parser.error('--config is required for bridge scope')
    config = json.loads(args.config.read_text(encoding='utf-8')) if args.config is not None else {}
    root = Path(__file__).resolve().parents[1]
    scopes = ('events', 'bridge') if args.scope == 'both' else (args.scope,)
    targets = []
    for scope in scopes:
        repo = Path(config.get('eventsRepo', root) if scope == 'events' else config['bridgeRepo']).resolve()
        # Bind each checked-out commit to its own controller source. Bridge
        # orchestration remains supplied by the Events repository's protect_ops.
        events_repo = Path(config.get('eventsRepo', root)).resolve()
        controller = (repo / 'tools/serverrelease.py') if scope == 'events' else (events_repo / 'tools/protect_ops.py')
        if not controller.is_file() or controller.is_symlink():
            raise RuntimeError('hook_controller_missing')
        text = hook_text(args.python.resolve(), controller,
                         args.config.resolve() if scope == 'bridge' else None)
        value = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--git-path', 'hooks/pre-push'], text=True).strip()
        target = Path(value) if Path(value).is_absolute() else repo / value
        if target.is_symlink() or target.exists() and MARKER not in target.read_text(encoding='utf-8'):
            raise RuntimeError('existing_unowned_hook_preserved')
        targets.append((target, text))
    for target, text in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        os.chmod(target, 0o700)
    print(json.dumps({'ok': True, 'installed': len(targets), 'scope': args.scope,
                      'trigger': 'local-push-main', 'upstreamPolling': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': 'hook_installation_failed', 'errorType': type(error).__name__}))
        raise SystemExit(1)
