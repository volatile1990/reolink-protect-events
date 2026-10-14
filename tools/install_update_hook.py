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


def hook_text(python, controller, config):
    command = ' '.join(shlex.quote(str(p).replace('\\', '/')) for p in (python, controller))
    command += ' update --config ' + shlex.quote(str(config).replace('\\', '/'))
    return ('#!/bin/sh\n' + MARKER + '\ntrigger=0\n'
            'while read local_ref local_oid remote_ref remote_oid; do\n'
            '  if [ "$remote_ref" = refs/heads/main ] && [ "$local_oid" != 0000000000000000000000000000000000000000 ]; then\n'
            '    current=$(git rev-parse HEAD) || exit 1\n'
            '    if [ "$local_oid" != "$current" ]; then echo "Deploy requires the checked-out release commit." >&2; exit 1; fi\n'
            '    trigger=1\n  fi\ndone\n'
            'if [ "$trigger" = 1 ]; then\n  ' + command + '\n  exit $?\nfi\nexit 0\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--python', default=sys.executable, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    controller = Path(__file__).resolve().with_name('protect_ops.py')
    text = hook_text(args.python.resolve(), controller, args.config.resolve())
    targets = []
    for key in ('bridgeRepo', 'eventsRepo'):
        repo = Path(config[key]).resolve()
        value = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--git-path', 'hooks/pre-push'], text=True).strip()
        target = Path(value) if Path(value).is_absolute() else repo / value
        if target.is_symlink() or target.exists() and MARKER not in target.read_text(encoding='utf-8'):
            raise RuntimeError('existing_unowned_hook_preserved')
        targets.append(target)
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        os.chmod(target, 0o700)
    print(json.dumps({'ok': True, 'installed': len(targets), 'trigger': 'local-push-main', 'upstreamPolling': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'errorCode': 'hook_installation_failed', 'errorType': type(error).__name__}))
        raise SystemExit(1)
