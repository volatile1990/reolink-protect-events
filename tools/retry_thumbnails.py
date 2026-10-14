#!/usr/bin/env python3
"""Review/reset thumbnail retry state for explicit journal event IDs over SSH."""
import argparse
import base64
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import base64,json,os,pathlib,sqlite3,sys,types
root=pathlib.Path('/data/reolink-protect-events')
def secure(path):
 for item in (path,*path.parents):
  if item.is_symlink() and not (item==pathlib.Path('/data') and item.resolve()==pathlib.Path('/ssd1/.data')):
   raise ValueError('unsafe_path')
  if item.exists():
   info=item.stat()
   if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('unsafe_owner_or_mode')
if os.geteuid()!=0:raise ValueError('root_required')
os.umask(0o077)
config=root/'config.json';database=root/'journal.sqlite3'
secure(config);secure(database)
if not config.is_file() or not database.is_file() or (config.stat().st_mode|database.stat().st_mode)&0o077:
 raise ValueError('private_existing_state_required')
cfg=json.loads(config.read_text())
allowed={row['cameraId'] for row in cfg['bridges']}
package=types.ModuleType('reolink_protect_events');package.__path__=[]
sys.modules[package.__name__]=package
for name in ('http_deadline','runtime'):
 module=types.ModuleType('reolink_protect_events.'+name);module.__package__='reolink_protect_events'
 sys.modules[module.__name__]=module
 exec(compile(base64.b64decode(sources[name]),name+'.py','exec'),module.__dict__)
from reolink_protect_events.runtime import Journal
db=sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True)
try:
 columns={row[1] for row in db.execute('PRAGMA table_info(media)')}
 reason='m.error_reason' if 'error_reason' in columns else 'NULL'
 rows=[]
 for identity in event_ids:
  row=db.execute('SELECT i.camera,i.delivered_revision,m.attempts,m.done,'+reason+' FROM intervals i JOIN media m ON m.event_id=i.id WHERE i.id=?',(identity,)).fetchone()
  if row is None or row[0] not in allowed or row[1]<=0:raise ValueError('delivered_event_scope_required')
  rows.append({'eventId':identity,'cameraId':row[0],'attempts':row[2],'done':bool(row[3]),'errorReason':row[4]})
finally:db.close()
changed=0
if mode=='apply':
 journal=Journal(database)
 try:changed=journal.retry_media(event_ids)
 finally:journal.db.close()
print(json.dumps({'ok':True,'mode':mode,'events':rows,'resetAttempts':changed,
  'nativeWrites':False,'deliveryStatePreserved':True,'retiredEventGuardPreserved':True}))
'''


def remote_script(mode, event_ids):
    sources = {name: base64.b64encode((ROOT / 'reolink_protect_events' / (name + '.py')).read_bytes()).decode('ascii')
               for name in ('http_deadline', 'runtime')}
    return ('mode=' + repr(mode) + '\nevent_ids=' + repr(event_ids) + '\nsources=' + repr(sources) + '\ntry:\n' +
            '\n'.join(' ' + line for line in REMOTE.splitlines()) +
            "\nexcept Exception as error:\n print(json.dumps({'ok':False,'errorType':type(error).__name__}));raise SystemExit(1)\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'apply'), nargs='?', default='plan')
    parser.add_argument('--event-id', action='append', required=True)
    parser.add_argument('--ssh-alias', default='unifi-dream-machine')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.ssh_alias):
        parser.error('Use an existing SSH alias')
    if any(not re.fullmatch(r'[a-f0-9]{24}', value) for value in args.event_id):
        parser.error('Event IDs must be 24 lowercase hex characters')
    result = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                             '-o', 'ConnectTimeout=10', args.ssh_alias, 'python3 -'],
                            input=remote_script(args.mode, sorted(set(args.event_id))), encoding='utf-8',
                            capture_output=True, timeout=45)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = {'ok': False, 'error': 'thumbnail_retry_failed'}
    print(json.dumps(report))
    return 0 if result.returncode == 0 and report.get('ok') is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
