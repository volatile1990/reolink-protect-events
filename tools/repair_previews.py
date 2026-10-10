#!/usr/bin/env python3
"""Plan or repair owned event previews through a trusted console SSH alias.

The default is read-only. Apply copies existing images inside the database and
sends only event updates. Camera credentials, event IDs and images stay remote.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import base64,json,os,pathlib,re,sys,types
report={'ok':False,'mode':mode,'batchLimit':128,'maximumBatches':10,
 'candidateCount':0,'examinedCandidates':0,'repaired':0,'retiredSkipped':0,
 'updatesSent':0,'updateWarnings':0,'batches':0,'remainingCandidates':0,
 'remainingCountLimited':False,'sourceSha256':source_hashes}
def load(name,encoded):
 module=types.ModuleType(name);sys.modules[name]=module
 exec(compile(base64.b64decode(encoded),name+'.py','exec'),module.__dict__)
 return module
def candidates(adapter,bridges):
 rows=adapter.preview_repair_candidates(limit=128)
 if not isinstance(rows,list) or len(rows)>128:raise ValueError('candidate_shape')
 # Validate the entire batch before its first write.
 for row in rows:
  if not isinstance(row,dict) or row.get('cameraId') not in bridges:
   raise ValueError('candidate_camera_scope')
  if not re.fullmatch('[a-f0-9]{24}',row.get('eventId','')):
   raise ValueError('candidate_identity')
  if type(row.get('start')) is not int or row['start']<=0:
   raise ValueError('candidate_timestamp')
  if not isinstance(row.get('fullfovId'),str) or not row['fullfovId']:
   raise ValueError('candidate_fullfov')
 return rows
try:
 path=pathlib.Path('/data/reolink-protect-events/config.json')
 if os.geteuid()!=0 or path.is_symlink() or not path.is_file():
  raise RuntimeError('private_root_configuration_required')
 info=path.stat()
 if info.st_uid!=0 or info.st_mode&0o077 or info.st_size>256000:
  raise RuntimeError('private_root_configuration_required')
 config=json.loads(path.read_text())
 rows=config.get('bridges')
 if not isinstance(rows,list) or len(rows)!=6:raise ValueError('six_bridge_scope')
 bridges={};hosts=set()
 for row in rows:
  if not isinstance(row,dict) or not re.fullmatch('[a-f0-9]{24}',row.get('cameraId','')):
   raise ValueError('camera_configuration')
  camera=row['cameraId'];host=row.get('host');mac=row.get('mac')
  if camera in bridges or not isinstance(host,str) or host in hosts:
   raise ValueError('duplicate_camera_configuration')
  if not isinstance(mac,str) or not re.fullmatch('[a-fA-F0-9]{12}',re.sub('[:-]','',mac)):
   raise ValueError('camera_mac_configuration')
  bridges[camera]=row;hosts.add(host)
 port=config.get('dsProxyPort')
 if type(port) is not int or not 1<=port<=65535:raise ValueError('ds_port_configuration')
 native=load('preview_repair_native',native_source)
 updates=load('preview_repair_updates',updates_source)
 adapter=native.NativeAdapter(protect_version=config.get('protectVersion','7.3.70'))
 adapter.guard_schema()
 pending=candidates(adapter,bridges)
 report['candidateCount']=len(pending)
 if mode=='apply':
  for _ in range(10):
   if not pending:break
   repaired=0;report['batches']+=1
   for candidate in pending:
    report['examinedCandidates']+=1
    event=adapter.repair_preview_thumbnail(candidate)
    if event is None:
     report['retiredSkipped']+=1
     continue
    if not isinstance(event,dict) or event.get('id')!=candidate['eventId'] or event.get('camera')!=candidate['cameraId']:
     raise ValueError('repair_event_identity_mismatch')
    repaired+=1;report['repaired']+=1
    client=None
    try:
     client=updates.DsUpdateClient(bridges[candidate['cameraId']]['mac'],port=port)
     client.send_event('update',event)
     report['updatesSent']+=1
    except Exception:
     # The committed database repair remains valid; reopening the app reads it.
     report['updateWarnings']+=1
    finally:
     if client is not None:
      try:client.close()
      except Exception:pass
   if repaired==0:break
   pending=candidates(adapter,bridges)
  pending=candidates(adapter,bridges)
 report['remainingCandidates']=len(pending)
 report['remainingCountLimited']=len(pending)==128
 report['ok']=True
except Exception as error:
 report['errorType']=type(error).__name__
print(json.dumps(report))
raise SystemExit(0 if report['ok'] else 1)
'''


def remote_script(mode):
    sources = {name: (ROOT / 'reolink_protect_events' / (name + '.py')).read_bytes()
               for name in ('native', 'updates')}
    prefix = 'mode=' + repr(mode) + '\n'
    for name, source in sources.items():
        prefix += name + '_source=' + repr(base64.b64encode(source).decode('ascii')) + '\n'
    hashes = {name: hashlib.sha256(source).hexdigest() for name, source in sources.items()}
    return prefix + 'source_hashes=' + repr(hashes) + '\n' + REMOTE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'apply'), nargs='?', default='plan')
    parser.add_argument('--host', '--ssh-alias', default='unifi-dream-machine',
                        help='Trusted SSH alias from your existing SSH configuration')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.host):
        parser.error('Use an SSH alias, without command-line options or a user prefix')
    try:
        result = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o',
            'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10', args.host, 'python3 -'],
            input=remote_script(args.mode), encoding='utf-8', stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=1800 if args.mode == 'apply' else 60,
            shell=False)
        report = json.loads(result.stdout)
        if not isinstance(report, dict) or not isinstance(report.get('ok'), bool):
            raise ValueError('invalid_remote_report')
    except Exception as error:
        report = {'ok': False, 'mode': args.mode, 'errorType': type(error).__name__}
        result = None
    print(json.dumps(report))
    return 0 if result is not None and result.returncode == 0 and report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
