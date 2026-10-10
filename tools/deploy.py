#!/usr/bin/env python3
"""Deploy from a trusted SSH alias. Bridge credentials remain on the console."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]

REMOTE = r'''
import base64,hashlib,io,json,os,pathlib,shutil,ssl,stat,subprocess,time,urllib.request,zipfile
root=pathlib.Path('/data/reolink-protect-events')
unit=pathlib.Path('/etc/systemd/system/reolink-protect-native-events.service')
service=unit.name
def run(args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
 if p.returncode: raise RuntimeError('system_command_failed')
 return p.stdout.strip()
def secure(path):
 for item in (path,*path.parents):
  if item.is_symlink():
   if item!=pathlib.Path('/data') or item.resolve()!=pathlib.Path('/ssd1/.data'): raise RuntimeError('unsafe_symlink')
  if item.exists():
   s=item.stat()
   if s.st_uid!=0 or s.st_mode&0o002 or (s.st_mode&0o020 and s.st_gid!=0): raise RuntimeError('unsafe_owner_or_mode')
def write(path,data):
 tmp=path.with_name(path.name+'.new')
 with tmp.open('wb') as f: os.chmod(tmp,0o600);f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
def get_config():
 prior=pathlib.Path('/data/reolink-bridge-events/config.json')
 secure(prior)
 if prior.stat().st_mode&0o077: raise RuntimeError('source_config_not_private')
 cfg=json.loads(prior.read_text())
 headers={'X-UserId':cfg['protectUserId'],'X-UserRole':'owner','X-UserPermissionMask':'64',
          'X-UserPermissions':'65535','X-Internal-Use':'true','Content-Type':'application/json'}
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
 with op.open(urllib.request.Request('https://127.0.0.1:7443/api/bootstrap',headers=headers),timeout=10) as r: boot=json.load(r)
 version=boot.get('nvr',{}).get('version')
 if version!='7.3.70': raise RuntimeError('unsupported_protect_version')
 cams={c['id']:c for c in boot['cameras']}
 if {b['host'] for b in cfg['bridges']}!={'192.168.30.'+str(i) for i in range(210,216)}: raise RuntimeError('unexpected_bridge_scope')
 for b in cfg['bridges']:
  c=cams[b['cameraId']]
  if c['host']!=b['host']: raise RuntimeError('camera_mapping_changed')
  b['mac']=c['mac']
 cfg['protectVersion']=version
 cfg['dsProxyPort']=json.loads(pathlib.Path('/usr/share/unifi-protect/app/config/default.json').read_text())['ports']['dsProxy']
 return cfg
def health():
 value=json.loads((root/'health.json').read_text())
 return {'active':run(['systemctl','is-active',service]),'enabled':run(['systemctl','is-enabled',service]),
         'health':value,'configPrivate':((root/'config.json').stat().st_mode&0o077)==0}
def restore(backup):
 secure(backup)
 subprocess.run(['systemctl','stop',service],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
 state_path=backup/'service-state.json'
 state=json.loads(state_path.read_text()) if state_path.exists() else {'active':(backup/unit.name).exists(),'enabled':(backup/unit.name).exists()}
 if not state['enabled']:
  subprocess.run(['systemctl','disable',service],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
 for p in (unit,root/'config.json',root/'deployment.json'):
  saved=backup/p.name
  if saved.exists(): write(p,saved.read_bytes())
  elif p.exists(): p.unlink()
 run(['systemctl','daemon-reload'])
 if state['enabled'] and (backup/unit.name).exists(): run(['systemctl','enable',service])
 if state['active'] and (backup/unit.name).exists(): run(['systemctl','start',service])
os.umask(0o077)
if os.geteuid()!=0: raise RuntimeError('root_required')
secure(root);secure(unit)
if mode=='status': print(json.dumps(health()));raise SystemExit(0)
if mode=='rollback':
 meta=json.loads((root/'deployment.json').read_text());backup=pathlib.Path(meta['backup'])
 if backup.parent!=root/'backups' or not backup.is_dir(): raise RuntimeError('unsafe_backup_path')
 restore(backup);print(json.dumps({'ok':True,'restoredBackup':str(backup),'journalPreserved':True}));raise SystemExit(0)
archive=base64.b64decode(package)
if hashlib.sha256(archive).hexdigest()!=digest: raise RuntimeError('package_digest_mismatch')
cfg=get_config()
release=root/'releases'/digest[:16]
release.mkdir(parents=True,exist_ok=True,mode=0o700)
with zipfile.ZipFile(io.BytesIO(archive)) as z:
 for name in z.namelist():
  if not name.startswith('reolink_protect_events/') or '..' in pathlib.PurePosixPath(name).parts or not name.endswith('.py'): raise RuntimeError('unsafe_package_member')
  p=release/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);write(p,z.read(name))
run(['/usr/bin/python3','-m','compileall','-q',str(release)])
backup=root/'backups'/str(int(time.time()))
backup.mkdir(parents=True,mode=0o700)
state={key:subprocess.run(['systemctl',verb,'--quiet',service],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25).returncode==0 for key,verb in (('active','is-active'),('enabled','is-enabled'))}
write(backup/'service-state.json',json.dumps(state).encode())
for p in (unit,root/'config.json',root/'deployment.json'):
 if p.exists(): shutil.copy2(p,backup/p.name)
capture=' --capture-only' if mode=='capture' else ''
unit_text='[Unit]\nDescription=Reolink camera AI native Protect event importer\nAfter=network-online.target unifi-protect.service\nWants=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory='+str(release)+'\nExecStart=/usr/bin/python3 -m reolink_protect_events.runtime --config '+str(root/'config.json')+' --root '+str(root)+capture+'\nRestart=on-failure\nRestartSec=10\nUMask=0077\nProtectSystem=full\nProtectHome=true\nPrivateTmp=true\nTimeoutStopSec=20\n[Install]\nWantedBy=multi-user.target\n'
try:
 subprocess.run(['systemctl','stop',service],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
 write(root/'config.json',json.dumps(cfg).encode());write(unit,unit_text.encode())
 write(root/'deployment.json',json.dumps({'sha256':digest,'mode':mode,'release':str(release),'backup':str(backup)}).encode())
 run(['systemctl','daemon-reload']);run(['systemctl','enable',service]);run(['systemctl','start',service])
 deadline=time.time()+25
 while time.time()<deadline:
  try:
   h=health()
   if h['health']['atMs']>int((deadline-25)*1000) and h['health']['mode']==('capture' if mode=='capture' else 'native') and h['health']['healthy']:
    print(json.dumps({'ok':True,'deployment':{'sha256':digest,'mode':mode,'release':str(release)},**h}));raise SystemExit(0)
  except (FileNotFoundError,ValueError,RuntimeError): pass
  time.sleep(1)
except Exception:
 restore(backup)
 raise
restore(backup)
print(json.dumps({'ok':False,'error':'deployment_health_timeout','service':service,'previousDeploymentRestored':(backup/unit.name).exists()}));raise SystemExit(1)
'''


def package():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted((ROOT / "reolink_protect_events").glob("*.py")):
            archive.writestr(str(file.relative_to(ROOT)).replace("\\", "/"), file.read_bytes())
    return data.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("capture", "install", "status", "rollback"))
    parser.add_argument("--host", default="unifi-dream-machine")
    args = parser.parse_args()
    archive = package()
    code = "mode=" + repr(args.mode) + "\npackage=" + repr(base64.b64encode(archive).decode()) + "\ndigest=" + repr(hashlib.sha256(archive).hexdigest()) + "\n"
    code += "try:\n" + "\n".join(" " + line for line in REMOTE.splitlines())
    code += "\nexcept Exception as error:\n print(json.dumps({'ok':False,'errorType':type(error).__name__,'error':str(error) if isinstance(error,RuntimeError) else 'remote_deployment_failed'}));raise SystemExit(1)\n"
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes", args.host, "python3 -"],
                            input=code, text=True, capture_output=True, timeout=90)
    # Only the controlled projected JSON is printed. Never echo command/remote
    # exception details, which may include third-party credential responses.
    try:
        value = json.loads(result.stdout)
    except ValueError:
        value = {"ok": False, "error": "remote_deployment_failed", "exitCode": result.returncode}
    print(json.dumps(value))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
