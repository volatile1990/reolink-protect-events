#!/usr/bin/env python3
"""Review/apply camera feature gates over trusted SSH; restart is explicit.

No bridge credentials leave the console. The reviewed module sources are loaded
in memory, so `plan` has no deployment or filesystem side effects on the host.
"""

import argparse
import base64
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import base64,json,os,pathlib,ssl,stat,subprocess,sys,time,types,urllib.error,urllib.request
root=pathlib.Path('/data/reolink-protect-events')
def secure(path):
 for item in (path,*path.parents):
  if item.is_symlink() and not (item==pathlib.Path('/data') and item.resolve()==pathlib.Path('/ssd1/.data')):
   raise RuntimeError('unsafe_symlink')
  if item.exists():
   info=item.stat()
   if info.st_uid!=0 or info.st_mode&0o002 or (info.st_mode&0o020 and info.st_gid!=0):
    raise RuntimeError('unsafe_owner_or_mode')
def run(args,timeout=30):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
 if p.returncode: raise RuntimeError('system_command_failed')
 return p.stdout.strip()
if os.geteuid()!=0: raise RuntimeError('root_required')
os.umask(0o077)
package=types.ModuleType('reolink_protect_events');package.__path__=[]
sys.modules[package.__name__]=package
for name in ('native','features'):
 module=types.ModuleType('reolink_protect_events.'+name)
 module.__package__='reolink_protect_events'
 sys.modules[module.__name__]=module
 exec(compile(base64.b64decode(sources[name]),name+'.py','exec'),module.__dict__)
from reolink_protect_events.native import NativeAdapter
from reolink_protect_events.features import CameraFeatures,FeaturePatch,_atomic_write,sha256
cfg_path=root/'config.json'
if not cfg_path.exists(): cfg_path=pathlib.Path('/data/reolink-bridge-events/config.json')
secure(cfg_path)
if cfg_path.stat().st_mode&0o077: raise RuntimeError('configuration_not_private')
cfg=json.loads(cfg_path.read_text())
if {b['host'] for b in cfg['bridges']}!={'192.168.30.'+str(i) for i in range(210,216)}:
 raise RuntimeError('unexpected_bridge_scope')
ids=[bridge['cameraId'] for bridge in cfg['bridges']]
native=NativeAdapter();cameras=CameraFeatures(native);patch=FeaturePatch()
state_path=root/'features.json'
if not state_path.exists() and (root/'feature-deployment.json').exists():
 state_path=root/'feature-deployment.json'
secure(root);secure(state_path)
def checked_state():
 state=json.loads(state_path.read_text())
 if state.get('protectVersion')!='7.3.70' or sorted(state['cameraIds'])!=sorted(ids):
  raise RuntimeError('feature_deployment_scope_changed')
 for key in ('cameraManifest','uiManifest'):
  path=pathlib.Path(state[key]);secure(path)
  allowed=[(root/name).resolve() for name in ('feature-backups','camera-feature-backups','ui-feature-backups')]
  if not any(folder in path.resolve().parents for folder in allowed): raise RuntimeError('unsafe_feature_manifest')
 return state
def status(state):
 patch.guard_version()
 ui=json.loads(pathlib.Path(state['uiManifest']).read_text())
 for item in ui['files']:
  if sha256(pathlib.Path(item['path']).read_bytes())!=item['afterSha256']:
   raise RuntimeError('feature_ui_changed')
 manifest=json.loads(pathlib.Path(state['cameraManifest']).read_text())
 actual={row['id']:row for row in cameras._read(ids)}
 refresh=0
 for item in manifest['cameras']:
  changed=False
  for field in ('featureFlags','smartDetectZones'):
   value=item['configured'][field]
   current=actual[item['id']][field]
   if current!=value:
    if current!=item['original'][field]: raise RuntimeError('feature_camera_fields_changed')
    changed=True
  refresh+=int(changed)
 return {'ok':True,'state':'applied','protectVersion':'7.3.70','cameraIds':sorted(ids),
         'restartRequired':state.get('restartRequired',True) or refresh>0,'cameraFieldRefreshRequired':refresh,
         'cameraManifest':state['cameraManifest'],
         'uiManifest':state['uiManifest'],'managedFields':['featureFlags','smartDetectZones'],
         'nativeRecognitionSettingsPreserved':True,'userAgreementUnchanged':True}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args): raise RuntimeError('protect_api_redirect_rejected')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
 urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
def api(path):
 headers={'X-UserId':cfg['protectUserId'],'X-UserRole':'owner','X-UserPermissionMask':'64',
          'X-UserPermissions':'65535','X-Internal-Use':'true','Content-Type':'application/json'}
 request=urllib.request.Request('https://127.0.0.1:7443/api/'+path,headers=headers)
 try:
  with opener.open(request,timeout=8) as response:
   content=response.read(10000001)
   if len(content)>10000000: raise RuntimeError('protect_api_response_oversized')
   return json.loads(content)
 except urllib.error.HTTPError:
  raise RuntimeError('protect_api_request_rejected') from None
def refresh(state):
 # Read-only proof that the source event display gates are loaded. Native AI
 # objectTypes settings and user agreement are deliberately not changed.
 result=status(state)
 manifest=json.loads(pathlib.Path(state['cameraManifest']).read_text())
 wanted={item['id']:item for item in manifest['cameras']}
 bridges={item['cameraId']:item for item in cfg['bridges']}
 bootstrap=api('bootstrap')
 if bootstrap.get('nvr',{}).get('version')!='7.3.70': raise RuntimeError('protect_api_version_changed')
 actual={camera['id']:camera for camera in bootstrap['cameras']}
 for camera_id in ids:
  current=actual[camera_id];item=wanted[camera_id];flags=current['featureFlags']
  if current['host']!=bridges[camera_id]['host'] or not current['isThirdPartyCamera'] or current['isPairedWithAiPort']:
   raise RuntimeError('protect_api_camera_scope_changed')
  if not flags.get('hasSmartDetect') or flags['smartDetectTypes']!=item['configured']['featureFlags']['smartDetectTypes']:
   raise RuntimeError('protect_api_feature_flags_not_loaded')
  zones=current['smartDetectZones']
  if len(zones)!=1 or any(zones[0].get(k)!=v for k,v in item['configured']['smartDetectZones'][0].items()):
   raise RuntimeError('protect_api_camera_zones_changed')
 result.update(readOnly=True,apiVerifiedCameras=len(ids),restartRequired=False)
 return result
if mode=='plan':
 if state_path.exists():
  print(json.dumps(status(checked_state())));raise SystemExit(0)
 camera_plan=cameras.plan(ids)
 ui_plan=patch.plan(ids)
 print(json.dumps({'ok':True,'cameraPlan':cameras.public_plan(camera_plan),
                   'uiPlan':patch.public_plan(ui_plan),'backendPatchRequired':False}));raise SystemExit(0)
if mode=='status': print(json.dumps(status(checked_state())));raise SystemExit(0)
if mode=='refresh': print(json.dumps(refresh(checked_state())));raise SystemExit(0)
if mode=='apply':
 if state_path.exists():
  result=status(checked_state());result['alreadyConfigured']=True
  print(json.dumps(result));raise SystemExit(0)
 # Validate both operations before any mutation; package drift cannot leave
 # flags changed merely because the frontend gate is no longer recognizable.
 cameras.plan(ids);patch.plan(ids)
 backup=root/'feature-backups'
 secure(backup)
 configured=cameras.apply(ids,backup)
 try:
  ui_manifest=patch.apply(ids,backup)
 except Exception:
  cameras.rollback(configured['manifest'])
  raise
 state={'state':'applied','protectVersion':'7.3.70','cameraIds':sorted(ids),'cameraManifest':configured['manifest'],
        'uiManifest':ui_manifest,'restartRequired':True,'appliedAtMs':int(time.time()*1000)}
 _atomic_write(state_path,json.dumps(state,indent=2).encode(),0o600)
 print(json.dumps(status(state)));raise SystemExit(0)
if mode=='restart':
 state=checked_state();status(state)
 # PostgreSQL has PartOf=unifi-protect.service. Never run SQL between stopping
 # and starting Protect: the cluster is stopped with the application.
 # The ordinary restart loads persisted flags. Native recognition settings
 # stay untouched; the following refresh is read-only bootstrap verification.
 began=time.monotonic()
 run(['systemctl','restart','unifi-protect.service'],timeout=60)
 active=run(['systemctl','is-active','unifi-protect.service'])
 state['restartedAtMs']=int(time.time()*1000);state['restartRequired']=False
 _atomic_write(state_path,json.dumps(state,indent=2).encode(),0o600)
 result=refresh(state);result.update(protectActive=active,restartSeconds=round(time.monotonic()-began,2))
 print(json.dumps(result));raise SystemExit(0)
if mode=='rollback':
 state=checked_state()
 # Each operation checks ownership/hash/current values before restoring.
 # A subsequent Protect restart is deliberately a separate root decision.
 patch.rollback(state['uiManifest']);cameras.rollback(state['cameraManifest'])
 saved_folder=root/'feature-backups';secure(saved_folder);saved_folder.mkdir(mode=0o700,exist_ok=True)
 saved=saved_folder/('rolled-back-deployment-'+str(int(time.time()))+'.json')
 _atomic_write(saved,state_path.read_bytes(),0o600);state_path.unlink()
 print(json.dumps({'ok':True,'state':'rolled_back','restartRequired':True}));raise SystemExit(0)
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "apply", "status", "refresh", "restart", "rollback"))
    parser.add_argument("--host", default="unifi-dream-machine")
    args = parser.parse_args()
    sources = {name: base64.b64encode((ROOT / "reolink_protect_events" / (name + ".py")).read_bytes()).decode()
               for name in ("native", "features")}
    code = "mode=" + repr(args.mode) + "\nsources=" + repr(sources) + "\n"
    code += "try:\n" + "\n".join(" " + line for line in REMOTE.splitlines())
    safe_errors = ("unsafe_symlink", "unsafe_owner_or_mode", "system_command_failed", "root_required",
                   "configuration_not_private", "unexpected_bridge_scope", "feature_deployment_scope_changed",
                   "unsafe_feature_manifest", "feature_ui_changed", "feature_camera_fields_changed",
                   "protect_api_redirect_rejected", "protect_api_response_oversized", "protect_api_request_rejected",
                   "protect_api_version_changed", "protect_api_camera_scope_changed", "protect_api_feature_flags_not_loaded",
                   "protect_api_camera_zones_changed", "protect_api_camera_settings_changed", "protect_api_refresh_not_applied",
                   "protect_api_unrelated_fields_changed", "protect_api_refresh_verification_failed")
    code += "\nexcept Exception as error:\n print(json.dumps({'ok':False,'errorType':type(error).__name__,'error':str(error) if type(error).__name__ in ('FeatureError','NativeError','SchemaError') or str(error) in " + repr(safe_errors) + " else 'feature_operation_failed'}));raise SystemExit(1)\n"
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes", args.host, "python3 -"],
        input=code, text=True, encoding="utf-8", capture_output=True, timeout=90)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        value = {"ok": False, "error": "feature_operation_failed", "exitCode": result.returncode}
    print(json.dumps(value, ensure_ascii=False))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
