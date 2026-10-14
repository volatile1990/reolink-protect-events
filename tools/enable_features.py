#!/usr/bin/env python3
"""Review/apply camera feature gates over trusted SSH; restart is explicit.

No bridge credentials leave the console. The reviewed module sources are loaded
in memory, so `plan` has no deployment or filesystem side effects on the host.
"""

import argparse
import base64
import json
import re
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
REMOTE = r'''
import base64,json,os,pathlib,re,ssl,stat,subprocess,sys,time,types,urllib.error,urllib.request
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
for name in ('http_deadline','native','features','control_ui_layer','controls_ui_guard','feature_rollback'):
 module=types.ModuleType('reolink_protect_events.'+name)
 module.__package__='reolink_protect_events'
 sys.modules[module.__name__]=module
 exec(compile(base64.b64decode(sources[name]),name+'.py','exec'),module.__dict__)
from reolink_protect_events.native import NativeAdapter
from reolink_protect_events.features import CameraFeatures,FeaturePatch,_atomic_write,sha256
from reolink_protect_events.control_ui_layer import verified_controls_layer,rollback_dependency,user_modified_zone_fields
from reolink_protect_events.feature_rollback import resume_rollback,recover_legacy_state
from reolink_protect_events.http_deadline import get_bytes
from reolink_protect_events import controls_ui_guard as controls_patch
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
 return recover_legacy_state(state,json.loads(pathlib.Path(state['uiManifest']).read_text()))
def ui_status(state):
 patch.guard_version()
 ui=json.loads(pathlib.Path(state['uiManifest']).read_text())
 if ui.get('schemaVersion')!=1 or ui.get('protectVersion')!='7.3.70' or ui.get('state')!='applied' or sorted(ui.get('cameraIds',[]))!=sorted(ids):
  raise RuntimeError('feature_ui_manifest_changed')
 allowed={str(p) for p in patch.ui_paths+[patch.service_path]}
 if not isinstance(ui.get('files'),list) or not ui['files'] or len({item.get('path')for item in ui['files']})!=len(ui['files']):
  raise RuntimeError('feature_ui_manifest_changed')
 controls_root=pathlib.Path('/data/reolink-protect-controls/backups')
 candidates=None;layers=[]
 for item in ui['files']:
  target=pathlib.Path(item['path'])
  if str(target)not in allowed or target.is_symlink()or not target.is_file():raise RuntimeError('feature_ui_manifest_changed')
  content=target.read_bytes()
  if sha256(content)==item['afterSha256']:continue
  if str(target)not in {str(p)for p in patch.ui_paths}:raise RuntimeError('feature_ui_changed')
  if candidates is None:
   candidates=[]
   if controls_root.exists():
    secure(controls_root)
    if controls_root.stat().st_mode&0o077:raise RuntimeError('owned_controls_backups_not_private')
    paths=sorted(controls_root.glob('*/manifest.json'))
    if len(paths)>32:raise RuntimeError('owned_controls_manifests_ambiguous')
    for candidate in paths:
     if not re.fullmatch(r'[0-9]{8}T[0-9]{12}Z',candidate.parent.name):raise RuntimeError('owned_controls_manifest_path_invalid')
     secure(candidate);secure(candidate.parent)
     if not candidate.is_file()or candidate.stat().st_mode&0o077 or candidate.parent.stat().st_mode&0o077 or candidate.stat().st_size>8388608:
      raise RuntimeError('owned_controls_manifest_not_private')
     manifest=json.loads(candidate.read_text())
     if manifest.get('state')=='applied':candidates.append((candidate,manifest))
  verified=[]
  for candidate,manifest in candidates:
   files=manifest.get('files',[])
   if not isinstance(files,list):raise RuntimeError('owned_controls_manifest_files_invalid')
   rows=[row for row in files if row.get('path')==str(target)and row.get('afterSha256')==sha256(content)]
   if not rows:continue
   if len(rows)!=1 or not re.fullmatch(r'[0-9]{1,2}\.original',rows[0].get('backup','')):raise RuntimeError('owned_controls_backup_path_invalid')
   backup=candidate.parent/rows[0]['backup'];secure(backup)
   if not backup.is_file()or backup.stat().st_mode&0o077 or backup.stat().st_size>16000000:raise RuntimeError('owned_controls_backup_not_private')
   layer=verified_controls_layer(content,item,ids,manifest,backup.read_bytes(),controls_patch.unpatched_bytes)
   verified.append(dict(layer,path=str(target),manifest=str(candidate)))
  if len(verified)!=1:
   raise RuntimeError('feature_ui_changed')
  layers.append(verified[0])
 if layers and len(layers)!=len(patch.ui_paths):raise RuntimeError('owned_controls_ui_layers_incomplete')
 return layers

def status(state):
 if state.get('rollbackPhase'):
  patch.guard_version()
  return {'ok':False,'state':state.get('state'),'rollbackPhase':state['rollbackPhase'],
          'restartRequired':True,'resumeCommand':'python tools/enable_features.py rollback'}
 layers=ui_status(state)
 manifest=json.loads(pathlib.Path(state['cameraManifest']).read_text())
 actual={row['id']:row for row in cameras._read(ids)}
 refresh=0;user_modified=[]
 for item in manifest['cameras']:
  changed=False
  for field in ('featureFlags','smartDetectZones'):
   value=item['configured'][field]
   current=actual[item['id']][field]
   if current!=value:
    if current!=item['original'][field]:
     if field!='smartDetectZones':raise RuntimeError('feature_camera_fields_changed')
     user_modified.append(dict(user_modified_zone_fields(value,current),cameraId=item['id']));continue
    changed=True
  refresh+=int(changed)
 return {'ok':True,'state':'applied','protectVersion':'7.3.70','cameraIds':sorted(ids),
         'restartRequired':state.get('restartRequired',True) or refresh>0,'cameraFieldRefreshRequired':refresh,
         'cameraManifest':state['cameraManifest'],
         'uiManifest':state['uiManifest'],'managedFields':['featureFlags','smartDetectZones'],
         'ownedControlsLayer':bool(layers),'uiLayers':layers,'rollbackDependency':'reolink-protect-controls'if layers else None,
         'userModifiedZoneFields':user_modified,'historicalZoneSettingsRestored':False,
         'nativeRecognitionSettingsPreserved':True,'userAgreementUnchanged':True}
def api(path):
 headers={'X-UserId':cfg['protectUserId'],'X-UserRole':'owner','X-UserPermissionMask':'64',
          'X-UserPermissions':'65535','X-Internal-Use':'true','Content-Type':'application/json'}
 status,content=get_bytes('https://127.0.0.1:7443/api/'+path,headers,timeout=8,limit=10000000)
 if status!=200:raise RuntimeError('protect_api_request_rejected')
 return json.loads(content)
def refresh(state):
 # Read-only proof that the source event display gates are loaded. Native AI
 # objectTypes settings and user agreement are deliberately not changed.
 result=status(state)
 if result.get('rollbackPhase'):raise RuntimeError('feature_rollback_in_progress')
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
  expected_zones=item['configured']['smartDetectZones']
  if len(zones)!=1:raise RuntimeError('protect_api_camera_zones_changed')
  projected=[{key:value for key,value in zones[0].items()if key in set(expected_zones[0])|{'sensitivity','mergeId'}}]
  if projected!=expected_zones:user_modified_zone_fields(expected_zones,projected)
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
  result=status(checked_state())
  if result.get('rollbackPhase'):raise RuntimeError('feature_rollback_in_progress')
  if result['userModifiedZoneFields']:raise RuntimeError('feature_camera_fields_changed')
  result['alreadyConfigured']=True
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
 state=checked_state();result=status(state)
 if result.get('rollbackPhase'):raise RuntimeError('feature_rollback_in_progress')
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
 # Controls must be removed first, restoring this layer's exact native UI.
 # Check this dependency before either UI restoration or camera-field SQL.
 def preflight():
  rollback_dependency(ui_status(state))
  if status(state)['userModifiedZoneFields']:raise RuntimeError('feature_camera_fields_changed')
 # Each operation checks ownership/hash/current values before restoring.
 # A subsequent Protect restart is deliberately a separate root decision.
 def persist(value):_atomic_write(state_path,json.dumps(value,indent=2).encode(),0o600)
 resume_rollback(state,persist,patch,cameras,preflight)
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
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.host):
        parser.error('Use an existing SSH alias')
    sources = {name: base64.b64encode((ROOT / "reolink_protect_events" / (name + ".py")).read_bytes()).decode()
               for name in ("http_deadline", "native", "features", "control_ui_layer", "controls_ui_guard", "feature_rollback")}
    code = "mode=" + repr(args.mode) + "\nsources=" + repr(sources) + "\n"
    code += "try:\n" + "\n".join(" " + line for line in REMOTE.splitlines())
    safe_errors = ("unsafe_symlink", "unsafe_owner_or_mode", "system_command_failed", "root_required",
                   "configuration_not_private", "unexpected_bridge_scope", "feature_deployment_scope_changed",
                   "unsafe_feature_manifest", "feature_ui_changed", "feature_camera_fields_changed",
                   "protect_api_redirect_rejected", "protect_api_response_oversized", "protect_api_request_rejected",
                   "protect_api_version_changed", "protect_api_camera_scope_changed", "protect_api_feature_flags_not_loaded",
                   "protect_api_camera_zones_changed", "protect_api_camera_settings_changed", "protect_api_refresh_not_applied",
                   "protect_api_unrelated_fields_changed", "protect_api_refresh_verification_failed",
                   "feature_ui_manifest_changed", "owned_controls_backups_not_private", "owned_controls_manifests_ambiguous",
                   "owned_controls_manifest_path_invalid", "owned_controls_manifest_not_private", "owned_controls_manifest_files_invalid",
                   "owned_controls_backup_path_invalid", "owned_controls_backup_not_private", "owned_controls_ui_layers_incomplete",
                   "owned_controls_manifest_not_applied", "owned_controls_camera_scope_invalid", "owned_controls_camera_scope_changed",
                   "owned_controls_ui_target_missing", "owned_controls_native_base_changed", "owned_controls_digest_changed",
                    "owned_controls_unpatch_failed", "feature_rollback_controls_dependency", "feature_rollback_in_progress")
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
