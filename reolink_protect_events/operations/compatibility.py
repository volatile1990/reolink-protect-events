"""Read-only compatibility assessment; unknown versions are never certified."""
import hashlib
import json
from pathlib import Path
from ..native import NativeAdapter
from .http import protect_json
from .protect import selected_cameras
from .safety import VERSION, OperationError, error_code, need, private_path, read_json, validate_config

ACTIVE_FILES={
 '/usr/share/unifi-protect/app/service.js':'a4e546e4a9d7cd82dc130a26cc5e92fa2b69f4cdb6fce1368870a543f0d08a7f',
 '/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat.cjs':'1d5e5e581f74b0755fd27dc2d4e724eadaaf683eceb58a9b1f03d11bdea9c54e',
 '/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat-all.cjs':'139b46a64eb0170a8fdbb4c890db823f12ec2ea2ea1743f40791f8c34ded2a0b'}
UI_ROOT=Path('/usr/share/unifi-protect/app/node_modules/@ubnt/unifi-protect-ui-internal/dist')


def _layers(events_root,ids,file_reader):
    """Verify actual applied UI bytes and reverse owned Controls layers."""
    from ..control_ui_layer import verified_controls_layer
    from ..controls_ui_guard import unpatched_bytes
    root=Path(events_root);state_path=root/'features.json'
    if not state_path.exists():state_path=root/'feature-deployment.json'
    state=read_json(state_path)
    need(state.get('protectVersion')==VERSION and sorted(state.get('cameraIds',[]))==sorted(ids)
         and not state.get('rollbackPhase'),'compatibility_feature_state_changed')
    path=Path(state['uiManifest']);private_path(path)
    need(any((root/name).resolve()in path.resolve().parents for name in
             ('feature-backups','camera-feature-backups','ui-feature-backups')),'compatibility_manifest_path_invalid')
    manifest=read_json(path,limit=8388608)
    need(manifest.get('state')=='applied'and manifest.get('protectVersion')==VERSION,
         'compatibility_feature_manifest_invalid')
    expected_paths={str(UI_ROOT/'swai.js'),str(UI_ROOT/'swai-7.3.26.js')};files=manifest.get('files',[])
    need(isinstance(files,list)and {r.get('path')for r in files}==expected_paths,
         'compatibility_ui_scope_changed')
    controls_root=Path('/data/reolink-protect-controls/backups');reports=[]
    for item in files:
        current=file_reader(item['path']);actual=hashlib.sha256(current).hexdigest()
        if actual==item['afterSha256']:
            reports.append({'path':item['path'],'sha256':actual,'ownedControlsLayer':False});continue
        candidates=[]
        for candidate in sorted(controls_root.glob('*/manifest.json'))[:33]:
            record=read_json(candidate,limit=8388608)
            matching=[r for r in record.get('files',[])if r.get('path')==item['path']and r.get('afterSha256')==actual]
            if record.get('state')!='applied'or len(matching)!=1:continue
            backup_name=matching[0].get('backup','')
            need('/'not in backup_name and '\\'not in backup_name and backup_name.endswith('.original'),
                 'compatibility_controls_backup_invalid')
            backup=private_path(candidate.parent/backup_name)
            verified_controls_layer(current,item,ids,record,backup.read_bytes(),unpatched_bytes)
            candidates.append({'path':item['path'],'sha256':actual,'ownedControlsLayer':True})
        need(len(candidates)==1,'compatibility_ui_bytes_unrecognized');reports.extend(candidates)
    return reports


def assess(config,events_root='/data/reolink-protect-events',*,api=None,file_reader=None,schema_reader=None,
           layer_reader=None):
    validate_config(config);api=api or protect_json
    result={'schemaVersion':1,'readOnly':True,'certified':False,'nativeWritesAllowed':False,
            'autoUpgradeAllowed':False,'fullDatabaseRollbackAllowed':False,'checks':{}}
    try:
        bootstrap=api(config,'/api/bootstrap');version=bootstrap.get('nvr',{}).get('version')
        result['observedProtectVersion']=version if isinstance(version,str)and len(version)<=40 else None
        if version!=VERSION:
            result.update(ok=False,state='unsupported',errorCode='unsupported_protect_version',
                          nextAction='inspect_and_test_new_release_contracts');return result
        cameras=selected_cameras(config,bootstrap);ids=[c['id']for c in cameras]
        result['checks']['cameraScope']=True
        schema=(schema_reader or (lambda:NativeAdapter().guard_schema()))()
        result['checks']['databaseContract']=schema.get('schemaVerified')is True
        file_reader=file_reader or (lambda path:Path(path).read_bytes())
        hashes={path:hashlib.sha256(file_reader(path)).hexdigest()for path in ACTIVE_FILES}
        result['activeFileHashes']=hashes;result['checks']['serviceAndAacLayers']=hashes==ACTIVE_FILES
        layers=(layer_reader or _layers)(events_root,ids,file_reader)
        result['uiLayers']=layers;result['checks']['uiLayerOwnership']=len(layers)==2
        result['ok']=all(result['checks'].values())
        result['state']='compatible'if result['ok']else'drift'
        # This reports an already audited contract, never approval of an
        # unknown version based only on apparently matching schema columns.
        result['certified']=result['ok'];result['nativeWritesAllowed']=result['ok']
        result['certificationBasis']='existing-audited-7.3.70-contract'
    except Exception as error:
        result.update(ok=False,state='drift',errorCode=error_code(error,'compatibility_assessment_failed'))
    return result
