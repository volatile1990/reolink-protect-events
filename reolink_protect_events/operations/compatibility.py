"""Read-only compatibility assessment; unknown versions are never certified."""
import hashlib
import json
from pathlib import Path
import re
import stat
from ..native import NativeAdapter
from .http import protect_json
from .protect import selected_cameras, settings_digest
from .safety import VERSION, OperationError, error_code, need, private_path, read_json, validate_config

ACTIVE_FILES={
 '/usr/share/unifi-protect/app/service.js':'a4e546e4a9d7cd82dc130a26cc5e92fa2b69f4cdb6fce1368870a543f0d08a7f',
 '/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat.cjs':'1d5e5e581f74b0755fd27dc2d4e724eadaaf683eceb58a9b1f03d11bdea9c54e',
 '/usr/local/lib/reolink-protect-controls/ubv-aac-clock-compat-all.cjs':'139b46a64eb0170a8fdbb4c890db823f12ec2ea2ea1743f40791f8c34ded2a0b'}
UI_ROOT=Path('/usr/share/unifi-protect/app/node_modules/@ubnt/unifi-protect-ui-internal/dist')
SERVICE_PATH='/usr/share/unifi-protect/app/service.js'
AUTOMATIC_SERVICE_SHA256='a8009e4768be7e507a07639bdadc74f24f0981664580298294d94b9e2e74c2f9'
AUTOMATIC_RECEIPT=Path('/data/reolink-protect-controls/automatic-quality/active.json')
AUTOMATIC_GUARD_PATH='/usr/local/lib/reolink-protect-controls/automatic-quality-guard.py'
AUTOMATIC_DROPIN_PATH='/etc/systemd/system/unifi-protect.service.d/70-reolink-automatic-quality.conf'
AUTOMATIC_FILES={
 AUTOMATIC_GUARD_PATH:'0ada43a86f67f9379eff70625b921722e42f723c795dc1ec209adfc9c1742ba2',
 AUTOMATIC_DROPIN_PATH:'1c0ce4897730fb64a36983f2189106ff800ec96d3b18f12305c27363a71f7e34'}
AUTOMATIC_ADDITIONAL_FILES={
 '/usr/local/lib/reolink-protect-controls/automatic-quality-nginx-guard.py':'15aa3d36b5a9f47b10bc6eaf0d046bff17effa6c020816b3b2872d2d7924267d',
 '/etc/systemd/system/unifi-protect.service.d/71-reolink-nginx-compat.conf':'d7b54808617426318b42acf88d270a1071d7128a80e0a59523b448cf747aef71'}
AUTOMATIC_WATCH_FILES={
 '/etc/systemd/system/reolink-protect-nginx-regeneration.service':'8381467f8fed88d11d945d6de263f4704b0564df92b590b5f8acfcb036dce93f',
 '/etc/systemd/system/reolink-protect-nginx-regeneration.path':'3fc436a3815b28a28194e4510af545e8a6186529052aa2415c63958585aecd12'}


def _automatic_input_layer(config,bootstrap,file_reader):
    """Recognize only the exact applied, private Automatic-input owned layer.

    This never installs or repairs a layer. The predecessor remains a separately
    audited contract; arbitrary newer service bytes cannot be vouched for by a
    receipt or by an apparently matching database schema.
    """
    path=private_path(AUTOMATIC_RECEIPT);info=path.stat()
    need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink==1
         and not info.st_mode&0o077,'compatibility_auto_receipt_not_root_private')
    receipt=read_json(path,limit=8388608)
    need(type(receipt.get('schemaVersion'))is int and receipt['schemaVersion']==1
         and receipt.get('owner')=='reolink-protect-controls:automatic-input'
         and receipt.get('state')=='applied'and receipt.get('protectVersion')==VERSION,
         'compatibility_auto_receipt_invalid')
    operation=receipt.get('operation')
    need(isinstance(operation,str)and re.fullmatch('[a-f0-9]{32}',operation)is not None,
         'compatibility_auto_operation_invalid')
    need(receipt.get('beforeSha256')==ACTIVE_FILES[SERVICE_PATH]
         and receipt.get('afterSha256')==AUTOMATIC_SERVICE_SHA256,
         'compatibility_auto_service_chain_changed')
    for name,field in((AUTOMATIC_GUARD_PATH,'guardSha256'),(AUTOMATIC_DROPIN_PATH,'dropinSha256')):
        expected=AUTOMATIC_FILES[name]
        need(receipt.get(field)==expected
             and hashlib.sha256(file_reader(name)).hexdigest()==expected,
             'compatibility_auto_startup_layer_changed')
    additional=receipt.get('additionalOwnedFiles')
    need(isinstance(additional,list)and len(additional)==2
         and all(isinstance(row,dict)and set(row)=={'path','sha256'}
                 and isinstance(row['path'],str)and isinstance(row['sha256'],str)for row in additional)
         and len({row['path']for row in additional})==2
         and {row['path']:row['sha256']for row in additional}==AUTOMATIC_ADDITIONAL_FILES,
         'compatibility_auto_nginx_ownership_changed')
    for name,expected in AUTOMATIC_ADDITIONAL_FILES.items():
        need(hashlib.sha256(file_reader(name)).hexdigest()==expected,
             'compatibility_auto_nginx_startup_changed')
    watch=receipt.get('nginxWatchFiles')
    need(receipt.get('nginxWatchState')=='applied'and isinstance(watch,list)and len(watch)==2
         and all(isinstance(row,dict)and set(row)=={'path','sha256'}
                 and isinstance(row['path'],str)and isinstance(row['sha256'],str)for row in watch)
         and len({row['path']for row in watch})==2
         and {row['path']:row['sha256']for row in watch}==AUTOMATIC_WATCH_FILES,
         'compatibility_auto_nginx_watch_ownership_changed')
    for name,expected in AUTOMATIC_WATCH_FILES.items():
        need(hashlib.sha256(file_reader(name)).hexdigest()==expected,
             'compatibility_auto_nginx_watch_changed')
    baseline=receipt.get('baseline')
    need(isinstance(baseline,dict)and baseline.get('settingsSha256')==settings_digest(config,bootstrap),
         'compatibility_auto_camera_settings_changed')
    return {'operation':operation,'ownedAppliedLayer':True,'startupFilesVerified':True,
            'nginxRegenerationGuardVerified':True,
            'nginxEventWatchFilesVerified':True,
            'allCameraSettingsVerified':True,'serviceSha256':AUTOMATIC_SERVICE_SHA256}


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
        result['activeFileHashes']=hashes
        recognized=hashes==ACTIVE_FILES
        if hashes[SERVICE_PATH]==AUTOMATIC_SERVICE_SHA256 and all(
                hashes[path]==expected for path,expected in ACTIVE_FILES.items()if path!=SERVICE_PATH):
            result['automaticInputLayer']=_automatic_input_layer(config,bootstrap,file_reader)
            result['checks']['automaticInputLayerOwnership']=True
            recognized=True
        result['checks']['serviceAndAacLayers']=recognized
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
