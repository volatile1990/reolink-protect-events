"""Owned single-camera null -> true -> null recorder rebuild with crash recovery.

No global Protect restart, camera adoption, stream profile change or NAS mutation.
Only forceTcp is patched; an exact settings digest gates every dispatch.
"""
import time
from pathlib import Path
from .http import bridge_metrics, protect_json
from .media_health import source_health
from .protect import automatic_channel, recording_ends, selected_cameras, settings_digest
from .safety import OperationError, error_code, maintenance_blocks, need, read_json, write_json


def _camera(config, bootstrap, camera_id):
    return next(c for c in selected_cameras(config, bootstrap) if c['id']==camera_id)


def _guard(config, bootstrap, receipt, temporary):
    expected=receipt['temporarySettingsSha256']if temporary else receipt['originalSettingsSha256']
    need(settings_digest(config,bootstrap)==expected,'recovery_settings_drift')
    camera=_camera(config,bootstrap,receipt['cameraId'])
    need(camera.get('thirdPartyCameraInfo',{}).get('forceTcp')is(True if temporary else None),
         'recovery_force_tcp_drift')
    return camera


def _patch(config,root,api,camera_id,value,maintenance_owner=None):
    need(not maintenance_blocks(root,maintenance_owner),'recovery_maintenance_active')
    api(config,'/api/cameras/'+camera_id,method='PATCH',body={'thirdPartyCameraInfo':{'forceTcp':value}},timeout=8)


def _wait(config,api,receipt,temporary,checkpoint,*,clock,sleep,wait_seconds):
    deadline=clock()+wait_seconds; consecutive=0; busy=False
    while True:
        boot=api(config,'/api/bootstrap');camera=_guard(config,boot,receipt,temporary)
        busy=busy or camera.get('videoReconfigurationInProgress')is True
        ends=recording_ends(camera);now=int(time.time()*1000)
        advanced=bool(ends)and all(type(end)in(int,float)and type(checkpoint.get(q))in(int,float)
            and end>checkpoint[q]and -5000<=now-end<=120000 for q,end in ends.items())
        ready=camera.get('state')=='CONNECTED'and camera.get('hasRecordingStarted')is True
        ready=ready and camera.get('videoReconfigurationInProgress')is False and(busy or advanced)
        consecutive=consecutive+1 if ready else 0
        if consecutive>=2:return boot
        need(clock()<deadline,'recovery_settlement_timeout');sleep(min(2,max(0,deadline-clock())))


def _restore(config,root,api,receipt,*,clock,sleep,wait_seconds,maintenance_owner=None):
    path=Path(root)/'recovery.json'; last=None
    for attempt in range(3):
        try:
            boot=api(config,'/api/bootstrap');camera=_camera(config,boot,receipt['cameraId'])
            flag=camera.get('thirdPartyCameraInfo',{}).get('forceTcp')
            need(flag is None or flag is True,'recovery_force_tcp_drift')
            _guard(config,boot,receipt,flag is True)
            if flag is True:
                checkpoint=recording_ends(camera);receipt['phase']='restore-dispatching';write_json(path,receipt)
                _patch(config,root,api,receipt['cameraId'],None,maintenance_owner)
                try:_wait(config,api,receipt,False,checkpoint,clock=clock,sleep=sleep,wait_seconds=wait_seconds)
                except OperationError as error:
                    if error.code!='recovery_settlement_timeout':raise
                    # A still-stalled recorder does not make restoration of the
                    # exact original flag ambiguous: verify the settings again.
                    final=api(config,'/api/bootstrap');_guard(config,final,receipt,False)
                    receipt['restoredOriginalTcp']=True;write_json(path,receipt);raise
            else:
                _guard(config,boot,receipt,False)
            receipt['restoredOriginalTcp']=True;receipt['restoreAttempts']=attempt+1
            receipt['phase']='restored';write_json(path,receipt);return
        except OperationError as error:
            last=error
            if error.code in ('recovery_settings_drift','recovery_force_tcp_drift','recovery_maintenance_active'):
                raise
        except Exception as error:last=error
    raise OperationError('recovery_restore_failed')from last


def resume_pending(config,root,*,api=None,fetch=None,probe=None,clock=None,sleep=None,wait_seconds=30,
                   maintenance_owner=None):
    path=Path(root)/'recovery.json'
    if not path.exists():return None
    receipt=read_json(path)
    if receipt.get('phase')=='complete':return None
    if receipt.get('phase')=='blocked':
        return {'cameraId':receipt.get('cameraId'),'resumed':True,'ok':False,
                'restoredOriginalTcp':receipt.get('restoredOriginalTcp')is True,
                'errorCode':'recovery_blocked_requires_review'}
    api=api or protect_json;fetch=fetch or bridge_metrics;clock=clock or time.monotonic;sleep=sleep or time.sleep
    result={'cameraId':receipt.get('cameraId'),'resumed':True,'ok':False,'restoredOriginalTcp':False}
    try:
        need(not maintenance_blocks(root,maintenance_owner),'recovery_maintenance_active')
        need(maintenance_owner is None or receipt.get('maintenanceOwner')==maintenance_owner,
             'recovery_receipt_owner_changed')
        need(receipt.get('schemaVersion')==1 and receipt.get('cameraId')in{b['cameraId']for b in config['bridges']},
             'recovery_receipt_scope_invalid')
        _restore(config,root,api,receipt,clock=clock,sleep=sleep,wait_seconds=wait_seconds,
                 maintenance_owner=maintenance_owner)
        from .ubv import probe_ubv
        boot=api(config,'/api/bootstrap');camera=_guard(config,boot,receipt,False)
        bridge=next(b for b in config['bridges']if b['cameraId']==receipt['cameraId'])
        source=source_health(fetch(bridge));need(source['ok'],'recovery_source_unhealthy')
        if camera.get('thirdPartyCameraInfo',{}).get('enableRtspAudio')is True:
            need(all(s['audioAvailable']and s['audioMetadataCurrent']for s in source['streams']),
                 'recovery_source_audio_unhealthy')
        need(not maintenance_blocks(root,maintenance_owner),'recovery_maintenance_active')
        verify=(probe or probe_ubv)(config,camera,automatic_channel(camera),seconds=8)
        result['postRepairActiveProbe']=verify;need(verify.get('ok')is True,'recovery_active_verification_failed')
        boot=api(config,'/api/bootstrap');camera=_guard(config,boot,receipt,False)
        latest=recording_ends(camera);checkpoint=receipt.get('checkpoint',{});now=int(time.time()*1000)
        need(set(checkpoint)==set(latest)and all(type(end)in(int,float)and type(checkpoint[q])in(int,float)
            and end>checkpoint[q]and -5000<=now-end<=120000 for q,end in latest.items()),
            'recovery_recordings_not_fresh')
        receipt['postRepairActiveProbe']=verify;receipt['recordingVerifiedEnds']=latest
        receipt['completionAtMs']=int(time.time()*1000)
        receipt['phase']='complete';write_json(path,receipt)
        result.update(ok=True,restoredOriginalTcp=True)
    except Exception as error:
        result['errorCode']=error_code(error,'recovery_resume_failed')
        result['restoredOriginalTcp']=receipt.get('restoredOriginalTcp')is True
        if result['restoredOriginalTcp']:
            receipt['phase']='complete';receipt['verificationErrorCode']=result['errorCode'];write_json(path,receipt)
    return result


def rebuild(config,root,camera_id,*,api=None,fetch=None,probe=None,clock=None,sleep=None,wait_seconds=30,
            maintenance_owner=None):
    """Try one bounded known-version repair; public result contains no settings."""
    api=api or protect_json;fetch=fetch or bridge_metrics;clock=clock or time.monotonic;sleep=sleep or time.sleep
    result={'cameraId':camera_id,'attempted':False,'ok':False,'restoredOriginalTcp':False,
            'protectedSettingsPreserved':False,'globalServiceRestarted':False}
    receipt=None;path=Path(root)/'recovery.json'
    try:
        need(type(wait_seconds)is int and 4<=wait_seconds<=45,'recovery_wait_invalid')
        need(not maintenance_blocks(root,maintenance_owner),'recovery_maintenance_active')
        if path.exists():
            prior=read_json(path)
            need(prior.get('phase')in('complete','blocked'),'recovery_already_pending')
        before=api(config,'/api/bootstrap');camera=_camera(config,before,camera_id)
        need(before['nvr'].get('isRecordingDisabled')is False,'recovery_global_recording_disabled')
        need(camera.get('state')=='CONNECTED'and camera.get('isProvisioned')is True
             and camera.get('isUpdating')is not True and camera.get('videoReconfigurationInProgress')is False,
             'recovery_camera_not_ready')
        third=camera.get('thirdPartyCameraInfo',{})
        need(camera.get('rtspClient')=='gstreamer'and 'forceTcp'in third and third['forceTcp']is None,
             'recovery_requires_original_null_tcp')
        bridge=next(b for b in config['bridges']if b['cameraId']==camera_id)
        source=source_health(fetch(bridge));need(source['ok'],'recovery_source_unhealthy')
        if third.get('enableRtspAudio')is True:
            need(all(s['audioAvailable']and s['audioMetadataCurrent']for s in source['streams']),
                 'recovery_source_audio_unhealthy')
        receipt={'schemaVersion':1,'cameraId':camera_id,'atMs':int(time.time()*1000),'phase':'prepared',
            'maintenanceOwner':maintenance_owner,
            'originalSettingsSha256':settings_digest(config,before),
            'temporarySettingsSha256':settings_digest(config,before,target=camera_id,force_tcp=True),
            'checkpoint':recording_ends(camera),'restoredOriginalTcp':False}
        write_json(path,receipt)
        current=api(config,'/api/bootstrap');_guard(config,current,receipt,False)
        receipt['phase']='toggle-dispatching';write_json(path,receipt);result['attempted']=True
        phase_error=None
        try:
            _patch(config,root,api,camera_id,True,maintenance_owner)
            _wait(config,api,receipt,True,receipt['checkpoint'],clock=clock,sleep=sleep,wait_seconds=wait_seconds)
            receipt['phase']='temporary-ready';write_json(path,receipt)
        except Exception as error:phase_error=error
        finally:
            _restore(config,root,api,receipt,clock=clock,sleep=sleep,wait_seconds=wait_seconds,
                     maintenance_owner=maintenance_owner)
        result['restoredOriginalTcp']=True
        if phase_error is not None:raise phase_error
        final=api(config,'/api/bootstrap');camera=_guard(config,final,receipt,False)
        ends=recording_ends(camera)
        need(all(type(end)in(int,float)and type(receipt['checkpoint'].get(q))in(int,float)
                 and end>receipt['checkpoint'][q] for q,end in ends.items()),'recovery_recordings_not_advancing')
        from .ubv import probe_ubv
        need(not maintenance_blocks(root,maintenance_owner),'recovery_maintenance_active')
        verify=(probe or probe_ubv)(config,camera,automatic_channel(camera),seconds=8)
        result['postRepairActiveProbe']=verify
        need(verify.get('ok')is True,'recovery_active_verification_failed')
        after=api(config,'/api/bootstrap');camera=_guard(config,after,receipt,False)
        latest=recording_ends(camera);now=int(time.time()*1000)
        need(all(type(end)in(int,float)and end>receipt['checkpoint'][q]and -5000<=now-end<=120000
                 for q,end in latest.items()),'recovery_recordings_not_fresh')
        receipt['postRepairActiveProbe']=verify;receipt['recordingVerifiedEnds']=latest
        receipt['completionAtMs']=int(time.time()*1000)
        receipt['phase']='complete';write_json(path,receipt)
        result.update(ok=True,protectedSettingsPreserved=True,recordingProfiles=len(latest))
    except Exception as error:
        result['errorCode']=error_code(error,'recorder_recovery_failed')
        if receipt is not None:
            result['restoredOriginalTcp']=receipt.get('restoredOriginalTcp')is True
            if result['restoredOriginalTcp']:
                receipt['phase']='complete';write_json(path,receipt)
            elif isinstance(error,OperationError)and error.code in('recovery_settings_drift','recovery_force_tcp_drift'):
                receipt['phase']='blocked';write_json(path,receipt)
    return result
