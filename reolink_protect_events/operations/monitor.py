"""Independent 30-second Protect media monitor with bounded owned recovery."""
import argparse
import json
import os
from pathlib import Path
import signal
import time
from . import recovery
from .http import protect_json
from .media_health import inspect
from .protect import selected_cameras,read_only_cameras
from .safety import OperationError, ensure_root, error_code, maintenance, need, read_json, validate_config, write_json
from .ubv import probe_ubv
from .fmp4 import configuration as fmp4_configuration, verify_configuration as verify_fmp4_configuration, probe_fmp4
from .maintenance_lease import reconcile as reconcile_maintenance,identity as boot_identity

INTERVAL_MS=30000
STARTUP_GRACE_MS=120000
FAILURE_THRESHOLD=3
PROBE_INTERVAL_MS=50000
ACTIVE_PROBE_TTL_MS=900000
URGENT_PROBE_INTERVAL_MS=30000
REPAIR_COOLDOWN_MS=900000
REPAIR_WINDOW_MS=86400000
REPAIR_LIMIT=2
ABSOLUTE_REPAIR_LIMIT=12
HEALTHY_REARM_MS=1800000
RESUME_RETRY_MS=30000


def _generation(previous):
    value=previous.get('probeGeneration',0)
    need(type(value)is int and value>=0,'monitor_probe_generation_invalid')
    return value


def _current_probe(at,epoch,generation,row,previous,now_ms):
    return type(at)is int and 0<=now_ms-at<=ACTIVE_PROBE_TTL_MS \
        and at>=max(previous.get('repairAttempts',[]),default=0) \
        and type(row['source'].get('connectionEpoch'))is int and epoch==row['source']['connectionEpoch'] \
        and generation==_generation(previous)


def _bad_channels(row,previous,now_ms,quality_checks):
    failed=[]
    if quality_checks:
        for channel in row['enabledChannels']:
            value=previous.get('qualityProbes',{}).get(str(channel),{})
            if (value.get('result')or{}).get('ok')is False and _current_probe(value.get('atMs'),
                    value.get('sourceEpoch'),value.get('generation',0),row,previous,now_ms):failed.append(channel)
    channel=row['automaticChannel']
    if channel not in failed and (previous.get('lastActiveProbe')or{}).get('ok')is False \
            and _current_probe(previous.get('lastActiveProbeAtMs'),previous.get('activeProbeSourceEpoch'),
                previous.get('activeProbeGeneration',0),row,previous,now_ms):failed.append(channel)
    return failed


def _failure_count(previous,row,observations):
    epoch=row['source'].get('connectionEpoch');generation=_generation(previous)
    if previous.get('failureEvidenceVersion')!=1 or previous.get('failureEvidenceEpoch')!=epoch \
            or previous.get('failureEvidenceGeneration')!=generation:
        # Legacy aggregate counts cannot prove independent failed probes.
        samples=previous.get('sampleFailures',0)if previous.get('failureEvidenceVersion')==1 \
            and previous.get('failureEvidenceGeneration')==generation else 0
        previous.update(failureEvidenceVersion=1,failureEvidenceEpoch=epoch,
                        failureEvidenceGeneration=generation,sampleFailures=samples,mediaFailures={})
    quick_bad=not(row['sourceHealthy']and row['protectHealthy'])
    previous['sampleFailures']=previous.get('sampleFailures',0)+1 if quick_bad else 0
    counts=[previous['sampleFailures']];saved=previous['mediaFailures']
    need(isinstance(saved,dict),'monitor_failure_evidence_invalid')
    for channel,at,ok in observations:
        key=str(channel);prior=saved.get(key,{})
        need(isinstance(prior,dict)and type(prior.get('count',0))is int,'monitor_failure_evidence_invalid')
        if ok:
            saved[key]={'atMs':at,'count':0};continue
        if prior.get('atMs')==at:count=prior.get('count',1)
        else:
            last=prior.get('atMs')
            count=prior.get('count',0)+1 if type(last)is int and 0<at-last<=ACTIVE_PROBE_TTL_MS else 1
            saved[key]={'atMs':at,'count':count}
        counts.append(count)
    return max(counts)


def _invalidate_probe_generation(root,state,cid,now_ms,reason):
    previous=state['cameras'].setdefault(cid,{})
    history=ensure_root(Path(root)/'repair-history')
    write_json(history/(cid+'-'+str(now_ms)+'-'+reason+'.json'),{'cameraId':cid,'atMs':now_ms,
        'reason':reason,'probeGeneration':_generation(previous),
        'qualityProbes':previous.get('qualityProbes',{}),'lastActiveProbe':previous.get('lastActiveProbe'),
        'lastActiveProbeAtMs':previous.get('lastActiveProbeAtMs'),
        'lastFmp4StartupProbe':previous.get('lastFmp4StartupProbe'),
        'lastFmp4StartupProbeAtMs':previous.get('lastFmp4StartupProbeAtMs')})
    previous['probeGeneration']=_generation(previous)+1
    previous.update(failures=0,sampleFailures=0,mediaFailures={})
    write_json(Path(root)/'state.json',state)


def _resume_pending(config,root,state,now_ms,*,allow_repair,marker,api,fetch,probe,resume):
    path=Path(root)/'recovery.json'
    if not path.exists():return None
    receipt=read_json(path)
    if receipt.get('phase')in('complete','blocked')or marker or not allow_repair:return None
    boot=boot_identity();due=state.get('resumeNextAtMs',0)
    if state.get('resumeBootId')!=boot:due=0
    if type(due)is not int or due>now_ms+300000:due=now_ms
    if now_ms<due:return None
    attempts=state.get('resumeRetryCount',0)
    need(type(attempts)is int and attempts>=0,'monitor_resume_state_invalid')
    state['resumeRetryCount']=min(attempts+1,10);state['resumeBootId']=boot
    state['resumeNextAtMs']=now_ms+min(300000,RESUME_RETRY_MS*2**min(attempts,4))
    write_json(Path(root)/'state.json',state)
    result=(resume or recovery.resume_pending)(config,root,api=api,fetch=fetch,probe=probe)
    if isinstance(result,dict)and result.get('restoredOriginalTcp')is True \
            and result.get('cameraId')in state['cameras']:
        _invalidate_probe_generation(root,state,result['cameraId'],now_ms,'resume-restored')
    if not path.exists()or read_json(path).get('phase')=='complete':
        state['resumeRetryCount']=0;state['resumeNextAtMs']=0
    state['lastResumeResult']=result
    return result


def _state(root,now_ms,startup_at_ms):
    path=Path(root)/'state.json'
    if not path.exists():
        return {'schemaVersion':1,'startedAtMs':startup_at_ms if startup_at_ms is not None else now_ms,
                'cameras':{},'lastProbeAtMs':0,'rotation':0}
    value=read_json(path)
    need(value.get('schemaVersion')==1 and isinstance(value.get('cameras'),dict)
         and type(value.get('startedAtMs'))is int and type(value.get('lastProbeAtMs'))is int
         and type(value.get('rotation'))is int,'monitor_state_invalid')
    for row in value['cameras'].values():
        need(isinstance(row,dict)and type(row.get('failures',0))is int
             and isinstance(row.get('repairAttempts',[]),list)
             and all(type(t)is int and t>=0 for t in row.get('repairAttempts',[])), 'monitor_state_invalid')
    value.setdefault('lastRotationAtMs',value['lastProbeAtMs'])
    need(type(value['lastRotationAtMs'])is int and value['lastRotationAtMs']>=0,'monitor_state_invalid')
    return value


def run_once(config,root,*,allow_repair=False,now_ms=None,startup_at_ms=None,api=None,fetch=None,
             probe=None,recover=None,startup_probe=None,resume=None,monotonic_ms=None,public_status=None):
    """Persist one sample/decision. Dependency hooks keep tests hardware-free."""
    now_ms=int(time.time()*1000)if now_ms is None else now_ms
    root=ensure_root(root);state=None
    try:
        validate_config(config);state=_state(root,now_ms,startup_at_ms)
        startup_options=fmp4_configuration(config)
        startup_configuration_ok=True
        if startup_options['enabled']:
            try:verify_fmp4_configuration(startup_options, config)
            except OperationError:startup_configuration_ok=False
        known_ids={b['cameraId']for b in config['bridges']}|{b['cameraId']for b in config.get('readOnlyCameras',[])}
        need(set(state['cameras'])<=known_ids,'monitor_state_scope_changed')
        lease_state=reconcile_maintenance(root)
        marker=maintenance(root);api=api or protect_json;probe=probe or probe_ubv
        resumed=_resume_pending(config,root,state,now_ms,allow_repair=allow_repair,marker=marker,
            api=api,fetch=fetch,probe=probe,resume=resume)
        report,bootstrap=inspect(config,prior=state['cameras'],now_ms=now_ms,api=api,fetch=fetch)
        report['maintenanceLease']=lease_state;report['resumeRecovery']=resumed
        if resumed is not None:report['readOnly']=False
        report['maintenanceActive']=marker
        grace_origin=startup_at_ms if startup_at_ms is not None else state['startedAtMs']
        report['startupGraceActive']=now_ms-grace_origin<STARTUP_GRACE_MS
        report['repairEnabled']=allow_repair
        recovery_path=root/'recovery.json'
        pending_recovery=None
        if recovery_path.exists():
            receipt=read_json(recovery_path)
            if receipt.get('phase')!='complete':
                pending_recovery={'cameraId':receipt.get('cameraId'),'phase':receipt.get('phase'),
                    'restoredOriginalTcp':receipt.get('restoredOriginalTcp')is True,
                    'requiresReview':receipt.get('phase')=='blocked'}
        report['pendingRecovery']=pending_recovery
        report['monitorIntervalMs']=INTERVAL_MS
        all_qualities=config.get('allQualityMediaChecks',False)
        rotation_interval=25000 if all_qualities or config.get('readOnlyCameras')else PROBE_INTERVAL_MS
        report['activeProbePolicy']={'seconds':8,'globalRotationIntervalMs':rotation_interval,
                                    'maximumConcurrent':1,'onSuspect':True,'resultTtlMs':ACTIVE_PROBE_TTL_MS,
                                    'urgentMinimumIntervalMs':URGENT_PROBE_INTERVAL_MS,
                                    'fmp4StartupEnabled':startup_options['enabled'],
                                    'fmp4StartupSeconds':12 if startup_options['enabled']else None,
                                    'allExplicitQualities':all_qualities,'nativeObservationIsReadOnly':True}
        report['fmp4ConfigurationVerified']=startup_configuration_ok
        report['repairPolicy']={'consecutiveFailures':FAILURE_THRESHOLD,'startupGraceMs':STARTUP_GRACE_MS,
                                'cooldownMs':REPAIR_COOLDOWN_MS,'maximumPerCamera24h':ABSOLUTE_REPAIR_LIMIT,
                                'maximumPerUnhealthyEpisode':REPAIR_LIMIT,'healthyRearmMs':HEALTHY_REARM_MS}
        cameras={c['id']:c for c in selected_cameras(config,bootstrap)+read_only_cameras(config,bootstrap)}
        monitored_rows=report['cameras']+report.get('nativeCameras',[])
        rows={r['cameraId']:r for r in monitored_rows}
        # Rollouts suppress active sessions too, avoiding false camera errors
        # and competition with deliberate deployment media gates.
        epoch_candidates=[]
        for row in monitored_rows:
            previous=state['cameras'].setdefault(row['cameraId'],{})
            epoch=row['source'].get('connectionEpoch');old=previous.get('connectionEpoch')
            if epoch is not None and old is not None and epoch!=old:previous['epochProbePending']=True
            if previous.get('failureSourceEpoch')!=epoch:
                previous['failures']=0
            previous['failureSourceEpoch']=epoch
            previous['connectionEpoch']=epoch
            row['sourceEpochChanged']=previous.get('epochProbePending')is True
            if row['sourceHealthy']and row['sourceEpochChanged']:epoch_candidates.append(row['cameraId'])
        bad_channels={cid:_bad_channels(row,state['cameras'][cid],now_ms,all_qualities or row.get('readOnly'))for cid,row in rows.items()}
        candidates=[r['cameraId']for r in monitored_rows if r['sourceHealthy']and(
            not r['protectHealthy']or bad_channels[r['cameraId']]
            or not all_qualities and startup_options['enabled']and state['cameras'][r['cameraId']].get('lastFmp4StartupProbe',{}).get('ok')is False)
            and not(state['cameras'][r['cameraId']].get('failureEvidenceVersion')==1
                    and state['cameras'][r['cameraId']].get('failures',0)>=FAILURE_THRESHOLD)]
        selected=None
        if not marker and not report['startupGraceActive']:
            reason='rotation'
            # Urgent failures never consume the independent global rotation.
            # A permanently broken camera or exhausted repair budget must not
            # prevent every other camera from receiving fresh media evidence.
            urgent=epoch_candidates or candidates
            ready=[cid for cid in urgent if now_ms-state['cameras'][cid].get('lastAnyProbeAtMs',
                state['cameras'][cid].get('lastActiveProbeAtMs',0))>=URGENT_PROBE_INTERVAL_MS]
            if ready and state.get('urgentSinceRotation')is not True:
                selected=min(ready,key=lambda cid:(state['cameras'][cid].get('lastAnyProbeAtMs',
                    state['cameras'][cid].get('lastActiveProbeAtMs',0)),cid))
                reason='source_epoch_changed'if epoch_candidates else'suspect'
                state['urgentSinceRotation']=True
            elif now_ms-state.get('lastRotationAtMs',state['lastProbeAtMs'])>=rotation_interval:
                ids=sorted(rows)
                for offset in range(len(ids)):
                    index=(state['rotation']+offset)%len(ids)
                    if rows[ids[index]]['sourceHealthy']:
                        selected=ids[index];state['rotation']=(index+1)%len(ids)
                        state['lastRotationAtMs']=now_ms;state['urgentSinceRotation']=False;break
            if selected is not None:
                state['lastProbeAtMs']=now_ms
                previous=state['cameras'].setdefault(selected,{})
                native=rows[selected].get('readOnly')is True
                quality_checks=all_qualities or native
                channel=rows[selected]['automaticChannel']
                if quality_checks:
                    channels=list(dict.fromkeys([channel]+rows[selected]['enabledChannels']))
                    plan=[('ubv',ch)for ch in channels]
                    if startup_options['enabled']and not native:plan.append(('fmp4',channel))
                    index=previous.get('qualityRotation',0)
                    need(type(index)is int and index>=0,'monitor_quality_state_invalid')
                    kind,channel=plan[index%len(plan)]
                    if reason=='rotation':previous['qualityRotation']=(index+1)%len(plan)
                else:kind=previous.get('nextProbeType','ubv')if startup_options['enabled']else'ubv'
                if reason!='rotation'and bad_channels[selected]:kind,channel='ubv',bad_channels[selected][0]
                if kind=='fmp4':
                    result=(startup_probe or probe_fmp4)(config,cameras[selected],channel,seconds=12) \
                        if startup_configuration_ok else {'ok':False,'errorCode':'fmp4_configuration_drift'}
                    previous['lastFmp4StartupProbe']=result;previous['lastFmp4StartupProbeAtMs']=now_ms
                    previous['fmp4ProbeSourceEpoch']=rows[selected]['source'].get('connectionEpoch')
                    previous['fmp4ProbeGeneration']=_generation(previous)
                    previous['nextProbeType']='ubv'
                else:
                    result=probe(config,cameras[selected],channel,seconds=8)
                    if channel==rows[selected]['automaticChannel']:
                        previous['lastActiveProbe']=result;previous['lastActiveProbeAtMs']=now_ms
                        previous['activeProbeSourceEpoch']=rows[selected]['source'].get('connectionEpoch')
                        previous['activeProbeGeneration']=_generation(previous)
                    previous.setdefault('qualityProbes',{})[str(channel)]={'result':result,'atMs':now_ms,
                        'sourceEpoch':rows[selected]['source'].get('connectionEpoch'),'generation':_generation(previous)}
                    previous['nextProbeType']='fmp4'if startup_options['enabled']else'ubv'
                previous['lastAnyProbeAtMs']=now_ms
                if not startup_options['enabled']or kind=='fmp4'or native and previous.get('qualityRotation')==0:
                    previous['epochProbePending']=False
                rows[selected]['activeProbePerformed']=True
                rows[selected]['activeProbeReason']=reason
                rows[selected]['activeProbeType']=kind
                rows[selected]['activeProbeChannel']=channel
        repair_candidates=[]
        for cid,row in rows.items():
            previous=state['cameras'].setdefault(cid,{})
            active=previous.get('lastActiveProbe')
            startup=previous.get('lastFmp4StartupProbe')
            row['lastActiveProbe']=active
            row['lastActiveProbeAtMs']=previous.get('lastActiveProbeAtMs')
            def fresh(at_key,epoch_key,generation_key):
                at=previous.get(at_key)
                return epoch_key in previous and _current_probe(at,previous[epoch_key],
                    previous.get(generation_key,0),row,previous,now_ms)
            row['activeProbeFresh']=fresh('lastActiveProbeAtMs','activeProbeSourceEpoch','activeProbeGeneration')
            active_bad=row['activeProbeFresh']and isinstance(active,dict)and active.get('ok')is False
            observations=[]
            if row['activeProbeFresh']and isinstance(active,dict)and type(active.get('ok'))is bool:
                observations.append((row['automaticChannel'],previous['lastActiveProbeAtMs'],active['ok']))
            row['activeMediaVerified']=bool(row['sourceHealthy']and row['protectHealthy']and row['activeProbeFresh']
                and isinstance(active,dict)and active.get('ok')is True)
            native=row.get('readOnly')is True
            if all_qualities or native:
                checks=[]
                for channel in row['enabledChannels']:
                    q=previous.get('qualityProbes',{}).get(str(channel),{})
                    at=q.get('atMs');epoch=row['source'].get('connectionEpoch')
                    current=_current_probe(at,q.get('sourceEpoch'),q.get('generation',0),row,previous,now_ms)
                    result=q.get('result')or{}
                    checks.append({'channel':channel,'atMs':at,'fresh':current,'ok':current and result.get('ok')is True,
                                   'probe':result})
                    active_bad=active_bad or current and result.get('ok')is False
                    if current and type(result.get('ok'))is bool:
                        observations=[value for value in observations if value[0]!=channel]
                        observations.append((channel,at,result['ok']))
                row['qualityMediaChecks']=checks
                row['activeMediaVerified']=bool(row['sourceHealthy']and row['protectHealthy']and checks and all(q['ok']for q in checks))
            row['lastFmp4StartupProbe']=startup
            row['lastFmp4StartupProbeAtMs']=previous.get('lastFmp4StartupProbeAtMs')
            fmp4_required=startup_options['enabled']and not native
            row['fmp4StartupProbeFresh']=bool(fmp4_required and startup_configuration_ok
                and fresh('lastFmp4StartupProbeAtMs','fmp4ProbeSourceEpoch','fmp4ProbeGeneration'))
            startup_bad=row['fmp4StartupProbeFresh']and isinstance(startup,dict)and startup.get('ok')is False
            row['fmp4StartupVerified']=bool(fmp4_required and startup_configuration_ok
                and row['sourceHealthy']and row['protectHealthy']and isinstance(startup,dict)and startup.get('ok')is True
                and row['fmp4StartupProbeFresh'])
            row['allActivePathsVerified']=row['activeMediaVerified']and(
                not fmp4_required or row['fmp4StartupVerified'])
            row['recorderAndUbvHealthy']=row['ok']and not active_bad
            row['fmp4StartupNeedsReview']=bool(startup_bad)
            row['ok']=row['recorderAndUbvHealthy']and not startup_bad
            if active_bad and row['sourceHealthy']:row['cause']='protect_media_unhealthy'
            elif startup_bad and row['recorderAndUbvHealthy']:row['cause']='protect_fmp4_startup_unhealthy'
            # A packaging/clock defect in fMP4 alone is a review finding, not
            # authority to toggle a healthy native recorder or spend its budget.
            count=_failure_count(previous,row,observations)
            previous['failures']=count;row['consecutiveFailures']=count
            previous['recordingEnds']=row['recordingEnds']
            attempts=[t for t in previous.get('repairAttempts',[])if t>=now_ms-REPAIR_WINDOW_MS]
            previous['repairAttempts']=attempts
            mono=int(time.monotonic()*1000)if monotonic_ms is None else monotonic_ms
            boot=boot_identity();last_mono=previous.get('healthyLastMonotonicMs')
            independent_health=bool(row['sourceHealthy']and row['protectHealthy']and row['activeMediaVerified'])
            continuity=previous.get('healthyBootId')==boot and type(last_mono)is int and 0<=mono-last_mono<=90000
            if not independent_health:
                previous.pop('healthySinceMonotonicMs',None)
            else:
                if not continuity or type(previous.get('healthySinceMonotonicMs'))is not int:
                    previous['healthySinceMonotonicMs']=mono
                previous['healthyBootId']=boot;previous['healthyLastMonotonicMs']=mono
                if attempts and mono-previous['healthySinceMonotonicMs']>=HEALTHY_REARM_MS \
                        and previous.get('budgetEpochAtMs',0)<=attempts[-1]:
                    previous['budgetEpochAtMs']=now_ms
                    previous['lastBudgetRearmAtMs']=now_ms
            epoch=previous.get('budgetEpochAtMs',0)
            need(type(epoch)is int and epoch>=0,'monitor_budget_state_invalid')
            episode_attempts=[t for t in attempts if t>=epoch]
            cooldown=bool(attempts)and now_ms-attempts[-1]<REPAIR_COOLDOWN_MS
            row['repairAttempts24h']=len(attempts);row['repairCooldownActive']=cooldown
            row['repairAttemptsCurrentEpisode']=len(episode_attempts)
            row['budgetRearmedAtMs']=previous.get('lastBudgetRearmAtMs')
            row['budgetExhausted']=len(episode_attempts)>=REPAIR_LIMIT or len(attempts)>=ABSOLUTE_REPAIR_LIMIT
            row['confirmedFailure']=count>=FAILURE_THRESHOLD and not report['startupGraceActive']and not marker
            row['recommendedAction']='review_native_camera'if native and row['confirmedFailure']else'wait_for_bridge_reconnect'if row['confirmedFailure']and not row['sourceHealthy']else'rebuild_native_stream'if row['confirmedFailure']else'review_fmp4_startup'if startup_bad else None
            # A drifted frontend exception is not permission to rebuild a native
            # stream. Configuration review must precede any repair dispatch.
            row['repairEligible']=bool(not native and allow_repair and startup_configuration_ok and pending_recovery is None and row['confirmedFailure']and row['sourceHealthy']
                and type(row['source'].get('connectionEpoch'))is int and not cooldown and not row['budgetExhausted'])
            if row['repairEligible']:repair_candidates.append(cid)
        # Persist the cooldown/attempt BEFORE any dispatch. Restarting the
        # service cannot reset rate limits or authorize another uncertain send.
        report['recovery']=None
        if repair_candidates:
            cid=sorted(repair_candidates)[0]
            state['cameras'][cid]['repairAttempts'].append(now_ms)
            write_json(root/'state.json',state)
            history=ensure_root(root/'repair-history')
            write_json(history/(cid+'-'+str(now_ms)+'.json'),{'cameraId':cid,'atMs':now_ms,
                'sourceEpoch':rows[cid]['source'].get('connectionEpoch'),'reservedBeforeDispatch':True})
            outcome=(recover or recovery.rebuild)(config,root,cid,api=api,fetch=fetch,probe=probe)
            report['recovery']=outcome
            state['cameras'][cid]['lastRecovery']=outcome
            report['readOnly']=outcome.get('attempted')is not True
            report['configurationWritePerformed']=outcome.get('attempted')is True
            if outcome.get('ok')is True or outcome.get('attempted')is True and outcome.get('restoredOriginalTcp')is True:
                _invalidate_probe_generation(root,state,cid,now_ms,'recorder-restored')
            if outcome.get('ok')is True:
                state['cameras'][cid]['failures']=0
                state['cameras'][cid]['lastActiveProbe']=outcome['postRepairActiveProbe']
                state['cameras'][cid]['lastActiveProbeAtMs']=now_ms
                state['cameras'][cid]['activeProbeSourceEpoch']=rows[cid]['source'].get('connectionEpoch')
                state['cameras'][cid]['activeProbeGeneration']=_generation(state['cameras'][cid])
                if startup_options['enabled']:
                    state['cameras'][cid]['lastFmp4StartupProbeAtMs']=0
                    state['cameras'][cid]['nextProbeType']='fmp4'
                # The current report retains the triggering failure. The next
                # sample independently verifies recovery and all recorders.
        report['quickHealthy']=report['scopeValid']and all(r['recorderAndUbvHealthy']for r in monitored_rows)
        report['nativeHealthy']=all(r['recorderAndUbvHealthy']for r in report.get('nativeCameras',[]))
        report['fmp4StartupFailureCameraIds']=[r['cameraId']for r in report['cameras']if r['fmp4StartupNeedsReview']]
        report['activeCoverageVerified']=all(r['allActivePathsVerified']for r in monitored_rows)
        report['alerts']=[]
        if not startup_configuration_ok:
            report['alerts'].append({'code':'media_configuration_requires_review','actionRequired':True})
        if lease_state.get('requiresReview'):
            report['alerts'].append({'code':'maintenance_requires_review','actionRequired':True})
        if lease_state.get('expired')and lease_state.get('waitingForMutation'):
            report['alerts'].append({'code':'maintenance_expired_mutation_active','actionRequired':True})
        if pending_recovery is not None:
            report['alerts'].append({'code':'recovery_requires_review'if pending_recovery['requiresReview']else'recovery_restoration_pending',
                'cameraId':pending_recovery['cameraId'],'actionRequired':True})
        for row in monitored_rows:
            if row['confirmedFailure']and (row.get('readOnly')or not row['sourceHealthy']):
                report['alerts'].append({'code':'native_media_requires_attention'if row.get('readOnly')else'source_unhealthy',
                    'cameraId':row['cameraId'],'actionRequired':True})
            if row['confirmedFailure']and row['budgetExhausted']:
                report['alerts'].append({'code':'recorder_repair_budget_exhausted','cameraId':row['cameraId'],'actionRequired':True})
        report['actionRequired']=any(a['actionRequired']for a in report['alerts'])
        report['ok']=report['quickHealthy']and pending_recovery is None and startup_configuration_ok and report['activeCoverageVerified']
        report['state']='maintenance'if marker else'starting'if report['startupGraceActive']else'attention'if pending_recovery is not None or not startup_configuration_ok or report['actionRequired']else'healthy'if report['ok']else'verifying'if report['quickHealthy']and not report['fmp4StartupFailureCameraIds']else'degraded'
        report['nextProbeDueAtMs']=state.get('lastRotationAtMs',state['lastProbeAtMs'])+rotation_interval if not marker and not report['startupGraceActive']and any(r['sourceHealthy']for r in rows.values())else None
        report['atMs']=now_ms;state['lastSampleAtMs']=now_ms
        report['completedAtMs']=int(time.time()*1000)
        write_json(root/'state.json',state);write_json(root/'health.json',report)
        if public_status is not None:
            from .public_status import write
            write(public_status,report)
        return report
    except Exception as error:
        report={'schemaVersion':1,'atMs':now_ms,'ok':False,'state':'degraded',
                'errorCode':error_code(error,'monitor_sample_failed'),'repairPerformed':False,
                'mediaPersisted':False,'readOnly':not allow_repair,'handsetPlaybackVerified':False,
                'completedAtMs':int(time.time()*1000),'actionRequired':True,
                'alerts':[{'code':'monitor_sample_failed','actionRequired':True}]}
        write_json(root/'health.json',report)
        if public_status is not None:
            from .public_status import write
            write(public_status,report)
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--allow-repair',action='store_true');parser.add_argument('--once',action='store_true')
    parser.add_argument('--public-status',type=Path)
    args=parser.parse_args()
    need(args.public_status is None or args.public_status==Path('/srv/cameras/protect/status/monitor.json'),
         'public_monitor_path_invalid')
    need(not hasattr(os,'geteuid')or os.geteuid()==0,'monitor_root_required')
    os.umask(0o077);root=ensure_root(args.root);config=validate_config(read_json(args.config))
    from .safety import private_path
    lock_path=private_path(root/'monitor.lock');descriptor=os.open(str(lock_path),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    import fcntl
    try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:raise OperationError('monitor_already_running')from None
    stop=[False]
    def stopping(*_):stop[0]=True
    signal.signal(signal.SIGTERM,stopping);signal.signal(signal.SIGINT,stopping)
    startup=int(time.time()*1000)
    from ..service_liveness import notify
    try:
        notify('READY=1\nWATCHDOG=1')
        while not stop[0]:
            notify('WATCHDOG=1')
            began=time.monotonic()
            report=run_once(config,root,allow_repair=args.allow_repair,startup_at_ms=startup,public_status=args.public_status)
            notify('WATCHDOG=1')
            print(json.dumps({'atMs':report['atMs'],'state':report['state'],'ok':report['ok'],
                              'errorCode':report.get('errorCode'),'recovery':report.get('recovery')}),flush=True)
            if args.once:return 0 if report['ok']else 1
            next_due=report.get('nextProbeDueAtMs')
            wait_seconds=30
            if type(next_due)is int and next_due>report['atMs']:
                wait_seconds=min(30,max(1,(next_due-report['atMs'])/1000))
            while not stop[0]:
                remaining=wait_seconds-(time.monotonic()-began)
                if remaining<=0:break
                notify('WATCHDOG=1')
                time.sleep(min(1,remaining))
    finally:
        os.close(descriptor)
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok':False,'errorCode':error_code(error,'monitor_start_failed')}),flush=True)
        raise SystemExit(1)
