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
from .protect import selected_cameras
from .safety import OperationError, ensure_root, error_code, maintenance, need, read_json, validate_config, write_json
from .ubv import probe_ubv
from .fmp4 import configuration as fmp4_configuration, verify_configuration as verify_fmp4_configuration, probe_fmp4

INTERVAL_MS=30000
STARTUP_GRACE_MS=120000
FAILURE_THRESHOLD=3
PROBE_INTERVAL_MS=50000
ACTIVE_PROBE_TTL_MS=900000
URGENT_PROBE_INTERVAL_MS=30000
REPAIR_COOLDOWN_MS=900000
REPAIR_WINDOW_MS=86400000
REPAIR_LIMIT=2


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
             probe=None,recover=None,startup_probe=None):
    """Persist one sample/decision. Dependency hooks keep tests hardware-free."""
    now_ms=int(time.time()*1000)if now_ms is None else now_ms
    root=ensure_root(root);state=None
    try:
        validate_config(config);state=_state(root,now_ms,startup_at_ms)
        startup_options=fmp4_configuration(config)
        startup_configuration_ok=True
        if startup_options['enabled']:
            try:verify_fmp4_configuration(startup_options)
            except OperationError:startup_configuration_ok=False
        need(set(state['cameras'])<={b['cameraId']for b in config['bridges']},'monitor_state_scope_changed')
        marker=maintenance(root);api=api or protect_json;probe=probe or probe_ubv
        report,bootstrap=inspect(config,prior=state['cameras'],now_ms=now_ms,api=api,fetch=fetch)
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
        report['activeProbePolicy']={'seconds':8,'globalRotationIntervalMs':PROBE_INTERVAL_MS,
                                    'maximumConcurrent':1,'onSuspect':True,'resultTtlMs':ACTIVE_PROBE_TTL_MS,
                                    'urgentMinimumIntervalMs':URGENT_PROBE_INTERVAL_MS,
                                    'fmp4StartupEnabled':startup_options['enabled'],
                                    'fmp4StartupSeconds':12 if startup_options['enabled']else None}
        report['fmp4ConfigurationVerified']=startup_configuration_ok
        report['repairPolicy']={'consecutiveFailures':FAILURE_THRESHOLD,'startupGraceMs':STARTUP_GRACE_MS,
                                'cooldownMs':REPAIR_COOLDOWN_MS,'maximumPerCamera24h':REPAIR_LIMIT}
        cameras={c['id']:c for c in selected_cameras(config,bootstrap)}
        rows={r['cameraId']:r for r in report['cameras']}
        # Rollouts suppress active sessions too, avoiding false camera errors
        # and competition with deliberate deployment media gates.
        epoch_candidates=[]
        for row in report['cameras']:
            previous=state['cameras'].setdefault(row['cameraId'],{})
            epoch=row['source'].get('connectionEpoch');old=previous.get('connectionEpoch')
            if epoch is not None and old is not None and epoch!=old:previous['epochProbePending']=True
            if previous.get('failureSourceEpoch')!=epoch:
                previous['failures']=0
            previous['failureSourceEpoch']=epoch
            previous['connectionEpoch']=epoch
            row['sourceEpochChanged']=previous.get('epochProbePending')is True
            if row['sourceHealthy']and row['sourceEpochChanged']:epoch_candidates.append(row['cameraId'])
        candidates=[r['cameraId']for r in report['cameras']if r['sourceHealthy']and(
            not r['protectHealthy']or state['cameras'].get(r['cameraId'],{}).get('lastActiveProbe',{}).get('ok')is False
            or startup_options['enabled']and state['cameras'].get(r['cameraId'],{}).get('lastFmp4StartupProbe',{}).get('ok')is False)]
        selected=None
        if not marker and not report['startupGraceActive']:
            reason='rotation'
            # Urgent failures never consume the independent global rotation.
            # A permanently broken camera or exhausted repair budget must not
            # prevent every other camera from receiving fresh media evidence.
            if now_ms-state.get('lastRotationAtMs',state['lastProbeAtMs'])>=PROBE_INTERVAL_MS:
                ids=sorted(rows)
                for offset in range(len(ids)):
                    index=(state['rotation']+offset)%len(ids)
                    if rows[ids[index]]['sourceHealthy']:
                        selected=ids[index];state['rotation']=(index+1)%len(ids)
                        state['lastRotationAtMs']=now_ms;break
            else:
                urgent=epoch_candidates or candidates
                ready=[cid for cid in urgent if now_ms-state['cameras'][cid].get('lastAnyProbeAtMs',
                    state['cameras'][cid].get('lastActiveProbeAtMs',0))>=URGENT_PROBE_INTERVAL_MS]
                if ready:
                    selected=min(ready,key=lambda cid:(state['cameras'][cid].get('lastAnyProbeAtMs',
                        state['cameras'][cid].get('lastActiveProbeAtMs',0)),cid))
                    reason='source_epoch_changed'if epoch_candidates else'suspect'
            if selected is not None:
                state['lastProbeAtMs']=now_ms
                previous=state['cameras'].setdefault(selected,{})
                kind=previous.get('nextProbeType','ubv')if startup_options['enabled']else'ubv'
                if kind=='fmp4':
                    result=(startup_probe or probe_fmp4)(config,cameras[selected],rows[selected]['automaticChannel'],seconds=12) \
                        if startup_configuration_ok else {'ok':False,'errorCode':'fmp4_configuration_drift'}
                    previous['lastFmp4StartupProbe']=result;previous['lastFmp4StartupProbeAtMs']=now_ms
                    previous['fmp4ProbeSourceEpoch']=rows[selected]['source'].get('connectionEpoch')
                    previous['nextProbeType']='ubv'
                else:
                    result=probe(config,cameras[selected],rows[selected]['automaticChannel'],seconds=8)
                    previous['lastActiveProbe']=result;previous['lastActiveProbeAtMs']=now_ms
                    previous['activeProbeSourceEpoch']=rows[selected]['source'].get('connectionEpoch')
                    previous['nextProbeType']='fmp4'if startup_options['enabled']else'ubv'
                previous['lastAnyProbeAtMs']=now_ms
                if not startup_options['enabled']or kind=='fmp4':previous['epochProbePending']=False
                rows[selected]['activeProbePerformed']=True
                rows[selected]['activeProbeReason']=reason
                rows[selected]['activeProbeType']=kind
        repair_candidates=[]
        for cid,row in rows.items():
            previous=state['cameras'].setdefault(cid,{})
            active=previous.get('lastActiveProbe')
            startup=previous.get('lastFmp4StartupProbe')
            row['lastActiveProbe']=active
            row['lastActiveProbeAtMs']=previous.get('lastActiveProbeAtMs')
            def fresh(at_key,epoch_key):
                at=previous.get(at_key)
                epoch=row['source'].get('connectionEpoch')
                return type(at)is int and 0<=now_ms-at<=ACTIVE_PROBE_TTL_MS and epoch_key in previous \
                    and type(epoch)is int and previous[epoch_key]==epoch
            row['activeProbeFresh']=fresh('lastActiveProbeAtMs','activeProbeSourceEpoch')
            active_bad=row['activeProbeFresh']and isinstance(active,dict)and active.get('ok')is False
            row['activeMediaVerified']=bool(row['sourceHealthy']and row['protectHealthy']and row['activeProbeFresh']
                and isinstance(active,dict)and active.get('ok')is True)
            row['lastFmp4StartupProbe']=startup
            row['lastFmp4StartupProbeAtMs']=previous.get('lastFmp4StartupProbeAtMs')
            row['fmp4StartupProbeFresh']=bool(startup_options['enabled']and startup_configuration_ok
                and fresh('lastFmp4StartupProbeAtMs','fmp4ProbeSourceEpoch'))
            startup_bad=row['fmp4StartupProbeFresh']and isinstance(startup,dict)and startup.get('ok')is False
            row['fmp4StartupVerified']=bool(startup_options['enabled']and startup_configuration_ok
                and row['sourceHealthy']and row['protectHealthy']and isinstance(startup,dict)and startup.get('ok')is True
                and row['fmp4StartupProbeFresh'])
            row['allActivePathsVerified']=row['activeMediaVerified']and(
                not startup_options['enabled']or row['fmp4StartupVerified'])
            row['recorderAndUbvHealthy']=row['ok']and not active_bad
            row['fmp4StartupNeedsReview']=bool(startup_bad)
            row['ok']=row['recorderAndUbvHealthy']and not startup_bad
            if active_bad and row['sourceHealthy']:row['cause']='protect_media_unhealthy'
            elif startup_bad and row['recorderAndUbvHealthy']:row['cause']='protect_fmp4_startup_unhealthy'
            # A packaging/clock defect in fMP4 alone is a review finding, not
            # authority to toggle a healthy native recorder or spend its budget.
            count=previous.get('failures',0)+1 if not row['recorderAndUbvHealthy']else 0
            previous['failures']=count;row['consecutiveFailures']=count
            previous['recordingEnds']=row['recordingEnds']
            attempts=[t for t in previous.get('repairAttempts',[])if t>=now_ms-REPAIR_WINDOW_MS]
            previous['repairAttempts']=attempts
            cooldown=bool(attempts)and now_ms-attempts[-1]<REPAIR_COOLDOWN_MS
            row['repairAttempts24h']=len(attempts);row['repairCooldownActive']=cooldown
            row['confirmedFailure']=count>=FAILURE_THRESHOLD and not report['startupGraceActive']and not marker
            row['recommendedAction']='nas_watchdog'if row['confirmedFailure']and not row['sourceHealthy']else'rebuild_native_stream'if row['confirmedFailure']else'review_fmp4_startup'if startup_bad else None
            # A drifted frontend exception is not permission to rebuild a native
            # stream. Configuration review must precede any repair dispatch.
            row['repairEligible']=bool(allow_repair and startup_configuration_ok and pending_recovery is None and row['confirmedFailure']and row['sourceHealthy']
                and type(row['source'].get('connectionEpoch'))is int and not cooldown and len(attempts)<REPAIR_LIMIT)
            if row['repairEligible']:repair_candidates.append(cid)
        # Persist the cooldown/attempt BEFORE any dispatch. Restarting the
        # service cannot reset rate limits or authorize another uncertain send.
        report['recovery']=None
        if repair_candidates:
            cid=sorted(repair_candidates)[0]
            state['cameras'][cid]['repairAttempts'].append(now_ms)
            write_json(root/'state.json',state)
            outcome=(recover or recovery.rebuild)(config,root,cid,api=api,fetch=fetch,probe=probe)
            report['recovery']=outcome
            state['cameras'][cid]['lastRecovery']=outcome
            report['readOnly']=outcome.get('attempted')is not True
            report['configurationWritePerformed']=outcome.get('attempted')is True
            if outcome.get('ok')is True:
                state['cameras'][cid]['failures']=0
                state['cameras'][cid]['lastActiveProbe']=outcome['postRepairActiveProbe']
                state['cameras'][cid]['lastActiveProbeAtMs']=now_ms
                state['cameras'][cid]['activeProbeSourceEpoch']=rows[cid]['source'].get('connectionEpoch')
                if startup_options['enabled']:
                    state['cameras'][cid]['lastFmp4StartupProbeAtMs']=0
                    state['cameras'][cid]['nextProbeType']='fmp4'
                # The current report retains the triggering failure. The next
                # sample independently verifies recovery and all recorders.
        report['quickHealthy']=report['scopeValid']and all(r['recorderAndUbvHealthy']for r in report['cameras'])
        report['fmp4StartupFailureCameraIds']=[r['cameraId']for r in report['cameras']if r['fmp4StartupNeedsReview']]
        report['activeCoverageVerified']=all(r['allActivePathsVerified']for r in report['cameras'])
        report['ok']=report['quickHealthy']and pending_recovery is None and startup_configuration_ok and report['activeCoverageVerified']
        report['state']='maintenance'if marker else'starting'if report['startupGraceActive']else'attention'if pending_recovery is not None or not startup_configuration_ok else'healthy'if report['ok']else'verifying'if report['quickHealthy']and not report['fmp4StartupFailureCameraIds']else'degraded'
        report['nextProbeDueAtMs']=state.get('lastRotationAtMs',state['lastProbeAtMs'])+PROBE_INTERVAL_MS if not marker and not report['startupGraceActive']and any(r['sourceHealthy']for r in rows.values())else None
        report['atMs']=now_ms;state['lastSampleAtMs']=now_ms
        write_json(root/'state.json',state);write_json(root/'health.json',report)
        return report
    except Exception as error:
        report={'schemaVersion':1,'atMs':now_ms,'ok':False,'state':'degraded',
                'errorCode':error_code(error,'monitor_sample_failed'),'repairPerformed':False,
                'mediaPersisted':False,'readOnly':not allow_repair,'handsetPlaybackVerified':False}
        write_json(root/'health.json',report)
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--allow-repair',action='store_true');parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
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
    try:
        resumed=None
        if args.allow_repair and not maintenance(root):
            resumed=recovery.resume_pending(config,root)
        while not stop[0]:
            began=time.monotonic()
            report=run_once(config,root,allow_repair=args.allow_repair,startup_at_ms=startup)
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
                time.sleep(min(1,remaining))
    finally:
        os.close(descriptor)
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'ok':False,'errorCode':error_code(error,'monitor_start_failed')}),flush=True)
        raise SystemExit(1)
