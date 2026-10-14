"""Projected quick/all-profile media health; credentials stay in worker memory."""
import concurrent.futures
import time
from .http import bridge_metrics, protect_json
from .protect import automatic_channel, qualities, recording_ends, selected_cameras
from .safety import VERSION, OperationError, error_code, need, validate_config
from .ubv import probe_ubv

PROGRESS_WAIT_SECONDS = 45
PROGRESS_POLL_SECONDS = 8


def _number(value):
    return type(value) in (int, float) and 0 <= value <= 10**16


def source_health(metrics):
    if not isinstance(metrics, dict):
        return {'ok':False,'errorCode':'bridge_metrics_failed','streams':[]}
    streams=[]
    for row in metrics.get('streams', [])[:8]:
        if row.get('profile') not in ('main','sub'): continue
        audio=row.get('audio') or {}
        streams.append({'profile':row['profile'],'liveVideo':row.get('liveVideo') is True,
            'videoReady':row.get('videoReady') is True,'lastVideoAgeMs':row.get('lastVideoAgeMs') if _number(row.get('lastVideoAgeMs')) else None,
            'sourceEpoch':row.get('sourceEpoch') if type(row.get('sourceEpoch')) is int else None,
            'audioAvailable':audio.get('available') is True,'audioMetadataCurrent':audio.get('metadataCurrent') is True,
            'audioSampleRate':audio.get('sampleRate') if type(audio.get('sampleRate')) is int else None})
    ready=metrics.get('status')=='ready' and bool(streams) and all(s['liveVideo'] and s['videoReady']
          and s['lastVideoAgeMs'] is not None and s['lastVideoAgeMs']<=5000 for s in streams)
    epoch=metrics.get('events',{}).get('source',{}).get('connectionEpoch')
    return {'ok':ready,'errorCode':None if ready else 'source_unhealthy','streams':streams,
            'connectionEpoch':epoch if type(epoch)is int and 0<=epoch<=10**12 else None}


def inspect(config, *, prior=None, now_ms=None, api=None, fetch=None, deadline=None, clock=None):
    """Return a public report plus raw bootstrap in worker memory only."""
    validate_config(config); real_api=api is None; api=api or protect_json; fetch=fetch or bridge_metrics
    now_ms=int(time.time()*1000) if now_ms is None else now_ms
    if deadline is not None and real_api:
        # Reserve the source requests' existing four-second total deadline.
        remaining=deadline-(clock or time.monotonic)()
        need(remaining>4,'recording_progress_timeout')
        bootstrap=api(config,'/api/bootstrap',timeout=min(8,remaining-4))
    else:bootstrap=api(config,'/api/bootstrap')
    cameras=selected_cameras(config,bootstrap)
    bridges={b['cameraId']:b for b in config['bridges']}
    def read(camera):
        try:return camera['id'], source_health(fetch(bridges[camera['id']]))
        except Exception as error:return camera['id'],{'ok':False,'errorCode':error_code(error,'bridge_metrics_failed'),'streams':[]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        sources=dict(pool.map(read,cameras))
    rows=[]; expected_count=0
    for camera in cameras:
        ends=recording_ends(camera); expected_count+=len(ends); recordings=[]
        previous=(prior or {}).get(camera['id'],{}).get('recordingEnds',{})
        for quality,end in ends.items():
            age=now_ms-end if _number(end) else None
            old=previous.get(quality)
            advanced=end>old if _number(end) and _number(old) else None
            recordings.append({'quality':quality,'endMs':end if _number(end) else None,'ageMs':age,
                'fresh':age is not None and -5000<=age<=120000,'advanced':advanced})
        source=sources[camera['id']]
        connected=camera.get('state')=='CONNECTED' and camera.get('isConnected') is not False
        recording_ok=bool(recordings) and all(r['fresh'] and r['advanced'] is not False for r in recordings)
        rows.append({'cameraId':camera['id'],'host':camera['host'],'source':source,
            'protectConnected':connected,'recordings':recordings,'recordingEnds':ends,
            'automaticChannel':automatic_channel(camera),'enabledChannels':sorted(c['id'] for c in camera.get('channels',[])if c.get('enabled') is True),
            'sourceHealthy':source['ok'],'protectHealthy':connected and recording_ok,
            'cause':None if source['ok'] and connected and recording_ok else 'source_unhealthy'if not source['ok']else'protect_media_unhealthy',
            'ok':source['ok'] and connected and recording_ok})
    scope_ok=expected_count==11
    return {'schemaVersion':1,'atMs':now_ms,'protectVersion':bootstrap['nvr']['version'],
            'ok':scope_ok and all(r['ok']for r in rows),'expectedRecordingProfiles':expected_count,
            'scopeValid':scope_ok,'cameras':rows,'readOnly':True,'mediaPersisted':False,
            'handsetPlaybackVerified':False},bootstrap


def _available(report):
    """Only fresh, connected input may wait for cached recorder statistics."""
    return report['scopeValid'] and all(row['sourceHealthy'] and row['protectConnected']
        and bool(row['recordings']) and all(r['fresh'] for r in row['recordings'])
        for row in report['cameras'])


def _progress(report, wanted=None):
    rows=[row for row in report['cameras'] if wanted is None or row['cameraId'] in wanted]
    return report['scopeValid'] and bool(rows) and all(bool(row['recordings'])
        and all(r['advanced'] is True for r in row['recordings']) for row in rows)


def run_once(config, root=None, *, mode='quick', prior=None, now_ms=None, api=None, fetch=None, probe=None,
             camera_ids=None, clock=None, sleep=None):
    """Public readonly health API. Full means actual UBV metadata for every mode.

    Payload decoding is intentionally not claimed by metadata probes. External
    rollout gates may add bounded FFmpeg recording/RTSP decode evidence.
    """
    if mode not in ('quick','full'):raise OperationError('health_mode_invalid')
    observe=prior is None and (api is None or clock is not None)
    clock=clock or time.monotonic; sleep=sleep or time.sleep
    began=clock(); deadline=began+PROGRESS_WAIT_SECONDS
    def sample_time():
        return None if now_ms is None else now_ms+int((clock()-began)*1000)
    try:
        report,bootstrap=inspect(config,prior=prior,now_ms=sample_time(),api=api,fetch=fetch,
                                 deadline=deadline if observe else None,clock=clock)
        # Never replace this checkpoint while waiting: different cached profiles
        # may advance in different responses, and all eleven must advance.
        previous=prior if prior is not None else {
            row['cameraId']:{'recordingEnds':dict(row['recordingEnds'])}for row in report['cameras']}
        known={row['cameraId']for row in report['cameras']}
        if camera_ids is not None:
            need(isinstance(camera_ids,(list,tuple))and 1<=len(camera_ids)<=6
                 and all(isinstance(cid,str)for cid in camera_ids)
                 and len(set(camera_ids))==len(camera_ids)and set(camera_ids)<=known,'health_camera_scope_invalid')
        wanted=known if camera_ids is None else set(camera_ids)
        timeout=False
        if observe:
            # Protect publishes recording ends in cached blocks. A fresh value
            # can legitimately stay unchanged across several eight-second reads.
            while _available(report) and not _progress(report):
                remaining=deadline-clock()
                if remaining<=0:timeout=True;break
                if api is None and remaining<=5:
                    sleep(remaining);timeout=True;break
                sleep(min(PROGRESS_POLL_SECONDS,remaining-5 if api is None else remaining))
                if clock()>=deadline:timeout=True;break
                report,bootstrap=inspect(config,prior=previous,now_ms=sample_time(),api=api,fetch=fetch,
                                         deadline=deadline,clock=clock)
        report['activeProbeCameraIds']=[];report['fullActiveCoverage']=False
        if mode=='full' and report['ok'] and not timeout:
            probe=probe or probe_ubv; by_id={c['id']:c for c in selected_cameras(config,bootstrap)}
            evidence={}
            for row in report['cameras']:
                if row['cameraId']not in wanted:continue
                camera=by_id[row['cameraId']]
                evidence[row['cameraId']]=[]
                for channel in sorted(set([c for _,_,c in qualities(camera)]+[automatic_channel(camera)])):
                    result=probe(config,camera,channel,seconds=8)
                    evidence[row['cameraId']].append(result)
            # The full sweep can last more than two minutes. Refresh both source
            # and recording age, preserving the original comparison checkpoint.
            report,bootstrap=inspect(config,prior=previous,now_ms=sample_time(),api=api,fetch=fetch)
            for row in report['cameras']:
                if row['cameraId']not in evidence:continue
                row['activeProbes']=evidence[row['cameraId']]
                active_ok=all(p.get('ok')is True for p in row['activeProbes'])
                row['ok']=row['ok']and active_ok
                if not active_ok and row['sourceHealthy']:row['cause']='protect_media_unhealthy'
            report['activeProbeCameraIds']=sorted(evidence)
            report['fullActiveCoverage']=set(evidence)==known
            report['ok']=report['scopeValid']and all(row['ok']for row in report['cameras'])
        report['recordingProgressSampleSeconds']=round(clock()-began,3) if observe or mode=='full' else None
        report['recordingProgressObserved']=_progress(report)
        report['scopedRecordingProgressObserved']=_progress(report,wanted)
        report['mode']=mode
        if timeout:
            report['ok']=False;report['errorCode']='recording_progress_timeout'
        return report
    except Exception as error:
        return {'schemaVersion':1,'atMs':int(time.time()*1000)if now_ms is None else now_ms,
                'mode':mode,'ok':False,'errorCode':error_code(error,'media_health_failed'),
                'readOnly':True,'mediaPersisted':False,'handsetPlaybackVerified':False}
