"""Projected quick/all-profile media health; credentials stay in worker memory."""
import concurrent.futures
import time
from .http import bridge_metrics, protect_json
from .protect import automatic_channel, qualities, recording_ends, selected_cameras
from .safety import VERSION, OperationError, error_code, need, validate_config
from .ubv import probe_ubv


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


def inspect(config, *, prior=None, now_ms=None, api=None, fetch=None):
    """Return a public report plus raw bootstrap in worker memory only."""
    validate_config(config); api=api or protect_json; fetch=fetch or bridge_metrics
    now_ms=int(time.time()*1000) if now_ms is None else now_ms
    bootstrap=api(config,'/api/bootstrap')
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


def run_once(config, root=None, *, mode='quick', prior=None, now_ms=None, api=None, fetch=None, probe=None,
             camera_ids=None):
    """Public readonly health API. Full means actual UBV metadata for every mode.

    Payload decoding is intentionally not claimed by metadata probes. External
    rollout gates may add bounded FFmpeg recording/RTSP decode evidence.
    """
    if mode not in ('quick','full'):raise OperationError('health_mode_invalid')
    try:
        report,bootstrap=inspect(config,prior=prior,now_ms=now_ms,api=api,fetch=fetch)
        if prior is None and api is None:
            # One fresh historical end alone cannot prove a running recorder.
            # The service supplies its previous 30-second sample; a one-shot
            # real health command observes a second snapshot instead.
            previous={row['cameraId']:{'recordingEnds':row['recordingEnds']}for row in report['cameras']}
            time.sleep(8)
            report,bootstrap=inspect(config,prior=previous,now_ms=None if now_ms is None else now_ms+8000,
                                     api=api,fetch=fetch)
            report['recordingProgressSampleSeconds']=8
        else:report['recordingProgressSampleSeconds']=None
        report['recordingProgressObserved']=all(r['advanced']is True for row in report['cameras']for r in row['recordings'])
        report['mode']=mode
        known={row['cameraId']for row in report['cameras']}
        if camera_ids is not None:
            need(isinstance(camera_ids,(list,tuple))and 1<=len(camera_ids)<=6
                 and all(isinstance(cid,str)for cid in camera_ids)
                 and len(set(camera_ids))==len(camera_ids)and set(camera_ids)<=known,'health_camera_scope_invalid')
        wanted=known if camera_ids is None else set(camera_ids)
        report['activeProbeCameraIds']=sorted(wanted)if mode=='full'else[]
        report['fullActiveCoverage']=mode=='full'and wanted==known
        if mode=='full':
            probe=probe or probe_ubv; by_id={c['id']:c for c in selected_cameras(config,bootstrap)}
            for row in report['cameras']:
                if row['cameraId']not in wanted:continue
                camera=by_id[row['cameraId']]
                row['activeProbes']=[]
                for channel in sorted(set([c for _,_,c in qualities(camera)]+[automatic_channel(camera)])):
                    result=probe(config,camera,channel,seconds=8)
                    row['activeProbes'].append(result)
                row['ok']=row['ok']and all(p.get('ok')is True for p in row['activeProbes'])
            report['ok']=report['scopeValid']and all(row['ok']for row in report['cameras'])
        return report
    except Exception as error:
        return {'schemaVersion':1,'atMs':int(time.time()*1000)if now_ms is None else now_ms,
                'mode':mode,'ok':False,'errorCode':error_code(error,'media_health_failed'),
                'readOnly':True,'mediaPersisted':False,'handsetPlaybackVerified':False}
