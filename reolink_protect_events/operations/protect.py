"""Known Protect camera scope and immutable settings projection."""
import copy
import re
from .safety import digest, need, validate_config

CAMERA_FIELDS = ('id','name','host','mac','uuid','isAdopted','isThirdPartyCamera','isPairedWithAiPort',
 'recordingSettings','recordingSchedules','recordingSchedulesV2','recordingPathSettings',
 'smartDetectSettings','smartDetectZones','smartDetectLines','smartDetectRegions','motionZones','privacyZones',
 'featureFlags','ispSettings','osdSettings','audioSettings','isMicEnabled','micVolume','speakerSettings',
 'videoCodec','videoMode','hdrMode','rtspClient')
CHANNEL_FIELDS = ('id','videoId','name','enabled','width','height','fps','bitrate','fpsValues','autoFps',
                  'autoBitrate','isRtspEnabled','isAiPortRtspEnabled')
NVR_FIELDS = ('id','version','isRecordingDisabled','isRecordingMotionOnly','smartDetection',
             'recordingRetentionDurationMs','storageAllocationMode','storageRetentionMode')
OBSERVED_THIRD = frozenset(('availableProfiles','mediaVersion','errors'))


def _camera_list(bootstrap):
    """Validate the identity contract, independently of the package label."""
    need(isinstance(bootstrap, dict), 'bootstrap_invalid')
    cameras = bootstrap.get('cameras')
    need(isinstance(cameras, list) and all(isinstance(row, dict) for row in cameras), 'camera_list_invalid')
    need(all(isinstance(row.get('id'), str) and re.fullmatch('[a-f0-9]{24}', row['id'])
             for row in cameras), 'camera_identity_changed')
    by_id = {row.get('id'): row for row in cameras}
    need(len(by_id) == len(cameras), 'camera_identity_changed')
    return by_id


def observed_version(bootstrap):
    """The version is diagnostic metadata, never evidence of a capability."""
    value = bootstrap.get('nvr', {}).get('version')
    # Keep this standalone operations bundle independent of the native SQL
    # adapter; use the same bounded package-metadata syntax.
    return value if isinstance(value, str) and re.fullmatch(r'[0-9][0-9A-Za-z.+:~_-]{0,63}', value) else None


def selected_cameras(config, bootstrap):
    validate_config(config, require_credentials=False)
    by_id = _camera_list(bootstrap)
    need(isinstance(bootstrap.get('nvr'), dict), 'protect_nvr_contract_invalid')
    result = []
    for bridge in sorted(config['bridges'], key=lambda row: row['host']):
        camera = by_id.get(bridge['cameraId'])
        need(camera and camera.get('host') == bridge['host'] and camera.get('isAdopted') is True
             and camera.get('isThirdPartyCamera') is True and camera.get('isPairedWithAiPort') is not True,
             'camera_mapping_changed')
        if bridge.get('mac'):
            clean = lambda value: str(value).lower().replace(':', '').replace('-', '')
            need(clean(camera.get('mac')) == clean(bridge['mac']), 'camera_mac_changed')
        result.append(camera)
    return result


def enabled_channels(camera):
    channels = camera.get('channels')
    need(isinstance(channels, list) and 1 <= len(channels) <= 32
         and all(isinstance(channel, dict) and type(channel.get('id')) is int
                 and 0 <= channel['id'] <= 31 and type(channel.get('enabled')) is bool
                 for channel in channels), 'camera_channels_invalid')
    ids = [channel['id'] for channel in channels]
    need(len(ids) == len(set(ids)), 'camera_channels_invalid')
    enabled = {channel['id'] for channel in channels if channel['enabled']}
    allowed={0,1,2,3}if camera.get('isThirdPartyCamera')is False else{0,1,2}
    need(0 in enabled and enabled <= allowed, 'camera_channels_invalid')
    return sorted(enabled)


def qualities(camera):
    enabled = enabled_channels(camera)
    return [('high', 'recordingEnd', 0)] + ([('low', 'recordingEndLQ', 2)] if 2 in enabled else [])


def read_only_cameras(config,bootstrap):
    """An explicit native identity adds observation, never a recovery target."""
    validate_config(config,require_credentials=False)
    by_id = _camera_list(bootstrap)
    rows=[]
    for expected in config.get('readOnlyCameras',[]):
        c=by_id.get(expected['cameraId'])
        need(c is not None,'readonly_camera_identity_changed')
        need(c.get('host')==expected['host']and c.get('isAdopted')is True
             and c.get('isThirdPartyCamera')is False,'readonly_camera_mapping_changed')
        if expected.get('mac'):
            clean=lambda x:str(x).lower().replace(':','').replace('-','')
            need(clean(c.get('mac'))==clean(expected['mac']),'readonly_camera_mac_changed')
        rows.append(c)
    return rows


def automatic_channel(camera):
    enabled = enabled_channels(camera)
    return 1 if 1 in enabled else 0


def setting_snapshot(config, bootstrap, *, target=None, force_tcp=None):
    selected_cameras(config, bootstrap)
    rows = []
    # Include every camera, not just the six selected IDs, when checking an
    # exact per-camera mutation. Unrelated camera settings are preserved too.
    for camera in sorted(bootstrap['cameras'], key=lambda item: item['id']):
        row = {key: copy.deepcopy(camera[key]) for key in CAMERA_FIELDS if key in camera}
        row['channels'] = sorted([{key: copy.deepcopy(c[key]) for key in CHANNEL_FIELDS if key in c}
                                  for c in camera.get('channels', [])], key=lambda c:c['id'])
        third = {key: copy.deepcopy(value) for key, value in camera.get('thirdPartyCameraInfo', {}).items()
                 if key not in OBSERVED_THIRD}
        if camera['id'] == target:
            need('forceTcp' in third, 'force_tcp_missing'); third['forceTcp'] = force_tcp
        row['thirdPartyCameraInfo'] = third; rows.append(row)
    return {'nvr': {key: copy.deepcopy(bootstrap['nvr'][key]) for key in NVR_FIELDS if key in bootstrap['nvr']},
            'allCameraIds': sorted(c['id'] for c in bootstrap['cameras']), 'cameras': rows}


def settings_digest(config, bootstrap, **options):
    return digest(setting_snapshot(config, bootstrap, **options))


def recording_ends(camera):
    video = camera.get('stats', {}).get('video', {})
    return {quality: video.get(key, camera.get(key)) for quality, key, _ in qualities(camera)}
