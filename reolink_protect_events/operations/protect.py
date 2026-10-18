"""Known Protect camera scope and immutable settings projection."""
import copy
from .safety import VERSION, digest, need, validate_config

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


def selected_cameras(config, bootstrap, *, require_version=True):
    validate_config(config, require_credentials=False)
    need(isinstance(bootstrap, dict), 'bootstrap_invalid')
    if require_version:
        need(bootstrap.get('nvr', {}).get('version') == VERSION, 'unsupported_protect_version')
    cameras = bootstrap.get('cameras')
    need(isinstance(cameras, list) and all(isinstance(row, dict) for row in cameras), 'camera_list_invalid')
    by_id = {row.get('id'): row for row in cameras}
    need(len(by_id) == len(cameras), 'camera_identity_changed')
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


def qualities(camera):
    enabled = {c.get('id') for c in camera.get('channels', []) if isinstance(c, dict) and c.get('enabled') is True}
    need(0 in enabled and enabled <= {0, 1, 2}, 'camera_channels_invalid')
    return [('high', 'recordingEnd', 0)] + ([('low', 'recordingEndLQ', 2)] if 2 in enabled else [])


def automatic_channel(camera):
    enabled = {c.get('id') for c in camera.get('channels', []) if isinstance(c, dict) and c.get('enabled') is True}
    need(0 in enabled and enabled <= {0, 1, 2}, 'camera_channels_invalid')
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
