"""Current routing contract of the exact audited Automatic-input service bytes."""
import hashlib
from .protect import qualities, selected_cameras
from .safety import need

SCOPE = [
    {
        "id": "6ac83993001a6d03e4001690",
        "host": "192.168.30.210",
        "mac": "0242C0A81ED2",
        "rtspUrlSha256": "844fc5e209ded98286bb5d3adf4c9cf7da3b1b9a96e60c615dfdbba82e0c5a97",
        "rtspUrlLQSha256": "ffa36c199adafe340da306d6af3b7932c3c5d17daa6619ce04ace2512faa4f23",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    },
    {
        "id": "6ac83fed00bd6d03e4001b81",
        "host": "192.168.30.211",
        "mac": "0242C0A81ED3",
        "rtspUrlSha256": "e3b8e445ab583cd866be99281ed10c466c1545f3aab02ffb6e0bce7ecc906720",
        "rtspUrlLQSha256": "0a7a7f6e9b92cc77199c099a3a3a956984b5671c8dd0471ccf377ce1e62fe592",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    },
    {
        "id": "6ac844bd01096d03e4001f22",
        "host": "192.168.30.212",
        "mac": "0242C0A81ED4",
        "rtspUrlSha256": "ec6b791ce6c549e19a8e348d9686ec4dade3b69ff315922052f74dcda93c2833",
        "rtspUrlLQSha256": "4c1f0cfc5d953e11b1a9fec300cb1926bf235e24770f7ade7eda5443dd6bcdd9",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    },
    {
        "id": "6ac844bf02026d03e4001f5f",
        "host": "192.168.30.213",
        "mac": "0242C0A81ED5",
        "rtspUrlSha256": "44cd22938ca141e72209564dcdeb7578e3304ba5507f7b94e9b2bbf01f809ba0",
        "rtspUrlLQSha256": "d043468f3a7df21b69ce914687de31c805b232776b5f19ab41e0755f4deefa6d",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    },
    {
        "id": "6ac8ae7001ab6d03e4006410",
        "host": "192.168.30.214",
        "mac": "0242C0A81ED6",
        "rtspUrlSha256": "4f7fda8c1f0f334acb0ef3e170c448e622780917915ee41e51ae78ef32da9624",
        "rtspUrlLQSha256": "d17898a2a2042653661bbb18900c1e22dbd15a5a7ce899abd06296aaddeedd88",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    },
    {
        "id": "6ac8ae7102b76d03e4006447",
        "host": "192.168.30.215",
        "mac": "0242C0A81ED7",
        "rtspUrlSha256": "176afa9c426caf315822c909e99553eb3ee356e140acc93b20b3b51289bee319",
        "rtspUrlLQSha256": "a5ebe2746663032667a9a0ad4ec92bb49b02ef802e6ac956c61ddfa38ae11904",
        "profileTokenSha256": "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605",
        "profileTokenLQSha256": "ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
    }
]


def source_hash(value):
    return hashlib.sha256(value.encode()).hexdigest() if isinstance(value, str) and 0 < len(value) <= 8192 else None


def verify(config, bootstrap):
    """Check source identity/routing, never historic user preferences."""
    cameras = selected_cameras(config, bootstrap)
    by = {row['id']: row for row in cameras}
    need(len(SCOPE) == 6 and set(by) == {row['id'] for row in SCOPE},
         'compatibility_auto_camera_scope_changed')
    for pin in SCOPE:
        camera = by[pin['id']]
        need(camera.get('host') == pin['host'] and camera.get('mac') == pin['mac']
             and camera.get('isAdopted') is True and camera.get('isThirdPartyCamera') is True
             and camera.get('isPairedWithAiPort') is False and camera.get('rtspClient') == 'gstreamer',
             'compatibility_auto_camera_identity_changed')
        third = camera.get('thirdPartyCameraInfo')
        need(isinstance(third, dict) and third.get('enableRtspAudio') is True,
             'compatibility_auto_audio_disabled')
        channels = camera.get('channels')
        need(isinstance(channels, list) and channels and all(isinstance(c, dict)
             and type(c.get('id')) is int and c['id'] in (0, 1, 2) for c in channels)
             and len({c['id'] for c in channels}) == len(channels),
             'compatibility_auto_channels_changed')
        enabled = {c['id'] for c in channels if c.get('enabled') is True}
        need(enabled == {0, 1, 2} and len(channels) == 3,
             'compatibility_auto_channels_changed')
        # Bootstrap omits the native computed recordingChannels getter. The
        # fixed 7.3.70 service maps HIGH/LOW to recording channels 0/2; verify
        # current enabled profiles through that same existing contract.
        recording = {row[2] for row in qualities(camera)}
        want_recording = {0, 2}
        need(recording == want_recording, 'compatibility_auto_recording_profiles_changed')
        if 'recordingChannels' in camera:
            values = camera['recordingChannels']
            need(isinstance(values, list) and all(type(v) is int for v in values)
                 and len(values) == len(set(values)) and set(values) == want_recording,
                 'compatibility_auto_recording_profiles_changed')
        need(all(source_hash(third.get(field)) == pin[field + 'Sha256']
                 for field in ('rtspUrl', 'rtspUrlLQ', 'profileToken', 'profileTokenLQ')),
             'compatibility_auto_source_profile_changed')
    return {'cameraCount': 6, 'automaticReuseCameraCount': 6,
            'mainOnlyCameraCount': 0, 'recordingProfileCount': 12,
            'audioEnabled': True, 'sourceIdentityAndProfilePinsVerified': True,
            'recordingChannelsBasis': 'audited-7.3.70-enabled-profile-contract'}
