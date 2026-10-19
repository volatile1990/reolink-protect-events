"""Exact owned Automatic input compatibility; no infrastructure or media."""
import copy
import hashlib
import json
import stat
import types
import unittest
from unittest.mock import patch
from reolink_protect_events.operations import compatibility, protect
from reolink_protect_events.operations.safety import OperationError


def sha(data):return hashlib.sha256(data).hexdigest()


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.config={'protectUserId':'synthetic-owner','protectVersion':'7.3.70','bridges':[]}
        self.boot={'nvr':{'version':'7.3.70','isRecordingDisabled':False},'cameras':[]}
        for number in range(210,216):
            identity='%024x'%number;host='192.168.30.'+str(number)
            self.config['bridges'].append({'cameraId':identity,'host':host,
                                           'username':'synthetic','password':'synthetic'})
            self.boot['cameras'].append({'id':identity,'host':host,'mac':'%012X'%number,
                'isAdopted':True,'isThirdPartyCamera':True,'isPairedWithAiPort':False,
                'rtspClient':'gstreamer','recordingSettings':{'mode':'always'},
                'channels':[{'id':0,'enabled':True}],
                'thirdPartyCameraInfo':{'forceTcp':None,'enableRtspAudio':True}})
        self.auto_scope=[]
        for camera in self.boot['cameras']:
            camera['channels']=[{'id':cid,'enabled':True}for cid in(0,1,2)]
            third=camera['thirdPartyCameraInfo']
            third.update(rtspUrl='rtsp://'+camera['host']+':8554/main',profileToken='main')
            third.update(rtspUrlLQ='rtsp://'+camera['host']+':8554/sub',profileTokenLQ='sub')
            pin={key:camera[key]for key in('id','host','mac')}
            pin.update({field+'Sha256':sha(third[field].encode())for field in('rtspUrl','rtspUrlLQ','profileToken','profileTokenLQ')})
            self.auto_scope.append(pin)
        service=compatibility.SERVICE_PATH
        self.old=b'synthetic-reviewed-predecessor';self.new=b'synthetic-reviewed-automatic-layer'
        self.old_files={path:(self.old if path==service else ('synthetic:'+path).encode())
                        for path in compatibility.ACTIVE_FILES}
        self.expected={path:sha(value)for path,value in self.old_files.items()}
        self.data=dict(self.old_files);self.data[service]=self.new
        self.auto_files={path:('synthetic-startup:'+path).encode()for path in compatibility.AUTOMATIC_FILES}
        self.additional_files={path:('synthetic-nginx-startup:'+path).encode()
                               for path in compatibility.AUTOMATIC_ADDITIONAL_FILES}
        self.additional_expected={path:sha(value)for path,value in self.additional_files.items()}
        self.watch_files={path:('synthetic-event-watch:'+path).encode()
                          for path in compatibility.AUTOMATIC_WATCH_FILES}
        self.watch_expected={path:sha(value)for path,value in self.watch_files.items()}
        self.data.update(self.auto_files)
        self.data.update(self.additional_files)
        self.data.update(self.watch_files)
        self.auto_expected={path:sha(value)for path,value in self.auto_files.items()}
        self.receipt={'schemaVersion':1,'owner':'reolink-protect-controls:automatic-input',
            'state':'applied','protectVersion':'7.3.70','operation':'a'*32,
            'beforeSha256':sha(self.old),'afterSha256':sha(self.new),
            'guardSha256':self.auto_expected[compatibility.AUTOMATIC_GUARD_PATH],
            'dropinSha256':self.auto_expected[compatibility.AUTOMATIC_DROPIN_PATH],
            'additionalOwnedFiles':[{'path':path,'sha256':value}for path,value in self.additional_expected.items()],
            'nginxWatchState':'applied',
            'nginxWatchFiles':[{'path':path,'sha256':value}for path,value in self.watch_expected.items()],
            'baseline':{'settingsSha256':protect.settings_digest(self.config,self.boot)}}
        self.metadata=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
        self.private=types.SimpleNamespace(stat=lambda:self.metadata)
        self.reads=[];self.file_reads=[];self.layers=[{'path':'synthetic-ui-one'},{'path':'synthetic-ui-two'}]

    def assess(self, *, receipt=None, private_error=None, boot=None):
        def private(path):
            self.assertEqual(path,compatibility.AUTOMATIC_RECEIPT)
            if private_error:raise private_error
            return self.private
        def read(path, **options):
            self.assertIs(path,self.private);self.assertEqual(options,{'limit':8388608})
            self.reads.append('fixed-private-receipt')
            return copy.deepcopy(self.receipt if receipt is None else receipt)
        def read_file(path):self.file_reads.append(path);return self.data[path]
        with patch.object(compatibility,'ACTIVE_FILES',self.expected), \
             patch.object(compatibility,'AUTOMATIC_SERVICE_SHA256',sha(self.new)), \
             patch.object(compatibility,'AUTOMATIC_FILES',self.auto_expected), \
             patch.object(compatibility,'AUTOMATIC_ADDITIONAL_FILES',self.additional_expected), \
             patch.object(compatibility,'AUTOMATIC_WATCH_FILES',self.watch_expected), \
             patch.object(compatibility.automatic_profiles,'SCOPE',self.auto_scope), \
             patch.object(compatibility,'private_path',side_effect=private), \
             patch.object(compatibility,'read_json',side_effect=read):
            return compatibility.assess(self.config,api=lambda *_:copy.deepcopy(self.boot if boot is None else boot),
                file_reader=read_file,schema_reader=lambda:{'schemaVerified':True},
                layer_reader=lambda *_:copy.deepcopy(self.layers))

    def assert_drift(self, report):
        self.assertFalse(report['ok'],report)
        self.assertFalse(report['certified'])
        self.assertFalse(report['nativeWritesAllowed'])

    def test_fixed_production_chain_matches_audited_final_source(self):
        self.assertEqual(compatibility.AUTOMATIC_SERVICE_SHA256,
            '099e9dc702bce8145b83e54c3f7f41c13c55b114c6e59514fc592087631646fe')
        self.assertEqual(compatibility.ACTIVE_FILES[compatibility.SERVICE_PATH],
            'a4e546e4a9d7cd82dc130a26cc5e92fa2b69f4cdb6fce1368870a543f0d08a7f')
        self.assertEqual(compatibility.AUTOMATIC_RECEIPT.as_posix(),
            '/data/reolink-protect-controls/automatic-quality/active.json')

    def test_predecessor_remains_accepted_without_new_receipt(self):
        self.data[compatibility.SERVICE_PATH]=self.old
        report=self.assess(private_error=AssertionError('must-not-read-a-receipt'))
        self.assertTrue(report['certified'],report);self.assertTrue(report['nativeWritesAllowed'])
        self.assertNotIn('automaticInputLayer',report);self.assertEqual(self.reads,[])

    def test_exact_owned_applied_layer_is_accepted_with_settings_and_startup_proof(self):
        report=self.assess()
        self.assertTrue(report['certified'],report);self.assertTrue(report['nativeWritesAllowed'])
        self.assertTrue(report['checks']['serviceAndAacLayers'])
        self.assertTrue(report['checks']['automaticInputLayerOwnership'])
        self.assertTrue(report['automaticInputLayer']['currentProfileContractVerified'])
        self.assertEqual(report['automaticInputLayer']['currentProfileContract']['automaticReuseCameraCount'],6)
        self.assertEqual(report['automaticInputLayer']['currentProfileContract']['recordingProfileCount'],12)
        self.assertTrue(report['automaticInputLayer']['historicalSettingsBaselineMatches'])
        self.assertTrue(report['automaticInputLayer']['nginxRegenerationGuardVerified'])
        self.assertTrue(report['automaticInputLayer']['nginxEventWatchFilesVerified'])
        self.assertEqual(self.reads,['fixed-private-receipt'])

    def test_metadata_only_scope_needs_no_dummy_or_real_bridge_credentials(self):
        from reolink_protect_events.operations.safety import validate_config
        for bridge in self.config['bridges']:
            bridge.pop('username'); bridge.pop('password')
        self.assertIs(validate_config(self.config, require_credentials=False), self.config)
        with self.assertRaisesRegex(OperationError, 'monitor_bridge_credentials_invalid'):
            validate_config(self.config)
        report = self.assess()
        self.assertTrue(report['ok'], report)
        self.assertTrue(report['automaticInputLayer']['currentProfileContractVerified'])

    def test_unknown_service_cannot_be_authorized_by_a_forged_matching_receipt(self):
        unknown=b'synthetic-unknown-service';self.data[compatibility.SERVICE_PATH]=unknown
        receipt=copy.deepcopy(self.receipt);receipt['afterSha256']=sha(unknown)
        self.assert_drift(self.assess(receipt=receipt));self.assertEqual(self.reads,[])

    def test_applied_receipt_owner_schema_state_version_and_operation_are_required(self):
        for field,value in (('schemaVersion',True),('schemaVersion',2),('owner','other'),
                            ('state','prepared'),('state','needs_acceptance'),('state','rolled_back'),('protectVersion','7.3.71'),
                            ('operation','../other'),('operation','A'*32)):
            with self.subTest(field=field,value=value):
                receipt=copy.deepcopy(self.receipt);receipt[field]=value
                self.assert_drift(self.assess(receipt=receipt))

    def test_receipt_requires_exact_predecessor_successor_and_startup_hashes(self):
        for field in ('beforeSha256','afterSha256','guardSha256','dropinSha256'):
            with self.subTest(field=field):
                receipt=copy.deepcopy(self.receipt);receipt[field]='0'*64
                self.assert_drift(self.assess(receipt=receipt))

    def test_guard_and_dropin_actual_bytes_must_still_match_receipt_and_pin(self):
        for path in self.auto_files:
            with self.subTest(path=path):
                self.data[path]=b'changed-startup-file'
                self.assert_drift(self.assess());self.data[path]=self.auto_files[path]

    def test_additional_nginx_owned_paths_and_hashes_must_match_exactly(self):
        rows=self.receipt['additionalOwnedFiles']
        wrong_path=copy.deepcopy(rows);wrong_path[0]['path']='/tmp/untrusted-private-file'
        wrong_hash=copy.deepcopy(rows);wrong_hash[0]['sha256']='0'*64
        extra_key=copy.deepcopy(rows);extra_key[0]['other']='unsupported'
        for value in(None,[],rows[:1],[rows[0],rows[0]],rows+[rows[0]],wrong_path,wrong_hash,extra_key):
            with self.subTest(value=value):
                receipt=copy.deepcopy(self.receipt);receipt['additionalOwnedFiles']=value
                self.assert_drift(self.assess(receipt=receipt))
        self.assertNotIn('/tmp/untrusted-private-file',self.file_reads)

    def test_additional_nginx_actual_files_cannot_drift(self):
        for path in self.additional_files:
            with self.subTest(path=path):
                self.data[path]=b'changed-nginx-persistence-file'
                report=self.assess();self.assert_drift(report)
                self.assertEqual(report['errorCode'],'compatibility_auto_nginx_startup_changed')
                self.data[path]=self.additional_files[path]

    def test_event_watch_manifest_and_applied_state_are_required(self):
        rows=self.receipt['nginxWatchFiles'];wrong=copy.deepcopy(rows);wrong[0]['path']='/tmp/foreign-watch'
        changed_hash=copy.deepcopy(rows);changed_hash[0]['sha256']='0'*64
        for value in(None,[],rows[:1],[rows[0],rows[0]],rows+[rows[0]],wrong,changed_hash):
            with self.subTest(value=value):
                receipt=copy.deepcopy(self.receipt);receipt['nginxWatchFiles']=value
                self.assert_drift(self.assess(receipt=receipt))
        receipt=copy.deepcopy(self.receipt);receipt['nginxWatchState']='prepared'
        self.assert_drift(self.assess(receipt=receipt))
        self.assertNotIn('/tmp/foreign-watch',self.file_reads)

    def test_event_watch_unit_files_cannot_drift(self):
        for path in self.watch_files:
            with self.subTest(path=path):
                self.data[path]=b'foreign-event-watch-unit'
                report=self.assess();self.assert_drift(report)
                self.assertEqual(report['errorCode'],'compatibility_auto_nginx_watch_changed')
                self.data[path]=self.watch_files[path]

    def test_aac_modules_and_both_owned_ui_layers_remain_required(self):
        for path in self.old_files:
            if path==compatibility.SERVICE_PATH:continue
            with self.subTest(path=path):
                self.data[path]=b'changed-aac-layer'
                self.assert_drift(self.assess());self.data[path]=self.old_files[path]
        self.layers=self.layers[:1]
        report=self.assess();self.assert_drift(report)
        self.assertFalse(report['checks']['uiLayerOwnership'])

    def test_normal_user_or_motion_capability_changes_do_not_repin_historical_receipt(self):
        changed=copy.deepcopy(self.boot)
        changed['cameras'][-1]['recordingSettings']['mode']='motion'
        changed['cameras'][-1]['featureFlags']={'hasMotionDetection':False}
        changed['cameras'][-1]['thirdPartyCameraInfo']['motionDetection']='unavailable'
        changed['cameras'][0]['osdSettings']={'isNameEnabled':False}
        changed['cameras'][1]['micVolume']=25
        before=copy.deepcopy(self.receipt)
        report=self.assess(boot=changed)
        self.assertTrue(report['ok'],report)
        self.assertFalse(report['automaticInputLayer']['historicalSettingsBaselineMatches'])
        self.assertFalse(report['automaticInputLayer']['historicalSettingsBaselineEnforced'])
        self.assertNotEqual(report['currentSettingsSha256'],self.receipt['baseline']['settingsSha256'])
        self.assertEqual(self.receipt,before)

    def test_actual_automatic_identity_source_profile_channel_and_audio_drift_fail(self):
        mutations=[lambda c:c.update(mac='000000000000'),lambda c:c.update(rtspClient='different'),
            lambda c:c.update(isPairedWithAiPort=True),
            lambda c:c['channels'][1].update(enabled=False),
            lambda c:c['channels'].append({'id':2,'enabled':True}),
            lambda c:c.update(recordingChannels=[0,1,2]),
            lambda c:c['thirdPartyCameraInfo'].update(profileTokenLQ='different'),
            lambda c:c['thirdPartyCameraInfo'].update(rtspUrlLQ='rtsp://unrelated.invalid/sub'),
            lambda c:c['thirdPartyCameraInfo'].update(enableRtspAudio=False)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed=copy.deepcopy(self.boot);mutate(changed['cameras'][0])
                self.assert_drift(self.assess(boot=changed))
        for mutation in ('channels','source'):
            changed=copy.deepcopy(self.boot);camera=changed['cameras'][-1]
            if mutation=='channels':camera['channels'].append({'id':2,'enabled':True})
            else:camera['thirdPartyCameraInfo']['rtspUrl']='rtsp://unrelated.invalid:8554/main'
            self.assert_drift(self.assess(boot=changed))

    def test_sixth_dual_accepts_exact_approved_native_uris_not_guessed_paths(self):
        changed=copy.deepcopy(self.boot)
        uri='rtsp://'+changed['cameras'][-1]['host']+':8554/approved-native-onvif-profile'
        changed['cameras'][-1]['thirdPartyCameraInfo']['rtspUrl']=uri
        self.auto_scope[-1]['rtspUrlSha256']=sha(uri.encode())
        self.assertTrue(self.assess(boot=changed)['ok'])
        for field,value in(('rtspUrl',uri+'-foreign'),('profileToken','foreign-profile'),
                           ('rtspUrlLQ',uri),('profileTokenLQ','foreign-sub')):
            with self.subTest(field=field):
                mismatch=copy.deepcopy(changed)
                mismatch['cameras'][-1]['thirdPartyCameraInfo'][field]=value
                report=self.assess(boot=mismatch)
                self.assert_drift(report)
                self.assertEqual(report['errorCode'],'compatibility_auto_source_profile_changed')

    def test_previous_main_only_sixth_camera_is_rejected(self):
        changed=copy.deepcopy(self.boot);camera=changed['cameras'][-1]
        camera['channels']=[{'id':0,'enabled':True}]
        camera['thirdPartyCameraInfo'].update(rtspUrlLQ=None,profileTokenLQ=None)
        report=self.assess(boot=changed)
        self.assert_drift(report)
        self.assertEqual(report['errorCode'],'compatibility_auto_channels_changed')

    def test_receipt_is_root_private_regular_and_single_link(self):
        for field,value in (('st_uid',1000),('st_mode',stat.S_IFREG|0o644),
                            ('st_mode',stat.S_IFDIR|0o700),('st_nlink',2)):
            with self.subTest(field=field,value=value):
                old=getattr(self.metadata,field);setattr(self.metadata,field,value)
                self.assert_drift(self.assess());setattr(self.metadata,field,old)
        self.assert_drift(self.assess(private_error=OperationError('private_path_symlink')))

    def test_receipt_extra_private_material_never_appears_in_report(self):
        receipt=copy.deepcopy(self.receipt);receipt['untrustedExtra']='PRIVATE_SENTINEL_NEVER_OUTPUT'
        report=self.assess(receipt=receipt)
        self.assertTrue(report['ok'],report)
        self.assertNotIn('PRIVATE_SENTINEL_NEVER_OUTPUT',json.dumps(report))


if __name__=='__main__':unittest.main()
