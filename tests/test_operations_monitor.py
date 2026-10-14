"""Persistent monitor decisions and narrow repairs against synthetic Protect."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from reolink_protect_events.operations import compatibility, media_health, monitor, protect, recovery
from reolink_protect_events.operations.safety import OperationError, read_json, write_json


def fixture():
    now=int(time.time()*1000)
    bridges=[{'host':'192.168.30.'+str(n),'cameraId':'%024x'%n,'mac':'02:00:00:00:00:%02x'%n,
              'username':'synthetic-user','password':'synthetic-secret-never-output'}for n in range(210,216)]
    config={'protectUserId':'test-owner','protectVersion':'7.3.70','bridges':bridges}
    cameras=[]
    for b in bridges:
        channels=[{'id':0,'name':'High','enabled':True,'width':320,'height':180,'fps':20}]
        if not b['host'].endswith('.215'):
            channels.extend([{'id':1,'name':'Medium','enabled':True,'width':160,'height':90,'fps':20},
                             {'id':2,'name':'Low','enabled':True,'width':160,'height':90,'fps':20}])
        cameras.append(dict(id=b['cameraId'],host=b['host'],mac=b['mac'],name='Synthetic camera',
            isAdopted=True,isThirdPartyCamera=True,isPairedWithAiPort=False,isProvisioned=True,
            state='CONNECTED',isConnected=True,hasRecordingStarted=True,videoReconfigurationInProgress=False,
            rtspClient='gstreamer',channels=channels,recordingSettings={'mode':'always'},
            thirdPartyCameraInfo={'forceTcp':None,'enableRtspAudio':True,'hasAudio':True,
                'rtspUrl':'rtsp://private-user:PRIVATE_URL_SECRET@192.168.30.210/main',
                'rtspUrlLQ':'rtsp://private-user:PRIVATE_URL_SECRET@192.168.30.210/sub'},
            stats={'video':{'recordingEnd':now,'recordingEndLQ':now}}))
    return config,{'nvr':{'version':'7.3.70','isRecordingDisabled':False},'cameras':cameras},now


def metrics(_):
    return {'status':'ready','events':{'source':{'connectionEpoch':1}},'streams':[{'profile':'main','videoReady':True,'liveVideo':True,'lastVideoAgeMs':100,
        'sourceEpoch':1,'audio':{'available':True,'metadataCurrent':True,'sampleRate':16000}}]}


class FakeProtect:
    def __init__(self,boot,advance=False):
        self.boot=copy.deepcopy(boot);self.advance=advance;self.patches=[];self.crash_after_true=False;self.drift=False
    def __call__(self,config,path,method='GET',body=None,**_):
        if method=='GET':
            if self.advance:
                for c in self.boot['cameras']:
                    for k in ('recordingEnd','recordingEndLQ'):c['stats']['video'][k]+=100
            return copy.deepcopy(self.boot)
        cid=path.rsplit('/',1)[-1];value=body['thirdPartyCameraInfo']['forceTcp']
        self.patches.append((cid,value))
        next(c for c in self.boot['cameras']if c['id']==cid)['thirdPartyCameraInfo']['forceTcp']=value
        if value is True and self.drift:self.boot['cameras'][-1]['recordingSettings']={'mode':'motion'}
        if value is True and self.crash_after_true:raise RuntimeError('PRIVATE_URL_SECRET bearer-token')
        return {}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.api=FakeProtect(self.boot);self.probes=[];self.repairs=[]
    def tearDown(self):self.temp.cleanup()
    def probe(self,config,camera,channel,**_):
        self.probes.append((camera['id'],channel));return {'ok':True,'channel':channel,'mediaSaved':False}
    def repair(self,config,root,cid,**_):
        self.repairs.append(cid);return {'ok':True,'attempted':True,'postRepairActiveProbe':{'ok':True}}
    def sample(self,at=None,**options):
        return monitor.run_once(self.config,self.root,now_ms=self.now if at is None else at,
            startup_at_ms=self.now-120000,api=self.api,fetch=metrics,probe=self.probe,recover=self.repair,**options)
    def test_quick_profiles_and_automatic_channel_are_actual(self):
        report=media_health.run_once(self.config,api=self.api,fetch=metrics,now_ms=self.now)
        self.assertTrue(report['ok']);self.assertEqual(report['expectedRecordingProfiles'],11)
        self.assertEqual([r['automaticChannel']for r in report['cameras']],[1,1,1,1,1,0])
    def test_full_live_scope_is_explicit_and_invalid_ids_never_probe(self):
        cid=self.config['bridges'][-1]['cameraId']
        report=media_health.run_once(self.config,mode='full',camera_ids=[cid],api=self.api,fetch=metrics,probe=self.probe)
        self.assertTrue(report['ok']);self.assertFalse(report['fullActiveCoverage'])
        self.assertEqual(report['activeProbeCameraIds'],[cid]);self.assertEqual(self.probes,[(cid,0)])
        for ids in ([],[cid,cid],['f'*24]):
            report=media_health.run_once(self.config,mode='full',camera_ids=ids,api=self.api,fetch=metrics,probe=self.probe)
            self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'health_camera_scope_invalid')
        self.assertEqual(self.probes,[(cid,0)])
        self.probes=[]
        report=media_health.run_once(self.config,mode='full',api=self.api,fetch=metrics,probe=self.probe)
        self.assertTrue(report['fullActiveCoverage']);self.assertEqual(len(self.probes),16)
    def test_one_rotating_probe_per_50s_covers_all_cameras_in_five_minutes(self):
        self.api.advance=True
        for i in range(6):
            for camera in self.api.boot['cameras']:
                for key in ('recordingEnd','recordingEndLQ'):camera['stats']['video'][key]=self.now+i*50000
            self.sample(self.now+i*50000)
        self.assertEqual(len(self.probes),6)
        self.assertEqual(len({cid for cid,_ in self.probes}),6)
        self.assertEqual(self.probes[-1][1],0)
    def test_source_epoch_change_is_prioritized_and_maintenance_keeps_it_pending(self):
        self.api.advance=True;self.sample()
        cid=self.config['bridges'][-1]['cameraId']
        def changed(bridge):
            value=metrics(bridge)
            if bridge['cameraId']==cid:value['events']['source']['connectionEpoch']=2
            return value
        write_json(self.root/'maintenance.json',{})
        report=monitor.run_once(self.config,self.root,now_ms=self.now+30000,startup_at_ms=self.now-120000,
            api=self.api,fetch=changed,probe=self.probe)
        self.assertEqual(len(self.probes),1)
        self.assertTrue(next(r for r in report['cameras']if r['cameraId']==cid)['sourceEpochChanged'])
        (self.root/'maintenance.json').unlink()
        report=monitor.run_once(self.config,self.root,now_ms=self.now+31000,startup_at_ms=self.now-120000,
            api=self.api,fetch=changed,probe=self.probe)
        self.assertEqual(self.probes[-1],(cid,0))
        self.assertEqual(next(r for r in report['cameras']if r['cameraId']==cid)['activeProbeReason'],'source_epoch_changed')
    def test_three_failures_are_required_and_source_failure_never_repairs(self):
        self.sample(allow_repair=True)
        for i in range(1,3):self.sample(self.now+i*30000,allow_repair=True)
        self.assertFalse(self.repairs)
        report=self.sample(self.now+90000,allow_repair=True)
        self.assertEqual(len(self.repairs),1)
        self.assertTrue(report['recovery']['ok'])
        other=Path(self.temp.name)/'other';other.mkdir(mode=0o700)
        def bad(_):return {'status':'waiting-for-camera','streams':[]}
        for i in range(4):
            report=monitor.run_once(self.config,other,now_ms=self.now+i*30000,
                startup_at_ms=self.now-120000,allow_repair=True,api=self.api,fetch=bad,probe=self.probe,recover=self.repair)
        self.assertEqual(len(self.repairs),1)
        self.assertTrue(all(r['recommendedAction']=='nas_watchdog'for r in report['cameras']))
    def test_startup_and_maintenance_suppress_probes_and_repairs(self):
        for i in range(4):
            report=monitor.run_once(self.config,self.root,now_ms=self.now+i*30000,
                startup_at_ms=self.now,allow_repair=True,api=self.api,fetch=metrics,probe=self.probe,recover=self.repair)
        self.assertFalse(self.probes);self.assertFalse(self.repairs)
        write_json(self.root/'maintenance.json',{'untrusted':'PRIVATE_URL_SECRET'})
        report=self.sample(self.now+200000,allow_repair=True)
        self.assertTrue(report['maintenanceActive']);self.assertFalse(self.probes);self.assertFalse(self.repairs)
        self.assertNotIn('PRIVATE_URL_SECRET',json.dumps(report))
    def test_persisted_repair_budget_survives_monitor_restart(self):
        cid=self.config['bridges'][0]['cameraId']
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
            'lastProbeAtMs':self.now,'rotation':0,'cameras':{cid:{'failures':2,
            'recordingEnds':{'high':self.now,'low':self.now},'repairAttempts':[self.now-1200000,self.now-1000000]}}})
        report=self.sample(self.now+30000,allow_repair=True)
        row=next(r for r in report['cameras']if r['cameraId']==cid)
        self.assertTrue(row['confirmedFailure']);self.assertFalse(row['repairEligible']);self.assertFalse(self.repairs)
    def test_invalid_state_and_unknown_version_never_dispatch(self):
        write_json(self.root/'state.json',{'schemaVersion':2,'repairAttempts':[]})
        report=self.sample(allow_repair=True);self.assertFalse(report['ok']);self.assertFalse(self.repairs)
        self.assertEqual(report['errorCode'],'monitor_state_invalid')
        self.api.boot['nvr']['version']='future'
        report=media_health.run_once(self.config,api=self.api,fetch=metrics)
        self.assertEqual(report['errorCode'],'unsupported_protect_version')
    def test_upstream_secrets_are_not_emitted(self):
        def bad(_):raise RuntimeError('rtsp://PRIVATE_URL_SECRET@upstream bearer-token')
        report=media_health.run_once(self.config,api=self.api,fetch=bad,now_ms=self.now)
        self.assertFalse(report['ok']);self.assertNotIn('PRIVATE_URL_SECRET',json.dumps(report))
    def test_unrestored_blocked_receipt_requires_attention_even_when_media_is_healthy(self):
        self.api.advance=True
        write_json(self.root/'recovery.json',{'schemaVersion':1,'cameraId':self.config['bridges'][0]['cameraId'],
            'phase':'blocked','restoredOriginalTcp':False})
        report=self.sample(allow_repair=True)
        self.assertFalse(report['ok']);self.assertEqual(report['state'],'attention')
        self.assertTrue(report['pendingRecovery']['requiresReview']);self.assertFalse(self.repairs)
    def test_assessment_cannot_certify_future_matching_schema(self):
        self.api.boot['nvr']['version']='7.3.71';called=[]
        report=compatibility.assess(self.config,api=self.api,schema_reader=lambda:called.append(True))
        self.assertEqual(report['state'],'unsupported');self.assertFalse(report['certified'])
        self.assertFalse(report['nativeWritesAllowed']);self.assertFalse(called)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.api=FakeProtect(self.boot,advance=True);self.probes=[]
    def tearDown(self):self.temp.cleanup()
    def probe(self,config,camera,channel,**_):
        self.probes.append(channel);return {'ok':True,'channel':channel,'mediaSaved':False}
    def run_repair(self,index=0,**options):
        return recovery.rebuild(self.config,self.root,self.config['bridges'][index]['cameraId'],
            api=self.api,fetch=metrics,probe=self.probe,sleep=lambda _:None,**options)
    def test_dual_and_single_profile_restore_and_verify_actual_automatic(self):
        before=protect.settings_digest(self.config,self.api.boot)
        report=self.run_repair()
        self.assertTrue(report['ok']);self.assertTrue(report['restoredOriginalTcp']);self.assertEqual(report['recordingProfiles'],2)
        self.assertEqual(self.probes,[1]);self.assertEqual(protect.settings_digest(self.config,self.api.boot),before)
        report=self.run_repair(5)
        self.assertTrue(report['ok']);self.assertEqual(report['recordingProfiles'],1);self.assertEqual(self.probes,[1,0])
        self.assertEqual([flag for _,flag in self.api.patches],[True,None,True,None])
        self.assertNotIn('PRIVATE_URL_SECRET',json.dumps(report))
    def test_ambiguous_true_response_still_restores_original(self):
        self.api.crash_after_true=True;report=self.run_repair()
        self.assertFalse(report['ok']);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual([flag for _,flag in self.api.patches],[True,None])
        self.assertNotIn('PRIVATE_URL_SECRET',json.dumps(report))
    def test_unrelated_settings_drift_blocks_restore_cas(self):
        self.api.drift=True;report=self.run_repair()
        self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'recovery_settings_drift')
        self.assertEqual([flag for _,flag in self.api.patches],[True])
        self.assertEqual(read_json(self.root/'recovery.json')['phase'],'blocked')
    def test_missing_source_audio_or_maintenance_never_patches(self):
        def bad(_):
            value=metrics(None);value['streams'][0]['audio']['available']=False;return value
        cid=self.config['bridges'][0]['cameraId']
        report=recovery.rebuild(self.config,self.root,cid,api=self.api,fetch=bad,probe=self.probe)
        self.assertEqual(report['errorCode'],'recovery_source_audio_unhealthy');self.assertFalse(self.api.patches)
        write_json(self.root/'maintenance.json',{})
        report=self.run_repair();self.assertEqual(report['errorCode'],'recovery_maintenance_active');self.assertFalse(self.api.patches)
    def test_controller_can_only_use_its_exact_private_maintenance_owner(self):
        owner='a'*32;write_json(self.root/'maintenance.json',{'owner':owner})
        report=self.run_repair();self.assertEqual(report['errorCode'],'recovery_maintenance_active')
        report=self.run_repair(maintenance_owner='b'*32)
        self.assertEqual(report['errorCode'],'recovery_maintenance_active');self.assertFalse(self.api.patches)
        report=self.run_repair(maintenance_owner='not-an-owner')
        self.assertEqual(report['errorCode'],'maintenance_owner_invalid');self.assertFalse(self.api.patches)
        report=self.run_repair(maintenance_owner=owner)
        self.assertTrue(report['ok']);self.assertEqual([flag for _,flag in self.api.patches],[True,None])
        self.assertEqual(read_json(self.root/'recovery.json')['maintenanceOwner'],owner)
    def test_post_repair_active_failure_is_not_reported_as_success(self):
        cid=self.config['bridges'][0]['cameraId']
        report=recovery.rebuild(self.config,self.root,cid,api=self.api,fetch=metrics,
            probe=lambda *_a,**_k:{'ok':False},sleep=lambda _:None)
        self.assertFalse(report['ok']);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual(report['errorCode'],'recovery_active_verification_failed')
    def test_pending_true_flag_is_restored_after_process_restart(self):
        cid=self.config['bridges'][0]['cameraId']
        receipt={'schemaVersion':1,'cameraId':cid,'phase':'toggle-dispatching',
            'originalSettingsSha256':protect.settings_digest(self.config,self.api.boot),
            'temporarySettingsSha256':protect.settings_digest(self.config,self.api.boot,target=cid,force_tcp=True),
            'checkpoint':protect.recording_ends(self.api.boot['cameras'][0])}
        self.api.boot['cameras'][0]['thirdPartyCameraInfo']['forceTcp']=True
        write_json(self.root/'recovery.json',receipt)
        report=recovery.resume_pending(self.config,self.root,api=self.api,fetch=metrics,probe=self.probe,sleep=lambda _:None)
        self.assertTrue(report['ok']);self.assertEqual([flag for _,flag in self.api.patches],[None])
        self.assertTrue(report['postRepairActiveProbe']['ok']);self.assertEqual(self.probes,[1])
    def test_pending_resume_verification_failure_keeps_original_and_is_not_success(self):
        cid=self.config['bridges'][-1]['cameraId'];camera=self.api.boot['cameras'][-1]
        receipt={'schemaVersion':1,'cameraId':cid,'phase':'toggle-dispatching',
            'originalSettingsSha256':protect.settings_digest(self.config,self.api.boot),
            'temporarySettingsSha256':protect.settings_digest(self.config,self.api.boot,target=cid,force_tcp=True),
            'checkpoint':protect.recording_ends(camera)}
        camera['thirdPartyCameraInfo']['forceTcp']=True;write_json(self.root/'recovery.json',receipt)
        report=recovery.resume_pending(self.config,self.root,api=self.api,fetch=metrics,
            probe=lambda *_a,**_k:{'ok':False},sleep=lambda _:None)
        self.assertFalse(report['ok']);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual(report['errorCode'],'recovery_active_verification_failed')
        self.assertEqual([flag for _,flag in self.api.patches],[None])


if __name__=='__main__':unittest.main()
