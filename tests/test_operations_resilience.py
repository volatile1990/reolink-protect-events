"""Regression of the actual stalled-recovery/maintenance audit scenarios."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.operations import maintenance_lease as lease,media_health,monitor,protect,recovery
from reolink_protect_events.operations import public_status
from reolink_protect_events.operations.safety import OperationError,read_json,write_json
from reolink_protect_events.operations.transport import MaintenanceLease
from test_operations_monitor import fixture,FakeProtect,metrics


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.owner='a'*32
    def acquire(self,now=1000):return lease.change(self.root,self.owner,True,monotonic_ms=now,boot_id='boot')
    def test_expired_automatic_lease_is_archived_and_late_owner_is_fenced(self):
        self.acquire()
        result=lease.reconcile(self.root,monotonic_ms=181000,boot_id='boot')
        self.assertTrue(result['orphanArchived']);self.assertFalse(result['active'])
        self.assertTrue((self.root/'retired-maintenance'/(self.owner+'.json')).exists())
        for enabled in (True,False):
            with self.assertRaisesRegex(OperationError,'maintenance_owner_expired'):
                lease.change(self.root,self.owner,enabled,monotonic_ms=181001,boot_id='boot')
    def test_renewal_preserves_owner_and_new_boot_orphans_are_reconciled(self):
        self.acquire();self.acquire(170000)
        self.assertFalse(lease.reconcile(self.root,monotonic_ms=181000,boot_id='boot')['orphanArchived'])
        self.assertTrue(lease.reconcile(self.root,monotonic_ms=100,boot_id='nextboot')['orphanArchived'])
    def test_manual_legacy_invalid_and_foreign_markers_never_auto_release(self):
        for value in ({'owner':self.owner,'atMs':1},{}, {'schemaVersion':2,'mode':'manual','owner':self.owner}):
            write_json(self.root/'maintenance.json',value)
            result=lease.reconcile(self.root,monotonic_ms=999999999,boot_id='other')
            self.assertTrue(result['active']);self.assertTrue(result['requiresReview'])
            self.assertFalse(result['orphanArchived'])
        with self.assertRaises(OperationError):lease.change(self.root,'b'*32,True)
    def test_held_mutation_or_deployment_lock_prevents_orphan_cleanup(self):
        self.acquire()
        from reolink_protect_events.operations.locking import process_lock
        for path in [self.root/'mutation.lock',self.root/'deployment.lock']:
            with process_lock(path):
                result=lease.reconcile(self.root,monotonic_ms=181000,boot_id='boot',extra_locks=[path])
                self.assertFalse(result['orphanArchived']);self.assertTrue(result['waitingForMutation'])
        self.assertTrue(lease.reconcile(self.root,monotonic_ms=181000,boot_id='boot')['orphanArchived'])
    def test_expired_owner_cannot_start_a_mutation_before_cleanup(self):
        self.acquire()
        with patch.object(lease,'identity',return_value='boot'),patch.object(lease,'_now',return_value=181000):
            self.assertTrue(lease.blocks(self.root,self.owner))
            with self.assertRaisesRegex(OperationError,'maintenance_mutation_fenced'):
                with lease.mutation_guard(self.root,self.owner):self.fail('expired writer entered')
    def test_first_acquire_and_release_cannot_overlap_an_active_mutation(self):
        from reolink_protect_events.operations.locking import process_lock
        with process_lock(self.root/'mutation.lock'):
            with self.assertRaises((OSError,RuntimeError)):self.acquire()
        self.assertFalse((self.root/'maintenance.json').exists())
        self.acquire()
        with process_lock(self.root/'mutation.lock'):
            # Owner heartbeats must remain possible across its own bounded RPC.
            self.acquire(2000)
            with self.assertRaises((OSError,RuntimeError)):
                lease.change(self.root,self.owner,False,monotonic_ms=3000,boot_id='boot')
        self.assertTrue((self.root/'maintenance.json').exists())
    def test_new_controller_waits_for_pending_restoration_before_acquire(self):
        self.acquire();write_json(self.root/'recovery.json',{'phase':'restore-dispatching'})
        self.acquire(2000)  # An existing bounded controller can finish its repair.
        with self.assertRaisesRegex(OperationError,'maintenance_pending_restoration'):
            lease.change(self.root,'b'*32,True,monotonic_ms=182001,boot_id='boot')
        self.assertFalse(lease.status(self.root)['active'])
        self.assertTrue((self.root/'retired-maintenance'/(self.owner+'.json')).exists())
        write_json(self.root/'recovery.json',{'phase':'complete','restoredOriginalTcp':True})
        self.assertTrue(lease.change(self.root,'b'*32,True,monotonic_ms=182002,boot_id='boot')['ok'])
    def test_client_uncertain_heartbeat_fences_later_steps_and_stops_renewal(self):
        calls=[]
        def send(request):
            calls.append(request)
            if len(calls)>1:raise RuntimeError('synthetic interruption')
            return {'ok':True,'automatic':True}
        value=MaintenanceLease(send,self.owner,interval_seconds=0.005);value.start()
        import time
        deadline=time.monotonic()+1
        while value.failure is None and time.monotonic()<deadline:time.sleep(.005)
        with self.assertRaisesRegex(RuntimeError,'maintenance_heartbeat_failed'):value.check()
        value.stop(release=False)


class ClientLeaseLivenessTests(unittest.TestCase):
    def setUp(self):self.at=0.;self.requests=[];self.value=None
    def tearDown(self):
        if self.value is not None:self.value.stop(release=False)
    def send(self,request):
        self.requests.append(request);return {'ok':True,'automatic':True,'ttlMs':180000}
    def start(self,progress=60):
        self.value=MaintenanceLease(self.send,'a'*32,interval_seconds=60,
            progress_timeout_seconds=progress,clock=lambda:self.at)
        self.value.start();return self.value
    def test_local_expired_confirmation_fences_without_waiting_for_heartbeat_thread(self):
        value=self.start(progress=600);self.at=176
        with self.assertRaisesRegex(RuntimeError,'maintenance_confirmation_expired'):value.check()
        with self.assertRaisesRegex(RuntimeError,'maintenance_confirmation_expired'):value._request(True)
        self.assertEqual(len(self.requests),1)
    def test_heartbeat_cannot_extend_a_stalled_main_controller(self):
        value=self.start()
        for at in [30,59]:self.at=at;value._request(True)
        self.at=61
        with self.assertRaisesRegex(RuntimeError,'maintenance_controller_progress_stalled'):value._request(True)
        self.assertEqual(len(self.requests),3)
    def test_finite_known_rpc_activity_can_renew_but_expires_at_its_own_limit(self):
        value=self.start()
        with value.activity(120):
            for at in [30,59,89,119]:self.at=at;value._request(True)
            self.at=121
        value.check()
        with self.assertRaisesRegex(RuntimeError,'maintenance_controller_progress_stalled'):
            with value.activity(30):
                self.at=155;value._request(True)
                self.at=157
    def test_late_confirmation_after_starvation_never_resurrects_expired_owner(self):
        value=self.start(progress=600);self.at=170
        def slow(request):self.requests.append(request);self.at=176;return {'ok':True,'ttlMs':180000}
        value.send=slow
        with self.assertRaisesRegex(RuntimeError,'maintenance_confirmation_expired'):value._request(True)
        with self.assertRaisesRegex(RuntimeError,'maintenance_confirmation_expired'):value.check()
    def test_nested_rpc_activity_cannot_outlive_the_outer_operation_limit(self):
        value=self.start()
        with self.assertRaisesRegex(RuntimeError,'maintenance_controller_progress_stalled'):
            with value.activity(30):
                with value.activity(600):
                    self.at=36;value._request(True)
        self.assertEqual(len(self.requests),1)


class RecoveryProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.api=FakeProtect(self.boot,advance=True)
        self.cid=self.config['bridges'][0]['cameraId']
    def pending(self):
        c=self.api.boot['cameras'][0]
        receipt={'schemaVersion':1,'cameraId':self.cid,'phase':'restore-dispatching',
          'originalSettingsSha256':protect.settings_digest(self.config,self.api.boot),
          'temporarySettingsSha256':protect.settings_digest(self.config,self.api.boot,target=self.cid,force_tcp=True),
          'checkpoint':protect.recording_ends(c),'restoredOriginalTcp':False}
        c['thirdPartyCameraInfo']['forceTcp']=True;write_json(self.root/'recovery.json',receipt)
    def sample(self,at,**options):
        return monitor.run_once(self.config,self.root,now_ms=at,startup_at_ms=self.now-120000,
          api=self.api,fetch=metrics,probe=lambda *a,**kw:{'ok':True},**options)
    def test_transient_resume_retries_without_service_restart_and_never_repeats_true(self):
        self.pending();calls=[]
        def resume(config,root,**kw):
            calls.append(1)
            if len(calls)==1:return {'ok':False,'errorCode':'recovery_restore_failed'}
            return recovery.resume_pending(config,root,**kw,sleep=lambda _:None)
        first=self.sample(self.now,allow_repair=True,resume=resume)
        self.assertIsNotNone(first['pendingRecovery']);self.assertEqual(len(calls),1)
        self.sample(self.now+29999,allow_repair=True,resume=resume);self.assertEqual(len(calls),1)
        last=self.sample(self.now+30000,allow_repair=True,resume=resume)
        self.assertIsNone(last['pendingRecovery']);self.assertEqual(len(calls),2)
        self.assertEqual([v for _,v in self.api.patches],[None]);self.assertTrue(last['resumeRecovery']['ok'])
    def test_drifted_blocked_receipt_does_not_retry_or_write(self):
        self.pending();value=read_json(self.root/'recovery.json');value['phase']='blocked';write_json(self.root/'recovery.json',value)
        report=self.sample(self.now,allow_repair=True,resume=lambda *a,**kw:self.fail('blocked retry'))
        self.assertTrue(report['actionRequired']);self.assertEqual(report['state'],'attention');self.assertFalse(self.api.patches)
    def test_persistent_restore_dispatch_failure_is_publicly_actionable_without_another_toggle(self):
        self.pending();attempts=[]
        def unavailable(config,path,method='GET',body=None,**options):
            if method=='PATCH':
                attempts.append(body['thirdPartyCameraInfo']['forceTcp'])
                raise OSError('synthetic_patch_unavailable')
            return self.api(config,path,method=method,body=body,**options)
        def resume(config,root,**options):
            return recovery.resume_pending(config,root,**options,sleep=lambda _:None)
        for elapsed in(0,30000,90000):
            report=monitor.run_once(self.config,self.root,now_ms=self.now+elapsed,
              startup_at_ms=self.now-120000,allow_repair=True,api=unavailable,fetch=metrics,
              probe=lambda *a,**kw:{'ok':True},resume=resume,
              recover=lambda *a,**kw:self.fail('pending restoration cannot start another repair'))
            self.assertTrue(report['quickHealthy']);self.assertFalse(report['pendingRecovery']['requiresReview'])
            self.assertTrue(report['actionRequired']);self.assertEqual(report['state'],'attention')
            alert=next(row for row in report['alerts']if row['code']=='recovery_restoration_pending')
            self.assertTrue(alert['actionRequired']);self.assertEqual(alert['cameraId'],self.cid)
            self.assertTrue(public_status.projection(report)['actionRequired'])
        self.assertEqual(attempts,[None]*9)
        self.assertEqual(read_json(self.root/'recovery.json')['phase'],'restore-dispatching')
    def test_restored_flag_with_failed_postmedia_verification_completes_restoration_barrier(self):
        self.pending()
        result=recovery.resume_pending(self.config,self.root,api=self.api,fetch=metrics,
            probe=lambda *a,**kw:{'ok':False,'errorCode':'synthetic_media_failure'},sleep=lambda _:None)
        receipt=read_json(self.root/'recovery.json')
        self.assertFalse(result['ok']);self.assertTrue(result['restoredOriginalTcp'])
        self.assertEqual(receipt['phase'],'complete');self.assertIn('verificationErrorCode',receipt)
        self.assertEqual([value for _,value in self.api.patches],[None])
    def test_expired_automatic_lease_reconciles_before_pending_restore(self):
        lease.change(self.root,'a'*32,True,monotonic_ms=1,boot_id='old');self.pending()
        with patch.object(lease,'identity',return_value='new'):
            report=self.sample(self.now,allow_repair=True,
              resume=lambda config,root,**kw:recovery.resume_pending(config,root,**kw,sleep=lambda _:None))
        self.assertTrue(report['maintenanceLease']['orphanArchived']);self.assertIsNone(report['pendingRecovery'])
        self.assertEqual([v for _,v in self.api.patches],[None])
    def test_direct_rebuild_cannot_overwrite_a_blocked_receipt(self):
        self.pending();value=read_json(self.root/'recovery.json');value['phase']='blocked'
        write_json(self.root/'recovery.json',value)
        result=recovery.rebuild(self.config,self.root,self.cid,api=self.api,fetch=metrics)
        self.assertEqual(result['errorCode'],'recovery_already_pending');self.assertFalse(self.api.patches)
        self.assertEqual(read_json(self.root/'recovery.json'),value)
    def test_new_budget_episode_requires_continuous_monotone_proven_health(self):
        rows={b['cameraId']:{'failures':0,'repairAttempts':[self.now-2000000,self.now-1000000],
              'connectionEpoch':1,'failureSourceEpoch':1,'lastActiveProbe':{'ok':True},
              'lastActiveProbeAtMs':self.now,'activeProbeSourceEpoch':1}for b in self.config['bridges']}
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,'cameras':rows,
          'lastProbeAtMs':self.now,'lastRotationAtMs':self.now,'rotation':0})
        for index in range(61):
            at=self.now+index*30000
            for c in self.api.boot['cameras']:c['stats']['video']={'recordingEnd':at-1000,'recordingEndLQ':at-1000}
            # Keep independent fresh current-source UBV evidence while the
            # fake time advances, without wall-time jumps proving health.
            state=read_json(self.root/'state.json')
            for row in state['cameras'].values():row['lastActiveProbeAtMs']=at
            write_json(self.root/'state.json',state)
            report=self.sample(at,monotonic_ms=index*30000)
        self.assertTrue(all(c['repairAttempts24h']==2 for c in report['cameras']))
        self.assertTrue(all(c['repairAttemptsCurrentEpisode']==0 for c in report['cameras']))
        self.assertTrue(all(c['budgetRearmedAtMs']==at for c in report['cameras']))
    def test_public_projection_never_contains_private_receipt_or_unrecognized_text(self):
        raw={'atMs':1,'completedAtMs':2,'state':'attention','actionRequired':True,
          'recovery':{'password':'SECRET'},'alerts':[{'code':'source_unhealthy','cameraId':self.cid,
            'actionRequired':True,'details':'SECRET'},{'code':'SECRET','actionRequired':True}]}
        result=public_status.projection(raw)
        self.assertNotIn('SECRET',json.dumps(result));self.assertEqual(len(result['alerts']),1)
        destination=self.root/'monitor.json';public_status.write(destination,raw)
        self.assertEqual(json.loads(destination.read_text()),result)
    def test_large_observation_gap_or_wall_jump_cannot_rearm_budget(self):
        rows={b['cameraId']:{'failures':0,'repairAttempts':[self.now-2000000,self.now-1000000],
              'connectionEpoch':1,'failureSourceEpoch':1,'lastActiveProbe':{'ok':True},
              'lastActiveProbeAtMs':self.now,'activeProbeSourceEpoch':1}for b in self.config['bridges']}
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,'cameras':rows,
          'lastProbeAtMs':self.now,'lastRotationAtMs':self.now,'rotation':0})
        self.sample(self.now,monotonic_ms=0)
        at=self.now+1800000
        for c in self.api.boot['cameras']:c['stats']['video']={'recordingEnd':at-1000,'recordingEndLQ':at-1000}
        state=read_json(self.root/'state.json')
        for row in state['cameras'].values():row['lastActiveProbeAtMs']=at
        write_json(self.root/'state.json',state)
        report=self.sample(at,monotonic_ms=1800000)
        self.assertTrue(all(c['budgetRearmedAtMs']is None for c in report['cameras']))
    def test_absolute_daily_limit_survives_episode_rearming_and_demands_attention(self):
        rows={b['cameraId']:{'failures':2,'repairAttempts':[self.now-7200000+i*1000 for i in range(12)],
            'budgetEpochAtMs':self.now-1000,'connectionEpoch':1,'failureSourceEpoch':1,
            'lastActiveProbe':{'ok':True},'lastActiveProbeAtMs':self.now,'activeProbeSourceEpoch':1}
            for b in self.config['bridges']}
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,'cameras':rows,
          'lastProbeAtMs':self.now,'lastRotationAtMs':self.now,'rotation':0})
        for c in self.api.boot['cameras']:c['stats']['video']={'recordingEnd':self.now-180000,'recordingEndLQ':self.now-180000}
        self.api.advance=False
        report=self.sample(self.now,allow_repair=True,recover=lambda *a,**kw:self.fail('absolute limit'))
        self.assertTrue(all(c['repairAttemptsCurrentEpisode']==0 for c in report['cameras']))
        self.assertTrue(all(c['repairAttempts24h']==12 and c['budgetExhausted']for c in report['cameras']))
        self.assertTrue(report['actionRequired']);self.assertEqual(report['state'],'attention')


class QualityCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.config['allQualityMediaChecks']=True
        self.config['fmp4Startup']={'enabled':True};self.calls=[];self.at=self.now
        self.native='f'*24
        self.config['readOnlyCameras']=[{'cameraId':self.native,'host':'192.168.30.129'}]
        camera=copy.deepcopy(self.boot['cameras'][0]);camera.update(id=self.native,host='192.168.30.129',
            isThirdPartyCamera=False,connectedSince=self.now-1000000,isMicEnabled=True)
        camera['channels'].append({'id':3,'name':'Package Camera','enabled':True,'width':1600,'height':1200,'fps':3})
        self.boot['cameras'].append(camera)
    def api(self,*a,**kw):
        value=copy.deepcopy(self.boot)
        for c in value['cameras']:c['stats']['video']={'recordingEnd':self.at-1000,'recordingEndLQ':self.at-1000}
        return value
    def probe(self,kind):
        def run(config,camera,channel,**kw):
            self.calls.append((kind,camera['id'],channel));return {'ok':True,'channel':channel}
        return run
    def test_all_qualities_and_native_are_serially_probed_without_native_recovery(self):
        for index in range(28):
            self.at=self.now+index*25000;before=len(self.calls)
            report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
              api=self.api,fetch=metrics,probe=self.probe('ubv'),startup_probe=self.probe('fmp4'),
              allow_repair=True,recover=lambda *a,**kw:self.fail('healthy/native scope cannot repair'))
            self.assertEqual(len(self.calls)-before,1)
        expected={('ubv',b['cameraId'],ch)for b in self.config['bridges']for ch in [0,1,2]}
        expected|={('fmp4',b['cameraId'],1)for b in self.config['bridges']}
        expected|={('ubv',self.native,ch)for ch in [0,1,2,3]}
        self.assertEqual(set(self.calls),expected)
        self.assertTrue(report['activeCoverageVerified']);self.assertTrue(report['ok'])
        self.assertTrue(report['nativeCameras'][0]['readOnly']);self.assertFalse(report['nativeCameras'][0]['repairEligible'])
    def test_native_failure_is_visible_but_never_dispatches_reolink_toggle(self):
        def broken(config,camera,channel,**kw):return {'ok':camera['id']!=self.native,'channel':channel}
        for index in range(28):
            self.at=self.now+index*25000
            report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
              api=self.api,fetch=metrics,probe=broken,startup_probe=self.probe('fmp4'),
              allow_repair=True,recover=lambda *a,**kw:self.fail('native failure must not toggle'))
        self.assertTrue(report['actionRequired']);self.assertEqual(report['state'],'attention')
        self.assertIn('native_media_requires_attention',{x['code']for x in report['alerts']})
    def test_native_identity_drift_fails_closed_before_media(self):
        self.boot['cameras'][-1]['host']='192.168.30.130'
        report=monitor.run_once(self.config,self.root,now_ms=self.now,startup_at_ms=self.now-120000,
          api=self.api,fetch=metrics,probe=self.probe('ubv'))
        self.assertFalse(self.calls);self.assertEqual(report['errorCode'],'readonly_camera_mapping_changed')
    def test_public_full_health_includes_native_all_four_channels_and_no_native_fmp4(self):
        def advancing(*a,**kw):self.at+=100;return self.api(*a,**kw)
        report=media_health.run_once(self.config,mode='full',api=advancing,fetch=metrics,
            probe=self.probe('ubv'),startup_probe=self.probe('fmp4'))
        self.assertTrue(report['ok']);self.assertTrue(report['nativeHealthy'])
        self.assertTrue(report['fullActiveCoverage']);self.assertEqual(len(report['activeProbeCameraIds']),7)
        self.assertEqual([x[2]for x in self.calls if x[1]==self.native],[0,1,2,3])
        self.assertTrue(all(x[0]=='ubv'for x in self.calls if x[1]==self.native))
        self.assertTrue(report['fmp4StartupCoverageVerified'])
        self.calls=[]
        scoped=media_health.run_once(self.config,mode='full',camera_ids=[self.native],api=advancing,
            fetch=metrics,probe=self.probe('ubv'),startup_probe=lambda *a,**kw:self.fail('native fmp4'))
        self.assertTrue(scoped['ok']);self.assertFalse(scoped['fullActiveCoverage'])
        self.assertEqual(scoped['activeProbeCameraIds'],[self.native]);self.assertEqual(len(self.calls),4)
    def test_public_health_native_outage_never_reports_overall_healthy(self):
        self.boot['cameras'][-1]['isConnected']=False
        quick=media_health.run_once(self.config,api=self.api,fetch=metrics)
        self.assertFalse(quick['ok']);self.assertFalse(quick['nativeHealthy'])
        self.boot['cameras'][-1]['isConnected']=True
        full=media_health.run_once(self.config,mode='full',api=self.api,fetch=metrics,
            probe=lambda cfg,camera,*a,**kw:{'ok':camera['id']!=self.native},startup_probe=self.probe('fmp4'))
        self.assertFalse(full['ok']);self.assertFalse(full['nativeHealthy'])
        self.assertEqual(full['nativeCameras'][0]['cause'],'native_media_unhealthy')
    def test_native_recording_progress_is_required_by_public_health(self):
        prior={row['id']:{'recordingEnds':protect.recording_ends(row)}for row in self.boot['cameras']}
        prior[self.native]['recordingEnds']={'high':self.at-1000,'low':self.at-1000}
        report=media_health.run_once(self.config,api=self.api,fetch=metrics,prior=prior)
        self.assertFalse(report['ok']);self.assertFalse(report['recordingProgressObserved'])
        self.assertFalse(report['nativeCameras'][0]['recordings'][0]['advanced'])
    def test_fmp4_only_warning_does_not_prevent_healthy_budget_rearm(self):
        self.config.pop('readOnlyCameras');self.boot['cameras'].pop()
        rows={b['cameraId']:{'failures':0,'repairAttempts':[self.now-2000000,self.now-1000000],
            'connectionEpoch':1,'failureSourceEpoch':1,'lastActiveProbe':{'ok':True},
            'lastActiveProbeAtMs':self.now,'activeProbeSourceEpoch':1,
            'qualityProbes':{str(ch):{'atMs':self.now,'sourceEpoch':1,'result':{'ok':True}}for ch in [0,1,2]}}
            for b in self.config['bridges']}
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,'cameras':rows,
          'lastProbeAtMs':self.now,'lastRotationAtMs':self.now,'rotation':0})
        for index in range(61):
            self.at=self.now+index*30000;state=read_json(self.root/'state.json')
            for row in state['cameras'].values():
                row['lastActiveProbeAtMs']=self.at
                for q in row['qualityProbes'].values():q['atMs']=self.at
            write_json(self.root/'state.json',state)
            report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
              api=self.api,fetch=metrics,probe=self.probe('ubv'),startup_probe=lambda *a,**kw:{'ok':False},monotonic_ms=index*30000)
        self.assertTrue(all(c['repairAttemptsCurrentEpisode']==0 for c in report['cameras']))
        self.assertTrue(all(c['repairAttempts24h']==2 for c in report['cameras']))
        self.assertFalse(report['actionRequired']);self.assertTrue(report['quickHealthy']);self.assertFalse(report['ok'])


if __name__=='__main__':unittest.main()
