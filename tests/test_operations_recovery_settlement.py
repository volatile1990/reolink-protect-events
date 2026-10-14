"""Bounded native media settlement and restore CAS, entirely offline."""
import copy
from pathlib import Path
import tempfile
import unittest

from test_operations_monitor import FakeProtect, fixture, metrics
from reolink_protect_events.operations import protect, recovery
from reolink_protect_events.operations.safety import read_json, write_json


def empty_probe():
    return {'ok':False,'errorCode':None,'websocketFrames':0,'binaryBytesDiscarded':0,'tracks':[],
            'checks':{'transport':True,'parser':False,'videoPictures':False,'audioPictures':False,
                      'aacCompatibility':False,'continuousMediaTimes':True},'mediaSaved':False}


def good_probe():
    return {'ok':True,'errorCode':None,'websocketFrames':80,'binaryBytesDiscarded':1024,'tracks':[],
            'checks':{'transport':True,'parser':True,'videoPictures':True,'audioPictures':True,
                      'aacCompatibility':True,'continuousMediaTimes':True},'mediaSaved':False}


class Clock:
    def __init__(self):self.elapsed=0;self.sleeps=[]
    def __call__(self):return self.elapsed
    def sleep(self,seconds):self.sleeps.append(seconds);self.elapsed+=seconds


class RecoverySettlementTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.api=FakeProtect(self.boot,advance=True)
        self.cid=self.config['bridges'][0]['cameraId'];self.clock=Clock();self.calls=[]
        self.original=protect.settings_digest(self.config,self.api.boot)
    def tearDown(self):self.temp.cleanup()
    def probe(self,responses):
        responses=iter(responses)
        def run(config,camera,channel,seconds):
            self.assertEqual(seconds,8);self.assertEqual(channel,1)
            current=next(c for c in self.api.boot['cameras']if c['id']==self.cid)
            self.calls.append((current['thirdPartyCameraInfo']['forceTcp'],self.clock.elapsed))
            # First frames arrive during a real eight-second observation; these
            # tests model its elapsed budget without network or recording data.
            self.clock.elapsed+=seconds
            return next(responses)
        return run
    def repair(self,responses,fetch=metrics,api=None):
        return recovery.rebuild(self.config,self.root,self.cid,api=api or self.api,fetch=fetch,
                    probe=self.probe(responses),clock=self.clock,sleep=self.clock.sleep)
    def assert_original(self):
        self.assertEqual(protect.settings_digest(self.config,self.api.boot),self.original)
        self.assertEqual([flag for _,flag in self.api.patches],[True,None])
    def test_delayed_first_frames_are_proven_before_restore_and_after_restore(self):
        report=self.repair([empty_probe(),good_probe(),empty_probe(),good_probe()])
        self.assertTrue(report['ok'],report);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual([flag for flag,_ in self.calls],[True,True,None,None])
        self.assertEqual(self.clock.sleeps,[2,1,2,1]);self.assertLessEqual(self.clock.elapsed,40)
        receipt=read_json(self.root/'recovery.json')
        self.assertEqual(receipt['temporaryActiveProbeAttempts'],2)
        self.assertEqual(receipt['postRepairActiveProbeAttempts'],2)
        self.assertTrue(receipt['temporaryActiveProbe']['ok']);self.assertTrue(receipt['postRepairActiveProbe']['ok'])
        self.assert_original()
    def test_real_error_or_any_frame_or_byte_is_not_waitable_readiness(self):
        failures=[]
        for key,value in (('errorCode','ubv_checksum_mismatch'),('websocketFrames',1),
                          ('binaryBytesDiscarded',1),('tracks',[{'kind':'AAC','invalidAdts':1}])):
            bad=empty_probe();bad[key]=value;failures.append(bad)
        for key in ('transport','continuousMediaTimes'):
            bad=empty_probe();bad['checks'][key]=False;failures.append(bad)
        for bad in failures:
            self.assertFalse(recovery._empty_waitable_probe(bad),bad)
        report=self.repair([failures[0]])
        self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'recovery_active_verification_failed')
        self.assertEqual(len(self.calls),1);self.assertTrue(report['restoredOriginalTcp']);self.assert_original()
    def test_corrupt_after_original_restore_is_not_retried(self):
        bad=empty_probe();bad['binaryBytesDiscarded']=500
        bad['errorCode']='ubv_invalid_clock_sync_nanoseconds'
        report=self.repair([good_probe(),bad])
        self.assertFalse(report['ok']);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual([flag for flag,_ in self.calls],[True,None])
        self.assertEqual(report['postRepairActiveProbe']['errorCode'],'ubv_invalid_clock_sync_nanoseconds')
        self.assertEqual(report['errorCode'],'recovery_active_verification_failed');self.assert_original()
    def test_source_fails_during_empty_wait_then_original_is_always_restored(self):
        reads=[0]
        def source(bridge):
            reads[0]+=1
            return metrics(bridge)if reads[0]<=2 else{'status':'waiting-for-camera','streams':[]}
        report=self.repair([empty_probe()],fetch=source)
        self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'recovery_source_unhealthy')
        self.assertEqual(len(self.calls),1);self.assertTrue(report['restoredOriginalTcp']);self.assert_original()
    def test_endless_empty_probe_stops_at_attempt_budget_with_original_restored(self):
        report=self.repair([empty_probe()]*10)
        self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'recovery_active_settlement_timeout')
        self.assertEqual(len(self.calls),3);self.assertLessEqual(self.clock.elapsed,45)
        self.assertTrue(report['restoredOriginalTcp']);self.assert_original()
    def test_too_little_setup_budget_never_starts_another_stream(self):
        def slow_probe(config,camera,channel,seconds):
            self.calls.append((camera['thirdPartyCameraInfo']['forceTcp'],self.clock.elapsed))
            self.clock.elapsed+=22
            return empty_probe()
        report=recovery.rebuild(self.config,self.root,self.cid,api=self.api,fetch=metrics,
                    probe=slow_probe,clock=self.clock,sleep=self.clock.sleep)
        self.assertFalse(report['ok']);self.assertEqual(report['errorCode'],'recovery_active_settlement_timeout')
        self.assertEqual(len(self.calls),1);self.assertTrue(report['restoredOriginalTcp']);self.assert_original()
    def test_settings_drift_during_empty_wait_blocks_original_restore_cas(self):
        def drift_probe(config,camera,channel,seconds):
            self.calls.append((True,self.clock.elapsed));self.clock.elapsed+=seconds
            self.api.boot['cameras'][-1]['recordingSettings']={'mode':'motion'}
            return empty_probe()
        report=recovery.rebuild(self.config,self.root,self.cid,api=self.api,fetch=metrics,
                    probe=drift_probe,clock=self.clock,sleep=self.clock.sleep)
        self.assertFalse(report['ok']);self.assertFalse(report['restoredOriginalTcp'])
        self.assertEqual(report['errorCode'],'recovery_settings_drift')
        self.assertEqual([flag for _,flag in self.api.patches],[True])
        self.assertEqual(read_json(self.root/'recovery.json')['phase'],'blocked')
    def test_restore_lost_ack_is_read_back_with_original_guard_before_success(self):
        def lost_ack(config,path,method='GET',body=None,**kwargs):
            result=self.api(config,path,method=method,body=body,**kwargs)
            if method=='PATCH'and body['thirdPartyCameraInfo']['forceTcp']is None:
                self.assertEqual(read_json(self.root/'recovery.json')['phase'],'restore-dispatching')
                raise RuntimeError('synthetic lost response')
            return result
        report=self.repair([good_probe(),good_probe()],api=lost_ack)
        self.assertTrue(report['ok'],report);self.assertTrue(report['restoredOriginalTcp']);self.assert_original()
        self.assertEqual(read_json(self.root/'recovery.json')['restoreAttempts'],2)
    def test_restore_lost_ack_does_not_bypass_original_settings_guard(self):
        def lost_ack(config,path,method='GET',body=None,**kwargs):
            result=self.api(config,path,method=method,body=body,**kwargs)
            if method=='PATCH'and body['thirdPartyCameraInfo']['forceTcp']is None:
                self.api.boot['cameras'][-1]['recordingSettings']={'mode':'motion'}
                raise RuntimeError('synthetic lost response')
            return result
        report=self.repair([good_probe()],api=lost_ack)
        self.assertFalse(report['ok']);self.assertFalse(report['restoredOriginalTcp'])
        self.assertEqual(report['errorCode'],'recovery_settings_drift')
        self.assertEqual([flag for _,flag in self.api.patches],[True,None])
        self.assertEqual(read_json(self.root/'recovery.json')['phase'],'blocked')
    def test_crash_receipt_after_temporary_media_restores_original_before_probing(self):
        camera=self.api.boot['cameras'][0]
        receipt={'schemaVersion':1,'cameraId':self.cid,'phase':'temporary-media-settling',
            'originalSettingsSha256':self.original,
            'temporarySettingsSha256':protect.settings_digest(self.config,self.api.boot,target=self.cid,force_tcp=True),
            'checkpoint':protect.recording_ends(camera),'temporaryActiveProbe':empty_probe()}
        camera['thirdPartyCameraInfo']['forceTcp']=True;write_json(self.root/'recovery.json',receipt)
        report=recovery.resume_pending(self.config,self.root,api=self.api,fetch=metrics,
                    probe=self.probe([empty_probe(),good_probe()]),clock=self.clock,sleep=self.clock.sleep)
        self.assertTrue(report['ok'],report);self.assertTrue(report['restoredOriginalTcp'])
        self.assertEqual([flag for flag,_ in self.calls],[None,None])
        self.assertEqual([flag for _,flag in self.api.patches],[None])
        self.assertEqual(protect.settings_digest(self.config,self.api.boot),self.original)


if __name__=='__main__':unittest.main()
