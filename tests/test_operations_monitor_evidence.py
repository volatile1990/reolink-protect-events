"""Independent failed-probe confirmation and recorder-generation regression."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.operations import monitor
from reolink_protect_events.operations.safety import read_json,write_json
from test_operations_monitor import fixture,metrics


class ProbeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.config,self.boot,self.now=fixture();self.config['allQualityMediaChecks']=True
        self.at=self.now;self.target=self.config['bridges'][-1]['cameraId'];self.calls=[];self.repairs=[]
        self.low_bad=True;self.epoch=1;self.source_bad=False
        rows={b['cameraId']:{'failures':13 if b['cameraId']==self.target else 0,
          'connectionEpoch':1,'failureSourceEpoch':1,'lastAnyProbeAtMs':self.now-60000,
          'lastActiveProbe':{'ok':True},'lastActiveProbeAtMs':self.now-1000,'activeProbeSourceEpoch':1,
          'recordingEnds':{'high':self.now-2000,'low':self.now-2000},'repairAttempts':[],
          'qualityProbes':{str(ch):{'atMs':self.now-1000,'sourceEpoch':1,'result':{'ok':True}}for ch in(0,1,2)}}
          for b in self.config['bridges']}
        rows[self.target]['qualityProbes']['2']['result']={'ok':False,'errorCode':None,'backwardDts':1}
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
          'lastProbeAtMs':self.now,'lastRotationAtMs':self.now,'rotation':0,'cameras':rows})
    def api(self,*a,**kw):
        boot=copy.deepcopy(self.boot)
        for row in boot['cameras']:row['stats']['video']={'recordingEnd':self.at-1000,'recordingEndLQ':self.at-1000}
        return boot
    def fetch(self,bridge):
        value=metrics(bridge);value['events']['source']['connectionEpoch']=self.epoch
        if self.source_bad and bridge['cameraId']==self.target:value['status']='waiting-for-camera'
        return value
    def probe(self,config,camera,channel,**kw):
        self.assertEqual(kw['seconds'],8);self.calls.append((camera['id'],channel))
        return {'ok':not(self.low_bad and camera['id']==self.target and channel==2),'channel':channel}
    def repair(self,config,root,cid,**kw):
        self.repairs.append(cid)
        return {'ok':True,'attempted':True,'restoredOriginalTcp':True,'postRepairActiveProbe':{'ok':True}}
    def sample(self,elapsed,**options):
        self.at=self.now+elapsed;before=len(self.calls)
        result=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
          api=self.api,fetch=self.fetch,probe=self.probe,recover=self.repair,**options)
        self.assertLessEqual(len(self.calls)-before,1);return result
    def target_row(self,report):return next(row for row in report['cameras']if row['cameraId']==self.target)
    def test_legacy_thirteen_and_thirteen_cached_reuses_do_not_dispatch_or_reset_budget(self):
        state=read_json(self.root/'state.json');state['cameras'][self.target]['repairAttempts']=[self.now-2000000]
        write_json(self.root/'state.json',state);write_json(self.root/'maintenance.json',{})
        for i in range(13):
            row=self.target_row(self.sample(i*1000,allow_repair=True))
            self.assertEqual(row['consecutiveFailures'],1);self.assertFalse(row['confirmedFailure'])
            self.assertEqual(row['repairAttempts24h'],1)
        self.assertFalse(self.calls);self.assertFalse(self.repairs)
        (self.root/'maintenance.json').unlink()
        row=self.target_row(self.sample(40000,allow_repair=True))
        self.assertEqual(self.calls,[(self.target,2)]);self.assertEqual(row['consecutiveFailures'],2)
        self.assertFalse(self.repairs)
    def test_fresh_automatic_success_neither_counts_nor_hides_cached_low_failure(self):
        write_json(self.root/'maintenance.json',{})
        first=self.target_row(self.sample(0));self.assertEqual(first['consecutiveFailures'],1)
        state=read_json(self.root/'state.json');row=state['cameras'][self.target]
        row['lastActiveProbeAtMs']=self.now+1000
        row['qualityProbes']['1']['atMs']=self.now+1000
        write_json(self.root/'state.json',state)
        result=self.sample(1000,allow_repair=True);row=self.target_row(result)
        self.assertEqual(row['consecutiveFailures'],1);self.assertFalse(result['quickHealthy'])
        self.assertFalse(row['qualityMediaChecks'][2]['probe']['ok']);self.assertFalse(self.repairs)
    def test_only_three_fresh_low_failures_dispatch_once_and_preserve_old_negative(self):
        for elapsed in(0,25000,50000,75000,100000):self.sample(elapsed,allow_repair=True)
        self.assertEqual(self.repairs,[self.target])
        self.assertEqual([channel for cid,channel in self.calls if cid==self.target],[2,2,2])
        state=read_json(self.root/'state.json')['cameras'][self.target]
        self.assertEqual(state['probeGeneration'],1);self.assertEqual(len(state['repairAttempts']),1)
        self.assertFalse(state['qualityProbes']['2']['result']['ok'])
        old=read_json(next((self.root/'repair-history').glob(self.target+'-*-recorder-restored.json')))
        self.assertFalse(old['qualityProbes']['2']['result']['ok'])
        row=self.target_row(self.sample(125000,allow_repair=True))
        self.assertEqual(row['consecutiveFailures'],0);self.assertEqual(row['repairAttempts24h'],1)
        low=next(q for q in row['qualityMediaChecks']if q['channel']==2)
        self.assertFalse(low['fresh']);self.assertFalse(low['probe']['ok']);self.assertEqual(len(self.repairs),1)
    def test_positive_low_recheck_clears_the_failure_without_a_repair(self):
        self.low_bad=False;result=self.sample(0,allow_repair=True)
        self.assertEqual(self.calls,[(self.target,2)]);self.assertEqual(self.target_row(result)['consecutiveFailures'],0)
        self.assertTrue(result['quickHealthy']);self.assertFalse(self.repairs)
    def test_urgent_low_does_not_consume_the_regular_quality_plan(self):
        state=read_json(self.root/'state.json');state['cameras'][self.target]['qualityRotation']=1
        state['rotation']=5;write_json(self.root/'state.json',state)
        self.sample(0)
        self.assertEqual(read_json(self.root/'state.json')['cameras'][self.target]['qualityRotation'],1)
        report=self.sample(25000)
        self.assertEqual(self.calls,[(self.target,2),(self.target,0)])
        self.assertEqual(self.target_row(report)['consecutiveFailures'],1)
        self.assertEqual(read_json(self.root/'state.json')['cameras'][self.target]['qualityRotation'],2)
    def test_legacy_pre_repair_proofs_are_not_current_in_any_media_path(self):
        self.config['fmp4Startup']={'enabled':True}
        state=read_json(self.root/'state.json');row=state['cameras'][self.target]
        row.update(repairAttempts=[self.now-500],lastRecovery={'ok':True,'restoredOriginalTcp':True},
          lastFmp4StartupProbe={'ok':True},lastFmp4StartupProbeAtMs=self.now-1000,fmp4ProbeSourceEpoch=1)
        write_json(self.root/'state.json',state);write_json(self.root/'maintenance.json',{})
        report=self.sample(0,allow_repair=True);row=self.target_row(report)
        self.assertFalse(row['activeProbeFresh']);self.assertFalse(row['fmp4StartupProbeFresh'])
        self.assertTrue(all(not q['fresh']for q in row['qualityMediaChecks']))
        self.assertFalse(row['activeMediaVerified']);self.assertFalse(row['allActivePathsVerified'])
        self.assertFalse(row['qualityMediaChecks'][2]['probe']['ok'])
        self.assertEqual(row['consecutiveFailures'],0);self.assertEqual(row['repairAttempts24h'],1)
        self.assertFalse(self.repairs)
    def test_seven_camera_rotation_is_fair_and_has_at_most_one_urgent_between_regular_slots(self):
        cid='f'*24;camera=copy.deepcopy(self.boot['cameras'][0])
        camera.update(id=cid,host='192.168.30.129',isThirdPartyCamera=False,connectedSince=self.now-60000)
        self.boot['cameras'].append(camera);self.config['readOnlyCameras']=[{'cameraId':cid,'host':'192.168.30.129'}]
        reasons=[];regular=[]
        for i in range(18):
            report=self.sample(i*25000)
            for row in report['cameras']+report['nativeCameras']:
                if row.get('activeProbePerformed'):
                    reasons.append(row['activeProbeReason'])
                    if row['activeProbeReason']=='rotation':regular.append(row['cameraId'])
        self.assertEqual(set(regular),{b['cameraId']for b in self.config['bridges']}|{cid})
        self.assertTrue(all(a=='rotation'or b=='rotation'for a,b in zip(reasons,reasons[1:])))
    def test_resume_generation_fence_is_durable_even_if_following_inspect_fails(self):
        write_json(self.root/'recovery.json',{'phase':'restore-dispatching','cameraId':self.target})
        def resume(config,root,**kw):
            write_json(root/'recovery.json',{'phase':'complete','cameraId':self.target,'restoredOriginalTcp':True})
            return {'ok':True,'cameraId':self.target,'restoredOriginalTcp':True}
        with patch.object(monitor,'inspect',side_effect=OSError('synthetic_next_read_failed')):
            report=self.sample(0,allow_repair=True,resume=resume)
        self.assertFalse(report['ok']);state=read_json(self.root/'state.json')['cameras'][self.target]
        self.assertEqual(state['probeGeneration'],1);self.assertFalse(state['qualityProbes']['2']['result']['ok'])
        self.assertTrue(list((self.root/'repair-history').glob(self.target+'-*-resume-restored.json')))
        row=self.target_row(self.sample(1000,allow_repair=True))
        self.assertEqual(row['consecutiveFailures'],0);self.assertFalse(self.repairs)
    def test_three_unhealthy_quick_samples_survive_changing_source_epochs_without_rebuild(self):
        self.source_bad=True
        for i in range(3):
            self.epoch=i+1;report=self.sample(i*25000,allow_repair=True)
        row=self.target_row(report)
        self.assertEqual(row['consecutiveFailures'],3);self.assertTrue(row['confirmedFailure'])
        self.assertIn('source_unhealthy',{value['code']for value in report['alerts']})
        self.assertFalse(row['repairEligible']);self.assertFalse(self.repairs)


if __name__=='__main__':unittest.main()
