"""Regression for live exhausted-budget starvation and expired probe labels."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from reolink_protect_events.operations import media_health, monitor
from reolink_protect_events.operations.safety import OperationError, write_json
from test_operations_monitor import fixture, metrics


class FairMonitorTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.root=Path(self.folder.name)
        self.addCleanup(self.folder.cleanup)
        self.config,self.boot,self.now=fixture();self.at=self.now;self.calls=[]
        self.ids=[b['cameraId']for b in self.config['bridges']]

    def api(self,*_a,**_kw):
        boot=copy.deepcopy(self.boot)
        for c in boot['cameras']:
            c['stats']['video']={'recordingEnd':self.at-1000,'recordingEndLQ':self.at-1000}
        return boot

    def probe(self,_config,camera,_channel,**_):
        self.calls.append(('ubv',camera['id']));return {'ok':True}

    def startup(self,_config,camera,_channel,**_):
        self.calls.append(('fmp4',camera['id']));return {'ok':True}

    def sample(self,**options):
        return monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
            api=self.api,fetch=metrics,probe=self.probe,startup_probe=self.startup,**options)

    def test_permanently_failed_camera_with_exhausted_budget_cannot_starve_rotation(self):
        bad=self.ids[0]
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
            'lastProbeAtMs':self.now-60000,'rotation':0,'cameras':{cid:{'failures':3 if cid==bad else 0,
            'repairAttempts':[self.now-2000000,self.now-1000000]if cid==bad else[],
            'lastActiveProbe':{'ok':cid!=bad},'lastActiveProbeAtMs':self.now-600000,
            'activeProbeSourceEpoch':1}for cid in self.ids}})
        def probe(config,camera,channel,**kw):
            result=self.probe(config,camera,channel,**kw);result['ok']=camera['id']!=bad;return result
        with patch.object(monitor,'probe_ubv',probe):
            for i in range(20):
                self.at=self.now+i*30000
                report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
                    api=self.api,fetch=metrics,probe=probe,allow_repair=True,
                    recover=lambda *_a,**_kw:self.fail('exhausted repair must not dispatch'))
        self.assertEqual({cid for _,cid in self.calls},set(self.ids))
        self.assertTrue(all(row['activeMediaVerified']for row in report['cameras']if row['cameraId']!=bad))
        self.assertFalse(report['ok']);self.assertIsNone(report['recovery'])

    def test_day_old_success_and_unhealthy_source_are_never_media_verified(self):
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
            'lastProbeAtMs':self.now-86400000,'rotation':0,'cameras':{cid:{'failures':0,
            'repairAttempts':[],'lastActiveProbe':{'ok':True},'lastActiveProbeAtMs':self.now-86400000,
            'activeProbeSourceEpoch':1}for cid in self.ids}})
        report=monitor.run_once(self.config,self.root,now_ms=self.now,startup_at_ms=self.now-120000,
            api=self.api,fetch=lambda _: {'status':'offline'},probe=self.probe)
        self.assertFalse(self.calls);self.assertFalse(any(r['activeMediaVerified']for r in report['cameras']))
        self.assertFalse(report['activeCoverageVerified']);self.assertFalse(report['ok'])

    def test_probe_ttl_and_legacy_epoch_are_independent_of_healthy_source(self):
        write_json(self.root/'maintenance.json',{})
        for age,epoch_present,verified in ((900000,True,True),(900001,True,False),(-1,True,False),(0,False,False)):
            with self.subTest(age=age,epoch_present=epoch_present):
                camera_state={'failures':0,'repairAttempts':[],'lastActiveProbe':{'ok':True},
                    'lastActiveProbeAtMs':self.now-age}
                if epoch_present:camera_state['activeProbeSourceEpoch']=1
                write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
                    'lastProbeAtMs':self.now,'rotation':0,'cameras':{cid:copy.deepcopy(camera_state)for cid in self.ids}})
                report=self.sample()
                self.assertTrue(all(r['sourceHealthy']and r['protectHealthy']for r in report['cameras']))
                self.assertTrue(all(r['activeMediaVerified']is verified for r in report['cameras']))
                self.assertFalse(self.calls)

    def test_changed_epoch_invalidates_good_probe_while_maintenance_blocks_reprobe(self):
        for i in range(6):self.at=self.now+i*50000;self.sample()
        write_json(self.root/'maintenance.json',{})
        def changed(bridge):
            value=metrics(bridge);value['events']['source']['connectionEpoch']=2;return value
        report=monitor.run_once(self.config,self.root,now_ms=self.at+1,startup_at_ms=self.now-120000,
            api=self.api,fetch=changed,probe=self.probe)
        self.assertFalse(any(r['activeMediaVerified']for r in report['cameras']))
        self.assertTrue(all(r['sourceEpochChanged']for r in report['cameras']))

    def test_missing_source_epoch_cannot_verify_current_or_legacy_media(self):
        def unknown_epoch(bridge):
            value=metrics(bridge);value.pop('events');return value
        for i in range(6):
            self.at=self.now+i*50000
            report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
                api=self.api,fetch=unknown_epoch,probe=self.probe)
        self.assertTrue(all(r['sourceHealthy']for r in report['cameras']))
        self.assertFalse(any(r['activeMediaVerified']for r in report['cameras']))
        self.assertFalse(report['ok']);self.assertEqual(report['state'],'verifying')

    def test_enabled_startup_probe_alternates_one_viewer_per_slot_and_covers_every_camera(self):
        self.config['fmp4Startup']={'enabled':True}
        for i in range(12):
            self.at=self.now+i*50000;before=len(self.calls);report=self.sample()
            self.assertEqual(len(self.calls)-before,1)
        self.assertEqual({(kind,cid)for kind,cid in self.calls},
            {(kind,cid)for kind in ('ubv','fmp4')for cid in self.ids})
        self.assertTrue(report['activeCoverageVerified']);self.assertTrue(report['ok']);self.assertEqual(report['state'],'healthy')

    def test_pin_drift_requires_attention_and_never_repairs_or_claims_startup_verified(self):
        self.config['fmp4Startup']={'enabled':True}
        with patch.object(monitor,'verify_fmp4_configuration',side_effect=OperationError('fmp4_configuration_drift')):
            for i in range(13):
                self.at=self.now+i*50000
                report=self.sample(allow_repair=True,recover=lambda *_a,**_kw:self.fail('config drift cannot repair'))
        self.assertEqual(report['state'],'attention');self.assertFalse(report['ok'])
        self.assertFalse(any(kind=='fmp4'for kind,_ in self.calls))
        self.assertFalse(any(r['fmp4StartupVerified']for r in report['cameras']))

    def evidence_state(self):
        return {cid:{'connectionEpoch':1,'failureSourceEpoch':1,'failures':0,'repairAttempts':[],
            'lastActiveProbe':{'ok':True},'lastActiveProbeAtMs':self.now-1,'activeProbeSourceEpoch':1,
            'lastFmp4StartupProbe':{'ok':True},'lastFmp4StartupProbeAtMs':self.now-1,'fmp4ProbeSourceEpoch':1,
            'lastAnyProbeAtMs':self.now,'nextProbeType':'fmp4'}for cid in self.ids}

    def save_evidence_state(self,rows,last_rotation=None):
        write_json(self.root/'state.json',{'schemaVersion':1,'startedAtMs':self.now-120000,
            'lastProbeAtMs':self.now,'lastRotationAtMs':self.now if last_rotation is None else last_rotation,
            'rotation':0,'cameras':rows})

    def test_expired_or_previous_epoch_failures_never_dispatch_recovery(self):
        self.config['fmp4Startup']={'enabled':True};bad=self.ids[0]
        for kind in ('ubv','fmp4'):
            for age,epoch in ((900001,1),(1000,0)):
                with self.subTest(kind=kind,age=age,epoch=epoch):
                    rows=self.evidence_state();row=rows[bad];row.update(failures=2,connectionEpoch=epoch,failureSourceEpoch=epoch)
                    result_key,at_key,epoch_key=('lastActiveProbe','lastActiveProbeAtMs','activeProbeSourceEpoch')if kind=='ubv'else('lastFmp4StartupProbe','lastFmp4StartupProbeAtMs','fmp4ProbeSourceEpoch')
                    row.update({result_key:{'ok':False},at_key:self.now-age,epoch_key:epoch})
                    self.save_evidence_state(rows)
                    report=self.sample(allow_repair=True,recover=lambda *_a,**_kw:self.fail('stale failure cannot repair'))
                    result=next(r for r in report['cameras']if r['cameraId']==bad)
                    self.assertTrue(result['sourceHealthy']and result['protectHealthy'])
                    self.assertFalse(result['repairEligible']);self.assertEqual(result['consecutiveFailures'],0)
                    self.assertIsNone(report['recovery']);self.assertFalse(self.calls)

    def test_fresh_fmp4_only_failure_stays_degraded_without_spending_repair_budget(self):
        self.config['fmp4Startup']={'enabled':True};bad=self.ids[0];rows=self.evidence_state()
        rows[bad].update(failures=2,lastFmp4StartupProbe={'ok':False})
        self.save_evidence_state(rows)
        for index in range(3):
            self.at=self.now+index
            report=self.sample(allow_repair=True,recover=lambda *_a,**_kw:self.fail('fmp4 packaging cannot toggle recorder'))
            result=next(r for r in report['cameras']if r['cameraId']==bad)
            self.assertEqual(result['consecutiveFailures'],0);self.assertEqual(result['repairAttempts24h'],0)
            self.assertEqual(result['recommendedAction'],'review_fmp4_startup');self.assertFalse(result['repairEligible'])
            self.assertTrue(result['activeMediaVerified']);self.assertTrue(report['quickHealthy'])
            self.assertFalse(report['ok']);self.assertEqual(report['state'],'degraded')

    def test_new_epoch_first_failure_cannot_inherit_two_previous_failures(self):
        bad=min(self.ids);rows=self.evidence_state()
        rows[bad].update(connectionEpoch=0,failureSourceEpoch=0,failures=2)
        self.save_evidence_state(rows,last_rotation=self.now-60000)
        report=monitor.run_once(self.config,self.root,now_ms=self.now,startup_at_ms=self.now-120000,
            api=self.api,fetch=metrics,probe=lambda *_a,**_kw:{'ok':False},allow_repair=True,
            recover=lambda *_a,**_kw:self.fail('first failure in a new epoch cannot inherit old count'))
        result=next(r for r in report['cameras']if r['cameraId']==bad)
        self.assertEqual(result['consecutiveFailures'],1);self.assertFalse(result['repairEligible'])
        self.assertIsNone(report['recovery'])

    def test_full_acceptance_adds_serialized_fmp4_startup_gate(self):
        self.config['fmp4Startup']={'enabled':True};cid=self.ids[-1]
        def advancing(*args,**kwargs):
            self.at+=100
            return self.api(*args,**kwargs)
        report=media_health.run_once(self.config,mode='full',camera_ids=[cid],now_ms=self.now,
            api=advancing,fetch=metrics,probe=self.probe,startup_probe=self.startup)
        self.assertTrue(report['ok'],report);self.assertTrue(report['fmp4StartupCoverageVerified'])
        self.assertEqual(self.calls,[('ubv',cid),('ubv',cid),('ubv',cid),('fmp4',cid)])
        self.calls=[]
        report=media_health.run_once(self.config,mode='full',camera_ids=[cid],now_ms=self.now,
            api=advancing,fetch=metrics,probe=self.probe,startup_probe=lambda *_a,**_kw:{'ok':False})
        self.assertFalse(report['ok']);self.assertFalse(report['fmp4StartupCoverageVerified'])
