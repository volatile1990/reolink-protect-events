"""Installation metadata cannot override successful functional media evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.operations import monitor,public_status
from reolink_protect_events.operations.safety import OperationError
from test_operations_monitor import fixture,metrics


class MediaConfigurationAlert(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);self.config,self.boot,self.now=fixture()
        self.config['fmp4Startup']={'enabled':True};self.at=self.now;self.startup_calls=[]

    def api(self,*_args,**_kwargs):
        boot=copy.deepcopy(self.boot)
        for camera in boot['cameras']:
            camera['stats']['video']={'recordingEnd':self.at-1000,'recordingEndLQ':self.at-1000}
        return boot

    def sample(self,startup):
        return monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
            api=self.api,fetch=metrics,probe=lambda *_a,**_kw:{'ok':True},startup_probe=startup,
            allow_repair=True,recover=lambda *_a,**_kw:self.fail('configuration/media warning cannot toggle recorder'),
            public_status=self.root/'monitor.json')

    def test_hash_drift_alone_stays_healthy_without_operator_alarm(self):
        def startup(*_args,**_kwargs):
            self.startup_calls.append(True);return {'ok':True}
        with patch.object(monitor,'verify_fmp4_configuration',side_effect=OperationError('fmp4_configuration_drift')) as pins:
            for index in range(13):
                self.at=self.now+index*50000;report=self.sample(startup)
        self.assertEqual(report['state'],'healthy');self.assertFalse(report['actionRequired'])
        self.assertIsNone(report['fmp4ConfigurationVerified']);pins.assert_not_called()
        self.assertEqual(report['alerts'],[]);self.assertTrue(self.startup_calls)
        self.assertTrue(report['activeCoverageVerified'])
        self.assertTrue(report['readOnly']);self.assertIsNone(report['recovery'])
        projected=public_status.projection(report)
        published=json.loads((self.root/'monitor.json').read_bytes())
        for value in (projected,published):
            self.assertEqual(value['state'],'healthy');self.assertFalse(value['actionRequired'])
            self.assertEqual(value['alerts'],[])

    def test_small_fmp4_continuity_warning_stays_degraded_without_operator_alarm(self):
        bad=self.config['bridges'][0]['cameraId']
        def startup(_config,camera,_channel,**_kwargs):
            return {'ok':camera['id']!=bad,'errorCode':'fmp4_audio_gap'if camera['id']==bad else None,'audioGapMs':5}
        for index in range(13):
            self.at=self.now+index*50000;report=self.sample(startup)
        self.assertEqual(report['state'],'degraded');self.assertFalse(report['actionRequired'])
        self.assertNotIn('media_configuration_requires_review',[value['code']for value in report['alerts']])
        self.assertTrue(report['quickHealthy']);self.assertIsNone(report['recovery'])
        self.assertTrue(report['readOnly'])
        projected=public_status.projection(report)
        self.assertFalse(projected['actionRequired']);self.assertEqual(projected['alerts'],[])

    def test_pin_verification_remains_at_actual_recovery_boundary(self):
        boot=copy.deepcopy(self.boot)
        for camera in boot['cameras']:
            camera['stats']['video']={'recordingEnd':self.now-600000,'recordingEndLQ':self.now-600000}
        with patch.object(monitor,'verify_fmp4_configuration',side_effect=OperationError('fmp4_configuration_drift')) as pins:
            for index in range(4):
                report=monitor.run_once(self.config,self.root,now_ms=self.now+index*30000,
                    startup_at_ms=self.now-120000,api=lambda *_a,**_k:copy.deepcopy(boot),fetch=metrics,
                    probe=lambda *_a,**_kw:{'ok':True},allow_repair=True,
                    recover=lambda *_a,**_kw:self.fail('unverified mutation contract cannot dispatch'))
        self.assertTrue(pins.called)
        self.assertFalse(report['fmp4ConfigurationVerified'])
        self.assertFalse(report['quickHealthy']);self.assertEqual(report['state'],'attention')
        self.assertTrue(any(row['confirmedFailure']for row in report['cameras']))
        self.assertFalse(any(row['repairEligible']for row in report['cameras']))
        self.assertNotIn('media_configuration_requires_review',[value['code']for value in report['alerts']])
        self.assertTrue(report['actionRequired'])
        self.assertIn('recorder_media_requires_attention',[value['code']for value in report['alerts']])

    def test_confirmed_ubv_failure_alerts_when_hash_gate_blocks_recovery(self):
        bad=self.config['bridges'][0]['cameraId']
        with patch.object(monitor,'verify_fmp4_configuration',side_effect=OperationError('fmp4_configuration_drift')):
            for index in range(25):
                self.at=self.now+index*30000
                report=monitor.run_once(self.config,self.root,now_ms=self.at,startup_at_ms=self.now-120000,
                    api=self.api,fetch=metrics,
                    probe=lambda _config,camera,_channel,**_kwargs:{'ok':camera['id']!=bad},
                    startup_probe=lambda *_a,**_kw:{'ok':True},allow_repair=True,
                    recover=lambda *_a,**_kw:self.fail('unverified recovery must not dispatch'))
        row=next(row for row in report['cameras']if row['cameraId']==bad)
        self.assertTrue(row['protectHealthy'])
        self.assertTrue(row['sourceHealthy'])
        self.assertTrue(row['confirmedFailure'])
        self.assertFalse(row['repairEligible'])
        self.assertTrue(report['actionRequired'])
        self.assertIn({'code':'recorder_media_requires_attention','cameraId':bad,'actionRequired':True},report['alerts'])
        self.assertNotIn('media_configuration_requires_review',[value['code']for value in report['alerts']])
        projected=public_status.projection(report)
        self.assertTrue(projected['actionRequired'])
        self.assertIn({'code':'recorder_media_requires_attention','cameraId':bad,'actionRequired':True},projected['alerts'])


if __name__=='__main__':unittest.main()
