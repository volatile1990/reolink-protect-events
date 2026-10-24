"""Configuration drift must reach operator status without escalating media gaps."""
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

    def test_invalid_configuration_requires_action_and_survives_public_projection(self):
        def startup(*_args,**_kwargs):
            self.startup_calls.append(True);return {'ok':True}
        with patch.object(monitor,'verify_fmp4_configuration',side_effect=OperationError('fmp4_configuration_drift')):
            for index in range(13):
                self.at=self.now+index*50000;report=self.sample(startup)
        self.assertEqual(report['state'],'attention');self.assertTrue(report['actionRequired'])
        expected={'code':'media_configuration_requires_review','actionRequired':True}
        self.assertIn(expected,report['alerts']);self.assertFalse(self.startup_calls)
        self.assertTrue(report['readOnly']);self.assertIsNone(report['recovery'])
        projected=public_status.projection(report)
        published=json.loads((self.root/'monitor.json').read_bytes())
        for value in (projected,published):
            self.assertEqual(value['state'],'attention');self.assertTrue(value['actionRequired'])
            self.assertIn(expected,value['alerts'])

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


if __name__=='__main__':unittest.main()
