"""Observation and exact single-camera recovery depend on contracts, not labels."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from reolink_protect_events.operations import media_health, monitor, protect, recovery
from reolink_protect_events.operations.safety import OperationError
from test_operations_monitor import FakeProtect, fixture, metrics


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.config,self.boot,self.now=fixture()

    def health(self,boot):
        return media_health.run_once(self.config,now_ms=self.now,
            api=FakeProtect(boot),fetch=metrics)

    def test_changed_and_missing_version_labels_preserve_healthy_contract(self):
        for label in ('7.3.74','8.0.0','9.0.0-preview',None):
            with self.subTest(label=label):
                boot=copy.deepcopy(self.boot)
                if label is None:boot['nvr'].pop('version')
                else:boot['nvr']['version']=label
                report=self.health(boot)
                self.assertTrue(report['ok'],report)
                self.assertEqual(report['protectVersion'],label)
                self.assertEqual(len(report['cameras']),6)
                self.assertEqual(report['expectedRecordingProfiles'],12)

    def test_version_metadata_is_bounded_and_never_exposes_control_characters(self):
        for label in ('private\nheader',{'unexpected':'object'},'x'*81):
            boot=copy.deepcopy(self.boot);boot['nvr']['version']=label
            report=self.health(boot)
            self.assertTrue(report['ok'],report)
            self.assertIsNone(report['protectVersion'])
            self.assertNotIn('private',json.dumps(report))

    def test_missing_recording_evidence_remains_unhealthy_on_new_version(self):
        self.boot['nvr']['version']='7.3.74'
        self.boot['cameras'][0]['stats']['video'].pop('recordingEndLQ')
        report=self.health(self.boot)
        self.assertFalse(report['ok'])
        row=report['cameras'][0]
        self.assertFalse(row['protectHealthy'])
        self.assertEqual(row['cause'],'protect_media_unhealthy')
        self.assertIsNone(row['recordings'][1]['endMs'])

    def test_malformed_bootstrap_identity_and_channels_fail_closed(self):
        cases=[]
        boot=copy.deepcopy(self.boot);boot['nvr']=[];cases.append((boot,'protect_nvr_contract_invalid'))
        boot=copy.deepcopy(self.boot);boot['cameras'].append(copy.deepcopy(boot['cameras'][0]))
        cases.append((boot,'camera_identity_changed'))
        boot=copy.deepcopy(self.boot);boot['cameras'][0]['id']=[];cases.append((boot,'camera_identity_changed'))
        boot=copy.deepcopy(self.boot);boot['cameras'][0]['host']='192.168.30.200';cases.append((boot,'camera_mapping_changed'))
        for channels in (None,[],[{'id':0,'enabled':1}],[{'id':True,'enabled':True}],
                         [{'id':0,'enabled':True},{'id':0,'enabled':False}],
                         [{'id':0,'enabled':True},{'id':4,'enabled':True}]):
            boot=copy.deepcopy(self.boot);boot['cameras'][0]['channels']=channels
            cases.append((boot,'camera_channels_invalid'))
        for boot,error in cases:
            with self.subTest(error=error,boot=boot['cameras'][0].get('channels')):
                if isinstance(boot['nvr'],dict):boot['nvr']['version']='7.3.74'
                report=self.health(boot)
                self.assertFalse(report['ok'])
                self.assertEqual(report['errorCode'],error)

    def test_new_version_monitor_still_observes_and_rotates_media(self):
        self.boot['nvr']['version']='7.3.74';api=FakeProtect(self.boot,advance=True);probes=[]
        with tempfile.TemporaryDirectory() as directory:
            report=monitor.run_once(self.config,Path(directory),now_ms=self.now,
                startup_at_ms=self.now-120000,api=api,fetch=metrics,
                probe=lambda _config,camera,channel,**_:probes.append((camera['id'],channel)) or {'ok':True})
        self.assertTrue(report['quickHealthy'],report)
        self.assertNotIn('errorCode',report)
        self.assertEqual(len(probes),1)
        self.assertFalse(api.patches)

    def test_exact_recovery_contract_works_on_new_version(self):
        self.boot['nvr']['version']='7.3.74';api=FakeProtect(self.boot,advance=True)
        before=protect.settings_digest(self.config,api.boot)
        with tempfile.TemporaryDirectory() as directory:
            report=recovery.rebuild(self.config,Path(directory),self.config['bridges'][0]['cameraId'],
                api=api,fetch=metrics,probe=lambda *_a,**_kw:{'ok':True},sleep=lambda _:None)
        self.assertTrue(report['ok'],report)
        self.assertEqual([flag for _,flag in api.patches],[True,None])
        self.assertEqual(protect.settings_digest(self.config,api.boot),before)

    def test_missing_recovery_field_on_new_version_never_patches(self):
        self.boot['nvr']['version']='7.3.74';self.boot['cameras'][0]['thirdPartyCameraInfo'].pop('forceTcp')
        api=FakeProtect(self.boot,advance=True)
        with tempfile.TemporaryDirectory() as directory:
            report=recovery.rebuild(self.config,Path(directory),self.config['bridges'][0]['cameraId'],
                api=api,fetch=metrics,probe=lambda *_a,**_kw:{'ok':True},sleep=lambda _:None)
        self.assertEqual(report['errorCode'],'recovery_requires_original_null_tcp')
        self.assertFalse(api.patches)

    def test_mid_transaction_version_change_still_invalidates_exact_settings(self):
        before=protect.settings_digest(self.config,self.boot)
        self.boot['nvr']['version']='7.3.74'
        self.assertNotEqual(protect.settings_digest(self.config,self.boot),before)
        self.boot['cameras'][0]['id']=False
        with self.assertRaisesRegex(OperationError,'camera_identity_changed'):
            protect.settings_digest(self.config,self.boot)


if __name__=='__main__':unittest.main()
