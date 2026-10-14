"""Controller crash/failure tests: no real SSH, NAS, media, packages or alarms."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from reolink_protect_events.operations.orchestrator import Backend, Update
from reolink_protect_events.operations import orchestrator
from reolink_protect_events.operations import transport


IPS=['192.168.30.'+str(i)for i in range(210,216)]


class FakeBackend:
    def __init__(self):
        self.calls=[];self.changed=False;self.applied=[];self.receipts=[];self.marker=None
        self.events_digest='0'*64;self.previous_digest=self.events_digest
        self.fail_decode_ip=None;self.fail_rollback=False;self.fail_clear=False
        self.unknown_compat=False;self.partial_native=False;self.partial_decode=False
        self.source_bad_ip=None;self.change_after_canary=False
        self.install_ack_lost=False;self.enable_ack_lost=False;self.clear_ack_lost=False
        self.apply_ack_lost=False;self.native_after_rollback_partial=False;self.in_rollback=False
        self.identities={ip:'%024x'%(210+i)for i,ip in enumerate(IPS)}
    def progress(self,_):pass
    def current_sources(self):
        return {p:{'sourceRevision':('2'if self.changed and p=='bridge'else'1')*40,
                   'sourceSha256':('b'if self.changed and p=='bridge'else'a')*64,
                   'sourceDirty':False,'version':'1.4.0'if p=='bridge'else'1.2.0'}for p in ('bridge','events')}
    def freeze(self,directory):
        archive=b'synthetic-bridge-archive';package=b'synthetic-events-package'
        (directory/'bridge-source.zip').write_bytes(archive);(directory/'events-package.zip').write_bytes(package)
        (directory/'operation-sources.json').write_text(json.dumps({'events':'synthetic-owned-code','bridge':{}}))
        self.candidate=hashlib.sha256(package).hexdigest()
        return {'sources':self.current_sources(),'archiveSha256':hashlib.sha256(archive).hexdigest(),
            'operationSourcesSha256':hashlib.sha256((directory/'operation-sources.json').read_bytes()).hexdigest(),
            'eventsManifest':{'packageSha256':self.candidate,'version':'1.2.0'}}
    def tests(self):self.calls.append(('tests',));return {'ok':True}
    def bridges(self):
        return [{'ip':ip,'id':'id-'+ip,'imageId':'new'if ip in self.applied else'old',
                 'configSha256':'c'*64,'composeSha256':{'private-compose':'d'*64}}for ip in IPS]
    def nas(self,payload):
        mode=payload['mode'];self.calls.append(('nas',mode,copy.deepcopy(payload),self.marker))
        if mode=='build':return {'ok':True,'productionInventoryPreserved':True,'cleanupConfirmed':True,
            'release':{'version':'1.4.0','sourceSha256':'a'*64,'imageId':'sha256:'+'e'*64,
                       'imageTag':'reolink-bridge:fake','testsPassed':True,'testedApplicationDllIdentical':True}}
        if mode=='plan':return {'ok':True,'baseline':'private-baseline','bridges':self.bridges()}
        if mode=='resume':return {'ok':True,'receipts':list(self.receipts),'bridges':self.bridges(),
            'pendingIps':[ip for ip in IPS if ip not in self.applied],'phase':'deploying'}
        if mode=='apply':
            ip=payload['ip'];self.applied.append(ip);self.receipts.append('/private/receipt-'+ip)
            if ip==IPS[0]and self.change_after_canary:self.changed=True
            if self.apply_ack_lost:
                self.apply_ack_lost=False;raise TimeoutError('PRIVATE_UPSTREAM_TOKEN')
            return {'ok':True,'bridges':self.bridges(),'receipt':self.receipts[-1]}
        if mode=='final':return {'ok':True,'receipts':list(self.receipts),'bridges':self.bridges()}
        if mode=='rollback-all':
            self.in_rollback=True
            if self.fail_rollback:return {'ok':False,'errorCode':'synthetic_rollback_failed'}
            restored=list(reversed(self.applied));self.applied=[];self.receipts=[]
            return {'ok':True,'steps':[{'ip':ip}for ip in restored],'receipts':[],
                    'allPreviousImagesRestored':True,'configurationBytesPreserved':True,'bridges':self.bridges()}
        raise AssertionError('unexpected NAS mode '+mode)
    def udm(self,request,timeout=None):
        self.calls.append(('udm',copy.deepcopy(request),self.marker))
        action=request['action']
        if action=='compatibility':return {'ok':not self.unknown_compat,'state':'unsupported'if self.unknown_compat else'compatible'}
        if action=='health':
            ids=request.get('cameraIds');rows=[]
            for ip in IPS:
                source_bad=ids is not None and ip==self.source_bad_ip
                rows.append({'host':ip,'cameraId':self.identities[ip],'sourceHealthy':not source_bad,
                             'protectHealthy':True,'ok':not source_bad})
            coverage=not(self.partial_native or self.in_rollback and self.native_after_rollback_partial)
            return {'ok':all(r['ok']for r in rows),'cameras':rows,'fullActiveCoverage':ids is None and coverage,
                    'activeProbeCameraIds':list(ids)if ids is not None else list(self.identities.values())}
        if action=='recover':return {'ok':True,'restoredOriginalTcp':True,'postRepairActiveProbe':{'ok':True}}
        if action=='event-evidence':return {'ok':True,'rawPayloadsExported':False,'syntheticEvents':False}
        if action=='installer':
            value=request['request'];mode=value['mode']
            if mode=='maintenance':
                owner=value['owner'];enabled=value['enable']
                if self.marker is not None and self.marker!=owner:return {'ok':False}
                if enabled:
                    self.marker=owner
                    if self.enable_ack_lost:
                        self.enable_ack_lost=False;raise TimeoutError('PRIVATE_UPSTREAM_TOKEN')
                else:
                    if self.fail_clear:raise RuntimeError('PRIVATE_UPSTREAM_TOKEN')
                    self.marker=None
                    if self.clear_ack_lost:
                        self.clear_ack_lost=False;raise TimeoutError('PRIVATE_UPSTREAM_TOKEN')
                return {'ok':True,'maintenance':enabled}
            if mode=='status':return {'ok':True,'deployment':{'sha256':self.events_digest}}
            if mode=='install':
                self.events_digest=value['digest']
                if self.install_ack_lost:
                    self.install_ack_lost=False;raise TimeoutError('PRIVATE_UPSTREAM_TOKEN')
                return {'ok':True,'deployment':{'sha256':self.events_digest}}
            if mode=='rollback':
                if value['expectedDigest']!=self.events_digest:return {'ok':False}
                self.events_digest=self.previous_digest
                return {'ok':True,'journalPreserved':True}
        raise AssertionError('unexpected UDM action')
    def decode(self,ips=None,not_before_ms=None):
        self.calls.append(('decode',copy.deepcopy(ips),not_before_ms))
        failed=(ips is not None and self.fail_decode_ip in ips)or(self.partial_decode and ips is None and not self.in_rollback)
        return {'ok':True,'realDecodes':True,
            'rtspProfileCoverage':{'allEleven':not failed,'allRequested':not failed},
            'recordedProfileCoverage':{'allEleven':not failed,'allRequested':not failed},
            'mediaPersisted':False}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name)/'release';self.backend=FakeBackend()
    def tearDown(self):self.temp.cleanup()
    def execute(self):
        return Update(self.backend,self.directory).run()
    def modes(self,mode):return [r for r in self.backend.calls if r[0]=='nas'and r[1]==mode]
    def installers(self,mode):return [r for r in self.backend.calls if r[0]=='udm'and r[1]['action']=='installer'and r[1]['request']['mode']==mode]
    def test_full_success_orders_six_targets_and_keeps_actual_postactivation_decode_gates(self):
        report=self.execute();self.assertTrue(report['ok'],report)
        self.assertEqual([r[2]['ip']for r in self.modes('apply')],IPS)
        self.assertEqual(len(self.installers('install')),1);self.assertFalse(self.modes('rollback-all'))
        self.assertIsNone(self.backend.marker)
        decoded=[r for r in self.backend.calls if r[0]=='decode'and r[1]is not None]
        self.assertEqual([r[1]for r in decoded],[[ip]for ip in IPS]);self.assertTrue(all(type(r[2])is int for r in decoded))
        state=json.loads((self.directory/'update.json').read_text());self.assertEqual(state['status'],'complete')
    def test_unknown_compatibility_or_partial_decode_before_build_does_not_mutate(self):
        self.backend.unknown_compat=True;report=self.execute()
        self.assertFalse(report['ok']);self.assertFalse(self.modes('build'));self.assertFalse(self.installers('maintenance'))
        other=Path(self.temp.name)/'other';backend=FakeBackend();backend.partial_decode=True
        report=Update(backend,other).run();self.assertFalse(report['ok'])
        self.assertFalse(any(r[0]=='nas'for r in backend.calls));self.assertIsNone(backend.marker)
    def test_partial_native_global_coverage_is_not_green(self):
        self.backend.partial_native=True;report=self.execute()
        self.assertFalse(report['ok']);self.assertFalse(self.modes('build'));self.assertIsNone(self.backend.marker)
    def test_canary_decode_failure_rolls_back_only_actual_active_prefix(self):
        self.backend.fail_decode_ip=IPS[0];report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report);self.assertEqual(len(self.modes('apply')),1)
        restored=self.modes('rollback-all');self.assertEqual(len(restored),1)
        self.assertFalse(self.backend.applied);self.assertIsNone(self.backend.marker)
        self.assertFalse(self.installers('install'))
    def test_source_change_after_canary_stops_next_target_and_rolls_back(self):
        self.backend.change_after_canary=True;report=self.execute()
        self.assertEqual(report['errorCode'],'sources_changed_since_release_freeze')
        self.assertEqual(len(self.modes('apply')),1);self.assertFalse(self.backend.applied);self.assertFalse(self.installers('install'))
    def test_unhealthy_source_during_canary_never_dispatches_native_repair(self):
        self.backend.source_bad_ip=IPS[0];report=self.execute()
        self.assertEqual(report['errorCode'],'source_unhealthy_no_recorder_repair')
        self.assertFalse(any(r[0]=='udm'and r[1]['action']=='recover'for r in self.backend.calls))
        self.assertEqual(report['status'],'rolled-back')
    def test_healthy_media_cannot_clear_marker_without_original_recorder_setting_proof(self):
        for outcome in ('restored', 'not-restored', 'lost-ack'):
            with self.subTest(outcome=outcome):
                backend=FakeBackend();directory=Path(self.temp.name)/outcome;base=backend.udm
                cid=backend.identities[IPS[0]]
                def dispatch(request,timeout=None):
                    result=base(request,timeout)
                    if request['action']=='health' and request.get('cameraIds'):
                        target=next(row for row in result['cameras'] if row['cameraId']==cid)
                        target.update(ok=False,protectHealthy=False,cause='native_empty')
                        result['ok']=False
                    if request['action']=='recover':
                        self.assertEqual(timeout,300)
                        before=json.loads((directory/'update.json').read_text())
                        self.assertIn(cid,before['repairAttempts'])
                        self.assertEqual(before['evidence']['repair-trigger-'+cid]['cause'],'native_empty')
                        if outcome=='lost-ack':raise TimeoutError('PRIVATE_UPSTREAM_TOKEN')
                        return {'ok':False,'restoredOriginalTcp':outcome=='restored',
                                'errorCode':'synthetic_native_still_empty'}
                    return result
                backend.udm=dispatch
                report=Update(backend,directory).run()
                self.assertFalse(backend.applied,'owned images must still be restored')
                if outcome=='restored':
                    self.assertEqual(report['status'],'rolled-back',report)
                    self.assertIsNone(backend.marker)
                else:
                    self.assertEqual(report['status'],'failed',report)
                    self.assertFalse(report['rollback']['ok'])
                    self.assertIsNotNone(backend.marker,'healthy frames cannot prove forceTcp restoration')
    def test_recorded_gate_starts_after_successful_transport_rebuild(self):
        clock=[1000.0];recovered=[False];base=self.backend.udm
        cid=self.backend.identities[IPS[0]]
        def dispatch(request,timeout=None):
            result=base(request,timeout)
            if request['action']=='health' and request.get('cameraIds') and not recovered[0]:
                target=next(row for row in result['cameras'] if row['cameraId']==cid)
                target.update(ok=False,protectHealthy=False,cause='native_empty');result['ok']=False
            if request['action']=='recover':
                clock[0]+=60;recovered[0]=True
            return result
        self.backend.udm=dispatch
        with patch.object(orchestrator.time,'time',side_effect=lambda:clock[0]):
            report=self.execute()
        self.assertTrue(report['ok'],report)
        state=json.loads((self.directory/'update.json').read_text())
        boundary=state['recorderReadyAfterMs'][cid]
        first=state['evidence']['camera-'+IPS[0]]
        self.assertGreater(boundary,first['afterActivationMs'])
        self.assertEqual(first['afterRecorderReadyMs'],boundary)
        decoded=next(row for row in self.backend.calls if row[0]=='decode' and row[1]==[IPS[0]])
        self.assertEqual(decoded[2],boundary,'an activation-only window would overlap the real rebuild')
    def test_rollback_decode_starts_after_original_images_are_restored(self):
        clock=[1000.0];base=self.backend.nas
        self.backend.fail_decode_ip=IPS[0]
        def dispatch(payload):
            result=base(payload)
            if payload['mode']=='rollback-all':clock[0]+=30
            return result
        self.backend.nas=dispatch
        with patch.object(orchestrator.time,'time',side_effect=lambda:clock[0]):
            report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report)
        state=json.loads((self.directory/'update.json').read_text())
        boundary=state['evidence']['rollback-recording-boundary-ms']
        self.assertEqual(boundary,1030000)
        self.assertGreater(boundary,state['activations'][IPS[0]])
        decoded=[row for row in self.backend.calls if row[0]=='decode' and row[1] is None][-1]
        self.assertEqual(decoded[2],boundary)
    def test_unrelated_unhealthy_source_during_canary_never_repairs_healthy_target(self):
        self.backend.source_bad_ip=IPS[1];report=self.execute()
        self.assertEqual(report['errorCode'],'unrelated_camera_health_failed',report)
        self.assertEqual(report['status'],'rolled-back',report)
        self.assertFalse(any(r[0]=='udm'and r[1]['action']=='recover'for r in self.backend.calls))
        self.assertEqual([row[2]['ip']for row in self.modes('apply')],[IPS[0]])
        restored=self.modes('rollback-all');self.assertEqual(len(restored),1)
        self.assertEqual(len(report['rollback']['restored']),1)
        self.assertEqual([step['ip']for step in report['rollback']['restored'][0]['steps']],[IPS[0]])
        self.assertFalse(self.backend.applied);self.assertIsNone(self.backend.marker)
        self.assertFalse(self.installers('install'))
    def test_ack_lost_after_events_install_restores_candidate_and_journal(self):
        self.backend.install_ack_lost=True;report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report)
        self.assertEqual(self.backend.events_digest,self.backend.previous_digest)
        self.assertEqual(len(self.installers('rollback')),1);self.assertFalse(self.backend.applied)
        self.assertNotIn('PRIVATE_UPSTREAM_TOKEN',json.dumps(report))
        self.assertNotIn('PRIVATE_UPSTREAM_TOKEN',(self.directory/'update.json').read_text())
    def test_ack_lost_after_bridge_apply_uses_persisted_remote_receipt(self):
        self.backend.apply_ack_lost=True;report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report);self.assertEqual(len(self.modes('apply')),1)
        self.assertEqual(len(self.modes('rollback-all')),1);self.assertFalse(self.backend.applied)
    def test_ack_lost_after_maintenance_enable_does_not_leave_an_orphan_marker(self):
        self.backend.enable_ack_lost=True;report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report);self.assertIsNone(self.backend.marker)
        self.assertFalse(self.modes('apply'))
    def test_failed_rollback_retains_marker_and_resume_finishes_rollback_only(self):
        self.backend.fail_decode_ip=IPS[0];self.backend.fail_rollback=True;report=self.execute()
        self.assertEqual(report['status'],'failed');self.assertIsNotNone(self.backend.marker)
        self.assertFalse(self.installers('rollback'));self.assertEqual(len(self.modes('apply')),1)
        self.backend.fail_rollback=False
        report=Update(self.backend,self.directory,resume=True).run()
        self.assertEqual(report['status'],'rolled-back',report);self.assertIsNone(self.backend.marker)
        self.assertEqual(len(self.modes('apply')),1);self.assertFalse(self.backend.applied)
    def test_failed_maintenance_cleanup_retains_marker(self):
        self.backend.fail_clear=True;report=self.execute()
        self.assertFalse(report['ok']);self.assertEqual(report['status'],'failed');self.assertIsNotNone(self.backend.marker)
    def test_partial_native_rollback_proof_cannot_clear_marker(self):
        self.backend.fail_decode_ip=IPS[0];self.backend.native_after_rollback_partial=True;report=self.execute()
        self.assertEqual(report['status'],'failed',report);self.assertIsNotNone(self.backend.marker)
    def test_ack_lost_after_marker_removal_reacquires_lease_before_host_rollback(self):
        self.backend.clear_ack_lost=True;report=self.execute()
        self.assertEqual(report['status'],'rolled-back',report)
        for row in self.modes('rollback-all')+self.installers('rollback'):
            self.assertIsNotNone(row[-1],'host rollback ran without owned maintenance')
    def test_stale_process_lock_file_does_not_prevent_resume(self):
        update=Update(self.backend,self.directory)
        (self.directory/'controller.lock').write_text('expired process metadata')
        report=update.run();self.assertTrue(report['ok'],report)
    def test_live_process_lock_prevents_any_controller_host_action(self):
        from reolink_protect_events.operations.locking import process_lock
        update=Update(self.backend,self.directory)
        with process_lock(self.directory/'controller.lock'):
            with self.assertRaises(Exception):update.run()
        self.assertFalse(self.backend.calls);self.assertIsNone(self.backend.marker)
    def test_modified_frozen_workers_cannot_be_loaded_by_resume(self):
        self.backend.fail_decode_ip=IPS[0];self.backend.fail_rollback=True
        self.execute();before=len(self.backend.calls)
        (self.directory/'operation-sources.json').write_text(json.dumps({'events':'unreviewed-worker','bridge':{}}))
        with self.assertRaisesRegex(RuntimeError,'^frozen_operation_sources_changed$'):
            Update(self.backend,self.directory,resume=True)
        self.assertEqual(len(self.backend.calls),before)
    def test_crash_before_initial_freeze_can_resume_without_prior_host_mutations(self):
        Update(self.backend,self.directory)
        self.assertFalse(self.backend.calls)
        result=Update(self.backend,self.directory,resume=True).run()
        self.assertTrue(result['ok'],result)


def persistent_recording_audio_missing(ip, cid):
    rows = [dict(host=ip, cameraId=cid, profile=profile, quality=quality, channel=channel,
                 ok=True, realVideoDecode=True, realAudioDecode=True, cleanDecode=True,
                 expectedDimensionsMatch=True, expectedAudioMatch=True, warningCategories={},
                 decodedTimestampErrors=0, errorCode=None, sdpMetadata={'videoCodec':'hevc'},
                 decodedDimensions=[[64,36]])
            for profile,quality,channel in (('main','high',0),('sub','low',2))]
    first = {k:rows[0][k] for k in ('host','cameraId','profile','quality','channel')}
    first.update(startMs=1001000,endMs=1025000,requestedExportSeconds=24,exportBytes=32768,
                 ok=False,errorCode='decode_recording_audio_missing',videoMetadataPreserved=True,
                 streams=[{'codec_type':'video','codec_name':'hevc','width':64,'height':36,
                           'start_time':'0.0','duration':'24.001'}])
    second = dict(copy.deepcopy(first),startMs=1025001,endMs=1049001)
    bad = dict(copy.deepcopy(second),exportAttempts=[first,second],exportRetryUsed=True)
    good = {k:rows[1][k] for k in ('host','cameraId','profile','quality','channel')}
    good.update(ok=True,decode={'ok':True,'realVideoDecode':True,'realAudioDecode':True})
    return {'ok':False,'realDecodes':False,'rtsp':rows,'recordings':[bad,good],
            'rtspProfileCoverage':{'expectedRequested':2,'checked':2,'passed':2,'allRequested':True},
            'recordedProfileCoverage':{'expectedRequested':2,'checked':2,'passed':1,'allRequested':False}}


class RecordingAudioRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve();self.directory=self.root/'release'
        self.backend=FakeBackend();self.cid=self.backend.identities[IPS[0]]
        self.failure=persistent_recording_audio_missing(IPS[0],self.cid)
        self.clock=[1000.0];self.recovered=False;self.native_calls=0;self.scoped_decodes=[]
        self.bad_precheck=False;self.native_failure_first=False;self.persistent_after_repair=False
        self.restore_proven=True;self.after_repair_failure=None
        original_udm,original_decode=self.backend.udm,self.backend.decode

        def dispatch(request,timeout=None):
            result=original_udm(request,timeout)
            if request['action']=='health' and request.get('cameraIds')==[self.cid]:
                self.native_calls+=1
                if self.native_failure_first and self.native_calls==1:
                    target=next(row for row in result['cameras'] if row['cameraId']==self.cid)
                    target.update(ok=False,protectHealthy=False,cause='native_empty');result['ok']=False
                if self.bad_precheck and self.native_calls==2:
                    target=next(row for row in result['cameras'] if row['cameraId']==self.cid)
                    target.update(ok=False,sourceHealthy=False);result['ok']=False
            if request['action']=='recover':
                self.assertEqual(timeout,300)
                saved=json.loads((self.directory/'update.json').read_text())
                self.assertEqual(saved['repairAttempts'],[self.cid],'attempt must be charged before remote dispatch')
                trigger=saved['evidence']['repair-trigger-'+self.cid]
                if trigger['cause']=='recording_audio_missing':
                    self.assertEqual(trigger['decodeEvidence'],self.failure)
                    self.assertEqual(saved['evidence']['camera-'+IPS[0]+'-decode-before-audio-repair'],self.failure)
                    self.assertTrue(saved['evidence']['camera-'+IPS[0]+'-audio-repair-precheck']['ok'])
                self.clock[0]+=60;self.recovered=True
                result['restoredOriginalTcp']=self.restore_proven
            return result

        def decode(ips=None,not_before_ms=None):
            result=original_decode(ips,not_before_ms)
            if ips==[IPS[0]]:
                self.scoped_decodes.append(not_before_ms);self.clock[0]+=120
                if not self.recovered or self.persistent_after_repair:
                    return copy.deepcopy(self.failure)
                if self.after_repair_failure is not None:
                    return copy.deepcopy(self.after_repair_failure)
            return result

        self.backend.udm,self.backend.decode=dispatch,decode

    def tearDown(self):self.temp.cleanup()

    def execute(self):
        with patch.object(orchestrator.time,'time',side_effect=lambda:self.clock[0]):
            return Update(self.backend,self.directory).run()

    def repairs(self):
        return [row for row in self.backend.calls if row[0]=='udm' and row[1]['action']=='recover']

    def test_exact_two_disjoint_video_only_exports_repair_once_and_decode_after_ack(self):
        self.assertTrue(orchestrator.recording_audio_repair_candidate(self.failure,IPS[0],self.cid))
        report=self.execute();self.assertTrue(report['ok'],report)
        self.assertEqual([row[1]['cameraId'] for row in self.repairs()],[self.cid])
        state=json.loads((self.directory/'update.json').read_text())
        self.assertEqual(state['repairAttempts'],[self.cid])
        boundary=state['recorderReadyAfterMs'][self.cid]
        self.assertEqual(boundary,1180000,'recording boundary must follow the successful remote ack')
        self.assertEqual(self.scoped_decodes,[1000000,boundary])
        self.assertGreater(boundary,self.failure['recordings'][0]['endMs'])
        self.assertTrue(state['evidence']['camera-'+IPS[0]+'-health-after-audio-repair']['ok'])
        self.assertEqual(state['evidence']['camera-'+IPS[0]]['afterRecorderReadyMs'],boundary)
        self.assertIsNone(self.backend.marker)

    def test_corrupt_codec_audio_clock_and_payload_errors_never_dispatch_recovery(self):
        original=copy.deepcopy(self.failure)
        for code in ('decode_recording_video_metadata_changed','decode_recording_probe_failed',
                     'decode_recording_tracks_invalid','decode_track_timing_invalid','decode_codec_mismatch',
                     'decode_export_timeout','decode_export_http_500','decode_export_http_503'):
            with self.subTest(code=code):
                self.failure=copy.deepcopy(original);self.failure['recordings'][0]['errorCode']=code
                report=self.execute();self.assertFalse(report['ok']);self.assertFalse(self.repairs())
                self.assertEqual(report['status'],'rolled-back',report)
                self.directory=self.root/code
        for mutation in ('payload','wrong_codec','bad_clock','overlap','one_attempt','rtsp','two_profiles'):
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(original);bad=value['recordings'][0]
                if mutation=='payload':bad['decode']={'ok':False,'realVideoDecode':False,'warningCategories':{'decodeErrors':1}}
                elif mutation=='wrong_codec':bad['exportAttempts'][1]['streams'][0]['codec_name']='h264'
                elif mutation=='bad_clock':bad['exportAttempts'][1]['streams'][0]['duration']='NaN'
                elif mutation=='overlap':bad['exportAttempts'][1]['startMs']=bad['exportAttempts'][0]['endMs']
                elif mutation=='one_attempt':bad['exportAttempts'].pop()
                elif mutation=='rtsp':value['rtsp'][0].update(ok=False,realAudioDecode=False)
                elif mutation=='two_profiles':value['recordings'][1].update(ok=False,errorCode='decode_recording_audio_missing')
                self.assertFalse(orchestrator.recording_audio_repair_candidate(value,IPS[0],self.cid))

    def test_fresh_unhealthy_source_precheck_never_dispatches_audio_repair(self):
        self.bad_precheck=True
        report=self.execute()
        self.assertEqual(report['errorCode'],'recording_audio_repair_precheck_failed')
        self.assertEqual(report['status'],'rolled-back',report);self.assertFalse(self.repairs())

    def test_recording_and_native_failures_share_one_charged_repair_budget(self):
        self.native_failure_first=True;self.persistent_after_repair=True
        report=self.execute()
        self.assertEqual(report['errorCode'],'release_recorder_repair_limit')
        self.assertEqual(len(self.repairs()),1,'audio export failure cannot charge a second native rebuild')
        state=json.loads((self.directory/'update.json').read_text())
        self.assertEqual(state['repairAttempts'],[self.cid]);self.assertEqual(report['status'],'rolled-back',report)

    def test_existing_charged_attempt_prevents_another_audio_repair_before_dispatch(self):
        with patch.object(orchestrator.time,'time',side_effect=lambda:self.clock[0]):
            update=Update(self.backend,self.directory)
            update.state['frozen']=self.backend.freeze(self.directory)
            update.state['repairAttempts']=[self.cid]
            update.state['evidence']['repair-'+self.cid]={'restoredOriginalTcp':True}
            update.persist()
            with self.assertRaisesRegex(RuntimeError,'^release_recorder_repair_limit$'):
                update.verify_camera(IPS[0],self.cid,1000000)
        self.assertFalse(self.repairs())
        self.assertEqual(json.loads((self.directory/'update.json').read_text())['repairAttempts'],[self.cid])

    def test_audio_repair_requires_original_tcp_restore_proof_before_new_decode(self):
        self.restore_proven=False
        report=self.execute();self.assertEqual(report['errorCode'],'native_recorder_repair_failed')
        self.assertEqual(len(self.repairs()),1);self.assertEqual(len(self.scoped_decodes),1)
        self.assertEqual(report['status'],'failed',report);self.assertIsNotNone(self.backend.marker)

    def test_actual_postrepair_payload_failure_has_no_second_repair_or_decode_retry(self):
        self.after_repair_failure={'ok':False,'realDecodes':False,'errorCode':'decode_codec_mismatch'}
        report=self.execute();self.assertEqual(report['errorCode'],'real_media_decode_failed')
        self.assertEqual(len(self.repairs()),1);self.assertEqual(len(self.scoped_decodes),2)
        self.assertEqual(report['status'],'rolled-back',report)


class TransportTests(unittest.TestCase):
    def test_invalid_host_is_rejected_before_running_ssh(self):
        with patch.object(transport.subprocess,'run')as called:
            with self.assertRaises(ValueError):transport.invoke('.', 'alias;echo PRIVATE_TOKEN',{'action':'health'})
            called.assert_not_called()
    def test_remote_stderr_and_unparseable_reply_are_not_exposed(self):
        response=subprocess.CompletedProcess([],1,stdout='PRIVATE_UPSTREAM_TOKEN',stderr='PRIVATE_CONFIG_PASSWORD')
        with patch.object(transport,'source_bundle',return_value='safe'),patch.object(transport.subprocess,'run',return_value=response):
            with self.assertRaisesRegex(RuntimeError,'^operation_transport_failed$'):
                transport.invoke('.', 'unifi-dream-machine',{'action':'health'})
    def test_bootstrap_catches_upstream_secret_and_never_exports_private_config(self):
        sources={
          'reolink_protect_events/__init__.py':'',
          'reolink_protect_events/operations/__init__.py':'',
          'reolink_protect_events/operations/safety.py':"def private_path(p):return p\ndef read_json(p):return {'password':'PRIVATE_CONFIG_PASSWORD'}\n",
          'reolink_protect_events/operations/compatibility.py':"def assess(config):raise RuntimeError(config['password'])\n"}
        import base64,io,zipfile
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w')as archive:
            for name,text in sources.items():archive.writestr(name,text)
        payload={'sources':base64.b64encode(data.getvalue()).decode(),'request':{'action':'compatibility'}}
        result=subprocess.run([sys.executable,'-c',transport.BOOTSTRAP],input=json.dumps(payload),
                              capture_output=True,text=True,timeout=5)
        value=json.loads(result.stdout)
        self.assertFalse(value['ok']);self.assertEqual(value['errorCode'],'remote_operation_failed')
        self.assertNotIn('PRIVATE_',result.stdout)


class BackendFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.sources={p:{'sourceRevision':'1'*40,'sourceSha256':'a'*64,'sourceDirty':False}for p in ('bridge','events')}
        self.nas_code={'engine':'original-owned-engine'}
        self.nas=types.SimpleNamespace(source_bundle=lambda:copy.deepcopy(self.nas_code),
                                       invoke=unittest.mock.Mock(return_value={'ok':True}))
        self.bridge=types.SimpleNamespace(manifest=lambda *_a,**_k:copy.deepcopy(self.sources['bridge']),
            source_files=lambda _root:[],archive_sources=lambda _files,path,**_k:path.write_bytes(b'bridge-source'))
        self.package=b'events-package'
    def tearDown(self):self.temp.cleanup()
    def construct(self):
        return Backend(self.root/'bridge',self.root/'events','external-protected-connector.py',progress=lambda _:None)
    def test_actual_backend_keeps_captured_worker_sources_after_checkout_changes(self):
        with patch.object(orchestrator,'load_module',side_effect=[self.bridge,self.nas]),\
             patch.object(orchestrator,'source_bundle',return_value='original-owned-events')as bundle,\
             patch.object(orchestrator,'source_snapshot',side_effect=lambda *_a,**_k:copy.deepcopy(self.sources['events'])),\
             patch.object(orchestrator,'build_package',return_value=(self.package,{'version':'1.2.0',
                 'packageSha256':hashlib.sha256(self.package).hexdigest()})),\
             patch.object(orchestrator,'invoke',return_value={'ok':True})as remote:
            backend=self.construct();release=self.root/'frozen';release.mkdir()
            frozen=backend.freeze(release)
            bundle.return_value='unreviewed-new-events';self.nas_code['engine']='unreviewed-new-engine'
            backend.udm({'action':'health'});backend.nas({'mode':'inventory'})
            self.assertEqual(remote.call_args.kwargs['sources'],'original-owned-events')
            self.assertEqual(self.nas.invoke.call_args.kwargs['sources'],{'engine':'original-owned-engine'})
            saved=json.loads((release/'operation-sources.json').read_text())
            self.assertEqual(saved,{'events':'original-owned-events','bridge':{'engine':'original-owned-engine'}})
            self.assertEqual(frozen['sources']['events']['sourceSha256'],'a'*64)
    def test_actual_backend_source_mismatch_prevents_every_forward_host_dispatch(self):
        with patch.object(orchestrator,'load_module',side_effect=[self.bridge,self.nas]),\
             patch.object(orchestrator,'source_bundle',return_value='original-owned-events'),\
             patch.object(orchestrator,'source_snapshot',side_effect=lambda *_a,**_k:copy.deepcopy(self.sources['events'])),\
             patch.object(orchestrator,'build_package',return_value=(self.package,{'version':'1.2.0',
                 'packageSha256':hashlib.sha256(self.package).hexdigest()})),\
             patch.object(orchestrator,'invoke',return_value={'ok':True})as remote:
            backend=self.construct();update=Update(backend,self.root/'release')
            update.state['frozen']=backend.freeze(update.directory);update.persist()
            self.sources['events']['sourceSha256']='b'*64
            result=update.run()
            self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],'sources_changed_since_release_freeze')
            remote.assert_not_called();self.nas.invoke.assert_not_called()


if __name__=='__main__':unittest.main()
