"""Projected full-decode gates plus real bounded local MP4 decode integration."""
import asyncio
import ast
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import types
import urllib.parse
import unittest
from unittest.mock import Mock, patch

from reolink_protect_events.operations import decode
from reolink_protect_events.operations.rtsp_proxy import (
    BoundedLines, ProbeError, Route, Warnings, rewrite_sdp)
from reolink_protect_events.operations.safety import HOSTS, OperationError

SECRET = 'private-password-for-test'
START = 1791586947512


def profile(host='192.168.30.215', kind='main'):
    return {'host':host,'cameraId':('%024x'%int(host.split('.')[-1])),
            'profile':kind,'quality':'high'if kind=='main'else'low','channel':0 if kind=='main'else 2,
            'url':'rtsp://'+host+':8554/'+kind,'username':'private-user','password':SECRET,
            'expectedCodec':'h264','expectedWidth':64,'expectedHeight':36,
            'startMs':START,'endMs':START+decode.EXPORT_WINDOW_MS}


def all_profiles():
    return [profile(host,kind)for host in sorted(HOSTS)
            for kind in ('main','sub')]


def camera_profiles(row):
    return [dict(row,profile=kind,quality='high'if kind=='main'else'low',channel=0 if kind=='main'else 2)
            for kind in ('main','sub')]


def success(row,recorded=False):
    result=dict(decode._public_profile(row),ok=True,realVideoDecode=True,realAudioDecode=True)
    if recorded:
        result['decode']={'realVideoDecode':True,'realAudioDecode':True,'ok':True}
        result.pop('realVideoDecode');result.pop('realAudioDecode')
    return result


class DecodeScopeTests(unittest.TestCase):
    def test_private_payload_strict_scope_and_profile_coverage(self):
        rows=all_profiles()
        self.assertEqual(len(decode._private_profiles({'ok':True,'profiles':rows},sorted(HOSTS))),12)
        for mutation in ('extra','missing','duplicate','foreign','credentials','profile','url','short','long'):
            value=copy.deepcopy(rows)
            if mutation=='extra':value[0]['bootstrap']={'token':SECRET}
            elif mutation=='missing':value.pop()
            elif mutation=='duplicate':value[-1]=value[0]
            elif mutation=='foreign':value[0]['host']='192.168.30.216'
            elif mutation=='credentials':value[0]['username']='bad:user'
            elif mutation=='profile':value[0]['channel']=1
            elif mutation=='short':value[0]['endMs']-=1000
            elif mutation=='long':value[0]['endMs']+=1000
            else:value[0]['url']='rtsp://private-user:'+SECRET+'@'+value[0]['host']+':8554/main'
            with self.subTest(mutation=mutation),self.assertRaises((OperationError,ValueError)):
                decode._private_profiles({'ok':True,'profiles':value},sorted(HOSTS))

    def test_decoder_command_contains_only_loopback_not_authentication(self):
        url='rtsp://127.0.0.1:49152/probe'
        command=decode._decode_command('/public/ffmpeg',url,5,rtsp=True)
        self.assertNotIn(SECRET,' '.join(command))
        self.assertIn('showinfo=checksum=0',command)
        self.assertIn('pcm_s16le',command)
        self.assertEqual(command[command.index('-i')+1],url)
        self.assertNotIn('-c:v',command)  # No passthrough shortcut to fake decode.
        self.assertEqual(decode._ssh_command('unifi-dream-machine')[-1],'python3 -')
        for alias in ('-evil','host; echo bad','host\nother','user@host'):
            with self.assertRaises(OperationError):decode._ssh_command(alias)

    def test_remote_input_has_no_credentials_and_only_allowed_read_actions(self):
        payload={'action':'discover','configPath':decode.DEFAULT_CONFIG,'remoteRelease':None,
                 'ips':['192.168.30.215'],'lagSeconds':30,'notBeforeMs':None,'exportWindowMs':decode.EXPORT_WINDOW_MS}
        source=decode._remote_source(payload)
        self.assertNotIn(SECRET.encode(),source)
        self.assertNotIn(b'private-user',source)
        compile(source,'<remote>','exec')
        self.assertIn(b"/api/video/export?",source)
        self.assertIn(b"timeout=35,limit=67108864",source)
        self.assertIn(b"connection.request('POST','/onvif/media_service'",source)
        self.assertNotIn(b"request('PATCH'",source)
        self.assertNotIn(b'systemctl',source)

    def test_export_window_is_fixed_in_local_and_remote_input(self):
        self.assertEqual(decode.EXPORT_WINDOW_SECONDS,24)
        self.assertEqual(decode.EXPORT_WINDOW_MS,24000)
        self.assertEqual(decode.MIN_RECORDED_SECONDS,19)
        payload={'action':'unsupported','configPath':decode.DEFAULT_CONFIG,'remoteRelease':None,
                 'ips':['192.168.30.215'],'lagSeconds':30,'notBeforeMs':None,'exportWindowMs':decode.EXPORT_WINDOW_MS}
        source=decode._remote_source(payload).decode()
        encoded=ast.literal_eval(re.search(r'payload=json.loads\(base64.b64decode\(([^\n]+)\)\)',source)[1])
        original=json.loads(base64.b64decode(encoded))
        for window in (None,True,20000,23000,25000):
            value=dict(payload,exportWindowMs=window)
            with self.subTest(window=window),self.assertRaisesRegex(OperationError,'decode_export_window_invalid'):
                decode._remote_source(value)
            # Deliberately bypass the local validator to verify the public
            # Python3.9 helper independently rejects a tampered payload before
            # any configuration read, export, or network context is entered.
            altered=dict(original,exportWindowMs=window)
            changed=base64.b64encode(json.dumps(altered,separators=(',',':')).encode()).decode()
            remote=source.replace(repr(encoded),repr(changed)).encode()
            code,output,errors=asyncio.run(decode._run_bytes([sys.executable,'-B','-'],
                 input_data=remote,timeout=5,stdout_limit=1024))
            self.assertEqual(code,2)
            self.assertEqual(json.loads(output),{'ok':False,'errorCode':'decode_export_window_invalid'})
            self.assertEqual(errors,b'')

    def test_entire_export_window_must_follow_activation_before_any_viewer(self):
        tree=ast.parse(decode._REMOTE_COMMON)
        functions=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in ('current_source','discover')]
        now=START+300000;recording_end=now-5000;start=recording_end-30000-decode.EXPORT_WINDOW_MS
        camera={'id':'1'*24,'host':'192.168.30.215','channels':[{'id':0,'enabled':True,'width':64,'height':36}],
                'state':'CONNECTED','isConnected':True,'hasRecordingStarted':True,'videoReconfigurationInProgress':False,
                'thirdPartyCameraInfo':{'enableRtspAudio':True},
                'stats':{'video':{'recordingEnd':recording_end,'recordingStart':START}}}
        config={'bridges':[{'cameraId':camera['id'],'host':camera['host'],
                            'username':'private-user','password':SECRET}]}
        uri=Mock(return_value='rtsp://192.168.30.215:8554/main')
        namespace={'EXPORT_WINDOW_MS':decode.EXPORT_WINDOW_MS,'need':decode.need,
                   'context':lambda:(config,[camera]),'time':types.SimpleNamespace(time=lambda:now/1000),
                   'qualities':lambda _:[('high','recordingEnd',0)],'uri_for':uri,
                   'bridge_metrics':lambda _:{'status':'ready','streams':[{'profile':'main','codec':'H264','width':64,'height':36,
                         'liveVideo':True,'videoReady':True,'lastVideoAgeMs':100,
                         'audio':{'available':True,'metadataCurrent':True,'sampleRate':16000}}]},
                   'payload':{'lagSeconds':30,'notBeforeMs':start+1}}
        exec(compile(ast.Module(body=functions,type_ignores=[]),'<public-discover-test>','exec'),namespace)
        with self.assertRaisesRegex(OperationError,'decode_new_recording_pending'):
            namespace['discover']()
        uri.assert_not_called()
        namespace['payload']['notBeforeMs']=start
        result=namespace['discover']();row=result['profiles'][0]
        self.assertEqual((row['startMs'],row['endMs']),(start,start+decode.EXPORT_WINDOW_MS))
        uri.assert_called_once()

    def test_minimum_delivered_tracks_is_preserved_before_real_five_second_decode(self):
        row=profile();payload={'action':'discover','configPath':decode.DEFAULT_CONFIG,'remoteRelease':None,
              'ips':[row['host']],'lagSeconds':30,'notBeforeMs':START,'exportWindowMs':decode.EXPORT_WINDOW_MS}
        streams=[{'codec_type':'video','codec_name':'h264','width':64,'height':36,'start_time':'0','duration':'19.000'},
                 {'codec_type':'audio','codec_name':'aac','channels':1,'sample_rate':'16000','start_time':'0','duration':'19.000'}]
        async def read(command,**kwargs):
            return (0,b'0000ftyp'+b'x'*32,b'')if command[0]=='ssh'else(0,json.dumps({'streams':streams}).encode(),b'')
        fake_server=Mock(url='http://127.0.0.1:49152/recording.mp4')
        async def actual_decode(*args):
            return {'ok':True,'realVideoDecode':True,'realAudioDecode':True}
        with patch.object(decode,'_run_bytes',side_effect=read),patch.object(decode,'_MemoryServer',return_value=fake_server), \
             patch.object(decode,'_decode_av',side_effect=actual_decode)as actual:
            passed=asyncio.run(decode._recorded_decode(row,'ffmpeg','ffprobe',5,['ssh'],payload))
            self.assertTrue(passed['ok'],passed)
            self.assertEqual(passed['requestedExportSeconds'],24)
            self.assertEqual(passed['minimumRecordedSeconds'],19)
            self.assertEqual(actual.call_args.args[2],5)
            for video_seconds,audio_seconds in ((18.823,18.752),(18.999,19),(19,18.999)):
                actual.reset_mock()
                streams[0]['duration']=str(video_seconds);streams[1]['duration']=str(audio_seconds)
                failed=asyncio.run(decode._recorded_decode(row,'ffmpeg','ffprobe',5,['ssh'],payload))
                self.assertFalse(failed['ok'])
                self.assertEqual(failed['errorCode'],'decode_recording_export_too_short')
                actual.assert_not_called()
            streams[0]['duration']='19';streams[1]['duration']='19.351'
            mismatch=asyncio.run(decode._recorded_decode(row,'ffmpeg','ffprobe',5,['ssh'],payload))
            self.assertFalse(mismatch['ok'])
            self.assertFalse(mismatch['deliveredTimelineDurationsCompatible'])

    def test_tools_missing_is_explicit_failure_before_ssh(self):
        with patch.object(decode.shutil,'which',return_value=None),patch.object(decode,'_run_bytes')as network:
            result=decode.run_full_decodes()
        self.assertFalse(result['ok']);self.assertFalse(result['realDecodes'])
        self.assertEqual(result['errorCode'],'local_ffmpeg_unavailable')
        self.assertFalse(result['recordedProfileCoverage']['allProfiles'])
        network.assert_not_called()

    def test_validations_fail_before_subprocess_or_private_input(self):
        for options in ({'duration':2},{'duration':float('nan')},{'duration':True},
                        {'config_path':'/etc/shadow'},{'ips':['192.168.30.216']},
                        {'ips':['192.168.30.210']*2},{'recording_lag_seconds':0},
                        {'remote_release':'/tmp/release'},{'not_before_ms':int(time.time()*1000)+60000}):
            with self.subTest(options=options),patch.object(decode,'_run_bytes')as network:
                result=decode.run_full_decodes(**options)
                self.assertFalse(result['ok']);network.assert_not_called()

    def test_full_gate_requires_actual_decodes_and_all_twelve_reports(self):
        rows=all_profiles();calls=[]
        async def captured(command,**kwargs):
            self.assertEqual(command[-1],'python3 -')
            self.assertEqual(kwargs['stdout_limit'],decode.MAX_PRIVATE_JSON)
            self.assertLessEqual(kwargs['timeout'],150)
            return 0,json.dumps({'ok':True,'profiles':rows}).encode(),b''
        async def live(row,*_):calls.append(('live',row['host'],row['profile']));return success(row)
        async def recorded(row,*_):calls.append(('recorded',row['host'],row['profile']));return success(row,True)
        with patch.object(decode,'_executable',side_effect=lambda _,name:'/public/'+name), \
             patch.object(decode,'_run_bytes',side_effect=captured), \
             patch.object(decode,'_rtsp_decode',side_effect=live),patch.object(decode,'_recorded_decode',side_effect=recorded):
            result=decode.run_full_decodes(not_before_ms=START)
        self.assertTrue(result['ok']);self.assertTrue(result['realDecodes'])
        self.assertTrue(result['recordedProfileCoverage']['allProfiles'])
        self.assertTrue(result['rtspProfileCoverage']['allProfiles'])
        self.assertEqual(result['recordedProfileCoverage']['expectedFull'],12)
        self.assertEqual(len(calls),24)
        self.assertEqual([kind for kind,_,_ in calls],['live','recorded']*12)
        self.assertNotIn(SECRET,json.dumps(result));self.assertNotIn('rtsp://',json.dumps(result))
        self.assertTrue(result['newRecordingGateRequired'])

    def test_scoped_result_never_claims_all_profiles(self):
        rows=camera_profiles(profile())
        async def captured(*_,**kwargs):return 0,json.dumps({'ok':True,'profiles':rows}).encode(),b''
        async def live(row,*_):return success(row)
        async def recorded(row,*_):return success(row,True)
        with patch.object(decode,'_executable',side_effect=lambda _,name:'/public/'+name), \
             patch.object(decode,'_run_bytes',side_effect=captured), \
             patch.object(decode,'_rtsp_decode',side_effect=live),patch.object(decode,'_recorded_decode',side_effect=recorded):
            result=decode.run_full_decodes(ips=['192.168.30.215'])
        self.assertTrue(result['ok'])
        self.assertEqual(result['recordedProfileCoverage']['expectedRequested'],2)
        self.assertFalse(result['recordedProfileCoverage']['allProfiles'])

    def test_vorhaus_main_only_is_incomplete_even_when_its_hq_passes(self):
        rows=camera_profiles(profile())
        with self.assertRaisesRegex(OperationError,'decode_profile_coverage_invalid'):
            decode._private_profiles({'ok':True,'profiles':rows[:1]},['192.168.30.215'])
        coverage=decode._coverage(rows,[success(rows[0])])
        self.assertEqual(coverage['expectedRequested'],2)
        self.assertFalse(coverage['allRequested'])
        self.assertFalse(coverage['allProfiles'])

    def test_metadata_only_result_is_not_a_real_decode(self):
        rows=camera_profiles(profile())
        async def captured(*_,**kwargs):return 0,json.dumps({'ok':True,'profiles':rows}).encode(),b''
        async def metadata(row,*_):return dict(decode._public_profile(row),ok=True)
        with patch.object(decode,'_executable',side_effect=lambda _,name:'/public/'+name), \
             patch.object(decode,'_run_bytes',side_effect=captured), \
             patch.object(decode,'_rtsp_decode',side_effect=metadata),patch.object(decode,'_recorded_decode',side_effect=metadata):
            result=decode.run_full_decodes(ips=['192.168.30.215'])
        self.assertFalse(result['ok']);self.assertFalse(result['realDecodes'])

    def test_track_timelines_are_measured_without_capture_sync_claim(self):
        result=decode.timeline_comparison({'start_time':'0.0','duration':'20.0'},
                                         {'start_time':'0.01','duration':'20.04'})
        self.assertTrue(result['deliveredTimelineDurationsCompatible'])
        self.assertFalse(result['captureSynchronizationMeasured'])
        result=decode.timeline_comparison({'start_time':'0','duration':'12'},
                                         {'start_time':'0','duration':'20'})
        self.assertFalse(result['deliveredTimelineDurationsCompatible'])

    def test_projected_metadata_drops_tags_and_rejects_arbitrary_strings(self):
        raw={'streams':[{'codec_type':'video','codec_name':'h264','width':64,'height':36,
                         'start_time':'0.00','duration':'20','tags':{'private':SECRET}}]}
        result=decode._project_streams(raw)
        self.assertNotIn(SECRET,json.dumps(result));self.assertNotIn('tags',result[0])
        raw['streams'][0]['duration']=SECRET
        with self.assertRaises(OperationError):decode._project_streams(raw)

    def test_frame_observation_and_warnings_are_categorical(self):
        logs=decode.DecodeLogs()
        logs.line('[Parsed_showinfo_0 @ 1] [info] n: 0 pts: 0 pts_time:0 fmt:yuv420p s:64x36')
        logs.line('[Parsed_showinfo_0 @ 1] [info] n: 1 pts: 0 pts_time:0.05 fmt:yuv420p s:64x36')
        logs.line('[h264 @ 1] [warning] error while decoding '+SECRET)
        self.assertEqual(logs.video_frames,2);self.assertEqual(logs.dimensions,{(64,36)})
        self.assertEqual(logs.warnings.categories['decodeErrors'],1)
        self.assertNotIn(SECRET,json.dumps(dict(logs.warnings.categories)))
        lines=BoundedLines(logs.line);lines.feed((SECRET*2000+'\n').encode())
        self.assertEqual(lines.overlong,1)

    def test_proxy_rewrites_only_exact_bridge_and_hides_authorization_route(self):
        endpoint=decode.urllib.parse.urlsplit(profile()['url'])
        route=Route(endpoint,8554,49152)
        self.assertEqual(route.upstream('rtsp://127.0.0.1:49152/probe/trackID=0'),
                         'rtsp://192.168.30.215:8554/main/trackID=0')
        for uri in ('rtsp://192.168.30.216:8554/main','rtsp://private-user:'+SECRET+'@192.168.30.215:8554/main'):
            with self.assertRaises(ProbeError):route.local(uri)
        sdp=b'v=0\r\na=control:rtsp://192.168.30.215:8554/main/trackID=0\r\nc=IN IP4 192.168.30.215\r\n'
        rewritten=rewrite_sdp(sdp,route)
        self.assertNotIn(b'192.168.30.215',rewritten)
        self.assertIn(b'127.0.0.1',rewritten)

    def test_child_process_total_timer_and_capture_limit(self):
        async def run():
            began=time.monotonic()
            with self.assertRaisesRegex(OperationError,'subprocess_total_deadline'):
                await decode._run_bytes([sys.executable,'-B','-c','import time;time.sleep(20)'],
                                        timeout=.1,stdout_limit=10)
            self.assertLess(time.monotonic()-began,3)
            with self.assertRaisesRegex(OperationError,'subprocess_output_limit'):
                await decode._run_bytes([sys.executable,'-B','-c','print("x"*1000)'],timeout=2,stdout_limit=10)
        asyncio.run(run())

    def test_http_proxy_environment_is_removed_for_local_media(self):
        with patch.dict(os.environ,{'HTTP_PROXY':'http://foreign.invalid','https_proxy':'http://foreign.invalid'}):
            result=decode._process_env()
        self.assertFalse(any(key.lower()in ('http_proxy','https_proxy','all_proxy')for key in result))
        self.assertEqual(result['no_proxy'],'127.0.0.1,localhost')

    def test_ram_range_server_exact_path_no_redirect_and_bounded_range(self):
        server=decode._MemoryServer(b'0123456789')
        try:
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
            conn.request('GET','/recording.mp4',headers={'Range':'bytes=2-4'})
            response=conn.getresponse();self.assertEqual(response.status,206);self.assertEqual(response.read(),b'234');conn.close()
            for path,headers,status in (('/private',{},404),('/recording.mp4',{'Range':'bytes=0-2,4-5'},416)):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                conn.request('GET',path,headers=headers);response=conn.getresponse()
                self.assertEqual(response.status,status);self.assertIsNone(response.getheader('Location'));response.read();conn.close()
        finally:server.close()
        self.assertEqual(server.video,b'')


class ExportRetryTests(unittest.TestCase):
    def setUp(self):
        self.row=profile();self.elapsed=0;self.readiness_calls=[];self.sleeps=[]
        self.payload={'action':'discover','configPath':decode.DEFAULT_CONFIG,'remoteRelease':None,
             'ips':[self.row['host']],'lagSeconds':30,'notBeforeMs':START,'exportWindowMs':decode.EXPORT_WINDOW_MS}
    def first_failure(self,code='decode_recording_audio_missing'):
        return dict(decode._public_profile(self.row),startMs=self.row['startMs'],endMs=self.row['endMs'],
             requestedExportSeconds=24,ok=False,errorCode=code,exportBytes=32768,
             streams=[{'codec_type':'video','codec_name':'h264','width':64,'height':36,
                       'start_time':'0','duration':'25.770'}],videoMetadataPreserved=True)
    def fresh(self,boundary=None):
        boundary=max(self.row['endMs']+1,self.payload.get('notBeforeMs')or 0)if boundary is None else boundary
        return dict(self.row,startMs=boundary,endMs=boundary+decode.EXPORT_WINDOW_MS)
    def clock(self):return self.elapsed
    async def sleep(self,seconds):self.sleeps.append(seconds);self.elapsed+=seconds
    def test_one_retry_preserves_first_projection_and_actual_second_decode(self):
        first=self.first_failure();second=dict(success(self.fresh(),True),startMs=self.fresh()['startMs'],endMs=self.fresh()['endMs'])
        request=dict(self.payload,notBeforeMs=self.row['endMs']+1)
        async def ready(*args):return self.fresh(),request
        with patch.object(decode,'_recorded_once',side_effect=[first,second])as once, \
             patch.object(decode,'_retry_recording_profile',side_effect=ready)as wait:
            result=asyncio.run(decode._recorded_decode(self.row,'ffmpeg','ffprobe',5,['ssh'],self.payload))
        self.assertTrue(result['ok']);self.assertTrue(result['exportRetryUsed'])
        self.assertEqual(result['exportAttempts'],[first,second]);self.assertEqual(once.call_count,2)
        self.assertEqual(once.call_args.args[0]['startMs'],self.row['endMs']+1)
        self.assertEqual(once.call_args.args[3],5);wait.assert_called_once()
        self.assertNotIn(SECRET,json.dumps(result));self.assertNotIn('rtsp://',json.dumps(result))
    def test_persistent_missing_audio_or_timeout_never_gets_a_third_export(self):
        for code in decode.EXPORT_RETRY_ERRORS:
            first=self.first_failure(code);second=dict(first,startMs=self.fresh()['startMs'],endMs=self.fresh()['endMs'])
            async def ready(*args):return self.fresh(),dict(self.payload,notBeforeMs=self.row['endMs']+1)
            with self.subTest(code=code),patch.object(decode,'_recorded_once',side_effect=[first,second])as once, \
                 patch.object(decode,'_retry_recording_profile',side_effect=ready):
                result=asyncio.run(decode._recorded_decode(self.row,'ffmpeg','ffprobe',5,['ssh'],self.payload))
                self.assertFalse(result['ok']);self.assertEqual(len(result['exportAttempts']),2)
                self.assertEqual(once.call_count,2);self.assertEqual(result['errorCode'],code)
    def test_readiness_failure_preserves_first_failed_attempt(self):
        first=self.first_failure()
        with patch.object(decode,'_recorded_once',return_value=first)as once, \
             patch.object(decode,'_retry_recording_profile',side_effect=OperationError('decode_source_audio_unhealthy')):
            result=asyncio.run(decode._recorded_decode(self.row,'ffmpeg','ffprobe',5,['ssh'],self.payload))
        self.assertFalse(result['ok']);self.assertFalse(result['exportRetryUsed'])
        self.assertEqual(result['exportAttempts'],[first]);self.assertEqual(once.call_count,1)
        self.assertEqual(result['retryReadinessErrorCode'],'decode_source_audio_unhealthy')
    def test_actual_decode_or_hard_export_failures_are_never_retried(self):
        failures=[self.first_failure(code)for code in ('decode_remote_read_failed','decode_export_rejected',
             'decode_export_payload_invalid','decode_recording_tracks_invalid','decode_recording_export_too_short',
             'decode_recording_probe_failed','decode_recording_video_metadata_changed','decode_track_timing_invalid')]
        for code in decode.EXPORT_RETRY_ERRORS:
            failures.append(dict(self.first_failure(code),decode={'ok':False,'warningCategories':{'decodeErrors':1}}))
        failures.append(dict(self.first_failure(None),decode={'ok':False,'decodedTimestampErrors':1}))
        for first in failures:
            with self.subTest(first=first),patch.object(decode,'_recorded_once',return_value=first)as once, \
                 patch.object(decode,'_retry_recording_profile')as wait:
                result=asyncio.run(decode._recorded_decode(self.row,'ffmpeg','ffprobe',5,['ssh'],self.payload))
                self.assertIs(result,first);once.assert_called_once();wait.assert_not_called()
    def test_readiness_uses_strictly_new_window_and_original_not_before(self):
        self.payload['notBeforeMs']=self.row['endMs']+60000
        boundary=self.payload['notBeforeMs'];fresh=self.fresh(boundary)
        pending={'ok':False,'errorCode':'decode_new_recording_pending'}
        async def read(command,**kwargs):
            self.readiness_calls.append(kwargs)
            if len(self.readiness_calls)==1:return 2,json.dumps(pending).encode(),b''
            return 0,json.dumps({'ok':True,'profiles':camera_profiles(fresh)}).encode(),b''
        captured=[]
        def source(value):captured.append(value);return b'public-readonly-source'
        with patch.object(decode,'_run_bytes',side_effect=read),patch.object(decode,'_remote_source',side_effect=source):
            row,payload=asyncio.run(decode._retry_recording_profile(self.row,self.payload,['ssh'],clock=self.clock,sleep=self.sleep))
        self.assertEqual(row['startMs'],boundary);self.assertEqual(row['endMs']-row['startMs'],24000)
        self.assertEqual([p['notBeforeMs']for p in captured],[boundary,boundary])
        self.assertEqual(self.sleeps,[10]);self.assertEqual(payload['ips'],[self.row['host']])
    def test_readiness_pending_is_bounded_including_subprocess_cleanup(self):
        pending={'ok':False,'errorCode':'decode_new_recording_pending'}
        async def read(command,**kwargs):
            self.readiness_calls.append(kwargs)
            self.assertLessEqual(kwargs['timeout']+decode.SUBPROCESS_CLEANUP_RESERVE_SECONDS,120-self.elapsed)
            return 2,json.dumps(pending).encode(),b''
        with patch.object(decode,'_run_bytes',side_effect=read),patch.object(decode,'_remote_source',return_value=b'public'), \
             self.assertRaisesRegex(OperationError,'decode_export_retry_readiness_timeout'):
            asyncio.run(decode._retry_recording_profile(self.row,self.payload,['ssh'],clock=self.clock,sleep=self.sleep))
        self.assertLessEqual(self.elapsed,120);self.assertEqual(self.elapsed,118)
        self.assertLessEqual(len(self.readiness_calls),13)
    def test_readiness_network_time_and_cleanup_are_inside_one_120_second_budget(self):
        pending={'ok':False,'errorCode':'decode_new_recording_pending'}
        async def read(command,**kwargs):
            self.readiness_calls.append(kwargs)
            self.elapsed+=kwargs['timeout']+decode.SUBPROCESS_CLEANUP_RESERVE_SECONDS
            return 2,json.dumps(pending).encode(),b''
        with patch.object(decode,'_run_bytes',side_effect=read),patch.object(decode,'_remote_source',return_value=b'public'), \
             self.assertRaisesRegex(OperationError,'decode_export_retry_readiness_timeout'):
            asyncio.run(decode._retry_recording_profile(self.row,self.payload,['ssh'],clock=self.clock,sleep=self.sleep))
        self.assertEqual(self.elapsed,120);self.assertEqual(len(self.readiness_calls),3)
        self.assertEqual([call['timeout']for call in self.readiness_calls],[40,40,14])
    def test_whole_readiness_timer_cancels_a_stalled_process_creation(self):
        cancelled=[]
        async def stalled(command,**kwargs):
            try:await asyncio.sleep(60)
            finally:
                cancelled.append(True)
                await asyncio.sleep(.01)
        started=time.monotonic()
        with patch.object(decode,'EXPORT_RETRY_WAIT_SECONDS',.06), \
             patch.object(decode,'SUBPROCESS_CLEANUP_RESERVE_SECONDS',.01), \
             patch.object(decode,'_run_bytes',side_effect=stalled),patch.object(decode,'_remote_source',return_value=b'public'), \
             self.assertRaisesRegex(OperationError,'decode_export_retry_readiness_timeout'):
            asyncio.run(decode._retry_recording_profile(self.row,self.payload,['ssh']))
        self.assertEqual(cancelled,[True]);self.assertLess(time.monotonic()-started,.5)
    def test_fresh_readiness_rejects_overlap_metadata_change_and_source_failure(self):
        for mutation in ('overlap','codec','dimensions','source'):
            fresh=self.fresh()
            if mutation=='overlap':fresh['startMs']-=1;fresh['endMs']-=1
            if mutation=='codec':fresh['expectedCodec']='hevc'
            if mutation=='dimensions':fresh['expectedWidth']=128
            async def read(command,**kwargs):
                if mutation=='source':return 2,json.dumps({'ok':False,'errorCode':'decode_source_unhealthy'}).encode(),b''
                return 0,json.dumps({'ok':True,'profiles':camera_profiles(fresh)}).encode(),b''
            expected={'overlap':'decode_retry_window_overlaps_failed_export','codec':'decode_retry_profile_changed',
                      'dimensions':'decode_retry_profile_changed','source':'decode_source_unhealthy'}[mutation]
            with self.subTest(mutation=mutation),patch.object(decode,'_run_bytes',side_effect=read), \
                 patch.object(decode,'_remote_source',return_value=b'public'),self.assertRaisesRegex(OperationError,expected):
                asyncio.run(decode._retry_recording_profile(self.row,self.payload,['ssh'],clock=self.clock,sleep=self.sleep))
            self.assertFalse(self.sleeps)
    def test_single_expected_video_is_the_only_missing_audio_retry_shape(self):
        video={'codec_type':'video','codec_name':'h264','width':64,'height':36,'start_time':'0','duration':'25.770'}
        audio={'codec_type':'audio','codec_name':'aac','sample_rate':'16000','channels':1,'start_time':'0','duration':'25.770'}
        fixtures=[([video],'decode_recording_audio_missing'),
                  ([dict(video,codec_name='hevc')],'decode_recording_video_metadata_changed'),
                  ([dict(video,width=128)],'decode_recording_video_metadata_changed'),
                  ([video,video],'decode_recording_tracks_invalid'),([audio],'decode_recording_tracks_invalid'),
                  ([video,audio,audio],'decode_recording_tracks_invalid'),
                  ([dict(video,duration='18.999')],'decode_recording_export_too_short'),
                  ([dict(video,duration='-1')],'decode_track_timing_invalid'),
                  ([dict(video,start_time='not-a-time')],'decode_probe_metadata_invalid')]
        for streams,expected in fixtures:
            async def read(command,**kwargs):
                return (0,b'0000ftyp'+b'x'*32,b'')if command[0]=='ssh'else(0,json.dumps({'streams':streams}).encode(),b'')
            with self.subTest(expected=expected),patch.object(decode,'_run_bytes',side_effect=read), \
                 patch.object(decode,'_MemoryServer',return_value=Mock(url='http://127.0.0.1:49152/recording.mp4')), \
                 patch.object(decode,'_decode_av')as actual:
                result=asyncio.run(decode._recorded_once(self.row,'ffmpeg','ffprobe',5,['ssh'],self.payload))
                self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],expected)
                actual.assert_not_called()
    def test_remote_export_timeout_and_status_are_categorical_before_decode(self):
        tree=ast.parse(decode._REMOTE_COMMON)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='export')
        now=START+300000
        camera={'id':self.row['cameraId'],'host':self.row['host'],
                'stats':{'video':{'recordingEnd':now,'recordingStart':START}}}
        bridge={'cameraId':camera['id'],'host':camera['host']}
        namespace={'EXPORT_WINDOW_MS':decode.EXPORT_WINDOW_MS,'need':decode.need,'OperationError':OperationError,
             'context':lambda:({'bridges':[bridge]},[camera]),'current_source':Mock(),
             'time':types.SimpleNamespace(time=lambda:now/1000),'qualities':lambda _:[('high','recordingEnd',0)],
             'owner_headers':lambda _:{},'urllib':urllib,'sys':types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=Mock())),
             'payload':dict(self.payload,profile={key:self.row[key]for key in ('host','cameraId','quality','channel','startMs','endMs')})}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<public-export-test>','exec'),namespace)
        for status,expected in ((500,'decode_export_http_500'),(503,'decode_export_http_503'),(404,'decode_export_rejected')):
            namespace['get_bytes']=Mock(return_value=(status,b'private body'))
            with self.subTest(status=status),self.assertRaisesRegex(OperationError,expected):namespace['export']()
        namespace['get_bytes']=Mock(side_effect=TimeoutError(SECRET))
        with self.assertRaisesRegex(OperationError,'^decode_export_timeout$'):namespace['export']()
        namespace['get_bytes']=Mock(return_value=(200,b'corrupt'))
        with self.assertRaisesRegex(OperationError,'^decode_export_payload_invalid$'):namespace['export']()
    def test_fresh_remote_source_rejects_lost_video_audio_or_reconfiguration(self):
        tree=ast.parse(decode._REMOTE_COMMON)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='current_source')
        camera={'state':'CONNECTED','isConnected':True,'hasRecordingStarted':True,'videoReconfigurationInProgress':False,
                'thirdPartyCameraInfo':{'enableRtspAudio':True}}
        live={'status':'ready','streams':[{'profile':'main','liveVideo':True,'videoReady':True,'lastVideoAgeMs':100,
                'audio':{'available':True,'metadataCurrent':True,'sampleRate':16000}}]}
        namespace={'need':decode.need,'qualities':lambda _:[('high','recordingEnd',0)]}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<public-source-test>','exec'),namespace)
        namespace['bridge_metrics']=lambda _:live
        self.assertEqual(set(namespace['current_source']({},camera)),{'main'})
        for mutation in ('video','age','audio','rate','busy','duplicate'):
            source=copy.deepcopy(live);current=copy.deepcopy(camera)
            if mutation=='video':source['streams'][0]['liveVideo']=False
            if mutation=='age':source['streams'][0]['lastVideoAgeMs']=5001
            if mutation=='audio':source['streams'][0]['audio']['metadataCurrent']=False
            if mutation=='rate':source['streams'][0]['audio']['sampleRate']=48000
            if mutation=='busy':current['videoReconfigurationInProgress']=True
            if mutation=='duplicate':source['streams'].append(copy.deepcopy(source['streams'][0]))
            namespace['bridge_metrics']=lambda _:source
            with self.subTest(mutation=mutation),self.assertRaises(OperationError):
                namespace['current_source']({},current)


@unittest.skipUnless(shutil.which('ffmpeg')and shutil.which('ffprobe'),'real local decode integration requires FFmpeg/ffprobe')
class RealRecordedDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe=decode._executable(None,'ffmpeg');cls.probe=decode._executable(None,'ffprobe')
        async def generate():
            command=[cls.exe,'-hide_banner','-loglevel','error','-f','lavfi','-i','testsrc=size=64x36:rate=20',
                '-f','lavfi','-i','sine=frequency=440:sample_rate=16000','-t','20','-c:v','libx264','-pix_fmt','yuv420p',
                '-preset','ultrafast','-c:a','aac','-ac','1','-movflags','frag_keyframe+empty_moov','-f','mp4','pipe:1']
            code,data,_=await decode._run_bytes(command,timeout=15,stdout_limit=decode.MAX_MEDIA_BYTES)
            if code or not data:raise RuntimeError('local_fixture_generation_failed')
            return data
        cls.content=asyncio.run(generate())

    def test_real_local_video_and_pcm_decode_through_ram_server(self):
        row=profile();payload={'action':'discover','configPath':decode.DEFAULT_CONFIG,'remoteRelease':None,
                              'ips':[row['host']],'lagSeconds':30,'notBeforeMs':START,'exportWindowMs':decode.EXPORT_WINDOW_MS}
        original=decode._run_bytes
        async def read(command,**kwargs):
            if command[0]=='ssh':
                self.assertNotIn(SECRET.encode(),kwargs['input_data'])
                self.assertEqual(kwargs['stdout_limit'],decode.MAX_MEDIA_BYTES)
                return 0,self.content,b''
            return await original(command,**kwargs)
        with patch.object(decode,'_run_bytes',side_effect=read):
            result=asyncio.run(decode._recorded_decode(row,self.exe,self.probe,3,['ssh'],payload))
        self.assertTrue(result['ok'],result)
        self.assertTrue(result['videoMetadataPreserved'])
        self.assertTrue(result['decode']['realVideoDecode'])
        self.assertTrue(result['decode']['realAudioDecode'])
        self.assertGreaterEqual(result['decode']['videoFrames'],50)
        self.assertGreaterEqual(result['decode']['decodedPcmSampleFrames'],40000)
        self.assertEqual(result['decode']['decodedDimensions'],[[64,36]])
        self.assertFalse(result['captureSynchronizationMeasured'])
        self.assertNotIn(SECRET,json.dumps(result))


if __name__=='__main__':unittest.main()
