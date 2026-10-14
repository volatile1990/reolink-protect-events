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
            for kind in (('main',)if host.endswith('.215')else('main','sub'))]


def success(row,recorded=False):
    result=dict(decode._public_profile(row),ok=True,realVideoDecode=True,realAudioDecode=True)
    if recorded:
        result['decode']={'realVideoDecode':True,'realAudioDecode':True,'ok':True}
        result.pop('realVideoDecode');result.pop('realAudioDecode')
    return result


class DecodeScopeTests(unittest.TestCase):
    def test_private_payload_strict_scope_and_profile_coverage(self):
        rows=all_profiles()
        self.assertEqual(len(decode._private_profiles({'ok':True,'profiles':rows},sorted(HOSTS))),11)
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
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='discover')
        now=START+300000;recording_end=now-5000;start=recording_end-30000-decode.EXPORT_WINDOW_MS
        camera={'id':'1'*24,'host':'192.168.30.215','channels':[{'id':0,'enabled':True,'width':64,'height':36}],
                'stats':{'video':{'recordingEnd':recording_end,'recordingStart':START}}}
        config={'bridges':[{'cameraId':camera['id'],'host':camera['host'],
                            'username':'private-user','password':SECRET}]}
        uri=Mock(return_value='rtsp://192.168.30.215:8554/main')
        namespace={'EXPORT_WINDOW_MS':decode.EXPORT_WINDOW_MS,'need':decode.need,
                   'context':lambda:(config,[camera]),'time':types.SimpleNamespace(time=lambda:now/1000),
                   'qualities':lambda _:[('high','recordingEnd',0)],'uri_for':uri,
                   'bridge_metrics':lambda _:{'streams':[{'profile':'main','codec':'H264','width':64,'height':36}]},
                   'payload':{'lagSeconds':30,'notBeforeMs':start+1}}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<public-discover-test>','exec'),namespace)
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
        self.assertFalse(result['recordedProfileCoverage']['allEleven'])
        network.assert_not_called()

    def test_validations_fail_before_subprocess_or_private_input(self):
        for options in ({'duration':2},{'duration':float('nan')},{'duration':True},
                        {'config_path':'/etc/shadow'},{'ips':['192.168.30.216']},
                        {'ips':['192.168.30.210']*2},{'recording_lag_seconds':0},
                        {'remote_release':'/tmp/release'},{'not_before_ms':int(time.time()*1000)+60000}):
            with self.subTest(options=options),patch.object(decode,'_run_bytes')as network:
                result=decode.run_full_decodes(**options)
                self.assertFalse(result['ok']);network.assert_not_called()

    def test_full_gate_requires_actual_decodes_and_all_eleven_reports(self):
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
        self.assertTrue(result['recordedProfileCoverage']['allEleven'])
        self.assertTrue(result['rtspProfileCoverage']['allEleven'])
        self.assertEqual(len(calls),22)
        self.assertEqual([kind for kind,_,_ in calls],['live','recorded']*11)
        self.assertNotIn(SECRET,json.dumps(result));self.assertNotIn('rtsp://',json.dumps(result))
        self.assertTrue(result['newRecordingGateRequired'])

    def test_scoped_result_never_claims_all_profiles(self):
        rows=[profile()]
        async def captured(*_,**kwargs):return 0,json.dumps({'ok':True,'profiles':rows}).encode(),b''
        async def live(row,*_):return success(row)
        async def recorded(row,*_):return success(row,True)
        with patch.object(decode,'_executable',side_effect=lambda _,name:'/public/'+name), \
             patch.object(decode,'_run_bytes',side_effect=captured), \
             patch.object(decode,'_rtsp_decode',side_effect=live),patch.object(decode,'_recorded_decode',side_effect=recorded):
            result=decode.run_full_decodes(ips=['192.168.30.215'])
        self.assertTrue(result['ok'])
        self.assertEqual(result['recordedProfileCoverage']['expectedRequested'],1)
        self.assertFalse(result['recordedProfileCoverage']['allEleven'])

    def test_metadata_only_result_is_not_a_real_decode(self):
        rows=[profile()]
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
