"""Synthetic native TCP startup framing, clocks, flags and secret-safe failures."""
import hashlib
import json
import socket
import struct
import unittest
from unittest.mock import patch
from reolink_protect_events.operations import fmp4
from reolink_protect_events.operations.safety import OperationError

CID='a'*24
EPOCH=1792230000*1000

def box(kind, data):return struct.pack('!I4s',len(data)+8,kind)+data

def initialization(audio=True,video_size=1,duration=100):
    tracks=[];defaults=[]
    for tid,kind in ((1,b'vide'),(2,b'soun')) if audio else ((1,b'vide'),):
        tkhd=box(b'tkhd',struct.pack('!IIII',0,0,0,tid))
        mdhd=box(b'mdhd',struct.pack('!IIII',0,0,0,1000))
        hdlr=box(b'hdlr',struct.pack('!II4s',0,0,kind))
        tracks.append(box(b'trak',tkhd+box(b'mdia',mdhd+hdlr)))
        defaults.append(box(b'trex',struct.pack('!IIIIII',0,tid,1,duration,video_size if tid==1 else 1,0)))
    return box(b'moov',b''.join(tracks)+box(b'mvex',b''.join(defaults)))

def fragment(index,*,audio=True,first_relative=False,backward=False,audio_offset=0,payload_size=None):
    trafs=[]
    for tid in (1,2) if audio else (1,):
        start=EPOCH+index*1000
        if tid==2:start+=audio_offset
        if first_relative and index==0:start=0
        if backward and index==3:start-=100
        trafs.append(box(b'traf',box(b'tfhd',struct.pack('!II',0,tid))+
            box(b'tfdt',struct.pack('!IQ',0x01000000,start))+
            box(b'trun',struct.pack('!II',0,10))))
    body=b'PRIVATE_MEDIA_BYTES!' if audio else b'0123456789'
    return box(b'moof',b''.join(trafs)),box(b'mdat',body if payload_size is None else b'x'*payload_size)

def frame(kind,data):return bytes([kind])+len(data).to_bytes(3,'big')+data

def stream(*,extended=True,audio=True,first_relative=False,backward=False,audio_offset=0,payload_size=None):
    init=initialization(audio)
    values=[frame(250,init) if extended else init]
    for index in range(12):
        moof,mdat=fragment(index,audio=audio,first_relative=first_relative,backward=backward,audio_offset=audio_offset,payload_size=payload_size)
        if extended:
            values.append(frame(249,b'')+frame(251,moof)+frame(254,mdat[:8])+
                frame(252,mdat[8:])+frame(255,b''))
        else:values.append(moof+mdat)
    return values

class Clock:
    def __init__(self):self.now=0.
    def __call__(self):return self.now

class Socket:
    def __init__(self,clock,values,dribble=False):
        self.clock=clock;self.values=list(values);self.closed=False;self.sent=[];self.dribble=dribble
    def settimeout(self,_):pass
    def sendall(self,value):self.sent.append(value)
    def recv(self,count):
        self.clock.now+=1 if not self.dribble else .001
        if not self.values:raise socket.timeout()
        value=self.values.pop(0)
        if len(value)>count:self.values.insert(0,value[count:]);value=value[:count]
        return value
    def close(self):self.closed=True

class StartupProbeTests(unittest.TestCase):
    def check(self,values=None,*,flags_change=None,connector_error=False):
        config={'protectUserId':'test-owner','bridges':[{'cameraId':CID}], 'fmp4Startup':{'enabled':True}}
        camera={'id':CID,'channels':[{'id':1,'enabled':True}], 'thirdPartyCameraInfo':{'enableRtspAudio':True}}
        clock=Clock();sock=Socket(clock,stream()if values is None else values);seen=[]
        def api(_config,path,**_):
            seen.append(path);flags=fmp4.browser_flags(fmp4.configuration(config),CID)
            if flags_change:flags.update(flags_change)
            body=json.dumps({'cmd':'play','params':{'channel':1,'type':'fmp4',**flags},'privateToken':'PRIVATE_NATIVE_TOKEN'}).encode()
            return {'uri':'tcp://127.0.0.1:7447','data':{'type':'Buffer','data':list(len(body).to_bytes(4,'big')+body)}}
        def connector(*_):
            if connector_error:raise OSError('PRIVATE_CREDENTIAL')
            return sock
        result=fmp4.probe_fmp4(config,camera,1,api=api,connector=connector,clock=clock)
        self.assertNotIn('PRIVATE_',json.dumps(result));self.assertFalse(result['mediaSaved'])
        self.assertFalse(result['frontdoorAuthenticationVerified'])
        if not connector_error and not flags_change:self.assertTrue(sock.closed)
        return result,sock,seen

    def test_extended_and_raw_startups_include_first_fragment_and_discard_media(self):
        for extended in (True,False):
            result,_,seen=self.check(stream(extended=extended))
            self.assertTrue(result['ok'],result)
            self.assertTrue(result['checks']['continuousFromFirstFragment'])
            self.assertLessEqual(result['maxMetadataBufferBytes'],1024*1024)
            self.assertIn('allowPartialGOP=true',seen[0]);self.assertIn('useWallClock=true',seen[0])
            self.assertEqual({x['kind']for x in result['tracks']},{'video','audio'})

    def test_initial_relative_to_epoch_jump_is_not_hidden_by_warmup(self):
        result,_,_=self.check(stream(first_relative=True))
        self.assertFalse(result['ok']);self.assertFalse(result['checks']['continuousFromFirstFragment'])
        self.assertTrue(any(t['clockGaps'] for t in result['tracks']))

    def test_full_gop_startup_delay_accepts_overlapping_clocks_not_arbitrary_skew(self):
        result,_,_=self.check(stream(audio_offset=-3000))
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['tracks'][0]['trackStartSkewSeconds'],3)
        self.assertGreaterEqual(result['tracks'][0]['trackClockOverlapSeconds'],2)
        for offset in (-10000,10000):
            result,_,_=self.check(stream(audio_offset=offset))
            self.assertFalse(result['ok']);self.assertFalse(result['checks']['overlappingTrackClocks'])

    def test_backward_clock_missing_audio_stall_and_wrong_flags_fail(self):
        for values,check in ((stream(backward=True),'continuousFromFirstFragment'),
                             (stream(audio=False),'audio'),(stream()[:4],'freshProgress')):
            result,_,_=self.check(values);self.assertFalse(result['ok']);self.assertFalse(result['checks'][check])
        result,sock,_=self.check(flags_change={'allowPartialGOP':False})
        self.assertEqual(result['errorCode'],'fmp4_effective_flags_mismatch');self.assertFalse(sock.sent)
        result,_,_=self.check(connector_error=True);self.assertEqual(result['errorCode'],'fmp4_transport_failed')

    def test_malformed_framing_and_segment_byte_count_fail_closed(self):
        for values in ([b'not fmp4'],stream()[:1]+[frame(249,b'')+frame(251,fragment(0)[0])+
                frame(254,struct.pack('!I4s',100,b'mdat'))+frame(252,b'x')+frame(255,b'')]):
            result,_,_=self.check(values);self.assertFalse(result['ok'])

    def test_declared_sample_bytes_match_actual_mdat_in_raw_and_split_framing(self):
        for extended in (True,False):
            good,_,_=self.check(stream(extended=extended))
            self.assertTrue(good['checks']['samplePayloadSizes'])
            self.assertEqual(good['payloadByteCounts']['actualMdatBytes'],good['payloadByteCounts']['declaredSampleBytes'])
            for size in (0,19,21):
                result,_,_=self.check(stream(extended=extended,payload_size=size))
                self.assertFalse(result['ok']);self.assertFalse(result['checks']['samplePayloadSizes'])
                self.assertEqual(result['errorCode'],'fmp4_sample_payload_size_mismatch')

    def test_fragment_work_is_bounded_across_all_track_runs(self):
        def traf(tid,count):
            return box(b'traf',box(b'tfhd',struct.pack('!II',0,tid))+
                box(b'tfdt',struct.pack('!IQ',0x01000000,EPOCH))+box(b'trun',struct.pack('!II',0,count)))
        defaults={tid:{'duration':100,'size':1}for tid in range(1,20)}
        for payload in (traf(1,10)+traf(1,10),b''.join(traf(tid,4096)for tid in (1,2,3)),
                        b''.join(traf(tid,1)for tid in range(1,18))):
            with self.assertRaises(fmp4.ProbeError):fmp4.fragment_metadata(payload,defaults)

    def test_audio_bytes_cannot_substitute_for_empty_video_samples(self):
        for extended in (True,False):
            values=stream(extended=extended,payload_size=10)
            values[0]=frame(250,initialization(video_size=0))if extended else initialization(video_size=0)
            result,_,_=self.check(values)
            self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],'missing_sample_size')

    def test_full_gop_freshness_uses_observed_duration_with_hard_five_second_cap(self):
        for full_gop in (True,False):
            collector=fmp4.StartupClock(0,full_gop=full_gop)
            collector.on_box(b'moov',initialization(duration=400)[8:],0)
            for index,arrival in ((0,2),(4,6)):
                moof,_=fragment(index)
                collector.on_box(b'moof',moof[8:],arrival)
                collector.on_box(b'mdat',b'',arrival,body_bytes=20)
            rows,checks=collector.result(9.2,True)
            self.assertTrue(checks['continuousFromFirstFragment']);self.assertTrue(checks['samplePayloadSizes'])
            self.assertEqual(checks['freshProgress'],full_gop)
            self.assertTrue(all(row['freshnessBudgetSeconds']==(5 if full_gop else 3)for row in rows))
            _,checks=collector.result(11.01,True)
            self.assertFalse(checks['freshProgress'])

    def test_full_gop_exceptions_require_current_explicit_nginx_pins(self):
        cid='6ac8ae7001ab6d03e4006410'
        config={'bridges':[{'cameraId':cid}], 'fmp4Startup':{'enabled':True,'fullGopCameraIds':[cid]}}
        with self.assertRaises(OperationError):fmp4.configuration(config)
        config['fmp4Startup']['nginxFilePins']=[{'path':path,'sha256':hashlib.sha256(b'expected').hexdigest()}for path in (
            '/etc/nginx/nginx.conf','/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf',
            '/ssd1/.data/unifi-core/config/http/upstream-protect_api_backend.conf')]
        options=fmp4.configuration(config)
        self.assertFalse(fmp4.browser_flags(options,cid)['allowPartialGOP'])
        reviewed=[cid,'6ac83fed00bd6d03e4001b81','6ac844bf02026d03e4001f5f','6ac8ae7102b76d03e4006447',
                  '6ac83993001a6d03e4001690','6ac844bd01096d03e4001f22']
        config['bridges']=[{'cameraId':value}for value in reviewed]+[{'cameraId':CID}]
        config['fmp4Startup']['fullGopCameraIds']=reviewed
        options=fmp4.configuration(config)
        self.assertTrue(all(fmp4.browser_flags(options,value)['allowPartialGOP']is False for value in reviewed))
        self.assertTrue(fmp4.browser_flags(options,CID)['allowPartialGOP'])
        config['fmp4Startup']['fullGopCameraIds']=reviewed+[CID]
        with self.assertRaises(OperationError):fmp4.configuration(config)
        with patch.object(fmp4.Path,'is_file',return_value=False):
            with self.assertRaises(OperationError)as error:fmp4.verify_configuration(options)
        self.assertEqual(error.exception.code,'fmp4_configuration_drift')

    def test_unscoped_uris_channels_and_duration_are_rejected_before_network(self):
        config={'bridges':[{'cameraId':CID}], 'fmp4Startup':{'enabled':True}}
        camera={'id':CID,'channels':[{'id':1,'enabled':True}]}
        for options in ({'seconds':100},{'seconds':True}):
            with self.assertRaises(OperationError):fmp4.probe_fmp4(config,camera,1,**options)
        with self.assertRaises(OperationError):fmp4.probe_fmp4(config,camera,2)
