"""Synthetic websocket/protocol faults; encoded payloads are never exported."""
import base64
import hashlib
import json
import re
import socket
import struct
import unittest
from reolink_protect_events.operations.ubv import UbvMetadataParser, UbvMetadataError, probe_ubv, _local_endpoint
from reolink_protect_events.operations.safety import OperationError


def record(track,seq,dts,payload,flags=0xcd,index=12):
    header=bytes([0xa0,track>>8,track&255,0xa0^(track>>8)^(track&255),flags,index])+struct.pack('!H',seq)
    header+=struct.pack('!Q'if flags&4 else'!I',dts)
    if flags&2:header+=struct.pack('!I',0)
    if not flags&0x40:header+=struct.pack('!I',7200)
    header+=struct.pack('!I',len(payload))
    body=header+payload+bytes(-(len(header)+len(payload))%4)
    return body+struct.pack('!I',len(body))


def adts():
    size=24
    return bytes([255,241,0x60,0x40,size>>3,(size&7)<<5|31,252])+b'PRIVATE_PAYLOAD!!'+b'0'


def ws(data,opcode=2,fin=True):
    first=(128 if fin else 0)|opcode
    return bytes([first,len(data)])+data if len(data)<126 else bytes([first,126])+struct.pack('!H',len(data))+data


class Clock:
    def __init__(self):self.now=0.
    def __call__(self):return self.now


class Socket:
    def __init__(self,clock,frames,bad_accept=False):
        self.clock=clock;self.frames=list(frames);self.buffer=bytearray();self.closed=False;self.bad_accept=bad_accept
    def settimeout(self,_):pass
    def sendall(self,data):
        if data.startswith(b'GET '):
            key=re.search(br'Sec-WebSocket-Key: ([^\r]+)',data)[1].decode()
            accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            if self.bad_accept:accept='invalid'
            self.buffer.extend(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode())
    def recv(self,count):
        if not self.buffer:
            self.clock.now+=0.08
            if not self.frames:raise socket.timeout()
            self.buffer.extend(self.frames.pop(0))
        data=bytes(self.buffer[:count]);del self.buffer[:count];return data
    def close(self):self.closed=True


def frames(audio=True,aac_compat=True,frozen=False):
    result=[];audio_seq=0
    for i in range(120):
        payload=record(1003,i,i*7200,b'PRIVATE_VIDEO',flags=0xed if i%25==0 else 0xcd)
        if audio:
            while audio_seq*64<=i*80:
                payload+=record(1000,audio_seq,audio_seq*(1024 if aac_compat else 64),adts(),
                                flags=0xfd if aac_compat else 0xf9,index=6 if aac_compat else 2)
                audio_seq+=1
        result.append(ws(payload))
        if frozen and i==10:break
    return result


class UbvProbeTests(unittest.TestCase):
    def check(self,packets=None,**options):
        clock=Clock();sock=Socket(clock,frames()if packets is None else packets,options.pop('bad_accept',False))
        config={'protectUserId':'test-owner','bridges':[{'cameraId':'a'*24}]}
        camera={'id':'a'*24,'channels':[{'id':1,'enabled':True}], 'thirdPartyCameraInfo':{'enableRtspAudio':True}}
        result=probe_ubv(config,camera,1,seconds=8,
            api=lambda *_a,**_k:{'url':'wss://127.0.0.1:7443/live?signedToken=PRIVATE_WS_TOKEN'},
            connector=lambda *_:sock,clock=clock,**options)
        self.assertTrue(sock.closed)
        self.assertNotIn('PRIVATE_',json.dumps(result));return result
    def test_real_reader_accepts_night_cadence_with_fd06_and_discards_payloads(self):
        result=self.check();self.assertTrue(result['ok'],result)
        self.assertTrue(result['checks']['videoPictures']);self.assertTrue(result['checks']['audioPictures'])
        self.assertLessEqual(result['maxHeaderBytesRetained'],36)
        self.assertFalse(result['mediaSaved']);self.assertFalse(result['mediaDecoded'])
    def test_stalled_cached_burst_or_missing_audio_cannot_be_green(self):
        frozen=self.check(frames(frozen=True));self.assertFalse(frozen['ok'])
        self.assertFalse(frozen['checks']['videoPictures'])
        missing=self.check(frames(audio=False));self.assertFalse(missing['checks']['audioPictures'])
    def test_wrong_aac_packet_clock_or_bad_handshake_fail_closed(self):
        result=self.check(frames(aac_compat=False));self.assertFalse(result['checks']['aacCompatibility'])
        result=self.check(bad_accept=True);self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],'ubv_upgrade_invalid')
    def test_websocket_continuations_controls_and_corruption_are_validated(self):
        original=frames();data=original[0]
        # Ping controls interleave fragmented messages without becoming media.
        payload=data[4:]if data[1]==126 else data[2:]
        original[0:1]=[ws(payload[:10],2,False),ws(b'ping',9),ws(payload[10:],0,True)]
        result=self.check(original);self.assertTrue(result['ok'],result)
        corrupt=frames();corrupt[0]=ws(b'not a valid UBV record')
        result=self.check(corrupt);self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],'ubv_magic_mismatch')
    def test_external_or_credentialed_endpoint_is_rejected(self):
        for url in ('wss://example.com/live?token=PRIVATE_WS_TOKEN','wss://u:p@127.0.0.1/live',
                    'https://127.0.0.1/live','wss://127.0.0.1:22/live'):
            with self.assertRaises(OperationError):_local_endpoint(url)
    def test_parser_rejects_unbounded_track_table_and_preserves_picture_chunks(self):
        parser=UbvMetadataParser()
        with self.assertRaises(UbvMetadataError):
            for i in range(17):parser.feed(record(i+2000,0,0,b'x'),1)
        parser=UbvMetadataParser()
        data=record(1003,0,0,b'x'*100000,flags=0xa5,index=12)
        data+=record(1003,1,0,b'x'*100000,flags=0x45,index=12)
        data+=record(1003,2,7200,b'x',flags=0xcd,index=12)
        for offset in range(0,len(data),37):parser.feed(data[offset:offset+37],offset/1000000)
        track=parser.summary()['tracks'][0]
        self.assertEqual(track['completeFrames'],2);self.assertEqual(track['zeroDts'],0)
        self.assertLessEqual(parser.max_metadata_buffer,36)


if __name__=='__main__':unittest.main()
