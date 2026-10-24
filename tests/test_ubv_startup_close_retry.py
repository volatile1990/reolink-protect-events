"""One empty WebSocket setup close may retry; actual media failures never do."""
import copy
import json
import struct
import unittest
from unittest.mock import patch

from reolink_protect_events.operations import ubv
from test_operations_monitor_ubv import Clock,Socket,frames,ws


def empty_close():
    return {'ok':False,'channel':2,'requestedSeconds':8,'errorCode':'ubv_closed_before_deadline',
        'websocketFrames':1,'binaryBytesDiscarded':0,'maxHeaderBytesRetained':0,'tracks':[],
        'checks':{'continuousMediaTimes':True},'mediaSaved':False,'mediaDecoded':False}


class EmptyStartupCloseRetry(unittest.TestCase):
    def test_only_exact_empty_close_can_retry_and_second_failure_is_final(self):
        first=empty_close();second=copy.deepcopy(first);waits=[]
        with patch.object(ubv,'_probe_ubv_once',side_effect=[first,second])as attempt:
            result=ubv.probe_ubv({}, {},2,sleep=waits.append)
        self.assertEqual(attempt.call_count,2);self.assertEqual(waits,[2])
        self.assertFalse(result['ok']);self.assertTrue(result['setupRetryUsed'])
        self.assertEqual(result['firstAttempt'],first);self.assertEqual(result['attempts'],[first,second])
        self.assertEqual(first,empty_close(),'retained original must not be marked successful')
        self.assertEqual(attempt.call_args_list[1].kwargs['seconds'],8)

    def test_media_partial_parser_timing_auth_and_other_failures_never_retry(self):
        changes=[{'binaryBytesDiscarded':1},{'binaryBytesDiscarded':544,'websocketFrames':2},
            {'maxHeaderBytesRetained':1},{'tracks':[{'kind':'H265','completeFrames':1}]},
            {'websocketFrames':2},{'websocketFrames':0},
            {'checks':{'continuousMediaTimes':False}},{'websocketFrames':True}]
        changes += [{'websocketCloseCode':code}for code in (1002,1008,1011)]
        changes += [{'errorCode':code}for code in ('ubv_magic_mismatch','ubv_upgrade_invalid',
            'ubv_upgrade_rejected','ubv_connection_closed','ubv_setup_timeout','ubv_transport_failed',None)]
        for change in changes:
            with self.subTest(change=change):
                first=dict(empty_close(),**change)
                with patch.object(ubv,'_probe_ubv_once',return_value=first)as attempt:
                    result=ubv.probe_ubv({}, {},2,sleep=lambda _s:self.fail('ineligible failure must not wait/retry'))
                self.assertEqual(attempt.call_count,1);self.assertFalse(result['setupRetryUsed'])
                self.assertEqual({k:v for k,v in result.items()if k!='setupRetryUsed'},first)

    def real_probe(self,packets):
        clock=Clock();created=[];waits=[];starts=[];api_calls=[]
        config={'protectUserId':'synthetic-owner','bridges':[{'cameraId':'a'*24}]}
        camera={'id':'a'*24,'channels':[{'id':2,'enabled':True}],
            'thirdPartyCameraInfo':{'enableRtspAudio':True}}
        def connector(*_args):
            starts.append(clock());peer=Socket(clock,packets[len(created)])
            created.append(peer);return peer
        def api(_config,path,**_kwargs):
            api_calls.append(path)
            return {'url':'wss://127.0.0.1:7443/live?signedToken=PRIVATE_WS_TOKEN'}
        def sleep(seconds):
            self.assertTrue(created[-1].closed,'first attempt must close before cleanup delay')
            waits.append(seconds);clock.now+=seconds
        result=ubv.probe_ubv(config,camera,2,api=api,connector=connector,clock=clock,sleep=sleep)
        self.assertTrue(all(peer.closed for peer in created))
        self.assertNotIn('PRIVATE_',json.dumps(result))
        self.assertTrue(all('channel=2'in path for path in api_calls))
        return result,created,waits,starts,clock()

    def test_actual_first_close_then_complete_fresh_eight_second_stream(self):
        result,created,waits,starts,ended=self.real_probe([[ws(struct.pack('!H',1000),8)],frames()])
        self.assertTrue(result['ok'],result);self.assertTrue(result['setupRetryUsed'])
        self.assertEqual(len(created),2);self.assertEqual(waits,[2])
        self.assertEqual(result['requestedSeconds'],8);self.assertGreaterEqual(ended-starts[1],7.99)
        self.assertFalse(result['firstAttempt']['ok'])
        self.assertEqual(result['firstAttempt']['errorCode'],'ubv_closed_before_deadline')
        self.assertEqual(result['firstAttempt']['binaryBytesDiscarded'],0)
        self.assertEqual(len(result['attempts']),2);self.assertTrue(result['attempts'][1]['ok'])
        self.assertTrue(all(result['checks'].values()))

    def test_actual_partial_first_record_and_midstream_close_are_not_retried(self):
        for packets in ([ws(b'\xa0'),ws(b'',8)],frames()[:5]+[ws(b'',8)]):
            with self.subTest(partial=len(packets)==2):
                result,created,waits,_starts,_ended=self.real_probe([packets])
                self.assertFalse(result['ok']);self.assertFalse(result['setupRetryUsed'])
                self.assertEqual(len(created),1);self.assertEqual(waits,[])
                self.assertGreater(result['binaryBytesDiscarded'],0)

    def test_actual_policy_protocol_and_malformed_closes_do_not_retry(self):
        for payload in (struct.pack('!H',1008),struct.pack('!H',1002),struct.pack('!H',1011),b'x'):
            with self.subTest(payloadBytes=len(payload),code=payload.hex()):
                result,created,waits,_starts,_ended=self.real_probe([[ws(payload,8)]])
                self.assertFalse(result['ok']);self.assertFalse(result['setupRetryUsed'])
                self.assertEqual(len(created),1);self.assertEqual(waits,[])
                self.assertEqual(result['binaryBytesDiscarded'],0)


if __name__=='__main__':unittest.main()
