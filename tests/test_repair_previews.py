"""Offline preview-repair faults; synthetic modules, no SSH or database access."""
import ast
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


NATIVE_SOURCE = '''from preview_repair_test_state import state
class NativeAdapter:
 def __init__(self,**kwargs):pass
 def guard_schema(self):state.guards+=1
 def preview_repair_candidates(self,limit=128):
  state.queries+=1
  return list(state.pending[:limit])
 def repair_preview_thumbnail(self,candidate):
  state.calls.append(('repair',candidate['eventId']))
  state.pending.remove(candidate)
  if state.retire:return None
  return {'id':candidate['eventId'],'camera':candidate['cameraId'],
          'start':candidate['start'],'end':candidate['start']+5000,
          'smartDetectTypes':['animal']}
'''
UPDATES_SOURCE = '''from preview_repair_test_state import state
class DsUpdateClient:
 def __init__(self,*args,**kwargs):state.calls.append(('client',))
 def send_event(self,action,event):
  state.calls.append(('send',action,dict(event)))
  if state.send_fail:raise ValueError('synthetic-private-response')
 def close(self):state.calls.append(('close',))
'''


class ConfigPath:
    def __init__(self, config):
        self.config = config

    def is_symlink(self):
        return False

    def is_file(self):
        return True

    def stat(self):
        return types.SimpleNamespace(st_uid=0, st_mode=0o100600, st_size=1000)

    def read_text(self):
        return json.dumps(self.config)


class RepairPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / 'tools' / 'repair_previews.py'
        spec = importlib.util.spec_from_file_location('preview_repair_tool', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        ast.parse(cls.tool.REMOTE, feature_version=(3, 9))

    def run_worker(self, mode, count=1, send_fail=False, retire=False,
                   outside_index=None):
        config = {'bridges': [
            {'cameraId': '%024x' % (i + 1), 'host': '192.0.2.' + str(i + 1),
             'mac': '0242c0a81e%02x' % (210 + i),
             'password': 'synthetic-private-password'} for i in range(6)],
            'dsProxyPort': 7448, 'protectVersion': '7.3.70'}
        state = types.SimpleNamespace(pending=[
            {'eventId': '%024x' % (i + 100),
             'cameraId': 'f' * 24 if i == outside_index else config['bridges'][0]['cameraId'],
             'start': 1700000000000, 'fullfovId': 'a' * 24} for i in range(count)],
            calls=[], guards=0, queries=0, send_fail=send_fail, retire=retire)
        initial_ids = [candidate['eventId'] for candidate in state.pending]
        module = types.ModuleType('preview_repair_test_state')
        module.state = state
        env = {'mode': mode, 'source_hashes': {},
               'native_source': base64.b64encode(NATIVE_SOURCE.encode()).decode(),
               'updates_source': base64.b64encode(UPDATES_SOURCE.encode()).decode()}
        output = io.StringIO()
        with patch.dict(sys.modules, {module.__name__: module}), \
                patch.object(os, 'geteuid', return_value=0, create=True), \
                patch('pathlib.Path', return_value=ConfigPath(config)), \
                patch('subprocess.run', side_effect=AssertionError('Live process forbidden')) as process, \
                contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                exec(self.tool.REMOTE, env)
            process.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(stopped.exception.code, 0 if result['ok'] else 1)
        self.assertNotIn('synthetic-private-password', output.getvalue())
        self.assertNotIn('synthetic-private-response', output.getvalue())
        for identifier in initial_ids:
            self.assertNotIn(identifier, output.getvalue())
        return result, state

    def test_plan_reads_candidates_without_writes_or_ds_notifications(self):
        result, state = self.run_worker('plan')
        self.assertTrue(result['ok'])
        self.assertEqual(result['candidateCount'], 1)
        self.assertEqual(result['remainingCandidates'], 1)
        self.assertEqual(state.guards, 1)
        self.assertEqual(state.calls, [])

    def test_apply_sends_only_updates_preserves_event_fields_and_closes_clients(self):
        result, state = self.run_worker('apply', count=2)
        self.assertTrue(result['ok'])
        self.assertEqual((result['repaired'], result['updatesSent'], result['remainingCandidates']),
                         (2, 2, 0))
        sends = [call for call in state.calls if call[0] == 'send']
        self.assertEqual(len(sends), 2)
        for _, action, event in sends:
            self.assertEqual(action, 'update')
            self.assertEqual((event['start'], event['end']), (1700000000000, 1700000005000))
            self.assertEqual(event['smartDetectTypes'], ['animal'])
        self.assertEqual(state.calls.count(('close',)), 2)

    def test_failed_ds_send_keeps_database_repair_and_closes_client(self):
        result, state = self.run_worker('apply', send_fail=True)
        self.assertTrue(result['ok'])
        self.assertEqual((result['repaired'], result['updatesSent'], result['updateWarnings']),
                         (1, 0, 1))
        self.assertEqual(result['remainingCandidates'], 0)
        self.assertEqual(state.pending, [])
        self.assertIn(('close',), state.calls)

    def test_concurrent_retirement_skips_notification_and_stops_zero_repair_batch(self):
        result, state = self.run_worker('apply', retire=True)
        self.assertTrue(result['ok'])
        self.assertEqual((result['retiredSkipped'], result['repaired'], result['batches']), (1, 0, 1))
        self.assertFalse(any(call[0] in ('client', 'send', 'close') for call in state.calls))

    def test_out_of_scope_second_candidate_blocks_entire_batch_before_first_write(self):
        result, state = self.run_worker('apply', count=2, outside_index=1)
        self.assertFalse(result['ok'])
        self.assertEqual(result['errorType'], 'ValueError')
        self.assertEqual(state.calls, [])
        self.assertEqual(len(state.pending), 2)

    def test_apply_stops_after_ten_batches_of_128_with_remainder_reported(self):
        result, state = self.run_worker('apply', count=1300)
        self.assertTrue(result['ok'])
        self.assertEqual((result['batches'], result['repaired'], result['remainingCandidates']),
                         (10, 1280, 20))
        self.assertEqual(result['examinedCandidates'], 1280)
        self.assertEqual(state.calls.count(('close',)), 1280)
        self.assertEqual(len(state.pending), 20)


if __name__ == '__main__':
    unittest.main()
