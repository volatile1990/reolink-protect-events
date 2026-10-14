"""Recording-index retry and frozen mutation/current verifier contracts, offline."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from reolink_protect_events.operations import decode, orchestrator
from reolink_protect_events.operations.orchestrator import Backend, Update


ACTIVATED = 1791990000000
IP = '192.168.30.210'
PENDING = {'ok': False, 'realDecodes': False, 'errorCode': 'decode_new_recording_pending'}
SUCCESS = {'ok': True, 'realDecodes': True,
           'rtspProfileCoverage': {'allRequested': True},
           'recordedProfileCoverage': {'allRequested': True}}


class FakeClock:
    def __init__(self, timestamp=ACTIVATED):
        self.timestamp = timestamp
        self.waits = []
        self.attempts = []

    def seconds(self):
        return self.timestamp / 1000

    def wait_until(self, timestamp):
        self.waits.append(timestamp)
        self.timestamp = max(self.timestamp, timestamp)


def decode_backend(clock):
    backend = Backend.__new__(Backend)
    backend.host = 'unifi-dream-machine'
    backend.ffmpeg, backend.ffprobe = '/public/ffmpeg', '/public/ffprobe'
    backend.progress = Mock()
    backend.wait_until = clock.wait_until
    return backend


class RecordingRetryTests(unittest.TestCase):
    def evaluate(self, responses, *, activation=ACTIVATED, now=ACTIVATED):
        clock = FakeClock(now)
        backend = decode_backend(clock)
        values = iter(responses)

        def attempt(*args, **kwargs):
            clock.attempts.append(clock.timestamp)
            return next(values)

        with patch.object(orchestrator.time, 'time', side_effect=clock.seconds), \
             patch.object(orchestrator.time, 'sleep', side_effect=AssertionError('real_sleep_forbidden')), \
             patch.object(orchestrator, 'run_full_decodes', side_effect=attempt) as decoder:
            result = backend.decode([IP], not_before_ms=activation)
        return result, clock, backend, decoder

    def test_pending_retries_then_returns_actual_success_with_original_scope(self):
        result, clock, backend, decoder = self.evaluate([PENDING, SUCCESS])
        self.assertIs(result, SUCCESS)
        self.assertEqual(clock.waits, [ACTIVATED + 56000, ACTIVATED + 76000])
        self.assertEqual(clock.attempts, clock.waits)
        self.assertEqual(decoder.call_count, 2)
        for call in decoder.call_args_list:
            self.assertEqual(call.args, ('unifi-dream-machine',))
            self.assertEqual(call.kwargs, {'ips': [IP], 'ffmpeg': '/public/ffmpeg',
                                           'ffprobe': '/public/ffprobe', 'not_before_ms': ACTIVATED})
        self.assertEqual(backend.progress.call_count, 1)

    def test_transport_codec_export_and_other_failures_never_retry(self):
        for code in ('rtsp_transport_error', 'decode_codec_mismatch', 'subprocess_total_deadline',
                     'decode_export_rejected', 'decode_recording_index_stale',
                     'decode_new_recording_pending_extra'):
            with self.subTest(code=code):
                failed = dict(PENDING, errorCode=code)
                result, clock, backend, decoder = self.evaluate([failed])
                self.assertIs(result, failed)
                self.assertEqual(decoder.call_count, 1)
                self.assertEqual(clock.waits, [ACTIVATED + 56000])
                backend.progress.assert_not_called()

    def test_real_failure_after_pending_stops_without_another_retry(self):
        failed = dict(PENDING, errorCode='decode_codec_mismatch')
        result, clock, _, decoder = self.evaluate([PENDING, failed])
        self.assertIs(result, failed)
        self.assertEqual(decoder.call_count, 2)
        self.assertEqual(clock.waits, [ACTIVATED + 56000, ACTIVATED + 76000])

    def test_pending_without_activation_is_returned_without_waiting_or_retry(self):
        result, clock, backend, decoder = self.evaluate([PENDING], activation=None)
        self.assertIs(result, PENDING)
        self.assertFalse(clock.waits)
        self.assertEqual(decoder.call_count, 1)
        backend.progress.assert_not_called()

    def test_endless_pending_stops_at_180_seconds_without_claiming_decode(self):
        result, clock, _, decoder = self.evaluate([PENDING] * 20)
        self.assertIs(result, PENDING)
        self.assertFalse(result['realDecodes'])
        self.assertEqual(clock.timestamp, ACTIVATED + 180000)
        self.assertEqual(decoder.call_count, 8)
        self.assertTrue(all(ACTIVATED + 56000 <= time <= ACTIVATED + 180000 for time in clock.attempts))
        self.assertEqual(clock.waits[-1], ACTIVATED + 180000)

    def test_expired_activation_cannot_start_a_new_retry_window(self):
        result, clock, backend, decoder = self.evaluate([PENDING], now=ACTIVATED + 181000)
        self.assertIs(result, PENDING)
        self.assertEqual(decoder.call_count, 1)
        self.assertEqual(clock.timestamp, ACTIVATED + 181000)
        backend.progress.assert_not_called()

    def test_pending_discovery_retries_before_opening_any_live_or_recorded_viewer(self):
        clock = FakeClock()
        backend = decode_backend(clock)

        async def discovery(*args, **kwargs):
            clock.attempts.append(clock.timestamp)
            return 2, json.dumps(PENDING).encode(), b''

        with patch.object(orchestrator.time, 'time', side_effect=clock.seconds), \
             patch.object(orchestrator.time, 'sleep', side_effect=AssertionError('real_sleep_forbidden')), \
             patch.object(orchestrator, 'run_full_decodes', wraps=decode.run_full_decodes), \
             patch.object(decode, '_executable', side_effect=lambda _, name: '/public/' + name), \
             patch.object(decode, '_remote_source', return_value=b'public-readonly-discovery'), \
             patch.object(decode, '_run_bytes', side_effect=discovery) as network, \
             patch.object(decode, '_rtsp_decode') as live, \
             patch.object(decode, '_recorded_decode') as recorded:
            result = backend.decode([IP], not_before_ms=ACTIVATED)
        self.assertEqual(result['errorCode'], 'decode_new_recording_pending')
        self.assertEqual(network.call_count, 8)
        self.assertEqual(clock.timestamp, ACTIVATED + 180000)
        self.assertEqual(result['rtsp'], [])
        self.assertEqual(result['recordings'], [])
        live.assert_not_called()
        recorded.assert_not_called()


class VerificationSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.current = {'sourceRevision': '2' * 40, 'sourceSha256': 'b' * 64,
                        'sourceDirty': False, 'version': '1.2.0'}

    def tearDown(self):
        self.temporary.cleanup()

    def backend(self):
        backend = Backend.__new__(Backend)
        backend.events_repo = self.root / 'events'
        backend.host = 'unifi-dream-machine'
        backend.connector = 'external-protected-connector'
        backend.progress = Mock()
        backend.operation_sources = 'current-mutation-source'
        backend.verification_sources = 'current-readonly-verifier'
        backend.nas_sources = {'engine': 'current-nas-source'}
        backend.nas_cli = types.SimpleNamespace(invoke=Mock(return_value={'ok': True}))
        backend.current_sources = Mock(return_value={'events': self.current})
        return backend

    def receipt(self):
        directory = self.root / 'release'
        directory.mkdir()
        frozen = {'events': 'original-frozen-mutation-source',
                  'bridge': {'engine': 'original-frozen-nas-source'}}
        data = json.dumps(frozen).encode()
        (directory / 'operation-sources.json').write_bytes(data)
        state = {'schemaVersion': 1, 'status': 'failed', 'completed': [], 'evidence': {},
                 'frozen': {'operationSourcesSha256': hashlib.sha256(data).hexdigest()}}
        (directory / 'update.json').write_text(json.dumps(state), encoding='utf-8')
        return directory, frozen

    def test_backend_captures_current_readonly_verifier_at_construction(self):
        nas = types.SimpleNamespace(source_bundle=lambda: {'engine': 'captured-nas-source'})
        with patch.object(orchestrator, 'load_module', side_effect=[object(), nas]), \
             patch.object(orchestrator, 'source_bundle', return_value='captured-current-verifier') as bundle, \
             patch.object(orchestrator, 'invoke', return_value={'ok': True}) as remote:
            backend = Backend(self.root / 'bridge', self.root / 'events', 'external-protected-connector',
                              progress=lambda _: None)
            backend.operation_sources = 'original-frozen-mutation-source'
            bundle.return_value = 'later-checkout-source'
            backend.udm({'action': 'health'})
        self.assertEqual(backend.verification_sources, 'captured-current-verifier')
        self.assertEqual(remote.call_args.kwargs['sources'], 'captured-current-verifier')
        self.assertEqual(bundle.call_count, 1)

    def test_resume_rebinds_only_frozen_mutation_sources_and_records_current_verifier_revision(self):
        backend = self.backend()
        directory, frozen = self.receipt()
        update = Update(backend, directory, resume=True)
        self.assertEqual(backend.operation_sources, frozen['events'])
        self.assertEqual(backend.nas_sources, frozen['bridge'])
        self.assertEqual(backend.verification_sources, 'current-readonly-verifier')
        self.assertEqual(update.state['resumedVerificationSources'], self.current)
        update.persist()
        self.assertEqual(json.loads((directory / 'update.json').read_text())['resumedVerificationSources'], self.current)
        with patch.object(orchestrator, 'invoke', return_value={'ok': True}) as remote:
            for action in ('compatibility', 'health', 'event-evidence', 'monitor-status'):
                backend.udm({'action': action})
                self.assertEqual(remote.call_args.kwargs['sources'], 'current-readonly-verifier')
            for request in ({'action': 'recover'}, {'action': 'installer', 'request': {'mode': 'maintenance'}},
                            {'action': 'installer', 'request': {'mode': 'rollback'}}):
                backend.udm(request)
                self.assertEqual(remote.call_args.kwargs['sources'], frozen['events'])
        backend.nas({'mode': 'rollback-all'})
        self.assertEqual(backend.nas_cli.invoke.call_args.kwargs['sources'], frozen['bridge'])

    def test_tampered_frozen_bundle_never_rebinds_sources_or_dispatches(self):
        backend = self.backend()
        directory, _ = self.receipt()
        (directory / 'operation-sources.json').write_text('{}', encoding='utf-8')
        with patch.object(orchestrator, 'invoke') as remote:
            with self.assertRaisesRegex(RuntimeError, '^frozen_operation_sources_changed$'):
                Update(backend, directory, resume=True)
        self.assertEqual(backend.operation_sources, 'current-mutation-source')
        self.assertEqual(backend.nas_sources, {'engine': 'current-nas-source'})
        self.assertEqual(backend.verification_sources, 'current-readonly-verifier')
        remote.assert_not_called()
        backend.nas_cli.invoke.assert_not_called()
        backend.current_sources.assert_not_called()


class ExactBuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.current = self.root / ('b' * 32)
        self.previous = self.root / ('a' * 32)
        self.current.mkdir()
        self.previous.mkdir()
        self.receipt = self.previous / 'update.json'
        self.required = {'version': '1.4.0', 'sourceSha256': 'c' * 64,
                         'sourceRevision': 'd' * 40}
        self.frozen = {'sources': {'bridge': self.required}, 'archiveSha256': 'e' * 64}
        self.value = {key: True for key in ('ok', 'testsPassed', 'testedApplicationDllIdentical',
                                          'cleanupConfirmed', 'productionInventoryPreserved',
                                          'kernelProcessLimitVerified')}
        self.value['release'] = dict(self.required, archiveSha256='e' * 64,
                                     imageId='sha256:' + 'f' * 64, imageTag='reolink-bridge:synthetic',
                                     applicationDllSha256='1' * 64, testsPassed=True,
                                     testedApplicationDllIdentical=True)
        self.value['actualKernelMaxProcesses'] = 256
        self.backend = Backend.__new__(Backend)
        self.backend.nas = Mock()
        self.write_receipt(self.value)

    def tearDown(self):
        self.temporary.cleanup()

    def write_receipt(self, value):
        # A later Protect gate may have failed while the exact image audit passed.
        self.receipt.write_text(json.dumps({'status': 'failed', 'evidence': {
            'isolated-build-and-hardware-tests': value}}), encoding='utf-8')

    def lookup(self, frozen=None):
        return self.backend.cached_build(self.current, frozen or self.frozen)

    def test_exact_successful_audit_is_reused_without_build_or_receipt_mutation(self):
        before = self.receipt.read_bytes()
        result = self.lookup()
        self.assertEqual(result['release'], self.value['release'])
        self.assertTrue(result['buildCacheReused'])
        self.assertEqual(result['buildCacheReceipt'], str(self.receipt))
        self.assertEqual(result['actualKernelMaxProcesses'], 256)
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertNotIn('buildCacheReused', self.value)
        self.backend.nas.assert_not_called()

    def test_changed_zip_digest_is_not_reused_despite_identical_source_and_revision(self):
        changed = copy.deepcopy(self.frozen)
        changed['archiveSha256'] = '2' * 64
        self.assertIsNone(self.lookup(changed))
        self.backend.nas.assert_not_called()

    def test_changed_or_missing_source_digest_revision_or_version_is_not_reused(self):
        for key, wrong in (('sourceSha256', '3' * 64), ('sourceRevision', '4' * 40),
                           ('version', '1.4.1')):
            for missing in (False, True):
                with self.subTest(key=key, missing=missing):
                    value = copy.deepcopy(self.value)
                    if missing:
                        value['release'].pop(key)
                    else:
                        value['release'][key] = wrong
                    self.write_receipt(value)
                    self.assertIsNone(self.lookup())
        self.backend.nas.assert_not_called()

    def test_every_required_proof_must_be_boolean_true(self):
        for key in ('ok', 'testsPassed', 'testedApplicationDllIdentical', 'cleanupConfirmed',
                    'productionInventoryPreserved', 'kernelProcessLimitVerified'):
            for invalid in (False, None, 1, 'true', 'missing'):
                with self.subTest(key=key, invalid=invalid):
                    value = copy.deepcopy(self.value)
                    if invalid == 'missing':
                        value.pop(key)
                    else:
                        value[key] = invalid
                    self.write_receipt(value)
                    self.assertIsNone(self.lookup())
        self.backend.nas.assert_not_called()

    def test_corrupt_receipts_and_symlinked_receipt_or_directory_are_ignored(self):
        for content in ('{', 'null', '[]', '{"evidence":{}}'):
            with self.subTest(content=content):
                self.receipt.write_text(content, encoding='utf-8')
                self.assertIsNone(self.lookup())
        self.write_receipt(self.value)
        original = Path.is_symlink
        # Mock symlink metadata rather than requiring Windows symlink privileges.
        for linked in (self.receipt, self.previous):
            with self.subTest(linked=linked), patch.object(Path, 'is_symlink', autospec=True,
                    side_effect=lambda path, linked=linked: path == linked or original(path)):
                self.assertIsNone(self.lookup())
        self.backend.nas.assert_not_called()


if __name__ == '__main__':
    unittest.main()
