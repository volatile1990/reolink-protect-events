"""Off-host monitor transport with local parsers and unchanged repair scope."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from reolink_protect_events import remote
from reolink_protect_events.operations import fmp4, http, safety, ubv
from test_operations_monitor import fixture
from test_operations_monitor_ubv import Clock as UbvClock, Socket as UbvSocket, frames
from test_operations_fmp4 import Clock as Fmp4Clock, Socket as Fmp4Socket, stream


REMOTE = {'sshAlias': 'udm-protect', 'rpcCommand': 'python3 /usr/local/lib/reolink-protect-connector.py',
          'snapshotPort': 17080, 'dsPort': 17448, 'apiPort': 17443}


def config():
    value, _, _ = fixture()
    value['protectRemote'] = copy.deepcopy(REMOTE)
    return value


class RemoteHttpTests(unittest.TestCase):
    def test_api_uses_rpc_without_local_requests_or_owner_headers(self):
        value = config()
        with patch.object(http, 'remote_rpc', return_value={'nvr': {'version': '7.3.70'}}) as rpc, \
             patch.object(http, 'get_bytes', side_effect=AssertionError('unexpected local API')), \
             patch.object(http, 'owner_headers', side_effect=AssertionError('owner headers must stay remote')):
            result = http.protect_json(value, '/api/bootstrap', timeout=5, limit=65536)
        self.assertEqual(result['nvr']['version'], '7.3.70')
        rpc.assert_called_once_with(value, 'api', {'path': '/api/bootstrap', 'method': 'GET',
            'body': None, 'timeout': 5, 'limit': 65536}, timeout=5)
        self.assertNotIn('protectUserId', rpc.call_args.args[2])

    def test_remote_patch_retains_camera_and_exact_force_tcp_scope(self):
        value = config(); cid = value['bridges'][0]['cameraId']
        with patch.object(http, 'remote_rpc', return_value={}) as rpc:
            for path, body in [('/api/cameras/' + 'f'*24, {'thirdPartyCameraInfo': {'forceTcp': True}}),
                               ('/api/cameras/' + cid, {'thirdPartyCameraInfo': {'forceTcp': False}}),
                               ('/api/cameras/' + cid, {'thirdPartyCameraInfo': {'forceTcp': None}, 'name': 'changed'})]:
                with self.assertRaises(safety.OperationError):
                    http.protect_json(value, path, method='PATCH', body=body)
            rpc.assert_not_called()
            body = {'thirdPartyCameraInfo': {'forceTcp': None}}
            http.protect_json(value, '/api/cameras/' + cid, method='PATCH', body=body)
        self.assertEqual(rpc.call_args.args[2]['body'], body)

    def test_rpc_failure_and_invalid_result_never_expose_remote_details(self):
        value = config()
        with patch.object(http, 'remote_rpc', side_effect=remote.RemoteError('remote_rpc_failed')):
            with self.assertRaises(safety.OperationError) as caught:
                http.protect_json(value, '/api/bootstrap')
        self.assertEqual(caught.exception.code, 'remote_rpc_failed')
        with patch.object(http, 'remote_rpc', return_value='PRIVATE_RESPONSE'):
            with self.assertRaises(safety.OperationError) as caught:
                http.protect_json(value, '/api/bootstrap')
        self.assertEqual(caught.exception.code, 'protect_json_invalid')
        self.assertNotIn('PRIVATE_', str(caught.exception))

    def test_invalid_remote_settings_are_not_silently_used_as_local_mode(self):
        value = config(); value['protectRemote']['sshAlias'] = 'udm-protect; injected'
        with self.assertRaises(safety.OperationError):
            safety.validate_config(value)
        self.assertEqual(safety.error_code(ValueError('PRIVATE_TOKEN'), 'safe_fallback'), 'safe_fallback')
        self.assertEqual(safety.error_code(remote.RemoteError('remote_rpc_failed')), 'remote_rpc_failed')


class RemoteMediaTests(unittest.TestCase):
    def test_ubv_parses_on_this_host_over_explicit_local_tls_tunnel(self):
        value = config(); cid = value['bridges'][0]['cameraId']
        camera = {'id': cid, 'channels': [{'id': 1, 'enabled': True}],
                  'thirdPartyCameraInfo': {'enableRtspAudio': True}}
        clock = UbvClock(); sock = UbvSocket(clock, frames())
        with patch.object(ubv, 'remote_open_socket', return_value=sock) as opened, \
             patch('socket.create_connection', side_effect=AssertionError('must not use local UDM loopback')):
            result = ubv.probe_ubv(value, camera, 1, clock=clock,
                api=lambda *_a, **_k: {'url': 'wss://127.0.0.1:7443/live?signedToken=PRIVATE_TOKEN'})
        self.assertTrue(result['ok'], result)
        opened.assert_called_once_with(value, 7443, 5, tls=True)
        self.assertTrue(sock.closed)
        self.assertNotIn('PRIVATE_', json.dumps(result))
        self.assertFalse(result['mediaDecoded'])

    def test_fmp4_parses_locally_over_binary_tunnel(self):
        value = config(); value['fmp4Startup'] = {'enabled': True}
        cid = value['bridges'][0]['cameraId']
        camera = {'id': cid, 'channels': [{'id': 1, 'enabled': True}],
                  'thirdPartyCameraInfo': {'enableRtspAudio': True}}
        clock = Fmp4Clock(); sock = Fmp4Socket(clock, stream())
        def api(_config, _path, **_):
            flags = fmp4.browser_flags(fmp4.configuration(value), cid)
            body = json.dumps({'cmd': 'play', 'params': {'channel': 1, 'type': 'fmp4', **flags},
                               'privateToken': 'PRIVATE_TOKEN'}).encode()
            return {'uri': 'tcp://127.0.0.1:7447',
                    'data': {'type': 'Buffer', 'data': list(len(body).to_bytes(4, 'big') + body)}}
        with patch.object(fmp4, 'remote_open_socket', return_value=sock) as opened, \
             patch.object(fmp4.socket, 'create_connection', side_effect=AssertionError('must use tunnel')):
            result = fmp4.probe_fmp4(value, camera, 1, clock=clock, api=api)
        self.assertTrue(result['ok'], result)
        opened.assert_called_once_with(value, 7447, 8)
        self.assertTrue(sock.closed)
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_nginx_pins_are_verified_on_udm_not_the_worker_filesystem(self):
        value = config(); path = '/etc/nginx/nginx.conf'; digest = hashlib.sha256(b'expected').hexdigest()
        options = {'nginxFilePins': [{'path': path, 'sha256': digest}]}
        with patch.object(fmp4, 'remote_rpc', return_value={path: digest}) as rpc, \
             patch.object(fmp4.Path, 'open', side_effect=AssertionError('must not read local nginx')):
            self.assertTrue(fmp4.verify_configuration(options, value))
        rpc.assert_called_once_with(value, 'hashes', {'paths': [path]}, timeout=8)
        for result in ({}, {path: '0'*64}, {path: digest, '/unexpected': digest}):
            with patch.object(fmp4, 'remote_rpc', return_value=result):
                with self.assertRaises(safety.OperationError) as caught:
                    fmp4.verify_configuration(options, value)
            self.assertEqual(caught.exception.code, 'fmp4_configuration_drift')

    def test_remote_file_read_failure_is_a_pin_failure(self):
        value = config()
        options = {'nginxFilePins': [{'path': '/etc/nginx/nginx.conf', 'sha256': '0'*64}]}
        with patch.object(fmp4, 'remote_rpc', side_effect=remote.RemoteError('remote_rpc_failed')):
            with self.assertRaises(safety.OperationError) as caught:
                fmp4.verify_configuration(options, value)
        self.assertEqual(caught.exception.code, 'fmp4_configuration_drift')

    def test_fmp4_remote_setup_and_final_pin_reads_preserve_viewer_budget(self):
        value = config(); value['fmp4Startup'] = {'enabled': True}
        cid = value['bridges'][0]['cameraId']
        camera = {'id': cid, 'channels': [{'id': 1, 'enabled': True}],
                  'thirdPartyCameraInfo': {'enableRtspAudio': True}}
        clock = Fmp4Clock(); sock = Fmp4Socket(clock, stream()); timeouts = []
        def pins(_options, _config, **_kwargs):
            if not timeouts:
                clock.now += 6
            else:
                self.assertTrue(sock.closed)
                clock.now += 8
            return True
        def api(_config, _path, **kwargs):
            timeouts.append(kwargs['timeout']); clock.now += 1
            flags = fmp4.browser_flags(fmp4.configuration(value), cid)
            body = json.dumps({'cmd': 'play', 'params': {'channel': 1, 'type': 'fmp4', **flags}}).encode()
            return {'uri': 'tcp://127.0.0.1:7447',
                    'data': {'type': 'Buffer', 'data': list(len(body).to_bytes(4, 'big') + body)}}
        with patch.object(fmp4, 'verify_configuration', side_effect=pins), \
             patch.object(fmp4, 'remote_open_socket', return_value=sock) as opened:
            result = fmp4.probe_fmp4(value, camera, 1, clock=clock, api=api)
        self.assertTrue(result['ok'], result)
        self.assertEqual(timeouts, [2])
        opened.assert_called_once_with(value, 7447, 1)
        self.assertTrue(all(row['lastFragmentAgeSeconds'] <= 3 for row in result['tracks']))

    def test_fmp4_exhausted_remote_setup_never_starts_api_or_viewer(self):
        value = config(); value['fmp4Startup'] = {'enabled': True}
        camera = {'id': value['bridges'][0]['cameraId'], 'channels': [{'id': 1, 'enabled': True}]}
        clock = Fmp4Clock()
        def pins(*_args, **_kwargs):
            clock.now += 8
            return True
        with patch.object(fmp4, 'verify_configuration', side_effect=pins), \
             patch.object(fmp4, 'protect_json', side_effect=AssertionError('API after deadline')), \
             patch.object(fmp4, 'remote_open_socket') as opened:
            result = fmp4.probe_fmp4(value, camera, 1, clock=clock)
        self.assertFalse(result['ok'])
        self.assertEqual(result['errorCode'], 'fmp4_setup_timeout')
        opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
