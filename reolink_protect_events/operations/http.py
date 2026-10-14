"""Loopback Protect requests with one total TCP/TLS/body deadline."""
import base64
import json
import re
import socket
import time
import urllib.parse
from ..http_deadline import _DeadlineSocket, _HTTPSConnection, get_bytes
from .safety import OperationError, need


def owner_headers(config):
    return {'X-UserId': config['protectUserId'], 'X-UserRole': 'owner',
            'X-UserPermissionMask': '64', 'X-UserPermissions': '65535',
            'X-Internal-Use': 'true', 'Content-Type': 'application/json',
            'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': '127.0.0.1'}


def protect_json(config, path, *, method='GET', body=None, timeout=8, limit=10000000):
    need(isinstance(path, str) and path.startswith('/api/') and not any(c in path for c in '\r\n\0'),
         'protect_path_invalid')
    need(method in ('GET', 'PATCH'), 'protect_method_invalid')
    if method == 'PATCH':
        ids = {row['cameraId'] for row in config['bridges']}
        need(path in {'/api/cameras/' + i for i in ids} and isinstance(body, dict)
             and set(body) == {'thirdPartyCameraInfo'} and isinstance(body['thirdPartyCameraInfo'], dict)
             and set(body['thirdPartyCameraInfo']) == {'forceTcp'}
             and body['thirdPartyCameraInfo']['forceTcp'] in (None, True)
             and type(body['thirdPartyCameraInfo']['forceTcp']) in (type(None), bool), 'protect_patch_out_of_scope')
    try:
        if method == 'GET':
            status, raw = get_bytes('https://127.0.0.1:7443' + path, owner_headers(config),
                                    timeout=timeout, limit=limit)
        else:
            import ssl
            connection = _HTTPSConnection('127.0.0.1', 7443, timeout=timeout,
                                          context=ssl._create_unverified_context())
            connection.deadline = time.monotonic() + timeout
            sock = None
            try:
                connection.connect(); sock = connection.sock
                connection.sock = _DeadlineSocket(sock, connection.deadline)
                connection.request(method, path, body=json.dumps(body).encode(), headers=owner_headers(config))
                with connection.getresponse() as response:
                    status = response.status; raw = response.read(limit + 1)
                    need(len(raw) <= limit, 'protect_response_size_limit')
            finally:
                connection.close()
                if sock is not None: sock.close()
        need(status == 200, 'protect_http_rejected')
        result = json.loads(raw)
        need(isinstance(result, (dict, list)), 'protect_json_invalid')
        return result
    except OperationError:
        raise
    except (TimeoutError, socket.timeout):
        raise OperationError('protect_total_deadline') from None
    except Exception:
        raise OperationError('protect_read_failed' if method == 'GET' else 'protect_patch_failed') from None


def bridge_metrics(bridge):
    token = base64.b64encode((bridge['username'] + ':' + bridge['password']).encode()).decode()
    try:
        status, raw = get_bytes('http://' + bridge['host'] + ':8080/metrics',
                                {'Authorization': 'Basic ' + token}, timeout=4, limit=1048576)
        need(status == 200, 'bridge_http_rejected')
        result = json.loads(raw)
        need(isinstance(result, dict), 'bridge_json_invalid')
        return result
    except OperationError:
        raise
    except Exception:
        raise OperationError('bridge_metrics_failed') from None
