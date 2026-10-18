"""Stateless Protect-side SSH connector. No listener, journal or daemon.

Installed as a root-owned standalone file and selected by a dedicated forced
SSH command. Application processing and persistent state live on the server.
Never log requests, database diagnostics, headers or response bodies.
"""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import selectors
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse

CONFIG = Path('/data/reolink-protect-connector/config.json')
RPC_COMMAND = 'python3 /usr/local/lib/reolink-protect-connector.py'
MAX_REQUEST = 12 * 1024 * 1024
VERSION = '7.3.70'


class ConnectorError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
        self.refs, self.closed = 0, False

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.sock.settimeout(remaining)

    def recv_into(self, *args):
        self.remaining()
        return self.sock.recv_into(*args)

    def sendall(self, value):
        self.remaining()
        return self.sock.sendall(value)

    def makefile(self, mode, buffering=None):
        self.refs += 1
        raw = None
        try:
            raw = socket.SocketIO(self, mode)
            return io.BufferedReader(raw)
        except Exception:
            if raw is not None:
                raw.close()
            else:
                self._decref_socketios()
            raise

    def _decref_socketios(self):
        self.refs -= 1
        if self.closed and not self.refs:
            self.sock.close()

    def close(self):
        self.closed = True
        if not self.refs:
            self.sock.close()


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        http.client.HTTPConnection.connect(self)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.sock.settimeout(remaining)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def need(condition, code):
    if not condition:
        raise ConnectorError(code)


def load_config(path=CONFIG):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
         'connector_config_permissions')
    value = json.loads(path.read_text())
    need(isinstance(value, dict) and isinstance(value.get('cameraIds'), list)
         and len(value['cameraIds']) == 6
         and all(re.fullmatch('[a-f0-9]{24}', c) for c in value['cameraIds'])
         and len(set(value['cameraIds'])) == 6, 'connector_camera_scope')
    need(isinstance(value.get('protectUserId'), str)
         and re.fullmatch('[a-f0-9-]{36}', value['protectUserId']), 'connector_user_scope')
    return value


def installed_version():
    response = subprocess.run(['dpkg-query', '--show', '--showformat=${Version}', 'unifi-protect'],
                              capture_output=True, text=True, timeout=5)
    need(response.returncode == 0 and response.stdout.strip() == VERSION,
         'connector_protect_version_changed')
    return response.stdout.strip()


def validate_sql(value):
    # This is a privileged Protect-database transport, not an arbitrary shell.
    # Schema, ownership, identity and idempotency checks also run in the adapter.
    need(isinstance(value, str) and 1 <= len(value.encode()) <= MAX_REQUEST,
         'connector_sql_size')
    need(value.lstrip().startswith('BEGIN')
         and value.rstrip().endswith(('COMMIT;', 'ROLLBACK;')),
         'connector_sql_transaction_required')
    need('\\' not in value and '\x00' not in value,
         'connector_psql_commands_forbidden')
    need(not re.search(r'\b(?:COPY|PROGRAM|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE|VACUUM|LOAD|dblink|lo_import|lo_export|pg_read_file|pg_write_file|pg_execute_server_program)\b', value, re.I),
         'connector_sql_operation_forbidden')
    return value


def execute_sql(value):
    installed_version()
    sql = validate_sql(value)
    response = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-h', '/run/postgresql',
        '-p', '5433', '-d', 'unifi-protect', '-w', '-X', '-q', '-A', '-t',
        '-v', 'ON_ERROR_STOP=1'], input=sql, capture_output=True, text=True, timeout=18)
    if response.returncode:
        raise ConnectorError('event_retired' if 'reolink-protect-events:retired' in response.stderr
                             else 'connector_database_failed')
    need(len(response.stdout.encode()) <= MAX_REQUEST, 'connector_database_response_limit')
    return response.stdout


def api_request(config, request):
    path, method, body = request.get('path'), request.get('method', 'GET'), request.get('body')
    need(isinstance(path, str) and len(path) <= 16384 and not any(c in path for c in '\r\n\x00'),
         'connector_api_path')
    endpoint = urllib.parse.urlsplit(path)
    need(not endpoint.scheme and not endpoint.netloc and not endpoint.fragment,
         'connector_api_path')
    camera_paths = {'/api/cameras/' + c for c in config['cameraIds']}
    allowed_get = {'/api/bootstrap', '/api/ws/livestream', '/api/tcp/livestream'} | camera_paths
    if re.fullmatch(r'/api/events/[a-f0-9]{24}', endpoint.path):
        allowed_get.add(endpoint.path)
    if method == 'GET':
        need(endpoint.path in allowed_get and body is None, 'connector_api_scope')
        if endpoint.path in {'/api/ws/livestream', '/api/tcp/livestream'}:
            params = urllib.parse.parse_qs(endpoint.query)
            need(len(params.get('camera', [])) == 1 and params['camera'][0] in config['cameraIds'],
                 'connector_api_camera_scope')
    elif method == 'PATCH':
        need(path in camera_paths and isinstance(body, dict)
             and set(body) == {'thirdPartyCameraInfo'}
             and isinstance(body['thirdPartyCameraInfo'], dict)
             and set(body['thirdPartyCameraInfo']) == {'forceTcp'}
             and type(body['thirdPartyCameraInfo']['forceTcp']) in (type(None), bool)
             and body['thirdPartyCameraInfo']['forceTcp'] in (None, True),
             'connector_api_write_scope')
        installed_version()
    else:
        raise ConnectorError('connector_api_method')
    timeout, limit = request.get('timeout', 8), request.get('limit', 10000000)
    need(type(timeout) in (int, float) and 0 < timeout <= 30
         and type(limit) is int and 1 <= limit <= MAX_REQUEST, 'connector_api_budget')
    headers = {'X-UserId': config['protectUserId'], 'X-UserRole': 'owner',
        'X-UserPermissionMask': '64', 'X-UserPermissions': '65535',
        'X-Internal-Use': 'true', 'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': '127.0.0.1'}
    conn = DeadlineHTTPSConnection('127.0.0.1', 7443, timeout=timeout,
                                   context=ssl._create_unverified_context())
    conn.deadline = time.monotonic() + timeout
    raw_socket = None
    try:
        conn.connect()
        raw_socket = conn.sock
        conn.sock = DeadlineSocket(raw_socket, conn.deadline)
        conn.request(method, path, None if body is None else json.dumps(body).encode(), headers)
        with conn.getresponse() as response:
            need(response.status == 200, 'connector_api_rejected')
            content = response.read(limit + 1)
            need(len(content) <= limit, 'connector_api_response_limit')
            return json.loads(content)
    finally:
        conn.close()
        if raw_socket is not None:
            raw_socket.close()


def file_hashes(config, request):
    paths = request.get('paths')
    need(isinstance(paths, list) and 1 <= len(paths) <= 32
         and all(isinstance(p, str) and p in config.get('hashPaths', []) for p in paths),
         'connector_hash_scope')
    result = {}
    for name in paths:
        path = Path(name)
        need(not path.is_symlink() and all(not p.is_symlink() for p in path.parents),
             'connector_hash_symlink')
        need(path.is_file() and path.stat().st_size <= 128 * 1024 * 1024, 'connector_hash_size')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for part in iter(lambda: stream.read(262144), b''):
                digest.update(part)
        result[name] = digest.hexdigest()
    return result


def dispatch(config, request):
    need(isinstance(request, dict), 'connector_request')
    action = request.get('action')
    if action == 'version':
        return installed_version()
    if action == 'sql':
        return execute_sql(request.get('sql'))
    if action == 'api':
        return api_request(config, request)
    if action == 'hashes':
        return file_hashes(config, request)
    if action == 'ping':
        return {'connectorVersion': 1, 'protectVersion': installed_version(), 'cameraCount': 6}
    raise ConnectorError('connector_action')


def relay(port):
    """Byte-only bounded loopback transport; parsing and TLS run on Debian."""
    need(type(port) is int and 1024 <= port <= 65535, 'connector_stream_port')
    stream = socket.create_connection(('127.0.0.1', port), timeout=8)
    incoming, outgoing = bytearray(), bytearray()
    deadline = time.monotonic() + 120
    total = 0
    eof = False
    upstream_eof = False
    os.set_blocking(0, False)
    os.set_blocking(1, False)
    stream.setblocking(False)
    select = selectors.DefaultSelector()
    try:
        while time.monotonic() < deadline:
            for key in list(select.get_map().values()):
                select.unregister(key.fileobj)
            if not eof and not upstream_eof and len(incoming) < 262144:
                select.register(0, selectors.EVENT_READ, 'stdin')
            flags = ((selectors.EVENT_READ if len(outgoing) < 262144 else 0)
                     | (selectors.EVENT_WRITE if incoming else 0)) if not upstream_eof else 0
            if flags:
                select.register(stream, flags, 'socket')
            if outgoing:
                select.register(1, selectors.EVENT_WRITE, 'stdout')
            if (upstream_eof or eof and not incoming) and not outgoing:
                return
            for key, event in select.select(min(1, max(0, deadline - time.monotonic()))):
                if key.data == 'stdin':
                    data = os.read(0, 65536)
                    if not data:
                        eof = True
                    else:
                        incoming.extend(data)
                elif key.data == 'stdout':
                    sent = os.write(1, outgoing)
                    del outgoing[:sent]
                else:
                    if event & selectors.EVENT_WRITE:
                        sent = stream.send(incoming)
                        del incoming[:sent]
                    if event & selectors.EVENT_READ:
                        data = stream.recv(65536)
                        if not data:
                            upstream_eof = True
                            incoming.clear()
                        else:
                            outgoing.extend(data)
                            total += len(data)
                            need(total <= 128 * 1024 * 1024, 'connector_stream_budget')
        raise ConnectorError('connector_stream_deadline')
    finally:
        select.close()
        stream.close()


def main():
    os.umask(0o077)
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    try:
        if re.fullmatch(r'stream:[1-9][0-9]{3,4}', command):
            load_config()
            relay(int(command.split(':')[1]))
            return 0
        need(command == RPC_COMMAND, 'connector_command')
        config = load_config()
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        need(len(raw) <= MAX_REQUEST, 'connector_request_limit')
        result = dispatch(config, json.loads(raw))
        print(json.dumps({'ok': True, 'result': result}, separators=(',', ':')))
        return 0
    except Exception as exc:
        if command.startswith('stream:'):
            return 1
        print(json.dumps({'ok': False, 'errorCode': exc.code if isinstance(exc, ConnectorError)
                          else 'connector_operation_failed'}))
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
