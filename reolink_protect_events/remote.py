"""Private Protect connector over trusted SSH, without retries or secret output.

RPC uses one JSON request on stdin. Binary streams use the separately restricted
``stream:<port>`` command; TLS, when needed, terminates on this machine.
"""
import json
import math
import re
import socket
import ssl
import subprocess
import threading
import time


RPC_COMMAND = "python3 /usr/local/lib/reolink-protect-connector.py"
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ACTION = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_MAX_RPC_BYTES = 32 * 1024 * 1024


class RemoteError(RuntimeError):
    """Fixed local error vocabulary; never include remote bodies or diagnostics."""

    def __init__(self, code, *, remote_code=None):
        super().__init__(code)
        self.code = code
        # Only this fixed semantic result crosses the native tombstone boundary.
        self.remote_code = "event_retired" if remote_code == "event_retired" else None


def settings(config):
    """Return validated remote settings, or None for the existing local mode."""
    if not isinstance(config, dict):
        raise RemoteError("protect_remote_config_invalid")
    if "protectRemote" not in config:
        return None
    value = config["protectRemote"]
    if not isinstance(value, dict):
        raise RemoteError("protect_remote_config_invalid")
    alias = value.get("sshAlias")
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
        raise RemoteError("protect_remote_alias_invalid")
    if value.get("rpcCommand") != RPC_COMMAND:
        raise RemoteError("protect_remote_command_invalid")
    for name in ("snapshotPort", "dsPort", "apiPort"):
        if type(value.get(name)) is not int or not 1 <= value[name] <= 65535:
            raise RemoteError("protect_remote_port_invalid")
    return dict(value)


def _timeout(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 < value <= 300):
        raise RemoteError("protect_remote_timeout_invalid")
    return value


def _ssh(options, command):
    return ["ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
            "-oConnectTimeout=10", options["sshAlias"], command]


def rpc(config, action, payload=None, timeout=15):
    """Call the pinned connector once; uncertain writes are never retried here."""
    options = settings(config)
    if options is None:
        raise RemoteError("protect_remote_not_configured")
    timeout = _timeout(timeout)
    if not isinstance(action, str) or not _ACTION.fullmatch(action):
        raise RemoteError("protect_remote_action_invalid")
    if payload is None:
        payload = {}
    if not isinstance(payload, dict) or "action" in payload:
        raise RemoteError("protect_remote_payload_invalid")
    try:
        request = json.dumps(dict(payload, action=action), ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False)
        if len(request.encode("utf-8")) > _MAX_RPC_BYTES:
            raise RemoteError("protect_remote_request_limit")
    except (TypeError, ValueError, UnicodeError):
        raise RemoteError("protect_remote_payload_invalid") from None
    try:
        result = subprocess.run(_ssh(options, options["rpcCommand"]), input=request,
                                encoding="utf-8", stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                check=False, shell=False)
    except subprocess.TimeoutExpired:
        raise RemoteError("protect_remote_rpc_timeout") from None
    except UnicodeError:
        raise RemoteError("protect_remote_response_invalid") from None
    except OSError:
        raise RemoteError("protect_remote_transport_failed") from None
    if result.returncode:
        raise RemoteError("protect_remote_transport_failed")
    try:
        if not isinstance(result.stdout, str) or len(result.stdout.encode("utf-8")) > _MAX_RPC_BYTES:
            raise RemoteError("protect_remote_response_limit")
        response = json.loads(result.stdout)
    except (ValueError, TypeError, UnicodeError):
        raise RemoteError("protect_remote_response_invalid") from None
    if not isinstance(response, dict) or type(response.get("ok")) is not bool:
        raise RemoteError("protect_remote_response_invalid")
    if response["ok"] is not True:
        raise RemoteError("protect_remote_rpc_rejected", remote_code=response.get("errorCode"))
    if "result" not in response:
        raise RemoteError("protect_remote_response_invalid")
    return response["result"]


class _ProcessSocket:
    """Own a real local socket, its pipe pumps and exactly one SSH subprocess."""

    def __init__(self, connection, peer, process):
        self._socket, self._peer, self._process = connection, peer, process
        self._closed = False
        self._close_lock = threading.Lock()
        self._threads = [threading.Thread(target=self._receive, name="protect-ssh-receive", daemon=True),
                         threading.Thread(target=self._send, name="protect-ssh-send", daemon=True)]
        for thread in self._threads:
            thread.start()

    def _receive(self):
        try:
            while True:
                data = self._process.stdout.read(65536)
                if not data:
                    break
                self._peer.sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._peer.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _send(self):
        try:
            while True:
                data = self._peer.recv(65536)
                if not data:
                    break
                remaining = memoryview(data)
                while remaining:
                    written = self._process.stdin.write(remaining)
                    if not written:
                        return
                    remaining = remaining[written:]
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._process.stdin.close()
            except (OSError, ValueError):
                pass

    def recv(self, size, flags=0):
        return self._socket.recv(size, flags)

    def sendall(self, data, flags=0):
        return self._socket.sendall(data, flags)

    def settimeout(self, timeout):
        self._socket.settimeout(timeout)

    def gettimeout(self):
        return self._socket.gettimeout()

    def fileno(self):
        return self._socket.fileno()

    def close(self):
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            for connection in (self._socket, self._peer):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            try:
                if self._process.poll() is None:
                    self._process.terminate()
                try:
                    self._process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for pipe in (self._process.stdin, self._process.stdout):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
            for thread in self._threads:
                thread.join(timeout=0.2)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_socket(config, port, timeout, tls=False):
    """Open one loopback-only UDM stream through SSH, optionally with local TLS.

    A socketpair keeps normal socket/TLS deadlines on the caller's side while
    two pipe pumps carry opaque bytes through OpenSSH. No key files are read by
    this code and no extra listener is opened on either host.
    """
    options = settings(config)
    if options is None:
        raise RemoteError("protect_remote_not_configured")
    timeout = _timeout(timeout)
    if type(port) is not int or not 1024 <= port <= 65535 or type(tls) is not bool:
        raise RemoteError("protect_remote_stream_invalid")
    began = time.monotonic()
    connection = peer = process = stream = None
    try:
        connection, peer = socket.socketpair()
        connection.settimeout(timeout)
        process = subprocess.Popen(_ssh(options, "stream:" + str(port)), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   bufsize=0, shell=False)
        stream = _ProcessSocket(connection, peer, process)
        if tls:
            # As in the local Protect transport, its self-signed loopback TLS
            # identity is carried inside the independently pinned SSH channel.
            context = ssl._create_unverified_context()
            stream._socket = context.wrap_socket(connection, server_hostname="127.0.0.1",
                                                  do_handshake_on_connect=False)
            remaining = timeout - (time.monotonic() - began)
            if remaining <= 0:
                raise TimeoutError()
            stream.settimeout(remaining)
            stream._socket.do_handshake()
            stream.settimeout(timeout)
        return stream
    except (OSError, ValueError):
        if stream is not None:
            stream.close()
        else:
            for endpoint in (connection, peer):
                if endpoint is not None:
                    endpoint.close()
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        raise RemoteError("protect_remote_tls_failed" if tls else "protect_remote_stream_failed") from None
