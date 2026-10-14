"""Bounded HTTP GETs: numeric hosts, no redirects/proxies, one total deadline."""
import http.client
import io
import ipaddress
import socket
import ssl
import time
import urllib.parse


class _DeadlineSocket:
    """Keep http.client's buffered header/body reads within the same deadline."""
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
        self._io_refs = 0
        self._closed = False

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("http_total_deadline")
        self.sock.settimeout(remaining)

    def recv_into(self, *args):
        self._remaining()
        return self.sock.recv_into(*args)

    def sendall(self, data):
        self._remaining()
        return self.sock.sendall(data)

    def makefile(self, mode, buffering=None):
        # Socket.makefile normally owns this increment, not SocketIO itself.
        # http.client may close its connection after parsing a close-delimited
        # response while the buffered response still needs to read its body.
        self._io_refs += 1
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
        self._io_refs -= 1
        if self._closed and not self._io_refs:
            self.sock.close()

    def close(self):
        self._closed = True
        if not self._io_refs:
            self.sock.close()


class _HTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        http.client.HTTPConnection.connect(self)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("http_total_deadline")
        self.sock.settimeout(remaining)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def get_bytes(url, headers=None, *, timeout=5, limit=2 * 1024 * 1024, include_headers=False):
    """Return status and bytes; never forward authentication through redirects."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("invalid_http_target")
    ipaddress.ip_address(parsed.hostname)  # Avoid unbounded DNS and unexpected targets.
    deadline = time.monotonic() + timeout
    connection_type = _HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    options = {"context": ssl._create_unverified_context()} if parsed.scheme == "https" else {}
    connection = connection_type(parsed.hostname, parsed.port, timeout=timeout, **options)
    connection.deadline = deadline
    sock = None
    try:
        connection.connect()
        sock = connection.sock
        connection.sock = _DeadlineSocket(sock, deadline)
        connection.request("GET", parsed.path + ("?" + parsed.query if parsed.query else ""), headers=headers or {})
        with connection.getresponse() as response:
            if 300 <= response.status < 400:
                raise ValueError("http_redirect_rejected")
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("http_response_oversized")
            return (response.status, data, dict(response.headers)) if include_headers else (response.status, data)
    except socket.timeout:
        # Before Python 3.10 socket.timeout is a separate OSError subclass.
        # Normalize every TCP/TLS/request/response timeout at this API boundary.
        raise TimeoutError("http_total_deadline") from None
    finally:
        connection.close()
        if sock is not None:
            sock.close()
