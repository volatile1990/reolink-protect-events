"""Private Protect 7.3.70 updates-ds transport, using Python 3.9 stdlib.

This loopback socket authenticates the existing camera MAC, not its password.
It forwards persisted event updates through Protect's native notification and
alarm handlers. A successful send is a transport write, never an application
acknowledgement. The caller must reconcile persistence through the Protect API.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import threading
import time
import uuid


CLASSES = frozenset(("person", "vehicle", "animal"))
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAX_PACKET = 1024 * 1024


class DsUpdateError(RuntimeError):
    """Sanitized transport failure; no credentials or event payload in errors."""


def encode_ucp(header, body):
    """Encode the two uncompressed JSON UCP parts used by shipped module 58738."""
    parts = []
    for kind, value in ((1, header), (2, body)):
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
        parts.append(struct.pack("!BBBBI", kind, 1, 0, 0, len(payload)) + payload)
    packet = b"".join(parts)
    if len(packet) > _MAX_PACKET:
        raise ValueError("DS update exceeds the packet limit")
    return packet


def _identifier(value, name):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid " + name)
    return value


def event_packet(action, event, update_id=None):
    """Validate source classifications and construct native event authorization.

    Zone 1 is the adapter's whole-camera integration rule, not a spatial box or
    proof of crossing a user-defined zone. Persistence owns this metadata.
    """
    if action not in ("add", "update") or not isinstance(event, dict):
        raise ValueError("Invalid event action or body")
    event_id = _identifier(event.get("id"), "event identity")
    camera_id = _identifier(event.get("camera"), "event camera")
    if event.get("type") != "smartDetectZone":
        raise ValueError("Only source-classified smartDetectZone events are supported")
    classes = event.get("smartDetectTypes")
    if not isinstance(classes, list) or not classes or any(
            not isinstance(kind, str) or kind not in CLASSES for kind in classes):
        raise ValueError("Event requires real person, vehicle or animal classifications")
    start, end = event.get("start"), event.get("end")
    if type(start) is not int or not 0 < start < 2 ** 53 or (
            end is not None and (type(end) is not int or not start <= end < 2 ** 53)):
        raise ValueError("Invalid event interval")
    metadata = event.get("metadata")
    expected_status = "enter" if end is None else "leave"
    if not isinstance(metadata, dict) or metadata.get("zonesStatus", {}).get("1", {}).get("status") != expected_status:
        raise ValueError("Event integration zone status must match the interval")
    # The serialization copy prevents mutations to the caller's persisted body.
    body = json.loads(json.dumps(event, allow_nan=False))
    body["modelKey"] = "event"
    body["metadata"].setdefault("loiterStatus", {})
    body["metadata"].setdefault("linesStatus", {})
    update_id = _identifier(update_id or uuid.uuid4().hex[:24], "update identity")
    header = {"routingType": "genericModelUpdate", "newUpdateId": update_id,
              "action": action, "id": event_id, "modelKey": "event",
              "authorizationModelKey": "camera", "authorizationModelId": camera_id}
    return update_id, encode_ucp(header, body)


def _frame(opcode, payload):
    """RFC 6455: every client frame is final, uncompressed and masked."""
    length = len(payload)
    mask = os.urandom(4)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length <= 65535:
        header = bytes((0x80 | opcode, 0xfe)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 0xff)) + struct.pack("!Q", length)
    return header + mask + bytes(byte ^ mask[n % 4] for n, byte in enumerate(payload))


class DsUpdateClient:
    """One reusable updates-ds connection per adopted camera.

    Failed writes are never retried inside this class: the server may already
    have processed them. Durable event identities and the caller's outbox handle
    reconnect/reconciliation. Protect does not send a per-event acceptance ACK.
    """

    def __init__(self, mac, host="127.0.0.1", port=7448, timeout=5):
        normalized = re.sub(r"[:-]", "", mac) if isinstance(mac, str) else ""
        if not re.fullmatch(r"[a-fA-F0-9]{12}", normalized):
            raise ValueError("Invalid camera MAC")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("DS updates require a numeric loopback address") from None
        if not address.is_loopback or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("DS updates require a loopback address and valid port")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 30:
            raise ValueError("Invalid DS transport timeout")
        self.mac = normalized.upper()
        self.host, self.port, self.timeout = host, port, timeout
        self._socket = None
        self._reader = None
        self._write_lock = threading.RLock()
        self._connect_lock = threading.Lock()

    @property
    def connected(self):
        return self._socket is not None

    def connect(self):
        with self._connect_lock:
            if self.connected:
                return
            connection = None
            deadline = time.monotonic() + self.timeout
            try:
                connection = socket.create_connection((self.host, self.port), timeout=self.timeout)
                key = base64.b64encode(os.urandom(16)).decode("ascii")
                host = "[" + self.host + "]" if ":" in self.host else self.host
                request = ("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                           "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: updates-ds\r\n"
                           "x-mac: %s\r\n\r\n") % (host, self.port, key, self.mac)
                connection.sendall(request.encode("ascii"))
                response = bytearray()
                # Read only through the headers, preserving any coalesced WS data.
                while not response.endswith(b"\r\n\r\n"):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DsUpdateError("DS handshake deadline exceeded")
                    connection.settimeout(remaining)
                    chunk = connection.recv(1)
                    if not chunk or len(response) >= 16384:
                        raise DsUpdateError("DS handshake is incomplete or oversized")
                    response.extend(chunk)
                lines = response.decode("ascii").split("\r\n")
                if not re.fullmatch(r"HTTP/1\.[01] 101(?: .*)?", lines[0]):
                    raise DsUpdateError("DS websocket upgrade was rejected")
                headers = {}
                for line in lines[1:]:
                    if line:
                        name, value = line.split(":", 1)
                        name = name.strip().lower()
                        if name in headers:
                            raise DsUpdateError("DS handshake contains duplicate headers")
                        headers[name] = value.strip()
                accepted = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
                if (headers.get("sec-websocket-accept") != accepted
                        or headers.get("sec-websocket-protocol") != "updates-ds"
                        or headers.get("upgrade", "").lower() != "websocket"
                        or "upgrade" not in {x.strip().lower() for x in headers.get("connection", "").split(",")}):
                    raise DsUpdateError("DS websocket handshake validation failed")
                connection.settimeout(0.5)
                with self._write_lock:
                    self._socket = connection
                self._reader = threading.Thread(target=self._read_loop, args=(connection,),
                                                name="protect-updates-ds", daemon=True)
                self._reader.start()
            except (OSError, ValueError, DsUpdateError):
                if connection is not None:
                    connection.close()
                raise DsUpdateError("DS websocket connection failed") from None

    def _drop(self, connection):
        with self._write_lock:
            if self._socket is connection:
                self._socket = None
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def _send(self, opcode, payload, connection):
        with self._write_lock:
            if self._socket is not connection:
                raise DsUpdateError("DS websocket is closed")
            try:
                connection.sendall(_frame(opcode, payload))
            except OSError:
                self._drop(connection)
                raise DsUpdateError("DS write failed; delivery is uncertain") from None

    def send_event(self, action, event, update_id=None):
        update_id, packet = event_packet(action, event, update_id)
        self.connect()
        connection = self._socket
        if connection is None:
            raise DsUpdateError("DS websocket closed before event write")
        self._send(2, packet, connection)
        return update_id

    def _read_exact(self, connection, length):
        data = bytearray()
        while len(data) < length:
            if self._socket is not connection:
                raise DsUpdateError("DS websocket is closed")
            try:
                chunk = connection.recv(length - len(data))
            except socket.timeout:
                continue
            if not chunk:
                raise DsUpdateError("DS websocket ended")
            data.extend(chunk)
        return bytes(data)

    def _read_loop(self, connection):
        fragmented = False
        try:
            while self._socket is connection:
                first, second = self._read_exact(connection, 2)
                final, opcode = bool(first & 0x80), first & 0x0f
                if first & 0x70 or second & 0x80:
                    raise DsUpdateError("Unsupported DS websocket frame")
                length = second & 0x7f
                if length == 126:
                    length = struct.unpack("!H", self._read_exact(connection, 2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", self._read_exact(connection, 8))[0]
                if length > _MAX_PACKET or opcode not in (0, 1, 2, 8, 9, 10) or (
                        opcode >= 8 and (not final or length > 125)):
                    raise DsUpdateError("Invalid DS websocket frame")
                payload = self._read_exact(connection, length)
                if opcode == 8:
                    if len(payload) == 1:
                        raise DsUpdateError("Invalid DS websocket close")
                    self._send(8, payload, connection)
                    return
                if opcode == 9:
                    self._send(10, payload, connection)
                elif opcode in (0, 1, 2):
                    if (opcode == 0 and not fragmented) or (opcode != 0 and fragmented):
                        raise DsUpdateError("Invalid DS websocket fragmentation")
                    fragmented = not final
                    # updates-ds has no event ACK. Incoming data is not treated
                    # as acceptance, nor printed into logs.
        except (OSError, DsUpdateError):
            pass
        finally:
            self._drop(connection)

    def close(self):
        connection = self._socket
        if connection is not None:
            try:
                self._send(8, struct.pack("!H", 1000), connection)
            except DsUpdateError:
                pass
            self._drop(connection)
        reader = self._reader
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=1)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()
