import base64
import hashlib
import json
import socket
import struct
import threading
import unittest

from reolink_protect_events.updates import DsUpdateClient, DsUpdateError, encode_ucp, event_packet


def decode_ucp(packet):
    values = []
    position = 0
    for expected in (1, 2):
        kind, format_, compressed, reserved, length = struct.unpack("!BBBBI", packet[position:position + 8])
        assert (kind, format_, compressed, reserved) == (expected, 1, 0, 0)
        position += 8
        values.append(json.loads(packet[position:position + length]))
        position += length
    assert position == len(packet)
    return tuple(values)


def event(end=None):
    return {"id": "0123456789abcdef01234567", "camera": "1123456789abcdef01234567",
            "type": "smartDetectZone", "start": 1730000000000, "end": end,
            "smartDetectTypes": ["person"], "metadata": {
                "zonesStatus": {"1": {"status": "enter" if end is None else "leave"}},
                "reolinkProtectEvents": {"classificationOrigin": "camera", "spatialTrackAvailable": False}}}


def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        block = connection.recv(length - len(data))
        if not block:
            raise EOFError()
        data.extend(block)
    return bytes(data)


def read_client_frame(connection):
    first, second = exact(connection, 2)
    assert first & 0x80
    assert second & 0x80, "all client frames must be masked"
    length = second & 0x7f
    if length == 126:
        length = struct.unpack("!H", exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", exact(connection, 8))[0]
    mask = exact(connection, 4)
    encoded = exact(connection, length)
    return first & 15, bytes(byte ^ mask[n % 4] for n, byte in enumerate(encoded))


class MockDs:
    def __init__(self, behavior):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.behavior = behavior
        self.headers = {}
        self.frames = []
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        connection = None
        try:
            connection, _ = self.listener.accept()
            connection.settimeout(4)
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                headers.extend(exact(connection, 1))
            for line in headers.decode().split("\r\n")[1:]:
                if line:
                    name, value = line.split(":", 1)
                    self.headers[name.lower()] = value.strip()
            key = self.headers["sec-websocket-key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.behavior(self, connection, accept)
        except Exception as error:
            self.error = error
        finally:
            if connection:
                connection.close()
            self.listener.close()
            self.done.set()

    def finish(self):
        if not self.done.wait(5):
            raise AssertionError("Mock DS did not complete")
        if self.error:
            raise self.error

    def upgrade(self, connection, accept, protocol="updates-ds"):
        connection.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n"
                            "Sec-WebSocket-Protocol: %s\r\n\r\n" % (accept, protocol)).encode())


class PacketTests(unittest.TestCase):
    def test_header_authentication_and_zone_lifecycle(self):
        original = event()
        update_id, packet = event_packet("add", original, "abc")
        header, body = decode_ucp(packet)
        self.assertEqual(update_id, "abc")
        self.assertEqual(header, {"routingType": "genericModelUpdate", "newUpdateId": "abc",
            "action": "add", "id": original["id"], "modelKey": "event",
            "authorizationModelKey": "camera", "authorizationModelId": original["camera"]})
        self.assertEqual(body["smartDetectTypes"], ["person"])
        self.assertEqual(body["metadata"]["loiterStatus"], {})
        self.assertNotIn("loiterStatus", original["metadata"])
        _, closed = event_packet("update", event(1730000001000))
        self.assertEqual(decode_ucp(closed)[1]["metadata"]["zonesStatus"]["1"]["status"], "leave")

    def test_rejects_generic_motion_inferred_and_inconsistent_events(self):
        for change in ({"type": "motion"}, {"smartDetectTypes": ["face"]},
                       {"smartDetectTypes": []}, {"smartDetectTypes": ["person", "motion"]},
                       {"start": True}, {"end": 2}, {"camera": "a\r\nx-mac:b"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                event_packet("add", {**event(), **change})
        inconsistent = event(1730000001000)
        inconsistent["metadata"]["zonesStatus"]["1"]["status"] = "enter"
        with self.assertRaises(ValueError):
            event_packet("update", inconsistent)

    def test_audio_native_enums_pass_without_visual_zone_and_wrong_enum_family_fails(self):
        native_audio = ("alrmBabyCry", "alrmBark", "alrmSpeak", "alrmGlassBreak", "alrmSiren", "alrmCarHorn", "alrmSmoke")
        for kind in native_audio:
            original = event()
            original.update(type="smartAudioDetect", smartDetectTypes=[kind])
            original["metadata"]["zonesStatus"] = {}
            _, packet = event_packet("add", original, "audio-fixture")
            header, body = decode_ucp(packet)
            self.assertEqual(header["authorizationModelId"], original["camera"])
            self.assertEqual(body["type"], "smartAudioDetect")
            self.assertEqual(body["smartDetectTypes"], [kind])
            self.assertEqual(body["metadata"]["zonesStatus"], {})
            original["end"] = original["start"] + 1000
            event_packet("update", original)
        for event_type, classes in (("smartAudioDetect", ["person"]), ("smartAudioDetect", ["babyCry"]),
                                    ("smartAudioDetect", ["alrmBabyCry", "animal"]),
                                    ("smartDetectZone", ["alrmBark"])):
            with self.assertRaises(ValueError):
                event_packet("add", {**event(), "type": event_type, "smartDetectTypes": classes})
        with self.assertRaisesRegex(ValueError, "visual integration zone"):
            event_packet("add", {**event(), "type": "smartAudioDetect", "smartDetectTypes": ["alrmBabyCry"]})

    def test_unicode_lengths_are_bytes_and_nan_is_rejected(self):
        packet = encode_ucp({"name": "T\u00fcr"}, {"value": "\U0001f600"})
        self.assertEqual(decode_ucp(packet), ({"name": "T\u00fcr"}, {"value": "\U0001f600"}))
        with self.assertRaises(ValueError):
            encode_ucp({}, {"value": float("nan")})


class TransportTests(unittest.TestCase):
    def test_native_binary_ping_pong_and_close(self):
        ping_done = threading.Event()

        def behavior(mock, connection, accept):
            mock.upgrade(connection, accept)
            connection.sendall(b"\x89\x04ping")
            for _ in range(2):
                frame = read_client_frame(connection)
                mock.frames.append(frame)
                if frame[0] == 10:
                    ping_done.set()
            connection.sendall(b"\x88\x02\x03\xe8")
            mock.frames.append(read_client_frame(connection))

        server = MockDs(behavior)
        client = DsUpdateClient("aa:bb:cc:dd:ee:ff", port=server.port)
        self.assertEqual(client.send_event("add", event(), "abc"), "abc")
        self.assertTrue(ping_done.wait(2))
        server.finish()
        client.close()
        self.assertEqual(server.headers["x-mac"], "AABBCCDDEEFF")
        self.assertEqual(server.headers["sec-websocket-protocol"], "updates-ds")
        frames = dict(server.frames)
        self.assertEqual(frames[10], b"ping")
        self.assertEqual(decode_ucp(frames[2])[0]["newUpdateId"], "abc")
        self.assertEqual(frames[8], b"\x03\xe8")

    def test_handshake_requires_accept_and_subprotocol(self):
        for bad_accept, protocol in ((True, "updates-ds"), (False, "ucp4")):
            def behavior(mock, connection, accept):
                mock.upgrade(connection, "invalid" if bad_accept else accept, protocol)
            server = MockDs(behavior)
            with self.assertRaises(DsUpdateError):
                DsUpdateClient("AABBCCDDEEFF", port=server.port).connect()
            server.finish()

    def test_large_binary_client_frame(self):
        def behavior(mock, connection, accept):
            mock.upgrade(connection, accept)
            mock.frames.append(read_client_frame(connection))
        server = MockDs(behavior)
        original = event()
        original["metadata"]["padding"] = "x" * 70000
        client = DsUpdateClient("AABBCCDDEEFF", port=server.port)
        client.send_event("add", original)
        server.finish()
        client.close()
        self.assertEqual(len(decode_ucp(server.frames[0][1])[1]["metadata"]["padding"]), 70000)

    def test_no_nonloopback_or_header_injection(self):
        for mac, host in (("AABBCCDDEEFF\r\nx-mac: a", "127.0.0.1"),
                          ("AABBCCDDEEFF", "192.168.1.1"),
                          ("AABBCCDDEEFF", "localhost")):
            with self.subTest(mac=mac, host=host), self.assertRaises(ValueError):
                DsUpdateClient(mac, host=host)


if __name__ == "__main__":
    unittest.main()
