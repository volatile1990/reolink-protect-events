"""Bounded incremental UBV metadata parser. All encoded media is skipped.

Envelope basis: the author's current Rust implementation, not executable code:
https://github.com/petergeneric/unifi-protect-remux/blob/master/ubv/src/format.rs
https://github.com/petergeneric/unifi-protect-remux/blob/master/ubv/src/record.rs
Only seven ADTS header bytes or eight ClockSync bytes are inspected. Never return
media/header bytes. feed accepts any network splitting; summary emits numbers.
"""
import struct
import hashlib
from ..remote import open_socket as remote_open_socket, settings as remote_settings


class UbvMetadataError(Exception):
    pass


CLOCK_RATES = (0, 0, 1000, 8000, 11025, 12000, 16000, 22050,
               24000, 32000, 44100, 48000, 90000, 1000000, 1000000000, 0)
ADTS_RATES = (96000, 88200, 64000, 48000, 44100, 32000, 24000,
              22050, 16000, 12000, 11025, 8000, 7350)
MEDIA_TRACKS = {7: 'H264', 1000: 'AAC', 1003: 'H265', 1004: 'AV1'}


class UbvMetadataParser:
    MAX_RECORD_BYTES = 16 * 1024 * 1024
    MAX_OBSERVATIONS = 2000

    def __init__(self, hash_payloads=False):
        self.header = bytearray()
        self.trailer = bytearray()
        self.prefix = bytearray()
        self.state = 'header'
        self.required_header = 8
        self.offset = 0
        self.record = None
        self.payload_remaining = self.padding_remaining = 0
        self.started_at = None
        self.last_received_at = None
        self.bytes_received = self.records = 0
        self.max_metadata_bytes = 0
        self.tracks = {}
        self.clocks = []
        self.partition_headers = 0
        self.unknown_tracks = set()
        self.hash_payloads = bool(hash_payloads)
        self.payload_hashes = {}

    def _parse_base(self):
        h = self.header
        if h[0] != 0xA0:
            raise UbvMetadataError('ubv_magic_mismatch')
        if h[3] != h[0] ^ h[1] ^ h[2]:
            raise UbvMetadataError('ubv_checksum_mismatch')
        flags, rate_index = h[4], h[5] & 15
        format_code = flags << 8 | h[5]
        if format_code == 0xF100:
            size_offset = 8
        elif 1 <= rate_index <= 14:
            size_offset = 8 + (4 if rate_index == 1 else 0)
            size_offset += 8 if flags & 4 else 4
            size_offset += 4 if flags & 2 else 0
            size_offset += 4 if not flags & 0x40 else 0
        else:
            raise UbvMetadataError('ubv_unsupported_layout')
        if size_offset > 32:
            raise UbvMetadataError('ubv_header_limit')
        self.required_header = size_offset + 4

    def _parse_header(self, now):
        h = self.header
        track, fmt, sequence = struct.unpack_from('!H', h, 1)[0], (h[4] << 8 | h[5]), struct.unpack_from('!H', h, 6)[0]
        flags, index = h[4], h[5] & 15
        pos = 8
        rate = dts = extra = duration = None
        if fmt != 0xF100:
            if index == 1:
                rate = struct.unpack_from('!I', h, pos)[0]
                pos += 4
            else:
                rate = CLOCK_RATES[index]
            if not rate or rate > 1000000000:
                raise UbvMetadataError('ubv_invalid_clock_rate')
            if flags & 4:
                dts = struct.unpack_from('!Q', h, pos)[0]
                pos += 8
            else:
                dts = struct.unpack_from('!I', h, pos)[0]
                pos += 4
            if flags & 2:
                extra = struct.unpack_from('!I', h, pos)[0]
                pos += 4
            if not flags & 0x40:
                duration = struct.unpack_from('!I', h, pos)[0]
                pos += 4
        size = struct.unpack_from('!I', h, pos)[0]
        if pos + 4 != len(h) or size > self.MAX_RECORD_BYTES:
            raise UbvMetadataError('ubv_record_size_limit')
        pad = -(self.offset + len(h) + size) % 4
        self.record = {'track': track, 'format': fmt, 'sequence': sequence,
                       'dts': dts, 'rate': rate, 'extra': extra, 'duration': duration,
                       'keyframe': bool(flags & 0x20), 'position': flags >> 6,
                       'size': size, 'pad': pad, 'headerSize': len(h), 'receivedAt': now}
        self.payload_remaining, self.padding_remaining = size, pad
        self.prefix.clear()
        self.state = 'payload'

    @staticmethod
    def _adts(prefix, size):
        if len(prefix) < 7 or prefix[0] != 255 or prefix[1] & 0xF6 != 0xF0:
            return {'valid': False}
        index = (prefix[2] >> 2) & 15
        frame_size = (prefix[3] & 3) << 11 | prefix[4] << 3 | prefix[5] >> 5
        channels = (prefix[2] & 1) << 2 | prefix[3] >> 6
        return {'valid': index < len(ADTS_RATES) and frame_size <= size and frame_size >= 7,
                'rate': ADTS_RATES[index] if index < len(ADTS_RATES) else None,
                'channels': channels, 'objectType': (prefix[2] >> 6) + 1,
                'frameBytes': frame_size, 'payloadBytes': size,
                'singleAdtsFrame': frame_size == size,
                'rawDataBlocks': (prefix[6] & 3) + 1}

    def _finish_record(self, now):
        if self.records >= 10000 or (self.record['track'] not in self.tracks and len(self.tracks) >= 16):
            raise UbvMetadataError('ubv_metadata_record_limit')
        r = self.record
        expected = r['headerSize'] + r['size'] + r['pad']
        observed = struct.unpack('!I', self.trailer)[0]
        if expected != observed:
            raise UbvMetadataError('ubv_back_size_mismatch')
        self.offset += expected + 4
        self.records += 1
        t = self.tracks.setdefault(r['track'], {'records': 0, 'bytes': 0,
                'sequenceErrors': 0, 'lastSequence': None, 'keyframes': 0,
                'rates': set(), 'formats': set(), 'positions': {}, 'observations': [],
                'adtsConfigurations': set(), 'invalidAdts': 0, 'adtsClockMismatches': 0,
                'partialAdtsPayloads': 0, 'lastDts': None, 'zeroDts': 0,
                'backwardDts': 0, 'clockJumpsOverFiveSeconds': 0,
                'clockRateChanges': 0, 'lastRate': None, 'pendingChunkKeyframe': False})
        t['records'] += 1
        t['bytes'] += r['size']
        t['formats'].add(r['format'])
        t['positions'][r['position']] = t['positions'].get(r['position'], 0) + 1
        if t['lastSequence'] is not None and r['sequence'] != (t['lastSequence'] + 1) & 65535:
            t['sequenceErrors'] += 1
        t['lastSequence'] = r['sequence']
        if r['rate'] is not None:
            t['rates'].add(r['rate'])
        if r['track'] == 9:
            self.partition_headers += 1
        elif r['track'] == 0xDA7E:
            if len(self.prefix) != 8 or r['size'] != 8:
                raise UbvMetadataError('ubv_invalid_clock_sync_size')
            seconds, nanos = struct.unpack('!II', self.prefix)
            if nanos >= 1000000000:
                raise UbvMetadataError('ubv_invalid_clock_sync_nanoseconds')
            if len(self.clocks) >= self.MAX_OBSERVATIONS:
                raise UbvMetadataError('ubv_clock_observation_limit')
            self.clocks.append({'dts': r['dts'], 'rate': r['rate'],
                                'utcSeconds': seconds + nanos / 1000000000,
                                'arrivalSeconds': now - self.started_at})
        elif r['track'] in MEDIA_TRACKS:
            # Large encoded pictures can be split into multiple UBV records.
            # A complete frame ends with Single(3) or Last(1), so do not mistake
            # equal DTS across its chunks for separate zero-duration pictures.
            if r['position'] == 2:
                t['pendingChunkKeyframe'] = r['keyframe']
            if r['position'] in (1, 3):
                if len(t['observations']) >= self.MAX_OBSERVATIONS:
                    raise UbvMetadataError('ubv_media_observation_limit')
                if t['lastDts'] is not None:
                    if r['rate'] != t['lastRate']:
                        t['clockRateChanges'] += 1
                    else:
                        delta = r['dts'] - t['lastDts']
                        if not r['format'] & 0x0400 and delta < -0x80000000:
                            delta += 2**32
                        if delta == 0:
                            t['zeroDts'] += 1
                        elif delta < 0:
                            t['backwardDts'] += 1
                        elif delta > r['rate'] * 5:
                            t['clockJumpsOverFiveSeconds'] += 1
                t['observations'].append((now - self.started_at, r['dts'], r['rate']))
                t['lastDts'], t['lastRate'] = r['dts'], r['rate']
                if r['keyframe'] or (r['position'] == 1 and t['pendingChunkKeyframe']):
                    t['keyframes'] += 1
                t['pendingChunkKeyframe'] = False
            if r['track'] == 1000 and r['position'] == 3:
                adts = self._adts(self.prefix, r['size'])
                if not adts['valid']:
                    t['invalidAdts'] += 1
                else:
                    t['adtsConfigurations'].add((adts['objectType'], adts['rate'], adts['channels'], adts['rawDataBlocks']))
                    # A live UBV stream can normalize all tracks to milliseconds
                    # (actual C902 layout). Packet clock is not AAC sample rate.
                    # Keep the difference as metadata, never declare it corrupt.
                    if adts['rate'] != r['rate']:
                        t['adtsClockMismatches'] += 1
                    if not adts['singleAdtsFrame']:
                        t['partialAdtsPayloads'] += 1
        else:
            self.unknown_tracks.add(r['track'])
        self.header.clear()
        self.trailer.clear()
        self.prefix.clear()
        self.required_header = 8
        self.record = None
        self.state = 'header'

    def feed(self, data, now):
        if self.started_at is None:
            self.started_at = now
        self.last_received_at = now
        self.bytes_received += len(data)
        view, pos = memoryview(data), 0
        while pos < len(view):
            if self.state == 'header':
                take = min(self.required_header - len(self.header), len(view) - pos)
                self.header.extend(view[pos:pos + take]); pos += take
                if len(self.header) == 8 and self.required_header == 8:
                    self._parse_base()
                if len(self.header) == self.required_header:
                    self._parse_header(now)
            elif self.state == 'payload':
                take = min(self.payload_remaining, len(view) - pos)
                if self.hash_payloads and take:
                    digest = self.payload_hashes.setdefault(self.record['track'], hashlib.sha256())
                    digest.update(view[pos:pos + take])
                retain = 8 if self.record['track'] == 0xDA7E else 7 if self.record['track'] == 1000 else 0
                prefix_take = min(max(0, retain - len(self.prefix)), take)
                if prefix_take:
                    self.prefix.extend(view[pos:pos + prefix_take])
                pos += take
                self.payload_remaining -= take
                if self.payload_remaining == 0:
                    self.state = 'padding'
            elif self.state == 'padding':
                take = min(self.padding_remaining, len(view) - pos)
                pos += take
                self.padding_remaining -= take
                if self.padding_remaining == 0:
                    self.state = 'trailer'
            elif self.state == 'trailer':
                take = min(4 - len(self.trailer), len(view) - pos)
                self.trailer.extend(view[pos:pos + take]); pos += take
                if len(self.trailer) == 4:
                    self._finish_record(now)
            self.max_metadata_bytes = max(self.max_metadata_bytes, len(self.header) + len(self.prefix) + len(self.trailer))

    def summary(self):
        rows = []
        for track, t in sorted(self.tracks.items()):
            obs = t['observations']
            gaps = [b[0] - a[0] for a, b in zip(obs, obs[1:])]
            deltas = [(b[1] / b[2] - a[1] / a[2]) for a, b in zip(obs, obs[1:])]
            span = obs[-1][1] / obs[-1][2] - obs[0][1] / obs[0][2] if len(obs) > 1 else 0
            wall = obs[-1][0] - obs[0][0] if len(obs) > 1 else 0
            rows.append({'trackId': track, 'kind': MEDIA_TRACKS.get(track, 'ClockSync' if track == 0xDA7E else 'Partition' if track == 9 else 'Other'),
                         'records': t['records'], 'payloadBytesSkipped': t['bytes'], 'completeFrames': len(obs),
                         'sequenceErrors': t['sequenceErrors'], 'keyframes': t['keyframes'],
                         'clockRates': sorted(t['rates']), 'formatCodes': [format(x, '04x') for x in sorted(t['formats'])],
                         'packetPositions': t['positions'], 'zeroDts': t['zeroDts'],
                         'backwardDts': t['backwardDts'], 'clockJumpsOverFiveSeconds': t['clockJumpsOverFiveSeconds'],
                         'clockRateChanges': t['clockRateChanges'], 'dtsSpanSeconds': span, 'wallSpanSeconds': wall,
                         'framesPerWallSecond': (len(obs) - 1) / wall if wall else None,
                         'firstDts': obs[0][1] if obs else None, 'lastDts': obs[-1][1] if obs else None,
                         'maxArrivalGapMs': max(gaps, default=0) * 1000,
                         'minDtsDeltaMs': min(deltas, default=0) * 1000,
                         'maxDtsDeltaMs': max(deltas, default=0) * 1000,
                         'invalidAdts': t['invalidAdts'], 'adtsPacketClockRateDifferences': t['adtsClockMismatches'],
                         'partialAdtsPayloads': t['partialAdtsPayloads'],
                         'encodedPayloadSha256': self.payload_hashes[track].hexdigest()
                         if track in self.payload_hashes else None,
                         'adtsConfigurations': [{'objectType': a, 'sampleRate': b, 'channels': c, 'rawDataBlocks': d}
                                                for a, b, c, d in sorted(t['adtsConfigurations'])],
                         'tenSecondWindows': [{'start': i, 'frames': sum(i <= x[0] < i + 10 for x in obs)}
                                              for i in range(0, int(self.last_received_at - self.started_at) + 1 if self.started_at else 0, 10)]})
        sync_offsets = [c['utcSeconds'] - c['dts'] / c['rate'] for c in self.clocks if c['rate']]
        media = [t for t in rows if t['kind'] in MEDIA_TRACKS.values()]
        return {'ok': bool(media) and all(not t['sequenceErrors'] and not t['zeroDts']
                                        and not t['backwardDts'] and not t['clockJumpsOverFiveSeconds']
                                        and not t['invalidAdts'] for t in media),
                'records': self.records, 'tracks': rows, 'partitionHeaders': self.partition_headers,
                'clockSyncRecords': len(self.clocks), 'clockSyncUtcMinusDtsSpreadMs':
                (max(sync_offsets) - min(sync_offsets)) * 1000 if sync_offsets else None,
                'clockSyncMetadata': self.clocks, 'unknownTrackIds': sorted(self.unknown_tracks),
                'incompleteFinalRecord': bool(self.header or self.record),
                'totalBytesReceived': self.bytes_received, 'maxMediaHeaderBytesRetained': self.max_metadata_bytes,
                'mediaSaved': False, 'mediaDecoded': False}

    result = summary

    @property
    def counts(self):
        return {str(track): item['records'] for track, item in self.tracks.items()}

    @property
    def max_metadata_buffer(self):
        return self.max_metadata_bytes

    @property
    def incomplete(self):
        return bool(self.header or self.record)


def _local_endpoint(url):
    import urllib.parse
    from .safety import need
    need(isinstance(url, str) and not any(c in url for c in '\r\n\0'), 'ubv_endpoint_invalid')
    endpoint = urllib.parse.urlsplit(url)
    try:
        port = endpoint.port or 7443
    except ValueError:
        from .safety import OperationError
        raise OperationError('ubv_endpoint_invalid') from None
    need(endpoint.scheme == 'wss' and endpoint.hostname == '127.0.0.1' and endpoint.username is None
         and endpoint.password is None and not endpoint.fragment and endpoint.path.startswith('/')
         and port in (7443, 7444, 7447), 'ubv_endpoint_invalid')
    return endpoint, port


def _control(opcode, payload):
    import os
    from .safety import need
    need(len(payload) <= 125, 'ubv_ws_control_limit')
    mask = os.urandom(4)
    return bytes((128 | opcode, 128 | len(payload))) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def probe_ubv(config, camera, channel, *, seconds=8, api=None, connector=None, clock=None):
    """Read one native UBV stream; retain only bounded numeric metadata.

    Neither the signed URL nor media bytes can enter the returned report.
    A bounded deadline terminating a partial final record is normal.
    """
    import base64
    import os
    import socket
    import ssl
    import time
    import urllib.parse
    from .http import protect_json
    from .safety import OperationError, error_code, need
    from .protect import qualities
    need(type(channel) is int and channel in (0, 1, 2), 'ubv_channel_invalid')
    need(type(seconds) is int and 3 <= seconds <= 12, 'ubv_probe_duration_invalid')
    need(camera.get('id') in {b['cameraId'] for b in config['bridges']}, 'ubv_camera_out_of_scope')
    enabled = {c.get('id') for c in camera.get('channels', []) if c.get('enabled') is True}
    need(channel in enabled, 'ubv_channel_not_enabled')
    api = api or protect_json; clock = clock or time.monotonic
    parser = UbvMetadataParser(); connection = None; failure = None
    frames = binary_bytes = 0; started = None
    try:
        params = urllib.parse.urlencode({'camera': camera['id'], 'channel': channel, 'lens': 0, 'type': 'ubv',
            'allowPartialGOP': 'false', 'fragmentDurationMillis': 500, 'chunkSize': 1024,
            'progressive': 'false', 'extendedVideoMetadata': 'false', 'useWallClock': 'false'})
        metadata = api(config, '/api/ws/livestream?' + params, timeout=5, limit=65536)
        endpoint, port = _local_endpoint(metadata.get('url'))
        setup_deadline = clock() + 8
        if connector:
            connection = connector(port, 5)
        elif remote_settings(config) is not None:
            # TLS terminates on this host, over binary SSH stdio to UDM loopback.
            connection = remote_open_socket(config, port, 5, tls=True)
        else:
            raw = socket.create_connection(('127.0.0.1', port), timeout=5)
            try:
                raw.settimeout(max(0.01, setup_deadline - clock()))
                connection = ssl._create_unverified_context().wrap_socket(raw, server_hostname='127.0.0.1')
            except Exception:
                raw.close(); raise
        key = base64.b64encode(os.urandom(16)).decode('ascii')
        path = endpoint.path + ('?' + endpoint.query if endpoint.query else '')
        upgrade = ('GET ' + path + ' HTTP/1.1\r\nHost: 127.0.0.1:' + str(port)
            + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + key
            + '\r\nX-UserId: ' + config['protectUserId'] + '\r\nX-UserRole: owner\r\nX-UserPermissionMask: 64'
            + '\r\nX-UserPermissions: 65535\r\n\r\n')
        connection.settimeout(max(0.01, setup_deadline - clock())); connection.sendall(upgrade.encode('ascii'))
        buffered = bytearray()
        while b'\r\n\r\n' not in buffered:
            need(clock() < setup_deadline, 'ubv_upgrade_timeout')
            connection.settimeout(min(1, max(0.01, setup_deadline - clock())))
            try: part = connection.recv(4096)
            except socket.timeout: continue
            need(bool(part), 'ubv_connection_closed'); buffered.extend(part)
            need(len(buffered) <= 16384, 'ubv_upgrade_header_limit')
        header, remainder = bytes(buffered).split(b'\r\n\r\n', 1)
        lines = header.decode('ascii').split('\r\n'); need(lines[0].startswith('HTTP/1.1 101 '), 'ubv_upgrade_rejected')
        headers = {}
        for line in lines[1:]:
            need(':' in line, 'ubv_upgrade_invalid')
            name, value = line.split(':', 1); name = name.lower()
            need(name not in headers, 'ubv_upgrade_duplicate_header'); headers[name] = value.strip()
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        need(headers.get('sec-websocket-accept') == accept and headers.get('upgrade', '').lower() == 'websocket'
             and 'upgrade' in {v.strip().lower() for v in headers.get('connection', '').split(',')}, 'ubv_upgrade_invalid')
        buffered = bytearray(remainder); started = clock(); deadline = started + seconds
        def read(count):
            need(count <= 65536, 'ubv_read_buffer_limit')
            while len(buffered) < count:
                if clock() >= deadline: raise TimeoutError()
                connection.settimeout(min(1, max(0.01, deadline - clock())))
                try: part = connection.recv(min(65536, count - len(buffered)))
                except socket.timeout: continue
                need(bool(part), 'ubv_connection_closed'); buffered.extend(part)
            value = bytes(buffered[:count]); del buffered[:count]; return value
        fragmented = None
        while clock() < deadline:
            first, second = read(2); fin, opcode = bool(first & 128), first & 15
            need(not first & 112 and not second & 128, 'ubv_ws_framing_invalid')
            length = second & 127
            if length == 126: length = struct.unpack('!H', read(2))[0]
            elif length == 127: length = struct.unpack('!Q', read(8))[0]
            need(length <= 16 * 1024 * 1024 and frames < 10000, 'ubv_ws_frame_limit'); frames += 1
            if opcode >= 8:
                need(fin and length <= 125 and opcode in (8, 9, 10), 'ubv_ws_control_invalid')
                control = read(length)
                if opcode == 8: raise OperationError('ubv_closed_before_deadline')
                if opcode == 9: connection.sendall(_control(10, control))
                continue
            if opcode == 0:
                need(fragmented is not None, 'ubv_ws_continuation_invalid'); data_opcode = fragmented
                if fin: fragmented = None
            else:
                need(opcode in (1, 2) and fragmented is None, 'ubv_ws_opcode_invalid'); data_opcode = opcode
                if not fin: fragmented = opcode
            while length:
                chunk = read(min(length, 65536)); length -= len(chunk)
                if data_opcode == 2:
                    binary_bytes += len(chunk); need(binary_bytes <= 64 * 1024 * 1024, 'ubv_total_byte_limit')
                    parser.feed(chunk, clock())
    except TimeoutError:
        if started is None: failure = 'ubv_setup_timeout'
    except UbvMetadataError as error:
        failure = str(error)  # Parser errors are a closed vocabulary.
    except Exception as error:
        failure = error_code(error, 'ubv_transport_failed')
    finally:
        if connection is not None:
            try: connection.settimeout(0.1); connection.sendall(_control(8, struct.pack('!H', 1000)))
            except Exception: pass
            connection.close()
    summary = parser.summary()
    tracks = [{key: row[key] for key in ('kind','completeFrames','keyframes','sequenceErrors','clockRates',
        'formatCodes','zeroDts','backwardDts','clockJumpsOverFiveSeconds','clockRateChanges','dtsSpanSeconds',
        'wallSpanSeconds','maxArrivalGapMs','minDtsDeltaMs','maxDtsDeltaMs','invalidAdts',
        'partialAdtsPayloads','adtsConfigurations')} for row in summary['tracks'] if row['kind'] in MEDIA_TRACKS.values()]
    ended=clock()
    for raw,row in zip([t for t in summary['tracks']if t['kind']in MEDIA_TRACKS.values()],tracks):
        observations=parser.tracks[raw['trackId']]['observations']
        row['lastCompleteFrameAgeMs']=(ended-parser.started_at-observations[-1][0])*1000 if observations else None
    video = [t for t in tracks if t['kind'] in ('H264','H265','AV1')]; audio = [t for t in tracks if t['kind'] == 'AAC']
    expected_audio = camera.get('thirdPartyCameraInfo', {}).get('enableRtspAudio') is True
    checks = {'transport': failure is None, 'parser': summary['ok'],
        'videoPictures': bool(video) and all(t['completeFrames'] >= 5 and t['dtsSpanSeconds'] >= 2 and t['keyframes'] >= 1
            and t['wallSpanSeconds']>=2 and t['lastCompleteFrameAgeMs']is not None and t['lastCompleteFrameAgeMs']<=3000 for t in video),
        'audioPictures': not expected_audio or bool(audio) and all(t['completeFrames'] >= 10 and t['dtsSpanSeconds'] >= 2
            and t['wallSpanSeconds']>=2 and t['lastCompleteFrameAgeMs']is not None and t['lastCompleteFrameAgeMs']<=3000 for t in audio),
        'aacCompatibility': not expected_audio or bool(audio) and all(t['clockRates'] == [16000]
            and t['formatCodes'] == ['fd06'] and t['adtsConfigurations']
            and all(a['sampleRate'] == 16000 and a['channels'] == 1 for a in t['adtsConfigurations']) for t in audio),
        'continuousMediaTimes': all(t['sequenceErrors'] == t['zeroDts'] == t['backwardDts'] == t['clockJumpsOverFiveSeconds'] == t['clockRateChanges'] == t['invalidAdts'] == 0 for t in tracks)}
    return {'ok': all(checks.values()), 'channel': channel, 'requestedSeconds': seconds, 'checks': checks,
            'errorCode': failure, 'tracks': tracks, 'websocketFrames': frames, 'binaryBytesDiscarded': binary_bytes,
            'maxHeaderBytesRetained': summary['maxMediaHeaderBytesRetained'],
            'mediaSaved': False, 'mediaDecoded': False, 'handsetPlaybackVerified': False}
