"""Bounded native fMP4 startup clock probes; encoded payloads are discarded.

The ISO-BMFF/progressive framing parser is derived from the reviewed local
protect_fmp4_timing_probe. No camera media, signed URI or play payload is returned.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import socket
import struct
import time
import urllib.parse
from .http import protect_json
from .safety import OperationError, error_code, need

class ProbeError(Exception):
    pass


def u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ProbeError("invalid_bmff_metadata")
    return struct.unpack_from("!I", data, offset)[0]


def u64(data, offset):
    if offset < 0 or offset + 8 > len(data):
        raise ProbeError("invalid_bmff_metadata")
    return struct.unpack_from("!Q", data, offset)[0]


def boxes(data):
    """Child-box views into bounded metadata; never called on mdat."""
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ProbeError("invalid_bmff_metadata")
        size = u32(data, offset)
        kind = bytes(data[offset + 4:offset + 8])
        header = 8
        if size == 1:
            size, header = u64(data, offset + 8), 16
        elif size == 0:
            size = len(data) - offset
        if size < header or offset + size > len(data):
            raise ProbeError("invalid_bmff_metadata")
        yield kind, memoryview(data)[offset + header:offset + size]
        offset += size


def movie_metadata(payload):
    tracks, defaults = {}, {}
    for kind, body in boxes(payload):
        if kind == b"trak":
            track_id, scale, handler = None, None, None
            for child, value in boxes(body):
                if child == b"tkhd":
                    if not value or value[0] not in (0, 1):
                        raise ProbeError("unsupported_tkhd")
                    track_id = u32(value, 20 if value[0] == 1 else 12)
                elif child == b"mdia":
                    for media, md in boxes(value):
                        if media == b"mdhd":
                            if not md or md[0] not in (0, 1):
                                raise ProbeError("unsupported_mdhd")
                            scale = u32(md, 20 if md[0] == 1 else 12)
                        elif media == b"hdlr":
                            if len(md) < 12:
                                raise ProbeError("invalid_bmff_metadata")
                            handler = bytes(md[8:12])
            if track_id is not None and scale and handler in (b"vide", b"soun"):
                if len(tracks) >= 16 or track_id in tracks:
                    raise ProbeError("invalid_track_table")
                tracks[track_id] = {"timescale": scale, "video": handler == b"vide"}
        elif kind == b"mvex":
            for child, value in boxes(body):
                if child == b"trex":
                    if len(value) < 24:
                        raise ProbeError("invalid_bmff_metadata")
                    defaults[u32(value, 4)] = {"duration": u32(value, 12), "size": u32(value, 16)}
    if not any(track["video"] for track in tracks.values()):
        raise ProbeError("missing_video_init")
    return tracks, defaults


def fragment_metadata(payload, defaults):
    fragments = []
    seen_tracks = set(); total_samples = 0
    for kind, body in boxes(payload):
        if kind != b"traf":
            continue
        children = list(boxes(body))
        tfhd = next((value for child, value in children if child == b"tfhd"), None)
        tfdt = next((value for child, value in children if child == b"tfdt"), None)
        if tfhd is None or len(tfhd) < 8 or tfdt is None or len(tfdt) < 8:
            raise ProbeError("missing_fragment_clock")
        flags, track_id = u32(tfhd, 0) & 0xFFFFFF, u32(tfhd, 4)
        if track_id in seen_tracks or len(seen_tracks) >= 16:
            raise ProbeError('fragment_track_limit')
        seen_tracks.add(track_id)
        if tfhd[0] != 0 or flags & ~0x03003B:
            raise ProbeError("unsupported_tfhd")
        default = defaults.get(track_id, {})
        default_duration, default_size = default.get("duration", 0), default.get("size", 0)
        offset = 8
        if flags & 1:
            u64(tfhd, offset)
            offset += 8
        if flags & 2:
            u32(tfhd, offset)
            offset += 4
        if flags & 8:
            default_duration = u32(tfhd, offset)
            offset += 4
        if flags & 16:
            default_size = u32(tfhd, offset)
            offset += 4
        if flags & 32:
            u32(tfhd, offset)
            offset += 4
        if offset != len(tfhd):
            raise ProbeError("invalid_tfhd_length")
        if tfdt[0] == 0:
            decode_start = u32(tfdt, 4)
        elif tfdt[0] == 1:
            decode_start = u64(tfdt, 4)
        else:
            raise ProbeError("unsupported_tfdt")
        total_duration, sample_bytes, samples = 0, 0, 0
        presentation_first, presentation_min, presentation_end = None, None, None
        for child, value in children:
            if child != b"trun":
                continue
            if len(value) < 8 or value[0] not in (0, 1):
                raise ProbeError("invalid_trun")
            run_flags, count = u32(value, 0) & 0xFFFFFF, u32(value, 4)
            if run_flags & ~0xF05:
                raise ProbeError("unsupported_trun_flags")
            if count > 4096 or samples + count > 4096 or total_samples + samples + count > 8192:
                raise ProbeError("sample_count_limit")
            offset = 8
            if run_flags & 1:
                u32(value, offset)  # Signed data offset, deliberately not followed.
                offset += 4
            if run_flags & 4:
                u32(value, offset)
                offset += 4
            for _ in range(count):
                duration = u32(value, offset) if run_flags & 0x100 else default_duration
                if run_flags & 0x100:
                    offset += 4
                size = u32(value, offset) if run_flags & 0x200 else default_size
                if run_flags & 0x200:
                    offset += 4
                if run_flags & 0x400:
                    u32(value, offset)
                    offset += 4
                composition = 0
                if run_flags & 0x800:
                    composition = u32(value, offset)
                    if value[0] == 1 and composition >= 0x80000000:
                        composition -= 0x100000000
                    offset += 4
                if duration <= 0:
                    raise ProbeError("missing_sample_duration")
                if size <= 0:
                    raise ProbeError('missing_sample_size')
                presentation = decode_start + total_duration + composition
                if presentation_first is None:
                    presentation_first = presentation
                presentation_min = presentation if presentation_min is None else min(presentation_min, presentation)
                presentation_end = presentation + duration if presentation_end is None else max(presentation_end, presentation + duration)
                total_duration += duration
                sample_bytes += size
                samples += 1
            if offset != len(value):
                raise ProbeError("invalid_trun_length")
        if samples:
            total_samples += samples
            fragments.append({"trackId": track_id, "decodeStart": decode_start,
                              "decodeEnd": decode_start + total_duration,
                              "duration": total_duration, "samples": samples, "declaredSampleBytes": sample_bytes,
                              "presentationFirst": presentation_first, "presentationMin": presentation_min,
                              "presentationEnd": presentation_end})
    return fragments


class BoxStream:
    MAX_METADATA = 1024 * 1024
    MAX_BOX = 64 * 1024 * 1024
    ALLOWED = {b"ftyp", b"styp", b"moov", b"moof", b"mdat", b"free", b"skip", b"sidx", b"emsg", b"prft", b"uuid", b"mfra", b"mfro"}

    def __init__(self, on_box):
        self.on_box = on_box
        self.header = bytearray()
        self.body = bytearray()
        self.kind, self.remaining = None, 0
        self.counts = {}
        self.mdat_bytes = 0
        self.max_metadata_buffer = 0
        self.started_at = None
        self.body_size = 0

    def feed(self, data, now):
        view, position = memoryview(data), 0
        while position < len(view):
            if self.kind is None:
                needed = 8 if len(self.header) < 8 else (16 if u32(self.header, 0) == 1 else 8)
                take = min(needed - len(self.header), len(view) - position)
                self.header.extend(view[position:position + take])
                position += take
                if len(self.header) < needed:
                    break
                size, kind, header_size = u32(self.header, 0), bytes(self.header[4:8]), 8
                if size == 1:
                    if len(self.header) < 16:
                        continue
                    size, header_size = u64(self.header, 8), 16
                if kind not in self.ALLOWED or size == 0 or size < header_size or size > self.MAX_BOX:
                    raise ProbeError("unsupported_fmp4_framing")
                if kind in (b"moov", b"moof") and size - header_size > self.MAX_METADATA:
                    raise ProbeError("metadata_box_limit")
                self.kind, self.remaining = kind, size - header_size
                self.body_size = self.remaining
                self.started_at = now
                self.header.clear()
                self.counts[kind.decode("ascii")] = self.counts.get(kind.decode("ascii"), 0) + 1
                if self.remaining == 0:
                    self._finish(now)
                    continue
            take = min(self.remaining, len(view) - position)
            if self.kind in (b"moov", b"moof"):
                self.body.extend(view[position:position + take])
                self.max_metadata_buffer = max(self.max_metadata_buffer, len(self.body))
            elif self.kind == b"mdat":
                self.mdat_bytes += take
            self.remaining -= take
            position += take
            if self.remaining == 0:
                self._finish(now)

    def _finish(self, now):
        kind, started = self.kind, self.started_at
        payload = bytes(self.body) if self.body else b""
        self.body.clear()
        self.kind, self.started_at = None, None
        self.on_box(kind, payload, now, now - started, self.body_size if kind == b'mdat' else None)

    @property
    def incomplete(self):
        return bool(self.header or self.kind is not None)


class ProtectFrameStream:
    """Protect's documented SDK framing: type u8, length u24 BE, then bytes.

    The SDK concatenates separate moof, mdat, video and audio collections at end
    of segment. Arrival can differ from concatenation order. Here only moof and
    the mdat header are retained; video/audio/mdat payloads become byte counters.
    Reference: hjdhjd/unifi-protect src/transport/livestream-session.ts.
    """
    NAMES = {247: "timestamp", 248: "codecInformation", 249: "beginSegment",
             250: "initSegment", 251: "moof", 252: "video", 253: "audio",
             254: "mdat", 255: "endSegment"}

    def __init__(self, box_stream):
        self.box_stream = box_stream
        self.header = bytearray()
        self.kind, self.remaining = None, 0
        self.counts = {}
        self.skipped_control_bytes = 0
        self.completed_segments = 0
        self.open_segment = False
        self.moof = bytearray()
        self.mdat_header = bytearray()
        self.mdat_header_size = None
        self.mdat_declared_body = None
        self.mdat_type_body_bytes = 0
        self.video_bytes, self.audio_bytes = 0, 0
        self.segment_started, self.moof_completed = None, None
        self.max_segment_transfer_ms = 0
        self.max_video_bytes, self.max_audio_bytes, self.max_mdat_body_bytes = 0, 0, 0

    def _begin(self, now):
        if self.open_segment or self.box_stream.incomplete:
            raise ProbeError("incomplete_fmp4_segment")
        self.open_segment = True
        self.moof.clear()
        self.mdat_header.clear()
        self.mdat_header_size, self.mdat_declared_body = None, None
        self.mdat_type_body_bytes, self.video_bytes, self.audio_bytes = 0, 0, 0
        self.segment_started, self.moof_completed = now, None

    def _mdat(self, data):
        view, position = memoryview(data), 0
        while position < len(view) and self.mdat_declared_body is None:
            needed = 8 if len(self.mdat_header) < 8 else (16 if u32(self.mdat_header, 0) == 1 else 8)
            take = min(needed - len(self.mdat_header), len(view) - position)
            self.mdat_header.extend(view[position:position + take])
            position += take
            if len(self.mdat_header) < needed:
                return
            size = u32(self.mdat_header, 0)
            header_size = 8
            if size == 1:
                if len(self.mdat_header) < 16:
                    continue
                size, header_size = u64(self.mdat_header, 8), 16
            if bytes(self.mdat_header[4:8]) != b"mdat" or size == 0 or size < header_size or size > BoxStream.MAX_BOX:
                raise ProbeError("unsupported_mdat_header")
            self.mdat_header_size, self.mdat_declared_body = header_size, size - header_size
        self.mdat_type_body_bytes += len(view) - position
        if self.mdat_type_body_bytes > BoxStream.MAX_BOX:
            raise ProbeError("mdat_payload_count_limit")

    def _end(self, now):
        if not self.open_segment or self.box_stream.incomplete:
            raise ProbeError("incomplete_fmp4_segment")
        if not self.moof or self.mdat_declared_body is None:
            raise ProbeError("missing_segment_metadata")
        received_body = self.mdat_type_body_bytes + self.video_bytes + self.audio_bytes
        if received_body != self.mdat_declared_body:
            raise ProbeError("mdat_payload_count_mismatch")
        metadata = bytes(self.moof)
        self.moof.clear()
        children = list(boxes(metadata))
        if len(children) != 1 or children[0][0] != b"moof":
            raise ProbeError("unsupported_segment_moof_shape")
        # These are bounded metadata views. No media bytes are reconstituted.
        self.box_stream.max_metadata_buffer = max(self.box_stream.max_metadata_buffer, len(metadata))
        self.box_stream.counts["moof"] = self.box_stream.counts.get("moof", 0) + 1
        self.box_stream.counts["mdat"] = self.box_stream.counts.get("mdat", 0) + 1
        self.box_stream.mdat_bytes += received_body
        self.box_stream.on_box(b"moof", children[0][1], self.moof_completed, 0)
        self.box_stream.on_box(b"mdat", b"", now, 0, received_body)
        self.max_segment_transfer_ms = max(self.max_segment_transfer_ms, (now - self.segment_started) * 1000)
        self.max_video_bytes = max(self.max_video_bytes, self.video_bytes)
        self.max_audio_bytes = max(self.max_audio_bytes, self.audio_bytes)
        self.max_mdat_body_bytes = max(self.max_mdat_body_bytes, self.mdat_declared_body)
        self.open_segment = False
        self.completed_segments += 1

    def feed(self, data, now):
        view, position = memoryview(data), 0
        while position < len(view):
            if self.kind is None:
                take = min(4 - len(self.header), len(view) - position)
                self.header.extend(view[position:position + take])
                position += take
                if len(self.header) < 4:
                    break
                kind = self.header[0]
                length = int.from_bytes(self.header[1:4], "big")
                if kind not in self.NAMES:
                    raise ProbeError("unsupported_protect_frame_type")
                if kind in (247, 248, 249, 255) and length > 65536:
                    raise ProbeError("protect_control_frame_limit")
                self.kind, self.remaining = kind, length
                self.header.clear()
                name = self.NAMES[kind]
                self.counts[name] = self.counts.get(name, 0) + 1
                if kind == 249:
                    self._begin(now)
                if kind in (251, 252, 253, 254) and not self.open_segment:
                    raise ProbeError("media_outside_protect_segment")
                if self.remaining == 0:
                    self._finish(now)
                    continue
            take = min(self.remaining, len(view) - position)
            chunk = view[position:position + take]
            if self.kind == 250:
                if self.open_segment:
                    raise ProbeError("init_inside_media_segment")
                self.box_stream.feed(chunk, now)
            elif self.kind == 251:
                if len(self.moof) + take > BoxStream.MAX_METADATA:
                    raise ProbeError("metadata_box_limit")
                self.moof.extend(chunk)
                self.moof_completed = now
            elif self.kind == 254:
                self._mdat(chunk)
            elif self.kind == 252:
                self.video_bytes += take
                if self.video_bytes > BoxStream.MAX_BOX:
                    raise ProbeError("media_payload_count_limit")
            elif self.kind == 253:
                self.audio_bytes += take
                if self.audio_bytes > BoxStream.MAX_BOX:
                    raise ProbeError("media_payload_count_limit")
            else:
                self.skipped_control_bytes += take
            self.remaining -= take
            position += take
            if self.remaining == 0:
                self._finish(now)

    def _finish(self, now):
        kind, self.kind = self.kind, None
        if kind == 255:
            self._end(now)

    @property
    def incomplete(self):
        return bool(self.header or self.kind is not None or self.open_segment)


def configuration(config):
    """An explicit full-GOP exception must remain tied to inspected nginx bytes."""
    value = config.get('fmp4Startup', {})
    need(isinstance(value, dict) and not set(value) - {'enabled', 'fullGopCameraIds', 'nginxFilePins'},
         'fmp4_configuration_invalid')
    enabled = value.get('enabled', False)
    ids = value.get('fullGopCameraIds', [])
    pins = value.get('nginxFilePins', [])
    scope = {b['cameraId'] for b in config['bridges']}
    need(type(enabled) is bool and isinstance(ids, list)
         and all(isinstance(cid, str) and cid in scope for cid in ids)
         and len(ids) == len(set(ids)), 'fmp4_configuration_invalid')
    # These are the reviewed frontend exceptions, not a general way to suppress
    # a failed browser flag on a different camera.
    need(set(ids) <= {'6ac8ae7001ab6d03e4006410', '6ac83fed00bd6d03e4001b81',
                     '6ac844bf02026d03e4001f5f', '6ac8ae7102b76d03e4006447',
                     '6ac83993001a6d03e4001690', '6ac844bd01096d03e4001f22'}, 'fmp4_configuration_invalid')
    need(isinstance(pins, list) and len(pins) <= 8 and (not ids or bool(pins)), 'fmp4_configuration_invalid')
    seen = set()
    for pin in pins:
        need(isinstance(pin, dict) and set(pin) == {'path', 'sha256'} and isinstance(pin['path'], str)
             and isinstance(pin['sha256'], str) and re.fullmatch('[a-f0-9]{64}', pin['sha256']),
             'fmp4_configuration_invalid')
        path = PurePosixPath(pin['path'])
        need(path.is_absolute() and '..' not in path.parts and str(path) in {
            '/etc/nginx/nginx.conf', '/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf',
            '/ssd1/.data/unifi-core/config/http/upstream-protect_api_backend.conf'}
             and str(path) not in seen, 'fmp4_configuration_invalid')
        seen.add(str(path))
    need(not ids or seen == {'/etc/nginx/nginx.conf',
        '/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf',
        '/ssd1/.data/unifi-core/config/http/upstream-protect_api_backend.conf'}, 'fmp4_configuration_invalid')
    return {'enabled': enabled, 'fullGopCameraIds': ids, 'nginxFilePins': pins}


def verify_configuration(options):
    """Read public nginx files only; never interpret a changed exception as valid."""
    for pin in options['nginxFilePins']:
        path = Path(pin['path'])
        try:
            need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                 and path.stat().st_size <= 8 * 1024 * 1024, 'fmp4_configuration_drift')
            with path.open('rb') as stream:
                data = stream.read(8 * 1024 * 1024 + 1)
            need(len(data) <= 8 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == pin['sha256'],
                 'fmp4_configuration_drift')
        except OperationError:
            raise
        except (OSError, ValueError):
            raise OperationError('fmp4_configuration_drift') from None
    return True


def browser_flags(options, camera_id):
    return {'useWallClock': True, 'allowPartialGOP': camera_id not in options['fullGopCameraIds'],
            'progressive': True, 'extendedVideoMetadata': True, 'rebaseTimestampsToZero': False,
            'fragmentDurationMillis': 100}


class StartupClock:
    """Include the very first fragment; no warmup can hide a startup discontinuity."""
    def __init__(self, started, *, full_gop=False):
        self.started = started
        self.full_gop = full_gop
        self.tracks, self.defaults, self.stats, self.pending = {}, {}, {}, None
        self.payload_fragments = self.payload_bytes = self.sample_bytes = 0
        self.payload_sizes_valid = True

    def on_box(self, kind, payload, now, _read_seconds=0, body_bytes=None):
        if kind == b'moov':
            tracks, defaults = movie_metadata(payload)
            if self.stats and tracks != self.tracks:
                raise ProbeError('fmp4_track_configuration_changed')
            self.tracks, self.defaults = tracks, defaults
        elif kind == b'moof':
            if self.pending is not None:
                raise ProbeError('fmp4_missing_mdat')
            self.pending = fragment_metadata(payload, self.defaults)
        elif kind == b'mdat':
            if self.pending is None:
                raise ProbeError('fmp4_missing_moof')
            declared = sum(fragment['declaredSampleBytes'] for fragment in self.pending)
            if type(body_bytes) is not int or declared <= 0 or body_bytes != declared:
                self.payload_sizes_valid = False
                raise ProbeError('fmp4_sample_payload_size_mismatch')
            self.payload_fragments += 1; self.payload_bytes += body_bytes; self.sample_bytes += declared
            for fragment in self.pending:
                tid = fragment['trackId']; info = self.tracks.get(tid)
                if info is None:
                    raise ProbeError('fmp4_unknown_track')
                scale = info['timescale']
                state = self.stats.setdefault(tid, {'trackId': tid, 'kind': 'video' if info['video'] else 'audio',
                    'timescale': scale, 'fragments': 0, 'samples': 0, 'first': fragment['decodeStart'],
                    'end': fragment['decodeStart'], 'duration': 0, 'firstWall': now, 'lastWall': now,
                    'clockGaps': 0, 'clockOverlaps': 0, 'maximumFragmentDurationSeconds': 0})
                if state['fragments']:
                    delta = fragment['decodeStart'] - state['end']
                    state['clockGaps'] += int(delta > 0)
                    state['clockOverlaps'] += int(delta < 0)
                state['fragments'] += 1; state['samples'] += fragment['samples']
                state['end'] = fragment['decodeEnd']; state['duration'] += fragment['duration']
                state['lastWall'] = now
                state['maximumFragmentDurationSeconds'] = max(state['maximumFragmentDurationSeconds'],fragment['duration']/scale)
            self.pending = None

    def result(self, ended, expected_audio):
        rows = []
        for state in self.stats.values():
            scale = state['timescale']; span = (state['end'] - state['first']) / scale
            rows.append({k: state[k] for k in ('trackId', 'kind', 'timescale', 'fragments', 'samples',
                                               'clockGaps', 'clockOverlaps', 'maximumFragmentDurationSeconds')})
            rows[-1].update(initialClockOrigin='epoch' if state['first'] / scale >= 1_000_000_000 else 'relative',
                firstDecodeSeconds=state['first'] / scale, mediaSpanSeconds=span,
                summedDurationSeconds=state['duration'] / scale,
                observedSpanSeconds=state['lastWall'] - state['firstWall'],
                lastFragmentAgeSeconds=max(0, ended - state['lastWall']),
                freshnessBudgetSeconds=max(3,min(5,state['maximumFragmentDurationSeconds']+1))if self.full_gop else 3)
        video = [s for s in rows if s['kind'] == 'video']; audio = [s for s in rows if s['kind'] == 'audio']
        # A full GOP can delay the first video fragment by four seconds while
        # audio already advances. Compare their overlapping clock windows; this
        # checks startup time axes, not lip sync or sensor capture timestamps.
        start_skew = video[0]['firstDecodeSeconds'] - audio[0]['firstDecodeSeconds'] if video and audio else None
        overlap = min(video[0]['firstDecodeSeconds'] + video[0]['mediaSpanSeconds'],
                      audio[0]['firstDecodeSeconds'] + audio[0]['mediaSpanSeconds']) - max(
                          video[0]['firstDecodeSeconds'], audio[0]['firstDecodeSeconds']) if video and audio else None
        for row in rows:
            row['trackStartSkewSeconds'] = start_skew
            row['trackClockOverlapSeconds'] = overlap
        return rows, {'video': bool(video), 'audio': not expected_audio or bool(audio),
            'samplePayloadSizes': self.payload_sizes_valid and self.payload_fragments > 0,
            'continuousFromFirstFragment': bool(rows) and all(s['fragments'] >= 2 and s['samples'] >= 5
                and s['clockGaps'] == s['clockOverlaps'] == 0 and s['initialClockOrigin'] == 'epoch'
                and 2 <= s['mediaSpanSeconds'] <= 20
                and abs(s['mediaSpanSeconds'] - s['summedDurationSeconds']) <= 1 / s['timescale'] + 1e-6
                for s in rows),
            'freshProgress': bool(rows) and all(s['observedSpanSeconds'] >= 2 and s['lastFragmentAgeSeconds'] <= s['freshnessBudgetSeconds']
                                               for s in rows),
            'overlappingTrackClocks': not expected_audio or bool(video and audio) and
                abs(start_skew) <= 5 and overlap >= 2}


def probe_fmp4(config, camera, channel, *, seconds=12, api=None, connector=None, clock=None):
    """One local EMS session using effective browser flags, never a UI/auth claim."""
    options = configuration(config)
    need(options['enabled'], 'fmp4_probe_not_enabled')
    need(type(seconds) is int and 8 <= seconds <= 12, 'fmp4_duration_invalid')
    need(camera.get('id') in {b['cameraId'] for b in config['bridges']}, 'fmp4_camera_out_of_scope')
    need(type(channel) is int and channel in {c['id'] for c in camera.get('channels', [])
         if c.get('enabled') is True}, 'fmp4_channel_invalid')
    flags = browser_flags(options, camera['id']); clock = clock or time.monotonic; api = api or protect_json
    began = clock(); deadline = began + 8; connection = None; started = None; received = 0
    collector = None; parser = None; first = None; failure = None; returned = None
    try:
        verify_configuration(options)
        query = {'camera': camera['id'], 'channel': channel, 'lens': 0, 'type': 'fmp4', **flags}
        query = {k: str(v).lower() if type(v) is bool else v for k, v in query.items()}
        metadata = api(config, '/api/tcp/livestream?' + urllib.parse.urlencode(query), timeout=5, limit=65536)
        endpoint = urllib.parse.urlsplit(metadata.get('uri', ''))
        need(endpoint.scheme == 'tcp' and endpoint.hostname in ('127.0.0.1', 'localhost')
             and not endpoint.username and not endpoint.password and not endpoint.fragment
             and type(endpoint.port) is int and 1024 <= endpoint.port <= 65535, 'fmp4_endpoint_invalid')
        leading = metadata.get('data', {})
        need(isinstance(leading, dict) and leading.get('type') == 'Buffer'
             and isinstance(leading.get('data'), list) and len(leading['data']) <= 65536
             and all(type(n) is int and 0 <= n <= 255 for n in leading['data']), 'fmp4_play_payload_invalid')
        leading = bytes(leading['data'])
        need(4 < len(leading) <= 65536 and int.from_bytes(leading[:4], 'big') == len(leading) - 4,
             'fmp4_play_payload_invalid')
        command = json.loads(leading[4:]); params = command.get('params', {})
        need(command.get('cmd') == 'play' and isinstance(params, dict), 'fmp4_play_payload_invalid')
        returned = {k: params.get(k) for k in flags}
        need(params.get('type') == 'fmp4' and params.get('channel') == channel and returned == flags,
             'fmp4_effective_flags_mismatch')
        remaining = max(0.01, deadline - clock())
        connection = connector(endpoint.port, remaining) if connector else socket.create_connection(
            ('127.0.0.1', endpoint.port), timeout=remaining)
        need(clock() < deadline, 'fmp4_setup_timeout')
        connection.settimeout(max(0.01, deadline - clock())); connection.sendall(leading)
        started = clock(); deadline = started + seconds; collector = StartupClock(started,full_gop=flags['allowPartialGOP']is False)
        parser = BoxStream(collector.on_box); framed = ProtectFrameStream(parser)
        prelude = bytearray(); wire = None
        while clock() < deadline:
            connection.settimeout(min(1, max(0.01, deadline - clock())))
            try: chunk = connection.recv(65536)
            except socket.timeout: continue
            need(bool(chunk), 'fmp4_connection_closed')
            now = clock(); first = now if first is None else first; received += len(chunk)
            need(received <= 64 * 1024 * 1024, 'fmp4_byte_limit')
            if wire is None:
                prelude.extend(chunk)
                if len(prelude) < 8: continue
                wire = framed if prelude[0] in framed.NAMES else parser
                chunk = bytes(prelude); prelude.clear()
            wire.feed(chunk, now)
        verify_configuration(options)
    except ProbeError as error:
        failure = str(error)  # Parser errors have a fixed vocabulary.
    except Exception as error:
        failure = error_code(error, 'fmp4_transport_failed')
    finally:
        if connection is not None: connection.close()
    ended = clock()
    tracks, checks = collector.result(ended, camera.get('thirdPartyCameraInfo', {}).get('enableRtspAudio') is True) \
        if collector else ([], {'video': False, 'audio': False, 'samplePayloadSizes': False, 'continuousFromFirstFragment': False,
                              'freshProgress': False, 'overlappingTrackClocks': False})
    checks['transport'] = failure is None
    checks['effectiveFlags'] = returned == flags
    return {'ok': all(checks.values()), 'channel': channel, 'requestedSeconds': seconds,
        'checks': checks, 'errorCode': failure, 'tracks': tracks, 'effectiveBrowserFlags': flags,
        'nativePlayFlags': returned, 'firstByteSeconds': first - started if first is not None else None,
        'receivedBytesDiscardedOrMetadataParsed': received,
        'payloadByteCounts': {'completeMdats': collector.payload_fragments, 'actualMdatBytes': collector.payload_bytes,
            'declaredSampleBytes': collector.sample_bytes, 'paddingAllowed': False} if collector else None,
        'maxMetadataBufferBytes': parser.max_metadata_buffer if parser else 0,
        'method': 'native_tcp_effective_browser_flags', 'frontdoorAuthenticationVerified': False,
        'mediaSaved': False, 'mediaDecoded': False, 'handsetPlaybackVerified': False}
