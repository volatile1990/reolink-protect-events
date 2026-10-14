"""Bounded loopback RTSP authentication proxy and categorical decoder parsers.

Self-contained adaptation of the previously audited proxy. Private upstream
credentials stay in memory and never appear in the local decoder URI or argv.
"""
import asyncio
import base64
import collections
import ipaddress
import math
from pathlib import Path
import re
import time
import urllib.parse

class ProbeError(Exception):
    """Only fixed, non-sensitive error codes may be supplied."""


class ProxyIoError(Exception):
    """Internal I/O origin plus original exception; never output raw details."""
    def __init__(self, origin, error):
        super().__init__(origin)
        self.origin, self.error = origin, error


def settings(value):
    if not isinstance(value, dict):
        raise ProbeError("invalid_input")
    url, user, password, executable = (value.get(key) for key in
        ("url", "username", "password", "ffmpegPath"))
    if not all(isinstance(item, str) and item and len(item) <= 8192
               and not any(character in item for character in "\r\n\x00")
               for item in (url, user, password, executable)) or ":" in user:
        raise ProbeError("invalid_input")
    try:
        endpoint = urllib.parse.urlsplit(url)
        ipaddress.IPv4Address(endpoint.hostname)
        port = 554 if endpoint.port is None else endpoint.port
        duration = float(value.get("duration", 5))
        if (endpoint.scheme != "rtsp" or endpoint.username is not None
                or endpoint.fragment or not endpoint.path.startswith("/")
                or not 1 <= port <= 65535 or not math.isfinite(duration)
                or not 3 <= duration <= 5):
            raise ValueError()
        path = Path(executable)
        if not path.is_absolute() or path.name.lower() not in ("ffmpeg.exe", "ffmpeg") or not path.is_file():
            raise ValueError()
    except (ValueError, TypeError, OSError):
        raise ProbeError("invalid_input") from None
    return endpoint, port, user, password, str(path), duration


class Route:
    """Exact endpoint/path mapping; no foreign redirect or credential URI."""
    def __init__(self, endpoint, upstream_port, local_port):
        self.endpoint, self.upstream_port, self.local_port = endpoint, upstream_port, local_port
        self.upstream_path = endpoint.path.rstrip("/") or "/"
        self.local_path = "/probe"
        self.local_url = "rtsp://127.0.0.1:" + str(local_port) + self.local_path

    @staticmethod
    def _parse(uri):
        if not isinstance(uri, str) or not uri or any(c in uri for c in "\r\n\x00\t "):
            raise ProbeError("invalid_rtsp_uri")
        try:
            parsed = urllib.parse.urlsplit(uri)
            _ = parsed.port
            if parsed.username is not None or parsed.fragment:
                raise ValueError()
            return parsed
        except ValueError:
            raise ProbeError("invalid_rtsp_uri") from None

    @staticmethod
    def _suffix(path, base):
        if path == base:
            return ""
        if base == "/" and path.startswith("/"):
            return path[1:]
        if path.startswith(base + "/"):
            return path[len(base):]
        raise ProbeError("foreign_rtsp_path")

    def upstream(self, uri):
        if uri == "*":
            return uri
        parsed = self._parse(uri)
        if parsed.scheme and (parsed.scheme, parsed.hostname, parsed.port or 554) != (
                "rtsp", "127.0.0.1", self.local_port):
            raise ProbeError("foreign_client_endpoint")
        suffix = self._suffix(parsed.path, self.local_path)
        path = self.upstream_path + suffix
        query = parsed.query or self.endpoint.query
        return urllib.parse.urlunsplit(("rtsp", self.endpoint.hostname + ":" + str(self.upstream_port), path, query, ""))

    def local(self, uri):
        if uri == "*":
            return uri
        parsed = self._parse(uri)
        if parsed.scheme and (parsed.scheme, parsed.hostname, parsed.port or 554) != (
                "rtsp", self.endpoint.hostname, self.upstream_port):
            raise ProbeError("foreign_upstream_endpoint")
        suffix = self._suffix(parsed.path, self.upstream_path)
        return urllib.parse.urlunsplit(("rtsp", "127.0.0.1:" + str(self.local_port), self.local_path + suffix, parsed.query, ""))


HEADER_LIMIT = 65536
BODY_LIMIT = 262144
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


async def read_message(reader):
    try:
        first = await reader.readexactly(1)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            return None
        raise ProbeError("truncated_rtsp_message") from None
    if first == b"$":
        try:
            header = first + await reader.readexactly(3)
            size = int.from_bytes(header[2:4], "big")
            return ("media", header + await reader.readexactly(size))
        except asyncio.IncompleteReadError:
            raise ProbeError("truncated_interleaved_frame") from None
    try:
        header = first + await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        raise ProbeError("invalid_rtsp_header") from None
    if len(header) > HEADER_LIMIT:
        raise ProbeError("rtsp_header_limit")
    try:
        lines = header[:-4].decode("ascii").split("\r\n")
        if any("\x00" in line for line in lines):
            raise ValueError()
        headers, names = [], set()
        for line in lines[1:]:
            name, val = line.split(":", 1)
            if not HEADER_NAME.fullmatch(name) or "\r" in val or "\n" in val:
                raise ValueError()
            key = name.lower()
            if key in names and key in ("content-length", "cseq"):
                raise ValueError()
            names.add(key)
            headers.append((name, val.strip()))
        length = int(next((val for name, val in headers if name.lower() == "content-length"), "0"))
        if not 0 <= length <= BODY_LIMIT:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ProbeError("invalid_rtsp_header") from None
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise ProbeError("truncated_rtsp_body") from None
    return ("control", lines[0], headers, body)


def encode_message(start, headers, body):
    headers = [(name, val) for name, val in headers if name.lower() != "content-length"]
    if body:
        headers.append(("Content-Length", str(len(body))))
    try:
        return (start + "\r\n" + "\r\n".join(name + ": " + val for name, val in headers)
                + "\r\n\r\n").encode("ascii") + body
    except UnicodeError:
        raise ProbeError("invalid_rtsp_encoding") from None


def rewrite_sdp(body, route):
    try:
        text = body.decode("ascii")
    except UnicodeError:
        raise ProbeError("invalid_sdp_encoding") from None
    output = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if "\r" in line or "\x00" in line:
            raise ProbeError("invalid_sdp_encoding")
        if line.startswith("a=control:"):
            value = line[len("a=control:"):]
            if value.startswith("/") or "://" in value:
                line = "a=control:" + route.local(value)
            elif value != "*" and (not value or any(c in value for c in " \t\r\n\x00") or value.startswith("..")):
                raise ProbeError("invalid_sdp_control")
        elif line.startswith("c=IN IP4 "):
            line = "c=IN IP4 127.0.0.1"
        elif line.startswith("o="):
            fields = line.split()
            if len(fields) == 6 and fields[3:5] == ["IN", "IP4"]:
                fields[5] = "127.0.0.1"
                line = " ".join(fields)
        output.append(line)
    return "\r\n".join(output).encode("ascii")


class RtspProxy:
    def __init__(self, endpoint, upstream_port, user, password, inspect_sdp=None):
        self.endpoint, self.upstream_port = endpoint, upstream_port
        self.authorization = "Basic " + base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        self.inspect_sdp = inspect_sdp
        self.route = None
        self.server = None
        self.connections = 0
        self.tasks = set()
        self.requests, self.responses, self.errors = collections.Counter(), collections.Counter(), collections.Counter()
        self.interleaved_frames, self.interleaved_bytes = 0, 0
        self.teardown_requested = False
        self.normal_closes, self.local_close_candidates = collections.Counter(), collections.Counter()

    def _record_failure(self, error, local_reader=None):
        # Only network closure/truncated media can be an expected end. Protocol
        # validation, timeouts and unexpected upstream failures remain errors.
        origin = error.origin if isinstance(error, ProxyIoError) else "proxy"
        if isinstance(error, ProxyIoError):
            error = error.error
        closure = (isinstance(error, (ConnectionError, OSError))
                   and not isinstance(error, TimeoutError)) or (
            isinstance(error, ProbeError) and str(error) in (
                "truncated_rtsp_message", "truncated_interleaved_frame", "truncated_rtsp_body"))
        suffix = str(error) if isinstance(error, ProbeError) else "connection_failure"
        code = origin + "_" + suffix
        if closure and self.teardown_requested:
            self.normal_closes["tcp_close_after_teardown"] += 1
        elif closure and origin in ("local_read", "local_write"):
            # Finalize only after FFmpeg has really completed the requested
            # decode with exit 0. Windows RST sets a reader exception rather
            # than at_eof(). Upstream failures are never local-exit candidates.
            self.local_close_candidates[code] += 1
        else:
            self.errors[code] += 1

    @staticmethod
    async def _read_io(reader, origin):
        try:
            return await read_message(reader)
        except Exception as error:
            raise ProxyIoError(origin, error) from None

    @staticmethod
    async def _write_io(writer, wire, origin):
        try:
            writer.write(wire)
            await writer.drain()
        except Exception as error:
            raise ProxyIoError(origin, error) from None

    def finish_process(self, completed):
        for code, count in self.local_close_candidates.items():
            if completed:
                self.normal_closes["tcp_close_after_completed_local_exit"] += count
            else:
                self.errors[code] += count
        self.local_close_candidates.clear()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=HEADER_LIMIT)
        port = self.server.sockets[0].getsockname()[1]
        self.route = Route(self.endpoint, self.upstream_port, port)
        return self.route.local_url

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle(self, local_reader, local_writer):
        current = asyncio.current_task()
        self.tasks.add(current)
        upstream_writer, pumps = None, []
        try:
            # One FFmpeg viewer and no authentication retry/reconnect loop.
            if self.connections:
                return
            self.connections += 1
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(
                self.endpoint.hostname, self.upstream_port, limit=HEADER_LIMIT), timeout=5)
            pumps = [asyncio.create_task(self._client(local_reader, upstream_writer)),
                     asyncio.create_task(self._upstream(upstream_reader, local_writer))]
            done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            results = await asyncio.gather(*done, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    self._record_failure(result, local_reader)
                elif result == "upstream_eof" and not self.teardown_requested and not local_reader.at_eof():
                    self.errors["unexpected_upstream_eof"] += 1
        except asyncio.CancelledError:
            pass
        except ProbeError as error:
            self._record_failure(error, local_reader)
        except Exception as error:
            self._record_failure(error, local_reader)
        finally:
            for task in pumps:
                if not task.done():
                    task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            for writer in (upstream_writer, local_writer):
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=1)
                    except (OSError, asyncio.TimeoutError):
                        pass
            self.tasks.discard(current)

    async def _client(self, reader, writer):
        methods = {"OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER"}
        while (message := await self._read_io(reader, "local_read")) is not None:
            if message[0] == "media":
                wire = message[1]
            else:
                try:
                    method, target, version = message[1].split(" ")
                except ValueError:
                    raise ProbeError("invalid_rtsp_request") from None
                if method not in methods or version != "RTSP/1.0":
                    raise ProbeError("unsupported_rtsp_method")
                self.requests[method] += 1
                headers = [(name, val) for name, val in message[2]
                           if name.lower() not in ("authorization", "proxy-authorization")]
                transport = next((val for name, val in headers if name.lower() == "transport"), "")
                if method == "SETUP" and "RTP/AVP/TCP" not in transport.upper():
                    raise ProbeError("unsupported_rtsp_transport")
                headers.append(("Authorization", self.authorization))
                wire = encode_message(method + " " + self.route.upstream(target) + " RTSP/1.0", headers, message[3])
                if method == "TEARDOWN":
                    self.teardown_requested = True
            await self._write_io(writer, wire, "upstream_write")
        return "local_eof"

    async def _upstream(self, reader, writer):
        while (message := await self._read_io(reader, "upstream_read")) is not None:
            if message[0] == "media":
                wire = message[1]
                self.interleaved_frames += 1
                self.interleaved_bytes += len(wire) - 4
            else:
                try:
                    version, status, _ = message[1].split(" ", 2)
                    status = int(status)
                    if version != "RTSP/1.0" or not 100 <= status <= 599:
                        raise ValueError()
                except ValueError:
                    raise ProbeError("invalid_rtsp_response") from None
                self.responses[str(status)] += 1
                headers = []
                for name, val in message[2]:
                    if name.lower() in ("content-base", "content-location", "location"):
                        val = self.route.local(val)
                    elif name.lower() == "rtp-info":
                        val = re.sub(r"(?i)\burl=([^;\s,]+)", lambda match: "url=" + self.route.local(match.group(1)), val)
                    headers.append((name, val))
                content_type = next((val for name, val in headers if name.lower() == "content-type"), "")
                if "application/sdp" in content_type.lower() and self.inspect_sdp is not None:
                    self.inspect_sdp(message[3])
                body = rewrite_sdp(message[3], self.route) if "application/sdp" in content_type.lower() else message[3]
                wire = encode_message(message[1], headers, body)
            await self._write_io(writer, wire, "local_write")
        return "upstream_eof"

    def result(self):
        return {"connections": self.connections, "requests": dict(self.requests),
                "responses": dict(self.responses), "errors": dict(self.errors),
                "normalCloses": dict(self.normal_closes), "teardownRequested": self.teardown_requested,
                "interleavedFramesPassed": self.interleaved_frames,
                "interleavedBytesPassed": self.interleaved_bytes}


class BoundedLines:
    """No unlimited readlines, no retained raw log records."""
    def __init__(self, on_line):
        self.on_line, self.buffer, self.discarding = on_line, bytearray(), False
        self.overlong = 0

    def feed(self, data):
        for part in data.splitlines(keepends=True):
            ends = part.endswith((b"\n", b"\r"))
            if not self.discarding:
                if len(self.buffer) + len(part) > 16384:
                    self.buffer.clear(); self.discarding = True; self.overlong += 1
                else:
                    self.buffer.extend(part)
            if ends:
                if not self.discarding:
                    self.on_line(bytes(self.buffer).decode("utf-8", "replace").strip())
                self.buffer.clear(); self.discarding = False

    def finish(self):
        if self.buffer and not self.discarding:
            self.on_line(bytes(self.buffer).decode("utf-8", "replace").strip())
        self.buffer.clear()


class Progress:
    def __init__(self):
        self.frames, self.media_us, self.updates, self.ended = 0, 0, 0, False
        self.duplicate_frames, self.dropped_frames = 0, 0

    def line(self, line):
        key, separator, value = line.partition("=")
        if not separator:
            return
        if key in ("frame", "out_time_us", "dup_frames", "drop_frames"):
            try:
                number = int(value)
            except ValueError:
                return
            if not 0 <= number <= 10**15:
                return
            if key == "frame": self.frames = max(self.frames, number)
            elif key == "out_time_us": self.media_us = max(self.media_us, number)
            elif key == "dup_frames": self.duplicate_frames = max(self.duplicate_frames, number)
            else: self.dropped_frames = max(self.dropped_frames, number)
        elif key == "progress" and value in ("continue", "end"):
            self.updates += 1
            self.ended |= value == "end"


class Warnings:
    PATTERNS = {
        "pps": ("pps",), "sps": ("sps",), "vps": ("vps",),
        "invalidNal": ("invalid nal", "invalid nalu", "nal unit type is invalid", "error parsing nal"),
        "missingReference": ("could not find ref", "missing reference", "reference picture missing", "missing ref"),
        "decodeErrors": ("error while decoding", "decoding error", "decode_slice_header error", "error parsing nal", "invalid data found when processing input"),
        "corrupt": ("corrupt",), "authentication": ("401 unauthorized", "authorization failed", "authentication failed"),
        "timeout": ("timed out", "timeout"), "connection": ("connection refused", "connection reset", "error opening input", "connection closed")
    }

    def __init__(self):
        self.categories = collections.Counter()
        self.lines, self.suppressed_repeats, self.previous_categories = 0, 0, []

    def line(self, line):
        if not line:
            return
        self.lines += 1
        repeated = re.search(r"last message repeated\s+(\d+)\s+times", line.lower())
        if repeated:
            digits = repeated.group(1)
            count = 10**7 if len(digits) > 7 else min(10**7, int(digits))
            self.suppressed_repeats += count
            for category in self.previous_categories:
                self.categories[category] += count
            return
        lower = line.lower()
        matched = [category for category, patterns in self.PATTERNS.items() if any(pattern in lower for pattern in patterns)]
        if any(pattern in lower for pattern in ("non monoton", "non-monoton", "nonmonoton", "invalid pts", "invalid dts")):
            if ("to muxer" in lower or "[null @" in lower or "muxer" in lower):
                matched.append("muxerNonmonotonic")
            elif any(context in lower for context in ("[hevc @", "[h264 @", "decoder")):
                matched.append("decoderNonmonotonic")
            elif any(context in lower for context in ("[rtsp @", "demuxer")):
                matched.append("inputNonmonotonic")
            else:
                matched.append("unknownNonmonotonic")
        self.previous_categories = matched or ["other"]
        for category in self.previous_categories:
            self.categories[category] += 1


async def drain_lines(reader, lines):
    while data := await reader.read(4096):
        lines.feed(data)
    lines.finish()

