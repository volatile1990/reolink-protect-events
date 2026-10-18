"use strict";

// Dedicated-host port of verified production SHA256 7c7242ed3cd37e5de8e22ce56cb612351a1e1b6ff8a8ad6d5cfdd251f417edae.
// No installation, authentication override, request logging,
// recording access, file writes, transcoding, or control-message synthesis.
// The native MSP supplies the actual HTTP/WebSocket authorization response.
const net = require("node:net");
const path = require("node:path");
const crypto = require("node:crypto");
const { Transform, pipeline } = require("node:stream");

const CAMERA = "6ac8ae7102b76d03e4006447";
const DEFAULT_TRANSFORM_PATH = path.resolve(__dirname, "aac-clock.cjs");
const MAX_HEADER = 16384;
const MAX_FRAME = 2 * 1024 * 1024;
const MAX_MESSAGE = 4 * 1024 * 1024;
const MAX_SESSION_BYTES = 0;
const MAX_CONTROL_BYTES = 4 * 1024 * 1024;
const MAX_SESSION_MS = 0;
const IDLE_MS = 0;
const HEADER_MS = 5000;
const MAX_SESSIONS = 6;
const MAX_CONNECTIONS = 8;
const KEEP_ALIVE_MS = 30000;
const UPSTREAM_CHECK_MS = 750;

class ProtocolError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function need(condition, code) { if (!condition) throw new ProtocolError(code); }
function loadTransform(filename) {
  const module = require(filename);
  need(typeof module.UbvAacClockTransform === "function", "compat_transform_export");
  return module.UbvAacClockTransform;
}
function headers(raw, request) {
  const lines = raw.toString("latin1").split("\r\n");
  const first = lines.shift();
  const values = new Map();
  for (const line of lines) {
    if (!line) continue;
    need(!/^[ \t]/.test(line), "http_folded_header");
    const position = line.indexOf(":");
    need(position > 0, "http_header");
    const name = line.slice(0, position).toLowerCase();
    need(/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name), "http_header_name");
    const value = line.slice(position + 1).trim();
    const list = values.get(name) || [];
    list.push(value); values.set(name, list);
  }
  const one = name => { const found = values.get(name); return found && found.length === 1 ? found[0] : null; };
  if (request) {
    const match = /^GET ([\x21-\x7e]+) HTTP\/1\.1$/.exec(first);
    need(match && match[1].length <= 8192 && !match[1].includes("#"), "http_request");
    need(!values.has("transfer-encoding") && (!values.has("content-length") || one("content-length") === "0"), "http_request_body");
    return { first, values, one, target: match[1] };
  }
  const match = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/.exec(first);
  need(match, "http_response");
  return { first, values, one, status: Number(match[1]) };
}

function parseCameraIds(value) {
  const values = value === undefined ? [CAMERA] : typeof value === "string" ? value.split(",") : value;
  need(Array.isArray(values) && values.length >= 1 && values.length <= 8 &&
    [...values].every(id => typeof id === "string" && /^[a-f0-9]{24}$/.test(id)) &&
    new Set(values).size === values.length, "compat_camera_allowlist");
  return Object.freeze([...values]);
}

function parseCameraChannels(value, cameraIds) {
  if (value === undefined) {
    const result = {};
    for (const id of parseCameraIds(cameraIds)) result[id] = Object.freeze([0]);
    return Object.freeze(result);
  }
  need(cameraIds === undefined, "compat_ambiguous_camera_scope");
  let source = value, serialized = null;
  if (typeof value === "string") {
    need(value.length <= 8192, "compat_camera_channels");
    serialized = value;
    try { source = JSON.parse(value); } catch (_) { throw new ProtocolError("compat_camera_channels"); }
  }
  need(source && typeof source === "object" && !Array.isArray(source) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(source)), "compat_camera_channels");
  const ids = Object.keys(source);
  need(ids.length >= 1 && ids.length <= 8 && ids.length === Object.getOwnPropertyNames(source).length &&
    !Object.getOwnPropertySymbols(source).length && ids.every(id => /^[a-f0-9]{24}$/.test(id)), "compat_camera_channels");
  if (serialized !== null) {
    const declared = [...serialized.matchAll(/"([a-f0-9]{24})"\s*:/g)].map(match => match[1]);
    need(declared.length === ids.length && new Set(declared).size === ids.length, "compat_camera_channels");
  }
  const result = {};
  for (const id of ids) {
    const channels = source[id];
    need(Array.isArray(channels) && channels.length >= 1 && channels.length <= 2 &&
      [...channels].every(channel => Number.isInteger(channel) && [0, 2].includes(channel)) &&
      new Set(channels).size === channels.length, "compat_camera_channels");
    result[id] = Object.freeze([...channels].sort((a, b) => a - b));
  }
  return Object.freeze(result);
}

function transformationGate(request, cameraIds, configuredChannels) {
  const permitted = parseCameraChannels(configuredChannels, cameraIds);
  // Decisions never alter or reconstruct the forwarded target. Opaque auth and
  // unrecognized query values remain with native MSP, including bypass cases.
  if (request.target.split("?", 1)[0] !== "/playback/") return false;
  const query = new URLSearchParams(request.target.includes("?") ? request.target.slice(request.target.indexOf("?") + 1) : "");
  const unique = name => query.getAll(name).length === 1;
  for (const name of ["camera", "channel", "format", "start"])
    if (!unique(name)) return false;
  const selected = query.get("camera");
  const allowed = Object.prototype.hasOwnProperty.call(permitted, selected) ? permitted[selected] : null;
  if (!allowed || !/^(0|2)$/.test(query.get("channel")) || !allowed.includes(Number(query.get("channel"))) ||
      query.get("format").toLowerCase() !== "ubv" || !/^\d{12,16}$/.test(query.get("start"))) return false;
  if (!Number.isSafeInteger(Number(query.get("start")))) return false;
  for (const name of ["direction", "speed", "rate", "scale", "step", "interval", "playbackSpeed",
      "videoStructure", "idrFrequency", "motionEvent"])
    if (query.has(name)) return false;
  if (query.has("end") && (!unique("end") || !/^\d{12,16}$/.test(query.get("end")) ||
      !Number.isSafeInteger(Number(query.get("end"))) || Number(query.get("end")) <= Number(query.get("start")))) return false;
  if (query.has("lens") && (!unique("lens") || query.get("lens") !== "0")) return false;
  if (query.has("reverse") && (!unique("reverse") || !/^(false|0)$/i.test(query.get("reverse")))) return false;
  return true;
}

function websocketFrame(opcode, payload, fin = true) {
  let header;
  if (payload.length < 126) header = Buffer.from([(fin ? 128 : 0) | opcode, payload.length]);
  else if (payload.length <= 65535) {
    header = Buffer.alloc(4); header[0] = (fin ? 128 : 0) | opcode;
    header[1] = 126; header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10); header[0] = (fin ? 128 : 0) | opcode;
    header[1] = 127; header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

function isBinmeStatus(data) {
  // Native command/status messages are independent binary WS messages. Validate
  // both complete envelopes; a media continuation beginning with 0x01 alone is
  // insufficient. No content is logged, interpreted as a command, or rewritten.
  if (data.length < 16 || data.length > 65536 || data[0] !== 1) return false;
  let offset = 0;
  for (const kind of [1, 2]) {
    if (offset + 8 > data.length || data[offset] !== kind ||
        ![1, 2, 3].includes(data[offset + 1]) || data[offset + 2] || data[offset + 3]) return false;
    const size = data.readUInt32BE(offset + 4);
    if (size > 32768 || offset + 8 + size > data.length) return false;
    offset += 8 + size;
  }
  return offset === data.length;
}

class ArchiveFrameTransform extends Transform {
  constructor(TransformClass, options = {}) {
    super({ readableHighWaterMark: 65536, writableHighWaterMark: 65536 });
    this.buffer = Buffer.alloc(0);
    this.fragmentOpcode = null;
    this.messageParts = [];
    this.messageBytes = 0;
    this.messageFrames = [];
    this.frameCount = 0;
    this.messageCount = 0;
    this.statusCount = 0;
    this.maxBufferedBytes = 0;
    this.media = new TransformClass({ autoDestroy: false });
    this.mediaError = null;
    this.outputParts = null;
    this.media.on("data", data => {
      if (this.outputParts) this.outputParts.push(data);
      else this.destroy(new ProtocolError("compat_unexpected_output"));
    });
    this.media.on("error", error => { this.mediaError = error; });
    this.onStats = options.onStats || (() => {});
  }

  async _message(opcode, data, rawFrames) {
    this.messageCount++;
    if (opcode === 1 || data.length === 0 || isBinmeStatus(data)) {
      if (opcode === 2) this.statusCount++;
      for (const frame of rawFrames) this.push(frame);
      return;
    }
    need(data.length > 0, "compat_empty_binary");
    const partial = this.media._state !== "header" || this.media._headerUsed !== 0;
    need(partial || data[0] === 0xa0, "compat_unknown_binary");
    this.outputParts = [];
    try {
      await new Promise((resolve, reject) => this.media.write(data, error => error ? reject(error) : resolve()));
      if (this.mediaError) throw this.mediaError;
      const output = Buffer.concat(this.outputParts);
      // A tiny source chunk may leave only a partial UBV header. Emit it with
      // the next actual UBV bytes rather than manufacturing an empty record.
      if (output.length) this.push(websocketFrame(2, output));
    } finally { this.outputParts = null; }
  }

  async _consume(chunk) {
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    this.maxBufferedBytes = Math.max(this.maxBufferedBytes, this.buffer.length + this.messageBytes);
    need(this.buffer.length <= MAX_FRAME + 65550, "compat_frame_buffer_bound");
    while (this.buffer.length >= 2) {
      const a = this.buffer[0], b = this.buffer[1], fin = Boolean(a & 128), opcode = a & 15;
      need(!(a & 112) && !(b & 128), "compat_ws_flags");
      let size = b & 127, offset = 2;
      if (size === 126) {
        if (this.buffer.length < 4) return;
        size = this.buffer.readUInt16BE(2); offset = 4;
      } else if (size === 127) {
        if (this.buffer.length < 10) return;
        const wide = this.buffer.readBigUInt64BE(2);
        need(wide <= BigInt(MAX_FRAME), "compat_frame_bound");
        size = Number(wide); offset = 10;
      }
      need(size <= MAX_FRAME, "compat_frame_bound");
      if (this.buffer.length < offset + size) return;
      const raw = this.buffer.subarray(0, offset + size);
      const payload = raw.subarray(offset);
      this.buffer = this.buffer.subarray(offset + size);
      this.frameCount++;
      if (opcode >= 8) {
        need(fin && size <= 125 && [8, 9, 10].includes(opcode), "compat_ws_control");
        // A close must not silently bless a truncated UBV record.
        if (opcode === 8) need(this.fragmentOpcode === null &&
          this.media._state === "header" && !this.media._headerUsed, "compat_close_mid_record");
        this.push(raw); continue;
      }
      if (opcode === 0) need(this.fragmentOpcode !== null, "compat_ws_continuation");
      else {
        need([1, 2].includes(opcode) && this.fragmentOpcode === null, "compat_ws_opcode");
        this.fragmentOpcode = opcode;
      }
      this.messageParts.push(payload); this.messageFrames.push(raw);
      this.messageBytes += payload.length;
      need(this.messageBytes <= MAX_MESSAGE && this.messageFrames.length <= 4096, "compat_message_bound");
      this.maxBufferedBytes = Math.max(this.maxBufferedBytes, this.buffer.length + this.messageBytes);
      if (fin) {
        const messageOpcode = this.fragmentOpcode;
        const message = Buffer.concat(this.messageParts, this.messageBytes), frames = this.messageFrames;
        this.fragmentOpcode = null; this.messageParts = []; this.messageFrames = []; this.messageBytes = 0;
        await this._message(messageOpcode, message, frames);
      }
    }
  }
  _transform(chunk, encoding, callback) {
    this._consume(chunk).then(() => callback(), error => callback(error));
  }
  _flush(callback) {
    if (this.buffer.length || this.fragmentOpcode !== null) return callback(new ProtocolError("compat_incomplete_ws"));
    this.outputParts = [];
    this.media.end(error => {
      this.outputParts = null;
      if (error || this.mediaError) return callback(error || this.mediaError);
      this.onStats(this.snapshot()); callback();
    });
  }
  snapshot() {
    return { ...this.media.snapshot(), websocketFrames: this.frameCount,
      websocketMessages: this.messageCount, statusMessages: this.statusCount,
      maxBufferedBytes: this.maxBufferedBytes };
  }
  _destroy(error, callback) {
    this.buffer = Buffer.alloc(0); this.messageParts = []; this.messageFrames = [];
    this.messageBytes = 0; this.outputParts = null; this.media.destroy(); callback(error);
  }
}

function port(value, zero = false) {
  need(Number.isInteger(value) && value >= (zero ? 0 : 1) && value <= 65535, "compat_port");
  return value;
}
function limit(value, fallback, maximum, minimum = 0) {
  value = value === undefined ? fallback : value;
  need(Number.isSafeInteger(value) && value >= minimum && value <= maximum, "compat_limit");
  return value;
}
function upstreamReachable(host, portNumber, timeoutMs) {
  // TCP readiness only. Native MSP keeps authentication and media ownership.
  // One bounded shared check avoids probe fan-out from concurrent health reads.
  return new Promise(resolve => {
    let socket, timer, settled = false;
    const done = ready => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (socket) socket.destroy();
      resolve(ready);
    };
    timer = setTimeout(() => done(false), timeoutMs);
    try {
      socket = net.createConnection({ host, port: portNumber });
      socket.once("connect", () => done(true));
      socket.once("error", () => done(false));
      socket.once("close", () => done(false));
    } catch (_) { done(false); }
  });
}
function createProxy(options = {}) {
  const listenHost = options.listenHost || "127.0.0.1", upstreamHost = options.upstreamHost || "127.0.0.1";
  need(listenHost === "127.0.0.1" && upstreamHost === "127.0.0.1", "compat_loopback_required");
  const listenPort = port(options.listenPort === undefined ? 7712 : options.listenPort, true);
  const upstreamPort = port(options.upstreamPort === undefined ? 17702 : options.upstreamPort);
  need(listenPort !== upstreamPort, "compat_proxy_loop");
  // Hard lifetime/cumulative-byte limits are explicit canary boundaries, not a
  // permanent playback feature. Zero disables either; resident state stays
  // independently bounded by frames, messages, stream backpressure and peers.
  const sessionMs = limit(options.sessionMs, MAX_SESSION_MS, 2147483647);
  const sessionBytes = limit(options.sessionBytes, MAX_SESSION_BYTES, Number.MAX_SAFE_INTEGER);
  const idleMs = limit(options.idleMs, IDLE_MS, 2147483647);
  const headerMs = limit(options.headerMs, HEADER_MS, 60000, 1);
  const maxSessions = limit(options.maxSessions, MAX_SESSIONS, 8, 1);
  const keepAliveMs = limit(options.keepAliveMs, KEEP_ALIVE_MS, 600000, 1000);
  const upstreamCheckMs = limit(options.upstreamCheckMs, UPSTREAM_CHECK_MS, 5000, 1);
  const cameraChannels = parseCameraChannels(options.cameraChannels, options.cameraIds);
  const cameraIds = Object.freeze(Object.keys(cameraChannels));
  const profileCount = cameraIds.reduce((total, id) => total + cameraChannels[id].length, 0);
  const TransformClass = options.TransformClass || loadTransform(options.transformPath || DEFAULT_TRANSFORM_PATH);
  const sockets = new Set();
  const metrics = { accepted: 0, transformed: 0, bypassed: 0, closed: 0, failed: 0, normalizedAudioRecords: 0 };
  let activeSessions = 0, readinessPending = null;
  const checkUpstream = () => {
    if (readinessPending === null) {
      readinessPending = upstreamReachable(upstreamHost, upstreamPort, upstreamCheckMs)
        .finally(() => { readinessPending = null; });
    }
    return readinessPending;
  };
  const server = net.createServer({ allowHalfOpen: false }, client => {
    client.on("error", () => {});
    // Paused WebSocket sessions stay valid; dead TCP peers are reclaimed by
    // kernel keepalive without adding or altering native WebSocket messages.
    client.setKeepAlive(true, keepAliveMs);
    if (sockets.size >= MAX_CONNECTIONS) { client.destroy(); return; }
    sockets.add(client); metrics.accepted++;
    let upstream = null, transformer = null, header = Buffer.alloc(0), settled = false, upgraded = false, responseRelayed = false;
    let counted = false, inBytes = 0, outBytes = 0, idle = null;
    const deadline = sessionMs ? setTimeout(() => stop(true), sessionMs) : null;
    let headerTimer = setTimeout(() => stop(true), headerMs);
    const touch = () => { if (idle) idle.refresh(); };
    const finish = failed => {
      if (settled) return;
      settled = true; clearTimeout(deadline); clearTimeout(headerTimer); clearTimeout(idle);
      if (counted) { activeSessions--; metrics.closed++; }
      if (failed) metrics.failed++;
      if (transformer) metrics.normalizedAudioRecords += transformer.snapshot().normalizedAudioRecords;
    };
    const stop = failed => {
      finish(failed); if (transformer) transformer.destroy();
      if (upstream) upstream.destroy(); client.destroy();
    };
    client.once("close", () => { sockets.delete(client); if (!settled) stop(false); });
    const respond = response => {
      if (settled) return;
      client.pause(); client.removeListener("data", requestData);
      finish(false);
      // A half-open peer must not retain one of the eight accepted sockets
      // after a local health/rejection response has completely flushed.
      client.end(response, () => client.destroy());
    };
    const reject = status => respond("HTTP/1.1 " + status + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    const requestData = chunk => {
      header = header.length ? Buffer.concat([header, chunk]) : chunk;
      const marker = header.indexOf("\r\n\r\n");
      if (marker < 0) { if (header.length > MAX_HEADER) reject("431 Request Header Fields Too Large"); return; }
      if (marker + 4 > MAX_HEADER) { reject("431 Request Header Fields Too Large"); return; }
      client.pause(); client.removeListener("data", requestData);
      let request;
      try { request = headers(header.subarray(0, marker + 4), true); }
      catch (_) { reject("400 Bad Request"); return; }
      if (["/healthz", "/livez"].includes(request.target) && !request.values.has("upgrade")) {
        const reply = reachable => {
          if (settled) return;
          const capacityAvailable = activeSessions < maxSessions;
          const ready = reachable && capacityAvailable;
          const livenessOnly = request.target === "/livez";
          const body = JSON.stringify({ schemaVersion: 2, ok: livenessOnly || ready,
            liveness: true, readinessChecked: !livenessOnly,
            upstreamTcpReachable: livenessOnly ? null : reachable,
            capacityAvailable, activeSessions, sessionLimitMs: sessionMs,
            sessionByteLimit: sessionBytes, idleLimitMs: idleMs, activeSessionLimit: maxSessions,
            keepAliveMs, cameraCount: cameraIds.length, profileCount, ...metrics });
          respond("HTTP/1.1 " + (livenessOnly || ready ? "200 OK" : "503 Service Unavailable") +
            "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " +
            Buffer.byteLength(body) + "\r\n\r\n" + body);
        };
        if (request.target === "/livez") reply(false);
        else checkUpstream().then(reply, () => reply(false));
        return;
      }
      const key = request.one("sec-websocket-key");
      if (request.one("upgrade")?.toLowerCase() !== "websocket" ||
          !request.one("connection")?.toLowerCase().split(/\s*,\s*/).includes("upgrade") ||
          request.one("sec-websocket-version") !== "13" || !key || !/^[A-Za-z0-9+/]{22}==$/.test(key)) {
        reject("400 Bad Request"); return;
      }
      if (activeSessions >= maxSessions) { reject("503 Service Unavailable"); return; }
      counted = true; activeSessions++;
      const enabled = transformationGate(request, undefined, cameraChannels);
      if (enabled) metrics.transformed++; else metrics.bypassed++;
      idle = idleMs ? setTimeout(() => stop(true), idleMs) : null;
      upstream = net.createConnection({ host: upstreamHost, port: upstreamPort, noDelay: true });
      upstream.setKeepAlive(true, keepAliveMs);
      upstream.on("error", () => stop(true));
      client.once("finish", () => {
        // `finish` follows every buffered destination write, including the
        // transform's flush. Release a half-open client's readable side only
        // after that drain, for native EOF and native auth errors alike.
        finish(false); if (upstream) upstream.destroy(); client.destroy();
      });
      client.on("data", data => { touch(); inBytes += data.length;
        if (sessionBytes && inBytes > Math.min(MAX_CONTROL_BYTES, sessionBytes)) stop(true); });
      upstream.on("data", data => { touch(); outBytes += data.length; if (sessionBytes && outBytes > sessionBytes) stop(true); });
      let response = Buffer.alloc(0);
      const responseData = chunk => {
        response = response.length ? Buffer.concat([response, chunk]) : chunk;
        const end = response.indexOf("\r\n\r\n");
        if (end < 0) { if (response.length > MAX_HEADER) stop(true); return; }
        if (end + 4 > MAX_HEADER) { stop(true); return; }
        upstream.pause(); upstream.removeListener("data", responseData);
        let parsed;
        try { parsed = headers(response.subarray(0, end + 4), false); }
        catch (_) { stop(true); return; }
        if (parsed.status !== 101) {
          // Native auth/status headers and body are relayed verbatim. Never
          // synthesize a successful upgrade or follow an auth redirect.
          clearTimeout(headerTimer); headerTimer = null;
          client.write(response); response = Buffer.alloc(0);
          responseRelayed = true;
          upstream.pipe(client); client.pipe(upstream); client.resume(); upstream.resume();
          return;
        }
        const expected = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
        if (parsed.one("sec-websocket-accept") !== expected || parsed.one("upgrade")?.toLowerCase() !== "websocket" ||
            !parsed.one("connection")?.toLowerCase().split(/\s*,\s*/).includes("upgrade")) { stop(true); return; }
        // Compression is negotiated solely by native MSP. Unsupported extended
        // frames remain transparently proxied, never partially transformed.
        const transformResponse = enabled && !parsed.values.has("sec-websocket-extensions");
        if (enabled && !transformResponse) { metrics.transformed--; metrics.bypassed++; }
        upgraded = true; clearTimeout(headerTimer); headerTimer = null;
        client.write(response.subarray(0, end + 4));
        const remaining = response.subarray(end + 4); response = Buffer.alloc(0);
        if (remaining.length) upstream.unshift(remaining);
        if (transformResponse) {
          transformer = new ArchiveFrameTransform(TransformClass);
          pipeline(upstream, transformer, client, error => {
            finish(Boolean(error)); if (error) stop(true);
            if (!upstream.destroyed) upstream.end();
          });
        } else pipeline(upstream, client, error => { finish(Boolean(error)); if (error) stop(true); });
        client.pipe(upstream); client.resume(); upstream.resume();
      };
      upstream.on("data", responseData);
      upstream.once("connect", () => {
        // Preserve original HTTP request bytes, opaque target, auth headers,
        // Host, subprotocol and any client upgrade head. No trusted auth added.
        upstream.write(header); header = Buffer.alloc(0);
      });
      upstream.once("end", () => { if (!upgraded && response.length) stop(true); });
      upstream.once("close", () => {
        if (!upgraded && !settled && !responseRelayed) stop(true);
      });
    };
    client.on("data", requestData);
  });
  return {
    server, metrics, cameraIds, cameraChannels, profileCount, keepAliveMs,
    listen: () => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(listenPort, listenHost, () => { server.removeListener("error", reject); resolve(server.address()); });
    }),
    close: () => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(resolve); }),
    activeSessions: () => activeSessions
  };
}

if (require.main === module) {
  try {
    const proxy = createProxy({ listenHost: process.env.LISTEN_HOST || "127.0.0.1",
      listenPort: Number(process.env.LISTEN_PORT || 7712), upstreamHost: process.env.UPSTREAM_HOST || "127.0.0.1",
      upstreamPort: Number(process.env.UPSTREAM_PORT || 17702), transformPath: process.env.TRANSFORM_PATH || DEFAULT_TRANSFORM_PATH,
      sessionMs: process.env.MAX_SESSION_MS === undefined ? undefined : Number(process.env.MAX_SESSION_MS),
      sessionBytes: process.env.MAX_SESSION_BYTES === undefined ? undefined : Number(process.env.MAX_SESSION_BYTES),
      idleMs: process.env.IDLE_MS === undefined ? undefined : Number(process.env.IDLE_MS),
      maxSessions: process.env.MAX_SESSIONS === undefined ? undefined : Number(process.env.MAX_SESSIONS),
      cameraIds: process.env.CAMERA_IDS, cameraChannels: process.env.CAMERA_CHANNELS });
    proxy.listen().then(address => process.stdout.write(JSON.stringify({ ready: true, listenHost: "127.0.0.1",
      listenPort: address.port, upstreamPort: Number(process.env.UPSTREAM_PORT || 17702),
      cameraCount: proxy.cameraIds.length, profileCount: proxy.profileCount }) + "\n"),
      () => { process.stderr.write("compat_listen_failed\n"); process.exitCode = 1; });
    const shutdown = () => proxy.close().then(() => process.exit(0));
    process.once("SIGTERM", shutdown); process.once("SIGINT", shutdown);
  } catch (_) { process.stderr.write("compat_start_failed\n"); process.exitCode = 1; }
}
module.exports = { createProxy, ArchiveFrameTransform, transformationGate, headers,
  websocketFrame, isBinmeStatus, parseCameraIds, parseCameraChannels, ProtocolError, CAMERA, DEFAULT_TRANSFORM_PATH };
