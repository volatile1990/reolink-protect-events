"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const net = require("node:net");
const crypto = require("node:crypto");
const { once } = require("node:events");
const { Readable, Writable } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const candidate = require("./proxy.cjs");
const { UbvAacClockTransform } = require(candidate.DEFAULT_TRANSFORM_PATH);
const KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const TARGET = "/playback/?camera=" + candidate.CAMERA + "&channel=0&format=ubv&start=1792219340000";
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const frame = candidate.websocketFrame;

function record(track, format, dts, payload) {
  const flags = format >>> 8, index = format & 15;
  const size = format === 0xf100 ? 12 : 8 + (flags & 4 ? 8 : 4) + (flags & 2 ? 4 : 0) + (flags & 0x40 ? 0 : 4) + 4;
  const header = Buffer.alloc(size);
  header.set([0xa0, track >>> 8, track & 255, 0xa0 ^ (track >>> 8) ^ (track & 255)]);
  header.writeUInt16BE(format, 4);
  let offset = 8;
  if (format !== 0xf100) {
    assert.notEqual(index, 1);
    if (flags & 4) { header.writeBigUInt64BE(BigInt(dts), offset); offset += 8; }
    else { header.writeUInt32BE(dts, offset); offset += 4; }
    if (flags & 2) offset += 4;
    if (!(flags & 0x40)) offset += 4;
  }
  header.writeUInt32BE(payload.length, offset);
  const pad = Buffer.alloc((4 - ((header.length + payload.length) % 4)) % 4, 0x37);
  const back = Buffer.alloc(4); back.writeUInt32BE(header.length + payload.length + pad.length);
  return Buffer.concat([header, payload, pad, back]);
}
const AAC = Buffer.from([0xff, 0xf1, 0x60, 0x40, 0x01, 0x3f, 0xfc, 0x12, 0x34]);
const audio = time => record(1000, 0xf902, time, AAC);
function binme(command = "status") {
  return Buffer.concat([Buffer.from(JSON.stringify({ success: true, command })), Buffer.from('{}')].map((data, index) => {
    const header = Buffer.alloc(8); header[0] = index + 1; header[1] = 1; header.writeUInt32BE(data.length, 4);
    return Buffer.concat([header, data]);
  }));
}
function parseFrames(data) {
  const records = [];
  for (let pos = 0; pos < data.length;) {
    const begin = pos, a = data[pos++], b = data[pos++];
    assert(!(b & 128)); let size = b & 127;
    if (size === 126) { size = data.readUInt16BE(pos); pos += 2; }
    else if (size === 127) { size = Number(data.readBigUInt64BE(pos)); pos += 8; }
    assert(pos + size <= data.length);
    records.push({ opcode: a & 15, fin: !!(a & 128), data: data.subarray(pos, pos + size), raw: data.subarray(begin, pos + size) });
    pos += size;
  }
  return records;
}
function parseUbv(data) {
  const records = [];
  for (let pos = 0; pos < data.length;) {
    const begin = pos, track = data.readUInt16BE(pos + 1), format = data.readUInt16BE(pos + 4), flags = format >>> 8;
    assert.equal(data[pos], 0xa0); pos += 8; let dts = null;
    if (format !== 0xf100) {
      if ((format & 15) === 1) pos += 4;
      dts = flags & 4 ? data.readBigUInt64BE(pos) : BigInt(data.readUInt32BE(pos)); pos += flags & 4 ? 8 : 4;
      if (flags & 2) pos += 4;
      if (!(flags & 0x40)) pos += 4;
    }
    const size = data.readUInt32BE(pos); pos += 4;
    const payload = data.subarray(pos, pos + size); pos += size;
    pos += (4 - (pos % 4)) % 4;
    assert.equal(data.readUInt32BE(pos), pos - begin); pos += 4;
    records.push({ track, format, dts, payload, raw: data.subarray(begin, pos) });
  }
  return records;
}
async function convert(chunks, destination) {
  const transform = new candidate.ArchiveFrameTransform(UbvAacClockTransform);
  const output = [];
  const sink = destination || new Writable({ write(data, encoding, callback) { output.push(Buffer.from(data)); callback(); } });
  await pipeline(Readable.from(chunks), transform, sink);
  return { data: Buffer.concat(output), stats: transform.snapshot(), transform };
}

test("normalizes exact AAC clock/header only; mixed status/text/control/HEVC/ClockSync stay byte-identical", async () => {
  const source = [record(6, 0xf100, 0, Buffer.alloc(0)),
    record(1003, 0xc902, 2000, Buffer.alloc(101, 0x45)),
    record(0xda7e, 0xfd0c, 180000, Buffer.alloc(8, 0x27)), audio(2000), audio(2064)];
  const status = frame(2, binme()), text = frame(1, Buffer.from('native-status'));
  const ping = frame(9, Buffer.from('native-ping')), pong = frame(10, Buffer.from('native-pong'));
  const input = [status, text, frame(2, Buffer.concat(source.slice(0, 3))), ping,
    frame(2, source[3]), pong, frame(2, source[4]), frame(2, Buffer.alloc(0)), frame(8, Buffer.from([3, 232]))];
  const result = await convert(input);
  const messages = parseFrames(result.data);
  for (const exact of [status, text, ping, pong]) assert(messages.some(row => row.raw.equals(exact)));
  const ubv = Buffer.concat(messages.filter(row => row.opcode === 2 && !candidate.isBinmeStatus(row.data)).map(row => row.data));
  const actual = parseUbv(ubv), before = parseUbv(Buffer.concat(source));
  assert.equal(actual.length, before.length);
  for (let i = 0; i < actual.length; i++) {
    assert.equal(sha(actual[i].payload), sha(before[i].payload));
    if (actual[i].track === 1000) {
      assert.equal(actual[i].format, 0xfd06); assert.equal(actual[i].dts, before[i].dts * 16n);
    } else assert.deepEqual(actual[i].raw, before[i].raw);
  }
  assert.equal(result.stats.normalizedAudioRecords, 2);
  assert.equal(result.stats.retainedMetadataBytes, 0);
});

test("TCP chunking, WS fragmentation and media split between separate messages preserve complete encoded media", async () => {
  const source = Buffer.concat([audio(1000), audio(1064), record(1003, 0xe902, 1064, Buffer.alloc(501, 0x01))]);
  const input = Buffer.concat([frame(2, source.subarray(0, 5), false), frame(9, Buffer.from('p')),
    frame(0, source.subarray(5, 13), true), frame(2, source.subarray(13, 47)),
    frame(2, binme('pause')), frame(2, source.subarray(47))]);
  const chunks = Array.from(input, byte => Buffer.from([byte]));
  const result = await convert(chunks);
  const actual = parseUbv(Buffer.concat(parseFrames(result.data)
    .filter(row => row.opcode === 2 && !candidate.isBinmeStatus(row.data)).map(row => row.data)));
  assert.deepEqual(actual.map(row => sha(row.payload)), parseUbv(source).map(row => sha(row.payload)));
  assert.equal(result.stats.normalizedAudioRecords, 2);
  assert.equal(result.stats.statusMessages, 1);
});

test("seek index, incomplete EOF, masked/extended upstream frames and oversized envelopes fail closed", async () => {
  await assert.rejects(convert([frame(2, record(10, 0xf100, 0, Buffer.alloc(20)))]),
    error => error.code === "ubv_compat_live_seek_index_unsupported");
  await assert.rejects(convert([frame(2, audio(1000).subarray(0, 11))]),
    error => error.code === "ubv_compat_incomplete_final_record");
  for (const bytes of [Buffer.from([0x82, 0x80]), Buffer.from([0xc2, 0]),
      Buffer.from([0x82, 127, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff])])
    await assert.rejects(convert([bytes]), error => error.code.startsWith("compat_"));
  await assert.rejects(convert([Buffer.from([0x82, 126, 0])]), error => error.code === "compat_incomplete_ws");
});

test("slow downstream applies ordinary stream backpressure and fully drains EOF within explicit memory bounds", async () => {
  const video = record(1003, 0xc902, 1000, Buffer.alloc(1024 * 1024, 0x56));
  const frames = Array.from({ length: 8 }, () => frame(2, video));
  const chunks = frames.flatMap(bytes => {
    const parts = []; for (let pos = 0; pos < bytes.length; pos += 32768) parts.push(bytes.subarray(pos, pos + 32768)); return parts;
  });
  let bytes = 0, writes = 0;
  const sink = new Writable({ highWaterMark: 1, write(data, encoding, callback) {
    bytes += data.length; writes++; setTimeout(callback, 2);
  } });
  const result = await convert(chunks, sink);
  assert.equal(bytes, Buffer.concat(frames).length);
  assert.equal(writes, 8);
  assert(result.stats.maxBufferedBytes <= 2 * 1024 * 1024);
  assert.equal(result.stats.retainedMetadataBytes, 0);
});

function request(target = TARGET, extra = '') {
  return Buffer.from('GET ' + target + ' HTTP/1.1\r\nHost: original-protect.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + KEY + '\r\nCookie: fixture-auth-only\r\n' + extra + '\r\n');
}
function masked(opcode, payload) {
  assert(payload.length < 126); const mask = Buffer.from([1, 2, 3, 4]);
  return Buffer.concat([Buffer.from([128 | opcode, 128 | payload.length]), mask,
    Buffer.from(payload.map((value, index) => value ^ mask[index % 4]))]);
}
const ACCEPT = crypto.createHash('sha1').update(KEY + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
const UPGRADE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + ACCEPT + '\r\n\r\n');
async function fixture(handler, options = {}) {
  const connections = new Set();
  const upstream = net.createServer(socket => {
    connections.add(socket); socket.on('error', () => {}); socket.once('close', () => connections.delete(socket));
    let header = Buffer.alloc(0);
    const first = chunk => {
      header = Buffer.concat([header, chunk]); const end = header.indexOf('\r\n\r\n'); if (end < 0) return;
      socket.removeListener('data', first); handler(socket, header.subarray(0, end + 4), header.subarray(end + 4));
    };
    socket.on('data', first);
  });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const proxy = candidate.createProxy({ upstreamPort: upstream.address().port, listenPort: 0,
    TransformClass: UbvAacClockTransform, ...options });
  await proxy.listen();
  const close = async () => { await proxy.close(); for (const socket of connections) socket.destroy(); await new Promise(resolve => upstream.close(resolve)); };
  return { proxy, close, connect: () => net.createConnection(proxy.server.address().port, '127.0.0.1') };
}
async function exchange(testFixture, rawRequest) {
  const client = testFixture.connect(); client.on('error', () => {});
  const parts = []; client.on('data', bytes => parts.push(bytes));
  client.write(rawRequest); await once(client, 'close'); return Buffer.concat(parts);
}

test("native authentication and opaque query/headers retain exact identity; real 401/403 are not bypassed", async () => {
  const inputs = [];
  const f = await fixture((socket, head) => {
    inputs.push(head); const status = head.includes(Buffer.from('X-Fixture-Deny: 403')) ? '403 Forbidden' : '401 Unauthorized';
    socket.end('HTTP/1.1 ' + status + '\r\nContent-Length: 6\r\nConnection: close\r\nX-Native: yes\r\n\r\ndenied');
  });
  try {
    for (const status of [401, 403]) {
      const sent = request(TARGET + '&opaque=fixture%2F%2B%3D&futureNativeFlag=fixture',
        'X-UserId: fixture-not-a-real-identity\r\nX-Fixture-Deny: ' + status + '\r\n');
      const response = await exchange(f, sent);
      assert.deepEqual(inputs.at(-1), sent); assert(response.includes(Buffer.from('HTTP/1.1 ' + status)));
      assert(response.toString().endsWith('denied')); assert(!response.includes(Buffer.from('101 Switching')));
    }
    assert.equal(f.proxy.activeSessions(), 0);
  } finally { await f.close(); }
});

test("network EOF drains transformed media; ambiguous and other-camera requests bypass without changing a byte", async () => {
  const body = Buffer.concat([frame(2, binme()), frame(2, audio(12345)), frame(8, Buffer.from([3, 232]))]);
  const received = [];
  const f = await fixture((socket, head) => { received.push(head); socket.end(Buffer.concat([UPGRADE, body])); });
  try {
    const direct = await exchange(f, request());
    assert(direct.subarray(0, UPGRADE.length).equals(UPGRADE));
    const binary = parseFrames(direct.subarray(UPGRADE.length)).find(row => row.opcode === 2 && !candidate.isBinmeStatus(row.data));
    assert.equal(parseUbv(binary.data)[0].format, 0xfd06);
    for (const target of [TARGET.replace(candidate.CAMERA, '111111111111111111111111'),
        TARGET + '&camera=' + candidate.CAMERA, TARGET + '&speed=1.5', TARGET + '&rate=1.5',
        TARGET + '&scale=1.5', TARGET + '&step=1', TARGET + '&interval=1', TARGET + '&playbackSpeed=1.5',
        TARGET + '&reverse=true', TARGET + '&end=now', TARGET + '&end=1792219300000']) {
      const sent = request(target); const response = await exchange(f, sent);
      assert.deepEqual(response, Buffer.concat([UPGRADE, body])); assert.deepEqual(received.at(-1), sent);
    }
    const closed = await exchange(f, request(TARGET + '&end=1792219430000'));
    const closedMedia = parseFrames(closed.subarray(UPGRADE.length)).find(row => row.opcode === 2 && !candidate.isBinmeStatus(row.data));
    assert.equal(parseUbv(closedMedia.data)[0].format, 0xfd06);
    assert.equal(f.proxy.metrics.transformed, 2); assert.equal(f.proxy.metrics.bypassed, 11);
    assert.equal(f.proxy.activeSessions(), 0);
  } finally { await f.close(); }
});

test("pause/resume controls remain masked and byte-identical; fresh seek session has independent DTS state", async () => {
  const pause = masked(2, Buffer.from('fixture-pause')), resume = masked(2, Buffer.from('fixture-resume'));
  const controls = Buffer.concat([pause, resume]); const observed = [];
  let sessions = 0;
  const f = await fixture(socket => {
    sessions++; const time = sessions === 1 ? 300000 : 1000;
    socket.write(Buffer.concat([UPGRADE, frame(2, audio(time))])); let incoming = Buffer.alloc(0);
    socket.on('data', bytes => {
      incoming = Buffer.concat([incoming, bytes]);
      if (incoming.length >= controls.length) { observed.push(incoming); socket.end(frame(2, audio(time + 64))); }
    });
  });
  try {
    for (let index = 0; index < 2; index++) {
      const client = f.connect(); client.on('error', () => {}); const parts = []; let sent = false;
      client.on('data', bytes => { parts.push(bytes); if (!sent) { sent = true; client.write(pause); setTimeout(() => client.write(resume), 5); } });
      client.write(request(index ? TARGET.replace('1792219340000', '1792219000000') : TARGET));
      await once(client, 'close');
      const response = Buffer.concat(parts); const media = Buffer.concat(parseFrames(response.subarray(UPGRADE.length)).map(row => row.data));
      const records = parseUbv(media);
      assert.equal(records.length, 2); assert.equal(records[0].dts, BigInt(index ? 1000 : 300000) * 16n);
    }
    assert.deepEqual(observed, [controls, controls]); assert.equal(f.proxy.activeSessions(), 0);
  } finally { await f.close(); }
});

test("session cap, deadlines, loopback restriction and health counters terminate cleanly", async () => {
  assert.throws(() => candidate.createProxy({ listenHost: '0.0.0.0' }), /compat_loopback_required/);
  const f = await fixture(socket => socket.write(UPGRADE), { sessionMs: 150, idleMs: 1000, maxSessions: 2 });
  const clients = [];
  try {
    for (let i = 0; i < 2; i++) {
      const client = f.connect(); client.on('error', () => {}); clients.push(client); client.write(request()); await once(client, 'data');
    }
    assert.equal(f.proxy.activeSessions(), 2);
    const response = await exchange(f, request()); assert(response.includes(Buffer.from('503 Service Unavailable')));
    const health = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    assert(health.includes(Buffer.from('"activeSessions":2')));
    assert(health.includes(Buffer.from('503 Service Unavailable')));
    const ready = JSON.parse(health.subarray(health.indexOf('\r\n\r\n') + 4));
    assert.equal(ready.ok, false); assert.equal(ready.capacityAvailable, false);
    assert.equal(ready.upstreamTcpReachable, true);
    await Promise.all(clients.map(client => once(client, 'close')));
    assert.equal(f.proxy.activeSessions(), 0);
  } finally { for (const client of clients) client.destroy(); await f.close(); }
});

test("readiness cannot stay green with a closed native upstream while liveness stays separate", async () => {
  const closed = net.createServer(); closed.listen(0, '127.0.0.1'); await once(closed, 'listening');
  const upstreamPort = closed.address().port; await new Promise(resolve => closed.close(resolve));
  const proxy = candidate.createProxy({ upstreamPort, listenPort: 0, TransformClass: UbvAacClockTransform });
  await proxy.listen();
  const f = { connect: () => net.createConnection(proxy.server.address().port, '127.0.0.1') };
  try {
    const response = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const health = JSON.parse(response.subarray(response.indexOf('\r\n\r\n') + 4));
    assert(response.includes(Buffer.from('503 Service Unavailable')));
    assert.equal(health.ok, false); assert.equal(health.upstreamTcpReachable, false);
    assert.equal(health.readinessChecked, true); assert.equal(health.keepAliveMs, 30000);
    const live = await exchange(f, Buffer.from('GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const data = JSON.parse(live.subarray(live.indexOf('\r\n\r\n') + 4));
    assert(live.includes(Buffer.from('200 OK'))); assert.equal(data.ok, true);
    assert.equal(data.readinessChecked, false); assert.equal(data.upstreamTcpReachable, null);
    assert.equal(proxy.activeSessions(), 0);
  } finally { await proxy.close(); }
});

test("long paused responsive peers retain capacity while dead-peer keepalive is enabled", async () => {
  const f = await fixture(socket => socket.write(UPGRADE), { sessionMs: 0, sessionBytes: 0, idleMs: 0 });
  const client = f.connect(); client.on('error', () => {});
  try {
    client.write(request()); await once(client, 'data');
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(f.proxy.activeSessions(), 1); assert.equal(f.proxy.keepAliveMs, 30000);
    const response = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const health = JSON.parse(response.subarray(response.indexOf('\r\n\r\n') + 4));
    assert.equal(health.ok, true); assert.equal(health.capacityAvailable, true);
  } finally { client.destroy(); await f.close(); }
});

test("eight half-open rejected or health clients cannot retain connection slots", async () => {
  const f = await fixture(socket => socket.end(Buffer.concat([UPGRADE, frame(2, audio(1000))])));
  const clients = [];
  try {
    for (let index = 0; index < 8; index++) {
      const client = net.createConnection({ port: f.proxy.server.address().port, host: '127.0.0.1', allowHalfOpen: true });
      client.on('error', () => {}); clients.push(client); client.resume();
      client.write(index % 2 ? 'GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n' :
        'GET /playback/ HTTP/1.1\r\nHost: localhost\r\n\r\n');
      await once(client, 'end');
    }
    await new Promise(resolve => setImmediate(resolve));
    const count = await new Promise((resolve, reject) => f.proxy.server.getConnections((error, value) => error ? reject(error) : resolve(value)));
    assert.equal(count, 0);
    const health = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    assert(health.includes(Buffer.from('200 OK')));
    const valid = await exchange(f, request());
    assert(valid.subarray(0, UPGRADE.length).equals(UPGRADE));
    assert.equal(f.proxy.activeSessions(), 0);
  } finally { for (const client of clients) client.destroy(); await f.close(); }
});

test("zero canary lifetime/byte limits do not introduce an implicit playback hard stop", async () => {
  const f = await fixture(socket => setTimeout(() => socket.end(Buffer.concat([UPGRADE, frame(2, audio(1000))])), 25),
    { sessionMs: 0, sessionBytes: 0, idleMs: 0 });
  try {
    const valid = await exchange(f, request()); assert(valid.subarray(0, UPGRADE.length).equals(UPGRADE));
    const health = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    assert(health.includes(Buffer.from('"sessionLimitMs":0')));
    assert(health.includes(Buffer.from('"sessionByteLimit":0')));
    assert(health.includes(Buffer.from('"idleLimitMs":0')));
  } finally { await f.close(); }
  const many = Buffer.concat(Array.from({ length: 100001 }, () => frame(2, Buffer.alloc(0))));
  const result = await convert([many]);
  assert.equal(result.stats.websocketFrames, 100001);
  assert.equal(result.data.length, many.length);
});

test("eight valid EOF sessions fully drain and release half-open peers before the next viewer", async () => {
  const body = frame(2, Buffer.concat([audio(1000), record(1003, 0xc902, 1000, Buffer.alloc(512000, 0x65))]));
  const f = await fixture(socket => socket.end(Buffer.concat([UPGRADE, body])));
  const clients = [];
  try {
    for (let index = 0; index < 8; index++) {
      const client = net.createConnection({ port: f.proxy.server.address().port, host: '127.0.0.1', allowHalfOpen: true });
      client.on('error', () => {}); clients.push(client); const parts = []; client.on('data', data => parts.push(data));
      client.write(request()); await once(client, 'end');
      const response = Buffer.concat(parts); assert(response.subarray(0, UPGRADE.length).equals(UPGRADE));
      const media = Buffer.concat(parseFrames(response.subarray(UPGRADE.length)).map(row => row.data));
      const records = parseUbv(media); assert.equal(records[0].format, 0xfd06);
      assert.equal(records[1].payload.length, 512000);
      assert.equal(sha(records[1].payload), sha(Buffer.alloc(512000, 0x65)));
    }
    await new Promise(resolve => setImmediate(resolve));
    const count = await new Promise((resolve, reject) => f.proxy.server.getConnections((error, value) => error ? reject(error) : resolve(value)));
    assert.equal(count, 0); assert.equal(f.proxy.activeSessions(), 0);
    const valid = await exchange(f, request()); assert(valid.subarray(0, UPGRADE.length).equals(UPGRADE));
  } finally { for (const client of clients) client.destroy(); await f.close(); }
});

test("camera allowlist is canonical, unique, bounded, immutable and defaults to the original camera", () => {
  const entrance = '6ac8ae7001ab6d03e4006410';
  assert.deepEqual(candidate.parseCameraIds(), [candidate.CAMERA]);
  assert.deepEqual(candidate.parseCameraIds(candidate.CAMERA + ',' + entrance), [candidate.CAMERA, entrance]);
  const eight = Array.from({ length: 8 }, (_, index) => index.toString(16).padStart(24, '0'));
  assert.deepEqual(candidate.parseCameraIds(eight), eight);
  for (const bad of ['', null, {}, 42, [], [candidate.CAMERA, candidate.CAMERA],
      candidate.CAMERA + ',', ' ' + candidate.CAMERA, candidate.CAMERA + '\n', candidate.CAMERA.toUpperCase(),
      'prefix' + candidate.CAMERA, [candidate.CAMERA, 'not-an-id'], [...eight, 'f'.repeat(24)]])
    assert.throws(() => candidate.parseCameraIds(bad), /compat_camera_allowlist/);
  const source = [candidate.CAMERA, entrance];
  const proxy = candidate.createProxy({ cameraIds: source, listenPort: 0, upstreamPort: 7702, TransformClass: UbvAacClockTransform });
  source.push('1'.repeat(24));
  assert.deepEqual(proxy.cameraIds, [candidate.CAMERA, entrance]);
  assert(Object.isFrozen(proxy.cameraIds));
  assert.throws(() => proxy.cameraIds.push('2'.repeat(24)), TypeError);
});

test("two configured cameras normalize AAC and preserve H264 bytes; unknown cameras, other channels and query ambiguity stay native", async () => {
  const entrance = '6ac8ae7001ab6d03e4006410';
  const sourceVideo = record(7, 0xc902, 1000, Buffer.alloc(1001, 0x44));
  const body = Buffer.concat([frame(2, binme()), frame(2, audio(1000)), frame(2, sourceVideo)]);
  const requests = [];
  const f = await fixture((socket, head) => { requests.push(head); socket.end(Buffer.concat([UPGRADE, body])); },
    { cameraIds: candidate.CAMERA + ',' + entrance });
  try {
    for (const identifier of [candidate.CAMERA, entrance]) {
      const sent = request(TARGET.replace(candidate.CAMERA, identifier) + '&opaqueAuth=fixture%2Fvalue');
      const response = await exchange(f, sent);
      assert.deepEqual(requests.at(-1), sent);
      const data = Buffer.concat(parseFrames(response.subarray(UPGRADE.length))
        .filter(row => row.opcode === 2 && !candidate.isBinmeStatus(row.data)).map(row => row.data));
      const records = parseUbv(data);
      assert.equal(records[0].format, 0xfd06); assert.equal(records[0].dts, 16000n);
      assert.deepEqual(records[0].payload, AAC);
      assert.deepEqual(records[1].raw, sourceVideo);
    }
    const entryTarget = TARGET.replace(candidate.CAMERA, entrance);
    const bypasses = [TARGET.replace(candidate.CAMERA, '111111111111111111111111'),
      entryTarget.replace('channel=0', 'channel=1'), entryTarget + '&camera=' + entrance,
      entryTarget + '&reverse=true', entryTarget + '&reverse=', entryTarget + '&speed=1.5',
      entryTarget + '&rate=1.5', entryTarget + '&direction=reverse', entryTarget + '&videoStructure=fixture'];
    for (const target of bypasses) {
      const sent = request(target), response = await exchange(f, sent);
      assert.deepEqual(requests.at(-1), sent);
      assert.deepEqual(response, Buffer.concat([UPGRADE, body]));
    }
    assert.equal(f.proxy.metrics.transformed, 2); assert.equal(f.proxy.metrics.bypassed, bypasses.length);
    assert.equal(f.proxy.activeSessions(), 0);
    const health = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const healthBody = JSON.parse(health.subarray(health.indexOf('\r\n\r\n') + 4).toString());
    assert.equal(healthBody.cameraCount, 2);
  } finally { await f.close(); }
});

const ALL_CHANNELS = {
  '6ac83993001a6d03e4001690': [0, 2], '6ac83fed00bd6d03e4001b81': [0, 2],
  '6ac844bd01096d03e4001f22': [0, 2], '6ac844bf02026d03e4001f5f': [0, 2],
  '6ac8ae7001ab6d03e4006410': [0, 2], '6ac8ae7102b76d03e4006447': [0]
};
test("camera/channel map is strict, deeply immutable and retains CAMERA_IDS channel0 compatibility", () => {
  assert.deepEqual(candidate.parseCameraChannels(), { [candidate.CAMERA]: [0] });
  assert.deepEqual(candidate.parseCameraChannels(undefined, Object.keys(ALL_CHANNELS).join(',')),
    Object.fromEntries(Object.keys(ALL_CHANNELS).map(id => [id, [0]])));
  const copied = candidate.parseCameraChannels(ALL_CHANNELS);
  assert.deepEqual(copied, ALL_CHANNELS);
  assert(Object.isFrozen(copied)); assert(Object.values(copied).every(Object.isFrozen));
  const source = { [candidate.CAMERA]: [0] }, immutable = candidate.parseCameraChannels(source);
  source[candidate.CAMERA].push(2); assert.deepEqual(immutable[candidate.CAMERA], [0]);
  const duplicate = '{"' + candidate.CAMERA + '":[0],"' + candidate.CAMERA + '":[0,2]}';
  const sparse = []; sparse.length = 1;
  for (const bad of ['', '{}', '[]', 'null', duplicate, { invalid: [0] }, { [candidate.CAMERA]: [] },
      { [candidate.CAMERA]: [0, 0] }, { [candidate.CAMERA]: [1] }, { [candidate.CAMERA]: [true] },
      { [candidate.CAMERA]: ['0'] }, { [candidate.CAMERA]: [16] }, { [candidate.CAMERA]: sparse },
      Object.fromEntries(Array.from({ length: 9 }, (_, i) => [i.toString(16).padStart(24, '0'), [0]]))])
    assert.throws(() => candidate.parseCameraChannels(bad), /compat_camera_channels/);
  assert.throws(() => candidate.parseCameraChannels(ALL_CHANNELS, candidate.CAMERA), /compat_ambiguous_camera_scope/);
  assert.throws(() => candidate.parseCameraIds(sparse), /compat_camera_allowlist/);
});

test("exact six-camera eleven-profile map normalizes only those pairs, preserving native auth, payload and unknown/Mid1 bypass", async () => {
  const video = record(7, 0xc902, 1000, Buffer.alloc(1237, 0x57));
  const body = Buffer.concat([frame(2, audio(1000)), frame(2, video)]), seen = [];
  const f = await fixture((socket, head) => {
    seen.push(head);
    if (head.includes(Buffer.from('X-Fixture-Deny: yes'))) socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    else socket.end(Buffer.concat([UPGRADE, body]));
  }, { cameraChannels: JSON.stringify(ALL_CHANNELS), maxSessions: 6 });
  const target = (id, channel) => TARGET.replace(candidate.CAMERA, id).replace('channel=0', 'channel=' + channel);
  try {
    for (const [id, channels] of Object.entries(ALL_CHANNELS)) for (const channel of channels) {
      const sent = request(target(id, channel) + '&opaque=fixture%2Fauth');
      const response = await exchange(f, sent); assert.deepEqual(seen.at(-1), sent);
      const records = parseUbv(Buffer.concat(parseFrames(response.subarray(UPGRADE.length)).map(row => row.data)));
      assert.equal(records[0].format, 0xfd06); assert.deepEqual(records[0].payload, AAC);
      assert.deepEqual(records[1].raw, video);
    }
    const bypasses = [[candidate.CAMERA, 2], ['1'.repeat(24), 0], ['__proto__', 0], ['toString', 0],
      ...Object.keys(ALL_CHANNELS).map(id => [id, 1]), [Object.keys(ALL_CHANNELS)[0], 3]];
    for (const [id, channel] of bypasses) {
      const sent = request(target(id, channel)), response = await exchange(f, sent);
      assert.deepEqual(response, Buffer.concat([UPGRADE, body])); assert.deepEqual(seen.at(-1), sent);
    }
    const denied = await exchange(f, request(target(Object.keys(ALL_CHANNELS)[0], 2), 'X-Fixture-Deny: yes\r\n'));
    assert(denied.includes(Buffer.from('403 Forbidden'))); assert(!denied.includes(Buffer.from('101 Switching')));
    const health = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const values = JSON.parse(health.subarray(health.indexOf('\r\n\r\n') + 4).toString());
    assert.equal(values.cameraCount, 6); assert.equal(values.profileCount, 11); assert.equal(values.activeSessionLimit, 6);
    assert.equal(f.proxy.metrics.transformed, 12); assert.equal(f.proxy.metrics.bypassed, bypasses.length);
    assert.equal(f.proxy.activeSessions(), 0);
  } finally { await f.close(); }
});

test("dedicated-host defaults retain all six production viewer slots without lifetime, byte or idle cutoff", async () => {
  const f = await fixture(socket => socket.write(UPGRADE), { cameraChannels: ALL_CHANNELS });
  const clients = [];
  try {
    for (let index = 0; index < 6; index++) {
      const client = f.connect(); client.on('error', () => {}); clients.push(client);
      client.write(request()); await once(client, 'data');
    }
    assert.equal(f.proxy.activeSessions(), 6);
    const rejected = await exchange(f, request());
    assert(rejected.includes(Buffer.from('503 Service Unavailable')));
    const reply = await exchange(f, Buffer.from('GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    const health = JSON.parse(reply.subarray(reply.indexOf('\r\n\r\n') + 4));
    assert.equal(health.activeSessionLimit, 6);
    assert.equal(health.sessionLimitMs, 0); assert.equal(health.sessionByteLimit, 0);
    assert.equal(health.idleLimitMs, 0); assert.equal(health.cameraCount, 6); assert.equal(health.profileCount, 11);
    const live = await exchange(f, Buffer.from('GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n'));
    assert(live.includes(Buffer.from('200 OK')));
  } finally { for (const client of clients) client.destroy(); await f.close(); }
});
