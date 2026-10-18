"use strict";

// Offline compatibility experiment. This module does not install a hook.
// UBV envelope reference: petergeneric/unifi-protect-remux, ubv/src/format.rs
// and record.rs. It changes only a validated AAC16k mono record's clock units.
const { Transform } = require("node:stream");

const MAX_RECORD_BYTES = 16 * 1024 * 1024;
const UINT32_MAX = 0xffffffffn;
const UINT64_MAX = 0xffffffffffffffffn;
const CANARY_CAMERA_ID = "6ac83993001a6d03e4001690";
const ALLOWED_CAMERA_IDS = Object.freeze([
  "6ac83993001a6d03e4001690",
  "6ac83fed00bd6d03e4001b81",
  "6ac844bd01096d03e4001f22",
  "6ac844bf02026d03e4001f5f",
  "6ac8ae7001ab6d03e4006410",
  "6ac8ae7102b76d03e4006447"
]);
const CLOCK_RATES = [0, 0, 1000, 8000, 11025, 12000, 16000, 22050,
  24000, 32000, 44100, 48000, 90000, 1000000, 1000000000, 0];

class UbvClockCompatibilityError extends Error {
  constructor(code) { super(code); this.name = "UbvClockCompatibilityError"; this.code = code; }
}

function fail(code) { throw new UbvClockCompatibilityError(code); }

function matchingAdts(prefix, payloadSize) {
  if (prefix.length !== 7 || prefix[0] !== 0xff || (prefix[1] & 0xf6) !== 0xf0) return false;
  const profile = prefix[2] >>> 6;
  const frequencyIndex = (prefix[2] >>> 2) & 15;
  const channels = ((prefix[2] & 1) << 2) | (prefix[3] >>> 6);
  const frameBytes = ((prefix[3] & 3) << 11) | (prefix[4] << 3) | (prefix[5] >>> 5);
  const headerBytes = (prefix[1] & 1) ? 7 : 9;
  return profile === 1 && frequencyIndex === 8 && channels === 1 &&
    (prefix[6] & 3) === 0 && frameBytes === payloadSize && frameBytes > headerBytes;
}

class UbvAacClockTransform extends Transform {
  constructor(options = {}) {
    // Encoded media is subject only to ordinary Node stream backpressure.
    // Our own retained state contains a <=36B header, 7B ADTS prefix and 4B trailer.
    super({ ...options, readableObjectMode: false, writableObjectMode: false });
    this._header = Buffer.alloc(36);
    this._headerUsed = 0;
    this._headerNeed = 8;
    this._prefix = Buffer.alloc(7);
    this._prefixUsed = 0;
    this._trailer = Buffer.alloc(4);
    this._trailerUsed = 0;
    this._state = "header";
    this._record = null;
    this._sourceOffset = 0n;
    this._parts = null;
    this._callChanged = false;
    this.diagnostics = { records: 0, normalizedAudioRecords: 0, normalizedDts32Records: 0,
      normalizedDts64Records: 0, unsupportedAudioRecords: 0, passthroughAudioRecords: 0,
      payloadBytesForwarded: 0, maxRetainedMetadataBytes: 0, errors: 0,
      sourceClockWrapsRejected: 0, lastNormalizedSourceDts: null };
  }

  _retainDiagnostic() {
    this.diagnostics.maxRetainedMetadataBytes = Math.max(this.diagnostics.maxRetainedMetadataBytes,
      this._headerUsed + this._prefixUsed + this._trailerUsed);
  }

  _emit(data) { if (data.length) this._parts.push(data); }

  _baseHeader() {
    const h = this._header;
    if (h[0] !== 0xa0) fail("ubv_compat_magic");
    if ((h[0] ^ h[1] ^ h[2]) !== h[3]) fail("ubv_compat_checksum");
    const format = h.readUInt16BE(4), index = h[5] & 15, flags = h[4];
    if (format === 0xf100) this._headerNeed = 12;
    else if (index >= 1 && index <= 14) {
      this._headerNeed = 8 + (index === 1 ? 4 : 0) + ((flags & 4) ? 8 : 4) +
        ((flags & 2) ? 4 : 0) + ((flags & 0x40) ? 0 : 4) + 4;
    } else fail("ubv_compat_layout");
    if (this._headerNeed > this._header.length) fail("ubv_compat_header_bound");
  }

  _completeHeader() {
    const h = this._header, flags = h[4], index = h[5] & 15, format = h.readUInt16BE(4);
    const track = h.readUInt16BE(1);
    let pos = 8, rate = null, dts = null;
    if (format !== 0xf100) {
      rate = index === 1 ? h.readUInt32BE(pos) : CLOCK_RATES[index];
      if (index === 1) pos += 4;
      if (!rate || rate > 1000000000) fail("ubv_compat_clock_rate");
      dts = (flags & 4) ? h.readBigUInt64BE(pos) : BigInt(h.readUInt32BE(pos));
      pos += (flags & 4) ? 8 : 4;
      if (flags & 2) pos += 4;
      if (!(flags & 0x40)) pos += 4;
    }
    const size = h.readUInt32BE(pos);
    if (pos + 4 !== this._headerNeed || size > MAX_RECORD_BYTES) fail("ubv_compat_record_bound");
    // A file seek table contains physical byte offsets. This live-view-only
    // experiment grows AAC headers, so silently forwarding such offsets would
    // be incorrect. Actual native live captures contain no seek-table records.
    if (track === 10 && format === 0xf100) fail("ubv_compat_live_seek_index_unsupported");
    const pad = Number((-((this._sourceOffset + BigInt(this._headerNeed + size)) % 4n) + 4n) % 4n);
    this._record = { track, format, rate, dts, size, pad, headerBytes: this._headerNeed,
      payloadRemaining: size, padRemaining: pad, rewritten: false, addedBytes: 0,
      candidate: track === 1000 && format === 0xf902 && rate === 1000 && size >= 7 };
    this._state = "payload";
    if (!this._record.candidate) {
      this._emit(Buffer.from(h.subarray(0, this._headerNeed)));
      if (track === 1000) this.diagnostics.passthroughAudioRecords++;
      this._headerUsed = 0;
    }
  }

  _releaseAudioHeader() {
    const r = this._record;
    if (matchingAdts(this._prefix.subarray(0, this._prefixUsed), r.size)) {
      const scaled = r.dts * 16n;
      if (r.dts > UINT32_MAX || scaled > UINT64_MAX) fail("ubv_compat_audio_timestamp_bound");
      const last = this.diagnostics.lastNormalizedSourceDts;
      // A new64-bit representation cannot silently retain the source's32-bit
      // rollover modulus. Close this viewer and let a new connection establish
      // the next source epoch. No source/recording stream is modified.
      if (last !== null && r.dts < last) {
        if (last - r.dts > 0x80000000n) {
          this.diagnostics.sourceClockWrapsRejected++;
          fail("ubv_compat_source_clock_wrap_reconnect");
        }
        fail("ubv_compat_audio_clock_backwards");
      }
      // Use the native-style64-bit AAC layout from the first rewritten record.
      // This avoids a new74-hour sample-counter wrap or a mid-view width change.
      const header = Buffer.alloc(20);
      this._header.copy(header, 0, 0, 8);
      header[4] = 0xfd;
      header[5] = 6; // 16 kHz packet clock; actual encoded sampling stays16 kHz.
      header.writeBigUInt64BE(scaled, 8);
      header.writeUInt32BE(r.size, 16);
      r.rewritten = true; r.addedBytes = 4;
      this._emit(header);
      this._callChanged = true;
      this.diagnostics.normalizedAudioRecords++;
      this.diagnostics.normalizedDts64Records++;
      this.diagnostics.lastNormalizedSourceDts = r.dts;
    } else {
      this._emit(Buffer.from(this._header.subarray(0, r.headerBytes)));
      this.diagnostics.unsupportedAudioRecords++;
    }
    this._emit(Buffer.from(this._prefix.subarray(0, this._prefixUsed)));
    this._headerUsed = this._prefixUsed = 0;
  }

  _finishRecord() {
    const r = this._record, expected = r.headerBytes + r.size + r.pad;
    if (this._trailer.readUInt32BE(0) !== expected) fail("ubv_compat_back_size");
    if (r.addedBytes) {
      const trailer = Buffer.alloc(4); trailer.writeUInt32BE(expected + r.addedBytes);
      this._emit(trailer); this._callChanged = true;
    } else this._emit(Buffer.from(this._trailer));
    this._sourceOffset += BigInt(expected + 4);
    this.diagnostics.records++;
    this._headerUsed = this._prefixUsed = this._trailerUsed = 0;
    this._headerNeed = 8; this._state = "header"; this._record = null;
  }

  _transform(data, _encoding, callback) {
    try {
      if (!Buffer.isBuffer(data)) data = Buffer.from(data);
      const hadBufferedMetadata = this._headerUsed + this._prefixUsed + this._trailerUsed > 0;
      this._parts = []; this._callChanged = false;
      let pos = 0;
      while (pos < data.length) {
        if (this._state === "header") {
          const take = Math.min(this._headerNeed - this._headerUsed, data.length - pos);
          data.copy(this._header, this._headerUsed, pos, pos + take);
          this._headerUsed += take; pos += take; this._retainDiagnostic();
          if (this._headerUsed === 8 && this._headerNeed === 8) this._baseHeader();
          if (this._headerUsed === this._headerNeed) this._completeHeader();
        } else if (this._state === "payload") {
          const r = this._record;
          if (r.candidate && this._headerUsed) {
            const take = Math.min(7 - this._prefixUsed, r.payloadRemaining, data.length - pos);
            data.copy(this._prefix, this._prefixUsed, pos, pos + take);
            this._prefixUsed += take; pos += take; r.payloadRemaining -= take;
            this.diagnostics.payloadBytesForwarded += take; this._retainDiagnostic();
            if (this._prefixUsed === 7 || r.payloadRemaining === 0) this._releaseAudioHeader();
          } else {
            const take = Math.min(r.payloadRemaining, data.length - pos);
            this._emit(data.subarray(pos, pos + take)); pos += take; r.payloadRemaining -= take;
            this.diagnostics.payloadBytesForwarded += take;
          }
          if (r.payloadRemaining === 0) this._state = "padding";
        } else if (this._state === "padding") {
          const r = this._record, take = Math.min(r.padRemaining, data.length - pos);
          this._emit(data.subarray(pos, pos + take)); pos += take; r.padRemaining -= take;
          if (r.padRemaining === 0) this._state = "trailer";
        } else if (this._state === "trailer") {
          const take = Math.min(4 - this._trailerUsed, data.length - pos);
          data.copy(this._trailer, this._trailerUsed, pos, pos + take);
          this._trailerUsed += take; pos += take; this._retainDiagnostic();
          if (this._trailerUsed === 4) this._finishRecord();
        } else fail("ubv_compat_state");
      }
      // One output per source read, as in the native WebSocketStream pipe. Video
      // reads with no retained header and no rewrite reuse the original buffer.
      const length = this._parts.reduce((total, item) => total + item.length, 0);
      if (length) this.push(!hadBufferedMetadata && !this._callChanged && length === data.length
        ? data : this._parts.length === 1 ? this._parts[0] : Buffer.concat(this._parts, length));
      this._parts = null; callback();
    } catch (error) {
      this.diagnostics.errors++; this._parts = null; callback(error);
    }
  }

  _flush(callback) {
    if (this._state !== "header" || this._headerUsed || this._record) {
      this.diagnostics.errors++; callback(new UbvClockCompatibilityError("ubv_compat_incomplete_final_record"));
    } else callback();
  }

  _destroy(error, callback) {
    this._header.fill(0); this._prefix.fill(0); this._trailer.fill(0);
    this._headerUsed = this._prefixUsed = this._trailerUsed = 0;
    this._record = this._parts = null; callback(error);
  }

  get retainedMetadataBytes() { return this._headerUsed + this._prefixUsed + this._trailerUsed; }
  snapshot() {
    const { lastNormalizedSourceDts, ...numbers } = this.diagnostics;
    return { ...numbers, lastNormalizedSourceDts: lastNormalizedSourceDts === null ? null : lastNormalizedSourceDts.toString(),
      retainedMetadataBytes: this.retainedMetadataBytes, mediaDecoded: false,
      encodedSamplingRateChanged: false, encodedPayloadChanged: false };
  }
}

function wireOutgoing(emsSocket, wsDuplex, cameraId, streamType) {
  if (!ALLOWED_CAMERA_IDS.includes(cameraId) || String(streamType).toLowerCase() !== "ubv") {
    emsSocket.pipe(wsDuplex);
    return null;
  }
  // The native sockets own normal connection teardown. An intermediate
  // Transform's automatic close must not prematurely destroy a destination
  // that is still finishing its final buffered write.
  const transform = new UbvAacClockTransform({ autoDestroy: false });
  let stopping = false, sourceClosed = false, destinationClosed = false;
  const release = () => {
    if (!sourceClosed || !destinationClosed) return;
    emsSocket.removeListener("error", onSocketError);
    wsDuplex.removeListener("error", onSocketError);
    emsSocket.removeListener("close", onSourceClose);
    wsDuplex.removeListener("close", onDestinationClose);
    transform.removeListener("error", stop);
    transform.removeListener("close", onTransformClose);
  };
  const stop = error => {
    if (stopping) return;
    stopping = true;
    emsSocket.unpipe(transform); transform.unpipe(wsDuplex);
    // Leave error listeners until both sockets have closed, so an asynchronous
    // destroy(error) event remains handled alongside the native route's listeners.
    transform.destroy(); emsSocket.destroy(error); wsDuplex.destroy(error);
    release();
  };
  const onSocketError = error => stop(error);
  const onSourceClose = () => { sourceClosed = true; stop(); release(); };
  const onDestinationClose = () => { destinationClosed = true; stop(); release(); };
  const onTransformClose = () => { stop(); release(); };
  transform.on("error", stop);
  transform.on("close", onTransformClose);
  emsSocket.on("error", onSocketError); wsDuplex.on("error", onSocketError);
  emsSocket.once("close", onSourceClose); wsDuplex.once("close", onDestinationClose);
  emsSocket.pipe(transform).pipe(wsDuplex);
  return transform;
}

module.exports = { UbvAacClockTransform, UbvClockCompatibilityError, matchingAdts,
  MAX_RECORD_BYTES, CANARY_CAMERA_ID, wireOutgoing };
