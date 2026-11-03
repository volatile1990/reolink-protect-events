# Functional compatibility

Camera health describes observed operation, not a list of approved package
versions. A Protect update or changed vendor-file hash is not a camera failure.

- Monitoring verifies source freshness, actual UBV/fMP4 media, camera connection
  and recording progress. It does not require a package-version or nginx-hash
  match before attempting these read-only checks.
- Native publication verifies the required database columns, types and unique
  index semantics. Camera identity, event ownership, tombstones, idempotency and
  the restricted SQL transport still govern every write. Package metadata is
  informational; changes invalidate cached schema evidence and missing metadata
  causes a fresh check rather than a version alarm.
- Readiness is independent of historical UI/AAC file receipts. Those receipts
  remain available as `legacyPatchOwnership` diagnostics without disabling an
  otherwise functional event adapter.
- Recovery requires real, repeated media failures and retains its identity,
  settings, lease, restoration and attempt-budget checks. Complete nginx-file
  hashes do not authorize or block the narrowly scoped `forceTcp` transaction.
- Reapplying an owned vendor adaptation requires one unambiguous original or
  already-applied anchor per transformation. Whole vendor-file hashes and package
  versions do not determine whether that local transformation applies. Ambiguous
  edits are refused without overwriting unrelated vendor changes.

An actual stream failure, stalled recorder, failed event publication or broken
control request is reported for its affected function. A healthy function is not
marked failed merely because another integration component is unavailable.

Strict fMP4 continuity remains visible as `checks.continuousFromFirstFragment`.
Operational health uses `checks.functionalTimeline` together with real video,
audio, payload-size, freshness, overlapping-clock, transport and effective-flag
checks. Only proven `mp4a` audio with consistent 960/1024-sample blocks permits
small timestamp corrections. At 16 kHz with 1024 samples the bounds are 4 ms per
correction, 8 ms maximum accumulated drift and 20 ms total corrections in the
bounded probe. Video and unknown audio retain exact continuity. Large or repeated
jumps, wrong clock origin, missing audio, stalls and malformed payloads fail.

The motivating incident on 3 November 2026 was a Protect 7.3.70 to 7.3.74 update.
Seven cameras and all fourteen recording ranges continued to advance, while old
version checks stopped monitor samples and native event delivery. The checks
above replace those version-based operational gates.

Validation for source `262d277`: the full local Windows suite passed; Linux
discovered 813 Python cases (31 expected skips), compilation, both archive syntax
checks and 24 archive tests passed on the existing household server. Additional
read-only live checks verified 22 UBV profiles, fourteen advancing recording
ranges, twelve new recordings with actual video/PCM decoding, twelve Controls
GETs and thirteen checks of an actually published native event. Media and decoder
logs stayed in RAM. Tests ran locally or on existing owned hosts.
