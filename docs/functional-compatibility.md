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
  settings, lease, restoration and attempt-budget checks. Read-only media checks
  remain available when a recovery-specific mutation prerequisite is absent.
- Reapplying an owned vendor adaptation requires one unambiguous original or
  already-applied anchor per transformation. Whole vendor-file hashes and package
  versions do not determine whether that local transformation applies. Ambiguous
  edits are refused without overwriting unrelated vendor changes.

An actual stream failure, stalled recorder, failed event publication or broken
control request is reported for its affected function. A healthy function is not
marked failed merely because another integration component is unavailable.

The motivating incident on 3 November 2026 was a Protect 7.3.70 to 7.3.74 update.
Seven cameras and all fourteen recording ranges continued to advance, while old
version checks stopped monitor samples and native event delivery. The checks
above replace those version-based operational gates.
