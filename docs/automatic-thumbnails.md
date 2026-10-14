# Automatic recorded thumbnails

`thumbnailSelection.mode: "automatic"` chooses one genuine recorded Protect
snapshot from a small window inside a camera AI event. It compares image signal
quality: foreground change relative to the first usable candidate, sharpness in
changed areas, and clipping/exposure. It does not recognize a person, vehicle or
animal in pixels. The original camera classification, event start, source
timestamps, zones and confidence availability remain unchanged.

The scorer uses decoded 64 × 36 grayscale pixels. A median brightness adjustment
prevents a uniform lighting change from counting as foreground movement. The
image with the highest score wins; equal scores keep the earlier image. A moving
sharp foreground patch can score above a blurred patch or an empty start frame.
Camera movement, foliage, IR noise and an object already present in the first
frame can still affect the result. This is an image quality heuristic, not a
semantic object detector.

## Configuration

The production configuration must explicitly enable automatic selection. An
absent setting retains the earlier single event-start snapshot behavior.

```json
"thumbnailSelection": {
  "mode": "automatic",
  "maxCandidates": 4,
  "windowSeconds": 6,
  "settleSeconds": 3,
  "recordingLagMs": 1500,
  "historyDays": 30,
  "budgetSeconds": 8
}
```

| Setting | Allowed values | Meaning |
| --- | --- | --- |
| `mode` | `start`, `automatic` | One start snapshot, or bounded signal scoring |
| `maxCandidates` | Integer 2–5 | Maximum recorded snapshot requests per selection |
| `windowSeconds` | Integer 1–12 | Maximum distance from the real event start |
| `settleSeconds` | Integer 0–12, at most `windowSeconds` | Wait for a small useful recorded window; an earlier real event end shortens this wait |
| `recordingLagMs` | Integer 0–10000 | Margin behind current UTC before requesting recording frames |
| `historyDays` | Integer 1–30 | Skip image work for older replay events |
| `budgetSeconds` | Finite number 1–12 | Total elapsed budget for starting additional snapshot requests/scoring |

The four default candidate timestamps are evenly spaced from the actual event
start to the earliest of its end, start + six seconds, or current UTC minus the
recording margin. A live event is never sampled in its future. Short intervals
can yield fewer distinct timestamps. The default settle period means a still
open event can get its image after about 4.5 seconds, while its native event is
delivered immediately.

## Dependency and resource bounds

The UDM release bundles Pillow 11.3.0 for CPython 3.9/aarch64 under the private
release directory. `vendor_support.ensure_pillow()` verifies the declared bundle
members before loading it. No system package installation, ffmpeg, continuous
video decode, external inference service or Coral is used. Development tests can
use an installed Pillow. Decoder integrity/load failure never starts an
unverified replacement decoder.

There is one dedicated thumbnail worker. It can hold at most one selection job
and does not use the native adapter, SQLite connection or DS update client from
that worker thread. Native event delivery continues on its owner thread while
recorded image requests run. Completed image writes use the existing native row
lock, ownership/camera/start/class checks and retirement guard, so removal or
retention cannot recreate an event. The native adapter still preserves favorites
and the first stored thumbnail.

Each JPEG is limited to 2 MiB and 16 million source pixels. JPEG draft decoding
must reduce the decode surface to at most one million pixels before conversion;
the scoring buffers contain only 2304 grayscale bytes per image. Only the first,
best and current full JPEG need remain in memory, up to 6 MiB combined. The
Pillow library and temporary decoder/Python allocations add process memory; this
is not an RSS ceiling. Each candidate GET has a total request timeout of at most
two seconds and the remaining selection budget. No new work starts after the
budget expires; a bounded JPEG decode already running can finish. History is
limited by age and one concurrent worker, with no periodic rescanning of
successful images.

## Stored evidence and fallback behavior

The selected `Thumbnail.timestamp` and native `detectedThumbnails.clockBestWall`
use the exact chosen recorded snapshot request timestamp. The event `start`
continues to describe the original camera AI event. Protect's snapshot response
does not supply an independently recovered sensor capture PTS, so evidence says
`timeBasis: "Protect-recorded-snapshot-requested-UTC"` and
`captureTimestampRecovered: false`.

`provenance.thumbnailSelection` records the chosen timestamp, number of planned
and decoded candidates, candidate request timestamps and signal components,
failure count, and `semanticObjectDetection: false`. `automaticSelected: true`
requires at least two candidates actually decoded and scored. A decision is
pinned in the journal before the native image write: a notification retry or a
crash after the native commit requests the same selected timestamp instead of
choosing another image. The source provenance fields are preserved, and adding
selection evidence does not change event revisions or bridge replay cursors.

When Pillow is unavailable, a valid recorded JPEG can still supply an honest
`mode: "recorded_fallback"` thumbnail with `automaticSelected: false` and a fixed
fallback reason. Insufficient valid candidates, decode failure or exhausted
budget are also explicit. Invalid JPEGs never become thumbnails. If no valid
recorded JPEG is available, normal bounded media retries apply; a current live
image is never substituted for a historical frame. An expired history window
ends image work without removing its native event. Existing stored images are
preserved through automatic mode activation.

Health counters distinguish `automaticallySelectedThumbnails`,
`fallbackThumbnails`, `expiredThumbnailWindows`, and a sample discarded because
a newly received real clear shortened its event (`thumbnailWindowChanged`). The
existing native/media error vocabulary remains categorical; URLs, owner headers,
credentials and raw exception text are never stored in selection evidence.

## Verification

`tests/test_thumbnails.py` checks real JPEG day/night sharp-vs-blur selection,
clipping, brightness shifts, exact requested sample time, event/source
preservation, bounded past/end/history/CPU request work, dependency fallback,
native delivery during a blocked image worker, deletion while loading, late
event clear, and pinned notification retries. The real JPEG tests require
Pillow and otherwise explicitly skip; a release validation run must supply the
decoder and have no such skips. Existing native adapter tests cover SQL graph,
favorite/retention preservation and first-thumbnail behavior.

For a production event, require `automaticSelected: true` and at least two
decoded candidates. Compare the chosen evidence timestamp to the persisted
native thumbnail timestamp and `clockBestWall`, and verify that its original
event start/classes/source provenance are unchanged. The chosen time can equal
the start when that frame wins; a different timestamp is not itself a quality
guarantee.
