# Optional Frigate class union

The pilot adds a second source for an existing Protect camera. Reolink continues
to provide its own genuine AI classifications. Frigate contributes only
confirmed `data.type="object"` events with `false_positive=false`. Frigate 0.18.1
can leave its legacy false_positive/top_score columns NULL while storing accepted
object data in `data`. Explicit NULL is supported only with the real object type
and a valid nested `data.top_score`; the original NULL and acceptance basis remain
in provenance. A missing flag, malformed nullable object data or an explicit true
flag cannot become a supported detection. Generic motion,
manual timeline entries, unknown types and unsupported labels cannot
create a supported class. Inference and video decoding remain in Frigate, not
on the Protect console. The native adapter remains pinned to Protect 7.3.70.

The supported label map is `person` to person; car, bus, truck, motorcycle and
bicycle to vehicle; dog, cat, bird, horse, sheep, cow, elephant, bear, zebra and
giraffe to animal. These are mappings for labels actually emitted by the chosen
model and enabled in Frigate, not a promise that every model detects every animal.

Version 1.4 accepts real `data.type="audio"` events only with a finite nested
`data.top_score` from 0 to 1 and an explicit false or NULL legacy false-positive
flag. Labels map as follows: bark to alrmBark, speech to alrmSpeak, shatter to
alrmGlassBreak, siren to alrmSiren, honk to alrmCarHorn, and smoke_detector or
fire_alarm to alrmSmoke. The last class describes an audible alarm, not visual
smoke or carbon monoxide. Generic crying is deliberately excluded; the specific
Reolink cry signal supplies alrmBabyCry. Audio and visual classes remain separate
native intervals and use the existing camera/class/time union for duplicates.

Supported source details enrich the same native visual event and object:
bicycle becomes vehicleType:bike, motorcycle and bus retain their vehicleType;
cat, dog and bird become species. Generic car is not inferred to be a sedan,
and Reolink dog_cat does not identify a species. All supported detail values are
searchable. A scalar native attribute is emitted only for a single unambiguous
value. Metadata updates preserve the existing event, object and thumbnail IDs,
recorded pixels and timestamp. Source diagnostic lists are bounded separately
from the full set of detail evidence.

After audio inputs have entered the journal, keep version 1.4 or later. Disable
audio capture and capability flags for a scoped rollback; retain the journal,
existing native events and the union-aware binary. Do not blindly downgrade to
an older binary that rejects audio classes. NAS audio configuration must also
update the host supervisor's configuration hashes while its own service is
stopped, then use its normal managed start path.

## Private interface

The existing root-owned mode-0600 configuration may contain:

```json
{
  "frigate": {
    "url": "http://192.0.2.10:18799",
    "bearerToken": "insert-a-separate-private-token-on-the-console",
    "cameraMap": {"front_camera": "111111111111111111111111"},
    "pollSeconds": 2,
    "historySeconds": 300,
    "overlapSeconds": 30,
    "staleSeconds": 120,
    "finalizeSeconds": 4
  }
}
```

This is a partial configuration, retaining the existing bridges and credentials.
Every target camera must already be in the bridge list. The interface uses
numeric HTTP(S) hosts, no redirects, no proxy environment and no credentials in
URLs. Tokens never enter event provenance, logs or command arguments. Use a
dedicated read-only projection restricted to the console's source address; do
not expose Frigate's unrestricted internal API to the LAN. Plain HTTP is suitable
only on the explicitly restricted trusted local path. The shared HTTP helper's
HTTPS mode does not validate certificates; do not treat it as authenticated TLS.

Required endpoints are `/health?camera=...` with boolean `healthy=true` and the
exact camera name echoed in `camera`, filtered
`/api/events?camera=...&after=...&before=...&limit=200&include_thumbnails=0`, an
`in_progress=1` list, and `/api/events/{id}` for previous active IDs. The health
projection must check the actual camera processing and Coral process, not just
the availability of Frigate's web server. Each mapped camera has its own health
gate, polling worker and expiry. An unhealthy camera does not prevent healthy
cameras' history from advancing or detections from arriving. Aggregate service
health still reports the failure. The projection can retain global `/health`
for compatibility with older single-camera collectors. Event fields are id, camera, label,
start_time, end_time, false_positive, optional top_score and `data.type` with
optional `data.top_score`. The contract follows Frigate 0.18.1's event API.

## Persistence and union

The original bridge cursors, payload rows, source epochs, SQLite journal and
native outbox are retained. Additional `fusion_*` tables track each source's
intervals, an independent union bridge watermark and the completed Frigate
history watermark. Enabling a camera adopts
its existing intervals and native IDs, including open intervals, rather than
creating a second detection for already active Reolink AI. Other cameras retain
the original collector and interval behavior.

Frigate history polling re-reads an overlap, separately fetches current tracks
and refreshes saved active IDs until their real end is observed. Full 200-row
history windows are split with overlapping boundaries because upstream uses
strict after/before comparisons. A saturated indivisible window or exhausted
request budget fails the batch without advancing its cursor. A batch and its
watermark commit atomically; restart replay is idempotent. Network jobs have
body limits, total deadlines and a 32-request/12-second poll budget. They do not
block subsequent Reolink collection passes. Catch-up is bounded to 60 seconds
of source history per completed poll, while live tracks are always checked.

Frigate HTTP history has no sequence number or retention-floor proof. An API
response cannot prove that upstream retention or deletion has removed no older
events. Long outages are counted as possible history gaps; health reports this
limitation rather than claiming lossless replay. A disappeared active event is
not invented as a clear. Its last genuine state expires after the configured
timeout. Unhealthy detector/API polling also stops refreshing the source state;
Reolink collection continues and only that source expires.

The output covers the temporal union of each camera/class's source intervals.
A Reolink clear cannot close a still-active Frigate detection, or conversely.
Different classes and separated time intervals remain separate. A brief
finalization delay gives the other poll time to discover an overlapping event;
the actual source end is retained. Source interval details remain in SQLite;
native provenance includes up to 16 contributing intervals and their total
count. Unknown confidence, boxes, tracks and spatial matches remain omitted.
Source scores may appear only as provenance, not fabricated Protect confidence.

Delayed genuine history can correct the bounds of an owned union event.
`identityStart` remains immutable so event/object/track/thumbnail IDs stay stable.
Retention tombstones, ownership, camera, classes, favorite state and the Protect
schema/version guards remain enforced. When delayed history joins two already
published native events, both existing IDs are retained as adjacent, nonoverlapping
partitions. This preserves their combined coverage without deleting vendor
history; it does not promise one timeline tile for every late-connected component.
This is class/time deduplication, not proof that two systems saw the same person.

## Disable and rollback

Disable the pilot by removing only the optional `frigate` configuration and
restarting the service with this release. External source intervals close once
with an explicit disabled-source estimate; still-active Reolink intervals retain
their state. The bridge list, six camera IDs, recordings and all source/outbox
history remain. The original Reolink path resumes. Re-enabling replays genuine
bridge payloads collected during the disabled period from its independent union
watermark, so an already-received clear cannot reopen or extend an old interval.
Do not delete `fusion_*` tables or restore an old SQLite database over new history.

After union activation, do not use the standard deployment rollback to a
pre-union binary with this preserved journal. Older code does not understand
immutable identityStart, source-union corrections or truthful external/mixed
provenance; later media or lifecycle writes could create extra graph IDs.
Disabling the optional source on the union-aware binary is the supported pilot
rollback. A binary downgrade needs a separately reviewed journal/graph migration.
Re-enabling this release retains its saved source history and cursor; inspect
the reported history-gap and timeout state before assuming continuity.
