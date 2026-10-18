# Multiple visual types in one Protect event

Version 1.5 adds an optional publication layer after the existing per-class
Reolink/Frigate fusion. Source pushes, independent class lifecycles and their
SQLite intervals remain authoritative. The new layer changes the events sent
to Protect, not camera recognition or video recording.

Enable with the scoped Events installer:

```console
python tools/deploy.py install --events-only --group-visual-events --group-max-span-seconds 120
```

The corresponding private runtime configuration is:

```json
{"eventGrouping":{"enabled":true,"maxSpanSeconds":120}}
```

Only person, vehicle and animal detections from the same camera with genuine
positive temporal overlap share an event. Mere proximity in time does not join
unrelated clips, and this rule does not claim that two detections are the same
physical object. Audio remains in its existing independent events. The default
maximum group span is 120 seconds, configurable from 30 to 300 seconds. Longer
continuous activity is divided into bounded presentation partitions; these
boundaries are explicitly administrative, not fabricated camera clear signals.
For a still-open long track, a continuation needs a genuinely new detection
start or a real end confirming coverage beyond the boundary. Merely polling an
old open track does not create speculative continuation events. A later real
end can add its verified overlap to an already published continuation.

A live group can begin with one type and gain another type under the same event
ID. Protect receives the complete sorted `smartDetectTypes` array, a separate
searchable object for each type, event/object labels, and the exact class
intervals in provenance. Each object's detection time is its own first genuine
class time, rather than the group's start. The source intervals are retained
in full in SQLite; bounded diagnostic lists are not the classification evidence.
The adapter's existing strict identity rule remains for ordinary events. Only
the explicit visual-group protocol permits monotonic addition of visual types
and updates all dependent graph rows in one transaction.

The once-persisted activation boundary and permanent source enrollment prevent
historical or already published events from being silently replaced. An older
open event continues on its existing path. Late history keeps published group
IDs stable and cannot recreate events deleted by Protect retention. Favorites
and locks remain under Protect's control. The first recorded preview remains
pinned; a frame is only associated with a class when its actual timestamp falls
within that class's genuine intervals. No object boxes, image crops or unknown
confidence values are fabricated.

For the delivery on 16 October 2026, the original vehicle interval
18:32:14.444–18:33:21.784 and person interval
18:32:18.586–18:33:11.380 form one bounded group carrying both types. This is a
read-only replay example; enabling the feature does not rewrite that historical
pair. The iOS app decides how many icons it draws; storing both types does not
promise two visible icons in every timeline layout.

## Operation and rollback

Once a group has been published, later source finalization preserves its bounded
member association. For example, an initially open person source can later clear
to a time range separated from an animal source by a genuine short gap. The
published event keeps both types, while `classIntervals` records each exact range
and the uncovered gap remains uncovered. `publishedGroupSticky` and
`stickyGroupingReason=source_finalization_gap` explain this case. A new source
located solely inside that gap does not join the group. Unpublished groups still
require positive overlap, and the 120-second publication boundaries remain.

This prevents an already published native type from being withdrawn by a delayed
clear. The native writer still rejects class removal. An older persisted split
that has already produced two native IDs requires an explicit scoped journal
repair; it must not silently delete the second published ID or rewrite sources.

The Events-only path preserves the existing media-monitor service, thumbnail
settings, cameras, bridges and Protect process. The installer backs up the
private configuration and a consistent journal before activation. Monitor and
camera recordings do not need restarting for this change.

After a source has joined a group, do not run an old binary that cannot read the
group projection. A legacy outbox would expose the suppressed source intervals
again. The installer rejects that rollback. To stop grouping new events, retain
the compatible runtime and set `eventGrouping.enabled` to false. Existing
enrolled groups still finish and deliver their pending revisions. Do not restore
an old journal or remove enrollment rows as a routine rollback.

## Explicit historical merge

Version 1.5.1 also supports immutable, explicitly requested historical groups.
They have an operation ID, exact source IDs and digest in `visual_group_manual`
and are excluded from automatic reprocessing. This does not lower the global
activation boundary or reset original source acknowledgments.

The guarded historical-pair writer retains the vehicle event ID and its real
preview, object and track IDs. It accepts only a complete snapshot of two closed,
unlocked, unfavorited, owned events with genuinely overlapping person/vehicle
intervals. It locks and checks the event and graph snapshots again, changes the
retained event to the validated multi-type contract, writes the complete graph,
then removes only the replaced person event within the same PostgreSQL
transaction. No video or recording table is modified. Private graph/image and
consistent journal backups are required before applying an operation.

The coordinating operator tool pauses only Events while adding the explicit
manual journal membership and performing that bounded native transaction. It
keeps the current journal, source rows, cursor tables, selected pixels and global
configuration. The group starts with a nonzero notification revision so its
delivery is a historical update, not a new event-start alarm. Resume decisions
use the durable operation receipt and actual native state after uncertain
responses; the guarded pair transaction itself must not be blindly replayed.

After manual groups exist, rollback and direct installation also require the
verified manual-group schema capability. An older automatic-only 1.5.0 runtime
is not a compatible target. Normal automatic grouping and retention continue for
other events; original manual-member data is retained until the whole group can
be safely pruned.

Meaningful release checks include the actual delivery replay, live type
expansion, two independent SQLite connections, media/acknowledgment/retry routes,
class times, long-track partitions, late history, retention and favorite guards,
and the real PostgreSQL transaction and search-label contracts in the isolated
test database. Production verification uses genuine events and GET/read-only
database checks; it never creates synthetic detections in the home timeline.

## Grouping change tracking

Version 1.5.5 skips historical grouping scans for commits that only update source
cursors, counters, media attempts or Frigate poll state. A private, additive
`visual_group_changes` row and SQLite triggers track actual grouping inputs,
including writes by another connection or an administrative operation. A random
transactional token avoids reusing a cached generation after rollback or
savepoint replay. Relevant input changes force recomputation even when only
provenance, raw fusion bounds or manual membership changed. Delivery-only group
acknowledgments do not change group shape; subsequent input changes read their
latest publication state.

Each pass checks the schema cookie and exact table/trigger definitions, so a
deleted or replaced tracking trigger is repaired under the existing writer lock.
Definitions are checked even when a rolled-back schema cookie is reused. Source
collection, native delivery, Frigate polling, health publication, retry deadlines
and group time boundaries retain their existing cadence. No journal rows, media
or history are removed. The previous 1.5.4 runtime safely ignores the additive
tracking objects; its existing group/manual compatibility rules still apply.
