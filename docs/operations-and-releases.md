# Own releases and Protect media monitoring

The bridge and Events repositories are maintained by this installation's owner.
An update means deploying newly developed, committed code from those repositories.
The tools do not poll for third-party bridge/Events updates or develop changes by
themselves. Protect and DSM firmware upgrades remain separate operations.

## Automatic local release trigger

`tools/install_update_hook.py --config <local-controller.json>` installs an owned
`pre-push` hook in both configured repositories. It preserves any unrecognized
existing hook. A local push of the checked-out commit to `main` runs the entire
release controller before Git sends the ref update; other branches and ordinary
file editing do not trigger deployment. Tests or production verification failures
block the push. A second push of the same two source trees verifies the actual
six NAS image IDs, Events package ID, active services and current camera health
before reusing the successful receipt. A separate manual rollback is reported
as deployment drift. A crashed running transaction resumes its existing receipt,
including a crash after clearing maintenance but before the final commit.

The trigger runs on the home computer with its existing trusted SSH alias and
external protected NAS connector. It is not a GitHub-hosted deployment job; a
push from another computer does not have this local hook. No remote account
password, private key or console configuration is copied into either repository.

Example local controller configuration (paths and an SSH alias, no credentials):

```json
{
  "bridgeRepo": "/path/to/reolink-bridge",
  "eventsRepo": "/path/to/reolink-protect-events",
  "connector": "/outside/repos/protected-nas-access.py",
  "sshAlias": "unifi-dream-machine",
  "ffmpeg": "/path/to/ffmpeg",
  "ffprobe": "/path/to/ffprobe",
  "dependencyCache": "/path/to/public-wheel-cache",
  "stateDirectory": "/path/to/local-release-receipts"
}
```

The connector implements `nas_execute(command, payload, sudo=True, timeout=...)`;
it obtains access from its own protected store. Keep the controller configuration
outside Git. Python 3.9+, Git, SSH, FFmpeg, FFprobe and Pillow are needed on the
controller. The console uses a digest-pinned ARM64 Pillow 11.3.0 wheel bundled
inside each release; its system Python and package manager are unchanged.

```console
python tools/protect_ops.py assess --config /path/to/local-controller.json
python tools/protect_ops.py update --config /path/to/local-controller.json
python tools/protect_ops.py status --config /path/to/local-controller.json
python tools/protect_ops.py resume --config /path/to/local-controller.json --run /path/to/receipt
```

## Events-only release

For a change confined to native event import, install a clean, committed Events
package without running the six-bridge release controller:

```console
python -m unittest discover -s tests
python tools/test_postgres.py
python tools/deploy.py install --events-only --dependency-cache /path/to/public-wheel-cache
python tools/deploy.py status
```

This path stages and verifies the same immutable package and ARM64 decoder, then
validates the private configuration with that package's runtime before stopping
Events. It backs up the Events unit, private configuration, deployment metadata
and a consistent SQLite journal. It restarts only
`reolink-protect-native-events.service`; the media-monitor unit and process,
thumbnail selection, bridge containers, camera settings and Controls remain as
they were. The active configuration must already match the verified camera
mapping. The regular installer retains its existing monitor installation and
automatic-thumbnail defaults.

The low-level installer can separately pin a pre-existing six-camera Frigate
`ConnectionRefusedError` outage through `existingFrigateFailure`. This requires
Events-only scope without a monitor, grouping or startup-options change, current
configuration/deployment digests, and a server-validated failure fingerprint.
After restart, all six Reolink sources must have fresh successful polls, native
delivery must be ready, the outbox must be empty, and error counters must remain
unchanged. The result explicitly reports
`deploymentAcceptance: events-native-ready-existing-frigate-failure`; overall
`health.healthy` stays false. The ordinary installer and CLI still require full
health. This option neither starts Frigate nor clears its NAS protection latch.
Rollback of such a release requires an explicit low-level `owner` and that
owner's current maintenance lease, in addition to the current package digest.
Events-only writes and rollback check all owned files and the lease throughout.

For changes to the owned media monitor as well, explicitly add `--update-monitor`
to this Events-only installation. That backs up, replaces and restarts both owned
units from the same release while preserving thumbnail settings and the live
journal. It does not invoke the NAS/six-bridge release controller. Rollback restores
both prior units and configuration; source journal and monitor repair budgets stay
current.

An optional public JSON file can enable the fMP4 startup gate during that same
transaction:

```console
python tools/deploy.py install --events-only --update-monitor --fmp4-startup-config /path/to/public-startup-options.json --expected-config-sha256 CURRENT_PRIVATE_CONFIG_SHA256 --expected-deployment-sha256 CURRENT_DEPLOYMENT_JSON_FILE_SHA256 --dependency-cache /path/to/public-wheel-cache
```

The JSON contains `enabled: true`, `fullGopCameraIds` and `nginxFilePins` (path/SHA256
pairs). The full-GOP allowlist is limited to the reviewed Eingang
`6ac8ae7001ab6d03e4006410`, Garage `6ac83fed00bd6d03e4001b81`, Garten
`6ac844bf02026d03e4001f5f`, Vor dem Haus `6ac8ae7102b76d03e4006447`, Neubau Eingang
`6ac83993001a6d03e4001690` and Hintertür `6ac844bd01096d03e4001f22` IDs.
Enable an exception only when its actual frontend scope has been reviewed and
freshly pinned. It requires exact current hashes for
`/etc/nginx/nginx.conf`, `/ssd1/.data/unifi-core/config/http/shared-runnable-protect.conf`
and `/ssd1/.data/unifi-core/config/http/upstream-protect_api_backend.conf`. Obtain
those from the verified frontend plan and fresh readback, not from an arbitrary
changed configuration. Symlink parents and changed files invalidate the gate.
Only the private `fmp4Startup` field is added or replaced, after the whole private
configuration digest matches; backup, file fsync and parent-directory fsync precede
activation. Monitor upgrades also require the current deployment JSON file digest;
both units, configuration and metadata are checked again before any stop and each
owned write. A later conflicting edit blocks automatic overwrite and rollback;
the maintenance lease is retained for review.

To enroll subsequent visual intervals in the grouping projection, explicitly
enable it during that scoped installation:

```console
python tools/deploy.py install --events-only --group-visual-events --group-max-span-seconds 120 --dependency-cache /path/to/public-wheel-cache
```

The span limit accepts 30–300 seconds and defaults to 120. These options add only
the private `eventGrouping` setting, with `enabled: true` and `maxSpanSeconds`.
Credentials stay on the console and reach the staged validator only through
stdin. The deployment receipt records its Events-only scope and the presence
of the manifest-verified grouping runtime.

Manual rollback requires the current package digest:

```console
python tools/deploy.py rollback --expected-digest CURRENT_PACKAGE_SHA256
```

Once the journal contains `visual_group_members`, rollback to a runtime without
that projection is rejected before any service stops. To stop new enrollment,
set `eventGrouping.enabled` to `false` in the private console configuration and
restart Events while retaining the compatible release. It continues servicing
existing groups. Do not restore a historical journal or delete memberships to
bypass this guard.

If activation fails after groups were enrolled and the prior binary cannot
service them, automatic recovery keeps the compatible Events release, restores
the prior configuration with new enrollment disabled and checks fresh native
health. The failed installation reports this recovery explicitly; it does not
claim an old-binary rollback. An Events-only recovery without `--update-monitor` leaves the monitor
untouched. Ordinary pre-enrollment failures restore the prior Events release.
If success or healthy compatible recovery cannot be confirmed, the Events-only
CLI retains its owned maintenance marker and reports `maintenanceOwner` with
`maintenanceRetained: true`. Inspect and verify recovery before clearing that
exact marker; no successful installation is reported in this case.

## Release gates and restoration

1. Require clean committed source trees. Freeze UTF-8 sources with LF line endings
   and record the exact archive/package hashes and Git revisions. Binary bytes
   remain unchanged. Freeze the actual remote worker source for restoration too.
2. Run both repositories' offline contracts. Check the currently audited Protect
   7.3.70 database, camera scope and owned UI/AAC layers without changing them.
3. Verify six fresh video sources, eleven advancing recording profiles, all native
   High/Low/Automatic modes and real video/audio decoding of all eleven live and
   recorded profiles. Missing decoders or incomplete coverage stop the update.
   Each recorded probe requests a fixed 24-second window, allowing room for
   the observed variation in Protect export duration while still requiring at least
   19 seconds in both delivered tracks. Five seconds of video frames and AAC
   decoded to PCM must pass the existing codec, dimensions, warning and 350 ms
   audio/video timeline checks. The entire requested window must follow a
   camera's activation; an older overlapping window cannot pass its gate.
   An export timeout, HTTP 500/503, or one correctly shaped video track with
   missing AAC can request exactly one replacement export before payload decode.
   The replacement window must begin strictly after the failed window ends and
   satisfy the original activation/recovery boundary. Readiness is bounded to
   120 seconds with fresh source/index checks and no open viewers while waiting.
   Both attempt projections remain in the report. A persistent missing audio
   track, malformed media, changed codec/dimensions, timeline mismatch or actual
   decoder warning remains a failed gate; this retry never repairs a recorder.
   When a recorder repair is needed, it must also follow that repair's successful
   original-setting/media verification, keeping reconfiguration out of the probe.
4. Build bridge audit and production images from the same frozen ZIP on Synology.
   Run real .NET self-tests, Protect contracts and the hardware low-quality test
   in isolated containers; require the production application DLL to be identical
   to the tested DLL. Preserve every running bridge during the build.
5. Set an owned maintenance marker. Update one camera at a time, preserving
   complete configuration, replay state, runtime identity and Compose settings.
   Gate each camera on native playback and real decoded clips recorded entirely
   after activation. The first camera is the canary for the remaining five.
   One persistent missing recorded AAC track can use the same single-camera
   repair budget as a native failure. It requires two disjoint exports containing
   exactly the expected video, clean live video/audio decodes and freshly checked
   healthy sources/native streams. Other recording or decode faults remain hard
   failures. After repair, native playback and new recorded AV must pass again.
6. Install the Events release and separate media-monitor service. Back up service
   files, private configuration and a consistent SQLite source journal. Enable
   automatic thumbnail selection for new events. Verify compatibility, all media
   profiles and genuine imported event evidence again before clearing maintenance.

Successful/failed steps have local public receipts and private host checkpoints.
On a failure, restore only this rollout's bridge images and owned service/config
files after comparing their current state with the receipt chain. **Keep the
current Events journal and Protect database**; restoring an old source journal
would discard genuine events received during the rollout. The SQLite snapshot is
a disaster-recovery backup, not part of routine rollback.
Restoration's recorded probes also require their entire window after the
original images have been restored, keeping restart intervals out of that proof.

If restoration or its verification is inconclusive, the controller retains the
owned maintenance marker and reports failure. Resume finishes that restoration
using the frozen workers. OS locks release automatically after a controller
crash. A mismatched receipt, foreign maintenance marker or configuration drift
requires investigation; the controller never resets unrelated camera settings.
Every charged recorder repair also needs an explicit original-TCP restoration
receipt before maintenance can clear. Healthy playback alone does not supply
that proof after a missing or failed repair response. The triggering camera
health row is retained before dispatch for diagnosis.

A resume can use a corrected read-only health checker from the current clean
repository; its source revision/hash is recorded separately. Every mutating
rollback worker still comes from the original frozen bundle. A fresh clip waits
up to three minutes for post-activation recording-index readiness. Decode errors
remain failures, and per-camera health/decode evidence is retained before gating.
An already successful bridge hardware audit can be reused only for the exact
same clean source revision, canonical ZIP hash and version. The NAS validates
its immutable image ID, tag and source labels again before deployment. An Events
checker correction therefore does not need another identical bridge build.

## Continuous monitor

`reolink-protect-media-monitor.service` uses the same private console config as
Events and writes its own state under `/data/reolink-protect-monitor`. It samples
source readiness, current audio metadata, camera connection and recording progress
every 30 seconds. One bounded eight-second Automatic stream probe runs at a time,
roughly every 50 seconds; all six cameras rotate in about five minutes. The global
rotation keeps its own cursor/deadline and cannot be consumed by repeated suspect
or exhausted-budget cameras. New connection epochs and suspect media receive
additional probes between global slots, with a 30-second per-camera minimum.
Successful results expire after 15 minutes and are invalidated by source epoch or
source/recorder failure. `healthy` requires fresh active coverage; `verifying`
means quick source/recorder checks passed but active coverage is incomplete.
Quiet cameras need no detections to pass these checks.

With `fmp4Startup.enabled`, each camera alternates its UBV read with one 12-second
fMP4 startup read, so both paths rotate over all six in about ten minutes, with
only one new viewer at a time. The full acceptance gate adds one serialized fMP4
Automatic read per selected camera. It checks the very first fragment, media-clock
continuity, epoch origin, overlapping track clocks, actual elapsed progress and freshness;
actual raw or split-framed `mdat` bytes must equal the declared sample sizes, and
every counted sample has positive size. Metadata parsing has a global track/sample
work limit as well as a byte limit. Unsupported padding stays unverified;
the first audio/video clock starts may differ by up to five seconds for a four-second
full GOP, with at least two seconds of shared timeline. This is not a lip-sync check;
with `allowPartialGOP=false`, fragment freshness allows its observed complete-GOP
duration plus one second, bounded to at most five seconds. Partial-GOP freshness
retains the three-second limit. All continuity, payload and progress gates remain;
no warmup hides a startup timestamp jump. Browser flags are wall clock, progressive,
extended metadata, 100-ms fragments and no zero rebasing. The probe uses native
loopback EMS TCP, with `allowPartialGOP=false` only for the pinned frontend
exception; it explicitly does not certify frontend authentication, UI quality
switching or handset playback. Pin drift reports `attention`, prevents stream
repair and cannot retain a green fMP4 result.

Both positive and negative probe evidence expire after fifteen minutes and are
bound to a known current source epoch. Expired errors prompt another active read;
they cannot authorize recorder repair. Failure streaks restart when the source
epoch changes, while persisted repair-attempt budgets remain intact. A fresh
fMP4-only packaging or clock failure remains degraded with `review_fmp4_startup`;
it never toggles a healthy UBV recorder or consumes its repair budget.

The monitor distinguishes unhealthy bridge input from stalled Protect playback.
For a healthy source with a repeated native failure it can perform the audited,
camera-scoped `forceTcp: null → true → null` recorder rebuild. The original setting
must be restored; fresh recording progress and a real Automatic stream are then
required. Settings for every other camera and the NVR are checked for preservation.
The temporary TCP phase must itself deliver a valid Automatic stream before
the original setting is restored. Both media phases have a 45-second budget and
at most three sequential eight-second probes, reserving bounded source/stream
setup time before dispatch. A later asynchronous `not ready` state after restoration
waits within the same budget, rechecking exact settings, healthy source and lease
ownership on every pass, without charging another viewer attempt or PATCH. Only a stream with zero WebSocket frames, zero
binary bytes, no tracks and no transport/parser error can wait for readiness.
Received corrupt bytes, invalid AAC, broken clocks or an unhealthy source fail
immediately. Every attempt rechecks fresh source media and the exact settings
digest; original-setting restoration still runs in `finally`. A lost PATCH
response requires reading back the exact temporary or original settings guard,
and a crash receipt restores the original setting before testing playback.
Attempts are charged before dispatch, limited to two per camera in 24 hours with
a 15-minute cooldown. Crash recovery first settles a pending original-setting
restoration. Source faults remain the NAS watchdog's responsibility.

Maintenance suppresses monitor probes and repairs. Only the controller holding
the exact marker owner can perform its explicit bounded recorder repair while
maintenance remains active. Unknown Protect versions are assessed read-only and
are never certified automatically. Normal collection continues according to the
existing runtime's version/schema guard.

The lightweight monitor validates delivered UBV frames/audio and timing; the
release controller additionally performs real FFmpeg payload decodes. Neither
check claims handset playback or sensor capture synchronization.
