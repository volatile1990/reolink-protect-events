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
4. Build bridge audit and production images from the same frozen ZIP on Synology.
   Run real .NET self-tests, Protect contracts and the hardware low-quality test
   in isolated containers; require the production application DLL to be identical
   to the tested DLL. Preserve every running bridge during the build.
5. Set an owned maintenance marker. Update one camera at a time, preserving
   complete configuration, replay state, runtime identity and Compose settings.
   Gate each camera on native playback and real decoded clips recorded entirely
   after activation. The first camera is the canary for the remaining five.
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

If restoration or its verification is inconclusive, the controller retains the
owned maintenance marker and reports failure. Resume finishes that restoration
using the frozen workers. OS locks release automatically after a controller
crash. A mismatched receipt, foreign maintenance marker or configuration drift
requires investigation; the controller never resets unrelated camera settings.

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
roughly every 50 seconds; all six cameras rotate in about five minutes. A new
source connection epoch prioritizes that camera. Quiet cameras need no detections
to pass these checks.

The monitor distinguishes unhealthy bridge input from stalled Protect playback.
For a healthy source with a repeated native failure it can perform the audited,
camera-scoped `forceTcp: null → true → null` recorder rebuild. The original setting
must be restored; fresh recording progress and a real Automatic stream are then
required. Settings for every other camera and the NVR are checked for preservation.
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
