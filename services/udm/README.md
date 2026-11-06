# Owned Protect adaptations

These sources replace the former loose, locally maintained runtime-restore and
nginx helpers. They do not move a separate application repository or include its
private configuration. Protect recordings and native databases remain untouched.

`prepare_legacy_recipes.py` reads the existing root-private restore manifest and
its verified owned source snapshots. It extracts only the precise transformations
which were already installed, retaining camera scope and optional-feature intent.
It writes one exclusive, mode-0600 recipe file in an existing root-private
directory. Recipes and old manifests remain on the console and must not be
committed, exported or printed.

`runtime_contracts.py --recipes PATH --check` reports whether each transformation
is present, applicable or structurally different. Without `--check`, it applies
only unambiguous transformations with a syntax check and a final byte comparison.
Dependent transformations are grouped; an incompatible group is left untouched
while independent functions remain available. The helper never restarts Protect
or prevents its native startup. Runtime health comes from actual function probes.

`nginx_guard.py --recipes PATH --check` plans restoration of the owned query map
and three precisely owned live routes even when firmware regenerated the root
configuration. The optional paired private fields `nginxOwnedArchiveMaps` and
`nginxOwnedArchiveRoute` retain the existing scoped archive bridge to port 7712.
`archive_recipe_fragments` extracts these fragments only from independently
verified historical snapshots and requires both existing ownership hashes.
Applying recovery copies the *current* native Protect authentication blocks,
retains unrelated locations, rejects overlapping foreign routes, validates
Nginx and reloads it. A failed transaction rolls back only its own unchanged
candidates in both files. It never restarts Protect.
`--watch-seconds 45` handles bounded native regeneration after startup. Both
mutating helpers serialize their own operations and preserve root ownership.
Missing native root/shared configuration is reported as `native_config_pending`
and retried within that window. Missing private recipes or source directories
remain errors. The existing path unit watches both native files and can restore
their owned fragments when Core generates them after the startup window.

## Required modules survive firmware replacement

`runtime_assets.py` is part of startup recovery, before the service/UI
transformations. The private `assets.json` beside `recipes.json` describes
exactly four owned dependencies: `protect-hook.cjs`, the two
`ubv-aac-clock-compat*.cjs` modules and `reolink-protect-connector.py`. Their
verified source files live in the adjacent private `assets/` directory.
Directories are root-owned 0700; the manifest and saved sources are 0600.
Restored runtime programs under `/usr/local/lib` are root-owned 0644.

Every row has `target`, `source` (the target basename), `sha256` and
`allowedBefore` (explicit hashes of older owned bytes, normally empty). No
additional target or arbitrary source path is accepted. Hashes apply only to
our own module bytes; Protect version numbers and complete vendor bundles do
not determine compatibility. Prepare the saved connector from the current
canonical `reolink_protect_events/connector.py`, not an older legacy snapshot.
Update the private saved sources and their manifest together when publishing
new owned module code. An unknown existing target is a conflict, not permission
to replace another operator's changes.

Before the first write, recovery checks the complete source set, current target
ownership, permissions, links and syntax. Missing files and their one approved
directory are restored atomically with compare-and-swap and directory fsync.
The runtime guard then verifies the installed dependencies before adding their
callers. If a required runtime module remains unavailable, only an exact,
unambiguous owned caller can be reversed so native Protect can start without a
dangling `require`. A bad saved copy alone does not remove callers whose current
installed modules still match their approved hashes. The report distinguishes
backup readiness from actual runtime readiness.

`runtime_contracts.py --recipes PATH --check` checks both the saved sources and
the installed dependencies without restoring files. The normal startup command
uses the same manifest and restores absent modules first. The existing
root-private recipe lock serializes both stages. The old `runtime_restore.py`
must not be reinstated: it also contains old complete vendor bundles.

Install all four scripts together in a root-owned mode-0700 directory. Their
startup commands use `python3 -B`. Replace only the existing owned runtime,
Automatic-input and nginx drop-ins; preserve native service configuration and
unrelated drop-ins. The separate Automatic-input pre-hook is redundant because
those four transformations belong to the runtime recipe transaction. Update the
owned nginx-regeneration service to call the new nginx helper as well.

Before applying a reviewed plan, acquire the existing monitor maintenance lease.
Activating changed service hooks requires one controlled Protect restart; record
that actual restart in the native-recovery budget and verify camera identity,
settings, recording progress, live video/audio, controls and event delivery.
Release only that lease after verification. A future version or complete vendor
hash change alone requires neither a restart nor an alert when the integrations
remain present and functional.
