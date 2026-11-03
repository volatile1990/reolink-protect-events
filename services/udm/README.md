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

`nginx_guard.py --recipes PATH --check` verifies the existing owned query map and
plans three precisely owned live routes. Applying it copies the *current* native
Protect authentication block, retains unrelated locations, rejects overlapping
foreign routes and validates nginx before reloading. It never restarts Protect.
`--watch-seconds 45` handles bounded native regeneration after startup. Both
mutating helpers serialize their own operations and preserve root ownership.

Install these three scripts together in a root-owned mode-0700 directory. Their
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
