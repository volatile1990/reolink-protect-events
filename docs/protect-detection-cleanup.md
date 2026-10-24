# Protect 7.3.70 detection cleanup

Repair of 24 October 2026 for permanently active camera detection borders.
The exact native module 211088 removed stale DS tracking entries after five
minutes, but decremented only the aggregate event count. Motion and smart
detection counters remained active. Later end messages were ignored because
their tracking entry had already been removed. This also affects native G6
cameras and is independent of the Reolink publisher.

The reviewed correction calls the existing module 954843 `onDsEventEnd`
for each expired entry, without `eventData`. This balances all existing
counters and sends the ordinary state notification without inventing any
database event end or altering recorded history. The five-minute cutoff and
minute schedule remain unchanged. Existing leaked process state requires one
Protect service restart; camera and media-server restarts are unnecessary.

The corrected service SHA256 is
`e9d90673366b3a5fcb8a01ba967d485881bbef273769d6c0fabc98fafdfd800c`.
The previous exact service was
`099e9dc702bce8145b83e54c3f7f41c13c55b114c6e59514fc592087631646fe`.
The compatibility constants also pin the corresponding Automatic and Nginx
startup companions. The recovery runtime sources and manifest, Automatic
ownership receipt and its patched source must be advanced together.
Unknown vendor builds remain unsupported and are preserved.

The local operation sources, exact reversible patch, ten regressions using
the real extracted native modules and startup-guard branch tests are under
`output/protect-detection-stuck-20261024` in the infrastructure workspace.
The logs establish this timeout for Eingang and Door Hub on 22 October.
