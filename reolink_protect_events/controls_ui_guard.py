"""Bundled, read-only Controls v1 reversal contract; no sibling checkout needed.

Copied from the inspected 7.3.70 Controls contract. Only pure byte operations are
used by event-feature ownership checks; no control runtime or installer is loaded.
"""
from __future__ import annotations

import hashlib
import json
import re

VERSION = "7.3.70"
UI_VERSION = "7.3.26"
UI_HASH = "0ffb0344d673a7f6e04703e1ae6695b77d65d07ba16886cb06956e2581e5cff4"
UI_ROOT = "/usr/share/unifi-protect/app/node_modules/@ubnt/unifi-protect-ui-internal/dist"
LEGACY_ANCHOR = "!C||!F?null:d.isThirdPartyCamera?d.featureFlags.isPtz?"
ANCHOR = "(()=>{if(!C||!F)return null;let e=d.featureFlags.hasFisheye"
EVENT_GATE = "qq=(e,a,r)=>(!a||!!r.has(e.nvrMac))&&(!e.isThirdPartyCamera||!!e.isPairedWithAiPort)"
PREFIX_BEGIN = b"/* reolink-protect-controls:v1 begin */\n"
PREFIX_END = b"\n/* reolink-protect-controls:v1 end */\n"


class PatchError(RuntimeError):
    pass


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def camera_ids(ids):
    if not isinstance(ids, (list, tuple)) or not ids or len(ids) > 64 or any(
        not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9]{24}", identity) for identity in ids
    ) or len(set(ids)) != len(ids):
        raise ValueError("Explicit unique camera identities are required")
    return sorted(ids)


def event_gate(ids):
    selected = json.dumps(camera_ids(ids), separators=(",", ":"))
    return EVENT_GATE[:-1] + "||(" + selected + ".includes(e.id)&&e.featureFlags.hasSmartDetect))"


def insertion(ids, *, legacy=False):
    selected = json.dumps(camera_ids(ids), separators=(",", ":"))
    # C is camera:settings:edit; F is isAvailable in the inspected ConfigureCamera
    # component. The native API instance retains local/remote portal transport.
    return ("!C||!F||!d.isThirdPartyCamera||!" + selected +
            ".includes(d.id)?null:{id:\"reolink-controls\",defaultIsOpen:" + ("!1" if legacy else "!0") + ",header:\"Reolink-Kamerafunktionen\","
            "children:tT.createElement(window.ReolinkProtectControls.createPanel(tT),{cameraId:d.id,api:d.api})}," + (LEGACY_ANCHOR if legacy else ANCHOR))


def prefix(runtime=None):
    content = runtime
    if not isinstance(content, bytes) or not content or len(content) > 150_000 or PREFIX_BEGIN in content or PREFIX_END in content:
        raise PatchError("Invalid control runtime")
    return PREFIX_BEGIN + content + PREFIX_END


def validate_source(content, ids, *, feature_camera_ids=None, ui_hash=UI_HASH):
    """Confirm exact vendor bytes after undoing only the known event gate."""
    selected_features = camera_ids(feature_camera_ids or ids)
    if digest(content) == ui_hash:
        return "vendor"
    gate = event_gate(selected_features).encode("ascii")
    if content.count(gate) == 1 and content.count(EVENT_GATE.encode("ascii")) == 0:
        restored = content.replace(gate, EVENT_GATE.encode("ascii"), 1)
        if digest(restored) == ui_hash:
            return "native-events"
    raise PatchError("Protect UI differs from the inspected vendor/event integration hashes")


def patched_bytes(content, ids, *, runtime=None, feature_camera_ids=None, ui_hash=UI_HASH):
    camera_ids(ids)
    injected = insertion(ids).encode("ascii")
    runtime_prefix = prefix(runtime)
    if content.startswith(PREFIX_BEGIN):
        if not content.startswith(runtime_prefix) or content.count(injected) != 1:
            raise PatchError("Existing controls runtime or camera selection differs")
        source = content[len(runtime_prefix):].replace(injected, ANCHOR.encode("ascii"), 1)
        validate_source(source, ids, feature_camera_ids=feature_camera_ids, ui_hash=ui_hash)
        return content
    validate_source(content, ids, feature_camera_ids=feature_camera_ids, ui_hash=ui_hash)
    if content.count(ANCHOR.encode("ascii")) != 1 or b"reolink-controls\"" in content:
        raise PatchError("Inspected camera-settings insertion is absent or ambiguous")
    return runtime_prefix + content.replace(ANCHOR.encode("ascii"), injected, 1)


def unpatched_bytes(content, ids, *, expected_sha256, feature_camera_ids=None, ui_hash=UI_HASH):
    """Read-only reversal of an exact manifest-owned controls layer.

    The runtime is taken from the already hash-verified bytes, allowing an older
    installed runtime to be checked without requiring today's local JS runtime.
    The stripped native/vendor bundle must still match the audited base exactly.
    """
    camera_ids(ids)
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(content) != expected_sha256:
        raise PatchError("Controls layer does not match its trusted manifest hash")
    if not content.startswith(PREFIX_BEGIN) or content.count(PREFIX_BEGIN) != 1 or content.count(PREFIX_END) != 1:
        raise PatchError("Controls layer boundary is absent or ambiguous")
    boundary = content.index(PREFIX_END)
    runtime = content[len(PREFIX_BEGIN):boundary]
    body = content[boundary + len(PREFIX_END):]
    matches = [(insertion(ids, legacy=legacy).encode("ascii"), (LEGACY_ANCHOR if legacy else ANCHOR).encode("ascii"))
               for legacy in (False, True) if body.count(insertion(ids, legacy=legacy).encode("ascii")) == 1]
    if len(matches) != 1:
        raise PatchError("Controls layer insertion or camera selection differs")
    injected, anchor = matches[0]
    if body.count(anchor) != 1:
        raise PatchError("Controls layer insertion anchor is ambiguous")
    source = body.replace(injected, anchor, 1)
    validate_source(source, ids, feature_camera_ids=feature_camera_ids, ui_hash=ui_hash)
    if prefix(runtime) + source.replace(anchor, injected, 1) != content:
        raise PatchError("Controls layer cannot be reversed exactly")
    return source
