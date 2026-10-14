"""Load the pinned release-local JPEG decoder without changing system Python."""
import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
import sys
import threading

_LOCK = threading.Lock()
_VERIFIED = False


class VendorError(RuntimeError):
    pass


def verify_vendor(root):
    """Verify complete declared member contents before importing native code."""
    root = Path(root)
    manifest = root / "integrity.json"
    if root.is_symlink() or manifest.is_symlink() or not manifest.is_file():
        raise VendorError("decoder_integrity_missing")
    if manifest.stat().st_size > 256 * 1024:
        raise VendorError("decoder_integrity_invalid")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 1 or data.get("project") != "pillow" or data.get("version") != "11.3.0":
        raise VendorError("decoder_integrity_invalid")
    members = data.get("files")
    if not isinstance(members, list) or not 1 <= len(members) <= 500:
        raise VendorError("decoder_integrity_invalid")
    seen = set()
    total = 0
    for member in members:
        name = member.get("path")
        if not isinstance(name, str):
            raise VendorError("decoder_member_invalid")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or name in seen or not relative.parts:
            raise VendorError("decoder_member_invalid")
        if relative.parts[0] not in ("PIL", "pillow.libs", "pillow-11.3.0.dist-info"):
            raise VendorError("decoder_member_invalid")
        seen.add(name)
        path = root.joinpath(*relative.parts)
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            raise VendorError("decoder_member_invalid") from None
        for parent in (path, *path.parents):
            if parent == root.parent:
                break
            if parent.is_symlink():
                raise VendorError("decoder_member_invalid")
        if not path.is_file() or path.stat().st_size != member.get("bytes"):
            raise VendorError("decoder_member_changed")
        total += path.stat().st_size
        if total > 48 * 1024 * 1024:
            raise VendorError("decoder_budget_exceeded")
        if hashlib.sha256(path.read_bytes()).hexdigest() != member.get("sha256"):
            raise VendorError("decoder_member_changed")
    # Bytecode is created by Python after first use; other undeclared files are
    # rejected rather than silently importing an unverified extra module.
    actual = {str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p != manifest}
    if actual != seen:
        raise VendorError("decoder_member_inventory_changed")
    return data


def ensure_pillow():
    """Prefer the digest-verified release bundle; allow installed Pillow for development."""
    global _VERIFIED
    with _LOCK:
        if _VERIFIED:
            return
        root = Path(__file__).resolve().parent / "_vendor"
        bundled = root.exists()
        if bundled:
            verify_vendor(root)
            if "PIL" in sys.modules:
                loaded = Path(sys.modules["PIL"].__file__).resolve()
                try:
                    loaded.relative_to(root.resolve())
                except ValueError:
                    raise VendorError("decoder_import_origin_changed") from None
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        try:
            module = importlib.import_module("PIL")
            importlib.import_module("PIL.Image")
        except ImportError:
            raise VendorError("decoder_unavailable") from None
        if bundled and module.__version__ != "11.3.0":
            raise VendorError("decoder_version_changed")
        _VERIFIED = True
