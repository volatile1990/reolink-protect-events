"""Deterministic public release packages with pinned, release-local dependencies."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.request
import zipfile


class ReleaseError(RuntimeError):
    pass


def canonical(content):
    if b"\0" in content:
        return content
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    return content.replace(b"\r\n", b"\n")


def member_name(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name or "\0" in name:
        raise ReleaseError("release_member_invalid")
    return name


def source_snapshot(root, require_clean=False):
    root = Path(root).resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"]))
    if require_clean and dirty:
        raise ReleaseError("release_requires_clean_sources")
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    digest = hashlib.sha256()
    count = 0
    private = {".git", "secrets", "state", "artifacts", "backups", "dist", "build", "_vendor", "__pycache__"}
    for name in sorted(set(names.decode().split("\0")) - {""}):
        member_name(name)
        p = root / name
        if set(PurePosixPath(name).parts) & private or p.name in ("config.json", "deployment.json", "health.json", ".env"):
            continue
        if p.is_symlink():
            raise ReleaseError("release_symlink_invalid")
        if p.is_file():
            digest.update(name.encode() + b"\0")
            digest.update(hashlib.sha256(canonical(p.read_bytes())).digest())
            count += 1
    return {"sourceRevision": revision, "sourceDirty": dirty, "sourceSha256": digest.hexdigest(), "sourceFiles": count}


def dependency_bytes(root, cache=None, downloader=None):
    manifest = json.loads((Path(root) / "dependencies/pillow-cp39-aarch64.json").read_text(encoding="utf-8"))
    required = {"project": "pillow", "version": "11.3.0", "python": "cp39", "architecture": "aarch64"}
    if any(manifest.get(k) != v for k, v in required.items()) or not re.fullmatch(r"[a-f0-9]{64}", manifest.get("sha256", "")):
        raise ReleaseError("dependency_manifest_invalid")
    url = manifest.get("url", "")
    if not url.startswith("https://files.pythonhosted.org/") or not 1 <= manifest.get("bytes", 0) <= 12 * 1024 * 1024:
        raise ReleaseError("dependency_manifest_invalid")
    name = member_name(manifest["filename"])
    if "/" in name or not name.endswith(".whl"):
        raise ReleaseError("dependency_manifest_invalid")
    cached = Path(cache) / name if cache else None
    if cached and cached.is_symlink():
        raise ReleaseError("dependency_cache_invalid")
    if cached and cached.is_file():
        content = cached.read_bytes()
    elif downloader:
        content = downloader(url, 12 * 1024 * 1024 + 1)
    else:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(url, timeout=45) as response:
                content = response.read(12 * 1024 * 1024 + 1)
        except Exception:
            raise ReleaseError("dependency_download_failed") from None
    if len(content) != manifest["bytes"] or hashlib.sha256(content).hexdigest() != manifest["sha256"]:
        raise ReleaseError("dependency_digest_mismatch")
    if cached and not cached.exists():
        cached.parent.mkdir(parents=True, exist_ok=True)
        with cached.open("xb") as f:
            f.write(content)
    return manifest, content


def vendor_members(manifest, wheel):
    members = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        for info in archive.infolist():
            name = member_name(info.filename)
            if info.is_dir():
                continue
            if info.external_attr >> 16 & 0o170000 == 0o120000 or name in members:
                raise ReleaseError("dependency_member_invalid")
            if PurePosixPath(name).parts[0] not in ("PIL", "pillow.libs", "pillow-11.3.0.dist-info"):
                raise ReleaseError("dependency_member_invalid")
            total += info.file_size
            if total > 48 * 1024 * 1024 or len(members) >= 500:
                raise ReleaseError("dependency_budget_exceeded")
            members[name] = archive.read(info)
    required = {"PIL/__init__.py", "PIL/Image.py"}
    if not required <= set(members) or not any(n.startswith("PIL/_imaging.") and n.endswith(".so") for n in members):
        raise ReleaseError("dependency_decoder_missing")
    integrity = {"schemaVersion": 1, "project": "pillow", "version": "11.3.0", "wheelSha256": manifest["sha256"],
                 "files": [{"path": n, "bytes": len(c), "sha256": hashlib.sha256(c).hexdigest()} for n, c in sorted(members.items())]}
    result = {"reolink_protect_events/_vendor/" + n: c for n, c in members.items()}
    result["reolink_protect_events/_vendor/integrity.json"] = json.dumps(integrity, sort_keys=True, separators=(",", ":")).encode()
    return result


def build_package(root, include_dependency=True, cache=None, require_clean=False, downloader=None):
    root = Path(root).resolve()
    source = source_snapshot(root, require_clean=require_clean)
    members = {}
    for path in sorted((root / "reolink_protect_events").rglob("*.py")):
        if "_vendor" in path.parts or "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise ReleaseError("release_symlink_invalid")
        name = member_name(str(path.relative_to(root)).replace("\\", "/"))
        members[name] = canonical(path.read_bytes())
    for path in sorted((root / "compatibility").glob("*.json")):
        if path.is_symlink():
            raise ReleaseError("release_symlink_invalid")
        members["reolink_protect_events/compatibility/" + path.name] = canonical(path.read_bytes())
    dependency = None
    if include_dependency:
        dependency, wheel = dependency_bytes(root, cache, downloader)
        members.update(vendor_members(dependency, wheel))
    version_source = members.get("reolink_protect_events/__init__.py", b"").decode()
    match = re.search(r'__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', version_source)
    if not match:
        raise ReleaseError("release_version_invalid")
    metadata = {"schemaVersion": 1, "project": "reolink-protect-events", "version": match[1], **source,
                "dependencySha256": dependency["sha256"] if dependency else None,
                "members": [{"path": n, "bytes": len(c), "sha256": hashlib.sha256(c).hexdigest()} for n, c in sorted(members.items())]}
    members["reolink_protect_events/release.json"] = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            archive.writestr(info, content)
    data = output.getvalue()
    metadata["packageSha256"] = hashlib.sha256(data).hexdigest()
    return data, metadata
