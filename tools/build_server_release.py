#!/usr/bin/env python3
"""Build one deterministic public four-component release from this repository."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reolink_protect_events.operations.heimserver import (
    VERSION, ServerError, canonical, public_member, verified_bundle)

ASSETS = {"controls/worker.py": "services/controls/worker.py",
          "archive/proxy.cjs": "services/archive/proxy.cjs",
          "archive/aac-clock.cjs": "services/archive/aac-clock.cjs"}
PRIVATE_PARTS = {"secrets", "private", "state", "backups", "artifacts", "dist", "build"}


class BuildError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise BuildError(code)


def git(repo, *args):
    try:
        result = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise BuildError("server_build_git_failed") from None
    need(result.returncode == 0, "server_build_git_failed")
    return result.stdout


def revision(repo, *, require_clean=False):
    head = git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    need(re.fullmatch(r"[a-f0-9]{40,64}", head) is not None, "server_build_revision_invalid")
    dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=all"))
    need(not require_clean or not dirty, "server_build_requires_clean_commit")
    return head, dirty


def read_source(repo, path):
    need(path.is_relative_to(repo), "server_build_source_outside_repo")
    need(not any(item.is_symlink() or getattr(item, "is_junction", lambda: False)()
                 for item in (path, *path.parents) if item.is_relative_to(repo)),
         "server_build_source_symlink")
    need(path.is_file(), "server_build_source_missing")
    need(path.resolve().is_relative_to(repo.resolve()), "server_build_source_outside_repo")
    content = path.read_bytes()
    need(b"\0" not in content, "server_build_source_not_text")
    try:
        content.decode("utf-8")
    except UnicodeError:
        raise BuildError("server_build_source_not_utf8") from None
    return content.replace(b"\r\n", b"\n")


def collect(repo):
    package = repo / "reolink_protect_events"
    need(package.is_dir() and not package.is_symlink(), "server_build_package_missing")
    contents, sources = {}, {}
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package)
        if {"_vendor", "__pycache__"} & set(relative.parts):
            continue
        need(not PRIVATE_PARTS & set(relative.parts[:-1]), "server_build_private_source_path")
        member = "events/reolink_protect_events/" + relative.as_posix()
        need(public_member(member), "server_build_member_invalid")
        contents[member] = read_source(repo, path)
        sources[member] = path.relative_to(repo).as_posix()
    for member, relative in ASSETS.items():
        contents[member] = read_source(repo, repo / relative)
        sources[member] = relative
    return contents, sources


def release_bytes(repo, *, require_clean=False):
    """Freeze only public source bytes; no private config/state path is read."""
    repo = Path(repo).absolute()
    need(not repo.is_symlink() and repo.is_dir(), "server_build_repo_invalid")
    head = dirty = None
    if require_clean:
        head, dirty = revision(repo, require_clean=True)
    contents, sources = collect(repo)
    if require_clean:
        # A clean status alone does not prove ignored source files are committed.
        # Build from verified HEAD blobs, so edits racing the snapshot cannot
        # enroll bytes from a different commit even if subsequently reverted.
        tracked = set(git(repo, "ls-files", "-z", "--", *sources.values()).decode("utf-8").split("\0"))
        need(set(sources.values()) <= tracked, "server_build_source_not_committed")
        for member, relative in sources.items():
            committed = git(repo, "show", head + ":" + relative).replace(b"\r\n", b"\n")
            need(contents[member] == committed, "server_build_source_changed")
            contents[member] = committed
        after, _ = revision(repo, require_clean=True)
        need(after == head, "server_build_revision_changed")
    members = [{"path": name, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
               for name, content in sorted(contents.items())]
    digest = hashlib.sha256(canonical(members)).hexdigest()
    manifest = {"schemaVersion": 1, "version": VERSION, "digest": digest, "members": members}
    raw_manifest = canonical(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(dict(contents, **{"release.json": raw_manifest}).items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content, compresslevel=9)
    data = output.getvalue()
    try:
        verified_bundle(data, digest)
    except ServerError as error:
        raise BuildError(error.code) from None
    return data, {"ok": True, "version": VERSION, "digest": digest, "members": len(members),
                  "bytes": len(data), "bundleSha256": hashlib.sha256(data).hexdigest(),
                  "manifestSha256": hashlib.sha256(raw_manifest).hexdigest(),
                  "sourceRevision": head, "sourceDirty": dirty, "privateConfigsIncluded": False}


def build(repo=ROOT, output_dir=None, *, require_clean=False):
    data, result = release_bytes(repo, require_clean=require_clean)
    output_dir = Path(output_dir) if output_dir is not None else Path(repo) / "artifacts/server-releases"
    output_dir.mkdir(parents=True, exist_ok=True)
    need(output_dir.is_dir() and not output_dir.is_symlink(), "server_build_output_invalid")
    destination = output_dir / ("release-" + result["digest"] + ".zip")
    need(not destination.is_symlink(), "server_build_output_symlink")
    if destination.exists():
        need(destination.is_file() and destination.read_bytes() == data, "server_build_output_changed")
    else:
        with destination.open("xb") as stream:
            stream.write(data)
    return dict(result, bundle=str(destination.absolute()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--require-clean", action="store_true", help="Require a clean committed HEAD including all bundled source files")
    args = parser.parse_args(argv)
    try:
        result = build(output_dir=args.output_dir, require_clean=args.require_clean)
    except Exception as error:
        result = {"ok": False, "errorCode": error.code if isinstance(error, BuildError) else "server_build_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
