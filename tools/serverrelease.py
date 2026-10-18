#!/usr/bin/env python3
"""Test and release this committed four-component server source with CAS."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_server_release import BuildError, build, revision
from reolink_protect_events.operations.heimserver import invoke, valid_digest


class ReleaseError(RuntimeError):
    def __init__(self, code, details=None):
        self.code = code
        allowed = ("previousReleaseRestored", "manualInspectionRequired", "privateConfigPreserved",
                   "privateConfigAndStateReplaced")
        self.details = {key: value for key, value in (details or {}).items()
                        if key in allowed and type(value) is bool}
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise ReleaseError(code)


def run_tests(repo, node="node"):
    """Exercise Events/transport/controller tests and parse both canonical JS assets."""
    commands = [[sys.executable, "-m", "unittest", "discover", "-s", "tests"]]
    commands.extend([[node, "--check", str(Path(repo) / relative)]
                     for relative in ("services/archive/proxy.cjs", "services/archive/aac-clock.cjs")])
    commands.append([node, "--test", str(Path(repo) / "services/archive/test_proxy.cjs")])
    for command in commands:
        try:
            result = subprocess.run(command, cwd=str(repo), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ReleaseError("server_release_tests_failed") from None
        need(result.returncode == 0, "server_release_tests_failed")


def update(repo=ROOT, output_dir=None, *, expected_current=None, node="node",
           tests=None, builder=None, remote=None, source_revision=None):
    """No state copying/restores: only stage public bytes and use the owned CAS."""
    tests = tests or run_tests
    builder = builder or build
    remote = remote or invoke
    source_revision = source_revision or revision
    repo = Path(repo).resolve()
    if expected_current is not None:
        need(valid_digest(expected_current), "server_release_expected_digest_invalid")
    tested, _ = source_revision(repo, require_clean=True)
    tests(repo, node=node)
    release = builder(repo, output_dir, require_clean=True)
    need(release.get("ok") is True and release.get("sourceRevision") == tested
         and valid_digest(release.get("digest")), "server_release_tested_revision_changed")
    target = release["digest"]

    def request(value, failure):
        result = remote(value)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ReleaseError(failure, result if isinstance(result, dict) else None)
        return result

    before = request({"mode": "check"}, "server_release_current_unhealthy")
    previous = before.get("deployment", {}).get("digest")
    need(valid_digest(previous), "server_release_current_identity_invalid")
    need(expected_current is None or previous == expected_current, "server_release_current_changed")
    common = {"ok": True, "digest": target, "previousDigest": previous,
              "sourceRevision": tested, "bundle": release["bundle"],
              "privateConfigsIncluded": False, "privateStateRestoreRequested": False}
    if previous == target:
        return dict(common, alreadyCurrent=True, activated=False, checked=True)

    path = Path(release["bundle"])
    need(path.is_file() and not path.is_symlink(), "server_release_bundle_invalid")
    staged = request({"mode": "stage", "digest": target,
                      "bundle": base64.b64encode(path.read_bytes()).decode("ascii")},
                     "server_release_stage_failed")
    need(staged.get("digest") == target, "server_release_staged_identity_invalid")
    request({"mode": "check", "digest": target}, "server_release_candidate_unhealthy")
    # The remote controller preserves config/state and owns its crash receipt,
    # readiness gate and automatic rollback if activation itself fails.
    request({"mode": "activate", "digest": target, "expectedCurrent": previous},
            "server_release_activation_failed")
    try:
        after = request({"mode": "check"}, "server_release_final_check_failed")
        need(after.get("deployment", {}).get("digest") == target, "server_release_final_identity_changed")
    except Exception:
        # Revert only our just-activated digest. CAS refuses to overwrite an
        # intervening deployment, and neither path rolls back journal data.
        try:
            result = remote({"mode": "rollback", "expectedCurrent": target})
            restored = isinstance(result, dict) and result.get("ok") is True
        except Exception:
            restored = False
        raise ReleaseError("server_release_postcheck_failed_rolled_back" if restored
                           else "server_release_postcheck_failed_requires_review") from None
    return dict(common, alreadyCurrent=False, activated=True, checked=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    build_parser = modes.add_parser("build", help="Build public code locally without deploying")
    build_parser.add_argument("--output-dir", type=Path)
    build_parser.add_argument("--require-clean", action="store_true")
    deploy_parser = modes.add_parser("update", help="Test committed code, stage, CAS-activate and check")
    deploy_parser.add_argument("--output-dir", type=Path)
    deploy_parser.add_argument("--expected-current")
    deploy_parser.add_argument("--node", default="node", help="Local Node binary used for JS syntax checks")
    args = parser.parse_args(argv)
    try:
        if args.mode == "build":
            result = build(output_dir=args.output_dir, require_clean=args.require_clean)
        else:
            result = update(output_dir=args.output_dir, expected_current=args.expected_current, node=args.node)
    except Exception as error:
        result = {"ok": False, "errorCode": error.code if isinstance(error, (ReleaseError, BuildError))
                  else "server_release_failed"}
        if isinstance(error, ReleaseError):
            result.update(error.details)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
