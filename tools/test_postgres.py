#!/usr/bin/env python3
"""Run native SQL contracts in one disposable, isolated PostgreSQL container.

Examples:
  python tools/test_postgres.py
  python tools/test_postgres.py --connector /path/to/approved/access.py --docker /usr/local/bin/docker
  python tools/test_postgres.py --cpu-mode cpuset --process-mode rlimit

No ports, host mounts, production credentials or existing databases are used.
"""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Docker:
    def __init__(self, binary, connector=None):
        self.binary = binary
        self.remote = None
        if connector:
            spec = importlib.util.spec_from_file_location("approved_nas_access", connector)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.remote = module.nas_execute

    def run(self, args, payload="", timeout=30):
        argv = [self.binary] + args
        if self.remote:
            result = self.remote(" ".join(shlex.quote(arg) for arg in argv), payload=payload, sudo=True, timeout=timeout)
            return result["exit_code"], result.get("stdout", ""), result.get("stderr", "")
        result = subprocess.run(argv, input=payload, encoding="utf-8", capture_output=True, timeout=timeout, shell=False)
        return result.returncode, result.stdout, result.stderr


def process_limit_args(mode):
    if mode == "pids":
        return ["--pids-limit", "64"]
    if mode == "rlimit":
        return ["--ulimit", "nproc=64:64"]
    raise ValueError("Unsupported process-limit mode")


def verify_nproc_limit(docker, name):
    """Verify the actual database PID, not HostConfig or an exec helper's limit.

    The official Debian postgres image execs postgres as UID 999 into PID 1 after
    initialization. RLIMIT_NPROC applies to that non-root real UID, unlike root.
    Its accounting scope is the shared real UID, not a cgroup/PID namespace.
    """
    status, output, _ = docker.run(["exec", name, "cat", "/proc/1/status", "/proc/1/limits"])
    if status:
        raise RuntimeError("PostgreSQL process-limit read failed")
    command = re.findall(r"^Name:\s*(\S+)\s*$", output, re.MULTILINE)
    users = re.findall(r"^Uid:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", output, re.MULTILINE)
    limits = re.findall(r"^Max processes\s+(\S+)\s+(\S+)\s+processes\s*$", output, re.MULTILINE)
    if command != ["postgres"] or users != [("999",) * 4] or limits != [("64", "64")]:
        raise RuntimeError("PostgreSQL actual UID or RLIMIT_NPROC guard failed")
    return {"method": "proc_pid1_status_and_limits", "pid": 1, "name": "postgres",
            "realUid": 999, "soft": 64, "hard": 64,
            "accountingScope": "shared_real_uid_999"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--connector", type=Path)
    parser.add_argument("--image", default="postgres:16")
    parser.add_argument("--cpu-mode", choices=("quota", "cpuset"), default="quota",
                        help="Use cpuset for NAS kernels without the CPU CFS controller; pins CPU 0")
    parser.add_argument("--process-mode", choices=("pids", "rlimit"), default="pids",
                        help="Use verified UID999 RLIMIT_NPROC for NAS kernels without the PIDs controller")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"postgres(?::[0-9]+(?:\.[0-9]+)?|@sha256:[a-f0-9]{64})", args.image):
        parser.error("Use an official postgres version or pinned digest")
    docker = Docker(args.docker, args.connector)
    run_id = uuid.uuid4().hex
    name = "rpe-pg-test-" + run_id[:16]
    report = {"schemaVersion": 1, "container": name, "network": "none", "publishedPorts": False,
              "syntheticDatabase": True, "productionDatabaseAccess": False, "memoryMiB": 256, "cpus": 1,
              "image": args.image, "testsRun": 0, "passed": False, "cleanupConfirmed": False}
    report["cpuLimitMode"] = args.cpu_mode
    report["processLimitMode"] = args.process_mode
    log = io.StringIO()
    try:
        status, output, _ = docker.run(["image", "inspect", args.image, "--format", "{{.Id}}"])
        if status:
            raise RuntimeError("PostgreSQL image unavailable; pull it explicitly before running")
        report["imageId"] = output.strip()
        cpu_args = ["--cpus", "1"] if args.cpu_mode == "quota" else ["--cpuset-cpus", "0"]
        status, output, error = docker.run(["run", "--detach", "--name", name, "--label", "rpe.integration.run=" + run_id,
            "--network", "none", "--memory", "256m"] + cpu_args + process_limit_args(args.process_mode) + ["--shm-size", "16m",
            "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=256m",
            "--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--env", "POSTGRES_DB=unifi-protect", args.image,
            "postgres", "-c", "shared_buffers=16MB", "-c", "max_connections=16", "-c", "work_mem=1MB",
            "-c", "maintenance_work_mem=16MB"], timeout=40)
        if status or not re.fullmatch(r"[a-f0-9]{64}", output.strip()):
            report["containerStartError"] = error.strip()[:1000]
            raise RuntimeError("Isolated PostgreSQL container did not start")
        report["containerId"] = output.strip()
        projected = '{"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},' \
                    '"memory":{{json .HostConfig.Memory}},"cpuSet":{{json .HostConfig.CpusetCpus}},' \
                    '"pidsLimit":{{json .HostConfig.PidsLimit}},' \
                    '"nanoCpus":{{json .HostConfig.NanoCpus}},"tmpfs":{{json .HostConfig.Tmpfs}},' \
                    '"mounts":{{json .Mounts}}}'
        status, output, _ = docker.run(["inspect", name, "--format", projected])
        isolation = json.loads(output)
        cpu_ok = isolation.get("cpuSet") == "0" if args.cpu_mode == "cpuset" else isolation.get("nanoCpus") == 1000000000
        if status or isolation.get("network") != "none" or isolation.get("ports") or isolation.get("memory") != 256 * 1024 * 1024 \
                or not cpu_ok or (args.process_mode == "pids" and isolation.get("pidsLimit") != 64) \
                or "/var/lib/postgresql/data" not in (isolation.get("tmpfs") or {}) \
                or any(mount.get("Type") in ("bind", "volume") for mount in isolation.get("mounts", [])):
            raise RuntimeError("Isolated PostgreSQL resource or network guard failed")
        report["isolationVerified"] = True
        deadline = time.monotonic() + 40
        while True:
            status, _, _ = docker.run(["exec", name, "pg_isready", "-U", "postgres", "-d", "unifi-protect"], timeout=10)
            if status == 0:
                if args.process_mode == "rlimit":
                    try:
                        # The entrypoint's temporary init server may answer
                        # pg_isready before postgres has actually execed PID 1.
                        report["processLimitEvidence"] = verify_nproc_limit(docker, name)
                    except RuntimeError:
                        pass
                    else:
                        break
                else:
                    break
            if time.monotonic() >= deadline:
                raise RuntimeError("Isolated PostgreSQL did not become ready")
            time.sleep(0.25)
        if args.process_mode != "rlimit":
            report["processLimitEvidence"] = {"method": "docker_pids_controller", "pidsLimit": 64}
        report["processLimitVerified"] = True
        spec = importlib.util.spec_from_file_location("postgres_integration_contracts", ROOT / "tests" / "test_postgres_integration.py")
        tests = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tests)

        def execute(sql):
            from reolink_protect_events.native import NativeError, RetiredEventError
            status, output, error = docker.run(["exec", "-i", name, "psql", "-U", "postgres", "-d", "unifi-protect",
                "-w", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], payload=sql, timeout=25)
            if status:
                if "reolink-protect-events:retired" in error:
                    raise RetiredEventError("Synthetic event was retired")
                raise NativeError("Isolated PostgreSQL command failed")
            return output
        execute("COMMENT ON DATABASE \"unifi-protect\" IS '" + tests.MARKER + "';")
        tests.EXECUTOR = execute
        tests.PostgreSqlIntegrationTests.__unittest_skip__ = False
        report["postgresVersion"] = tests.value("SELECT to_json(version());")
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(tests.PostgreSqlIntegrationTests))
        report.update(testsRun=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                      skipped=len(result.skipped), passed=result.wasSuccessful(), testLog=log.getvalue())
    except Exception as error:
        report["errorType"] = type(error).__name__
        report["passed"] = False
        if log.getvalue():
            report["testLog"] = log.getvalue()
    finally:
        # An interrupted create can still have succeeded. Remove only our exact
        # random name AND ownership label, never enumerate or prune other objects.
        status, owner, _ = docker.run(["inspect", name, "--format", '{{index .Config.Labels "rpe.integration.run"}}'])
        if status == 0 and owner.strip() == run_id:
            removed, _, _ = docker.run(["rm", "--force", "--volumes", name], timeout=30)
            missing, _, _ = docker.run(["inspect", name])
            report["cleanupConfirmed"] = removed == 0 and missing != 0
        elif status != 0:
            report["cleanupConfirmed"] = True
        if not report["cleanupConfirmed"]:
            report["passed"] = False
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
