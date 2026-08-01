#!/usr/bin/env python3
"""Run a checked-in VOT workload and emit one public-result JSON object per line.

The backend command is intentionally external: this runner supplies the
workload, impairment, seed, and machine metadata, but never invents a
throughput or cycle result when a backend did not measure it.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BACKENDS = {"msquic", "quiche", "tcp", "simulator"}
SUITE_NAMES = {"blake3-bao64", "sha256-bep52"}


def load(relative: str) -> dict[str, Any]:
    with (ROOT / relative).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain an object")
    return value


def git_value(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
    ).strip()


def machine() -> dict[str, Any]:
    cpu_model = platform.processor() or platform.machine()
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    memory_bytes = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_bytes = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError):
        pass
    if memory_bytes <= 0:
        raise ValueError("unable to capture machine memory")
    return {
        "os": platform.system(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": cpu_model,
        "logical_cpus": os.cpu_count() or 1,
        "memory_bytes": memory_bytes,
    }


def last_json(stdout: str) -> dict[str, Any]:
    for line in reversed([line.strip() for line in stdout.splitlines() if line.strip()]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("backend command did not emit a JSON object")


def measured_int(value: Any, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"backend field {name} must be an integer >= {minimum}")
    return value


def build_result(
    measured: dict[str, Any],
    *,
    workload_id: str,
    impairment_id: str,
    backend: str,
    source_commit: str,
    dirty: bool,
    suite: str,
    worker_count: int,
    seed: int,
    object_bytes: int,
    machine_info: dict[str, Any],
    assurance: str,
    iteration: int,
) -> dict[str, Any]:
    bytes_sent = measured_int(measured.get("bytes_sent"), "bytes_sent")
    verified_bytes = measured_int(measured.get("verified_bytes"), "verified_bytes")
    elapsed_ns = measured_int(measured.get("elapsed_ns"), "elapsed_ns", 1)
    memory_high_water = measured_int(
        measured.get("memory_high_water_bytes"), "memory_high_water_bytes"
    )
    cycles_value = measured.get("cycles")
    cycles = None if cycles_value is None else measured_int(cycles_value, "cycles")
    if bytes_sent < verified_bytes:
        raise ValueError("backend reported verified_bytes greater than bytes_sent")
    if verified_bytes != object_bytes:
        raise ValueError(
            f"backend verified {verified_bytes} bytes, expected workload object {object_bytes}"
        )
    notes = str(measured.get("notes", ""))
    suffix = f"iteration={iteration};dirty_worktree={str(dirty).lower()}"
    notes = f"{notes};{suffix}" if notes else suffix
    return {
        "schema_version": 1,
        "workload_id": workload_id,
        "impairment_id": impairment_id,
        "backend": backend,
        "source_commit": source_commit,
        "suite": suite,
        "worker_count": worker_count,
        "seed": seed,
        "machine": machine_info,
        "bytes_sent": bytes_sent,
        "verified_bytes": verified_bytes,
        "elapsed_ns": elapsed_ns,
        "cycles": cycles,
        "memory_high_water_bytes": memory_high_water,
        "assurance": assurance,
        "notes": notes,
    }


def command_environment(
    *,
    workload: dict[str, Any],
    impairment: dict[str, Any],
    backend: str,
    suite: str,
    workers: int,
    seed: int,
    object_bytes: int,
) -> dict[str, str]:
    env = os.environ.copy()
    values = {
        "VOT_BENCH_BACKEND": backend,
        "VOT_BENCH_SUITE": suite,
        "VOT_BENCH_WORKERS": str(workers),
        "VOT_BENCH_SEED": str(seed),
        "VOT_BENCH_OBJECT_BYTES": str(object_bytes),
        "VOT_BENCH_RECORD_BYTES": str(workload["record_bytes"]),
        "VOT_BENCH_IMPAIRMENT": str(impairment["id"]),
    }
    env.update(values)
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default="bench/workloads/ram-to-ram.json")
    parser.add_argument("--impairment", default="bench/impairments/clean-path.json")
    parser.add_argument("--backend", required=True, choices=sorted(BACKENDS))
    parser.add_argument("--suite", choices=sorted(SUITE_NAMES))
    parser.add_argument("--workers", type=int)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=3600.0)
    parser.add_argument(
        "--command",
        nargs=argparse.REMAINDER,
        required=True,
        help="backend command, introduced with --",
    )
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("--command requires an executable")
    if args.seed < 0:
        parser.error("--seed must be non-negative")

    workload = load(args.workload)
    impairment = load(args.impairment)
    if workload.get("seed_required") is not True or impairment.get("seed_required") is not True:
        raise ValueError("both workload and impairment must require a seed")
    suites = [args.suite] if args.suite else workload.get("suites", [])
    workers = (
        [args.workers] if args.workers is not None else workload.get("worker_counts", [])
    )
    object_sizes = workload.get("object_bytes", [])
    if not suites or not workers or not object_sizes:
        raise ValueError("workload has no suite, worker, or object-size matrix")
    if any(suite not in SUITE_NAMES for suite in suites):
        raise ValueError("workload contains an unsupported suite")
    if any(not isinstance(value, int) or value < 1 for value in workers + object_sizes):
        raise ValueError("workload matrix values must be positive integers")
    if args.workers is not None and args.workers < 1:
        raise ValueError("--workers must be positive")

    source_commit = git_value("rev-parse", "HEAD")
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    )
    machine_info = machine()
    warmups = int(workload.get("warmup_iterations", 0))
    iterations = int(workload.get("measurement_iterations", 1))
    if warmups < 0 or iterations < 1:
        raise ValueError("workload iteration counts are invalid")
    results: list[dict[str, Any]] = []
    combination = 0
    for object_bytes in object_sizes:
        for suite in suites:
            for workers_count in workers:
                run_seed = args.seed + combination
                combination += 1
                env = command_environment(
                    workload=workload,
                    impairment=impairment,
                    backend=args.backend,
                    suite=suite,
                    workers=workers_count,
                    seed=run_seed,
                    object_bytes=object_bytes,
                )
                for _ in range(warmups):
                    subprocess.run(
                        command,
                        cwd=ROOT,
                        env=env,
                        check=True,
                        timeout=args.timeout_seconds,
                        stdout=subprocess.PIPE,
                        stderr=None,
                        text=True,
                    )
                for iteration in range(iterations):
                    completed = subprocess.run(
                        command,
                        cwd=ROOT,
                        env=env,
                        check=True,
                        timeout=args.timeout_seconds,
                        stdout=subprocess.PIPE,
                        stderr=None,
                        text=True,
                    )
                    measured = last_json(completed.stdout)
                    results.append(
                        build_result(
                            measured,
                            workload_id=str(workload["id"]),
                            impairment_id=str(impairment["id"]),
                            backend=args.backend,
                            source_commit=source_commit,
                            dirty=dirty,
                            suite=suite,
                            worker_count=workers_count,
                            seed=run_seed,
                            object_bytes=object_bytes,
                            machine_info=machine_info,
                            assurance=str(workload["assurance"]),
                            iteration=iteration,
                        )
                    )
    encoded = "".join(json.dumps(result, sort_keys=True) + "\n" for result in results)
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"benchmark runner: {error}", file=sys.stderr)
        raise SystemExit(2)
