"""Validate the checked-in Wave 5.5 benchmark contract without dependencies."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(relative: str) -> object:
    with (ROOT / relative).open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    schema = load("bench/public_result_schema.json")
    workload = load("bench/workloads/ram-to-ram.json")
    impairment = load("bench/impairments/clean-path.json")

    assert isinstance(schema, dict)
    assert isinstance(workload, dict)
    assert workload["id"] == "ram-to-ram-root-verified-v1"
    assert workload["record_bytes"] == 65536
    assert workload["seed_required"] is True
    assert workload["suites"] == ["blake3-bao64", "sha256-bep52"]
    assert isinstance(impairment, dict)
    assert impairment["id"] == "clean-path-v1"
    assert impairment["seed_required"] is True
    assert impairment["loss_ppm"] == 0
    assert schema["properties"]["machine"]["required"] == [
        "os", "kernel", "arch", "cpu_model", "logical_cpus", "memory_bytes"
    ]
    for field in [
        "bytes_sent", "verified_bytes", "elapsed_ns",
        "memory_high_water_bytes", "assurance",
    ]:
        assert field in schema["required"]
    runner = ROOT / "tools/run_benchmark.py"
    assert runner.is_file() and runner.read_text(encoding="utf-8").startswith(
        "#!/usr/bin/env python3"
    )
    rejected = subprocess.run(
        [
            sys.executable,
            str(runner),
            "--backend",
            "simulator",
            "--seed",
            "-1",
            "--command",
            "true",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode == 2
    assert "--seed must be non-negative" in rejected.stderr
    print("benchmark contract: ok")


if __name__ == "__main__":
    main()
