"""Validate the checked-in Wave 5.5 benchmark contract without dependencies."""

from __future__ import annotations

import importlib.util
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
    runner_module_spec = importlib.util.spec_from_file_location(
        "vot_run_benchmark", ROOT / "tools/run_benchmark.py"
    )
    assert runner_module_spec is not None and runner_module_spec.loader is not None
    runner_module = importlib.util.module_from_spec(runner_module_spec)
    runner_module_spec.loader.exec_module(runner_module)
    environment = runner_module.command_environment(
        workload=workload,
        impairment=impairment,
        backend="simulator",
        suite="blake3-bao64",
        workers=1,
        seed=7,
        object_bytes=1,
        impairment_path=ROOT / "bench/impairments/clean-path.json",
    )
    assert environment["VOT_BENCH_IMPAIRMENT_PATH"].endswith(
        "bench/impairments/clean-path.json"
    )
    assert environment["VOT_BENCH_IMPAIRMENT_MTU_BYTES"] == "1500"
    assert environment["VOT_BENCH_IMPAIRMENT_RTT_US"] == "1000"
    assert environment["VOT_BENCH_IMPAIRMENT_LOSS_PPM"] == "0"
    assert environment["VOT_BENCH_IMPAIRMENT_BANDWIDTH_BPS"] == "10000000000"
    assert environment["VOT_BENCH_IMPAIRMENT_QUEUE_BYTES"] == "33554432"
    assert runner_module.validate_assurance("root-verified") == "root-verified"
    try:
        runner_module.validate_assurance("not-an-assurance")
    except ValueError as error:
        assert "workload assurance" in str(error)
    else:
        raise AssertionError("invalid workload assurance must be rejected")
    try:
        runner_module.validate_positive_matrix([True])
    except ValueError as error:
        assert str(error) == "workload matrix values must be positive integers"
    else:
        raise AssertionError("boolean workload matrix values must be rejected")
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
