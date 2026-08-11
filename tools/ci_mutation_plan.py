#!/usr/bin/env python3
"""Select mutation jobs before GitHub allocates their runners."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .ci_mutation_packages import PACKAGES
else:
    from ci_mutation_packages import PACKAGES

WIRE_SHARDS = (
    {"shard": "fetch-protocol", "args": "-f crates/vot-cli/src/fetch/protocol.rs"},
    {
        "shard": "fetch",
        "args": "-f crates/vot-cli/src/fetch.rs -f 'crates/vot-cli/src/fetch/**' -e crates/vot-cli/src/fetch/protocol.rs",
    },
    {
        "shard": "serve",
        "args": "-f crates/vot-cli/src/serve.rs -f 'crates/vot-cli/src/serve/**'",
    },
    {
        "shard": "drive",
        "args": "-f crates/vot-cli/src/drive.rs -f crates/vot-cli/src/nowire.rs",
    },
    {
        "shard": "wire",
        "args": "-f crates/vot-cli/src/wire.rs -f 'crates/vot-cli/src/wire/**'",
    },
    {
        "shard": "core",
        "args": "-e crates/vot-cli/src/fetch.rs -e 'crates/vot-cli/src/fetch/**' -e crates/vot-cli/src/serve.rs -e 'crates/vot-cli/src/serve/**' -e crates/vot-cli/src/drive.rs -e crates/vot-cli/src/wire.rs -e 'crates/vot-cli/src/wire/**' -e crates/vot-cli/src/nowire.rs -e crates/vot-cli/src/main.rs -e crates/vot-cli/src/rendezvous.rs -e 'crates/vot-cli/src/rendezvous/**' -e crates/vot-cli/src/relay.rs -e 'crates/vot-cli/src/relay/**'",
    },
)

PLAN_INFRASTRUCTURE = {
    ".github/workflows/ci.yml",
    "tools/ci_mutation_plan.py",
    "tools/test_ci_mutation_plan.py",
}
LIVE_CONFIGURATION = ".cargo/mutants-live.toml"
DEFAULT_CONFIGURATION = ".cargo/mutants.toml"
LIVE_CHECKER = "tools/check_live_mutants.py"
QUICHE_EVIDENCE = "test-vectors/mutants/the_quiche_pump_is_mutation_tested.md"
MSQUIC_EVIDENCE = "test-vectors/mutants/the_live_transport_is_mutation_tested.md"


def _package(path: str) -> str | None:
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] == "crates" and parts[1] in PACKAGES:
        if parts[-1].endswith(".rs"):
            return parts[1]
    return None


def _wire_shard(path: str) -> str | None:
    prefix = "crates/vot-cli/src/"
    if not path.startswith(prefix) or not path.endswith(".rs"):
        return None
    relative = path.removeprefix(prefix)
    if relative == "fetch/protocol.rs":
        return "fetch-protocol"
    if relative == "fetch.rs" or relative.startswith("fetch/"):
        return "fetch"
    if relative == "serve.rs" or relative.startswith("serve/"):
        return "serve"
    if relative in {"drive.rs", "nowire.rs"}:
        return "drive"
    if relative == "wire.rs" or relative.startswith("wire/"):
        return "wire"
    if relative == "main.rs" or relative == "rendezvous.rs":
        return None
    if relative.startswith("rendezvous/") or relative == "relay.rs":
        return None
    if relative.startswith("relay/"):
        return None
    return "core"


def plan(paths: list[str], *, full: bool = False) -> dict[str, object]:
    changed = set(paths)
    all_jobs = full or bool(changed & PLAN_INFRASTRUCTURE)

    if all_jobs or DEFAULT_CONFIGURATION in changed:
        packages = set(PACKAGES)
    else:
        packages = {package for path in changed if (package := _package(path))}

    live_configuration_changed = LIVE_CONFIGURATION in changed
    checker_changed = LIVE_CHECKER in changed
    quiche = (
        all_jobs
        or live_configuration_changed
        or checker_changed
        or bool(
            changed
            & {
                "crates/vot-transport-quiche/src/live.rs",
                QUICHE_EVIDENCE,
            }
        )
    )
    msquic = (
        all_jobs
        or live_configuration_changed
        or checker_changed
        or bool(
            changed
            & {
                "crates/vot-transport-msquic/src/live.rs",
                MSQUIC_EVIDENCE,
            }
        )
    )

    if all_jobs or live_configuration_changed:
        wire_names = {entry["shard"] for entry in WIRE_SHARDS}
    else:
        wire_names = {
            shard for path in changed if (shard := _wire_shard(path)) is not None
        }

    package_matrix = []
    for package in PACKAGES:
        if package not in packages:
            continue
        entry: dict[str, object] = {"package": package, "required": True}
        if package == "vot-object-store":
            entry["features"] = "s3-live"
        package_matrix.append(entry)

    wire_matrix = [entry for entry in WIRE_SHARDS if entry["shard"] in wire_names]
    return {
        "packages": package_matrix,
        "wire": wire_matrix,
        "quiche": quiche,
        "msquic": msquic,
    }


def _paths(path: Path) -> list[str]:
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in path.read_bytes().split(b"\0")
        if item
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", dest="full")
    parser.add_argument("--paths-file", type=Path)
    args = parser.parse_args()
    paths = _paths(args.paths_file) if args.paths_file else []
    result = plan(paths, full=args.full)
    compact = {
        key: json.dumps(value, separators=(",", ":")) for key, value in result.items()
    }
    for key in ("packages", "wire", "quiche", "msquic"):
        print(f"{key}={compact[key]}")


if __name__ == "__main__":
    main()
