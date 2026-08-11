#!/usr/bin/env python3
"""Materialize the mutation diff for a GitHub Actions event."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

CommitExists = Callable[[str], bool]
SHA1 = re.compile(r"[0-9a-fA-F]{40}")


def mutation_revision(
    event_name: str,
    base_ref: str,
    before_sha: str,
    commit_exists: CommitExists,
) -> str | None:
    """Return the event's diff revision, or ``None`` for a full sweep."""
    if event_name == "pull_request" and base_ref:
        base = f"origin/{base_ref}"
        separator = "..."
    elif (
        event_name == "push"
        and SHA1.fullmatch(before_sha)
        and before_sha != "0" * 40
    ):
        base = before_sha
        separator = ".."
    else:
        return None

    if not commit_exists(base):
        return None
    return f"{base}{separator}HEAD"


def _git_commit_exists(revision: str) -> bool:
    return (
        subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _write_diff(output: Path, revision: str, *, name_only: bool) -> None:
    temporary = output.with_name(f".{output.name}.tmp")
    command = ["git", "diff"]
    if name_only:
        command.extend(("--name-only", "-z"))
    command.extend((revision, "--"))
    try:
        with temporary.open("wb") as stream:
            subprocess.run(command, stdout=stream, check=True)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--before-sha", default="")
    parser.add_argument("--name-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    revision = mutation_revision(
        args.event_name,
        args.base_ref,
        args.before_sha,
        _git_commit_exists,
    )
    if revision is None:
        args.output.unlink(missing_ok=True)
        print("full")
        return

    _write_diff(args.output, revision, name_only=args.name_only)
    print("targeted")


if __name__ == "__main__":
    main()
