"""Hold a live mutation run against the survivors this repository classifies.

A count cannot tell one survivor from another. A run that kills a classified
mutant and grows a new one reports the same total as the run before it, so a
bound on the number passes while the set underneath it has changed. This compares
the set, which also means the missed and timed-out split stops mattering: a
survivor that hangs and a survivor that fails are the same mutant either way.

The classified list is the table in the evidence file rather than a second file
beside it, so a survivor cannot be admitted without a reason written next to it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "test-vectors/mutants/the_live_transport_is_mutation_tested.md"

# `MISSED   crates/…/lib.rs:733:13: replace live::Carrier::teardown with () in 1s build + 1s test`
SURVIVOR = re.compile(r"^(MISSED|TIMEOUT)\b")
TIMING = re.compile(r" in \d+(\.\d+)?s build \+ .*$")
# A table row whose first cell is the mutant `cargo-mutants` prints.
CLASSIFIED = re.compile(r"^\|\s*`([^`]+)`\s*\|")
# `265 mutants tested in 9m: 13 missed, 219 caught, 31 unviable, 2 timeouts`
SUMMARY = re.compile(r"^\d+ mutants tested\b")
# What it says instead when the diff selected nothing to run.
NOTHING_SELECTED = ("No mutants to filter", "Diff changes no Rust source files")


def fail(message: str) -> NoReturn:
    # The annotation is for CI; the same line reads fine in a terminal.
    raise SystemExit(f"::error::live mutant check: {message}")


def classified() -> list[str]:
    rows = [
        match.group(1)
        for line in EVIDENCE.read_text(encoding="utf-8").splitlines()
        if (match := CLASSIFIED.match(line))
    ]
    if not rows:
        # An unparsed table would classify nothing, which fails every survivor
        # for the wrong reason. Say the real one instead.
        fail(f"no classified survivors found in {EVIDENCE.name}")
    duplicates = {row for row in rows if rows.count(row) > 1}
    if duplicates:
        fail(f"the classified table repeats {sorted(duplicates)}")
    return rows


def survivors(log: Path) -> list[str]:
    found = []
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    # A run that died before testing anything leaves no survivors either, and
    # the job ignores the tool's own exit code because it is non-zero for any
    # survivor at all. Without this, a crashed run reads as a clean one.
    finished = any(SUMMARY.match(line) for line in lines) or any(
        marker in line for line in lines for marker in NOTHING_SELECTED
    )
    if not finished:
        fail(f"{log} has no run summary in it, so the run did not finish")
    for line in lines:
        if not SURVIVOR.match(line):
            continue
        # `MISSED   path:line:col: description in Ns build + Ns test`. The path
        # holds no spaces, so the first colon-space ends it, and the description
        # can hold ` in ` of its own without the split moving.
        _, _, rest = line.partition(": ")
        if not rest:
            fail(f"could not read the mutant out of: {line}")
        # The timing is what the description ends at. A line without it means the
        # tool prints something else now, and every mutant would then fail to
        # match the table for a reason that has nothing to do with the code.
        if not TIMING.search(rest):
            fail(f"no build and test timing in: {line}")
        found.append(TIMING.sub("", rest).strip())
    return found


def main(argv: list[str]) -> None:
    full = "--full" in argv
    paths = [argument for argument in argv if not argument.startswith("--")]
    if len(paths) != 1:
        raise SystemExit("usage: check_live_mutants.py [--full] <mutants.log>")
    log = Path(paths[0])
    if not log.is_file():
        fail(f"{log} does not exist, so the run it should hold said nothing")

    known = classified()
    observed = survivors(log)
    unclassified = sorted({mutant for mutant in observed if mutant not in known})
    if unclassified:
        for mutant in unclassified:
            print(f"::error::unclassified live survivor: {mutant}")
        fail(
            f"{len(unclassified)} of {len(observed)} survivors are not in "
            f"{EVIDENCE.name}. Kill them, or record each with its reason."
        )

    # Only a full sweep tests every classified mutant, so only a full sweep can
    # say one is gone. In a diff run the untested ones are simply not in it.
    if full:
        for mutant in known:
            if mutant not in observed:
                print(
                    f"::notice::classified survivor no longer survives: {mutant}. "
                    f"Remove its row from {EVIDENCE.name}."
                )
    print(f"live mutant check: PASS ({len(observed)} survivors, all classified)")


if __name__ == "__main__":
    main(sys.argv[1:])
