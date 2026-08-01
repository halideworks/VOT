# ADR-0014: Windows atomic file replacement FFI

- Status: Accepted
- Date: 2026-07-31
- Decision owner: David Torcivia

## Context

Resume compaction must replace an earlier snapshot atomically. Unix rename
provides replacement semantics, while Windows `std::fs::rename` fails when the
destination already exists. Workspace-wide `unsafe_code = "forbid"` also means
the required Windows API cannot be called from an ordinary VOT crate.

## Decision

Keep native file replacement in the isolated `vot-platform-fs` crate. All
other crates retain `unsafe_code = "forbid"`. The FFI crate uses
`unsafe_code = "deny"`, permits unsafe code only on the Windows wrapper, and
requires a documented safety argument for every unsafe block.

Windows resume compaction uses `MoveFileExW` with replacement and write-through
flags. Unix uses `std::fs::rename`. Append records are checksummed and bounded;
the source and destination are always in the same directory.

## Consequences

Periodic compaction replaces the prior snapshot atomically on Windows instead
of failing when the destination exists. Native Windows CI executes the
replacement and append/replay tests.
