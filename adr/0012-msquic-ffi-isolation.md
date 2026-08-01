# ADR-0012: Isolate MsQuic FFI

Status: Accepted

## Context

VOT forbids unsafe Rust in core protocol, verification, scheduling, and commit
crates. MsQuic exposes a C API and requires explicit buffer lifetime management.
The workspace-wide `unsafe_code = "forbid"` lint cannot be weakened inside a
member that inherits it.

## Decision

`vot-transport-msquic` does not inherit the workspace lint table. It denies
unsafe code at crate scope and allows it only in the `live` module. Every unsafe
operation in that module requires a `SAFETY` explanation, and Clippy denies
undocumented unsafe blocks.

The public backend queues owned commands and translates native callback events
to `vot-transport-api` types. No MsQuic type crosses that boundary. Send buffers
remain owned until the MsQuic send-complete callback returns their context.

The official Microsoft `msquic` crate is pinned to the immutable v2.5.9 release
commit. Its bundled C library is built only when the `live` feature is selected.

## Consequences

Core crates retain `unsafe_code = "forbid"`. The FFI exception is small enough
for sanitizer coverage and manual lifetime review. Live builds take longer than
the default workspace build because they compile MsQuic.
