# Contributing

Contributions must preserve the layer order and invariants in
`spec/architecture.md`. Do not begin a later-wave feature before its dependencies
and gate are satisfied.

Every contribution must:

- be original work or identify every permitted source;
- include a `Signed-off-by:` line certifying the Developer Certificate of Origin
  1.1 or an equivalent repository-host attestation;
- avoid proprietary source, decompiled logic, leaked material, or undocumented
  protocol cloning;
- include success and failure-path tests;
- update conformance vectors for wire- or identity-visible changes;
- use only identifiers allocated by `spec/registries.md`;
- state memory, CPU, storage, and wire amplification impacts; and
- update security, telemetry, provenance, and ADR records when relevant.

Unsafe Rust is forbidden in core parsers and state machines. A platform or FFI
module requiring unsafe code must isolate it, document every safety invariant,
and include dedicated lifetime, race, and fault tests.

By signing off a contribution, the contributor certifies that they have the
right to submit it under AGPL-3.0-only and that known necessarily infringed patent
claims they own or control have been disclosed according to `PATENTS.md`.
