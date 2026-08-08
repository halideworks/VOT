# Contributing

Contributions must preserve the layer order and invariants in
`spec/architecture.md`.

## Requirements

Every contribution must:

- be original work or identify every permitted source;
- include a `Signed-off-by:` line certifying the DCO 1.1;
- avoid proprietary source, decompiled logic, leaked material, or undocumented
  protocol cloning;
- include success and failure-path tests;
- update conformance vectors for wire- or identity-visible changes;
- use only identifiers allocated by `spec/registries.md`;
- state memory, CPU, storage, and wire amplification impacts; and
- update security, telemetry, provenance, and ADR records when relevant.

## Acceptance criteria

Every acceptance criterion must include:

1. a passing test;
2. a minimal deliberate mutant in the code under test; and
3. captured output proving the test rejects the mutant.

Record the mutant diff and failure output in
`test-vectors/mutants/<criterion>.md`. A surviving mutant means the criterion
is not met.

Tests that depend on a platform mechanism must report an explicit skip on
ordinary runners and must fail, not skip, when the designated runner
environment variable is set.

## Unsafe code

Forbidden in core parsers and state machines. A platform or FFI module
requiring unsafe must isolate it, document every safety invariant, and include
dedicated lifetime, race, and fault tests.

## CLA

Before a non-trivial outside contribution is merged, the Project Owner must
have a signed CLA based on `CLA.md`. DCO sign-off records provenance but does
not replace the agreement.
