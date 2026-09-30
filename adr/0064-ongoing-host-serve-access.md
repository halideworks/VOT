# ADR-0064: Ongoing host serve access

- Status: Accepted
- Date: 2026-09-30
- Applies to: `vot-cli::ServeAdmission`, `ServeSession`, and the host serve seam in ADR-0048.

## Context

Admission authenticates a capability once. An embedding host can revoke a
link, withdraw a recipient, or change a delivery deadline while its fetch
is still running. Admission alone cannot stop that session.

## Decision

`ServeAdmission.access` optionally supplies a `Fn() -> bool + Send` owned
by the admitted session. The serve seam installs it with
`ServeSession::set_access_guard`. Every service pass checks it before
authorization or source reads. False closes the transport with the existing
`AUTHENTICATION_FAILED` code and returns `Error::Cancelled` through the
existing observer report. The observer still owns and releases the host's
session resources. No callback preserves existing CLI behavior.

The host attaches the guard before its final admission check and keeps the
cancellation state alive until the last session ends. The callback must be
short and must not panic. It may use a cancellation token and cached deadline;
the engine does not prescribe storage, clocks, or policy. Revocation prevents
new service work; bytes already accepted by a carrier cannot be recalled.

## Consequences

The wire format, negotiated identifiers, conformance vectors, provenance,
and logging fields are unchanged. Memory grows by one optional boxed callback
per session. CPU adds one optional callback per service pass. There is no
additional payload storage or wire amplification. A host that blocks in its
callback delays only that session's thread.

## Verification

`revoked_access_stops_before_the_next_service_pass` checks both initial denial
and withdrawal after an allowed pass, without further serving progress.
`serve_on_admits_by_root_and_reports_each_session` checks installation over a
real socket and cancellation reporting with zero payload bytes; its allowed
case still completes. Existing no-guard wire tests preserve CLI behavior.
Deliberate mutants and observed failures are recorded in
`test-vectors/mutants/adr_0064_serve_access.md`.
