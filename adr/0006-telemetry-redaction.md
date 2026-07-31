# ADR-0006: Ordinary telemetry is pseudonymous by default

- Status: Accepted
- Date: 2026-07-31
- Decision owners: A00 architecture; A16 security and telemetry

## Context

Post-production paths, filenames, object roots, and tokens can reveal customer,
title, facility, and workflow information. Transport traces are commonly shared
for support and performance analysis, increasing their disclosure surface.

## Decision

VOT defines `minimal`, `pseudonymous`, and `diagnostic` telemetry. The default is
`pseudonymous`. Stable identifiers use domain-separated, deployment-keyed,
rotating pseudonyms.

Credentials, capabilities, TLS secrets, payload or proof bytes, manifest bytes,
raw filenames and paths, raw stable roots and IDs, and peer free-form errors are
forbidden from ordinary VOT and qlog-compatible telemetry at every level.
Diagnostic mode is explicit, local, time-bounded opt-in; it does not waive the
forbidden-data list.

Authenticated receipts and dedicated audit records are separate sinks with
separate access and retention policy. They cannot be routed accidentally to
ordinary qlog output.

## Consequences

- Default traces remain useful through bounded enums, counters, timing, and
  pseudonymous correlation.
- Metric labels exclude per-object, request, session, principal, source, and job
  pseudonyms to bound cardinality.
- Automated sentinel scans are conformance tests.

## Rejected alternatives

- Raw paths in diagnostic qlog.
- Hashing identifiers without a secret key.
- One pseudonym domain for all identifier types.
- Treating receipt/audit artifacts as ordinary telemetry.
