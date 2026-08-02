# ADR-0018: Chain observations and anchor them with witnesses

Status: Accepted

## Context

ADR-0017 made receipts third-party verifiable. It did not make them evidence.

A single signed receipt is a claim about history. The issuer holds its own key,
so it can rewrite any observation and re-sign it, and `observed_at` is whatever
the issuer writes. Signing alone raises the cost of a lie from nothing to one
re-sign.

Publication is the last of five observations. The four before it, admission,
transit verification, durability, and at-rest verification, happened at
different times and were not recorded as they happened.

## Decision

Each observation is its own signed receipt, and each links to the envelope
digest of its predecessor for the same subject. Key 17 carries that link and is
absent only on the first observation.

Rewriting one observation therefore invalidates every link after it. The record
becomes all-or-nothing rather than editable entry by entry.

That alone still does not bind the issuer, because an issuer can reissue the
whole chain. So a chain is anchored by witness signatures: an independent party
signs a statement naming the head digest and **its own** observation time. A
witness signature is Ed25519 only. A symmetric witness would be checkable only
by a party able to forge it, which is not a witness.

Witnesses are mandatory for a chain to count as anchored. Any party can be a
witness; it is a key pair and a clock, with no protocol role beyond signing what
it saw. That keeps the design open to a counterparty, a customer, an auditor, or
a third-party operator, rather than requiring one blessed service.

## Consequences

The receipt map grows an optional key. Fourteen entries means an unlinked
observation, fifteen means a linked one, and the decoder accepts only those two
shapes.

`verify_chain` checks structure: the first entry does not link, every later one
links to its predecessor's digest, the subject never changes, and the issuer
sequence advances. It deliberately does not verify signatures, so a caller
chooses the key policy rather than inheriting one.

What this still does not give: a receiver serving several counterparties can
issue two different chains for the same object and witness each separately, and
nothing forces the two to be reconciled. Preventing that needs an append-only
log the counterparties can both read. That is the next decision, and the
envelope digest defined here is what such a log would record.
