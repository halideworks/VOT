# ADR-0019: Publish chain heads to an append-only log

Status: Accepted

## Context

ADR-0018 chained observations and anchored them with witnesses. That stops an
issuer rewriting its own history. It does not stop an issuer telling two
counterparties two different histories for the same object, because neither
counterparty sees the other's copy, and each chain can be witnessed separately.

## Decision

Chain heads are published to an append-only log. A reader holding any two
published heads can ask for a consistency proof, which shows the earlier tree is
a prefix of the later one. Equivocation then requires two logs, which is visible.

The tree is RFC 6962. It is precisely specified, independently implemented many
times, and its proofs are checkable by a reader who holds only a published head.
Leaf and interior hashes carry distinct prefixes so a leaf can never be
presented as an interior node.

Checkpoints use the signed note format from Go's checkpoint tooling and
Sigstore, so an existing witness can co-sign a VOT checkpoint without knowing
anything about VOT. The origin line names the log, so a signature over one log's
head is not valid for another's.

Nothing in the format distinguishes the operator's signature from a witness's.
That is deliberate. A witness is a key pair and a clock; the log grants it no
role. A customer, a counterparty, an auditor, or a third-party service can all
operate a log or witness one, and a relying party decides how many distinct
witnesses a head needs.

## Alternatives

The public Sigstore instance was rejected on confidentiality. Entries would
expose subject digest, length, timestamps, and provider for every transfer, and
for a known asset a content hash is a fingerprint that confirms who delivered
what and when. The customers this exists for cannot publish that.

Self-hosted Rekor was rejected because its credibility comes from the public
instance and its witness network. Running a private one gives the schema without
the trust, and brings an operational and dependency footprint at odds with a
small auditable core.

## Consequences

Proofs are recomputed from stored leaf hashes rather than cached interior nodes.
That is linear per proof and holds every leaf in memory, which suits a log of
this size and is why `MAX_ENTRIES` exists. An operator serving a large log would
keep interior nodes; the proof formats do not change.

`base64` moves from an optional S3-only dependency to a default one, for the
note format.

This ADR covers the log. Wiring publication into the commit path, and deciding
when an object is considered logged, are separate.
