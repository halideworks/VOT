# VOT v0.3 Commit and Assurance State Machine

Status: normative Wave 0 transition specification

## 1. Scope

The Commit Layer converts transit-verified immutable bytes into provider-visible
objects and emits authenticated observations. It does not interpret transport
acknowledgements. A provider advertises the commit profiles it can perform and
MUST reject an unsupported requested profile before publication.

## 2. Identity and incarnation

Commit state is scoped by:

```text
(subject_identity, session_id, incarnation_id)
```

Session and incarnation identifiers are independent random 128-bit values. A
provider maintains exactly one current incarnation for a staging operation. A
checksummed but non-current incarnation is stale and cannot advance or publish.

Every durable transition has a monotonically increasing journal sequence within
the incarnation. Duplicate replay of the same sequence and identical record is
idempotent. Reuse with different content, a sequence decrease, or a gap not
explained by the checkpoint format requires recovery and cannot publish.

## 3. Externally observable assurance

| Level | Meaning |
|---|---|
| `ADMITTED` | Bounded staging and work capacity was atomically reserved. |
| `TRANSIT_VERIFIED` | Every byte in the reported unit authenticates to the exact object identity. |
| `DURABLE` | Provider durability barrier and durable journal transition completed. |
| `AT_REST_VERIFIED` | Durable bytes passed an independent or conforming delegated integrity check. |
| `PUBLISHED` | Atomic visibility and required namespace durability completed. |

Observations are monotonic within an incarnation. A provider may omit a receipt
for an intermediate level but may never imply work it skipped.

Publication requires:

| Profile | Required predecessor |
|---|---|
| Fast | `TRANSIT_VERIFIED` |
| Balanced | `DURABLE` |
| Strict | `AT_REST_VERIFIED` |

All profiles still perform provider-declared atomic no-overwrite visibility and
the namespace durability operation required by that provider. Fast does not
claim data durability merely because namespace publication completes.

## 4. Internal states

These internal states are not assurance levels:

- `NEW`: no reservation or staging object;
- `DATA_FLUSHED`: data barrier returned successfully but the corresponding
  journal transition is not yet durable;
- `NAMESPACE_LINKED`: the no-overwrite namespace operation succeeded but its
  parent/container durability result is not yet known;
- `RECOVERY_REQUIRED`: persistent state may be valid but cannot advance without
  reconstruction and validation;
- `POISONED`: a write or durability failure made the incarnation permanently
  ineligible for publication; and
- `ABORTED`: reservation released and incarnation terminal by explicit policy.

`PUBLISHED`, `POISONED`, and `ABORTED` are terminal. `RECOVERY_REQUIRED` can
select a validated checkpoint or create a new incarnation, but it cannot itself
transition directly to `PUBLISHED`.

## 5. Allowed transitions

| Current | Event and completed predicate | Next | Receipt allowed |
|---|---|---|---|
| `NEW` | authorization, length bounds, quotas, and atomic reservation succeed | `ADMITTED` | `ADMITTED` |
| `NEW` | requested provider/profile unsupported | terminal rejection | none; explicit unsupported result |
| `ADMITTED` | all reported bytes and proofs verify to exact identity | `TRANSIT_VERIFIED` | `TRANSIT_VERIFIED` |
| `TRANSIT_VERIFIED` | Fast publication requested | publication sequence | none until complete |
| `TRANSIT_VERIFIED` | data durability barrier succeeds | `DATA_FLUSHED` | none |
| `DATA_FLUSHED` | durable journal record for the barrier succeeds | `DURABLE` | `DURABLE` |
| `DURABLE` | Balanced publication requested | publication sequence | none until complete |
| `DURABLE` | independent/delegated verification succeeds and record is durably flushed | `AT_REST_VERIFIED` | `AT_REST_VERIFIED` |
| `AT_REST_VERIFIED` | Strict publication requested | publication sequence | none until complete |
| required predecessor | atomic no-overwrite link/rename/complete succeeds | `NAMESPACE_LINKED` | none |
| `NAMESPACE_LINKED` | parent directory or provider namespace durability succeeds | `PUBLISHED` | `PUBLISHED` |
| any nonterminal | authorized abort before ambiguous namespace mutation | `ABORTED` | optional terminal audit result |
| recoverable state | crash, torn tail, or ambiguous operation | `RECOVERY_REQUIRED` | none |

No other successful transition exists. In particular:

- `ADMITTED` cannot become `DURABLE` without transit verification;
- `TRANSIT_VERIFIED` cannot produce Balanced or Strict publication;
- `DURABLE` cannot produce Strict publication;
- `NAMESPACE_LINKED` cannot emit `PUBLISHED` before namespace durability; and
- no terminal state can advance.

## 6. Poisoning and failures

A short write, write failure, data flush failure, journal flush failure, or
provider durability failure poisons the incarnation. Retrying the failed call
does not rehabilitate it. Recovery creates a new incarnation or revalidates and
reconstructs affected ranges under a new current incarnation.

Proof failure or source mutation invalidates the affected inbound bundle and may
abort ingest, but it does not poison already durable local storage unless bytes
were written into an extent whose correctness is now unknown. Provider code must
make that distinction explicit.

An atomic link/rename/complete failure before namespace mutation leaves no
publication and enters `RECOVERY_REQUIRED` or `ABORTED` according to the
provider's ability to prove absence. A directory-flush failure after a namespace
operation leaves `NAMESPACE_LINKED` and enters `RECOVERY_REQUIRED`; no receipt is
emitted. Recovery inspects both namespace and journal, validates identity, and
either completes the durability step or constructs a new incarnation. It never
infers success from visibility alone.

## 7. Strict POSIX provider

The Strict sequence is ADR-0001:

1. unique temporary object and incarnation;
2. bounded reservation;
3. writes and transit verification;
4. data-file `fsync`/`fdatasync`, poisoning on failure;
5. durable journal flush;
6. separately opened aligned `O_DIRECT` read and complete hash, or approved
   delegated mechanism;
7. durable at-rest verification record;
8. atomic no-overwrite link or rename;
9. parent directory flush; and
10. authenticated publication receipt.

A buffered reread and `POSIX_FADV_DONTNEED` are not Strict. Alignment, final-tail
handling, filesystem support, and the actual mechanism appear in the provider
conformance profile.

## 8. Object-store provider

An object-store provider maps multipart part checksums, completion, independent
backend checksum, conditional no-overwrite creation, and read-after-write
visibility to the same state machine. A successful HTTP response alone is not a
durability or integrity guarantee; the provider profile declares the exact
backend semantics relied upon.

Multipart mismatch, failed completion, or ambiguous timeout enters poisoning or
recovery as declared by whether prior state can be proven. Active authenticated
leases prevent orphan collection during recovery.

## 9. Receipts

The deterministic data model is `spec/receipt.cddl`. `PUBLISH_RECEIPT` binds:

- subject identity and suite;
- observed assurance;
- requested profile and actual predecessor;
- provider identifier and semantic version;
- session and incarnation;
- monotonic issuer sequence;
- wall observation and clock source; and
- delegation, explicit downgrade history, unsupported, and experimental flags.

Receipt authentication covers the deterministic CBOR bytes of the inner
`receipt`, not a decode/re-encode of unvalidated bytes. Cross-boundary receipts
use a registered authentication scheme. The verifier checks the key identifier,
algorithm, signature/MAC, schema version, subject identity, and monotonicity.

Wall time is audit metadata. Logical/journal sequence and monotonic clocks drive
correctness.

## 10. Recovery invariants

Recovery MUST:

- reject torn or checksum-invalid records after the last valid checkpoint;
- reject a stale valid incarnation;
- preserve already verified groups when their identity and journal state remain
  valid;
- rehash or retransmit only the checkpoint window and active unsealed units;
- never interpret transport resume state as commit state;
- never move backward within the selected valid incarnation; and
- emit no receipt until a transition is newly proven or an identical prior
  authenticated receipt is replayed.

## 11. Executable-model requirements

COM-001 models every state and failure above, including Fast, Balanced, Strict,
stale incarnation, write/flush poisoning, namespace ambiguity, recovery, and
receipt emission. Model invariants include:

```text
Published(profile=Fast)     => TransitVerified
Published(profile=Balanced) => Durable
Published(profile=Strict)   => AtRestVerified
Receipt(level)              => Performed(level)
Poisoned                    => never Published
StaleIncarnation            => never Current
```

The model emits transition fixtures consumed by journal and provider tests.
