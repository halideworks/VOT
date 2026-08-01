# Manifest seal size bound

Criterion: every accepted manifest seal fits the 1 MiB canonical page limit.

Passing evidence: `seal_round_trips_and_rejects_inconsistent_commitments`
constructs all 26,883 permitted page commitments, uses the widest legal
package-length encoding, encodes the complete seal, and requires its
length to remain at or below 1,048,576 bytes. A 26,884th commitment is rejected.

Mutant: add rather than subtract the fixed canonical CBOR envelope when
deriving `MAX_PAGE_COMMITMENTS`.

```diff
-(MAX_PAGE_BYTES - MAX_SEAL_FIXED_BYTES) / MAX_ENCODED_PAGE_COMMITMENT_BYTES
+(MAX_PAGE_BYTES + MAX_SEAL_FIXED_BYTES) / MAX_ENCODED_PAGE_COMMITMENT_BYTES
```

Observed failure:

```text
assertion `left == right` failed
  left: 26889
 right: 26883
```

The focused `vot-manifest` mutation run caught this mutant and every arithmetic
mutant in the seal-cap expression. The crate remains report-only under the
repository mutation policy; unrelated surviving mutants are reported by CI.
