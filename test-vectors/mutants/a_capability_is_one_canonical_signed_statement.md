# A capability is one canonical signed statement

Criterion: `ed25519-cbor-v1` has one encoding per capability, refuses every rule
`spec/security.md` section 5 and `spec/capability.cddl` state, and its signature
covers the bytes that travel rather than a re-encoding of them.

Passing evidence: `a_capability_round_trips_through_its_canonical_bytes` and
`the_signature_is_over_the_bytes_that_arrived` prove the envelope keeps what was
signed and that a decoded capability verifies without being encoded again.
`a_signature_is_bound_to_its_key_identifier_and_its_format` relabels the key
identifier, edits the format identifier inside the signing input, and offers
another issuer's key, and none of the three verifies.
`one_altered_byte_of_the_capability_fails_the_signature` flips every bit position
of the capability and of the signature in turn.

`every_rule_the_format_fixes_is_refused_on_its_own` is one row per rule, and each
row is refused by `validate` and refused again by the encoder, so a rule cannot be
skipped by encoding directly.
`every_bound_is_tested_at_its_own_edge` asserts the value that must be accepted
beside the one that must not, for adjacent against separated ranges, a range
ending exactly at a known length, the widest operation the registry can name, and
an input of exactly the field size against one byte more.

`the_widest_capability_fits_the_field_that_carries_it` measures rather than
estimates. The first version of this computed an upper bound from the field bounds
and asserted it fitted; the arithmetic then had twenty-six surviving mutants,
because slack absorbs a change to an estimate and the conclusion still holds.
Encoding the widest capability this crate will produce and recording its size
cannot be wrong that way: 1,251 bytes for a scope against a 4 KiB field, and 1,905
for a signed capability against 48 KiB.

`an_envelope_that_is_not_one_canonical_item_is_refused` covers truncation at every
length, trailing bytes, a wider head than the length needs, and a version this
format does not define.

Cross-implementation evidence: `tools/validate_capability_vectors.py` reimplements
`spec/capability.cddl` and the section 5 rules in Python and cross-checks 13 cases
against the Rust crate through `vot-capability-oracle`. Five of them are refusals,
which the validator requires: a file of nothing but accepted cases proves only
that a decoder decodes. Checked in both directions by changing a byte of a
canonical vector and by deleting the delegation rule from the crate; each fails
it.

Mutants: encode a head wider than its value needs; accept adjacent ranges; accept
a range ending one byte past a known length; accept the reserved operation or
limit zero; accept an unordered or repeated operation set; accept an expiry at its
not-before; read a delegation constraint without checking it; leave the key
identifier out of the signing input; verify a re-encoding rather than the bytes
that arrived.

Observed failure:

```text
assertion `left == right` failed
  left: Ok(())
 right: Err(InvalidRange)
assertion `left == right` failed
  left: Ok(())
 right: Err(Signature)
assertion `left == right` failed
  left: Ok(())
 right: Err(UnsupportedDelegation(1))
capability vector validation failed: python=err|UNSUPPORTED_DELEGATION rust=ok|capability|issuer.example|receiver.example
```

The required `vot-capability` mutation run reports 90 mutants, 83 caught, 7
unviable, and 0 missed. The two binaries are excluded in `.cargo/mutants.toml`:
the oracle exists to be compared against the Python implementation on every run,
which `cargo-mutants` does not do, and the vector writer produces the committed
file that comparison reads.

What this does not cover is the decision a verifier makes: whether the issuer that
signed a capability is one this deployment trusts for this audience, whether the
window is open on its clock, and whether the token identifier is on a deny list.
That is ADR-0023's anchor model, and it is the next change.
