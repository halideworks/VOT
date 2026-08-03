# A verifier believes only what it anchored

Criterion: a capability is believed only when an anchored key signed it for the
issuer that claims it and the audience it names, the window is open on this
verifier's clock, the token is not denied, the holder proved possession of the key
the capability names, and every limit it states is one this verifier can enforce.
A peer learns almost nothing about which of those failed.

This is ADR-0023 applied. The format decides whether bytes are a capability and
whether the signature holds; this decides whether to believe it.

Passing evidence, named for the tests `security/abuse-cases.yaml` SEC-TOK-001
requires:

- `token_signature_rejected`: an altered signature, a capability signed by
  another key under an identifier this deployment does anchor, and an identifier
  nothing anchors.
- `token_issuer_rejected`: an anchored key signing for a name it was not anchored
  for.
- `token_audience_rejected`: both halves. The entry decides whether that key may
  issue for an audience at all, and the policy decides whether that audience is
  this deployment, which is what makes a capability issued for one deployment fail
  at every other that trusts the same issuer.
- `token_expiry_rejected`: each edge of the window with the second outside it, and
  the same again with declared skew moving both edges and nothing else.
- `token_revoked_rejected`: the token identifier on the deny list, and another
  identifier on it.
- `token_channel_binding_rejected`: a proof under a thief's key, over another
  challenge, from another attempt on the same session, and made for another
  capability. Also a proof of the wrong size and a challenge outside the bounds
  `spec/session.cddl` gives one.
- `token_scope_rejected`: an operation the capability does not name, another
  object by root and by suite, and one byte past the range it allows beside the
  last byte inside it.
- `token_delegation_rejected`: a delegation constraint this format does not
  define, signed by an anchored key, so the refusal is the verifier's answer to an
  issuer rather than a decoder's answer to a stranger.

`a_peer_learns_the_same_thing_from_almost_every_refusal` holds thirteen denials
against one wire reason. `spec/wire.md` section 1.1 forbids a rejection that
distinguishes a valid capability with insufficient scope from an invalid one,
because that difference is an oracle a holder can probe. The audit record keeps
the difference and the peer does not, and the detail is empty for the same reason:
every string useful to an operator is useful to someone probing.

`two_issuers_may_choose_the_same_key_identifier` is the case ADR-0023 names: an
identifier is issuer-chosen, so it selects candidates and the issuer claim decides
between them. A verifier keyed on the identifier alone works until the second
issuer arrives.

`a_limit_this_verifier_cannot_enforce_refuses_the_capability` is the asymmetry
`spec/registries.md` section 13 states. An unknown operation grants nothing; an
unknown limit refuses the capability, because ignoring a restriction lifts it.

Mutants: accept a capability issued for another deployment; leave the attempt
identifier out of the proof of possession; ignore a limit this verifier cannot
enforce; check the audience against the entry and not the policy; compare the
clock without the declared skew; read the claims before checking the signature;
report a scope refusal with its own wire reason.

Observed failure:

```text
assertion `left == right` failed
  left: Ok(Authorized { capability: Capability { issuer: "issuer.example", audience: "receiver.elsewhere", ...
 right: Err(AudienceIsAnother)
assertion `left == right` failed
  left: Ok(Authorized { capability: Capability { ... token_id: [193, ...] } })
 right: Err(ProofOfPossession)
assertion `left == right` failed
  left: Ok(Authorized { capability: Capability { ... limits: [Limit { id: 16384, value: 1 }] ...
 right: Err(LimitNotEnforceable(16384))
```

The required `vot-capability` mutation run reports 134 mutants, 122 caught, 12
unviable, and 0 missed.

Over a real carrier,
`a_capability_is_presented_and_authorized_over_the_real_carrier` runs the whole
arc: an issuer mints a capability, a client presents it with a proof of possession
over the server's own challenge, this verifier decides, and the server grants a
narrower scope than was asked for. The same presentation with one bit of the
signature turned over is refused in the same test, so it fails if the verifier ever
answers yes to everything.
