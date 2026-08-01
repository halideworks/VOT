# QUIC to TCP preserves verified state

Criterion: a carrier switch preserves verified and durable object units without
using the old connection identity.

Passing evidence: `quic_to_tcp_preserves_verified_and_durable_state` and the
E-RESUME UDP-blackhole scenario switch from QUIC to TLS/TCP, change the
connection ID, and assert that verified and durable unit membership is unchanged.

Mutant: replace `CarrierNeutralState::switch` with an empty body.

Observed failure:

```text
assertion failed: left == right
  left: Quic
 right: TlsTcp
```

The required `vot-resume` mutation run caught the mutant.
