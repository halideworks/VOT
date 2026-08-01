# Startup does not wait for a long UDP timeout

Criterion: TLS/TCP starts after the configured carrier-race delay while QUIC may
still be attempting to connect.

Passing evidence: `startup_does_not_wait_for_long_udp_timeout` advances only a
caller-provided monotonic counter from 1049 to 1050 and observes `StartTlsTcp` at
the exact boundary. No real clock or sleep is used.

Mutant: replace the successful `CarrierRace::poll` result with `None`.

Observed failure:

```text
assertion failed: left == right
  left: None
 right: Some(StartTlsTcp)
```

The required `vot-transport-tcp` mutation run caught the mutant.
