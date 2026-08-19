# Automatic FEC uses measured loss

Criteria:

- `VOT_DATAGRAM_FEC=auto` keeps new ranges on the reliable path until a
  meaningful path sample reaches the measured 5% corrected-loss crossover,
  then codes later ranges on the same connection.
- adaptive repair covers the expected missing sources plus one safety symbol,
  bounded by the shipped eight-symbol profile.

Passing evidence: `automatic_fec_keeps_clean_ranges_reliable_then_codes_lossy_ranges`
answers one range with zero loss and a second at 5% on the same negotiated,
credited session, asserting that only the second emits datagrams.
`repair_count_tracks_real_loss_after_startup` pins the repair calculation at
its boundaries and after subtracting spurious loss.

Mutant 1: replace the automatic-path decision with
`connection.fec_coding = true`.

Observed failure:

```text
thread 'serve::tests::automatic_fec_keeps_clean_ranges_reliable_then_codes_lossy_ranges' panicked at crates/vot-cli/src/serve/mod.rs:569:13:
assertion `left == right` failed
  left: true
 right: false
test result: FAILED. 0 passed; 1 failed
```

Mutant 2: remove the one-symbol safety margin from the repair calculation.

Observed failure:

```text
thread 'serve::tests::repair_count_tracks_real_loss_after_startup' panicked at crates/vot-cli/src/serve/mod.rs:514:9:
assertion `left == right` failed
  left: 1
 right: 2
test result: FAILED. 0 passed; 1 failed
```
