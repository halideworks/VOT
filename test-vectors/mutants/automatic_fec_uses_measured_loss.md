# Automatic FEC uses measured loss

Criteria:

- `VOT_DATAGRAM_FEC=auto` keeps new ranges on the reliable path until a
  meaningful path sample reaches the measured 5% corrected-loss crossover,
  then codes later ranges on the same connection.
- adaptive repair covers the expected missing sources plus one safety symbol,
  bounded by the shipped eight-symbol profile.
- decisions use recent counter deltas in 8,192-packet windows, retain coding
  between 3% and 5% loss, and discard a partial sample when carrier counters
  reset.

Passing evidence: `automatic_fec_keeps_clean_ranges_reliable_then_codes_lossy_ranges`
answers one range with zero loss and a second at 5% on the same negotiated,
credited session, asserting that only the second emits datagrams.
`repair_count_tracks_recent_real_loss_after_startup` pins the repair calculation at
its boundaries and after subtracting spurious loss.
`automatic_fec_follows_recent_loss_with_hysteresis` exercises both sides of
the hysteresis band and proves a clean recent window overrides lossy history.
`a_path_counter_reset_starts_a_new_fec_sample` proves pre-reset packets cannot
contaminate the next repair decision.

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
thread 'serve::tests::repair_count_tracks_recent_real_loss_after_startup' panicked at crates/vot-cli/src/serve/mod.rs:520:9:
assertion `left == right` failed
  left: 1
 right: 2
test result: FAILED. 0 passed; 1 failed
```

Mutant 3: use the 5% activation threshold to retain coding too, removing the
3% deactivation threshold.

Observed failure:

```text
thread 'serve::tests::automatic_fec_follows_recent_loss_with_hysteresis' panicked at crates/vot-cli/src/serve/mod.rs:557:13:
assertion `left == right` failed: at 738 losses of 16384
  left: false
 right: true
test result: FAILED. 0 passed; 1 failed
```

Mutant 4: retain the preceding window's loss count after a decision.

Observed failure:

```text
thread 'serve::tests::automatic_fec_follows_recent_loss_with_hysteresis' panicked at crates/vot-cli/src/serve/mod.rs:557:13:
assertion `left == right` failed: at 1229 losses of 32768
  left: true
 right: false
test result: FAILED. 0 passed; 1 failed
```

Mutant 5: retain accumulated losses when carrier counters reset.

Observed failure:

```text
thread 'serve::tests::a_path_counter_reset_starts_a_new_fec_sample' panicked at crates/vot-cli/src/serve/mod.rs:575:9:
assertion `left == right` failed
  left: 5
 right: 1
test result: FAILED. 0 passed; 1 failed
```
