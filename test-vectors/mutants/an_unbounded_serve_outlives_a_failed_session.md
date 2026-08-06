# An unbounded serve outlives a failed session

Criterion: a `vot serve` with no session bound survives any one session's
failure and is ended only by its own endpoint failing; a serve bounded to a
count surfaces a session's failure, answers exactly its bound, and no more.

This exists because one fetch that connected and died left its serve session
making no progress; `drive` returned `Stalled` and `serve_bundle` propagated
it, killing the server for every later client. Observed twice on 2026-08-06
while measuring the wire between erebus and tr-desktop
(`docs/perf-engineering.md`). The loop now lives in `drive.rs` as
`serve_sessions`, under the mutation gate `wire.rs` is excluded from.

Passing evidence: `an_unbounded_serve_outlives_a_failed_session` serves three
sessions from a factory: one that stalls (an empty carrier), one that settles,
and one where the factory itself fails. It proves the unbounded serve reaches
the third, ends with the factory's error rather than the stalled session's,
and that a bounded serve both stops at a failure and answers exactly its bound
when sessions succeed (the factory refuses any call past the bound).

Mutants: propagate a session's failure regardless of the bound
(`if sessions.is_some()` to `if true`); answer one session past the bound
(`answered < bound` to `<=`); never count an answer (`answered += 1` to `*=`).
The last two were found missed by the diff mutation run and the bounded
success scenario was added to kill them; the rerun catches all six mutants the
diff produces.

Observed failure, first mutant:

```text
thread 'drive::tests::an_unbounded_serve_outlives_a_failed_session' panicked at crates/vot-cli/src/drive.rs:272:9:
the endpoint's own failure ends the serve, a session's never
```

Observed failure, count mutants (from the diff mutation run):

```text
MISSED   crates/vot-cli/src/drive.rs:199:48: replace < with <= in serve_sessions
MISSED   crates/vot-cli/src/drive.rs:210:18: replace += with *= in serve_sessions
6 mutants tested in 21s: 6 caught   (after the bounded scenario landed)
```
