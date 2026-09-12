# ADR-0061 mutation evidence

The focused positioned-I/O run found ten mutants: nine caught, one unviable,
zero missed and zero timeouts. Removing reads or writes, offset advancement,
loop termination, or the retry budget fails the short-I/O and native file tests.
The unviable replacement of generic `retry<T>` with `Ok(Default::default())`
requires an absent `T: Default` bound.

The changed common filesystem run found 25 mutants: 22 caught, three unviable,
zero missed and zero timeouts. The other unviable bodies require `File: Default`.
Identity and link counts are checked against the held file and a hard-link alias.

CI initially reported a surviving comparison in Windows journal error mapping
because a statement-level Windows cfg removed it from Linux tests. The mapping
now compiles for Windows and unit tests. The test distinguishes sharing violation
32 from native errors 2, 5, 33 and an error without a native code. Hand-applying
the exact `==` to `!=` mutant fails that test before the follow-up push.

```sh
TMPDIR=/tmp CARGO_NET_OFFLINE=true cargo +1.97.1 mutants \
  -p vot-platform-fs -f crates/vot-platform-fs/src/positioned.rs \
  --jobs 2 -- --locked
```

Windows-only native files follow the existing exclusion convention for the
Linux mutation runner. They compile under deny-warning Clippy and their native
ownership, ACL, replacement and sparse-file tests run in `proof-store-native`.
Capture state, journal replay and metadata logic remain common code under their
existing mutation jobs. No common capture guards are excluded.
