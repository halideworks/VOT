# Growing-file source lifecycle mutation checks

The changed `CaptureSource` implementation rejects all 71 viable generated
mutants. Fifteen variants do not compile. No mutant survives or times out.

```sh
git diff origin/main...HEAD > source.diff
TMPDIR=/tmp CARGO_NET_OFFLINE=true cargo +1.97.1 mutants -p vot-sdk-file \
  -f 'crates/vot-sdk-file/src/capture/source.rs' --in-diff source.diff \
  --jobs 4 -- --locked
```

An initial run exposed three equivalent-result variants that changed I/O work:
preparing a same-length truncation, reading the entire truncated prefix, and
using a different promotion window. Exact read-byte assertions now reject the
first two. Promotion was simplified to a 65,537-byte window with an explicit
small-object guard. The promotion multiplier variant is rejected by the
small-to-large lifecycle test. The same-length comparison, truncation offset,
and promotion multiplier were also applied by hand; each failed its named test.

The I/O check requires zero bytes for a no-op refresh or aligned truncation,
131,072 bytes for a changed header group, and exactly the affected tail for
append. A full dirty hint on an existing large object is exercised for both
suites, so the promotion window cannot leak into an interior-group update.

Recovery regressions refuse an old short tail after interrupted zero extension,
including when the extended payload already hashes to the selected new root.
The adapter must reconcile incomplete staging before exposing a checkpoint.
Tests also fail source changes between preparation and installation, missing
source data, capture/source aliases, late growth during completion, missed
header rewrites, and stale completion after a staged read failure.
