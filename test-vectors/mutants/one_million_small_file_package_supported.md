# One million small-file package

Criterion: one million small files pass through bounded pack construction.

Passing evidence: the explicit `million_package` gate streams 1,000,000 empty
logical files through `StreamingPacker`. It produces 123 packs, preserves all
entries, and never retains more than 8,192 entry descriptors in one pack.

Mutant: remove the entry-count flush condition.

Observed failure: the largest pack contains more than 8,192 entries and the
gate fails.

The isolated required mutation run completed with:

```text
vot-pack: 51 total, 44 caught, 7 unviable, 0 missed
```
