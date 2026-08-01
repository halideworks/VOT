# Unsupported profile rejection

Criterion: a provider rejects a requested assurance profile it cannot perform.

Passing evidence: `Commit.tla` chooses a provider capability set independently from the requested profile. `Admit` requires support, and `RejectUnsupported` records a terminal rejection before any assurance is performed.

Mutant: `InjectUnsupportedAdvance` permits an unsupported request to jump directly to `PUBLISHED`.

Observed failure: TLC reports `Invariant UnsupportedNeverAdvanced is violated` under `CommitUnsupportedAdvance.cfg`. CI requires that failure text.
