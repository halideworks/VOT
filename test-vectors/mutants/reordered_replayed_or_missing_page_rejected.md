# reordered_replayed_or_missing_page_rejected

The test sends reordered, replayed, missing, and broken-chain pages through
`ProgressiveIngest::accept` and checks the state-machine error.

Mutant:

```diff
-if page.index != self.digests.len() as u64 {
-    return Err(Error::WrongPageIndex);
-}
```

Observed failure:

```text
assertion left == right failed
left: Err(BrokenPageChain)
right: Err(WrongPageIndex)
test result: FAILED. 0 passed; 1 failed
```
