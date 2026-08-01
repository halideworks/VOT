# source_mutation_prevents_seal

The control accepts the original page, then presents a seal derived from a
mutated source page. Rejection occurs in `verify_seal`.

Mutant:

```diff
-|| seal.final_page_digest != *last_digest
```

Observed failure:

```text
assertion left == right failed
left: Ok(())
right: Err(InvalidSeal)
test result: FAILED. 0 passed; 1 failed
```
