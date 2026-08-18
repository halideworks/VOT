# FEC missing-only solve subtracts known sources

The decoder reduces only the missing source columns. Every source that did
arrive is therefore multiplied by its repair coefficient and subtracted from
the repair symbol before elimination.

Mutant:

```diff
-for source_esi in (0..k).filter(|source_esi| symbols[*source_esi].is_some()) {
-    gf::mul_add(&mut row[m..], coefficients[source_esi], symbols[source_esi].expect("seen"));
-}
```

Observed failure:

```text
test tests::every_erasure_pattern_within_the_repair_count_decodes ... FAILED
assertion `left == right` failed: k=2 r=2 mask=101
left: Ok([[80, 97, 114], [47, 183, 50]])
right: Ok([[80, 97, 114], [87, 104, 121]])
```
