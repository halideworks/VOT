# FEC product tables are indexed by coefficient

The shared Galois-field product table returns the row for the requested
coefficient.

Mutant:

```diff
-&PRODUCTS[coefficient as usize]
+&PRODUCTS[coefficient.wrapping_add(1) as usize]
```

Observed failure:

```text
test gf::tests::every_product_table_matches_the_scalar_rule ... FAILED
assertion `left == right` failed: 1 times 1
left: 2
right: 1
```
