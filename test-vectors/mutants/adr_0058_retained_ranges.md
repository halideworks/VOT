# ADR-0058 retained-range mutation evidence

The changed proof and retained-range paths were tested with Rust 1.97.1 and cargo-mutants 26.0.0. Of 85 generated mutants, 77 were caught by test failure and eight did not compile. None survived or timed out.

The generated diff sweep includes both proof crates, `vot-verified-range`, and the SDK. Selected viable mutants and their captured failures follow.

## vot-proof-blake3: verify_group_cvs, replacement `Ok(())`

```diff
--- crates/vot-proof-blake3/src/lib.rs
+++ replace verify_group_cvs -> Result<(), Error> with Ok(())
@@ -716,23 +716,17 @@
 pub fn verify_group_cvs(
     expected_root: &[u8; 32],
     object_len: u64,
     covered_offset: u64,
     covered_length: u64,
     cvs: &[[u8; 32]],
     proof: &[u8],
 ) -> Result<(), Error> {
-    let (first, end) = check_cover(object_len, covered_offset, covered_length)?;
-    if object_len <= GROUP_SIZE || cvs.len() as u64 != end - first {
-        return Err(Error::OutOfBounds);
-    }
-    verify_tree(expected_root, object_len, first, end, proof, &mut |index| {
-        cvs[(index - first) as usize]
-    })
+    Ok(()) /* ~ changed by cargo-mutants ~ */
 }

 fn check_cover(object_len: u64, covered_offset: u64, data_len: u64) -> Result<(u64, u64), Error> {
     if !covered_offset.is_multiple_of(GROUP_SIZE) || data_len == 0 {
         return Err(Error::OutOfBounds);
     }
     let covered_end = covered_offset
         .checked_add(data_len)
```

Build succeeded. Tests exited with status 101. Captured failures include:

- `tests::cached_commitments_share_byte_verification_and_validate_their_cover`


## vot-proof-sha256: verify_piece_hashes, replacement `Ok(())`

```diff
--- crates/vot-proof-sha256/src/lib.rs
+++ replace verify_piece_hashes -> Result<(), Error> with Ok(())
@@ -600,21 +600,17 @@
 pub fn verify_piece_hashes(
     expected_root: &[u8; 32],
     object_len: u64,
     covered_offset: u64,
     covered_length: u64,
     hashes: &[[u8; 32]],
     proof: &[u8],
 ) -> Result<(), Error> {
-    let (first, end) = check_cover(object_len, covered_offset, covered_length)?;
-    if object_len <= PIECE_SIZE {
-        return Err(Error::OutOfBounds);
-    }
-    verify_hashes(expected_root, object_len, first, end, hashes, proof)
+    Ok(()) /* ~ changed by cargo-mutants ~ */
 }

 fn check_cover(object_len: u64, covered_offset: u64, data_len: u64) -> Result<(u64, u64), Error> {
     if !covered_offset.is_multiple_of(PIECE_SIZE) || data_len == 0 {
         return Err(Error::OutOfBounds);
     }
     let covered_end = covered_offset
         .checked_add(data_len)
```

Build succeeded. Tests exited with status 101. Captured failures include:

- `tests::proof_input_bounds_window_allocation_before_decoding`
- `tests::cached_commitments_share_byte_verification_and_validate_their_cover`


## vot-proof-sha256: window_capacity, replacement `>=`

```diff
--- crates/vot-proof-sha256/src/lib.rs
+++ replace > with >= in window_capacity
@@ -856,17 +856,17 @@
 fn window_capacity(
     piece_count: u64,
     window_start: u64,
     window_width: u64,
     covered: usize,
     proof_bytes: usize,
 ) -> Result<usize, Error> {
     let supplied = window_width.min(piece_count - window_start) - covered as u64;
-    if supplied > (proof_bytes / 32) as u64 {
+    if supplied >= /* ~ changed by cargo-mutants ~ */ (proof_bytes / 32) as u64 {
         return Err(Error::MalformedProof);
     }
     usize::try_from(window_width).map_err(|_| Error::OutOfBounds)
 }

 #[cfg(test)]
 mod tests {
```

Build succeeded. Tests exited with status 101. Captured failures include:

- `tests::proof_input_bounds_window_allocation_before_decoding`
- `tests::proof_decoder_rebuilds_every_subrange_across_padding`
- `tests::cached_commitments_share_byte_verification_and_validate_their_cover`


## vot-verified-range: RetainedRange::verify_for, replacement `||`

```diff
--- crates/vot-verified-range/src/retained.rs
+++ replace && with || in RetainedRange::verify_for
@@ -94,17 +94,17 @@
         let relative = usize::try_from(relative).map_err(|_| Error::LengthExceeded)?;
         let relative_end = usize::try_from(covered_end - self.range.covered_offset)
             .map_err(|_| Error::LengthExceeded)?;
         let data = self
             .range
             .data
             .get(relative..relative_end)
             .ok_or(Error::LengthExceeded)?;
-        if relative_end != self.range.data.len() && !relative_end.is_multiple_of(GROUP_SIZE) {
+        if relative_end != self.range.data.len() || /* ~ changed by cargo-mutants ~ */ !relative_end.is_multiple_of(GROUP_SIZE) {
             return Err(Error::LengthExceeded);
         }
         if object.length <= RANGE_UNIT_BYTES {
             if !proof.is_empty() || self.small_root != Some(object.root) {
                 return Err(Error::ProofInvalid);
             }
         } else {
             let first = relative / GROUP_SIZE;
```

Build succeeded. Tests exited with status 101. Captured failures include:

- `retained::tests::retained_subranges_match_byte_verification_across_tree_and_tail_boundaries`
- `retained::tests::small_roots_and_group_commitments_are_kept_distinct_on_growth_and_truncation`
- `retained::tests::nonzero_retention_binds_suite_offset_length_and_original_tail`


## Reproduction

```sh
git diff 2ba1f7a -- crates > changed.diff
cargo +1.97.1 mutants --package vot-proof-blake3 --package vot-proof-sha256 \
  --package vot-verified-range --package vot-sdk --in-diff changed.diff \
  --jobs 4 --timeout 30 -C=--offline -C=--locked
```
