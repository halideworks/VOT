# Pack layout is validated

Criterion: a pack's entries are 8-byte aligned, in offset order without
overlap, and inside the pack bytes. extract refuses a pack that fails
that check before it hashes a slice.

Passing evidence: `a_pack_layout_refuses_overlap_misalignment_and_overflow`
and the existing alignment assertions on built packs.

Mutants: drop the `offset < cursor` check, which the duplicated-entry
overlap case fails. Drop the alignment modulus, which the offset-1 case
fails. Drop the end-versus-pack-length check, which the length-past-end
case fails.
