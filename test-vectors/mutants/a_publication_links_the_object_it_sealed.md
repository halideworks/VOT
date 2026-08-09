# A publication links the object it sealed

Criterion: what reaches the destination is the inode publication sealed, not
whatever the staging name resolves to when the link is made; and recovery
decides by identity rather than by a name that publication removes.

This exists because sealing proved an inode and publishing linked a name, with
nothing joining the two. Sealing a staging file, replacing the staging name
with an unrelated file, and calling `publish()` returned a success receipt and
put the impostor's bytes at the destination. On Fast and Balanced the window
is microseconds; on Strict it is the whole `O_DIRECT` read-back, so an object
could be hashed and certified while a different inode was linked and
receipted. Found by review of PR 140 after it merged, and reproduced against
the merge commit.

Passing evidence: `a_name_swapped_after_sealing_is_never_published` seals,
swaps the name, and proves publication refuses and the destination stays
absent. `publication_is_retryable_once_the_destination_is_the_sealed_object`
proves a destination that is already the sealed inode is this call having run
before, and that somebody else's file at the destination still is not.
`recovery_finishes_a_link_the_journal_never_recorded` covers the crash window
between the hard link and the record of it, where the staging alias is the
only evidence.

Mutants: drop the identity comparison after the link (`if
Identity::of_path(&self.destination)? == sealed` to unconditional `Ok(())`),
which `a_name_swapped_after_sealing_is_never_published` fails with "a swapped
name published"; treat any link error as a retry rather than asking whether
the destination is the sealed object; compare only two of the three parents in
`flushed_directories`, which leaves the staging unlink unsynced in the
single-directory layout.
