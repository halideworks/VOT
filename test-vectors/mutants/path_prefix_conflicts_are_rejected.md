# Path prefix conflicts are rejected

Criterion: a file cannot be a path ancestor of another entry. The
check is the last accepted canonical key plus whether that entry was a
file. A shared spelling prefix is not an ancestor.

Passing evidence: `a_file_cannot_be_the_ancestor_of_another_entry`
accepts a directory over a child and `foo` next to `foobar`, and
rejects a file over a child on one page and across pages.

Mutants: drop the `EntryKind::File` guard, which the directory-plus-child
case fails. Drop the 0-byte boundary in `is_path_prefix`, which
`foo`/`foobar` fails. Drop the progressive last-file check, which the
cross-page file-then-child case fails.
