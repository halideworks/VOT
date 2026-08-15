# Proof node split is checked

Criterion: Bao tree split uses the largest power of two strictly below
the node count. A count of 0 or 1 does not shift or subtract through
wraparound. Intersection does not add start and count in a way that
overflows.

Passing evidence: `a_node_splits_on_the_largest_power_of_two_below_its_count`.

Mutants: drop the `count < 2` zeros, which the 0 and 1 cases fail.
Change a tabulated left_count, which the matching row fails.
