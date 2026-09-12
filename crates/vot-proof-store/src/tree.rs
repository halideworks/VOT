use std::sync::Arc;

use crate::ProofNode;

type Merge = fn(&ProofNode, &ProofNode) -> ProofNode;

/// Immutable, shared proof subtrees with a power-of-two left child.
///
/// Hashes use the supplied non-root merge operation. Padding and root-mode
/// hashing remain the suite's responsibility. This is computation state,
/// not evidence of source ownership or durable storage.
#[derive(Clone)]
pub struct ProofTree {
    root: Option<Arc<Node>>,
    merge: Merge,
}

struct Node {
    hash: ProofNode,
    count: usize,
    children: Option<(Arc<Self>, Arc<Self>)>,
}

/// Borrowed view for walking retained branches without restarting at the root.
#[derive(Clone, Copy)]
pub struct ProofSubtree<'a>(&'a Node);

impl ProofSubtree<'_> {
    /// Non-root hash of this subtree, without suite-specific padding.
    #[must_use]
    pub const fn hash(self) -> ProofNode {
        self.0.hash
    }

    /// Number of leaves below this nonempty subtree.
    #[must_use]
    pub const fn leaf_count(self) -> usize {
        self.0.count
    }

    /// Left and right children, or `None` for a leaf.
    #[must_use]
    pub fn children(self) -> Option<(Self, Self)> {
        self.0
            .children
            .as_ref()
            .map(|(left, right)| (Self(left), Self(right)))
    }

    /// An exact retained descendant, using a start relative to this subtree.
    #[must_use]
    pub fn subtree(self, start: usize, count: usize) -> Option<Self> {
        self.0.subtree(start, count).map(Self)
    }
}

fn split(count: usize) -> usize {
    1 << (usize::BITS - (count - 1).leading_zeros() - 1)
}

impl Node {
    fn join(left: Arc<Self>, right: Arc<Self>, merge: Merge) -> Arc<Self> {
        Arc::new(Self {
            hash: merge(&left.hash, &right.hash),
            count: left.count + right.count,
            children: Some((left, right)),
        })
    }

    fn build(leaves: &[ProofNode], merge: Merge) -> Arc<Self> {
        if leaves.len() == 1 {
            return Arc::new(Self {
                hash: leaves[0],
                count: 1,
                children: None,
            });
        }
        let (left, right) = leaves.split_at(split(leaves.len()));
        Self::join(Self::build(left, merge), Self::build(right, merge), merge)
    }

    fn prefix(node: &Arc<Self>, count: usize, merge: Merge) -> Arc<Self> {
        if count == node.count {
            return Arc::clone(node);
        }
        let (left, right) = node
            .children
            .as_ref()
            .expect("a strict nonempty prefix branches");
        if count <= left.count {
            Self::prefix(left, count, merge)
        } else {
            Self::join(
                Arc::clone(left),
                Self::prefix(right, count - left.count, merge),
                merge,
            )
        }
    }

    fn replace(node: &Arc<Self>, start: usize, leaves: &[ProofNode], merge: Merge) -> Arc<Self> {
        if leaves.is_empty() {
            return Arc::clone(node);
        }
        if start == 0 && leaves.len() == node.count {
            return Self::build(leaves, merge);
        }
        let (left, right) = node
            .children
            .as_ref()
            .expect("a partial replacement branches");
        let left_len = left.count.saturating_sub(start).min(leaves.len());
        let updated_left = if left_len == 0 {
            Arc::clone(left)
        } else {
            Self::replace(left, start, &leaves[..left_len], merge)
        };
        let updated_right = Self::replace(
            right,
            start.saturating_sub(left.count),
            &leaves[left_len..],
            merge,
        );
        Self::join(updated_left, updated_right, merge)
    }

    fn append(node: &Arc<Self>, leaves: &[ProofNode], merge: Merge) -> Arc<Self> {
        if leaves.is_empty() {
            return Arc::clone(node);
        }
        let left_width = split(node.count + 1);
        let take = (left_width - (node.count - left_width)).min(leaves.len());
        let next = if node.count == left_width {
            Self::join(Arc::clone(node), Self::build(&leaves[..take], merge), merge)
        } else {
            let (left, right) = node.children.as_ref().expect("an incomplete tree branches");
            Self::join(
                Arc::clone(left),
                Self::append(right, &leaves[..take], merge),
                merge,
            )
        };
        Self::append(&next, &leaves[take..], merge)
    }

    fn subtree(&self, start: usize, count: usize) -> Option<&Self> {
        if start == 0 && count == self.count {
            return Some(self);
        }
        let (left, right) = self.children.as_ref()?;
        if start < left.count {
            left.subtree(start, count)
        } else {
            right.subtree(start - left.count, count)
        }
    }
}

impl ProofTree {
    /// Builds retained subtrees from all supplied leaves.
    #[must_use]
    pub fn new(leaves: &[ProofNode], merge: fn(&ProofNode, &ProofNode) -> ProofNode) -> Self {
        Self {
            root: (!leaves.is_empty()).then(|| Node::build(leaves, merge)),
            merge,
        }
    }

    /// Number of represented leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |node| node.count)
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Hash of an exact retained subtree, without padding or root-mode hashing.
    #[must_use]
    pub fn subtree(&self, start: usize, count: usize) -> Option<ProofNode> {
        self.root()?.subtree(start, count).map(ProofSubtree::hash)
    }

    /// Borrowed root for a direct walk of the retained branches.
    #[must_use]
    pub fn root(&self) -> Option<ProofSubtree<'_>> {
        self.root.as_deref().map(ProofSubtree)
    }

    /// Replaces a contiguous leaf range and sets the new leaf count.
    ///
    /// Returns `None` for overflow, a range outside the new tree, or growth
    /// without all appended leaves. The original tree remains unchanged.
    /// Hashing and new nodes cost O(replaced leaves + log(tree size)). Dropping
    /// snapshots can additionally reclaim every node they alone retain.
    #[must_use]
    pub fn updated(&self, start: usize, leaves: &[ProofNode], count: usize) -> Option<Self> {
        let end = start.checked_add(leaves.len())?;
        if end > count || (count > self.len() && (start > self.len() || end != count)) {
            return None;
        }
        let retained = count.min(self.len());
        let root = if retained == 0 {
            (!leaves.is_empty()).then(|| Node::build(leaves, self.merge))
        } else {
            let previous = self.root.as_ref()?;
            let prefix = Node::prefix(previous, retained, self.merge);
            let replace_count = retained.saturating_sub(start).min(leaves.len());
            let replaced = Node::replace(&prefix, start, &leaves[..replace_count], self.merge);
            Some(Node::append(
                &replaced,
                &leaves[replace_count..],
                self.merge,
            ))
        };
        Some(Self {
            root,
            merge: self.merge,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn merge(left: &ProofNode, right: &ProofNode) -> ProofNode {
        std::array::from_fn(|index| left[index].wrapping_mul(17).wrapping_add(right[index]))
    }

    fn reference(
        leaves: &[ProofNode],
        first: usize,
        nodes: &mut BTreeMap<(usize, usize), ProofNode>,
    ) -> ProofNode {
        let hash = if leaves.len() == 1 {
            leaves[0]
        } else {
            let half = leaves.len().next_power_of_two() / 2;
            merge(
                &reference(&leaves[..half], first, nodes),
                &reference(&leaves[half..], first + half, nodes),
            )
        };
        nodes.insert((first, leaves.len()), hash);
        hash
    }

    #[test]
    fn edits_match_rebuilding_and_leave_earlier_snapshots_unchanged() {
        for initial in 0..20 {
            let original: Vec<_> = (0..initial)
                .map(|i| [u8::try_from(i).unwrap(); 32])
                .collect();
            let tree = ProofTree::new(&original, merge);
            assert_eq!(tree.is_empty(), initial == 0);
            if initial == 0 {
                assert!(tree.root().is_none());
            } else {
                let root = tree.root().unwrap();
                assert_eq!(root.leaf_count(), initial);
                let mut pending = vec![root];
                let mut actual = Vec::new();
                while let Some(node) = pending.pop() {
                    if let Some((left, right)) = node.children() {
                        pending.push(right);
                        pending.push(left);
                    } else {
                        assert_eq!(node.leaf_count(), 1);
                        actual.push(node.hash());
                    }
                }
                assert_eq!(actual, original);
            }
            for count in 0..24 {
                for start in 0..=count {
                    let replacement = vec![[91; 32]; count - start];
                    let result = tree.updated(start, &replacement, count);
                    if count > initial && start > initial {
                        assert!(result.is_none());
                        continue;
                    }
                    let result = result.unwrap();
                    let mut expected = original[..initial.min(count)].to_vec();
                    expected.resize(count, [0; 32]);
                    expected[start..].copy_from_slice(&replacement);
                    let mut fresh = BTreeMap::new();
                    if !expected.is_empty() {
                        reference(&expected, 0, &mut fresh);
                    }
                    assert_eq!(result.len(), count);
                    for first in 0..=count {
                        for width in 0..=count - first {
                            assert_eq!(
                                result.subtree(first, width),
                                fresh.get(&(first, width)).copied()
                            );
                        }
                    }
                    assert_eq!(
                        tree.subtree(0, initial),
                        ProofTree::new(&original, merge).subtree(0, initial)
                    );
                }
            }
            assert!(tree.subtree(usize::MAX, 1).is_none());
            assert!(tree.subtree(initial, 1).is_none());
            assert!(tree.subtree(0, 0).is_none());
            assert!(tree.updated(usize::MAX, &[[0; 32]], initial).is_none());
            assert!(tree.updated(initial + 1, &[], initial).is_none());
            assert!(tree.updated(0, &[], initial + 1).is_none());
        }
    }

    #[test]
    fn a_small_edit_shares_unchanged_subtrees_and_bounds_merges() {
        static MERGES: AtomicUsize = AtomicUsize::new(0);
        fn counted(left: &ProofNode, right: &ProofNode) -> ProofNode {
            MERGES.fetch_add(1, Ordering::Relaxed);
            merge(left, right)
        }
        let tree = ProofTree::new(&vec![[7; 32]; 4096], counted);
        MERGES.store(0, Ordering::Relaxed);
        let changed = tree.updated(2048, &[[8; 32]], 4096).unwrap();
        assert_eq!(MERGES.load(Ordering::Relaxed), 12);
        let (old_left, _) = tree.root.as_ref().unwrap().children.as_ref().unwrap();
        let (new_left, _) = changed.root.as_ref().unwrap().children.as_ref().unwrap();
        assert!(Arc::ptr_eq(old_left, new_left));
        MERGES.store(0, Ordering::Relaxed);
        let grown = changed.updated(4096, &[[9; 32]], 4097).unwrap();
        assert_eq!(MERGES.load(Ordering::Relaxed), 1);
        MERGES.store(0, Ordering::Relaxed);
        let shrunk = grown.updated(4096, &[], 4096).unwrap();
        assert_eq!(MERGES.load(Ordering::Relaxed), 0);
        assert!(Arc::ptr_eq(
            changed.root.as_ref().unwrap(),
            shrunk.root.as_ref().unwrap()
        ));
    }
}
