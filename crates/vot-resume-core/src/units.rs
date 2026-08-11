//! Run-length unit sets for resume checkpoint state.
//! Reduces memory from one entry per unit to one entry per run.

use std::fmt;

/// Highest representable unit index. Runs compare by exclusive end, so
/// `u64::MAX` itself is excluded.
pub const MAX_UNIT: u64 = u64::MAX - 1;

/// Sorted set of unit indices held as disjoint, non-adjacent runs.
/// Representation is unique: adjacent runs are always merged.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnitRanges {
    runs: Vec<(u64, u64)>,
}

impl UnitRanges {
    #[must_use]
    pub const fn new() -> Self {
        Self { runs: Vec::new() }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Number of contiguous runs, which is what the set costs to hold and to
    /// encode. Not the number of units.
    #[must_use]
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Number of units in the set.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.runs
            .iter()
            .fold(0_u64, |total, (_, length)| total.saturating_add(*length))
    }

    /// Highest unit in the set.
    #[must_use]
    pub fn max(&self) -> Option<u64> {
        let (start, length) = *self.runs.last()?;
        Some(start.saturating_add(length).saturating_sub(1))
    }

    /// Runs as `(start, length)` pairs, in order.
    pub fn runs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.runs.iter().copied()
    }

    /// Every unit in the set, in order. Avoid for large objects.
    pub fn units(&self) -> impl Iterator<Item = u64> + '_ {
        self.runs
            .iter()
            .flat_map(|(start, length)| *start..start.saturating_add(*length))
    }

    #[must_use]
    pub fn contains(&self, unit: u64) -> bool {
        self.run_index(unit).is_some()
    }

    /// Index of the run containing `unit`.
    fn run_index(&self, unit: u64) -> Option<usize> {
        let index = match self.runs.binary_search_by_key(&unit, |(start, _)| *start) {
            Ok(index) => return Some(index),
            Err(0) => return None,
            Err(index) => index - 1,
        };
        let (start, length) = self.runs[index];
        (unit - start < length).then_some(index)
    }

    /// Adds one unit.
    ///
    /// Units above [`MAX_UNIT`] are ignored, the same index [`from_runs`]
    /// refuses, so every accessor agrees about what the set holds.
    ///
    /// [`from_runs`]: Self::from_runs
    pub fn insert(&mut self, unit: u64) {
        if unit > MAX_UNIT {
            return;
        }
        let at = self.runs.partition_point(|(start, _)| *start <= unit);
        let previous = at.checked_sub(1);
        if previous.is_some_and(|index| unit < self.end_of(index)) {
            return;
        }
        let joins_previous = previous.is_some_and(|index| self.end_of(index) == unit);
        let joins_next = self
            .runs
            .get(at)
            .is_some_and(|(start, _)| *start == unit.saturating_add(1));
        match (joins_previous, joins_next) {
            (true, true) => {
                let (_, next_length) = self.runs.remove(at);
                let previous = at - 1;
                self.runs[previous].1 = self.runs[previous]
                    .1
                    .saturating_add(1)
                    .saturating_add(next_length);
            }
            (true, false) => {
                let previous = at - 1;
                self.runs[previous].1 = self.runs[previous].1.saturating_add(1);
            }
            (false, true) => {
                self.runs[at] = (unit, self.runs[at].1.saturating_add(1));
            }
            (false, false) => self.runs.insert(at, (unit, 1)),
        }
    }

    /// One past the last unit of a run.
    fn end_of(&self, index: usize) -> u64 {
        let (start, length) = self.runs[index];
        start.saturating_add(length)
    }

    /// Adds every unit an iterator yields.
    pub fn extend_units<I: IntoIterator<Item = u64>>(&mut self, units: I) {
        for unit in units {
            self.insert(unit);
        }
    }

    /// Adds every unit of `other`.
    pub fn union(&mut self, other: &Self) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            self.runs.clone_from(&other.runs);
            return;
        }
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.runs.len() + other.runs.len());
        let mut left = self.runs.iter().copied().peekable();
        let mut right = other.runs.iter().copied().peekable();
        loop {
            let take_left = match (left.peek(), right.peek()) {
                (Some((left_start, _)), Some((right_start, _))) => left_start <= right_start,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let run = if take_left { left.next() } else { right.next() };
            let Some((start, length)) = run else {
                break;
            };
            push_run(&mut merged, start, length);
        }
        self.runs = merged;
    }

    /// Builds a set from `(start, length)` runs. Normalises order and merges.
    ///
    /// # Errors
    /// Rejects a zero-length run or one whose end overflows.
    pub fn from_runs<I: IntoIterator<Item = (u64, u64)>>(runs: I) -> Result<Self, RunError> {
        Self::from_runs_bounded(runs, usize::MAX)
    }

    /// Builds a set from at most `max_input_runs` `(start, length)` runs.
    /// Normalises order and merges after the bounded input has been validated.
    ///
    /// # Errors
    /// Rejects a zero-length run, one whose end overflows, or an input that
    /// yields more than `max_input_runs` runs. The first excess run is neither
    /// validated nor stored, and no later input is consumed.
    pub fn from_runs_bounded<I: IntoIterator<Item = (u64, u64)>>(
        runs: I,
        max_input_runs: usize,
    ) -> Result<Self, RunError> {
        let mut collected: Vec<(u64, u64)> = Vec::new();
        for (start, length) in runs {
            if collected.len() == max_input_runs {
                return Err(RunError::TooManyRuns);
            }
            if length == 0 {
                return Err(RunError::EmptyRun);
            }
            start.checked_add(length).ok_or(RunError::EndOverflow)?;
            collected.push((start, length));
        }
        collected.sort_unstable();
        let mut normalised: Vec<(u64, u64)> = Vec::with_capacity(collected.len());
        for (start, length) in collected {
            push_run(&mut normalised, start, length);
        }
        Ok(Self { runs: normalised })
    }

    /// Units in this set that `other` does not contain. Single-pass over both.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut others = other.runs.iter().copied().peekable();
        for (start, length) in self.runs.iter().copied() {
            let end = start.saturating_add(length);
            let mut cursor = start;
            while let Some((other_start, other_length)) = others.peek().copied() {
                let other_end = other_start.saturating_add(other_length);
                if other_end <= cursor {
                    others.next();
                    continue;
                }
                if other_start >= end {
                    break;
                }
                if other_start > cursor {
                    push_run(&mut runs, cursor, other_start - cursor);
                }
                cursor = cursor.max(other_end);
                if cursor >= end {
                    break;
                }
                others.next();
            }
            if cursor < end {
                push_run(&mut runs, cursor, end - cursor);
            }
        }
        Self { runs }
    }

    /// Units below `total_units` not in the set. Lazy: avoids materializing
    /// the full gap list.
    pub fn missing(&self, total_units: u64) -> impl Iterator<Item = u64> + '_ {
        let leading = std::iter::once((
            0,
            self.runs.first().map_or(total_units, |(start, _)| *start),
        ));
        let between = self.runs.windows(2).map(|pair| {
            let (start, length) = pair[0];
            (start.saturating_add(length), pair[1].0)
        });
        let trailing = std::iter::once(
            self.runs
                .last()
                .map_or((total_units, total_units), |(start, length)| {
                    (start.saturating_add(*length), total_units)
                }),
        );
        leading
            .chain(between)
            .chain(trailing)
            .flat_map(move |(from, to)| from.min(total_units)..to.min(total_units))
    }
}

/// Appends a run to a list already in order, merging when it touches the tail.
fn push_run(runs: &mut Vec<(u64, u64)>, start: u64, length: u64) {
    let end = start.saturating_add(length);
    if let Some(last) = runs.last_mut() {
        let last_end = last.0.saturating_add(last.1);
        if start <= last_end {
            last.1 = end.max(last_end).saturating_sub(last.0);
            return;
        }
    }
    runs.push((start, length));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunError {
    EmptyRun,
    EndOverflow,
    TooManyRuns,
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRun => formatter.write_str("a checkpoint run covers no units"),
            Self::EndOverflow => formatter.write_str("a checkpoint run ends past u64"),
            Self::TooManyRuns => formatter.write_str("checkpoint run count exceeds its limit"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RunError, UnitRanges};

    fn ranges(units: impl IntoIterator<Item = u64>) -> UnitRanges {
        let mut set = UnitRanges::new();
        set.extend_units(units);
        set
    }

    #[test]
    fn a_contiguous_transfer_costs_one_run() {
        let set = ranges(0..10_000);
        assert_eq!(set.run_count(), 1);
        assert_eq!(set.count(), 10_000);
        assert_eq!(set.max(), Some(9_999));
        assert_eq!(set.runs().collect::<Vec<_>>(), vec![(0, 10_000)]);
    }

    #[test]
    fn insertion_order_does_not_change_the_set() {
        let forward = ranges(0..64);
        let backward = ranges((0..64).rev());
        let shuffled = ranges(
            [32, 0, 63, 1, 31, 33]
                .into_iter()
                .chain(2..31)
                .chain(34..63),
        );
        assert_eq!(forward, backward);
        assert_eq!(forward, shuffled);
        assert_eq!(forward.run_count(), 1);
    }

    #[test]
    fn a_gap_becomes_two_runs_and_closing_it_merges_them() {
        let mut set = ranges([0, 1, 2, 4, 5]);
        assert_eq!(set.runs().collect::<Vec<_>>(), vec![(0, 3), (4, 2)]);
        set.insert(3);
        assert_eq!(set.runs().collect::<Vec<_>>(), vec![(0, 6)]);
        assert_eq!(set.count(), 6);
    }

    #[test]
    fn each_join_direction_is_handled() {
        let mut previous = ranges([0, 1]);
        previous.insert(2);
        assert_eq!(previous.runs().collect::<Vec<_>>(), vec![(0, 3)]);

        let mut next = ranges([5, 6]);
        next.insert(4);
        assert_eq!(next.runs().collect::<Vec<_>>(), vec![(4, 3)]);

        let mut isolated = ranges([0]);
        isolated.insert(9);
        assert_eq!(isolated.runs().collect::<Vec<_>>(), vec![(0, 1), (9, 1)]);

        let mut both = ranges([0, 2]);
        both.insert(1);
        assert_eq!(both.runs().collect::<Vec<_>>(), vec![(0, 3)]);
    }

    #[test]
    fn reinserting_a_unit_changes_nothing() {
        let mut set = ranges([0, 1, 2, 7]);
        let before = set.clone();
        for unit in [0, 1, 2, 7] {
            set.insert(unit);
        }
        assert_eq!(set, before);
        assert_eq!(set.count(), 4);
    }

    #[test]
    fn membership_matches_a_plain_set() {
        let present = [0, 1, 2, 5, 9, 10, 11, 40];
        let set = ranges(present);
        for unit in 0..45_u64 {
            assert_eq!(
                set.contains(unit),
                present.contains(&unit),
                "unit {unit} disagreed"
            );
        }
        assert!(!UnitRanges::new().contains(0));
    }

    #[test]
    fn union_merges_runs_without_expanding_units() {
        let mut left = ranges([0, 1, 2, 10, 11]);
        let right = ranges([3, 4, 12, 20]);
        left.union(&right);
        assert_eq!(
            left.runs().collect::<Vec<_>>(),
            vec![(0, 5), (10, 3), (20, 1)]
        );
        assert_eq!(left.count(), 9);

        let expected = left.clone();
        left.union(&UnitRanges::new());
        assert_eq!(left, expected);
        let mut empty = UnitRanges::new();
        empty.union(&expected);
        assert_eq!(empty, expected);
    }

    #[test]
    fn union_of_overlapping_runs_does_not_double_count() {
        let mut left = ranges(0..100);
        left.union(&ranges(50..150));
        assert_eq!(left.runs().collect::<Vec<_>>(), vec![(0, 150)]);
        assert_eq!(left.count(), 150);
    }

    #[test]
    fn runs_round_trip_through_from_runs() {
        let set = ranges([0, 1, 2, 9, 20, 21]);
        let rebuilt = UnitRanges::from_runs(set.runs()).unwrap();
        assert_eq!(rebuilt, set);

        assert_eq!(
            UnitRanges::from_runs([(9, 1), (0, 3), (3, 2)])
                .unwrap()
                .runs()
                .collect::<Vec<_>>(),
            vec![(0, 5), (9, 1)]
        );
        assert_eq!(
            UnitRanges::from_runs([(0, 10), (4, 2)])
                .unwrap()
                .runs()
                .collect::<Vec<_>>(),
            vec![(0, 10)]
        );
        assert_eq!(UnitRanges::from_runs([]).unwrap(), UnitRanges::new());
    }

    #[test]
    fn bounded_from_runs_enforces_zero_one_and_n_exactly() {
        assert_eq!(
            UnitRanges::from_runs_bounded([], 0).unwrap(),
            UnitRanges::new()
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(4, 1)], 0),
            Err(RunError::TooManyRuns)
        );

        assert_eq!(
            UnitRanges::from_runs_bounded([(4, 1)], 1)
                .unwrap()
                .runs()
                .collect::<Vec<_>>(),
            vec![(4, 1)]
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(4, 1), (8, 1)], 1),
            Err(RunError::TooManyRuns)
        );

        assert_eq!(
            UnitRanges::from_runs_bounded([(4, 2), (0, 2), (2, 3)], 3)
                .unwrap()
                .runs()
                .collect::<Vec<_>>(),
            vec![(0, 6)]
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(4, 2), (0, 2), (2, 3), (9, 1)], 3),
            Err(RunError::TooManyRuns)
        );
    }

    #[test]
    fn bounded_from_runs_stops_after_the_first_excess_item() {
        use std::cell::Cell;

        let consumed = Cell::new(0);
        let runs = [(0, 1), (2, 1), (4, 1), (6, 1)].into_iter().inspect(|_| {
            consumed.set(consumed.get() + 1);
        });
        assert_eq!(
            UnitRanges::from_runs_bounded(runs, 2),
            Err(RunError::TooManyRuns)
        );
        assert_eq!(consumed.get(), 3);
    }

    #[test]
    fn invalid_runs_at_or_before_the_limit_take_precedence() {
        assert_eq!(
            UnitRanges::from_runs_bounded([(0, 0), (2, 1)], 1),
            Err(RunError::EmptyRun)
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(0, 1), (u64::MAX, 1), (2, 1)], 2),
            Err(RunError::EndOverflow)
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(0, 1), (2, 0)], 1),
            Err(RunError::TooManyRuns)
        );
    }

    #[test]
    fn from_runs_rejects_a_run_that_covers_nothing_or_overflows() {
        assert_eq!(UnitRanges::from_runs([(0, 0)]), Err(RunError::EmptyRun));
        assert_eq!(
            UnitRanges::from_runs([(u64::MAX, 2)]),
            Err(RunError::EndOverflow)
        );
        assert_eq!(
            UnitRanges::from_runs([(u64::MAX, 1)]),
            Err(RunError::EndOverflow)
        );
        assert!(UnitRanges::from_runs([(u64::MAX - 1, 1)]).is_ok());
        assert_eq!(
            UnitRanges::from_runs_bounded([(u64::MAX, 2)], 1),
            Err(RunError::EndOverflow)
        );
        assert_eq!(
            UnitRanges::from_runs_bounded([(u64::MAX, 1)], 1),
            Err(RunError::EndOverflow)
        );
        assert!(UnitRanges::from_runs_bounded([(u64::MAX - 1, 1)], 1).is_ok());
    }

    #[test]
    fn missing_units_are_the_complement_below_the_total() {
        let set = ranges([0, 1, 4, 7, 8, 9]);
        assert_eq!(set.missing(10).collect::<Vec<_>>(), vec![2, 3, 5, 6]);
        assert_eq!(ranges(0..10).missing(10).count(), 0);
        assert_eq!(
            UnitRanges::new().missing(4).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(ranges([0, 5]).missing(3).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(set.missing(0).count(), 0);
    }

    #[test]
    fn units_expands_back_to_individual_indices() {
        let set = ranges([0, 1, 2, 9]);
        assert_eq!(set.units().collect::<Vec<_>>(), vec![0, 1, 2, 9]);
        assert_eq!(UnitRanges::new().units().count(), 0);
    }

    #[test]
    fn the_worst_case_alternating_pattern_is_one_run_per_pair() {
        let set = ranges((0..100).map(|unit| unit * 2));
        assert_eq!(set.run_count(), 100);
        assert_eq!(set.count(), 100);
        assert_eq!(set.max(), Some(198));
    }

    #[test]
    fn difference_removes_exactly_what_the_other_set_holds() {
        let all = ranges(0..20);
        assert_eq!(all.difference(&UnitRanges::new()), all);
        assert_eq!(all.difference(&all), UnitRanges::new());

        assert_eq!(
            all.difference(&ranges(0..5)).runs().collect::<Vec<_>>(),
            vec![(5, 15)]
        );
        assert_eq!(
            all.difference(&ranges(15..20)).runs().collect::<Vec<_>>(),
            vec![(0, 15)]
        );
        assert_eq!(
            all.difference(&ranges(8..12)).runs().collect::<Vec<_>>(),
            vec![(0, 8), (12, 8)]
        );

        let mut holes = ranges(2..6);
        holes.union(&ranges(10..12));
        assert_eq!(
            all.difference(&holes).runs().collect::<Vec<_>>(),
            vec![(0, 2), (6, 4), (12, 8)]
        );
        assert_eq!(ranges(5..10).difference(&ranges(0..20)), UnitRanges::new());

        let low = ranges(0..5);
        assert_eq!(low.difference(&ranges(100..105)), low);
    }

    #[test]
    fn difference_matches_a_plain_set_over_many_shapes() {
        use std::collections::BTreeSet;
        let left_units: BTreeSet<u64> = [0, 1, 2, 5, 6, 9, 20, 21, 22].into_iter().collect();
        let right_units: BTreeSet<u64> = [1, 6, 20, 22, 40].into_iter().collect();
        let expected: Vec<u64> = left_units.difference(&right_units).copied().collect();
        let left = ranges(left_units.iter().copied());
        let right = ranges(right_units.iter().copied());
        assert_eq!(
            left.difference(&right).units().collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn the_last_index_is_out_of_range_everywhere() {
        let mut set = ranges([1, 2]);
        set.insert(u64::MAX);
        assert!(!set.contains(u64::MAX));
        assert_eq!(set.max(), Some(2));
        assert_eq!(set.count(), 2);
        assert_eq!(set.units().collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(set.difference(&UnitRanges::new()), set);
        assert_eq!(
            UnitRanges::from_runs([(u64::MAX, 1)]),
            Err(RunError::EndOverflow)
        );

        let mut edge = UnitRanges::new();
        edge.insert(super::MAX_UNIT);
        assert!(edge.contains(super::MAX_UNIT));
        assert_eq!(edge.max(), Some(super::MAX_UNIT));
        assert_eq!(edge.count(), 1);
    }

    #[test]
    fn difference_walks_each_side_once() {
        let left = ranges((0..20_000).map(|unit| unit * 2));
        let right = ranges((0..20_000).map(|unit| unit * 2 + 20_000));
        assert_eq!(left.difference(&right).count(), 10_000);
        assert_eq!(left.difference(&right).max(), Some(19_998));
        assert_eq!(left.difference(&left), UnitRanges::new());
    }

    #[test]
    fn missing_walks_gaps_not_units() {
        let mut set = ranges(0..1_000);
        set.union(&ranges(2_000..3_000));
        let missing: Vec<u64> = set.missing(4_000).collect();
        assert_eq!(missing.len(), 2_000);
        assert_eq!(missing.first().copied(), Some(1_000));
        assert_eq!(missing.last().copied(), Some(3_999));

        assert_eq!(ranges(0..10).missing(5).count(), 0);
        assert_eq!(ranges([0, 8]).missing(4).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn missing_does_no_work_the_caller_does_not_ask_for() {
        let set = ranges((0..200_000).map(|unit| unit * 2));
        assert_eq!(set.run_count(), 200_000);
        assert_eq!(set.missing(400_000).next(), Some(1));
        assert_eq!(
            set.missing(400_000).take(3).collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn run_errors_say_what_was_wrong() {
        assert_eq!(
            RunError::EmptyRun.to_string(),
            "a checkpoint run covers no units"
        );
        assert_eq!(
            RunError::EndOverflow.to_string(),
            "a checkpoint run ends past u64"
        );
        assert_eq!(
            RunError::TooManyRuns.to_string(),
            "checkpoint run count exceeds its limit"
        );
    }

    #[test]
    fn an_empty_set_reports_nothing() {
        let set = UnitRanges::new();
        assert!(set.is_empty());
        assert_eq!(set.run_count(), 0);
        assert_eq!(set.count(), 0);
        assert_eq!(set.max(), None);
        assert_eq!(set.runs().count(), 0);
    }
}
