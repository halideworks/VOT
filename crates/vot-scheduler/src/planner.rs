//! Priority-ordered transfer planning.

use super::{BTreeSet, Ordering, Reverse, SubjectId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Job {
    pub priority: u8,
    pub sequence: u64,
    pub subject: SubjectId,
}

impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering {
        (Reverse(self.priority), self.sequence, self.subject).cmp(&(
            Reverse(other.priority),
            other.sequence,
            other.subject,
        ))
    }
}

impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic highest-priority-first planner with FIFO tie breaking.
#[derive(Default)]
pub struct Planner {
    jobs: BTreeSet<Job>,
    next_sequence: u64,
}

impl Planner {
    pub fn push(&mut self, job: Job) {
        let mut job = job;
        job.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.jobs.insert(job);
    }

    pub fn pop(&mut self) -> Option<Job> {
        self.jobs.pop_first()
    }
}
