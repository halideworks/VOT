//! A checked budget whose outstanding amount is owned by [`Permit`] values.

use std::sync::{Arc, Mutex, PoisonError};

use super::Error;

#[derive(Debug)]
struct Inner {
    limit: u64,
    used: u64,
    poisoned: bool,
}

/// Shared checked budget. [`Clone`] is another handle to the same counters.
#[derive(Clone, Debug)]
pub struct Ledger {
    inner: Arc<Mutex<Inner>>,
}

/// Outstanding reservation. Dropping it returns the amount once.
#[derive(Debug)]
pub struct Permit {
    ledger: Arc<Mutex<Inner>>,
    amount: u64,
}

impl Ledger {
    /// # Errors
    /// Rejects a zero limit.
    pub fn new(limit: u64) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                limit,
                used: 0,
                poisoned: false,
            })),
        })
    }

    /// # Errors
    /// Rejects a zero amount, overflow, a request past the limit, or a
    /// poisoned ledger. A rejection leaves the counters unchanged.
    pub fn acquire(&self, amount: u64) -> Result<Permit, Error> {
        if amount == 0 {
            return Err(Error::InvalidConfiguration);
        }
        let mut inner = lock(&self.inner);
        if inner.poisoned {
            return Err(Error::AccountingPoisoned);
        }
        let next = inner
            .used
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow)?;
        if next > inner.limit {
            return Err(Error::StagingExhausted);
        }
        inner.used = next;
        Ok(Permit {
            ledger: Arc::clone(&self.inner),
            amount,
        })
    }

    /// A new empty ledger with this one's limit. Live permits still release
    /// into the ledger they came from.
    #[must_use]
    pub fn rebuilt(&self) -> Self {
        let limit = lock(&self.inner).limit;
        Self {
            inner: Arc::new(Mutex::new(Inner {
                limit,
                used: 0,
                poisoned: false,
            })),
        }
    }

    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        lock(&self.inner).poisoned
    }

    /// Held amount. A poisoned ledger reports its limit.
    #[must_use]
    pub fn used(&self) -> u64 {
        let inner = lock(&self.inner);
        if inner.poisoned {
            inner.limit
        } else {
            inner.used
        }
    }

    /// Free amount. A poisoned ledger reports zero.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        let inner = lock(&self.inner);
        if inner.poisoned {
            return 0;
        }
        inner.limit.saturating_sub(inner.used)
    }

    #[cfg(test)]
    fn force_used(&self, used: u64) {
        lock(&self.inner).used = used;
    }
}

impl Permit {
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Moves `take` into a new permit. The ledger used amount is unchanged.
    ///
    /// # Errors
    /// Rejects a zero take or a take larger than this permit. The ledger is
    /// not poisoned: nothing was released.
    pub fn split(&mut self, take: u64) -> Result<Permit, Error> {
        if take == 0 {
            return Err(Error::InvalidConfiguration);
        }
        self.amount = self
            .amount
            .checked_sub(take)
            .ok_or(Error::InvalidConfiguration)?;
        Ok(Permit {
            ledger: Arc::clone(&self.ledger),
            amount: take,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.amount == 0 {
            return;
        }
        let mut inner = lock(&self.ledger);
        if let Some(used) = inner.used.checked_sub(self.amount) {
            inner.used = used;
        } else {
            inner.used = inner.limit;
            inner.poisoned = true;
        }
        self.amount = 0;
    }
}

fn lock(inner: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_returns_the_reservation() {
        let ledger = Ledger::new(10).unwrap();
        let permit = ledger.acquire(4).unwrap();
        assert_eq!(ledger.used(), 4);
        assert_eq!(ledger.remaining(), 6);
        drop(permit);
        assert_eq!(ledger.used(), 0);
        assert_eq!(ledger.remaining(), 10);
    }

    #[test]
    fn rejected_acquire_leaves_the_ledger() {
        let ledger = Ledger::new(10).unwrap();
        let held = ledger.acquire(4).unwrap();
        assert_eq!(ledger.acquire(0).err(), Some(Error::InvalidConfiguration));
        assert_eq!(ledger.acquire(7).err(), Some(Error::StagingExhausted));
        assert_eq!(ledger.used(), 4);
        drop(held);
    }

    #[test]
    fn overflow_acquire_is_rejected() {
        let ledger = Ledger::new(u64::MAX).unwrap();
        let held = ledger.acquire(2).unwrap();
        assert_eq!(
            ledger.acquire(u64::MAX).err(),
            Some(Error::ArithmeticOverflow)
        );
        assert_eq!(ledger.used(), 2);
        drop(held);
    }

    #[test]
    fn split_conserves_the_reservation() {
        let ledger = Ledger::new(10).unwrap();
        let mut parent = ledger.acquire(6).unwrap();
        let child = parent.split(2).unwrap();
        assert_eq!(parent.amount(), 4);
        assert_eq!(child.amount(), 2);
        assert_eq!(ledger.used(), 6);
        drop(child);
        assert_eq!(ledger.used(), 4);
        drop(parent);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn split_rejects_without_touching_the_ledger() {
        let ledger = Ledger::new(10).unwrap();
        let mut parent = ledger.acquire(3).unwrap();
        assert_eq!(parent.split(0).err(), Some(Error::InvalidConfiguration));
        assert_eq!(parent.split(4).err(), Some(Error::InvalidConfiguration));
        assert_eq!(parent.amount(), 3);
        assert_eq!(ledger.used(), 3);
    }

    #[test]
    fn panic_unwind_releases() {
        let ledger = Ledger::new(10).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = ledger.acquire(5).unwrap();
            panic!("unwind");
        }));
        assert!(caught.is_err());
        assert_eq!(ledger.used(), 0);
        assert!(!ledger.is_poisoned());
    }

    #[test]
    fn rebuilt_does_not_take_live_permits() {
        let ledger = Ledger::new(10).unwrap();
        let permit = ledger.acquire(4).unwrap();
        let fresh = ledger.rebuilt();
        assert_eq!(fresh.used(), 0);
        assert_eq!(ledger.used(), 4);
        drop(permit);
        assert_eq!(ledger.used(), 0);
        assert_eq!(fresh.used(), 0);
    }

    #[test]
    fn zero_limit_is_rejected() {
        assert_eq!(Ledger::new(0).err(), Some(Error::InvalidConfiguration));
    }

    #[test]
    fn acquire_may_fill_the_limit() {
        let ledger = Ledger::new(10).unwrap();
        let permit = ledger.acquire(10).unwrap();
        assert_eq!(ledger.used(), 10);
        assert_eq!(ledger.remaining(), 0);
        assert_eq!(ledger.acquire(1).err(), Some(Error::StagingExhausted));
        drop(permit);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn over_release_poisons() {
        let ledger = Ledger::new(10).unwrap();
        let permit = ledger.acquire(4).unwrap();
        ledger.force_used(0);
        drop(permit);
        assert!(ledger.is_poisoned());
        assert_eq!(ledger.used(), 10);
        assert_eq!(ledger.remaining(), 0);
        assert_eq!(ledger.acquire(1).err(), Some(Error::AccountingPoisoned));
    }
}
