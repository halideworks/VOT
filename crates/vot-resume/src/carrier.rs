//! Carrier-neutral resume state and observations.

use crate::{BTreeSet, Carrier, Error, PathReject, PathStats};

/// Verified and durable state that survives connection and carrier changes.
pub struct CarrierNeutralState {
    carrier: Carrier,
    connection: u64,
    verified: BTreeSet<u64>,
    durable: BTreeSet<u64>,
}

impl CarrierNeutralState {
    #[must_use]
    pub const fn new(carrier: Carrier, connection: u64) -> Self {
        Self {
            carrier,
            connection,
            verified: BTreeSet::new(),
            durable: BTreeSet::new(),
        }
    }

    pub fn verified(&mut self, unit: u64) {
        self.verified.insert(unit);
    }

    pub fn durable(&mut self, unit: u64) -> Result<(), Error> {
        if !self.verified.contains(&unit) {
            return Err(Error::InvalidUnit);
        }
        self.durable.insert(unit);
        Ok(())
    }

    pub fn switch(&mut self, carrier: Carrier, connection: u64) {
        self.carrier = carrier;
        self.connection = connection;
    }

    #[must_use]
    pub fn is_verified(&self, unit: u64) -> bool {
        self.verified.contains(&unit)
    }

    #[must_use]
    pub fn is_durable(&self, unit: u64) -> bool {
        self.durable.contains(&unit)
    }

    #[must_use]
    pub const fn carrier(&self) -> Carrier {
        self.carrier
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RemoteEndpoint {
    pub interface: u64,
    pub destination: [u8; 16],
    pub dscp: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub saved_cwnd: u64,
    pub saved_rtt: u64,
    pub expires_at: u64,
    pub configuration_epoch: u64,
}

impl Observation {
    /// Builds a resumable observation from the backend-neutral path metrics.
    ///
    /// # Errors
    /// Rejects adapters that cannot expose both RTT and congestion window.
    pub fn from_path_stats(
        stats: PathStats,
        expires_at: u64,
        configuration_epoch: u64,
    ) -> Result<Self, PathReject> {
        Ok(Self {
            saved_cwnd: stats
                .congestion_window_bytes
                .ok_or(PathReject::InvalidObservation)?,
            saved_rtt: stats
                .smoothed_rtt_us
                .ok_or(PathReject::InvalidObservation)?,
            expires_at,
            configuration_epoch,
        })
    }
}
