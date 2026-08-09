//! RFC 9959 Careful Resume path memory and admission.

use crate::{BTreeMap, Observation, RemoteEndpoint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SavedPath {
    observation: Observation,
    owner: Option<u64>,
    discard_on_release: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reconnaissance {
    pub now: u64,
    pub current_min_rtt: u64,
    pub initial_flight_acknowledged: bool,
    pub congestion_detected: bool,
    pub local_path_changed: bool,
    pub configuration_epoch: u64,
    pub max_jump: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumePermit {
    pub jump_cwnd: u64,
    pub paced_rtt: u64,
    owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathReject {
    Unknown,
    PathChanged,
    Expired,
    ConfigurationChanged,
    AlreadyInUse,
    InitialFlightUnacknowledged,
    Congestion,
    RttTooSmall,
    RttTooLarge,
    InvalidObservation,
}

/// One saved RFC 9959 CC parameter set per remote endpoint.
#[derive(Default)]
pub struct CarefulResumeCache {
    saved: BTreeMap<RemoteEndpoint, SavedPath>,
    next_owner: u64,
}

impl CarefulResumeCache {
    pub fn observe(
        &mut self,
        endpoint: RemoteEndpoint,
        observation: Observation,
    ) -> Result<(), PathReject> {
        if observation.saved_cwnd == 0 || observation.saved_rtt == 0 || observation.expires_at == 0
        {
            return Err(PathReject::InvalidObservation);
        }
        if self
            .saved
            .get(&endpoint)
            .is_some_and(|saved| saved.owner.is_some())
        {
            return Err(PathReject::AlreadyInUse);
        }
        self.saved.insert(
            endpoint,
            SavedPath {
                observation,
                owner: None,
                discard_on_release: false,
            },
        );
        Ok(())
    }

    pub fn reconnoitre(
        &mut self,
        saved_endpoint: RemoteEndpoint,
        current_endpoint: RemoteEndpoint,
        input: Reconnaissance,
    ) -> Result<ResumePermit, PathReject> {
        if let Some(saved) = self.saved.get_mut(&saved_endpoint) {
            if saved.owner.is_some() {
                saved.discard_on_release |= saved_endpoint != current_endpoint
                    || input.local_path_changed
                    || input.congestion_detected
                    || input.now >= saved.observation.expires_at
                    || input.configuration_epoch != saved.observation.configuration_epoch;
                return Err(PathReject::AlreadyInUse);
            }
        }
        if saved_endpoint != current_endpoint || input.local_path_changed {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::PathChanged);
        }
        let Some(saved) = self.saved.get_mut(&saved_endpoint) else {
            return Err(PathReject::Unknown);
        };
        if input.congestion_detected {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::Congestion);
        }
        if input.now >= saved.observation.expires_at {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::Expired);
        }
        if input.configuration_epoch != saved.observation.configuration_epoch {
            self.saved.remove(&saved_endpoint);
            return Err(PathReject::ConfigurationChanged);
        }
        if !input.initial_flight_acknowledged {
            return Err(PathReject::InitialFlightUnacknowledged);
        }
        if input.current_min_rtt.saturating_mul(2) <= saved.observation.saved_rtt {
            return Err(PathReject::RttTooSmall);
        }
        if input.current_min_rtt > saved.observation.saved_rtt.saturating_mul(10) {
            return Err(PathReject::RttTooLarge);
        }
        let jump_cwnd = input.max_jump.min(saved.observation.saved_cwnd / 2);
        if jump_cwnd == 0 {
            return Err(PathReject::InvalidObservation);
        }
        let owner = self
            .next_owner
            .checked_add(1)
            .ok_or(PathReject::InvalidObservation)?;
        self.next_owner = owner;
        saved.owner = Some(owner);
        Ok(ResumePermit {
            jump_cwnd,
            paced_rtt: input.current_min_rtt,
            owner,
        })
    }

    pub fn release(
        &mut self,
        endpoint: RemoteEndpoint,
        permit: &ResumePermit,
        congestion_detected: bool,
    ) -> bool {
        if self.saved.get(&endpoint).and_then(|saved| saved.owner) != Some(permit.owner) {
            return false;
        }
        let discard_on_release = self
            .saved
            .get(&endpoint)
            .is_some_and(|saved| saved.discard_on_release);
        if congestion_detected || discard_on_release {
            self.saved.remove(&endpoint);
        } else if let Some(saved) = self.saved.get_mut(&endpoint) {
            saved.owner = None;
        }
        true
    }
}
