use std::fs;
use std::path::PathBuf;

use vot_resume::{
    CarefulResumeCache, CarrierNeutralState, Observation, PathReject, Reconnaissance,
    RemoteEndpoint, ResumeStore, ResumeTracker,
};
use vot_transport_api::SubjectId;
use vot_transport_tcp::{Carrier, CarrierRace, RaceAction};

fn subject() -> SubjectId {
    SubjectId {
        suite: 1,
        root: [0x51; 32],
        length: 100 * 65_536,
    }
}

fn path(case: u8) -> PathBuf {
    std::env::temp_dir().join(format!("vot-e-resume-{}-{case}", std::process::id()))
}

#[test]
fn random_process_kills_at_every_percent_keep_waste_bounded() {
    for kill_percent in 1_u64..=99 {
        let store_path = path(u8::try_from(kill_percent).unwrap());
        let mut store = ResumeStore::open(&store_path).unwrap();
        let mut tracker = ResumeTracker::discover(&mut store, subject(), 100, 8).unwrap();
        for unit in 0..kill_percent {
            tracker.begin_unit(unit).unwrap();
            if tracker.complete_unit(unit).unwrap() {
                tracker.checkpoint(&mut store).unwrap();
            }
        }
        if kill_percent < 99 {
            tracker.begin_unit(kill_percent).unwrap();
        }
        assert!(tracker.retransmission_units_after_crash() <= tracker.retransmission_bound());
        let mut reopened = ResumeStore::open(&store_path).unwrap();
        let restarted = ResumeTracker::discover(&mut reopened, subject(), 100, 8).unwrap();
        assert_eq!(
            restarted.missing_units().take(101).count(),
            100 - usize::try_from(kill_percent / 8 * 8).unwrap()
        );
        if store_path.exists() {
            fs::remove_file(store_path).unwrap();
        }
    }
}

#[test]
fn vm_stale_snapshot_resends_but_never_invents_verified_units() {
    let current_path = path(100);
    let snapshot_path = path(101);
    let mut store = ResumeStore::open(&current_path).unwrap();
    let mut tracker = ResumeTracker::discover(&mut store, subject(), 100, 4).unwrap();
    for unit in 0..4 {
        tracker.begin_unit(unit).unwrap();
        tracker.complete_unit(unit).unwrap();
    }
    tracker.checkpoint(&mut store).unwrap();
    fs::copy(&current_path, &snapshot_path).unwrap();
    for unit in 4..8 {
        tracker.begin_unit(unit).unwrap();
        tracker.complete_unit(unit).unwrap();
    }
    tracker.checkpoint(&mut store).unwrap();

    let mut snapshot_store = ResumeStore::open(&snapshot_path).unwrap();
    let stale = ResumeTracker::discover(&mut snapshot_store, subject(), 100, 4).unwrap();
    assert!(stale.is_checkpointed(3));
    assert!(!stale.is_checkpointed(4));
    assert_eq!(stale.missing_units().take(101).count(), 96);
    fs::remove_file(current_path).unwrap();
    fs::remove_file(snapshot_path).unwrap();
}

#[test]
fn nat_rebind_interface_change_and_stale_cc_state_are_rejected() {
    let endpoint = RemoteEndpoint {
        interface: 1,
        destination: [4; 16],
        dscp: 8,
    };
    let observation = Observation {
        saved_cwnd: 2_000_000,
        saved_rtt: 100,
        expires_at: 10_000,
        configuration_epoch: 3,
    };
    let input = Reconnaissance {
        now: 5_000,
        current_min_rtt: 100,
        initial_flight_acknowledged: true,
        congestion_detected: false,
        local_path_changed: false,
        configuration_epoch: 3,
        max_jump: 750_000,
    };
    let mut cache = CarefulResumeCache::default();
    cache.observe(endpoint, observation).unwrap();
    assert_eq!(
        cache.reconnoitre(
            endpoint,
            RemoteEndpoint {
                interface: 2,
                ..endpoint
            },
            input
        ),
        Err(PathReject::PathChanged)
    );
    assert_eq!(
        cache.reconnoitre(endpoint, endpoint, input),
        Err(PathReject::Unknown)
    );
    cache.observe(endpoint, observation).unwrap();
    assert_eq!(
        cache.reconnoitre(
            endpoint,
            endpoint,
            Reconnaissance {
                current_min_rtt: 50,
                ..input
            }
        ),
        Err(PathReject::RttTooSmall)
    );
    cache.observe(endpoint, observation).unwrap();
    assert_eq!(
        cache.reconnoitre(
            endpoint,
            endpoint,
            Reconnaissance {
                local_path_changed: true,
                ..input
            }
        ),
        Err(PathReject::PathChanged)
    );
    assert_eq!(
        cache.reconnoitre(endpoint, endpoint, input),
        Err(PathReject::Unknown)
    );
}

#[test]
fn udp_blackhole_switches_to_tcp_without_redownloading_verified_units() {
    let mut state = CarrierNeutralState::new(Carrier::Quic, 11);
    state.verified(1);
    state.verified(2);
    let (mut race, _) = CarrierRace::start(0, 20, 2).unwrap();
    race.ready(Carrier::Quic).unwrap();
    assert_eq!(race.poll(20), Some(RaceAction::StartTlsTcp));
    race.ready(Carrier::TlsTcp);
    assert_eq!(race.observe_quic(0, false), None);
    assert_eq!(
        race.observe_quic(0, false),
        Some(RaceAction::Switched(Carrier::TlsTcp))
    );
    state.switch(Carrier::TlsTcp, 12);
    assert!(state.is_verified(1));
    assert!(state.is_verified(2));
}

#[test]
fn source_loss_allows_alternate_source_for_same_identity() {
    let store_path = path(102);
    let mut store = ResumeStore::open(&store_path).unwrap();
    let mut original = ResumeTracker::discover(&mut store, subject(), 100, 4).unwrap();
    for unit in 0..4 {
        original.begin_unit(unit).unwrap();
        original.complete_unit(unit).unwrap();
    }
    original.checkpoint(&mut store).unwrap();

    let mut alternate_store = ResumeStore::open(&store_path).unwrap();
    let alternate = ResumeTracker::discover(&mut alternate_store, subject(), 100, 4).unwrap();
    assert!(alternate.is_checkpointed(0));
    assert_eq!(alternate.missing_units().take(101).count(), 96);
    fs::remove_file(store_path).unwrap();
}
