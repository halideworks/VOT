//! Push and receive-push over a live socket.

use super::fetch::{client_config, verify_serve_identity};
use super::serve::identity_digest;
use super::{
    Config, Credentials, DATAGRAM_FEC, Error, Listener, PackageSummary, Path, SocketAddr,
    Transport, apply_datagram_bytes, carrier_failure, extensions_from, limits,
    push_requirement_from,
};
use vot_transport_api::TransportAdapter as _;

/// An untrusted, pending presentation passed to a receiver's admission policy.
///
/// The policy must verify the capability signature, proof of possession and
/// channel binding, issuer, audience, validity window, `PUBLISH` operation,
/// and exact scope before returning an admission. [`crate::authz::PushRequirement::decide`]
/// performs those checks.
pub struct PushPresentation<'a> {
    pub peer: SocketAddr,
    pub challenge: &'a vot_codec::frames::AuthContext,
    pub open: &'a vot_codec::frames::SessionOpen,
    pub channel_binding: vot_transport_api::ChannelBinding,
    pub now: u64,
}

/// One admitted push: its exact grant, manifest workspace, and receive hooks.
pub struct PushAdmission {
    pub scope: vot_capability::Scope,
    pub directory: std::path::PathBuf,
    pub seams: crate::ReceiveSeams,
}

#[derive(Clone)]
enum PlanSlot {
    Building,
    Ready(crate::fetch::SharedPlan),
    Complete(PackageSummary, u64),
    Failed,
}

type PlanKey = ([u8; 32], [u8; 32], std::path::PathBuf);
type PlanGroup = (std::sync::Mutex<PlanSlot>, std::sync::Condvar);
type ReceivePlans = std::sync::Arc<
    std::sync::Mutex<std::collections::BTreeMap<PlanKey, std::sync::Weak<PlanGroup>>>,
>;

const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PLAN_WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(50);

struct PrimaryPlan {
    group: std::sync::Arc<PlanGroup>,
    published: bool,
}

impl PrimaryPlan {
    fn publish(&mut self, plan: crate::fetch::SharedPlan) -> Result<(), Error> {
        *self.group.0.lock().map_err(|_| Error::CarrierUnavailable)? = PlanSlot::Ready(plan);
        self.published = true;
        self.group.1.notify_all();
        Ok(())
    }

    fn complete(&mut self, package: PackageSummary, cursor: u64) -> Result<(), Error> {
        *self.group.0.lock().map_err(|_| Error::CarrierUnavailable)? =
            PlanSlot::Complete(package, cursor);
        self.published = true;
        self.group.1.notify_all();
        Ok(())
    }
}

impl Drop for PrimaryPlan {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        if let Ok(mut state) = self.group.0.lock() {
            *state = PlanSlot::Failed;
            self.group.1.notify_all();
        }
    }
}

fn plan_group(
    plans: &ReceivePlans,
    key: PlanKey,
) -> Result<(std::sync::Arc<PlanGroup>, bool), Error> {
    let mut held = plans.lock().map_err(|_| Error::CarrierUnavailable)?;
    held.retain(|_, group| group.strong_count() != 0);
    if let Some(group) = held.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok((group, false));
    }
    let group = std::sync::Arc::new((
        std::sync::Mutex::new(PlanSlot::Building),
        std::sync::Condvar::new(),
    ));
    held.insert(key, std::sync::Arc::downgrade(&group));
    Ok((group, true))
}

fn await_push_close(session: &mut vot_session::Session<Transport>) -> Result<(), Error> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(vot_transport_api::Event::Disconnected(_)) = session.poll()? {
            return Ok(());
        }
        session.flush()?;
        if std::time::Instant::now() >= deadline {
            return Err(Error::Stalled);
        }
        session
            .driver()
            .wait_for_event(std::time::Duration::from_millis(10));
    }
}

fn joined_plan(
    group: &PlanGroup,
    cancellation: &crate::CancellationHandle,
) -> Result<Option<PlanSlot>, Error> {
    let mut state = group.0.lock().map_err(|_| Error::CarrierUnavailable)?;
    loop {
        match &*state {
            PlanSlot::Ready(_) | PlanSlot::Complete(_, _) | PlanSlot::Failed => {
                return Ok(Some(state.clone()));
            }
            PlanSlot::Building => {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                state = group
                    .1
                    .wait_timeout(state, PLAN_WAIT_POLL)
                    .map_err(|_| Error::CarrierUnavailable)?
                    .0;
            }
        }
    }
}

/// Sends `bundle` to a receiver whose certificate has the required digest.
pub fn push_bundle(
    bundle: &Path,
    address: SocketAddr,
    capability: &Path,
    key_source: &str,
    identity: [u8; 32],
) -> Result<PackageSummary, Error> {
    let rails = super::rails_from(
        std::env::var(super::FETCH_RAILS).ok().as_deref(),
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
    )?;
    push_bundle_railed(bundle, address, capability, key_source, identity, rails)
}

pub(super) fn push_bundle_railed(
    bundle: &Path,
    address: SocketAddr,
    capability: &Path,
    key_source: &str,
    identity: [u8; 32],
    rails: usize,
) -> Result<PackageSummary, Error> {
    if rails == 0 || rails > crate::drive::CONCURRENT_SESSIONS {
        return Err(Error::InvalidArguments);
    }
    let server = crate::BundleServer::open(bundle)?;
    if server.objects.is_empty() {
        return Err(Error::InvalidBundle);
    }
    let holder = crate::load_capability_holder(capability, key_source)?;
    let mut config = client_config()?;
    apply_datagram_bytes(&mut config)?;
    let extensions = {
        let mut offered = extensions_from(std::env::var(DATAGRAM_FEC).ok().as_deref())?;
        offered.insert(vot_codec::extension_id::PUSH);
        offered
    };
    std::thread::scope(|scope| {
        let mut sessions = Vec::with_capacity(rails);
        for _ in 0..rails {
            let holder = std::sync::Arc::clone(&holder);
            let carrier = Transport::connect(
                super::local_for(address)?,
                address,
                Some("localhost"),
                &config,
            )
            .map_err(carrier_failure)?;
            verify_serve_identity(&carrier, Some(identity))?;
            let session = vot_session::Session::client(
                carrier,
                vot_codec::Settings::default(),
                extensions.clone(),
                vot_session::Authentication::Presenting,
            );
            let mut pushing = crate::ServeSession::begin_push_session(&server, session, holder)?;
            pushing.negotiate_push()?;
            sessions.push(pushing);
        }
        let mut running = Vec::with_capacity(rails);
        for mut pushing in sessions {
            running.push(scope.spawn(move || {
                match crate::drive::drive_until(&mut pushing, crate::ServeSession::push_completed)?
                {
                    None => {
                        pushing.finish_push();
                        Ok(())
                    }
                    Some(crate::ServeStatus::Closed(code)) => Err(Error::PeerClosed(code)),
                    Some(crate::ServeStatus::Disconnected | crate::ServeStatus::Active) => {
                        Err(Error::CarrierUnavailable)
                    }
                }
            }));
        }
        for rail in running {
            rail.join().map_err(|_| Error::CarrierUnavailable)??;
        }
        Ok(server.package())
    })
}

/// Receives pushed bundles below `directory`.
pub fn receive_push(
    address: SocketAddr,
    directory: &Path,
    credentials: &Credentials,
    sessions: Option<u32>,
    mut listening: impl FnMut(SocketAddr, [u8; 32]),
) -> Result<(), Error> {
    let requirement = push_requirement_from(
        std::env::var(super::SERVE_ISSUER).ok().as_deref(),
        std::env::var(super::SERVE_ISSUER_NAME).ok().as_deref(),
        std::env::var(super::SERVE_AUDIENCE).ok().as_deref(),
    )?
    .ok_or(Error::InvalidArguments)?;
    let ephemeral = match credentials {
        Credentials::Ephemeral => Some(super::Ephemeral::generate()?),
        Credentials::Files { .. } => None,
    };
    let (certificate, key) = match (credentials, &ephemeral) {
        (Credentials::Files { certificate, key }, _) => (certificate.clone(), key.clone()),
        (Credentials::Ephemeral, Some(generated)) => {
            (generated.certificate.clone(), generated.key.clone())
        }
        (Credentials::Ephemeral, None) => return Err(Error::InvalidArguments),
    };
    let mut config = Config::server(
        limits()?,
        certificate.to_str().ok_or(Error::InvalidPath)?.to_owned(),
        key.to_str().ok_or(Error::InvalidPath)?.to_owned(),
    );
    if sessions.is_none() {
        config.accept_timeout_ms = 0;
    }
    config.stateless_retry = true;
    apply_datagram_bytes(&mut config)?;
    let identity = identity_digest(&certificate)?;
    let listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    listening(listener.local_address(), identity);
    receive_push_on_bounded(&listener, sessions, |presentation| {
        requirement
            .decide(
                presentation.challenge,
                presentation.open,
                presentation.channel_binding,
                presentation.now,
            )
            .map(|scope| PushAdmission {
                directory: directory.join(crate::hex_of(&scope.root)),
                scope,
                seams: crate::ReceiveSeams::default(),
            })
    })
}

/// Binds a Retry-protected listener suitable for [`receive_push_on`].
pub fn bind_push_listener(
    address: SocketAddr,
    credentials: &Credentials,
) -> Result<(Listener, [u8; 32]), Error> {
    let ephemeral = match credentials {
        Credentials::Ephemeral => Some(super::Ephemeral::generate()?),
        Credentials::Files { .. } => None,
    };
    let (certificate, key) = match (credentials, &ephemeral) {
        (Credentials::Files { certificate, key }, _) => (certificate.clone(), key.clone()),
        (Credentials::Ephemeral, Some(generated)) => {
            (generated.certificate.clone(), generated.key.clone())
        }
        (Credentials::Ephemeral, None) => return Err(Error::InvalidArguments),
    };
    let mut config = Config::server(
        limits()?,
        certificate.to_str().ok_or(Error::InvalidPath)?.to_owned(),
        key.to_str().ok_or(Error::InvalidPath)?.to_owned(),
    );
    config.accept_timeout_ms = 0;
    config.stateless_retry = true;
    apply_datagram_bytes(&mut config)?;
    let identity = identity_digest(&certificate)?;
    let listener = Listener::bind(address, &config).map_err(carrier_failure)?;
    Ok((listener, identity))
}

/// Accepts and concurrently receives pushes on an already-bound listener.
///
/// `policy` receives an untrusted pending presentation and must authenticate
/// and authorize it before returning [`PushAdmission`].
pub fn receive_push_on<P>(listener: &Listener, policy: P) -> Result<(), Error>
where
    P: Fn(PushPresentation<'_>) -> Option<PushAdmission> + Sync,
{
    receive_push_on_bounded(listener, None, policy)
}

pub(super) fn receive_push_on_bounded<P>(
    listener: &Listener,
    sessions: Option<u32>,
    policy: P,
) -> Result<(), Error>
where
    P: Fn(PushPresentation<'_>) -> Option<PushAdmission> + Sync,
{
    receive_push_on_bounded_with_timeout(listener, sessions, AUTHENTICATION_TIMEOUT, policy)
}

pub(super) fn receive_push_on_bounded_with_timeout<P>(
    listener: &Listener,
    sessions: Option<u32>,
    authentication_timeout: std::time::Duration,
    policy: P,
) -> Result<(), Error>
where
    P: Fn(PushPresentation<'_>) -> Option<PushAdmission> + Sync,
{
    if !listener.stateless_retry_enabled() {
        return Err(Error::InvalidArguments);
    }
    std::thread::scope(|scope| {
        let plans = ReceivePlans::default();
        let mut running: std::collections::VecDeque<
            std::thread::ScopedJoinHandle<'_, Result<PackageSummary, Error>>,
        > = std::collections::VecDeque::new();
        let mut failed = Ok(());
        for _ in 0..sessions.unwrap_or(u32::MAX) {
            while running.len() >= crate::drive::CONCURRENT_SESSIONS {
                let finished = loop {
                    if let Some(finished) = running
                        .iter()
                        .position(std::thread::ScopedJoinHandle::is_finished)
                    {
                        break finished;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                };
                let done = running.remove(finished).ok_or(Error::CarrierUnavailable)?;
                let result = done.join().map_err(|_| Error::CarrierUnavailable)?;
                if sessions.is_some() && failed.is_ok() {
                    failed = result.map(|_| ());
                }
            }
            let carrier = listener.accept().map_err(carrier_failure)?;
            let policy = &policy;
            let plans = std::sync::Arc::clone(&plans);
            running.push_back(
                scope.spawn(move || receive_one(carrier, policy, &plans, authentication_timeout)),
            );
        }
        while let Some(done) = running.pop_front() {
            let result = done.join().map_err(|_| Error::CarrierUnavailable)?;
            if sessions.is_some() && failed.is_ok() {
                failed = result.map(|_| ());
            }
        }
        failed
    })
}

fn receive_one<P>(
    carrier: Transport,
    policy: &P,
    plans: &ReceivePlans,
    authentication_timeout: std::time::Duration,
) -> Result<PackageSummary, Error>
where
    P: Fn(PushPresentation<'_>) -> Option<PushAdmission>,
{
    let peer = carrier.peer_address().ok_or(Error::CarrierUnavailable)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let mut extensions = crate::authz::default_extensions();
    extensions.insert(vot_codec::extension_id::PUSH);
    let mut session = vot_session::Session::server(
        carrier,
        vot_codec::Settings::default(),
        extensions,
        vot_session::Authentication::Capability {
            challenge: vot_codec::frames::AuthContext {
                nonce: nonce.to_vec(),
                binding: vot_codec::frames::Binding::ProofOfPossession,
                formats: vec![u64::from(vot_capability::FORMAT_ID)],
            },
        },
    );
    session.require_extension(vot_codec::extension_id::PUSH);
    session.begin()?;
    let authentication_deadline = std::time::Instant::now() + authentication_timeout;
    let (admission, group, primary, mut primary_plan) = loop {
        if std::time::Instant::now() >= authentication_deadline {
            let _ = session
                .driver()
                .close(vot_codec::error_code::AUTHENTICATION_FAILED);
            return Err(Error::PeerClosed(
                vot_codec::error_code::AUTHENTICATION_FAILED,
            ));
        }
        if let Some((challenge, open)) = session.pending_authorization() {
            let binding = session
                .channel_binding()
                .ok_or(Error::ChannelBindingUnavailable)?;
            let capability_id = *blake3::hash(&open.capability).as_bytes();
            let Some(admission) = policy(PushPresentation {
                peer,
                challenge,
                open,
                channel_binding: binding,
                now: crate::authz::now_seconds()?,
            }) else {
                session.refuse(
                    vot_codec::error_code::AUTHORIZATION_FAILED,
                    crate::authz::REFUSAL_DETAIL.to_owned(),
                )?;
                session.flush()?;
                continue;
            };
            if std::time::Instant::now() >= authentication_deadline {
                let _ = session
                    .driver()
                    .close(vot_codec::error_code::AUTHENTICATION_FAILED);
                return Err(Error::PeerClosed(
                    vot_codec::error_code::AUTHENTICATION_FAILED,
                ));
            }
            if admission.scope.suite != 1
                || admission.scope.length.is_none()
                || !admission.scope.ranges.is_empty()
            {
                session.refuse(
                    vot_codec::error_code::AUTHORIZATION_FAILED,
                    crate::authz::REFUSAL_DETAIL.to_owned(),
                )?;
                session.flush()?;
                continue;
            }
            let root = admission.scope.root;
            let key = (root, capability_id, admission.directory.clone());
            let (group, primary) = plan_group(plans, key)?;
            let primary_plan = primary.then(|| PrimaryPlan {
                group: std::sync::Arc::clone(&group),
                published: false,
            });
            session.grant(
                vot_capability::encode_scope(&admission.scope)
                    .map_err(|_| Error::InvalidArguments)?,
            )?;
            session.flush()?;
            break (admission, group, primary, primary_plan);
        }
        if let Some(vot_transport_api::Event::Disconnected(_)) = session.poll()? {
            return Err(Error::CarrierUnavailable);
        }
        session.flush()?;
        session
            .driver()
            .wait_for_event(std::time::Duration::from_millis(10));
    };
    let root = admission.scope.root;
    let plan = if primary {
        None
    } else {
        match joined_plan(&group, &admission.seams.cancellation)? {
            Some(PlanSlot::Ready(plan)) => Some(plan),
            Some(PlanSlot::Complete(package, cursor)) => {
                let frame = crate::serve::encoded(&vot_codec::frames::TypedFrame::GoAway(
                    vot_codec::frames::GoAway { cursor },
                ))?;
                session.send_control(&frame)?;
                session.flush()?;
                await_push_close(&mut session)?;
                return Ok(package);
            }
            Some(PlanSlot::Failed) => return Err(Error::CarrierUnavailable),
            Some(PlanSlot::Building) => unreachable!(),
            None => {
                let frame = crate::serve::encoded(&vot_codec::frames::TypedFrame::GoAway(
                    vot_codec::frames::GoAway { cursor: 0 },
                ))?;
                session.send_control(&frame)?;
                session.flush()?;
                return Err(Error::CarrierUnavailable);
            }
        }
    };

    let mut fetcher = if let Some(plan) = plan {
        crate::BundleFetcher::join_started_session(session, &admission.directory, plan)?
    } else {
        crate::BundleFetcher::from_started_session(session, &admission.directory, Some(root))?
    };
    fetcher.set_receive_seams(admission.seams);
    if primary {
        let planned =
            crate::drive::drive_until(&mut fetcher, |fetcher| fetcher.shared_plan().is_some());
        let plan = match planned {
            Ok(None) => fetcher.shared_plan().ok_or(Error::InvalidBundle),
            Ok(Some(crate::FetchStatus::Complete)) => {
                let cursor = fetcher.acknowledge_push()?;
                primary_plan
                    .as_mut()
                    .ok_or(Error::CarrierUnavailable)?
                    .complete(fetcher.package().ok_or(Error::InvalidBundle)?, cursor)?;
                fetcher.await_push_close()?;
                return fetcher.package().ok_or(Error::InvalidBundle);
            }
            Ok(Some(crate::FetchStatus::Closed(code))) => Err(Error::PeerClosed(code)),
            Ok(Some(_)) => Err(Error::CarrierUnavailable),
            Err(error) => Err(error),
        };
        match plan {
            Ok(plan) => {
                primary_plan
                    .as_mut()
                    .ok_or(Error::CarrierUnavailable)?
                    .publish(plan)?;
            }
            Err(error) => {
                return Err(error);
            }
        }
    }
    let status = crate::drive(&mut fetcher)?;
    match status {
        crate::FetchStatus::Complete => {
            fetcher.acknowledge_push()?;
            fetcher.await_push_close()?;
            fetcher.package().ok_or(Error::InvalidBundle)
        }
        crate::FetchStatus::Closed(code) => Err(Error::PeerClosed(code)),
        crate::FetchStatus::Disconnected
        | crate::FetchStatus::Active
        | crate::FetchStatus::Cancelled(_) => Err(Error::CarrierUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u8) -> PlanKey {
        (
            [index; 32],
            [index.wrapping_add(1); 32],
            index.to_string().into(),
        )
    }

    #[test]
    fn a_failed_primary_wakes_every_waiter() {
        let plans = ReceivePlans::default();
        let (group, primary) = plan_group(&plans, key(1)).unwrap();
        assert!(primary);
        let (joined, primary) = plan_group(&plans, key(1)).unwrap();
        assert!(!primary);
        let waiting = {
            std::thread::spawn(move || {
                let mut state = joined.0.lock().unwrap();
                while matches!(*state, PlanSlot::Building) {
                    state = joined.1.wait(state).unwrap();
                }
                matches!(*state, PlanSlot::Failed)
            })
        };
        drop(PrimaryPlan {
            group: std::sync::Arc::clone(&group),
            published: false,
        });
        assert!(waiting.join().unwrap());
    }

    #[test]
    fn completed_groups_are_replaced_and_dead_roots_are_pruned() {
        let plans = ReceivePlans::default();
        for index in 0..100 {
            let (group, primary) = plan_group(&plans, key(index)).unwrap();
            assert!(primary);
            drop(group);
        }
        let (first, primary) = plan_group(&plans, key(7)).unwrap();
        assert!(primary);
        let (joined, primary) = plan_group(&plans, key(7)).unwrap();
        assert!(!primary);
        assert!(std::sync::Arc::ptr_eq(&first, &joined));
        assert_eq!(plans.lock().unwrap().len(), 1);
    }

    #[test]
    fn one_root_admitted_to_two_destinations_never_shares_a_plan() {
        let plans = ReceivePlans::default();
        let root = [7; 32];
        let capability = [8; 32];
        let (left, left_primary) = plan_group(&plans, (root, capability, "left".into())).unwrap();
        let (right, right_primary) =
            plan_group(&plans, (root, capability, "right".into())).unwrap();
        assert!(left_primary && right_primary);
        assert!(!std::sync::Arc::ptr_eq(&left, &right));
    }

    #[test]
    fn an_empty_primary_publishes_completion_to_its_joiners() {
        let group = std::sync::Arc::new((
            std::sync::Mutex::new(PlanSlot::Building),
            std::sync::Condvar::new(),
        ));
        let package = PackageSummary {
            root: [9; 32],
            logical_length: 0,
            entries: 0,
        };
        PrimaryPlan {
            group: std::sync::Arc::clone(&group),
            published: false,
        }
        .complete(package, 0)
        .unwrap();
        assert!(
            matches!(*group.0.lock().unwrap(), PlanSlot::Complete(found, 0) if found == package)
        );
    }

    #[test]
    fn a_cancelled_joiner_leaves_a_building_primary() {
        let group = (
            std::sync::Mutex::new(PlanSlot::Building),
            std::sync::Condvar::new(),
        );
        let cancellation = crate::CancellationHandle::default();
        let cancelling = cancellation.clone();
        let wake = std::thread::spawn(move || {
            std::thread::sleep(PLAN_WAIT_POLL);
            cancelling.cancel();
        });
        assert!(joined_plan(&group, &cancellation).unwrap().is_none());
        wake.join().unwrap();
    }
}
