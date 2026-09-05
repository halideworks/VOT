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

type PlanScope = ([u8; 32], u64);
type PlanGroup = (std::sync::Mutex<PlanSlot>, std::sync::Condvar);
type ReceivePlans = std::sync::Arc<
    std::sync::Mutex<
        std::collections::BTreeMap<std::path::PathBuf, (PlanScope, std::sync::Weak<PlanGroup>)>,
    >,
>;

const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PLAN_WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(50);

const fn valid_rail_count(rails: usize) -> bool {
    rails != 0 && rails <= crate::drive::CONCURRENT_SESSIONS
}

pub(super) const fn should_record_failure(bounded: bool, clean: bool) -> bool {
    bounded && clean
}

fn valid_push_scope(scope: &vot_capability::Scope) -> bool {
    scope.suite == 1 && scope.length.is_some() && scope.ranges.is_empty()
}

const fn real_directory(is_directory: bool) -> bool {
    is_directory
}

const fn missing_path(kind: std::io::ErrorKind) -> bool {
    matches!(kind, std::io::ErrorKind::NotFound)
}

const fn safe_parent(strict: bool, sticky: bool) -> bool {
    strict || sticky
}

const fn raced_existing(kind: std::io::ErrorKind) -> bool {
    matches!(kind, std::io::ErrorKind::AlreadyExists)
}

#[cfg(not(unix))]
fn prepare_push_destination_unsupported(_path: &Path) -> Result<(), Error> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "push receive requires guarded directory operations on this platform",
    )))
}

#[cfg(not(unix))]
use prepare_push_destination_unsupported as prepare_push_destination;

#[cfg(not(unix))]
fn canonical_push_destination_unsupported(path: &Path) -> Result<std::path::PathBuf, Error> {
    prepare_push_destination(path)?;
    Ok(path.to_path_buf())
}

#[cfg(not(unix))]
use canonical_push_destination_unsupported as canonical_push_destination;

fn canonical_push_destination_before(
    path: &Path,
    deadline: std::time::Instant,
) -> Result<Option<std::path::PathBuf>, Error> {
    let canonical = canonical_push_destination(path)?;
    Ok(deadline_live(std::time::Instant::now(), deadline).then_some(canonical))
}

fn deadline_live(now: std::time::Instant, deadline: std::time::Instant) -> bool {
    now < deadline
}

#[cfg(unix)]
fn prepare_push_destination(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !real_directory(metadata.file_type().is_dir()) {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "push destination is not a real directory",
                )));
            }
            vot_platform_fs::validate_removal_parent(&path.join("objects")).map_err(Error::Io)
        }
        Err(error) => prepare_absent_destination(path, error),
    }
}

#[cfg(unix)]
fn canonical_push_destination(path: &Path) -> Result<std::path::PathBuf, Error> {
    prepare_push_destination(path)?;
    let canonical = std::fs::canonicalize(path)?;
    prepare_push_destination(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn prepare_absent_destination(path: &Path, error: std::io::Error) -> Result<(), Error> {
    if !missing_path(error.kind()) {
        return Err(Error::Io(error));
    }
    let strict = vot_platform_fs::validate_removal_parent(path).is_ok();
    #[cfg(unix)]
    let sticky = sticky_parent(path)?;
    #[cfg(not(unix))]
    let sticky = false;
    if !safe_parent(strict, sticky) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "push destination has an unsafe parent",
        )));
    }
    finish_destination_create(path, crate::create_private_directory(path))
}

#[cfg(unix)]
fn finish_destination_create(path: &Path, result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Ok(()) => prepare_push_destination(path),
        Err(Error::Io(error)) if raced_existing(error.kind()) => prepare_push_destination(path),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn sticky_parent(path: &Path) -> Result<bool, Error> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent)?;
    Ok(trusted_sticky_parent(
        metadata.file_type().is_dir(),
        metadata.mode() & 0o1000 != 0,
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    ))
}

#[cfg(unix)]
const fn trusted_sticky_parent(directory: bool, sticky: bool, owner: u32, effective: u32) -> bool {
    directory && sticky && (owner == 0 || owner == effective)
}

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

struct SharedPlanFailure(Option<crate::fetch::SharedPlan>);

impl SharedPlanFailure {
    fn arm(&mut self, plan: crate::fetch::SharedPlan) {
        self.0 = Some(plan);
    }

    fn complete(mut self) {
        self.0 = None;
    }
}

impl Drop for SharedPlanFailure {
    fn drop(&mut self) {
        if let Some(plan) = &self.0 {
            crate::fetch::abandon_plan(plan);
        }
    }
}

fn plan_group(
    plans: &ReceivePlans,
    key: (std::path::PathBuf, PlanScope),
) -> Result<Option<(std::sync::Arc<PlanGroup>, bool)>, Error> {
    let (directory, scope) = key;
    let mut held = plans.lock().map_err(|_| Error::CarrierUnavailable)?;
    held.retain(|_, (_, group)| group.strong_count() != 0);
    if let Some((held_scope, group)) = held.get(&directory)
        && let Some(group) = group.upgrade()
    {
        if *held_scope != scope {
            return Ok(None);
        }
        return Ok(Some((group, false)));
    }
    let group = std::sync::Arc::new((
        std::sync::Mutex::new(PlanSlot::Building),
        std::sync::Condvar::new(),
    ));
    held.insert(directory, (scope, std::sync::Arc::downgrade(&group)));
    Ok(Some((group, true)))
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
    if !valid_rail_count(rails) {
        return Err(Error::InvalidArguments);
    }
    let server = crate::BundleServer::open(bundle)?;
    if server.objects.is_empty() {
        return Err(Error::InvalidBundle);
    }
    let holder = crate::load_capability_holder(capability, key_source)?;
    let extensions = extensions_from(std::env::var(DATAGRAM_FEC).ok().as_deref())?;
    push_from(
        &server,
        crate::PushOptions {
            address,
            holder,
            identity,
            rails,
            extensions,
            progress: None,
        },
    )
}

/// Pushes what `server` holds to the receiver `options` names, over
/// `options.rails` sessions at once.
///
/// The server is the caller's: opened from a bundle, or assembled from a
/// manifest and the files where they sit ([`crate::build_manifest`] and
/// [`crate::BundleServer::assemble`]), so nothing is copied to be sent.
/// Only the process-wide carrier tuning stays with the environment
/// (`VOT_DATAGRAM_BYTES`, `VOT_CONGESTION`, `VOT_INITIAL_CWND`,
/// `VOT_PREFIX_DUP`), as it does for every command.
///
/// # Errors
/// Refuses a rail count outside one to the receiver's session limit (eight)
/// and a zero progress quantum with [`Error::InvalidArguments`], and a
/// server with no objects with [`Error::InvalidBundle`], all before a dial;
/// otherwise surfaces a receiver that will not open, refuses the
/// capability, or closes before completing.
pub fn push_from(
    server: &crate::BundleServer,
    options: crate::PushOptions,
) -> Result<PackageSummary, Error> {
    let crate::PushOptions {
        address,
        holder,
        identity,
        rails,
        extensions,
        progress,
    } = options;
    if !valid_rail_count(rails) || progress.as_ref().is_some_and(|(quantum, _)| *quantum == 0) {
        return Err(Error::InvalidArguments);
    }
    if server.objects.is_empty() {
        return Err(Error::InvalidBundle);
    }
    let mut config = client_config()?;
    apply_datagram_bytes(&mut config)?;
    let extensions = {
        let mut offered = extensions;
        offered.insert(vot_codec::extension_id::PUSH);
        offered
    };
    let progress = progress.map(|(quantum, observer)| Reporter::new(quantum, observer, rails));
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
            let mut pushing = crate::ServeSession::begin_push_session(server, session, holder)?;
            pushing.negotiate_push()?;
            sessions.push(pushing);
        }
        let mut running = Vec::with_capacity(rails);
        for (rail, mut pushing) in sessions.into_iter().enumerate() {
            let progress = progress.as_ref();
            running.push(scope.spawn(move || {
                let status = crate::drive::drive_until(&mut pushing, |session| {
                    if let Some(progress) = progress {
                        progress.taken(rail, session.served_bytes());
                    }
                    false
                })?
                .ok_or(Error::Stalled)?;
                if let Some(progress) = progress {
                    progress.taken(rail, pushing.served_bytes());
                }
                match status {
                    crate::ServeStatus::Completed => Ok(()),
                    crate::ServeStatus::Closed(code) => Err(Error::PeerClosed(code)),
                    crate::ServeStatus::Disconnected | crate::ServeStatus::Active => {
                        Err(Error::CarrierUnavailable)
                    }
                }
            }));
        }
        for rail in running {
            rail.join().map_err(|_| Error::CarrierUnavailable)??;
        }
        if let Some(progress) = &progress {
            progress.finish();
        }
        Ok(server.package())
    })
}

/// Sums what every rail's carrier has taken and hands the observer the sum
/// once per quantum, in order: the sum is read and compared under the one
/// lock the observer is called under, so it never goes backwards.
pub(super) struct Reporter {
    quantum: u64,
    rails: Vec<std::sync::atomic::AtomicU64>,
    state: std::sync::Mutex<(u64, crate::Progress)>,
}

impl Reporter {
    pub(super) fn new(quantum: u64, observer: crate::Progress, rails: usize) -> Self {
        Self {
            quantum,
            rails: (0..rails)
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect(),
            state: std::sync::Mutex::new((0, observer)),
        }
    }

    pub(super) fn taken(&self, rail: usize, bytes: u64) {
        let before = self.rails[rail].swap(bytes, std::sync::atomic::Ordering::Relaxed);
        // A rail crosses a quantum boundary of its own before it pays for
        // the lock; the sum is what the observer hears.
        if crossed_quantum(before, bytes, self.quantum) {
            self.report(false);
        }
    }

    pub(super) fn finish(&self) {
        self.report(true);
    }

    fn report(&self, last: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let sum: u64 = self
            .rails
            .iter()
            .map(|rail| rail.load(std::sync::atomic::Ordering::Relaxed))
            .sum();
        let (reported, observer) = &mut *state;
        if report_due(*reported, sum, self.quantum, last) {
            *reported = sum;
            observer(sum, None);
        }
    }
}

/// Whether a count moved from one quantum to another.
pub(super) const fn crossed_quantum(before: u64, after: u64, quantum: u64) -> bool {
    before / quantum != after / quantum
}

/// Whether `sum` is worth an observer's call after `reported` was the last
/// one: a new quantum, or the end of the transfer with anything unreported.
pub(super) const fn report_due(reported: u64, sum: u64, quantum: u64, last: bool) -> bool {
    sum / quantum > reported / quantum || (last && sum > reported)
}

/// Receives pushed bundles below `directory` on Unix.
///
/// Non-Unix platforms fail closed until guarded directory operations are
/// available there. Dialing [`push_bundle`] remains cross-platform.
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
    prepare_push_destination(directory)?;
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
    bind_retry_listener(address, credentials)
}

/// A Retry-protected listener with no accept timeout, and the identity a
/// peer pins, for a host that runs its own admission.
pub(super) fn bind_retry_listener(
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
/// Non-Unix platforms refuse every admitted destination.
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
    let plans = ReceivePlans::default();
    accept_sessions(listener, sessions, |carrier| {
        receive_one(carrier, &policy, &plans, authentication_timeout).map(|_| ())
    })
}

/// Accepts carriers from a Retry-protected listener and runs `session` on
/// each in its own thread, at most [`crate::drive::CONCURRENT_SESSIONS`] at
/// once, until `sessions` are answered or the listener fails. A session's
/// own failure surfaces only under a bound; an unbounded loop outlives it.
///
/// # Errors
/// Refuses a listener without Retry with [`Error::InvalidArguments`].
pub(super) fn accept_sessions<S>(
    listener: &Listener,
    sessions: Option<u32>,
    session: S,
) -> Result<(), Error>
where
    S: Fn(Transport) -> Result<(), Error> + Sync,
{
    if !listener.stateless_retry_enabled() {
        return Err(Error::InvalidArguments);
    }
    std::thread::scope(|scope| {
        let mut running: std::collections::VecDeque<
            std::thread::ScopedJoinHandle<'_, Result<(), Error>>,
        > = std::collections::VecDeque::new();
        let mut failed = Ok(());
        for _ in 0..sessions.unwrap_or(u32::MAX) {
            while running
                .len()
                .checked_sub(crate::drive::CONCURRENT_SESSIONS)
                .is_some()
            {
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
                if should_record_failure(sessions.is_some(), failed.is_ok()) {
                    failed = result;
                }
            }
            let carrier = listener.accept().map_err(carrier_failure)?;
            let session = &session;
            running.push_back(scope.spawn(move || session(carrier)));
        }
        while let Some(done) = running.pop_front() {
            let result = done.join().map_err(|_| Error::CarrierUnavailable)?;
            if should_record_failure(sessions.is_some(), failed.is_ok()) {
                failed = result;
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
            let Some(mut admission) = policy(PushPresentation {
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
            if !valid_push_scope(&admission.scope) {
                session.refuse(
                    vot_codec::error_code::AUTHORIZATION_FAILED,
                    crate::authz::REFUSAL_DETAIL.to_owned(),
                )?;
                session.flush()?;
                continue;
            }
            let Some(directory) =
                canonical_push_destination_before(&admission.directory, authentication_deadline)?
            else {
                let _ = session
                    .driver()
                    .close(vot_codec::error_code::AUTHENTICATION_FAILED);
                return Err(Error::PeerClosed(
                    vot_codec::error_code::AUTHENTICATION_FAILED,
                ));
            };
            admission.directory = directory;
            let scope = (
                admission.scope.root,
                admission.scope.length.ok_or(Error::InvalidArguments)?,
            );
            let Some((group, primary)) = plan_group(plans, (admission.directory.clone(), scope))?
            else {
                session.refuse(
                    vot_codec::error_code::AUTHORIZATION_FAILED,
                    crate::authz::REFUSAL_DETAIL.to_owned(),
                )?;
                session.flush()?;
                continue;
            };
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

    let mut shared_failure = SharedPlanFailure(plan.clone());
    let mut fetcher = if let Some(plan) = plan {
        crate::BundleFetcher::join_started_session(session, &admission.directory, plan)?
    } else {
        crate::BundleFetcher::from_started_session(session, &admission.directory, Some(root))?
    };
    fetcher.set_receive_seams(admission.seams);
    if primary {
        // The receive side never learns how many sessions the sender will
        // open, and every one of them joins this plan; the sender's own
        // ceiling is `valid_rail_count`, so the window is the one those
        // rails would earn.
        fetcher.set_object_window(crate::fetch::object_window(
            crate::drive::CONCURRENT_SESSIONS,
        ));
        let planned =
            crate::drive::drive_until(&mut fetcher, |fetcher| fetcher.shared_plan().is_some());
        let plan = match planned {
            Ok(None) => fetcher.shared_plan().ok_or(Error::InvalidBundle),
            Ok(Some(crate::FetchStatus::Complete)) => {
                let cursor = fetcher.acknowledge_completion()?;
                primary_plan
                    .as_mut()
                    .ok_or(Error::CarrierUnavailable)?
                    .complete(fetcher.package().ok_or(Error::InvalidBundle)?, cursor)?;
                fetcher.await_peer_close()?;
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
                    .publish(plan.clone())?;
                shared_failure.arm(plan);
            }
            Err(error) => {
                return Err(error);
            }
        }
    }
    let driven = crate::drive(&mut fetcher);
    // Joined per session, before this receive answers: what the flusher
    // still holds is owed however this session ended.
    let status = fetcher.finish_completions().and(driven)?;
    match status {
        crate::FetchStatus::Complete => {
            fetcher.acknowledge_completion()?;
            fetcher.await_peer_close()?;
            let package = fetcher.package().ok_or(Error::InvalidBundle)?;
            shared_failure.complete();
            Ok(package)
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

    fn key(index: u8) -> (std::path::PathBuf, PlanScope) {
        (
            index.to_string().into(),
            ([index; 32], u64::from(index.wrapping_add(1))),
        )
    }

    #[test]
    fn push_bounds_and_scope_are_exact() {
        assert!(!valid_rail_count(0));
        assert!(valid_rail_count(1));
        assert!(valid_rail_count(crate::drive::CONCURRENT_SESSIONS));
        assert!(!valid_rail_count(crate::drive::CONCURRENT_SESSIONS + 1));
        let now = std::time::Instant::now();
        assert!(!deadline_live(now, now));
        assert!(deadline_live(now, now + std::time::Duration::from_nanos(1)));
        for (bounded, clean, expected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            assert_eq!(should_record_failure(bounded, clean), expected);
        }

        let exact = crate::authz::push_scope([7; 32], 42);
        assert!(valid_push_scope(&exact));
        assert!(!valid_push_scope(&vot_capability::Scope {
            suite: 2,
            ..exact.clone()
        }));
        assert!(!valid_push_scope(&vot_capability::Scope {
            length: None,
            ..exact.clone()
        }));
        assert!(!valid_push_scope(&vot_capability::Scope {
            ranges: vec![vot_capability::Range::new(0, 1).unwrap()],
            ..exact
        }));
        assert!(real_directory(true));
        assert!(!real_directory(false));
        assert!(missing_path(std::io::ErrorKind::NotFound));
        assert!(!missing_path(std::io::ErrorKind::PermissionDenied));
        assert!(raced_existing(std::io::ErrorKind::AlreadyExists));
        assert!(!raced_existing(std::io::ErrorKind::PermissionDenied));
        for (strict, sticky, expected) in [
            (false, false, false),
            (false, true, true),
            (true, false, true),
            (true, true, true),
        ] {
            assert_eq!(safe_parent(strict, sticky), expected);
        }
        #[cfg(unix)]
        {
            assert!(trusted_sticky_parent(true, true, 0, 42));
            assert!(trusted_sticky_parent(true, true, 42, 42));
            assert!(!trusted_sticky_parent(true, true, 41, 42));
            assert!(!trusted_sticky_parent(false, true, 42, 42));
            assert!(!trusted_sticky_parent(true, false, 42, 42));
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn push_receive_is_refused_without_guarded_directories() {
        assert!(prepare_push_destination(Path::new("push")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn push_destinations_must_be_owned_directories() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        let parent = crate::tests::temporary("push-destination");
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700).create(&parent).unwrap();
        let destination = parent.join("bundle");
        let not_directory = parent.join("file");
        std::fs::write(&not_directory, []).unwrap();
        let error = prepare_absent_destination(
            &not_directory.join("bundle"),
            std::io::Error::from(std::io::ErrorKind::NotADirectory),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::NotADirectory)
        );

        let denied = parent.join("denied");
        let error = finish_destination_create(
            &denied,
            Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
        );
        assert!(!denied.exists());
        finish_destination_create(
            &denied,
            Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists,
            ))),
        )
        .unwrap();
        assert!(denied.is_dir());

        assert!(!sticky_parent(&destination).unwrap());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1700)).unwrap();
        assert!(sticky_parent(&destination).unwrap());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        prepare_push_destination(&destination).unwrap();
        prepare_push_destination(&destination).unwrap();

        let sub = parent.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let dotdot = sub.join("..").join("bundle");
        let ancestor = parent.join("ancestor");
        std::os::unix::fs::symlink(".", &ancestor).unwrap();
        let through_symlink = ancestor.join("bundle");
        let canonical = canonical_push_destination(&destination).unwrap();
        assert_eq!(
            canonical_push_destination_before(
                &destination,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap(),
            Some(canonical.clone())
        );
        assert!(
            canonical_push_destination_before(
                &destination,
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .unwrap(),
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(canonical_push_destination(&dotdot).unwrap(), canonical);
        assert_eq!(
            canonical_push_destination(&through_symlink).unwrap(),
            canonical
        );

        let plans = ReceivePlans::default();
        let scope = ([7; 32], 8);
        let (primary, first) = plan_group(&plans, (canonical.clone(), scope))
            .unwrap()
            .unwrap();
        assert!(first);
        let (joined, first) = plan_group(
            &plans,
            (canonical_push_destination(&dotdot).unwrap(), scope),
        )
        .unwrap()
        .unwrap();
        assert!(!first);
        assert!(std::sync::Arc::ptr_eq(&primary, &joined));
        assert!(
            plan_group(
                &plans,
                (
                    canonical_push_destination(&through_symlink).unwrap(),
                    ([7; 32], 9),
                ),
            )
            .unwrap()
            .is_none()
        );

        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_push_destination(&destination).is_err());
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(&destination).unwrap();

        let outside = parent.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();
        assert!(prepare_push_destination(&destination).is_err());
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn a_failed_primary_wakes_every_waiter() {
        let plans = ReceivePlans::default();
        let (group, primary) = plan_group(&plans, key(1)).unwrap().unwrap();
        assert!(primary);
        let (joined, primary) = plan_group(&plans, key(1)).unwrap().unwrap();
        assert!(!primary);
        let waiting = {
            std::thread::spawn(move || {
                let mut state = joined.0.lock().unwrap();
                while matches!(*state, PlanSlot::Building) {
                    let (next, timeout) = joined
                        .1
                        .wait_timeout(state, std::time::Duration::from_secs(1))
                        .unwrap();
                    state = next;
                    if timeout.timed_out() {
                        return false;
                    }
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
    fn a_failed_rail_abandons_its_plan_and_a_completed_one_does_not() {
        let (bundle, _) = crate::harness::built_bundle("push-plan-guard", &[("a", vec![1; 8])]);
        let (server, mut session, mut connection) = crate::fetch::tests::serving(&bundle);
        let output = crate::tests::temporary("push-plan-guard-output");
        let mut fetcher =
            crate::BundleFetcher::begin(crate::harness::Loopback::default(), &output, None)
                .unwrap();
        let plan =
            crate::fetch::tests::planned(&server, &mut session, &mut connection, &mut fetcher);

        let mut failed = SharedPlanFailure(None);
        failed.arm(plan.clone());
        drop(failed);
        assert!(plan.lock().unwrap().abandoned);
        plan.lock().unwrap().abandoned = false;
        SharedPlanFailure(Some(plan.clone())).complete();
        assert!(!plan.lock().unwrap().abandoned);
        crate::harness::discard(&[&bundle, &output]);
    }

    #[test]
    fn completed_groups_are_replaced_and_dead_roots_are_pruned() {
        let plans = ReceivePlans::default();
        for index in 0..100 {
            let (group, primary) = plan_group(&plans, key(index)).unwrap().unwrap();
            assert!(primary);
            drop(group);
        }
        let (first, primary) = plan_group(&plans, key(7)).unwrap().unwrap();
        assert!(primary);
        let (joined, primary) = plan_group(&plans, key(7)).unwrap().unwrap();
        assert!(!primary);
        assert!(std::sync::Arc::ptr_eq(&first, &joined));
        assert_eq!(plans.lock().unwrap().len(), 1);
    }

    #[test]
    fn equivalent_grants_join_and_conflicting_scopes_are_refused() {
        let plans = ReceivePlans::default();
        let key = ("bundle".into(), ([7; 32], 8));
        let (primary, first) = plan_group(&plans, key.clone()).unwrap().unwrap();
        assert!(first);
        let (joined, first) = plan_group(&plans, key).unwrap().unwrap();
        assert!(!first);
        assert!(std::sync::Arc::ptr_eq(&primary, &joined));
        assert!(
            plan_group(&plans, ("bundle".into(), ([7; 32], 9)))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn one_root_admitted_to_two_destinations_never_shares_a_plan() {
        let plans = ReceivePlans::default();
        let scope = ([7; 32], 8);
        let (left, left_primary) = plan_group(&plans, ("left".into(), scope)).unwrap().unwrap();
        let (right, right_primary) = plan_group(&plans, ("right".into(), scope))
            .unwrap()
            .unwrap();
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
        let group = std::sync::Arc::new((
            std::sync::Mutex::new(PlanSlot::Building),
            std::sync::Condvar::new(),
        ));
        let cancellation = crate::CancellationHandle::default();
        let cancelling = cancellation.clone();
        let finishing = std::sync::Arc::clone(&group);
        let wake = std::thread::spawn(move || {
            std::thread::sleep(PLAN_WAIT_POLL);
            cancelling.cancel();
            finishing.1.notify_all();
            std::thread::sleep(PLAN_WAIT_POLL);
            *finishing.0.lock().unwrap() = PlanSlot::Failed;
            finishing.1.notify_all();
        });
        assert!(joined_plan(&group, &cancellation).unwrap().is_none());
        wake.join().unwrap();
    }
}
