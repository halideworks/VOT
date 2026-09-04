//! QUIC transport endpoint for the serve and fetch commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use vot_transport_api::ReceiveLimits;
pub use vot_transport_quiche::live::Listener;
use vot_transport_quiche::live::{Config, CongestionControl, SideChannel, Transport};

use crate::{BundleFetcher, BundleServer, Credentials, Error, PackageSummary, ServeSession};

mod certificate;
mod config;
mod fetch;
mod push;
mod registration;
mod relay;
mod resolution;
mod serve;

pub use fetch::{fetch_bundle, fetch_bundle_with, fetch_via_rendezvous, probe_serve};
pub use push::{
    PushAdmission, PushPresentation, bind_push_listener, push_bundle, push_from, receive_push,
    receive_push_on,
};
pub use registration::rendezvous_service;
pub use relay::relay_service;
pub use serve::{
    ServeAdmission, ServePresentation, ServeReport, bind_serve_listener, serve_bundle, serve_on,
};

pub(crate) use certificate::*;
pub(crate) use config::*;
#[cfg(test)]
pub(crate) use fetch::*;
pub(crate) use registration::*;
#[cfg(test)]
pub(crate) use relay::*;
pub(crate) use resolution::*;
#[cfg(test)]
pub(crate) use serve::*;

/// Maps carrier errors: configuration failures become argument errors,
/// everything else is the endpoint.
fn carrier_failure(error: vot_transport_api::Error) -> Error {
    match error {
        vot_transport_api::Error::InvalidConfiguration => Error::InvalidArguments,
        _ => Error::CarrierUnavailable,
    }
}

/// Finds the local source address for reaching `peer`. quiche rejects
/// wildcard binds, so a real address is needed before connect.
fn local_for(peer: SocketAddr) -> Result<SocketAddr, Error> {
    let wildcard = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let probe = std::net::UdpSocket::bind(wildcard)?;
    probe.connect(peer)?;
    let mut local = probe.local_addr()?;
    local.set_port(0);
    Ok(local)
}

/// Milliseconds since `began`, saturating rather than wrapping.
fn elapsed_ms(began: std::time::Instant) -> u64 {
    u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// `target` as a socket bound in `local`'s family can address it. A
/// dual-stack socket takes an IPv4 destination only in its mapped form,
/// which is the inverse of what [`crate::side_channel::address::canonical`] undoes.
fn for_socket(target: SocketAddr, local: SocketAddr) -> SocketAddr {
    match (local, target) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => target,
    }
}

/// What a failed read is worth reporting as: a wait that ran out is
/// nothing, and any other failure is the carrier's.
fn read_failure(error: &std::io::Error) -> Option<Error> {
    if waited_out(error) {
        None
    } else {
        Some(Error::CarrierUnavailable)
    }
}

/// Returns true for timeout/WouldBlock, false for real errors.
fn waited_out(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Runs `work` on a thread and waits `seconds` for its answer. A step that
    /// never finishes fails the test naming itself, instead of hanging the run
    /// the way a stalled fetch, or a bounded serve left waiting for a session
    /// that never comes, otherwise would.
    fn within<T: Send + 'static>(
        step: &str,
        seconds: u64,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, answer) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = done.send(work());
        });
        match answer.recv_timeout(Duration::from_secs(seconds)) {
            Ok(value) => value,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("{step} did not finish within {seconds} seconds")
            }
            // The sender went with a panicking thread: report its panic.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(worker.join().expect_err("a panicking thread"))
            }
        }
    }

    /// [`within`] for a thread already running: joins it under a bound.
    fn joined<T: Send + 'static>(step: &str, handle: std::thread::JoinHandle<T>) -> T {
        match within(step, 30, move || handle.join()) {
            Ok(value) => value,
            Err(panicked) => std::panic::resume_unwind(panicked),
        }
    }

    fn serve_token(
        issuer: &ed25519_dalek::SigningKey,
        holder: ed25519_dalek::SigningKey,
        root: [u8; 32],
    ) -> std::sync::Arc<crate::authz::Holder> {
        let token = crate::authz::issue(
            "issuer.example",
            "serve.example",
            issuer,
            holder.verifying_key().to_bytes(),
            root,
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        std::sync::Arc::new(crate::authz::Holder::new(token, holder).expect("a holder"))
    }

    fn fetch_holding(
        at: SocketAddr,
        into: &Path,
        pin: [u8; 32],
        holder: std::sync::Arc<crate::authz::Holder>,
    ) -> Result<(crate::FetchStatus, Option<PackageSummary>), Error> {
        let into = into.to_path_buf();
        within("the fetch holding a token", 60, move || {
            let client = client_config().expect("a client config");
            let carrier = Transport::connect(
                local_for(at).expect("a local address"),
                at,
                Some("localhost"),
                &client,
            )
            .expect("a carrier");
            let mut fetcher = BundleFetcher::begin_with(
                carrier,
                &into,
                Some(pin),
                Some(holder),
                std::collections::BTreeSet::new(),
            )
            .expect("a fetch holding the token");
            let status = crate::drive::drive(&mut fetcher)?;
            Ok((status, fetcher.package()))
        })
    }

    #[test]
    fn serve_on_admits_by_root_and_reports_each_session() {
        use ed25519_dalek::SigningKey;

        let (bundle_a, built_a) = crate::harness::built_bundle(
            "serve-on-a",
            &[("data.bin", crate::harness::patterned(200_000))],
        );
        let (bundle_b, built_b) =
            crate::harness::built_bundle("serve-on-b", &[("other.bin", vec![7; 1_000])]);
        let server_a = std::sync::Arc::new(BundleServer::open(&bundle_a).unwrap());
        let server_b = std::sync::Arc::new(BundleServer::open(&bundle_b).unwrap());
        let issuer = SigningKey::from_bytes(&[61; 32]);
        let (listener, _identity) =
            bind_serve_listener("127.0.0.1:0".parse().unwrap(), &Credentials::Ephemeral)
                .expect("a serve listener");
        let at = listener.local_address();
        let (reports, reported) = mpsc::channel::<ServeReport>();
        let verifying = issuer.verifying_key();
        let servers = [server_a, server_b];
        let serving = std::thread::spawn(move || {
            serve::serve_on_bounded(&listener, Some(3), |presentation| {
                // The policy tries every package it holds; the token's own
                // root is the one whose requirement decides.
                let decided = servers.iter().find_map(|server| {
                    crate::authz::Requirement::new(
                        "issuer.example",
                        crate::authz::key_id_of(&verifying),
                        verifying,
                        "serve.example",
                        server.package().root,
                    )
                    .decide(
                        presentation.challenge,
                        presentation.open,
                        presentation.channel_binding,
                        presentation.now,
                    )
                    .map(|scope| (server, scope))
                })?;
                let (server, scope) = decided;
                let root = vot_capability::decode_scope(&scope).expect("a scope").root;
                // A policy that answers B's token from A: the seam refuses it.
                let server = if root == servers[1].package().root {
                    std::sync::Arc::clone(&servers[0])
                } else {
                    std::sync::Arc::clone(server)
                };
                let reports = reports.clone();
                Some(ServeAdmission {
                    server,
                    scope,
                    observer: Some(Box::new(move |report| {
                        let _ = reports.send(report);
                    })),
                })
            })
        });

        // A token for A is served from A to completion.
        let fetched = crate::tests::temporary("serve-on-fetched");
        let (status, package) = fetch_holding(
            at,
            &fetched,
            built_a.root,
            serve_token(&issuer, SigningKey::from_bytes(&[62; 32]), built_a.root),
        )
        .expect("a driven fetch");
        assert_eq!(
            status,
            crate::FetchStatus::Complete,
            "A's holder was refused"
        );
        assert_eq!(package.expect("a package"), built_a);
        let report = reported
            .recv_timeout(Duration::from_secs(10))
            .expect("the observer heard the session end");
        assert_eq!(report.objects, 1);
        // `fetch_holding` drives the engine raw, without the wire layer's
        // completion handshake, so the serve sees the carrier drop rather than
        // a final-cursor GOAWAY. The wire path is covered by
        // `fetch_over_acknowledges_completion_on_one_session`.
        assert_eq!(report.cursor, None, "the raw-drive path sends no GOAWAY");
        assert!(
            report.served_bytes >= 200_000,
            "served {} bytes of a 200000 byte object",
            report.served_bytes
        );
        assert!(report.status.is_ok(), "{:?}", report.status);
        assert_eq!(report.peer.ip(), at.ip());

        // A token for an unknown root, and a token for B answered from A,
        // are both refused: the holder spends its presentation attempts on
        // the one constant refusal and the session ends with no bundle.
        for (name, root) in [("unknown", [9; 32]), ("mismatched", built_b.root)] {
            let refused = crate::tests::temporary(&format!("serve-on-{name}"));
            let outcome = fetch_holding(
                at,
                &refused,
                root,
                serve_token(&issuer, SigningKey::from_bytes(&[63; 32]), root),
            );
            assert!(
                matches!(outcome, Err(Error::Session(_))),
                "{name}: served, or refused for another reason: {outcome:?}"
            );
            let written = std::fs::read_dir(refused.join("objects")).map_or(0, Iterator::count);
            assert_eq!(written, 0, "{name}: an object was written anyway");
            crate::harness::discard(&[&refused]);
        }
        assert!(
            reported.try_recv().is_err(),
            "a refused session reached the observer"
        );
        // Bounded, so the refused sessions surface as the serve's failure.
        assert!(joined("the serving thread", serving).is_err());
        crate::harness::discard(&[&bundle_a, &bundle_b, &fetched]);
    }

    // A railed fetch over the wire path completes with the primary
    // acknowledging every transfer object: exactly one serve session ends
    // `Completed` with the final cursor, and the rails close without one.
    #[test]
    fn fetch_over_acknowledges_completion_on_one_session() {
        use ed25519_dalek::SigningKey;

        let (bundle, built) = crate::harness::built_bundle(
            "fetch-ack",
            &[("payload.bin", crate::harness::patterned(512 * 1024))],
        );
        let server = std::sync::Arc::new(BundleServer::open(&bundle).unwrap());
        let issuer = SigningKey::from_bytes(&[71; 32]);
        let (listener, _identity) =
            bind_serve_listener("127.0.0.1:0".parse().unwrap(), &Credentials::Ephemeral)
                .expect("a serve listener");
        let at = listener.local_address();
        let (reports, reported) = mpsc::channel::<ServeReport>();
        let verifying = issuer.verifying_key();
        let policy_server = std::sync::Arc::clone(&server);
        // Two rails open two sessions; serve both, then stop.
        let serving = std::thread::spawn(move || {
            serve::serve_on_bounded(&listener, Some(2), |presentation| {
                let scope = crate::authz::Requirement::new(
                    "issuer.example",
                    crate::authz::key_id_of(&verifying),
                    verifying,
                    "serve.example",
                    policy_server.package().root,
                )
                .decide(
                    presentation.challenge,
                    presentation.open,
                    presentation.channel_binding,
                    presentation.now,
                )?;
                let reports = reports.clone();
                Some(ServeAdmission {
                    server: std::sync::Arc::clone(&policy_server),
                    scope,
                    observer: Some(Box::new(move |report| {
                        let _ = reports.send(report);
                    })),
                })
            })
        });

        let destination = crate::tests::temporary("fetch-ack-destination");
        let holder = serve_token(&issuer, SigningKey::from_bytes(&[72; 32]), built.root);
        let config = client_config().expect("a client config");
        let connect = move || {
            let carrier = Transport::connect(
                local_for(at).expect("a local address"),
                at,
                Some("localhost"),
                &config,
            )
            .map_err(|_| Error::CarrierUnavailable)?;
            Ok(carrier)
        };
        let primary = connect().expect("a primary carrier");
        let mut fetcher = BundleFetcher::begin_with(
            primary,
            &destination,
            Some(built.root),
            Some(holder),
            std::collections::BTreeSet::new(),
        )
        .expect("a fetch holding the token");
        // Rails past one need proof workers to verify off the primary's thread.
        fetcher.set_proving_threads(2).expect("proving threads");
        let outcome = within("the railed fetch", 60, move || {
            crate::drive::fetch_striped(fetcher, 2, connect)
        })
        .expect("a railed fetch");
        assert_eq!(outcome.package, built);

        // Collect what the sessions reported. Both rails were admitted, so two
        // reports arrive; only the primary's carries the completion cursor.
        let mut collected = Vec::new();
        while let Ok(report) = reported.recv_timeout(Duration::from_secs(10)) {
            collected.push(report);
            if collected.len() == 2 {
                break;
            }
        }
        assert!(!collected.is_empty(), "no session reached the observer");
        let completed: Vec<_> = collected
            .iter()
            .filter(|report| report.status.as_ref().ok() == Some(&crate::ServeStatus::Completed))
            .collect();
        assert_eq!(
            completed.len(),
            1,
            "exactly one session completes: {collected:?}"
        );
        assert_eq!(completed[0].objects, 1);
        assert_eq!(
            completed[0].cursor,
            Some(1),
            "the completing session saw the final cursor"
        );
        // Only the completing session carried a cursor; the rails dropped.
        let with_cursor = collected
            .iter()
            .filter(|report| report.cursor.is_some())
            .count();
        assert_eq!(
            with_cursor, 1,
            "only one session carried a cursor: {collected:?}"
        );

        let _ = joined("the serving thread", serving);
        crate::harness::discard(&[&bundle, &destination]);
    }

    #[test]
    fn serve_on_refuses_a_listener_without_retry() {
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.stateless_retry = false;
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        assert!(matches!(
            serve_on(&listener, |_| panic!("a session was accepted")),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn serve_on_closes_a_silent_peer_at_the_deadline() {
        let (listener, _identity) =
            bind_serve_listener("127.0.0.1:0".parse().unwrap(), &Credentials::Ephemeral)
                .expect("a serve listener");
        let at = listener.local_address();
        // Announced over a channel, so a serve that never closes the peer
        // fails this test at the bounded wait instead of hanging it.
        let (ended, ending) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = ended.send(serve::serve_on_bounded_with_timeout(
                &listener,
                Some(1),
                Duration::from_millis(300),
                |_| panic!("a silent peer presented something"),
            ));
        });
        // A carrier that completes the handshake and never opens a session.
        let client = client_config().expect("a client config");
        let carrier = Transport::connect(
            local_for(at).expect("a local address"),
            at,
            Some("localhost"),
            &client,
        )
        .expect("a carrier");
        let outcome = ending
            .recv_timeout(Duration::from_secs(5))
            .expect("the serve did not close the silent peer at the deadline");
        drop(carrier);
        assert!(
            matches!(
                outcome,
                Err(Error::PeerClosed(
                    vot_codec::error_code::AUTHENTICATION_FAILED
                ))
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_serve_draws_a_fresh_nonce_for_every_session() {
        let drawn = || {
            let vot_session::Authentication::NotRequired { nonce } =
                serve_stance(None).expect("a nonce").authentication
            else {
                panic!("a serve with no requirement asks for no capability");
            };
            nonce
        };
        let first = drawn();
        assert_ne!(first, drawn(), "two sessions advertised the same nonce");
        assert_ne!(first, [0; 32], "the nonce is the constant it used to be");
    }

    #[test]
    fn ephemeral_credentials_are_unguessable_and_unreadable_by_others() {
        let first = Ephemeral::generate().expect("credentials");
        let second = Ephemeral::generate().expect("a second set");
        assert_ne!(
            first.directory, second.directory,
            "two serves in one process shared a directory"
        );
        let name = first
            .directory
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        // The shape, not the absence of the process ID as a substring: a
        // 32-character hex string contains a short decimal by chance most of
        // the time, and a one-digit PID is exactly what a PID namespace
        // gives, which is the case this change exists for. Hex throughout
        // says no decimal identifier is in there at all.
        let suffix = name
            .strip_prefix("vot-serve-")
            .expect("the credential prefix");
        assert_eq!(suffix.len(), 32, "{name}");
        assert!(
            suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the name carries something that is not the random suffix: {name}"
        );
        assert!(first.certificate.exists() && first.key.exists());

        // Unix-only because that is where mode bits decide it. Elsewhere the
        // per-user temp directory is what keeps the key private, and the
        // assertions above cover the part this change controls.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&first.directory), 0o700);
            assert_eq!(mode(&first.key), 0o600);
            assert_eq!(mode(&first.certificate), 0o600);
        }

        let directory = first.directory.clone();
        drop(first);
        assert!(!directory.exists(), "the key outlived its serve");

        // A temp root that does not exist yet is built rather than refused:
        // creating only the leaf aborted a serve before it bound, on any
        // TMPDIR whose tree the caller expects to be made on demand.
        let root = std::env::temp_dir().join(format!("vot-serve-root-{suffix}"));
        let leaf = root.join("deeper").join("credentials");
        crate::create_private_directory(&leaf).expect("a tree that did not exist yet");
        assert!(leaf.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&leaf), 0o700, "only the leaf holds a key");
        }
        std::fs::remove_dir_all(&root).expect("the tree");
    }

    #[test]
    fn a_carrier_refusing_its_configuration_names_the_argument() {
        assert!(matches!(
            carrier_failure(vot_transport_api::Error::InvalidConfiguration),
            Error::InvalidArguments
        ));
        assert!(matches!(
            carrier_failure(vot_transport_api::Error::Backend),
            Error::CarrierUnavailable
        ));
    }

    #[test]
    fn the_datagram_ceiling_is_the_value_given_or_the_default() {
        let mut config = Config::client(limits().unwrap());
        let unset = config.max_datagram_bytes;
        apply_datagram_value(&mut config, " 8972\n").unwrap();
        assert_eq!(config.max_datagram_bytes, 8972, "given, trimmed, taken");
        let mut config = Config::client(limits().unwrap());
        assert!(
            apply_datagram_value(&mut config, "jumbo").is_err(),
            "a value that is not a number is refused"
        );
        assert_eq!(
            config.max_datagram_bytes, unset,
            "a refused value changes nothing"
        );
        assert!(apply_datagram_value(&mut config, "0").is_err());
        assert!(apply_datagram_value(&mut config, "70000").is_err());
        assert_eq!(config.max_datagram_bytes, unset);
        assert!(
            std::env::var(DATAGRAM_BYTES).is_err(),
            "the suite owns no env"
        );
        let mut config = Config::client(limits().unwrap());
        apply_datagram_bytes(&mut config).unwrap();
        assert_eq!(
            config.max_datagram_bytes,
            vot_transport_quiche::live::LARGEST_DATAGRAM_SIZE
        );
    }

    #[test]
    fn the_service_pairs_a_register_with_a_resolve_across_real_sockets() {
        use crate::rendezvous::{Datagram, decode, encode};

        let (addressed, address) = mpsc::channel();
        let service = std::thread::spawn(move || {
            rendezvous_service("127.0.0.1:0".parse().unwrap(), Some(6), |at| {
                let _ = addressed.send(at);
            })
        });
        let at = address.recv().expect("the service reported its address");
        let key = [5; 32];

        let serve = UdpSocket::bind("127.0.0.1:0").expect("a serve socket");
        serve
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        serve
            .send_to(&encode(&Datagram::Register { key }), at)
            .expect("a register");
        let mut buffer = [0_u8; 128];
        let (length, _) = serve.recv_from(&mut buffer).expect("an acknowledgement");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Registered { key })
        );

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("a fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        fetch.send_to(&[], at).expect("an empty stray");
        fetch
            .send_to(&[0xC0, 1, 2, 3], at)
            .expect("a QUIC-shaped stray");
        fetch
            .send_to(&[0x1F, 1, 3, 9], at)
            .expect("a truncated stray");
        fetch
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a service-shaped stray");
        fetch
            .send_to(&encode(&Datagram::Resolve { key }), at)
            .expect("a resolve");
        let (length, _) = fetch.recv_from(&mut buffer).expect("an answer");
        let Some(Datagram::Resolved {
            serve: Some(mapping),
            ..
        }) = decode(&buffer[..length])
        else {
            panic!("the resolve was not answered with the serve's mapping");
        };
        assert_eq!(
            mapping.port(),
            serve.local_addr().expect("the socket").port(),
            "the mapping is the register's observed source"
        );

        let (length, _) = serve.recv_from(&mut buffer).expect("the notification");
        let Some(Datagram::Coming { fetch: coming, .. }) = decode(&buffer[..length]) else {
            panic!("the serve was not told the fetch is coming");
        };
        assert_eq!(
            coming.port(),
            fetch.local_addr().expect("the socket").port()
        );
        service
            .join()
            .expect("the service thread")
            .expect("the service served its bound");
    }

    #[test]
    fn a_registered_serve_is_resolved_and_warms_the_fetch_that_comes() {
        use crate::rendezvous::{Datagram, decode, encode, key_of};

        let (addressed, address) = mpsc::channel();
        let service_thread = std::thread::spawn(move || {
            rendezvous_service("127.0.0.1:0".parse().unwrap(), Some(120), |at| {
                let _ = addressed.send(at);
            })
        });
        let service = address.recv().expect("the service reported its address");

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let served = listener.local_address();
        let side = listener.take_side_channel().expect("a side channel");
        let root = [9; 32];
        let registration = Registration::begin(side, root, &[service]).expect("a registration");

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("a fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        let mut buffer = [0_u8; 128];
        let mut mapping = None;
        for _ in 0..40 {
            fetch
                .send_to(&encode(&Datagram::Resolve { key: key_of(&root) }), service)
                .expect("a resolve");
            let Ok((length, _)) = fetch.recv_from(&mut buffer) else {
                continue;
            };
            if let Some(Datagram::Resolved {
                serve: Some(at), ..
            }) = decode(&buffer[..length])
            {
                mapping = Some(at);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mapping = mapping.expect("the serve registered and was resolved");
        assert_eq!(
            mapping.port(),
            served.port(),
            "the mapping is the socket sessions arrive at"
        );

        let mut warmed = false;
        for _ in 0..40 {
            let Ok((length, from)) = fetch.recv_from(&mut buffer) else {
                continue;
            };
            if decode(&buffer[..length]) == Some(Datagram::Warming) {
                assert_eq!(from.port(), served.port(), "the serve warmed the path");
                warmed = true;
                break;
            }
        }
        assert!(warmed, "the fetch's mapping was never warmed");
        drop(registration);
        drop(listener);
        let _ = service_thread.join().expect("the service thread");
    }

    #[test]
    fn a_registration_needs_both_a_service_and_a_socket_and_releases_it() {
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let service: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let root = [4; 32];

        assert!(
            start_registration(&[], None, root)
                .expect("no service is no registration")
                .is_none()
        );
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        assert!(
            start_registration(&[], Some(side), root)
                .expect("a socket without a service is no registration")
                .is_none()
        );

        let served = {
            let mut listener =
                Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
            let at = listener.local_address();
            let side = listener.take_side_channel().expect("a side channel");
            let registration = start_registration(&[service], Some(side), root)
                .expect("a registration thread")
                .expect("a service and a socket register");
            let watch = registration.watch();
            drop(registration);
            assert!(
                watch.load(Ordering::Relaxed),
                "the drop stopped the registration thread and waited for it"
            );
            at
        };
        UdpSocket::bind(served).expect("the ended registration released the socket");

        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let unreachable: SocketAddr = "[::1]:9".parse().unwrap();
        assert!(
            matches!(
                start_registration(&[unreachable], Some(side), root),
                Err(Error::CarrierUnavailable)
            ),
            "a service with no address this socket can reach is refused"
        );

        // One address of several refusing is a route this host does not
        // have, which is what a dual-stack name looks like from a host with
        // only one family.
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let registration = start_registration(&[unreachable, service], Some(side), root)
            .expect("one address that took it is a registration")
            .expect("a service and a socket register");
        drop(registration);
    }

    #[test]
    fn a_dual_stack_service_answers_an_ipv4_peer_with_an_ipv4_mapping() {
        // A service bound to [::] sees an IPv4 peer as ::ffff:a.b.c.d. Handing
        // that back as the mapping gives a fetch an IPv6 peer to connect its
        // IPv4 socket to, which fails before a packet leaves.
        use crate::rendezvous::{Datagram, decode, encode};

        let (addressed, address) = mpsc::channel();
        let service = std::thread::spawn(move || {
            rendezvous_service("[::]:0".parse().unwrap(), Some(40), |at| {
                let _ = addressed.send(at);
            })
        });
        let at = address.recv().expect("the service reported its address");
        let reachable = SocketAddr::new("127.0.0.1".parse().unwrap(), at.port());
        let key = [11; 32];

        let serve = UdpSocket::bind("127.0.0.1:0").expect("an IPv4 serve socket");
        serve
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        serve
            .send_to(&encode(&Datagram::Register { key }), reachable)
            .expect("a register");
        let mut buffer = [0_u8; 128];
        let (length, _) = serve.recv_from(&mut buffer).expect("an acknowledgement");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Registered { key }),
            "the answer came back to an IPv4 socket"
        );

        let fetch = UdpSocket::bind("127.0.0.1:0").expect("an IPv4 fetch socket");
        fetch
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        fetch
            .send_to(&encode(&Datagram::Resolve { key }), reachable)
            .expect("a resolve");
        let (length, _) = fetch.recv_from(&mut buffer).expect("an answer");
        let Some(Datagram::Resolved {
            serve: Some(mapping),
            ..
        }) = decode(&buffer[..length])
        else {
            panic!("the resolve was not answered with the serve's mapping");
        };
        assert!(
            mapping.is_ipv4(),
            "an IPv4 serve is named by an IPv4 mapping, not {mapping}"
        );
        assert_eq!(mapping, serve.local_addr().expect("the socket"));

        let (length, _) = serve.recv_from(&mut buffer).expect("the notification");
        let Some(Datagram::Coming { fetch: coming, .. }) = decode(&buffer[..length]) else {
            panic!("the serve was not told the fetch is coming");
        };
        assert_eq!(
            coming,
            fetch.local_addr().expect("the socket"),
            "and so is the fetch it is told about"
        );
        service
            .join()
            .expect("the service thread")
            .expect("the service served its bound");
    }

    #[test]
    fn an_address_is_the_family_that_is_really_its_own() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:4433".parse().expect("an address");
        let plain: SocketAddr = "192.0.2.7:4433".parse().expect("an address");
        let six: SocketAddr = "[2001:db8::1]:4433".parse().expect("an address");
        assert_eq!(crate::side_channel::address::canonical(mapped), plain);
        assert_eq!(crate::side_channel::address::canonical(plain), plain);
        assert_eq!(crate::side_channel::address::canonical(six), six);

        let v6_socket: SocketAddr = "[::]:9999".parse().expect("an address");
        let v4_socket: SocketAddr = "0.0.0.0:9999".parse().expect("an address");
        assert_eq!(
            for_socket(plain, v6_socket),
            mapped,
            "a dual-stack socket takes IPv4 only in its mapped form"
        );
        assert_eq!(for_socket(plain, v4_socket), plain);
        assert_eq!(for_socket(six, v6_socket), six);
        assert_eq!(for_socket(six, v4_socket), six, "nothing to do about it");
    }

    #[test]
    fn a_datagram_the_socket_refuses_does_not_end_the_cadence() {
        // What happens on a real serve: a warming goes to a fetch that has
        // gone, an ICMP unreachable comes back, and the kernel reports it on
        // the next send. If that ended the cadence, the serve would stop
        // being findable over one datagram nobody was waiting for.
        use crate::rendezvous::{Datagram, decode};

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");

        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        service
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = service.local_addr().expect("the service address");
        // An address this socket cannot send to at all: it is bound to IPv4.
        let refused: SocketAddr = "[::1]:9".parse().expect("an address");

        post_regardless(
            &side,
            vec![
                (refused, Datagram::Register { key: [1; 32] }),
                (at, Datagram::Register { key: [2; 32] }),
            ],
        );
        let mut buffer = [0_u8; 128];
        let (length, _) = service.recv_from(&mut buffer).expect("the second send");
        assert_eq!(
            decode(&buffer[..length]),
            Some(Datagram::Register { key: [2; 32] }),
            "the send after the refused one still went"
        );
    }

    #[test]
    fn a_rendezvous_is_the_address_or_name_given_or_nowhere() {
        assert!(std::env::var(RENDEZVOUS).is_err(), "the suite owns no env");
        assert_eq!(rendezvous_from(None).expect("unset is nowhere"), Vec::new());
        assert_eq!(
            rendezvous_from(Some(" 198.51.100.7:9000 ")).expect("an address"),
            vec!["198.51.100.7:9000".parse::<SocketAddr>().unwrap()],
        );
        assert_eq!(
            rendezvous_from(Some("[2001:db8::1]:9000")).expect("an address"),
            vec!["[2001:db8::1]:9000".parse::<SocketAddr>().unwrap()],
        );
        assert!(
            matches!(
                rendezvous_from(Some("rendezvous.example.com")),
                Err(Error::InvalidArguments)
            ),
            "a name without a port names no service"
        );
        let named = rendezvous_from(Some("localhost:9000")).expect("a name the resolver knows");
        assert!(!named.is_empty(), "localhost resolves to something");
        assert!(
            named.iter().all(|address| address.ip().is_loopback()),
            "localhost is this machine, {named:?}"
        );
        assert!(named.iter().all(|address| address.port() == 9000));
        assert!(
            named
                .windows(2)
                .all(|pair| !pair[0].is_ipv4() || !pair[1].is_ipv6()),
            "IPv6 comes first, {named:?}"
        );
        assert!(matches!(
            rendezvous_from(Some("198.51.100.7")),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(
            side_channel_lead(&[]),
            None,
            "no service is nothing to shed aside"
        );
        assert_eq!(
            side_channel_lead(&["198.51.100.7:9000".parse().unwrap()]),
            Some(crate::rendezvous::MAGIC)
        );
        assert!(matches!(
            rendezvous_from(Some("")),
            Err(Error::InvalidArguments)
        ));
    }

    /// A service that answers one resolve with `serve`, warms whoever asked,
    /// and reports the source it observed. Ahead of the answer it sends what
    /// a rail has to read past: a datagram that is no answer, and an answer
    /// under another key naming `elsewhere`.
    fn one_resolve(
        serve: SocketAddr,
        elsewhere: SocketAddr,
    ) -> (SocketAddr, std::thread::JoinHandle<SocketAddr>) {
        use crate::rendezvous::{Datagram, decode, encode};

        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = socket.local_addr().expect("the service address");
        let thread = std::thread::spawn(move || {
            let mut buffer = [0_u8; 128];
            loop {
                let (length, from) = socket.recv_from(&mut buffer).expect("a resolve");
                let Some(Datagram::Resolve { key }) = decode(&buffer[..length]) else {
                    continue;
                };
                let noise = [
                    Datagram::Registered { key },
                    Datagram::Resolved {
                        key: [0xAB; 32],
                        serve: Some(elsewhere),
                    },
                    Datagram::Resolved {
                        key,
                        serve: Some(serve),
                    },
                    Datagram::Warming,
                ];
                for datagram in noise {
                    socket.send_to(&encode(&datagram), from).expect("an answer");
                }
                return from;
            }
        });
        (at, thread)
    }

    #[test]
    fn a_rail_announces_the_socket_it_then_connects_on() {
        // The mapping the service observes is what the serve opens its NAT
        // for, so it has to be the session's own socket. Loopback cannot
        // filter by port, so the identity itself is the assertion.
        //
        // The rail also has to send toward the serve before it waits: a
        // warming that arrives before this end sent anything is unsolicited,
        // and a NAT that tracks it takes the mapping the session wanted.
        // Loopback cannot show that either, so what is asserted is that the
        // datagrams go, and go from the session's socket.
        use crate::rendezvous::{Datagram, decode};

        let at_serve = UdpSocket::bind("127.0.0.1:0").expect("a socket at the serve's mapping");
        // The warmings are queued before the punch returns, so this bound only
        // prices a mutant that sends none.
        at_serve
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bounded wait");
        let serve = at_serve.local_addr().expect("the serve's mapping");
        let elsewhere: SocketAddr = "198.51.100.9:4433".parse().expect("an address");
        let (service, observed) = one_resolve(serve, elsewhere);
        let punched = punch_within(
            [5; 32],
            service,
            Duration::from_millis(1),
            Duration::from_millis(50),
        )
        .expect("a punch");
        assert_eq!(
            punched.serve, serve,
            "the mapping the service holds under this key, not another"
        );
        let announced = punched.socket.local_addr().expect("the socket");
        assert_eq!(
            announced,
            observed.join().expect("the service thread"),
            "the announced mapping is the socket the session connects on"
        );

        let mut buffer = [0_u8; 128];
        for datagram in 0..crate::rendezvous::WARMING_DATAGRAMS {
            let (length, from) = at_serve
                .recv_from(&mut buffer)
                .unwrap_or_else(|_| panic!("warming {datagram} never reached the serve"));
            assert_eq!(decode(&buffer[..length]), Some(Datagram::Warming));
            assert_eq!(
                from, announced,
                "the rail opened its own side from the session's socket"
            );
        }
    }

    #[test]
    fn the_ladder_takes_the_first_candidate_that_opens() {
        // The candidates are the service's addresses, IPv6 first. One that
        // cannot open a carrier costs its own attempt and no more: the rest
        // of the rails take the route that worked, rather than paying the
        // punch bound again to learn the same thing.
        let refusing: SocketAddr = "[2001:db8::1]:9000".parse().expect("an address");
        let working: SocketAddr = "198.51.100.7:9000".parse().expect("an address");
        let tried = std::sync::Mutex::new(Vec::new());
        let open = |service: SocketAddr| -> Result<(Transport, SocketAddr), Error> {
            tried.lock().expect("a lock").push(service);
            Err(Error::RendezvousUnpunched)
        };
        assert!(
            matches!(
                first_route(&[refusing, working], &open),
                Err(Error::RendezvousUnpunched)
            ),
            "every candidate refusing is the last refusal"
        );
        assert_eq!(
            *tried.lock().expect("a lock"),
            vec![refusing, working],
            "in the order given, which is IPv6 first"
        );
        assert!(
            matches!(first_route(&[], &open), Err(Error::InvalidArguments)),
            "no candidates at all is an argument error, not a punch failure"
        );
        assert_eq!(
            tried.lock().expect("a lock").len(),
            2,
            "and nothing was opened for it"
        );
    }

    #[test]
    fn a_stray_before_the_answer_does_not_deny_it() {
        // The first arrival used to shorten every later read to 100ms, so a
        // single stray datagram denied any answer slower than that.
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        let service_at = service.local_addr().expect("the service address");
        let serve = "203.0.113.9:443".parse().expect("a serve address");

        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("something that is not an answer");
        let answering = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            service
                .send_to(
                    &encode(&Datagram::Resolved {
                        key: [5; 32],
                        serve: Some(serve),
                    }),
                    at,
                )
                .expect("the answer");
        });
        let mut buffer = [0_u8; 128];
        assert_eq!(
            resolved(&rail, &mut buffer, [5; 32], service_at).expect("a read"),
            Some(serve),
            "a stray spent the wait the answer needed"
        );
        answering.join().expect("the service");
    }

    #[test]
    fn a_wait_spends_one_budget_however_many_strays_arrive() {
        // Each read used to arm the whole wait again, so eight strays turned
        // a 250ms floor into a two second one.
        use crate::rendezvous::{Datagram, encode};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let budget = Duration::from_millis(250);
        let done = Arc::new(AtomicBool::new(false));
        let sending = Arc::clone(&done);
        // One stray just inside each read, so every read has something to
        // take and only the spent budget can end the wait.
        let straying = std::thread::spawn(move || {
            for _ in 0..STRAY_READS {
                if sending.load(Ordering::Relaxed) {
                    break;
                }
                let _ = stranger.send_to(&encode(&Datagram::Registered { key: [3; 32] }), at);
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let mut buffer = [0_u8; 128];
        let began = std::time::Instant::now();
        let found = read_until(
            &rail,
            &mut buffer,
            budget,
            crate::rendezvous::decode,
            |_, _| None::<()>,
        )
        .expect("a read");
        let spent = began.elapsed();
        done.store(true, Ordering::Relaxed);
        straying.join().expect("the stranger");
        assert_eq!(found, None, "nothing was accepted");
        assert!(
            spent < Duration::from_secs(1),
            "a {budget:?} budget under strays took {spent:?}"
        );
    }

    #[test]
    fn only_the_service_that_was_asked_can_name_the_serve() {
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let service = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        let service_at = service.local_addr().expect("the service address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let steered = "203.0.113.9:443".parse().expect("an address to be sent to");

        // The right key, the right shape, from the wrong host.
        let answer = encode(&Datagram::Resolved {
            key: [7; 32],
            serve: Some(steered),
        });
        stranger.send_to(&answer, at).expect("a forged answer");
        let mut buffer = [0_u8; 128];
        assert_eq!(
            resolved(&rail, &mut buffer, [7; 32], service_at).expect("a read"),
            None,
            "a stranger steered the rail"
        );

        // The same answer from the service is taken.
        service.send_to(&answer, at).expect("the real answer");
        assert_eq!(
            resolved(&rail, &mut buffer, [7; 32], service_at).expect("a read"),
            Some(steered)
        );
    }

    #[test]
    fn only_the_relay_that_was_asked_names_a_slot_and_only_for_the_key() {
        use crate::relay::{Datagram, encode};

        let taker = UdpSocket::bind("127.0.0.1:0").expect("a taker socket");
        let at = taker.local_addr().expect("the taker address");
        let relay = UdpSocket::bind("127.0.0.1:0").expect("a relay socket");
        let relay_at = relay.local_addr().expect("the relay address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let steered = "203.0.113.9:443".parse().expect("an address to be sent to");
        let mut buffer = [0_u8; 128];

        // The right shape from the wrong host, then the wrong key from the
        // right host: neither may steer the fetch to a slot.
        let forged = encode(&Datagram::Slot {
            key: [7; 32],
            at: Some(steered),
        });
        stranger.send_to(&forged, at).expect("a forged slot");
        relay
            .send_to(
                &encode(&Datagram::Slot {
                    key: [8; 32],
                    at: Some(steered),
                }),
                at,
            )
            .expect("another key's slot");
        assert_eq!(
            slot_answered(&taker, &mut buffer, [7; 32], relay_at).expect("a read"),
            None,
            "a slot nobody asked this relay for steered the fetch"
        );

        // The right key from the relay that was asked is taken, and a
        // relay with nothing to give is a retry, not an answer.
        relay
            .send_to(
                &encode(&Datagram::Slot {
                    key: [7; 32],
                    at: None,
                }),
                at,
            )
            .expect("a full relay");
        relay
            .send_to(
                &encode(&Datagram::Slot {
                    key: [7; 32],
                    at: Some(steered),
                }),
                at,
            )
            .expect("the real slot");
        assert_eq!(
            slot_answered(&taker, &mut buffer, [7; 32], relay_at).expect("a read"),
            Some(steered)
        );
    }

    #[test]
    fn a_rail_reads_its_warming_and_gives_up_without_one() {
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let serve = UdpSocket::bind("127.0.0.1:0").expect("a serve socket");
        let serve_at = serve.local_addr().expect("the serve address");
        serve
            .send_to(&encode(&Datagram::Registered { key: [1; 32] }), at)
            .expect("something that is not a warming");
        serve
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a warming");
        let mut buffer = [0_u8; 128];
        wait_warm(&rail, &mut buffer, serve_at, Duration::from_secs(10)).expect("a wait");
        rail.set_nonblocking(true).expect("a peek");
        assert!(
            rail.recv_from(&mut buffer).is_err(),
            "the warming was read, not left for the session's socket"
        );
        rail.set_nonblocking(false).expect("a bounded wait");
        wait_warm(&rail, &mut buffer, serve_at, Duration::from_millis(50))
            .expect("a warming that never comes is not a failure");
    }

    #[test]
    fn only_the_serve_ends_the_warming_floor() {
        // The floor is what the serve gets to open its side. Anyone else
        // ending it early hands the session a hole that is not open yet.
        use crate::rendezvous::{Datagram, encode};

        let rail = UdpSocket::bind("127.0.0.1:0").expect("a rail socket");
        let at = rail.local_addr().expect("the rail address");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("a stranger's socket");
        let stranger_at = stranger.local_addr().expect("the stranger's address");
        let elsewhere = "203.0.113.9:443".parse().expect("the serve's address");
        let floor = Duration::from_millis(250);

        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("a forged warming");
        let mut buffer = [0_u8; 128];
        let began = std::time::Instant::now();
        wait_warm(&rail, &mut buffer, elsewhere, floor).expect("a wait");
        assert!(
            began.elapsed() >= Duration::from_millis(200),
            "a warming from {stranger_at} ended a floor owed to {elsewhere}"
        );

        // The same datagram from the serve's own address does end it. A
        // different port there is the unpunchable case, not a stranger.
        stranger
            .send_to(&encode(&Datagram::Warming), at)
            .expect("the serve's warming");
        let began = std::time::Instant::now();
        let reported = SocketAddr::new(stranger_at.ip(), stranger_at.port().wrapping_add(1));
        wait_warm(&rail, &mut buffer, reported, Duration::from_secs(10)).expect("a wait");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the serve's own warming did not end the floor"
        );
    }

    #[test]
    fn a_root_nobody_registered_is_unresolved_rather_than_punched() {
        use crate::rendezvous::{Datagram, decode, encode};

        // A service that is up and answers, but holds no mapping for the key.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let at = socket.local_addr().expect("the service address");
        let service = std::thread::spawn(move || {
            let mut buffer = [0_u8; 128];
            let mut answered = 0_u32;
            while answered < RESOLVE_RETRIES {
                let (length, from) = socket.recv_from(&mut buffer).expect("a resolve");
                let Some(Datagram::Resolve { key }) = decode(&buffer[..length]) else {
                    continue;
                };
                let answer = Datagram::Resolved { key, serve: None };
                socket.send_to(&encode(&answer), from).expect("an answer");
                answered += 1;
            }
            answered
        });
        assert!(
            matches!(
                punch_within(
                    [6; 32],
                    at,
                    Duration::from_millis(1),
                    Duration::from_millis(1)
                ),
                Err(Error::RendezvousUnresolved)
            ),
            "a service that names no serve is not a path to punch"
        );
        assert_eq!(
            service.join().expect("the service thread"),
            RESOLVE_RETRIES,
            "the whole retry budget was spent before the root was called unresolved"
        );
    }

    #[test]
    fn only_a_read_without_a_datagram_is_waited_out() {
        use std::io::ErrorKind;
        // What a failed read is reported as, which is the whole decision.
        assert!(read_failure(&std::io::Error::from(ErrorKind::WouldBlock)).is_none());
        assert!(read_failure(&std::io::Error::from(ErrorKind::TimedOut)).is_none());
        assert!(matches!(
            read_failure(&std::io::Error::from(ErrorKind::ConnectionRefused)),
            Some(Error::CarrierUnavailable)
        ));
        assert!(matches!(
            read_failure(&std::io::Error::from(ErrorKind::BrokenPipe)),
            Some(Error::CarrierUnavailable)
        ));
        assert!(waited_out(&std::io::Error::from(ErrorKind::WouldBlock)));
        assert!(waited_out(&std::io::Error::from(ErrorKind::TimedOut)));
        assert!(!waited_out(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(!waited_out(&std::io::Error::from(ErrorKind::Other)));
    }

    #[test]
    fn the_width_is_the_value_given_or_the_machines_own() {
        assert_eq!(rails_from(None, 1).unwrap(), 2);
        assert_eq!(rails_from(None, 3).unwrap(), 6);
        assert_eq!(rails_from(None, 4).unwrap(), 8);
        assert_eq!(rails_from(None, 64).unwrap(), 8, "the default caps at 8");
        assert_eq!(rails_from(None, 0).unwrap(), 1, "no cores is still one");
        assert_eq!(
            rails_from(Some(" 2\n"), 1).unwrap(),
            2,
            "given, trimmed, taken"
        );
        assert_eq!(
            rails_from(Some("8"), 1).unwrap(),
            MAX_FETCH_RAILS,
            "the bound itself is allowed"
        );
        assert!(rails_from(Some("0"), 4).is_err());
        assert!(rails_from(Some("9"), 4).is_err());
        assert!(rails_from(Some("wide"), 4).is_err());
        assert!(std::env::var(FETCH_RAILS).is_err(), "the suite owns no env");
    }

    #[test]
    fn a_fetch_at_width_two_crosses_one_serve_socket() {
        let source = crate::tests::temporary("railwire-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("big.bin"), crate::harness::patterned(2_000_000)).unwrap();
        let bundle = crate::tests::temporary("railwire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving_bundle = bundle.to_path_buf();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &serving_bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(2),
                |at, _, _| {
                    let _ = listening.send(at);
                },
            )
        });

        let at = address.recv().expect("the server reported its address");
        let fetched = crate::tests::temporary("railwire-fetched");
        let into = fetched.to_path_buf();
        let root = built.root;
        let package = within("the striped fetch", 60, move || {
            fetch_railed(at, &into, Some(root), 2)
        })
        .expect("a striped fetch");
        assert_eq!(package, built);
        let served = joined("the serving thread", serving).expect("served");
        assert_eq!(served, built);
        // The leaves a send keeps beside an object are skipped: a cache a
        // serve rebuilds by reading the object, which a fetch does not write.
        let objects = |root: &Path| -> Vec<(std::ffi::OsString, Vec<u8>)> {
            let mut all: Vec<_> = std::fs::read_dir(root.join("objects"))
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .filter(|(name, _)| !name.to_string_lossy().ends_with(".leaves"))
                .collect();
            all.sort();
            all
        };
        assert_eq!(objects(&bundle), objects(&fetched));
        crate::harness::discard(&[&source, &bundle, &fetched]);
    }

    #[test]
    fn a_rail_is_handed_the_token_the_primary_holds() {
        use ed25519_dalek::SigningKey;

        // Every rail opens its own session and answers its own challenge, so
        // a primary that kept its token to itself would leave every rail
        // after the first refused.
        let holder = SigningKey::from_bytes(&[24; 32]);
        let token = crate::authz::issue(
            "you.example",
            "them.example",
            &SigningKey::from_bytes(&[25; 32]),
            holder.verifying_key().to_bytes(),
            [6; 32],
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let held = std::sync::Arc::new(
            crate::authz::Holder::new(token, holder).expect("a holder for that token"),
        );
        let output = crate::tests::temporary("rail-token");
        let fetcher = BundleFetcher::begin_with(
            crate::harness::Loopback::default(),
            &output,
            None,
            Some(std::sync::Arc::clone(&held)),
            std::collections::BTreeSet::new(),
        )
        .expect("a fetch holding a token");
        let handed = fetcher.holder().expect("the token, for a rail");
        assert!(
            std::sync::Arc::ptr_eq(&handed, &held),
            "a rail would have opened its session with no capability"
        );

        let without = BundleFetcher::begin_with(
            crate::harness::Loopback::default(),
            &output,
            None,
            None,
            std::collections::BTreeSet::new(),
        )
        .expect("a fetch holding none");
        assert!(without.holder().is_none(), "a token appeared from nowhere");
    }

    #[test]
    fn a_serve_requires_all_three_or_none_of_them() {
        use ed25519_dalek::SigningKey;

        let root = [4; 32];
        let key = SigningKey::from_bytes(&[21; 32]);
        let source = crate::tests::temporary("issuer-key");
        std::fs::write(
            &source,
            format!(
                "ed25519-public:{}",
                crate::hex_of(&key.verifying_key().to_bytes())
            ),
        )
        .expect("a key file");
        let named = source.to_string_lossy().into_owned();

        assert!(
            requirement_from(None, None, None, root)
                .expect("no requirement")
                .is_none(),
            "a serve given nothing required something"
        );
        assert!(
            requirement_from(
                Some(&named),
                Some("you.example"),
                Some("them.example"),
                root
            )
            .expect("a requirement")
            .is_some(),
            "a serve given all three required nothing"
        );
        assert!(
            push_requirement_from(None, None, None)
                .expect("no requirement")
                .is_none()
        );
        assert!(
            push_requirement_from(Some(&named), Some("you.example"), Some("them.example"))
                .expect("a push requirement")
                .is_some()
        );
        // Any partial configuration. A key with no audience would take a
        // token minted for another deployment, and an audience with no key
        // would refuse everyone, which reads as a bug rather than a policy.
        for partial in [
            (Some(named.as_str()), None, None),
            (None, Some("you.example"), None),
            (None, None, Some("them.example")),
            (Some(named.as_str()), Some("you.example"), None),
            (Some(named.as_str()), None, Some("them.example")),
            (None, Some("you.example"), Some("them.example")),
        ] {
            assert!(
                matches!(
                    requirement_from(partial.0, partial.1, partial.2, root),
                    Err(Error::InvalidArguments)
                ),
                "{partial:?} was not refused"
            );
            assert!(matches!(
                push_requirement_from(partial.0, partial.1, partial.2),
                Err(Error::InvalidArguments)
            ));
        }
        // A secret where the public half belongs would let a serve mint what
        // it checks.
        let secret = crate::tests::temporary("issuer-secret");
        std::fs::write(
            &secret,
            format!("ed25519-secret:{}", crate::hex_of(&key.to_bytes())),
        )
        .expect("a key file");
        assert!(matches!(
            requirement_from(
                Some(&secret.to_string_lossy()),
                Some("you.example"),
                Some("them.example"),
                root
            ),
            Err(Error::InvalidArguments)
        ));
        assert!(
            std::env::var(SERVE_ISSUER).is_err(),
            "the suite owns no env"
        );
        assert!(matches!(
            push::receive_push(
                "127.0.0.1:0".parse().unwrap(),
                Path::new("/vot-unused-push-output"),
                &Credentials::Ephemeral,
                Some(0),
                |_, _| {}
            ),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn a_fetch_presents_both_or_neither() {
        use ed25519_dalek::SigningKey;

        let issuer = SigningKey::from_bytes(&[22; 32]);
        let holder = SigningKey::from_bytes(&[23; 32]);
        let token = crate::authz::issue(
            "you.example",
            "them.example",
            &issuer,
            holder.verifying_key().to_bytes(),
            [4; 32],
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let token_path = crate::tests::temporary("holder-token");
        std::fs::write(&token_path, &token).expect("a token file");
        let named = token_path.to_string_lossy().into_owned();
        let key_path = crate::tests::temporary("holder-key");
        std::fs::write(
            &key_path,
            format!("ed25519-secret:{}", crate::hex_of(&holder.to_bytes())),
        )
        .expect("a key file");
        let key_named = key_path.to_string_lossy().into_owned();

        assert!(
            holder_from(None, None).expect("no holder").is_none(),
            "a fetch given nothing presented something"
        );
        assert!(
            holder_from(Some(&named), Some(&key_named))
                .expect("a holder")
                .is_some(),
            "a fetch given both presented nothing"
        );
        // A token with no key cannot be proved, and a key with no token
        // proves nothing.
        for partial in [
            (Some(named.as_str()), None),
            (None, Some(key_named.as_str())),
        ] {
            assert!(
                matches!(
                    holder_from(partial.0, partial.1),
                    Err(Error::InvalidArguments)
                ),
                "{partial:?} was not refused"
            );
        }
        // The public half cannot prove possession.
        let public_path = crate::tests::temporary("holder-public");
        std::fs::write(
            &public_path,
            format!(
                "ed25519-public:{}",
                crate::hex_of(&holder.verifying_key().to_bytes())
            ),
        )
        .expect("a key file");
        assert!(matches!(
            holder_from(Some(&named), Some(&public_path.to_string_lossy())),
            Err(Error::InvalidArguments)
        ));
        assert!(
            std::env::var(FETCH_CAPABILITY).is_err(),
            "the suite owns no env"
        );
    }

    #[test]
    fn the_congestion_controller_is_the_value_given_or_bbr2() {
        assert_eq!(congestion_from(None).unwrap(), CongestionControl::Bbr2);
        assert_eq!(
            congestion_from(Some("cubic")).unwrap(),
            CongestionControl::Cubic
        );
        assert_eq!(
            congestion_from(Some(" bbr2\n")).unwrap(),
            CongestionControl::Bbr2,
            "given, trimmed, taken"
        );
        assert!(congestion_from(Some("reno")).is_err());
        assert!(std::env::var(CONGESTION).is_err(), "the suite owns no env");
    }

    #[test]
    fn datagram_fec_defaults_to_automatic_and_keeps_explicit_controls() {
        let fec = std::collections::BTreeSet::from([
            vot_codec::extension_id::DATAGRAM_FEC,
            vot_codec::extension_id::FEC_COVER_EPOCHS,
        ]);
        assert_eq!(extensions_from(None).unwrap(), fec);
        for off in ["0", "off", "false", " OFF "] {
            assert!(extensions_from(Some(off)).unwrap().is_empty(), "{off}");
        }
        for on in ["1", "on", "true", " True\n", "auto"] {
            assert_eq!(extensions_from(Some(on)).unwrap(), fec, "{on}");
        }
        assert!(automatic_fec(Some(" AUTO\n")));
        assert!(automatic_fec(None));
        assert!(!automatic_fec(Some("on")));
        assert!(extensions_from(Some("maybe")).is_err());
        assert!(
            std::env::var(DATAGRAM_FEC).is_err(),
            "the suite owns no env"
        );
    }

    #[test]
    fn the_fetch_report_is_off_unless_asked_for() {
        assert!(!stats_wanted(None).unwrap());
        for off in ["0", "off", "false", " OFF "] {
            assert!(!stats_wanted(Some(off)).unwrap(), "{off}");
        }
        for on in ["1", "on", "true", " True\n"] {
            assert!(stats_wanted(Some(on)).unwrap(), "{on}");
        }
        assert!(stats_wanted(Some("maybe")).is_err());
        assert!(std::env::var(FETCH_STATS).is_err(), "the suite owns no env");
    }

    #[test]
    fn the_fetch_report_names_every_number_it_measured() {
        // Every field distinct, so a line that reads one count into another
        // field's place cannot pass.
        assert_eq!(
            fetch::stats_line(
                4_294_967_296,
                std::time::Duration::from_millis(8_500),
                Some(std::time::Duration::from_millis(321)),
                vot_scheduler::FecCounts {
                    offered: 65_536,
                    coded: 65_530,
                    decoded: 65_500,
                    abandoned: 36,
                    refused: 2,
                    symbols: 4_194_304,
                    symbol_drops: 17,
                },
            ),
            "fetch stats bytes=4294967296 ms=8500 first_ms=321 fec_offered=65536 \
             fec_coded=65530 fec_decoded=65500 fec_abandoned=36 fec_refused=2 \
             fec_symbols=4194304 fec_symbol_drops=17"
        );
        assert_eq!(
            fetch::stats_line(
                0,
                std::time::Duration::ZERO,
                None,
                vot_scheduler::FecCounts::default(),
            ),
            "fetch stats bytes=0 ms=0 first_ms=none fec_offered=0 fec_coded=0 fec_decoded=0 \
             fec_abandoned=0 fec_refused=0 fec_symbols=0 fec_symbol_drops=0"
        );
        // Sub-millisecond is reported as what it is rather than rounded up:
        // a run this short is not a measurement, and saying 1 would hide it.
        assert_eq!(
            fetch::stats_line(
                7,
                std::time::Duration::from_micros(900),
                Some(std::time::Duration::from_micros(800)),
                vot_scheduler::FecCounts::default(),
            ),
            "fetch stats bytes=7 ms=0 first_ms=0 fec_offered=0 fec_coded=0 fec_decoded=0 \
             fec_abandoned=0 fec_refused=0 fec_symbols=0 fec_symbol_drops=0"
        );
    }

    #[test]
    fn proof_workers_are_a_fetch_budget_not_a_per_rail_multiplier() {
        for (provers, rails, expected) in [
            (4, 0, 4),
            (4, 1, 4),
            (4, 2, 2),
            (4, 4, 1),
            (4, 8, 1),
            (5, 4, 1),
            (9, 8, 1),
            (17, 8, 2),
            (32, 8, 4),
            // No prover books no coverage, so the split floors at one
            // however small the ceiling an operator names.
            (0, 8, 1),
        ] {
            assert_eq!(
                fetch::provers_per_rail(provers, rails),
                expected,
                "{provers} workers across {rails} rails"
            );
        }
    }

    #[test]
    fn an_ephemeral_certificate_goes_when_the_server_does() {
        let (certificate, key, directory) = {
            let written = Ephemeral::generate().expect("credentials");
            assert!(written.certificate.is_file());
            assert!(written.key.is_file());
            (
                written.certificate.clone(),
                written.key.clone(),
                written.directory.clone(),
            )
        };
        assert!(!certificate.exists(), "the certificate was left behind");
        assert!(!key.exists(), "the key was left behind");
        assert!(!directory.exists(), "the directory was left behind");
    }

    #[test]
    fn a_bundle_crosses_a_quic_socket_and_publishes() {
        let source = crate::tests::temporary("wire-source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.txt"), vec![7_u8; 1000]).unwrap();
        std::fs::write(source.join("nested/b.bin"), vec![9_u8; 300_000]).unwrap();
        let bundle = crate::tests::temporary("wire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(1),
                |at, root, _| {
                    let _ = listening.send((at, root));
                },
            )
        });

        let (at, announced) = address.recv().expect("the server reported its address");
        // The address and the root together, because a fetch needs both and
        // a caller that has to go and find the second one fetches unpinned.
        assert_eq!(
            announced, built.root,
            "the serve announced a root that is not the bundle's"
        );
        let fetched = crate::tests::temporary("wire-fetched");
        let into = fetched.to_path_buf();
        let root = built.root;
        let package = within("the fetch", 60, move || {
            fetch_railed(at, &into, Some(root), 1)
        })
        .expect("a fetched bundle");
        assert_eq!(package, built);
        let served = joined("the serving thread", serving).expect("served");
        assert_eq!(served, built);

        let destination = crate::tests::temporary("wire-destination");
        let receipt = crate::tests::temporary("wire-receipt.cbor");
        // receive_bundle writes a JSON summary beside the receipt, which the
        // receipt's own guard does not know about.
        let _summary = crate::tests::guarded(receipt.with_extension("json"));
        let report = crate::receive_bundle(
            &fetched,
            &destination,
            &receipt,
            &crate::KeyMaterial::Shared(vec![7; 32]),
            "2026-08-06T00:00:00Z",
        )
        .unwrap();
        assert_eq!(report.package, built);
        assert_eq!(
            std::fs::read(destination.join("a.txt")).unwrap(),
            vec![7_u8; 1000]
        );
    }

    #[test]
    fn a_pinned_identity_admits_its_serve_and_refuses_another() {
        let source = crate::tests::temporary("identity-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a.bin"), vec![5_u8; 4096]).unwrap();
        let bundle = crate::tests::temporary("identity-bundle");
        crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(1),
                |at, _, identity| {
                    let _ = listening.send((at, identity));
                },
            )
        });
        let (at, identity) = address.recv().expect("the server reported its address");

        let config = client_config().unwrap();
        let carrier =
            Transport::connect(local_for(at).unwrap(), at, Some("localhost"), &config).unwrap();
        assert!(
            verify_serve_identity(&carrier, None).is_ok(),
            "no pin admits any serve"
        );
        assert!(
            verify_serve_identity(&carrier, Some(identity)).is_ok(),
            "the announced identity is the certificate the handshake presented"
        );
        let mut wrong = identity;
        wrong[0] ^= 1;
        assert!(
            matches!(
                verify_serve_identity(&carrier, Some(wrong)),
                Err(Error::ServeIdentityMismatch)
            ),
            "any other pin refuses the carrier"
        );
        drop(carrier);
        let _ = joined("the serving thread", serving);
    }

    #[test]
    fn a_second_connection_resumes_the_firsts_session() {
        let source = crate::tests::temporary("resume-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a.bin"), vec![9_u8; 4096]).unwrap();
        let bundle = crate::tests::temporary("resume-bundle");
        crate::build_bundle(&source, &bundle).unwrap();

        let (listening, address) = mpsc::channel();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(2),
                |at, _, identity| {
                    let _ = listening.send((at, identity));
                },
            )
        });
        let (at, identity) = address.recv().expect("the server reported its address");

        let config = client_config().unwrap();
        let first =
            Transport::connect(local_for(at).unwrap(), at, Some("localhost"), &config).unwrap();
        assert!(first.connected_within(std::time::Duration::from_secs(5)));
        assert!(!first.is_resumed(), "nothing to resume the first time");
        // The ticket follows the handshake; bounded by its own count.
        let mut ticket = None;
        for _ in 0..500 {
            ticket = first.session_ticket();
            if ticket.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ticket = ticket.expect("the serve issued a ticket");

        let mut resumed_config = client_config().unwrap();
        resumed_config.session = Some(ticket);
        let second = Transport::connect(
            local_for(at).unwrap(),
            at,
            Some("localhost"),
            &resumed_config,
        )
        .unwrap();
        assert!(second.connected_within(std::time::Duration::from_secs(5)));
        assert!(second.is_resumed(), "the ticket resumed the session");
        // The pin still has a certificate to check: the resumed handshake
        // sends none, and the stack answers with the session's saved one.
        assert!(
            verify_serve_identity(&second, Some(identity)).is_ok(),
            "the identity pin verifies on a resumed handshake"
        );
        drop(first);
        drop(second);
        let _ = joined("the serving thread", serving);
    }

    #[test]
    fn an_initial_window_is_bounded_packets() {
        assert_eq!(initial_cwnd_from(None).unwrap(), None);
        assert_eq!(initial_cwnd_from(Some("1024")).unwrap(), Some(1024));
        assert_eq!(initial_cwnd_from(Some(" 7100\n")).unwrap(), Some(7_100));
        assert!(initial_cwnd_from(Some("9")).is_err(), "below the default");
        assert!(
            initial_cwnd_from(Some("7101")).is_err(),
            "past what start-of-connection flow control admits"
        );
        assert!(initial_cwnd_from(Some("wide")).is_err());
    }

    #[test]
    fn a_prefix_duplication_budget_is_bounded_datagrams() {
        assert_eq!(prefix_dup_from(None).unwrap(), None, "unset is the default");
        assert_eq!(
            prefix_dup_from(Some("0")).unwrap(),
            Some(0),
            "zero sends each datagram once"
        );
        assert_eq!(prefix_dup_from(Some(" 200\n")).unwrap(), Some(200));
        assert_eq!(prefix_dup_from(Some("4096")).unwrap(), Some(4_096));
        assert!(
            prefix_dup_from(Some("4097")).is_err(),
            "past a prefix-sized answer"
        );
        assert!(prefix_dup_from(Some("twice")).is_err());
    }

    #[test]
    fn an_identity_pin_is_exactly_its_hex() {
        assert_eq!(identity_from(None).unwrap(), None);
        let hex = "7503bcc1b8fe0bfe100a9d32204f17133de6a6069db7ff27770f9589f142a988";
        assert_eq!(
            identity_from(Some(hex)).unwrap().unwrap()[0],
            0x75,
            "the pin is the digest the hex spells"
        );
        assert!(identity_from(Some(&hex[..63])).is_err());
        assert!(identity_from(Some("zz")).is_err());
    }

    #[test]
    fn the_identity_digest_is_the_certificates_der() {
        let ephemeral = Ephemeral::generate().unwrap();
        let pem = std::fs::read(&ephemeral.certificate).unwrap();
        let der = serve::der_from_pem(&pem).unwrap();
        assert_eq!(
            serve::identity_digest(&ephemeral.certificate).unwrap(),
            *blake3::hash(&der).as_bytes()
        );
        assert!(serve::der_from_pem(b"not a pem").is_err());
        assert!(
            serve::der_from_pem(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
                .is_err(),
            "an empty armor block is not a certificate"
        );
        // A combined PEM that leads with the key still hashes the
        // certificate, the way the TLS stack skips to it.
        let mut combined = std::fs::read(&ephemeral.key).unwrap();
        combined.extend_from_slice(&pem);
        assert_eq!(serve::der_from_pem(&combined).unwrap(), der);
    }

    #[test]
    fn a_bundle_crosses_a_quic_socket_over_the_datagram_path() {
        // Both ends offer DATAGRAM_FEC, so every group-aligned answer rides
        // as coded symbols and the fetch decodes them; the reliable path
        // carries only what credit or loss left. The counter proves the
        // symbols were what carried the bytes.
        let source = crate::tests::temporary("fec-wire-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), vec![0x3c_u8; 1_500_000]).unwrap();
        let bundle = crate::tests::temporary("fec-wire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();
        let fec = std::collections::BTreeSet::from([
            vot_codec::extension_id::DATAGRAM_FEC,
            vot_codec::extension_id::FEC_COVER_EPOCHS,
        ]);

        let (listening, address) = mpsc::channel();
        let serving_offer = fec.clone();
        let serving = std::thread::spawn(move || {
            serve_bundle_offering(
                &bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(1),
                &serving_offer,
                false,
                |at, root, _| {
                    let _ = listening.send((at, root));
                },
            )
        });
        let (at, _) = address.recv().expect("the server reported its address");
        let fetched = crate::tests::temporary("fec-wire-fetched");
        let config = client_config().unwrap();
        let connect = move || {
            Transport::connect(local_for(at).unwrap(), at, Some("localhost"), &config)
                .map_err(carrier_failure)
        };
        let into = fetched.to_path_buf();
        let root = built.root;
        let outcome = within("the fetch over the datagram path", 60, move || {
            fetch_over_offering(connect().unwrap(), connect, &into, Some(root), 1, fec)
        })
        .expect("a fetched bundle");
        assert_eq!(outcome.package, built);
        let served = joined("the serving thread", serving).expect("served");
        assert_eq!(served, built);
        // 1500000 bytes of object are 23 generations, every one of them
        // offered over the datagram path; the manifest and the small tail
        // travel reliably. Coverage and decode are asserted separately: coded
        // against offered is how much of the object the coded path carried,
        // and decoded against coded is how well it decoded what it carried.
        let counts = outcome.fec;
        assert_eq!(
            counts.offered, 23,
            "the epochs opened span every generation of the object"
        );
        assert_eq!(counts.refused, 0, "credit admitted every epoch");
        assert_eq!(
            counts.coded, counts.offered,
            "every offered generation was coded: {counts:?}"
        );
        assert_eq!(
            counts.decoded, counts.coded,
            "every coded generation decoded from its symbols: {counts:?}"
        );
        assert!(
            counts.decoded + counts.abandoned <= counts.offered,
            "the outcomes are disjoint subsets of what was offered: {counts:?}"
        );
    }

    #[test]
    fn a_rendezvous_fetch_punches_once_for_every_rail() {
        // One hole in a serve's NAT admits one mapping, so a rail that did not
        // announce its own socket has no path. Loopback cannot filter, so what
        // this asserts is that the service saw one distinct source per rail.
        const RAILS: usize = 2;
        /// Reads the service loop makes before giving up on the flag, so a
        /// fetch that never returns cannot leave the thread running.
        const SERVICE_READS: usize = 400;

        let source = crate::tests::temporary("rendezvous-wire-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), vec![0x5a; 200_000]).unwrap();
        let bundle = crate::tests::temporary("rendezvous-wire-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        // The real pairing policy, in a loop that also records who resolved.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        let service = socket.local_addr().expect("the service address");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let service_thread = std::thread::spawn(move || {
            let mut pairings = crate::rendezvous::Pairings::default();
            let began = std::time::Instant::now();
            let mut resolvers = Vec::new();
            let mut buffer = [0_u8; 128];
            for _ in 0..SERVICE_READS {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) else {
                    continue;
                };
                if matches!(datagram, crate::rendezvous::Datagram::Resolve { .. }) {
                    resolvers.push(from);
                }
                let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
                let answer = pairings.take(datagram, from, now_ms);
                if let Some(reply) = answer.reply {
                    let _ = socket.send_to(&crate::rendezvous::encode(&reply), from);
                }
                if let Some((mapping, notice)) = answer.notify {
                    let _ = socket.send_to(&crate::rendezvous::encode(&notice), mapping);
                }
            }
            resolvers
        });

        // Start a serve with rendezvous registration.
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        // The default accept bound stays: a fetch broken enough never to
        // connect must fail this test, not hang the suite on the join.
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let registration =
            Registration::begin(side, built.root, &[service]).expect("a registration");

        let opened = BundleServer::open(&bundle).unwrap();
        let serving = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(u32::try_from(RAILS).unwrap()), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(None)?)
            })
            .unwrap();
            opened.package()
        });

        // Fetch via rendezvous: resolve root -> connect -> transfer.
        let fetched = crate::tests::temporary("rendezvous-wire-fetched");
        let into = fetched.to_path_buf();
        let root = built.root;
        let package = within("the fetch via rendezvous", 60, move || {
            fetch_via_rendezvous_railed(root, &into, &[service], &[], RAILS)
        })
        .expect("a fetch via rendezvous");
        assert_eq!(package, built);

        drop(registration);
        let served = joined("the serving thread", serving);
        assert_eq!(served, built);
        stop.store(true, Ordering::Relaxed);
        let mut resolvers = service_thread.join().expect("the service thread");
        resolvers.sort_unstable();
        resolvers.dedup();
        assert_eq!(
            resolvers.len(),
            RAILS,
            "every rail announced its own socket at the service"
        );
        crate::harness::discard(&[&source, &bundle, &fetched]);
    }

    #[test]
    fn a_fetch_with_no_route_left_crosses_a_relay_slot() {
        // ADR-0034 step 3 on loopback: the fetch takes a slot, the
        // invitation travels through the service, the serve warms the slot
        // it was told about, and the whole session crosses the relay with
        // neither end accepting a packet it did not ask for. The rung is
        // entered by hand because a loopback punch would succeed and the
        // ladder would rightly never get here.
        const SERVICE_READS: usize = 400;
        // The relay's control budget covers the fetch's whole retry bound
        // plus the releases at the end: a retried Take under suite load is
        // answered with the held slot, but it still spends the budget, and
        // a budget of two once stopped the relay mid-transfer here.
        const CONTROL_DATAGRAMS: u64 = 8;

        let source = crate::tests::temporary("relay-rung-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), vec![0x3c; 200_000]).unwrap();
        let bundle = crate::tests::temporary("relay-rung-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        // The real pairing policy, forwarding invitations like everything else.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a service socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a bounded wait");
        let service = socket.local_addr().expect("the service address");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let service_thread = std::thread::spawn(move || {
            let mut pairings = crate::rendezvous::Pairings::default();
            let began = std::time::Instant::now();
            let mut buffer = [0_u8; 128];
            for _ in 0..SERVICE_READS {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                let Some(datagram) = crate::rendezvous::decode(&buffer[..length]) else {
                    continue;
                };
                let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
                let answer = pairings.take(datagram, from, now_ms);
                if let Some(reply) = answer.reply {
                    let _ = socket.send_to(&crate::rendezvous::encode(&reply), from);
                }
                if let Some((mapping, notice)) = answer.notify {
                    let _ = socket.send_to(&crate::rendezvous::encode(&notice), mapping);
                }
            }
        });

        let (listening, address) = mpsc::channel();
        let relaying = std::thread::spawn(move || {
            relay_service(
                "127.0.0.1:0".parse().unwrap(),
                Some(CONTROL_DATAGRAMS),
                |at| {
                    let _ = listening.send(at);
                },
            )
        });
        let relay = address.recv().expect("the relay reported its address");

        // A serve with rendezvous registration and nothing else: it learns
        // the slot only from the invitation.
        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.side_channel_lead = Some(crate::rendezvous::MAGIC);
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let side = listener.take_side_channel().expect("a side channel");
        let registration =
            Registration::begin(side, built.root, &[service]).expect("a registration");

        let opened = BundleServer::open(&bundle).unwrap();
        let serving = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(1), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(None)?)
            })
            .unwrap();
            opened.package()
        });

        let client = client_config().unwrap();
        let key = crate::rendezvous::key_of(&built.root);
        let carrier = relay_route(key, &[relay], &[service], &client)
            .expect("the rung ran")
            .expect("a relayed carrier");
        let fetched = crate::tests::temporary("relay-rung-fetched");
        let into = fetched.to_path_buf();
        let root = built.root;
        let package = within("the fetch through the slot", 60, move || {
            fetch_over(
                carrier,
                || Err(Error::RelayUnavailable),
                &into,
                Some(root),
                1,
            )
        })
        .expect("a fetch through the slot");
        assert_eq!(package, built);

        drop(registration);
        let served = joined("the serving thread", serving);
        assert_eq!(served, built);
        stop.store(true, Ordering::Relaxed);
        service_thread.join().expect("the service thread");
        // Whatever the fetch left of the budget, the releases spend: one
        // key, so the first opens a slot and the rest re-answer it.
        let release = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        for _ in 0..CONTROL_DATAGRAMS {
            let _ = release.send_to(
                &crate::relay::encode(&crate::relay::Datagram::Take { key: [1; 32] }),
                relay,
            );
        }
        relaying
            .join()
            .expect("the relay thread")
            .expect("a clean relay stop");
        crate::harness::discard(&[&source, &bundle, &fetched]);
    }

    #[test]
    fn a_serve_that_requires_a_capability_answers_only_a_holder() {
        // ADR-0037 end to end over a real QUIC socket: the same serve refuses
        // a fetch with no token and completes one whose possession proof binds
        // to the exporter both ends derive for this connection.
        use ed25519_dalek::SigningKey;

        let source = crate::tests::temporary("capability-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), crate::harness::patterned(200_000)).unwrap();
        let bundle = crate::tests::temporary("capability-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        let issuer_key = SigningKey::from_bytes(&[11; 32]);
        let holder_key = SigningKey::from_bytes(&[12; 32]);
        let requirement = crate::authz::Requirement::new(
            "issuer.example",
            crate::authz::key_id_of(&issuer_key.verifying_key()),
            issuer_key.verifying_key(),
            "receiver.example",
            built.root,
        );
        let token = crate::authz::issue(
            "issuer.example",
            "receiver.example",
            &issuer_key,
            holder_key.verifying_key().to_bytes(),
            built.root,
            crate::authz::now_seconds().expect("a clock"),
            3_600,
        )
        .expect("a token");
        let holder = Arc::new(
            crate::authz::Holder::new(token, holder_key).expect("a holder for that token"),
        );

        let written = Ephemeral::generate().expect("credentials");
        let mut config = Config::server(
            limits().unwrap(),
            written.certificate.to_str().expect("a path").to_owned(),
            written.key.to_str().expect("a path").to_owned(),
        );
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a bind");
        let at = listener.local_address();

        let opened = BundleServer::open(&bundle).unwrap();
        let refused_requirement = requirement.clone();
        let refusing = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(1), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(Some(&refused_requirement))?)
            })
        });

        // No token. `spec/wire.md` 1.1 says the format list lets a client
        // holding none of the accepted formats fail immediately rather than
        // after a rejected SESSION_OPEN, and this is that: the fetch stops on
        // the challenge instead of waiting out a session it cannot open.
        let refused_into = crate::tests::temporary("capability-refused");
        let client = client_config().expect("a client config");
        let carrier = Transport::connect(
            local_for(at).expect("a local address"),
            at,
            Some("localhost"),
            &client,
        )
        .expect("a carrier");
        let mut naked = BundleFetcher::begin(carrier, &refused_into, Some(built.root))
            .expect("a fetch with no token");
        within("the fetch with no token", 60, move || {
            let refusal = crate::drive::drive(&mut naked).expect("a driven fetch");
            assert_eq!(
                refusal,
                crate::FetchStatus::Closed(vot_codec::error_code::AUTHENTICATION_FAILED),
                "a fetch with no capability was served, or refused for another reason"
            );
            assert!(naked.package().is_none(), "a bundle was written anyway");
        });
        // The peer left mid-negotiation, which a bounded serve surfaces. An
        // unbounded one outlives it, which is what a real serve is.
        assert!(
            joined("the refusing thread", refusing).is_err(),
            "a session whose peer never presented was reported as served"
        );

        // The same bundle and the same requirement, with the token it asked
        // for.
        let opened = BundleServer::open(&bundle).unwrap();
        let listener =
            Listener::bind("127.0.0.1:0".parse().unwrap(), &config).expect("a second bind");
        let at = listener.local_address();
        let granting = std::thread::spawn(move || {
            crate::drive::serve_sessions(Some(1), || {
                let carrier = listener.accept().map_err(carrier_failure)?;
                ServeSession::begin(&opened, carrier, serve_stance(Some(&requirement))?)
            })
        });
        let fetched = crate::tests::temporary("capability-fetched");
        let carrier = Transport::connect(
            local_for(at).expect("a local address"),
            at,
            Some("localhost"),
            &client,
        )
        .expect("a carrier");
        let mut holding = BundleFetcher::begin_with(
            carrier,
            &fetched,
            Some(built.root),
            Some(holder),
            std::collections::BTreeSet::new(),
        )
        .expect("a fetch holding the token");
        let package = within("the fetch holding the token", 60, move || {
            let status = crate::drive::drive(&mut holding).expect("a driven fetch");
            assert_eq!(
                status,
                crate::FetchStatus::Complete,
                "the holder was refused"
            );
            holding.package().expect("a package")
        });
        assert_eq!(package, built);
        joined("the granting thread", granting).expect("served");

        crate::harness::discard(&[&source, &bundle, &refused_into, &fetched]);
    }

    #[test]
    fn a_push_crosses_a_retrying_live_listener() {
        use ed25519_dalek::SigningKey;

        let source = crate::tests::temporary("push-live-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("data.bin"),
            crate::harness::patterned(8_500_000),
        )
        .unwrap();
        let bundle = crate::tests::temporary("push-live-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();
        let opened = BundleServer::open(&bundle).unwrap();
        let descriptor = match crate::harness::decode_control(&opened.announcement[0]) {
            vot_codec::frames::TypedFrame::PackageDescriptor(descriptor) => descriptor.package,
            _ => panic!("the descriptor"),
        };
        let issuer = SigningKey::from_bytes(&[51; 32]);
        let holder_key = SigningKey::from_bytes(&[52; 32]);
        let requirement = crate::authz::PushRequirement::new(
            "issuer.example",
            crate::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            "receiver.example",
        );
        let token = crate::authz::issue_push(
            "issuer.example",
            "receiver.example",
            &issuer,
            holder_key.verifying_key().to_bytes(),
            built.root,
            descriptor.length,
            crate::authz::now_seconds().unwrap(),
            3_600,
        )
        .unwrap();
        let token_path = crate::tests::temporary("push-live-token.cbor");
        std::fs::write(&token_path, token).unwrap();
        let holder_path = crate::tests::temporary("push-live-holder.key");
        std::fs::write(
            &holder_path,
            format!("ed25519-secret:{}", crate::hex_of(&holder_key.to_bytes())),
        )
        .unwrap();

        // Every push below rides a bounded wait: a receiver that never
        // finishes fails the test instead of hanging it.
        let pushing = |bundle: &Path, token: &Path, at, identity, rails| {
            let bundle = bundle.to_path_buf();
            let token = token.to_path_buf();
            let holder = holder_path.to_str().expect("a path").to_owned();
            within("the push", 60, move || {
                push::push_bundle_railed(&bundle, at, &token, &holder, identity, rails)
            })
        };

        let credentials = Ephemeral::generate().unwrap();
        let identity = identity_digest(&credentials.certificate).unwrap();
        let mut config = Config::server(
            limits().unwrap(),
            credentials.certificate.to_str().unwrap().to_owned(),
            credentials.key.to_str().unwrap().to_owned(),
        );
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        config.stateless_retry = true;
        {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(1), |_| {
                    panic!("identity mismatch reached SESSION_OPEN")
                })
            });
            let mut wrong = identity;
            wrong[0] ^= 1;
            assert!(matches!(
                pushing(&bundle, &token_path, at, wrong, 1),
                Err(Error::ServeIdentityMismatch)
            ));
            assert!(joined("the receiving thread", receiving).is_err());
        }
        {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let refused_output = crate::tests::temporary("push-live-refused");
            let refused_path = refused_output.to_path_buf();
            let policy_output = refused_path.clone();
            let wrong_issuer = SigningKey::from_bytes(&[53; 32]);
            let refusal = crate::authz::PushRequirement::new(
                "issuer.example",
                crate::authz::key_id_of(&wrong_issuer.verifying_key()),
                wrong_issuer.verifying_key(),
                "receiver.example",
            );
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(1), |presentation| {
                    refusal
                        .decide(
                            presentation.challenge,
                            presentation.open,
                            presentation.channel_binding,
                            presentation.now,
                        )
                        .map(|scope| push::PushAdmission {
                            scope,
                            directory: policy_output.clone(),
                            seams: crate::ReceiveSeams::default(),
                        })
                })
            });
            let refused = pushing(&bundle, &token_path, at, identity, 1).unwrap_err();
            assert!(
                matches!(
                    &refused,
                    Error::PeerClosed(vot_codec::error_code::AUTHORIZATION_FAILED)
                ),
                "wrong refusal: {refused:?}"
            );
            assert!(joined("the receiving thread", receiving).is_err());
            assert!(
                !refused_path.exists(),
                "a refused push accepted a descriptor"
            );
        }
        {
            let null_scope = vot_capability::Capability {
                issuer: "issuer.example".to_owned(),
                audience: "receiver.example".to_owned(),
                holder_key: holder_key.verifying_key().to_bytes(),
                operations: vec![vot_capability::Operation::Publish.identifier()],
                scope: crate::authz::package_scope(built.root),
                limits: Vec::new(),
                not_before: crate::authz::now_seconds().unwrap(),
                expiry: crate::authz::now_seconds().unwrap() + 3_600,
                token_id: [54; 16],
                delegation: vot_capability::NO_FURTHER_DELEGATION,
            };
            let signed = vot_capability::sign(
                &null_scope,
                &crate::authz::key_id_of(&issuer.verifying_key()),
                &issuer,
            )
            .unwrap();
            let null_token = crate::tests::temporary("push-live-null-length.cbor");
            std::fs::write(&null_token, vot_capability::encode(&signed).unwrap()).unwrap();
            let output = crate::tests::temporary("push-live-null-length-output");
            let receiver_output = output.to_path_buf();
            let requirement = requirement.clone();
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(1), |presentation| {
                    requirement
                        .decide(
                            presentation.challenge,
                            presentation.open,
                            presentation.channel_binding,
                            presentation.now,
                        )
                        .map(|scope| push::PushAdmission {
                            scope,
                            directory: receiver_output.clone(),
                            seams: crate::ReceiveSeams::default(),
                        })
                })
            });
            let refused = pushing(&bundle, &null_token, at, identity, 1).unwrap_err();
            assert!(
                matches!(
                    &refused,
                    Error::PeerClosed(vot_codec::error_code::AUTHORIZATION_FAILED)
                ),
                "wrong refusal: {refused:?}"
            );
            assert!(joined("the receiving thread", receiving).is_err());
            assert!(
                !output.exists(),
                "a null-length scope accepted a descriptor"
            );
            crate::harness::discard(&[&null_token]);
        }
        {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let output = crate::tests::temporary("push-live-hook-failure");
            let receiver_output = output.to_path_buf();
            let requirement = requirement.clone();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(1), |presentation| {
                    requirement
                        .decide(
                            presentation.challenge,
                            presentation.open,
                            presentation.channel_binding,
                            presentation.now,
                        )
                        .map(|scope| push::PushAdmission {
                            scope,
                            directory: receiver_output.clone(),
                            seams: crate::ReceiveSeams {
                                complete: Some(std::sync::Arc::new(|_, _| {
                                    Err(Error::InvalidArguments)
                                })),
                                ..crate::ReceiveSeams::default()
                            },
                        })
                })
            });
            let pushed = pushing(&bundle, &token_path, at, identity, 1);
            assert!(pushed.is_err(), "a failed receiver acknowledged the push");
            assert!(joined("the receiving thread", receiving).is_err());
            crate::harness::discard(&[&output]);
        }
        {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let output = crate::tests::temporary("push-live-policy-deadline");
            let receiver_output = output.to_path_buf();
            let requirement = requirement.clone();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded_with_timeout(
                    &listener,
                    Some(1),
                    Duration::from_millis(10),
                    |presentation| {
                        std::thread::sleep(Duration::from_millis(50));
                        requirement
                            .decide(
                                presentation.challenge,
                                presentation.open,
                                presentation.channel_binding,
                                presentation.now,
                            )
                            .map(|scope| push::PushAdmission {
                                scope,
                                directory: receiver_output.clone(),
                                seams: crate::ReceiveSeams::default(),
                            })
                    },
                )
            });
            let pushed = pushing(&bundle, &token_path, at, identity, 1);
            assert!(pushed.is_err(), "a late admission was granted");
            assert!(joined("the receiving thread", receiving).is_err());
            assert!(!output.exists(), "a late admission accepted a descriptor");
        }
        for rails in [1, 4] {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let output = crate::tests::temporary(&format!("push-live-output-{rails}"));
            let receiver_output = output.to_path_buf();
            let requirement = requirement.clone();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(rails), |presentation| {
                    assert!(presentation.peer.ip().is_loopback());
                    requirement
                        .decide(
                            presentation.challenge,
                            presentation.open,
                            presentation.channel_binding,
                            presentation.now,
                        )
                        .map(|scope| push::PushAdmission {
                            scope,
                            directory: receiver_output.clone(),
                            seams: crate::ReceiveSeams::default(),
                        })
                })
            });

            let pushed = pushing(&bundle, &token_path, at, identity, rails as usize);
            let received = joined("the receiving thread", receiving);
            assert!(received.is_ok(), "receiver {received:?}; holder {pushed:?}");
            assert_eq!(pushed.unwrap(), built);
            crate::fetch::tests::assert_same_tree(&bundle, &output);
            let destination = crate::tests::temporary(&format!("push-live-destination-{rails}"));
            let receipt = crate::tests::temporary(&format!("push-live-receipt-{rails}.cbor"));
            let _summary = crate::tests::guarded(receipt.with_extension("json"));
            let published = crate::receive_bundle(
                &output,
                &destination,
                &receipt,
                &crate::KeyMaterial::Shared(vec![7; 32]),
                "2026-08-27T00:00:00Z",
            )
            .unwrap();
            assert_eq!(published.package, built);
            crate::fetch::tests::assert_same_tree(&source, &destination);
            crate::harness::discard(&[&output, &destination, &receipt]);
        }
        {
            let empty_source = crate::tests::temporary("push-live-empty-source");
            std::fs::create_dir_all(&empty_source).unwrap();
            std::fs::write(empty_source.join("empty.bin"), []).unwrap();
            let empty_bundle = crate::tests::temporary("push-live-empty-bundle");
            let empty = crate::build_bundle(&empty_source, &empty_bundle).unwrap();
            let empty_token = crate::tests::temporary("push-live-empty-token.cbor");
            std::fs::write(
                &empty_token,
                crate::authz::issue_push(
                    "issuer.example",
                    "receiver.example",
                    &issuer,
                    holder_key.verifying_key().to_bytes(),
                    empty.root,
                    empty.logical_length,
                    crate::authz::now_seconds().unwrap(),
                    3_600,
                )
                .unwrap(),
            )
            .unwrap();
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let output = crate::tests::temporary("push-live-empty-output");
            let receiver_output = output.to_path_buf();
            let requirement = requirement.clone();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded(&listener, Some(4), |presentation| {
                    requirement
                        .decide(
                            presentation.challenge,
                            presentation.open,
                            presentation.channel_binding,
                            presentation.now,
                        )
                        .map(|scope| push::PushAdmission {
                            scope,
                            directory: receiver_output.clone(),
                            seams: crate::ReceiveSeams::default(),
                        })
                })
            });
            let pushed = pushing(&empty_bundle, &empty_token, at, identity, 4);
            let received = joined("the receiving thread", receiving);
            assert!(received.is_ok(), "receiver {received:?}; holder {pushed:?}");
            assert_eq!(pushed.unwrap(), empty);
            crate::fetch::tests::assert_same_tree(&empty_bundle, &output);
            crate::harness::discard(&[&empty_source, &empty_bundle, &empty_token, &output]);
        }
        {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
            let at = listener.local_address();
            let output = crate::tests::temporary("push-live-auth-deadline");
            crate::harness::discard(&[&output]);
            let receiver_output = output.to_path_buf();
            let holding_output = crate::tests::temporary("push-live-auth-holding");
            crate::harness::discard(&[&holding_output]);
            let policy_holding_output = holding_output.to_path_buf();
            let holding_now = crate::authz::now_seconds().unwrap().saturating_sub(1);
            let holding_token = crate::authz::issue_push(
                "issuer.example",
                "receiver.example",
                &issuer,
                holder_key.verifying_key().to_bytes(),
                built.root,
                descriptor.length,
                holding_now,
                3_601,
            )
            .unwrap();
            let holding_token_path = crate::tests::temporary("push-live-holding-token.cbor");
            std::fs::write(&holding_token_path, &holding_token).unwrap();
            let first_admission = std::sync::atomic::AtomicBool::new(true);
            let requirement = requirement.clone();
            let receiving = std::thread::spawn(move || {
                push::receive_push_on_bounded_with_timeout(
                    &listener,
                    Some(9),
                    Duration::from_secs(3),
                    |presentation| {
                        requirement
                            .decide(
                                presentation.challenge,
                                presentation.open,
                                presentation.channel_binding,
                                presentation.now,
                            )
                            .map(|scope| push::PushAdmission {
                                scope,
                                directory: if first_admission
                                    .swap(false, std::sync::atomic::Ordering::AcqRel)
                                {
                                    policy_holding_output.clone()
                                } else {
                                    receiver_output.clone()
                                },
                                seams: crate::ReceiveSeams::default(),
                            })
                    },
                )
            });
            let mut client = fetch::client_config().unwrap();
            apply_datagram_bytes(&mut client).unwrap();
            let carrier =
                Transport::connect(local_for(at).unwrap(), at, Some("localhost"), &client).unwrap();
            let mut extensions = extensions_from(None).unwrap();
            extensions.insert(vot_codec::extension_id::PUSH);
            let session = vot_session::Session::client(
                carrier,
                vot_codec::Settings::default(),
                extensions,
                vot_session::Authentication::Presenting,
            );
            let holding_holder =
                crate::load_capability_holder(&holding_token_path, holder_path.to_str().unwrap())
                    .unwrap();
            let mut holding =
                crate::ServeSession::begin_push_session(&opened, session, holding_holder).unwrap();
            assert!(!holding.push_ready());
            holding.negotiate_push().unwrap();
            assert!(holding.push_ready());
            let (ready, started) = mpsc::channel();
            let attackers: Vec<_> = (1..crate::drive::CONCURRENT_SESSIONS)
                .map(|_| {
                    let ready = ready.clone();
                    std::thread::spawn(move || {
                        let mut client = fetch::client_config().unwrap();
                        apply_datagram_bytes(&mut client).unwrap();
                        let carrier = Transport::connect(
                            local_for(at).unwrap(),
                            at,
                            Some("localhost"),
                            &client,
                        )
                        .unwrap();
                        let mut extensions = extensions_from(None).unwrap();
                        extensions.insert(vot_codec::extension_id::PUSH);
                        let mut session = vot_session::Session::client(
                            carrier,
                            vot_codec::Settings::default(),
                            extensions,
                            vot_session::Authentication::Presenting,
                        );
                        session.require_extension(vot_codec::extension_id::PUSH);
                        session.begin().unwrap();
                        while session.pending_presentation().is_none() {
                            let _ = session.poll().unwrap();
                            session.flush().unwrap();
                            vot_transport_api::TransportAdapter::wait_for_event(
                                session.driver(),
                                Duration::from_millis(10),
                            );
                        }
                        let mut ping = Vec::new();
                        vot_codec::encode_frame(vot_codec::frame_type::PING, &[], &mut ping)
                            .unwrap();
                        let until = std::time::Instant::now() + Duration::from_secs(5);
                        let mut ready = Some(ready);
                        let mut sent = 0;
                        while std::time::Instant::now() < until {
                            if vot_transport_api::TransportAdapter::send_control(
                                session.driver(),
                                &ping,
                            )
                            .is_ok()
                                && vot_transport_api::TransportAdapter::flush(session.driver())
                                    .is_ok()
                            {
                                sent += 1;
                                if let Some(ready) = ready.take() {
                                    ready.send(()).unwrap();
                                }
                            }
                            vot_transport_api::TransportAdapter::wait_for_event(
                                session.driver(),
                                Duration::from_millis(20),
                            );
                            if session.poll().is_err() {
                                break;
                            }
                        }
                        sent
                    })
                })
                .collect();
            drop(ready);
            for _ in 1..crate::drive::CONCURRENT_SESSIONS {
                started.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            let pushed = pushing(&bundle, &token_path, at, identity, 1);
            for attacker in attackers {
                assert!(attacker.join().unwrap() > 1, "the attacker sent no drip");
            }
            assert!(
                pushed.is_ok(),
                "finished later slots behind an active first starved {pushed:?}"
            );
            drop(holding);
            assert!(joined("the receiving thread", receiving).is_err());
            crate::harness::discard(&[&output, &holding_output, &holding_token_path]);
        }
        crate::harness::discard(&[&source, &bundle, &token_path, &holder_path]);
    }

    #[test]
    fn a_push_portal_refuses_a_listener_without_stateless_retry() {
        let credentials = Ephemeral::generate().unwrap();
        let config = Config::server(
            limits().unwrap(),
            credentials.certificate.to_str().unwrap().to_owned(),
            credentials.key.to_str().unwrap().to_owned(),
        );
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
        let result = push::receive_push_on(&listener, |_| None);
        assert!(matches!(result, Err(Error::InvalidArguments)));

        let (protected, identity) =
            push::bind_push_listener("127.0.0.1:0".parse().unwrap(), &Credentials::Ephemeral)
                .unwrap();
        assert!(protected.stateless_retry_enabled());
        assert_ne!(identity, [0; 32]);
        let at = protected.local_address();
        let connecting = std::thread::spawn(move || {
            let client = fetch::client_config().unwrap();
            Transport::connect(local_for(at).unwrap(), at, Some("localhost"), &client)
        });
        let accepted = protected.accept();
        assert!(accepted.is_ok(), "the ephemeral listener router died");
        assert!(connecting.join().unwrap().is_ok());
    }

    #[test]
    fn push_rail_count_uses_the_whole_supported_range() {
        let missing = Path::new("/vot-missing-push-bundle");
        let address = "127.0.0.1:1".parse().unwrap();
        for rails in [0, crate::drive::CONCURRENT_SESSIONS + 1] {
            assert!(matches!(
                push::push_bundle_railed(missing, address, missing, "-", [0; 32], rails),
                Err(Error::InvalidArguments)
            ));
        }
        assert!(!matches!(
            push::push_bundle_railed(
                missing,
                address,
                missing,
                "-",
                [0; 32],
                crate::drive::CONCURRENT_SESSIONS
            ),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn a_push_rejects_zero_transfer_objects_before_dial() {
        let bundle = crate::tests::temporary("push-empty-canonical");
        let manifest = bundle.join(crate::MANIFEST_DIRECTORY);
        std::fs::create_dir_all(&manifest).unwrap();
        let package = vot_package::PackageRootBuilder::new()
            .unwrap()
            .finish()
            .unwrap();
        let mut manifest_id = [0; 16];
        manifest_id.copy_from_slice(&package.root[..16]);
        let page = vot_manifest::ManifestPage {
            manifest_id,
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: vot_manifest::PathProfile::Portable,
            entries: Vec::new(),
        };
        let page = vot_manifest::encode_page(&page).unwrap();
        let page_digest = *blake3::hash(&page).as_bytes();
        let seal = vot_manifest::Seal {
            manifest_id,
            final_page_count: 1,
            final_page_digest: page_digest,
            package: vot_manifest::ObjectId {
                suite: 1,
                root: package.root,
                length: 0,
            },
            pages: vec![vot_manifest::PageCommitment {
                index: 0,
                digest: page_digest,
            }],
        };
        std::fs::write(crate::manifest_page_path(&manifest, 0), page).unwrap();
        std::fs::write(
            manifest.join(crate::MANIFEST_SEAL),
            vot_manifest::encode_seal(&seal).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            crate::scan_manifest(&bundle),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            push::push_bundle_railed(
                &bundle,
                "127.0.0.1:9".parse().unwrap(),
                Path::new("unused-capability"),
                "unused-key",
                [0; 32],
                1,
            ),
            Err(Error::InvalidBundle)
        ));

        crate::harness::discard(&[&bundle]);
    }

    #[test]
    fn a_relay_slot_carries_bytes_between_two_ends_and_nobody_else() {
        // ADR-0034 step 2 on loopback: take a slot, pair on it, and see the
        // bytes cross unchanged in both directions while a third address
        // gets nothing.
        use crate::relay::{Datagram, decode, encode};

        let (listening, address) = mpsc::channel();
        // Two answers: the take below, and one more at the end that releases
        // the relay once the assertions are done. A relay that stopped after
        // the first would close the slot before anything crossed it, which is
        // what stopping means.
        let relaying = std::thread::spawn(move || {
            relay_service("127.0.0.1:0".parse().unwrap(), Some(2), |at| {
                let _ = listening.send(at);
            })
        });
        let at = address.recv().expect("the relay reported its address");

        let taker = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        taker
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let key = [0x5a; 32];
        taker
            .send_to(&encode(&Datagram::Take { key }), at)
            .expect("a take");
        let mut buffer = [0_u8; 128];
        let (length, from) = taker.recv_from(&mut buffer).expect("an answer");
        assert_eq!(from, at, "the answer came from somewhere else");
        let Some(Datagram::Slot {
            key: answered,
            at: Some(slot),
        }) = decode(&buffer[..length])
        else {
            panic!("the relay gave no slot: {:?}", decode(&buffer[..length]));
        };
        assert_eq!(answered, key, "the answer named another key");
        assert_ne!(slot, at, "the slot is its own port, not the control one");

        // Two ends and a stranger, each with a bounded wait.
        let ends: Vec<UdpSocket> = (0..3)
            .map(|_| {
                let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
                socket
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("a bounded wait");
                socket
            })
            .collect();
        // The first arrival pairs nothing: there is nobody to send it to.
        ends[0].send_to(b"first", slot).expect("the first end");
        // The second pairs, and its bytes go to the first.
        ends[1].send_to(b"second", slot).expect("the second end");
        let mut carried = [0_u8; 64];
        let (length, from) = ends[0].recv_from(&mut carried).expect("the pairing");
        assert_eq!(&carried[..length], b"second", "the bytes changed");
        assert_eq!(from, slot, "not from the slot");

        // And back the other way, unchanged.
        ends[0]
            .send_to(b"reply", slot)
            .expect("the first end again");
        let (length, _) = ends[1].recv_from(&mut carried).expect("the reply");
        assert_eq!(&carried[..length], b"reply");

        // A third address is not part of this slot.
        ends[2].send_to(b"stranger", slot).expect("a stranger");
        assert!(
            ends[0].recv_from(&mut carried).is_err() && ends[1].recv_from(&mut carried).is_err(),
            "a third address was forwarded to an end of the slot"
        );

        // Release the relay, which stops its slots with it.
        taker
            .send_to(&encode(&Datagram::Take { key }), at)
            .expect("the releasing take");
        let _ = taker.recv_from(&mut buffer);
        relaying
            .join()
            .expect("the relay thread")
            .expect("a relay that answered its bound");
    }

    #[test]
    fn a_relay_refuses_past_its_bound_and_repeats_the_slot_it_gave() {
        use crate::relay::{Datagram, decode, encode};

        let (listening, address) = mpsc::channel();
        // Three control turns: two distinct keys and one repeat.
        let relaying = std::thread::spawn(move || {
            relay_service("127.0.0.1:0".parse().unwrap(), Some(3), |at| {
                let _ = listening.send(at);
            })
        });
        let at = address.recv().expect("the relay reported its address");
        let taker = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        taker
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a bounded wait");
        let mut buffer = [0_u8; 128];
        let mut ask = |key: [u8; 32]| -> Option<SocketAddr> {
            taker
                .send_to(&encode(&Datagram::Take { key }), at)
                .expect("a take");
            let (length, _) = taker.recv_from(&mut buffer).expect("an answer");
            match decode(&buffer[..length]) {
                Some(Datagram::Slot { at, .. }) => at,
                other => panic!("not a slot answer: {other:?}"),
            }
        };
        let first = ask([1; 32]).expect("a slot");
        assert_eq!(ask([1; 32]), Some(first), "the same key got a second port");
        assert!(ask([2; 32]).is_some(), "a second key was refused early");
        relaying
            .join()
            .expect("the relay thread")
            .expect("a relay that answered its bound");
    }

    #[test]
    fn a_slot_that_heard_nothing_ends_only_when_it_should() {
        use std::io::{Error, ErrorKind};

        // A socket that failed is over whatever the clock says.
        let broken = Error::from(ErrorKind::ConnectionReset);
        assert_eq!(idle_after(&broken, false), Idle::Ended);
        assert_eq!(idle_after(&broken, true), Idle::Ended);
        // A read that waited out is not a failure: the slot keeps its port
        // until its own window closes.
        for waited in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
            let error = Error::from(waited);
            assert_eq!(
                idle_after(&error, false),
                Idle::Waiting,
                "{waited:?} ended a slot that was still open"
            );
            assert_eq!(idle_after(&error, true), Idle::Expired);
        }
    }

    #[test]
    fn a_closing_slot_says_what_it_carried() {
        let mut meter = crate::relay::Meter::new(u64::MAX, u64::MAX);
        assert_eq!(closing_line(&meter), "slot closed after 0 bytes");
        let first = "198.51.100.7:9000".parse().expect("an address");
        let second = "203.0.113.9:60123".parse().expect("an address");
        meter.take(first, 40, 0);
        meter.take(second, 60, 0);
        assert_eq!(
            closing_line(&meter),
            "slot closed after 60 bytes",
            "the number an operator reads is not what the slot forwarded"
        );
    }

    #[test]
    fn the_clock_a_slot_reads_is_the_clock() {
        // A reading stuck at zero would make every slot immortal: nothing
        // ever reaches its deadline.
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(5))
            .expect("a clock with five seconds behind it");
        let seen = elapsed_ms(past);
        assert!(
            (5_000..60_000).contains(&seen),
            "{seen}ms is not five seconds ago"
        );
        assert!(elapsed_ms(std::time::Instant::now()) < 5_000);
    }

    #[test]
    fn the_relay_bounds_are_the_numbers_given_or_the_defaults() {
        let default = crate::relay::Limits::default();
        assert_eq!(relay_limits_from(None, None, None).unwrap(), default);
        assert_eq!(
            relay_limits_from(Some(" 2\n"), Some("500"), Some("1024")).unwrap(),
            crate::relay::Limits {
                concurrent: 2,
                ttl_ms: 500,
                bytes: 1024
            },
            "given, trimmed, taken"
        );
        // Zero is not a bound anyone meant: a relay with no slots, or one
        // that closes them the instant they open.
        for zero in [
            relay_limits_from(Some("0"), None, None),
            relay_limits_from(None, Some("0"), None),
            relay_limits_from(None, None, Some("0")),
        ] {
            assert!(matches!(zero, Err(Error::InvalidArguments)));
        }
        assert!(relay_limits_from(Some("many"), None, None).is_err());
        assert!(std::env::var(RELAY_SLOTS).is_err(), "the suite owns no env");
    }

    #[test]
    fn a_probe_confirms_the_serve_identity_within_its_budget() {
        let credentials = Ephemeral::generate().unwrap();
        let identity = identity_digest(&credentials.certificate).unwrap();
        let mut config = Config::server(
            limits().unwrap(),
            credentials.certificate.to_str().unwrap().to_owned(),
            credentials.key.to_str().unwrap().to_owned(),
        );
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        config.stateless_retry = true;
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
        let at = listener.local_address();
        // Two connections that carry no session: the accept loop takes
        // them and lets them go, as a serve does with a peer that vanishes.
        let accepting = std::thread::spawn(move || {
            push::accept_sessions(&listener, Some(2), |carrier| {
                let _ = carrier.connected_within(std::time::Duration::from_secs(5));
                Ok(())
            })
        });
        // The carrier's idle timeout is the budget, so each probe and its
        // drop finish within a small multiple of it, not the fetch idle
        // timeout; a regression to the longer one trips these bounds.
        let budget = std::time::Duration::from_secs(3);
        let started = std::time::Instant::now();
        within("a probe of the right identity", 20, move || {
            probe_serve(at, identity, budget)
        })
        .expect("a probe");
        within("a probe of a wrong identity", 20, move || {
            assert!(matches!(
                probe_serve(at, [0; 32], budget),
                Err(Error::ServeIdentityMismatch)
            ));
        });
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "two budget-bounded probes took {:?}",
            started.elapsed()
        );
        joined("the accepting thread", accepting).expect("accepted");

        // A port that answers nothing spends the budget and no more.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = silent.local_addr().unwrap();
        let budget = std::time::Duration::from_millis(500);
        let started = std::time::Instant::now();
        assert!(matches!(
            within("a probe of a silent port", 30, move || probe_serve(
                at, identity, budget
            )),
            Err(Error::CarrierUnavailable)
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the probe outlived its budget: {:?}",
            started.elapsed()
        );
        drop(silent);
    }

    #[test]
    #[cfg(unix)]
    fn a_push_from_an_assembled_manifest_reports_what_the_carriers_took() {
        use ed25519_dalek::SigningKey;

        // Nothing under the manifest root but the manifest: the push serves
        // the source files where they sit.
        let source = crate::tests::temporary("push-from-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("big.bin"), crate::harness::patterned(3_000_000)).unwrap();
        std::fs::write(source.join("note.txt"), b"a note beside the plate").unwrap();
        let manifest_root = crate::tests::temporary("push-from-manifest");
        let (built, sources) =
            crate::build_manifest(&source, &manifest_root, crate::DEFAULT_LOGICAL_SUITE).unwrap();
        let server = BundleServer::assemble(&manifest_root, sources).unwrap();

        let issuer = SigningKey::from_bytes(&[61; 32]);
        let holder_key = SigningKey::from_bytes(&[62; 32]);
        let requirement = crate::authz::PushRequirement::new(
            "issuer.example",
            crate::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            "receiver.example",
        );
        let token = crate::authz::issue_push(
            "issuer.example",
            "receiver.example",
            &issuer,
            holder_key.verifying_key().to_bytes(),
            built.root,
            built.logical_length,
            crate::authz::now_seconds().unwrap(),
            3_600,
        )
        .unwrap();
        let holder = Arc::new(crate::authz::Holder::new(token, holder_key).unwrap());

        let credentials = Ephemeral::generate().unwrap();
        let identity = identity_digest(&credentials.certificate).unwrap();
        let mut config = Config::server(
            limits().unwrap(),
            credentials.certificate.to_str().unwrap().to_owned(),
            credentials.key.to_str().unwrap().to_owned(),
        );
        config.congestion = congestion_from(None).unwrap();
        apply_datagram_bytes(&mut config).unwrap();
        config.stateless_retry = true;
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &config).unwrap();
        let at = listener.local_address();
        let output = crate::tests::temporary("push-from-output");
        let receiver_output = output.to_path_buf();
        let receiving = std::thread::spawn(move || {
            push::receive_push_on_bounded(&listener, Some(2), |presentation| {
                requirement
                    .decide(
                        presentation.challenge,
                        presentation.open,
                        presentation.channel_binding,
                        presentation.now,
                    )
                    .map(|scope| push::PushAdmission {
                        scope,
                        directory: receiver_output.clone(),
                        seams: crate::ReceiveSeams::default(),
                    })
            })
        });

        // A rail count the listener cannot take, and a quantum that would
        // report every byte, are refused before a dial.
        for (rails, progress) in [
            (0, None),
            (2, Some((0, Box::new(|_, _| {}) as crate::Progress))),
        ] {
            assert!(matches!(
                push_from(
                    &server,
                    crate::PushOptions {
                        address: at,
                        holder: Arc::clone(&holder),
                        identity,
                        rails,
                        extensions: std::collections::BTreeSet::new(),
                        progress,
                    },
                ),
                Err(Error::InvalidArguments)
            ));
        }

        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&heard);
        let observer: crate::Progress = Box::new(move |bytes, total| {
            assert_eq!(total, None, "a push claimed to know its total");
            recording.lock().unwrap().push(bytes);
        });
        let server = Arc::new(server);
        let pushing_server = Arc::clone(&server);
        let pushed = within("the push from an assembled server", 60, move || {
            push_from(
                &pushing_server,
                crate::PushOptions {
                    address: at,
                    holder,
                    identity,
                    rails: 2,
                    extensions: std::collections::BTreeSet::new(),
                    progress: Some((256 * 1024, observer)),
                },
            )
        })
        .expect("a push");
        assert_eq!(pushed, built);
        joined("the receiving thread", receiving).expect("received");

        let heard = heard.lock().unwrap();
        assert!(
            heard.windows(2).all(|pair| pair[0] < pair[1]),
            "progress went backwards or repeated: {heard:?}"
        );
        // Loopback can take the whole object in one pass, so the count is
        // not a property; the order and the end are.
        assert!(!heard.is_empty(), "no progress was reported");
        let last = *heard.last().expect("a final report");
        assert!(
            last >= built.logical_length,
            "the carriers took {last} bytes for {} of object",
            built.logical_length
        );
        // The receiver holds a bundle it can scan: the same package.
        assert_eq!(crate::scan_manifest(&output).unwrap(), built);
        crate::harness::discard(&[&source, &manifest_root, &output]);
    }

    #[test]
    fn a_fetch_through_options_reports_what_it_placed() {
        let source = crate::tests::temporary("fetch-options-source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("big.bin"), crate::harness::patterned(2_500_000)).unwrap();
        let bundle = crate::tests::temporary("fetch-options-bundle");
        let built = crate::build_bundle(&source, &bundle).unwrap();

        // Two fetches of two rails each, so four sessions.
        let (listening, address) = mpsc::channel();
        let serving_bundle = bundle.to_path_buf();
        let serving = std::thread::spawn(move || {
            serve_bundle(
                &serving_bundle,
                "127.0.0.1:0".parse().unwrap(),
                &Credentials::Ephemeral,
                Some(4),
                |at, _, identity| {
                    let _ = listening.send((at, identity));
                },
            )
        });
        let (at, identity) = address.recv().expect("the server reported its address");
        let root = built.root;
        let options = move |rails, progress| crate::FetchOptions {
            address: at,
            holder: None,
            serve_identity: Some(identity),
            pin: Some(root),
            rails,
            provers: Some(2),
            extensions: std::collections::BTreeSet::new(),
            progress,
        };

        // A rail count past the limit, and a quantum that would report every
        // byte, are refused before the bundle is opened.
        let fetched = crate::tests::temporary("fetch-options-fetched");
        for (rails, progress) in [
            (MAX_FETCH_RAILS + 1, None),
            (2, Some((0, Box::new(|_, _| {}) as crate::Progress))),
        ] {
            assert!(matches!(
                fetch_bundle_with(options(rails, progress), &fetched),
                Err(Error::InvalidArguments)
            ));
            assert!(!fetched.exists(), "a refused fetch opened its bundle");
        }

        // A quantum larger than the package: no crossing ever reports, and
        // the end is reported exactly once, as the package length.
        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&heard);
        let observer: crate::Progress = Box::new(move |placed, total| {
            recording.lock().unwrap().push((placed, total));
        });
        let into = fetched.to_path_buf();
        let package = within("the fetch through options", 60, move || {
            fetch_bundle_with(options(2, Some((4 << 20, observer))), &into)
        })
        .expect("a fetch");
        assert_eq!(package, built);
        assert_eq!(
            *heard.lock().unwrap(),
            vec![(built.logical_length, Some(built.logical_length))],
            "the end was not reported exactly once"
        );

        // A quantum of one byte: every placement reports, the last of them
        // is the whole package, and the end adds nothing to it.
        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&heard);
        let observer: crate::Progress = Box::new(move |placed, total| {
            recording.lock().unwrap().push((placed, total));
        });
        let again = crate::tests::temporary("fetch-options-fetched-again");
        let into = again.to_path_buf();
        let package = within("the fetch through options, every byte", 60, move || {
            fetch_bundle_with(options(2, Some((1, observer))), &into)
        })
        .expect("a fetch");
        assert_eq!(package, built);
        let served = joined("the serving thread", serving).expect("served");
        assert_eq!(served, built);
        let heard = heard.lock().unwrap();
        assert!(
            heard.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "placed bytes went backwards or repeated: {heard:?}"
        );
        assert_eq!(
            *heard.last().unwrap(),
            (built.logical_length, Some(built.logical_length)),
            "the last report is not the whole package: {heard:?}"
        );
        crate::harness::discard(&[&source, &bundle, &fetched, &again]);
    }

    #[test]
    fn push_progress_reports_once_per_quantum_and_once_at_the_end() {
        // The arithmetic behind the reporter, as a table: crossing is by
        // quantum index, and the end reports whatever a quantum did not.
        for (before, after, quantum, crossed) in [
            (0, 99, 100, false),
            (0, 100, 100, true),
            (99, 100, 100, true),
            (100, 199, 100, false),
            (150, 350, 100, true),
            (0, 0, 100, false),
            (5, 7, 1, true),
        ] {
            assert_eq!(
                push::crossed_quantum(before, after, quantum),
                crossed,
                "{before} to {after} by {quantum}"
            );
        }
        for (reported, sum, quantum, last, due) in [
            (0, 99, 100, false, false),
            (0, 100, 100, false, true),
            (100, 199, 100, false, false),
            (100, 200, 100, false, true),
            (250, 280, 100, false, false),
            (250, 280, 100, true, true),
            (280, 280, 100, true, false),
            (300, 250, 100, true, false),
            (0, 0, 100, true, false),
        ] {
            assert_eq!(
                push::report_due(reported, sum, quantum, last),
                due,
                "{reported} then {sum} by {quantum}, last {last}"
            );
        }

        // The reporter over two rails: a rail's own crossing pays for the
        // lock, the observer hears sums in order, and finish reports the
        // tail once.
        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = Arc::clone(&heard);
        let reporter = push::Reporter::new(
            100,
            Box::new(move |bytes, total| {
                assert_eq!(total, None);
                recording.lock().unwrap().push(bytes);
            }),
            2,
        );
        reporter.taken(0, 50);
        reporter.taken(1, 40);
        assert!(heard.lock().unwrap().is_empty(), "no quantum crossed yet");
        reporter.taken(0, 120);
        assert_eq!(*heard.lock().unwrap(), vec![160]);
        reporter.taken(1, 90);
        assert_eq!(
            *heard.lock().unwrap(),
            vec![160],
            "rail one stayed in its quantum"
        );
        reporter.taken(1, 100);
        assert_eq!(*heard.lock().unwrap(), vec![160, 220]);
        reporter.finish();
        assert_eq!(
            *heard.lock().unwrap(),
            vec![160, 220],
            "nothing unreported at the end"
        );
        reporter.taken(0, 130);
        reporter.finish();
        assert_eq!(*heard.lock().unwrap(), vec![160, 220, 230]);
        reporter.finish();
        assert_eq!(
            *heard.lock().unwrap(),
            vec![160, 220, 230],
            "a second end reports nothing"
        );
    }

    #[test]
    fn fetch_rail_count_uses_the_whole_supported_range() {
        assert!(!fetch::valid_fetch_rails(0));
        assert!(fetch::valid_fetch_rails(1));
        assert!(fetch::valid_fetch_rails(MAX_FETCH_RAILS));
        assert!(!fetch::valid_fetch_rails(MAX_FETCH_RAILS + 1));
    }
}
