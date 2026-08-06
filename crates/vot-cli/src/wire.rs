//! The commands' carrier: a QUIC endpoint under the two engines.
//!
//! ADR-0030 keeps the engines transport-agnostic and puts the
//! socket-owning backend behind a feature, so this module is the whole of
//! what `wire` adds: credentials, an endpoint at each end, and the two
//! calls the commands make.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use vot_transport_api::ReceiveLimits;
use vot_transport_quiche::live::{Config, Transport};

use crate::{BundleFetcher, BundleServer, Credentials, Error, PackageSummary, ServeSession, drive};

/// What a session may hold inbound, matched to what the codec settings the
/// engines use will let a peer send.
fn limits() -> Result<ReceiveLimits, Error> {
    ReceiveLimits::advertised(
        &vot_codec::Settings::default(),
        vot_transport_quiche::INBOUND_BYTE_CAPACITY,
    )
    .map_err(|_| Error::InvalidArguments)
}

/// Where an ephemeral certificate and key are written.
///
/// quiche loads both from files, so they cannot stay in memory. The
/// directory is this process's own and goes when the server does.
struct Ephemeral {
    directory: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        // Nothing to do about a failure here, and nothing to report it to:
        // the key was worth nothing to begin with.
        let _ = std::fs::remove_file(&self.certificate);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

impl Ephemeral {
    /// Generates a self-signed certificate for this process.
    ///
    /// ECDSA P-256, because `BoringSSL` as quiche configures it refuses an
    /// Ed25519 leaf, and because RSA would spend up to a second of every
    /// `serve` on key generation for a certificate nobody checks.
    fn generate() -> Result<Self, Error> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| Error::Randomness)?;
        let mut parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .map_err(|_| Error::InvalidArguments)?;
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let certificate = parameters
            .self_signed(&key)
            .map_err(|_| Error::InvalidArguments)?;

        let directory = std::env::temp_dir().join(format!("vot-serve-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        let written = Self {
            certificate: directory.join("cert.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        crate::write_new_synced(&written.certificate, certificate.pem().as_bytes())?;
        crate::write_new_synced(&written.key, key.serialize_pem().as_bytes())?;
        Ok(written)
    }
}

/// The address this host would send from to reach `peer`, port unset.
///
/// quiche is told the address its socket is bound to and validates the
/// path against it, so a wildcard bind names a local address no packet
/// ever arrives at and the handshake never completes. Asking the routing
/// table costs one unconnected socket and puts nothing on the wire.
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

/// Serves `bundle` to one session at a time on `address`, forever.
///
/// Each accepted carrier is driven to a settled state and then dropped;
/// the bundle is opened and proved once, ahead of any of them.
///
/// # Errors
/// Surfaces a bundle that will not open, a socket that will not bind, and
/// any failure of this end while a session is live.
pub fn serve_bundle(
    bundle: &Path,
    address: SocketAddr,
    credentials: &Credentials,
    sessions: Option<u32>,
    mut listening: impl FnMut(SocketAddr),
) -> Result<PackageSummary, Error> {
    let server = BundleServer::open(bundle)?;
    let ephemeral = match credentials {
        Credentials::Ephemeral => Some(Ephemeral::generate()?),
        Credentials::Files { .. } => None,
    };
    let (certificate, key) = match (credentials, &ephemeral) {
        (Credentials::Files { certificate, key }, _) => (certificate.clone(), key.clone()),
        (Credentials::Ephemeral, Some(written)) => {
            (written.certificate.clone(), written.key.clone())
        }
        (Credentials::Ephemeral, None) => return Err(Error::InvalidArguments),
    };
    let mut config = Config::server(
        limits()?,
        certificate.to_str().ok_or(Error::InvalidPath)?.to_owned(),
        key.to_str().ok_or(Error::InvalidPath)?.to_owned(),
    );
    // A server waits for a client for as long as it takes. The default
    // bound exists so a test fails rather than hangs, and giving up would
    // read here as a carrier that died during the handshake.
    config.accept_timeout_ms = 0;

    // A bounded count is what lets a test serve one session and return;
    // without one the command serves until it is stopped.
    let mut answered = 0;
    while sessions.is_none_or(|bound| answered < bound) {
        // `serve` waits for a connection on its own thread, so one
        // endpoint is one session here.
        let carrier = Transport::serve(address, &config).map_err(|_| Error::InvalidArguments)?;
        // Reported before the session starts, because a caller that asked
        // for port zero cannot connect until it knows what it got.
        listening(carrier.local_address());
        let mut session = ServeSession::begin(&server, carrier, crate::wire_authentication())?;
        drive(&mut session)?;
        answered += 1;
    }
    Ok(server.package())
}

/// Fetches a bundle from `address` into `bundle`.
///
/// # Errors
/// Surfaces a destination that exists, a connection that will not open,
/// and any refusal the fetch made of what the server answered.
pub fn fetch_bundle(
    address: SocketAddr,
    bundle: &Path,
    pin: Option<[u8; 32]>,
) -> Result<PackageSummary, Error> {
    let mut config = Config::client(limits()?);
    // ADR-0030: the channel is unauthenticated and says so. A forged
    // server can only serve bytes that fail the proofs the fetch checks.
    config.verify_peer = false;
    let carrier = Transport::connect(local_for(address)?, address, Some("localhost"), &config)
        .map_err(|_| Error::InvalidArguments)?;
    let mut fetcher = BundleFetcher::begin(carrier, bundle, pin)?;
    let status = drive(&mut fetcher)?;
    match status {
        crate::FetchStatus::Complete => fetcher.package().ok_or(Error::InvalidBundle),
        crate::FetchStatus::Closed(_) | crate::FetchStatus::Disconnected => {
            Err(Error::InvalidBundle)
        }
        crate::FetchStatus::Active => Err(Error::InvalidBundle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// The ADR's step-4 test: everything the CLI builds crosses a real
    /// socket and publishes unchanged, both engines driven by the one loop.
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
                |at| {
                    let _ = listening.send(at);
                },
            )
        });

        let at = address.recv().expect("the server reported its address");
        let fetched = crate::tests::temporary("wire-fetched");
        let package = fetch_bundle(at, &fetched, Some(built.root)).expect("a fetched bundle");
        assert_eq!(package, built);
        let served = serving.join().expect("the serving thread").expect("served");
        assert_eq!(served, built);

        // And the existing receive publishes what crossed the wire.
        let destination = crate::tests::temporary("wire-destination");
        let receipt = crate::tests::temporary("wire-receipt.cbor");
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
}
