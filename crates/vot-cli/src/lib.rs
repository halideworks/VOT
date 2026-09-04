//! Bounded package construction, reliable verification, and durable publication.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use vot_manifest::{
    Component, ManifestEntry, ManifestPage, PackagePath, PageCommitment, PathProfile, Seal,
    canonical_path_key, decode_page, decode_seal, is_path_prefix,
};
#[cfg(test)]
use vot_manifest::{EntryKind, ObjectId, StorageRef, encode_page, encode_seal};
use vot_pack::{CANDIDATE_MAX, LogicalFile, Pack, StreamingPacker};
pub use vot_package::PackageSummary;
pub use vot_package::{EntryRecord, Storage};
pub(crate) use vot_package::{
    PackageAssembly, PackageBuilder, PackageIngest, PackageRootBuilder, PageDraft,
};
use vot_receipt::{
    AssuranceLevel, AuthenticatedReceipt, CommitProfile, Receipt, SubjectKind,
    authenticate_hmac_sha256, decode_authenticated, encode_authenticated, sign_ed25519,
    verify_ed25519, verify_hmac_sha256,
};
use vot_scheduler::ReliableReceiver;
use vot_transport_api::{MAX_DATA_RECORD_BYTES, SubjectId};
use vot_verifier::{StreamVerifier, Suite};

/// Creates a directory only this user can enter.
pub(crate) fn create_private_directory(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

pub mod authz;
mod drive;
mod fetch;
#[cfg(test)]
mod harness;
#[cfg(not(feature = "wire"))]
mod nowire;
#[cfg(any(test, feature = "wire"))]
mod relay;
#[cfg(any(test, feature = "wire"))]
mod rendezvous;
mod serve;
#[cfg(any(test, feature = "wire"))]
mod side_channel;
#[cfg(feature = "wire")]
mod wire;

pub use drive::{Engine, ServeSession, drive};
pub use fetch::{
    BundleFetcher, CancellationHandle, CountingSink, FetchStatus, ReceiveObject, ReceiveSeams,
    ReceiveSessionId, ReceiveSink,
};
#[cfg(not(feature = "wire"))]
pub use nowire::{
    fetch_bundle, fetch_bundle_with, fetch_via_rendezvous, probe_serve, push_bundle, push_from,
    receive_push, relay_service, rendezvous_service, serve_bundle,
};
pub use serve::{BundleServer, ServeConnection, ServeStatus, ServedSource};
#[cfg(feature = "wire")]
pub use wire::{
    Listener, PushAdmission, PushPresentation, ServeAdmission, ServePresentation, ServeReport,
    bind_push_listener, bind_serve_listener, fetch_bundle, fetch_bundle_with, fetch_via_rendezvous,
    probe_serve, push_bundle, push_from, receive_push, receive_push_on, relay_service,
    rendezvous_service, serve_bundle, serve_on,
};

mod keys;
mod options;
mod package;
mod receipt_io;
mod util;

pub use keys::*;
pub use options::*;
#[cfg(test)]
use package::scan::validate_page_envelope;
pub(crate) use package::scan::{ManifestReader, scan_manifest, seal_page_digests};
pub use package::*;
pub use receipt_io::*;
pub use util::*;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidArguments,
    InvalidPath,
    InvalidBundle,
    DestinationExists,
    SourceMutation,
    RootMismatch,
    Randomness,
    Pack(vot_pack::Error),
    Scheduler(vot_scheduler::Error),
    Verifier(vot_verifier::VerifyError),
    Receipt(vot_receipt::Error),
    Session(Box<vot_session::Error>),
    Codec(vot_codec::frames::Error),
    Proof,
    /// A command that needs the `wire` feature, in a build without it.
    WireUnsupported,
    /// A session where nothing happened for as long as this end will wait.
    Stalled,
    /// A carrier that would not bind or connect.
    CarrierUnavailable,
    /// A capability session whose carrier cannot bind possession to its channel.
    ///
    /// Carries no exporter material, so reporting it cannot disclose the binding.
    ChannelBindingUnavailable,
    /// A pinned fetch reached a serve whose certificate is not the pinned
    /// identity. The bytes were never at risk, which the package root holds;
    /// the pin asked to also know who was answering, and this peer was not it.
    ServeIdentityMismatch,
    /// The peer ended the session under a registered code.
    PeerClosed(u16),
    /// No serve registered for this rendezvous key.
    RendezvousUnresolved,
    /// A serve was found but no session formed: the path could not be
    /// punched, which symmetric or carrier-grade NAT on either end
    /// produces. A literal address still reaches a serve that forwards a
    /// port.
    RendezvousUnpunched,
    /// The named relay answered no slot: full, unreachable, or refusing.
    RelayUnavailable,
    /// A fetch at an address that named no package root.
    ///
    /// The channel is not authenticated, so the root is the only thing that
    /// says which package this is. Every range proves without it, to
    /// whatever root the server chose.
    UnpinnedFetch,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vot_pack::Error> for Error {
    fn from(error: vot_pack::Error) -> Self {
        Self::Pack(error)
    }
}

impl From<vot_package::Error> for Error {
    fn from(error: vot_package::Error) -> Self {
        match error {
            vot_package::Error::InvalidPath => Self::InvalidPath,
            vot_package::Error::InvalidBundle => Self::InvalidBundle,
            vot_package::Error::RootMismatch => Self::RootMismatch,
            vot_package::Error::Verifier(error) => Self::Verifier(error),
        }
    }
}

impl From<vot_object::Error> for Error {
    fn from(error: vot_object::Error) -> Self {
        match error {
            vot_object::Error::Verifier(error) => Self::Verifier(error),
            _ => Self::Proof,
        }
    }
}

impl From<vot_scheduler::Error> for Error {
    fn from(error: vot_scheduler::Error) -> Self {
        Self::Scheduler(error)
    }
}

impl From<vot_verifier::VerifyError> for Error {
    fn from(error: vot_verifier::VerifyError) -> Self {
        match error {
            vot_verifier::VerifyError::RootMismatch => Self::RootMismatch,
            other => Self::Verifier(other),
        }
    }
}

impl From<vot_receipt::Error> for Error {
    fn from(error: vot_receipt::Error) -> Self {
        Self::Receipt(error)
    }
}

impl From<vot_session::Error> for Error {
    fn from(error: vot_session::Error) -> Self {
        Self::Session(Box::new(error))
    }
}

impl From<vot_codec::frames::Error> for Error {
    fn from(error: vot_codec::frames::Error) -> Self {
        Self::Codec(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveReport {
    pub package: PackageSummary,
    pub peak_staging: u64,
}

#[cfg(test)]
mod tests {
    /// Wraps a raw secret as shared key material, which is what these tests
    /// used before receipts gained a scheme.
    fn shared(bytes: &[u8]) -> KeyMaterial {
        KeyMaterial::Shared(bytes.to_vec())
    }

    /// The secret inside shared key material, for the loader tests.
    fn loaded_secret(key: &KeyMaterial) -> Vec<u8> {
        match key {
            KeyMaterial::Shared(bytes) => bytes.clone(),
            other => panic!("expected a shared secret, got {other:?}"),
        }
    }

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn object_verifier_failures_keep_their_error_class() {
        assert!(matches!(
            Error::from(vot_object::Error::Verifier(
                vot_verifier::VerifyError::InvalidGroupLength
            )),
            Error::Verifier(vot_verifier::VerifyError::InvalidGroupLength)
        ));
    }

    #[test]
    fn a_rendezvous_names_every_address_it_answers_at_with_ipv6_first() {
        use std::net::SocketAddr;

        let at = |text: &str| text.parse::<SocketAddr>().expect("an address");
        assert_eq!(
            parse_rendezvous(" 198.51.100.7:9000 ").expect("an address"),
            vec![at("198.51.100.7:9000")]
        );
        assert_eq!(
            parse_rendezvous("[2001:db8::1]:9000").expect("an address"),
            vec![at("[2001:db8::1]:9000")]
        );
        assert_eq!(
            parse_rendezvous("198.51.100.7:9000, [2001:db8::1]:9000").expect("a list"),
            vec![at("[2001:db8::1]:9000"), at("198.51.100.7:9000")],
            "IPv6 leads whatever order they were given in"
        );
        assert_eq!(
            parse_rendezvous("198.51.100.7:9000,198.51.100.7:9000").expect("a list"),
            vec![at("198.51.100.7:9000")],
            "one route named twice is one route, or the ladder pays for it twice"
        );
        let localhost = parse_rendezvous("localhost:9000").expect("a name the resolver knows");
        assert!(!localhost.is_empty());
        assert!(localhost.iter().all(|address| address.ip().is_loopback()));
        assert!(
            localhost
                .windows(2)
                .all(|pair| !pair[0].is_ipv4() || !pair[1].is_ipv6())
        );

        for refused in [
            "198.51.100.7",
            "rendezvous.example.com",
            "",
            "198.51.100.7:9000,",
            " ",
        ] {
            assert!(
                matches!(parse_rendezvous(refused), Err(Error::InvalidArguments)),
                "{refused:?} names no service"
            );
        }
    }

    /// A path that takes whatever is written at it with it.
    ///
    /// Cleaning up in a `Drop` is the only version a later test cannot
    /// forget. A sweep runs this suite once per mutant, so one leftover
    /// directory per test per mutant is tens of thousands of them in the
    /// shared temp directory, which is what has killed mutation runners here
    /// before.
    pub(crate) struct Temporary(PathBuf);

    impl std::ops::Deref for Temporary {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<Path> for Temporary {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<std::ffi::OsStr> for Temporary {
        fn as_ref(&self) -> &std::ffi::OsStr {
            self.0.as_os_str()
        }
    }

    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A guard over a path something else chose.
    ///
    /// For a second file the code under test writes beside the one the test
    /// named, such as the JSON summary `receive_bundle` puts next to a
    /// receipt. The guard over the receipt does not know about it.
    pub(crate) fn guarded(path: PathBuf) -> Temporary {
        Temporary(path)
    }

    pub(crate) fn temporary(name: &str) -> Temporary {
        Temporary(std::env::temp_dir().join(format!(
            "vot-cli-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    /// The call has to reach the filesystem on the platforms that have it.
    /// An fsync that quietly does nothing reads the same as one that worked,
    /// right up until the power goes.
    #[test]
    #[cfg(not(windows))]
    fn syncing_a_directory_that_is_not_there_says_so() {
        assert!(sync_directory(&temporary("absent-directory")).is_err());
    }

    #[test]
    fn a_package_root_is_exactly_its_hex() {
        let root =
            parse_package_root("7503bcc1b8fe0bfe100a9d32204f17133de6a6069db7ff27770f9589f142a988")
                .unwrap();
        assert_eq!(root[0], 0x75);
        assert_eq!(root[1], 0x03);
        assert_eq!(root[31], 0x88);
        // Round trips through the form send prints.
        let mut hex = String::new();
        for byte in &root {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        assert_eq!(parse_package_root(&hex).unwrap(), root);

        // A root of the wrong length is not a root, whatever it says.
        assert!(matches!(
            parse_package_root(&hex[..63]),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            parse_package_root(&format!("{hex}0")),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            parse_package_root(""),
            Err(Error::InvalidArguments)
        ));
        // And nor is 64 characters that are not hexadecimal.
        assert!(matches!(
            parse_package_root(&"g".repeat(64)),
            Err(Error::InvalidArguments)
        ));
        let mut spoiled = hex.clone();
        spoiled.replace_range(20..21, "z");
        assert!(matches!(
            parse_package_root(&spoiled),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn issuing_writes_a_token_the_holder_can_spend() {
        // The wrapper, not `authz::issue` underneath it: one that wrote
        // nothing and reported success would leave an operator with no token
        // and no error.
        let (holder_secret, holder_public) = generate_keypair().expect("a holder pair");
        let (issuer_secret, _) = generate_keypair().expect("an issuer pair");
        let issuer_file = tests::temporary("issue-issuer");
        std::fs::write(&issuer_file, &issuer_secret).expect("a key file");
        let holder_file = tests::temporary("issue-holder");
        std::fs::write(&holder_file, &holder_public).expect("a key file");
        let out = tests::temporary("issue-token");
        let root = "5c".repeat(32);

        issue_capability(
            &issuer_file.to_string_lossy(),
            "you.example",
            "them.example",
            &holder_file.to_string_lossy(),
            &root,
            "3600",
            &out,
        )
        .expect("a token");

        let written = std::fs::read(&out).expect("the token file");
        assert!(!written.is_empty(), "the token is empty");
        let signed = vot_capability::decode(&written).expect("a capability of this format");
        let capability = vot_capability::Capability::from_canonical_bytes(&signed.capability)
            .expect("the claims");
        assert_eq!(capability.audience, "them.example");
        assert_eq!(capability.issuer, "you.example");
        assert_eq!(capability.scope.root, [0x5c; 32], "another package");
        assert_eq!(
            capability.expiry - capability.not_before,
            3_600,
            "another window"
        );
        // The holder key in the token is the one that was named, so the
        // secret half can prove it.
        let seed: [u8; 32] = parse_package_root(
            holder_secret
                .strip_prefix("ed25519-secret:")
                .expect("the label"),
        )
        .expect("32 bytes");
        assert_eq!(
            capability.holder_key,
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            "the token names another holder"
        );

        // A destination that exists is not overwritten, and the labels are
        // not interchangeable.
        assert!(matches!(
            issue_capability(
                &issuer_file.to_string_lossy(),
                "you.example",
                "them.example",
                &holder_file.to_string_lossy(),
                &root,
                "3600",
                &out
            ),
            Err(Error::Io(_))
        ));
        let second = tests::temporary("issue-token-2");
        assert!(
            matches!(
                issue_capability(
                    &holder_file.to_string_lossy(),
                    "you.example",
                    "them.example",
                    &holder_file.to_string_lossy(),
                    &root,
                    "3600",
                    &second
                ),
                Err(Error::InvalidArguments)
            ),
            "a public key signed a token"
        );
        assert!(
            matches!(
                issue_capability(
                    &issuer_file.to_string_lossy(),
                    "you.example",
                    "them.example",
                    &issuer_file.to_string_lossy(),
                    &root,
                    "3600",
                    &second
                ),
                Err(Error::InvalidArguments)
            ),
            "a secret key was taken as a holder"
        );
    }

    #[test]
    fn a_generated_pair_is_two_halves_of_one_key() {
        let (secret, public) = generate_keypair().expect("a keypair");
        let (again, _) = generate_keypair().expect("a second keypair");
        assert_ne!(secret, again, "two calls gave the same key");

        let seed = secret
            .strip_prefix("ed25519-secret:")
            .expect("the secret label");
        let claimed = public
            .strip_prefix("ed25519-public:")
            .expect("the public label");
        assert_eq!(seed.len(), 64, "{secret}");
        assert_eq!(claimed.len(), 64, "{public}");
        // The halves have to match, or a token issued to the public one is a
        // token the secret cannot prove.
        let bytes: [u8; 32] = parse_package_root(seed).expect("32 bytes of hex");
        assert_eq!(
            hex_of(&SigningKey::from_bytes(&bytes).verifying_key().to_bytes()),
            claimed,
            "the public half is not this secret's"
        );
    }

    #[test]
    fn the_refusal_survives_the_wrapper_that_reads_the_environment() {
        // `pin_for_address` below holds the decision, and this holds the one
        // caller: a wrapper that returned `Ok(None)` whatever it was given
        // would waive every unpinned fetch while the decision underneath
        // still read correctly.
        assert!(
            std::env::var_os(UNPINNED).is_none(),
            "the suite owns no env"
        );
        assert!(
            matches!(address_pin(None), Err(Error::UnpinnedFetch)),
            "an address alone was accepted"
        );
        let root = "11".repeat(32);
        assert_eq!(
            address_pin(Some(&root)).expect("a root"),
            Some([0x11; 32]),
            "a named root did not reach the caller"
        );
    }

    #[test]
    fn a_fetch_at_an_address_names_the_package_or_says_it_will_not() {
        let root = "11".repeat(32);
        assert_eq!(
            pin_for_address(Some(&root), false).expect("a root"),
            Some([0x11; 32]),
            "a named root is the pin, override or not"
        );
        assert_eq!(
            pin_for_address(Some(&root), true).expect("a root"),
            Some([0x11; 32])
        );
        assert!(
            matches!(pin_for_address(None, false), Err(Error::UnpinnedFetch)),
            "an address alone does not say which package to accept"
        );
        assert_eq!(
            pin_for_address(None, true).expect("the override"),
            None,
            "and the override is what makes it a choice rather than an accident"
        );
        // A root that is not one is the argument error it always was, not the
        // refusal this adds.
        assert!(matches!(
            pin_for_address(Some("nonsense"), false),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn only_a_variable_that_carries_something_waives_the_pin() {
        use std::ffi::OsStr;

        assert!(unpinned_allowed(Some(OsStr::new("1"))));
        assert!(unpinned_allowed(Some(OsStr::new("no"))), "any value is yes");
        assert!(!unpinned_allowed(None), "unset is not a waiver");
        assert!(
            !unpinned_allowed(Some(OsStr::new(""))),
            "set and empty is what an unset variable expands to, not a waiver"
        );
    }

    /// Without the carrier the wire commands say which feature they need,
    /// rather than failing as though the caller got the arguments wrong.
    #[cfg(not(feature = "wire"))]
    #[test]
    fn the_wire_commands_name_the_feature_they_need() {
        let address = "127.0.0.1:1".parse().unwrap();
        let bundle = temporary("unsupported");
        assert!(matches!(
            serve_bundle(
                &bundle,
                address,
                &Credentials::Ephemeral,
                None,
                |_, _, _| {}
            ),
            Err(Error::WireUnsupported)
        ));
        assert!(matches!(
            fetch_bundle(address, &bundle, None),
            Err(Error::WireUnsupported)
        ));
        assert!(matches!(
            push_bundle(&bundle, address, &bundle, "-", [0; 32]),
            Err(Error::WireUnsupported)
        ));
        assert!(matches!(
            receive_push(address, &bundle, &Credentials::Ephemeral, None, |_, _| {}),
            Err(Error::WireUnsupported)
        ));
        assert!(matches!(
            rendezvous_service(address, None, |_| {}),
            Err(Error::WireUnsupported)
        ));
        assert!(matches!(
            relay_service(address, None, |_| {}),
            Err(Error::WireUnsupported)
        ));
    }

    #[test]
    fn canonical_manifest_bundle_publishes_with_matching_receipt() {
        let source = temporary("source");
        let bundle = temporary("bundle");
        let destination = temporary("destination");
        let receipt = temporary("receipt.cbor");
        fs::create_dir_all(source.join("frames")).unwrap();
        fs::write(source.join("frames/0001.exr"), b"frame-one").unwrap();
        fs::write(source.join("frames/0002.exr"), b"frame-two").unwrap();
        fs::write(source.join("large.mov"), vec![0x5a; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("large-copy.mov"), vec![0x5a; CANDIDATE_MAX + 1]).unwrap();

        let sent = build_bundle(&source, &bundle).unwrap();
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        let seal = decode_seal(&fs::read(manifest_directory.join(MANIFEST_SEAL)).unwrap()).unwrap();
        assert_eq!(seal.package.root, sent.root);
        assert_eq!(seal.package.length, sent.logical_length);
        let mut previous = [0; 32];
        for commitment in &seal.pages {
            let encoded =
                fs::read(manifest_page_path(&manifest_directory, commitment.index)).unwrap();
            let page = decode_page(&encoded).unwrap();
            assert_eq!(page.manifest_id, seal.manifest_id);
            assert_eq!(page.previous_digest, previous);
            assert_eq!(page.total, None);
            previous = *blake3::hash(&encoded).as_bytes();
            assert_eq!(commitment.digest, previous);
        }
        assert_eq!(scan_manifest(&bundle).unwrap(), sent);
        let seal_path = manifest_directory.join(MANIFEST_SEAL);
        let canonical_seal = encode_seal(&seal).unwrap();
        let mut wrong_root = seal.clone();
        wrong_root.package.root[0] ^= 1;
        fs::write(&seal_path, encode_seal(&wrong_root).unwrap()).unwrap();
        assert!(matches!(scan_manifest(&bundle), Err(Error::RootMismatch)));
        let mut wrong_length = seal.clone();
        wrong_length.package.length += 1;
        fs::write(&seal_path, encode_seal(&wrong_length).unwrap()).unwrap();
        assert!(matches!(scan_manifest(&bundle), Err(Error::RootMismatch)));
        fs::write(&seal_path, canonical_seal).unwrap();
        let received = receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &shared(&[7; 32]),
            "2026-07-31T23:59:59Z",
        )
        .unwrap();
        assert_eq!(sent, received.package);
        assert!(received.peak_staging <= (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64);
        assert_eq!(
            fs::read(destination.join("frames/0001.exr")).unwrap(),
            b"frame-one"
        );
        assert_eq!(
            fs::read(destination.join("frames/0002.exr")).unwrap(),
            b"frame-two"
        );
        assert_eq!(
            fs::read(destination.join("large.mov")).unwrap().len(),
            CANDIDATE_MAX + 1
        );
        assert_eq!(
            fs::read(destination.join("large-copy.mov")).unwrap().len(),
            CANDIDATE_MAX + 1
        );
        assert!(!fs::read(&receipt).unwrap().is_empty());
        let summary = fs::read_to_string(receipt.with_extension("json")).unwrap();
        assert!(summary.contains("\"assurance\":\"PUBLISHED\""));
        assert!(summary.contains(&object_name(&sent.root)[..64]));

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt.with_extension("json")).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn corruption_cannot_publish_or_emit_a_receipt() {
        let source = temporary("bad-source");
        let bundle = temporary("bad-bundle");
        let destination = temporary("bad-destination");
        let receipt = temporary("bad-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();
        let object = fs::read_dir(bundle.join("objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = fs::read(&object).unwrap();
        bytes[0] ^= 1;
        fs::write(object, bytes).unwrap();
        assert!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert!(!receipt.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }
    }

    #[test]
    fn invalid_receipt_metadata_cannot_publish_destination() {
        let source = temporary("timestamp-source");
        let bundle = temporary("timestamp-bundle");
        let destination = temporary("timestamp-destination");
        let receipt = temporary("timestamp-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "not-rfc3339"
            ),
            Err(Error::Receipt(vot_receipt::Error::InvalidTimestamp))
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }
    }

    #[test]
    fn receipt_outputs_are_prepared_before_destination_publication() {
        let source = temporary("receipt-output-source");
        let bundle = temporary("receipt-output-bundle");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"contents").unwrap();
        build_bundle(&source, &bundle).unwrap();

        let destination = temporary("missing-receipt-parent-destination");
        let receipt = temporary("missing-receipt-parent").join("receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::Io(_))
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());
        let staging = staging_path(&destination).unwrap();
        if staging.exists() {
            fs::remove_dir_all(staging).unwrap();
        }

        let collision_destination = temporary("summary-collision-destination");
        let collision_receipt = temporary("receipt.json");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &collision_destination,
                &collision_receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::InvalidArguments)
        ));
        assert!(!collision_destination.exists());
        assert!(!collision_receipt.exists());

        let existing_summary_destination = temporary("existing-summary-destination");
        let existing_summary_receipt = temporary("existing-summary.cbor");
        let existing_summary = existing_summary_receipt.with_extension("json");
        fs::write(&existing_summary, b"existing").unwrap();
        assert!(matches!(
            receive_bundle(
                &bundle,
                &existing_summary_destination,
                &existing_summary_receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));
        assert!(!existing_summary_destination.exists());
        assert!(!existing_summary_receipt.exists());
        fs::remove_file(existing_summary).unwrap();

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn destination_publication_is_atomic_and_no_replace() {
        let source = temporary("atomic-source");
        let destination = temporary("atomic-destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"verified").unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(matches!(
            atomic_rename_noreplace(&source, &destination),
            Err(Error::Io(_))
        ));
        assert_eq!(fs::read(source.join("file")).unwrap(), b"verified");
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir(destination).unwrap();
    }

    #[test]
    fn receipt_identifiers_are_fresh_for_each_publication() {
        let first = fresh_receipt_identifiers().unwrap();
        let second = fresh_receipt_identifiers().unwrap();
        assert_ne!(first, [0; 32]);
        assert_ne!(second, [0; 32]);
        assert_ne!(first, second);
        assert_ne!(&first[..16], &first[16..]);
        let package = PackageSummary {
            root: [3; 32],
            logical_length: 9,
            entries: 1,
        };
        let receipt = publication_receipt(&package, "2026-07-31T23:59:59Z", first);
        assert_eq!(receipt.session_id, first[..16]);
        assert_eq!(receipt.incarnation_id, first[16..]);
    }

    #[test]
    fn publication_receipt_claims_only_performed_assurance() {
        let package = PackageSummary {
            root: [3; 32],
            logical_length: 9,
            entries: 1,
        };
        let receipt = publication_receipt(&package, "2026-07-31T23:59:59Z", [7; 32]);
        assert_eq!(receipt.profile, CommitProfile::Fast);
        assert_eq!(receipt.actual_predecessor, AssuranceLevel::TransitVerified);
    }

    #[test]
    fn abandoned_prepared_receipt_is_removed() {
        let destination = temporary("prepared-final");
        let prepared = PreparedFile::new(&destination, b"receipt", "unique", "receipt").unwrap();
        let temporary = prepared.temporary.clone().unwrap();
        assert!(temporary.exists());
        drop(prepared);
        assert!(!temporary.exists());
        assert!(!destination.exists());
    }

    fn prepared_evidence(
        receipt: &Path,
        summary: &Path,
        package: &PackageSummary,
        key: &KeyMaterial,
    ) -> (PreparedFile, PreparedFile) {
        let authenticated = key
            .sign(publication_receipt(
                package,
                "2026-07-31T23:59:59Z",
                [5; 32],
            ))
            .unwrap();
        let encoded = encode_authenticated(&authenticated).unwrap();
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        (
            PreparedFile::new(receipt, &encoded, suffix, "receipt").unwrap(),
            PreparedFile::new(
                summary,
                receipt_summary_bytes(package).as_bytes(),
                suffix,
                "summary",
            )
            .unwrap(),
        )
    }

    #[test]
    fn receipt_publication_recovers_after_destination_publish() {
        let receipt = temporary("recover-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [4; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = shared(&[9; 32]);
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        let expected_receipt = fs::read(&prepared_receipt_path).unwrap();
        let expected_summary = fs::read(&prepared_summary_path).unwrap();
        drop(prepared_receipt);
        drop(prepared_summary);
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());
        fs::hard_link(&prepared_receipt_path, &receipt).unwrap();

        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
        assert_eq!(fs::read(&receipt).unwrap(), expected_receipt);
        assert_eq!(fs::read(&summary).unwrap(), expected_summary);
        assert!(!prepared_receipt_path.exists());
        assert!(!prepared_summary_path.exists());
        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn destination_sync_failure_preserves_receipt_recovery_evidence() {
        let staging = temporary("sync-failure-staging");
        let destination = temporary("sync-failure-destination");
        let receipt = temporary("sync-failure-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [14; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = shared(&[9; 32]);
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("file"), b"published").unwrap();
        let (prepared_receipt, prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        let mut owned_receipt = Some(prepared_receipt);
        let mut owned_summary = Some(prepared_summary);

        assert!(matches!(
            publish_staging_with(
                &staging,
                &destination,
                &mut owned_receipt,
                &mut owned_summary,
                |_| Err(Error::Io(io::Error::other(
                    "injected directory sync failure"
                ))),
            ),
            Err(Error::Io(_))
        ));
        drop((owned_receipt, owned_summary));
        assert!(destination.exists());
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());
        assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());

        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn receipt_recovery_reports_absent_evidence() {
        let receipt = temporary("absent-recovery-receipt.cbor");
        let summary = receipt.with_extension("json");
        let package = PackageSummary {
            root: [4; 32],
            logical_length: 7,
            entries: 1,
        };
        assert!(
            !recover_prepared_receipts(&receipt, &summary, &package, &shared(&[9; 32])).unwrap()
        );
    }

    #[test]
    fn receipt_recovery_completes_after_one_preparation_was_cleaned() {
        let package = PackageSummary {
            root: [5; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = shared(&[9; 32]);
        for remove_receipt_preparation in [false, true] {
            let receipt = temporary(&format!(
                "partial-cleanup-{remove_receipt_preparation}.cbor"
            ));
            let summary = receipt.with_extension("json");
            let (mut prepared_receipt, mut prepared_summary) =
                prepared_evidence(&receipt, &summary, &package, &key);
            prepared_receipt.preserve_for_recovery();
            prepared_summary.preserve_for_recovery();
            let prepared_receipt = prepared_receipt.path().unwrap();
            let prepared_summary = prepared_summary.path().unwrap();
            fs::hard_link(&prepared_receipt, &receipt).unwrap();
            fs::hard_link(&prepared_summary, &summary).unwrap();
            if remove_receipt_preparation {
                fs::remove_file(&prepared_receipt).unwrap();
            } else {
                fs::remove_file(&prepared_summary).unwrap();
            }

            assert!(recover_prepared_receipts(&receipt, &summary, &package, &key).unwrap());
            assert!(!prepared_receipt.exists());
            assert!(!prepared_summary.exists());
            validate_receipt_files(&receipt, &summary, &package, &key).unwrap();
            fs::remove_file(receipt).unwrap();
            fs::remove_file(summary).unwrap();
        }
    }

    #[test]
    fn receipt_recovery_rejects_partial_and_conflicting_preparations() {
        let package = PackageSummary {
            root: [6; 32],
            logical_length: 7,
            entries: 1,
        };
        let suffix = object_name(&package.root);
        let suffix = suffix.strip_suffix(".obj").unwrap();
        let key = shared(&[9; 32]);

        let receipt = temporary("only-receipt.cbor");
        let summary = receipt.with_extension("json");
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        fs::write(&prepared_receipt, b"receipt").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_receipt).unwrap();

        let receipt = temporary("only-summary.cbor");
        let summary = receipt.with_extension("json");
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&prepared_summary, b"summary").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(prepared_summary).unwrap();

        let receipt = temporary("conflicting-receipt.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt = prepared_receipt.path().unwrap();
        let prepared_summary = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        let prepared_receipt = prepared_output_path(&receipt, suffix, "receipt").unwrap();
        let prepared_summary = prepared_output_path(&summary, suffix, "summary").unwrap();
        fs::write(&receipt, b"conflict").unwrap();
        fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();

        let receipt = temporary("conflicting-summary.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt_owner, mut prepared_summary_owner) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt_owner.preserve_for_recovery();
        prepared_summary_owner.preserve_for_recovery();
        let prepared_receipt = prepared_receipt_owner.path().unwrap();
        let prepared_summary = prepared_summary_owner.path().unwrap();
        drop((prepared_receipt_owner, prepared_summary_owner));
        fs::copy(&prepared_receipt, &receipt).unwrap();
        fs::write(&summary, b"conflict").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &key),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn receipt_recovery_authenticates_prepared_evidence() {
        let package = PackageSummary {
            root: [8; 32],
            logical_length: 7,
            entries: 1,
        };
        let receipt = temporary("wrong-key-receipt.cbor");
        let summary = receipt.with_extension("json");
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &shared(&[8; 32]));
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &shared(&[9; 32])),
            Err(Error::InvalidBundle)
        ));
        assert!(!receipt.exists());
        assert!(!summary.exists());
        assert!(prepared_receipt_path.exists());
        assert!(prepared_summary_path.exists());

        fs::remove_file(&prepared_receipt_path).unwrap();
        fs::remove_file(&prepared_summary_path).unwrap();
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &shared(&[9; 32]));
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt_path = prepared_receipt.path().unwrap();
        let prepared_summary_path = prepared_summary.path().unwrap();
        drop((prepared_receipt, prepared_summary));
        fs::write(&prepared_summary_path, b"{\"root\":\"wrong\"}\n").unwrap();
        assert!(matches!(
            recover_prepared_receipts(&receipt, &summary, &package, &shared(&[9; 32])),
            Err(Error::InvalidBundle)
        ));
        assert!(!receipt.exists());
        assert!(!summary.exists());
        fs::remove_file(prepared_receipt_path).unwrap();
        fs::remove_file(prepared_summary_path).unwrap();
    }

    #[test]
    fn recovered_receipt_requires_every_publication_field() {
        let package = PackageSummary {
            root: [10; 32],
            logical_length: 7,
            entries: 1,
        };
        let key = shared(&[9; 32]);
        let base = publication_receipt(&package, "2026-07-31T23:59:59Z", [5; 32]);
        let mut cases = Vec::new();

        let mut wrong = base.clone();
        wrong.subject_kind = SubjectKind::Object;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.suite_id = 2;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.subject_digest[0] ^= 1;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.subject_length += 1;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.assurance = AssuranceLevel::Durable;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.profile = CommitProfile::Balanced;
        cases.push(wrong);
        let mut wrong = base.clone();
        wrong.actual_predecessor = AssuranceLevel::Durable;
        cases.push(wrong);
        let mut wrong = base;
        wrong.provider = 2;
        cases.push(wrong);

        for (index, wrong) in cases.into_iter().enumerate() {
            let receipt = temporary(&format!("wrong-field-{index}.cbor"));
            let summary = receipt.with_extension("json");
            let authenticated = authenticate_hmac_sha256(wrong, b"vot-cli", &[9; 32]).unwrap();
            fs::write(&receipt, encode_authenticated(&authenticated).unwrap()).unwrap();
            fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
            assert!(matches!(
                validate_receipt_files(&receipt, &summary, &package, &key),
                Err(Error::InvalidBundle)
            ));
            fs::remove_file(receipt).unwrap();
            fs::remove_file(summary).unwrap();
        }

        let receipt = temporary("wrong-key-id.cbor");
        let summary = receipt.with_extension("json");
        let authenticated = authenticate_hmac_sha256(
            publication_receipt(&package, "2026-07-31T23:59:59Z", [5; 32]),
            b"another-key",
            &[9; 32],
        )
        .unwrap();
        fs::write(&receipt, encode_authenticated(&authenticated).unwrap()).unwrap();
        fs::write(&summary, receipt_summary_bytes(&package)).unwrap();
        assert!(matches!(
            validate_receipt_files(&receipt, &summary, &package, &key),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(receipt).unwrap();
        fs::remove_file(summary).unwrap();
    }

    #[test]
    fn live_receipt_preparation_is_not_removed_by_a_contender() {
        let package = PackageSummary {
            root: [7; 32],
            logical_length: 1,
            entries: 1,
        };
        let receipt = temporary("live-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = shared(&[9; 32]);
        let (prepared_receipt, prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        let paths = existing_prepared_receipts(&receipt, &summary, &package, &key)
            .unwrap()
            .unwrap();
        assert!(paths.0.exists());
        assert!(paths.1.exists());
        assert!(matches!(
            existing_prepared_receipts(&receipt, &summary, &package, &shared(&[8; 32])),
            Err(Error::InvalidBundle)
        ));
        assert!(paths.0.exists());
        assert!(paths.1.exists());
        drop((prepared_receipt, prepared_summary));
        assert!(!paths.0.exists());
        assert!(!paths.1.exists());
    }

    #[test]
    fn receipt_file_bounds_are_exact() {
        let left = temporary("bounded-left");
        let right = temporary("bounded-right");
        fs::write(&left, b"same").unwrap();
        fs::write(&right, b"same").unwrap();
        assert!(bounded_files_equal(&left, &right, 4).unwrap());
        assert!(!bounded_files_equal(&left, &right, 3).unwrap());
        fs::write(&right, b"diff").unwrap();
        assert!(!bounded_files_equal(&left, &right, 4).unwrap());
        fs::write(&right, b"short").unwrap();
        assert!(!bounded_files_equal(&left, &right, 5).unwrap());
        fs::write(&left, b"longer").unwrap();
        assert!(!bounded_files_equal(&left, &right, 5).unwrap());

        fs::write(&left, b"same").unwrap();
        fs::write(&right, b"same").unwrap();
        assert!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::AlreadyExists),
                &left,
                &right,
                4
            )
            .is_ok()
        );
        assert!(matches!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::PermissionDenied),
                &left,
                &right,
                4
            ),
            Err(Error::Io(_))
        ));
        fs::write(&right, b"nope").unwrap();
        assert!(matches!(
            resolve_link_error(
                io::Error::from(io::ErrorKind::AlreadyExists),
                &left,
                &right,
                4
            ),
            Err(Error::DestinationExists)
        ));
        fs::remove_file(left).unwrap();
        fs::remove_file(right).unwrap();
    }

    #[test]
    fn prepared_cleanup_is_idempotent_but_preserves_real_errors() {
        let path = temporary("remove-preparation");
        remove_preparation(&path).unwrap();
        fs::write(&path, b"prepared").unwrap();
        remove_preparation(&path).unwrap();
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        assert!(matches!(remove_preparation(&path), Err(Error::Io(_))));
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn verified_pack_can_be_reloaded_after_cache_eviction() {
        let source = temporary("repeated-pack-source");
        let bundle = temporary("repeated-pack-bundle");
        let destination = temporary("repeated-pack-destination");
        let receipt = temporary("repeated-pack-receipt.cbor");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a"), [0x11]).unwrap();
        fs::write(source.join("b"), vec![0x31; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("c"), [0x22]).unwrap();
        fs::write(source.join("d"), vec![0x32; CANDIDATE_MAX + 1]).unwrap();
        fs::write(source.join("e"), [0x11]).unwrap();
        build_bundle(&source, &bundle).unwrap();
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &shared(&[7; 32]),
            "2026-07-31T23:59:59Z",
        )
        .unwrap();
        assert_eq!(fs::read(destination.join("a")).unwrap(), [0x11]);
        assert_eq!(fs::read(destination.join("c")).unwrap(), [0x22]);
        assert_eq!(fs::read(destination.join("e")).unwrap(), [0x11]);

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(receipt.with_extension("json")).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn repeated_direct_object_is_reverified_before_copy() {
        let object = temporary("repeated-direct-object");
        let first = temporary("repeated-direct-first");
        let second = temporary("repeated-direct-second");
        let bytes = vec![0x5a; CANDIDATE_MAX + 1];
        let root = vot_verifier::root(Suite::Sha256Bep52, &bytes).unwrap();
        fs::write(&object, &bytes).unwrap();
        let limit = (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64;
        let mut receiver = ReliableReceiver::new(
            limit,
            MAX_DATA_RECORD_BYTES as u64,
            MAX_DATA_RECORD_BYTES as u64,
        )
        .unwrap();
        receive_direct(
            &object,
            &first,
            root,
            bytes.len() as u64,
            Suite::Sha256Bep52,
            &mut receiver,
        )
        .unwrap();
        let mut corrupted = bytes;
        corrupted[0] ^= 1;
        fs::write(&object, corrupted).unwrap();
        assert!(matches!(
            receive_direct(
                &object,
                &second,
                root,
                fs::metadata(&object).unwrap().len(),
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::RootMismatch)
        ));
        fs::remove_file(object).unwrap();
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }

    #[test]
    fn suite_parser_accepts_every_public_alias() {
        assert_eq!(parse_suite("blake3").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("blake3-bao64").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("1").unwrap(), Suite::Blake3Bao64);
        assert_eq!(parse_suite("sha256").unwrap(), Suite::Sha256Bep52);
        assert_eq!(parse_suite("sha256-bep52").unwrap(), Suite::Sha256Bep52);
        assert_eq!(parse_suite("2").unwrap(), Suite::Sha256Bep52);
        assert!(matches!(
            parse_suite("unknown"),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn copying_an_object_names_it_and_refuses_a_length_that_moved() {
        let directory = temporary("copy-objects");
        fs::create_dir_all(&directory).unwrap();
        let source = temporary("copy-source");
        let data = b"copy-and-name";
        fs::write(&source, data).unwrap();
        let root = vot_verifier::root(Suite::Sha256Bep52, data).unwrap();

        // The pass names what it copied, and what it wrote is the source.
        let copied =
            copy_and_name(&directory, &source, data.len() as u64, Suite::Sha256Bep52).unwrap();
        assert_eq!(copied.root, root, "the copy named something else");
        assert_eq!(fs::read(&copied.temporary).unwrap(), data);
        fs::remove_file(&copied.temporary).unwrap();

        // A source that is not the length the manifest pass saw is a source
        // that moved, and the partial copy does not outlive the failure.
        assert!(matches!(
            copy_and_name(
                &directory,
                &source,
                data.len() as u64 + 1,
                Suite::Sha256Bep52
            ),
            Err(Error::SourceMutation)
        ));
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            0,
            "a failed copy left its bytes behind"
        );
        fs::remove_file(source).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_auditor_with_only_the_public_key_can_check_a_receipt() {
        // The whole reason receipts moved to Ed25519. The issuer publishes with
        // a private key; the auditor holds only the public half.
        let issuer = SigningKey::from_bytes(&[42; 32]);
        let signing = KeyMaterial::Signing(Box::new(issuer.clone()));
        let auditing = KeyMaterial::Verifying(Box::new(issuer.verifying_key()));

        let package = PackageSummary {
            root: [0x33; 32],
            logical_length: 4096,
            entries: 1,
        };
        let receipt_path = temporary("auditor-receipt.cbor");
        let authenticated = signing
            .sign(publication_receipt(
                &package,
                "2026-08-02T00:00:00Z",
                [5; 32],
            ))
            .unwrap();
        fs::write(&receipt_path, encode_authenticated(&authenticated).unwrap()).unwrap();

        let verified = verify_receipt_file(&receipt_path, &auditing).unwrap();
        assert_eq!(verified.root, package.root);
        assert_eq!(verified.logical_length, package.logical_length);
        assert_eq!(verified.assurance, AssuranceLevel::Published);
        assert!(verified.third_party_verifiable);

        // A signature only says who wrote the receipt. An observation that is
        // not a package publication must not print as one, however valid the
        // signature over it is.
        for wrong in [
            Receipt {
                subject_kind: SubjectKind::Object,
                ..authenticated.receipt.clone()
            },
            Receipt {
                assurance: AssuranceLevel::TransitVerified,
                ..authenticated.receipt.clone()
            },
            Receipt {
                actual_predecessor: AssuranceLevel::Admitted,
                ..authenticated.receipt.clone()
            },
            Receipt {
                profile: CommitProfile::Strict,
                ..authenticated.receipt.clone()
            },
            Receipt {
                suite_id: 2,
                ..authenticated.receipt.clone()
            },
            Receipt {
                provider: 2,
                ..authenticated.receipt.clone()
            },
        ] {
            let path = temporary("wrong-observation.cbor");
            let signed = signing.sign(wrong).unwrap();
            fs::write(&path, encode_authenticated(&signed).unwrap()).unwrap();
            assert!(
                matches!(
                    verify_receipt_file(&path, &auditing),
                    Err(Error::InvalidBundle)
                ),
                "a non-publication observation was accepted"
            );
            fs::remove_file(&path).unwrap();
        }

        // The auditor cannot produce one, which is the point.
        assert!(matches!(
            auditing.sign(publication_receipt(
                &package,
                "2026-08-02T00:00:00Z",
                [5; 32]
            )),
            Err(Error::InvalidArguments)
        ));

        // Another issuer's public key does not verify it.
        let stranger = SigningKey::from_bytes(&[43; 32]);
        let wrong = KeyMaterial::Verifying(Box::new(stranger.verifying_key()));
        assert!(matches!(
            verify_receipt_file(&receipt_path, &wrong),
            Err(Error::InvalidBundle)
        ));

        // A shared secret checks, but says so, because that result means
        // nothing to a third party.
        let secret = shared(&[9; 32]);
        let maced = temporary("auditor-hmac.cbor");
        fs::write(
            &maced,
            encode_authenticated(
                &secret
                    .sign(publication_receipt(
                        &package,
                        "2026-08-02T00:00:00Z",
                        [5; 32],
                    ))
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            !verify_receipt_file(&maced, &secret)
                .unwrap()
                .third_party_verifiable
        );
        // And the two schemes do not check each other.
        assert!(matches!(
            verify_receipt_file(&maced, &auditing),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            verify_receipt_file(&receipt_path, &secret),
            Err(Error::InvalidBundle)
        ));

        fs::remove_file(&receipt_path).unwrap();
        fs::remove_file(&maced).unwrap();
    }

    #[test]
    fn a_verifier_only_key_is_refused_before_anything_is_staged() {
        // Failing at signing time would already have copied the whole bundle
        // into staging, and nothing removes that tree, so every retry would
        // leave another hidden copy of the package on disk.
        let source = temporary("verify-only-src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("asset.bin"), vec![7; 4096]).unwrap();
        let bundle = temporary("verify-only.bundle");
        build_bundle(&source, &bundle).unwrap();

        let destination = temporary("verify-only-dest");
        let receipt = temporary("verify-only-receipt.cbor");
        let auditing =
            KeyMaterial::Verifying(Box::new(SigningKey::from_bytes(&[42; 32]).verifying_key()));
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &auditing,
                "2026-08-02T00:00:00Z"
            ),
            Err(Error::InvalidArguments)
        ));

        // No staging tree, no destination, no receipt.
        assert!(!staging_path(&destination).unwrap().exists());
        assert!(!destination.exists());
        assert!(!receipt.exists());

        // The same call with a signing key does publish, so the refusal is
        // about the key material and not about the bundle.
        let signing = KeyMaterial::Signing(Box::new(SigningKey::from_bytes(&[42; 32])));
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &signing,
            "2026-08-02T00:00:00Z",
        )
        .unwrap();
        assert!(receipt.exists());

        fs::remove_dir_all(&source).unwrap();
        fs::remove_dir_all(&destination).unwrap();
        fs::remove_dir_all(&bundle).unwrap();
        fs::remove_file(&receipt).unwrap();
        fs::remove_file(receipt.with_extension("json")).unwrap();
    }

    #[test]
    fn a_verifier_only_key_can_finish_an_interrupted_publication() {
        // Recovery only checks a receipt that is already signed, so refusing
        // the public key here would strand an operator who holds nothing else
        // with a published destination and no way to finalise its receipt.
        let source = temporary("verify-only-recover-src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("asset.bin"), vec![3; 4096]).unwrap();
        let bundle = temporary("verify-only-recover.bundle");
        build_bundle(&source, &bundle).unwrap();

        let destination = temporary("verify-only-recover-dest");
        let receipt = temporary("verify-only-recover-receipt.cbor");
        let summary = receipt.with_extension("json");
        let signing = SigningKey::from_bytes(&[42; 32]);
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &KeyMaterial::Signing(Box::new(signing.clone())),
            "2026-08-02T00:00:00Z",
        )
        .unwrap();

        // Put the run back into the state a crash between the rename and the
        // receipt finalisation leaves behind.
        let package = scan_manifest(&bundle).unwrap();
        let (prepared_receipt, prepared_summary) =
            prepared_receipt_paths(&receipt, &summary, &package).unwrap();
        fs::rename(&receipt, &prepared_receipt).unwrap();
        fs::rename(&summary, &prepared_summary).unwrap();

        let auditing = KeyMaterial::Verifying(Box::new(signing.verifying_key()));
        let report = receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &auditing,
            "2026-08-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(report.peak_staging, 0);
        assert!(receipt.exists());
        assert!(summary.exists());
        assert!(!prepared_receipt.exists());
        assert!(!prepared_summary.exists());

        fs::remove_dir_all(&source).unwrap();
        fs::remove_dir_all(&destination).unwrap();
        fs::remove_dir_all(&bundle).unwrap();
        fs::remove_file(&receipt).unwrap();
        fs::remove_file(&summary).unwrap();
    }

    #[test]
    fn a_verifier_only_key_reuses_a_prepared_receipt_when_publication_never_happened() {
        // Crashing after the receipt was prepared but before the staging rename
        // leaves a signed receipt and no destination. The rerun copies the
        // bundle again but signs nothing, so the public key is enough.
        let source = temporary("verify-only-reuse-src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("asset.bin"), vec![5; 4096]).unwrap();
        let bundle = temporary("verify-only-reuse.bundle");
        build_bundle(&source, &bundle).unwrap();

        let destination = temporary("verify-only-reuse-dest");
        let receipt = temporary("verify-only-reuse-receipt.cbor");
        let summary = receipt.with_extension("json");
        let signing = SigningKey::from_bytes(&[42; 32]);
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &KeyMaterial::Signing(Box::new(signing.clone())),
            "2026-08-02T00:00:00Z",
        )
        .unwrap();

        let package = scan_manifest(&bundle).unwrap();
        let (prepared_receipt, prepared_summary) =
            prepared_receipt_paths(&receipt, &summary, &package).unwrap();
        fs::rename(&receipt, &prepared_receipt).unwrap();
        fs::rename(&summary, &prepared_summary).unwrap();
        fs::remove_dir_all(&destination).unwrap();

        let auditing = KeyMaterial::Verifying(Box::new(signing.verifying_key()));
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &auditing,
            "2026-08-02T00:00:00Z",
        )
        .unwrap();
        assert!(destination.exists());
        assert!(receipt.exists());
        assert!(!prepared_receipt.exists());
        assert!(!prepared_summary.exists());
        // The reused receipt is the one that was signed, not a new one.
        validate_receipt_files(&receipt, &summary, &package, &auditing).unwrap();

        fs::remove_dir_all(&source).unwrap();
        fs::remove_dir_all(&destination).unwrap();
        fs::remove_dir_all(&bundle).unwrap();
        fs::remove_file(&receipt).unwrap();
        fs::remove_file(&summary).unwrap();
    }

    #[test]
    fn ed25519_key_specs_are_labelled_and_exact() {
        let seed = "ab".repeat(32);
        let secret_path = temporary("ed-secret");
        fs::write(&secret_path, format!("{SECRET_KEY_PREFIX}{seed}\n")).unwrap();
        let loaded = load_key_spec(secret_path.to_str().unwrap()).unwrap();
        assert!(matches!(loaded, KeyMaterial::Signing(_)));
        assert!(loaded.is_third_party_verifiable());
        fs::remove_file(&secret_path).unwrap();

        let public = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        let public_hex = public.iter().fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
        let public_path = temporary("ed-public");
        fs::write(&public_path, format!("{PUBLIC_KEY_PREFIX}{public_hex}\n")).unwrap();
        let loaded = load_key_spec(public_path.to_str().unwrap()).unwrap();
        assert!(matches!(loaded, KeyMaterial::Verifying(_)));
        fs::remove_file(&public_path).unwrap();

        // Wrong length, bad hex, and a public key that is not on the curve.
        // One hex digit either side of exactly 32 bytes, so the length check
        // is observed at its edge rather than only far from it.
        for bad in [
            // Empty is the dangerous one: without a length check it would zip
            // over nothing and hand back an all-zero key.
            SECRET_KEY_PREFIX.to_owned(),
            PUBLIC_KEY_PREFIX.to_owned(),
            format!("{SECRET_KEY_PREFIX}{}", "ab".repeat(17)),
            format!("{SECRET_KEY_PREFIX}{}", "a".repeat(63)),
            format!("{SECRET_KEY_PREFIX}{}", "a".repeat(65)),
            format!("{SECRET_KEY_PREFIX}{}", "ab".repeat(31)),
            format!("{SECRET_KEY_PREFIX}{}", "ab".repeat(33)),
            format!("{SECRET_KEY_PREFIX}{}", "zz".repeat(32)),
        ] {
            let path = temporary("ed-bad");
            fs::write(&path, &bad).unwrap();
            assert!(
                load_key_spec(path.to_str().unwrap()).is_err(),
                "accepted {bad}"
            );
            fs::remove_file(&path).unwrap();
        }

        // A shared secret is still shared, and is not third-party verifiable.
        assert!(!shared(&[9; 32]).is_third_party_verifiable());

        // Pin the decoding itself. Loading a key that succeeds proves nothing
        // about which key was loaded, and a wrong key would sign receipts
        // nobody can check against the public half that was published.
        let expected: [u8; ED25519_KEY_BYTES] =
            std::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let encoded = expected.iter().fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
        assert_eq!(decode_fixed_key(&encoded).unwrap(), expected);
        assert_eq!(decode_fixed_key(&"ff".repeat(32)).unwrap(), [0xff; 32]);
        assert_eq!(decode_fixed_key(&"0f".repeat(32)).unwrap(), [0x0f; 32]);
        assert_eq!(decode_fixed_key(&"f0".repeat(32)).unwrap(), [0xf0; 32]);
    }

    #[test]
    fn key_decoder_is_strict_and_bounded() {
        // The longest legal source is the longest prefix, a maximum length
        // shared secret in hex, and a trailing newline.
        assert_eq!(MAX_KEY_SOURCE_BYTES, SECRET_KEY_PREFIX.len() + 128 + 1);
        assert_eq!(MAX_KEY_SOURCE_BYTES, 144);
        // Every key spec has to fit inside it.
        for spec in [
            format!("{SECRET_KEY_PREFIX}{}", "ab".repeat(32)),
            format!("{PUBLIC_KEY_PREFIX}{}", "ab".repeat(32)),
            format!("{HEX_KEY_PREFIX}{}", "ab".repeat(64)),
            format!("{RAW_KEY_PREFIX}{}", "a".repeat(64)),
        ] {
            assert!(spec.len() < MAX_KEY_SOURCE_BYTES, "{spec} does not fit");
        }
        assert!(decode_key(&"ab".repeat(34)).is_ok());
        assert_eq!(decode_key(&"ab".repeat(64)).unwrap(), vec![0xab; 64]);
        assert!(matches!(
            decode_key(&"ab".repeat(65)),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            decode_key(&"a".repeat(65)),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(decode_key(&"00".repeat(32)).unwrap(), vec![0; 32]);
        assert!(matches!(decode_key("0"), Err(Error::InvalidArguments)));
        assert!(matches!(
            decode_key(&"gg".repeat(32)),
            Err(Error::InvalidArguments)
        ));
        assert!(matches!(
            decode_key(&"00".repeat(31)),
            Err(Error::InvalidArguments)
        ));
        assert_eq!(
            decode_key(&"0123456789abcdef".repeat(4)).unwrap(),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ]
        );
        assert_eq!(
            decode_key(&format!("{}0000", "ABCDEF".repeat(10))).unwrap()[..3],
            [0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn key_spec_loader_decodes_hex_and_preserves_raw_keys() {
        let hex_path = temporary("hex-key");
        fs::write(&hex_path, format!("hex:{}\n", "ab".repeat(32))).unwrap();
        assert_eq!(
            loaded_secret(&load_key_spec(hex_path.to_str().unwrap()).unwrap()),
            vec![0xab; 32]
        );
        fs::remove_file(&hex_path).unwrap();

        let raw_path = temporary("raw-key");
        fs::write(&raw_path, [7; 32]).unwrap();
        assert_eq!(
            loaded_secret(&load_key_spec(raw_path.to_str().unwrap()).unwrap()),
            vec![7; 32]
        );
        fs::remove_file(&raw_path).unwrap();

        let ambiguous_path = temporary("ambiguous-raw-key");
        fs::write(&ambiguous_path, [b'a'; 64]).unwrap();
        assert_eq!(
            loaded_secret(&load_key_spec(ambiguous_path.to_str().unwrap()).unwrap()),
            vec![b'a'; 64]
        );
        fs::remove_file(&ambiguous_path).unwrap();

        let short_path = temporary("short-key");
        fs::write(&short_path, [7; 31]).unwrap();
        assert!(matches!(
            load_key_spec(short_path.to_str().unwrap()),
            Err(Error::InvalidArguments)
        ));
        fs::remove_file(&short_path).unwrap();

        let oversized_path = temporary("oversized-key");
        fs::write(&oversized_path, [7; 65]).unwrap();
        assert!(matches!(
            load_key_spec(oversized_path.to_str().unwrap()),
            Err(Error::InvalidArguments)
        ));
        fs::remove_file(oversized_path).unwrap();
    }

    #[test]
    fn key_source_limit_is_exact_and_reads_are_bounded() {
        assert!(validate_key_source_length(MAX_KEY_SOURCE_BYTES).is_ok());
        assert!(matches!(
            validate_key_source_length(MAX_KEY_SOURCE_BYTES + 1),
            Err(Error::InvalidArguments)
        ));

        let exact = read_key_source(io::Cursor::new(vec![7; MAX_KEY_SOURCE_BYTES])).unwrap();
        assert_eq!(exact.len(), MAX_KEY_SOURCE_BYTES);
        assert!(matches!(
            read_key_source(io::Cursor::new(vec![7; MAX_KEY_SOURCE_BYTES + 1])),
            Err(Error::InvalidArguments)
        ));
    }

    #[test]
    fn package_boundaries_and_conflicts_are_exact() {
        let missing = temporary("missing-source");
        let bundle = temporary("existing-bundle");
        fs::create_dir(&bundle).unwrap();
        assert!(matches!(
            build_bundle(&missing, &temporary("missing-bundle")),
            Err(Error::InvalidArguments)
        ));

        let source = temporary("conflict-source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"content").unwrap();
        assert!(matches!(
            build_bundle(&source, &bundle),
            Err(Error::InvalidArguments)
        ));
        let new_bundle = temporary("conflict-bundle");
        build_bundle(&source, &new_bundle).unwrap();
        let destination = temporary("existing-destination");
        fs::create_dir(&destination).unwrap();
        let receipt = temporary("conflict-receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &new_bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));
        fs::remove_dir(&destination).unwrap();
        fs::write(&receipt, b"exists").unwrap();
        assert!(matches!(
            receive_bundle(
                &new_bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::DestinationExists)
        ));

        fs::remove_dir(bundle).unwrap();
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(new_bundle).unwrap();
        fs::remove_file(receipt).unwrap();
    }

    #[test]
    fn existing_destination_must_match_before_receipt_recovery() {
        let source = temporary("recovery-validation-source");
        let bundle = temporary("recovery-validation-bundle");
        let destination = temporary("recovery-validation-destination");
        let receipt = temporary("recovery-validation-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = shared(&[9; 32]);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("expected"), b"verified contents").unwrap();
        let package = build_bundle(&source, &bundle).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("unrelated"), b"wrong contents").unwrap();
        let (mut prepared_receipt, mut prepared_summary) =
            prepared_evidence(&receipt, &summary, &package, &key);
        prepared_receipt.preserve_for_recovery();
        prepared_summary.preserve_for_recovery();
        let prepared_receipt = prepared_receipt.path().unwrap();
        let prepared_summary = prepared_summary.path().unwrap();

        assert!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &key,
                "2026-07-31T23:59:59Z",
            )
            .is_err()
        );
        assert!(!receipt.exists());
        assert!(!summary.exists());
        assert!(prepared_receipt.exists());
        assert!(prepared_summary.exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(prepared_receipt).unwrap();
        fs::remove_file(prepared_summary).unwrap();
    }

    #[test]
    fn published_destination_validation_checks_every_boundary() {
        let source = temporary("published-validation-source");
        let bundle = temporary("published-validation-bundle");
        let destination = temporary("published-validation-destination");
        let receipt = temporary("published-validation-receipt.cbor");
        let summary = receipt.with_extension("json");
        let key = shared(&[7; 32]);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("expected"), b"verified contents").unwrap();
        let package = build_bundle(&source, &bundle).unwrap();
        receive_bundle(
            &bundle,
            &destination,
            &receipt,
            &key,
            "2026-07-31T23:59:59Z",
        )
        .unwrap();

        validate_published_destination(&bundle, &destination, &package).unwrap();
        fs::write(destination.join("expected"), b"corruptd contents").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &destination, &package),
            Err(Error::RootMismatch)
        ));
        fs::write(destination.join("expected"), b"verified contents").unwrap();
        fs::write(destination.join("extra"), b"extra").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &destination, &package),
            Err(Error::InvalidBundle)
        ));
        fs::remove_file(destination.join("extra")).unwrap();

        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &key,
                "2026-07-31T23:59:59Z",
            ),
            Err(Error::InvalidBundle)
        ));

        let not_directory = temporary("published-validation-file");
        fs::write(&not_directory, b"file").unwrap();
        assert!(matches!(
            validate_published_destination(&bundle, &not_directory, &package),
            Err(Error::InvalidBundle)
        ));

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_file(summary).unwrap();
        fs::remove_file(not_directory).unwrap();
    }

    #[test]
    fn published_destination_walk_has_exact_depth_and_count_bounds() {
        let single = temporary("published-count-single");
        fs::create_dir(&single).unwrap();
        fs::write(single.join("file"), b"file").unwrap();
        let mut count = 0;
        count_published_files(&single, vot_manifest::MAX_PATH_COMPONENTS, &mut count).unwrap();
        assert_eq!(count, 1);
        assert!(matches!(
            count_published_files(&single, vot_manifest::MAX_PATH_COMPONENTS + 1, &mut count,),
            Err(Error::InvalidBundle)
        ));
        fs::remove_dir_all(single).unwrap();

        let deep = temporary("published-count-deep");
        fs::create_dir_all(deep.join("d")).unwrap();
        assert!(matches!(
            count_published_files(&deep, vot_manifest::MAX_PATH_COMPONENTS, &mut 0),
            Err(Error::InvalidBundle)
        ));
        fs::remove_dir_all(deep).unwrap();
    }

    #[test]
    fn empty_canonical_manifest_cannot_publish() {
        let bundle = temporary("empty-canonical-bundle");
        let manifest_directory = bundle.join(MANIFEST_DIRECTORY);
        fs::create_dir_all(&manifest_directory).unwrap();
        let package = PackageRootBuilder::new().unwrap().finish().unwrap();
        let mut manifest_id = [0; 16];
        manifest_id.copy_from_slice(&package.root[..16]);
        let page = ManifestPage {
            manifest_id,
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: Vec::new(),
        };
        let encoded_page = encode_page(&page).unwrap();
        let page_digest = *blake3::hash(&encoded_page).as_bytes();
        let seal = Seal {
            manifest_id,
            final_page_count: 1,
            final_page_digest: page_digest,
            package: ObjectId {
                suite: 1,
                root: package.root,
                length: 0,
            },
            pages: vec![PageCommitment {
                index: 0,
                digest: page_digest,
            }],
        };
        fs::write(manifest_page_path(&manifest_directory, 0), encoded_page).unwrap();
        fs::write(
            manifest_directory.join(MANIFEST_SEAL),
            encode_seal(&seal).unwrap(),
        )
        .unwrap();
        let destination = temporary("empty-canonical-destination");
        let receipt = temporary("empty-canonical-receipt.cbor");
        assert!(matches!(
            receive_bundle(
                &bundle,
                &destination,
                &receipt,
                &shared(&[7; 32]),
                "2026-07-31T23:59:59Z"
            ),
            Err(Error::InvalidBundle)
        ));
        assert!(!destination.exists());
        assert!(!receipt.exists());
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn helpers_enforce_exact_bounds_and_identity() {
        let directory = temporary("objects");
        fs::create_dir(&directory).unwrap();
        let root = [3; 32];
        write_object(&directory, &root, b"bytes").unwrap();
        write_object(&directory, &root, b"bytes").unwrap();
        assert!(matches!(
            write_object(&directory, &root, b"other"),
            Err(Error::RootMismatch)
        ));

        let over = directory.join("over");
        fs::write(&over, vec![0; 5]).unwrap();
        assert_eq!(read_bounded_file(&over, 5).unwrap(), vec![0; 5]);
        assert!(matches!(
            read_bounded_file(&over, 4),
            Err(Error::InvalidBundle)
        ));

        assert_eq!(parent_directory(Path::new("receipt")), Path::new("."));
        assert_eq!(
            parent_directory(Path::new("nested/receipt")),
            Path::new("nested")
        );
        let cached = (Suite::Sha256Bep52, [5; 32], 9, Vec::new());
        assert!(!pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [5; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Blake3Bao64,
            [5; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [6; 32],
            9
        ));
        assert!(pack_needs_load(
            Some(&cached),
            Suite::Sha256Bep52,
            [5; 32],
            10
        ));
        assert!(pack_needs_load(None, Suite::Sha256Bep52, [5; 32], 9));

        let mut receiver = ReliableReceiver::new(
            (MAX_DATA_RECORD_BYTES + vot_verifier::GROUP_SIZE) as u64,
            MAX_DATA_RECORD_BYTES as u64,
            MAX_DATA_RECORD_BYTES as u64,
        )
        .unwrap();
        assert!(matches!(
            receive_object(
                Path::new("does-not-exist"),
                [0; 32],
                vot_pack::HARD_MAX as u64 + 1,
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            receive_object(
                Path::new("does-not-exist"),
                [0; 32],
                vot_pack::HARD_MAX as u64,
                Suite::Sha256Bep52,
                &mut receiver
            ),
            Err(Error::Io(_))
        ));
        let short = directory.join("short");
        fs::write(&short, b"x").unwrap();
        assert!(matches!(
            receive_object(&short, [0; 32], 2, Suite::Sha256Bep52, &mut receiver),
            Err(Error::InvalidBundle)
        ));
        fs::create_dir(directory.join("nested")).unwrap();
        assert_eq!(sync_directories(&directory).unwrap(), 2);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn manifest_record_validation_rejects_each_wrong_field() {
        let logical = ObjectId {
            suite: 2,
            root: [3; 32],
            length: 3,
        };
        let direct = ManifestEntry {
            path: PackagePath::portable(["file"]).unwrap(),
            kind: EntryKind::File,
            length: Some(3),
            storage: Some(StorageRef::Direct(logical.clone())),
            metadata: None,
        };
        assert!(EntryRecord::from_manifest(direct.clone()).is_ok());

        let mut wrong = direct.clone();
        wrong.kind = EntryKind::Directory;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.metadata = Some(vot_manifest::FileMetadata::default());
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.length = None;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = None;
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            suite: 1,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_ok());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            suite: 99,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_err());
        wrong = direct.clone();
        wrong.storage = Some(StorageRef::Direct(ObjectId {
            length: 2,
            ..logical.clone()
        }));
        assert!(EntryRecord::from_manifest(wrong).is_err());

        let pack = ObjectId {
            suite: 2,
            root: [4; 32],
            length: 8,
        };
        let packed = |pack: ObjectId, length: u64, logical: ObjectId| ManifestEntry {
            storage: Some(StorageRef::Pack {
                pack,
                offset: 0,
                length,
                logical,
            }),
            ..direct.clone()
        };
        assert!(EntryRecord::from_manifest(packed(pack.clone(), 3, logical.clone())).is_ok());
        assert!(
            EntryRecord::from_manifest(packed(
                ObjectId {
                    suite: 1,
                    ..pack.clone()
                },
                3,
                logical.clone()
            ))
            .is_err()
        );
        assert!(
            EntryRecord::from_manifest(packed(
                pack.clone(),
                3,
                ObjectId {
                    suite: 1,
                    ..logical.clone()
                }
            ))
            .is_err()
        );
        assert!(EntryRecord::from_manifest(packed(pack.clone(), 2, logical.clone())).is_err());
        assert!(
            EntryRecord::from_manifest(packed(
                pack,
                3,
                ObjectId {
                    length: 2,
                    ..logical
                }
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_envelope_checks_are_exact() {
        let mut page = ManifestPage {
            manifest_id: [1; 16],
            index: 0,
            total: None,
            previous_digest: [0; 32],
            profile: PathProfile::Portable,
            entries: Vec::new(),
        };
        let seal = Seal {
            manifest_id: [1; 16],
            final_page_count: 1,
            final_page_digest: [2; 32],
            package: ObjectId {
                suite: 1,
                root: [3; 32],
                length: 0,
            },
            pages: vec![PageCommitment {
                index: 0,
                digest: [2; 32],
            }],
        };
        let mut commitment = seal.pages[0].clone();
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_ok());
        page.manifest_id = [9; 16];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.manifest_id = seal.manifest_id;
        page.index = 1;
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.index = 0;
        page.total = Some(2);
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.total = Some(1);
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_ok());
        page.previous_digest = [8; 32];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        page.previous_digest = [0; 32];
        commitment.index = 1;
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
        commitment.index = 0;
        commitment.digest = [7; 32];
        assert!(validate_page_envelope(&page, &seal, &commitment, 0, [0; 32], [2; 32]).is_err());
    }
}
