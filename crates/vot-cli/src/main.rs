use std::path::Path;

const USAGE: &str = "\
vot - verified object transfer

Usage:
  vot send [SUITE] SOURCE_DIR BUNDLE_DIR
  vot receive BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE OBSERVED_AT
  vot verify-receipt RECEIPT.cbor KEY_SOURCE
  vot serve BUNDLE_DIR LISTEN_ADDR [CERT.pem KEY.pem]
  vot rendezvous LISTEN_ADDR
  vot fetch CONNECT_ADDR|ROOT BUNDLE_DIR [PACKAGE_ROOT]
  vot pull CONNECT_ADDR|ROOT BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE
           OBSERVED_AT [PACKAGE_ROOT]

serve and fetch move a bundle over the wire; fetch writes a bundle directory
that receive consumes unchanged, and pull is the two in one invocation.
They need a build with the wire feature and report so without one.

The channel is NOT authenticated. The server presents a throwaway certificate
and the client does not verify it, so anyone in the middle can see what you
fetch and can refuse to serve it. What they cannot do is give you different
bytes: every range proves to its object's root, every root is named by the
manifest, and the manifest proves to the seal. Give fetch a PACKAGE_ROOT, as
printed by send, to say which package you will accept.

SUITE is blake3 or sha256. The default is sha256.
OBSERVED_AT is an RFC 3339 timestamp, for example 2026-07-31T20:00:00Z.

KEY_SOURCE says where to read the key from:
  env:NAME     an environment variable
  -            standard input
  PATH         a file

What it reads decides the kind of key. An Ed25519 key is labelled, because a
secret and a public key are both 32 bytes and using one as the other would
either leak the secret or produce receipts nobody can check:
  ed25519-secret:HEX   signs, 64 hex characters. receive and pull only.
  ed25519-public:HEX   checks a signature, 64 hex characters
  hex:HEX              shared secret, 32 to 64 bytes
  raw:TEXT             shared secret as text
  anything else        shared secret as raw bytes, 32 to 64 bytes

A receipt signed with ed25519-secret can be checked by anyone holding only the
matching ed25519-public key. A shared secret cannot: whoever can check it can
also forge it, so verify-receipt reports SHARED-SECRET rather than
THIRD-PARTY-VERIFIABLE.

A ROOT in the address position is resolved through the rendezvous service
VOT_RENDEZVOUS names, as ADDR:PORT or NAME:PORT. There is no default: point
it at whatever service the two ends share, which `vot rendezvous` runs.
Both ends must name the same one.
";

fn main() {
    if let Err(error) = run() {
        eprintln!("vot: {error:?}");
        // The usage text answers an argument the caller got wrong. A
        // carrier that would not bind, a peer that closed, a session that
        // went nowhere: printing it at those buries the reason.
        if matches!(error, vot_cli::Error::InvalidArguments) {
            eprintln!();
            eprintln!("{USAGE}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), vot_cli::Error> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.as_slice() {
        [_, command, source, bundle] if command == "send" => {
            let summary = vot_cli::build_bundle(Path::new(source), Path::new(bundle))?;
            println!("{} {}", root_hex(&summary.root), summary.logical_length);
            Ok(())
        }
        [_, command, suite, source, bundle] if command == "send" => {
            let suite = vot_cli::parse_suite(suite)?;
            let summary =
                vot_cli::build_bundle_with_suite(Path::new(source), Path::new(bundle), suite)?;
            println!("{} {}", root_hex(&summary.root), summary.logical_length);
            Ok(())
        }
        [_, command, bundle, destination, receipt, key, observed_at] if command == "receive" => {
            let key = vot_cli::load_key_spec(key)?;
            let report = vot_cli::receive_bundle(
                Path::new(bundle),
                Path::new(destination),
                Path::new(receipt),
                &key,
                observed_at,
            )?;
            println!(
                "{} {} PUBLISHED",
                root_hex(&report.package.root),
                report.package.logical_length
            );
            Ok(())
        }
        [_, command, receipt, key] if command == "verify-receipt" => {
            let key = vot_cli::load_key_spec(key)?;
            let verified = vot_cli::verify_receipt_file(Path::new(receipt), &key)?;
            println!(
                "{} {} {:?} {}",
                root_hex(&verified.root),
                verified.logical_length,
                verified.assurance,
                if verified.third_party_verifiable {
                    "THIRD-PARTY-VERIFIABLE"
                } else {
                    "SHARED-SECRET"
                }
            );
            Ok(())
        }
        [_, command] if command == "help" || command == "--help" || command == "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        rest => wire_command(rest),
    }
}

/// The commands that move a bundle over the wire.
///
/// Split from [`run`] because the two halves are unrelated: one works a
/// directory this host already has, the other opens a session.
fn wire_command(arguments: &[String]) -> Result<(), vot_cli::Error> {
    match arguments {
        [_, command, address] if command == "rendezvous" => rendezvous(address),
        [_, command, bundle, address] if command == "serve" => {
            serve(bundle, address, &vot_cli::Credentials::Ephemeral)
        }
        [_, command, bundle, address, certificate, key] if command == "serve" => serve(
            bundle,
            address,
            &vot_cli::Credentials::Files {
                certificate: Path::new(certificate).to_path_buf(),
                key: Path::new(key).to_path_buf(),
            },
        ),
        [_, command, address, bundle] if command == "fetch" => fetch(address, bundle, None),
        [_, command, address, bundle, root] if command == "fetch" => {
            fetch(address, bundle, Some(root))
        }
        [
            _,
            command,
            address,
            bundle,
            destination,
            receipt,
            key,
            observed_at,
        ] if command == "pull" => pull(
            address,
            bundle,
            destination,
            receipt,
            key,
            observed_at,
            None,
        ),
        [
            _,
            command,
            address,
            bundle,
            destination,
            receipt,
            key,
            observed_at,
            root,
        ] if command == "pull" => pull(
            address,
            bundle,
            destination,
            receipt,
            key,
            observed_at,
            Some(root),
        ),
        _ => Err(vot_cli::Error::InvalidArguments),
    }
}

/// Runs the rendezvous service until it is stopped.
fn rendezvous(address: &str) -> Result<(), vot_cli::Error> {
    let address = address
        .parse()
        .map_err(|_| vot_cli::Error::InvalidArguments)?;
    vot_cli::rendezvous_service(address, None, |at| {
        println!("rendezvous {at}");
    })
}

/// Answers sessions from one bundle until it is stopped.
fn serve(
    bundle: &str,
    address: &str,
    credentials: &vot_cli::Credentials,
) -> Result<(), vot_cli::Error> {
    let address = address
        .parse()
        .map_err(|_| vot_cli::Error::InvalidArguments)?;
    let package = vot_cli::serve_bundle(Path::new(bundle), address, credentials, None, |at| {
        println!("listening {at}");
    })?;
    println!(
        "{} {} SERVED",
        root_hex(&package.root),
        package.logical_length
    );
    Ok(())
}

/// The rendezvous service a root-addressed fetch resolves at. Unset is an
/// argument error: nothing resolves a root without one.
fn rendezvous_service_address() -> Result<std::net::SocketAddr, vot_cli::Error> {
    let named = std::env::var("VOT_RENDEZVOUS").map_err(|_| vot_cli::Error::InvalidArguments)?;
    vot_cli::parse_rendezvous(&named)
}

fn fetch(target: &str, bundle: &str, root: Option<&str>) -> Result<(), vot_cli::Error> {
    let package = if let Ok(address) = target.parse::<std::net::SocketAddr>() {
        let pin = root.map(vot_cli::parse_package_root).transpose()?;
        vot_cli::fetch_bundle(address, Path::new(bundle), pin)
    } else {
        let parsed_root = vot_cli::parse_package_root(target)?;
        let service = rendezvous_service_address()?;
        vot_cli::fetch_via_rendezvous(parsed_root, Path::new(bundle), service)
    }?;
    println!(
        "{} {} FETCHED",
        root_hex(&package.root),
        package.logical_length
    );
    Ok(())
}

/// Fetch then receive, for the common case.
fn pull(
    target: &str,
    bundle: &str,
    destination: &str,
    receipt: &str,
    key: &str,
    observed_at: &str,
    root: Option<&str>,
) -> Result<(), vot_cli::Error> {
    // The key is loaded before a byte crosses the wire.
    let key = vot_cli::load_key_spec(key)?;
    if let Ok(address) = target.parse::<std::net::SocketAddr>() {
        let pin = root.map(vot_cli::parse_package_root).transpose()?;
        vot_cli::fetch_bundle(address, Path::new(bundle), pin)?;
    } else {
        let parsed_root = vot_cli::parse_package_root(target)?;
        let service = rendezvous_service_address()?;
        vot_cli::fetch_via_rendezvous(parsed_root, Path::new(bundle), service)?;
    }
    let report = vot_cli::receive_bundle(
        Path::new(bundle),
        Path::new(destination),
        Path::new(receipt),
        &key,
        observed_at,
    )?;
    println!(
        "{} {} PUBLISHED",
        root_hex(&report.package.root),
        report.package.logical_length
    );
    Ok(())
}

fn root_hex(root: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in root {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}
