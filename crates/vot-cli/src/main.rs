use std::path::Path;

const USAGE: &str = "\
vot - verified object transfer

Usage:
  vot send [SUITE] SOURCE_DIR BUNDLE_DIR
  vot receive BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE OBSERVED_AT
  vot verify-receipt RECEIPT.cbor KEY_SOURCE
  vot serve BUNDLE_DIR LISTEN_ADDR [CERT.pem KEY.pem]
  vot rendezvous LISTEN_ADDR
  vot relay LISTEN_ADDR
  vot capability keygen
  vot capability issue ISSUER_KEY_SOURCE ISSUER AUDIENCE HOLDER_PUBLIC
                       PACKAGE_ROOT SECONDS OUT.cbor
  vot fetch CONNECT_ADDR BUNDLE_DIR PACKAGE_ROOT
  vot fetch ROOT BUNDLE_DIR
  vot pull CONNECT_ADDR BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE
           OBSERVED_AT PACKAGE_ROOT
  vot pull ROOT BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE OBSERVED_AT

serve and fetch move a bundle over the wire; fetch writes a bundle directory
that receive consumes unchanged, and pull is the two in one invocation.
They need a build with the wire feature and report so without one.

The server's identity is not verified unless you pin it. The server presents
a throwaway certificate by default, so anyone in the middle can see which
root you ask for and can refuse to serve it. What they cannot do is give you
different bytes: every range proves to its object's root, every root is named
by the manifest, and the manifest proves to the seal. To also refuse an
imposter before asking, set VOT_FETCH_SERVE_IDENTITY to the identity line
serve prints; the fetch then drops any connection whose certificate digest
differs, before it sends anything.

That holds only for the package you named. A fetch at an address takes a
PACKAGE_ROOT, the 64 hex characters send printed, and refuses without one;
serve prints the whole fetch command for the bundle it is serving. A ROOT in
the address position pins itself. VOT_FETCH_UNPINNED=1 fetches from a server
whose package cannot be known in advance.

A serve requires a capability when VOT_SERVE_ISSUER, VOT_SERVE_ISSUER_NAME,
and VOT_SERVE_AUDIENCE are all set, and requires none when none of them is.
A fetch presents one when VOT_FETCH_CAPABILITY and VOT_FETCH_HOLDER_KEY are
both set. `capability keygen` makes a holder a key, and `capability issue`
mints a token for one package under an issuer key. Every key there is a
KEY_SOURCE, so it says where to read a key from rather than being one.

What the token decides is that whoever opened the session holds the key it
names on the TLS session carrying the request. The proof covers the session
challenge and the TLS exporter value, so an attacker that terminates TLS has a
different binding and cannot forward the proof. Capability authentication fails
closed on a carrier without that exporter. The exporter does not authenticate
the serve's identity to the fetch; anonymous mode authenticates received content
against the trusted root instead. See ADR-0037.

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

A relay forwards datagrams between two ends that cannot punch, and reads none
of them: it sees ciphertext, two addresses, and byte counts. VOT_RELAY_SLOTS,
VOT_RELAY_TTL_MS, and VOT_RELAY_BYTES bound what one donates. See ADR-0034.

A ROOT in the address position is resolved through the rendezvous service
VOT_RENDEZVOUS names, as ADDR:PORT or NAME:PORT. There is no default: point
it at whatever service the two ends share, which `vot rendezvous` runs.
Both ends must name the same one.
";

const UNPINNED_HELP: &str = "\
An address says where to fetch from, not what to fetch.

The channel is not authenticated. Without a PACKAGE_ROOT, a server can hand
you a different package and every range will still prove, to whatever root
that package declares. The root is what makes the proofs mean the package you
asked for.

  vot fetch CONNECT_ADDR BUNDLE_DIR PACKAGE_ROOT

The root is the 64 hex characters `vot send` printed. `vot serve` prints the
whole fetch command for the bundle it is serving, so the end that has the
bundle can hand over one line. A root in the address position needs nothing
further: it is resolved through the rendezvous and pins itself.

Set VOT_FETCH_UNPINNED=1 to fetch from a server whose package you cannot know
in advance.
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
        // Its own text, because the answer is a value the caller has to go
        // and get rather than an argument they spelled wrong.
        if matches!(error, vot_cli::Error::UnpinnedFetch) {
            eprintln!();
            eprintln!("{UNPINNED_HELP}");
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
        [_, command, address] if command == "relay" => relay(address),
        [_, command, sub] if command == "capability" && sub == "keygen" => {
            let (secret, public) = vot_cli::generate_keypair()?;
            // The warning goes to stderr so the two lines stdout carries are
            // the two values, and a caller redirecting them still reads it.
            eprintln!("vot: the first line is a secret key. It is printed once.");
            println!("{secret}");
            println!("{public}");
            Ok(())
        }
        [
            _,
            command,
            sub,
            issuer_source,
            issuer,
            audience,
            holder_public,
            root,
            seconds,
            out,
        ] if command == "capability" && sub == "issue" => vot_cli::issue_capability(
            issuer_source,
            issuer,
            audience,
            holder_public,
            root,
            seconds,
            Path::new(out),
        ),
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

/// Forwards datagrams between the two ends of a slot until it is stopped.
fn relay(address: &str) -> Result<(), vot_cli::Error> {
    let address = address
        .parse()
        .map_err(|_| vot_cli::Error::InvalidArguments)?;
    vot_cli::relay_service(address, None, |at| {
        println!("relay {at}");
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
    let package = vot_cli::serve_bundle(
        Path::new(bundle),
        address,
        credentials,
        None,
        |at, root, identity| {
            println!("listening {at}");
            // The whole command, because a fetch has to name the root and
            // this is the only place it is printed while the serve is
            // still up. A reader who has to go and find it is a reader
            // who fetches unpinned.
            println!(
                "fetch it with: vot fetch {} BUNDLE_DIR {}",
                reachable(at),
                root_hex(&root)
            );
            println!(
                "identity {} (pin with VOT_FETCH_SERVE_IDENTITY)",
                root_hex(&identity)
            );
        },
    )?;
    println!(
        "{} {} SERVED",
        root_hex(&package.root),
        package.logical_length
    );
    Ok(())
}

/// Every address the rendezvous service a root-addressed fetch resolves at
/// answers on. Unset is an argument error: nothing resolves a root without
/// one.
fn rendezvous_service_addresses() -> Result<Vec<std::net::SocketAddr>, vot_cli::Error> {
    let named = std::env::var("VOT_RENDEZVOUS").map_err(|_| vot_cli::Error::InvalidArguments)?;
    vot_cli::parse_rendezvous(&named)
}

/// What the address position named: somewhere to fetch from, or a root that
/// pins itself and is resolved through the rendezvous services.
enum Target {
    Address(std::net::SocketAddr),
    Root([u8; 32]),
}

fn parse_target(target: &str) -> Result<Target, vot_cli::Error> {
    if let Ok(address) = target.parse() {
        return Ok(Target::Address(address));
    }
    Ok(Target::Root(vot_cli::parse_package_root(target)?))
}

/// One fetch for both commands. An address takes the existing pin policy; a
/// root pins itself and needs the configured rendezvous services.
fn fetch_target(
    target: &str,
    bundle: &str,
    explicit_pin: Option<&str>,
) -> Result<vot_cli::PackageSummary, vot_cli::Error> {
    match parse_target(target)? {
        Target::Address(address) => vot_cli::fetch_bundle(
            address,
            Path::new(bundle),
            vot_cli::address_pin(explicit_pin)?,
        ),
        Target::Root(root) => {
            let services = rendezvous_service_addresses()?;
            vot_cli::fetch_via_rendezvous(root, Path::new(bundle), &services)
        }
    }
}

fn fetch(target: &str, bundle: &str, root: Option<&str>) -> Result<(), vot_cli::Error> {
    let package = fetch_target(target, bundle, root)?;
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
    fetch_target(target, bundle, root)?;
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

/// How to name this listener in a command someone else runs.
///
/// A wildcard bind answers on every address this host has and is not one of
/// them: `0.0.0.0` reaches this host from this host and nowhere else. Naming
/// it in a fetch command would be an instruction that works where it is
/// printed and fails everywhere it is pasted, so the host part is left for
/// the reader to fill in.
fn reachable(at: std::net::SocketAddr) -> String {
    if at.ip().is_unspecified() {
        format!("THIS_HOST:{}", at.port())
    } else {
        at.to_string()
    }
}

fn root_hex(root: &[u8; 32]) -> String {
    vot_cli::hex_of(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_bind_is_not_an_address_to_hand_out() {
        let named = |text: &str| reachable(text.parse().expect("an address"));
        assert_eq!(named("0.0.0.0:9000"), "THIS_HOST:9000");
        assert_eq!(named("[::]:9000"), "THIS_HOST:9000");
        assert_eq!(named("127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(named("198.51.100.7:9000"), "198.51.100.7:9000");
        assert_eq!(named("[2001:db8::7]:9000"), "[2001:db8::7]:9000");
    }

    #[test]
    fn a_root_is_lowercase_hexadecimal_of_the_whole_root() {
        assert_eq!(root_hex(&[0; 32]), "0".repeat(64));
        assert_eq!(root_hex(&[0xab; 32]), "ab".repeat(32));
        let mut counted = [0_u8; 32];
        counted[31] = 0x0f;
        assert_eq!(root_hex(&counted), format!("{}0f", "00".repeat(31)));
    }
}
