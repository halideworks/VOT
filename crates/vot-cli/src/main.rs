use std::path::Path;

const USAGE: &str = "\
vot - verified object transfer

Usage:
  vot send [SUITE] SOURCE_DIR BUNDLE_DIR
  vot receive BUNDLE_DIR DESTINATION_DIR RECEIPT.cbor KEY_SOURCE OBSERVED_AT
  vot verify-receipt RECEIPT.cbor KEY_SOURCE

SUITE is blake3 or sha256. The default is sha256.
OBSERVED_AT is an RFC 3339 timestamp, for example 2026-07-31T20:00:00Z.

KEY_SOURCE says where to read the key from:
  env:NAME     an environment variable
  -            standard input
  PATH         a file

What it reads decides the kind of key. An Ed25519 key is labelled, because a
secret and a public key are both 32 bytes and using one as the other would
either leak the secret or produce receipts nobody can check:
  ed25519-secret:HEX   signs, 64 hex characters. receive only.
  ed25519-public:HEX   checks a signature, 64 hex characters
  hex:HEX              shared secret, 32 to 64 bytes
  raw:TEXT             shared secret as text
  anything else        shared secret as raw bytes, 32 to 64 bytes

A receipt signed with ed25519-secret can be checked by anyone holding only the
matching ed25519-public key. A shared secret cannot: whoever can check it can
also forge it, so verify-receipt reports SHARED-SECRET rather than
THIRD-PARTY-VERIFIABLE.
";

fn main() {
    if let Err(error) = run() {
        eprintln!("vot: {error:?}");
        eprintln!();
        eprintln!("{USAGE}");
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
        _ => Err(vot_cli::Error::InvalidArguments),
    }
}

fn root_hex(root: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in root {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}
