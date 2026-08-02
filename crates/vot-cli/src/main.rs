use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("vot: {error:?}");
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
