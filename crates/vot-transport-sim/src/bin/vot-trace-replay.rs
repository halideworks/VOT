use std::env;
use std::fs;
use std::process::ExitCode;

use vot_transport_sim::{MAX_SCENARIO_BYTES, Scenario, Simulator};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(path) = arguments.next() else {
        eprintln!("usage: vot-trace-replay SCENARIO");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: vot-trace-replay SCENARIO");
        return ExitCode::from(2);
    }
    let Ok(metadata) = fs::metadata(&path) else {
        eprintln!("unable to read scenario metadata");
        return ExitCode::FAILURE;
    };
    if metadata.len() > MAX_SCENARIO_BYTES as u64 {
        eprintln!("scenario exceeds the input limit");
        return ExitCode::FAILURE;
    }
    let Ok(input) = fs::read_to_string(path) else {
        eprintln!("unable to read scenario");
        return ExitCode::FAILURE;
    };
    let Ok(scenario) = Scenario::parse(&input) else {
        eprintln!("invalid scenario");
        return ExitCode::FAILURE;
    };
    let trace = Simulator::run(&scenario);
    print!("{}", trace.canonical());
    eprintln!("digest {}", trace.digest_hex());
    let digest_matches = scenario
        .expected_trace
        .is_none_or(|expected| trace.digest() == expected);
    if trace.outcome.expected() == scenario.expected && digest_matches {
        ExitCode::SUCCESS
    } else {
        eprintln!("scenario outcome or trace digest did not match expectation");
        ExitCode::FAILURE
    }
}
