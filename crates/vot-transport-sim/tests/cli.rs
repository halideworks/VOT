use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use vot_transport_sim::{MAX_SCENARIO_BYTES, Scenario, shrink_failing};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temporary_file(label: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "vot-sim-cli-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, contents).unwrap();
    path
}

fn run(binary: &str, arguments: &[&std::ffi::OsStr]) -> Output {
    Command::new(binary).args(arguments).output().unwrap()
}

fn exact_size_scenario(expect: &str, body: &str) -> String {
    let prefix = format!(
        "VOT_SIM_SCENARIO_V1\nname cli-boundary\nseed 1\nexpect {expect}\ntrace -\n{body}#"
    );
    assert!(prefix.len() <= MAX_SCENARIO_BYTES);
    format!("{prefix}{}", "x".repeat(MAX_SCENARIO_BYTES - prefix.len()))
}

#[test]
fn replay_cli_enforces_arguments_size_outcome_and_digest() {
    let binary = env!("CARGO_BIN_EXE_vot-trace-replay");
    let no_arguments = run(binary, &[]);
    assert_eq!(no_arguments.status.code(), Some(2));

    let exact = exact_size_scenario("quiescent", "");
    let exact_path = temporary_file("replay-exact", &exact);
    let success = run(binary, &[exact_path.as_os_str()]);
    assert!(success.status.success());
    assert!(
        String::from_utf8(success.stdout)
            .unwrap()
            .starts_with("VOT_SIM_TRACE_V1\nscenario cli-boundary\n")
    );

    let over_path = temporary_file("replay-over", &format!("{exact}x"));
    let over = run(binary, &[over_path.as_os_str()]);
    assert!(!over.status.success());
    assert_eq!(
        String::from_utf8(over.stderr).unwrap(),
        "scenario exceeds the input limit\n"
    );

    let wrong_outcome = temporary_file(
        "replay-outcome",
        "VOT_SIM_SCENARIO_V1\nname wrong-outcome\nseed 1\nexpect complete\ntrace -\n",
    );
    assert!(!run(binary, &[wrong_outcome.as_os_str()]).status.success());

    let wrong_digest = temporary_file(
        "replay-digest",
        &format!(
            "VOT_SIM_SCENARIO_V1\nname wrong-digest\nseed 1\nexpect quiescent\ntrace {}\n",
            "00".repeat(32)
        ),
    );
    assert!(!run(binary, &[wrong_digest.as_os_str()]).status.success());

    for path in [exact_path, over_path, wrong_outcome, wrong_digest] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn shrink_cli_enforces_arguments_size_and_failure_precondition() {
    let binary = env!("CARGO_BIN_EXE_vot-trace-shrink");
    assert_eq!(run(binary, &[]).status.code(), Some(2));

    let body = "at 0 add-path 1 1200 1\nat 1 switch datagram\nat 2 send 1 1 1201\n";
    let exact = exact_size_scenario("failed", body);
    let exact_path = temporary_file("shrink-exact", &exact);
    let output = run(binary, &[exact_path.as_os_str()]);
    assert!(output.status.success());
    let scenario = Scenario::parse(&exact).unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        shrink_failing(&scenario).encode()
    );

    let over_path = temporary_file("shrink-over", &format!("{exact}x"));
    let over = run(binary, &[over_path.as_os_str()]);
    assert!(!over.status.success());
    assert_eq!(
        String::from_utf8(over.stderr).unwrap(),
        "scenario exceeds the input limit\n"
    );

    let quiescent = temporary_file(
        "shrink-quiescent",
        "VOT_SIM_SCENARIO_V1\nname quiet\nseed 1\nexpect quiescent\ntrace -\n",
    );
    let not_failing = run(binary, &[quiescent.as_os_str()]);
    assert!(!not_failing.status.success());
    assert_eq!(
        String::from_utf8(not_failing.stderr).unwrap(),
        "scenario does not fail\n"
    );

    for path in [exact_path, over_path, quiescent] {
        fs::remove_file(path).unwrap();
    }
}
