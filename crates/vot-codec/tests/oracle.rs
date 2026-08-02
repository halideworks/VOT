use std::io::Write;
use std::process::{Command, Stdio};

fn run_oracle(input: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vot-codec-oracle"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

#[test]
fn oracle_process_reports_decoding_and_hex_results() {
    assert_eq!(
        run_oracle("0100\nzz\n1f00\n"),
        "ok|k,1,\nerr|INVALID_HEX\nerr|UNKNOWN_CRITICAL_FRAME\n"
    );
}
