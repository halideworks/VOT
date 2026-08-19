#![allow(clippy::disallowed_methods)] // This executable measures real wall-clock time.

use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use vot_commit_model::Profile;
use vot_commit_posix::{NoFaults, PosixCommit};

fn baseline(directory: &Path, bytes: &[u8]) -> Duration {
    let start = Instant::now();
    black_box(vot_journal::crc32c(bytes));
    let staging = directory.join("stage");
    let destination = directory.join("object");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::hard_link(staging, destination).unwrap();
    File::open(directory).unwrap().sync_all().unwrap();
    start.elapsed()
}

fn balanced(directory: &Path, bytes: &[u8], incarnation: [u8; 16]) -> Duration {
    let start = Instant::now();
    black_box(vot_journal::crc32c(bytes));
    let mut commit = PosixCommit::create(
        Profile::Balanced,
        incarnation,
        directory.join("stage"),
        directory.join("object"),
        &directory.join("journal"),
        NoFaults,
    )
    .unwrap();
    commit.write_transit_verified(bytes).unwrap();
    black_box(commit.publish().unwrap());
    start.elapsed()
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn run_directory(root: &Path, kind: &str, iteration: usize) -> std::path::PathBuf {
    let path = root.join(format!("{kind}-{iteration}"));
    fs::create_dir(&path).unwrap();
    path
}

fn main() {
    let mebibytes = std::env::args()
        .nth(1)
        .map_or(Ok(256), |value| value.parse::<usize>())
        .expect("size must be an integer");
    let iterations = std::env::args()
        .nth(2)
        .map_or(Ok(7), |value| value.parse::<usize>())
        .expect("iterations must be an integer");
    assert!(iterations >= 3 && iterations % 2 == 1);
    let length = mebibytes.checked_mul(1024 * 1024).expect("size overflow");
    let bytes: Vec<u8> = (0..length)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let storage_root = std::env::var_os("VOT_BENCH_ROOT")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let root = storage_root.join(format!("vot-balanced-bench-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let mut baseline_samples = Vec::with_capacity(iterations);
    let mut balanced_samples = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let baseline_dir = run_directory(&root, "baseline", iteration);
        let balanced_dir = run_directory(&root, "balanced", iteration);
        if iteration.is_multiple_of(2) {
            baseline_samples.push(baseline(&baseline_dir, &bytes));
            balanced_samples.push(balanced(
                &balanced_dir,
                &bytes,
                u128::try_from(iteration + 1).unwrap().to_be_bytes(),
            ));
        } else {
            balanced_samples.push(balanced(
                &balanced_dir,
                &bytes,
                u128::try_from(iteration + 1).unwrap().to_be_bytes(),
            ));
            baseline_samples.push(baseline(&baseline_dir, &bytes));
        }
        fs::remove_dir_all(baseline_dir).unwrap();
        fs::remove_dir_all(balanced_dir).unwrap();
    }
    fs::remove_dir(root).unwrap();
    let baseline_median = median(&mut baseline_samples);
    let balanced_median = median(&mut balanced_samples);
    let overhead = (balanced_median.as_secs_f64() / baseline_median.as_secs_f64() - 1.0) * 100.0;
    println!(
        "{{\"size_mib\":{mebibytes},\"iterations\":{iterations},\"baseline_median_ms\":{:.3},\"balanced_median_ms\":{:.3},\"overhead_percent\":{overhead:.3}}}",
        baseline_median.as_secs_f64() * 1000.0,
        balanced_median.as_secs_f64() * 1000.0
    );
    if overhead > 5.0 {
        std::process::exit(1);
    }
}
