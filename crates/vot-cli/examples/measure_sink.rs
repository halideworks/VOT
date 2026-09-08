//! Run with `cargo run --release -p vot-cli --example measure_sink -- DIRECTORY WORKERS`.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use vot_cli::{CountingSink, ReceiveSink};
use vot_scheduler::RangeSink as _;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let parent = PathBuf::from(arguments.next().expect("DIRECTORY"));
    let workers: usize = arguments
        .next()
        .expect("WORKERS")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=16).contains(&workers));
    let path = parent.join(format!("vot-sink-measure-{}.obj", std::process::id()));
    let data = vec![0x5a; 1024 * 1024];
    let chunks = 128;
    let sink = CountingSink::at(&path, (chunks * data.len()) as u64).unwrap();
    let started = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let sink = &sink;
            let data = &data;
            scope.spawn(move || {
                for chunk in (worker..chunks).step_by(workers) {
                    sink.write_at((chunk * data.len()) as u64, data).unwrap();
                }
            });
        }
    });
    sink.flush().unwrap();
    let elapsed = started.elapsed();
    drop(sink);
    let received = fs::read(&path).unwrap();
    assert_eq!(received.len(), chunks * data.len());
    assert!(received.iter().all(|byte| *byte == 0x5a));
    fs::remove_file(path).unwrap();
    println!(
        "workers={workers} bytes={} elapsed_ms={:.3}",
        chunks * data.len(),
        elapsed.as_secs_f64() * 1000.0
    );
}
