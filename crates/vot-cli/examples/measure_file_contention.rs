//! Compare buffered positional writes with and without a userspace mutex.

use std::{fs, path::PathBuf, sync::Mutex, time::Instant};
use vot_scheduler::{FileSink, RangeSink as _};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let parent = PathBuf::from(args.next().expect("DIRECTORY"));
    let workers: usize = args
        .next()
        .expect("WORKERS")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=16).contains(&workers));
    let mode = args
        .next()
        .expect("concurrent, serialized, or preallocated");
    assert!(mode == "concurrent" || mode == "serialized" || mode == "preallocated");
    let serialized = mode == "serialized";
    let path = parent.join(format!("vot-contention-{}", std::process::id()));
    let data = vec![0x5a; 64 * 1024];
    let chunks = 8192;
    let sink = FileSink::create_new(&path, (chunks * data.len()) as u64).unwrap();
    let gate = Mutex::new(());
    let started = Instant::now();
    if mode == "preallocated" {
        assert!(
            std::process::Command::new("fallocate")
                .args(["-l", &(chunks * data.len()).to_string()])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
    }
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let (sink, gate, data) = (&sink, &gate, &data);
            scope.spawn(move || {
                for chunk in (worker..chunks).step_by(workers) {
                    let _held = serialized.then(|| gate.lock().unwrap());
                    sink.write_at((chunk * data.len()) as u64, data).unwrap();
                }
            });
        }
    });
    let write_ms = started.elapsed().as_secs_f64() * 1000.0;
    sink.file().sync_all().unwrap();
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    drop(sink);
    let received = fs::read(&path).unwrap();
    assert_eq!(received.len(), chunks * data.len());
    assert!(received.iter().all(|byte| *byte == 0x5a));
    fs::remove_file(path).unwrap();
    println!(
        "workers={workers} mode={} write_ms={write_ms:.3} total_ms={total_ms:.3}",
        mode.to_str().unwrap()
    );
}
