//! Compare full dirty-range reconciliation with one-group header refreshes.

#[cfg(any(unix, windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::time::Instant;
    use vot_platform_fs::{create_private_directory, write_all_at};
    use vot_sdk::object::Suite;
    use vot_sdk_file::capture::CaptureSource;

    let args: Vec<_> = std::env::args().collect();
    let [_, directory, groups, mode] = args.as_slice() else {
        return Err("usage: capture_source DIRECTORY GROUPS incremental|full".into());
    };
    let groups: u64 = groups.parse()?;
    if groups == 0 || groups > 65_536 || !matches!(mode.as_str(), "incremental" | "full") {
        return Err("expected 1..65536 groups and incremental|full".into());
    }
    let directory = PathBuf::from(directory);
    create_private_directory(&directory)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let path = directory.join("source.mov");
        let stage = directory.join("stage");
        create_private_directory(&stage)?;
        let mut producer = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        let block = vec![7; 65_536];
        for _ in 0..groups {
            producer.write_all(&block)?;
        }
        producer.sync_all()?;
        let mut capture = CaptureSource::create(
            File::open(&path)?,
            &stage,
            [63; 16],
            Suite::Blake3Bao64,
            groups,
        )?;
        let start = Instant::now();
        capture.refresh(0..0)?;
        let initial_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut refresh_ms = 0.0;
        for value in 0..8 {
            write_all_at(&producer, &[value], 0)?;
            let start = Instant::now();
            capture.refresh(0..if mode == "full" { groups * 65_536 } else { 1 })?;
            refresh_ms += start.elapsed().as_secs_f64() * 1000.0;
        }
        let start = Instant::now();
        let object = capture.finish()?;
        let finish_ms = start.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(object.length, groups * 65_536);
        assert!(capture.is_finished());
        assert_eq!(capture.read(0)?.as_slice().data()[0], 7);
        println!(
            "{{\"mode\":\"{mode}\",\"groups\":{groups},\"initial_ms\":{initial_ms},\"refresh_ms\":{refresh_ms},\"finish_ms\":{finish_ms}}}"
        );
        Ok(())
    })();
    fs::remove_dir_all(directory)?;
    result
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("capture source requires Unix or Windows");
}
