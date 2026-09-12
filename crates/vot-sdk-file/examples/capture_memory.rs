//! Run the built executable under a process-memory meter; preparation is separate from recovery.

#[cfg(any(unix, windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk_file::capture::CaptureFile;

    use std::path::Path;

    const GROUP: u64 = 65_536;
    const INCARNATION: [u8; 16] = [59; 16];
    let arguments: Vec<_> = std::env::args().collect();
    let command = arguments
        .get(1)
        .ok_or("expected prepare, compact, or recover")?;
    let path = arguments.get(2).ok_or("expected private capture path")?;
    if command == "prepare" {
        let groups: u64 = arguments.get(3).ok_or("expected group count")?.parse()?;
        let length = groups.checked_mul(GROUP).ok_or("length overflow")?;
        let bytes = vec![0; usize::try_from(GROUP)?];
        let mut builder = InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(length), length)?;
        for _ in 0..groups {
            builder.update(&bytes)?;
        }
        let target = builder.finish()?;
        vot_platform_fs::create_private_directory(Path::new(path))?;
        let mut capture = CaptureFile::create(path, INCARNATION, target.object_id(), groups)?;
        for index in 0..groups {
            let offset = index * GROUP;
            let proof = target.prove(offset, 1)?;
            let verified =
                vot_sdk::verify::verify_range(target.object_id(), offset, &bytes, proof.proof())?;
            capture.accept(&verified)?;
        }
        assert_eq!(capture.progress()?.covered_bytes, length);
        assert_eq!(capture.progress()?.cached_groups, groups);
    } else {
        if command != "compact" && command != "recover" {
            return Err("unknown command".into());
        }
        let mut capture = CaptureFile::open(path, INCARNATION)?;
        let progress = if command == "compact" {
            capture.checkpoint()?
        } else {
            capture.progress()?
        };
        assert_eq!(progress.covered_bytes, progress.object.length);
        println!(
            "covered_bytes={} cached_groups={}",
            progress.covered_bytes, progress.cached_groups
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("capture staging requires Unix or Windows");
}
