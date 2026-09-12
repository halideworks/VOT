//! Component sanity check, including preparation, parked admission and publication.
//! Usage: `receive_directory SOURCE NEW_DESTINATION local|nas fast|balanced`
//! This measures no network transport. Fixtures and final independent hashes are external.

#[cfg(unix)]
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{Read as _, Seek as _, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Instant;
#[cfg(unix)]
use vot_sdk::object::{InMemoryObjectBuilder, Suite};
#[cfg(unix)]
use vot_sdk::verify::verify_range;
#[cfg(unix)]
use vot_sdk_file::{CommitProfile, NasContract, ReceiveDirectory};

#[cfg(unix)]
fn prepare(file: &mut File, buffer: &mut [u8]) -> vot_sdk::object::InMemoryPreparedObject {
    let length = file.metadata().unwrap().len();
    let mut builder = InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(length), length).unwrap();
    let mut remaining = length;
    for _ in 0..length.div_ceil(buffer.len() as u64) {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        file.read_exact(&mut buffer[..count]).unwrap();
        builder.update(&buffer[..count]).unwrap();
        remaining -= count as u64;
    }
    assert_eq!(file.read(&mut [0]).unwrap(), 0);
    file.rewind().unwrap();
    builder.finish().unwrap()
}

#[cfg(unix)]
fn verify_prefix(
    receiver: &vot_sdk_file::NativeFile,
    object: &vot_sdk::object::InMemoryPreparedObject,
    covered: u64,
    buffer: &mut [u8],
) {
    let id = object.object_id();
    let mut stored = receiver.read_staging().unwrap();
    for start in (0..covered).step_by(buffer.len()) {
        let count = usize::try_from((covered - start).min(buffer.len() as u64)).unwrap();
        stored.read_exact(&mut buffer[..count]).unwrap();
        let proof = object.prove(start, count as u64).unwrap();
        verify_range(id, start, &buffer[..count], proof.proof()).unwrap();
    }
}

#[cfg(unix)]
fn sources(source: &std::path::Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(source)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            entry.path()
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty());
    paths
}

#[cfg(unix)]
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(
        args.len(),
        4,
        "SOURCE NEW_DESTINATION local|nas fast|balanced"
    );
    let destination = PathBuf::from(&args[1]);
    let contract = match args[2].to_str().unwrap() {
        "local" => NasContract::Unqualified,
        "nas" => NasContract::ServerAcknowledged,
        _ => panic!("expected local or nas"),
    };
    let profile = match args[3].to_str().unwrap() {
        "fast" => CommitProfile::Fast,
        "balanced" => CommitProfile::Balanced,
        _ => panic!("expected fast or balanced"),
    };
    assert!(!destination.exists(), "destination must be new");
    let paths = sources(std::path::Path::new(&args[0]));
    fs::create_dir(&destination).unwrap();
    let started = Instant::now();
    let namespace = ReceiveDirectory::open(&destination, contract).unwrap();
    let mut buffer = vec![0; 4 << 20];
    #[cfg(target_os = "linux")]
    let descriptors_before = fs::read_dir("/proc/self/fd").unwrap().count();
    let mut admissions = Vec::with_capacity(paths.len());
    let mut total = 0;
    for path in &paths {
        let object = prepare(&mut File::open(path).unwrap(), &mut buffer);
        total += object.object_id().length;
        let file = namespace
            .create(object.object_id(), path.file_name().unwrap(), profile)
            .unwrap();
        admissions.push((object.object_id().clone(), file.resume_state().unwrap()));
        file.abandon();
    }
    #[cfg(target_os = "linux")]
    assert!(
        fs::read_dir("/proc/self/fd").unwrap().count() <= descriptors_before + 2,
        "parked files must not retain per-file descriptors"
    );
    let admitted_seconds = started.elapsed().as_secs_f64();
    println!(
        "admitted files={} bytes={} seconds={admitted_seconds:.6}",
        paths.len(),
        total
    );
    for (index, (path, (id, state))) in paths.iter().zip(&admissions).enumerate() {
        let mut input = File::open(path).unwrap();
        let object = prepare(&mut input, &mut buffer);
        assert_eq!(object.object_id(), id);
        let mut receiver = namespace
            .resume(id, path.file_name().unwrap(), state)
            .unwrap();
        let original = fs::metadata(receiver.staging_path()).unwrap();
        let mut resumed = false;
        for offset in (0..id.length).step_by(buffer.len()) {
            let count = usize::try_from((id.length - offset).min(buffer.len() as u64)).unwrap();
            input.read_exact(&mut buffer[..count]).unwrap();
            let proof = object.prove(offset, count as u64).unwrap();
            let verified = verify_range(id, offset, &buffer[..count], proof.proof()).unwrap();
            receiver.accept(&verified).unwrap();
            if id.length >= 1 << 30 && !resumed && offset >= id.length / 2 {
                let state = receiver.resume_state().unwrap();
                receiver.abandon();
                receiver = namespace
                    .resume(id, path.file_name().unwrap(), &state)
                    .unwrap();
                let covered = receiver.progress().prefix_bytes;
                verify_prefix(&receiver, &object, covered, &mut buffer);
                input.seek(SeekFrom::Start(covered)).unwrap();
                resumed = true;
            }
        }
        receiver.publish().unwrap();
        let published = fs::metadata(destination.join(path.file_name().unwrap())).unwrap();
        assert_eq!(
            (original.dev(), original.ino()),
            (published.dev(), published.ino())
        );
        if (index + 1) % 10_000 == 0 {
            println!("published={}", index + 1);
        }
    }
    let completed_seconds = started.elapsed().as_secs_f64();
    assert_eq!(
        fs::read_dir(destination.join(".vot-stage"))
            .unwrap()
            .count(),
        0
    );
    println!(
        "completed files={} bytes={} admitted_seconds={admitted_seconds:.6} total_seconds={completed_seconds:.6}",
        paths.len(),
        total
    );
}

#[cfg(not(unix))]
fn main() {
    panic!("qualified receive directories require Unix");
}
