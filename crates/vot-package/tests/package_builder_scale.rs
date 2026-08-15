//! Explicit bounded-memory evidence for extracted package construction.
//!
//! Run with:
//! `cargo test -p vot-package --test package_builder_scale --locked -- --ignored --exact million_entry_package_stays_below_allocation_cap --nocapture`

#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use cap::Cap;
use vot_manifest::PackagePath;
use vot_package::{EntryRecord, PackageAssembly, PackageBuilder, PageDraft, Storage};
use vot_verifier::Suite;

const ALLOCATION_LIMIT: usize = 64 * 1024 * 1024;
const CHILD_ENV: &str = "VOT_PACKAGE_SCALE_CHILD";
const CHILD_POLL_ATTEMPTS: usize = 6_000;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_ENTRIES: u64 = 1_048_576;
const LOGICAL_ENTRY_BYTES: u64 = 1_048_576;
const SPOOL_ENV: &str = "VOT_PACKAGE_SCALE_SPOOL";
const TEST_NAME: &str = "million_entry_package_stays_below_allocation_cap";
const TIMEOUT_CHILD_ENV: &str = "VOT_PACKAGE_SCALE_TIMEOUT_CHILD";
const TIMEOUT_TEST_NAME: &str = "timeout_supervision_child";
static NEXT_SPOOL: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, ALLOCATION_LIMIT);

struct DraftSpool {
    file: Option<File>,
    path: PathBuf,
    pages: u64,
    bytes: u64,
}

struct TestPaths {
    directory: PathBuf,
    spool: PathBuf,
}

impl DraftSpool {
    fn create(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self {
            file: Some(
                File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)?,
            ),
            path,
            pages: 0,
            bytes: 0,
        })
    }

    fn write(&mut self, draft: &PageDraft) {
        let encoded = draft.encode().unwrap();
        let length = u32::try_from(encoded.len()).unwrap();
        let file = self.file.as_mut().unwrap();
        file.write_all(&length.to_be_bytes()).unwrap();
        file.write_all(&encoded).unwrap();
        self.pages += 1;
        self.bytes += 4 + u64::from(length);
    }

    fn rewind(&mut self) {
        self.file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::Start(0))
            .unwrap();
    }

    fn read(&mut self) -> PageDraft {
        let file = self.file.as_mut().unwrap();
        let mut length = [0_u8; 4];
        file.read_exact(&mut length).unwrap();
        let mut encoded = vec![0; u32::from_be_bytes(length) as usize];
        file.read_exact(&mut encoded).unwrap();
        PageDraft::decode(&encoded).unwrap()
    }

    fn position(&mut self) -> u64 {
        self.file.as_mut().unwrap().stream_position().unwrap()
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }

    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn test_paths() -> TestPaths {
    let root = std::env::var_os("VOT_TEST_TEMP")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CARGO_TARGET_TMPDIR").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|target| PathBuf::from(target).join("vot-test-temp"))
        })
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/vot-test-temp")
        });
    fs::create_dir_all(&root).unwrap();

    loop {
        let directory = root.join(format!(
            "vot-package-scale-{}-{}",
            std::process::id(),
            NEXT_SPOOL.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private_dir(&directory) {
            Ok(()) => {
                return TestPaths {
                    spool: directory.join("page-drafts"),
                    directory,
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("failed to create {}: {error}", directory.display()),
        }
    }
}

fn remove_spool(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to remove {}: {error}", path.display()),
    }
}

fn remove_directory(path: &Path) {
    match fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to remove {}: {error}", path.display()),
    }
}

fn cleanup(paths: &TestPaths) {
    remove_spool(&paths.spool);
    remove_directory(&paths.directory);
}

fn terminate_and_cleanup(mut child: Child, paths: &TestPaths) -> std::io::Result<()> {
    let _ = child.kill();
    let wait_result = child.wait();
    cleanup(paths);
    wait_result.map(|_| ())
}

fn supervise_child(
    mut child: Child,
    paths: &TestPaths,
    poll_attempts: usize,
    poll_interval: Duration,
) -> std::io::Result<ExitStatus> {
    assert!(poll_attempts > 0);

    for attempt in 0..poll_attempts {
        match child.try_wait() {
            Ok(Some(status)) => {
                cleanup(paths);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                terminate_and_cleanup(child, paths)?;
                return Err(error);
            }
        }

        if attempt + 1 < poll_attempts {
            thread::sleep(poll_interval);
        }
    }

    terminate_and_cleanup(child, paths)?;
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "package-scale child exceeded its polling budget",
    ))
}

impl Drop for DraftSpool {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

fn record(index: u64) -> EntryRecord {
    EntryRecord {
        path: PackagePath::portable([format!("{index:020}")]).unwrap(),
        suite: Suite::Sha256Bep52,
        logical_root: index.to_be_bytes().repeat(4).try_into().unwrap(),
        logical_length: LOGICAL_ENTRY_BYTES,
        storage: Storage::Direct,
    }
}

fn run_scale(spool_path: PathBuf) {
    let entries = std::env::var("VOT_SCALE_ENTRIES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ENTRIES);
    assert!(entries >= DEFAULT_ENTRIES);
    let logical_bytes = entries.checked_mul(LOGICAL_ENTRY_BYTES).unwrap();
    assert!(logical_bytes >= 1_u64 << 40);
    let mut builder = PackageBuilder::new().unwrap();
    let mut spool = DraftSpool::create(spool_path).unwrap();

    for index in 0..entries {
        if let Some(draft) = builder.push(&record(index)).unwrap() {
            spool.write(&draft);
        }
    }

    let PackageAssembly {
        summary,
        final_page,
        mut finalizer,
    } = builder.finish().unwrap();
    spool.write(&final_page);
    assert_eq!(summary.entries, entries);
    assert_eq!(summary.logical_length, logical_bytes);
    assert!(spool.pages > 1);

    let pages = spool.pages;
    spool.rewind();
    for _ in 0..pages {
        finalizer.push(spool.read()).unwrap();
    }
    assert_eq!(spool.position(), spool.bytes);
    let seal = finalizer.finish().unwrap();
    assert_eq!(seal.value.final_page_count, pages);
    assert_eq!(seal.value.package.root, summary.root);
    assert_eq!(seal.value.package.length, logical_bytes);
    assert!(spool.bytes > ALLOCATION_LIMIT as u64);
    assert!(spool.bytes < logical_bytes);
    assert!(ALLOCATOR.allocated() <= ALLOCATION_LIMIT);

    println!(
        "entries={entries} logical_payload_bytes={logical_bytes} page_count={pages} allocation_ceiling_bytes={ALLOCATION_LIMIT} allocated_at_finish_bytes={} spool_bytes={}",
        ALLOCATOR.allocated(),
        spool.bytes,
    );
}

#[test]
fn spool_creation_preserves_an_occupied_path() {
    const SENTINEL: &[u8] = b"existing spool target";

    let paths = test_paths();
    let target = paths.directory.join("sentinel");
    fs::write(&target, SENTINEL).unwrap();
    fs::hard_link(&target, &paths.spool).unwrap();

    let result = DraftSpool::create(paths.spool.clone());
    let error_kind = result.as_ref().err().map(std::io::Error::kind);
    let target_contents = fs::read(&target).unwrap();
    drop(result);
    remove_spool(&paths.spool);
    fs::remove_file(target).unwrap();
    cleanup(&paths);

    assert_eq!(error_kind, Some(std::io::ErrorKind::AlreadyExists));
    assert_eq!(target_contents, SENTINEL);
}

#[test]
fn timed_out_child_is_reaped_and_cleaned_up() {
    let executable = std::env::current_exe().unwrap();
    let paths = test_paths();
    fs::write(&paths.spool, b"timeout cleanup sentinel").unwrap();
    let child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            TIMEOUT_TEST_NAME,
            "--test-threads=1",
        ])
        .env(TIMEOUT_CHILD_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let error = supervise_child(child, &paths, 1, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(!paths.spool.exists());
    assert!(!paths.directory.exists());
}

#[test]
#[ignore = "helper process for timeout supervision"]
fn timeout_supervision_child() {
    assert!(std::env::var_os(TIMEOUT_CHILD_ENV).is_some());
    thread::sleep(Duration::from_secs(2));
}

#[test]
#[ignore = "builds at least one million entries representing one TiB under a 64 MiB cap"]
fn million_entry_package_stays_below_allocation_cap() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let spool_path = std::env::var_os(SPOOL_ENV).expect("the parent supplies a spool path");
        run_scale(PathBuf::from(spool_path));
        return;
    }

    let executable = std::env::current_exe().unwrap();
    let paths = test_paths();
    let child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env(SPOOL_ENV, &paths.spool)
        .spawn();
    let status = match child {
        Ok(child) => supervise_child(child, &paths, CHILD_POLL_ATTEMPTS, CHILD_POLL_INTERVAL),
        Err(error) => {
            cleanup(&paths);
            Err(error)
        }
    }
    .unwrap();
    assert!(
        status.success(),
        "capped package builder child failed: {status}"
    );
}
