#![cfg(unix)]

use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use vot_sdk::object::{InMemoryObjectBuilder, InMemoryPreparedObject, Suite};
use vot_sdk_file::capture::CaptureFile;

const G: usize = 65_536;
const INCARNATION: [u8; 16] = [23; 16];

fn prepared(value: u8) -> (InMemoryPreparedObject, Vec<u8>) {
    let mut bytes = vec![7; 2 * G];
    bytes[0] = value;
    let mut builder = InMemoryObjectBuilder::new(Suite::Blake3Bao64, None, 2 * G as u64).unwrap();
    builder.update(&bytes).unwrap();
    (builder.finish().unwrap(), bytes)
}

fn accept(capture: &mut CaptureFile, object: &InMemoryPreparedObject, bytes: &[u8], offset: usize) {
    let proof = object.prove(offset as u64, 1).unwrap();
    let verified = vot_sdk::verify::verify_range(
        object.object_id(),
        offset as u64,
        &bytes[offset..offset + G],
        proof.proof(),
    )
    .unwrap();
    capture.accept(&verified).unwrap();
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("VOT_CAPTURE_TEST_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut capture = CaptureFile::open(&path, INCARNATION).unwrap();
    let targets = [prepared(8), prepared(9)];
    for index in 0..10_000 {
        let (target, bytes) = &targets[index % 2];
        capture.select(target.object_id()).unwrap();
        capture
            .reuse(G as u64, target.prove(G as u64, 1).unwrap().proof())
            .unwrap();
        if index == 0 {
            fs::write(path.join("ready"), []).unwrap();
        }
        accept(&mut capture, target, bytes, 0);
    }
    panic!("child finished before termination");
}

struct Running(Child, PathBuf);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = fs::remove_dir_all(&self.1);
    }
}

#[test]
fn killed_writer_reopens_without_claiming_unverified_bytes() {
    for index in 0..4 {
        let path =
            std::env::temp_dir().join(format!("vot-capture-crash-{}-{index}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let (initial, bytes) = prepared(7);
        let mut capture = CaptureFile::create(&path, INCARNATION, initial.object_id(), 2).unwrap();
        accept(&mut capture, &initial, &bytes, 0);
        accept(&mut capture, &initial, &bytes, G);
        drop(capture);
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child"])
            .env("VOT_CAPTURE_TEST_PATH", &path)
            .spawn()
            .unwrap();
        let mut running = Running(child, path.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.join("ready").exists() {
            assert!(
                running.0.try_wait().unwrap().is_none(),
                "writer exited before mutation"
            );
            assert!(Instant::now() < deadline, "writer did not reach mutation");
            std::thread::sleep(Duration::from_millis(1));
        }
        running.0.kill().unwrap();
        assert!(!running.0.wait().unwrap().success());
        let mut capture = CaptureFile::open(&path, INCARNATION).unwrap();
        let progress = capture.progress().unwrap();
        let targets = [prepared(8), prepared(9)];
        let (target, expected) = targets
            .iter()
            .find(|(target, _)| *target.object_id() == progress.object)
            .unwrap();
        let mut verified_bytes = 0;
        for offset in [0, G] {
            let proof = target.prove(offset as u64, 1).unwrap();
            if let Ok(retained) = capture.read(offset as u64, proof.proof()) {
                assert_eq!(retained.as_slice().data(), &expected[offset..offset + G]);
                verified_bytes += G as u64;
            }
        }
        assert!(progress.covered_bytes <= verified_bytes);
        assert_eq!(
            capture.progress().unwrap().covered_bytes,
            progress.covered_bytes
        );
        drop(capture);
        assert_eq!(
            CaptureFile::open(&path, INCARNATION)
                .unwrap()
                .progress()
                .unwrap(),
            progress
        );
    }
}
