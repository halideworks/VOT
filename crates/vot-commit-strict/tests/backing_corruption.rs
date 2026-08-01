use std::fs::File;
use std::io::Read;
use std::path::Path;

use vot_commit_strict::{Error, LinuxDirectReader, Suite, verify};

#[test]
#[ignore = "requires the privileged loop-device harness"]
fn direct_read_detects_corruption_hidden_by_buffered_cache() {
    let file_path = std::env::var("VOT_STRICT_TEST_FILE").expect("test file path");
    if std::env::var_os("VOT_STORAGE_RUNNER").is_some() {
        let fs_type = filesystem_type(Path::new(&file_path)).expect("mounted filesystem type");
        assert!(
            !matches!(fs_type.as_str(), "tmpfs" | "overlay" | "overlayfs"),
            "designated storage test cannot run on {fs_type}"
        );
    }

    let mut buffered = File::open(&file_path).expect("open buffered control");
    let mut original = Vec::new();
    buffered
        .read_to_end(&mut original)
        .expect("prime buffered page cache");
    let expected = vot_verifier::root(Suite::Blake3Bao64, &original).expect("hash original");

    let mut buffered = File::open(&file_path).expect("reopen buffered control");
    let mut cached = Vec::new();
    buffered
        .read_to_end(&mut cached)
        .expect("read buffered control");
    assert_eq!(
        cached, original,
        "buffered control did not retain cached bytes"
    );

    let reader = LinuxDirectReader::new(Path::new(&file_path), original.len() as u64, 4096);
    match verify(&reader, Suite::Blake3Bao64, &expected) {
        Err(Error::HashMismatch) => {}
        Ok(false) => panic!("O_DIRECT was unsupported on the designated storage runner"),
        Ok(true) => panic!("direct read returned cached bytes instead of backing corruption"),
        Err(error) => panic!("direct verification failed before comparison: {error:?}"),
    }
}

fn filesystem_type(path: &Path) -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let _source = fields.next()?;
            let mount = fields.next()?;
            let fs_type = fields.next()?;
            path.starts_with(mount)
                .then_some((mount.len(), fs_type.to_owned()))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, fs_type)| fs_type)
}
