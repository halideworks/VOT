use std::fs;
use std::path::PathBuf;

use vot_cli::{
    CountingSink, Error, KeyMaterial, ReceiveSink, build_bundle, receive_bundle,
    verify_receipt_file,
};
use vot_scheduler::RangeSink as _;

#[test]
#[ignore = "set VOT_TEST_DIRECTORY to an existing mounted share and run with --ignored"]
fn a_bundle_and_its_receipt_publish_on_a_mounted_share() {
    let share = PathBuf::from(std::env::var_os("VOT_TEST_DIRECTORY").expect("VOT_TEST_DIRECTORY"));
    let name = format!("vot-package-share-{}", std::process::id());
    let local = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(&name);
    let remote = share.join(&name);
    fs::create_dir_all(&local).unwrap();
    fs::create_dir(&remote).unwrap();
    let partial = remote.join("cancelled.obj");
    let retained_sink = CountingSink::at(&partial, 2).unwrap();
    retained_sink.write_at(1, &[1]).unwrap();
    retained_sink.discard_partial().unwrap();
    assert!(
        !partial.exists(),
        "cancellation must close the SMB deletion handle"
    );
    assert!(retained_sink.write_at(0, &[2]).is_err());
    retained_sink.discard_partial().unwrap();
    let source = local.join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("Reel 01")).unwrap();
    let clip = vec![0x5a; 2 * 1024 * 1024 + 17];
    fs::write(source.join("Reel 01").join("Take 01.mxf"), &clip).unwrap();
    fs::write(source.join("notes.txt"), b"mounted share check").unwrap();
    let bundle = local.join("bundle");
    let expected = build_bundle(&source, &bundle).unwrap();
    let destination = remote.join("delivery");
    let receipt = remote.join("receipt.cbor");
    let key = KeyMaterial::Shared(vec![0x37; 32]);
    let observed = "2026-09-07T00:00:00Z";
    let received = receive_bundle(&bundle, &destination, &receipt, &key, observed).unwrap();
    assert_eq!(received.package, expected);
    assert_eq!(
        fs::read(destination.join("Reel 01").join("Take 01.mxf")).unwrap(),
        clip
    );
    assert_eq!(
        fs::read(destination.join("notes.txt")).unwrap(),
        b"mounted share check"
    );
    let verified = verify_receipt_file(&receipt, &key).unwrap();
    assert_eq!(verified.root, expected.root);
    assert_eq!(verified.logical_length, expected.logical_length);
    assert!(matches!(
        receive_bundle(
            &bundle,
            &destination,
            &remote.join("other.cbor"),
            &key,
            observed
        ),
        Err(Error::DestinationExists)
    ));
    assert_eq!(
        receive_bundle(&bundle, &destination, &receipt, &key, observed)
            .unwrap()
            .package,
        expected
    );
    fs::remove_dir_all(remote).unwrap();
    fs::remove_dir_all(local).unwrap();
}
