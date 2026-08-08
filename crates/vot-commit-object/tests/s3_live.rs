#![cfg(feature = "s3-live")]

use vot_commit_object::{Error as CommitError, ObjectCommit};
use vot_object_store::aws::AwsS3Store;
use vot_object_store::{Error as StoreError, MockStore, S3Compatible};

#[test]
fn minio_and_mock_emit_identical_assurance_receipts() {
    let endpoint = std::env::var("VOT_S3_ENDPOINT").expect("VOT_S3_ENDPOINT is required");
    let bucket = std::env::var("VOT_S3_BUCKET").expect("VOT_S3_BUCKET is required");
    let access_key = std::env::var("VOT_S3_ACCESS_KEY").expect("VOT_S3_ACCESS_KEY is required");
    let secret_key = std::env::var("VOT_S3_SECRET_KEY").expect("VOT_S3_SECRET_KEY is required");
    let key = format!("wave2-live-{}", std::process::id());
    let first = vec![0x5a; 5 * 1024 * 1024];
    let second = b"final verified part".to_vec();

    let mut mock = ObjectCommit::create(MockStore::default(), &key, 0).unwrap();
    mock.upload_verified_part(1, &first).unwrap();
    mock.upload_verified_part(2, &second).unwrap();
    let (mock_object, mock_receipt) = mock.complete().unwrap();

    let store = AwsS3Store::new(&endpoint, &bucket, "us-east-1", &access_key, &secret_key).unwrap();
    let mut live = ObjectCommit::create(store, &key, 0).unwrap();
    live.upload_verified_part(1, &first).unwrap();
    live.upload_verified_part(2, &second).unwrap();
    let (live_object, live_receipt) = live.complete().unwrap();

    assert_eq!(live_object, mock_object);
    assert_eq!(live_receipt, mock_receipt);
    assert_eq!(
        live.store().head(&key),
        Some((mock_object.length, mock_object.checksum_crc32c))
    );
    let conflict_store =
        AwsS3Store::new(&endpoint, &bucket, "us-east-1", &access_key, &secret_key).unwrap();
    let mut conflict = ObjectCommit::create(conflict_store, &key, 1).unwrap();
    conflict.upload_verified_part(1, &first).unwrap();
    conflict.upload_verified_part(2, &second).unwrap();
    assert!(matches!(
        conflict.complete(),
        Err(CommitError::Store(StoreError::Backend))
    ));

    live.store().delete_object(&key).unwrap();
}
