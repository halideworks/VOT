//! Live S3-compatible multipart adapter backed by the AWS Rust SDK.

use std::collections::BTreeMap;

use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::runtime::Runtime;

use crate::{CompletedObject, Error, PartReceipt, S3Compatible};

struct LivePart {
    bytes: Vec<u8>,
    checksum_crc32c: u32,
    etag: String,
}

struct LiveUpload {
    key: String,
    parts: BTreeMap<u32, LivePart>,
}

pub struct AwsS3Store {
    runtime: Runtime,
    client: aws_sdk_s3::Client,
    bucket: String,
    uploads: BTreeMap<String, LiveUpload>,
}

impl AwsS3Store {
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, Error> {
        let runtime = Runtime::new().map_err(|_| Error::Backend)?;
        let credentials = Credentials::new(access_key, secret_key, None, None, "vot-s3-compatible");
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(Region::new(region.to_owned()))
            .credentials_provider(credentials)
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build();
        Ok(Self {
            runtime,
            client: aws_sdk_s3::Client::from_conf(config),
            bucket: bucket.to_owned(),
            uploads: BTreeMap::new(),
        })
    }

    pub fn delete_object(&self, key: &str) -> Result<(), Error> {
        self.runtime
            .block_on(
                self.client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .map_err(|_| Error::Backend)?;
        Ok(())
    }

    fn read_object(&self, key: &str) -> Result<Vec<u8>, Error> {
        let output = self
            .runtime
            .block_on(
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .map_err(|_| Error::Backend)?;
        let body = self
            .runtime
            .block_on(output.body.collect())
            .map_err(|_| Error::Backend)?;
        Ok(body.into_bytes().to_vec())
    }
}

impl S3Compatible for AwsS3Store {
    fn create_multipart(&mut self, key: &str, _now: u64) -> Result<String, Error> {
        let output = self
            .runtime
            .block_on(
                self.client
                    .create_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .checksum_algorithm(ChecksumAlgorithm::Crc32C)
                    .send(),
            )
            .map_err(|_| Error::Backend)?;
        let upload_id = output.upload_id().ok_or(Error::Backend)?.to_owned();
        self.uploads.insert(
            upload_id.clone(),
            LiveUpload {
                key: key.to_owned(),
                parts: BTreeMap::new(),
            },
        );
        Ok(upload_id)
    }

    fn upload_part(
        &mut self,
        upload_id: &str,
        number: u32,
        bytes: &[u8],
        checksum_crc32c: u32,
    ) -> Result<PartReceipt, Error> {
        if number == 0 || number > 10_000 {
            return Err(Error::InvalidPart);
        }
        if vot_journal::crc32c(bytes) != checksum_crc32c {
            return Err(Error::ChecksumMismatch);
        }
        let upload = self.uploads.get(upload_id).ok_or(Error::UnknownUpload)?;
        let encoded_checksum = BASE64.encode(checksum_crc32c.to_be_bytes());
        let output = self
            .runtime
            .block_on(
                self.client
                    .upload_part()
                    .bucket(&self.bucket)
                    .key(&upload.key)
                    .upload_id(upload_id)
                    .part_number(i32::try_from(number).map_err(|_| Error::InvalidPart)?)
                    .checksum_crc32_c(&encoded_checksum)
                    .body(ByteStream::from(bytes.to_vec()))
                    .send(),
            )
            .map_err(|_| Error::Backend)?;
        if output
            .checksum_crc32_c()
            .is_some_and(|actual| actual != encoded_checksum)
        {
            return Err(Error::ChecksumMismatch);
        }
        let etag = output.e_tag().ok_or(Error::Backend)?.to_owned();
        self.uploads
            .get_mut(upload_id)
            .ok_or(Error::UnknownUpload)?
            .parts
            .insert(
                number,
                LivePart {
                    bytes: bytes.to_vec(),
                    checksum_crc32c,
                    etag,
                },
            );
        Ok(PartReceipt {
            number,
            checksum_crc32c,
            length: bytes.len() as u64,
        })
    }

    fn complete_multipart(
        &mut self,
        upload_id: &str,
        parts: &[PartReceipt],
    ) -> Result<CompletedObject, Error> {
        let upload = self.uploads.remove(upload_id).ok_or(Error::UnknownUpload)?;
        if parts.len() != upload.parts.len()
            || parts.first().is_none_or(|part| part.number != 1)
            || parts
                .windows(2)
                .any(|pair| pair[0].number.checked_add(1) != Some(pair[1].number))
        {
            self.uploads.insert(upload_id.to_owned(), upload);
            return Err(Error::CompletionMismatch);
        }
        let expected_length = upload.parts.values().try_fold(0_u64, |total, part| {
            total.checked_add(part.bytes.len() as u64)
        });
        let Some(expected_length) = expected_length else {
            self.uploads.insert(upload_id.to_owned(), upload);
            return Err(Error::CompletionMismatch);
        };
        let expected_checksum = crc32c_parts(&upload.parts);
        let mut completed_parts = Vec::with_capacity(parts.len());
        for receipt in parts {
            let Some(part) = upload.parts.get(&receipt.number) else {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionMismatch);
            };
            if receipt.length != part.bytes.len() as u64
                || receipt.checksum_crc32c != part.checksum_crc32c
            {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionMismatch);
            }
            completed_parts.push(
                CompletedPart::builder()
                    .part_number(
                        i32::try_from(receipt.number).expect("part number is at most 10000"),
                    )
                    .e_tag(&part.etag)
                    .checksum_crc32_c(BASE64.encode(part.checksum_crc32c.to_be_bytes()))
                    .build(),
            );
        }
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();
        let completion = self.runtime.block_on(
            self.client
                .complete_multipart_upload()
                .bucket(&self.bucket)
                .key(&upload.key)
                .upload_id(upload_id)
                .if_none_match("*")
                .multipart_upload(completed)
                .send(),
        );
        let completion_was_ambiguous = match completion {
            Ok(_) => false,
            Err(error) if error.as_service_error().is_some() => {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::Backend);
            }
            Err(_) => true,
        };
        let Ok(bytes) = self.read_object(&upload.key) else {
            self.uploads.insert(upload_id.to_owned(), upload);
            return Err(Error::CompletionAmbiguous);
        };
        let actual_checksum = vot_journal::crc32c(&bytes);
        if !read_back_matches(
            expected_length,
            expected_checksum,
            bytes.len() as u64,
            actual_checksum,
        ) {
            self.uploads.insert(upload_id.to_owned(), upload);
            return Err(if completion_was_ambiguous {
                Error::CompletionAmbiguous
            } else {
                Error::ChecksumMismatch
            });
        }
        let object = CompletedObject {
            key: upload.key,
            checksum_crc32c: actual_checksum,
            bytes,
        };
        Ok(object)
    }

    fn head(&self, key: &str) -> Option<(u64, u32)> {
        let bytes = self.read_object(key).ok()?;
        Some((bytes.len() as u64, vot_journal::crc32c(&bytes)))
    }
}

fn crc32c_parts(parts: &BTreeMap<u32, LivePart>) -> u32 {
    let mut crc = !0_u32;
    for byte in parts.values().flat_map(|part| part.bytes.iter()) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

const fn read_back_matches(
    expected_length: u64,
    expected_checksum: u32,
    actual_length: u64,
    actual_checksum: u32,
) -> bool {
    actual_length == expected_length && actual_checksum == expected_checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_parts_detect_stable_read_back_corruption() {
        let mut parts = BTreeMap::new();
        parts.insert(
            2,
            LivePart {
                bytes: b"two".to_vec(),
                checksum_crc32c: vot_journal::crc32c(b"two"),
                etag: "two".to_owned(),
            },
        );
        parts.insert(
            1,
            LivePart {
                bytes: b"one".to_vec(),
                checksum_crc32c: vot_journal::crc32c(b"one"),
                etag: "one".to_owned(),
            },
        );
        let expected_checksum = crc32c_parts(&parts);
        assert_eq!(expected_checksum, vot_journal::crc32c(b"onetwo"));
        assert!(read_back_matches(
            6,
            expected_checksum,
            6,
            vot_journal::crc32c(b"onetwo")
        ));
        assert!(!read_back_matches(
            6,
            expected_checksum,
            6,
            vot_journal::crc32c(b"oneXwo")
        ));
    }
}
