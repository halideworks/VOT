//! Live S3-compatible multipart adapter backed by the AWS Rust SDK.

use std::collections::{BTreeMap, HashMap};

use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::runtime::Runtime;

use crate::{CompletedObject, Error, PartReceipt, S3Compatible};

#[derive(Clone)]
struct LivePart {
    bytes: Vec<u8>,
    checksum_crc32c: u32,
    etag: String,
}

#[derive(Clone)]
struct LiveUpload {
    key: String,
    parts: BTreeMap<u32, LivePart>,
}

pub struct AwsS3Store {
    runtime: Runtime,
    client: aws_sdk_s3::Client,
    bucket: String,
    uploads: HashMap<String, LiveUpload>,
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
            uploads: HashMap::new(),
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
        let upload = self
            .uploads
            .get(upload_id)
            .ok_or(Error::UnknownUpload)?
            .clone();
        if parts.len() != upload.parts.len()
            || parts.first().is_none_or(|part| part.number != 1)
            || parts
                .windows(2)
                .any(|pair| pair[0].number.checked_add(1) != Some(pair[1].number))
        {
            return Err(Error::CompletionMismatch);
        }
        let mut completed_parts = Vec::with_capacity(parts.len());
        for receipt in parts {
            let part = upload
                .parts
                .get(&receipt.number)
                .ok_or(Error::CompletionMismatch)?;
            if receipt.length != part.bytes.len() as u64
                || receipt.checksum_crc32c != part.checksum_crc32c
            {
                return Err(Error::CompletionMismatch);
            }
            completed_parts.push(
                CompletedPart::builder()
                    .part_number(i32::try_from(receipt.number).map_err(|_| Error::InvalidPart)?)
                    .e_tag(&part.etag)
                    .checksum_crc32_c(BASE64.encode(part.checksum_crc32c.to_be_bytes()))
                    .build(),
            );
        }
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();
        self.runtime
            .block_on(
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(&upload.key)
                    .upload_id(upload_id)
                    .if_none_match("*")
                    .multipart_upload(completed)
                    .send(),
            )
            .map_err(|_| Error::Backend)?;
        let bytes = self.read_object(&upload.key)?;
        let object = CompletedObject {
            key: upload.key,
            checksum_crc32c: vot_journal::crc32c(&bytes),
            bytes,
        };
        self.uploads.remove(upload_id);
        Ok(object)
    }

    fn head(&self, key: &str) -> Option<(u64, u32)> {
        let bytes = self.read_object(key).ok()?;
        Some((bytes.len() as u64, vot_journal::crc32c(&bytes)))
    }
}
