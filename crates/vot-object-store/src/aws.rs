//! Live S3-compatible multipart adapter backed by the AWS Rust SDK.

use std::collections::BTreeMap;

use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::error::ProvideErrorMetadata as _;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::runtime::Runtime;

use crate::{
    CompletedObject, Error, MultipartCompleted, MultipartObjectStore, ObjectExpectation,
    ObjectMetadata, PartReceipt, ReadbackVerified,
};

/// What the adapter remembers about a part it has uploaded.
///
/// Not the bytes. A multipart upload of a large object would otherwise hold
/// every part until completion, so peak memory scaled with the object rather
/// than with a part. The length and the checksum are all completion needs,
/// and the two together combine into the whole object's checksum.
struct LivePart {
    length: u64,
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

    /// Reads an object back and reports only its length and checksum.
    ///
    /// Chunk by chunk, so peak memory is one chunk of the backend's choosing
    /// rather than the object. Nothing here needs the bytes: the caller is
    /// checking that what landed is what went up.
    fn measure_object(&self, key: &str) -> Result<(u64, u32), Error> {
        let mut output = self
            .runtime
            .block_on(
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send(),
            )
            .map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(|service| object_not_found(service.code()))
                {
                    Error::ObjectNotFound
                } else {
                    Error::Backend
                }
            })?;
        // One entry into the runtime for the whole body, not one per chunk.
        self.runtime.block_on(async {
            let mut length = 0_u64;
            let mut checksum = vot_journal::CRC32C_EMPTY;
            while let Some(chunk) = output.body.next().await {
                let chunk = chunk.map_err(|_| Error::Backend)?;
                length = length
                    .checked_add(chunk.len() as u64)
                    .ok_or(Error::Backend)?;
                checksum = vot_journal::crc32c_update(checksum, &chunk);
            }
            Ok((length, checksum))
        })
    }
}

impl MultipartObjectStore for AwsS3Store {
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
                    length: bytes.len() as u64,
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
    ) -> Result<MultipartCompleted, Error> {
        let upload = self.uploads.get(upload_id).ok_or(Error::UnknownUpload)?;
        let expectation = ObjectExpectation::from_parts(&upload.key, parts)?;
        let upload = self.uploads.remove(upload_id).ok_or(Error::UnknownUpload)?;
        if parts.len() != upload.parts.len() {
            self.uploads.insert(upload_id.to_owned(), upload);
            return Err(Error::CompletionMismatch);
        }
        let mut completed_parts = Vec::with_capacity(parts.len());
        for receipt in parts {
            let Some(part) = upload.parts.get(&receipt.number) else {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionMismatch);
            };
            if receipt.length != part.length {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionMismatch);
            }
            if receipt.checksum_crc32c != part.checksum_crc32c {
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
        match completion {
            Ok(_) => {}
            Err(error) if error.as_service_error().is_some() => {
                let could_be_completed = completion_error_may_be_ambiguous(
                    error.as_service_error().and_then(|service| service.code()),
                    error
                        .raw_response()
                        .is_some_and(|response| response.status().is_server_error()),
                );
                if !could_be_completed {
                    self.uploads.insert(upload_id.to_owned(), upload);
                    return Err(Error::Backend);
                }
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionAmbiguous);
            }
            Err(_) => {
                self.uploads.insert(upload_id.to_owned(), upload);
                return Err(Error::CompletionAmbiguous);
            }
        }
        Ok(MultipartCompleted::new(expectation))
    }

    fn stat_object(&self, key: &str) -> Result<Option<ObjectMetadata>, Error> {
        match self.runtime.block_on(
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        ) {
            Ok(output) => {
                let length = output.content_length().ok_or(Error::Backend)?;
                let length = u64::try_from(length).map_err(|_| Error::Backend)?;
                Ok(Some(ObjectMetadata::new(length)))
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| object_not_found(service.code())) =>
            {
                Ok(None)
            }
            Err(_) => Err(Error::Backend),
        }
    }

    fn verify_by_readback(&self, expected: &ObjectExpectation) -> Result<ReadbackVerified, Error> {
        let (actual_length, actual_checksum) = self.measure_object(expected.key())?;
        if !read_back_matches(
            expected.length(),
            expected.checksum_crc32c(),
            actual_length,
            actual_checksum,
        ) {
            return Err(Error::ChecksumMismatch);
        }
        Ok(ReadbackVerified::new(CompletedObject {
            key: expected.key().to_owned(),
            length: actual_length,
            checksum_crc32c: actual_checksum,
        }))
    }

    fn release_multipart(&mut self, upload_id: &str) {
        self.uploads.remove(upload_id);
    }
}

/// The checksum of the parts concatenated in number order, from their own
/// checksums and lengths. The bytes are long gone by completion.
#[cfg(test)]
fn crc32c_parts(parts: &BTreeMap<u32, LivePart>) -> u32 {
    parts
        .values()
        .fold(vot_journal::CRC32C_EMPTY, |whole, part| {
            vot_journal::crc32c_combine(whole, part.checksum_crc32c, part.length)
        })
}

fn completion_error_may_be_ambiguous(code: Option<&str>, server_error: bool) -> bool {
    server_error
        || matches!(
            code,
            Some(
                "NoSuchUpload"
                    | "SlowDown"
                    | "InternalError"
                    | "ServiceUnavailable"
                    | "RequestTimeout"
            )
        )
}

fn object_not_found(code: Option<&str>) -> bool {
    matches!(code, Some("NoSuchKey" | "NotFound"))
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    /// One S3 request, as much of it as a test needs to answer.
    #[derive(Clone, Debug)]
    struct Request {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Request {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.as_str())
        }

        fn is_create_multipart(&self) -> bool {
            self.method == "POST" && self.target.contains("uploads")
        }

        fn is_upload_part(&self) -> bool {
            self.method == "PUT" && self.target.contains("partNumber=")
        }

        fn is_complete_multipart(&self) -> bool {
            self.method == "POST" && self.target.contains("uploadId=")
        }

        fn is_stat_object(&self) -> bool {
            self.method == "HEAD"
        }

        fn is_readback(&self) -> bool {
            self.method == "GET"
        }
    }

    /// An S3-compatible endpoint that answers from a rule. Right regardless of
    /// how many times the SDK retries.
    struct FakeS3 {
        endpoint: String,
        seen: Arc<Mutex<Vec<Request>>>,
        stop: Arc<AtomicBool>,
    }

    impl FakeS3 {
        fn new<H>(handler: H) -> Self
        where
            H: Fn(&Request) -> Vec<u8> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a local port");
            let endpoint = format!("http://{}", listener.local_addr().expect("an address"));
            listener.set_nonblocking(true).expect("a polled listener");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let recorder = Arc::clone(&seen);
            let halt = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !halt.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_nonblocking(false)
                                .expect("a blocking connection");
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                                .expect("a connection that gives up");
                            let Some(request) = read_request(&mut stream) else {
                                continue;
                            };
                            let response = handler(&request);
                            recorder.lock().expect("the recorder").push(request);
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                endpoint,
                seen,
                stop,
            }
        }

        fn store(&self) -> AwsS3Store {
            AwsS3Store::new(&self.endpoint, "bucket", "us-east-1", "key", "secret")
                .expect("a store against the local endpoint")
        }

        fn requests(&self) -> Vec<Request> {
            self.seen.lock().expect("the recorder").clone()
        }
    }

    impl Drop for FakeS3 {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return None,
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.lines();
        let mut start = lines.next()?.split_whitespace();
        let method = start.next()?.to_owned();
        let target = start.next()?.to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        if length > 0 && stream.read_exact(&mut body).is_err() {
            return None;
        }
        Some(Request {
            method,
            target,
            headers,
            body,
        })
    }

    fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
        for (name, value) in headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        }
        out.extend_from_slice(b"connection: close\r\n\r\n");
        out.extend_from_slice(body);
        out
    }

    fn xml(body: &str) -> Vec<u8> {
        response(
            "200 OK",
            &[("content-type", "application/xml")],
            body.as_bytes(),
        )
    }

    fn created(upload_id: &str) -> Vec<u8> {
        xml(&format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <InitiateMultipartUploadResult>\
             <Bucket>bucket</Bucket><Key>key</Key><UploadId>{upload_id}</UploadId>\
             </InitiateMultipartUploadResult>"
        ))
    }

    fn completed_upload() -> Vec<u8> {
        xml("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <CompleteMultipartUploadResult>\
             <Location>http://localhost/bucket/key</Location>\
             <Bucket>bucket</Bucket><Key>key</Key><ETag>\"final\"</ETag>\
             </CompleteMultipartUploadResult>")
    }

    fn service_error(status: &str, code: &str) -> Vec<u8> {
        response(
            status,
            &[("content-type", "application/xml")],
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <Error><Code>{code}</Code><Message>{code}</Message></Error>"
            )
            .as_bytes(),
        )
    }

    /// The whole upload answered as an S3 endpoint would, with the part echoed
    /// back and the object readable afterwards.
    fn happy_endpoint(object: &'static [u8]) -> impl Fn(&Request) -> Vec<u8> {
        move |request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else if request.is_upload_part() {
                let checksum = request
                    .header("x-amz-checksum-crc32c")
                    .unwrap_or_default()
                    .to_owned();
                response(
                    "200 OK",
                    &[("etag", "\"part-1\""), ("x-amz-checksum-crc32c", &checksum)],
                    b"",
                )
            } else if request.is_complete_multipart() {
                completed_upload()
            } else if request.is_stat_object() {
                let length = object.len().to_string();
                response("200 OK", &[("content-length", &length)], b"")
            } else if request.is_readback() {
                response("200 OK", &[("etag", "\"final\"")], object)
            } else {
                response("204 No Content", &[], b"")
            }
        }
    }

    fn ambiguous_endpoint(object: &'static [u8]) -> impl Fn(&Request) -> Vec<u8> {
        move |request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else if request.is_upload_part() {
                let checksum = request
                    .header("x-amz-checksum-crc32c")
                    .unwrap_or_default()
                    .to_owned();
                response(
                    "200 OK",
                    &[("etag", "\"part-1\""), ("x-amz-checksum-crc32c", &checksum)],
                    b"",
                )
            } else if request.is_complete_multipart() {
                service_error("404 Not Found", "NoSuchUpload")
            } else {
                response("200 OK", &[], object)
            }
        }
    }

    /// Whether a completion describes exactly these bytes. The adapter does
    /// not hand back an object, so this is what stands in for comparing it.
    fn is_object(object: &CompletedObject, bytes: &[u8]) -> bool {
        object.length == bytes.len() as u64 && object.checksum_crc32c == vot_journal::crc32c(bytes)
    }

    fn is_expectation(expectation: &ObjectExpectation, bytes: &[u8]) -> bool {
        expectation.length() == bytes.len() as u64
            && expectation.checksum_crc32c() == vot_journal::crc32c(bytes)
    }

    fn upload_one_part(store: &mut AwsS3Store, bytes: &[u8]) -> (String, PartReceipt) {
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        let receipt = store
            .upload_part(&upload_id, 1, bytes, vot_journal::crc32c(bytes))
            .expect("a part");
        (upload_id, receipt)
    }

    #[test]
    fn completion_metadata_and_readback_are_distinct_requests() {
        let endpoint = FakeS3::new(happy_endpoint(b"payload"));
        let mut store = endpoint.store();

        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        assert_eq!(upload_id, "upload-1", "the identifier the endpoint gave");
        assert_eq!(
            receipt,
            PartReceipt {
                number: 1,
                checksum_crc32c: vot_journal::crc32c(b"payload"),
                length: 7,
            }
        );

        let completed = store
            .complete_multipart(&upload_id, std::slice::from_ref(&receipt))
            .expect("a completed object");
        assert_eq!(completed.expectation().key(), "key");
        assert_eq!(completed.expectation().length(), 7);
        assert_eq!(
            completed.expectation().checksum_crc32c(),
            vot_journal::crc32c(b"payload")
        );
        assert_eq!(
            endpoint
                .requests()
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["POST", "PUT", "POST"],
            "completion does not observe the object"
        );

        assert_eq!(store.stat_object("key"), Ok(Some(ObjectMetadata::new(7))));
        let verified = store
            .verify_by_readback(completed.expectation())
            .expect("the completed bytes read back exactly");
        assert!(is_object(verified.object(), b"payload"));

        let sent = endpoint.requests();
        assert_eq!(
            sent.iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["POST", "PUT", "POST", "HEAD", "GET"]
        );
        assert!(sent[3].is_stat_object());
        assert!(sent[3].body.is_empty(), "metadata does not read a body");
        assert!(sent[4].is_readback());
        let part = sent
            .iter()
            .find(|request| request.is_upload_part())
            .expect("a part request");
        assert_eq!(
            part.header("x-amz-checksum-crc32c"),
            Some(
                BASE64
                    .encode(vot_journal::crc32c(b"payload").to_be_bytes())
                    .as_str()
            )
        );
        assert_eq!(part.body, b"payload");
        assert!(part.target.contains("partNumber=1"));

        assert_eq!(store.delete_object("key"), Ok(()));
    }

    #[test]
    fn a_part_is_refused_before_it_reaches_the_endpoint() {
        let endpoint = FakeS3::new(happy_endpoint(b"payload"));
        let mut store = endpoint.store();
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        let before = endpoint.requests().len();

        for (name, id, number, checksum, expected) in [
            (
                "a part numbered zero",
                upload_id.as_str(),
                0_u32,
                vot_journal::crc32c(b"payload"),
                Error::InvalidPart,
            ),
            (
                "a part past the last a multipart upload may have",
                upload_id.as_str(),
                10_001,
                vot_journal::crc32c(b"payload"),
                Error::InvalidPart,
            ),
            (
                "a checksum that is not the bytes",
                upload_id.as_str(),
                1,
                vot_journal::crc32c(b"payload") ^ 1,
                Error::ChecksumMismatch,
            ),
            (
                "an upload nothing created",
                "upload-absent",
                1,
                vot_journal::crc32c(b"payload"),
                Error::UnknownUpload,
            ),
        ] {
            assert_eq!(
                store.upload_part(id, number, b"payload", checksum),
                Err(expected),
                "{name}"
            );
        }
        assert_eq!(
            endpoint.requests().len(),
            before,
            "nothing a caller got wrong was sent"
        );

        assert!(
            store
                .upload_part(
                    &upload_id,
                    10_000,
                    b"payload",
                    vot_journal::crc32c(b"payload")
                )
                .is_ok(),
            "the last part number allowed"
        );
    }

    #[test]
    fn a_part_the_endpoint_echoes_differently_is_refused() {
        let endpoint = FakeS3::new(|request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else {
                response(
                    "200 OK",
                    &[
                        ("etag", "\"part-1\""),
                        ("x-amz-checksum-crc32c", "AAAAAA=="),
                    ],
                    b"",
                )
            }
        });
        let mut store = endpoint.store();
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        assert_eq!(
            store.upload_part(&upload_id, 1, b"payload", vot_journal::crc32c(b"payload")),
            Err(Error::ChecksumMismatch)
        );

        let quiet = FakeS3::new(|request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else {
                response("200 OK", &[("etag", "\"part-1\"")], b"")
            }
        });
        let mut store = quiet.store();
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        assert!(
            store
                .upload_part(&upload_id, 1, b"payload", vot_journal::crc32c(b"payload"))
                .is_ok()
        );
    }

    #[test]
    fn a_completion_that_does_not_match_what_went_up_is_refused_and_the_upload_kept() {
        let endpoint = FakeS3::new(happy_endpoint(b"onetwo"));
        let mut store = endpoint.store();
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        let one = store
            .upload_part(&upload_id, 1, b"one", vot_journal::crc32c(b"one"))
            .expect("the first part");
        let two = store
            .upload_part(&upload_id, 2, b"two", vot_journal::crc32c(b"two"))
            .expect("the second part");

        for (name, parts) in [
            ("fewer receipts than parts", vec![one.clone()]),
            (
                "more receipts than parts",
                vec![one.clone(), two.clone(), two.clone()],
            ),
            ("a first part that is not the first", vec![two.clone()]),
            (
                "a gap between receipts",
                vec![
                    one.clone(),
                    PartReceipt {
                        number: 3,
                        ..two.clone()
                    },
                ],
            ),
            (
                "a receipt for a part that never went up",
                vec![
                    one.clone(),
                    PartReceipt {
                        number: 2,
                        checksum_crc32c: two.checksum_crc32c,
                        length: two.length,
                    },
                    PartReceipt {
                        number: 3,
                        checksum_crc32c: two.checksum_crc32c,
                        length: two.length,
                    },
                ],
            ),
            (
                "a length that is not the part's",
                vec![
                    one.clone(),
                    PartReceipt {
                        length: two.length + 1,
                        ..two.clone()
                    },
                ],
            ),
            (
                "a checksum that is not the part's",
                vec![
                    one.clone(),
                    PartReceipt {
                        checksum_crc32c: two.checksum_crc32c ^ 1,
                        ..two.clone()
                    },
                ],
            ),
        ] {
            assert_eq!(
                store.complete_multipart(&upload_id, &parts),
                Err(Error::CompletionMismatch),
                "{name}"
            );
        }

        let mut from_two = endpoint.store();
        let second_upload = from_two.create_multipart("key", 0).expect("an upload");
        let two_of_two = from_two
            .upload_part(&second_upload, 2, b"two", vot_journal::crc32c(b"two"))
            .expect("a second part with no first");
        let three = from_two
            .upload_part(&second_upload, 3, b"three", vot_journal::crc32c(b"three"))
            .expect("a third part");
        assert_eq!(
            from_two.complete_multipart(&second_upload, &[two_of_two, three.clone()]),
            Err(Error::CompletionMismatch),
            "an upload that does not begin at the first part"
        );

        let mut gapped = endpoint.store();
        let third_upload = gapped.create_multipart("key", 0).expect("an upload");
        let first = gapped
            .upload_part(&third_upload, 1, b"one", vot_journal::crc32c(b"one"))
            .expect("a first part");
        let third = gapped
            .upload_part(&third_upload, 3, b"three", vot_journal::crc32c(b"three"))
            .expect("a third part with no second");
        assert_eq!(
            gapped.complete_multipart(&third_upload, &[first, third]),
            Err(Error::CompletionMismatch),
            "an upload with a part missing from the middle"
        );

        let completed = store
            .complete_multipart(&upload_id, &[one, two])
            .expect("the completion that matches");
        assert!(is_expectation(completed.expectation(), b"onetwo"));
    }

    #[test]
    fn malformed_expectation_does_not_consume_the_upload() {
        let endpoint = FakeS3::new(happy_endpoint(b"onetwo"));
        let mut store = endpoint.store();
        let upload_id = store.create_multipart("key", 0).expect("an upload");
        let one = store
            .upload_part(&upload_id, 1, b"one", vot_journal::crc32c(b"one"))
            .expect("the first part");
        let two = store
            .upload_part(&upload_id, 2, b"two", vot_journal::crc32c(b"two"))
            .expect("the second part");
        let overflowing = [
            PartReceipt {
                length: u64::MAX,
                ..one.clone()
            },
            PartReceipt {
                length: 1,
                ..two.clone()
            },
        ];
        assert_eq!(
            store.complete_multipart(&upload_id, &overflowing),
            Err(Error::CompletionMismatch)
        );
        let completed = store
            .complete_multipart(&upload_id, &[one, two])
            .expect("the retained upload remains completable");
        assert!(is_expectation(completed.expectation(), b"onetwo"));
    }

    #[test]
    fn explicit_readback_rejects_an_object_that_is_not_what_went_up() {
        let endpoint = FakeS3::new(happy_endpoint(b"something else"));
        let mut store = endpoint.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let completed = store
            .complete_multipart(&upload_id, &[receipt])
            .expect("completion itself succeeded");
        assert_eq!(
            store.verify_by_readback(completed.expectation()),
            Err(Error::ChecksumMismatch)
        );

        let swapped = FakeS3::new(happy_endpoint(b"paylaod"));
        let mut store = swapped.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let completed = store
            .complete_multipart(&upload_id, &[receipt])
            .expect("completion itself succeeded");
        assert_eq!(
            store.verify_by_readback(completed.expectation()),
            Err(Error::ChecksumMismatch)
        );
    }

    #[test]
    fn ambiguous_completion_requires_explicit_readback() {
        let endpoint = FakeS3::new(ambiguous_endpoint(b"payload"));
        let mut store = endpoint.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let expected = ObjectExpectation::from_parts("key", std::slice::from_ref(&receipt))
            .expect("a valid expectation");
        assert_eq!(
            store.complete_multipart(&upload_id, &[receipt]),
            Err(Error::CompletionAmbiguous)
        );
        assert_eq!(
            endpoint
                .requests()
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["POST", "PUT", "POST"],
            "ambiguity is not reconciled implicitly"
        );
        let verified = store
            .verify_by_readback(&expected)
            .expect("the caller explicitly reconciles the ambiguity");
        assert!(is_object(verified.object(), b"payload"));
        store.release_multipart(&upload_id);
        assert_eq!(
            store.complete_multipart(
                &upload_id,
                &[PartReceipt {
                    number: 1,
                    checksum_crc32c: vot_journal::crc32c(b"payload"),
                    length: 7,
                }]
            ),
            Err(Error::UnknownUpload),
            "reconciled completion state is released"
        );

        let wrong = FakeS3::new(ambiguous_endpoint(b"something else"));
        let mut store = wrong.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let expected = ObjectExpectation::from_parts("key", std::slice::from_ref(&receipt))
            .expect("a valid expectation");
        assert_eq!(
            store.complete_multipart(&upload_id, &[receipt]),
            Err(Error::CompletionAmbiguous)
        );
        assert_eq!(
            store.verify_by_readback(&expected),
            Err(Error::ChecksumMismatch)
        );

        let absent = FakeS3::new(|request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else if request.is_upload_part() {
                let checksum = request
                    .header("x-amz-checksum-crc32c")
                    .unwrap_or_default()
                    .to_owned();
                response(
                    "200 OK",
                    &[("etag", "\"part-1\""), ("x-amz-checksum-crc32c", &checksum)],
                    b"",
                )
            } else if request.is_complete_multipart() {
                completed_upload()
            } else {
                service_error("404 Not Found", "NoSuchKey")
            }
        });
        let mut store = absent.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let expected = ObjectExpectation::from_parts("key", std::slice::from_ref(&receipt))
            .expect("a valid expectation");
        let completed = store
            .complete_multipart(&upload_id, &[receipt])
            .expect("the endpoint confirmed completion");
        assert_eq!(completed.expectation(), &expected);
        assert_eq!(
            store.stat_object("key"),
            Ok(None),
            "metadata distinguishes absence from backend failure"
        );
        assert_eq!(
            store.verify_by_readback(&expected),
            Err(Error::ObjectNotFound),
            "readback preserves absence"
        );
    }

    #[test]
    fn a_completion_that_is_never_answered_remains_ambiguous() {
        let endpoint = FakeS3::new(|request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else if request.is_upload_part() {
                let checksum = request
                    .header("x-amz-checksum-crc32c")
                    .unwrap_or_default()
                    .to_owned();
                response(
                    "200 OK",
                    &[("etag", "\"part-1\""), ("x-amz-checksum-crc32c", &checksum)],
                    b"",
                )
            } else if request.is_complete_multipart() {
                Vec::new()
            } else {
                response("200 OK", &[], b"payload")
            }
        });
        let mut store = endpoint.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        let expected = ObjectExpectation::from_parts("key", std::slice::from_ref(&receipt))
            .expect("a valid expectation");
        assert_eq!(
            store.complete_multipart(&upload_id, &[receipt]),
            Err(Error::CompletionAmbiguous)
        );
        let verified = store
            .verify_by_readback(&expected)
            .expect("explicit reconciliation succeeds");
        assert!(is_object(verified.object(), b"payload"));
    }

    #[test]
    fn a_completion_the_endpoint_refuses_outright_is_a_backend_failure() {
        let endpoint = FakeS3::new(|request: &Request| {
            if request.is_create_multipart() {
                created("upload-1")
            } else if request.is_upload_part() {
                let checksum = request
                    .header("x-amz-checksum-crc32c")
                    .unwrap_or_default()
                    .to_owned();
                response(
                    "200 OK",
                    &[("etag", "\"part-1\""), ("x-amz-checksum-crc32c", &checksum)],
                    b"",
                )
            } else if request.is_complete_multipart() {
                service_error("412 Precondition Failed", "PreconditionFailed")
            } else {
                response("200 OK", &[], b"payload")
            }
        });
        let mut store = endpoint.store();
        let (upload_id, receipt) = upload_one_part(&mut store, b"payload");
        assert_eq!(
            store.complete_multipart(&upload_id, std::slice::from_ref(&receipt)),
            Err(Error::Backend)
        );
        assert_eq!(
            store.complete_multipart(&upload_id, &[receipt]),
            Err(Error::Backend)
        );
    }

    #[test]
    fn an_endpoint_that_says_nothing_is_a_backend_failure() {
        let mut store =
            AwsS3Store::new("http://127.0.0.1:1", "bucket", "us-east-1", "key", "secret")
                .expect("a store against a closed port");
        assert_eq!(store.create_multipart("key", 0), Err(Error::Backend));
        assert_eq!(store.stat_object("key"), Err(Error::Backend));
        let expected = ObjectExpectation::from_parts(
            "key",
            &[PartReceipt {
                number: 1,
                checksum_crc32c: vot_journal::crc32c(b"payload"),
                length: 7,
            }],
        )
        .expect("a valid expectation");
        assert_eq!(store.verify_by_readback(&expected), Err(Error::Backend));
        assert_eq!(store.delete_object("key"), Err(Error::Backend));
        assert_eq!(
            store.upload_part("upload-1", 1, b"payload", vot_journal::crc32c(b"payload")),
            Err(Error::UnknownUpload),
            "no upload was ever created"
        );
    }

    #[test]
    fn measuring_adds_up_across_the_chunks_a_body_arrives_in() {
        // Every other body here is a handful of bytes and arrives whole, so
        // nothing exercised the accumulation. This one is large enough that
        // the transport has to deliver it in pieces, which is what every real
        // multipart object does.
        static BIG: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(|| (0..=255_u8).cycle().take(4 * 1024 * 1024).collect());

        let endpoint = FakeS3::new(|request: &Request| {
            if request.method == "GET" {
                response("200 OK", &[], &BIG)
            } else {
                service_error("500 Internal Server Error", "InternalError")
            }
        });
        let store = endpoint.store();
        let expected = ObjectExpectation::from_parts(
            "key",
            &[PartReceipt {
                number: 1,
                checksum_crc32c: vot_journal::crc32c(&BIG),
                length: BIG.len() as u64,
            }],
        )
        .expect("a valid expectation");
        let verified = store
            .verify_by_readback(&expected)
            .expect("the full body verifies");
        assert!(
            is_object(verified.object(), &BIG),
            "the measurement is of the whole body, not of its last piece"
        );
    }

    #[test]
    fn retained_parts_detect_stable_read_back_corruption() {
        let mut parts = BTreeMap::new();
        parts.insert(
            2,
            LivePart {
                length: b"two".len() as u64,
                checksum_crc32c: vot_journal::crc32c(b"two"),
                etag: "two".to_owned(),
            },
        );
        parts.insert(
            1,
            LivePart {
                length: b"one".len() as u64,
                checksum_crc32c: vot_journal::crc32c(b"one"),
                etag: "one".to_owned(),
            },
        );
        let expected_checksum = crc32c_parts(&parts);
        assert_eq!(expected_checksum, vot_journal::crc32c(b"onetwo"));
        assert_ne!(expected_checksum, vot_journal::crc32c(b"twoone"));
        assert_eq!(crc32c_parts(&BTreeMap::new()), vot_journal::crc32c(b""));

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
        assert!(!read_back_matches(
            6,
            expected_checksum,
            7,
            expected_checksum
        ));
        assert!(!read_back_matches(6, expected_checksum, 7, 0));
    }

    #[test]
    fn transient_completion_errors_enter_reconciliation() {
        for code in [
            "NoSuchUpload",
            "SlowDown",
            "InternalError",
            "ServiceUnavailable",
            "RequestTimeout",
        ] {
            assert!(
                completion_error_may_be_ambiguous(Some(code), false),
                "{code}"
            );
        }
        assert!(completion_error_may_be_ambiguous(Some("Unknown"), true));
        assert!(!completion_error_may_be_ambiguous(
            Some("PreconditionFailed"),
            false
        ));
        assert!(!completion_error_may_be_ambiguous(None, false));
        assert!(object_not_found(Some("NoSuchKey")));
        assert!(object_not_found(Some("NotFound")));
        assert!(!object_not_found(Some("AccessDenied")));
        assert!(!object_not_found(None));
    }
}
