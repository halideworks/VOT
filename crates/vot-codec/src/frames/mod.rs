//! Typed application payloads for the VOT v0.3 frame envelope.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{
    DecodeError, DecodeLimits, DecodedFrame, decode_one, encode_frame, encode_varint, frame_type,
};
use std::ops::Range;

const MAX_OBJECT_LENGTH: u64 = i64::MAX as u64;
const GROUP_BYTES: u64 = 65_536;

mod assurance;
mod cbor;
mod fec;
mod manifest;
mod session;
mod transfer;

pub use assurance::*;
use cbor::{Reader, cbor_byte_string_len, cbor_head_len, decode_object, encode_object};
pub use fec::*;
pub use manifest::*;
pub use session::*;
pub use transfer::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Envelope(DecodeError),
    WrongFrameType(u64),
    Malformed,
    InvalidValue,
    TooLarge,
    Manifest,
    Seal,
    Receipt,
}

impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        Self::Envelope(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
    pub suite: u16,
    pub root: [u8; 32],
    pub length: u64,
}

impl ObjectId {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.suite, 1 | 2) || self.length > MAX_OBJECT_LENGTH {
            Err(Error::InvalidValue)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedFrame {
    AuthContext(AuthContext),
    SessionOpen(SessionOpen),
    SessionAccept(SessionAccept),
    SessionReject(SessionReject),
    PackageDescriptor(PackageDescriptor),
    ManifestRequest(ManifestRequest),
    ManifestPage(Vec<u8>),
    Seal(Vec<u8>),
    Have(Have),
    RangeRequest(RangeRequest),
    ProofBundle(ProofBundle),
    DataRecord(DataRecord),
    Capacity(Capacity),
    TransitVerified(AssuranceFrame),
    ChunkDurable(AssuranceFrame),
    ChunkAtRestVerified(AssuranceFrame),
    PublishReceipt(Vec<u8>),
    DatagramCredit(DatagramCredit),
    CodingEpochOpen(CodingEpochOpen),
    GenState(GenState),
    GenDone(GenDone),
    CodingEpochClose(CodingEpochClose),
}

impl TypedFrame {
    #[must_use]
    pub const fn frame_type(&self) -> u64 {
        match self {
            Self::AuthContext(_) => frame_type::AUTH_CONTEXT,
            Self::SessionOpen(_) => frame_type::SESSION_OPEN,
            Self::SessionAccept(_) => frame_type::SESSION_ACCEPT,
            Self::SessionReject(_) => frame_type::SESSION_REJECT,
            Self::PackageDescriptor(_) => frame_type::PACKAGE_DESCRIPTOR,
            Self::ManifestRequest(_) => frame_type::MANIFEST_REQUEST,
            Self::ManifestPage(_) => frame_type::MANIFEST_PAGE,
            Self::Seal(_) => frame_type::SEAL,
            Self::Have(_) => frame_type::HAVE,
            Self::RangeRequest(_) => frame_type::RANGE_REQUEST,
            Self::ProofBundle(_) => frame_type::PROOF_BUNDLE,
            Self::DataRecord(_) => frame_type::DATA_RECORD,
            Self::Capacity(_) => frame_type::CAPACITY,
            Self::TransitVerified(_) => frame_type::TRANSIT_VERIFIED,
            Self::ChunkDurable(_) => frame_type::CHUNK_DURABLE,
            Self::ChunkAtRestVerified(_) => frame_type::CHUNK_AT_REST_VERIFIED,
            Self::PublishReceipt(_) => frame_type::PUBLISH_RECEIPT,
            Self::DatagramCredit(_) => frame_type::DATAGRAM_CREDIT,
            Self::CodingEpochOpen(_) => frame_type::CODING_EPOCH_OPEN,
            Self::GenState(_) => frame_type::GEN_STATE,
            Self::GenDone(_) => frame_type::GEN_DONE,
            Self::CodingEpochClose(_) => frame_type::CODING_EPOCH_CLOSE,
        }
    }
}

/// Encodes one typed frame and its bounded envelope.
pub fn encode(frame: &TypedFrame, output: &mut Vec<u8>) -> Result<(), Error> {
    if let TypedFrame::DataRecord(value) = frame {
        return encode_data_record(value.into(), output);
    }
    let mut payload = Vec::new();
    match frame {
        TypedFrame::AuthContext(value) => encode_auth_context(value, &mut payload)?,
        TypedFrame::SessionOpen(value) => encode_session_open(value, &mut payload)?,
        TypedFrame::SessionAccept(value) => encode_session_accept(value, &mut payload)?,
        TypedFrame::SessionReject(value) => encode_session_reject(value, &mut payload)?,
        TypedFrame::PackageDescriptor(value) => encode_package_descriptor(value, &mut payload)?,
        TypedFrame::ManifestRequest(value) => encode_manifest_request(value, &mut payload)?,
        TypedFrame::ManifestPage(bytes) => {
            validate_manifest_page(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Seal(bytes) => {
            validate_seal(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::Have(value) => encode_have(value, &mut payload)?,
        TypedFrame::RangeRequest(value) => encode_range_request(value, &mut payload)?,
        TypedFrame::ProofBundle(value) => encode_proof_bundle(value, &mut payload)?,
        TypedFrame::DataRecord(_) => unreachable!("data records return above"),
        TypedFrame::Capacity(value) => encode_capacity(value, &mut payload),
        TypedFrame::TransitVerified(value)
        | TypedFrame::ChunkDurable(value)
        | TypedFrame::ChunkAtRestVerified(value) => encode_assurance(value, &mut payload)?,
        TypedFrame::PublishReceipt(bytes) => {
            validate_receipt(bytes)?;
            payload.extend_from_slice(bytes);
        }
        TypedFrame::DatagramCredit(value) => encode_datagram_credit(value, &mut payload),
        TypedFrame::CodingEpochOpen(value) => encode_coding_epoch_open(value, &mut payload)?,
        TypedFrame::GenState(value) => encode_gen_state(value, &mut payload)?,
        TypedFrame::GenDone(value) => encode_gen_done(value, &mut payload),
        TypedFrame::CodingEpochClose(value) => encode_coding_epoch_close(*value, &mut payload),
    }
    encode_frame(frame.frame_type(), &payload, output)?;
    Ok(())
}

/// Encodes one borrowed data record and its bounded envelope.
pub fn encode_data_record(value: DataRecordRef<'_>, output: &mut Vec<u8>) -> Result<(), Error> {
    let encoded = value.encoded;
    begin_data_record(value.into(), output)?;
    output.extend_from_slice(encoded);
    Ok(())
}

/// Encodes a data-record envelope up to its encoded-byte field, reserves that
/// field, and returns the range that appending its bytes will fill.
pub fn begin_data_record(
    value: DataRecordHeader,
    output: &mut Vec<u8>,
) -> Result<Range<usize>, Error> {
    validate_data_record_header(value)?;
    let payload_len = data_record_payload_len(value);
    let length_width = match payload_len {
        0..=63 => 1,
        64..=16_383 => 2,
        _ => 4,
    };
    output.reserve_exact(payload_len.saturating_add(1 + length_width));
    encode_varint(frame_type::DATA_RECORD, output)?;
    encode_varint(payload_len as u64, output)?;
    encode_validated_data_record_header(value, output);
    let start = output.len();
    Ok(start..start.saturating_add(value.encoded_length))
}

/// Encodes a data-record envelope with a zeroed encoded-byte field and returns
/// the field's range so a caller can fill it in place.
pub fn reserve_data_record(
    value: DataRecordHeader,
    output: &mut Vec<u8>,
) -> Result<Range<usize>, Error> {
    let range = begin_data_record(value, output)?;
    output.resize(range.end, 0);
    Ok(range)
}

/// Decodes one `DATA_RECORD` frame, borrowing its encoded bytes from `input`.
///
/// # Errors
/// Returns [`Error::WrongFrameType`] for any other frame, and the same
/// envelope and record failures as [`decode`].
pub fn decode_data_record_ref(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<(DataRecordRef<'_>, usize), Error> {
    let (decoded, consumed) = decode_one(input, limits)?;
    let frame_kind = decoded.frame_type();
    let DecodedFrame::Known { payload, .. } = decoded else {
        return Err(Error::WrongFrameType(frame_kind));
    };
    if frame_kind != frame_type::DATA_RECORD {
        return Err(Error::WrongFrameType(frame_kind));
    }
    Ok((decode_data_record_ref_payload(payload)?, consumed))
}

/// Decodes one typed frame without accepting an unknown application payload.
pub fn decode(input: &[u8], limits: DecodeLimits) -> Result<(TypedFrame, usize), Error> {
    let (decoded, consumed) = decode_one(input, limits)?;
    let frame_kind = decoded.frame_type();
    let payload = match decoded {
        DecodedFrame::Known { payload, .. } => payload,
        DecodedFrame::SkippedOptional { .. } => return Err(Error::WrongFrameType(frame_kind)),
    };
    let frame = match frame_kind {
        frame_type::AUTH_CONTEXT => TypedFrame::AuthContext(decode_auth_context(payload)?),
        frame_type::SESSION_OPEN => TypedFrame::SessionOpen(decode_session_open(payload)?),
        frame_type::SESSION_ACCEPT => TypedFrame::SessionAccept(decode_session_accept(payload)?),
        frame_type::SESSION_REJECT => TypedFrame::SessionReject(decode_session_reject(payload)?),
        frame_type::PACKAGE_DESCRIPTOR => {
            TypedFrame::PackageDescriptor(decode_package_descriptor(payload)?)
        }
        frame_type::MANIFEST_REQUEST => {
            TypedFrame::ManifestRequest(decode_manifest_request(payload)?)
        }
        frame_type::MANIFEST_PAGE => {
            validate_manifest_page(payload)?;
            TypedFrame::ManifestPage(payload.to_vec())
        }
        frame_type::SEAL => {
            validate_seal(payload)?;
            TypedFrame::Seal(payload.to_vec())
        }
        frame_type::HAVE => TypedFrame::Have(decode_have(payload)?),
        frame_type::RANGE_REQUEST => TypedFrame::RangeRequest(decode_range_request(payload)?),
        frame_type::PROOF_BUNDLE => TypedFrame::ProofBundle(decode_proof_bundle(payload)?),
        frame_type::DATA_RECORD => TypedFrame::DataRecord(decode_data_record(payload)?),
        frame_type::CAPACITY => TypedFrame::Capacity(decode_capacity(payload)?),
        frame_type::TRANSIT_VERIFIED => TypedFrame::TransitVerified(decode_assurance(payload)?),
        frame_type::CHUNK_DURABLE => TypedFrame::ChunkDurable(decode_assurance(payload)?),
        frame_type::CHUNK_AT_REST_VERIFIED => {
            TypedFrame::ChunkAtRestVerified(decode_assurance(payload)?)
        }
        frame_type::PUBLISH_RECEIPT => {
            validate_receipt(payload)?;
            TypedFrame::PublishReceipt(payload.to_vec())
        }
        frame_type::DATAGRAM_CREDIT => TypedFrame::DatagramCredit(decode_datagram_credit(payload)?),
        frame_type::CODING_EPOCH_OPEN => {
            TypedFrame::CodingEpochOpen(decode_coding_epoch_open(payload)?)
        }
        frame_type::GEN_STATE => TypedFrame::GenState(decode_gen_state(payload)?),
        frame_type::GEN_DONE => TypedFrame::GenDone(decode_gen_done(payload)?),
        frame_type::CODING_EPOCH_CLOSE => {
            TypedFrame::CodingEpochClose(decode_coding_epoch_close(payload)?)
        }
        other => return Err(Error::WrongFrameType(other)),
    };
    Ok((frame, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> ObjectId {
        ObjectId {
            suite: 1,
            root: [7; 32],
            length: GROUP_BYTES * 2,
        }
    }

    fn wide_object() -> ObjectId {
        ObjectId {
            suite: 2,
            root: [9; 32],
            length: GROUP_BYTES * 64,
        }
    }

    /// A HAVE map at exactly its registered payload limit.
    fn have_at_payload_limit() -> Have {
        let limit = crate::registered_payload_limit(frame_type::HAVE).unwrap();
        let mut value = Have {
            object: ObjectId {
                suite: 2,
                root: [3; 32],
                length: MAX_OBJECT_LENGTH,
            },
            map_sequence: 0,
            runs: Vec::new(),
        };
        // Runs spaced 25 groups apart; sizes measured by the function under test.
        let mut total = have_payload_len(&value);
        for index in 0..MAX_HAVE_RUNS {
            let run = HaveRun {
                start_group: index * 25,
                group_count: 1,
            };
            let cost = have_run_len(&run);
            if total + cost > limit {
                break;
            }
            total += cost;
            value.runs.push(run);
        }
        // Re-measure: the array head widened as runs were added.
        while have_payload_len(&value) > limit {
            assert!(value.runs.pop().is_some(), "no map reaches the limit");
        }
        // Spend remaining bytes by widening run counts.
        let short = limit - have_payload_len(&value);
        for run in value.runs.iter_mut().take(short) {
            run.group_count = 24;
        }
        assert_eq!(have_payload_len(&value), limit, "the limit was not reached");
        value
    }

    #[test]
    fn a_have_map_at_its_registered_limit_is_carried_and_one_byte_more_is_not() {
        let limit = crate::registered_payload_limit(frame_type::HAVE).unwrap();
        let value = have_at_payload_limit();

        let mut encoded = Vec::new();
        encode(&TypedFrame::Have(value.clone()), &mut encoded).unwrap();
        // The refused size must match what encode would actually write.
        assert_eq!(payload_of(&encoded).len(), limit);
        assert_eq!(decode_have(payload_of(&encoded)), Ok(value.clone()));
        assert_eq!(
            decode(&encoded, DecodeLimits::default()),
            Ok((TypedFrame::Have(value.clone()), encoded.len())),
            "a map at its limit is a frame the layer above carries"
        );

        // One byte over, via the map sequence.
        let over = Have {
            map_sequence: 24,
            ..value
        };
        assert_eq!(have_payload_len(&over), limit + 1);
        assert_eq!(validate_have(&over), Err(Error::TooLarge));
    }

    #[test]
    fn a_have_map_is_refused_before_its_runs_are_reserved() {
        // Run count is bounded by the registry and by remaining bytes.
        let valid = have();
        let mut encoded = Vec::new();
        encode(&TypedFrame::Have(valid.clone()), &mut encoded).unwrap();
        let payload = payload_of(&encoded);
        assert_eq!(decode_have(payload), Ok(valid));

        // Run count exceeds what the remaining bytes can hold.
        let mut lying = Vec::new();
        vot_cbor::map(&mut lying, 3);
        vot_cbor::uint(&mut lying, 0);
        encode_object(&wide_object(), &mut lying);
        vot_cbor::uint(&mut lying, 1);
        vot_cbor::uint(&mut lying, 3);
        vot_cbor::uint(&mut lying, 2);
        vot_cbor::array(&mut lying, 64);
        assert_eq!(decode_have(&lying), Err(Error::Malformed));

        // Count of 4 exceeds the 6 bytes two runs occupy.
        let mut over_half = Vec::new();
        vot_cbor::map(&mut over_half, 3);
        vot_cbor::uint(&mut over_half, 0);
        encode_object(&wide_object(), &mut over_half);
        vot_cbor::uint(&mut over_half, 1);
        vot_cbor::uint(&mut over_half, 3);
        vot_cbor::uint(&mut over_half, 2);
        vot_cbor::array(&mut over_half, 4);
        for index in 0..2u64 {
            vot_cbor::array(&mut over_half, 2);
            vot_cbor::uint(&mut over_half, index * 2);
            vot_cbor::uint(&mut over_half, 1);
        }
        assert_eq!(decode_have(&over_half), Err(Error::Malformed));

        // Empty runs are valid: the peer has verified nothing yet.
        let empty = Have {
            object: wide_object(),
            map_sequence: 7,
            runs: Vec::new(),
        };
        let mut encoded_empty = Vec::new();
        encode(&TypedFrame::Have(empty.clone()), &mut encoded_empty).unwrap();
        assert_eq!(decode_have(payload_of(&encoded_empty)), Ok(empty));

        let mut exact = Vec::new();
        vot_cbor::map(&mut exact, 3);
        vot_cbor::uint(&mut exact, 0);
        encode_object(&wide_object(), &mut exact);
        vot_cbor::uint(&mut exact, 1);
        vot_cbor::uint(&mut exact, 3);
        vot_cbor::uint(&mut exact, 2);
        vot_cbor::array(&mut exact, 2);
        for index in 0..2u64 {
            vot_cbor::array(&mut exact, 2);
            vot_cbor::uint(&mut exact, index * 2);
            vot_cbor::uint(&mut exact, 1);
        }
        assert!(decode_have(&exact).is_ok(), "a count the bytes can hold");

        // Run at the last group (edge of the end check).
        let groups = wide_object().length.div_ceil(GROUP_BYTES);
        round_trip(&TypedFrame::Have(Have {
            runs: vec![HaveRun {
                start_group: groups - 1,
                group_count: 1,
            }],
            ..have()
        }));
    }

    /// The payload of a single encoded frame, envelope removed.
    fn payload_of(frame: &[u8]) -> &[u8] {
        let limits = DecodeLimits {
            max_unknown_payload: 1 << 22,
            max_frames: 1,
        };
        let (decoded, _) = crate::decode_one(frame, limits).unwrap();
        match decoded {
            crate::DecodedFrame::Known { payload, .. } => payload,
            crate::DecodedFrame::SkippedOptional { .. } => panic!("a known frame"),
        }
    }

    #[test]
    fn a_seal_is_bounded_by_the_payload_its_registry_entry_allows() {
        let limit = crate::registered_payload_limit(frame_type::SEAL)
            .expect("a seal has a registered payload limit");
        // One byte over: size refusal before manifest parsing.
        assert_eq!(validate_seal(&vec![0; limit + 1]), Err(Error::TooLarge));
        // At the limit: manifest parse failure, not size.
        assert_eq!(validate_seal(&vec![0; limit]), Err(Error::Seal));
    }

    #[test]
    fn a_challenge_outside_its_bounds_never_reaches_the_wire() {
        // A refused challenge must not encode through the payload API.
        let mut out = Vec::new();
        assert_eq!(
            encode_auth_context_payload(
                &AuthContext {
                    nonce: vec![1; MIN_AUTH_NONCE - 1],
                    binding: Binding::None,
                    formats: Vec::new(),
                },
                &mut out
            ),
            Err(Error::InvalidValue)
        );
        assert!(out.is_empty());
        assert_eq!(
            encode_auth_context_payload(
                &AuthContext {
                    nonce: vec![1; MIN_AUTH_NONCE],
                    binding: Binding::None,
                    formats: Vec::new(),
                },
                &mut out
            ),
            Ok(())
        );
        assert!(!out.is_empty(), "and one inside them does");
    }

    #[test]
    fn a_covered_range_that_stops_short_of_the_object_ends_on_a_group() {
        // A covered range at the object end may be short; one stopping early must be group-aligned.
        let ragged = ObjectId {
            length: GROUP_BYTES * 2 + 17,
            ..wide_object()
        };
        assert_eq!(
            validate_proof_bundle(&ProofBundle {
                object: ragged,
                requested_offset: GROUP_BYTES * 2,
                requested_length: 17,
                covered_offset: GROUP_BYTES * 2,
                covered_length: 17,
                total_plaintext_length: 17,
                data_record_count: 1,
                ..bundle()
            }),
            Ok(()),
            "the last group of the object, which is short"
        );
        assert_eq!(
            validate_proof_bundle(&ProofBundle {
                object: ragged,
                requested_offset: 0,
                requested_length: 17,
                covered_offset: 0,
                covered_length: 17,
                total_plaintext_length: 17,
                data_record_count: 1,
                ..bundle()
            }),
            Err(Error::InvalidValue),
            "a covered range that stops inside the object and not on a group"
        );
    }

    #[test]
    fn a_reader_that_has_not_finished_says_so() {
        let mut encoded = Vec::new();
        encode(
            &TypedFrame::Capacity(Capacity {
                epoch: 1,
                available_bytes: 2,
                bdp_target_bytes: 3,
                max_inflight_bytes: 4,
            }),
            &mut encoded,
        )
        .unwrap();
        let payload = payload_of(&encoded).to_vec();
        assert!(decode_capacity(&payload).is_ok());
        let mut trailing = payload;
        trailing.push(0);
        assert_eq!(decode_capacity(&trailing), Err(Error::Malformed));
    }

    #[test]
    fn an_object_identity_is_one_of_the_registered_suites_and_a_representable_length() {
        assert_eq!(object().validate(), Ok(()));
        for suite in [0, 3, u16::MAX] {
            assert_eq!(
                ObjectId { suite, ..object() }.validate(),
                Err(Error::InvalidValue),
                "suite {suite}"
            );
        }
        for suite in [1, 2] {
            assert_eq!(ObjectId { suite, ..object() }.validate(), Ok(()));
        }
        // Max length and one byte over.
        assert_eq!(
            ObjectId {
                length: MAX_OBJECT_LENGTH,
                ..object()
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            ObjectId {
                length: MAX_OBJECT_LENGTH + 1,
                ..object()
            }
            .validate(),
            Err(Error::InvalidValue)
        );
    }

    fn range_request() -> RangeRequest {
        RangeRequest {
            request_id: [1; 16],
            object: wide_object(),
            offset: GROUP_BYTES,
            length: GROUP_BYTES,
        }
    }

    #[test]
    fn every_rule_on_a_range_request_is_refused_on_its_own() {
        let valid = range_request();
        let mut out = Vec::new();
        assert_eq!(encode_range_request(&valid, &mut out), Ok(()));

        for (name, value) in [
            (
                "a zero length, which asks for nothing",
                RangeRequest {
                    length: 0,
                    ..valid.clone()
                },
            ),
            (
                "one byte past the largest range a request may name",
                RangeRequest {
                    offset: 0,
                    length: MAX_REQUESTED_RANGE + 1,
                    object: ObjectId {
                        length: MAX_OBJECT_LENGTH,
                        ..wide_object()
                    },
                    ..valid.clone()
                },
            ),
            (
                "an offset past the longest representable object",
                RangeRequest {
                    offset: MAX_OBJECT_LENGTH + 1,
                    length: 1,
                    ..valid.clone()
                },
            ),
            (
                "a range that ends past the object",
                RangeRequest {
                    offset: wide_object().length - 1,
                    length: 2,
                    ..valid.clone()
                },
            ),
            (
                "a range whose end overflows",
                RangeRequest {
                    offset: u64::MAX,
                    length: 2,
                    ..valid.clone()
                },
            ),
            (
                "an object identity that is not valid",
                RangeRequest {
                    object: ObjectId {
                        suite: 9,
                        ..wide_object()
                    },
                    ..valid.clone()
                },
            ),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                encode_range_request(&value, &mut out),
                Err(Error::InvalidValue),
                "{name}"
            );
            assert!(out.is_empty(), "{name} wrote bytes before refusing");
        }

        let mut out = Vec::new();
        assert_eq!(
            encode_range_request(
                &RangeRequest {
                    offset: 0,
                    length: MAX_REQUESTED_RANGE,
                    object: ObjectId {
                        length: MAX_OBJECT_LENGTH,
                        ..wide_object()
                    },
                    ..valid.clone()
                },
                &mut out
            ),
            Ok(())
        );
        out.clear();
        assert_eq!(
            encode_range_request(
                &RangeRequest {
                    offset: wide_object().length - 1,
                    length: 1,
                    ..valid
                },
                &mut out
            ),
            Ok(()),
            "the last byte of the object"
        );
    }

    fn manifest_request() -> ManifestRequest {
        ManifestRequest {
            request_id: [1; 16],
            manifest_id: [2; 16],
            first_page: 0,
            page_count: 4,
        }
    }

    #[test]
    fn every_rule_on_a_manifest_request_is_refused_on_its_own() {
        round_trip(&TypedFrame::ManifestRequest(manifest_request()));
        for (name, value) in [
            (
                "no pages, which asks for nothing",
                ManifestRequest {
                    page_count: 0,
                    ..manifest_request()
                },
            ),
            (
                "one page past the bound",
                ManifestRequest {
                    page_count: MAX_MANIFEST_REQUEST_PAGES + 1,
                    ..manifest_request()
                },
            ),
            (
                "a first page past the longest representable object",
                ManifestRequest {
                    first_page: MAX_OBJECT_LENGTH + 1,
                    ..manifest_request()
                },
            ),
            (
                "a page range whose end overflows",
                ManifestRequest {
                    first_page: u64::MAX,
                    page_count: 2,
                    ..manifest_request()
                },
            ),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                encode(&TypedFrame::ManifestRequest(value), &mut out),
                Err(Error::InvalidValue),
                "{name}"
            );
        }
        // Both bounds at their own maximum.
        round_trip(&TypedFrame::ManifestRequest(ManifestRequest {
            page_count: MAX_MANIFEST_REQUEST_PAGES,
            ..manifest_request()
        }));
        round_trip(&TypedFrame::ManifestRequest(ManifestRequest {
            first_page: MAX_OBJECT_LENGTH,
            page_count: 1,
            ..manifest_request()
        }));
    }

    fn have() -> Have {
        Have {
            object: wide_object(),
            map_sequence: 3,
            runs: vec![
                HaveRun {
                    start_group: 0,
                    group_count: 2,
                },
                HaveRun {
                    start_group: 4,
                    group_count: 1,
                },
            ],
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one row per rule reads as a table")]
    fn every_rule_on_a_have_map_is_refused_on_its_own() {
        round_trip(&TypedFrame::Have(have()));
        let groups = wide_object().length.div_ceil(GROUP_BYTES);

        for (name, runs) in [
            (
                "a run of no groups",
                vec![HaveRun {
                    start_group: 0,
                    group_count: 0,
                }],
            ),
            (
                "runs out of order",
                vec![
                    HaveRun {
                        start_group: 4,
                        group_count: 1,
                    },
                    HaveRun {
                        start_group: 0,
                        group_count: 1,
                    },
                ],
            ),
            (
                "overlapping runs",
                vec![
                    HaveRun {
                        start_group: 0,
                        group_count: 4,
                    },
                    HaveRun {
                        start_group: 2,
                        group_count: 1,
                    },
                ],
            ),
            (
                "adjacent runs, which are one run written twice",
                vec![
                    HaveRun {
                        start_group: 0,
                        group_count: 2,
                    },
                    HaveRun {
                        start_group: 2,
                        group_count: 1,
                    },
                ],
            ),
            (
                "a run ending past the object's groups",
                vec![HaveRun {
                    start_group: groups - 1,
                    group_count: 2,
                }],
            ),
            (
                "a run whose end overflows",
                vec![HaveRun {
                    start_group: u64::MAX,
                    group_count: 2,
                }],
            ),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                encode(&TypedFrame::Have(Have { runs, ..have() }), &mut out),
                Err(Error::InvalidValue),
                "{name}"
            );
        }

        // Full-coverage run and a run starting at zero.
        round_trip(&TypedFrame::Have(Have {
            runs: vec![HaveRun {
                start_group: 0,
                group_count: groups,
            }],
            ..have()
        }));
        round_trip(&TypedFrame::Have(Have {
            runs: vec![HaveRun {
                start_group: groups - 1,
                group_count: 1,
            }],
            ..have()
        }));

        // Invalid object identity refused before runs are read.
        let mut out = Vec::new();
        assert_eq!(
            encode(
                &TypedFrame::Have(Have {
                    object: ObjectId {
                        suite: 0,
                        ..wide_object()
                    },
                    ..have()
                }),
                &mut out
            ),
            Err(Error::InvalidValue)
        );

        // Too many runs: size refusal.
        let crowded = Have {
            object: ObjectId {
                length: MAX_OBJECT_LENGTH,
                ..wide_object()
            },
            // Wide start groups for wider CBOR heads.
            runs: (0..400_000)
                .map(|index| HaveRun {
                    start_group: index * (1 << 40),
                    group_count: 1,
                })
                .collect(),
            ..have()
        };
        out.clear();
        assert_eq!(
            encode(&TypedFrame::Have(crowded), &mut out),
            Err(Error::TooLarge)
        );
    }

    fn bundle() -> ProofBundle {
        ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: wide_object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: vec![3; 64],
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one row per rule reads as a table")]
    fn every_rule_on_a_proof_bundle_is_refused_on_its_own() {
        let valid = bundle();
        assert_eq!(validate_proof_bundle(&valid), Ok(()));

        for (name, value) in [
            (
                "an object of no length",
                ProofBundle {
                    object: ObjectId {
                        length: 0,
                        ..wide_object()
                    },
                    ..valid.clone()
                },
            ),
            (
                "a requested length of zero",
                ProofBundle {
                    requested_length: 0,
                    ..valid.clone()
                },
            ),
            (
                // Same rule isolated: covered range agrees, so only zero-length check refuses.
                "a requested length of zero with a covered range that agrees",
                ProofBundle {
                    requested_offset: 1,
                    requested_length: 0,
                    covered_offset: 0,
                    covered_length: GROUP_BYTES,
                    total_plaintext_length: GROUP_BYTES,
                    ..valid.clone()
                },
            ),
            (
                "a requested range that ends past the object",
                ProofBundle {
                    requested_offset: wide_object().length - GROUP_BYTES,
                    requested_length: GROUP_BYTES + 1,
                    ..valid.clone()
                },
            ),
            (
                "a covered offset that is not the group the request starts in",
                ProofBundle {
                    covered_offset: 0,
                    ..valid.clone()
                },
            ),
            (
                "a covered offset past the requested one",
                ProofBundle {
                    requested_offset: GROUP_BYTES + 1,
                    covered_offset: GROUP_BYTES * 2,
                    ..valid.clone()
                },
            ),
            (
                "a covered length of zero",
                ProofBundle {
                    covered_length: 0,
                    ..valid.clone()
                },
            ),
            (
                "a covered range that ends past the object",
                ProofBundle {
                    requested_offset: wide_object().length - GROUP_BYTES,
                    covered_offset: wide_object().length - GROUP_BYTES,
                    covered_length: GROUP_BYTES * 2,
                    total_plaintext_length: GROUP_BYTES * 2,
                    ..valid.clone()
                },
            ),
            (
                "no data records",
                ProofBundle {
                    data_record_count: 0,
                    ..valid.clone()
                },
            ),
            (
                "one record more than a bundle may carry",
                ProofBundle {
                    data_record_count: MAX_DATA_RECORDS_PER_BUNDLE as u64 + 1,
                    ..valid.clone()
                },
            ),
            (
                "a plaintext length that is not the covered length",
                ProofBundle {
                    total_plaintext_length: GROUP_BYTES - 1,
                    ..valid.clone()
                },
            ),
            (
                "an object identity that is not valid",
                ProofBundle {
                    object: ObjectId {
                        suite: 7,
                        ..wide_object()
                    },
                    ..valid.clone()
                },
            ),
        ] {
            assert_eq!(
                validate_proof_bundle(&value),
                Err(Error::InvalidValue),
                "{name}"
            );
        }

        // All bounds at their maximum. Covered may exceed requested.
        let long = ObjectId {
            length: MAX_OBJECT_LENGTH,
            ..wide_object()
        };
        // Unaligned max request: 64 groups requested, 65 covered.
        assert_eq!(
            validate_proof_bundle(&ProofBundle {
                object: long,
                requested_offset: 1,
                requested_length: MAX_REQUESTED_RANGE,
                covered_offset: 0,
                covered_length: MAX_COVERED_RANGE,
                total_plaintext_length: MAX_COVERED_RANGE,
                data_record_count: MAX_DATA_RECORDS_PER_BUNDLE as u64,
                ..valid.clone()
            }),
            Ok(()),
            "every bound at its maximum together"
        );
        assert_eq!(
            validate_proof_bundle(&ProofBundle {
                object: long,
                requested_offset: 1,
                requested_length: MAX_REQUESTED_RANGE + 1,
                covered_offset: 0,
                covered_length: MAX_COVERED_RANGE,
                total_plaintext_length: MAX_COVERED_RANGE,
                ..valid.clone()
            }),
            Err(Error::InvalidValue),
            "one byte past the requested maximum"
        );
        // Covered end must match the request's aligned end.
        for covered_length in [MAX_COVERED_RANGE - GROUP_BYTES, MAX_COVERED_RANGE + 1] {
            assert_eq!(
                validate_proof_bundle(&ProofBundle {
                    object: long,
                    requested_offset: 1,
                    requested_length: MAX_REQUESTED_RANGE,
                    covered_offset: 0,
                    covered_length,
                    total_plaintext_length: covered_length,
                    ..valid.clone()
                }),
                Err(Error::InvalidValue),
                "{covered_length} covered"
            );
        }

        // Proof edge: where the payload estimate meets the registry limit.
        let limit = crate::registered_payload_limit(frame_type::PROOF_BUNDLE)
            .expect("a proof bundle has a registered payload limit");
        let widest = (1..=limit)
            .rev()
            .find(|proof_len| proof_bundle_payload_len_with(&valid, *proof_len) <= limit)
            .expect("some proof length fits");
        assert!(
            widest < MAX_PROOF_BYTES,
            "the fields take room of their own"
        );
        assert_eq!(
            validate_proof_bundle_with_proof_len(&valid, widest),
            Ok(()),
            "the widest proof that fits its payload"
        );
        assert_eq!(
            validate_proof_bundle_with_proof_len(&valid, widest + 1),
            Err(Error::InvalidValue),
            "and one byte more"
        );
    }

    fn assurance() -> AssuranceFrame {
        AssuranceFrame {
            object: wide_object(),
            sequence: 1,
            unit_start: 0,
            unit_count: 2,
        }
    }

    #[test]
    fn every_rule_on_an_assurance_frame_is_refused_on_its_own() {
        round_trip(&TypedFrame::TransitVerified(assurance()));
        let units = wide_object().length.div_ceil(GROUP_BYTES);

        for (name, value) in [
            (
                "a sequence of zero, which is not monotonic from anywhere",
                AssuranceFrame {
                    sequence: 0,
                    ..assurance()
                },
            ),
            (
                "no units",
                AssuranceFrame {
                    unit_count: 0,
                    ..assurance()
                },
            ),
            (
                "units ending past the object",
                AssuranceFrame {
                    unit_start: units - 1,
                    unit_count: 2,
                    ..assurance()
                },
            ),
            (
                "a unit range whose end overflows",
                AssuranceFrame {
                    unit_start: u64::MAX,
                    unit_count: 2,
                    ..assurance()
                },
            ),
            (
                "an object identity that is not valid",
                AssuranceFrame {
                    object: ObjectId {
                        suite: 0,
                        ..wide_object()
                    },
                    ..assurance()
                },
            ),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                encode(&TypedFrame::ChunkDurable(value), &mut out),
                Err(Error::InvalidValue),
                "{name}"
            );
        }

        // Every unit of the object, and the last unit alone.
        round_trip(&TypedFrame::ChunkAtRestVerified(AssuranceFrame {
            unit_start: 0,
            unit_count: units,
            ..assurance()
        }));
        round_trip(&TypedFrame::TransitVerified(AssuranceFrame {
            unit_start: units - 1,
            unit_count: 1,
            ..assurance()
        }));
    }

    #[test]
    fn a_package_descriptor_names_at_least_one_page() {
        let valid = PackageDescriptor {
            package: wide_object(),
            manifest_id: [4; 16],
            page_count: 1,
        };
        round_trip(&TypedFrame::PackageDescriptor(valid.clone()));
        let mut out = Vec::new();
        assert_eq!(
            encode(
                &TypedFrame::PackageDescriptor(PackageDescriptor {
                    page_count: 0,
                    ..valid.clone()
                }),
                &mut out
            ),
            Err(Error::InvalidValue)
        );
        out.clear();
        assert_eq!(
            encode(
                &TypedFrame::PackageDescriptor(PackageDescriptor {
                    package: ObjectId {
                        suite: 0,
                        ..wide_object()
                    },
                    ..valid
                }),
                &mut out
            ),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn a_capacity_frame_carries_what_it_was_given() {
        // Capacity is unbounded; verify all fields round-trip.
        round_trip(&TypedFrame::Capacity(Capacity {
            epoch: 7,
            available_bytes: 1 << 40,
            bdp_target_bytes: 1 << 20,
            max_inflight_bytes: u64::MAX,
        }));
        round_trip(&TypedFrame::Capacity(Capacity {
            epoch: 0,
            available_bytes: 0,
            bdp_target_bytes: 0,
            max_inflight_bytes: 0,
        }));
    }

    fn round_trip(frame: &TypedFrame) {
        let mut out = Vec::new();
        encode(frame, &mut out).unwrap();
        let limits = DecodeLimits {
            max_unknown_payload: 1 << 20,
            max_frames: 1,
        };
        let (decoded, consumed) = decode(&out, limits).unwrap();
        assert_eq!(&decoded, frame);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn session_authentication_frames_round_trip() {
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![7; 16],
            binding: Binding::ProofOfPossession,
            formats: vec![1, 2, 9],
        }));
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![3; 64],
            binding: Binding::None,
            formats: Vec::new(),
        }));
        round_trip(&TypedFrame::SessionOpen(SessionOpen {
            session_id: [4; 16],
            capability_format: 1,
            capability: vec![9; 128],
            requested_scope: Vec::new(),
            binding_proof: vec![1; 64],
        }));
        round_trip(&TypedFrame::SessionAccept(SessionAccept {
            session_id: [4; 16],
            granted_scope: vec![2; 32],
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [4; 16],
            reason: u64::from(crate::error_code::AUTHORIZATION_FAILED),
            detail: String::new(),
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [4; 16],
            reason: u64::from(crate::error_code::REPLAY_REJECTED),
            detail: "scope".to_owned(),
        }));
    }

    #[test]
    fn the_payload_api_reads_what_the_typed_frame_api_writes() {
        // Payload API must match typed frame dispatch for session frames.
        let frames = [
            TypedFrame::AuthContext(AuthContext {
                nonce: vec![1; MIN_AUTH_NONCE],
                binding: Binding::ProofOfPossession,
                formats: vec![1, 7],
            }),
            TypedFrame::SessionOpen(SessionOpen {
                session_id: [2; 16],
                capability_format: 7,
                capability: vec![3; 8],
                requested_scope: vec![4; 8],
                binding_proof: vec![5; 8],
            }),
            TypedFrame::SessionAccept(SessionAccept {
                session_id: [2; 16],
                granted_scope: vec![6; 8],
            }),
            TypedFrame::SessionReject(SessionReject {
                session_id: [2; 16],
                reason: u64::from(crate::error_code::REPLAY_REJECTED),
                detail: "why".to_owned(),
            }),
        ];
        let limits = DecodeLimits {
            max_unknown_payload: 64 * 1024,
            max_frames: 1,
        };
        for frame in frames {
            let mut encoded = Vec::new();
            encode(&frame, &mut encoded).unwrap();
            let (envelope, _) = crate::decode_one(&encoded, limits).unwrap();
            let crate::DecodedFrame::Known { payload, .. } = envelope else {
                panic!("every section 1.1 frame is a known type");
            };
            let read = match &frame {
                TypedFrame::AuthContext(_) => {
                    TypedFrame::AuthContext(decode_auth_context_payload(payload).unwrap())
                }
                TypedFrame::SessionOpen(_) => {
                    TypedFrame::SessionOpen(decode_session_open_payload(payload).unwrap())
                }
                TypedFrame::SessionAccept(_) => {
                    TypedFrame::SessionAccept(decode_session_accept_payload(payload).unwrap())
                }
                _ => TypedFrame::SessionReject(decode_session_reject_payload(payload).unwrap()),
            };
            assert_eq!(read, frame);
        }

        assert!(decode_session_accept_payload(&[]).is_err());

        // Valid CBOR with an unregistered rejection reason.
        let mut unregistered = Vec::new();
        vot_cbor::map(&mut unregistered, 4);
        vot_cbor::uint(&mut unregistered, 0);
        vot_cbor::uint(&mut unregistered, 0);
        vot_cbor::uint(&mut unregistered, 1);
        vot_cbor::bytes(&mut unregistered, &[2; 16]);
        vot_cbor::uint(&mut unregistered, 2);
        vot_cbor::uint(
            &mut unregistered,
            u64::from(crate::error_code::MALFORMED_FRAME),
        );
        vot_cbor::uint(&mut unregistered, 3);
        vot_cbor::text(&mut unregistered, "");
        assert_eq!(
            decode_session_reject_payload(&unregistered),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn every_authentication_bound_admits_its_own_maximum() {
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![1; MIN_AUTH_NONCE],
            binding: Binding::None,
            formats: (1..=MAX_CAPABILITY_FORMATS).collect(),
        }));
        round_trip(&TypedFrame::AuthContext(AuthContext {
            nonce: vec![1; MAX_AUTH_NONCE],
            binding: Binding::ProofOfPossession,
            formats: vec![MAX_CAPABILITY_FORMAT],
        }));
        round_trip(&TypedFrame::SessionOpen(SessionOpen {
            session_id: [1; 16],
            capability_format: MAX_CAPABILITY_FORMAT,
            capability: vec![2; MAX_CAPABILITY_BYTES],
            requested_scope: vec![3; MAX_SCOPE_BYTES],
            binding_proof: vec![4; MAX_SCOPE_BYTES],
        }));
        round_trip(&TypedFrame::SessionAccept(SessionAccept {
            session_id: [1; 16],
            granted_scope: vec![5; MAX_SCOPE_BYTES],
        }));
        round_trip(&TypedFrame::SessionReject(SessionReject {
            session_id: [1; 16],
            reason: u64::from(crate::error_code::AUTHENTICATION_FAILED),
            detail: "d".repeat(MAX_REJECT_DETAIL_BYTES),
        }));

        let mut out = Vec::new();
        let mut wide = SessionAccept {
            session_id: [1; 16],
            granted_scope: vec![5; MAX_SCOPE_BYTES + 1],
        };
        assert!(encode_session_accept(&wide, &mut out).is_err());
        wide.granted_scope.pop();
        out.clear();
        assert!(encode_session_accept(&wide, &mut out).is_ok());

        let mut long = SessionReject {
            session_id: [1; 16],
            reason: u64::from(crate::error_code::AUTHENTICATION_FAILED),
            detail: "d".repeat(MAX_REJECT_DETAIL_BYTES + 1),
        };
        out.clear();
        assert!(encode_session_reject(&long, &mut out).is_err());
        long.detail.pop();
        out.clear();
        assert!(encode_session_reject(&long, &mut out).is_ok());
    }

    #[test]
    fn an_auth_context_states_one_server_policy_one_way() {
        let context = |formats: Vec<u64>| AuthContext {
            nonce: vec![7; 16],
            binding: Binding::None,
            formats,
        };
        let mut out = Vec::new();
        // Descending or repeated formats would give one policy two encodings.
        assert!(encode_auth_context(&context(vec![2, 1]), &mut out).is_err());
        assert!(encode_auth_context(&context(vec![1, 1]), &mut out).is_err());
        // 0x0000 is reserved by spec/registries.md section 11.
        assert!(encode_auth_context(&context(vec![0]), &mut out).is_err());
        assert!(encode_auth_context(&context(vec![65_536]), &mut out).is_err());
        assert!(
            encode_auth_context(&context((1..=17).collect()), &mut out).is_err(),
            "at most 16 formats"
        );

        let short = AuthContext {
            nonce: vec![7; 15],
            binding: Binding::None,
            formats: Vec::new(),
        };
        assert!(encode_auth_context(&short, &mut out).is_err());
        let long = AuthContext {
            nonce: vec![7; 65],
            binding: Binding::None,
            formats: Vec::new(),
        };
        assert!(encode_auth_context(&long, &mut out).is_err());
    }

    #[test]
    fn a_rejection_carries_a_registered_reason() {
        let mut out = Vec::new();
        for reason in [
            crate::error_code::AUTHENTICATION_FAILED,
            crate::error_code::AUTHORIZATION_FAILED,
            crate::error_code::REPLAY_REJECTED,
        ] {
            let reject = SessionReject {
                session_id: [1; 16],
                reason: u64::from(reason),
                detail: String::new(),
            };
            out.clear();
            assert!(encode_session_reject(&reject, &mut out).is_ok());
        }
        for reason in [0, u64::from(crate::error_code::MALFORMED_FRAME), 1 << 40] {
            let reject = SessionReject {
                session_id: [1; 16],
                reason,
                detail: String::new(),
            };
            out.clear();
            assert!(
                encode_session_reject(&reject, &mut out).is_err(),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_session_open_names_a_registered_capability_format() {
        let mut out = Vec::new();
        let open = |capability_format| SessionOpen {
            session_id: [1; 16],
            capability_format,
            capability: Vec::new(),
            requested_scope: Vec::new(),
            binding_proof: Vec::new(),
        };
        assert!(encode_session_open(&open(1), &mut out).is_ok());
        assert!(encode_session_open(&open(0), &mut out).is_err());
        assert!(encode_session_open(&open(65_536), &mut out).is_err());

        let mut oversized = open(1);
        oversized.capability = vec![0; MAX_CAPABILITY_BYTES + 1];
        assert!(encode_session_open(&oversized, &mut out).is_err());
        let mut wide_scope = open(1);
        wide_scope.requested_scope = vec![0; MAX_SCOPE_BYTES + 1];
        assert!(encode_session_open(&wide_scope, &mut out).is_err());
    }

    #[test]
    fn a_borrowed_record_validates_like_the_owned_one() {
        let mut record = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: GROUP_BYTES,
            compression: 0,
            encoded: vec![0xaa; GROUP_BYTES as usize],
        };
        assert_eq!(DataRecordRef::from(&record).validate(), Ok(()));
        record.plaintext_length = 0;
        assert_eq!(
            DataRecordRef::from(&record).validate(),
            Err(Error::InvalidValue)
        );
        assert_eq!(record.validate(), Err(Error::InvalidValue));
    }

    #[test]
    fn borrowed_data_record_decode_matches_the_owned_one() {
        let record = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: GROUP_BYTES,
            compression: 0,
            encoded: vec![0xaa; GROUP_BYTES as usize],
        };
        let mut encoded = Vec::new();
        encode(&TypedFrame::DataRecord(record), &mut encoded).unwrap();
        let (typed, owned_used) = decode(&encoded, DecodeLimits::default()).unwrap();
        let TypedFrame::DataRecord(owned) = typed else {
            panic!("a data record frame decoded as something else");
        };
        let (borrowed, used) = decode_data_record_ref(&encoded, DecodeLimits::default()).unwrap();
        assert_eq!(borrowed, DataRecordRef::from(&owned));
        assert_eq!(used, owned_used);
        let start = borrowed.encoded.as_ptr() as usize - encoded.as_ptr() as usize;
        assert_eq!(
            &encoded[start..start + borrowed.encoded.len()],
            borrowed.encoded
        );
    }

    #[test]
    fn borrowed_data_record_decode_refuses_another_frame_type() {
        let mut encoded = Vec::new();
        encode(
            &TypedFrame::CodingEpochClose(CodingEpochClose { epoch: 1 }),
            &mut encoded,
        )
        .unwrap();
        assert_eq!(
            decode_data_record_ref(&encoded, DecodeLimits::default()),
            Err(Error::WrongFrameType(frame_type::CODING_EPOCH_CLOSE))
        );
    }

    #[test]
    fn borrowed_data_record_decode_refuses_a_mismatched_encoded_length() {
        let frame = |declared: u64| {
            let mut payload = Vec::new();
            vot_cbor::map(&mut payload, 8);
            vot_cbor::uint(&mut payload, 0);
            vot_cbor::uint(&mut payload, 0);
            vot_cbor::uint(&mut payload, 1);
            vot_cbor::bytes(&mut payload, &[2; 16]);
            for (key, value) in [
                (2u64, 0u64),
                (3, GROUP_BYTES),
                (4, 3),
                (5, 0),
                (6, declared),
            ] {
                vot_cbor::uint(&mut payload, key);
                vot_cbor::uint(&mut payload, value);
            }
            vot_cbor::uint(&mut payload, 7);
            vot_cbor::bytes(&mut payload, &[0xaa; 3]);
            let mut encoded = Vec::new();
            encode_frame(frame_type::DATA_RECORD, &payload, &mut encoded).unwrap();
            encoded
        };
        assert_eq!(
            decode_data_record_ref(&frame(4), DecodeLimits::default()),
            Err(Error::InvalidValue)
        );
        assert!(decode_data_record_ref(&frame(3), DecodeLimits::default()).is_ok());
    }

    #[test]
    fn proof_and_data_frames_round_trip() {
        let bundle = TypedFrame::ProofBundle(ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        });
        let data = TypedFrame::DataRecord(DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: GROUP_BYTES,
            compression: 0,
            encoded: vec![0xaa; GROUP_BYTES as usize],
        });
        let mut encoded = Vec::new();
        encode(&bundle, &mut encoded).unwrap();
        encode(&data, &mut encoded).unwrap();
        let (decoded_bundle, used) = decode(&encoded, DecodeLimits::default()).unwrap();
        let (decoded_data, _) = decode(&encoded[used..], DecodeLimits::default()).unwrap();
        assert_eq!(decoded_bundle, bundle);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn direct_data_record_envelope_matches_generic_framing_and_fails_atomically() {
        let mut data = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: GROUP_BYTES,
            plaintext_length: 3,
            compression: 0,
            encoded: vec![1, 2, 3],
        };
        let mut payload = Vec::new();
        encode_validated_data_record((&data).into(), &mut payload);
        let mut expected = vec![0xaa];
        encode_frame(frame_type::DATA_RECORD, &payload, &mut expected).unwrap();
        let mut actual = vec![0xaa];
        encode(&TypedFrame::DataRecord(data.clone()), &mut actual).unwrap();
        assert_eq!(actual, expected);
        let mut borrowed = vec![0xaa];
        encode_data_record((&data).into(), &mut borrowed).unwrap();
        assert_eq!(borrowed, expected);
        let mut reserved = vec![0xaa];
        let encoded = reserve_data_record((&data).into(), &mut reserved).unwrap();
        assert_eq!(reserved[encoded.clone()], [0, 0, 0]);
        reserved[encoded].copy_from_slice(&data.encoded);
        assert_eq!(reserved, expected);
        let mut begun = vec![0xaa];
        let encoded = begin_data_record((&data).into(), &mut begun).unwrap();
        assert_eq!(begun.len(), encoded.start);
        begun.extend_from_slice(&data.encoded);
        assert_eq!(begun.len(), encoded.end);
        assert_eq!(begun, expected);

        data.record_index = 17;
        let before = actual.clone();
        assert_eq!(
            encode(&TypedFrame::DataRecord(data.clone()), &mut actual),
            Err(Error::InvalidValue)
        );
        assert_eq!(actual, before);
        assert_eq!(
            encode_data_record((&data).into(), &mut borrowed),
            Err(Error::InvalidValue)
        );
        assert_eq!(borrowed, before);
        assert_eq!(
            reserve_data_record((&data).into(), &mut reserved),
            Err(Error::InvalidValue)
        );
        assert_eq!(reserved, expected);
    }

    #[test]
    fn data_record_envelopes_reserve_each_varint_width_exactly() {
        for encoded_length in [1, 128, 20_000] {
            let encoded = vec![0xaa; encoded_length];
            let record = DataRecordRef {
                bundle_id: [2; 16],
                record_index: 0,
                plaintext_offset: 0,
                plaintext_length: encoded_length as u64,
                compression: 0,
                encoded: &encoded,
            };
            let mut wire = Vec::new();
            encode_data_record(record, &mut wire).unwrap();
            assert_eq!(wire.capacity(), wire.len());
        }
    }

    #[test]
    fn proof_bundle_metadata_is_checked_before_proof_size() {
        let proof = vec![0xaa; 1024];
        let mut payload = Vec::new();
        vot_cbor::map(&mut payload, 11);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 1);
        vot_cbor::bytes(&mut payload, &[1; 16]);
        vot_cbor::uint(&mut payload, 2);
        vot_cbor::bytes(&mut payload, &[2; 16]);
        vot_cbor::uint(&mut payload, 3);
        encode_object(&object(), &mut payload);
        vot_cbor::uint(&mut payload, 4);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 5);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 6);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 7);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 8);
        vot_cbor::uint(&mut payload, 0);
        vot_cbor::uint(&mut payload, 9);
        vot_cbor::uint(&mut payload, GROUP_BYTES);
        vot_cbor::uint(&mut payload, 10);
        vot_cbor::bytes(&mut payload, &proof);
        let mut encoded = Vec::new();
        encode_frame(frame_type::PROOF_BUNDLE, &payload, &mut encoded).unwrap();
        assert_eq!(
            decode(&encoded, DecodeLimits::default()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn proof_bundle_limit_includes_typed_payload_overhead() {
        let limit = crate::registered_payload_limit(frame_type::PROOF_BUNDLE).unwrap();
        let empty = ProofBundle {
            request_id: [1; 16],
            bundle_id: [2; 16],
            object: object(),
            requested_offset: GROUP_BYTES,
            requested_length: GROUP_BYTES,
            covered_offset: GROUP_BYTES,
            covered_length: GROUP_BYTES,
            data_record_count: 1,
            total_plaintext_length: GROUP_BYTES,
            proof: Vec::new(),
        };
        let metadata = proof_bundle_payload_len(&empty) - cbor_byte_string_len(0);
        let mut maximum_proof_length = MAX_PROOF_BYTES.min(limit.saturating_sub(metadata));
        while metadata.saturating_add(cbor_byte_string_len(maximum_proof_length)) > limit {
            maximum_proof_length -= 1;
        }
        let mut valid = empty.clone();
        valid.proof = vec![0xaa; maximum_proof_length];
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::ProofBundle(valid), &mut Vec::new()).is_ok());

        let mut invalid = empty;
        invalid.proof = vec![0xaa; maximum_proof_length + 1];
        assert!(proof_bundle_payload_len(&invalid) > limit);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::ProofBundle(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_limit_includes_typed_payload_overhead() {
        let make_data = |encoded_length: usize| DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: encoded_length as u64,
            compression: 0,
            encoded: vec![0xaa; encoded_length],
        };
        let mut maximum_encoded_length = MAX_DATA_BYTES;
        while data_record_payload_len((&make_data(maximum_encoded_length)).into()) > MAX_DATA_BYTES
        {
            maximum_encoded_length -= 1;
        }
        let valid = make_data(maximum_encoded_length);
        assert!(valid.validate().is_ok());
        assert!(encode(&TypedFrame::DataRecord(valid), &mut Vec::new()).is_ok());

        let invalid = make_data(maximum_encoded_length + 1);
        assert!(data_record_payload_len((&invalid).into()) > MAX_DATA_BYTES);
        assert_eq!(invalid.validate(), Err(Error::InvalidValue));
        assert_eq!(
            encode(&TypedFrame::DataRecord(invalid), &mut Vec::new()),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn data_record_validation_boundaries_are_explicit() {
        let mut data = DataRecord {
            bundle_id: [2; 16],
            record_index: 0,
            plaintext_offset: 0,
            plaintext_length: 1,
            compression: 0,
            encoded: vec![0xaa],
        };
        data.record_index = 16;
        assert!(data.validate().is_ok());
        data.record_index = 17;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.record_index = 0;
        data.plaintext_offset = MAX_OBJECT_LENGTH;
        assert!(data.validate().is_ok());
        data.plaintext_offset += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_offset = 0;
        data.plaintext_length = MAX_DATA_BYTES as u64;
        data.compression = 1;
        assert!(data.validate().is_ok());
        data.plaintext_length += 1;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.plaintext_length = 1;
        data.compression = 0;
        data.encoded.clear();
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.encoded.push(0xaa);
        data.compression = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));

        data.compression = 0;
        data.plaintext_length = 2;
        assert_eq!(data.validate(), Err(Error::InvalidValue));
        data.compression = 1;
        assert!(data.validate().is_ok());
    }

    #[test]
    fn cbor_head_width_boundaries_are_canonical() {
        assert_eq!(
            [
                cbor_head_len(0),
                cbor_head_len(23),
                cbor_head_len(24),
                cbor_head_len(255),
                cbor_head_len(256),
                cbor_head_len(65_535),
                cbor_head_len(65_536),
                cbor_head_len(u64::from(u32::MAX)),
                cbor_head_len(u64::from(u32::MAX) + 1),
            ],
            [1, 1, 2, 2, 3, 3, 5, 5, 9]
        );
    }

    #[test]
    fn adjacent_have_runs_are_rejected() {
        let error = encode(
            &TypedFrame::Have(Have {
                object: object(),
                map_sequence: 1,
                runs: vec![
                    HaveRun {
                        start_group: 0,
                        group_count: 1,
                    },
                    HaveRun {
                        start_group: 1,
                        group_count: 1,
                    },
                ],
            }),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::InvalidValue);
    }

    #[test]
    fn have_limit_includes_typed_run_overhead() {
        let run_count = 900_000_u64;
        let value = Have {
            object: ObjectId {
                suite: 1,
                root: [7; 32],
                length: GROUP_BYTES * (run_count * 2 + 1),
            },
            map_sequence: 1,
            runs: (0..run_count)
                .map(|index| HaveRun {
                    start_group: index * 2,
                    group_count: 1,
                })
                .collect(),
        };
        assert!(
            have_payload_len(&value) > crate::registered_payload_limit(frame_type::HAVE).unwrap()
        );
        assert_eq!(validate_have(&value), Err(Error::TooLarge));
        assert_eq!(
            encode(&TypedFrame::Have(value), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn valid_manifest_seals_are_bounded_by_the_wire_limit() {
        let pages = (0..vot_manifest::MAX_PAGE_COMMITMENTS)
            .map(|index| vot_manifest::PageCommitment {
                index: index as u64,
                digest: [8; 32],
            })
            .collect::<Vec<_>>();
        let seal = vot_manifest::Seal {
            manifest_id: [4; 16],
            final_page_count: pages.len() as u64,
            final_page_digest: [8; 32],
            package: vot_manifest::ObjectId {
                suite: 1,
                root: [9; 32],
                length: 123,
            },
            pages,
        };
        let encoded = vot_manifest::encode_seal(&seal).unwrap();
        assert!(encoded.len() > crate::registered_payload_limit(frame_type::SEAL).unwrap());
        assert_eq!(
            encode(&TypedFrame::Seal(encoded), &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn owner_payloads_are_validated_before_framing() {
        assert_eq!(
            encode(&TypedFrame::ManifestPage(vec![0]), &mut Vec::new()),
            Err(Error::Manifest)
        );
        assert_eq!(
            encode(&TypedFrame::PublishReceipt(vec![0]), &mut Vec::new()),
            Err(Error::Receipt)
        );
    }
}
