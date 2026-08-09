//! The shared deterministic CBOR reader and length helpers.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use super::{Error, ObjectId};

pub(super) fn cbor_byte_string_len(length: usize) -> usize {
    cbor_head_len(length as u64).saturating_add(length)
}

pub(super) fn cbor_head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(super) fn encode_object(value: &ObjectId, output: &mut Vec<u8>) {
    vot_cbor::array(output, 4);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, u64::from(value.suite));
    vot_cbor::bytes(output, &value.root);
    vot_cbor::uint(output, value.length);
}

pub(super) fn decode_object(reader: &mut Reader<'_>) -> Result<ObjectId, Error> {
    if reader.array(4)? != 4 {
        return Err(Error::Malformed);
    }
    if reader.uint()? != 1 {
        return Err(Error::InvalidValue);
    }
    let suite = u16::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)?;
    let root = reader.fixed::<32>()?;
    let length = reader.uint()?;
    let object = ObjectId {
        suite,
        root,
        length,
    };
    object.validate()?;
    Ok(object)
}

/// The frame codec's view of a deterministic CBOR reader.
///
/// Translates `vot-cbor` errors: registry-bound violations become `TooLarge`,
/// everything else `Malformed`.
pub(super) struct Reader<'a> {
    reader: vot_cbor::Reader<'a>,
}

pub(super) fn structural(error: vot_cbor::Error) -> Error {
    match error {
        vot_cbor::Error::TooLarge => Error::TooLarge,
        vot_cbor::Error::Truncated
        | vot_cbor::Error::Malformed
        | vot_cbor::Error::NonCanonical
        | vot_cbor::Error::WrongType
        | vot_cbor::Error::NotUtf8
        | vot_cbor::Error::Trailing => Error::Malformed,
    }
}

impl<'a> Reader<'a> {
    pub(super) const fn new(input: &'a [u8]) -> Self {
        Self {
            reader: vot_cbor::Reader::new(input),
        }
    }

    pub(super) fn uint(&mut self) -> Result<u64, Error> {
        self.reader.uint().map_err(structural)
    }

    /// A map key matching the expected schema key.
    pub(super) fn key(&mut self, expected: u64) -> Result<(), Error> {
        self.reader.key(expected).map_err(|_| Error::Malformed)
    }

    pub(super) fn map(&mut self, expected: u64) -> Result<(), Error> {
        self.reader.map(expected).map_err(|_| Error::Malformed)
    }

    pub(super) fn array(&mut self, expected: u64) -> Result<u64, Error> {
        self.reader
            .array(expected)
            .map(|()| expected)
            .map_err(|_| Error::Malformed)
    }

    /// An array head bounded by a registered maximum.
    pub(super) fn array_len(&mut self, maximum: u64) -> Result<u64, Error> {
        self.reader.array_len(maximum).map_err(|_| Error::TooLarge)
    }

    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        self.reader.bytes(maximum).map_err(structural)
    }

    pub(super) fn text(&mut self, maximum: usize) -> Result<&'a str, Error> {
        self.reader.text(maximum).map_err(structural)
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.reader.fixed_bytes::<N>().map_err(|error| match error {
            // Wrong-length byte string at a fixed position is malformed.
            vot_cbor::Error::TooLarge => Error::Malformed,
            other => structural(other),
        })
    }

    pub(super) fn finish(&self) -> Result<(), Error> {
        self.reader.finish().map_err(|_| Error::Malformed)
    }
}
