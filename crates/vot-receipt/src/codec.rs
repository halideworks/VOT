//! Canonical encode and decode.

use super::{
    AssuranceLevel, AuthScheme, AuthenticatedReceipt, CommitProfile, Error, Receipt, SubjectKind,
    validate_key_id,
};

pub fn encode_authenticated(receipt: &AuthenticatedReceipt) -> Result<Vec<u8>, Error> {
    validate_key_id(&receipt.key_id)?;
    if receipt.authentication.len() != receipt.scheme.authenticator_len() {
        return Err(Error::Authentication);
    }
    let canonical = receipt.receipt.canonical_bytes()?;
    let mut output = Vec::with_capacity(canonical.len() + receipt.key_id.len() + 48);
    vot_cbor::map(&mut output, 4);
    vot_cbor::uint(&mut output, 0);
    output.extend_from_slice(&canonical);
    vot_cbor::uint(&mut output, 1);
    vot_cbor::uint(&mut output, receipt.scheme as u64);
    vot_cbor::uint(&mut output, 2);
    vot_cbor::bytes(&mut output, &receipt.key_id);
    vot_cbor::uint(&mut output, 3);
    vot_cbor::bytes(&mut output, &receipt.authentication);
    Ok(output)
}

/// Decodes one bounded, deterministic authenticated receipt envelope.
pub fn decode_authenticated(input: &[u8]) -> Result<AuthenticatedReceipt, Error> {
    if input.len() > 65_536 {
        return Err(Error::TooLarge);
    }
    let mut decoder = Decoder::new(input);
    decoder.exact_map(4)?;
    decoder.exact_key(0)?;
    let receipt = decode_receipt(&mut decoder)?;
    decoder.exact_key(1)?;
    let scheme = AuthScheme::from_registry(decoder.uint()?).ok_or(Error::InvalidEncoding)?;
    decoder.exact_key(2)?;
    let key_id = decoder.bytes(64)?;
    if key_id.is_empty() {
        return Err(Error::InvalidKeyId);
    }
    decoder.exact_key(3)?;
    let authentication = decoder.bytes(scheme.authenticator_len())?;
    if authentication.len() != scheme.authenticator_len() {
        return Err(Error::InvalidEncoding);
    }
    decoder.finish()?;
    let authenticated = AuthenticatedReceipt {
        receipt,
        scheme,
        key_id,
        authentication,
    };
    if encode_authenticated(&authenticated)? != input {
        return Err(Error::NonCanonical);
    }
    Ok(authenticated)
}

pub(super) fn decode_receipt(decoder: &mut Decoder<'_>) -> Result<Receipt, Error> {
    // Fourteen keys, or fifteen when the observation links to a predecessor.
    let entries = decoder.map_len()?;
    if entries != 14 && entries != 15 {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(0)?;
    if decoder.uint()? != 0 {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(1)?;
    decoder.exact_array(4)?;
    let subject_kind = match decoder.uint()? {
        0 => SubjectKind::Object,
        1 => SubjectKind::Package,
        _ => return Err(Error::InvalidEncoding),
    };
    let suite_id = decoder.u16()?;
    let subject_digest = decoder.fixed_bytes()?;
    let subject_length = decoder.uint()?;
    decoder.exact_key(2)?;
    let assurance = decode_assurance(decoder.uint()?)?;
    decoder.exact_key(3)?;
    let profile = match decoder.uint()? {
        1 => CommitProfile::Fast,
        2 => CommitProfile::Balanced,
        3 => CommitProfile::Strict,
        _ => return Err(Error::InvalidEncoding),
    };
    decoder.exact_key(4)?;
    let actual_predecessor = decode_assurance(decoder.uint()?)?;
    decoder.exact_key(5)?;
    let provider = decoder.u16()?;
    decoder.exact_key(6)?;
    decoder.exact_array(3)?;
    let provider_version = [decoder.u16()?, decoder.u16()?, decoder.u16()?];
    decoder.exact_key(7)?;
    let session_id = decoder.fixed_bytes()?;
    decoder.exact_key(8)?;
    let incarnation_id = decoder.fixed_bytes()?;
    decoder.exact_key(9)?;
    let sequence = decoder.uint()?;
    decoder.exact_key(10)?;
    let observed_at = decoder.text(35)?;
    decoder.exact_key(11)?;
    let clock_source = decoder.u8()?;
    decoder.exact_key(12)?;
    if decoder.u16()? != suite_id {
        return Err(Error::InvalidEncoding);
    }
    decoder.exact_key(13)?;
    let flags = decoder.u8()?;
    let previous = if entries == 15 {
        decoder.exact_key(17)?;
        Some(decoder.fixed_bytes::<32>()?)
    } else {
        None
    };
    let receipt = Receipt {
        subject_kind,
        suite_id,
        subject_digest,
        subject_length,
        assurance,
        profile,
        actual_predecessor,
        provider,
        provider_version,
        session_id,
        incarnation_id,
        sequence,
        observed_at,
        clock_source,
        flags,
        previous,
    };
    receipt.validate()?;
    Ok(receipt)
}

pub(super) fn decode_assurance(value: u64) -> Result<AssuranceLevel, Error> {
    match value {
        1 => Ok(AssuranceLevel::Admitted),
        2 => Ok(AssuranceLevel::TransitVerified),
        3 => Ok(AssuranceLevel::Durable),
        4 => Ok(AssuranceLevel::AtRestVerified),
        5 => Ok(AssuranceLevel::Published),
        _ => Err(Error::InvalidEncoding),
    }
}

/// The receipt crate's view of a deterministic CBOR reader.
///
/// Maps `vot-cbor` failures to receipt errors: structural problems are invalid
/// encodings, except shortest-form violations (`NonCanonical`) and receipt-set
/// bounds (`TooLarge`).
pub(super) struct Decoder<'a> {
    reader: vot_cbor::Reader<'a>,
}

pub(super) fn structural(error: vot_cbor::Error) -> Error {
    match error {
        vot_cbor::Error::NonCanonical => Error::NonCanonical,
        vot_cbor::Error::TooLarge => Error::TooLarge,
        vot_cbor::Error::Truncated
        | vot_cbor::Error::Malformed
        | vot_cbor::Error::WrongType
        | vot_cbor::Error::NotUtf8
        | vot_cbor::Error::Trailing => Error::InvalidEncoding,
    }
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(remaining: &'a [u8]) -> Self {
        Self {
            reader: vot_cbor::Reader::new(remaining),
        }
    }

    pub(super) fn uint(&mut self) -> Result<u64, Error> {
        self.reader.uint().map_err(structural)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        u16::try_from(self.uint()?).map_err(|_| Error::InvalidEncoding)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        u8::try_from(self.uint()?).map_err(|_| Error::InvalidEncoding)
    }

    /// A map head whose length the caller decides about, which is how an
    /// envelope that carries one optional key is read.
    fn map_len(&mut self) -> Result<u64, Error> {
        self.reader.map_len(u64::MAX).map_err(structural)
    }

    fn exact_key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// A map of exactly `expected` pairs.
    ///
    /// Compared here rather than by the reader: a non-minimal head is
    /// `NonCanonical`, but a wrong count is an invalid encoding.
    fn exact_map(&mut self, expected: u64) -> Result<(), Error> {
        if self.map_len()? == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn exact_array(&mut self, expected: u64) -> Result<(), Error> {
        let length = self.reader.array_len(u64::MAX).map_err(structural)?;
        if length == expected {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        self.reader
            .bytes(maximum)
            .map(<[u8]>::to_vec)
            .map_err(structural)
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.reader.fixed_bytes::<N>().map_err(|error| match error {
            // A byte string of another length is the wrong shape rather than a
            // bound this receipt set being exceeded.
            vot_cbor::Error::TooLarge => Error::InvalidEncoding,
            other => structural(other),
        })
    }

    fn text(&mut self, maximum: usize) -> Result<String, Error> {
        self.reader
            .text(maximum)
            .map(str::to_owned)
            .map_err(structural)
    }

    fn finish(self) -> Result<(), Error> {
        self.reader.finish().map_err(|_| Error::InvalidEncoding)
    }
}
