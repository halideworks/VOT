//! Deterministic CBOR encoding for VOT structures.
//!
//! RFC 8949 section 4.2.1 core deterministic encoding, restricted to the item
//! types VOT uses: integers, byte/text strings, definite-length arrays and
//! maps, and `null`. Field-level rules (lengths, keys) stay with the schema.

#![forbid(unsafe_code)]

/// Why a CBOR item could not be read. Each variant maps to a distinct
/// caller error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The item claims more bytes than the input holds.
    Truncated,
    /// Not a well-formed item: a reserved additional-information value, or a
    /// simple value this profile does not define.
    Malformed,
    /// Well formed, but not the shortest encoding of its value, which
    /// deterministic encoding requires.
    NonCanonical,
    /// A well-formed item of a major type the caller did not ask for.
    WrongType,
    /// Longer, or more numerous, than the caller's bound allows.
    TooLarge,
    /// Bytes remain after the item the caller expected to be the last.
    Trailing,
    /// A text string that is not UTF-8.
    NotUtf8,
}

/// CBOR major types, by their RFC 8949 numbering.
pub mod major {
    pub const UNSIGNED: u8 = 0;
    pub const NEGATIVE: u8 = 1;
    pub const BYTES: u8 = 2;
    pub const TEXT: u8 = 3;
    pub const ARRAY: u8 = 4;
    pub const MAP: u8 = 5;
    pub const SIMPLE: u8 = 7;
}

/// The one encoding of `null` this profile has.
const NULL: u8 = 0xf6;

/// Appends the shortest head for `major` and `value`.
///
/// The tag uses `major * 32` (not `<< 5`) so mutation runs can verify it.
pub fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    debug_assert!(major <= major::SIMPLE, "major type outside CBOR's range");
    let tag = major.wrapping_mul(32);
    match value {
        0..=23 => out.push(tag + u8::try_from(value).unwrap_or(0)),
        24..=0xff => {
            out.push(tag + 24);
            out.push(u8::try_from(value).unwrap_or(0));
        }
        0x100..=0xffff => {
            out.push(tag + 25);
            out.extend_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(tag + 26);
            out.extend_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
        }
        _ => {
            out.push(tag + 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Appends an unsigned integer.
pub fn uint(out: &mut Vec<u8>, value: u64) {
    head(out, major::UNSIGNED, value);
}

/// Appends a signed integer, as the unsigned or negative type its sign selects.
pub fn int(out: &mut Vec<u8>, value: i64) {
    if value < 0 {
        // CBOR negative encoding is -1 - n. Computed on unsigned side to
        // avoid i64::MIN overflow.
        head(out, major::NEGATIVE, value.unsigned_abs() - 1);
    } else {
        head(out, major::UNSIGNED, value.unsigned_abs());
    }
}

/// Appends a byte string.
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, major::BYTES, value.len() as u64);
    out.extend_from_slice(value);
}

/// Appends a text string.
pub fn text(out: &mut Vec<u8>, value: &str) {
    head(out, major::TEXT, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Appends a definite-length array head.
pub fn array(out: &mut Vec<u8>, length: u64) {
    head(out, major::ARRAY, length);
}

/// Appends a definite-length map head.
pub fn map(out: &mut Vec<u8>, length: u64) {
    head(out, major::MAP, length);
}

/// Appends `null`.
pub fn null(out: &mut Vec<u8>) {
    out.push(NULL);
}

/// Reads deterministic CBOR items from a borrowed input.
///
/// A reader that has returned an error is finished; callers do not resync.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the first byte of `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// How many bytes have been consumed.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// What has not been consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.input.get(self.offset..).unwrap_or(&[])
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.offset >= self.input.len()
    }

    /// Consumes `length` bytes.
    ///
    /// # Errors
    /// Reports an input shorter than the request.
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Truncated)?;
        let bytes = self.input.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    /// Reads one head, returning its major type and argument.
    ///
    /// # Errors
    /// Reports a truncated head, a reserved additional-information value, and a
    /// value not in its shortest form.
    pub fn head(&mut self) -> Result<(u8, u64), Error> {
        let first = *self.take(1)?.first().ok_or(Error::Truncated)?;
        let major = first >> 5;
        let additional = first & 0x1f;
        let (value, floor) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.fixed()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.fixed()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.fixed()?), 0x1_0000_0000),
            _ => return Err(Error::Malformed),
        };
        if value < floor {
            return Err(Error::NonCanonical);
        }
        Ok((major, value))
    }

    /// Reads one head and requires its major type.
    ///
    /// # Errors
    /// Reports what [`head`](Self::head) does, and a head of another type.
    pub fn typed_head(&mut self, expected: u8) -> Result<u64, Error> {
        let (major, value) = self.head()?;
        if major == expected {
            Ok(value)
        } else {
            Err(Error::WrongType)
        }
    }

    /// Reads an unsigned integer.
    ///
    /// # Errors
    /// Reports a head that is not an unsigned integer.
    pub fn uint(&mut self) -> Result<u64, Error> {
        self.typed_head(major::UNSIGNED)
    }

    /// Reads an unsigned integer and requires a particular value, which is how
    /// a map key is read.
    ///
    /// # Errors
    /// Reports another value, and what [`uint`](Self::uint) does.
    pub fn key(&mut self, expected: u64) -> Result<(), Error> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(Error::WrongType)
        }
    }

    /// Reads a signed integer of either sign.
    ///
    /// # Errors
    /// Reports a head that is neither integer type, and a magnitude outside
    /// `i64`.
    pub fn int(&mut self) -> Result<i64, Error> {
        let (major, value) = self.head()?;
        match major {
            major::UNSIGNED => i64::try_from(value).map_err(|_| Error::TooLarge),
            major::NEGATIVE => i64::try_from(value)
                .map_err(|_| Error::TooLarge)
                .map(|magnitude| -1 - magnitude),
            _ => Err(Error::WrongType),
        }
    }

    /// Reads a byte string no longer than `maximum`.
    ///
    /// # Errors
    /// Reports a head that is not a byte string, a length past `maximum`, and
    /// an input shorter than the length.
    pub fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = self.length(major::BYTES, maximum)?;
        self.take(length)
    }

    /// Reads a byte string of exactly `N` bytes.
    ///
    /// # Errors
    /// Reports a head that is not a byte string and any other length.
    pub fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let length = self.length(major::BYTES, N)?;
        if length != N {
            return Err(Error::TooLarge);
        }
        self.fixed()
    }

    /// Reads a text string no longer than `maximum` bytes.
    ///
    /// # Errors
    /// Reports a head that is not a text string, a length past `maximum`, an
    /// input shorter than the length, and bytes that are not UTF-8.
    pub fn text(&mut self, maximum: usize) -> Result<&'a str, Error> {
        let length = self.length(major::TEXT, maximum)?;
        let bytes = self.take(length)?;
        core::str::from_utf8(bytes).map_err(|_| Error::NotUtf8)
    }

    /// Reads an array head no longer than `maximum` elements.
    ///
    /// # Errors
    /// Reports a head that is not an array and a length past `maximum`.
    pub fn array_len(&mut self, maximum: u64) -> Result<u64, Error> {
        let length = self.typed_head(major::ARRAY)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        Ok(length)
    }

    /// Reads an array head and requires exactly `expected` elements.
    ///
    /// # Errors
    /// Reports a head that is not an array and any other length.
    pub fn array(&mut self, expected: u64) -> Result<(), Error> {
        if self.typed_head(major::ARRAY)? == expected {
            Ok(())
        } else {
            Err(Error::WrongType)
        }
    }

    /// Reads a map head no longer than `maximum` pairs.
    ///
    /// # Errors
    /// Reports a head that is not a map and a length past `maximum`.
    pub fn map_len(&mut self, maximum: u64) -> Result<u64, Error> {
        let length = self.typed_head(major::MAP)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        Ok(length)
    }

    /// Reads a map head and requires exactly `expected` pairs.
    ///
    /// # Errors
    /// Reports a head that is not a map and any other length.
    pub fn map(&mut self, expected: u64) -> Result<(), Error> {
        if self.typed_head(major::MAP)? == expected {
            Ok(())
        } else {
            Err(Error::WrongType)
        }
    }

    /// Reads `null`.
    ///
    /// # Errors
    /// Reports any other item, including another simple value.
    pub fn null(&mut self) -> Result<(), Error> {
        if self.byte()? == NULL {
            Ok(())
        } else {
            Err(Error::WrongType)
        }
    }

    /// Whether the next byte is `null`, without consuming anything.
    #[must_use]
    pub fn peek_null(&self) -> bool {
        self.input.get(self.offset) == Some(&NULL)
    }

    /// Requires that nothing follows.
    ///
    /// # Errors
    /// Reports remaining bytes.
    pub const fn finish(&self) -> Result<(), Error> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }

    /// A length-prefixed head of `expected` type, bounded by `maximum`.
    fn length(&mut self, expected: u8, maximum: usize) -> Result<usize, Error> {
        let length = self.typed_head(expected)?;
        let length = usize::try_from(length).map_err(|_| Error::TooLarge)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        Ok(length)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(*self.take(1)?.first().ok_or(Error::Truncated)?)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every width boundary, and the value on each side of it.
    const BOUNDARIES: [u64; 12] = [
        0,
        1,
        23,
        24,
        25,
        0xff,
        0x100,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
    ];

    fn expected_width(value: u64) -> usize {
        match value {
            0..=23 => 1,
            24..=0xff => 2,
            0x100..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }

    #[test]
    fn every_head_is_the_shortest_that_holds_its_value() {
        for value in BOUNDARIES {
            for major in [
                major::UNSIGNED,
                major::NEGATIVE,
                major::BYTES,
                major::TEXT,
                major::ARRAY,
                major::MAP,
            ] {
                let mut out = Vec::new();
                head(&mut out, major, value);
                assert_eq!(out.len(), expected_width(value), "{major} {value:#x}");
                let mut reader = Reader::new(&out);
                assert_eq!(reader.head(), Ok((major, value)), "{major} {value:#x}");
                assert_eq!(reader.finish(), Ok(()));
            }
        }
    }

    #[test]
    fn a_wider_head_than_the_value_needs_is_refused() {
        // Canonical encoding check. Written per-width to avoid the off-by-one
        // a loop would reproduce.
        for (encoded, value) in [
            (vec![0x18, 0x00], 0u64),
            (vec![0x18, 0x17], 23),
            (vec![0x19, 0x00, 0x17], 23),
            (vec![0x19, 0x00, 0xff], 0xff),
            (vec![0x1a, 0x00, 0x00, 0xff, 0xff], 0xffff),
            (vec![0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], 0xffff_ffff),
        ] {
            assert_eq!(
                Reader::new(&encoded).head(),
                Err(Error::NonCanonical),
                "{value:#x} in a wider head"
            );
            let mut shortest = Vec::new();
            head(&mut shortest, major::UNSIGNED, value);
            assert_eq!(Reader::new(&shortest).head(), Ok((major::UNSIGNED, value)));
        }
    }

    #[test]
    fn reserved_additional_information_is_malformed() {
        for additional in 28..=30u8 {
            assert_eq!(
                Reader::new(&[additional]).head(),
                Err(Error::Malformed),
                "additional {additional}"
            );
        }
        assert_eq!(Reader::new(&[0x5f]).head(), Err(Error::Malformed));
        assert_eq!(Reader::new(&[0x7f]).head(), Err(Error::Malformed));
        assert_eq!(Reader::new(&[0x9f]).head(), Err(Error::Malformed));
        assert_eq!(Reader::new(&[0xbf]).head(), Err(Error::Malformed));
    }

    #[test]
    fn a_truncated_item_is_not_a_malformed_one() {
        assert_eq!(Reader::new(&[]).head(), Err(Error::Truncated));
        for head_byte in [0x18u8, 0x19, 0x1a, 0x1b] {
            assert_eq!(
                Reader::new(&[head_byte]).head(),
                Err(Error::Truncated),
                "{head_byte:#x} with no argument"
            );
        }
        let mut short = Vec::new();
        bytes(&mut short, b"eight!!!");
        short.truncate(short.len() - 1);
        assert_eq!(Reader::new(&short).bytes(64), Err(Error::Truncated));
    }

    #[test]
    fn signed_integers_round_trip_at_their_limits() {
        for value in [
            i64::MIN,
            i64::MIN + 1,
            -0x1_0000_0001,
            -0x1_0000_0000,
            -256,
            -24,
            -1,
            0,
            1,
            23,
            24,
            i64::MAX,
        ] {
            let mut out = Vec::new();
            int(&mut out, value);
            let mut reader = Reader::new(&out);
            assert_eq!(reader.int(), Ok(value), "{value}");
            assert_eq!(reader.finish(), Ok(()));
        }
        // Magnitude past i64 is well-formed CBOR this profile cannot represent.
        let mut huge = Vec::new();
        head(&mut huge, major::NEGATIVE, u64::MAX);
        assert_eq!(Reader::new(&huge).int(), Err(Error::TooLarge));
    }

    #[test]
    fn every_reader_helper_reports_the_wrong_type_rather_than_guessing() {
        let mut encoded = Vec::new();
        uint(&mut encoded, 7);
        assert_eq!(Reader::new(&encoded).bytes(8), Err(Error::WrongType));
        assert_eq!(Reader::new(&encoded).text(8), Err(Error::WrongType));
        assert_eq!(Reader::new(&encoded).array_len(8), Err(Error::WrongType));
        assert_eq!(Reader::new(&encoded).map_len(8), Err(Error::WrongType));
        assert_eq!(Reader::new(&encoded).null(), Err(Error::WrongType));
        assert_eq!(
            Reader::new(&encoded).fixed_bytes::<4>(),
            Err(Error::WrongType)
        );

        let mut array_head = Vec::new();
        array(&mut array_head, 2);
        assert_eq!(Reader::new(&array_head).uint(), Err(Error::WrongType));
        assert_eq!(Reader::new(&array_head).int(), Err(Error::WrongType));
        assert_eq!(Reader::new(&array_head).map(2), Err(Error::WrongType));
        assert_eq!(Reader::new(&array_head).array(3), Err(Error::WrongType));
        assert_eq!(Reader::new(&array_head).array(2), Ok(()));
    }

    #[test]
    fn bounds_admit_their_own_maximum_and_refuse_one_past_it() {
        let mut encoded = Vec::new();
        bytes(&mut encoded, &[0xa5; 16]);
        assert_eq!(Reader::new(&encoded).bytes(16).map(<[u8]>::len), Ok(16));
        assert_eq!(Reader::new(&encoded).bytes(15), Err(Error::TooLarge));
        assert_eq!(Reader::new(&encoded).fixed_bytes::<16>(), Ok([0xa5; 16]));
        assert_eq!(
            Reader::new(&encoded).fixed_bytes::<8>(),
            Err(Error::TooLarge)
        );

        let mut long = Vec::new();
        array(&mut long, 9);
        assert_eq!(Reader::new(&long).array_len(9), Ok(9));
        assert_eq!(Reader::new(&long).array_len(8), Err(Error::TooLarge));

        let mut wide = Vec::new();
        map(&mut wide, 4);
        assert_eq!(Reader::new(&wide).map_len(4), Ok(4));
        assert_eq!(Reader::new(&wide).map_len(3), Err(Error::TooLarge));
        assert_eq!(Reader::new(&wide).map(4), Ok(()));
    }

    #[test]
    fn a_length_past_usize_is_refused_before_it_is_used() {
        let mut enormous = Vec::new();
        head(&mut enormous, major::BYTES, u64::MAX);
        assert_eq!(Reader::new(&enormous).bytes(1024), Err(Error::TooLarge));
        let mut counted = Vec::new();
        head(&mut counted, major::ARRAY, u64::MAX);
        assert_eq!(Reader::new(&counted).array_len(4096), Err(Error::TooLarge));
    }

    #[test]
    fn text_has_to_be_utf8_and_a_key_has_to_be_its_value() {
        let mut valid = Vec::new();
        text(&mut valid, "vot");
        assert_eq!(Reader::new(&valid).text(8), Ok("vot"));

        let mut invalid = Vec::new();
        head(&mut invalid, major::TEXT, 2);
        invalid.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(Reader::new(&invalid).text(8), Err(Error::NotUtf8));

        let mut keyed = Vec::new();
        uint(&mut keyed, 3);
        assert_eq!(Reader::new(&keyed).key(3), Ok(()));
        assert_eq!(Reader::new(&keyed).key(4), Err(Error::WrongType));
    }

    #[test]
    fn a_reader_reports_where_it_is_and_what_is_left() {
        let mut encoded = Vec::new();
        map(&mut encoded, 1);
        uint(&mut encoded, 0);
        bytes(&mut encoded, b"xy");
        let total = encoded.len();

        let mut reader = Reader::new(&encoded);
        assert!(!reader.is_empty());
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.remaining().len(), total);
        reader.map(1).unwrap();
        reader.key(0).unwrap();
        assert_eq!(reader.finish(), Err(Error::Trailing));
        assert_eq!(reader.bytes(2), Ok(&b"xy"[..]));
        assert_eq!(reader.offset(), total);
        assert!(reader.is_empty());
        assert_eq!(reader.remaining(), &[] as &[u8]);
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn null_is_the_only_simple_value_this_profile_has() {
        let mut encoded = Vec::new();
        null(&mut encoded);
        assert_eq!(encoded, vec![0xf6]);
        let mut reader = Reader::new(&encoded);
        assert!(reader.peek_null());
        assert_eq!(reader.null(), Ok(()));
        assert_eq!(reader.finish(), Ok(()));

        for byte in [0xf4u8, 0xf5, 0xf7, 0xfa, 0xfb] {
            let encoded = [byte];
            let mut reader = Reader::new(&encoded);
            assert!(!reader.peek_null(), "{byte:#x}");
            assert_eq!(reader.null(), Err(Error::WrongType), "{byte:#x}");
        }
        assert!(!Reader::new(&[]).peek_null());
        assert_eq!(Reader::new(&[]).null(), Err(Error::Truncated));
    }
}
