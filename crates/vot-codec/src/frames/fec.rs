//! Experimental `DATAGRAM_FEC` payloads and the symbol datagram
//! (`spec/fec.md` sections 9 through 12, ADR-0040).

use super::{Error, ObjectId, Reader, decode_object, encode_object};
pub use vot_fec::Geometry;

/// The fixed symbol datagram header: u32 epoch, u32 generation, u8 esi.
pub const SYMBOL_HEADER_LEN: usize = 9;

/// Sender to receiver: one geometry over one byte range of one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodingEpochOpen {
    pub epoch: u32,
    pub object: ObjectId,
    pub offset: u64,
    pub length: u64,
    pub geometry: Geometry,
}

/// Receiver to sender, advisory: what one generation has and still lacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenState {
    pub epoch: u32,
    pub generation: u32,
    /// Scoped to `(epoch, generation)`; a lower or equal one is ignored.
    pub sequence: u64,
    /// Distinct symbols received so far.
    pub received: u8,
    /// Source ESIs not yet received, ascending.
    pub missing_sources: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenOutcome {
    Decoded,
    Abandoned,
    /// The whole epoch: its open was ignored, every generation is abandoned.
    Refused,
}

/// Receiver to sender, terminal for the generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenDone {
    pub epoch: u32,
    pub generation: u32,
    pub outcome: GenOutcome,
}

/// Sender to receiver, terminal for the epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodingEpochClose {
    pub epoch: u32,
}

/// Receiver to sender: the caps a newer credit epoch replaces whole.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramCredit {
    pub credit_epoch: u64,
    pub max_unretired_bytes: u64,
    pub max_active_generations: u64,
    pub max_decode_work: u64,
    pub max_open_epochs: u64,
}

/// The nine bytes in front of every symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolHeader {
    pub epoch: u32,
    pub generation: u32,
    pub esi: u8,
}

impl CodingEpochOpen {
    fn validate(&self) -> Result<(), Error> {
        self.object.validate()?;
        if self.length == 0
            || self
                .offset
                .checked_add(self.length)
                .is_none_or(|end| end > self.object.length)
        {
            return Err(Error::InvalidValue);
        }
        Ok(())
    }

    /// Generations under this epoch: `ceil(length / (k * L))`.
    #[must_use]
    pub fn generation_count(&self) -> u64 {
        let bytes = self.geometry.source_count() as u64 * self.geometry.symbol_length() as u64;
        self.length.div_ceil(bytes)
    }
}

pub(super) fn encode_coding_epoch_open(
    value: &CodingEpochOpen,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    value.validate()?;
    vot_cbor::map(output, 7);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, u64::from(value.epoch));
    vot_cbor::uint(output, 1);
    encode_object(&value.object, output);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.offset);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.length);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.geometry.source_count() as u64);
    vot_cbor::uint(output, 5);
    vot_cbor::uint(output, value.geometry.repair_count() as u64);
    vot_cbor::uint(output, 6);
    vot_cbor::uint(output, value.geometry.symbol_length() as u64);
    Ok(())
}

pub(super) fn decode_coding_epoch_open(input: &[u8]) -> Result<CodingEpochOpen, Error> {
    let mut reader = Reader::new(input);
    reader.map(7)?;
    reader.key(0)?;
    let epoch = u32_field(&mut reader)?;
    reader.key(1)?;
    let object = decode_object(&mut reader)?;
    reader.key(2)?;
    let offset = reader.uint()?;
    reader.key(3)?;
    let length = reader.uint()?;
    reader.key(4)?;
    let source_count = small(&mut reader)?;
    reader.key(5)?;
    let repair_count = small(&mut reader)?;
    reader.key(6)?;
    let symbol_length = small(&mut reader)?;
    reader.finish()?;
    let geometry = Geometry::new(source_count, repair_count, symbol_length)
        .map_err(|_| Error::InvalidValue)?;
    let value = CodingEpochOpen {
        epoch,
        object,
        offset,
        length,
        geometry,
    };
    value.validate()?;
    Ok(value)
}

pub(super) fn encode_gen_state(value: &GenState, output: &mut Vec<u8>) -> Result<(), Error> {
    if usize::from(value.received) > vot_fec::MAX_SYMBOLS
        || value.missing_sources.len() > vot_fec::MAX_SOURCE_SYMBOLS
        || value
            .missing_sources
            .iter()
            .any(|esi| usize::from(*esi) >= vot_fec::MAX_SOURCE_SYMBOLS)
        || !value.missing_sources.is_sorted_by(|a, b| a < b)
    {
        return Err(Error::InvalidValue);
    }
    vot_cbor::map(output, 5);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, u64::from(value.epoch));
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, u64::from(value.generation));
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.sequence);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, u64::from(value.received));
    vot_cbor::uint(output, 4);
    vot_cbor::array(output, value.missing_sources.len() as u64);
    for esi in &value.missing_sources {
        vot_cbor::uint(output, u64::from(*esi));
    }
    Ok(())
}

pub(super) fn decode_gen_state(input: &[u8]) -> Result<GenState, Error> {
    let mut reader = Reader::new(input);
    reader.map(5)?;
    reader.key(0)?;
    let epoch = u32_field(&mut reader)?;
    reader.key(1)?;
    let generation = u32_field(&mut reader)?;
    reader.key(2)?;
    let sequence = reader.uint()?;
    reader.key(3)?;
    let received = u8_field(&mut reader)?;
    reader.key(4)?;
    // Bounded before the loop: at most k entries, and the encoder rejects more.
    let count = reader.array_len(vot_fec::MAX_SOURCE_SYMBOLS as u64)?;
    let mut missing_sources = Vec::with_capacity(count as usize);
    for _ in 0..count {
        missing_sources.push(u8_field(&mut reader)?);
    }
    reader.finish()?;
    let value = GenState {
        epoch,
        generation,
        sequence,
        received,
        missing_sources,
    };
    encode_gen_state(&value, &mut Vec::new())?;
    Ok(value)
}

pub(super) fn encode_gen_done(value: &GenDone, output: &mut Vec<u8>) {
    vot_cbor::map(output, 3);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, u64::from(value.epoch));
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, u64::from(value.generation));
    vot_cbor::uint(output, 2);
    vot_cbor::uint(
        output,
        match value.outcome {
            GenOutcome::Decoded => 0,
            GenOutcome::Abandoned => 1,
            GenOutcome::Refused => 2,
        },
    );
}

pub(super) fn decode_gen_done(input: &[u8]) -> Result<GenDone, Error> {
    let mut reader = Reader::new(input);
    reader.map(3)?;
    reader.key(0)?;
    let epoch = u32_field(&mut reader)?;
    reader.key(1)?;
    let generation = u32_field(&mut reader)?;
    reader.key(2)?;
    let outcome = match reader.uint()? {
        0 => GenOutcome::Decoded,
        1 => GenOutcome::Abandoned,
        2 => GenOutcome::Refused,
        _ => return Err(Error::InvalidValue),
    };
    reader.finish()?;
    Ok(GenDone {
        epoch,
        generation,
        outcome,
    })
}

pub(super) fn encode_coding_epoch_close(value: CodingEpochClose, output: &mut Vec<u8>) {
    vot_cbor::map(output, 1);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, u64::from(value.epoch));
}

pub(super) fn decode_coding_epoch_close(input: &[u8]) -> Result<CodingEpochClose, Error> {
    let mut reader = Reader::new(input);
    reader.map(1)?;
    reader.key(0)?;
    let epoch = u32_field(&mut reader)?;
    reader.finish()?;
    Ok(CodingEpochClose { epoch })
}

pub(super) fn encode_datagram_credit(value: &DatagramCredit, output: &mut Vec<u8>) {
    vot_cbor::map(output, 5);
    vot_cbor::uint(output, 0);
    vot_cbor::uint(output, value.credit_epoch);
    vot_cbor::uint(output, 1);
    vot_cbor::uint(output, value.max_unretired_bytes);
    vot_cbor::uint(output, 2);
    vot_cbor::uint(output, value.max_active_generations);
    vot_cbor::uint(output, 3);
    vot_cbor::uint(output, value.max_decode_work);
    vot_cbor::uint(output, 4);
    vot_cbor::uint(output, value.max_open_epochs);
}

pub(super) fn decode_datagram_credit(input: &[u8]) -> Result<DatagramCredit, Error> {
    let mut reader = Reader::new(input);
    reader.map(5)?;
    reader.key(0)?;
    let credit_epoch = reader.uint()?;
    reader.key(1)?;
    let max_unretired_bytes = reader.uint()?;
    reader.key(2)?;
    let max_active_generations = reader.uint()?;
    reader.key(3)?;
    let max_decode_work = reader.uint()?;
    reader.key(4)?;
    let max_open_epochs = reader.uint()?;
    reader.finish()?;
    Ok(DatagramCredit {
        credit_epoch,
        max_unretired_bytes,
        max_active_generations,
        max_decode_work,
        max_open_epochs,
    })
}

/// Writes one symbol datagram: the header, then exactly the symbol bytes.
///
/// # Errors
/// `InvalidValue` when the symbol is not the geometry's length or the ESI is
/// outside it.
pub fn encode_symbol(
    header: SymbolHeader,
    geometry: Geometry,
    symbol: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if symbol.len() != geometry.symbol_length()
        || usize::from(header.esi) >= geometry.symbol_count()
    {
        return Err(Error::InvalidValue);
    }
    output.extend_from_slice(&header.epoch.to_be_bytes());
    output.extend_from_slice(&header.generation.to_be_bytes());
    output.push(header.esi);
    output.extend_from_slice(symbol);
    Ok(())
}

/// Splits one datagram into its header and symbol for a known geometry.
///
/// # Errors
/// `Malformed` when the datagram is not exactly `9 + L` bytes;
/// `InvalidValue` when the ESI is outside the geometry. Both are drops at
/// the receiver (`spec/fec.md` section 12), never session errors.
pub fn decode_symbol(datagram: &[u8], geometry: Geometry) -> Result<(SymbolHeader, &[u8]), Error> {
    if datagram.len() != SYMBOL_HEADER_LEN + geometry.symbol_length() {
        return Err(Error::Malformed);
    }
    let epoch = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    let generation = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    let esi = datagram[8];
    if usize::from(esi) >= geometry.symbol_count() {
        return Err(Error::InvalidValue);
    }
    Ok((
        SymbolHeader {
            epoch,
            generation,
            esi,
        },
        &datagram[SYMBOL_HEADER_LEN..],
    ))
}

fn u32_field(reader: &mut Reader<'_>) -> Result<u32, Error> {
    u32::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)
}

fn u8_field(reader: &mut Reader<'_>) -> Result<u8, Error> {
    u8::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)
}

/// A count the geometry will bound; anything past `usize` is already invalid.
fn small(reader: &mut Reader<'_>) -> Result<usize, Error> {
    usize::try_from(reader.uint()?).map_err(|_| Error::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::super::{DecodeLimits, TypedFrame, decode, encode};
    use super::*;

    const VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/fec/vectors.json"
    ));

    /// The `payload_hex` (or another string field) under one named frame
    /// vector, by text search: the file is generated and never escapes.
    fn vector(frame: &str, field: &str) -> Vec<u8> {
        let frames = VECTORS.find("\"frames\": {").expect("frames section");
        let start = VECTORS[frames..]
            .find(&format!("\"{frame}\": {{"))
            .expect("frame vector")
            + frames;
        let key = format!("\"{field}\": \"");
        let from = VECTORS[start..].find(&key).expect("field") + start + key.len();
        let text = &VECTORS[from..from + VECTORS[from..].find('"').expect("closing quote")];
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn vector_uint(frame: &str, field: &str) -> u64 {
        let frames = VECTORS.find("\"frames\": {").expect("frames section");
        let start = VECTORS[frames..]
            .find(&format!("\"{frame}\": {{"))
            .expect("frame vector")
            + frames;
        let key = format!("\"{field}\": ");
        let from = VECTORS[start..].find(&key).expect("field") + start + key.len();
        let end = VECTORS[from..]
            .find(|c: char| !c.is_ascii_digit())
            .expect("number end");
        VECTORS[from..from + end].parse().expect("a number")
    }

    fn limits() -> DecodeLimits {
        DecodeLimits {
            max_unknown_payload: 1 << 20,
            max_frames: 1,
        }
    }

    /// Encodes, checks the payload against the vector bytes, and decodes back.
    fn matches_vector(frame: &TypedFrame, name: &str) {
        let mut out = Vec::new();
        encode(frame, &mut out).expect("encodes");
        let expected = vector(name, "payload_hex");
        assert!(
            out.ends_with(&expected),
            "{name} payload differs from the vector"
        );
        let (decoded, consumed) = decode(&out, limits()).expect("decodes");
        assert_eq!(&decoded, frame, "{name}");
        assert_eq!(consumed, out.len());
    }

    fn open() -> CodingEpochOpen {
        CodingEpochOpen {
            epoch: 7,
            object: ObjectId {
                suite: 1,
                root: core::array::from_fn(|i| i as u8),
                length: 200_000,
            },
            offset: 65_536,
            length: 131_072,
            geometry: Geometry::new(64, 16, 1024).unwrap(),
        }
    }

    #[test]
    fn every_fec_payload_matches_its_vector() {
        matches_vector(&TypedFrame::CodingEpochOpen(open()), "coding_epoch_open");
        assert_eq!(
            open().generation_count(),
            vector_uint("coding_epoch_open", "generation_count")
        );
        matches_vector(
            &TypedFrame::GenState(GenState {
                epoch: 7,
                generation: 1,
                sequence: 3,
                received: 61,
                missing_sources: vec![2, 40, 63],
            }),
            "gen_state",
        );
        matches_vector(
            &TypedFrame::GenDone(GenDone {
                epoch: 7,
                generation: 1,
                outcome: GenOutcome::Decoded,
            }),
            "gen_done",
        );
        matches_vector(
            &TypedFrame::CodingEpochClose(CodingEpochClose { epoch: 7 }),
            "coding_epoch_close",
        );
        matches_vector(
            &TypedFrame::DatagramCredit(DatagramCredit {
                credit_epoch: 1,
                max_unretired_bytes: 8_388_608,
                max_active_generations: 32,
                max_decode_work: 4_194_304,
                max_open_epochs: 4,
            }),
            "datagram_credit",
        );
    }

    #[test]
    fn a_symbol_datagram_matches_its_vector_and_round_trips() {
        let geometry = Geometry::new(8, 2, 4).unwrap();
        let symbol = vector("symbol_datagram", "symbol_hex");
        let header = SymbolHeader {
            epoch: 7,
            generation: 1,
            esi: 5,
        };
        let mut out = Vec::new();
        encode_symbol(header, geometry, &symbol, &mut out).unwrap();
        assert_eq!(out, vector("symbol_datagram", "datagram_hex"));
        assert_eq!(out.len(), SYMBOL_HEADER_LEN + 4);
        let (decoded, body) = decode_symbol(&out, geometry).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(body, symbol.as_slice());

        // A wrong length is a drop, an ESI past the geometry is a drop, and
        // the encoder refuses both before they exist.
        assert_eq!(
            decode_symbol(&out[..out.len() - 1], geometry),
            Err(Error::Malformed)
        );
        let mut long = out.clone();
        long.push(0);
        assert_eq!(decode_symbol(&long, geometry), Err(Error::Malformed));
        let mut wide = out.clone();
        wide[8] = 10;
        assert_eq!(decode_symbol(&wide, geometry), Err(Error::InvalidValue));
        wide[8] = 9;
        assert!(
            decode_symbol(&wide, geometry).is_ok(),
            "the last repair ESI"
        );
        assert_eq!(
            encode_symbol(
                SymbolHeader { esi: 10, ..header },
                geometry,
                &symbol,
                &mut Vec::new()
            ),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            encode_symbol(header, geometry, &symbol[..3], &mut Vec::new()),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            decode_symbol(&[0; SYMBOL_HEADER_LEN + 4], Geometry::new(1, 0, 3).unwrap()),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn coding_epoch_open_bounds_are_the_specs() {
        let mut out = Vec::new();
        let base = open();
        let bad =
            |value: CodingEpochOpen| encode(&TypedFrame::CodingEpochOpen(value), &mut out.clone());
        assert_eq!(
            bad(CodingEpochOpen { length: 0, ..base }),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            bad(CodingEpochOpen {
                offset: 200_000 - 131_072 + 1,
                ..base
            }),
            Err(Error::InvalidValue),
            "offset + length past the object"
        );
        assert_eq!(
            bad(CodingEpochOpen {
                offset: u64::MAX,
                ..base
            }),
            Err(Error::InvalidValue),
            "offset + length overflows"
        );
        assert!(
            bad(CodingEpochOpen {
                offset: 200_000 - 131_072,
                ..base
            })
            .is_ok(),
            "an exact fit"
        );
        // A geometry outside the caps or an epoch past u32 cannot be built by
        // an encoder, so it is exercised on the decoder with hand-made bytes.
        encode(&TypedFrame::CodingEpochOpen(base), &mut out).unwrap();
        let payload_at = out.len() - vector("coding_epoch_open", "payload_hex").len();
        let mut wide_k = out.clone();
        // key 4 value 0x18 0x40 (64): make it 65.
        let k_at = payload_at
            + wide_k[payload_at..]
                .windows(3)
                .position(|w| w == [0x04, 0x18, 0x40])
                .unwrap();
        wide_k[k_at + 2] = 65;
        assert_eq!(decode(&wide_k, limits()), Err(Error::InvalidValue));
        let mut wide_r = out.clone();
        // key 5 value 0x10 (16): make it 17, still a one-byte minimal uint.
        let r_at = payload_at
            + wide_r[payload_at..]
                .windows(2)
                .position(|w| w == [0x05, 0x10])
                .unwrap();
        wide_r[r_at + 1] = 17;
        assert_eq!(decode(&wide_r, limits()), Err(Error::InvalidValue));
        assert_eq!(base.generation_count(), 2);
        assert_eq!(
            CodingEpochOpen {
                length: 65_536,
                ..base
            }
            .generation_count(),
            1
        );
        assert_eq!(
            CodingEpochOpen {
                length: 65_537,
                ..base
            }
            .generation_count(),
            2
        );
    }

    #[test]
    fn gen_state_missing_sources_are_bounded_ascending_source_esis() {
        let good = GenState {
            epoch: 1,
            generation: 2,
            sequence: 3,
            received: 80,
            missing_sources: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(encode(&TypedFrame::GenState(good.clone()), &mut out).is_ok());
        let bad = |value: GenState| encode(&TypedFrame::GenState(value), &mut Vec::new());
        assert_eq!(
            bad(GenState {
                received: 81,
                ..good.clone()
            }),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            bad(GenState {
                missing_sources: vec![64],
                ..good.clone()
            }),
            Err(Error::InvalidValue),
            "a repair ESI is never missing-source"
        );
        assert_eq!(
            bad(GenState {
                missing_sources: vec![3, 3],
                ..good.clone()
            }),
            Err(Error::InvalidValue),
            "strictly ascending"
        );
        assert_eq!(
            bad(GenState {
                missing_sources: vec![5, 4],
                ..good.clone()
            }),
            Err(Error::InvalidValue)
        );
        assert!(
            bad(GenState {
                missing_sources: (0..64).collect(),
                ..good.clone()
            })
            .is_ok(),
            "every source missing is the largest list"
        );
        assert_eq!(
            bad(GenState {
                missing_sources: (0..65).collect(),
                ..good
            }),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn gen_done_outcomes_and_u32_fields_are_checked_on_decode() {
        let mut out = Vec::new();
        encode(
            &TypedFrame::GenDone(GenDone {
                epoch: u32::MAX,
                generation: u32::MAX,
                outcome: GenOutcome::Abandoned,
            }),
            &mut out,
        )
        .unwrap();
        let (decoded, _) = decode(&out, limits()).unwrap();
        assert_eq!(
            decoded,
            TypedFrame::GenDone(GenDone {
                epoch: u32::MAX,
                generation: u32::MAX,
                outcome: GenOutcome::Abandoned,
            })
        );
        // Outcome 1 is the last byte; 2 is refused and 3 is not an outcome.
        let last = out.len() - 1;
        assert_eq!(out[last], 1);
        out[last] = 2;
        assert!(matches!(
            decode(&out, limits()),
            Ok((
                TypedFrame::GenDone(GenDone {
                    outcome: GenOutcome::Refused,
                    ..
                }),
                _
            ))
        ));
        out[last] = 3;
        assert_eq!(decode(&out, limits()), Err(Error::InvalidValue));
        // An epoch of 2^32 does not fit the datagram header.
        let mut wide = Vec::new();
        vot_cbor::map(&mut wide, 1);
        vot_cbor::uint(&mut wide, 0);
        vot_cbor::uint(&mut wide, 1 << 32);
        let mut framed = Vec::new();
        crate::encode_frame(crate::frame_type::CODING_EPOCH_CLOSE, &wide, &mut framed).unwrap();
        assert_eq!(decode(&framed, limits()), Err(Error::InvalidValue));
    }
}
