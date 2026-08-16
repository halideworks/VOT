//! A coding epoch's plan: which object bytes each generation and symbol
//! covers (`spec/fec.md` section 9).

use crate::{Error, Geometry};

/// One epoch as `CODING_EPOCH_OPEN` states it, without the object identity:
/// the byte range and the geometry, from which every generation follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochPlan {
    epoch: u32,
    offset: u64,
    length: u64,
    geometry: Geometry,
}

/// The bytes one source symbol covers, or the fact that it covers none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSpan {
    /// `bytes` of the object starting at `offset`; the symbol is zero-padded
    /// past `bytes` when `bytes < L`.
    Bytes { offset: u64, bytes: usize },
    /// Entirely past the range: all zero, never sent, counted as received.
    Zero,
}

impl EpochPlan {
    /// # Errors
    /// `InvalidGeometry` for a zero length or a length whose generation count
    /// does not fit u32.
    pub fn new(epoch: u32, offset: u64, length: u64, geometry: Geometry) -> Result<Self, Error> {
        if length == 0 || offset.checked_add(length).is_none() {
            return Err(Error::InvalidGeometry);
        }
        let plan = Self {
            epoch,
            offset,
            length,
            geometry,
        };
        if plan.generation_count() > u64::from(u32::MAX) + 1 {
            return Err(Error::InvalidGeometry);
        }
        Ok(plan)
    }

    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Bytes one full generation covers: `k * L`.
    #[must_use]
    pub const fn generation_bytes(&self) -> u64 {
        self.geometry.source_count() as u64 * self.geometry.symbol_length() as u64
    }

    /// `ceil(length / (k * L))`.
    #[must_use]
    pub const fn generation_count(&self) -> u64 {
        self.length.div_ceil(self.generation_bytes())
    }

    /// Whether `generation` lies inside this epoch.
    #[must_use]
    pub const fn holds(&self, generation: u32) -> bool {
        (generation as u64) < self.generation_count()
    }

    /// The object bytes generation `g` covers: `(offset, bytes)`, `bytes`
    /// short only for the last generation.
    ///
    /// # Panics
    /// When `generation` is past the epoch; check `holds` first.
    #[must_use]
    pub fn generation_span(&self, generation: u32) -> (u64, u64) {
        assert!(self.holds(generation), "generation past the epoch");
        let start = u64::from(generation) * self.generation_bytes();
        let bytes = self.generation_bytes().min(self.length - start);
        (self.offset + start, bytes)
    }

    /// What source symbol `esi` of `generation` covers.
    ///
    /// # Panics
    /// When `generation` is past the epoch or `esi` is not a source ESI.
    #[must_use]
    pub fn source_span(&self, generation: u32, esi: u8) -> SourceSpan {
        let esi = usize::from(esi);
        assert!(esi < self.geometry.source_count(), "not a source ESI");
        let (start, bytes) = self.generation_span(generation);
        let symbol_start = (esi * self.geometry.symbol_length()) as u64;
        if symbol_start >= bytes {
            return SourceSpan::Zero;
        }
        let covered = (bytes - symbol_start).min(self.geometry.symbol_length() as u64);
        SourceSpan::Bytes {
            offset: start + symbol_start,
            bytes: usize::try_from(covered).expect("at most L"),
        }
    }

    /// Source ESIs of `generation` that carry bytes: `0..this`. The rest are
    /// all zero and counted as received from the start.
    ///
    /// # Panics
    /// When `generation` is past the epoch.
    #[must_use]
    pub fn sent_source_count(&self, generation: u32) -> usize {
        let (_, bytes) = self.generation_span(generation);
        usize::try_from(bytes.div_ceil(self.geometry.symbol_length() as u64)).expect("at most k")
    }
}
