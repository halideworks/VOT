//! VOT datagram FEC erasure code: systematic Cauchy Reed-Solomon over GF(2^8)
//! as `spec/fec.md` (ADR-0039) defines it. Experimental; nothing on the
//! reliable path depends on this crate.

#![forbid(unsafe_code)]

mod gf;
mod plan;
mod receiver;
mod sender;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;

pub use plan::{EpochPlan, SourceSpan};
pub use receiver::{
    Credit, Decoded, Drop, MAX_TRACKED_GENERATIONS, Open, Receiver, Report, Symbol,
};
pub use sender::{Done, Sender, State, encode_generation};

/// The frozen v0.3 caps on one generation (`spec/architecture.md` section 9).
pub const MAX_SOURCE_SYMBOLS: usize = 64;
pub const MAX_REPAIR_SYMBOLS: usize = 16;
pub const MAX_SYMBOL_LENGTH: usize = 65_535;
/// The most ESIs one generation carries, source and repair together.
pub const MAX_SYMBOLS: usize = MAX_SOURCE_SYMBOLS + MAX_REPAIR_SYMBOLS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A source count, repair count, or symbol length outside the caps.
    InvalidGeometry,
    /// A received ESI the geometry has no row for, a symbol whose length is
    /// not the geometry's, or one ESI presented twice. The whole call fails.
    InvalidSymbol,
    /// Fewer than `k` distinct symbols; nothing is reconstructed.
    InsufficientSymbols,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidGeometry => "invalid FEC geometry",
            Self::InvalidSymbol => "invalid FEC symbol",
            Self::InsufficientSymbols => "insufficient FEC symbols",
        })
    }
}

impl std::error::Error for Error {}

/// One generation's shape: `k` source symbols, `r` repair symbols, every
/// symbol exactly `symbol_length` bytes. Constructed, so every value in one
/// is inside the caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    source_count: usize,
    repair_count: usize,
    symbol_length: usize,
}

impl Geometry {
    /// # Errors
    /// `InvalidGeometry` for a source count outside `1..=64`, a repair count
    /// above 16, or a symbol length outside `1..=65535`.
    pub const fn new(
        source_count: usize,
        repair_count: usize,
        symbol_length: usize,
    ) -> Result<Self, Error> {
        if source_count == 0
            || source_count > MAX_SOURCE_SYMBOLS
            || repair_count > MAX_REPAIR_SYMBOLS
            || symbol_length == 0
            || symbol_length > MAX_SYMBOL_LENGTH
        {
            return Err(Error::InvalidGeometry);
        }
        Ok(Self {
            source_count,
            repair_count,
            symbol_length,
        })
    }

    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.source_count
    }

    #[must_use]
    pub const fn repair_count(&self) -> usize {
        self.repair_count
    }

    #[must_use]
    pub const fn symbol_length(&self) -> usize {
        self.symbol_length
    }

    /// Source plus repair: the ESIs one generation carries are `0..this`.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.source_count + self.repair_count
    }

    /// Row `repair_index` of the Cauchy generator: `inverse((k + i) XOR j)`.
    /// `k + i` and `j` never coincide, so every entry is defined and non-zero.
    fn generator_row(&self, repair_index: usize, row: &mut [u8]) {
        debug_assert!(repair_index < self.repair_count);
        debug_assert_eq!(row.len(), self.source_count);
        let x = self.source_count + repair_index;
        for (j, entry) in row.iter_mut().enumerate() {
            // Both operands are below 128, so the XOR fits a byte, and
            // x >= k > j keeps it non-zero.
            *entry = gf::inv(u8::try_from(x ^ j).expect("operands below 128"));
        }
    }

    fn check_symbol(&self, symbol: &[u8]) -> Result<(), Error> {
        if symbol.len() == self.symbol_length {
            Ok(())
        } else {
            Err(Error::InvalidSymbol)
        }
    }
}

/// The `r` repair symbols of one generation, ESIs `k..k+r`, in order.
///
/// # Errors
/// `InvalidSymbol` when `source` does not hold exactly `k` symbols of the
/// geometry's length.
pub fn encode(geometry: Geometry, source: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
    if source.len() != geometry.source_count {
        return Err(Error::InvalidSymbol);
    }
    for symbol in source {
        geometry.check_symbol(symbol)?;
    }
    let mut row = vec![0_u8; geometry.source_count];
    let mut repair = Vec::with_capacity(geometry.repair_count);
    for i in 0..geometry.repair_count {
        geometry.generator_row(i, &mut row);
        let mut out = vec![0_u8; geometry.symbol_length];
        for (coefficient, symbol) in row.iter().zip(source) {
            gf::mul_add(&mut out, *coefficient, symbol);
        }
        repair.push(out);
    }
    Ok(repair)
}

/// All `k` source symbols of one generation from any `k` of its symbols.
///
/// `received` pairs each symbol with its ESI, in any order. Selection is the
/// spec's: every received source symbol, then repair symbols by ascending
/// ESI, so the same input always solves the same system.
///
/// # Errors
/// `InvalidSymbol` for an ESI at or above `k + r`, a symbol whose length is
/// not the geometry's, or a repeated ESI; `InsufficientSymbols` for fewer
/// than `k` distinct symbols. Neither reconstructs anything.
///
/// # Panics
/// Never for a valid geometry: every `k`-row selection of the generator is
/// invertible, so elimination always finds a pivot.
pub fn decode(geometry: Geometry, received: &[(usize, &[u8])]) -> Result<Vec<Vec<u8>>, Error> {
    let k = geometry.source_count;
    // At most 80 entries, so a fixed table rather than an allocation from
    // the peer's count.
    let mut symbols = [None; MAX_SYMBOLS];
    for (esi, symbol) in received {
        if *esi >= geometry.symbol_count() || symbols[*esi].is_some() {
            return Err(Error::InvalidSymbol);
        }
        geometry.check_symbol(symbol)?;
        symbols[*esi] = Some(*symbol);
    }
    if received.len() < k {
        return Err(Error::InsufficientSymbols);
    }
    let missing: Vec<usize> = (0..k).filter(|esi| symbols[*esi].is_none()).collect();
    if missing.is_empty() {
        // Every source symbol arrived; nothing to solve.
        return Ok((0..k)
            .map(|esi| symbols[esi].expect("seen").to_vec())
            .collect());
    }

    // Known sources move to the right-hand side, leaving one coefficient
    // column and one repair row per missing source.
    let m = missing.len();
    let width = m + geometry.symbol_length;
    let mut coefficients = [0_u8; MAX_SOURCE_SYMBOLS];
    let mut rows = Vec::with_capacity(m);
    for esi in (k..geometry.symbol_count())
        .filter(|esi| symbols[*esi].is_some())
        .take(m)
    {
        let mut row = vec![0_u8; width];
        geometry.generator_row(esi - k, &mut coefficients[..k]);
        for (column, source_esi) in missing.iter().enumerate() {
            row[column] = coefficients[*source_esi];
        }
        row[m..].copy_from_slice(symbols[esi].expect("seen"));
        for source_esi in (0..k).filter(|source_esi| symbols[*source_esi].is_some()) {
            gf::mul_add(
                &mut row[m..],
                coefficients[source_esi],
                symbols[source_esi].expect("seen"),
            );
        }
        rows.push(row);
    }
    debug_assert_eq!(rows.len(), m);
    gauss_jordan(&mut rows, m);

    let mut solved = rows.into_iter().map(|row| row[m..].to_vec());
    Ok((0..k)
        .map(|esi| {
            symbols[esi].map_or_else(
                || solved.next().expect("one row per missing source"),
                <[u8]>::to_vec,
            )
        })
        .collect())
}

/// Reduces `rows` to the identity on the first `k` columns, carrying the
/// remaining columns along. Every `k`-row selection of `[I; G]` is invertible,
/// so a pivot always exists.
fn gauss_jordan(rows: &mut [Vec<u8>], k: usize) {
    for col in 0..k {
        let pivot = (col..k)
            .find(|r| rows[*r][col] != 0)
            .expect("a Cauchy selection is invertible");
        rows.swap(col, pivot);
        let inv = gf::inv(rows[col][col]);
        for value in &mut rows[col] {
            *value = gf::mul(inv, *value);
        }
        let (before, rest) = rows.split_at_mut(col);
        let (pivot_row, after) = rest.split_first_mut().expect("the pivot row");
        for row in before.iter_mut().chain(after.iter_mut()) {
            let factor = row[col];
            gf::mul_add(row, factor, pivot_row);
        }
    }
}
