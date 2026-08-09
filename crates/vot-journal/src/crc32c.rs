//! CRC32C, its incremental update, and length-aware combination.

#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c_update(CRC32C_EMPTY, bytes)
}

/// The CRC of nothing, which is what a running checksum starts from.
pub const CRC32C_EMPTY: u32 = 0;

/// Extends a CRC over more bytes, so a checksum can be computed from a stream
/// without holding what it covers.
///
/// `crc32c_update(crc32c_update(CRC32C_EMPTY, a), b)` equals
/// `crc32c([a, b].concat())`.
#[must_use]
pub fn crc32c_update(crc: u32, bytes: &[u8]) -> u32 {
    let mut running = !crc;
    for byte in bytes {
        running ^= u32::from(*byte);
        for _ in 0..8 {
            running = (running >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(running & 1));
        }
    }
    !running
}

/// The CRC of `a` followed by `b`, given each one's CRC and the length of
/// `b`. zlib's `crc32_combine` over the CRC-32C polynomial: advancing `a`'s
/// remainder by `len_b` zero bytes is a linear map over GF(2), so squaring
/// the operator gets there in a logarithmic number of steps rather than one
/// per byte.
#[must_use]
pub fn crc32c_combine(a: u32, b: u32, len_b: u64) -> u32 {
    if len_b == 0 {
        return a;
    }
    let mut odd = [0_u32; 32];
    // The operator for one zero bit: the polynomial, then the identity.
    odd[0] = 0x82f6_3b78;
    let mut row = 1_u32;
    for entry in odd.iter_mut().skip(1) {
        *entry = row;
        row <<= 1;
    }
    let mut even = [0_u32; 32];
    square(&mut even, &odd); // two zero bits
    square(&mut odd, &even); // four, which is half a byte

    let mut advanced = a;
    let mut remaining = len_b;
    // One pass per bit of the length, counted, because a shift that stopped
    // shrinking would otherwise spin rather than answer wrongly.
    for _ in 0..u64::BITS {
        if remaining == 0 {
            break;
        }
        square(&mut even, &odd);
        if remaining & 1 != 0 {
            advanced = apply(&even, advanced);
        }
        remaining >>= 1;
        std::mem::swap(&mut even, &mut odd);
    }
    advanced ^ b
}

/// One GF(2) matrix applied to a vector, both of them 32 bits wide. The sum
/// of the columns the vector selects.
pub(super) fn apply(matrix: &[u32; 32], vector: u32) -> u32 {
    let mut sum = 0;
    for (index, column) in matrix.iter().enumerate() {
        if vector >> index & 1 != 0 {
            sum ^= *column;
        }
    }
    sum
}

/// The operator that does what `matrix` does twice.
pub(super) fn square(into: &mut [u32; 32], matrix: &[u32; 32]) {
    for (slot, column) in into.iter_mut().zip(matrix.iter()) {
        *slot = apply(matrix, *column);
    }
}
