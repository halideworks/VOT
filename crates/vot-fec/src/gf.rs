//! GF(2^8) with the 0x11D polynomial and generator 2 (`spec/fec.md` section 1).

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use std::sync::LazyLock;

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use fearless_simd::{Level, Simd, prelude::*, u8x16};

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
static SIMD_LEVEL: LazyLock<Level> = LazyLock::new(Level::new);

const POLYNOMIAL: u16 = 0x11D;

/// `EXP[i] = 2^i` for `i` in `0..255`, then repeated so a sum of two logs
/// indexes without a reduction. `LOG[EXP[i]] = i`; `LOG[0]` is unused.
#[allow(
    clippy::cast_possible_truncation,
    reason = "masked to a byte on the line above each cast"
)]
const fn tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0_u8; 512];
    let mut log = [0_u8; 256];
    let mut value: u16 = 1;
    let mut power = 0;
    while power < 255 {
        // `value` is reduced below 0x100 and `power` below 255 here.
        exp[power] = (value & 0xFF) as u8;
        log[value as usize] = (power & 0xFF) as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= POLYNOMIAL;
        }
        power += 1;
    }
    // Generator 2 has order 255 under 0x11D, so the cycle closes at 1.
    assert!(value == 1);
    while power < 512 {
        exp[power] = exp[power - 255];
        power += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

#[inline]
#[must_use]
pub(crate) const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
}

/// The multiplicative inverse of a non-zero element.
///
/// # Panics
/// On zero, which has no inverse; every caller passes a value it built as
/// non-zero.
#[inline]
#[must_use]
pub(crate) const fn inv(a: u8) -> u8 {
    assert!(a != 0, "no inverse of zero in GF(2^8)");
    EXP[255 - LOG[a as usize] as usize]
}

/// Every byte product, built once rather than once per encode-kernel call.
#[allow(clippy::large_stack_arrays)] // Const-evaluated directly into static storage.
const fn product_tables() -> [[u8; 256]; 256] {
    let mut products = [[0_u8; 256]; 256];
    let mut coefficient = 1;
    while coefficient < 256 {
        let log_c = LOG[coefficient] as usize;
        let mut value = 1;
        while value < 256 {
            products[coefficient][value] = EXP[log_c + LOG[value] as usize];
            value += 1;
        }
        coefficient += 1;
    }
    products
}

static PRODUCTS: [[u8; 256]; 256] = product_tables();

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
const fn nibble_tables() -> [[[u8; 16]; 2]; 256] {
    let mut tables = [[[0_u8; 16]; 2]; 256];
    let mut coefficient = 0;
    while coefficient < 256 {
        let mut nibble = 0;
        while nibble < 16 {
            tables[coefficient][0][nibble] = PRODUCTS[coefficient][nibble];
            tables[coefficient][1][nibble] = PRODUCTS[coefficient][nibble << 4];
            nibble += 1;
        }
        coefficient += 1;
    }
    tables
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
static NIBBLES: [[[u8; 16]; 2]; 256] = nibble_tables();

fn products_of(coefficient: u8) -> &'static [u8; 256] {
    &PRODUCTS[coefficient as usize]
}

/// `out[i] ^= coefficient * symbol[i]` for every byte, the encode kernel.
pub(crate) fn mul_add(out: &mut [u8], coefficient: u8, symbol: &[u8]) {
    debug_assert_eq!(out.len(), symbol.len());
    if coefficient == 0 {
        return;
    }
    if coefficient == 1 {
        for (o, s) in out.iter_mut().zip(symbol) {
            *o ^= *s;
        }
        return;
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if SIMD_LEVEL.as_sse4_2().is_none() {
        mul_add_scalar(out, coefficient, symbol);
        return;
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    fearless_simd::dispatch!(*SIMD_LEVEL, simd => mul_add_simd(simd, out, coefficient, symbol));

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    mul_add_scalar(out, coefficient, symbol)
}

fn mul_add_scalar(out: &mut [u8], coefficient: u8, symbol: &[u8]) {
    let products = products_of(coefficient);
    let mut out_chunks = out.chunks_exact_mut(8);
    let mut symbol_chunks = symbol.chunks_exact(8);
    for (o, s) in out_chunks.by_ref().zip(symbol_chunks.by_ref()) {
        o[0] ^= products[s[0] as usize];
        o[1] ^= products[s[1] as usize];
        o[2] ^= products[s[2] as usize];
        o[3] ^= products[s[3] as usize];
        o[4] ^= products[s[4] as usize];
        o[5] ^= products[s[5] as usize];
        o[6] ^= products[s[6] as usize];
        o[7] ^= products[s[7] as usize];
    }
    for (o, s) in out_chunks
        .into_remainder()
        .iter_mut()
        .zip(symbol_chunks.remainder())
    {
        *o ^= products[*s as usize];
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(
    clippy::inline_always,
    reason = "fearless_simd requires inlining to preserve target features after dispatch"
)]
#[inline(always)]
fn mul_add_simd<S: Simd>(simd: S, out: &mut [u8], coefficient: u8, symbol: &[u8]) {
    let tables = &NIBBLES[coefficient as usize];
    let low_table = S::u8s::block_splat(u8x16::from_slice(simd, &tables[0]));
    let high_table = S::u8s::block_splat(u8x16::from_slice(simd, &tables[1]));
    let mask = S::u8s::splat(simd, 0x0f);
    let mut out_chunks = out.chunks_exact_mut(S::u8s::N);
    let mut symbol_chunks = symbol.chunks_exact(S::u8s::N);
    for (o, s) in out_chunks.by_ref().zip(symbol_chunks.by_ref()) {
        let output = S::u8s::from_slice(simd, o);
        let input = S::u8s::from_slice(simd, s);
        let low = input & mask;
        let high = input >> 4;
        let product =
            low_table.swizzle_dyn_within_blocks(low) ^ high_table.swizzle_dyn_within_blocks(high);
        (output ^ product).store_slice(o);
    }
    mul_add_scalar(
        out_chunks.into_remainder(),
        coefficient,
        symbol_chunks.remainder(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the kernel's whole correctness: every entry has to be the
    /// product the scalar rule gives, including the zero the logarithm cannot
    /// take.
    #[test]
    fn every_product_table_matches_the_scalar_rule() {
        for coefficient in 1..=u8::MAX {
            let products = products_of(coefficient);
            assert_eq!(products[0], 0, "zero times {coefficient}");
            for value in 1..=u8::MAX {
                assert_eq!(
                    products[value as usize],
                    mul(coefficient, value),
                    "{coefficient} times {value}"
                );
            }
        }
    }

    #[test]
    fn every_non_zero_element_has_an_inverse_and_the_tables_agree() {
        for a in 1..=255_u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a}");
            assert_eq!(EXP[LOG[a as usize] as usize], a, "{a}");
        }
        assert_eq!(EXP[255], 1);
        assert_eq!(EXP[511], EXP[256]);
    }

    #[test]
    fn multiplication_is_the_field_operation() {
        // Schoolbook carry-less multiply reduced by 0x11D, independent of
        // the tables, over every pair.
        fn slow(a: u8, b: u8) -> u8 {
            let mut product: u16 = 0;
            let mut a = u16::from(a);
            let mut b = b;
            while b != 0 {
                if b & 1 != 0 {
                    product ^= a;
                }
                a <<= 1;
                if a & 0x100 != 0 {
                    a ^= POLYNOMIAL;
                }
                b >>= 1;
            }
            u8::try_from(product).expect("reduced below 0x100")
        }
        for a in 0..=255_u8 {
            for b in 0..=255_u8 {
                assert_eq!(mul(a, b), slow(a, b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn mul_add_matches_the_scalar_kernel() {
        for length in [0, 1, 15, 16, 31, 32, 33, 255, 256, 1_023, 1_024, 1_025] {
            let symbol: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 256).expect("under 256"))
                .collect();
            for coefficient in 0..=u8::MAX {
                let expected: Vec<u8> = symbol
                    .iter()
                    .map(|value| 0xA5 ^ mul(coefficient, *value))
                    .collect();
                let mut scalar = vec![0xA5_u8; length];
                mul_add_scalar(&mut scalar, coefficient, &symbol);
                assert_eq!(scalar, expected, "scalar {coefficient} at length {length}");

                let mut dispatched = vec![0xA5_u8; length];
                mul_add(&mut dispatched, coefficient, &symbol);
                assert_eq!(
                    dispatched, expected,
                    "dispatched {coefficient} at length {length}"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "no inverse of zero")]
    fn zero_has_no_inverse() {
        let _ = inv(0);
    }
}

#[cfg(test)]
mod cost {
    use super::*;

    /// Not a gate: what the kernel costs over the symbol length the shipped
    /// geometry uses. Run with
    /// `cargo test --release -p vot-fec what_the_kernel_costs -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement rather than a gate, and it wants a release build"]
    fn what_the_kernel_costs() {
        const LENGTH: u32 = 1_024;
        let symbol: Vec<u8> = (0..LENGTH)
            .map(|i| u8::try_from(i % 251).expect("under 251"))
            .collect();
        let mut out = vec![0_u8; symbol.len()];
        let rounds: u32 = 4_000_000;

        let began = std::time::Instant::now();
        for _ in 0..rounds {
            mul_add(&mut out, 1, &symbol);
        }
        let spent = began.elapsed();
        eprintln!(
            "mul_add xor: {rounds} calls of {LENGTH} bytes in {spent:?}, {:.2} GB/s, sink={}",
            (f64::from(rounds) * f64::from(LENGTH)) / spent.as_secs_f64() / 1e9,
            out[0]
        );

        let began = std::time::Instant::now();
        for round in 0..rounds {
            let coefficient = u8::try_from(round % 254).expect("under 254") + 2;
            mul_add(&mut out, coefficient, &symbol);
        }
        let spent = began.elapsed();
        eprintln!(
            "mul_add: {rounds} calls of {LENGTH} bytes in {spent:?}, {:.2} GB/s, sink={}",
            (f64::from(rounds) * f64::from(LENGTH)) / spent.as_secs_f64() / 1e9,
            out[0]
        );
    }
}
