//! GF(2^8) with the 0x11D polynomial and generator 2 (`spec/fec.md` section 1).

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
    let log_c = LOG[coefficient as usize] as usize;
    for (o, s) in out.iter_mut().zip(symbol) {
        if *s != 0 {
            *o ^= EXP[log_c + LOG[*s as usize] as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let symbol: Vec<u8> = (0..=255).collect();
        for coefficient in [0_u8, 1, 2, 0x1D, 0x80, 0xFF] {
            let mut out = vec![0xA5_u8; 256];
            mul_add(&mut out, coefficient, &symbol);
            for (i, byte) in out.iter().enumerate() {
                assert_eq!(
                    *byte,
                    0xA5 ^ mul(coefficient, symbol[i]),
                    "{coefficient} at {i}"
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
