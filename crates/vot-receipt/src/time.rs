//! The RFC 3339 subset receipts carry.

pub(super) fn valid_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 35
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let Some(year) = decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = decimal(&bytes[17..19]) else {
        return false;
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }

    let mut offset = 19;
    if bytes.get(offset) == Some(&b'.') {
        let fraction_start = offset + 1;
        let digits = bytes[fraction_start..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return false;
        }
        offset = fraction_start + digits;
    }
    match bytes.get(offset) {
        Some(b'Z' | b'z') => offset + 1 == bytes.len(),
        Some(b'+' | b'-') => {
            bytes.len() == offset + 6
                && bytes.get(offset + 3) == Some(&b':')
                && decimal(&bytes[offset + 1..offset + 3]).is_some_and(|hours| hours <= 23)
                && decimal(&bytes[offset + 4..offset + 6]).is_some_and(|minutes| minutes <= 59)
        }
        _ => false,
    }
}

pub(super) fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

pub(super) const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
