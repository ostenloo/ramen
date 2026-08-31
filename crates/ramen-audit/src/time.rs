//! RFC 3339 UTC timestamps with millisecond precision, dependency-free.
//!
//! Every record carries `ts` in the exact form
//! `YYYY-MM-DDTHH:MM:SS.mmmZ` (24 ASCII characters). Because the format is
//! fixed-width and always UTC, **lexicographic comparison is chronological**
//! — the verifier's non-decreasing check needs no parsing.

use std::time::{SystemTime, UNIX_EPOCH};

/// Render the current system time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn now_rfc3339() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    format_rfc3339(secs, millis)
}

/// Format a UNIX timestamp (seconds + milliseconds) as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn format_rfc3339(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Strictly validate the `YYYY-MM-DDTHH:MM:SS.mmmZ` shape.
///
/// A record whose `ts` fails this check is a `CorruptRecord` finding: the
/// writer always emits this exact format, so anything else means the bytes
/// were altered.
pub fn is_valid_rfc3339(s: &str) -> bool {
    let b = match s.as_bytes() {
        b if b.len() == 24 => b,
        _ => return false,
    };
    // Layout: 0-3 year, 4 '-', 5-6 month, 7 '-', 8-9 day, 10 'T',
    //         11-12 hour, 13 ':', 14-15 min, 16 ':', 17-18 sec, 19 '.',
    //         20-22 millis, 23 'Z'. `Some(c)` = fixed char, `None` = digit.
    const FIXED: [Option<u8>; 24] = [
        None, None, None, None, Some(b'-'), None, None, Some(b'-'), None, None, Some(b'T'), None,
        None, Some(b':'), None, None, Some(b':'), None, None, Some(b'.'), None, None, None,
        Some(b'Z'),
    ];
    for (i, &c) in b.iter().enumerate() {
        match FIXED[i] {
            Some(f) if c != f => return false,
            None if !c.is_ascii_digit() => return false,
            _ => {}
        }
    }
    let get = |lo: usize, hi: usize| -> u32 {
        s[lo..hi].parse().unwrap_or(u32::MAX)
    };
    let (month, day, hour, minute, second, millis) =
        (get(5, 7), get(8, 10), get(11, 13), get(14, 16), get(17, 19), get(20, 23));
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
        && millis < 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_correctly() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_date_round_trips() {
        // 2026-08-30T14:07:33.119Z == 1788098853.119 (checked with python3).
        let s = format_rfc3339(1_788_098_853, 119);
        assert_eq!(s, "2026-08-30T14:07:33.119Z");
    }

    #[test]
    fn validation_is_strict() {
        assert!(is_valid_rfc3339("2026-08-30T14:07:33.119Z"));
        assert!(!is_valid_rfc3339("2026-08-30T14:07:33Z")); // no millis
        assert!(!is_valid_rfc3339("2026-13-30T14:07:33.119Z")); // month 13
        assert!(!is_valid_rfc3339("2026-08-30T24:07:33.119Z")); // hour 24
        assert!(!is_valid_rfc3339("2026-08-30T14:07:33.119x"));
        assert!(!is_valid_rfc3339("2026-08-30 14:07:33.119Z"));
        assert!(!is_valid_rfc3339(""));
        assert!(!is_valid_rfc3339("2026-08-30T14:07:33.119+00:00"));
    }

    #[test]
    fn lexicographic_order_is_chronological() {
        let a = format_rfc3339(1_788_098_853, 119);
        let b = format_rfc3339(1_788_098_853, 120);
        let c = format_rfc3339(1_788_098_854, 0);
        assert!(a < b && b < c);
    }
}
