//! Date/time helpers — extracted from store-rs/memory.rs and server-rs/time_util.rs.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as ISO 8601 UTC string with nanosecond precision.
///
/// Format: `2006-01-02T15:04:05.999999999Z`
#[must_use]
pub fn now_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    let (year, month, day, hour, min, sec) = unix_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{nanos:09}Z")
}

/// Current time as ISO 8601 UTC string (second precision).
///
/// Format: `2006-01-02T15:04:05Z`
#[must_use]
pub fn now_iso_secs() -> String {
    format_iso(unix_now_secs())
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn format_iso(secs: u64) -> String {
    let (year, month, day, hour, min, sec) = unix_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Format a unix timestamp as `YYYY-MM-DD` (for `sunset_date` etc.).
#[must_use]
pub fn format_date(unix_secs: u64) -> String {
    #[allow(clippy::cast_possible_wrap)]
    // NOTE: days since epoch fit safely in i64 for any realistic timestamp
    let days = (unix_secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Current unix timestamp in seconds.
#[must_use]
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current time in bracketed format: `[YYYY-MM-DD HH:MM:SS]`.
///
/// Useful for log line timestamps.
#[must_use]
pub fn now_bracket() -> String {
    let secs = unix_now_secs();
    let (year, month, day, hour, min, sec) = unix_to_datetime(secs);
    format!("[{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}]")
}

/// Current unix timestamp in nanoseconds.
#[must_use]
pub fn unix_now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Convert unix seconds to `(year, month, day, hour, minute, second)`.
#[must_use]
#[allow(clippy::cast_possible_wrap)] // NOTE: days since epoch fit safely in i64 for realistic timestamps
#[allow(clippy::cast_possible_truncation)] // NOTE: time-of-day and index values fit in u32 by algorithm invariants
#[allow(clippy::cast_sign_loss)] // NOTE: remaining_days is always non-negative at this point
pub fn unix_to_datetime(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hour = (time_of_day / 3600) as u32;
    let min = ((time_of_day % 3600) / 60) as u32;
    let sec = (time_of_day % 60) as u32;

    let mut y = 1970i32;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let leap = is_leap_year(y);
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0u32;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = (i + 1) as u32;
            break;
        }
        remaining_days -= md;
    }

    let d = remaining_days as u32 + 1;
    (y, m, d, hour, min, sec)
}

/// Check if a year is a leap year.
#[must_use]
pub fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Howard Hinnant's algorithm: days since 1970-01-01 -> (year, month, day).
#[must_use]
#[allow(clippy::cast_sign_loss)] // NOTE: algorithm guarantees doe is non-negative
#[allow(clippy::cast_possible_wrap)] // NOTE: yoe as i64 fits; era*400 + yoe cannot overflow for realistic dates
#[allow(clippy::cast_possible_truncation)] // NOTE: d and m values are small by construction (day ≤ 31, month ≤ 12)
pub fn civil_from_days(mut z: i64) -> (i64, u32, u32) {
    z += 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_iso_format() {
        let iso = now_iso();
        assert!(iso.ends_with('Z'));
        assert!(iso.contains('T'));
        assert!(iso.len() > 20); // has nanoseconds
    }

    #[test]
    fn now_iso_secs_format() {
        let iso = now_iso_secs();
        assert_eq!(iso.len(), 20);
        assert!(iso.ends_with('Z'));
    }

    #[test]
    fn format_date_known_value() {
        // 2025-01-01 00:00:00 UTC = 1_735_689_600 unix secs
        assert_eq!(format_date(1_735_689_600), "2025-01-01");
    }

    #[test]
    fn format_iso_known_value() {
        assert_eq!(format_iso(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn now_bracket_format() {
        let ts = now_bracket();
        assert!(ts.starts_with('['));
        assert!(ts.ends_with(']'));
        assert!(ts.contains(' ')); // space between date and time
        assert_eq!(ts.len(), 21); // [YYYY-MM-DD HH:MM:SS]
    }

    #[test]
    fn leap_year_checks() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }
}
