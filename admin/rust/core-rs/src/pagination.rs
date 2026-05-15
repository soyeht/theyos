//! Cursor-based pagination utilities shared across crates.
//!
//! Cursors are opaque base64url-encoded strings of `{sort_value}|{id}`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

/// Encode an opaque cursor from a sort column value and row ID.
#[must_use]
pub fn encode_cursor(sort_value: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{sort_value}|{id}"))
}

/// Decode an opaque cursor into `(sort_value, id)`.
///
/// Returns `None` on invalid base64 or missing separator.
#[must_use]
pub fn decode_cursor(cursor: &str) -> Option<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    let (sort, id) = s.split_once('|')?;
    Some((sort.to_string(), id.to_string()))
}

/// Standard pagination query params: `?limit=N&cursor=...`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl PaginationParams {
    /// Clamp limit to `[1, max]`, defaulting to `default` when absent.
    #[must_use]
    pub fn effective_limit(&self, default: usize, max: usize) -> usize {
        self.limit.unwrap_or(default).clamp(1, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_cursor() {
        let encoded = encode_cursor("2026-01-15T10:30:00Z", "inst-abc");
        let (sort, id) = decode_cursor(&encoded).unwrap();
        assert_eq!(sort, "2026-01-15T10:30:00Z");
        assert_eq!(id, "inst-abc");
    }

    #[test]
    fn decode_invalid_base64_returns_none() {
        assert!(decode_cursor("not-valid-base64!!!").is_none());
    }

    #[test]
    fn decode_missing_separator_returns_none() {
        let encoded = URL_SAFE_NO_PAD.encode("no-separator-here");
        assert!(decode_cursor(&encoded).is_none());
    }

    #[test]
    fn effective_limit_defaults() {
        let p = PaginationParams {
            limit: None,
            cursor: None,
        };
        assert_eq!(p.effective_limit(50, 100), 50);
    }

    #[test]
    fn effective_limit_clamps_high() {
        let p = PaginationParams {
            limit: Some(999),
            cursor: None,
        };
        assert_eq!(p.effective_limit(50, 100), 100);
    }

    #[test]
    fn effective_limit_clamps_zero() {
        let p = PaginationParams {
            limit: Some(0),
            cursor: None,
        };
        assert_eq!(p.effective_limit(50, 100), 1);
    }

    #[test]
    fn cursor_with_special_chars_in_timestamp() {
        // Timestamps contain colons and hyphens — verify they roundtrip
        let encoded = encode_cursor("2026-01-15T10:30:00+00:00", "inst-abc123");
        let (sort, id) = decode_cursor(&encoded).unwrap();
        assert_eq!(sort, "2026-01-15T10:30:00+00:00");
        assert_eq!(id, "inst-abc123");
    }
}
