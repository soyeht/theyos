//! Slug normalization — extracted from store-rs/memory.rs.

/// Normalize a string into a URL-safe slug.
///
/// - Lowercases all characters
/// - Replaces whitespace, dashes, underscores with single dashes
/// - Strips non-alphanumeric/non-dash characters
/// - Trims leading/trailing dashes
#[must_use]
pub fn normalize_slug(input: &str) -> String {
    let input = input.trim().to_lowercase();
    if input.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity(input.len());
    let mut last_dash = false;

    for ch in input.chars() {
        if ch.is_alphanumeric() {
            result.push(ch);
            last_dash = false;
        } else if (ch == '-' || ch == '_' || ch.is_whitespace()) && !last_dash {
            result.push('-');
            last_dash = true;
        }
    }

    result.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_cases() {
        assert_eq!(normalize_slug("Alice"), "alice");
        assert_eq!(normalize_slug("  My Instance  "), "my-instance");
        assert_eq!(normalize_slug("hello_world"), "hello-world");
        assert_eq!(normalize_slug("---trimmed---"), "trimmed");
        assert_eq!(normalize_slug(""), "");
        assert_eq!(normalize_slug("UPPER CASE"), "upper-case");
        assert_eq!(normalize_slug("a--b__c  d"), "a-b-c-d");
    }
}
