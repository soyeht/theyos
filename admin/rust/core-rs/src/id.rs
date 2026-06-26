//! ID generation — extracted from jobs-rs.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique ID with the given prefix (e.g. `"job"`, `"log"`).
///
/// Format: `{prefix}_{hex}` truncated to `prefix.len() + 1 + 16` chars.
pub fn generate_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    #[allow(clippy::cast_possible_truncation)] // NOTE: lower 64 bits of nanos suffice for hashing
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut h = DefaultHasher::new();
    ts.hash(&mut h);
    n.hash(&mut h);
    let addr = &raw const n as u64;
    addr.hash(&mut h);
    let digest = h.finish();
    let full = format!("{prefix}_{ts:016x}{digest:016x}");
    full.chars().take(prefix.len() + 1 + 16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_ids() {
        let ids: std::collections::HashSet<String> =
            (0..200).map(|_| generate_id("test")).collect();
        assert_eq!(ids.len(), 200);
    }

    #[test]
    fn prefix_preserved() {
        let id = generate_id("job");
        assert!(id.starts_with("job_"));
    }

    #[test]
    fn correct_length() {
        let id = generate_id("job");
        assert_eq!(id.len(), 4 + 16); // "job_" + 16 hex chars
    }
}
