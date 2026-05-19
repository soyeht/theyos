//! FR-025 emoji security code — deterministic 6-emoji-word identifier
//! derived from `(m_pub, nonce, hostname)`.
//!
//! ## Algorithm (cross-language invariant — Swift implementation MUST match byte-for-byte)
//!
//! 1. Compute `digest = BLAKE3-256(m_pub_sec1 ‖ nonce ‖ hostname_utf8)`.
//! 2. Extract six 11-bit indices using the same bit-extraction as `fingerprint.rs`:
//!    - Each index `i ∈ [0, 2047]` selects one entry from
//!      `emoji-security-code-wordlist.csv`.
//! 3. Return the six emoji characters (Unicode scalars from the CSV).
//!
//! ## Source of truth
//!
//! `specs/005-soyeht-onboarding/contracts/emoji-security-code-wordlist.csv`
//! is embedded at compile time via `include_str!`. Any deviation between
//! the Rust parse and the CSV file is a test failure.

// The CSV is embedded at compile time so the mapping is always in sync with
// the contract file — no runtime I/O needed. `build.rs` resolves the
// absolute path (Nix env var, with repo-relative fallback for cargo build)
// and exposes it as THEYOS_EMOJI_WORDLIST_PATH.
const WORDLIST_CSV: &str = include_str!(env!("THEYOS_EMOJI_WORDLIST_PATH"));

/// Parse the embedded CSV into a 2048-entry array of (emoji, `codepoint_str`).
///
/// Called once at startup (via `std::sync::OnceLock`) — not on every derivation.
fn build_emoji_table() -> Vec<(String, String)> {
    let mut table = Vec::with_capacity(2048);
    for line in WORDLIST_CSV.lines() {
        // Skip header and comment lines.
        if line.starts_with('#') || line.starts_with("word_index") || line.trim().is_empty() {
            continue;
        }
        // Format: word_index,emoji,unicode_codepoint
        let mut parts = line.splitn(3, ',');
        let _idx = parts.next().unwrap_or("").trim();
        let emoji = parts.next().unwrap_or("").to_string();
        let codepoint = parts.next().unwrap_or("").to_string();
        table.push((emoji, codepoint));
    }
    assert_eq!(
        table.len(),
        2048,
        "emoji wordlist CSV must have exactly 2048 data rows (found {})",
        table.len()
    );
    table
}

static EMOJI_TABLE: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();

fn emoji_table() -> &'static Vec<(String, String)> {
    EMOJI_TABLE.get_or_init(build_emoji_table)
}

/// Extract six 11-bit indices from the first 9 bytes of a 32-byte digest.
///
/// Identical to `fingerprint::extract_indices` — shares the bit-extraction
/// logic so both fingerprint (BIP-39 words) and emoji code (emoji) use the
/// same derivation step.
#[must_use]
fn extract_11bit_indices(digest: &[u8; 32]) -> [u16; 6] {
    let b = |i: usize| u16::from(digest[i]);
    let i0 = (b(0) << 3) | (b(1) >> 5);
    let i1 = ((b(1) & 0x1f) << 6) | (b(2) >> 2);
    let i2 = ((b(2) & 0x03) << 9) | (b(3) << 1) | (b(4) >> 7);
    let i3 = ((b(4) & 0x7f) << 4) | (b(5) >> 4);
    let i4 = ((b(5) & 0x0f) << 7) | (b(6) >> 1);
    let i5 = ((b(6) & 0x01) << 10) | (b(7) << 2) | (b(8) >> 6);
    [i0, i1, i2, i3, i4, i5]
}

/// Derive the 6-emoji security code for a `(m_pub, nonce, hostname)` triple.
///
/// **Cross-language contract**: the Swift implementation in `SoyehtCore` MUST
/// produce the same 6 emojis for the same input. Test vectors in
/// `specs/005-soyeht-onboarding/contracts/emoji-security-code-fixtures.csv`
/// are the canonical cross-language check.
///
/// # Parameters
/// - `m_pub_sec1` — 33-byte SEC1-compressed P-256 public key of the machine.
/// - `nonce` — 32-byte random nonce (from the pair-machine session).
/// - `hostname` — UTF-8 hostname of the candidate machine (e.g. `"macStudio"`).
///
/// # Returns
/// Six strings, each containing one emoji character.
#[must_use]
pub fn derive_emoji_code(m_pub_sec1: &[u8; 33], nonce: &[u8; 32], hostname: &str) -> [String; 6] {
    let digest: [u8; 32] = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(m_pub_sec1);
        hasher.update(nonce);
        hasher.update(hostname.as_bytes());
        *hasher.finalize().as_bytes()
    };

    let indices = extract_11bit_indices(&digest);
    let table = emoji_table();
    std::array::from_fn(|i| table[indices[i] as usize].0.clone())
}

/// Return the `(emoji, codepoint_str)` pair for a given 11-bit index.
///
/// Used by tests and the fixture generator to verify the table.
#[must_use]
pub fn emoji_for_index(idx: u16) -> &'static (String, String) {
    &emoji_table()[idx as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_2048_entries() {
        assert_eq!(emoji_table().len(), 2048);
    }

    #[test]
    fn derive_returns_six_nonempty_strings() {
        let m_pub = [0x02u8; 33];
        let nonce = [0u8; 32];
        let result = derive_emoji_code(&m_pub, &nonce, "test");
        assert_eq!(result.len(), 6);
        for s in &result {
            assert!(!s.is_empty(), "emoji string must not be empty");
        }
    }

    #[test]
    fn derive_is_deterministic() {
        let m_pub = [0x02u8; 33];
        let nonce = [0xaau8; 32];
        let a = derive_emoji_code(&m_pub, &nonce, "studio");
        let b = derive_emoji_code(&m_pub, &nonce, "studio");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_codes() {
        let m_pub_a = [0x02u8; 33];
        let mut m_pub_b = m_pub_a;
        m_pub_b[1] ^= 0x01;
        let nonce = [0u8; 32];
        let a = derive_emoji_code(&m_pub_a, &nonce, "host");
        let b = derive_emoji_code(&m_pub_b, &nonce, "host");
        assert_ne!(a, b, "one-bit difference in m_pub should perturb the code");
    }

    #[test]
    fn each_index_maps_to_valid_table_entry() {
        let table = emoji_table();
        for (idx, (emoji, codepoint)) in table.iter().enumerate() {
            assert!(!emoji.is_empty(), "index {idx}: emoji must not be empty");
            assert!(
                codepoint.starts_with("U+"),
                "index {idx}: codepoint must start with U+"
            );
        }
    }

    #[test]
    fn indices_within_range() {
        // Feed many distinct digests through extract_11bit_indices and verify all
        // indices are in [0, 2047].
        for seed in 0u8..=255 {
            let digest: [u8; 32] = {
                let mut d = [0u8; 32];
                for (i, b) in d.iter_mut().enumerate() {
                    // i ∈ [0, 32) so the truncation cast is safe by construction.
                    #[allow(clippy::cast_possible_truncation)]
                    let i_u8 = i as u8;
                    *b = seed.wrapping_add(i_u8);
                }
                d
            };
            for idx in extract_11bit_indices(&digest) {
                assert!(idx < 2048, "index {idx} out of range for seed {seed}");
            }
        }
    }
}
