//! Phase 3 anti-phishing fingerprint
//! (FR-007 / `specs/003-machine-join/contracts/fingerprint-derivation.md`).
//!
//! The fingerprint is six BIP-39 English words derived from the first 66
//! bits of `BLAKE3-256(m_pub_sec1)`. Both the candidate's installer
//! console and the owner iPhone render it; the operator confirms a
//! byte-equal match before approving the join.
//!
//! The same 66-bit → six-word mapping also produces the pair-device code
//! ([`pair_device_fingerprint_words`]): six words over
//! `BLAKE3-256(hh_pub_sec1 ‖ nonce)`, byte-equal to the Swift
//! `OperatorFingerprint.derive(machinePublicKey:pairingNonce:wordlist:)`.

use crate::bip39_wordlist::WORDLIST;

/// Derive the six-word anti-phishing fingerprint of a SEC1-compressed
/// P-256 public key. Determinism is guaranteed by the contract — every
/// implementation (theyos Rust + iSoyehtTerm Swift) MUST produce
/// byte-equivalent output.
#[must_use]
pub fn fingerprint(m_pub_sec1: &[u8; 33]) -> String {
    let digest = blake3::hash(m_pub_sec1);
    let bytes = digest.as_bytes();
    let words = indices_to_words(extract_indices(bytes));
    words.join(" ")
}

/// The six 11-bit BIP-39 indices of the pair-device code for a
/// `(hh_pub, nonce)` pair: the first 66 bits of
/// `BLAKE3-256(hh_pub_sec1 ‖ nonce)`, MSB-first.
///
/// **Cross-language contract**: the input is the plain concatenation of
/// the two fields — no length prefixes, no separator and (unlike
/// `emoji_code`) no hostname — exactly what the Swift
/// `OperatorFingerprint.derive(machinePublicKey:pairingNonce:wordlist:)`
/// in `SoyehtCore` hashes. `tests/data/pair_device_fingerprint_vectors.json`
/// locks both sides.
#[must_use]
pub fn pair_device_fingerprint_indices(hh_pub_sec1: &[u8; 33], nonce: &[u8; 32]) -> [u16; 6] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(hh_pub_sec1);
    hasher.update(nonce);
    let digest = hasher.finalize();
    extract_indices(digest.as_bytes())
}

/// The pair-device code as six BIP-39 English words — the words the Mac
/// shows next to its pairing QR and the iPhone types back. See
/// [`pair_device_fingerprint_indices`] for the derivation.
#[must_use]
pub fn pair_device_fingerprint_words(
    hh_pub_sec1: &[u8; 33],
    nonce: &[u8; 32],
) -> [&'static str; 6] {
    indices_to_words(pair_device_fingerprint_indices(hh_pub_sec1, nonce))
}

/// Resolve a BIP-39 English word to its 11-bit index, or `None` when the
/// word is not in the list. Exact match only — no case folding, trimming
/// or prefix matching; callers normalise before looking up.
///
/// Binary search is sound because `WORDLIST` is strictly ASCII-sorted,
/// which `bip39_wordlist::tests::wordlist_is_strictly_sorted_ascii` and
/// `word_index_round_trips_every_wordlist_entry` below both lock.
#[must_use]
pub fn word_index(word: &str) -> Option<u16> {
    WORDLIST
        .binary_search(&word)
        .ok()
        .and_then(|i| u16::try_from(i).ok())
}

/// Extract the six 11-bit indices from the first 9 bytes of a 32-byte
/// digest. Each index lies in `[0, 2047]` (i.e., 11 bits). Bits 66..71
/// of the digest are discarded.
#[must_use]
pub(crate) fn extract_indices(digest: &[u8]) -> [u16; 6] {
    debug_assert!(digest.len() >= 9);
    let b0 = u16::from(digest[0]);
    let b1 = u16::from(digest[1]);
    let b2 = u16::from(digest[2]);
    let b3 = u16::from(digest[3]);
    let b4 = u16::from(digest[4]);
    let b5 = u16::from(digest[5]);
    let b6 = u16::from(digest[6]);
    let b7 = u16::from(digest[7]);
    let b8 = u16::from(digest[8]);

    let i0 = (b0 << 3) | (b1 >> 5);
    let i1 = ((b1 & 0x1f) << 6) | (b2 >> 2);
    let i2 = ((b2 & 0x03) << 9) | (b3 << 1) | (b4 >> 7);
    let i3 = ((b4 & 0x7f) << 4) | (b5 >> 4);
    let i4 = ((b5 & 0x0f) << 7) | (b6 >> 1);
    let i5 = ((b6 & 0x01) << 10) | (b7 << 2) | (b8 >> 6);

    [i0, i1, i2, i3, i4, i5]
}

#[must_use]
fn indices_to_words(indices: [u16; 6]) -> [&'static str; 6] {
    let mut out: [&'static str; 6] = [""; 6];
    for (slot, idx) in out.iter_mut().zip(indices.iter()) {
        // Each index is mathematically bounded to [0, 2047] by the 11-bit
        // mask above, so this index is always in range.
        *slot = WORDLIST[*idx as usize];
    }
    out
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::{
        WORDLIST, extract_indices, fingerprint, pair_device_fingerprint_indices,
        pair_device_fingerprint_words, word_index,
    };

    #[test]
    fn fingerprint_is_six_lowercase_ascii_words() {
        let m_pub: [u8; 33] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            for (i, b) in buf.iter_mut().enumerate().skip(1) {
                *b = i as u8;
            }
            buf
        };
        let fp = fingerprint(&m_pub);
        let words: Vec<&str> = fp.split(' ').collect();
        assert_eq!(words.len(), 6);
        for w in &words {
            assert!(!w.is_empty());
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn fingerprint_is_deterministic_for_fixed_input() {
        let m_pub: [u8; 33] = [0x02; 33];
        let a = fingerprint(&m_pub);
        let b = fingerprint(&m_pub);
        assert_eq!(a, b);
    }

    #[test]
    fn one_bit_input_change_perturbs_at_least_one_word() {
        let mut m_pub: [u8; 33] = [0x02; 33];
        let a = fingerprint(&m_pub);
        m_pub[1] ^= 0x01;
        let b = fingerprint(&m_pub);
        assert_ne!(a, b);
    }

    #[test]
    fn extract_indices_first_byte_zero_yields_low_indices() {
        let digest = [0u8; 32];
        let idx = extract_indices(&digest);
        assert_eq!(idx, [0; 6]);
    }

    #[test]
    fn extract_indices_high_byte_yields_top_index() {
        // First 11 bits all set → i0 = 0x7ff (2047).
        let mut digest = [0u8; 32];
        digest[0] = 0xff;
        digest[1] = 0xe0;
        let idx = extract_indices(&digest);
        assert_eq!(idx[0], 2047);
    }

    #[test]
    fn extract_indices_matches_swift_known_pattern() {
        // Same bytes and expectation as the Swift
        // `OperatorFingerprintTests.extractIndicesFromKnownPatternMatchesBigEndianBitOrder`:
        // bits FF E0 00 3F F0 → 11-bit windows 2047, 0, 127, 1792, 0, 0.
        let mut digest = [0u8; 32];
        digest[0] = 0xff;
        digest[1] = 0xe0;
        digest[2] = 0x00;
        digest[3] = 0x3f;
        digest[4] = 0xf0;
        assert_eq!(extract_indices(&digest), [2047, 0, 127, 1792, 0, 0]);
        // And the all-ones digest the same Swift suite pins to six 2047s.
        assert_eq!(extract_indices(&[0xff; 32]), [2047; 6]);
    }

    #[test]
    fn extract_indices_are_all_in_range() {
        for k in 0..256u16 {
            let mut digest = [0u8; 32];
            for (i, b) in digest.iter_mut().enumerate() {
                *b = (k.wrapping_mul(31).wrapping_add(i as u16)) as u8;
            }
            let idx = extract_indices(&digest);
            for x in idx {
                assert!(x < 2048, "index {x} out of range");
            }
        }
    }

    #[test]
    fn word_index_round_trips_every_wordlist_entry() {
        // The binary search in `word_index` is only correct over a sorted
        // list; prove the precondition here rather than trust the header
        // comment on the wordlist.
        for pair in WORDLIST.windows(2) {
            assert!(
                pair[0] < pair[1],
                "WORDLIST must be strictly ASCII-sorted for binary search ({:?} >= {:?})",
                pair[0],
                pair[1]
            );
        }
        for (i, word) in WORDLIST.iter().enumerate() {
            assert_eq!(word_index(word), Some(i as u16), "lookup of {word:?}");
        }
    }

    #[test]
    fn word_index_is_exact_match_only() {
        assert_eq!(word_index("abandon"), Some(0));
        assert_eq!(word_index("zoo"), Some(2047));
        assert_eq!(word_index(""), None);
        assert_eq!(word_index("Abandon"), None);
        assert_eq!(word_index(" zoo"), None);
        assert_eq!(word_index("zoo "), None);
        assert_eq!(word_index("zoos"), None);
        assert_eq!(word_index("aband"), None);
    }

    #[test]
    fn pair_device_words_are_the_wordlist_entries_at_the_indices() {
        let hh_pub: [u8; 33] = [0x02; 33];
        let nonce: [u8; 32] = [0x33; 32];
        let indices = pair_device_fingerprint_indices(&hh_pub, &nonce);
        let words = pair_device_fingerprint_words(&hh_pub, &nonce);
        for (idx, word) in indices.iter().zip(words.iter()) {
            assert!(*idx < 2048, "index {idx} out of range");
            assert_eq!(WORDLIST[*idx as usize], *word);
            assert_eq!(word_index(word), Some(*idx));
        }
        assert_eq!(pair_device_fingerprint_words(&hh_pub, &nonce), words);
    }

    #[test]
    fn pair_device_digest_is_the_plain_concatenation() {
        // The streaming hasher must equal a single hash over hh_pub ‖ nonce,
        // which is what the Swift side computes (`input.append(nonce)`).
        let hh_pub: [u8; 33] = [0x03; 33];
        let nonce: [u8; 32] = [0x5a; 32];
        let mut concat = Vec::with_capacity(65);
        concat.extend_from_slice(&hh_pub);
        concat.extend_from_slice(&nonce);
        let expected = extract_indices(blake3::hash(&concat).as_bytes());
        assert_eq!(pair_device_fingerprint_indices(&hh_pub, &nonce), expected);
    }

    #[test]
    fn pair_device_words_change_with_the_nonce() {
        let hh_pub: [u8; 33] = [0x02; 33];
        let a = pair_device_fingerprint_words(&hh_pub, &[0x01; 32]);
        let b = pair_device_fingerprint_words(&hh_pub, &[0x02; 32]);
        assert_ne!(a, b);
    }
}
