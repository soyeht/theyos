//! Guard against re-introducing legacy / hand-authored entries in the
//! versioned `claws/verify-results.json` file.
//!
//! Background: commit 84f307e shipped a `nemoclaw` entry written in a
//! pre-canonical schema (`status` / `reason` / `verified_at` /
//! `verified_by`), missing the mandatory `verify_status` field. The
//! daemon's `verify_results::load` failed the whole-file parse and
//! silently dropped every overlay, surfacing as the repeated runtime
//! warning `verify-results.json load failed: JSON error: missing field
//! verify_status`.
//!
//! The runtime reader is now resilient (skips malformed entries with a
//! warn log) but that is meant for *operator* situations — not as cover
//! for commits that bypass the canonical writer. This test ensures the
//! file checked into the repo is byte-for-byte parseable into the
//! canonical `VerifyResult` shape, so any future drift is caught at CI
//! time, not in production logs.

use std::collections::HashMap;
use std::path::PathBuf;

use claw_rs::verify_results::VerifyResult;

#[test]
fn repo_verify_results_json_has_zero_malformed_entries() {
    // CARGO_MANIFEST_DIR points at admin/rust/claw-rs.
    // Walk up three levels to the repo root, then to claws/.
    let repo_file: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "..",
        "claws",
        "verify-results.json",
    ]
    .iter()
    .collect();

    assert!(
        repo_file.is_file(),
        "expected to find versioned verify-results.json at {}",
        repo_file.display()
    );

    let content = std::fs::read_to_string(&repo_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", repo_file.display()));

    // First parse as a generic map to enumerate keys even when one entry
    // does not match the canonical shape — the failure message must point
    // at the specific offending entry.
    let raw: HashMap<String, serde_json::Value> =
        serde_json::from_str(&content).unwrap_or_else(|e| {
            panic!(
                "top-level JSON in {} is not a valid object: {e}",
                repo_file.display()
            )
        });

    let mut bad: Vec<(String, String)> = Vec::new();
    for (claw, value) in &raw {
        if let Err(e) = serde_json::from_value::<VerifyResult>(value.clone()) {
            bad.push((claw.clone(), e.to_string()));
        }
    }

    assert!(
        bad.is_empty(),
        "claws/verify-results.json contains entries that do not match the \
         canonical VerifyResult schema. Re-run `soyeht claws-verify <name>` \
         to repair, or remove the entry if the claw is `tier: catalog`. \
         Offenders:\n{}",
        bad.iter()
            .map(|(k, e)| format!("  - {k}: {e}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
