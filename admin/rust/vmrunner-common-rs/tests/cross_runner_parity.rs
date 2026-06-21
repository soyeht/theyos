//! Cross-runner method-parity contract.
//!
//! The host-agnostic delete / create / restart orchestration in `executor-rs`
//! issues the SAME JSON-RPC method vocabulary to whichever VM runner the host
//! provides (`vmrunner-rs` on Linux/Firecracker, `vmrunner-macos-rs` on macOS/VZ).
//!
//! If a host-specific runner is missing one of these shared methods, the executor
//! drops into its error branch. For `CleanupFs` that is not benign: the executor
//! gates the per-instance *storage lease* release on a successful `CleanupFs`, so
//! a missing arm means the disk lease is reported allocated forever — a silent
//! storage-lease leak on every delete on that host.
//!
//! This test pins the shared vocabulary into BOTH dispatch tables so that class of
//! drift fails CI on either platform. It scans source text (no VM/entitlements
//! required), so it runs anywhere `vmrunner-common-rs` builds.

use std::collections::BTreeSet;

const LINUX_DISPATCH: &str = include_str!("../../vmrunner-rs/src/bin/vmrunner_ipc.rs");
const MACOS_DISPATCH: &str =
    include_str!("../../vmrunner-macos-rs/src/bin/vmrunner_macos_ipc_macos.rs");

/// Methods the host-agnostic executor / orchestrator may invoke on ANY runner.
///
/// Source of truth: the lifecycle flow call sites in `executor-rs/src/flows/*`
/// (stop / delete / restart / rebuild / create / warm-pool) plus the delete
/// orchestrator (`orchestrator/delete.rs`). Host-specific guest-image methods
/// (`MacOs*`, `Linux*Base*`) and the unshared `Status` probe are intentionally
/// excluded — they are not part of the host-agnostic lifecycle contract.
const SHARED_LIFECYCLE_METHODS: &[&str] = &[
    "Create",
    "Stop",
    "Delete",
    "Restart",
    "Rebuild",
    "CleanupSystemd",
    "CleanupFs",
    "FetchLogs",
    "TakeBaseSnapshot",
    "WarmPoolInit",
    "WarmPoolRefill",
    "WarmPoolStatus",
    "WarmPoolDrain",
];

/// Slice the `match method { ... }` dispatch block so we only read real arms,
/// not method names that happen to appear elsewhere in the file.
fn dispatch_block(src: &str) -> &str {
    let start = src
        .find("match method {")
        .expect("runner source must contain a `match method {` dispatch block");
    let after = &src[start..];
    let end = after
        .find("unknown method")
        .expect("dispatch block must end with an `unknown method` fallback arm");
    &after[..end]
}

/// Collect the quoted method names from dispatch arms (`"X" =>`, `"X" | "Y" =>`).
fn dispatch_arm_methods(src: &str) -> BTreeSet<String> {
    let block = dispatch_block(src);
    let mut out = BTreeSet::new();
    for line in block.lines() {
        if !line.contains("=>") {
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            let token = &after[..close];
            if !token.is_empty() && token.chars().all(|c| c.is_ascii_alphabetic()) {
                out.insert(token.to_string());
            }
            rest = &after[close + 1..];
        }
    }
    out
}

#[test]
fn shared_lifecycle_methods_handled_by_both_runners() {
    let linux = dispatch_arm_methods(LINUX_DISPATCH);
    let macos = dispatch_arm_methods(MACOS_DISPATCH);

    let mut missing = Vec::new();
    for method in SHARED_LIFECYCLE_METHODS {
        if !linux.contains(*method) {
            missing.push(format!("vmrunner-rs (Linux) dispatch is missing `{method}`"));
        }
        if !macos.contains(*method) {
            missing.push(format!(
                "vmrunner-macos-rs (macOS) dispatch is missing `{method}`"
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "cross-runner method parity broken — the shared executor calls these on \
         every host, so both runners must handle them:\n{}",
        missing.join("\n")
    );
}

/// The shared list must not silently rot: every method in it must actually be a
/// real arm in at least one runner (catches typos / renamed methods in the list).
#[test]
fn shared_method_list_has_no_phantom_entries() {
    let linux = dispatch_arm_methods(LINUX_DISPATCH);
    let macos = dispatch_arm_methods(MACOS_DISPATCH);

    let phantom: Vec<&str> = SHARED_LIFECYCLE_METHODS
        .iter()
        .copied()
        .filter(|m| !linux.contains(*m) && !macos.contains(*m))
        .collect();

    assert!(
        phantom.is_empty(),
        "SHARED_LIFECYCLE_METHODS names methods no runner handles (typo or removed): {phantom:?}"
    );
}
