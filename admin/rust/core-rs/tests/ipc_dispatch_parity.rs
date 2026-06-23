//! Block B parity guard (C): the typed op enums in `core_rs::ipc::protocol`
//! must stay in lockstep with the REAL dispatch tables that consume their
//! `as_str()` values. B1 built these enums by hand-mirroring the dispatch; with
//! no guard the mirror can silently drift — a new dispatch arm with no enum
//! variant (so producers can't reference it typed), or a stale variant with no
//! arm (so a typed producer hits the `unknown method` error path; that is
//! exactly the `InstanceDbGetHostPort` bug this package fixes).
//!
//! Pure source-text scan of the canonical dispatch files (no VM, no IPC).
//! Complements protocol.rs round-trip tests (variant <-> wire string) and
//! `cross_runner_parity` (linux <-> macOS shared vocabulary); here we pin
//! `core_rs::*Op::ALL` == the dispatch arms themselves.

use core_rs::ipc::protocol::{StoreOp, VmRunnerOp};
use std::collections::BTreeSet;

const STORE_DISPATCH: &str = include_str!("../../store-rs/src/bin/store_ipc.rs");
const VMRUNNER_LINUX_DISPATCH: &str = include_str!("../../vmrunner-rs/src/bin/vmrunner_ipc.rs");
const VMRUNNER_MACOS_DISPATCH: &str =
    include_str!("../../vmrunner-macos-rs/src/bin/vmrunner_macos_ipc_macos.rs");

/// macOS-only ops served by the macOS runner that are intentionally OUTSIDE the
/// shared `VmRunnerOp` vocabulary (a guest-image op and the slot-status probe).
/// `MacOsSlotStatus` is the one the executor calls directly and the B3 source
/// guard allowlists.
const MACOS_ONLY_SAMPLE: &[&str] = &["MacOsSlotStatus", "Status"];

/// Extract method names from `"<M>" => ...` arms, including or-patterns
/// (`"A" | "B" => ...`, as the macOS runner uses for `Restart`/`Rebuild`).
/// Only quoted tokens LEFT of `=>` are arm methods, so the
/// `_ => Response::err("unknown method: ...")` fallback (quote on the right) is
/// ignored.
fn dispatch_methods(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let Some((lhs, _)) = line.split_once("=>") else {
            continue;
        };
        let mut rest = lhs;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            let name = &after[..close];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric()) {
                out.insert(name.to_string());
            }
            rest = &after[close + 1..];
        }
    }
    out
}

fn enum_methods<'a>(it: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    it.into_iter().map(str::to_string).collect()
}

#[test]
fn store_op_enum_matches_store_ipc_dispatch_exactly() {
    let dispatch = dispatch_methods(STORE_DISPATCH);
    let enums = enum_methods(StoreOp::ALL.iter().map(StoreOp::as_str));
    assert_eq!(
        enums,
        dispatch,
        "StoreOp::ALL must equal store_ipc.rs dispatch arms.\n  only in enum: {:?}\n  only in dispatch: {:?}",
        enums.difference(&dispatch).collect::<Vec<_>>(),
        dispatch.difference(&enums).collect::<Vec<_>>(),
    );
}

#[test]
fn vmrunner_op_enum_matches_linux_dispatch_exactly() {
    let dispatch = dispatch_methods(VMRUNNER_LINUX_DISPATCH);
    let enums = enum_methods(VmRunnerOp::ALL.iter().map(VmRunnerOp::as_str));
    assert_eq!(
        enums,
        dispatch,
        "VmRunnerOp::ALL must equal vmrunner_ipc.rs (Linux) dispatch arms.\n  only in enum: {:?}\n  only in dispatch: {:?}",
        enums.difference(&dispatch).collect::<Vec<_>>(),
        dispatch.difference(&enums).collect::<Vec<_>>(),
    );
}

#[test]
fn shared_vmrunner_ops_served_by_macos_and_macos_only_ops_stay_out_of_enum() {
    let macos = dispatch_methods(VMRUNNER_MACOS_DISPATCH);
    let shared = enum_methods(VmRunnerOp::ALL.iter().map(VmRunnerOp::as_str));
    // Every shared op is served by the macOS runner too (or-patterns handled).
    let missing: Vec<_> = shared.difference(&macos).collect();
    assert!(
        missing.is_empty(),
        "macOS runner is missing shared VmRunnerOp methods: {missing:?}"
    );
    // The macOS-only ops exist in the macOS dispatch but are NOT shared enum
    // variants — that is why the B3 source guard allowlists `MacOsSlotStatus`.
    for op in MACOS_ONLY_SAMPLE {
        assert!(macos.contains(*op), "expected macOS dispatch to serve {op}");
        assert!(
            !shared.contains(*op),
            "{op} must NOT be a shared VmRunnerOp variant"
        );
    }
}
