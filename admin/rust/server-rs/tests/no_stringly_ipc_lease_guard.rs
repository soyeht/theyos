//! Block B source guard (B3): prevent reintroduction of stringly-typed IPC
//! method names and lease owner/kind literals on the producer paths already
//! migrated to the typed identifiers in `core_rs::ipc::protocol` (B1 + B2a/B2b).
//!
//! It scans the PRODUCTION source (everything before the first test module) of
//! the IPC/lease *producer* crates — `executor-rs` and `server-rs` — by walking
//! the filesystem at runtime, so a NEW producer file is covered automatically.
//! (PR #131 missed two files precisely because its inventory used a hardcoded
//! file list; this guard deliberately does not.) It is a pure source-text scan:
//! no VM, no IPC, no entitlements — runs anywhere `server-rs` tests build.
//!
//! Receiver scope is intentional: only `.vmrunner.call` / `.store.call` are
//! checked (the migrated producers). The receive-side dispatch tables in
//! `vmrunner-rs` / `store-rs` (`"Create" => ...`) and `.terminal.call(...)`
//! (a separate op namespace) are out of scope and not scanned.
//!
//! Allowlist — the ONLY literals permitted on the producer paths:
//! - `MacOsSlotStatus`: a macOS-runner method outside the shared `VmRunnerOp`
//!   vocabulary (B1 covers only the cross-runner lifecycle methods).
//! - `ApplyAction`, `InstanceDbGetHostPort`: PRE-EXISTING dead store calls —
//!   no matching arm in the store IPC dispatch, error swallowed by the caller.
//!   Left as literals pending a dedicated bugfix and allowlisted here so they
//!   are NOT mistaken for real `StoreOp` variants.
//!
//! Test modules (`#[cfg(test)]`) are NOT scanned on purpose: those tests assert
//! the on-the-wire string values, proving the typed producers still emit the
//! same bytes — they should keep doing exactly that.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const LEASE_LITERALS: &[&str] = &["instance", "warm_pool", "runtime", "storage"];
const LEASE_KEYWORDS: &[&str] = &[
    "release_lease",
    "has_active_lease",
    "release_all_leases",
    "owner_type",
    "lease_kind",
];

/// `.call("X")` method literals permitted on producer paths (see module docs).
const CALL_LITERAL_ALLOWLIST: &[&str] =
    &["MacOsSlotStatus", "ApplyAction", "InstanceDbGetHostPort"];

/// `.../admin/rust` — the workspace root that holds the producer crates.
fn rust_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../admin/rust/server-rs
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs has a parent dir")
        .to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Production slice = everything before the first test-module marker. Test
/// modules in this codebase live at the bottom of the file.
fn prod_region(src: &str) -> &str {
    let cut = [src.find("#[cfg(test)]"), src.find("\nmod tests")]
        .into_iter()
        .flatten()
        .min();
    match cut {
        Some(i) => &src[..i],
        None => src,
    }
}

/// Find `<recv>.call(` / `.call_with_context(` sites whose FIRST argument is a
/// string literal, returning (line, method). Handles both `call("X"` (inline)
/// and `call(\n    "X",` (multi-line) forms.
fn call_literal_methods(prod: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for recv in [".vmrunner.call", ".store.call"] {
        let mut from = 0usize;
        while let Some(idx) = prod[from..].find(recv) {
            let at = from + idx;
            from = at + recv.len();
            let rest = &prod[at + recv.len()..];
            let rest = rest.strip_prefix("_with_context").unwrap_or(rest);
            let Some(paren) = rest.find('(') else {
                continue;
            };
            let after = rest[paren + 1..].trim_start(); // skips spaces + newlines
            if let Some(q) = after.strip_prefix('"') {
                if let Some(end) = q.find('"') {
                    let line = prod[..at].matches('\n').count() + 1;
                    out.push((line, q[..end].to_string()));
                }
            }
        }
    }
    out
}

/// Lines carrying a bare lease owner/kind literal in a lease context (a lease
/// keyword within the preceding few lines, to catch multi-line calls).
fn lease_literal_lines(prod: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = prod.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !LEASE_LITERALS
            .iter()
            .any(|k| line.contains(&format!("\"{k}\"")))
        {
            continue;
        }
        let lo = i.saturating_sub(4);
        let window = lines[lo..=i].join("\n");
        if LEASE_KEYWORDS.iter().any(|k| window.contains(k)) {
            out.push((i + 1, line.trim().to_string()));
        }
    }
    out
}

#[test]
fn no_reintroduced_stringly_ipc_or_lease_literals() {
    let root = rust_root();
    let mut files = Vec::new();
    for crate_src in ["executor-rs/src", "server-rs/src"] {
        collect_rs(&root.join(crate_src), &mut files);
    }
    assert!(
        files.len() > 20,
        "guard scanned only {} files — CARGO_MANIFEST_DIR layout changed?",
        files.len()
    );

    let allow: BTreeSet<&str> = CALL_LITERAL_ALLOWLIST.iter().copied().collect();
    let mut violations = Vec::new();

    for f in &files {
        let src = fs::read_to_string(f).expect("read source file");
        let prod = prod_region(&src);
        let rel = f.strip_prefix(&root).unwrap_or(f).display();

        for (line, method) in call_literal_methods(prod) {
            if !allow.contains(method.as_str()) {
                violations.push(format!(
                    "{rel}:{line}: stringly IPC method `.call(\"{method}\")` \
                     — use VmRunnerOp/StoreOp::*.as_str()"
                ));
            }
        }
        for (line, text) in lease_literal_lines(prod) {
            violations.push(format!(
                "{rel}:{line}: stringly lease owner/kind literal `{text}` \
                 — use LeaseOwnerType/LeaseKind::*.as_str()"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Block B source guard found reintroduced stringly literals on migrated \
         producer paths. Migrate to the typed identifiers in \
         core_rs::ipc::protocol, or (only for tests/dead-calls) extend the \
         allowlist in this file with a justification:\n  {}",
        violations.join("\n  ")
    );
}

// ── self-tests: prove the detection logic catches violations and ignores the
//    typed forms (so a green main guard means "clean", not "blind"). ──────────

#[test]
fn detection_flags_stringly_call_and_lease_literals() {
    let sample = "\
        exec.vmrunner.call(\"Create\", j);\n\
        exec.store.call(\n    \"ResourceLeaseRelease\",\n    j,\n);\n\
        let l = NewLease { owner_type: \"instance\", lease_kind: \"runtime\" };\n";
    let calls = call_literal_methods(sample);
    assert!(
        calls.iter().any(|(_, m)| m == "Create"),
        "must flag inline call literal"
    );
    assert!(
        calls.iter().any(|(_, m)| m == "ResourceLeaseRelease"),
        "must flag multi-line call literal"
    );
    assert!(
        !lease_literal_lines(sample).is_empty(),
        "must flag lease owner/kind literal"
    );
}

#[test]
fn detection_ignores_typed_calls_and_typed_leases() {
    let sample = "\
        exec.vmrunner.call(VmRunnerOp::Create.as_str(), j);\n\
        db.release_lease(LeaseOwnerType::Instance.as_str(), id, LeaseKind::Runtime.as_str());\n";
    assert!(
        call_literal_methods(sample).is_empty(),
        "typed call must not be flagged"
    );
    assert!(
        lease_literal_lines(sample).is_empty(),
        "typed lease must not be flagged"
    );
}
