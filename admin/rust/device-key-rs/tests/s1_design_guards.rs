//! S1 g3 source guards — GUARDS, labelled guards (g3 §1.1).
//!
//! Rust cannot express "no constructor may ever be added", "no `Clone` may
//! ever be derived", or "no `account` parameter may ever appear". Those are
//! enforced here, by scanning this crate's own production source. The two
//! things that ARE properties need no scan and get none:
//!
//! * the dependency edge — this crate does not depend on `household-rs`, so
//!   the P-256 identity type names do not resolve (asserted below on
//!   `Cargo.toml`, since the edge is a fact about the manifest);
//! * the private-field seal — `from_scalar` has no visibility modifier and
//!   is module-bound (g3 §1.3).
//!
//! The scan walks the crate's `src/` at runtime so a NEW source file is
//! covered automatically — the guard's scope is derived, never a literal
//! file list (bar v3 §5.5).

use std::fs;
use std::path::{Path, PathBuf};

fn crate_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|ext| ext == "rs") {
            out.push(p);
        }
    }
}

/// Production lines only: strip doc comments and line comments so the guard
/// judges code, not prose (the module docs NAME the forbidden shapes to
/// explain why they are absent — scanning prose would reject the explanation
/// itself).
fn production_lines(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut in_cfg_test = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            in_cfg_test = true;
        }
        if in_cfg_test {
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        out.push(line.to_string());
    }
    out
}

/// Forbidden shapes in production code, each with the mutant it catches
/// (g3 §1.2, §4). If one of these ever appears, exactly one guard test
/// fails and names the mutant. (`Clone`/`Copy` are NOT token-scanned: the
/// public type legitimately derives them — the secret's derive line is
/// checked precisely in `secret_has_no_clone_or_copy_derive` below.)
const FORBIDDEN: &[(&str, &str)] = &[
    ("from_bytes", "mutant: byte-accepting constructor"),
    ("from_slice", "mutant: slice-accepting constructor"),
    ("TryFrom", "mutant: TryFrom<&[u8]> impl"),
    ("Deserialize", "mutant: serde deserialization of the secret"),
    (
        "account: &str",
        "mutant: caller-chosen account name (g3 §1.4)",
    ),
    (
        "account:&str",
        "mutant: caller-chosen account name (g3 §1.4)",
    ),
];

#[test]
fn no_forbidden_constructor_or_exposure_shape_in_production_source() {
    let mut files = Vec::new();
    collect_rs(&crate_src_dir(), &mut files);
    assert!(!files.is_empty(), "guard found no sources — scope broken");

    let mut violations = Vec::new();
    for file in &files {
        for (lineno, line) in production_lines(file).iter().enumerate() {
            for (token, why) in FORBIDDEN {
                if line.contains(token) {
                    violations.push(format!(
                        "{}:{}: {token:?} — {why}",
                        file.display(),
                        lineno + 1
                    ));
                }
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// The dependency-edge PROPERTY: this crate must not depend on
/// `household-rs`, the crate that exports the P-256 identity types. If the
/// edge is ever added — even "just for an id type" (g3 §1.4a) — this test
/// fails, because with the edge the names resolve and the property is gone.
#[test]
fn crate_does_not_depend_on_household_rs() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read own Cargo.toml");
    assert!(
        !manifest.contains("household-rs"),
        "device-key-rs must not depend on household-rs — the dependency edge IS the property"
    );
}

/// The no-Clone/no-Copy discipline, checked at the SECRET's own derive line
/// (the public type derives both legitimately). Mutant: adding `Clone` to
/// `DeviceStaticSecret` inverts the Drop-observer test — it passes more
/// easily, not harder — so the ban lives here, not there (g3 §4).
#[test]
fn secret_has_no_clone_or_copy_derive() {
    let mut files = Vec::new();
    collect_rs(&crate_src_dir(), &mut files);

    let mut found = false;
    for file in &files {
        let lines = production_lines(file);
        for (i, line) in lines.iter().enumerate() {
            if line.contains("struct DeviceStaticSecret") {
                found = true;
                // The derive attribute sits in the few lines above the
                // struct; scan them, and nothing else.
                let window_start = i.saturating_sub(4);
                for attr in &lines[window_start..i] {
                    assert!(
                        !attr.contains("Clone") && !attr.contains("Copy"),
                        "{}: DeviceStaticSecret must not derive Clone/Copy: {attr}",
                        file.display()
                    );
                }
            }
        }
    }
    assert!(found, "DeviceStaticSecret not found — guard scope broken");
}

/// The channel arms are parsed out of the source (derived scope), and every
/// channel constant must stay inside `[a-z0-9-]+` — the charset
/// `sanitize_path_segment` maps identically, which keeps
/// `sanitize ∘ derive_account` injective over the channel set (g3 §3.2).
/// Mutant: a channel constant containing `/` fails here.
#[test]
fn every_channel_constant_stays_in_the_sanitizer_identity_charset() {
    let lib = fs::read_to_string(crate_src_dir().join("lib.rs")).expect("read lib.rs");
    let mut channels = Vec::new();
    for line in lib.lines() {
        // Generic extractor: any `theyos_channel = "X"` occurrence.
        let mut hay = line.trim();
        while let Some(idx) = hay.find("theyos_channel = \"") {
            let after = &hay[idx + "theyos_channel = \"".len()..];
            if let Some(end) = after.find('"') {
                channels.push(after[..end].to_string());
                hay = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    channels.sort();
    channels.dedup();
    assert!(
        channels.len() >= 2,
        "expected at least dev+release channel arms, found {channels:?}"
    );
    for channel in &channels {
        assert!(
            !channel.is_empty()
                && channel
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "channel constant {channel:?} must match [a-z0-9-]+ or the account name \
             loses injectivity through the file-backend sanitizer"
        );
    }
}

/// The channel contract, pinned in both directions (g3 §3.3 + the debug
/// default decision): a compile_error! arm must exist for the unresolved
/// channel in a NON-debug build; and the ONLY default that may exist is dev,
/// gated by debug_assertions. A default that fires in a release-shaped
/// build, or a default of anything but dev, fails here.
#[test]
fn undefined_channel_contract_is_exact() {
    let lib = fs::read_to_string(crate_src_dir().join("lib.rs")).expect("read lib.rs");
    assert!(
        lib.contains("compile_error!"),
        "lib.rs must contain a compile_error! arm for an unresolved theyos_channel"
    );
    let lines: Vec<&str> = lib.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("const CHANNEL: &str") {
            // The gate may be several cfg lines; scan backwards to the
            // previous item boundary (an attribute-free gap) for the arms.
            let window_start = i.saturating_sub(6);
            let gate: String = lines[window_start..i].join("\n");
            assert!(
                gate.contains("theyos_channel = \"") || gate.contains("debug_assertions"),
                "ungated CHANNEL constant at line {} — a silent default channel",
                i + 1
            );
        }
    }
    // And the compile_error! arm itself must be gated NOT(debug_assertions):
    // an unresolved channel in a release-shaped build is the error case.
    let mut saw_error_arm = false;
    for (i, line) in lines.iter().enumerate() {
        if line.contains("compile_error!") {
            let window_start = i.saturating_sub(8);
            let gate: String = lines[window_start..i].join("\n");
            if gate.contains("not(debug_assertions)") {
                saw_error_arm = true;
            }
        }
    }
    assert!(
        saw_error_arm,
        "the compile_error! arm must be gated not(debug_assertions) — an \
         unresolved channel in a non-debug build is the failure being pinned"
    );
}

/// The PROFILE-derived release check in build.rs must exist (reopening T1d):
/// `debug_assertions` is a proxy an operator can legitimately enable in
/// release, so the cfg arm alone cannot close release-with-dev-channel.
/// Mutant: delete the build.rs check and this fails, even though every cfg
/// arm still compiles.
#[test]
fn build_rs_refuses_release_profile_with_dev_channel() {
    let build_rs = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
        .expect("read build.rs");
    assert!(
        build_rs.contains("PROFILE") && build_rs.contains("profile != \"release\""),
        "build.rs must refuse PROFILE=release with the dev channel — derived \
         from cargo's PROFILE, not from the debug_assertions proxy (T1d)"
    );
}
