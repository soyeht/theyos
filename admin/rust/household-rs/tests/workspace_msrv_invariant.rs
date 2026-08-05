//! The declared MSRV must be at least every dependency's declared MSRV.
//!
//! `rust-version` is a promise to consumers about the oldest compiler that
//! builds this workspace. Nothing in this repository tests it. Clippy checks
//! MSRV-*gated lints*, not whether the code or its dependency graph honours the
//! declared floor, and the pinned toolchain compiles everything regardless — so
//! the number can drift from the truth indefinitely and only a downstream
//! consumer on an old compiler ever finds out.
//!
//! It had already drifted when this test was written: the workspace declared
//! `1.85` while `time@0.3.47` in the lock declares `1.88.0`, so `cargo +1.85.0`
//! refused before compiling a single line. Two of us measured around that fact
//! for a whole round without seeing it, because every instrument we used ran on
//! the pinned toolchain.
//!
//! Deliberately NOT a second-toolchain job. Installing `+<msrv>` on the runner
//! and building the world is expensive and reds for reasons unrelated to the
//! claim, which is how a gate gets switched off. This reads the resolved graph
//! cargo already produced: no network, no extra toolchain, and it names the
//! package that pushes the floor instead of leaving a bisect.
//!
//! What it does NOT prove, stated so nobody reads it wider: that the *source*
//! compiles on the declared version. A crate can declare `1.85` and still use
//! newer syntax — declaring is not verifying. This closes the dependency half,
//! which is the half that had actually drifted.

use std::process::Command;

/// `1.88`, `1.88.0` and `1.88.0-beta` all compare as (1, 88, 0).
fn parse(v: &str) -> (u32, u32, u32) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut it = core.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("household-rs sits inside admin/rust")
        .to_path_buf()
}

fn metadata() -> serde_json::Value {
    // `--offline` makes the no-network property a cargo-enforced fact rather
    // than an assumption about the runner.
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--offline"])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed ({}). This test cannot fall back to a guess: \
         without the resolved graph it would compare against an empty set and \
         pass while checking nothing.\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("cargo metadata emits JSON")
}

#[test]
fn declared_msrv_is_at_least_every_dependency_msrv() {
    let md = metadata();
    let packages = md["packages"].as_array().expect("packages array");
    let members: std::collections::BTreeSet<&str> = md["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();

    // Positive control. A parse that yields nothing, or a graph with no
    // declared MSRVs at all, would make the maximum below vacuously small and
    // this test green for the wrong reason — the usual way a guard search fails
    // toward "unprotected".
    assert!(
        packages.len() > 100,
        "only {} packages in the resolved graph; the metadata parse is broken",
        packages.len()
    );

    let mut declared: Option<(u32, u32, u32)> = None;
    let mut required: Vec<(&str, &str, (u32, u32, u32))> = Vec::new();

    for pkg in packages {
        let (Some(id), Some(name)) = (pkg["id"].as_str(), pkg["name"].as_str()) else {
            continue;
        };
        let Some(rv) = pkg["rust_version"].as_str() else {
            continue;
        };
        if members.contains(id) {
            // The weakest member claim is the floor a consumer may rely on, so
            // compare against the MINIMUM rather than the most generous one.
            let v = parse(rv);
            declared = Some(declared.map_or(v, |d| d.min(v)));
        } else {
            required.push((name, rv, parse(rv)));
        }
    }

    let declared = declared.expect(
        "no workspace member declares rust-version; if the declaration were \
         removed, this test must fail rather than silently stop checking",
    );
    assert!(
        !required.is_empty(),
        "no dependency declares rust-version; the field lookup is broken, so \
         the comparison below would be vacuous"
    );

    let ceiling = required
        .iter()
        .map(|(_, _, v)| *v)
        .max()
        .expect("non-empty");
    let culprits: Vec<String> = required
        .iter()
        .filter(|(_, _, v)| *v == ceiling)
        .map(|(n, raw, _)| format!("{n} requires {raw}"))
        .collect();

    assert!(
        declared >= ceiling,
        "declared MSRV {}.{}.{} is BELOW what the dependency graph requires \
         ({}.{}.{}). The declaration is a promise to consumers and it is \
         currently false — a build on the declared version fails before \
         compiling any of our code. Pushed up by: {}. Either raise the \
         declaration to the truth or pin the dependency back.",
        declared.0,
        declared.1,
        declared.2,
        ceiling.0,
        ceiling.1,
        ceiling.2,
        culprits.join(", ")
    );
}
