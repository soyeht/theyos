//! `soyeht claws-verify` — end-to-end verification of a claw's installer plan
//! inside a disposable sandbox VM.
//!
//! Post Phase I.2b, the host side of verify is a thin orchestrator: the heavy
//! lifting (boot VM, run plan, start claw, 60s soak, `kill -0`, destroy VM)
//! happens inside the [`Verifier`] implementation — typically an
//! `imagebuilder build <claw> --verify-only` subprocess.  This file just:
//!
//!   1. Resolves the target set (single claw or `--all-detected`).
//!   2. Builds a [`Verifier`] from the requested sandbox kind.
//!   3. Calls [`Verifier::verify`] per target, writes the subprocess log tail
//!      under `artifacts/verify/<claw>-<ts>.log`.
//!   4. Records the outcome in `claws/verify-results.json` via
//!      [`claw_rs::verify_results::record`] (flock-safe).
//!   5. On success, patches `claws/manifest.yml` to `tier: available`.

use std::path::{Path, PathBuf};

use claw_rs::verify_results::{self, VerifyResult, VerifyStatus};

use crate::verify_sandbox::{self, SandboxKind, Verifier, VerifyReport};

/// Arguments for `soyeht claws-verify`.
#[derive(Debug, Clone)]
pub struct ClawsVerifyArgs {
    pub claw: Option<String>,
    pub all_detected: bool,
    pub sandbox: String,
    pub concurrency: u32,
    pub keep_vm: bool,
}

/// Default path for `verify-results.json` relative to `THEYOS_DIR`.
#[must_use]
pub fn verify_results_path(root: &Path) -> PathBuf {
    root.join("claws").join("verify-results.json")
}

/// Default directory for per-run claw log tails, relative to `THEYOS_DIR`.
#[must_use]
pub fn verify_artifacts_dir(root: &Path) -> PathBuf {
    root.join("artifacts").join("verify")
}

/// CLI entry point.
pub fn cmd_claws_verify(root: &Path, args: &ClawsVerifyArgs) {
    if let Err(e) = run(root, args) {
        eprintln!("[claws-verify] error: {e}");
        std::process::exit(1);
    }
}

fn run(root: &Path, args: &ClawsVerifyArgs) -> Result<(), String> {
    let targets = decide_targets(args)?;
    if targets.is_empty() {
        println!("[claws-verify] no targets selected — pass a claw name or --all-detected");
        return Ok(());
    }

    let kind = SandboxKind::parse(&args.sandbox)?;
    if args.concurrency > 1 {
        eprintln!(
            "[claws-verify] warning: concurrency={} requested; v1 executes sequentially",
            args.concurrency
        );
    }
    if args.keep_vm {
        eprintln!(
            "[claws-verify] warning: --keep-vm has no effect when verify runs inside the imagebuilder subprocess"
        );
    }

    let verifier = verify_sandbox::make_verifier(kind)?;

    let results_path = verify_results_path(root);
    let logs_dir = verify_artifacts_dir(root);

    for claw in &targets {
        println!("[claws-verify] ▶ {claw}");
        match verify_one(root, verifier.as_ref(), claw, &results_path, &logs_dir) {
            Ok(()) => println!("[claws-verify] ✔ {claw}"),
            Err(e) => eprintln!("[claws-verify] ✖ {claw}: {e}"),
        }
    }
    Ok(())
}

/// Determine which claws to verify based on the CLI args.
///
/// `--all-detected` picks exactly the claws at `tier: detected` — `supported`
/// claws already have golden artifacts and a builtin plan, and `catalog`
/// claws have no install plan to execute.
fn decide_targets(args: &ClawsVerifyArgs) -> Result<Vec<String>, String> {
    if let Some(name) = &args.claw {
        if !core_rs::manifest::is_known(name) {
            return Err(format!("claw {name:?} is not in the manifest"));
        }
        return Ok(vec![name.clone()]);
    }
    if args.all_detected {
        let names: Vec<String> = core_rs::manifest::all_names()
            .into_iter()
            .filter(|n| {
                core_rs::manifest::get(n)
                    .is_some_and(|e| e.tier == core_rs::manifest::Tier::Detected)
            })
            .map(str::to_string)
            .collect();
        return Ok(names);
    }
    Err("missing target: pass a claw name or --all-detected".to_string())
}

/// Verify a single claw.  Records the outcome in `verify-results.json`,
/// persists the subprocess log tail, and patches the manifest on success.
fn verify_one(
    root: &Path,
    verifier: &dyn Verifier,
    claw: &str,
    results_path: &Path,
    logs_dir: &Path,
) -> Result<(), String> {
    let entry =
        core_rs::manifest::get(claw).ok_or_else(|| format!("manifest has no entry for {claw}"))?;

    let attempted_at = core_rs::time::now_iso_secs();
    let log_path = log_path_for(logs_dir, claw, &attempted_at);

    let report = run_verify_blocking(verifier, claw, entry.min_ram_mb);

    // Always persist the subprocess log — the whole point of this artifact
    // is to debug failures, so we write it regardless of outcome.
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&log_path, &report.log);

    let (status, err) = match report.outcome {
        Ok(()) => (VerifyStatus::Ok, None),
        Err(ref e) => (VerifyStatus::Failed, Some(e.clone())),
    };

    let result = VerifyResult {
        verify_status: status,
        verify_error: err.clone(),
        verify_log_path: Some(log_path.display().to_string()),
        verify_attempted_at: Some(attempted_at),
    };
    verify_results::record(results_path, claw, &result)
        .map_err(|e| format!("record verify-result: {e}"))?;

    if status == VerifyStatus::Ok {
        match patch_manifest_tier_available(root, claw) {
            Ok(true) => println!("[claws-verify]   manifest: set tier: available for {claw}"),
            Ok(false) => {}
            Err(e) => eprintln!("[claws-verify]   manifest patch skipped: {e}"),
        }
    }

    if let Some(e) = err {
        return Err(e);
    }
    Ok(())
}

/// Blocking wrapper around the async [`Verifier::verify`] so the CLI
/// entry point can stay synchronous.
fn run_verify_blocking(verifier: &dyn Verifier, claw: &str, min_ram_mb: u32) -> VerifyReport {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let msg = format!("build tokio runtime: {e}");
            return VerifyReport {
                outcome: Err(msg.clone()),
                log: msg,
            };
        }
    };
    rt.block_on(verifier.verify(claw, min_ram_mb))
}

/// Compute the per-run log path, ISO timestamp flattened to filesystem-safe chars.
fn log_path_for(logs_dir: &Path, claw: &str, iso_ts: &str) -> PathBuf {
    let ts = iso_ts.replace(':', "-");
    logs_dir.join(format!("{claw}-{ts}.log"))
}

/// Patch `claws/manifest.yml` to set `tier: available` for `claw`.
///
/// Returns `Ok(true)` on a successful patch, `Ok(false)` if the manifest
/// already has `tier: available` for this claw or if we couldn't find the
/// claw block safely.  Returns `Err` for I/O failures.
pub(crate) fn patch_manifest_tier_available(root: &Path, claw: &str) -> Result<bool, String> {
    let manifest_path = root.join("claws").join("manifest.yml");
    if !manifest_path.is_file() {
        return Ok(false);
    }
    let content =
        std::fs::read_to_string(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;
    let patched = apply_tier_patch(&content, claw, "available")?;
    if patched == content {
        return Ok(false);
    }
    std::fs::write(&manifest_path, patched).map_err(|e| format!("write manifest: {e}"))?;
    Ok(true)
}

/// Pure helper for the YAML string patch — exposed for tests.
fn apply_tier_patch(content: &str, claw: &str, new_tier: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let header = format!("  {claw}:");
    let Some(start) = lines.iter().position(|l| l.trim_end() == header.trim_end()) else {
        return Err(format!("claw block {claw:?} not found in manifest"));
    };
    // The block ends at the next top-level (2-space indented) "name:" header
    // or EOF.  Inside the block, every line is indented >= 4 spaces.
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| !l.is_empty() && !l.starts_with("    "))
        .map_or(lines.len(), |(i, _)| i);

    let mut patched_block: Vec<String> = Vec::with_capacity(end - start + 1);
    let mut saw_tier = false;
    for l in &lines[start..end] {
        if let Some(rest) = l.strip_prefix("    tier:") {
            let _ = rest; // we replace regardless of previous value
            patched_block.push(format!("    tier: {new_tier}"));
            saw_tier = true;
        } else {
            patched_block.push((*l).to_string());
        }
    }
    if !saw_tier {
        // Insert `tier: available` right after the header.
        patched_block.insert(1, format!("    tier: {new_tier}"));
    }

    let mut out = Vec::with_capacity(lines.len() + 1);
    out.extend(lines[..start].iter().map(|s| (*s).to_string()));
    out.extend(patched_block);
    out.extend(lines[end..].iter().map(|s| (*s).to_string()));
    let trailing_newline = content.ends_with('\n');
    let mut joined = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    Ok(joined)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[test]
    fn decide_targets_single_requires_manifest_entry() {
        let args = ClawsVerifyArgs {
            claw: Some("picoclaw".into()),
            all_detected: false,
            sandbox: "firecracker".into(),
            concurrency: 1,
            keep_vm: false,
        };
        assert_eq!(decide_targets(&args).unwrap(), vec!["picoclaw".to_string()]);
    }

    #[test]
    fn decide_targets_unknown_claw_errors() {
        let args = ClawsVerifyArgs {
            claw: Some("ghostclaw".into()),
            all_detected: false,
            sandbox: "firecracker".into(),
            concurrency: 1,
            keep_vm: false,
        };
        let err = decide_targets(&args).unwrap_err();
        assert!(err.contains("not in the manifest"), "got {err}");
    }

    #[test]
    fn decide_targets_all_detected_filters_by_tier_detected() {
        let args = ClawsVerifyArgs {
            claw: None,
            all_detected: true,
            sandbox: "firecracker".into(),
            concurrency: 1,
            keep_vm: false,
        };
        let targets = decide_targets(&args).unwrap();
        for t in &targets {
            let tier = core_rs::manifest::get(t)
                .map(|e| e.tier)
                .expect("target must be in manifest");
            assert_eq!(
                tier,
                core_rs::manifest::Tier::Detected,
                "{t} has tier {tier:?}, expected Detected"
            );
        }
    }

    #[test]
    fn decide_targets_no_target_errors() {
        let args = ClawsVerifyArgs {
            claw: None,
            all_detected: false,
            sandbox: "firecracker".into(),
            concurrency: 1,
            keep_vm: false,
        };
        assert!(decide_targets(&args).is_err());
    }

    // ── YAML patch tests (no I/O) ─────────────────────────────────────────

    const FIXTURE_YML: &str = concat!(
        "claws:\n",
        "  picoclaw:\n",
        "    description: \"x\"\n",
        "    language: go\n",
        "  zeroclaw:\n",
        "    description: \"y\"\n",
        "    tier: detected\n",
    );

    #[test]
    fn apply_tier_patch_inserts_when_missing() {
        let out = apply_tier_patch(FIXTURE_YML, "picoclaw", "available").unwrap();
        assert!(out.contains("  picoclaw:\n    tier: available\n    description:"));
    }

    #[test]
    fn apply_tier_patch_replaces_existing() {
        let out = apply_tier_patch(FIXTURE_YML, "zeroclaw", "available").unwrap();
        assert!(out.contains("    tier: available"));
        assert!(!out.contains("    tier: detected"));
    }

    #[test]
    fn apply_tier_patch_unknown_claw_errors() {
        let err = apply_tier_patch(FIXTURE_YML, "ghostclaw", "available").unwrap_err();
        assert!(err.contains("not found"), "got {err}");
    }

    #[test]
    fn apply_tier_patch_preserves_trailing_newline() {
        let yml_with_newline = FIXTURE_YML; // already ends with \n
        assert!(yml_with_newline.ends_with('\n'));
        let out = apply_tier_patch(yml_with_newline, "picoclaw", "available").unwrap();
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn log_path_for_flattens_colons() {
        let p = log_path_for(
            std::path::Path::new("/tmp/verify"),
            "picoclaw",
            "2026-04-14T12:00:00Z",
        );
        assert_eq!(
            p,
            std::path::PathBuf::from("/tmp/verify/picoclaw-2026-04-14T12-00-00Z.log")
        );
    }

    // ── Verifier integration via a fake sandbox ─────────────────────────

    /// Injectable fake [`Verifier`] that records every call and returns a
    /// pre-programmed report.
    struct FakeVerifier {
        outcome: Result<(), String>,
        log: String,
    }

    #[async_trait]
    impl Verifier for FakeVerifier {
        async fn verify(&self, _claw: &str, _min_ram_mb: u32) -> VerifyReport {
            VerifyReport {
                outcome: self.outcome.clone(),
                log: self.log.clone(),
            }
        }
    }

    #[test]
    fn verify_one_success_writes_log_and_patches_manifest() {
        // Set up a throwaway theyos_dir with a minimal manifest.yml that has
        // a detected claw we can flip.
        let tmp = tempfile::tempdir().unwrap();
        let claws_dir = tmp.path().join("claws");
        std::fs::create_dir_all(&claws_dir).unwrap();
        let manifest = concat!(
            "claws:\n",
            "  picoclaw:\n",
            "    description: \"x\"\n",
            "    tier: detected\n",
        );
        std::fs::write(claws_dir.join("manifest.yml"), manifest).unwrap();

        let verifier = FakeVerifier {
            outcome: Ok(()),
            log: "--- stdout ---\nVERIFY_OK:picoclaw\n".to_string(),
        };
        let results_path = verify_results_path(tmp.path());
        let logs_dir = verify_artifacts_dir(tmp.path());

        verify_one(tmp.path(), &verifier, "picoclaw", &results_path, &logs_dir).unwrap();

        // Log file must exist and contain the fake log.
        let mut logs = std::fs::read_dir(&logs_dir).unwrap();
        let log_entry = logs.next().expect("log file written").unwrap();
        let log_content = std::fs::read_to_string(log_entry.path()).unwrap();
        assert!(log_content.contains("VERIFY_OK:picoclaw"), "{log_content}");

        // Manifest was patched to tier: available.
        let patched = std::fs::read_to_string(claws_dir.join("manifest.yml")).unwrap();
        assert!(patched.contains("tier: available"), "{patched}");
    }

    #[test]
    fn verify_one_failure_records_error_and_keeps_tier_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let claws_dir = tmp.path().join("claws");
        std::fs::create_dir_all(&claws_dir).unwrap();
        let manifest = concat!(
            "claws:\n",
            "  picoclaw:\n",
            "    description: \"x\"\n",
            "    tier: detected\n",
        );
        std::fs::write(claws_dir.join("manifest.yml"), manifest).unwrap();

        let verifier = FakeVerifier {
            outcome: Err("installer step 3 exited 127".to_string()),
            log: "--- stderr ---\nno such file\n".to_string(),
        };
        let results_path = verify_results_path(tmp.path());
        let logs_dir = verify_artifacts_dir(tmp.path());

        let err = verify_one(tmp.path(), &verifier, "picoclaw", &results_path, &logs_dir)
            .expect_err("must fail");
        assert!(err.contains("installer step 3"));

        // Log still written (the whole reason log capture exists).
        let mut logs = std::fs::read_dir(&logs_dir).unwrap();
        assert!(logs.next().is_some(), "log file must be written on failure");

        // Manifest NOT patched — remains tier: detected.
        let patched = std::fs::read_to_string(claws_dir.join("manifest.yml")).unwrap();
        assert!(patched.contains("tier: detected"));
        assert!(!patched.contains("tier: available"));
    }
}
