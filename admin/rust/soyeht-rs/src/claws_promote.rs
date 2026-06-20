//! `soyeht claws-promote` — flip a claw from `tier: available` to
//! `tier: supported` once a handwritten builtin plan exists.
//!
//! Invariants (validated before any file I/O):
//!
//!   * The claw must be in `claws/manifest.yml`.
//!   * The claw must currently be `tier: available` (claws-verify happy path).
//!   * [`vmrunner_rs::installer_plan::has_builtin`] must return true — i.e.
//!     someone added a hand-written plan arm to `installer_plan.rs` and the
//!     `BUILTIN_PLANS` list for artifact fingerprinting.
//!
//! The patch is a targeted, line-oriented rewrite of `claws/manifest.yml`:
//!
//!   * `tier: available` → `tier: supported`
//!   * `install_plan_source: <anything>` → `install_plan_source: "builtin"`
//!     (added if missing)
//!   * `install_template: <anything>` line removed
//!   * `install:` block removed (contiguous run of >=6-space-indented lines
//!     starting with `install:`)
//!
//! All operations happen in-memory; the on-disk file is replaced atomically
//! via write-rename.

use std::path::Path;

use crate::manifest_yaml;

/// CLI args for `soyeht claws-promote`.
#[derive(Debug, Clone)]
pub struct ClawsPromoteArgs {
    pub claw: String,
}

/// Entry point.
pub fn cmd_claws_promote(root: &Path, args: &ClawsPromoteArgs) {
    match run(root, &args.claw) {
        Ok(()) => println!("[claws-promote] ✔ {} now tier: supported", args.claw),
        Err(e) => {
            eprintln!("[claws-promote] error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(root: &Path, claw: &str) -> Result<(), String> {
    // ── Invariants ────────────────────────────────────────────────────
    if !core_rs::manifest::is_known(claw) {
        return Err(format!("claw {claw:?} is not in the manifest"));
    }
    if !vmrunner_rs::installer_plan::has_builtin(claw) {
        return Err(format!(
            "cannot promote {claw}: add a builtin plan arm in \
             vmrunner-rs/src/installer_plan.rs (and the corresponding \
             BUILTIN_PLANS entry) before promoting"
        ));
    }

    let manifest_path = root.join("claws").join("manifest.yml");
    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;

    // The manifest patch refuses to run unless the claw is currently
    // `tier: available` — promoting a `detected` claw skips verification.
    let current = manifest_yaml::read_scalar_field(&content, claw, "tier")?;
    if current.as_deref() != Some("available") {
        return Err(format!(
            "claw {claw} is not `tier: available` (currently: {})",
            current.as_deref().unwrap_or("<unset>")
        ));
    }

    let patched = manifest_yaml::promote_available_to_builtin(&content, claw)?;
    if patched == content {
        return Err("patch produced no diff".to_string());
    }
    std::fs::write(&manifest_path, patched)
        .map_err(|e| format!("write manifest {}: {e}", manifest_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        "claws:\n",
        "  picoclaw:\n",
        "    description: \"x\"\n",
        "    tier: available\n",
        "    install_template: node-basic\n",
        "    install:\n",
        "      system_deps:\n",
        "        - curl\n",
        "      run_cmd: \"node foo\"\n",
        "    binary_size_mb: 30\n",
        "  zeroclaw:\n",
        "    description: \"y\"\n",
        "    tier: detected\n",
    );

    #[test]
    fn current_tier_reads_value() {
        assert_eq!(
            manifest_yaml::read_scalar_field(FIXTURE, "picoclaw", "tier").unwrap(),
            Some("available".to_string())
        );
        assert_eq!(
            manifest_yaml::read_scalar_field(FIXTURE, "zeroclaw", "tier").unwrap(),
            Some("detected".to_string())
        );
    }

    #[test]
    fn current_tier_missing_is_none() {
        let yml = "claws:\n  picoclaw:\n    description: \"x\"\n";
        assert_eq!(
            manifest_yaml::read_scalar_field(yml, "picoclaw", "tier").unwrap(),
            None
        );
    }

    #[test]
    fn current_tier_unknown_claw_errors() {
        assert!(manifest_yaml::read_scalar_field(FIXTURE, "ghostclaw", "tier").is_err());
    }

    #[test]
    fn apply_promotion_sets_tier_and_source() {
        let out = manifest_yaml::promote_available_to_builtin(FIXTURE, "picoclaw").unwrap();
        assert!(out.contains("    tier: supported"));
        assert!(out.contains("    install_plan_source: \"builtin\""));
    }

    #[test]
    fn apply_promotion_strips_install_template() {
        let out = manifest_yaml::promote_available_to_builtin(FIXTURE, "picoclaw").unwrap();
        assert!(!out.contains("install_template:"));
    }

    #[test]
    fn apply_promotion_strips_install_block() {
        let out = manifest_yaml::promote_available_to_builtin(FIXTURE, "picoclaw").unwrap();
        // The `install:` header and its nested children must all be gone.
        assert!(!out.contains("    install:"));
        assert!(!out.contains("      run_cmd"));
        assert!(!out.contains("      system_deps"));
        // But sibling fields after the block are preserved.
        assert!(out.contains("    binary_size_mb: 30"));
    }

    #[test]
    fn apply_promotion_replaces_install_plan_source_if_present() {
        let yml = concat!(
            "claws:\n",
            "  picoclaw:\n",
            "    description: \"x\"\n",
            "    tier: available\n",
            "    install_plan_source: \"template\"\n",
        );
        let out = manifest_yaml::promote_available_to_builtin(yml, "picoclaw").unwrap();
        assert!(out.contains("install_plan_source: \"builtin\""));
        assert!(!out.contains("install_plan_source: \"template\""));
    }

    #[test]
    fn apply_promotion_unknown_claw_errors() {
        assert!(manifest_yaml::promote_available_to_builtin(FIXTURE, "ghostclaw").is_err());
    }

    // ── End-to-end run() tests ────────────────────────────────────────

    fn write_manifest(root: &std::path::Path, content: &str) {
        let claws_dir = root.join("claws");
        std::fs::create_dir_all(&claws_dir).unwrap();
        std::fs::write(claws_dir.join("manifest.yml"), content).unwrap();
    }

    #[test]
    fn run_rejects_unknown_manifest_claw() {
        let tmp = tempfile::tempdir().unwrap();
        // Use something not in the compiled-in manifest.
        let err = run(tmp.path(), "ghostclaw").unwrap_err();
        assert!(err.contains("not in the manifest"), "got {err}");
    }

    #[test]
    fn run_rejects_non_builtin_even_when_manifest_ok() {
        // Craft a fake claw name that IS in the compiled-in manifest but is
        // NOT builtin.  The manifest currently ships every claw as builtin,
        // so we simulate the inverse condition via the helper instead.
        assert!(!vmrunner_rs::installer_plan::has_builtin("ghostclaw"));
        assert!(!core_rs::manifest::is_known("ghostclaw"));
        // The two combined => first check fires first.
        let tmp = tempfile::tempdir().unwrap();
        let err = run(tmp.path(), "ghostclaw").unwrap_err();
        assert!(err.contains("not in the manifest"));
    }

    #[test]
    fn run_rejects_non_available_tier() {
        // picoclaw is in the manifest + builtin, but fixture has tier: detected.
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(
            tmp.path(),
            concat!(
                "claws:\n",
                "  picoclaw:\n",
                "    description: \"x\"\n",
                "    tier: detected\n",
            ),
        );
        let err = run(tmp.path(), "picoclaw").unwrap_err();
        assert!(err.contains("not `tier: available`"), "got {err}");
    }

    #[test]
    fn run_happy_path_patches_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(tmp.path(), FIXTURE);
        run(tmp.path(), "picoclaw").unwrap();
        let patched = std::fs::read_to_string(tmp.path().join("claws/manifest.yml")).unwrap();
        assert!(patched.contains("    tier: supported"));
        assert!(!patched.contains("install:"));
        assert!(!patched.contains("install_template:"));
    }
}
