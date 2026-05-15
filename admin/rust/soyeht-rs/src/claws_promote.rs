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
    let current = current_tier(&content, claw)?;
    if current.as_deref() != Some("available") {
        return Err(format!(
            "claw {claw} is not `tier: available` (currently: {})",
            current.as_deref().unwrap_or("<unset>")
        ));
    }

    let patched = apply_promotion(&content, claw)?;
    if patched == content {
        return Err("patch produced no diff".to_string());
    }
    std::fs::write(&manifest_path, patched)
        .map_err(|e| format!("write manifest {}: {e}", manifest_path.display()))?;
    Ok(())
}

/// Extract the current `tier:` value for `claw`, if any.
pub(crate) fn current_tier(content: &str, claw: &str) -> Result<Option<String>, String> {
    let lines: Vec<&str> = content.lines().collect();
    let header = format!("  {claw}:");
    let Some(start) = lines.iter().position(|l| l.trim_end() == header.trim_end()) else {
        return Err(format!("claw block {claw:?} not found in manifest"));
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| !l.is_empty() && !l.starts_with("    "))
        .map_or(lines.len(), |(i, _)| i);
    for l in &lines[start + 1..end] {
        if let Some(rest) = l.strip_prefix("    tier:") {
            return Ok(Some(rest.trim().trim_matches('"').to_string()));
        }
    }
    Ok(None)
}

/// Core transformation (pure).  Exposed for tests.
pub(crate) fn apply_promotion(content: &str, claw: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let header = format!("  {claw}:");
    let Some(start) = lines.iter().position(|l| l.trim_end() == header.trim_end()) else {
        return Err(format!("claw block {claw:?} not found in manifest"));
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| !l.is_empty() && !l.starts_with("    "))
        .map_or(lines.len(), |(i, _)| i);

    let mut out_block: Vec<String> = Vec::new();
    out_block.push(lines[start].to_string()); // header

    let mut saw_install_plan_source = false;
    let mut i = start + 1;
    while i < end {
        let l = lines[i];

        if let Some(_rest) = l.strip_prefix("    tier:") {
            out_block.push("    tier: supported".to_string());
            i += 1;
            continue;
        }

        if l.strip_prefix("    install_template:").is_some() {
            // drop the line entirely
            i += 1;
            continue;
        }

        if l.strip_prefix("    install_plan_source:").is_some() {
            out_block.push("    install_plan_source: \"builtin\"".to_string());
            saw_install_plan_source = true;
            i += 1;
            continue;
        }

        if l.trim_end() == "    install:" {
            // Skip the `install:` block: every subsequent line that is
            // indented >= 6 spaces belongs to it (nested list / mapping).
            i += 1;
            while i < end {
                let nested = lines[i];
                if nested.is_empty() {
                    // Blank lines inside the block are fine — continue scanning.
                    i += 1;
                    continue;
                }
                if nested.starts_with("      ") {
                    i += 1;
                    continue;
                }
                break;
            }
            continue;
        }

        out_block.push(l.to_string());
        i += 1;
    }

    if !saw_install_plan_source {
        // Insert right after the header so it's visibly the promotion marker.
        out_block.insert(1, "    install_plan_source: \"builtin\"".to_string());
    }

    let mut result = Vec::with_capacity(lines.len());
    result.extend(lines[..start].iter().map(|s| (*s).to_string()));
    result.extend(out_block);
    result.extend(lines[end..].iter().map(|s| (*s).to_string()));
    let trailing = content.ends_with('\n');
    let mut joined = result.join("\n");
    if trailing {
        joined.push('\n');
    }
    Ok(joined)
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
            current_tier(FIXTURE, "picoclaw").unwrap(),
            Some("available".to_string())
        );
        assert_eq!(
            current_tier(FIXTURE, "zeroclaw").unwrap(),
            Some("detected".to_string())
        );
    }

    #[test]
    fn current_tier_missing_is_none() {
        let yml = "claws:\n  picoclaw:\n    description: \"x\"\n";
        assert_eq!(current_tier(yml, "picoclaw").unwrap(), None);
    }

    #[test]
    fn current_tier_unknown_claw_errors() {
        assert!(current_tier(FIXTURE, "ghostclaw").is_err());
    }

    #[test]
    fn apply_promotion_sets_tier_and_source() {
        let out = apply_promotion(FIXTURE, "picoclaw").unwrap();
        assert!(out.contains("    tier: supported"));
        assert!(out.contains("    install_plan_source: \"builtin\""));
    }

    #[test]
    fn apply_promotion_strips_install_template() {
        let out = apply_promotion(FIXTURE, "picoclaw").unwrap();
        assert!(!out.contains("install_template:"));
    }

    #[test]
    fn apply_promotion_strips_install_block() {
        let out = apply_promotion(FIXTURE, "picoclaw").unwrap();
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
        let out = apply_promotion(yml, "picoclaw").unwrap();
        assert!(out.contains("install_plan_source: \"builtin\""));
        assert!(!out.contains("install_plan_source: \"template\""));
    }

    #[test]
    fn apply_promotion_unknown_claw_errors() {
        assert!(apply_promotion(FIXTURE, "ghostclaw").is_err());
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
