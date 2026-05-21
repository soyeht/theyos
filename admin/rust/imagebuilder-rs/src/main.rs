//! imagebuilder — Golden image build, check, and rebuild for theyOS.
//!
//! # Subcommands
//!
//! ```text
//! imagebuilder check   [--force] [--max-age N] [claw...]   # staleness report
//! imagebuilder rebuild [--force] [--max-age N] [claw...]   # rebuild stale images using Rust pipeline
//! imagebuilder build   [--force] [claw... | --all]         # full Rust pipeline
//! imagebuilder list                                        # list golden image status
//! ```
//!
//! # Staleness rules (P28 — age-only)
//!
//! A golden image is stale when ANY of:
//!   1. The image file does not exist.
//!   2. The image is older than `MAX_AGE_DAYS` (default 7).
//!   3. `--force` was passed.
//!
//! # Environment
//!
//! | Variable                          | Default                               |
//! |-----------------------------------|---------------------------------------|
//! | `MAX_AGE_DAYS`                    | `7`                                   |
//! | `HOME`                            | standard `$HOME`                      |
//! | `THEYOS_DIR`                      | auto-detected from exe path           |
//! | `FIRECRACKER_BIN`                 | `~/firecracker/bin/firecracker`       |
//! | `FIRECRACKER_KERNEL_IMAGE`        | `~/firecracker/assets/vmlinux-*`      |
//! | `FIRECRACKER_BASE_ROOTFS`         | `~/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4` |
//! | `FIRECRACKER_SSH_KEY`             | `~/firecracker/assets/ubuntu-24.04-root.id_rsa` |
//! | `SLIRP4NETNS_BIN`                 | auto-resolved                         |

mod imagebuild;

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::{Parser, Subcommand};

use imagebuild::artifacts::{all_claws, file_size_human, golden_image_path, image_age_days};
use imagebuild::runner::{BuildContext, build_golden_image, stale_reason, verify_golden_image};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "imagebuilder",
    about = "Golden image build, check and rebuild for theyOS claw types",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check golden image staleness. Exits 1 if any images are stale.
    Check(CheckArgs),
    /// Rebuild stale golden images.
    Rebuild(RebuildArgs),
    /// Build golden images using the full Rust pipeline (P13).
    Build(BuildArgs),
    /// List all golden images and their status.
    List,
    /// DAG-based staleness check.  Outputs JSON: `{"<claw>": {"stale": bool, "reason": "...", "fingerprint": "..."}, ...}`
    /// Used by `soyeht artifacts sync` to determine which goldens need rebuilding.
    DagCheck(DagCheckArgs),
    /// Generate an artifact manifest (latest.json) from an existing golden build.
    /// Used by CI to publish pre-built artifacts to the registry.
    PublishManifest(PublishManifestArgs),
}

#[derive(clap::Args)]
struct DagCheckArgs {
    /// Claw types to check (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,
}

#[derive(clap::Args)]
struct PublishManifestArgs {
    /// Claw type to publish a manifest for.
    claw_type: String,

    /// Path to the compressed rootfs.ext4.zst file.
    /// The SHA-256 of this file is computed and included in the manifest.
    #[arg(long)]
    zst_file: PathBuf,

    /// Base URL where the artifact will be hosted.
    /// Used to construct the download URL: `<base-url>/<claw>/<arch>/<version>/rootfs.ext4.zst`.
    /// Ignored if `--artifact-url` is provided.
    #[arg(long, default_value = "")]
    base_url: String,

    /// Explicit download URL for the artifact.  Overrides the auto-constructed
    /// URL from `--base-url`.  Useful when the hosting layout doesn't match
    /// the default convention (e.g. GitHub Releases).
    #[arg(long)]
    artifact_url: Option<String>,

    /// Release channel (default: "stable").
    #[arg(long, default_value = "stable")]
    channel: String,

    /// Output path for the manifest JSON file (default: stdout).
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct CheckArgs {
    /// Claw types to check (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Treat all images as stale regardless of age.
    #[arg(long, env = "FORCE")]
    force: bool,

    /// Maximum age in days before an image is considered stale.
    #[arg(long, default_value = "7", env = "MAX_AGE_DAYS")]
    max_age: u64,
}

#[derive(clap::Args)]
struct RebuildArgs {
    /// Claw types to rebuild (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Rebuild all images unconditionally.
    #[arg(long, env = "FORCE")]
    force: bool,

    /// Maximum age in days before an image is considered stale.
    #[arg(long, default_value = "7", env = "MAX_AGE_DAYS")]
    max_age: u64,
}

#[derive(clap::Args)]
struct BuildArgs {
    /// Claw types to build (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Build all 6 claw types.
    #[arg(long, conflicts_with = "claw_types")]
    all: bool,

    /// Force rebuild even if golden image is up-to-date.
    #[arg(long, env = "FORCE")]
    force: bool,

    /// Run install plan in a disposable VM, smoke-test the entry point, and
    /// discard the rootfs without publishing a golden.
    ///
    /// Prints `VERIFY_OK` (exit 0) or `VERIFY_FAIL:<reason>` (exit 1) to stdout;
    /// consumed by `soyeht-rs::sandbox::firecracker` as a subprocess.
    #[arg(long)]
    verify_only: bool,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let repo_root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let home = core_rs::env::theyos_home(&repo_root);
    let assets_dir = PathBuf::from(&home).join("firecracker/assets");

    match cli.command {
        Commands::Check(args) => {
            let targets = resolve_claws(&args.claw_types);
            let any_stale = cmd_check(&targets, &assets_dir, args.max_age, args.force);
            std::process::exit(i32::from(any_stale));
        }

        Commands::Rebuild(args) => {
            let targets = resolve_claws(&args.claw_types);
            let ctx = make_build_context(&repo_root, &home, &assets_dir);
            let ok = cmd_rebuild_rust(&targets, &assets_dir, args.max_age, args.force, &ctx).await;
            std::process::exit(i32::from(!ok));
        }

        Commands::Build(args) => {
            // `--verify-only` accepts any claw that appears in the manifest
            // (detected / available / supported). The default build path stays
            // restricted to the 8 builtins that have goldens published.
            let ctx = make_build_context(&repo_root, &home, &assets_dir);
            let ok = if args.verify_only {
                let known = core_rs::manifest::all_names();
                let targets = if args.all {
                    known
                } else {
                    resolve_claws_from(&args.claw_types, &known)
                };
                cmd_verify(&targets, &ctx).await
            } else {
                // `--all` / no args: default to the 8 supported claws (CI
                // "build all ship goldens" semantics).
                // Named claws: accept any `installable` claw (supported OR
                // available) so the server's `install_worker` can invoke
                // `imagebuilder build <available-claw>` for on-demand golden
                // builds via template-driven installer plans (Fase C).
                let targets = if args.all || args.claw_types.is_empty() {
                    all_claws()
                } else {
                    resolve_claws_from(&args.claw_types, &core_rs::manifest::installable_names())
                };
                cmd_build(&targets, args.force, &ctx, &assets_dir).await
            };
            std::process::exit(i32::from(!ok));
        }

        Commands::List => {
            cmd_list(&assets_dir);
        }

        Commands::DagCheck(args) => {
            let targets = resolve_claws(&args.claw_types);
            let ctx = make_build_context(&repo_root, &home, &assets_dir);
            cmd_dag_check(&targets, &ctx);
        }

        Commands::PublishManifest(args) => {
            let ok = cmd_publish_manifest(&args, &assets_dir);
            std::process::exit(i32::from(!ok));
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_check(targets: &[&str], assets_dir: &Path, max_age: u64, force: bool) -> bool {
    println!("{:<12} {:<8} {:<12} REASON", "CLAW", "STATUS", "AGE");
    println!("{:<12} {:<8} {:<12} ------", "----", "------", "---");

    let mut any_stale = false;

    for &claw in targets {
        let age_days = image_age_days(assets_dir, claw);
        let reason = stale_reason(claw, assets_dir, max_age, force);
        let age_str = format!("{age_days}d");

        if reason.is_empty() {
            println!("{:<12} {:<8} {:<12} ok", claw, "fresh", age_str);
        } else {
            println!("{:<12} {:<8} {:<12} {reason}", claw, "STALE", age_str);
            any_stale = true;
        }
    }

    any_stale
}

/// Rebuild using the Rust pipeline.
async fn cmd_rebuild_rust(
    targets: &[&str],
    assets_dir: &Path,
    max_age: u64,
    force: bool,
    ctx: &BuildContext,
) -> bool {
    let mut rebuilt = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for &claw in targets {
        let reason = stale_reason(claw, assets_dir, max_age, force);

        if reason.is_empty() {
            eprintln!("[imagebuilder] {claw}: fresh — skipping");
            skipped += 1;
            continue;
        }

        eprintln!("[imagebuilder] {claw}: stale ({reason}) — building with Rust pipeline");
        match build_golden_image(claw, ctx).await {
            Ok(()) => {
                rebuilt += 1;
            }
            Err(e) => {
                eprintln!("[imagebuilder] {claw}: FAILED — {e}");
                failed += 1;
            }
        }
    }

    eprintln!("[imagebuilder] summary: rebuilt={rebuilt} failed={failed} skipped={skipped}");
    failed == 0
}

/// Disposable smoke test (`--verify-only`): run each claw's install plan in
/// a fresh VM, soak the entry point for 60s, discard the rootfs.
///
/// Prints one stdout line per target as a textual marker that the Rust
/// sandbox wrapper in `soyeht-rs::sandbox::firecracker` can parse:
///
/// ```text
/// VERIFY_OK:<claw>
/// VERIFY_FAIL:<claw>:<reason>
/// ```
///
/// Exits non-zero if any target failed.
async fn cmd_verify(targets: &[&str], ctx: &BuildContext) -> bool {
    let mut ok = true;
    for &claw in targets {
        match verify_golden_image(claw, ctx).await {
            Ok(()) => {
                println!("VERIFY_OK:{claw}");
            }
            Err(e) => {
                // Collapse the multi-line BuildError to a single-line reason so
                // downstream parsers can `.lines().find(...)` easily.
                let reason: String = ToString::to_string(&e).replace('\n', " ¶ ");
                println!("VERIFY_FAIL:{claw}:{reason}");
                ok = false;
            }
        }
    }
    ok
}

/// Build golden images using the full Rust pipeline.
async fn cmd_build(targets: &[&str], force: bool, ctx: &BuildContext, assets_dir: &Path) -> bool {
    let mut ok = true;

    for &claw in targets {
        // Skip fresh images unless --force
        if !force {
            let reason = stale_reason(claw, assets_dir, 7, false);
            if reason.is_empty() {
                eprintln!("[imagebuilder] {claw}: already up-to-date (use --force to rebuild)");
                continue;
            }
        }

        match build_golden_image(claw, ctx).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[imagebuilder] {claw}: BUILD FAILED — {e}");
                ok = false;
            }
        }
    }

    ok
}

fn cmd_list(assets_dir: &Path) {
    println!(
        "{:<12} {:<8} {:<8} {:<12} PATH",
        "CLAW", "STATUS", "AGE", "SIZE"
    );
    println!(
        "{:<12} {:<8} {:<8} {:<12} ----",
        "----", "------", "---", "----"
    );

    for claw in &all_claws() {
        // Try versionated layout first
        if let Some(rootfs) = core_rs::artifact_meta::golden_current_rootfs(assets_dir, claw) {
            let meta = core_rs::artifact_meta::read_current_golden_meta(assets_dir, claw);
            let size = file_size_human(&rootfs);
            let fp_short = meta
                .as_ref()
                .map_or_else(|| "?".to_string(), |m| m.fingerprint.short().to_string());
            println!(
                "{:<12} {:<8} {:<8} {:<12} {} (fp={})",
                claw,
                "READY",
                "-",
                size,
                rootfs.display(),
                fp_short,
            );
        } else {
            // Fallback to legacy flat path
            let img = golden_image_path(assets_dir, claw);
            if img.exists() {
                let age = image_age_days(assets_dir, claw);
                let size = file_size_human(&img);
                println!(
                    "{:<12} {:<8} {:<8} {:<12} {} (legacy)",
                    claw,
                    "READY",
                    format!("{age}d"),
                    size,
                    img.display()
                );
            } else {
                println!(
                    "{:<12} {:<8} {:<8} {:<12} {}",
                    claw,
                    "MISSING",
                    "?",
                    "-",
                    img.display()
                );
            }
        }
    }
}

/// Output JSON staleness report for each claw using DAG-based detection.
///
/// JSON format:
/// ```json
/// {
///   "picoclaw": {"stale": true, "reason": "input changed: base_rootfs_sha256", "fingerprint": "abc..."},
///   "nullclaw": {"stale": false, "reason": null, "fingerprint": "def..."},
///   ...
/// }
/// ```
fn cmd_dag_check(targets: &[&str], ctx: &BuildContext) {
    use std::collections::BTreeMap;

    let mut results: BTreeMap<&str, serde_json::Value> = BTreeMap::new();

    for &claw in targets {
        let reason = imagebuild::runner::stale_reason_dag(claw, ctx);
        let current_meta = core_rs::artifact_meta::read_current_golden_meta(&ctx.assets_dir, claw);
        let fp = current_meta
            .as_ref()
            .map(|m| m.fingerprint.as_str().to_string());

        let entry = serde_json::json!({
            "stale": reason.is_some(),
            "reason": reason.map(|r: core_rs::artifact_meta::StaleReason| r.to_string()),
            "fingerprint": fp,
        });
        results.insert(claw, entry);
    }

    // Output JSON to stdout (not stderr) so callers can parse it
    let json = serde_json::to_string_pretty(&results).expect("serialize dag-check results");
    println!("{json}");
}

// ── publish-manifest ─────────────────────────────────────────────────────

/// Generate an [`ArtifactManifest`] from an existing golden build.
///
/// Reads `golden.meta.json` from the current golden, computes the SHA-256 of
/// the provided `.zst` file, and writes the manifest JSON.
fn cmd_publish_manifest(args: &PublishManifestArgs, assets_dir: &Path) -> bool {
    use core_rs::artifact_meta;
    use core_rs::artifact_registry::ArtifactManifest;

    let claw = &args.claw_type;

    // 1. Read existing golden.meta.json
    let Some(meta) = artifact_meta::read_current_golden_meta(assets_dir, claw) else {
        eprintln!("[publish-manifest] no current golden found for {claw}");
        eprintln!("  hint: run `imagebuilder rebuild --force {claw}` first");
        return false;
    };

    // 2. Compute SHA-256 of the .zst file
    if !args.zst_file.is_file() {
        eprintln!(
            "[publish-manifest] zst file not found: {}",
            args.zst_file.display()
        );
        return false;
    }

    let zst_sha256 = match sha256_file_hex(&args.zst_file) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "[publish-manifest] failed to hash {}: {e}",
                args.zst_file.display()
            );
            return false;
        }
    };

    let zst_size = std::fs::metadata(&args.zst_file)
        .map(|m| m.len())
        .unwrap_or(0);

    // 3. Detect architecture
    let arch = core_rs::artifact_registry::host_arch();

    // 4. Look up version from manifest.yml
    let Some(entry) = core_rs::manifest::get(claw) else {
        eprintln!("[publish-manifest] unknown claw in manifest.yml: {claw}");
        return false;
    };
    let version = entry.version.to_string();

    // 5. Construct download URL
    let url = if let Some(ref explicit) = args.artifact_url {
        explicit.clone()
    } else {
        let base_url = args.base_url.trim_end_matches('/');
        if base_url.is_empty() {
            eprintln!(
                "[publish-manifest] either --artifact-url or a non-empty --base-url is required"
            );
            return false;
        }
        format!("{base_url}/{claw}/{arch}/{version}/rootfs.ext4.zst")
    };

    // 6. Build the artifact manifest
    let artifact = ArtifactManifest {
        manifest_version: 1,
        claw: claw.clone(),
        version,
        arch,
        fingerprint: meta.fingerprint.to_string(),
        base_rootfs_version: detect_base_rootfs_version(assets_dir),
        sha256: zst_sha256,
        size_bytes: zst_size,
        url,
        published_at: core_rs::time::now_iso_secs(),
        channel: args.channel.clone(),
        base_rootfs_sha256: meta.base_rootfs_sha256,
        installer_plan_sha256: meta.installer_plan_sha256,
        kernel_sha256: meta.kernel_sha256,
        kernel_version: Some(core_rs::constants::KERNEL_FILENAME.into()),
        firecracker_version: Some(core_rs::constants::FIRECRACKER_VERSION.into()),
        runtime_min_version: None,
    };

    if let Err(e) = artifact.validate() {
        eprintln!("[publish-manifest] generated manifest is invalid: {e}");
        return false;
    }

    // 7. Serialize
    let json = serde_json::to_string_pretty(&artifact).expect("serialize manifest");

    // 8. Write to file or stdout
    match &args.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, format!("{json}\n")) {
                eprintln!("[publish-manifest] failed to write {}: {e}", path.display());
                return false;
            }
            eprintln!(
                "[publish-manifest] wrote {} (claw={claw}, fp={})",
                path.display(),
                artifact.fingerprint,
            );
        }
        None => {
            println!("{json}");
        }
    }

    true
}

/// Compute SHA-256 of a file, streaming to avoid loading it all in memory.
fn sha256_file_hex(path: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Best-effort detection of base rootfs version from filename.
fn detect_base_rootfs_version(assets_dir: &Path) -> String {
    let v2 = assets_dir.join("ubuntu-24.04-rootfs-v2.ext4");
    if v2.exists() {
        return "v2".into();
    }
    let v1 = assets_dir.join("ubuntu-24.04-rootfs.ext4");
    if v1.exists() {
        return "v1".into();
    }
    "unknown".into()
}

// ── BuildContext resolution ───────────────────────────────────────────────────

fn make_build_context(repo_root: &Path, home: &str, assets_dir: &Path) -> BuildContext {
    let fc_bin = std::env::var("FIRECRACKER_BIN").map_or_else(
        |_| PathBuf::from(home).join("firecracker/bin/firecracker"),
        PathBuf::from,
    );

    let kernel = std::env::var("FIRECRACKER_KERNEL_IMAGE")
        .map_or_else(|_| resolve_kernel_image(assets_dir), PathBuf::from);

    let base_rootfs = std::env::var("FIRECRACKER_BASE_ROOTFS").map_or_else(
        |_| {
            let v2 = assets_dir.join("ubuntu-24.04-rootfs-v2.ext4");
            let v1 = assets_dir.join("ubuntu-24.04-rootfs.ext4");
            if v2.exists() { v2 } else { v1 }
        },
        PathBuf::from,
    );

    let ssh_key = std::env::var("FIRECRACKER_SSH_KEY").map_or_else(
        |_| assets_dir.join("ubuntu-24.04-root.id_rsa"),
        PathBuf::from,
    );

    let slirp_bin =
        std::env::var("SLIRP4NETNS_BIN").map_or_else(|_| resolve_slirp4netns(), PathBuf::from);

    BuildContext {
        base_rootfs,
        assets_dir: assets_dir.to_path_buf(),
        build_dir: repo_root.join("firecracker/golden-build"),
        ssh_key,
        firecracker_bin: fc_bin,
        kernel_image: kernel,
        slirp_bin,
        vcpu_count: 2,
        mem_mib: 4096,
        repo_root: repo_root.to_path_buf(),
    }
}

fn resolve_kernel_image(assets_dir: &Path) -> PathBuf {
    // Look for vmlinux-* in assets dir
    if let Ok(rd) = std::fs::read_dir(assets_dir) {
        let mut candidates: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("vmlinux"))
            .map(|e| e.path())
            .collect();
        candidates.sort();
        if let Some(p) = candidates.last() {
            return p.clone();
        }
    }
    assets_dir.join("vmlinux-6.1.155")
}

fn resolve_slirp4netns() -> PathBuf {
    core_rs::os::resolve_slirp4netns().unwrap_or_else(|| std::path::PathBuf::from("slirp4netns"))
}

// ── Path utilities ────────────────────────────────────────────────────────────

fn resolve_claws(specified: &[String]) -> Vec<&'static str> {
    resolve_claws_from(specified, &all_claws())
}

/// Same as [`resolve_claws`] but accepts a custom `known` list. Used by
/// `build --verify-only` which must accept any manifest entry (detected /
/// available), not only the 8 builtin-plan claws.
fn resolve_claws_from(specified: &[String], known: &[&'static str]) -> Vec<&'static str> {
    if specified.is_empty() {
        return known.to_vec();
    }
    specified
        .iter()
        .filter_map(|s| known.iter().find(|&&c| c == s.as_str()).copied())
        .collect()
}

fn _log(prefix: &str, msg: &str) {
    let now = {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        format!("{h:02}:{m:02}:{s:02}")
    };
    eprintln!("[{now}] {prefix}: {msg}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_current_golden(assets_dir: &Path, claw: &str) {
        let fp = core_rs::artifact_meta::Fingerprint::new(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        let version_dir = core_rs::artifact_meta::golden_version_dir(assets_dir, claw, &fp);
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("rootfs.ext4"), b"fake-rootfs").unwrap();
        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: claw.to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            builder_version: "test".into(),
            created_at: "2026-04-01T00:00:00Z".into(),
        };
        core_rs::artifact_meta::write_meta(&version_dir.join("golden.meta.json"), &meta).unwrap();
        let current_link = core_rs::artifact_meta::golden_current_link(assets_dir, claw);
        core_rs::artifact_meta::update_current_link(&current_link, &fp).unwrap();
    }

    #[test]
    fn resolve_claws_empty_returns_all() {
        let claws = resolve_claws(&[]);
        assert_eq!(claws.len(), all_claws().len());
    }

    #[test]
    fn resolve_claws_filters_unknown() {
        let claws = resolve_claws(&["nullclaw".to_string(), "fakeclaw".to_string()]);
        assert_eq!(claws, vec!["nullclaw"]);
    }

    #[test]
    fn cmd_check_all_fresh_returns_false() {
        let d = TempDir::new().unwrap();
        let claws = all_claws();
        // Create fake images (age-only staleness — no hash needed)
        for claw in &claws {
            let img = d.path().join(format!("ubuntu-24.04-{claw}.ext4"));
            fs::write(&img, b"fake").unwrap();
        }
        let any_stale = cmd_check(&claws, d.path(), 7, false);
        assert!(!any_stale, "all should be fresh");
    }

    #[test]
    fn cmd_check_missing_image_returns_true() {
        let d = TempDir::new().unwrap();
        let any_stale = cmd_check(&["nullclaw"], d.path(), 7, false);
        assert!(any_stale, "missing image should be stale");
    }

    #[test]
    fn cmd_list_does_not_panic() {
        let d = TempDir::new().unwrap();
        cmd_list(d.path()); // just ensure no panic
    }

    /// `cmd_dag_check` should output valid JSON even when no goldens or build
    /// artifacts exist.  All claws should be reported as stale.
    #[test]
    fn cmd_dag_check_all_missing_outputs_valid_json() {
        let d = TempDir::new().unwrap();
        let assets_dir = d.path();

        // Minimal BuildContext — files don't need to exist for dag-check
        // (stale_reason_dag handles missing files gracefully).
        let ctx = BuildContext {
            base_rootfs: assets_dir.join("nonexistent-rootfs.ext4"),
            assets_dir: assets_dir.to_path_buf(),
            build_dir: d.path().join("build"),
            ssh_key: d.path().join("key"),
            firecracker_bin: d.path().join("fc"),
            kernel_image: d.path().join("vmlinux"),
            slirp_bin: d.path().join("slirp"),
            vcpu_count: 2,
            mem_mib: 4096,
            repo_root: d.path().to_path_buf(),
        };

        // Capture stdout by calling the internals directly.
        // (cmd_dag_check prints to stdout, which is hard to capture in-process,
        //  so test the underlying logic instead.)
        for claw in &all_claws() {
            let reason = imagebuild::runner::stale_reason_dag(claw, &ctx);
            assert!(
                reason.is_some(),
                "{claw} should be stale when nothing exists"
            );
        }
    }

    /// When a versionated golden exists with metadata, `stale_reason_dag` should
    /// detect it as fresh if all inputs match.
    #[test]
    fn dag_check_detects_fresh_golden() {
        let d = TempDir::new().unwrap();
        let assets_dir = d.path();

        // Create fake base rootfs and kernel
        let rootfs = d.path().join("base.ext4");
        let kernel = d.path().join("vmlinux");
        fs::write(&rootfs, b"rootfs-content").unwrap();
        fs::write(&kernel, b"kernel-content").unwrap();

        let claw = "nullclaw";

        // Compute the plan hash the same way imagebuilder does
        let plan = vmrunner_rs::installer_plan::get_plan(claw).unwrap();
        let plan_hash = plan.content_hash();
        let rootfs_sha = core_rs::artifact_meta::sha256_file(&rootfs).unwrap();
        let kernel_sha = core_rs::artifact_meta::sha256_file(&kernel).unwrap();

        // Compute expected fingerprint
        let fp = core_rs::artifact_meta::golden_fingerprint(&rootfs_sha, &plan_hash, &kernel_sha);

        // Create versionated golden with matching metadata
        let ver_dir = core_rs::artifact_meta::golden_version_dir(assets_dir, claw, &fp);
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(ver_dir.join("rootfs.ext4"), b"golden").unwrap();

        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: claw.to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: rootfs_sha,
            installer_plan_sha256: plan_hash,
            kernel_sha256: kernel_sha,
            builder_version: "test".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        core_rs::artifact_meta::write_meta(&ver_dir.join("golden.meta.json"), &meta).unwrap();
        let link = core_rs::artifact_meta::golden_current_link(assets_dir, claw);
        core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();

        let ctx = BuildContext {
            base_rootfs: rootfs,
            assets_dir: assets_dir.to_path_buf(),
            build_dir: d.path().join("build"),
            ssh_key: d.path().join("key"),
            firecracker_bin: d.path().join("fc"),
            kernel_image: kernel,
            slirp_bin: d.path().join("slirp"),
            vcpu_count: 2,
            mem_mib: 4096,
            repo_root: d.path().to_path_buf(),
        };

        let reason = imagebuild::runner::stale_reason_dag(claw, &ctx);
        assert!(
            reason.is_none(),
            "nullclaw should be fresh, got: {reason:?}"
        );
    }

    #[test]
    fn publish_manifest_requires_url_source() {
        let d = TempDir::new().unwrap();
        let assets_dir = d.path();
        make_current_golden(assets_dir, "hermes-agent");
        let zst_path = d.path().join("rootfs.ext4.zst");
        fs::write(&zst_path, b"compressed-rootfs").unwrap();
        let output = d.path().join("latest.json");

        let args = PublishManifestArgs {
            claw_type: "hermes-agent".into(),
            zst_file: zst_path,
            base_url: String::new(),
            artifact_url: None,
            channel: "stable".into(),
            output: Some(output),
        };

        assert!(!cmd_publish_manifest(&args, assets_dir));
    }

    #[test]
    fn publish_manifest_writes_valid_manifest_with_explicit_url() {
        let d = TempDir::new().unwrap();
        let assets_dir = d.path();
        make_current_golden(assets_dir, "hermes-agent");
        let zst_path = d.path().join("rootfs.ext4.zst");
        fs::write(&zst_path, b"compressed-rootfs").unwrap();
        let output = d.path().join("latest.json");

        let args = PublishManifestArgs {
            claw_type: "hermes-agent".into(),
            zst_file: zst_path,
            base_url: String::new(),
            artifact_url: Some("https://example.com/hermes-agent/rootfs.ext4.zst".into()),
            channel: "stable".into(),
            output: Some(output.clone()),
        };

        assert!(cmd_publish_manifest(&args, assets_dir));
        let json = fs::read_to_string(&output).unwrap();
        let manifest: core_rs::artifact_registry::ArtifactManifest =
            serde_json::from_str(&json).unwrap();
        assert!(manifest.validate().is_ok());
        assert_eq!(manifest.claw, "hermes-agent");
        assert_eq!(manifest.version, "0.7.0");
        assert_eq!(
            manifest.url,
            "https://example.com/hermes-agent/rootfs.ext4.zst"
        );
    }
}
