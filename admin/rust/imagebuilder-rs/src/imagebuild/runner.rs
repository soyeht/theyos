//! Golden image build orchestrator.
//!
//! Ties together vm.rs, ssh.rs, cache.rs and artifacts.rs into the full
//! end-to-end build pipeline for a single claw type.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::artifacts::{
    NODE_CLAWS, RUST_CLAWS, build_rootfs_path, file_size_human, golden_image_path, image_age_days,
};
use super::cache::{CacheKind, pull_cache, push_cache};
use super::error::{BuildError, BuildPhase, BuildResult};
use super::ssh::{ssh_exec_live, verify_binary, vm_cleanup, wait_for_ssh};
use super::vm::{VmConfig, boot_build_vm};

// ── BuildContext ──────────────────────────────────────────────────────────────

/// All paths and settings needed for a golden image build.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// Path to base rootfs (read-only source).
    pub base_rootfs: PathBuf,
    /// Directory for golden image artifacts.
    pub assets_dir: PathBuf,
    /// Scratch directory for build sockets/logs/temp rootfs.
    pub build_dir: PathBuf,
    /// SSH private key for build VM.
    pub ssh_key: PathBuf,
    /// Firecracker binary.
    pub firecracker_bin: PathBuf,
    /// vmlinux kernel image.
    pub kernel_image: PathBuf,
    /// slirp4netns binary.
    pub slirp_bin: PathBuf,
    /// VM vCPU count.
    pub vcpu_count: u32,
    /// VM memory in MiB.
    pub mem_mib: u32,
    /// Repository root (for sudo-safe home resolution).
    pub repo_root: PathBuf,
}

// ── Build entry point ─────────────────────────────────────────────────────────

/// Build a golden image for `claw_type`.
///
/// Steps:
///   1. Preflight checks
///   2. Copy base rootfs to build workspace
///   3. Boot build VM
///   4. Wait for SSH
///   5. Push package manager caches (best-effort)
///   6. Run `InstallerPlan` steps via SSH
///   7. Verify installed binary
///   8. Pull updated caches (best-effort)
///   9. Cleanup temp files in VM
///  10. Shutdown VM
///  11. Move artifact to assets dir
#[allow(clippy::too_many_lines)]
pub async fn build_golden_image(claw: &str, ctx: &BuildContext) -> BuildResult<()> {
    let start = Instant::now();
    eprintln!("[golden][{claw}] ===== building golden image =====");

    // 1. Preflight
    preflight(claw, ctx)?;

    // 2. Copy base rootfs to build workspace
    let build_rootfs = build_rootfs_path(&ctx.build_dir, claw);
    copy_rootfs(claw, &ctx.base_rootfs, &build_rootfs, &ctx.ssh_key)?;

    // 2b. Expand build rootfs to 8 GiB so installers have room to work.
    //     The final golden image will be shrunk back with resize2fs -M later.
    expand_rootfs_for_build(claw, &build_rootfs)?;

    // 3-4. Boot VM and wait for SSH
    let vm_config = VmConfig {
        firecracker_bin: ctx.firecracker_bin.clone(),
        kernel_image: ctx.kernel_image.clone(),
        rootfs_path: build_rootfs.clone(),
        build_dir: ctx.build_dir.join(claw),
        slirp_bin: ctx.slirp_bin.clone(),
        vcpu_count: ctx.vcpu_count,
        mem_mib: ctx.mem_mib,
        ..Default::default()
    };

    eprintln!("[golden][{claw}] phase=boot-vm");
    let mut vm = boot_build_vm(vm_config, claw).await?;

    eprintln!("[golden][{claw}] phase=wait-ssh");
    let sess = match wait_for_ssh(
        vm.ssh_port,
        &ctx.ssh_key,
        std::time::Duration::from_secs(120),
        claw,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            vm.cleanup();
            return Err(e);
        }
    };

    // 5. Push caches (best-effort — errors are logged, not fatal)
    eprintln!("[golden][{claw}] phase=push-cache");
    if RUST_CLAWS.contains(&claw) {
        push_cache(
            CacheKind::Cargo,
            &sess,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }
    if NODE_CLAWS.contains(&claw) {
        push_cache(
            CacheKind::Npm,
            &sess,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }

    // 6. Run InstallerPlan steps via SSH (P28 — no shell scripts)
    eprintln!("[golden][{claw}] phase=run-installer (InstallerPlan, this may take a while)");
    let plan = vmrunner_rs::installer_plan::get_plan(claw).ok_or_else(|| {
        let err = BuildError::new(
            BuildPhase::RunInstaller,
            claw,
            format!("no InstallerPlan defined for claw type: {claw}"),
        );
        vm.cleanup();
        err
    })?;

    for (i, step) in plan.steps.iter().enumerate() {
        let label = format!("[{}/{}] {}", i + 1, plan.steps.len(), step.phase);

        // Idempotency check
        if let Some(check) = step.idempotency_check {
            let check_ok = ssh_exec_live(&sess, check, claw, BuildPhase::RunInstaller).await;
            if check_ok.is_ok() {
                eprintln!("[golden][{claw}] {label}: skipped (idempotent)");
                continue;
            }
        }

        // Retry loop
        let mut last_err = None;
        for attempt in 0..=step.max_retries {
            if attempt > 0 {
                eprintln!(
                    "[golden][{claw}] {label}: retry {attempt}/{}",
                    step.max_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            eprintln!("[golden][{claw}] {label}: running...");
            match ssh_exec_live(&sess, &step.command, claw, BuildPhase::RunInstaller).await {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if let Some(e) = last_err {
            eprintln!("[golden][{claw}] {label}: FAILED");
            vm.cleanup();
            return Err(e);
        }
    }

    // 7. Verify binary
    //    For tier:available claws the installed binary name can differ from
    //    the claw name (e.g. edgeclaw → openclaw, geneclaw → nanobot). Fall
    //    back to the claw name for builtins (install=None) and for entries
    //    with an empty entry_point.
    eprintln!("[golden][{claw}] phase=verify-binary");
    let binary_name = core_rs::manifest::get(claw)
        .and_then(|e| e.install.map(|ic| ic.entry_point))
        .filter(|s| !s.is_empty())
        .unwrap_or(claw);
    let version = match verify_binary(&sess, binary_name, claw).await {
        Ok(v) => v,
        Err(e) => {
            vm.cleanup();
            return Err(e);
        }
    };
    eprintln!("[golden][{claw}] binary verified: {version}");

    // 8. Pull caches back (best-effort)
    eprintln!("[golden][{claw}] phase=pull-cache");
    if RUST_CLAWS.contains(&claw) {
        pull_cache(
            CacheKind::Cargo,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }
    if NODE_CLAWS.contains(&claw) {
        pull_cache(
            CacheKind::Npm,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }

    // 9. Cleanup inside VM (reduce image size)
    eprintln!("[golden][{claw}] phase=cleanup");
    vm_cleanup(&sess, claw).await;

    // 10. Shutdown VM (also calls cleanup)
    eprintln!("[golden][{claw}] phase=shutdown");
    vm.shutdown();

    // 10b. Shrink rootfs back to minimum size to save disk space.
    shrink_rootfs(claw, &build_rootfs);

    // 11. Compute fingerprint and publish to versionated directory
    eprintln!("[golden][{claw}] phase=publish-artifact");

    // Compute fingerprint inputs:
    //  - base_rootfs_sha256: hash of the source rootfs used for the build
    //  - installer_plan_sha256: content_hash() of the InstallerPlan (env vars already resolved)
    //  - kernel_sha256: hash of the vmlinux kernel image
    let base_rootfs_sha256 =
        core_rs::artifact_meta::sha256_file(&ctx.base_rootfs).map_err(|e| {
            BuildError::new(
                BuildPhase::PublishArtifact,
                claw,
                format!("hash base rootfs: {e}"),
            )
        })?;
    let installer_plan_sha256 = plan.content_hash();
    let kernel_sha256 = core_rs::artifact_meta::sha256_file(&ctx.kernel_image).map_err(|e| {
        BuildError::new(
            BuildPhase::PublishArtifact,
            claw,
            format!("hash kernel: {e}"),
        )
    })?;

    let fingerprint = core_rs::artifact_meta::golden_fingerprint(
        &base_rootfs_sha256,
        &installer_plan_sha256,
        &kernel_sha256,
    );

    eprintln!(
        "[golden][{claw}] fingerprint={} (rootfs={}, plan={}, kernel={})",
        fingerprint.short(),
        &base_rootfs_sha256[..12],
        &installer_plan_sha256[..12],
        &kernel_sha256[..12],
    );

    // Create versionated directory: <assets_dir>/goldens/<claw>/<fingerprint>/
    let version_dir =
        core_rs::artifact_meta::golden_version_dir(&ctx.assets_dir, claw, &fingerprint);
    fs::create_dir_all(&version_dir).map_err(|e| {
        BuildError::new(
            BuildPhase::PublishArtifact,
            claw,
            format!("mkdir {}: {e}", version_dir.display()),
        )
    })?;

    // Move rootfs into versionated directory
    let output_path = version_dir.join("rootfs.ext4");
    fs::rename(&build_rootfs, &output_path).map_err(|e| {
        BuildError::new(
            BuildPhase::PublishArtifact,
            claw,
            format!(
                "mv {} -> {}: {e}",
                build_rootfs.display(),
                output_path.display()
            ),
        )
    })?;

    // Write golden.meta.json
    let builder_version = option_env!("CARGO_PKG_VERSION")
        .unwrap_or("unknown")
        .to_string();
    let created_at = core_rs::time::now_iso_secs();
    let meta = core_rs::artifact_meta::GoldenMeta {
        claw_type: claw.to_string(),
        fingerprint: fingerprint.clone(),
        base_rootfs_sha256,
        installer_plan_sha256,
        kernel_sha256,
        builder_version,
        created_at,
    };
    core_rs::artifact_meta::write_meta(&version_dir.join("golden.meta.json"), &meta).map_err(
        |e| {
            BuildError::new(
                BuildPhase::PublishArtifact,
                claw,
                format!("write golden.meta.json: {e}"),
            )
        },
    )?;

    // Update `current` symlink
    let current_link = core_rs::artifact_meta::golden_current_link(&ctx.assets_dir, claw);
    core_rs::artifact_meta::update_current_link(&current_link, &fingerprint).map_err(|e| {
        BuildError::new(
            BuildPhase::PublishArtifact,
            claw,
            format!("update current symlink: {e}"),
        )
    })?;

    // Also write to legacy flat path for backward compatibility during migration.
    // This ensures vmrunner and e2e-runner can still find the golden image at
    // the old location until all consumers are migrated.
    let legacy_path = golden_image_path(&ctx.assets_dir, claw);
    if let Err(e) = fs::copy(&output_path, &legacy_path) {
        eprintln!(
            "[golden][{claw}] WARNING: failed to write legacy path {}: {e}",
            legacy_path.display()
        );
        // Non-fatal: the versionated path is the source of truth
    }

    let elapsed = start.elapsed().as_secs();
    let size = file_size_human(&output_path);
    eprintln!(
        "[golden][{claw}] ===== done in {elapsed}s -- {size} -> {} (fp: {}) =====",
        version_dir.display(),
        fingerprint.short(),
    );

    Ok(())
}

// ── Verify-only entry point ──────────────────────────────────────────────────

/// Disposable smoke test for a claw's install plan — the `--verify-only`
/// counterpart of [`build_golden_image`].
///
/// Reuses steps 1-6 of the golden build pipeline (preflight → boot VM →
/// wait for SSH → run `InstallerPlan`), then skips publishing and instead:
///   7. Starts the claw in the background (`nohup <entry_point> &`).
///   8. Sleeps 60s (soak).
///   9. Runs `kill -0 <pid>` to check the process survived.
///  10. Shuts down the VM.
///  11. Deletes the scratch rootfs — nothing is published to `goldens/`.
///
/// Designed to be invoked as a subprocess by
/// `soyeht-rs::sandbox::firecracker`, which parses the textual
/// `VERIFY_OK` / `VERIFY_FAIL:<reason>` stdout markers emitted by
/// `main.rs::cmd_build`.
#[allow(clippy::too_many_lines)]
pub async fn verify_golden_image(claw: &str, ctx: &BuildContext) -> BuildResult<()> {
    let start = Instant::now();
    eprintln!("[verify][{claw}] ===== smoke-testing install plan =====");

    // 1. Preflight — identical to build_golden_image
    preflight(claw, ctx)?;

    // 2. Copy base rootfs to scratch workspace (will be deleted, not published)
    let build_rootfs = build_rootfs_path(&ctx.build_dir, claw);
    copy_rootfs(claw, &ctx.base_rootfs, &build_rootfs, &ctx.ssh_key)?;

    // 2b. Expand so installers have room to work
    expand_rootfs_for_build(claw, &build_rootfs)?;

    // 3-4. Boot VM + wait for SSH
    let vm_config = VmConfig {
        firecracker_bin: ctx.firecracker_bin.clone(),
        kernel_image: ctx.kernel_image.clone(),
        rootfs_path: build_rootfs.clone(),
        build_dir: ctx.build_dir.join(claw),
        slirp_bin: ctx.slirp_bin.clone(),
        vcpu_count: ctx.vcpu_count,
        mem_mib: ctx.mem_mib,
        ..Default::default()
    };

    eprintln!("[verify][{claw}] phase=boot-vm");
    let mut vm = boot_build_vm(vm_config, claw).await?;

    eprintln!("[verify][{claw}] phase=wait-ssh");
    let sess = match wait_for_ssh(
        vm.ssh_port,
        &ctx.ssh_key,
        std::time::Duration::from_secs(120),
        claw,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            vm.cleanup();
            let _ = std::fs::remove_file(&build_rootfs);
            return Err(e);
        }
    };

    // 5. Push caches (best-effort) — speeds up rust/node installs under verify too
    eprintln!("[verify][{claw}] phase=push-cache");
    if RUST_CLAWS.contains(&claw) {
        push_cache(
            CacheKind::Cargo,
            &sess,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }
    if NODE_CLAWS.contains(&claw) {
        push_cache(
            CacheKind::Npm,
            &sess,
            &ctx.ssh_key,
            vm.ssh_port,
            claw,
            &ctx.repo_root,
        )
        .await;
    }

    // 6. Run InstallerPlan
    eprintln!("[verify][{claw}] phase=run-installer");
    let plan = vmrunner_rs::installer_plan::get_plan(claw).ok_or_else(|| {
        let err = BuildError::new(
            BuildPhase::RunInstaller,
            claw,
            format!("no InstallerPlan defined for claw type: {claw}"),
        );
        vm.cleanup();
        err
    })?;

    for (i, step) in plan.steps.iter().enumerate() {
        let label = format!("[{}/{}] {}", i + 1, plan.steps.len(), step.phase);

        if let Some(check) = step.idempotency_check {
            let check_ok = ssh_exec_live(&sess, check, claw, BuildPhase::RunInstaller).await;
            if check_ok.is_ok() {
                eprintln!("[verify][{claw}] {label}: skipped (idempotent)");
                continue;
            }
        }

        let mut last_err = None;
        for attempt in 0..=step.max_retries {
            if attempt > 0 {
                eprintln!(
                    "[verify][{claw}] {label}: retry {attempt}/{}",
                    step.max_retries
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            eprintln!("[verify][{claw}] {label}: running...");
            match ssh_exec_live(&sess, &step.command, claw, BuildPhase::RunInstaller).await {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if let Some(e) = last_err {
            eprintln!("[verify][{claw}] {label}: FAILED");
            vm.cleanup();
            let _ = std::fs::remove_file(&build_rootfs);
            return Err(e);
        }
    }

    // 7. Smoke test — two modes based on `manifest.run_cmd`:
    //    - empty  ⇒ install-only verify; skip the 60s soak. Many claws are
    //      CLI tools that print help and exit when invoked bare, so a naive
    //      `nohup {claw}` would always fail.
    //    - non-empty ⇒ start the daemon explicitly, 60s soak, `kill -0` check.
    let run_cmd = core_rs::manifest::get(claw).map_or("", |e| e.run_cmd);

    if run_cmd.is_empty() {
        eprintln!(
            "[verify][{claw}] phase=smoke-test: skipped (install-only verify — \
             no run_cmd declared in manifest.yml)"
        );
    } else {
        eprintln!("[verify][{claw}] phase=smoke-test: starting `{run_cmd}`");
        let start_cmd = format!("nohup {run_cmd} > /tmp/claw.log 2>&1 < /dev/null & echo $!");
        let pid_out = match sess.exec_install(&start_cmd).await {
            Ok(s) => s,
            Err(e) => {
                vm.cleanup();
                let _ = std::fs::remove_file(&build_rootfs);
                return Err(BuildError::new(
                    BuildPhase::SmokeTest,
                    claw,
                    format!("start claw: {e}"),
                ));
            }
        };
        let pid = pid_out.trim().to_string();
        eprintln!("[verify][{claw}] started pid={pid}, soaking 60s...");

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        if let Err(e) = sess.exec(&format!("kill -0 {pid}")).await {
            // Best-effort log tail to aid debugging of verify failures.
            let tail = sess
                .exec("tail -n 50 /tmp/claw.log")
                .await
                .unwrap_or_default();
            vm.cleanup();
            let _ = std::fs::remove_file(&build_rootfs);
            return Err(BuildError::new(
                BuildPhase::SmokeTest,
                claw,
                format!("claw died during 60s soak: {e}"),
            )
            .with_stdout(tail));
        }
        eprintln!("[verify][{claw}] pid={pid} survived 60s soak");
    }

    // 8. Shutdown + cleanup — nothing to publish.
    eprintln!("[verify][{claw}] phase=shutdown");
    vm.shutdown();
    let _ = std::fs::remove_file(&build_rootfs);

    let elapsed = start.elapsed().as_secs();
    eprintln!(
        "[verify][{claw}] ===== done in {elapsed}s (verify-only, no artifact published) ====="
    );
    Ok(())
}

// ── Phase implementations ─────────────────────────────────────────────────────

fn preflight(claw: &str, ctx: &BuildContext) -> BuildResult<()> {
    eprintln!("[golden][{claw}] phase=preflight");

    let checks: &[(&Path, &str)] = &[
        (&ctx.firecracker_bin, "firecracker binary"),
        (&ctx.kernel_image, "kernel image"),
        (&ctx.base_rootfs, "base rootfs"),
        (&ctx.ssh_key, "ssh private key"),
        (&ctx.slirp_bin, "slirp4netns binary"),
    ];

    for (path, label) in checks {
        if !path.exists() {
            return Err(BuildError::new(
                BuildPhase::Preflight,
                claw,
                format!("{label} not found: {}", path.display()),
            ));
        }
    }

    // Verify an InstallerPlan exists for this claw type
    if vmrunner_rs::installer_plan::get_plan(claw).is_none() {
        return Err(BuildError::new(
            BuildPhase::Preflight,
            claw,
            format!("no InstallerPlan defined for claw type: {claw}"),
        ));
    }

    fs::create_dir_all(&ctx.build_dir).map_err(|e| {
        BuildError::new(
            BuildPhase::Preflight,
            claw,
            format!("create build_dir {}: {e}", ctx.build_dir.display()),
        )
    })?;

    eprintln!("[golden][{claw}] preflight OK");
    Ok(())
}

/// Final golden image size (10 GiB).
///
/// Firecracker locks the virtio-block device size at snapshot time, so the
/// guest can never see more space than this. 10 GiB gives ~6 GB free for
/// openclaw (the largest claw at ~3.6 GB) and ~9.5 GB free for picoclaw.
/// That is enough for Node.js + Claude Code + `OpenCode` + Codex.
///
/// The file on the host is sparse (`cp --sparse=always`), so only the
/// actually-written blocks consume real disk — a 10 GiB image that uses
/// 500 MB of data only occupies ~500 MB on the host.
const GOLDEN_ROOTFS_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

/// Expand the build rootfs to [`GOLDEN_ROOTFS_BYTES`] so that installers
/// (especially openclaw's pnpm build) have enough disk space.
fn expand_rootfs_for_build(claw: &str, rootfs: &Path) -> BuildResult<()> {
    let current_size = fs::metadata(rootfs).map_or(0, |m| m.len());

    if current_size >= GOLDEN_ROOTFS_BYTES {
        return Ok(()); // already large enough
    }

    eprintln!("[golden][{claw}] phase=expand-rootfs ({current_size} -> {GOLDEN_ROOTFS_BYTES})");

    let f = fs::OpenOptions::new()
        .write(true)
        .open(rootfs)
        .map_err(|e| {
            BuildError::new(
                BuildPhase::CopyRootfs,
                claw,
                format!("open for expand: {e}"),
            )
        })?;
    f.set_len(GOLDEN_ROOTFS_BYTES).map_err(|e| {
        BuildError::new(
            BuildPhase::CopyRootfs,
            claw,
            format!(
                "set_len to {}G: {e}",
                GOLDEN_ROOTFS_BYTES / 1024 / 1024 / 1024
            ),
        )
    })?;
    drop(f);

    // Resize the filesystem to fill the new space
    let rootfs_str = rootfs.to_str().unwrap_or("");
    let status = std::process::Command::new("resize2fs")
        .args([rootfs_str])
        .status()
        .map_err(|e| {
            BuildError::new(
                BuildPhase::CopyRootfs,
                claw,
                format!("resize2fs spawn: {e}"),
            )
        })?;

    if !status.success() {
        eprintln!("[golden][{claw}] resize2fs returned non-zero, trying e2fsck + resize2fs");
        let _ = std::process::Command::new("e2fsck")
            .args(["-fy", rootfs_str])
            .status();
        let retry = std::process::Command::new("resize2fs")
            .args([rootfs_str])
            .status()
            .map_err(|e| {
                BuildError::new(
                    BuildPhase::CopyRootfs,
                    claw,
                    format!("resize2fs retry: {e}"),
                )
            })?;
        if !retry.success() {
            return Err(BuildError::new(
                BuildPhase::CopyRootfs,
                claw,
                "resize2fs failed after e2fsck".to_string(),
            ));
        }
    }

    eprintln!(
        "[golden][{claw}] rootfs expanded to {}G for build",
        GOLDEN_ROOTFS_BYTES / 1024 / 1024 / 1024
    );
    Ok(())
}

/// Finalize the golden rootfs to exactly [`GOLDEN_ROOTFS_BYTES`].
///
/// After the build, the filesystem may have temporary files and cache that
/// bloat the used space. This function runs `e2fsck` and then ensures the
/// filesystem + file are exactly 10 GiB — the size Firecracker will bake
/// into the snapshot's virtio-block geometry.
///
/// Best-effort — failures are logged but do not abort the build.
fn shrink_rootfs(claw: &str, rootfs: &Path) {
    eprintln!(
        "[golden][{claw}] phase=finalize-rootfs (target={}G)",
        GOLDEN_ROOTFS_BYTES / 1024 / 1024 / 1024
    );

    let rootfs_str = rootfs.to_str().unwrap_or("");

    // fsck first (required before any resize2fs operation)
    let _ = std::process::Command::new("e2fsck")
        .args(["-fy", rootfs_str])
        .status();

    // Resize filesystem to exactly GOLDEN_ROOTFS_BYTES.
    // resize2fs accepts a size in filesystem blocks (4K each).
    let target_blocks = GOLDEN_ROOTFS_BYTES / 4096;
    let target_str = format!("{target_blocks}");

    let status = std::process::Command::new("resize2fs")
        .args([rootfs_str, &target_str])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Truncate/extend the file to the exact target size.
            if let Ok(f) = fs::OpenOptions::new().write(true).open(rootfs) {
                let _ = f.set_len(GOLDEN_ROOTFS_BYTES);
                eprintln!(
                    "[golden][{claw}] rootfs finalized to {}G",
                    GOLDEN_ROOTFS_BYTES / 1024 / 1024 / 1024
                );
            }
        }
        _ => {
            eprintln!(
                "[golden][{claw}] resize2fs to {}G failed (non-fatal, keeping current size)",
                GOLDEN_ROOTFS_BYTES / 1024 / 1024 / 1024
            );
        }
    }
}

fn copy_rootfs(claw: &str, src: &Path, dst: &Path, _ssh_key: &Path) -> BuildResult<()> {
    eprintln!("[golden][{claw}] phase=copy-rootfs");
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).ok();
    }
    // Try reflink first (fast on btrfs/xfs), fall back to regular copy
    let reflink_ok = std::process::Command::new("cp")
        .args([
            "--reflink=auto",
            src.to_str().unwrap_or(""),
            dst.to_str().unwrap_or(""),
        ])
        .status()
        .is_ok_and(|s| s.success());

    if !reflink_ok {
        fs::copy(src, dst).map_err(|e| {
            BuildError::new(
                BuildPhase::CopyRootfs,
                claw,
                format!("copy {} -> {}: {e}", src.display(), dst.display()),
            )
        })?;
    }

    eprintln!("[golden][{claw}] rootfs copied to {}", dst.display());
    Ok(())
}

// ── Staleness check used from main ───────────────────────────────────────────

/// Returns a non-empty reason string if the image is stale, empty if fresh.
///
/// Staleness criteria (DAG-based with legacy fallback):
///   1. `--force` was passed
///   2. No golden image exists (neither versionated nor legacy)
///   3. If `ctx` is provided: DAG-based fingerprint mismatch (input changed)
///   4. Legacy fallback: image age >= `max_age_days`
pub fn stale_reason(claw: &str, assets_dir: &Path, max_age_days: u64, force: bool) -> String {
    if force {
        return "forced".to_string();
    }

    // Try DAG-based staleness first (versionated layout).
    // If we have metadata + a current symlink the image is managed by DAG;
    // the lightweight `check` command considers it fresh.  Full DAG staleness
    // analysis is done by `artifacts sync`.
    if core_rs::artifact_meta::read_current_golden_meta(assets_dir, claw).is_some()
        && core_rs::artifact_meta::golden_current_rootfs(assets_dir, claw).is_some()
    {
        return String::new(); // managed by DAG, considered fresh
    }

    // Fallback: check legacy flat path + age-based staleness
    let img = golden_image_path(assets_dir, claw);
    if !img.exists() {
        // Also check if a versionated golden exists without legacy flat file
        if core_rs::artifact_meta::golden_current_rootfs(assets_dir, claw).is_some() {
            return String::new(); // versionated golden exists
        }
        return "missing".to_string();
    }
    let age = image_age_days(assets_dir, claw);
    if age >= max_age_days {
        return format!("age={age}d >= {max_age_days}d");
    }
    String::new()
}

/// DAG-aware staleness check.
///
/// Returns the specific [`StaleReason`] if the golden is stale, or `None` if fresh.
/// Requires the build context to compute the expected fingerprint from current inputs.
///
/// This is used by `artifacts sync` (Phase 6) for precise, field-level staleness detection.
pub fn stale_reason_dag(
    claw: &str,
    ctx: &BuildContext,
) -> Option<core_rs::artifact_meta::StaleReason> {
    use core_rs::artifact_meta;

    let current_meta = artifact_meta::read_current_golden_meta(&ctx.assets_dir, claw);

    // No metadata at all — check legacy flat path
    if current_meta.is_none() {
        let legacy = golden_image_path(&ctx.assets_dir, claw);
        if legacy.exists() {
            return Some(artifact_meta::StaleReason::NoMetadata);
        }
        return Some(artifact_meta::StaleReason::Missing);
    }

    // Compute expected fingerprint from current inputs
    let Ok(base_rootfs_sha256) = artifact_meta::sha256_file(&ctx.base_rootfs) else {
        return Some(artifact_meta::StaleReason::Missing);
    };
    let plan = vmrunner_rs::installer_plan::get_plan(claw)?;
    let installer_plan_sha256 = plan.content_hash();
    let Ok(kernel_sha256) = artifact_meta::sha256_file(&ctx.kernel_image) else {
        return Some(artifact_meta::StaleReason::Missing);
    };

    artifact_meta::golden_stale_reason_detailed(
        current_meta.as_ref(),
        &base_rootfs_sha256,
        &installer_plan_sha256,
        &kernel_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_fake_image(dir: &Path, claw: &str) {
        let img = golden_image_path(dir, claw);
        fs::write(&img, b"fake").unwrap();
    }

    /// Set up a versionated golden with metadata and `current` symlink.
    fn make_versionated_golden(assets_dir: &Path, claw: &str) {
        let fp = core_rs::artifact_meta::Fingerprint::new("abc123def456");
        let ver_dir = core_rs::artifact_meta::golden_version_dir(assets_dir, claw, &fp);
        fs::create_dir_all(&ver_dir).unwrap();
        fs::write(ver_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: claw.to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "rootfs_hash".into(),
            installer_plan_sha256: "plan_hash".into(),
            kernel_sha256: "kernel_hash".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        core_rs::artifact_meta::write_meta(&ver_dir.join("golden.meta.json"), &meta).unwrap();

        let link = core_rs::artifact_meta::golden_current_link(assets_dir, claw);
        core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();
    }

    #[test]
    fn stale_missing_image() {
        let d = TempDir::new().unwrap();
        let reason = stale_reason("nullclaw", d.path(), 7, false);
        assert_eq!(reason, "missing");
    }

    #[test]
    fn stale_force_overrides_fresh() {
        let d = TempDir::new().unwrap();
        make_fake_image(d.path(), "nullclaw");
        let reason = stale_reason("nullclaw", d.path(), 7, true);
        assert_eq!(reason, "forced");
    }

    #[test]
    fn fresh_legacy_image_returns_empty() {
        let d = TempDir::new().unwrap();
        make_fake_image(d.path(), "nullclaw");
        let reason = stale_reason("nullclaw", d.path(), 7, false);
        assert!(reason.is_empty(), "expected fresh, got: {reason}");
    }

    #[test]
    fn fresh_versionated_image_returns_empty() {
        let d = TempDir::new().unwrap();
        make_versionated_golden(d.path(), "nullclaw");
        let reason = stale_reason("nullclaw", d.path(), 7, false);
        assert!(
            reason.is_empty(),
            "versionated golden should be fresh, got: {reason}"
        );
    }

    #[test]
    fn versionated_without_legacy_returns_empty() {
        // Only versionated layout, no legacy flat file
        let d = TempDir::new().unwrap();
        make_versionated_golden(d.path(), "picoclaw");
        // No legacy file — should still report fresh
        let reason = stale_reason("picoclaw", d.path(), 7, false);
        assert!(
            reason.is_empty(),
            "expected fresh from versionated, got: {reason}"
        );
    }

    #[test]
    fn stale_force_overrides_versionated() {
        let d = TempDir::new().unwrap();
        make_versionated_golden(d.path(), "nullclaw");
        let reason = stale_reason("nullclaw", d.path(), 7, true);
        assert_eq!(reason, "forced");
    }
}
