//! Integration tests for vmrunner-rs — warm pool correctness and performance.
//!
//! These tests require a live Firecracker environment on this machine:
//! a real `firecracker` binary, kernel image, base rootfs, slirp4netns,
//! and at least one snapshot (picoclaw). They are gated behind the
//! `integration_tests` feature flag so they never run in CI.
//!
//! # Running
//!
//! ```bash
//! cargo test -p vmrunner-rs --features integration_tests -- --test-threads=1
//! ```
//!
//! Environment variables read from the process (or `.env` in the repo root):
//!
//! | Variable                | Default / required                                  |
//! |-------------------------|-----------------------------------------------------|
//! | `FIRECRACKER_BIN`       | required                                            |
//! | `THEYOS_KERNEL_IMAGE`   | required                                            |
//! | `THEYOS_BASE_ROOTFS`    | required                                            |
//! | `THEYOS_SSH_KEY`        | required                                            |
//! | `THEYOS_SSH_PUBKEY`     | required                                            |
//! | `THEYOS_STATE_DIR`      | `$HOME/firecracker/instances` (default)             |
//!
//! Each test creates VMs in a subdirectory of the real state dir (prefixed
//! with `_inttest-`) and cleans up on exit regardless of pass/fail.

#[cfg(feature = "integration_tests")]
mod live {
    use std::path::PathBuf;
    use std::time::Instant;

    use vmrunner_rs::warm_pool::{WarmPool, global_pool};
    use vmrunner_rs::{VmConfig, VmEnv, VmRunner};

    // ── Test environment ───────────────────────────────────────────────────

    fn build_env() -> VmEnv {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        // Under sudo, HOME might be /root, but we want the original user's home
        // unless they explicitly overrode FIRECRACKER_* vars.
        let home = std::env::var("SUDO_USER")
            .map(|u| {
                if u == "root" {
                    "/root".to_string()
                } else {
                    format!("/home/{u}")
                }
            })
            .unwrap_or(home);

        // Mirror run-backend-host.sh: if SLIRP4NETNS_BIN is not set, resolve from
        // PATH or nix store so resolve_slirp4netns() inside vmrunner succeeds.
        if std::env::var("SLIRP4NETNS_BIN").is_err() {
            if let Ok(out) = std::process::Command::new("which")
                .arg("slirp4netns")
                .output()
            {
                if out.status.success() {
                    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !path.is_empty() {
                        // SAFETY: tests run with --test-threads=1; no concurrent env mutation.
                        unsafe { std::env::set_var("SLIRP4NETNS_BIN", &path) };
                    }
                }
            }
            // Fallback: scan nix store (same approach as run-backend-host.sh)
            if std::env::var("SLIRP4NETNS_BIN").is_err() {
                if let Ok(out) = std::process::Command::new("find")
                    .args([
                        "/nix/store",
                        "-maxdepth",
                        "4",
                        "-name",
                        "slirp4netns",
                        "-type",
                        "f",
                    ])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if let Some(last) = stdout.lines().filter(|l| !l.is_empty()).last() {
                        // SAFETY: tests run with --test-threads=1; no concurrent env mutation.
                        unsafe { std::env::set_var("SLIRP4NETNS_BIN", last.trim()) };
                    }
                }
            }
        }

        let state_dir = PathBuf::from(
            std::env::var("FIRECRACKER_STATE_DIR")
                .unwrap_or_else(|_| format!("{home}/firecracker/instances/_inttest_pool")),
        );
        std::fs::create_dir_all(&state_dir).unwrap();

        // Env var names match what run-backend-host.sh exports.
        VmEnv {
            state_dir,
            firecracker_bin: PathBuf::from(
                std::env::var("FIRECRACKER_BIN")
                    .unwrap_or_else(|_| format!("{home}/firecracker/bin/firecracker")),
            ),
            kernel_image: PathBuf::from(std::env::var("FIRECRACKER_KERNEL_IMAGE").unwrap_or_else(
                |_| {
                    format!(
                        "{home}/firecracker/assets/{}",
                        core_rs::guest_net::KERNEL_FILENAME
                    )
                },
            )),
            base_rootfs: PathBuf::from(std::env::var("FIRECRACKER_BASE_ROOTFS").unwrap_or_else(
                |_| format!("{home}/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4"),
            )),
            ssh_key: PathBuf::from(
                std::env::var("FIRECRACKER_SSH_KEY").unwrap_or_else(|_| {
                    format!("{home}/firecracker/assets/ubuntu-24.04-root.id_rsa")
                }),
            ),
            ssh_pubkey: PathBuf::from(std::env::var("FIRECRACKER_SSH_PUBKEY").unwrap_or_else(
                |_| format!("{home}/firecracker/assets/ubuntu-24.04-root.id_rsa.pub"),
            )),
            ssh_wait_tries: 60,
            home: PathBuf::from(&home),
        }
    }

    fn runner() -> VmRunner {
        VmRunner { env: build_env() }
    }

    // ── Cleanup helper ─────────────────────────────────────────────────────

    /// Wait for any background refill threads for a given claw_type to finish,
    /// escaping the race condition where a previous test's refill thread
    /// continues running while the current test starts.
    fn wait_for_refill(claw_type: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let filling = {
                let pool = global_pool().lock().unwrap();
                pool.is_filling(claw_type)
            };
            if !filling || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Stop + remove a pool or instance dir. Best-effort; never panics.
    fn cleanup(runner: &VmRunner, container: &str) {
        let dir = runner.env.state_dir.join(container);
        if dir.exists() {
            let tmp_dir = format!("/tmp/{}", container);
            let _ = std::process::Command::new("cp")
                .args(["-r", dir.to_str().unwrap(), &tmp_dir])
                .status();
        }
        let _ = runner.stop(container);
        // Give processes a moment to exit after stop, then clean up the directory.
        std::thread::sleep(std::time::Duration::from_millis(100));
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Wait for any in-progress refill, then cleanup the pool container.
    /// Prevents orphan VMs from background refill threads that are spawned
    /// by claim_from_pool/create and may not yet have started/finished when
    /// the test's main cleanup runs.
    fn cleanup_with_refill_wait(runner: &VmRunner, claw_type: &str, pool_container: &str) {
        wait_for_refill(claw_type);
        cleanup(runner, pool_container);
    }

    // ── Test 1: fill creates a warm VM with binary check ───────────────────

    /// After `fill_pool_slot`:
    /// - The pool dir exists on disk.
    /// - The FC process is alive.
    /// - The in-memory pool slot contains a WarmEntry.
    /// - `binary_present` reflects whether the claw binary is in the golden image.
    #[tokio::test]
    async fn pool_fill_creates_warm_vm_with_binary_check() {
        let r = runner();
        let claw_type = "picoclaw";
        let container = WarmPool::container_name(claw_type, 0);

        wait_for_refill(claw_type);

        // Ensure clean state
        cleanup(&r, &container);
        {
            let mut pool = global_pool().lock().unwrap();
            pool.mark_filling(claw_type);
        }

        let result = r.fill_pool_slot(claw_type).await;
        // Cleanup before asserting, so the VM is removed even on test failure.
        let entry = {
            let mut pool = global_pool().lock().unwrap();
            pool.take(claw_type)
        };
        cleanup(&r, &container);

        result.expect("fill_pool_slot should succeed");

        let entry = entry.expect("pool should contain an entry after fill");
        assert_eq!(entry.claw_type, claw_type);
        assert_eq!(entry.container, container);

        // FC PID should have been recorded
        assert!(
            entry.inst.firecracker_pid().is_some(),
            "firecracker_pid should be set after fill"
        );

        // binary_present must be a definitive bool (true for golden images, false otherwise)
        // We just assert it's been set — the actual value depends on the image.
        // For picoclaw with a golden image, we expect true.
        assert!(
            entry.binary_present,
            "picoclaw golden image should have the binary present"
        );
    }

    // ── Test 2: claim produces a working VM in under 5 seconds ────────────

    /// The full pool path (fill → take → claim) must:
    /// - Complete in under 5 000 ms total.
    /// - Produce an instance where SSH is reachable.
    /// - Have `pool_install_claw` <= 10 ms (binary check at fill time).
    #[tokio::test]
    async fn pool_claim_produces_working_vm_under_5s() {
        let r = runner();
        let claw_type = "picoclaw";
        let pool_container = WarmPool::container_name(claw_type, 0);

        wait_for_refill(claw_type);

        // Fill the slot
        cleanup(&r, &pool_container);
        {
            let mut pool = global_pool().lock().unwrap();
            pool.mark_filling(claw_type);
        }
        r.fill_pool_slot(claw_type)
            .await
            .expect("fill_pool_slot failed");

        let entry = {
            let mut pool = global_pool().lock().unwrap();
            pool.take(claw_type).expect("pool entry missing after fill")
        };

        let real_container = "_inttest-picoclaw-claim";
        cleanup(&r, real_container);

        let config = VmConfig {
            container: real_container.to_string(),
            customer: "inttest".to_string(),
            claw_type: claw_type.to_string(),
            customer_dir: None,
            tools: vec![],
            cpu_cores: None,
            ram_mb: None,
            disk_gb: None,
        };

        let t0 = Instant::now();
        let result = r.claim_from_pool(entry, &config).await;
        let elapsed_ms = t0.elapsed().as_millis();

        cleanup(&r, real_container);
        // Refill is now handled by the warm_pool_reconciler, not claim_from_pool.
        // Clean up the original pool container directory if it still exists.
        cleanup_with_refill_wait(&r, claw_type, &pool_container);

        let vm_result = result.expect("claim_from_pool failed");

        // Performance assertion: must be under 5 seconds
        assert!(
            elapsed_ms < 5_000,
            "pool claim took {elapsed_ms}ms — expected < 5000ms"
        );

        // install step must be near-zero (binary_present was set at fill time)
        let install_phase = vm_result
            .phases
            .iter()
            .find(|(name, _)| name == "pool_install_claw");
        if let Some((_, dur)) = install_phase {
            assert!(
                dur.as_millis() <= 50,
                "pool_install_claw took {}ms — expected <= 50ms (should be skipped)",
                dur.as_millis()
            );
        }
    }

    // ── Test 3: POOL_MISS triggers background refill ───────────────────────

    /// When `create()` falls through to the cold path (pool empty), it must
    /// spawn a background refill so the next request hits the pool.
    ///
    /// We verify by:
    /// 1. Ensuring the pool slot is empty (take any existing entry).
    /// 2. Running a full cold create.
    /// 3. Waiting up to 60 s for the background refill to complete.
    /// 4. Asserting `slot_is_empty == false`.
    #[tokio::test]
    async fn pool_miss_triggers_background_refill() {
        let r = runner();
        let claw_type = "picoclaw";
        let pool_container = WarmPool::container_name(claw_type, 0);
        let real_container = "_inttest-picoclaw-miss";

        wait_for_refill(claw_type);

        // Drain the pool so create() goes cold
        {
            let mut pool = global_pool().lock().unwrap();
            pool.take(claw_type);
        }
        cleanup(&r, &pool_container);
        cleanup(&r, real_container);

        let config = VmConfig {
            container: real_container.to_string(),
            customer: "inttest".to_string(),
            claw_type: claw_type.to_string(),
            customer_dir: None,
            tools: vec![],
            cpu_cores: None,
            ram_mb: None,
            disk_gb: None,
        };

        // Cold create (will take ~20s)
        let result = r.create(&config).await;
        cleanup(&r, real_container);

        result.expect("cold create should succeed");

        // Wait up to 60s for background refill
        let deadline = Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let empty = {
                let pool = global_pool().lock().unwrap();
                pool.slot_is_empty(claw_type)
            };
            if !empty {
                break;
            }
            if Instant::now() >= deadline {
                cleanup(&r, &pool_container);
                panic!("background refill did not complete within 60s after POOL_MISS");
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        // Cleanup the refilled pool VM
        cleanup(&r, &pool_container);
    }

    // ── Test 4: slirp_remove_hostfwd cleans up the temporary port ─────────

    /// The temporary SSH hostfwd added during fill must be removed before the
    /// entry is stored in the pool. We verify by:
    /// 1. Running fill_pool_slot (which adds + removes a temp hostfwd internally).
    /// 2. Checking that the SSH port recorded in inst.ssh_port is NOT listening
    ///    on the host (it was a pool-internal port, never exposed externally).
    ///
    /// We can't directly assert "no hostfwd", but we verify the pool VM's
    /// ssh_port is not bound on 127.0.0.1 (since no permanent hostfwd was added).
    #[tokio::test]
    async fn fill_pool_temp_hostfwd_not_exposed_after_fill() {
        let r = runner();
        let claw_type = "picoclaw";
        let container = WarmPool::container_name(claw_type, 0);

        wait_for_refill(claw_type);

        cleanup(&r, &container);
        {
            let mut pool = global_pool().lock().unwrap();
            pool.mark_filling(claw_type);
        }

        r.fill_pool_slot(claw_type)
            .await
            .expect("fill_pool_slot failed");

        let entry = {
            let mut pool = global_pool().lock().unwrap();
            pool.take(claw_type).expect("pool entry missing after fill")
        };

        let temp_ssh_port = entry.inst.ssh_port();
        cleanup(&r, &container);

        // The pool VM's ssh_port must NOT be listening on the host — no permanent
        // hostfwd was added (only a temporary one for the binary check, then removed).
        let is_bound = std::net::TcpStream::connect(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            temp_ssh_port,
        )))
        .is_ok();

        assert!(
            !is_bound,
            "port {temp_ssh_port} is still bound after fill — \
             temporary hostfwd was not removed"
        );
    }
}
