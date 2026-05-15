use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::client::{AdminClient, InstanceItem};
use crate::error::E2eError;
use crate::ssh::{ssh_smoke_test, ssh_wait_and_exec};
use crate::terminal::{terminal_persistence_blocking, terminal_roundtrip_blocking};

/// All supported claw types from the manifest (single source of truth).
///
/// Returns only `Tier::Supported` claws — E2E exercises the full pipeline
/// (golden build + warm pool + real VM boot). Non-supported tiers don't have
/// goldens and can't run through the existing E2E scenarios.
#[must_use]
pub fn all_claw_types() -> Vec<&'static str> {
    core_rs::manifest::supported_names()
}

#[allow(clippy::struct_excessive_bools)]
pub struct TestConfig {
    pub timeout: Duration,
    pub retries: u32,
    pub retry_delay: Duration,
    pub settle_time: Duration,
    pub skip_ssh: bool,
    pub skip_terminal: bool,
    pub skip_terminal_restart: bool,
    pub skip_terminal_persist: bool,
    pub warm_pool_assertions: bool,
    pub skip_refill_test: bool,
    pub ssh_key_path: PathBuf,
    pub state_dir: PathBuf,
    /// Max create time (ms) for warm pool path assertions.
    pub max_create_ms: u64,
    /// Max `install_claw` phase time (ms) for warm pool assertions.
    pub max_install_ms: u64,
    /// When true, any job failure that lacks a well-formed `error_context` is
    /// treated as a test failure in its own right (error-quality assertion).
    pub require_error_context: bool,
}

pub struct ClawTestResult {
    pub claw_type: String,
    pub label: String,
    pub passed: bool,
    pub error: Option<E2eError>,
    pub total_ms: Option<u64>,
    pub used_pool: Option<bool>,
    pub ssh_ok: Option<bool>,
    pub terminal_ok: Option<bool>,
    pub terminal_restart_ok: Option<bool>,
    pub terminal_persist_ok: Option<bool>,
}

pub struct TestRunner {
    client: AdminClient,
    config: TestConfig,
}

impl TestRunner {
    #[must_use]
    pub fn new(client: AdminClient, config: TestConfig) -> Self {
        TestRunner { client, config }
    }

    /// Run the error-quality negative test: create a `brokenclaw` instance,
    /// assert the job fails, then validate the `ErrorContext` is well-formed.
    ///
    /// Requires the backend to have `brokenclaw` in its registry (i.e.
    /// `CLAW_TYPES` must include `brokenclaw`) and vmrunner to have
    /// `THEYOS_ENABLE_BROKENCLAW=1` set.  If the backend rejects the claw
    /// type with HTTP 4xx the test is skipped with a clear log message.
    ///
    /// # Panics
    ///
    /// Panics if `error_context` slice indexing overflows (only in debug; the
    /// `.min(80)` guard prevents this in practice).
    #[must_use]
    pub fn test_error_quality(&self) -> ClawTestResult {
        eprintln!("[e2e] --- Error-quality test (brokenclaw) ---");

        let mut result = ClawTestResult {
            claw_type: "brokenclaw".to_string(),
            label: "brokenclaw (error-quality)".to_string(),
            passed: false,
            error: None,
            total_ms: None,
            used_pool: None,
            ssh_ok: None,
            terminal_ok: None,
            terminal_restart_ok: None,
            terminal_persist_ok: None,
        };

        // Create — expect this to succeed at HTTP level (job enqueued)
        let (job_id, instance_id) = match self.client.create_instance("e2e-broken", "brokenclaw") {
            Ok(cr) => {
                let instance_id = cr
                    .instance
                    .as_ref()
                    .map(|i| i.id.clone())
                    .unwrap_or_default();
                (cr.job_id, instance_id)
            }
            Err(E2eError::Create { status, ref body }) if (400..500).contains(&status) => {
                // brokenclaw not registered in this environment — skip gracefully
                eprintln!(
                    "[e2e] brokenclaw: skipped (backend returned HTTP {status} — \
                     add 'brokenclaw' to CLAW_TYPES and set THEYOS_ENABLE_BROKENCLAW=1)"
                );
                result.passed = true; // skip = pass
                return result;
            }
            Err(e) => {
                eprintln!("[e2e] brokenclaw: create FAILED unexpectedly: {e}");
                result.error = Some(e);
                return result;
            }
        };

        eprintln!("[e2e] brokenclaw: job={job_id} instance={instance_id} — expecting failure");

        // Poll — must fail
        match self
            .client
            .poll_job(&job_id, self.config.timeout, "brokenclaw")
        {
            Ok(_) => {
                // Job succeeded when it should have failed
                eprintln!("[e2e] brokenclaw: job completed but expected failure");
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(E2eError::ExpectedFailure(
                    "brokenclaw job completed successfully — expected InstallerFailed".to_string(),
                ));
            }
            Err(E2eError::JobFailed {
                job_id: _,
                ref error,
                ref error_context,
            }) => {
                eprintln!("[e2e] brokenclaw: job failed as expected: {error}");

                // Validate error_context quality
                match validate_error_context(error_context.as_ref()) {
                    Ok(()) => {
                        let ctx = error_context.as_ref().unwrap();
                        eprintln!(
                            "[e2e] brokenclaw: error_context OK — phase={:?} command={:?} exit_code={:?} stderr_tail={:?}",
                            ctx.get("phase").and_then(|v| v.as_str()),
                            ctx.get("command").and_then(|v| v.as_str()),
                            ctx.get("exit_code"),
                            ctx.get("stderr_tail")
                                .and_then(|v| v.as_str())
                                .map(|s| &s[..s.len().min(80)]),
                        );
                        result.passed = true;
                    }
                    Err(quality_err) => {
                        eprintln!("[e2e] brokenclaw: error_context quality FAIL: {quality_err}");
                        result.error = Some(E2eError::ErrorQuality(quality_err));
                    }
                }

                // Best-effort cleanup regardless
                let _ = self.client.delete_instance(&instance_id);
            }
            Err(e) => {
                eprintln!("[e2e] brokenclaw: unexpected poll error: {e}");
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(e);
            }
        }

        result
    }

    /// Run tests for the given claw types, with settle time between each.
    /// Returns results for each test plus an optional refill test result.
    #[must_use]
    pub fn run_all(&self, claw_types: &[&str]) -> Vec<ClawTestResult> {
        let mut results = Vec::new();

        // Clean up stale e2e instances from previous runs that were not
        // deleted (e.g. due to timeout, backend restart, or crash).  Stale
        // instances hold ports, causing name-conflict errors when the next run
        // tries to create an instance with the same name.
        self.cleanup_stale_e2e_instances();

        // Error-quality negative test first (fast, doesn't need settle)
        if self.config.require_error_context {
            results.push(self.test_error_quality());
            if !claw_types.is_empty() {
                eprintln!("[e2e] Settling {}s...", self.config.settle_time.as_secs());
                std::thread::sleep(self.config.settle_time);
            }
        }

        for (i, ct) in claw_types.iter().enumerate() {
            if i > 0 {
                eprintln!("[e2e] Settling {}s...", self.config.settle_time.as_secs());
                std::thread::sleep(self.config.settle_time);
            }
            let restart_smoke =
                !self.config.skip_terminal && !self.config.skip_terminal_restart && i == 0;
            let r = self.test_claw(ct, &test_name(ct), restart_smoke);
            results.push(r);
        }

        // Warm pool refill regression test
        if !self.config.skip_refill_test && claw_types.len() > 1 {
            eprintln!("[e2e] Settling 30s for warm pool refill before round-2 test...");
            std::thread::sleep(Duration::from_secs(30));
            eprintln!("[e2e] --- Testing warm pool refill (picoclaw round 2) ---");
            let mut r = self.test_claw("picoclaw", "e2e-pico-r2", false);
            r.label = "picoclaw (refill)".to_string();
            results.push(r);
        }

        results
    }

    /// Test a single claw type: create → poll → verify → ssh → delete → verify.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn test_claw(&self, claw_type: &str, name: &str, restart_smoke: bool) -> ClawTestResult {
        eprintln!("[e2e] --- Testing {claw_type} ---");

        let mut result = ClawTestResult {
            claw_type: claw_type.to_string(),
            label: claw_type.to_string(),
            passed: false,
            error: None,
            total_ms: None,
            used_pool: None,
            ssh_ok: None,
            terminal_ok: None,
            terminal_restart_ok: None,
            terminal_persist_ok: None,
        };

        // Create (with retries)
        let (job_id, instance_id) = match self.create_with_retries(claw_type, name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[e2e] {claw_type}: create FAILED: {e}");
                result.error = Some(e);
                return result;
            }
        };

        eprintln!("[e2e] {claw_type}: job={job_id} instance={instance_id}");

        // Poll job
        let (_job_item, job_result) = match self.client.poll_job(
            &job_id,
            self.config.timeout,
            claw_type,
        ) {
            Ok(v) => v,
            Err(E2eError::JobFailed {
                job_id: _,
                ref error,
                ref error_context,
            }) => {
                eprintln!("[e2e] {claw_type}: poll FAILED: {error}");
                // Validate error context quality if present or required.
                if self.config.require_error_context {
                    match validate_error_context(error_context.as_ref()) {
                        Ok(()) => eprintln!("[e2e] {claw_type}: error_context quality OK"),
                        Err(quality_err) => {
                            eprintln!(
                                "[e2e] {claw_type}: error_context quality FAIL: {quality_err}"
                            );
                            let _ = self.client.delete_instance(&instance_id);
                            result.error = Some(E2eError::ErrorQuality(quality_err));
                            return result;
                        }
                    }
                } else if let Some(ctx) = error_context {
                    eprintln!(
                        "[e2e] {claw_type}: error_context present: phase={:?} command={:?} exit_code={:?}",
                        ctx.get("phase").and_then(|v| v.as_str()),
                        ctx.get("command").and_then(|v| v.as_str()),
                        ctx.get("exit_code"),
                    );
                } else {
                    eprintln!("[e2e] {claw_type}: no error_context in job failure");
                }
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(E2eError::JobFailed {
                    job_id: job_id.clone(),
                    error: error.clone(),
                    error_context: error_context.clone(),
                });
                return result;
            }
            Err(e) => {
                eprintln!("[e2e] {claw_type}: poll FAILED: {e}");
                // Best-effort cleanup
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(e);
                return result;
            }
        };

        let used_pool = job_result.phases.iter().any(|p| p.phase.contains("pool"));
        result.total_ms = job_result.total_ms;
        result.used_pool = Some(used_pool);

        // Warm pool timing assertions (if enabled)
        if self.config.warm_pool_assertions {
            if !used_pool {
                let e = E2eError::WarmPool(format!("{claw_type}: used COLD path instead of pool"));
                eprintln!("[e2e] {claw_type}: FAIL {e}");
                result.error = Some(e);
                let _ = self.client.delete_instance(&instance_id);
                return result;
            }
            if let Some(total) = job_result.total_ms {
                if total > self.config.max_create_ms {
                    let e = E2eError::WarmPool(format!(
                        "{claw_type}: total_ms={total} > {}ms",
                        self.config.max_create_ms
                    ));
                    eprintln!("[e2e] {claw_type}: FAIL {e}");
                    result.error = Some(e);
                    let _ = self.client.delete_instance(&instance_id);
                    return result;
                }
            }
            let install_ms = job_result
                .phases
                .iter()
                .find(|p| p.phase == "pool_install_claw")
                .map(|p| p.ms);
            if let Some(ms) = install_ms {
                if ms > self.config.max_install_ms {
                    let e = E2eError::WarmPool(format!(
                        "{claw_type}: pool_install_claw={ms}ms > {}ms",
                        self.config.max_install_ms
                    ));
                    eprintln!("[e2e] {claw_type}: FAIL {e}");
                    result.error = Some(e);
                    let _ = self.client.delete_instance(&instance_id);
                    return result;
                }
            }
        }

        // Verify instance is active and get app port
        let active_instance = match self.verify_active(&instance_id) {
            Ok(instance) => {
                eprintln!(
                    "[e2e] {claw_type}: instance active (container={}, port={})",
                    instance.container, instance.port
                );
                instance
            }
            Err(e) => {
                eprintln!("[e2e] {claw_type}: FAIL {e}");
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(e);
                return result;
            }
        };
        let app_port = active_instance.port;
        let container = if active_instance.container.is_empty() {
            let e = E2eError::Terminal {
                container: format!("{claw_type}-{name}"),
                reason: "active instance is missing container name".to_string(),
            };
            eprintln!("[e2e] {claw_type}: FAIL {e}");
            let _ = self.client.delete_instance(&instance_id);
            result.error = Some(e);
            return result;
        } else {
            active_instance.container.clone()
        };

        if app_port > 0 {
            eprintln!("[e2e] {claw_type}: app port {app_port} allocated (hostfwd configured)");
        } else {
            eprintln!("[e2e] {claw_type}: app port is 0");
        }

        // SSH smoke test
        if !self.config.skip_ssh {
            match self.run_ssh_smoke(&container) {
                Ok(port) => {
                    eprintln!("[e2e] {claw_type}: SSH smoke test on port {port} OK");
                    result.ssh_ok = Some(true);
                }
                Err(e) => {
                    eprintln!("[e2e] {claw_type}: SSH smoke test FAILED: {e}");
                    result.ssh_ok = Some(false);
                    let _ = self.client.delete_instance(&instance_id);
                    result.error = Some(e);
                    return result;
                }
            }
        }

        match self.verify_claw_installed(&container, claw_type) {
            Ok(()) => eprintln!("[e2e] {claw_type}: claw binary installed"),
            Err(e) => {
                eprintln!("[e2e] {claw_type}: claw binary check FAILED: {e}");
                let _ = self.client.delete_instance(&instance_id);
                result.error = Some(e);
                return result;
            }
        }

        // Terminal container + PTY smoke test
        if !self.config.skip_terminal {
            match self.verify_terminal_container_present(&container, Duration::from_secs(30)) {
                Ok(()) => eprintln!("[e2e] {claw_type}: terminal container visible"),
                Err(e) => {
                    eprintln!("[e2e] {claw_type}: terminal container check FAILED: {e}");
                    let _ = self.client.delete_instance(&instance_id);
                    result.error = Some(e);
                    return result;
                }
            }

            // Create a workspace once — reuse for all terminal sub-tests.
            let workspace_id = match self.client.create_workspace(&container) {
                Ok(id) => {
                    eprintln!("[e2e] {claw_type}: workspace created: {id}");
                    id
                }
                Err(e) => {
                    eprintln!("[e2e] {claw_type}: workspace creation FAILED: {e}");
                    let _ = self.client.delete_instance(&instance_id);
                    result.error = Some(e);
                    return result;
                }
            };

            match self.run_terminal_smoke(&container, &workspace_id) {
                Ok(()) => {
                    eprintln!("[e2e] {claw_type}: PTY round-trip OK");
                    result.terminal_ok = Some(true);
                }
                Err(e) => {
                    eprintln!("[e2e] {claw_type}: PTY round-trip FAILED: {e}");
                    result.terminal_ok = Some(false);
                    let _ = self.client.delete_instance(&instance_id);
                    result.error = Some(e);
                    return result;
                }
            }

            if restart_smoke {
                match self.run_terminal_restart_smoke(&container, &workspace_id) {
                    Ok(()) => {
                        eprintln!("[e2e] {claw_type}: terminal restart smoke OK");
                        result.terminal_restart_ok = Some(true);
                    }
                    Err(e) => {
                        eprintln!("[e2e] {claw_type}: terminal restart smoke FAILED: {e}");
                        result.terminal_restart_ok = Some(false);
                        let _ = self.client.delete_instance(&instance_id);
                        result.error = Some(e);
                        return result;
                    }
                }
            }

            // Terminal persistence test: connect → set env var → disconnect →
            // reconnect with same session → verify env var is still present.
            // Only run when terminal tests are enabled and persistence is not skipped.
            if !self.config.skip_terminal_persist {
                match self.run_terminal_persistence(&container, &workspace_id) {
                    Ok(()) => {
                        eprintln!("[e2e] {claw_type}: terminal persistence OK");
                        result.terminal_persist_ok = Some(true);
                    }
                    Err(e) => {
                        eprintln!("[e2e] {claw_type}: terminal persistence FAILED: {e}");
                        result.terminal_persist_ok = Some(false);
                        // Non-fatal: log the failure but continue
                    }
                }
            }
        }

        // Delete
        if let Err(e) = self.client.delete_instance(&instance_id) {
            eprintln!("[e2e] {claw_type}: delete FAILED: {e}");
            result.error = Some(e);
            return result;
        }

        // Brief pause for delete to propagate
        std::thread::sleep(Duration::from_secs(3));

        // Verify deleted
        match self.verify_deleted(&instance_id) {
            Ok(()) => eprintln!("[e2e] {claw_type}: instance cleaned up"),
            Err(e) => {
                eprintln!("[e2e] {claw_type}: FAIL {e}");
                result.error = Some(e);
                return result;
            }
        }

        if !self.config.skip_terminal {
            match self.verify_terminal_container_absent(&container, Duration::from_secs(20)) {
                Ok(()) => eprintln!("[e2e] {claw_type}: terminal cleanup OK"),
                Err(e) => {
                    eprintln!("[e2e] {claw_type}: terminal cleanup FAILED: {e}");
                    result.error = Some(e);
                    return result;
                }
            }
        }

        result.passed = true;
        result
    }

    /// Create with retries on 429 or other transient errors.
    fn create_with_retries(
        &self,
        claw_type: &str,
        base_name: &str,
    ) -> Result<(String, String), E2eError> {
        let mut name = base_name.to_string();

        for attempt in 1..=self.config.retries {
            eprintln!(
                "[e2e] {claw_type}: creating instance {name} (attempt {attempt}/{})...",
                self.config.retries
            );

            match self.client.create_instance(&name, claw_type) {
                Ok(cr) => {
                    let instance_id = cr
                        .instance
                        .as_ref()
                        .map(|i| i.id.clone())
                        .unwrap_or_default();
                    return Ok((cr.job_id, instance_id));
                }
                Err(E2eError::Create { status, ref body }) if status == 429 => {
                    if attempt < self.config.retries {
                        eprintln!(
                            "[e2e] {claw_type}: HTTP 429, retrying in {}s...",
                            self.config.retry_delay.as_secs()
                        );
                        std::thread::sleep(self.config.retry_delay);
                        name = format!("{base_name}-r{attempt}");
                    } else {
                        return Err(E2eError::Create {
                            status,
                            body: body.clone(),
                        });
                    }
                }
                Err(E2eError::Create { status, ref body })
                    if (500..600).contains(&status) && attempt < self.config.retries =>
                {
                    eprintln!(
                        "[e2e] {claw_type}: HTTP {status}, retrying in {}s...",
                        self.config.retry_delay.as_secs()
                    );
                    std::thread::sleep(self.config.retry_delay);
                    name = format!("{base_name}-r{attempt}");
                }
                Err(e) => return Err(e),
            }
        }

        Err(E2eError::Http(format!(
            "create exhausted {0} retries",
            self.config.retries
        )))
    }

    /// Delete stale e2e instances left over from previous test runs.
    ///
    /// Instances whose name starts with `e2e-` are test artifacts. If they
    /// exist when a new run starts, they hold ports and block name allocation.
    /// This cleanup is
    /// best-effort — failures are logged but do not abort the test run.
    fn cleanup_stale_e2e_instances(&self) {
        let instances = match self.client.list_instances() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[e2e] WARNING: could not list instances for stale cleanup: {e}");
                return;
            }
        };

        let stale: Vec<_> = instances
            .iter()
            .filter(|i| i.name.starts_with("e2e-"))
            .collect();

        if stale.is_empty() {
            return;
        }

        eprintln!(
            "[e2e] Cleaning up {} stale e2e instance(s) from previous run...",
            stale.len()
        );
        for inst in &stale {
            eprintln!("[e2e]   deleting stale: {} ({})", inst.name, inst.id);
            if let Err(e) = self.client.delete_instance(&inst.id) {
                eprintln!("[e2e]   WARNING: failed to delete {}: {e}", inst.id);
            }
        }
        // Let teardown settle before proceeding
        std::thread::sleep(Duration::from_secs(3));
    }

    /// Verify the instance appears in the list with status "active".
    /// Returns the app port on success.
    fn verify_active(&self, instance_id: &str) -> Result<InstanceItem, E2eError> {
        let instances = self.client.list_instances()?;
        for inst in &instances {
            if inst.id == instance_id {
                if inst.status == "active" {
                    return Ok(inst.clone());
                }
                return Err(E2eError::NotActive {
                    id: instance_id.to_string(),
                    status: inst.status.clone(),
                });
            }
        }
        Err(E2eError::NotActive {
            id: instance_id.to_string(),
            status: "not found in list".to_string(),
        })
    }

    fn verify_claw_installed(&self, container: &str, claw_type: &str) -> Result<(), E2eError> {
        let ssh_port = self.ssh_port_for_container(container)?;
        let cmd = format!("test -x /usr/local/bin/{claw_type} && echo CLAW_INSTALLED");
        let output = ssh_wait_and_exec(ssh_port, &self.config.ssh_key_path, &cmd, 5)?;
        if output.contains("CLAW_INSTALLED") {
            return Ok(());
        }

        Err(E2eError::ClawCheck {
            claw_type: claw_type.to_string(),
            reason: format!("binary /usr/local/bin/{claw_type} not found or not executable"),
        })
    }

    /// Verify the instance no longer appears in the list.
    fn verify_deleted(&self, instance_id: &str) -> Result<(), E2eError> {
        let instances = self.client.list_instances()?;
        if instances.iter().any(|i| i.id == instance_id) {
            return Err(E2eError::DeleteFailed {
                id: instance_id.to_string(),
            });
        }
        Ok(())
    }

    /// Read `SSH_PORT` from instance.env and run SSH smoke test.
    fn run_ssh_smoke(&self, container: &str) -> Result<u16, E2eError> {
        let ssh_port = self.ssh_port_for_container(container)?;
        ssh_smoke_test(ssh_port, &self.config.ssh_key_path)?;
        Ok(ssh_port)
    }

    fn ssh_port_for_container(&self, container: &str) -> Result<u16, E2eError> {
        let env_file = self.config.state_dir.join(container).join("instance.env");
        read_ssh_port(&env_file).map_err(|e| E2eError::Ssh {
            port: 0,
            reason: format!("reading instance.env at {}: {e}", env_file.display()),
        })
    }

    fn verify_terminal_container_present(
        &self,
        container: &str,
        timeout: Duration,
    ) -> Result<(), E2eError> {
        self.wait_for_terminal_container(container, true, timeout)
    }

    fn verify_terminal_container_absent(
        &self,
        container: &str,
        timeout: Duration,
    ) -> Result<(), E2eError> {
        self.wait_for_terminal_container(container, false, timeout)
    }

    fn wait_for_terminal_container(
        &self,
        container: &str,
        should_exist: bool,
        timeout: Duration,
    ) -> Result<(), E2eError> {
        let start = std::time::Instant::now();
        loop {
            let items = self.client.list_terminal_containers()?;
            let found = items.iter().any(|item| item == container);
            if found == should_exist {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                let state = if should_exist {
                    "did not appear"
                } else {
                    "did not disappear"
                };
                return Err(E2eError::Terminal {
                    container: container.to_string(),
                    reason: format!(
                        "container {state} in /terminals/containers within {}s",
                        timeout.as_secs()
                    ),
                });
            }

            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn run_terminal_smoke(&self, container: &str, workspace_id: &str) -> Result<(), E2eError> {
        terminal_roundtrip_blocking(
            self.client.base_url(),
            self.client.session_cookie(),
            container,
            workspace_id,
            "pty",
            Duration::from_secs(45),
        )
    }

    fn run_terminal_restart_smoke(
        &self,
        container: &str,
        workspace_id: &str,
    ) -> Result<(), E2eError> {
        self.client.reconnect_terminal(container, workspace_id)?;
        std::thread::sleep(Duration::from_secs(5));
        terminal_roundtrip_blocking(
            self.client.base_url(),
            self.client.session_cookie(),
            container,
            workspace_id,
            "restart",
            Duration::from_secs(60),
        )
    }

    fn run_terminal_persistence(
        &self,
        container: &str,
        workspace_id: &str,
    ) -> Result<(), E2eError> {
        terminal_persistence_blocking(
            self.client.base_url(),
            self.client.session_cookie(),
            container,
            workspace_id,
            Duration::from_secs(60),
        )
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Generate a test instance name from claw type.
fn test_name(claw_type: &str) -> String {
    let short = match claw_type {
        "picoclaw" => "pico",
        "zeroclaw" => "zero",
        "nanobot" => "nano",
        "openclaw" => "open",
        "nullclaw" => "null",
        "ironclaw" => "iron",
        other => other,
    };
    format!("e2e-{short}")
}

/// Validate that a job failure's `error_context` meets minimum quality standards.
///
/// Returns `Ok(())` if the context is well-formed, or `Err(reason)` describing
/// what is missing or malformed.
///
/// # Errors
///
/// Returns an error string if the context is missing, not an object, or lacks
/// required diagnostic fields.
pub fn validate_error_context(ctx: Option<&serde_json::Value>) -> Result<(), String> {
    let Some(ctx) = ctx else {
        return Err("error_context is missing entirely".to_string());
    };

    // Must be an object
    let Some(obj) = ctx.as_object() else {
        return Err(format!("error_context is not an object: {ctx}"));
    };

    // Must have at least one of: phase, command, exit_code, timed_out
    let has_phase =
        obj.contains_key("phase") && obj["phase"].as_str().is_some_and(|s| !s.is_empty());
    let has_command =
        obj.contains_key("command") && obj["command"].as_str().is_some_and(|s| !s.is_empty());
    let has_exit_code = obj.contains_key("exit_code") && !obj["exit_code"].is_null();
    let has_timed_out = obj.contains_key("timed_out") && !obj["timed_out"].is_null();

    if !has_phase && !has_command && !has_exit_code && !has_timed_out {
        return Err(
            "error_context missing all required fields (phase, command, exit_code, timed_out)"
                .to_string(),
        );
    }

    // Must have at least one of: stderr_tail, serial_log_tail, slirp_log_tail
    let has_stderr = obj
        .get("stderr_tail")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    let has_serial = obj
        .get("serial_log_tail")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    let has_slirp = obj
        .get("slirp_log_tail")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());

    if !has_stderr && !has_serial && !has_slirp {
        // This is a warning rather than a hard failure — some errors (e.g.
        // early boot failures) may not have all tails available.
        eprintln!(
            "[e2e] warn: error_context has no stderr_tail, serial_log_tail, or slirp_log_tail"
        );
    }

    Ok(())
}

/// Parse `SSH_PORT`=<n> from an instance.env file.
///
/// # Errors
///
/// Returns an error string if the file cannot be read or `SSH_PORT` is missing
/// or has an invalid value.
pub fn read_ssh_port(env_path: &Path) -> Result<u16, String> {
    let content = std::fs::read_to_string(env_path)
        .map_err(|e| format!("read {}: {e}", env_path.display()))?;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("SSH_PORT=") {
            return val
                .parse::<u16>()
                .map_err(|e| format!("bad SSH_PORT value '{val}': {e}"));
        }
    }
    Err("SSH_PORT not found".into())
}

/// Print the summary table to stderr.
pub fn print_summary(results: &[ClawTestResult]) {
    eprintln!("[e2e] === Summary ===");

    let all_passed = results.iter().all(|r| r.passed);

    for r in results {
        let status = if r.passed { "PASS" } else { "FAIL" };
        #[allow(clippy::cast_precision_loss)] // NOTE: timing ms fits in f64 mantissa for display
        let timing = r
            .total_ms
            .map_or_else(|| "-".into(), |ms| format!("{:.1}s", ms as f64 / 1000.0));
        let path_info = match r.used_pool {
            Some(true) => "pool",
            Some(false) => "cold",
            None => "-",
        };
        let ssh_info = match r.ssh_ok {
            Some(true) => "ssh=ok",
            Some(false) => "ssh=fail",
            None => "ssh=-",
        };
        let terminal_info = match r.terminal_ok {
            Some(true) => "tty=ok",
            Some(false) => "tty=fail",
            None => "tty=-",
        };
        let restart_info = match r.terminal_restart_ok {
            Some(true) => "restart=ok",
            Some(false) => "restart=fail",
            None => "restart=-",
        };
        let persist_info = match r.terminal_persist_ok {
            Some(true) => "persist=ok",
            Some(false) => "persist=fail",
            None => "persist=-",
        };
        eprintln!(
            "[e2e]   {:<20} {:<6} {:<8} ({}, {}, {}, {}, {})",
            r.label, status, timing, path_info, ssh_info, terminal_info, restart_info, persist_info
        );
    }

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();

    if all_passed {
        eprintln!("[e2e] All {total} tests passed.");
    } else {
        let failed = total - passed;
        eprintln!("[e2e] {failed} of {total} test(s) failed.");
        for r in results.iter().filter(|r| !r.passed) {
            if let Some(ref e) = r.error {
                eprintln!("[e2e]   {}: {e}", r.label);
            }
        }
    }
}
