use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::E2eError;

/// HTTP client for the theyOS admin API with session cookie handling.
pub struct AdminClient {
    agent: ureq::Agent,
    base_url: String,
    session_cookie: String,
}

// ─── API response types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateResponse {
    pub job_id: String,
    pub instance: Option<InstanceItem>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InstanceItem {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub claw_type: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct InstancesListResponse {
    pub data: Vec<InstanceItem>,
}

#[derive(Debug, Deserialize)]
pub struct TerminalContainersResponse {
    pub data: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct JobWrapper {
    pub item: JobItem,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JobItem {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
}

/// Parsed job result (embedded JSON string in `result` field).
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JobResult {
    #[serde(default)]
    pub total_ms: Option<u64>,
    #[serde(default)]
    pub phases: Vec<JobPhase>,
    #[serde(default)]
    pub golden_image_used: Option<bool>,
    #[serde(default)]
    pub install_skipped: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JobPhase {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub ms: u64,
}

// ─── AdminClient ────────────────────────────────────────────────────────────

impl AdminClient {
    /// Log in and return an authenticated client with session cookies.
    ///
    /// # Errors
    ///
    /// Returns an error if the login HTTP request fails or returns a non-200 status.
    pub fn login(base_url: &str, user: &str, password: &str) -> Result<Self, E2eError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();

        let url = format!("{}/api/v1/auth/login", base_url.trim_end_matches('/'));
        let resp = agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::json!({
                "username": user,
                "password": password,
            }))
            .map_err(|e| E2eError::Login(format!("{e}")))?;

        let session_cookie = resp
            .header("Set-Cookie")
            .or_else(|| resp.header("set-cookie"))
            .and_then(|cookie| cookie.split(';').next())
            .filter(|cookie| cookie.starts_with("soyeht_session="))
            .ok_or_else(|| E2eError::Login("missing soyeht_session cookie".to_string()))?
            .to_string();

        if resp.status() != 200 {
            return Err(E2eError::Login(format!("HTTP {}", resp.status())));
        }

        Ok(AdminClient {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            session_cookie,
        })
    }

    /// POST /api/v1/instances — create a new instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub fn create_instance(&self, name: &str, claw_type: &str) -> Result<CreateResponse, E2eError> {
        let url = format!("{}/api/v1/instances", self.base_url);
        // Pass empty tools array to skip AI coding tool installation during e2e tests.
        // Tool installation is tested separately; e2e validates the core VM lifecycle.
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::json!({
                "name": name,
                "claw_type": claw_type,
                "tools": [],
            }));

        match resp {
            Ok(r) => {
                let body: Value = r
                    .into_json()
                    .map_err(|e| E2eError::Http(format!("parse create response: {e}")))?;
                let cr: CreateResponse = serde_json::from_value(body.clone()).map_err(|e| {
                    E2eError::Http(format!("deserialize create response: {e} — body: {body}"))
                })?;
                Ok(cr)
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(E2eError::Create { status, body })
            }
            Err(e) => Err(E2eError::Http(format!("create request: {e}"))),
        }
    }

    /// Poll GET /api/v1/jobs/{id} until completed/failed or timeout.
    ///
    /// Returns the final `JobItem` and the parsed `JobResult` (from the `result` JSON string).
    /// Uses a default 10s poll interval.
    ///
    /// # Errors
    ///
    /// Returns an error if the job times out or fails.
    pub fn poll_job(
        &self,
        job_id: &str,
        timeout: Duration,
        log_prefix: &str,
    ) -> Result<(JobItem, JobResult), E2eError> {
        self.poll_job_interval(job_id, timeout, log_prefix, Duration::from_secs(10))
    }

    /// Like `poll_job` but with a configurable poll interval.
    ///
    /// # Errors
    ///
    /// Returns an error if the job times out or fails.
    pub fn poll_job_interval(
        &self,
        job_id: &str,
        timeout: Duration,
        log_prefix: &str,
        poll_interval: Duration,
    ) -> Result<(JobItem, JobResult), E2eError> {
        let start = Instant::now();
        let deadline = start + timeout;
        let url = format!("{}/api/v1/jobs/{}", self.base_url, job_id);
        let mut last_status = String::from("unknown");

        loop {
            let elapsed_secs = start.elapsed().as_secs();

            if Instant::now() >= deadline {
                return Err(E2eError::JobTimeout {
                    job_id: job_id.to_string(),
                    elapsed_secs,
                    last_status,
                });
            }

            let Ok(resp) = self.agent.get(&url).call() else {
                std::thread::sleep(Duration::from_secs(5));
                continue;
            };

            let Ok(job): Result<JobItem, _> = resp.into_json() else {
                std::thread::sleep(Duration::from_secs(5));
                continue;
            };

            last_status.clone_from(&job.status);

            match job.status.as_str() {
                "completed" => {
                    let job_result = parse_job_result(&job);
                    eprintln!(
                        "[e2e] {log_prefix}: job completed in {elapsed_secs}s{}",
                        match (&job_result.total_ms, has_pool_phase(&job_result)) {
                            (Some(ms), true) => format!(" ({ms}ms, pool path)"),
                            (Some(ms), false) => format!(" ({ms}ms, cold path)"),
                            _ => String::new(),
                        }
                    );
                    return Ok((job, job_result));
                }
                "failed" => {
                    let err = job.error.clone().unwrap_or_else(|| "unknown error".into());
                    let error_context = job
                        .result
                        .as_deref()
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                        .and_then(|v| v.get("error_context").cloned());
                    return Err(E2eError::JobFailed {
                        job_id: job_id.to_string(),
                        error: err,
                        error_context,
                    });
                }
                _ => {
                    eprintln!(
                        "[e2e] {log_prefix}: [{elapsed_secs}s] status={}",
                        job.status
                    );
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }

    /// GET /api/v1/instances — list all instances.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub fn list_instances(&self) -> Result<Vec<InstanceItem>, E2eError> {
        let url = format!("{}/api/v1/instances", self.base_url);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| E2eError::Http(format!("list instances: {e}")))?;

        let list: InstancesListResponse = resp
            .into_json()
            .map_err(|e| E2eError::Http(format!("parse instances list: {e}")))?;
        Ok(list.data)
    }

    /// DELETE /api/v1/instances/{id}
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub fn delete_instance(&self, id: &str) -> Result<(), E2eError> {
        let url = format!("{}/api/v1/instances/{}", self.base_url, id);
        let _ = self
            .agent
            .delete(&url)
            .call()
            .map_err(|e| E2eError::Http(format!("delete instance {id}: {e}")))?;
        Ok(())
    }

    /// GET /api/v1/terminals/containers
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub fn list_terminal_containers(&self) -> Result<Vec<String>, E2eError> {
        let url = format!("{}/api/v1/terminals/containers", self.base_url);
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| E2eError::Http(format!("list terminal containers: {e}")))?;

        let list: TerminalContainersResponse = resp
            .into_json()
            .map_err(|e| E2eError::Http(format!("parse terminal containers: {e}")))?;
        Ok(list.data)
    }

    /// POST /api/v1/terminals/{container}/workspace — resume or create workspace.
    ///
    /// Returns the workspace ID (hex string) to use as session ID for WebSocket
    /// PTY connections.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub fn create_workspace(&self, container: &str) -> Result<String, E2eError> {
        let url = format!("{}/api/v1/terminals/{}/workspace", self.base_url, container);
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .call()
            .map_err(|e| E2eError::Http(format!("create workspace {container}: {e}")))?;

        let body: Value = resp
            .into_json()
            .map_err(|e| E2eError::Http(format!("parse workspace response: {e}")))?;

        body["workspace"]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                E2eError::Http(format!("workspace response missing workspace.id: {body}"))
            })
    }

    /// POST /api/v1/terminals/{container}/reconnect?session={session}
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub fn reconnect_terminal(&self, container: &str, session: &str) -> Result<(), E2eError> {
        let url = format!(
            "{}/api/v1/terminals/{}/reconnect?session={}",
            self.base_url, container, session
        );
        let _ = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .call()
            .map_err(|e| E2eError::Http(format!("reconnect terminal {container}: {e}")))?;
        Ok(())
    }

    /// POST /api/v1/admin/drain-warm-pool — drain all warm pool VMs.
    ///
    /// This is needed before snapshot building so that seed instances are
    /// cold-booted (not claimed from the warm pool). Warm pool VMs carry
    /// a baked rootfs path from the PREVIOUS snapshot; if used as a snapshot
    /// seed, the new vmstate would still reference the old path, causing a
    /// path mismatch on the next restore.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub fn drain_warm_pool(&self) -> Result<(), E2eError> {
        let url = format!("{}/api/v1/admin/drain-warm-pool", self.base_url);
        let _ = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .call()
            .map_err(|e| E2eError::Http(format!("drain warm pool: {e}")))?;
        Ok(())
    }

    /// Check if the backend is reachable via /healthz.
    #[must_use]
    pub fn healthz(&self) -> bool {
        let url = format!("{}/healthz", self.base_url);
        matches!(self.agent.get(&url).call(), Ok(r) if r.status() == 200)
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn session_cookie(&self) -> &str {
        &self.session_cookie
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn parse_job_result(job: &JobItem) -> JobResult {
    job.result
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

fn has_pool_phase(jr: &JobResult) -> bool {
    jr.phases.iter().any(|p| p.phase.contains("pool"))
}
