#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    #[error("login failed: {0}")]
    Login(String),

    #[error("create instance failed (HTTP {status}): {body}")]
    Create { status: u16, body: String },

    #[error("job {job_id} timed out after {elapsed_secs}s (last status: {last_status})")]
    JobTimeout {
        job_id: String,
        elapsed_secs: u64,
        last_status: String,
    },

    /// Job failed — includes the human-readable message and optional structured
    /// diagnostic context from the backend (phase, command, `exit_code`, etc.).
    #[error("job {job_id} failed: {error}")]
    JobFailed {
        job_id: String,
        error: String,
        /// Structured `ErrorContext` from vmrunner-rs, if the backend provided it.
        error_context: Option<serde_json::Value>,
    },

    #[error("instance {id} not active after job completed (status: {status})")]
    NotActive { id: String, status: String },

    #[error("SSH smoke test failed on port {port}: {reason}")]
    Ssh { port: u16, reason: String },

    #[error("instance {id} still present after delete")]
    DeleteFailed { id: String },

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("warm pool assertion failed: {0}")]
    WarmPool(String),

    /// A job that was expected to fail did not fail (negative test case).
    #[error("expected job to fail but it completed successfully: {0}")]
    ExpectedFailure(String),

    /// A job failed but the error payload was missing required diagnostic fields.
    #[error("error quality assertion failed: {0}")]
    ErrorQuality(String),

    #[error("app port {port} not reachable: {reason}")]
    AppPort { port: u16, reason: String },

    #[error("claw check failed for {claw_type}: {reason}")]
    ClawCheck { claw_type: String, reason: String },

    #[error("terminal check failed for {container}: {reason}")]
    Terminal { container: String, reason: String },

    #[error("benchmark failed: {0}")]
    BenchmarkFailed(String),

    #[error("setup error: {detail}")]
    Setup { detail: String },
}
