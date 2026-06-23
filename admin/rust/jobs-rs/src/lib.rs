//! jobs-rs — Rust implementation of the theyOS jobs/store.
//!
//! # Design
//!
//! Replaces the Go JSON+flock implementation with `SQLite` WAL for superior
//! concurrent-writer safety without relying on OS-level advisory locks.
//!
//! Key deliberate improvements:
//!   - `BEGIN IMMEDIATE` in `claim_next_pending` serialises concurrent claimers
//!     inside a single `SQLite` transaction instead of a filesystem flock.
//!   - WAL mode allows concurrent reads while a writer is active.
//!   - `busy_timeout(5000)` prevents spurious `SQLITE_BUSY` errors.
//!
//! The public API surface mirrors the Go `Store` interface so both sides can be
//! validated against the same language-neutral contract fixtures.

mod schema;

use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Column list for job SELECT queries.
const JOB_COLS: &str = "id, type, status, instance_id, payload, result, error, \
    message, actor, created_at, started_at, completed_at, retries";

// ─── Public types ─────────────────────────────────────────────────────────────

/// Observable status values — mirrors Go's `Status` type.
/// Serializes as its lowercase string form (e.g. `"pending"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Status {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Running => "running",
            Status::Completed => "completed",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        }
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)] // intentional infallible parse, not std::str::FromStr
    pub fn from_str(s: &str) -> Self {
        match s {
            "running" => Status::Running,
            "completed" => Status::Completed,
            "failed" => Status::Failed,
            "cancelled" => Status::Cancelled,
            _ => Status::Pending,
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Status {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Status::from_str(&s))
    }
}

/// Job type — mirrors Go's `Type`.
/// Serializes as its `snake_case` string form (e.g. `"create_instance"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobType {
    CreateInstance,
    DeleteInstance,
    RestartInstance,
    InstallClaw,
    UninstallClaw,
    Unknown(String),
}

impl JobType {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            JobType::CreateInstance => "create_instance",
            JobType::DeleteInstance => "delete_instance",
            JobType::RestartInstance => "restart_instance",
            JobType::InstallClaw => "install_claw",
            JobType::UninstallClaw => "uninstall_claw",
            JobType::Unknown(s) => s.as_str(),
        }
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)] // intentional infallible parse, not std::str::FromStr
    pub fn from_str(s: &str) -> Self {
        match s {
            "create_instance" => JobType::CreateInstance,
            "delete_instance" => JobType::DeleteInstance,
            "restart_instance" => JobType::RestartInstance,
            "install_claw" => JobType::InstallClaw,
            "uninstall_claw" => JobType::UninstallClaw,
            other => JobType::Unknown(other.to_string()),
        }
    }
}

impl Serialize for JobType {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JobType {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(JobType::from_str(&s))
    }
}

/// Core job struct.
///
/// Serializes with `snake_case` for API output.  Aliases retain backward
/// compatibility with old `camelCase` rows that may still exist in `SQLite`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Job {
    pub id: String,
    #[serde(rename = "type")]
    pub job_type: JobType,
    pub status: Status,
    #[serde(alias = "instanceId")]
    pub instance_id: String,
    pub payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Who triggered this job (username).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// ISO 8601 UTC string, e.g. "2026-01-01T00:00:00Z"
    #[serde(alias = "createdAt")]
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", alias = "startedAt")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "completedAt")]
    pub completed_at: Option<String>,
    pub retries: i64,
}

impl Job {
    /// Create a new Job with generated ID, status=Pending, and current timestamp.
    pub fn new(
        job_type: JobType,
        instance_id: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        Job {
            id: generate_id(),
            job_type,
            status: Status::Pending,
            instance_id: instance_id.into(),
            payload: payload.into(),
            result: None,
            error: None,
            message: None,
            actor: None,
            created_at: now_iso(),
            started_at: None,
            completed_at: None,
            retries: 0,
        }
    }
}

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("job not found: {0}")]
    NotFound(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

impl core_rs::error::AppError for JobError {
    fn code(&self) -> core_rs::error::ErrorCode {
        match self {
            JobError::NotFound(_) => core_rs::error::ErrorCode::NotFound,
            JobError::Database(_) | JobError::Internal(_) => core_rs::error::ErrorCode::Internal,
        }
    }
}

pub type Result<T> = std::result::Result<T, JobError>;

/// Deprecated: use `JobError` instead.
#[deprecated(note = "renamed to JobError")]
pub type StoreError = JobError;

// ─── Store ────────────────────────────────────────────────────────────────────

/// File-backed job store using `SQLite` WAL.
///
/// A `Mutex<Connection>` serialises intra-process concurrent access.  `SQLite`'s
/// `BEGIN IMMEDIATE` in `claim_next_pending` additionally serialises concurrent
/// writers (including from other processes via WAL locking).
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open or create the jobs `SQLite` database at `path`.
    /// Applies WAL mode, `busy_timeout`, and DDL on every open (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the schema cannot be applied.
    pub fn new(path: &str) -> Result<Self> {
        let conn = core_rs::db::open_wal(std::path::Path::new(path))?;
        schema::apply(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Persist a job. If `job.id` is empty, a new ID is generated.
    /// Sets `status=Pending` and `created_at=now` if not already set.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL insert fails.
    pub fn create(&self, job: &mut Job) -> Result<()> {
        if job.id.is_empty() {
            job.id = generate_id();
        }
        if job.status == Status::Pending && job.created_at.is_empty() {
            job.created_at = now_iso();
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO jobs (id, type, status, instance_id, payload, result, error,
                               message, actor, created_at, started_at, completed_at, retries)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                job.id,
                job.job_type.as_str(),
                job.status.as_str(),
                job.instance_id,
                job.payload,
                job.result,
                job.error,
                job.message,
                job.actor,
                job.created_at,
                job.started_at,
                job.completed_at,
                job.retries,
            ],
        )?;
        Ok(())
    }

    /// Retrieve a job by ID. Returns `JobError::NotFound` if absent.
    ///
    /// # Errors
    ///
    /// Returns `JobError::NotFound` if the job does not exist, or a database
    /// error if the query fails.
    pub fn get(&self, id: &str) -> Result<Job> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let result = conn
            .query_row(
                "SELECT id, type, status, instance_id, payload, result, error,
                    message, actor, created_at, started_at, completed_at, retries
             FROM jobs WHERE id = ?1",
                params![id],
                row_to_job,
            )
            .optional()?;

        result.ok_or_else(|| JobError::NotFound(id.to_string()))
    }

    /// Overwrite a job record in full.
    ///
    /// # Errors
    ///
    /// Returns `JobError::NotFound` if no matching job exists, or a database
    /// error if the update fails.
    pub fn update(&self, job: &Job) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let rows = conn.execute(
            "UPDATE jobs SET type=?2, status=?3, instance_id=?4, payload=?5,
                             result=?6, error=?7, message=?8, actor=?9,
                             started_at=?10, completed_at=?11, retries=?12
             WHERE id=?1",
            params![
                job.id,
                job.job_type.as_str(),
                job.status.as_str(),
                job.instance_id,
                job.payload,
                job.result,
                job.error,
                job.message,
                job.actor,
                job.started_at,
                job.completed_at,
                job.retries,
            ],
        )?;
        if rows == 0 {
            return Err(JobError::NotFound(job.id.clone()));
        }
        Ok(())
    }

    /// Overwrite only the `result` column of a job.
    ///
    /// Cheaper than `update(&Job)` — one indexed single-column UPDATE.
    /// Used by the install worker to report progress throttled to 1 Hz
    /// without rewriting every column on every tick.
    ///
    /// # Semantics
    ///
    /// Historically `Job.result` was only set once at terminal completion
    /// (see `server-rs::jobs_worker::mark_completed`). This function
    /// extends that to "opaque worker-defined metadata valid in any state".
    /// Consumers that read `result` must not assume the job has reached
    /// a terminal status — check `status` separately.
    ///
    /// # Errors
    ///
    /// Returns `JobError::NotFound` if no matching job exists, or an
    /// underlying database error if the UPDATE fails.
    pub fn update_result(&self, id: &str, result_json: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let rows = conn.execute(
            "UPDATE jobs SET result = ?2 WHERE id = ?1",
            params![id, result_json],
        )?;
        if rows == 0 {
            return Err(JobError::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// Delete a job by ID. Returns `JobError::NotFound` if no matching row
    /// exists.
    ///
    /// Used to roll back a job that was created but whose follow-up state
    /// transition failed (see `claw_store_service::install_claw` /
    /// `uninstall_claw`), so the jobs table stays consistent with the claw
    /// store. Mirrors the `rows == 0 -> NotFound` convention of `update` /
    /// `update_result`.
    pub fn delete_by_id(&self, id: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let rows = conn.execute("DELETE FROM jobs WHERE id = ?1", params![id])?;
        if rows == 0 {
            return Err(JobError::NotFound(id.to_string()));
        }
        Ok(())
    }

    /// Mark all pending/running install and uninstall jobs as failed on
    /// server startup.
    ///
    /// Must be called alongside `claw_rs::ClawStore::reset_stale_installing`
    /// (which resets claws in `Installing` AND `Uninstalling` to `Failed`)
    /// to prevent drift between the two stores: if the `ClawStore` is reset
    /// but a pending/running job still exists, the scheduler would
    /// eventually pick it up and try to run it against a store state
    /// that no longer makes sense.
    ///
    /// Covers both `install_claw` and `uninstall_claw` job types, and
    /// both `pending` and `running` statuses (a job can crash before
    /// ever being claimed by the worker).
    ///
    /// Returns the number of rows reset so callers can log it.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL execute fails.
    pub fn reset_stale_install_jobs(&self) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let now = core_rs::time::now_iso_secs();
        let rows = conn.execute(
            "UPDATE jobs
             SET status = 'failed',
                 error = 'server restarted during operation',
                 result = NULL,
                 completed_at = ?1
             WHERE type IN ('install_claw', 'uninstall_claw')
               AND status IN ('pending', 'running')",
            params![now],
        )?;
        Ok(rows)
    }

    /// Return pending jobs sorted oldest-first (by `created_at` ASC).
    /// `limit=0` returns all.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_pending(&self, limit: usize) -> Result<Vec<Job>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let sql = if limit > 0 {
            format!(
                "SELECT id, type, status, instance_id, payload, result, error,
                        message, actor, created_at, started_at, completed_at, retries
                 FROM jobs WHERE status='pending' ORDER BY created_at ASC LIMIT {limit}"
            )
        } else {
            "SELECT id, type, status, instance_id, payload, result, error,
                    message, actor, created_at, started_at, completed_at, retries
             FROM jobs WHERE status='pending' ORDER BY created_at ASC"
                .to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        let jobs = stmt
            .query_map([], row_to_job)?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(jobs)
    }

    /// Return jobs for a specific instance, newest-first.
    /// `limit=0` returns all.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_by_instance(&self, instance_id: &str, limit: usize) -> Result<Vec<Job>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let sql = if limit > 0 {
            format!(
                "SELECT id, type, status, instance_id, payload, result, error,
                        message, actor, created_at, started_at, completed_at, retries
                 FROM jobs WHERE instance_id=?1 ORDER BY created_at DESC LIMIT {limit}"
            )
        } else {
            "SELECT id, type, status, instance_id, payload, result, error,
                    message, actor, created_at, started_at, completed_at, retries
             FROM jobs WHERE instance_id=?1 ORDER BY created_at DESC"
                .to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        let jobs = stmt
            .query_map(params![instance_id], row_to_job)?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(jobs)
    }

    /// Return all jobs, newest-first. `limit=0` returns all.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_recent(&self, limit: usize) -> Result<Vec<Job>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let sql = if limit > 0 {
            format!("SELECT {JOB_COLS} FROM jobs ORDER BY created_at DESC LIMIT {limit}")
        } else {
            format!("SELECT {JOB_COLS} FROM jobs ORDER BY created_at DESC")
        };
        let mut stmt = conn.prepare(&sql)?;
        let jobs = stmt
            .query_map([], row_to_job)?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(jobs)
    }

    /// Paginated job list. Returns up to `limit + 1` rows so the caller
    /// can detect `has_more`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_paginated(&self, limit: usize, cursor: Option<(&str, &str)>) -> Result<Vec<Job>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let fetch = limit + 1;
        if let Some((created_at, id)) = cursor {
            let sql = format!(
                "SELECT {JOB_COLS} FROM jobs \
                 WHERE (created_at, id) < (?1, ?2) \
                 ORDER BY created_at DESC, id DESC LIMIT {fetch}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let jobs = stmt
                .query_map(params![created_at, id], row_to_job)?
                .collect::<SqlResult<Vec<_>>>()?;
            Ok(jobs)
        } else {
            let sql = format!(
                "SELECT {JOB_COLS} FROM jobs \
                 ORDER BY created_at DESC, id DESC LIMIT {fetch}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let jobs = stmt
                .query_map([], row_to_job)?
                .collect::<SqlResult<Vec<_>>>()?;
            Ok(jobs)
        }
    }

    /// Atomically claim the oldest pending job → Running.
    ///
    /// Uses `BEGIN IMMEDIATE` to serialise concurrent claimers: only one
    /// writer can hold an IMMEDIATE transaction at a time in `SQLite` WAL mode.
    /// The `AND status='pending'` guard in the UPDATE makes the claim
    /// idempotent even if two writers somehow race inside the same transaction.
    ///
    /// Returns `Ok(None)` when no pending jobs exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned, a race is detected, or the
    /// SQL transaction fails.
    pub fn claim_next_pending(&self) -> Result<Option<Job>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;

        // BEGIN IMMEDIATE acquires a reserved lock immediately, blocking other
        // writers without blocking readers.
        conn.execute_batch("BEGIN IMMEDIATE")?;

        // Find oldest pending job
        let maybe_job: Option<Job> = conn
            .query_row(
                "SELECT id, type, status, instance_id, payload, result, error,
                        message, actor, created_at, started_at, completed_at, retries
                 FROM jobs WHERE status='pending' ORDER BY created_at ASC LIMIT 1",
                [],
                row_to_job,
            )
            .optional()?;

        let Some(mut job) = maybe_job else {
            conn.execute_batch("COMMIT")?;
            return Ok(None);
        };

        let now = now_iso();
        job.status = Status::Running;
        job.started_at = Some(now.clone());
        job.message = Some("Processing...".to_string());

        let rows = conn.execute(
            "UPDATE jobs SET status='running', started_at=?2, message='Processing...'
             WHERE id=?1 AND status='pending'",
            params![job.id, now],
        )?;

        if rows == 0 {
            // Race: another writer claimed it between SELECT and UPDATE.
            conn.execute_batch("ROLLBACK")?;
            return Err(JobError::Internal(format!("claim race on job {}", job.id)));
        }

        conn.execute_batch("COMMIT")?;
        Ok(Some(job))
    }

    /// Like [`claim_next_pending`](Self::claim_next_pending) but only claims jobs
    /// whose type is in the `include` list.
    ///
    /// Used by the install worker to only process `install_claw`/`uninstall_claw`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL transaction fails.
    pub fn claim_next_pending_by_types(&self, include: &[&str]) -> Result<Option<Job>> {
        self.claim_next_pending_filtered(include, true)
    }

    /// Like [`claim_next_pending`](Self::claim_next_pending) but skips jobs
    /// whose type is in the `exclude` list.
    ///
    /// Used by the main jobs worker to skip `install_claw`/`uninstall_claw`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL transaction fails.
    pub fn claim_next_pending_excluding(&self, exclude: &[&str]) -> Result<Option<Job>> {
        self.claim_next_pending_filtered(exclude, false)
    }

    /// Internal helper for filtered claims.
    ///
    /// `is_include = true`: only match types in the list.
    /// `is_include = false`: exclude types in the list.
    fn claim_next_pending_filtered(&self, types: &[&str], is_include: bool) -> Result<Option<Job>> {
        if types.is_empty() {
            return self.claim_next_pending();
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;

        conn.execute_batch("BEGIN IMMEDIATE")?;

        let op = if is_include { "IN" } else { "NOT IN" };
        let placeholders: Vec<String> = (1..=types.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT id, type, status, instance_id, payload, result, error,
                    message, actor, created_at, started_at, completed_at, retries
             FROM jobs WHERE status='pending' AND type {op} ({})
             ORDER BY created_at ASC LIMIT 1",
            placeholders.join(", ")
        );

        let maybe_job: Option<Job> = {
            let mut stmt = conn.prepare(&sql)?;
            let params: Vec<&dyn rusqlite::types::ToSql> = types
                .iter()
                .map(|s| s as &dyn rusqlite::types::ToSql)
                .collect();
            stmt.query_row(rusqlite::params_from_iter(params.iter()), row_to_job)
                .optional()?
        };

        let Some(mut job) = maybe_job else {
            conn.execute_batch("COMMIT")?;
            return Ok(None);
        };

        let now = now_iso();
        job.status = Status::Running;
        job.started_at = Some(now.clone());
        job.message = Some("Processing...".to_string());

        let rows = conn.execute(
            "UPDATE jobs SET status='running', started_at=?2, message='Processing...'
             WHERE id=?1 AND status='pending'",
            params![job.id, now],
        )?;

        if rows == 0 {
            conn.execute_batch("ROLLBACK")?;
            return Err(JobError::Internal(format!("claim race on job {}", job.id)));
        }

        conn.execute_batch("COMMIT")?;
        Ok(Some(job))
    }

    /// Remove jobs whose `completed_at` is older than `older_than_secs`.
    /// Returns count of deleted jobs.
    /// Mark all `running` jobs as `failed` with the given reason.
    ///
    /// Called at startup to recover from a previous unclean shutdown where jobs
    /// were left in `running` state.  Returns the number of rows updated.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn fail_running_jobs(&self, reason: &str) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let now = now_iso();
        let rows = conn.execute(
            "UPDATE jobs SET status='failed', error=?1, completed_at=?2
             WHERE status='running'",
            params![reason, now],
        )?;
        Ok(rows as u64)
    }

    /// Clean up completed jobs older than the given threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn cleanup_old(&self, older_than_secs: u64) -> Result<u64> {
        let cutoff_secs = unix_now_secs().saturating_sub(older_than_secs);
        // SQLite datetime comparison via string ordering works for ISO 8601 UTC.
        let cutoff = format_iso(cutoff_secs);
        let conn = self
            .conn
            .lock()
            .map_err(|_| JobError::Internal("jobs lock poisoned".into()))?;
        let rows = conn.execute(
            "DELETE FROM jobs WHERE completed_at IS NOT NULL AND completed_at < ?1",
            params![cutoff],
        )?;
        Ok(rows as u64)
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn row_to_job(row: &rusqlite::Row<'_>) -> SqlResult<Job> {
    Ok(Job {
        id: row.get(0)?,
        job_type: JobType::from_str(&row.get::<_, String>(1)?),
        status: Status::from_str(&row.get::<_, String>(2)?),
        instance_id: row.get(3)?,
        payload: row.get(4)?,
        result: row.get(5)?,
        error: row.get(6)?,
        message: row.get(7)?,
        actor: row.get(8)?,
        created_at: row.get(9)?,
        started_at: row.get(10)?,
        completed_at: row.get(11)?,
        retries: row.get(12)?,
    })
}

/// Generate a random job ID: "job_" + 16 hex chars.
#[must_use]
pub fn generate_id() -> String {
    core_rs::id::generate_id("job")
}

fn unix_now_secs() -> u64 {
    core_rs::time::unix_now_secs()
}

fn format_iso(secs: u64) -> String {
    core_rs::time::format_iso(secs)
}

#[must_use]
pub fn now_iso() -> String {
    core_rs::time::now_iso_secs()
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    fn temp_db() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = core_rs::time::unix_now_nanos();
        let path = format!("/tmp/jobs_rs_test_{ts}_{n}.db");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn make_job() -> Job {
        Job::new(
            JobType::CreateInstance,
            "inst-test",
            r#"{"name":"test","clawType":"picoclaw","port":0}"#,
        )
    }

    #[test]
    fn store_new_creates_table() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        // If the table was created we can query it without error.
        let jobs = s.list_pending(0).expect("list_pending on fresh db");
        assert!(jobs.is_empty());
    }

    #[test]
    fn create_sets_pending_status() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        s.create(&mut job).expect("create");
        assert_eq!(job.status, Status::Pending);
    }

    #[test]
    fn create_auto_generates_id() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        job.id = String::new(); // force auto-generation
        s.create(&mut job).expect("create");
        assert!(!job.id.is_empty(), "ID should be auto-generated");
    }

    #[test]
    fn create_preserves_provided_id() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        job.id = "job_fixed_id_xyz".to_string();
        s.create(&mut job).expect("create");
        let got = s.get("job_fixed_id_xyz").expect("get");
        assert_eq!(got.id, "job_fixed_id_xyz");
    }

    #[test]
    fn get_returns_created_job() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        s.create(&mut job).expect("create");
        let got = s.get(&job.id).expect("get");
        assert_eq!(got.id, job.id);
        assert_eq!(got.instance_id, "inst-test");
        assert_eq!(got.status, Status::Pending);
    }

    #[test]
    fn get_missing_errors() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let result = s.get("nonexistent_id");
        assert!(
            matches!(result, Err(JobError::NotFound(_))),
            "expected NotFound, got {result:?}"
        );
    }

    #[test]
    fn update_changes_status() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        s.create(&mut job).expect("create");
        job.status = Status::Completed;
        job.completed_at = Some(now_iso());
        s.update(&job).expect("update");
        let got = s.get(&job.id).expect("get after update");
        assert_eq!(got.status, Status::Completed);
    }

    #[test]
    fn claim_returns_none_when_empty() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let result = s.claim_next_pending().expect("claim on empty");
        assert!(result.is_none(), "expected None on empty store");
    }

    #[test]
    fn claim_sets_running() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        s.create(&mut job).expect("create");
        let claimed = s.claim_next_pending().expect("claim").expect("some job");
        assert_eq!(claimed.status, Status::Running);
        assert!(claimed.started_at.is_some(), "started_at must be set");
        assert_eq!(claimed.message.as_deref(), Some("Processing..."));
    }

    #[test]
    fn claim_oldest_first() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        let mut old = Job {
            id: "old_job".to_string(),
            job_type: JobType::CreateInstance,
            status: Status::Pending,
            instance_id: "inst-old".to_string(),
            payload: "{}".to_string(),
            result: None,
            error: None,
            message: None,
            actor: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            started_at: None,
            completed_at: None,
            retries: 0,
        };
        let mut new = Job {
            id: "new_job".to_string(),
            job_type: JobType::CreateInstance,
            status: Status::Pending,
            instance_id: "inst-new".to_string(),
            payload: "{}".to_string(),
            result: None,
            error: None,
            message: None,
            actor: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            started_at: None,
            completed_at: None,
            retries: 0,
        };
        s.create(&mut old).expect("create old");
        s.create(&mut new).expect("create new");

        let claimed = s.claim_next_pending().expect("claim").expect("some job");
        assert_eq!(
            claimed.instance_id, "inst-old",
            "should claim oldest job first"
        );
    }

    #[test]
    fn claim_skips_non_pending() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        // Create a job and mark it running manually
        let mut running = make_job();
        running.instance_id = "inst-running".to_string();
        s.create(&mut running).expect("create running");
        running.status = Status::Running;
        running.started_at = Some(now_iso());
        s.update(&running).expect("update to running");

        // Create a pending job
        let mut pending = make_job();
        pending.instance_id = "inst-pending".to_string();
        s.create(&mut pending).expect("create pending");

        let claimed = s.claim_next_pending().expect("claim").expect("some job");
        assert_eq!(claimed.instance_id, "inst-pending");
    }

    #[test]
    fn claim_concurrent_no_duplicates() {
        // 10 threads racing to claim 1 job → exactly 1 or 0 claims
        // (0 is acceptable if a race causes an error, but duplicates are not)
        let path = temp_db();
        let store = Arc::new(Store::new(&path).expect("Store::new"));

        let mut job = make_job();
        store.create(&mut job).expect("create");

        let claimed = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut handles = vec![];
        for _ in 0..10 {
            let s = Arc::clone(&store);
            let c = Arc::clone(&claimed);
            handles.push(std::thread::spawn(move || {
                if let Ok(Some(_)) = s.claim_next_pending() {
                    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let n = claimed.load(std::sync::atomic::Ordering::SeqCst);
        assert!(n <= 1, "expected at most 1 claim, got {n}");
    }

    #[test]
    fn list_pending_sorted_oldest_first() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        for (instance_id, ts) in [
            ("inst-mid", "2023-06-01T00:00:00Z"),
            ("inst-old", "2020-01-01T00:00:00Z"),
            ("inst-new", "2025-01-01T00:00:00Z"),
        ] {
            let mut job = Job {
                id: generate_id(),
                job_type: JobType::CreateInstance,
                status: Status::Pending,
                instance_id: instance_id.to_string(),
                payload: "{}".to_string(),
                result: None,
                error: None,
                message: None,
                actor: None,
                created_at: ts.to_string(),
                started_at: None,
                completed_at: None,
                retries: 0,
            };
            s.create(&mut job).expect("create");
        }

        let pending = s.list_pending(0).expect("list_pending");
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].instance_id, "inst-old");
        assert_eq!(pending[1].instance_id, "inst-mid");
        assert_eq!(pending[2].instance_id, "inst-new");
    }

    #[test]
    fn list_pending_excludes_running() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        let mut running = make_job();
        running.instance_id = "inst-running".to_string();
        s.create(&mut running).expect("create");
        running.status = Status::Running;
        running.started_at = Some(now_iso());
        s.update(&running).expect("update");

        let mut pending = make_job();
        pending.instance_id = "inst-pending".to_string();
        s.create(&mut pending).expect("create");

        let list = s.list_pending(0).expect("list_pending");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].instance_id, "inst-pending");
    }

    #[test]
    fn generate_id_produces_unique_ids() {
        let n = 200;
        let ids: std::collections::HashSet<String> = (0..n).map(|_| generate_id()).collect();
        assert_eq!(ids.len(), n, "all generated IDs must be unique");
    }

    #[test]
    fn now_iso_format_looks_correct() {
        let iso = now_iso();
        // e.g. "2026-02-25T12:34:56Z"
        assert_eq!(iso.len(), 20, "ISO string length = {iso}");
        assert!(iso.ends_with('Z'), "must end with Z: {iso}");
        assert!(iso.contains('T'), "must contain T: {iso}");
    }

    #[test]
    fn install_claw_job_type_roundtrip() {
        assert_eq!(JobType::InstallClaw.as_str(), "install_claw");
        assert_eq!(JobType::from_str("install_claw"), JobType::InstallClaw);
    }

    #[test]
    fn uninstall_claw_job_type_roundtrip() {
        assert_eq!(JobType::UninstallClaw.as_str(), "uninstall_claw");
        assert_eq!(JobType::from_str("uninstall_claw"), JobType::UninstallClaw);
    }

    #[test]
    fn claim_by_types_filters_correctly() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        // Create one instance job and one install job
        let mut inst_job = make_job(); // CreateInstance
        inst_job.instance_id = "inst-a".to_string();
        s.create(&mut inst_job).expect("create");

        let mut install_job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
        s.create(&mut install_job).expect("create");

        // claim_by_types with install_claw should only get the install job
        let claimed = s
            .claim_next_pending_by_types(&["install_claw"])
            .expect("claim")
            .expect("should find install job");
        assert_eq!(claimed.job_type, JobType::InstallClaw);
        assert_eq!(claimed.instance_id, "picoclaw");

        // The instance job should still be pending
        let pending = s.list_pending(0).expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].instance_id, "inst-a");
    }

    #[test]
    fn claim_excluding_filters_correctly() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        // Create one install job and one instance job
        let mut install_job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
        install_job.created_at = "2020-01-01T00:00:00Z".to_string();
        s.create(&mut install_job).expect("create");

        let mut inst_job = make_job(); // CreateInstance
        inst_job.instance_id = "inst-a".to_string();
        inst_job.created_at = "2025-01-01T00:00:00Z".to_string();
        s.create(&mut inst_job).expect("create");

        // claim_excluding install types should skip the install job
        let claimed = s
            .claim_next_pending_excluding(&["install_claw", "uninstall_claw"])
            .expect("claim")
            .expect("should find instance job");
        assert_eq!(claimed.job_type, JobType::CreateInstance);
        assert_eq!(claimed.instance_id, "inst-a");

        // The install job should still be pending
        let pending = s.list_pending(0).expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].job_type, JobType::InstallClaw);
    }

    #[test]
    fn update_result_overwrites_only_result_column() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = Job::new(JobType::InstallClaw, "picoclaw", "{}");
        s.create(&mut job).expect("create");
        let job_id = job.id.clone();

        // First write
        s.update_result(&job_id, r#"{"phase":"downloading","percent":25}"#)
            .expect("update_result");
        let got = s.get(&job_id).expect("get");
        assert_eq!(
            got.result.as_deref(),
            Some(r#"{"phase":"downloading","percent":25}"#)
        );
        // Status must be unchanged
        assert_eq!(got.status, Status::Pending);

        // Overwrite
        s.update_result(&job_id, r#"{"phase":"downloading","percent":75}"#)
            .expect("update_result");
        let got = s.get(&job_id).expect("get");
        assert_eq!(
            got.result.as_deref(),
            Some(r#"{"phase":"downloading","percent":75}"#)
        );
    }

    #[test]
    fn update_result_returns_not_found_for_missing_job() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let err = s
            .update_result("does-not-exist", "{}")
            .expect_err("should be NotFound");
        matches!(err, JobError::NotFound(_));
    }

    #[test]
    fn delete_by_id_removes_created_job() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let mut job = make_job();
        s.create(&mut job).expect("create");
        s.delete_by_id(&job.id).expect("delete");
        assert!(
            matches!(s.get(&job.id), Err(JobError::NotFound(_))),
            "job should be gone after delete_by_id"
        );
    }

    #[test]
    fn delete_by_id_returns_not_found_for_missing_job() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");
        let err = s
            .delete_by_id("does-not-exist")
            .expect_err("should be NotFound");
        assert!(
            matches!(err, JobError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn reset_stale_install_jobs_covers_install_and_uninstall_pending_and_running() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        // install_claw / pending
        let mut j1 = Job::new(JobType::InstallClaw, "picoclaw", "{}");
        s.create(&mut j1).expect("create");

        // install_claw / running
        let mut j2 = Job::new(JobType::InstallClaw, "zeroclaw", "{}");
        s.create(&mut j2).expect("create");
        j2.status = Status::Running;
        j2.started_at = Some(now_iso());
        s.update(&j2).expect("update");

        // uninstall_claw / pending
        let mut j3 = Job::new(JobType::UninstallClaw, "nanobot", "{}");
        s.create(&mut j3).expect("create");

        // uninstall_claw / running
        let mut j4 = Job::new(JobType::UninstallClaw, "openclaw", "{}");
        s.create(&mut j4).expect("create");
        j4.status = Status::Running;
        j4.started_at = Some(now_iso());
        s.update(&j4).expect("update");

        // create_instance / running — must NOT be touched
        let mut j5 = make_job();
        j5.instance_id = "inst-untouched".to_string();
        s.create(&mut j5).expect("create");
        j5.status = Status::Running;
        j5.started_at = Some(now_iso());
        s.update(&j5).expect("update");

        let reset = s.reset_stale_install_jobs().expect("reset");
        assert_eq!(reset, 4, "should reset all 4 install/uninstall jobs");

        // All four install/uninstall jobs now Failed
        for (id, _) in [
            (j1.id.as_str(), "j1"),
            (j2.id.as_str(), "j2"),
            (j3.id.as_str(), "j3"),
            (j4.id.as_str(), "j4"),
        ] {
            let got = s.get(id).expect("get");
            assert_eq!(got.status, Status::Failed);
            assert!(got.error.is_some());
            assert_eq!(got.result, None, "result must be cleared on reset");
            assert!(got.completed_at.is_some());
        }

        // create_instance untouched
        let got_inst = s.get(&j5.id).expect("get");
        assert_eq!(got_inst.status, Status::Running);
        assert!(got_inst.error.is_none());
    }

    #[test]
    fn reset_stale_install_jobs_leaves_already_completed_alone() {
        let path = temp_db();
        let s = Store::new(&path).expect("Store::new");

        let mut j = Job::new(JobType::InstallClaw, "picoclaw", "{}");
        s.create(&mut j).expect("create");
        j.status = Status::Completed;
        j.completed_at = Some(now_iso());
        j.result = Some(r#"{"ok":true}"#.to_string());
        s.update(&j).expect("update");

        let reset = s.reset_stale_install_jobs().expect("reset");
        assert_eq!(reset, 0);

        let got = s.get(&j.id).expect("get");
        assert_eq!(got.status, Status::Completed);
        assert_eq!(got.result.as_deref(), Some(r#"{"ok":true}"#));
    }
}
