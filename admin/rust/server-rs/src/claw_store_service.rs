//! Shared Claw Store install/uninstall semantics.
//!
//! HTTP handlers stay as surface-specific auth/status adapters. This module
//! owns the manifest, installability, status, job, and `ClawStore` mutations so
//! admin, mobile, and household-forwarded routes cannot drift.

use crate::{responses::ClawJobResponse, state::SharedState};
use claw_rs::ClawStatus;
use core_rs::{
    error::{ApiError, blocking},
    manifest::{ClawInstallability, UnavailableReasonCode},
};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawStoreAction {
    Install,
    Uninstall,
}

#[derive(Debug)]
pub enum ClawActionOutcome {
    AlreadyInstalling {
        job_id: String,
    },
    Queued {
        action: ClawStoreAction,
        job_id: String,
        claw_name: String,
    },
}

impl ClawActionOutcome {
    #[must_use]
    pub const fn is_already_installing(&self) -> bool {
        matches!(self, Self::AlreadyInstalling { .. })
    }

    #[must_use]
    pub fn into_job_response(self) -> ClawJobResponse {
        match self {
            Self::AlreadyInstalling { job_id } => {
                ClawJobResponse::install_already_in_progress(job_id)
            }
            Self::Queued {
                action: ClawStoreAction::Install,
                job_id,
                claw_name,
            } => ClawJobResponse::install_queued(job_id, &claw_name),
            Self::Queued {
                action: ClawStoreAction::Uninstall,
                job_id,
                claw_name,
            } => ClawJobResponse::uninstall_queued(job_id, &claw_name),
        }
    }
}

/// Queue a Claw install or report the current pre-existing install state.
///
/// # Errors
///
/// Returns the current v1 API errors for unknown claws, unavailable install
/// entries, already-ready claws, job creation failures, or store mutations.
pub async fn install_claw(
    state: &SharedState,
    name: String,
) -> Result<ClawActionOutcome, ApiError> {
    let Some(entry) = core_rs::manifest::get(&name) else {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    };

    if let ClawInstallability::Unavailable { code, message } = entry.installability() {
        return Err(install_unavailable_error(&name, code, &message));
    }

    match state.claw_store.get_status(&name) {
        ClawStatus::Ready => {
            return Err(ApiError::bad_request(format!(
                "claw type '{name}' is already installed"
            )));
        }
        ClawStatus::Installing => {
            let existing_state = state.claw_store.get_state(&name);
            let job_id = existing_state
                .and_then(|state| state.job_id)
                .unwrap_or_default();
            return Ok(ClawActionOutcome::AlreadyInstalling { job_id });
        }
        ClawStatus::NotInstalled | ClawStatus::Failed | ClawStatus::Uninstalling => {}
    }

    let mut job = jobs_rs::Job::new(jobs_rs::JobType::InstallClaw, &name, "{}");
    let job_id = job.id.clone();
    let claw_name = name.clone();

    let st = state.clone();
    blocking(move || {
        st.jobs
            .create(&mut job)
            .map_err(|e| ApiError::internal(format!("failed to create install job: {e}")))
    })
    .await??;

    state
        .claw_store
        .mark_installing(&claw_name, &job_id)
        .map_err(|e| ApiError::internal(format!("failed to mark installing: {e}")))?;

    tracing::info!("[claw-store] install queued: claw={claw_name} job={job_id}");

    Ok(ClawActionOutcome::Queued {
        action: ClawStoreAction::Install,
        job_id,
        claw_name,
    })
}

/// Queue a Claw uninstall after preserving the current readiness and instance
/// guard semantics.
///
/// # Errors
///
/// Returns the current v1 API errors for unknown claws, not-ready claws,
/// existing instances, job creation failures, or store mutations.
pub async fn uninstall_claw(
    state: &SharedState,
    name: String,
) -> Result<ClawActionOutcome, ApiError> {
    if !core_rs::manifest::is_known(&name) {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    }

    if !state.claw_store.is_ready(&name) {
        return Err(ApiError::bad_request(format!(
            "claw type '{name}' is not installed"
        )));
    }

    let n = name.clone();
    let st = state.clone();
    let count = blocking(move || {
        st.instance_db
            .count_by_claw_type(&n)
            .map_err(|e| ApiError::internal(format!("failed to count instances: {e}")))
    })
    .await??;

    if count > 0 {
        return Err(ApiError::bad_request(format!(
            "cannot uninstall: {count} instance(s) of type '{name}' still exist — delete them first"
        )));
    }

    let mut job = jobs_rs::Job::new(jobs_rs::JobType::UninstallClaw, &name, "{}");
    let job_id = job.id.clone();
    let claw_name = name.clone();

    let st = state.clone();
    blocking(move || {
        st.jobs
            .create(&mut job)
            .map_err(|e| ApiError::internal(format!("failed to create uninstall job: {e}")))
    })
    .await??;

    state
        .claw_store
        .mark_uninstalling(&claw_name)
        .map_err(|e| ApiError::internal(format!("failed to mark uninstalling: {e}")))?;

    tracing::info!("[claw-store] uninstall queued: claw={claw_name} job={job_id}");

    Ok(ClawActionOutcome::Queued {
        action: ClawStoreAction::Uninstall,
        job_id,
        claw_name,
    })
}

fn install_unavailable_error(name: &str, code: UnavailableReasonCode, message: &str) -> ApiError {
    ApiError::bad_request_with_reasons(
        format!("claw type '{name}' is not installable yet: {message}"),
        json!({
            "unavailable_reason_code": code,
            "unavailable_reason": message,
        }),
    )
}
