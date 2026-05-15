//! Job handlers:
//!   GET /api/v1/jobs
//!   GET /api/v1/jobs/{id}

use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use core_rs::error::{ApiError, blocking};
use core_rs::pagination::{PaginationParams, decode_cursor, encode_cursor};
use serde_json::{Value, json};

/// `GET /api/v1/jobs`
///
/// Supports cursor pagination: `?limit=N&cursor=...`
/// When no params are given, returns the 100 most recent jobs.
///
/// # Errors
///
/// Returns `ApiError` if the job database query or blocking task fails.
pub async fn handle_list_jobs(
    State(state): State<SharedState>,
    Query(q): Query<PaginationParams>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.effective_limit(100, 200);
    let cursor = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(|| ApiError::bad_request("invalid cursor")))
        .transpose()?;

    let mut jobs = blocking(move || {
        let cur_ref = cursor.as_ref().map(|(s, id)| (s.as_str(), id.as_str()));
        state
            .jobs
            .list_paginated(limit, cur_ref)
            .map_err(ApiError::from)
    })
    .await??;

    let has_more = jobs.len() > limit;
    if has_more {
        jobs.truncate(limit);
    }
    let next_cursor = if has_more {
        jobs.last().map(|j| encode_cursor(&j.created_at, &j.id))
    } else {
        None
    };

    Ok(Json(
        json!({ "data": jobs, "has_more": has_more, "next_cursor": next_cursor }),
    ))
}

/// `GET /api/v1/jobs/{id}`
///
/// # Errors
///
/// Returns `ApiError` if the job is not found or the database query fails.
pub async fn handle_get_job(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let job = blocking(move || state.jobs.get(&id).map_err(ApiError::from)).await??;
    Ok(Json(serde_json::to_value(job).unwrap_or_default()))
}
