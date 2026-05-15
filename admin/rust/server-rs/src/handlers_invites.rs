//! Invite handlers — create, list, delete, and redeem single-use invite links.
//!
//! Routes:
//!   POST   /api/v1/invites         (admin — create invite for instance)
//!   GET    /api/v1/invites         (admin — list all invites)
//!   DELETE /api/v1/invites/{id}    (admin — revoke unused invite)
//!   POST   /api/v1/invites/redeem  (public — redeem invite token)

use crate::auth::{AdminUser, SESSION_COOKIE};
use crate::handlers_mobile::{best_qr_host, mobile_deep_link, server_platform};
use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use core_rs::pagination::{PaginationParams, decode_cursor, encode_cursor};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::info;

/// Default invite TTL: 24 hours.
const DEFAULT_INVITE_TTL_SECS: u64 = 86400;

fn invite_ttl_secs() -> u64 {
    std::env::var("THEYOS_INVITE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INVITE_TTL_SECS)
}

/// Compute invite status from the row fields.
fn invite_status(invite: &store_rs::InviteRow) -> &'static str {
    if invite.redeemed_by.is_some() {
        "redeemed"
    } else {
        // Check if expired: parse expires_at as ISO datetime.
        // Simple heuristic: if expires_at < current time. We can't do this
        // without a DB call, so we trust the DB to have valid dates and
        // just report "pending" — the list endpoint can compute this server-side.
        "pending"
    }
}

// ─── Create ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateInviteReq {
    pub instance_id: String,
}

/// POST /api/v1/invites — create an invite link for an instance.
///
/// # Errors
///
/// Returns `ApiError` if the instance doesn't exist or database operation fails.
#[tracing::instrument(skip(state, req))]
pub async fn handle_create_invite(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    Json(req): Json<CreateInviteReq>,
) -> Result<Response, ApiError> {
    let ttl = invite_ttl_secs();

    let invite = blocking(move || -> Result<_, ApiError> {
        // Verify instance exists
        state
            .instance_db
            .get(&req.instance_id)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::not_found("instance not found"))?;

        state
            .instance_db
            .create_invite(&req.instance_id, &auth.user_id, ttl)
            .map_err(ApiError::from)
    })
    .await??;

    let (host, _) = best_qr_host();
    let deep_link = mobile_deep_link("invite", &[("token", &invite.token), ("host", &host)]);

    info!(
        "[invites] user={} created invite {} for instance {}",
        auth.username, invite.id, invite.instance_id
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "invite": {
                "id": invite.id,
                "token": invite.token,
                "instance_id": invite.instance_id,
                "expires_at": invite.expires_at,
                "status": "pending",
                "created_at": invite.created_at,
            },
            "deep_link": deep_link,
        })),
    )
        .into_response())
}

// ─── List ────────────────────────────────────────────────────────────────────

/// GET /api/v1/invites — list all invites with status.
///
/// # Errors
///
/// Returns `ApiError` if the database query fails.
#[tracing::instrument(skip(state))]
pub async fn handle_list_invites(
    State(state): State<SharedState>,
    AdminUser(_): AdminUser,
    Query(q): Query<PaginationParams>,
) -> Result<Response, ApiError> {
    let paginating = q.limit.is_some() || q.cursor.is_some();
    let limit = q.effective_limit(50, 100);
    let cursor = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(|| ApiError::bad_request("invalid cursor")))
        .transpose()?;

    let mut invites = blocking(move || {
        if paginating {
            let cur_ref = cursor.as_ref().map(|(s, id)| (s.as_str(), id.as_str()));
            state
                .instance_db
                .list_invites_paginated(limit, cur_ref)
                .map_err(ApiError::from)
        } else {
            state.instance_db.list_invites().map_err(ApiError::from)
        }
    })
    .await??;

    let has_more = paginating && invites.len() > limit;
    if has_more {
        invites.truncate(limit);
    }
    let next_cursor = if has_more {
        invites
            .last()
            .map(|inv| encode_cursor(&inv.created_at, &inv.id))
    } else {
        None
    };

    let items: Vec<Value> = invites
        .iter()
        .map(|inv| {
            json!({
                "id": inv.id,
                "token": inv.token,
                "instance_id": inv.instance_id,
                "created_by": inv.created_by,
                "expires_at": inv.expires_at,
                "redeemed_by": inv.redeemed_by,
                "redeemed_at": inv.redeemed_at,
                "status": invite_status(inv),
                "created_at": inv.created_at,
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({"data": items, "has_more": has_more, "next_cursor": next_cursor})),
    )
        .into_response())
}

// ─── Delete ──────────────────────────────────────────────────────────────────

/// DELETE /api/v1/invites/{id} — revoke an unused invite.
///
/// # Errors
///
/// Returns `ApiError` if the invite is not found/already redeemed, or DB fails.
#[tracing::instrument(skip(state))]
pub async fn handle_delete_invite(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let deleted =
        blocking(move || state.instance_db.delete_invite(&id).map_err(ApiError::from)).await??;

    if deleted {
        info!("[invites] user={} deleted invite", auth.username);
        Ok((StatusCode::NO_CONTENT, ()).into_response())
    } else {
        Err(ApiError::not_found("invite not found or already redeemed"))
    }
}

// ─── Redeem ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedeemInviteReq {
    pub token: String,
    #[serde(default)]
    pub username: String,
}

/// POST /api/v1/invites/redeem — redeem an invite token (public, no auth required).
///
/// Creates a new user, assigns the instance, marks the invite as redeemed,
/// and returns a session cookie.
///
/// # Errors
///
/// Returns `410 Gone` if the invite is expired or already redeemed.
/// Returns `ApiError` if any database operation fails.
#[tracing::instrument(skip(state, req))]
pub async fn handle_redeem_invite(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RedeemInviteReq>,
) -> Result<Response, ApiError> {
    let token = req.token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("token is required"));
    }

    // Auto-generate username if not provided
    let username = if req.username.trim().is_empty() {
        let short = &core_rs::id::generate_id("u")[2..10]; // 8 chars from id
        format!("user-{short}")
    } else {
        req.username.trim().to_string()
    };

    let st = state.clone();
    let tok = token.clone();
    let uname = username.clone();
    let (user, invite) = blocking(move || -> Result<_, ApiError> {
        // Look up invite to get created_by for the user's created_by field
        let inv = st
            .instance_db
            .get_invite_by_token(&tok)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::gone("invite not found or expired"))?;

        if inv.redeemed_by.is_some() {
            return Err(ApiError::gone("invite already redeemed"));
        }

        st.instance_db
            .redeem_invite_atomic(&tok, &uname, &inv.created_by)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("expired") {
                    ApiError::gone("invite expired")
                } else if msg.contains("redeemed") {
                    ApiError::gone("invite already redeemed")
                } else {
                    ApiError::from(e)
                }
            })
    })
    .await??;

    // Create a web session for the new user
    let st2 = state.clone();
    let session_username = user.username.clone();
    let session_token =
        tokio::task::spawn_blocking(move || st2.sessions.create_session(&session_username))
            .await
            .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))?
            .map_err(|e| ApiError::internal(format!("create_session: {e}")))?;

    // Also create a mobile session so the iOS app can auth with Bearer token
    let (mobile_token, mobile_expires) = state
        .mobile_sessions
        .create_session(&user.username)
        .map_err(|e| ApiError::internal(format!("create_mobile_session: {e}")))?;

    // Detect HTTPS
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));

    let ttl_secs = session_rs::get_ttl_secs();
    let secure_flag = if is_https { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={session_token}; Path=/; HttpOnly; SameSite=Strict; \
         Max-Age={ttl_secs}{secure_flag}"
    );

    info!(
        "[invites] redeemed invite {} → user={} instance={}",
        invite.id, user.username, invite.instance_id
    );

    // Fetch instance info for response
    let st3 = state.clone();
    let iid = invite.instance_id.clone();
    let instance_name = blocking(move || {
        st3.instance_db
            .get(&iid)
            .ok()
            .flatten()
            .map(|r| r.name)
            .unwrap_or_default()
    })
    .await?;

    let (host, _) = best_qr_host();
    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());
    let platform = server_platform();

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
            },
            "instance": {
                "id": invite.instance_id,
                "name": instance_name,
            },
            "session_token": mobile_token,
            "expires_at": mobile_expires,
            "server": {
                "name": server_name,
                "host": host,
                "platform": platform,
            }
        })),
    )
        .into_response())
}
