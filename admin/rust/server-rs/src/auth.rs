//! Auth middleware and handlers:
//!   POST /api/v1/auth/login
//!   POST /api/v1/auth/logout
//!   GET  /api/v1/me
//!
//! Cookie name: `soyeht_session` (`HttpOnly`, SameSite=Strict).

use crate::state::SharedState;
use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use core_rs::error::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SESSION_COOKIE: &str = "soyeht_session";

const MAX_USERNAME_LEN: usize = 64;
const MAX_PASSWORD_LEN: usize = 256;

// ─── Middleware ────────────────────────────────────────────────────────────────

/// Axum middleware: validates authentication and injects `AuthUser` extension.
///
/// Checks in order:
/// 1. `soyeht_session` cookie (web admin panel)
/// 2. `Authorization: Bearer <token>` header (mobile app sessions)
/// 3. `?token=<token>` query parameter (WebSocket upgrades from mobile app)
///
/// Returns 401 if none of these provide a valid session.
///
/// # Errors
///
/// Returns `401 Unauthorized` if no valid credential is found.
pub async fn require_auth(
    State(state): State<SharedState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    // 1. Try cookie auth (existing web flow)
    let cookie_token = extract_session_cookie(req.headers());
    let is_https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));

    let username = match cookie_token.as_ref() {
        Some(t) => {
            let st = state.clone();
            let t = t.clone();
            tokio::task::spawn_blocking(move || st.sessions.validate_session(&t))
                .await
                .ok()
                .flatten()
        }
        None => None,
    };

    // 2. Try Bearer token (mobile session — persistent SQLite store)
    let username = match username {
        Some(u) => Some(u),
        None => extract_bearer_token(req.headers())
            .and_then(|t| state.mobile_sessions.validate_session(&t)),
    };

    // 3. Try query parameter ?token= (WebSocket upgrade from mobile)
    let username = match username {
        Some(u) => Some(u),
        None => {
            extract_query_token(req.uri()).and_then(|t| state.mobile_sessions.validate_session(&t))
        }
    };

    // 4. Try bootstrap token (install-time one-shot auth)
    let username = match username {
        Some(u) => Some(u),
        None => extract_bearer_token(req.headers()).and_then(|t| match_bootstrap_token(&t)),
    };

    // Return a JSON body so the frontend can parse it and detect the 401 status.
    let username = username.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized", "code": "UNAUTHORIZED"})),
        )
            .into_response()
    })?;
    let auth_user = {
        let st = state.clone();
        let u = username.clone();
        match tokio::task::spawn_blocking(move || resolve_auth_user(&st, u)).await {
            Ok(Ok(user)) => user,
            Ok(Err(_)) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "user not found", "code": "UNAUTHORIZED"})),
                )
                    .into_response());
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "auth resolution failed", "code": "INTERNAL"})),
                )
                    .into_response());
            }
        }
    };
    req.extensions_mut().insert(auth_user);
    let mut response = next.run(req).await;

    // Re-emit cookie with fresh Max-Age so the browser stays in sync with
    // the server-side sliding window.  Without this, the browser drops the
    // cookie after the original login-time Max-Age even though the server
    // extended it.
    if let Some(token) = cookie_token {
        let ttl = session_rs::get_ttl_secs();
        let secure = if is_https { "; Secure" } else { "" };
        let cookie = format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure}"
        );
        if let Ok(val) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, val);
        }
    }

    Ok(response)
}

/// Typed extension carrying the authenticated user through the handler chain.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: String,
    pub username: String,
    pub role: store_rs::UserRole,
}

/// Resolve a username to a full `AuthUser` by looking up the `users` table.
///
/// Returns an error if the user is not found or the database query fails.
/// This prevents privilege escalation when a user's account is deleted but
/// their session token is still valid.
#[allow(clippy::needless_pass_by_value)] // callers move String into spawn_blocking closure
fn resolve_auth_user(state: &SharedState, username: String) -> Result<AuthUser, ApiError> {
    match state.instance_db.get_user_by_username(&username) {
        Ok(Some(row)) => Ok(AuthUser {
            user_id: row.id,
            username: row.username,
            role: row.role,
        }),
        Ok(None) => {
            tracing::warn!("[auth] user '{}' not found in users table", username);
            Err(ApiError::unauthorized("user not found"))
        }
        Err(e) => {
            tracing::error!("[auth] failed to look up user '{}': {e}", username);
            Err(ApiError::internal("auth lookup failed"))
        }
    }
}

/// Axum extractor: validates authentication directly from request parts.
/// Checks cookie, then Bearer header, then query param (same order as middleware).
/// Handlers that declare `AuthUser` as a parameter are automatically authenticated.
/// The `require_auth` middleware still runs as a safety net for SSE/WS routes.
impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // If the require_auth middleware already validated, reuse its result
        // to avoid a second DB write (the sliding window UPDATE in validate_session).
        if let Some(user) = parts.extensions.get::<AuthUser>() {
            return Ok(user.clone());
        }

        // 1. Try cookie
        let mut username: Option<String> = None;
        if let Some(token) = extract_session_cookie(&parts.headers) {
            let st = state.clone();
            username = tokio::task::spawn_blocking(move || st.sessions.validate_session(&token))
                .await
                .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))?;
        }

        // 2. Try Bearer token (mobile session — persistent SQLite store)
        if username.is_none() {
            if let Some(token) = extract_bearer_token(&parts.headers) {
                username = state.mobile_sessions.validate_session(&token);
            }
        }

        // 3. Try query parameter ?token= (WebSocket upgrade from mobile)
        if username.is_none() {
            if let Some(token) = extract_query_token(&parts.uri) {
                username = state.mobile_sessions.validate_session(&token);
            }
        }

        // 4. Try bootstrap token (install-time one-shot auth)
        if username.is_none() {
            if let Some(token) = extract_bearer_token(&parts.headers) {
                username = match_bootstrap_token(&token);
            }
        }

        let username = username.ok_or_else(|| ApiError::unauthorized("invalid session"))?;

        // Resolve user role from users table
        let st = state.clone();
        let u = username.clone();
        let auth_user = tokio::task::spawn_blocking(move || resolve_auth_user(&st, u))
            .await
            .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))??;

        Ok(auth_user)
    }
}

/// Axum extractor: requires admin role. Returns 403 Forbidden for non-admins.
///
/// Usage: `AdminUser(auth): AdminUser` in handler parameters.
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<SharedState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.role != store_rs::UserRole::Admin {
            return Err(ApiError::forbidden("admin access required"));
        }
        Ok(AdminUser(user))
    }
}

/// Check if a Bearer token matches the bootstrap token on disk.
///
/// Used by the install script to authenticate before any admin session exists.
/// Returns the bootstrap admin username if the token matches.
fn match_bootstrap_token(token: &str) -> Option<String> {
    let path = std::env::var("THEYOS_BOOTSTRAP_TOKEN_PATH").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            format!("{home}/.theyos/bootstrap-token")
        } else {
            "/var/lib/theyos/secrets/bootstrap-token".to_string()
        }
    });
    let expected = std::fs::read_to_string(&path).ok()?;
    let expected = expected.trim();
    if expected.is_empty() || token != expected {
        return None;
    }
    // Return the bootstrap admin username
    let admin_user = std::env::var("SOYEHT_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    Some(admin_user)
}

/// Extract the session cookie value from the request headers.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let kv = part.trim();
                kv.strip_prefix(SESSION_COOKIE)
                    .and_then(|rest| rest.strip_prefix('='))
                    .map(std::string::ToString::to_string)
            })
        })
}

/// Extract a Bearer token from the `Authorization` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(std::string::ToString::to_string)
}

/// Extract a `token` query parameter from the URI (for WebSocket upgrades).
fn extract_query_token(uri: &axum::http::Uri) -> Option<String> {
    uri.query().and_then(|q| {
        q.split('&').find_map(|part| {
            part.strip_prefix("token=")
                .map(std::string::ToString::to_string)
        })
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    ok: bool,
    user: UserInfo,
}

#[derive(Serialize)]
struct UserInfo {
    username: String,
    role: store_rs::UserRole,
}

/// `POST /api/v1/auth/login`
///
/// # Errors
///
/// Returns an error if credentials are invalid, empty, or too long, or if
/// session creation fails.
pub async fn handle_login(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let username = req.username.trim().to_string();
    let password = req.password.trim().to_string();

    if username.is_empty() || password.is_empty() {
        return Err(ApiError::bad_request("username and password are required"));
    }
    if username.len() > MAX_USERNAME_LEN || password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::bad_request("credentials too long"));
    }

    let st = state.clone();
    let u = username.clone();
    let p = password.clone();
    let token = tokio::task::spawn_blocking(move || -> Result<String, ApiError> {
        st.sessions
            .validate_credentials(&u, &p)
            .map_err(|_| ApiError::unauthorized("invalid credentials"))?;
        st.sessions.create_session(&u).map_err(|e| {
            tracing::error!("create_session failed: {e}");
            ApiError::internal("failed to create session")
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))??;

    // Detect HTTPS via x-forwarded-proto (Caddy / Cloudflare Tunnel set this).
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));

    let ttl_secs = session_rs::get_ttl_secs();
    let secure_flag = if is_https { "; Secure" } else { "" };

    // Build Set-Cookie header manually for full control over attributes.
    // Use Max-Age only (not Expires) — browsers prefer Max-Age per RFC 6265,
    // and the require_auth middleware renews it on every authenticated request.
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; \
         Max-Age={ttl_secs}{secure_flag}"
    );

    // Resolve user role for response.
    // If the user is not in the DB, default to User role (not Admin) and log a warning.
    // This can happen if the admin account was not seeded — the login still succeeds
    // because validate_credentials checks an env var, but the role should not be elevated.
    let role = {
        let st = state.clone();
        let u = username.clone();
        tokio::task::spawn_blocking(move || {
            st.instance_db.get_user_by_username(&u).map_err(|e| {
                tracing::error!("[auth] failed to look up user '{}' at login: {e}", u);
                e
            })
        })
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .map_or_else(
            || {
                tracing::warn!(
                    "[auth] user '{}' logged in but not in users table — defaulting to User role",
                    username
                );
                store_rs::UserRole::User
            },
            |r| r.role,
        )
    };

    tracing::info!("user '{}' logged in (role={})", username, role);

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            ok: true,
            user: UserInfo { username, role },
        }),
    )
        .into_response())
}

/// `POST /api/v1/auth/logout`
#[allow(clippy::unused_async)]
pub async fn handle_logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = extract_session_cookie(&headers) {
        tokio::task::spawn_blocking(move || {
            if let Err(e) = state.sessions.delete_session(&token) {
                tracing::warn!("[auth] failed to delete session on logout: {e}");
            }
        });
    }

    // Expire the cookie immediately (MaxAge=-1 / Expires=epoch).
    let clear = format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; \
         Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0"
    );

    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, clear)]).into_response()
}

/// `GET /api/v1/me`
#[allow(clippy::unused_async)]
pub async fn handle_me(auth: AuthUser) -> Json<Value> {
    Json(json!({ "username": auth.username, "role": auth.role }))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_session_cookie_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "soyeht_session=abc123; other=xyz".parse().unwrap(),
        );
        assert_eq!(extract_session_cookie(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_session_cookie_absent() {
        let headers = HeaderMap::new();
        assert!(extract_session_cookie(&headers).is_none());
    }

    #[test]
    fn extract_session_cookie_other_cookie_only() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "other=xyz".parse().unwrap());
        assert!(extract_session_cookie(&headers).is_none());
    }

    #[test]
    fn extract_bearer_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-token-123".parse().unwrap(),
        );
        assert_eq!(
            extract_bearer_token(&headers).as_deref(),
            Some("my-token-123")
        );
    }

    #[test]
    fn extract_bearer_absent() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
    }

    #[test]
    fn extract_bearer_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert!(extract_bearer_token(&headers).is_none());
    }

    #[test]
    fn extract_query_token_present() {
        let uri: axum::http::Uri = "/api/v1/terminals/foo/pty?token=abc123&session=xyz"
            .parse()
            .unwrap();
        assert_eq!(extract_query_token(&uri).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_query_token_absent() {
        let uri: axum::http::Uri = "/api/v1/terminals/foo/pty?session=xyz".parse().unwrap();
        assert!(extract_query_token(&uri).is_none());
    }

    #[test]
    fn extract_query_token_no_query() {
        let uri: axum::http::Uri = "/api/v1/terminals/foo/pty".parse().unwrap();
        assert!(extract_query_token(&uri).is_none());
    }
}
