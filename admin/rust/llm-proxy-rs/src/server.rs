//! Axum HTTP surface for the LLM proxy.
//!
//! Three route families:
//!
//! - **Default profile** (no claw stamp):
//!   - `GET  /health`
//!   - `GET  /v1/models`
//!   - `POST /v1/chat/completions`
//!
//! - **Per-claw profile** (URL-stamped with the claw type):
//!   - `GET  /v1/c/:claw_type/models`
//!   - `POST /v1/c/:claw_type/chat/completions`
//!
//! - **Admin** (loopback only — front-ended by `server-rs` after AdminUser
//!   auth via reverse proxy):
//!   - `GET  /admin/catalog`
//!   - `GET  /admin/llm/active`
//!   - `PUT  /admin/llm/active`
//!   - `PUT  /admin/llm/active/:claw_type`
//!   - `DELETE /admin/llm/active/:claw_type`
//!
//! Claws hit the per-claw routes — their bootstrap script bakes the
//! `claw_type` into `THEYOS_LLM_OPENAI_BASE_URL`. The proxy uses the path
//! segment to look up that claw's overlay profile (if any) and otherwise
//! falls back to the global default. Provider configs themselves are
//! never per-claw — they live in the global `default.toml`.
//!
//! ## Hot-reload
//!
//! The mutable state — default active, per-claw overlays, provider
//! registry — lives in a `RwLock<Arc<StateSnapshot>>`. Readers (every
//! `/v1/*` chat path) take a read-lock just long enough to clone the
//! `Arc`, then drop the lock; the request runs against a stable snapshot
//! that cannot be mutated underneath it. Writers (the admin endpoints)
//! take a write-lock, build the next snapshot, and atomically replace
//! the `Arc`. This is the same pattern arc-swap uses; we keep std-only
//! to avoid pulling a dep for one usage site.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{AuditLogger, AuditRecord, AuditStatus};
use crate::catalog::CatalogDoc;
use crate::error::ProxyError;
use crate::profile::{ActiveProfile, ProfileDoc, ProviderConfig, ProviderKind};
use crate::provider::{ChatResponse, Provider};

use keystore_rs::KeystoreBackend;

// `Value` is imported above so the macro picks up `Value::Object(...)` style
// matches that may appear in later slices; the get/and_then path uses
// closures explicitly to avoid the trait-object inference issue.

/// Hot-reloadable snapshot of every piece of state the request path
/// needs. Replaced atomically by admin mutators — readers see a single
/// consistent view per request.
pub(crate) struct StateSnapshot {
    pub providers: HashMap<String, Arc<dyn Provider>>,
    pub default_active: ActiveProfile,
    pub per_claw_active: HashMap<String, ActiveProfile>,
}

/// Shared handle across request handlers. Cheap to clone (single `Arc`
/// bump). All mutable state lives behind `snapshot`; the audit logger and
/// profile dir are pinned for the process lifetime.
#[derive(Clone)]
pub struct ServerState {
    inner: Arc<StateInner>,
}

struct StateInner {
    /// Read-mostly: read on every chat request, written by admin mutators.
    snapshot: RwLock<Arc<StateSnapshot>>,
    /// Where `default.toml` and per-claw overlay files live. Set at
    /// startup from `ProxyConfig::profile_dir`. `None` disables disk
    /// persistence — used by tests so they don't poke real files.
    profile_dir: Option<PathBuf>,
    /// Serializes ALL writes to the profile directory.
    /// `update_default_active` reads → mutates → renames; two
    /// concurrent admin PUTs without this lock would race and lose one
    /// caller's update (the late writer reloads the file written by the
    /// early writer and silently overwrites it). Held across the full
    /// load→mutate→fsync→rename sequence. Cheap: contended only by
    /// admin clicks, never by chat requests.
    profile_io_lock: Mutex<()>,
    /// Credential backend the admin endpoints write into when adding /
    /// removing a provider. `None` disables credential mutation — used
    /// by tests that construct providers directly and don't care about
    /// the keystore. In production this is always populated from
    /// `build_credential_store`.
    keystore: Option<Arc<dyn KeystoreBackend>>,
    audit: AuditLogger,
}

impl ServerState {
    /// Construct with audit logging disabled and no disk persistence —
    /// handy for tests + the no-log production path. Most callers should
    /// use [`with_audit_and_profile_dir`] so the proxy's persistent audit
    /// trail and admin mutators are intact.
    #[must_use]
    pub fn new(
        providers: HashMap<String, Arc<dyn Provider>>,
        default_active: ActiveProfile,
        per_claw_active: HashMap<String, ActiveProfile>,
    ) -> Self {
        Self::with_audit(
            providers,
            default_active,
            per_claw_active,
            AuditLogger::disabled(),
        )
    }

    /// Construct with an active audit logger, no profile-dir wiring.
    #[must_use]
    pub fn with_audit(
        providers: HashMap<String, Arc<dyn Provider>>,
        default_active: ActiveProfile,
        per_claw_active: HashMap<String, ActiveProfile>,
        audit: AuditLogger,
    ) -> Self {
        Self::with_audit_and_profile_dir(providers, default_active, per_claw_active, audit, None)
    }

    /// Full constructor — audit logger + profile dir for disk-backed
    /// admin mutations. Production path.
    #[must_use]
    pub fn with_audit_and_profile_dir(
        providers: HashMap<String, Arc<dyn Provider>>,
        default_active: ActiveProfile,
        per_claw_active: HashMap<String, ActiveProfile>,
        audit: AuditLogger,
        profile_dir: Option<PathBuf>,
    ) -> Self {
        Self::with_full_wiring(
            providers,
            default_active,
            per_claw_active,
            audit,
            profile_dir,
            None,
        )
    }

    /// Maximum-arity constructor — adds the keystore handle that admin
    /// providers-CRUD endpoints need. Production wires this through;
    /// the older `with_audit_and_profile_dir` is kept as a back-compat
    /// shortcut for tests that don't exercise provider mutation.
    #[must_use]
    pub fn with_full_wiring(
        providers: HashMap<String, Arc<dyn Provider>>,
        default_active: ActiveProfile,
        per_claw_active: HashMap<String, ActiveProfile>,
        audit: AuditLogger,
        profile_dir: Option<PathBuf>,
        keystore: Option<Arc<dyn KeystoreBackend>>,
    ) -> Self {
        Self {
            inner: Arc::new(StateInner {
                snapshot: RwLock::new(Arc::new(StateSnapshot {
                    providers,
                    default_active,
                    per_claw_active,
                })),
                profile_dir,
                profile_io_lock: Mutex::new(()),
                keystore,
                audit,
            }),
        }
    }

    /// The default active profile, used when no claw stamp is present.
    /// Exposed for `/health` and tests. Returns a snapshot copy — calling
    /// again may return different data if an admin mutator ran in between.
    #[must_use]
    pub fn default_active(&self) -> ActiveProfile {
        self.snapshot().default_active.clone()
    }

    /// Take a read-locked snapshot pointer. Cheap (Arc clone); the
    /// caller can hold this through the entire request without blocking
    /// admin writers.
    #[must_use]
    pub(crate) fn snapshot(&self) -> Arc<StateSnapshot> {
        // Recover from a poisoned lock (a panic in a writer): there is
        // nothing sensitive in the snapshot, and serving with stale state
        // is preferable to crashing every subsequent request.
        let guard = self
            .inner
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Reload the provider registry from the on-disk profile + current
    /// keystore. Used by the SIGHUP signal handler so operators who
    /// rotated a credential via `theyos-llm-proxy set-credential` (or
    /// hand-edited the keystore) can refresh the running daemon without
    /// a service restart — providers cache their credential at
    /// construction time, so the live registry needs to be rebuilt.
    ///
    /// Returns the count of reloaded providers, or an error when:
    /// - profile-dir or keystore wiring is missing (test builds);
    /// - the profile file is malformed;
    /// - a configured provider's credential cannot be read.
    ///
    /// In the last case the in-memory state is NOT replaced — the live
    /// daemon keeps serving with the previous registry. Same ordering
    /// guarantee as `set_active`: disk is the source of truth, memory
    /// is updated only on success.
    pub fn reload_from_disk(&self) -> Result<usize, ProxyError> {
        let dir = self
            .inner
            .profile_dir
            .as_ref()
            .ok_or_else(|| ProxyError::Profile {
                path: "<no-profile-dir>".into(),
                kind: "reload_from_disk called on a ServerState without profile_dir wired".into(),
            })?;
        let keystore = self
            .inner
            .keystore
            .as_ref()
            .ok_or_else(|| ProxyError::Profile {
                path: dir.display().to_string(),
                kind: "reload_from_disk called on a ServerState without keystore wired".into(),
            })?;
        let _io = self
            .inner
            .profile_io_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let doc = ProfileDoc::load_default(dir)?;
        let per_claw = ProfileDoc::load_per_claw_overlays(dir)?;
        let registry = crate::build_provider_registry(&doc.providers, &**keystore)?;
        let new_default = doc
            .active
            .clone()
            .unwrap_or_else(|| self.snapshot().default_active.clone());
        let count = registry.len();
        let next = Arc::new(StateSnapshot {
            providers: registry,
            default_active: new_default,
            per_claw_active: per_claw,
        });
        self.replace_snapshot(next);
        Ok(count)
    }

    /// Atomically replace the snapshot. Writers build the new snapshot
    /// off-lock, then take the write-lock just long enough to swap the
    /// `Arc` pointer.
    fn replace_snapshot(&self, next: Arc<StateSnapshot>) {
        let mut guard = self
            .inner
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = next;
    }

    /// Resolve `(provider, model)` for a given claw type against a
    /// previously-captured snapshot. The snapshot is passed in so the
    /// request path can keep using the same view across logging + chat.
    fn resolve_in(
        snap: &StateSnapshot,
        claw_type: Option<&str>,
    ) -> Result<(Arc<dyn Provider>, String), ProxyError> {
        let active = match claw_type {
            Some(ct) => snap.per_claw_active.get(ct).unwrap_or(&snap.default_active),
            None => &snap.default_active,
        };
        let provider = snap
            .providers
            .get(&active.provider)
            .cloned()
            .ok_or_else(|| ProxyError::NoProvider(active.provider.clone()))?;
        Ok((provider, active.model.clone()))
    }
}

/// Build the public router. Run as `axum::serve(listener, router(state))`.
pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/models", get(list_models_default))
        .route("/v1/chat/completions", post(chat_default))
        .route("/v1/c/{claw_type}/models", get(list_models_claw))
        .route("/v1/c/{claw_type}/chat/completions", post(chat_claw))
        // Admin (loopback only; server-rs reverse-proxies after auth).
        .route("/admin/catalog", get(admin_catalog))
        .route(
            "/admin/llm/active",
            get(admin_get_active).put(admin_put_active),
        )
        .route(
            "/admin/llm/active/{claw_type}",
            put(admin_put_active_claw).delete(admin_delete_active_claw),
        )
        .route(
            "/admin/llm/providers",
            get(admin_list_providers).post(admin_upsert_provider),
        )
        .route("/admin/llm/providers/{id}", delete(admin_delete_provider))
        .route("/admin/llm/providers/{id}/test", post(admin_test_provider))
        .route("/admin/llm/audit", get(admin_get_audit))
        .with_state(state)
}

/// Static provider catalog. Served at `GET /admin/catalog`; the
/// admin-frontend Models page fetches this rather than hard-coding the
/// list of providers.
async fn admin_catalog() -> Json<CatalogDoc> {
    // CatalogDoc::builtin() allocates a few strings but the result is
    // small (~3 kB JSON). Tests live in `catalog::tests` to verify the
    // contract that the frontend depends on.
    Json(CatalogDoc::builtin())
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    default_provider: String,
    default_model: String,
    per_claw_overrides: Vec<HealthClawOverride>,
}

#[derive(Serialize)]
struct HealthClawOverride {
    claw_type: String,
    provider: String,
    model: String,
}

async fn health(State(state): State<ServerState>) -> Json<HealthResponse> {
    let snap = state.snapshot();
    let mut overrides: Vec<HealthClawOverride> = snap
        .per_claw_active
        .iter()
        .map(|(k, v)| HealthClawOverride {
            claw_type: k.clone(),
            provider: v.provider.clone(),
            model: v.model.clone(),
        })
        .collect();
    overrides.sort_by(|a, b| a.claw_type.cmp(&b.claw_type));
    Json(HealthResponse {
        status: "ok",
        default_provider: snap.default_active.provider.clone(),
        default_model: snap.default_active.model.clone(),
        per_claw_overrides: overrides,
    })
}

#[derive(Serialize)]
struct ModelsResponse {
    object: &'static str,
    data: Vec<ModelEntry>,
}

#[derive(Serialize)]
struct ModelEntry {
    id: String,
    object: &'static str,
    owned_by: &'static str,
}

async fn list_models_default(
    State(state): State<ServerState>,
) -> Result<Json<ModelsResponse>, ApiError> {
    list_models_inner(&state, None)
}

async fn list_models_claw(
    State(state): State<ServerState>,
    Path(claw_type): Path<String>,
) -> Result<Json<ModelsResponse>, ApiError> {
    list_models_inner(&state, Some(claw_type.as_str()))
}

fn list_models_inner(
    state: &ServerState,
    claw_type: Option<&str>,
) -> Result<Json<ModelsResponse>, ApiError> {
    let snap = state.snapshot();
    let (provider, _) = ServerState::resolve_in(&snap, claw_type)?;
    let data = provider
        .models()
        .iter()
        .map(|m| ModelEntry {
            id: m.id.clone(),
            object: "model",
            owned_by: m.owned_by,
        })
        .collect();
    Ok(Json(ModelsResponse {
        object: "list",
        data,
    }))
}

async fn chat_default(
    State(state): State<ServerState>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    chat_inner(&state, None, body).await
}

async fn chat_claw(
    State(state): State<ServerState>,
    Path(claw_type): Path<String>,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    chat_inner(&state, Some(claw_type.as_str()), body).await
}

async fn chat_inner(
    state: &ServerState,
    claw_type: Option<&str>,
    body: Value,
) -> Result<Response, ApiError> {
    let started = std::time::Instant::now();
    let stream = body
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let model_in_request = body
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(default)")
        .to_string();

    // Snapshot the state once for the entire request: a concurrent admin
    // mutation must not be able to swap providers mid-call.
    let snap = state.snapshot();
    let (provider, _active_model) = match ServerState::resolve_in(&snap, claw_type) {
        Ok(v) => v,
        Err(e) => {
            // Audit the resolution failure even though no provider ran.
            state.inner.audit.write(&AuditRecord::now(
                "(unresolved)",
                claw_type,
                &model_in_request,
                stream,
                AuditStatus::Error,
                Some(e.kind()),
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ));
            return Err(ApiError(e));
        }
    };
    let provider_id = provider.id().to_string();
    tracing::debug!(
        provider = %provider_id,
        claw_type,
        stream,
        model = %model_in_request,
        "chat request"
    );

    let response = provider.chat(&body, stream).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match response {
        Ok(resp) => {
            state.inner.audit.write(&AuditRecord::now(
                &provider_id,
                claw_type,
                &model_in_request,
                stream,
                AuditStatus::Ok,
                None,
                latency_ms,
            ));
            Ok(match resp {
                ChatResponse::Json(bytes) => {
                    let mut headers = HeaderMap::new();
                    headers.insert("content-type", HeaderValue::from_static("application/json"));
                    (StatusCode::OK, headers, bytes).into_response()
                }
                ChatResponse::Stream(stream) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "content-type",
                        HeaderValue::from_static("text/event-stream"),
                    );
                    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
                    headers.insert("connection", HeaderValue::from_static("keep-alive"));
                    let body = Body::from_stream(stream);
                    (StatusCode::OK, headers, body).into_response()
                }
            })
        }
        Err(e) => {
            state.inner.audit.write(&AuditRecord::now(
                &provider_id,
                claw_type,
                &model_in_request,
                stream,
                AuditStatus::Error,
                Some(e.kind()),
                latency_ms,
            ));
            Err(ApiError(e))
        }
    }
}

/// Newtype so axum's `IntoResponse` can map [`ProxyError`] without orphan-
/// rule violations. Stays private to the server module.
struct ApiError(ProxyError);

impl From<ProxyError> for ApiError {
    fn from(e: ProxyError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.0.http_status();
        let kind = self.0.kind();
        let message = self.0.to_string();
        tracing::warn!(error.kind = kind, error.message = %message, "proxy error");
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let payload = serde_json::json!({
            "error": {
                "kind": kind,
                "message": message,
            }
        });
        (status, Json(payload)).into_response()
    }
}

// ─── Admin: active profile read/write ────────────────────────────────────

/// Response body for `GET /admin/llm/active`. Mirrors the on-disk layout
/// so the frontend can render and mutate without translation.
#[derive(Serialize)]
struct ActiveSnapshot {
    default: ActiveProfile,
    per_claw: std::collections::BTreeMap<String, ActiveProfile>,
}

async fn admin_get_active(State(state): State<ServerState>) -> Json<ActiveSnapshot> {
    let snap = state.snapshot();
    let mut per_claw: std::collections::BTreeMap<String, ActiveProfile> =
        std::collections::BTreeMap::new();
    for (claw, active) in &snap.per_claw_active {
        per_claw.insert(claw.clone(), active.clone());
    }
    Json(ActiveSnapshot {
        default: snap.default_active.clone(),
        per_claw,
    })
}

/// Request body for `PUT /admin/llm/active` and `/admin/llm/active/:claw_type`.
#[derive(Deserialize)]
struct SetActiveBody {
    provider: String,
    model: String,
}

async fn admin_put_active(
    State(state): State<ServerState>,
    Json(body): Json<SetActiveBody>,
) -> Result<Json<ActiveProfile>, ApiError> {
    set_active(&state, None, body)
}

async fn admin_put_active_claw(
    State(state): State<ServerState>,
    Path(claw_type): Path<String>,
    Json(body): Json<SetActiveBody>,
) -> Result<Json<ActiveProfile>, ApiError> {
    set_active(&state, Some(&claw_type), body)
}

async fn admin_delete_active_claw(
    State(state): State<ServerState>,
    Path(claw_type): Path<String>,
) -> Result<StatusCode, ApiError> {
    let normalized = normalize_claw_type(&claw_type)?;

    // Persist (delete the overlay file) FIRST, under the IO lock — same
    // ordering rationale as `set_active`: if disk fails, leave both
    // memory and disk in the OLD state so the client sees an honest
    // error and can retry, rather than diverging silently.
    if let Some(dir) = &state.inner.profile_dir {
        let _io = state
            .inner
            .profile_io_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = dir.join(format!("{normalized}.toml"));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %path.display(),
                    "failed to delete per-claw overlay; in-memory state unchanged"
                );
                return Err(ApiError(ProxyError::Profile {
                    path: path.display().to_string(),
                    kind: format!("remove: {e}"),
                }));
            }
        }
    }

    // Disk delete succeeded — drop the entry from the in-memory snapshot.
    let snap = state.snapshot();
    let mut new_per_claw = snap.per_claw_active.clone();
    new_per_claw.remove(&normalized);
    state.replace_snapshot(Arc::new(StateSnapshot {
        providers: snap.providers.clone(),
        default_active: snap.default_active.clone(),
        per_claw_active: new_per_claw,
    }));
    Ok(StatusCode::NO_CONTENT)
}

/// Shared mutator for both `PUT /active` (claw_type=None) and
/// `PUT /active/:claw_type`. Validates that the requested provider
/// exists in the registry, **persists to disk first**, then atomically
/// swaps the snapshot.
///
/// Ordering rationale: if we swap in-memory first and disk fails, the
/// admin client gets 5xx but the new value is already live until process
/// restart — at which point disk wins and the operator's change vanishes
/// silently. Persisting first means a disk failure leaves both memory
/// and disk in the OLD state, which the client sees as an honest 5xx
/// they can retry. The disk write is durable (atomic rename + fsync),
/// so any subsequent restart sees the new value.
///
/// All writes go under `profile_io_lock` to serialize concurrent admin
/// mutations against the load→mutate→rename sequence in `ProfileDoc::
/// update_default_active`.
fn set_active(
    state: &ServerState,
    claw_type: Option<&str>,
    body: SetActiveBody,
) -> Result<Json<ActiveProfile>, ApiError> {
    let SetActiveBody { provider, model } = body;
    if provider.trim().is_empty() {
        return Err(ApiError(ProxyError::BadRequest(
            "provider must not be empty".into(),
        )));
    }
    if model.trim().is_empty() {
        return Err(ApiError(ProxyError::BadRequest(
            "model must not be empty".into(),
        )));
    }
    let new_active = ActiveProfile {
        provider: provider.clone(),
        model: model.clone(),
    };
    let snap = state.snapshot();
    if !snap.providers.contains_key(&provider) {
        // Client-supplied provider id is not configured → 422
        // (Unprocessable Entity). UnknownProvider stays for the
        // server-side resolution path on /v1/chat/completions where
        // the *profile* points at a missing id — that's a 503 (the
        // server isn't currently able to fulfil any chat request).
        return Err(ApiError(ProxyError::InvalidProviderSelection {
            provider: provider.clone(),
            hint: format!(
                "no `[providers.{provider}]` block exists in the profile — add the provider before activating it"
            ),
        }));
    }

    // Persist to disk FIRST, under the profile-IO lock. Two concurrent
    // PUTs would otherwise race on `update_default_active`: both read
    // the same starting doc, both mutate, and the late writer's rename
    // silently overwrites the early writer's change.
    if let Some(dir) = &state.inner.profile_dir {
        let _io = state
            .inner
            .profile_io_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = match claw_type {
            Some(ct) => {
                let normalized = normalize_claw_type(ct)?;
                ProfileDoc::write_per_claw_overlay(dir, &normalized, &new_active)
            }
            None => ProfileDoc::update_default_active(dir, &new_active),
        };
        if let Err(e) = result {
            tracing::error!(
                error.kind = e.kind(),
                error.message = %e,
                "active profile persist failed; in-memory state untouched"
            );
            return Err(ApiError(e));
        }
        // _io guard drops here, releasing the lock before we touch the
        // in-memory snapshot.
    }

    // Disk write succeeded (or profile_dir is None for tests): build the
    // next snapshot off-lock, then atomically swap.
    let next = if let Some(claw_type) = claw_type {
        let normalized = normalize_claw_type(claw_type)?;
        let mut new_per_claw = snap.per_claw_active.clone();
        new_per_claw.insert(normalized, new_active.clone());
        Arc::new(StateSnapshot {
            providers: snap.providers.clone(),
            default_active: snap.default_active.clone(),
            per_claw_active: new_per_claw,
        })
    } else {
        Arc::new(StateSnapshot {
            providers: snap.providers.clone(),
            default_active: new_active.clone(),
            per_claw_active: snap.per_claw_active.clone(),
        })
    };
    state.replace_snapshot(next);

    Ok(Json(new_active))
}

/// Reject claw_type strings that could escape the profile directory via
/// path traversal or shell metacharacters. The bootstrap script bakes
/// these into URL paths so we accept only the same character class that
/// `core_rs::claw_llm::normalize_provider_id` accepts.
fn normalize_claw_type(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError(ProxyError::BadRequest(
            "claw_type must not be empty".into(),
        )));
    }
    if trimmed.len() > 64 {
        return Err(ApiError(ProxyError::BadRequest(
            "claw_type too long (max 64 chars)".into(),
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError(ProxyError::BadRequest(
            "claw_type must match [A-Za-z0-9_-]+".into(),
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

// ─── Admin: providers CRUD + live test ───────────────────────────────────

/// Summary of one configured provider as returned by `GET /admin/llm/providers`.
/// Intentionally omits the credential value itself — the admin UI shows
/// presence, never the secret.
#[derive(Serialize)]
struct ProviderSummary {
    id: String,
    kind: ProviderKind,
    base_url: String,
    models: Vec<String>,
    /// `true` when a credential is configured AND readable from the
    /// keystore. `false` covers both "no credential_account in profile"
    /// and "account configured but missing from the keystore".
    has_credential: bool,
    credential_account: Option<String>,
    /// `true` when the active profile (default or any per-claw overlay)
    /// references this provider — the admin UI uses this to prevent
    /// deletion or warn the operator.
    in_use: bool,
}

#[derive(Serialize)]
struct ProvidersListResponse {
    providers: Vec<ProviderSummary>,
}

async fn admin_list_providers(
    State(state): State<ServerState>,
) -> Result<Json<ProvidersListResponse>, ApiError> {
    let Some(dir) = &state.inner.profile_dir else {
        // Tests that bypass disk persistence can't list disk-backed
        // providers; return what's in-memory so callers still get a
        // useful answer.
        let snap = state.snapshot();
        let providers = snap
            .providers
            .keys()
            .map(|id| ProviderSummary {
                id: id.clone(),
                kind: ProviderKind::OpenaiCompat,
                base_url: String::new(),
                models: Vec::new(),
                has_credential: false,
                credential_account: None,
                in_use: snap.default_active.provider == *id
                    || snap.per_claw_active.values().any(|a| &a.provider == id),
            })
            .collect();
        return Ok(Json(ProvidersListResponse { providers }));
    };
    let doc = ProfileDoc::load_default(dir).map_err(ApiError)?;
    let snap = state.snapshot();
    let providers: Vec<ProviderSummary> = doc
        .providers
        .iter()
        .map(|(id, cfg)| {
            let has_credential = match (&cfg.credential_account, &state.inner.keystore) {
                (Some(account), Some(ks)) => ks.get(account).is_ok(),
                _ => false,
            };
            let in_use = snap.default_active.provider == *id
                || snap.per_claw_active.values().any(|a| a.provider == *id);
            ProviderSummary {
                id: id.clone(),
                kind: cfg.kind,
                base_url: cfg.base_url.clone(),
                models: cfg.models.clone(),
                has_credential,
                credential_account: cfg.credential_account.clone(),
                in_use,
            }
        })
        .collect();
    Ok(Json(ProvidersListResponse { providers }))
}

/// Body for `POST /admin/llm/providers`. Setting `credential` to `Some`
/// writes it to the keystore under `credential_account` (the field must
/// be provided in `config`); leaving `credential` as `None` requires that
/// either no credential is needed (local providers) or that the keystore
/// already has the value (operator imported it via `set-credential`).
#[derive(Deserialize)]
struct UpsertProviderBody {
    id: String,
    #[serde(flatten)]
    config: ProviderConfig,
    /// Secret value to store under `config.credential_account`. Never
    /// echoed back to the caller. Use the empty string to remove a
    /// previously-stored credential.
    #[serde(default)]
    credential: Option<String>,
}

async fn admin_upsert_provider(
    State(state): State<ServerState>,
    Json(body): Json<UpsertProviderBody>,
) -> Result<Json<ProviderSummary>, ApiError> {
    let UpsertProviderBody {
        id,
        config,
        credential,
    } = body;
    let id = normalize_provider_id(&id)?;
    if let Some(account) = config.credential_account.as_deref() {
        validate_credential_account(account)?;
    }

    // Write the credential (if any) BEFORE persisting the profile entry.
    // If we persisted first and the keystore write failed, the profile
    // would reference an unreachable account and the next provider
    // registry rebuild would 503.
    if let (Some(account), Some(secret), Some(ks)) = (
        config.credential_account.as_deref(),
        credential.as_deref(),
        state.inner.keystore.as_ref(),
    ) {
        if secret.is_empty() {
            // Empty string = caller wants to clear the credential.
            if let Err(e) = ks.delete(account) {
                tracing::warn!(error = %e, account, "credential delete failed; continuing");
            }
        } else if let Err(e) = ks.set(account, secret.as_bytes()) {
            return Err(ApiError(ProxyError::Credential {
                provider: id.clone(),
                hint: format!("keystore.set({account:?}) failed: {e}"),
            }));
        }
    }

    // Persist + rebuild the in-memory registry under the profile-IO lock.
    if let Some(dir) = &state.inner.profile_dir {
        let _io = state
            .inner
            .profile_io_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let doc = ProfileDoc::upsert_provider(dir, &id, config.clone()).map_err(ApiError)?;
        // Rebuild registry from the persisted state. If this fails (e.g.
        // missing keystore credential for AnthropicApi), the disk write
        // remains but the in-memory snapshot stays at the previous
        // version — surfacing the error without leaving the runtime in
        // a half-updated state.
        let keystore = state.inner.keystore.as_ref().ok_or_else(|| {
            ApiError(ProxyError::Profile {
                path: dir.display().to_string(),
                kind: "keystore not wired on this ServerState; admin mutators disabled".into(),
            })
        })?;
        let registry =
            crate::build_provider_registry(&doc.providers, &**keystore).map_err(ApiError)?;
        let snap = state.snapshot();
        state.replace_snapshot(Arc::new(StateSnapshot {
            providers: registry,
            default_active: snap.default_active.clone(),
            per_claw_active: snap.per_claw_active.clone(),
        }));
    }

    let has_credential = match (config.credential_account.as_deref(), &state.inner.keystore) {
        (Some(account), Some(ks)) => ks.get(account).is_ok(),
        _ => false,
    };
    let snap = state.snapshot();
    Ok(Json(ProviderSummary {
        id: id.clone(),
        kind: config.kind,
        base_url: config.base_url.clone(),
        models: config.models.clone(),
        has_credential,
        credential_account: config.credential_account.clone(),
        in_use: snap.default_active.provider == id
            || snap.per_claw_active.values().any(|a| a.provider == id),
    }))
}

async fn admin_delete_provider(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = normalize_provider_id(&id)?;
    let snap = state.snapshot();
    if snap.default_active.provider == id || snap.per_claw_active.values().any(|a| a.provider == id)
    {
        return Err(ApiError(ProxyError::BadRequest(format!(
            "provider {id:?} is in use by the active profile or a per-claw overlay; switch active first"
        ))));
    }

    if let Some(dir) = &state.inner.profile_dir {
        let _io = state
            .inner
            .profile_io_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let doc = ProfileDoc::delete_provider(dir, &id).map_err(ApiError)?;
        let keystore = state.inner.keystore.as_ref().ok_or_else(|| {
            ApiError(ProxyError::Profile {
                path: dir.display().to_string(),
                kind: "keystore not wired on this ServerState; admin mutators disabled".into(),
            })
        })?;
        // Best-effort credential delete — the operator may have already
        // cleared it via `set-credential`, in which case the delete
        // returns NotFound which the keystore treats as success.
        if let Some(cfg) = snap.providers.get(&id) {
            // The deleted provider's account label is not on the
            // current snapshot's ProviderConfig (the registry stores
            // Arc<dyn Provider>, not the config); instead we look up
            // the just-removed entry from the previously-loaded doc.
            // `doc` here reflects state AFTER removal so we can't use
            // it; fall back to a best-effort delete by the conventional
            // account name `llm.api_key.<id>`.
            let _ = cfg; // silence unused warning if we ever take a different path
            let _ = keystore.delete(&format!("llm.api_key.{id}"));
        }
        let registry =
            crate::build_provider_registry(&doc.providers, &**keystore).map_err(ApiError)?;
        state.replace_snapshot(Arc::new(StateSnapshot {
            providers: registry,
            default_active: doc.active.unwrap_or_else(|| snap.default_active.clone()),
            per_claw_active: snap.per_claw_active.clone(),
        }));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Response for `POST /admin/llm/providers/:id/test`.
#[derive(Serialize)]
struct ProviderTestResponse {
    ok: bool,
    latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn admin_test_provider(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> Result<Json<ProviderTestResponse>, ApiError> {
    let id = normalize_provider_id(&id)?;
    let snap = state.snapshot();
    let provider = snap.providers.get(&id).cloned().ok_or_else(|| {
        ApiError(ProxyError::InvalidProviderSelection {
            provider: id.clone(),
            hint: "not configured; add it via POST /admin/llm/providers first".into(),
        })
    })?;
    let model = provider
        .models()
        .first()
        .map_or_else(|| "default".to_string(), |m| m.id.clone());
    // Minimal one-token probe — most upstreams will respond in under a
    // second for "hi". This is intentionally not configurable: a long
    // test prompt would invite operators to use this endpoint as a
    // chat surface, which it isn't.
    let body = serde_json::json!({
        "model": model,
        "stream": false,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1
    });
    let started = std::time::Instant::now();
    let resp = provider.chat(&body, false).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (ok, error) = match resp {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };
    Ok(Json(ProviderTestResponse {
        ok,
        latency_ms,
        error,
    }))
}

/// Query string for `GET /admin/llm/audit`. Defaults: limit=100, no
/// before-cutoff. The wire format is `?limit=N&before=ISO-8601`.
#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
    #[serde(default)]
    before: Option<String>,
}

fn default_audit_limit() -> usize {
    100
}

#[derive(Serialize)]
struct AuditResponse {
    records: Vec<AuditRecord>,
}

async fn admin_get_audit(
    State(state): State<ServerState>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    let limit = q.limit.clamp(1, 1000);
    let records = state
        .inner
        .audit
        .read_paginated(limit, q.before.as_deref())
        .map_err(|e| {
            ApiError(ProxyError::Profile {
                path: "audit.log".into(),
                kind: format!("read: {e}"),
            })
        })?;
    Ok(Json(AuditResponse { records }))
}

/// Reject provider ids that could escape the profile namespace via path
/// traversal or unusual characters. Catalog ids are kebab-case (e.g.
/// `claude-cli`, `openai-codex`) so we accept `[A-Za-z0-9_-]+` only.
fn normalize_provider_id(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError(ProxyError::BadRequest(
            "provider id must not be empty".into(),
        )));
    }
    if trimmed.len() > 64 {
        return Err(ApiError(ProxyError::BadRequest(
            "provider id too long (max 64 chars)".into(),
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError(ProxyError::BadRequest(
            "provider id must match [A-Za-z0-9_-]+".into(),
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Reject keystore account names that could collide or escape in the
/// file backend, whose lossy sanitizer maps `/`, `\` and `\0` all to
/// `_`. Accounts follow the documented `llm.api_key.<provider>` /
/// `llm.oauth.<provider>` convention, so we accept `[A-Za-z0-9._-]+`
/// (same class as provider ids, plus the namespace dot). Unlike
/// `normalize_provider_id` we never case-fold: an account is a
/// reference, not a namespace key, and silently rewriting it would be
/// its own collision source.
fn validate_credential_account(raw: &str) -> Result<(), ApiError> {
    if raw.is_empty() {
        return Err(ApiError(ProxyError::BadRequest(
            "credential_account must not be empty".into(),
        )));
    }
    if raw.len() > 64 {
        return Err(ApiError(ProxyError::BadRequest(
            "credential_account too long (max 64 chars)".into(),
        )));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ApiError(ProxyError::BadRequest(
            "credential_account must match [A-Za-z0-9._-]+".into(),
        )));
    }
    Ok(())
}
