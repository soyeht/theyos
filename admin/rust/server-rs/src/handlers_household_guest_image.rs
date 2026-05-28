//! Household-namespaced handler for remotely starting macOS guest-image
//! preparation from the iPhone owner.
//!
//! Endpoint:
//!
//!   POST /api/v1/household/guest-image/prepare
//!
//! Authority model
//! ───────────────
//! The iPhone owner is the household's product authority. We gate on the
//! same Soyeht-PoP signature scheme as the rest of the household router
//! (see [`crate::household_auth`]); no second product permission is
//! collected on the Mac at preparation time. Authorisation reuses
//! `Operation::ClawsCreate` so already-issued owner `PersonCert`s
//! (which carry `claws.create`) keep working — adding a
//! `guest_image.prepare` operation today would brick owners that
//! haven't re-paired since the cert was minted.
//!
//! Non-interactivity contract
//! ──────────────────────────
//! The Mac engine runs as a `launchd`/Homebrew daemon with no
//! controlling TTY. The launcher MUST NOT take any code path that can
//! block waiting for a sudo prompt, password, or terminal interaction.
//! Capability gaps (missing privileged helper, missing IPC binary)
//! surface as a structured `helper_missing` response so the iPhone can
//! present an actionable error instead of hanging on an unresponsive
//! Mac.
//!
//! State source of truth
//! ─────────────────────
//! Progress lives in `init-state.json` written by the
//! `vmrunner_macos_ipc` IPC handler. This endpoint reads that file via
//! [`crate::guest_image_state::GuestImageState`] — the same shape the
//! iPhone already consumes via `GET /bootstrap/status`. We deliberately
//! do not mint a parallel status format here.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use household_rs::caveats::Operation;
use serde::{Deserialize, Serialize};

use crate::guest_image_state::GuestImageState;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::time_util;

// ── Public types ──────────────────────────────────────────────────────

/// What the launcher can do on this host. Determined at request time
/// because helper binaries / sudoers entries are operator-controlled and
/// may appear or vanish without restarting the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCheck {
    /// Host can run a non-interactive prepare. Spawning is safe.
    Available,
    /// Host's platform doesn't support a macOS guest image (Linux
    /// engine). The iPhone treats this as a per-machine capability
    /// flag, not a recoverable error.
    NotSupported,
    /// A required helper / capability is missing. `reason` is logged
    /// only — the response body returns a stable `status` code so the
    /// iPhone never has to substring-match.
    HelperMissing { reason: String },
}

/// Result of asking the launcher to spawn a job. `Spawned` consumes the
/// in-flight guard; the launcher must keep it alive for the lifetime of
/// the background task it owns.
#[derive(Debug)]
pub enum LaunchOutcome {
    Spawned,
    Failed(String),
}

/// Source of truth for the on-disk guest-image state. Trait-shaped so
/// tests can drive every branch on a Linux CI runner without touching
/// `~/Library/Application Support`.
pub trait GuestImageInspector: Send + Sync + 'static {
    fn read(&self) -> GuestImageState;
}

/// Production reader. Delegates to the existing
/// [`GuestImageState::read_current`] resolver (same one
/// `/bootstrap/status` uses).
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultInspector;

impl GuestImageInspector for DefaultInspector {
    fn read(&self) -> GuestImageState {
        GuestImageState::read_current()
    }
}

/// Spawns the actual prepare work. The handler holds it via
/// `Arc<dyn PrepareLauncher>` so tests can plug a counter-based mock.
pub trait PrepareLauncher: Send + Sync + 'static {
    /// Capability probe. MUST be cheap (no network, no long I/O) — runs
    /// on every request before the handler decides what to do.
    fn check(&self) -> CapabilityCheck;

    /// Schedule the prepare job. Returns immediately; the actual work
    /// is owned by a tokio task the launcher spawns internally.
    ///
    /// `guard` is the in-flight RAII flag — the launcher must move it
    /// into the spawned task so the next POST sees `in_flight == true`
    /// until the task finishes.
    ///
    /// `force` is forwarded into the prepare logic (caller decided that
    /// a retry is safe; e.g. previous attempt was `failed` and the
    /// iPhone explicitly opted in).
    fn start(&self, force: bool, guard: InFlightGuard) -> LaunchOutcome;
}

/// RAII guard that resets the in-process "currently preparing" flag
/// when dropped. The launcher owns one through the lifetime of its
/// background task.
pub struct InFlightGuard {
    flag: Arc<AtomicBool>,
}

impl InFlightGuard {
    #[must_use]
    pub fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flag }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

/// State injected into the axum router. Wraps both the household
/// identity (for `PoP` auth) and the launcher/inspector pair (for the
/// actual prep logic). Tests build it with mock implementations.
#[derive(Clone)]
pub struct GuestImagePrepareState {
    pub household: HouseholdState,
    pub inspector: Arc<dyn GuestImageInspector>,
    pub launcher: Arc<dyn PrepareLauncher>,
    pub in_flight: Arc<AtomicBool>,
}

// ── Request / response shape ──────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    /// When `true`, allows starting a fresh attempt on top of a
    /// `failed` state (otherwise we 409 to make the operator's intent
    /// explicit).
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Serialize)]
pub struct PrepareResponse {
    v: u8,
    /// Top-level status the iPhone branches on. Stable string set:
    /// `starting`, `in_progress`, `done`, `failed`, `not_supported`,
    /// `helper_missing`, `invalid_request`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_error: Option<String>,
    /// Machine-readable failure reason (`snake_case`). Present only when the
    /// most recent phase failed; absent otherwise and on older engines.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_failure_code: Option<core_rs::guest_image_failure::GuestImageFailureCode>,
}

// ── Handler ───────────────────────────────────────────────────────────

/// `POST /api/v1/household/guest-image/prepare` — start (or report on) a
/// macOS guest-image preparation initiated by the iPhone owner.
///
/// Status codes:
///
///   - 200 — guest image already `done` (idempotent).
///   - 202 — `starting` (fresh spawn), `in_progress`, or `pending`.
///   - 409 — last attempt `failed`; caller must opt in with
///     `{"force": true}` to retry.
///   - 401 — `PoP` auth rejected (deterministic empty body — no oracle).
///   - 400 — non-empty body is malformed or contains unsupported fields.
///   - 501 — `not_supported` (e.g. Linux engine).
///   - 503 — `helper_missing` (capability locally unavailable).
pub async fn handle_household_prepare_guest_image(
    State(state): State<GuestImagePrepareState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // ── Step 1: PoP auth, same shape as handlers_household_claws.
    let Some(now) = time_util::unix_now_secs_checked("guest_image.prepare.clock") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if let Err(e) = household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        // Reuse the already-emitted `claws.create` caveat so existing
        // owner certs keep working. A dedicated `guest_image.prepare`
        // op can be added once we can require cert re-issuance.
        Operation::ClawsCreate,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "guest_image.prepare.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // ── Step 2: parse the (optional) body. Empty body is allowed —
    // the launcher treats that as `force = false`.
    let req = match parse_request_body(&body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                stage = "guest_image.prepare.bad_request",
                error = %e,
            );
            return reply(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &GuestImageState::not_applicable(),
            );
        }
    };

    // ── Step 3: branch on the on-disk state. This is the same source
    // the iPhone polls via /bootstrap/status, so the values surfaced
    // here MUST match that contract.
    //
    // `pending` is a special case. The IPC subprocess writes
    // `pending` for the *next* phase before it actually starts work
    // on it; if the prepare crashes or is killed between phases (lost
    // SSH session, daemon restart, panic before `fail_phase`), the
    // on-disk record stays `pending` even though no task is running.
    // Trusting `pending` unconditionally would brick the endpoint —
    // every subsequent POST would return 202 in_progress forever,
    // with no spawn and no way to recover short of clearing the file
    // by hand. Gate on the in-process `in_flight` flag: if no task
    // owns it, treat the pending record as stale and fall through
    // to spawn (the worker resumes from the last completed phase).
    let current = state.inspector.read();
    let in_flight_now = state.in_flight.load(Ordering::SeqCst);
    match current.status.as_deref() {
        Some("done") => {
            tracing::info!(stage = "guest_image.prepare.idempotent", outcome = "done",);
            return reply(StatusCode::OK, "done", &current);
        }
        Some("in_progress") => {
            tracing::info!(
                stage = "guest_image.prepare.idempotent",
                outcome = "in_progress",
                phase = ?current.phase,
            );
            return reply(StatusCode::ACCEPTED, "in_progress", &current);
        }
        Some("pending") if in_flight_now => {
            tracing::info!(
                stage = "guest_image.prepare.idempotent",
                outcome = "in_progress",
                source = "pending_with_inflight",
                phase = ?current.phase,
            );
            return reply(StatusCode::ACCEPTED, "in_progress", &current);
        }
        Some("pending") => {
            // Stale: no task is preparing, but the disk record never
            // transitioned. Falls through to the spawn path so the
            // worker can resume from the last completed phase.
            tracing::warn!(
                stage = "guest_image.prepare.stale_pending",
                phase = ?current.phase,
                "resuming prepare for stale `pending` record (no task in flight)",
            );
        }
        Some("failed") if !req.force => {
            tracing::info!(
                stage = "guest_image.prepare.refused_failed",
                reason = "force_required",
            );
            return reply(StatusCode::CONFLICT, "failed", &current);
        }
        _ => {
            // Falls through: not_started (`None`), or `failed` with
            // `force = true` (operator-driven retry).
        }
    }

    // ── Step 4: capability probe BEFORE acquiring the in-flight flag.
    // If the host can't actually run a prep, do not consume a guard slot.
    match state.launcher.check() {
        CapabilityCheck::Available => {}
        CapabilityCheck::NotSupported => {
            tracing::info!(
                stage = "guest_image.prepare.not_supported",
                reason = "platform_does_not_support_macos_guest",
            );
            return reply(
                StatusCode::NOT_IMPLEMENTED,
                "not_supported",
                &GuestImageState::not_applicable(),
            );
        }
        CapabilityCheck::HelperMissing { reason } => {
            tracing::warn!(
                stage = "guest_image.prepare.helper_missing",
                reason = %reason,
            );
            return reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "helper_missing",
                &GuestImageState::not_applicable(),
            );
        }
    }

    // ── Step 5: in-flight guard. CAS so two simultaneous POSTs don't
    // both spawn. Losers report current state as in_progress (a true
    // statement: another POST is preparing, just hasn't written
    // init-state.json yet).
    if state
        .in_flight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        tracing::info!(
            stage = "guest_image.prepare.contended",
            reason = "another_prepare_already_in_flight",
        );
        return reply(StatusCode::ACCEPTED, "in_progress", &current);
    }
    let guard = InFlightGuard::new(Arc::clone(&state.in_flight));

    // ── Step 6: hand the guard to the launcher. From this point on
    // the launcher owns the AtomicBool lifetime via `Drop`.
    match state.launcher.start(req.force, guard) {
        LaunchOutcome::Spawned => {
            tracing::info!(stage = "guest_image.prepare.spawned", force = req.force,);
            reply(
                StatusCode::ACCEPTED,
                "starting",
                &GuestImageState::not_applicable(),
            )
        }
        LaunchOutcome::Failed(reason) => {
            // The guard was already dropped (start moved it). Belt-and-
            // suspenders: log and surface helper_missing — a spawn
            // failure is operationally indistinguishable from "the box
            // is missing a capability".
            tracing::warn!(
                stage = "guest_image.prepare.spawn_failed",
                reason = %reason,
            );
            reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "helper_missing",
                &GuestImageState::not_applicable(),
            )
        }
    }
}

// ── Production launcher ───────────────────────────────────────────────

/// Default launcher used by the daemon path. On non-macOS hosts every
/// call returns [`CapabilityCheck::NotSupported`] — the Mac is the only
/// place a guest image lives. On macOS the launcher orchestrates the
/// same two IPC calls `init_macos_guest` issues, but skips that
/// binary's interactive `sudo -v` prompt: this code path MUST stay
/// non-blocking and TTY-free because the daemon is a `launchd`/Homebrew
/// background service.
///
/// Operator setup expectations (today's contract — surfaced as
/// `helper_missing` if violated):
///
///   - `theyos-provision-inject` binary present (NixOS/Homebrew install).
///   - `vmrunner_macos_ipc` binary present and resolvable via
///     `THEYOS_VMRUNNER_MACOS_RS_BIN` or the same exe directory.
///
/// If sudo is not NOPASSWD-configured for `theyos-provision-inject`,
/// the IPC subprocess fails fast at the privileged step (sudo without
/// a TTY exits non-zero immediately) and writes a `failed` record into
/// `init-state.json`. The iPhone then observes `status = "failed"` on
/// its next `/bootstrap/status` poll.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosPrepareLauncher;

impl PrepareLauncher for MacosPrepareLauncher {
    fn check(&self) -> CapabilityCheck {
        #[cfg(not(target_os = "macos"))]
        {
            CapabilityCheck::NotSupported
        }
        #[cfg(target_os = "macos")]
        {
            match resolve_required_binaries() {
                Ok(_) => CapabilityCheck::Available,
                Err(reason) => CapabilityCheck::HelperMissing { reason },
            }
        }
    }

    fn start(&self, force: bool, guard: InFlightGuard) -> LaunchOutcome {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (force, guard);
            LaunchOutcome::Failed("guest image prepare not supported on this platform".into())
        }
        #[cfg(target_os = "macos")]
        {
            macos::spawn_prepare_job(force, guard)
        }
    }
}

#[cfg(target_os = "macos")]
fn resolve_required_binaries() -> Result<macos::ResolvedBinaries, String> {
    macos::resolve_required_binaries()
}

#[cfg(target_os = "macos")]
mod macos {
    //! macOS-only orchestration. Kept in a sub-module so the rest of
    //! the file compiles cleanly on Linux (CI runner / Linux engines).

    use super::{InFlightGuard, LaunchOutcome};
    use core_rs::ipc::client::IpcClient;
    use serde_json::json;
    use std::path::PathBuf;

    #[derive(Debug, Clone)]
    pub struct ResolvedBinaries {
        pub vmrunner: PathBuf,
    }

    /// Surface both binaries' resolvability through a single
    /// `Result`. The provision-inject path is only validated here —
    /// the actual `sudo theyos-provision-inject` invocation lives
    /// inside `vmrunner_macos_ipc`, which resolves the binary in its
    /// own process. Letting one side advertise it and the other side
    /// run it keeps the responsibility split that already exists
    /// between `init_macos_guest` (orchestrator) and the IPC daemon
    /// (privileged step).
    pub fn resolve_required_binaries() -> Result<ResolvedBinaries, String> {
        let vmrunner = resolve_vmrunner_bin()
            .ok_or_else(|| "vmrunner_macos_ipc binary not resolvable".to_string())?;
        // Surface a structured `helper_missing` BEFORE the iPhone
        // hits the long-running prepare path — otherwise the
        // privileged step would only fail 30+ min in.
        if resolve_provision_inject_bin().is_none() {
            return Err("theyos-provision-inject binary not resolvable".into());
        }
        Ok(ResolvedBinaries { vmrunner })
    }

    /// Mirrors the binary resolution `init_macos_guest::build_client`
    /// performs. Order:
    ///   1. `THEYOS_VMRUNNER_MACOS_RS_BIN` env var.
    ///   2. Same directory as the running server binary.
    ///   3. Cargo target dir (dev fallback).
    fn resolve_vmrunner_bin() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("THEYOS_VMRUNNER_MACOS_RS_BIN") {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return Some(pb);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let cand = dir.join("vmrunner_macos_ipc");
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
        let cand = PathBuf::from(manifest)
            .parent()?
            .join("target/release/vmrunner_macos_ipc");
        cand.is_file().then_some(cand)
    }

    /// Mirrors `vmrunner_macos_rs::macos_guest::resolve_provision_inject_bin`
    /// — same search order so a host that satisfies one side satisfies
    /// the other.
    fn resolve_provision_inject_bin() -> Option<PathBuf> {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let cand = dir.join("theyos-provision-inject");
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        if let Ok(bin_dir) = std::env::var("THEYOS_BIN_DIR") {
            let cand = PathBuf::from(bin_dir).join("theyos-provision-inject");
            if cand.is_file() {
                return Some(cand);
            }
        }
        let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
        let cand = PathBuf::from(manifest)
            .parent()?
            .join("target/release/theyos-provision-inject");
        cand.is_file().then_some(cand)
    }

    /// Hand the prep job off to a blocking task. The guard moves into
    /// the task so the in-flight flag stays asserted until both IPC
    /// calls finish (or fail) — there is no chance of an early reset
    /// while the IPC subprocess is still running.
    pub fn spawn_prepare_job(force: bool, guard: InFlightGuard) -> LaunchOutcome {
        // Resolve once on the caller's thread so a misconfigured host
        // surfaces synchronously instead of disappearing into a task.
        let bins = match resolve_required_binaries() {
            Ok(b) => b,
            Err(reason) => return LaunchOutcome::Failed(reason),
        };

        // `tokio::spawn` schedules the future on the current runtime.
        // axum handlers always run inside one, so this never panics.
        tokio::spawn(async move {
            let _guard = guard;
            let vmrunner_path = bins.vmrunner.display().to_string();
            // The IPC client is sync + blocking. Park it on the
            // blocking pool so other handlers keep being served while
            // the 30+ min prepare runs.
            let outcome =
                tokio::task::spawn_blocking(move || run_prepare(&vmrunner_path, force)).await;
            match outcome {
                Ok(Ok(())) => tracing::info!(
                    stage = "guest_image.prepare.completed",
                    "macOS guest image preparation finished",
                ),
                Ok(Err(e)) => {
                    tracing::warn!(
                        stage = "guest_image.prepare.failed",
                        error = %e,
                    );
                    // Best-effort: idempotent stamp so the next POST
                    // observes `failed` and (if `force = true`) can
                    // retry, instead of staring at a stale `pending`.
                    let path = init_state_path();
                    tokio::task::spawn_blocking(move || {
                        super::mark_init_state_failed_at_path(&path, &e);
                    })
                    .await
                    .ok();
                }
                Err(e) => {
                    tracing::error!(
                        stage = "guest_image.prepare.panicked",
                        error = %e,
                    );
                    let message = format!("prepare task panicked: {e}");
                    let path = init_state_path();
                    tokio::task::spawn_blocking(move || {
                        super::mark_init_state_failed_at_path(&path, &message);
                    })
                    .await
                    .ok();
                }
            }
        });

        LaunchOutcome::Spawned
    }

    /// Canonical path the IPC handler writes
    /// (`<base_dir>/init-state.json`). Resolved on every call so
    /// `THEYOS_VM_ASSETS_DIR` overrides applied after the daemon
    /// started still apply — same contract as `GuestImageState::read_current`.
    fn init_state_path() -> PathBuf {
        crate::guest_image_state::macos_base_dir().join("init-state.json")
    }

    fn run_prepare(vmrunner_path: &str, force: bool) -> Result<(), String> {
        let client =
            IpcClient::start(vmrunner_path, &[]).map_err(|e| format!("spawn vmrunner: {e}"))?;
        let registry_url = std::env::var("THEYOS_CLAW_BINARIES_URL").unwrap_or_default();

        // Step 1 — non-privileged download + install. ~30 min; stdin
        // stays connected to the IPC client which only sends JSON-RPC
        // frames, never a password prompt.
        let prepare_params = json!({
            "force": force,
            "force_provision": false,
            "ipsw": serde_json::Value::Null,
            "registry_url": registry_url,
        });
        let prepare = client
            .call("MacOsPrepare", prepare_params)
            .map_err(|e| format!("MacOsPrepare: {e}"))?;
        match prepare.get("status").and_then(|s| s.as_str()) {
            Some("already_complete") => return Ok(()),
            Some("ready_for_provision") => {}
            other => {
                return Err(format!(
                    "MacOsPrepare returned unexpected status: {other:?}"
                ));
            }
        }

        // Step 2/3 — privileged provision + snapshot. The IPC handler
        // internally invokes `sudo -n theyos-provision-inject`. If the
        // operator hasn't set NOPASSWD, sudo fails fast (no TTY ⇒ no
        // prompt). The IPC handler normally calls `fail_phase` on its
        // way out, but the post-task `mark_init_state_failed_at_path`
        // fallback above is the canonical guarantee that the iPhone
        // sees `failed` (and not `pending`) even if the IPC subprocess
        // crashes before transitioning the file.
        let snapshot_params = json!({
            "cpus": 4u32,
            "memory_mb": 4096u32,
            "force_provision": false,
            "plist_dir": resolve_plist_dir(),
        });
        let snapshot = client
            .call("MacOsProvisionAndSnapshot", snapshot_params)
            .map_err(|e| format!("MacOsProvisionAndSnapshot: {e}"))?;
        match snapshot.get("status").and_then(|s| s.as_str()) {
            Some("complete") => Ok(()),
            other => Err(format!(
                "MacOsProvisionAndSnapshot returned unexpected status: {other:?}"
            )),
        }
    }

    /// Mirror of `init_macos_guest::resolve_plist_dir`.
    fn resolve_plist_dir() -> String {
        if let Ok(dir) = std::env::var("THEYOS_DIR") {
            let p = PathBuf::from(&dir).join("scripts/launchd");
            if p.is_dir() {
                return p.display().to_string();
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(rust_dir) = exe.parent().and_then(|p| p.parent()) {
                let p = rust_dir.join("../../scripts/launchd");
                if p.is_dir() {
                    return p.display().to_string();
                }
            }
        }
        "scripts/launchd".to_string()
    }
}

// ── Internals ─────────────────────────────────────────────────────────

fn parse_request_body(body: &Bytes) -> Result<PrepareRequest, serde_json::Error> {
    if body.is_empty() {
        return Ok(PrepareRequest::default());
    }
    serde_json::from_slice::<PrepareRequest>(body)
}

fn reply(code: StatusCode, status: &'static str, current: &GuestImageState) -> Response {
    let body = PrepareResponse {
        v: 1,
        status,
        guest_image_phase: current.phase.clone(),
        guest_image_status: current.status.clone(),
        guest_image_error: current.error.clone(),
        guest_image_failure_code: current.failure_code,
    };
    (code, Json(body)).into_response()
}

/// Stamp a `status = "failed"` record into the existing `init-state.json`
/// when the launcher's background task ends with an error.
///
/// The `vmrunner_macos_ipc` IPC handler normally calls `fail_phase` on
/// every error path, but it cannot do that if it crashes outright
/// (panic, OOM, segfault from `VZ`) — and there's no way to be sure
/// every error tail in `macos_guest.rs` actually transitions before
/// returning. Without this best-effort fallback, the iPhone would see
/// `status = "pending"` forever after such a crash and the prepare
/// would only resume via the stale-pending path on the *next* POST —
/// surfacing no error in the meantime.
///
/// Behaviour:
///
///   - Missing or unparseable file ⇒ create a minimal failed record.
///   - Existing file with `status == "done"` ⇒ no-op. The job may have
///     succeeded between the launcher's `Err` and us reaching here
///     (e.g. a transient IPC stream error after `MacOsProvisionAndSnapshot`
///     already wrote the success record). Don't clobber a done state.
///   - Otherwise ⇒ merge in `status: "failed"` and a
///     `phase_history[<phase>]` entry carrying the error message.
///
/// Best-effort: any I/O / serde failure is logged at `warn` and
/// swallowed. The endpoint stays available even if the state file is
/// unwritable.
//
// `dead_code` on non-macOS: the only prod caller lives in `mod macos`
// (cfg-gated). Tests are cfg(test), which the workspace clippy gate
// (`cargo clippy --workspace -- -D warnings`) does not compile. The
// function is still meaningfully reachable on macOS and from tests on
// any platform, so silence the lint instead of cfg-gating the
// function out of Linux (which would also remove the cross-platform
// unit coverage).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn mark_init_state_failed_at_path(state_path: &std::path::Path, message: &str) {
    let Some(parent) = state_path.parent() else {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            reason = "state_path_has_no_parent",
        );
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            error = %e,
            "cannot create state directory; not stamping failure",
        );
        return;
    }

    let mut value = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let Some(root) = value.as_object_mut() else {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            reason = "init_state_root_not_object",
        );
        return;
    };

    // Don't overwrite a successfully-completed run.
    if root.get("status").and_then(|s| s.as_str()) == Some("done") {
        tracing::info!(
            stage = "guest_image.prepare.mark_failed.skip",
            reason = "status_already_done",
        );
        return;
    }

    // Pick the phase the failure attaches to. Prefer the existing
    // top-level `phase` (set by `begin_phase` in the IPC handler);
    // otherwise stamp `unknown` so the iPhone still sees a record
    // instead of a silent gap.
    let phase_key = root
        .get("phase")
        .and_then(|v| v.as_str())
        .map_or_else(|| "unknown".to_string(), str::to_string);

    root.insert(
        "status".to_string(),
        serde_json::Value::String("failed".into()),
    );
    let history = root
        .entry("phase_history".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(history_map) = history.as_object_mut() else {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            reason = "phase_history_not_object",
        );
        return;
    };
    let record = history_map
        .entry(phase_key.clone())
        .or_insert_with(|| serde_json::json!({}));
    let Some(record_map) = record.as_object_mut() else {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            reason = "phase_record_not_object",
            phase = %phase_key,
        );
        return;
    };
    record_map.insert(
        "status".to_string(),
        serde_json::Value::String("failed".into()),
    );
    record_map.insert(
        "error".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    // Machine-readable reason code, classified from the failure message (the
    // IPC's host-limit message carries stable tokens; PR-A returns err_code
    // 2001 for it). Lets the iPhone select localized recovery copy instead of
    // parsing the raw daemon string.
    let failure_code = core_rs::guest_image_failure::GuestImageFailureCode::classify(None, message);
    record_map.insert(
        "failure_code".to_string(),
        serde_json::Value::String(failure_code.as_str().to_string()),
    );

    // Write atomically: tempfile + persist (rename). Tempfile shares
    // the destination directory so `persist` stays on a single
    // filesystem (rename(2) atomicity).
    let serialized = match serde_json::to_vec_pretty(&value) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                stage = "guest_image.prepare.mark_failed.skip",
                error = %e,
                "serde write failed",
            );
            return;
        }
    };
    let tmp = match tempfile::NamedTempFile::new_in(parent) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                stage = "guest_image.prepare.mark_failed.skip",
                error = %e,
                "tempfile create failed",
            );
            return;
        }
    };
    if let Err(e) = std::fs::write(tmp.path(), &serialized) {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            error = %e,
            "tempfile write failed",
        );
        return;
    }
    if let Err(e) = tmp.persist(state_path) {
        tracing::warn!(
            stage = "guest_image.prepare.mark_failed.skip",
            error = %e.error,
            "tempfile persist failed",
        );
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use axum::routing::post;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::person_cert::SignOwnerOptions;
    use household_rs::pop::RequestSigningContext;
    use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert};
    use std::sync::Mutex;
    use tower::ServiceExt;

    // ── Mocks ────────────────────────────────────────────────────────

    #[derive(Clone)]
    struct StaticInspector {
        state: GuestImageState,
    }

    impl GuestImageInspector for StaticInspector {
        fn read(&self) -> GuestImageState {
            self.state.clone()
        }
    }

    struct MockLauncher {
        capability: CapabilityCheck,
        starts: Mutex<u32>,
        keep_guard: Mutex<Option<InFlightGuard>>,
    }

    impl MockLauncher {
        fn new(capability: CapabilityCheck) -> Self {
            Self {
                capability,
                starts: Mutex::new(0),
                keep_guard: Mutex::new(None),
            }
        }

        fn start_count(&self) -> u32 {
            *self.starts.lock().unwrap()
        }
    }

    impl PrepareLauncher for MockLauncher {
        fn check(&self) -> CapabilityCheck {
            self.capability.clone()
        }

        fn start(&self, _force: bool, guard: InFlightGuard) -> LaunchOutcome {
            *self.starts.lock().unwrap() += 1;
            // Stash the guard so the in-flight flag stays asserted for
            // the rest of the test (mirrors the real launcher's
            // task-owned lifetime).
            *self.keep_guard.lock().unwrap() = Some(guard);
            LaunchOutcome::Spawned
        }
    }

    // ── Fixture ──────────────────────────────────────────────────────

    struct Fixture {
        app: Router,
        person: P256Keypair,
        launcher: Arc<MockLauncher>,
        in_flight: Arc<AtomicBool>,
    }

    fn fixture_with(state: GuestImageState, capability: CapabilityCheck) -> Fixture {
        let td = tempfile::tempdir().unwrap();
        let identity = household_rs::bootstrap_or_load(
            td.path(),
            BootstrapOpts {
                household_name: "Sample Home".into(),
                hostname_label: Some("studio-test".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let person = P256Keypair::generate();
        let cert = PersonCert::sign_owner(
            identity
                .hh_priv
                .as_deref()
                .expect("hh_priv present in single-machine household"),
            SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: identity.record.created_at,
            },
        )
        .unwrap();
        let auth = HouseholdAuthState::new(&identity.record, cert);
        let household = HouseholdState::loaded_with_owner_auth(
            Arc::new(rehydrate_identity(&identity)),
            Some(Arc::new(auth)),
        );
        let launcher = Arc::new(MockLauncher::new(capability));
        let in_flight = Arc::new(AtomicBool::new(false));
        let app_state = GuestImagePrepareState {
            household,
            inspector: Arc::new(StaticInspector { state }),
            launcher: Arc::clone(&launcher) as Arc<dyn PrepareLauncher>,
            in_flight: Arc::clone(&in_flight),
        };
        let app = Router::new()
            .route(
                "/api/v1/household/guest-image/prepare",
                post(handle_household_prepare_guest_image),
            )
            .with_state(app_state);
        Fixture {
            app,
            person,
            launcher,
            in_flight,
        }
    }

    fn rehydrate_identity(identity: &household_rs::LoadedIdentity) -> household_rs::LoadedIdentity {
        // Mirror tests/phase2_pop_auth.rs::identity_for_state — keep the
        // owner's hh_priv accessible so PoP verification can stat the
        // anchor chain.
        household_rs::LoadedIdentity {
            record: identity.record.clone(),
            cert: identity.cert.clone(),
            hh_priv: Some(Box::new(
                P256Keypair::from_secret_scalar(
                    identity
                        .hh_priv
                        .as_ref()
                        .and_then(|k| k.as_software_secret())
                        .expect("software hh_priv in single-machine household"),
                )
                .unwrap(),
            )),
            m_priv: Box::new(
                P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap())
                    .unwrap(),
            ),
            backing: identity.backing,
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed(person: &P256Keypair, path: &str, body: &[u8]) -> String {
        let ts = unix_now();
        let ctx = RequestSigningContext::new("POST", path, ts, body);
        let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
        format!(
            "Soyeht-PoP v1:{}:{}:{}",
            household_rs::derive_person_id(&person.public()).0,
            ts,
            B64URL.encode(sig.as_bytes())
        )
    }

    async fn post_prepare(
        app: Router,
        auth: Option<String>,
        body: &[u8],
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/household/guest-image/prepare");
        if let Some(a) = auth {
            req = req.header(header::AUTHORIZATION, a);
        }
        if !body.is_empty() {
            req = req.header(header::CONTENT_TYPE, "application/json");
        }
        let resp = app
            .oneshot(req.body(Body::from(body.to_vec())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    // ── Tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn unauthorized_request_is_rejected_with_empty_body() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::Available,
        );
        let (status, body) = post_prepare(fx.app, None, b"").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body.is_null(),
            "empty body — no oracle for missing vs bad sig"
        );
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn malformed_json_returns_400_without_spawning() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::Available,
        );
        let path = "/api/v1/household/guest-image/prepare";
        let body = br#"{"force":"yes"}"#;
        let auth = signed(&fx.person, path, body);
        let (status, json) = post_prepare(fx.app, Some(auth), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["status"], "invalid_request");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn unknown_field_returns_400_without_spawning() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::Available,
        );
        let path = "/api/v1/household/guest-image/prepare";
        let body = br#"{"force":false,"later":true}"#;
        let auth = signed(&fx.person, path, body);
        let (status, json) = post_prepare(fx.app, Some(auth), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["status"], "invalid_request");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn not_supported_platform_short_circuits_before_spawn() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::NotSupported,
        );
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["v"], 1);
        assert_eq!(body["status"], "not_supported");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn already_done_returns_200_without_spawning() {
        let done = GuestImageState {
            phase: Some("complete".into()),
            status: Some("done".into()),
            error: None,
            failure_code: None,
        };
        let fx = fixture_with(done, CapabilityCheck::Available);
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "done");
        assert_eq!(body["guest_image_phase"], "complete");
        assert_eq!(body["guest_image_status"], "done");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn in_progress_returns_202_without_spawning_second_job() {
        let in_progress = GuestImageState {
            phase: Some("install_macos".into()),
            status: Some("in_progress".into()),
            error: None,
            failure_code: None,
        };
        let fx = fixture_with(in_progress, CapabilityCheck::Available);
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "in_progress");
        assert_eq!(body["guest_image_phase"], "install_macos");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn not_started_spawns_once_and_returns_starting() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::Available,
        );
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "starting");
        assert_eq!(fx.launcher.start_count(), 1);
    }

    #[tokio::test]
    async fn helper_missing_returns_503_and_does_not_spawn() {
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::HelperMissing {
                reason: "theyos-provision-inject missing".into(),
            },
        );
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "helper_missing");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn failed_without_force_returns_409() {
        let failed = GuestImageState {
            phase: Some("install_macos".into()),
            status: Some("failed".into()),
            error: Some("VZMacOSInstaller failed".into()),
            failure_code: Some(
                core_rs::guest_image_failure::GuestImageFailureCode::HostVmLimitReached,
            ),
        };
        let fx = fixture_with(failed, CapabilityCheck::Available);
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["status"], "failed");
        assert_eq!(body["guest_image_error"], "VZMacOSInstaller failed");
        // The machine-readable code rides alongside the human error.
        assert_eq!(body["guest_image_failure_code"], "host_vm_limit_reached");
        assert_eq!(fx.launcher.start_count(), 0);
    }

    #[tokio::test]
    async fn failed_with_force_spawns_retry() {
        let failed = GuestImageState {
            phase: Some("install_macos".into()),
            status: Some("failed".into()),
            error: Some("VZMacOSInstaller failed".into()),
            failure_code: Some(
                core_rs::guest_image_failure::GuestImageFailureCode::HostVmLimitReached,
            ),
        };
        let fx = fixture_with(failed, CapabilityCheck::Available);
        let path = "/api/v1/household/guest-image/prepare";
        let body = br#"{"force":true}"#;
        let auth = signed(&fx.person, path, body);
        let (status, json) = post_prepare(fx.app, Some(auth), body).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(json["status"], "starting");
        assert_eq!(fx.launcher.start_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_callers_only_spawn_one_job() {
        // Second POST should observe the in-flight flag set by the
        // first and 202 in_progress instead of spawning again.
        let fx = fixture_with(
            GuestImageState::not_applicable(),
            CapabilityCheck::Available,
        );
        let path = "/api/v1/household/guest-image/prepare";
        let auth1 = signed(&fx.person, path, b"");
        let (status1, body1) = post_prepare(fx.app.clone(), Some(auth1), b"").await;
        assert_eq!(status1, StatusCode::ACCEPTED);
        assert_eq!(body1["status"], "starting");

        let auth2 = signed(&fx.person, path, b"");
        let (status2, body2) = post_prepare(fx.app.clone(), Some(auth2), b"").await;
        assert_eq!(status2, StatusCode::ACCEPTED);
        // No init-state.json update yet — second caller reads the
        // (still empty) on-disk state but the in-flight CAS proves a
        // peer is mid-launch.
        assert_eq!(body2["status"], "in_progress");
        assert_eq!(fx.launcher.start_count(), 1);
    }

    #[tokio::test]
    async fn pending_without_inflight_spawns_resume() {
        // Stale-pending lifecycle: the IPC subprocess transitioned the
        // disk record to `pending` before its next phase but then died
        // (panic, daemon restart, lost session) without flipping to
        // `in_progress` or `failed`. With no `in_flight` guard held,
        // the handler MUST treat this as resumable instead of locking
        // the iPhone into a permanent 202 in_progress reply.
        let stale_pending = GuestImageState {
            phase: Some("provision".into()),
            status: Some("pending".into()),
            error: None,
            failure_code: None,
        };
        let fx = fixture_with(stale_pending, CapabilityCheck::Available);
        // No pre-set on `fx.in_flight` — default is `false`, matching
        // "no task is preparing right now".
        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "starting");
        assert_eq!(
            fx.launcher.start_count(),
            1,
            "stale pending must trigger a fresh spawn (resume), not a no-op",
        );
    }

    #[tokio::test]
    async fn pending_with_inflight_stays_in_progress() {
        // Live pending: a peer task already owns the in-flight flag
        // and is mid-execution. The disk record reads `pending` only
        // because the IPC subprocess hasn't issued `begin_phase` for
        // the next stage yet. We must NOT spawn a second job here.
        let live_pending = GuestImageState {
            phase: Some("provision".into()),
            status: Some("pending".into()),
            error: None,
            failure_code: None,
        };
        let fx = fixture_with(live_pending, CapabilityCheck::Available);
        fx.in_flight.store(true, Ordering::SeqCst);

        let path = "/api/v1/household/guest-image/prepare";
        let auth = signed(&fx.person, path, b"");
        let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "in_progress");
        assert_eq!(
            fx.launcher.start_count(),
            0,
            "in-flight pending must not spawn",
        );
    }

    // ── mark_init_state_failed_at_path ───────────────────────────────

    #[test]
    fn mark_failed_stamps_status_and_error_when_file_missing() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("init-state.json");
        super::mark_init_state_failed_at_path(&path, "boom");
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["status"], "failed");
        assert_eq!(written["phase_history"]["unknown"]["status"], "failed");
        assert_eq!(written["phase_history"]["unknown"]["error"], "boom");
        // Unclassifiable message → fail-soft `unknown` code (still stamped).
        assert_eq!(
            written["phase_history"]["unknown"]["failure_code"],
            "unknown"
        );
    }

    #[test]
    fn mark_failed_classifies_host_vm_limit_code() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("init-state.json");
        std::fs::write(
            &path,
            r#"{ "version": 2, "phase": "install_macos", "status": "in_progress" }"#,
        )
        .unwrap();
        // The IPC's host-limit message carries a stable token (PR-A returns
        // err_code 2001 with this guidance text).
        super::mark_init_state_failed_at_path(
            &path,
            "MacOsPrepare: macOS VM startup hit the host active-VM limit while installing",
        );
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["status"], "failed");
        assert_eq!(
            written["phase_history"]["install_macos"]["failure_code"],
            "host_vm_limit_reached"
        );
    }

    #[test]
    fn mark_failed_preserves_existing_phase_and_attaches_error() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("init-state.json");
        // Simulate a stale pending: phase set but no failure record.
        std::fs::write(
            &path,
            r#"{
                "version": 2,
                "phase": "provision",
                "status": "pending",
                "phase_history": {
                    "install_macos": { "status": "done", "attempts": 1 }
                }
            }"#,
        )
        .unwrap();
        super::mark_init_state_failed_at_path(&path, "sudo: no password set");
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["status"], "failed");
        assert_eq!(written["phase"], "provision", "top-level phase preserved");
        // Existing prior-phase record untouched.
        assert_eq!(written["phase_history"]["install_macos"]["status"], "done");
        // New failure attaches to the current phase.
        assert_eq!(written["phase_history"]["provision"]["status"], "failed");
        assert_eq!(
            written["phase_history"]["provision"]["error"],
            "sudo: no password set"
        );
    }

    #[test]
    fn mark_failed_does_not_clobber_done_status() {
        // Race: launcher returned Err (e.g. transient pipe close from
        // the IPC subprocess) but the prepare actually completed
        // successfully and the IPC wrote `done` to disk. Don't undo
        // that success.
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("init-state.json");
        std::fs::write(
            &path,
            r#"{ "version": 2, "phase": "complete", "status": "done" }"#,
        )
        .unwrap();
        super::mark_init_state_failed_at_path(&path, "stale launcher error");
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["status"], "done");
        assert!(
            written.get("phase_history").is_none()
                || written["phase_history"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty),
            "no phase_history entry created over a done state",
        );
    }
}
