#![cfg(test)]

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
            P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap()).unwrap(),
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
async fn stale_boot_scoped_failure_is_preparable_and_spawns_without_force() {
    // After a reboot, `guest_image_state::reconcile_failure` masks a stale
    // `current_boot` host-limit failure to a preparable state (the resolver
    // returns `not_applicable()`, validated in guest_image_state tests). The
    // prepare handler reads through that same resolver, so a masked-stale
    // state must NOT hit the `failed → 409 without force` branch — it falls
    // through and spawns, with no `force` required. This is the end of the
    // "Check Again after reboot un-sticks the iPhone" chain.
    let fx = fixture_with(
        GuestImageState::not_applicable(),
        CapabilityCheck::Available,
    );
    let path = "/api/v1/household/guest-image/prepare";
    let auth = signed(&fx.person, path, b"");
    let (status, body) = post_prepare(fx.app, Some(auth), b"").await;
    assert_eq!(status, StatusCode::ACCEPTED, "stale failure must not 409");
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
        failure_code: Some(core_rs::guest_image_failure::GuestImageFailureCode::HostVmLimitReached),
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
        failure_code: Some(core_rs::guest_image_failure::GuestImageFailureCode::HostVmLimitReached),
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
    // `unknown` code defaults to `persistent` scope (conservative — keeps
    // blocking) and therefore carries NO `failure_boot_id`. `occurred_at`
    // is stamped regardless.
    let rec = &written["phase_history"]["unknown"];
    assert_eq!(rec["failure_scope"], "persistent");
    assert!(
        rec.get("failure_boot_id").is_none(),
        "persistent failures must not carry a boot id"
    );
    assert!(
        rec["occurred_at"].is_number(),
        "occurred_at must be stamped"
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
    let rec = &written["phase_history"]["install_macos"];
    assert_eq!(rec["failure_code"], "host_vm_limit_reached");
    // host_vm_limit_reached is boot-scoped: scope `current_boot` plus a
    // `failure_boot_id` stamped from the core_rs SSoT (so it compares
    // byte-for-byte with the admission registry / live boot id later).
    assert_eq!(rec["failure_scope"], "current_boot");
    let boot_id = rec["failure_boot_id"]
        .as_str()
        .expect("current_boot failure must carry a boot id");
    assert!(
        boot_id.starts_with("boottime:") || boot_id.starts_with("boottime-raw:"),
        "boot id must match the core_rs::boot_id format, got: {boot_id}"
    );
    assert_eq!(boot_id, core_rs::boot_id::current_boot_id());
    assert!(rec["occurred_at"].is_number());
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
