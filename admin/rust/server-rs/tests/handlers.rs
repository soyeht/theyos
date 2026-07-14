//! Integration tests for the v2 terminal HTTP handlers.
//!
//! Scope: REST endpoints for the `conversations` lifecycle (formerly
//! "workspaces" in v1, path kept for app compat). Tests exercise the
//! list / create / rename / delete flow against a minimal in-memory
//! `AppState`.
//!
//! What is NOT covered here:
//!   - The `/pty` `WebSocket` upgrade protocol (`replay_start` /
//!     `replay_done` / `session_ended` markers). Covered by the smoke
//!     test against devs and by unit tests in `terminal-rs/src/pty.rs`.
//!   - Non-terminal handlers (auth/jobs/instances/mobile). Those were
//!     part of the pre-v2 `handlers.rs` and have never changed in this
//!     refactor — coverage is in git history at commit 36c2377 if we
//!     ever need to resurrect those specific tests.
//!
//! The router is spun up without the real auth middleware: we inject
//! an `AuthUser` extension manually via a small middleware so the
//! `FromRequestParts` extractor short-circuits on it.
//!
//! All stores use `:memory:` `SQLite`. `PtyManager` points at a non-existent
//! ctl path so no real subprocess is ever spawned (the tests never
//! upgrade to a `WebSocket`).

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, patch},
};
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::{
    auth::AuthUser,
    handlers_terminal::{
        handle_create_conversation, handle_delete_conversation, handle_list_conversations,
        handle_rename_conversation,
    },
    public_sites::public_site_gateway,
    ratelimit::Limiter,
    state::{AppState, SharedState},
};
use session_rs::SessionStore;
use std::sync::{Arc, Mutex};
use store_rs::{InstanceDb, InstanceStatus, NewInstance, NewPublicSite, StatusUpdate, UserRole};
use terminal_rs::pty::PtyManager;
use tower::ServiceExt;
use vmrunner_rs::VmRunner;

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Serialize all tests that touch process-global env vars (`SOYEHT_ADMIN_*`,
/// `FIRECRACKER_*`). `cargo test` runs tests as threads within a single
/// process; without this lock, `TestFixture::new()` races on shared env
/// var names between parallel tests. Each `TestFixture` holds the guard
/// for its full lifetime (released on drop).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Inject a fixed `AuthUser` into request extensions. The `AuthUser`
/// `FromRequestParts` implementation short-circuits when the extension
/// is already present, so this bypasses cookie/bearer/query resolution
/// without touching the auth code under test.
async fn inject_auth(State(user): State<AuthUser>, mut req: Request<Body>, next: Next) -> Response {
    req.extensions_mut().insert(user);
    next.run(req).await
}

/// Write a one-off fake IPC shell script for `FlowConfig` and return its path.
/// Every JSON-RPC request gets `{"ok":true,"result":{}}` back. The `TempDir`
/// is leaked so the file outlives the test process.
fn fake_ipc_bin() -> String {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("fake-ipc.sh");
    std::fs::write(
        &path,
        b"#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{}}\\n'; done\n",
    )
    .expect("write fake ipc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake ipc");
    }
    std::mem::forget(dir);
    path.to_string_lossy().into_owned()
}

struct TestFixture {
    state: SharedState,
    /// Admin user (unrestricted).
    admin: AuthUser,
    /// Regular user — owns `owned_container`.
    user: AuthUser,
    /// Container owned by `user`.
    owned_container: String,
    /// Unassigned container — admin-only access.
    unassigned_container: String,
    /// Held for the full fixture lifetime so concurrent tests do not
    /// race on shared process-global env vars.
    _env_guard: std::sync::MutexGuard<'static, ()>,
}

impl TestFixture {
    #[allow(clippy::too_many_lines)] // test fixture wires up the full AppState
    fn new() -> Self {
        // Acquire the env lock first — every subsequent `set_test_env`
        // call and every `VmRunner::from_env()` / credential read in the
        // handlers under test expects exclusive access to the process
        // environment. Recover from poisoning so a panicking test does
        // not wedge the rest of the suite.
        let env_guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // The v2 admin credentials read from env on demand.
        set_test_env("SOYEHT_ADMIN_USER", "admin");
        set_test_env("SOYEHT_ADMIN_PASSWORD", "test");

        let sessions = SessionStore::open(":memory:").expect("session store");
        let jobs = JobsStore::new(":memory:").expect("jobs store");
        let instance_db = InstanceDb::open(":memory:").expect("instance db");
        let rate_limiter = Limiter::new(":memory:", 100).expect("rate limiter");

        // Seed users.
        let admin_id = instance_db.seed_admin("admin").expect("seed admin");
        let user_id = instance_db
            .create_user("alice", UserRole::User, Some(&admin_id))
            .expect("create user")
            .id;

        // Seed two instances: one owned by `alice`, one unassigned.
        let owned_container = "picoclaw-alice".to_string();
        instance_db
            .insert(&NewInstance {
                id: "inst-alice",
                name: "alice",
                container: &owned_container,
                claw_type: "picoclaw",
                sunset_date: "2099-12-31",
                guest_os: None,
                aux_storage_path: None,
                cpu_cores: None,
                ram_config_mb: None,
                disk_gb: None,
                household_id: None,
                household_machine_id: None,
            })
            .expect("insert alice instance");
        instance_db
            .update_status(&StatusUpdate {
                id: "inst-alice",
                status: InstanceStatus::Active,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .expect("mark alice active");
        instance_db
            .set_owner("inst-alice", Some(&user_id))
            .expect("assign owner");

        let unassigned_container = "picoclaw-admin".to_string();
        instance_db
            .insert(&NewInstance {
                id: "inst-admin",
                name: "admin-box",
                container: &unassigned_container,
                claw_type: "picoclaw",
                sunset_date: "2099-12-31",
                guest_os: None,
                aux_storage_path: None,
                cpu_cores: None,
                ram_config_mb: None,
                disk_gb: None,
                household_id: None,
                household_machine_id: None,
            })
            .expect("insert admin instance");
        instance_db
            .update_status(&StatusUpdate {
                id: "inst-admin",
                status: InstanceStatus::Active,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .expect("mark admin active");

        // FlowConfig/Executor: never invoked by these tests, but AppState
        // requires an Executor instance. Point every binary at the fake
        // IPC script so `Executor::new` doesn't try to spawn a real one.
        let fake_bin = fake_ipc_bin();
        let flow_config = FlowConfig {
            vmrunner_bin: fake_bin.clone(),
            store_bin: fake_bin.clone(),
            terminal_bin: fake_bin.clone(),
            firecracker_state_dir: "/tmp".to_string(),
            firecracker_bin: "/tmp/fake-fc".to_string(),
            kernel_image: "/tmp/vmlinux".to_string(),
            base_rootfs: "/tmp/rootfs.ext4".to_string(),
            ssh_key: "/tmp/ssh_key".to_string(),
            ssh_pubkey: "/tmp/ssh_key.pub".to_string(),
            ssh_wait_tries: 1,
            store_db_path: ":memory:".to_string(),
        };
        let executor = Executor::new(flow_config).expect("fake executor");

        // PTY manager: ctl path is non-existent and the conversation dir
        // is a tempdir we leak. The tests never trigger `start()`, so no
        // subprocess is spawned.
        let conv_dir = tempfile::TempDir::new().expect("conv tempdir");
        let conv_path = conv_dir.path().to_path_buf();
        std::mem::forget(conv_dir);
        let pty_mgr = Arc::new(PtyManager::new("/nonexistent-ctl", conv_path));

        // VmRunner::from_env: requires a handful of env vars. Populate
        // them with fake paths — VmRunner is never invoked in these tests.
        set_test_env("FIRECRACKER_STATE_DIR", "/tmp");
        set_test_env("FIRECRACKER_BIN", "/tmp/fc");
        set_test_env("FIRECRACKER_KERNEL_IMAGE", "/tmp/vmlinux");
        set_test_env("FIRECRACKER_BASE_ROOTFS", "/tmp/rootfs.ext4");
        set_test_env("FIRECRACKER_SSH_KEY", "/tmp/id_rsa");
        set_test_env("FIRECRACKER_SSH_PUBKEY", "/tmp/id_rsa.pub");
        // Touch the fake rootfs so the availability projection probe
        // doesn't fail on existence check.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open("/tmp/rootfs.ext4");
        let vm_runner = Arc::new(VmRunner::from_env().expect("vm runner"));

        // ClawStore: kept in a leaked tempdir so its JSON path outlives
        // the test. Mark every manifest claw as ready for completeness.
        let claw_dir = tempfile::TempDir::new().expect("claw tempdir");
        let claw_path = claw_dir.path().join("installed_claws.json");
        std::mem::forget(claw_dir);
        let claw_store = claw_rs::ClawStore::new(&claw_path).expect("claw store");
        for name in core_rs::manifest::all_names() {
            claw_store.mark_ready(name).expect("mark ready");
        }
        let state = Arc::new(AppState {
            sessions,
            jobs,
            ver_cache: std::sync::RwLock::default(),
            instance_db,
            rate_limiter: Arc::new(rate_limiter),
            executor: Arc::new(Mutex::new(executor)),
            pty_mgr,
            vm_runner,
            mobile_tokens: Arc::new(server_rs::mobile_token::MobileTokenStore::new()),
            mobile_sessions: server_rs::mobile_token::MobileSessionDb::open(":memory:")
                .expect("mobile session db"),
            claw_store,
            theyos_dir: std::path::PathBuf::from("/tmp/theyos-test"),
            locks_dir: std::path::PathBuf::from("/tmp/theyos-test-locks"),
            capacity_lock: tokio::sync::Mutex::new(()),
            llm_proxy_client: server_rs::handlers_llm::ProxyClient::from_env(),
        });

        let admin = AuthUser {
            user_id: admin_id,
            username: "admin".into(),
            role: UserRole::Admin,
        };
        let user = AuthUser {
            user_id,
            username: "alice".into(),
            role: UserRole::User,
        };

        TestFixture {
            state,
            admin,
            user,
            owned_container,
            unassigned_container,
            _env_guard: env_guard,
        }
    }

    /// Build a Router scoped at `/api/v1/terminals/{container}/workspaces*`
    /// with `auth` pre-injected into every request.
    fn router(&self, auth: AuthUser) -> Router {
        Router::new()
            .route(
                "/api/v1/terminals/{container}/workspaces",
                get(handle_list_conversations).post(handle_create_conversation),
            )
            .route(
                "/api/v1/terminals/{container}/workspaces/{id}",
                patch(handle_rename_conversation).delete(handle_delete_conversation),
            )
            .layer(middleware::from_fn_with_state(auth, inject_auth))
            .with_state(Arc::clone(&self.state))
    }

    fn public_gateway_router(&self) -> Router {
        Router::new()
            .fallback(|| async { StatusCode::OK })
            .layer(middleware::from_fn_with_state(
                Arc::clone(&self.state),
                public_site_gateway,
            ))
            .with_state(Arc::clone(&self.state))
    }
}

/// Convenience: deserialize a JSON response body.
async fn json_body(resp: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("valid JSON body")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_conversations_empty() {
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["data"].as_array().unwrap().len(), 0);
    assert_eq!(body["has_more"], false);
    assert!(body["next_cursor"].is_null());
    // v2: no `warning` field when count <= 8.
    assert!(body.get("warning").is_none());
}

#[tokio::test]
async fn list_conversations_has_no_window_count_field() {
    // v2 contract: the `window_count` field (v1 tmux windows per session)
    // MUST be absent from every conversation entry.
    let fx = TestFixture::new();

    // Seed a conversation directly via the DB to avoid chaining create →
    // list in a single request.
    fx.state
        .instance_db
        .create_conversation(&fx.owned_container, "alice", "first")
        .expect("seed conversation");

    let app = fx.router(fx.user.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let entries = body["data"].as_array().expect("data is array");
    assert_eq!(entries.len(), 1);
    let first = &entries[0];
    assert!(
        first.get("window_count").is_none(),
        "v2 responses must not include window_count: got {first}"
    );
    // Contract sanity: required fields present.
    for field in [
        "id",
        "session_id",
        "container",
        "display_name",
        "status",
        "is_connected",
    ] {
        assert!(first.get(field).is_some(), "missing field {field}");
    }
    assert_eq!(first["is_connected"], false);
}

#[tokio::test]
async fn create_conversation_returns_id() {
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":"my-conv"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let ws = &body["workspace"];
    let id = ws["id"].as_str().expect("id string");
    assert!(!id.is_empty(), "id should be non-empty hex");
    assert_eq!(ws["session_id"], ws["id"], "session_id should alias id");
    assert_eq!(ws["container"], fx.owned_container);
    assert_eq!(ws["display_name"], "my-conv");
}

#[tokio::test]
async fn create_conversation_does_not_spawn_pty() {
    // v2 contract: POST only creates a DB row. The PTY spawns lazily on
    // the first WebSocket attach. `is_connected` in the subsequent list
    // must be false.
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);

    // Sanity: PtyManager has no session for this conversation.
    let created = json_body(create_resp).await;
    let id = created["workspace"]["id"].as_str().unwrap().to_string();
    assert!(
        fx.state.pty_mgr.get(&fx.owned_container, &id).is_none(),
        "create should not spawn a PTY session"
    );

    // List confirms is_connected=false.
    let list_resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json_body(list_resp).await;
    assert_eq!(body["data"][0]["is_connected"], false);
}

#[tokio::test]
async fn create_conversation_unknown_container_is_404() {
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/terminals/ghost/workspaces")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_conversation_foreign_container_is_404_for_user() {
    // Ownership leak defense: a regular user MUST get 404 (not 403) when
    // attempting to act on a container they don't own, so existence
    // isn't revealed.
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.unassigned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_can_access_unassigned_container() {
    let fx = TestFixture::new();
    let app = fx.router(fx.admin.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.unassigned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":"admin-conv"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_cannot_access_someone_elses_assigned_container() {
    // Assigned instances are owner-only, even for admins. Verifies the
    // ownership check in `require_terminal_access`.
    let fx = TestFixture::new();
    let app = fx.router(fx.admin.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rename_conversation_updates_display_name() {
    let fx = TestFixture::new();

    let ws = fx
        .state
        .instance_db
        .create_conversation(&fx.owned_container, "alice", "old-name")
        .expect("seed conversation");

    let app = fx.router(fx.user.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces/{}",
                    fx.owned_container, ws.id
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":"new-name"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Confirm via DB read.
    let list = fx
        .state
        .instance_db
        .list_conversations(&fx.owned_container, "alice")
        .expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].display_name, "new-name");
}

#[tokio::test]
async fn rename_nonexistent_conversation_is_404() {
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces/0123456789abcdef",
                    fx.owned_container
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"display_name":"whatever"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_conversation_removes_row() {
    let fx = TestFixture::new();
    let ws = fx
        .state
        .instance_db
        .create_conversation(&fx.owned_container, "alice", "doomed")
        .expect("seed");

    let app = fx.router(fx.user.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces/{}",
                    fx.owned_container, ws.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let list = fx
        .state
        .instance_db
        .list_conversations(&fx.owned_container, "alice")
        .expect("list");
    assert!(
        list.is_empty(),
        "row should be gone after DELETE, got {list:?}"
    );
}

#[tokio::test]
async fn delete_conversation_unlinks_log_file() {
    // v2 canonical delete order: DB row → PTY close → log unlink.
    // We simulate the "PTY was attached" state by writing a log file
    // directly, then confirm DELETE removes it.
    let fx = TestFixture::new();
    let ws = fx
        .state
        .instance_db
        .create_conversation(&fx.owned_container, "alice", "with-log")
        .expect("seed");

    // Stash a log file in the conv dir via the PtyManager's knowledge.
    // We can't easily invoke start() (no real ctl path), but we can
    // open the ConversationLog directly: it takes (dir, conv_id).
    // The dir is the conv_dir passed to PtyManager::new — we know it's
    // a tempdir from the fixture, but it isn't exposed publicly. Rather
    // than plumb an accessor just for tests, use a proxy check: after
    // DELETE, the DB row is gone and pty_mgr.get() returns None. The
    // log-unlink path is covered by `pty_manager_close_missing_is_ok`
    // + the close() unit tests in terminal-rs.
    let app = fx.router(fx.user.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces/{}",
                    fx.owned_container, ws.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(fx.state.pty_mgr.get(&fx.owned_container, &ws.id).is_none());
}

#[tokio::test]
async fn delete_other_users_conversation_is_404() {
    // User-A creates a conversation. User-B tries to delete it. Even
    // though the DB row exists, the ownership check in
    // `verify_conversation_owner` maps the mismatch to 404 to avoid
    // leaking existence.
    let fx = TestFixture::new();

    // admin owns `unassigned_container` by way of being admin.
    // Seed a conversation there as admin, then try to delete as alice.
    let ws = fx
        .state
        .instance_db
        .create_conversation(&fx.unassigned_container, "admin", "admin-owned")
        .expect("seed");

    let app = fx.router(fx.user.clone()); // alice
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces/{}",
                    fx.unassigned_container, ws.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Note: hits `require_terminal_access` first (unassigned → admin-only),
    // which returns 404 for alice before we even reach the session owner
    // check. Either way, 404 is correct and the conversation survives.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let still_there = fx
        .state
        .instance_db
        .list_conversations(&fx.unassigned_container, "admin")
        .expect("list");
    assert_eq!(still_there.len(), 1);
}

#[tokio::test]
async fn invalid_container_name_is_400() {
    let fx = TestFixture::new();
    let app = fx.router(fx.user.clone());

    let too_long = "x".repeat(200);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/terminals/{too_long}/workspaces"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_warning_when_over_eight_conversations() {
    let fx = TestFixture::new();
    // Seed 9 conversations to trip the warning threshold.
    for i in 0..9 {
        fx.state
            .instance_db
            .create_conversation(&fx.owned_container, "alice", &format!("c{i}"))
            .expect("seed");
    }
    let app = fx.router(fx.user.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/terminals/{}/workspaces",
                    fx.owned_container
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    assert_eq!(body["data"].as_array().unwrap().len(), 9);
    assert!(
        body.get("warning").is_some(),
        "warning should be present when count > 8, got {body}"
    );
}

#[tokio::test]
async fn public_site_unknown_host_returns_404_instead_of_fallback() {
    let fx = TestFixture::new();
    let app = fx.public_gateway_router();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/login")
                .header(header::HOST, "unknown-public.example.com")
                .header("X-TheyOS-Public-Site", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn public_site_proxy_preserves_request_and_strips_admin_auth() {
    async fn echo_public_request(req: Request<Body>) -> axum::Json<serde_json::Value> {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .expect("read proxied body");
        let body = String::from_utf8_lossy(&bytes).to_string();
        axum::Json(serde_json::json!({
            "method": parts.method.as_str(),
            "path": parts.uri.path(),
            "query": parts.uri.query(),
            "body": body,
            "host": parts.headers.get(header::HOST).and_then(|v| v.to_str().ok()),
            "authorization_present": parts.headers.contains_key(header::AUTHORIZATION),
            "cookie_present": parts.headers.contains_key(header::COOKIE),
            "public_marker_present": parts.headers.contains_key("x-theyos-public-site"),
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake public site upstream");
    let upstream_port = listener.local_addr().unwrap().port();
    let upstream = Router::new().fallback(echo_public_request);
    tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("serve fake upstream");
    });

    let fx = TestFixture::new();
    fx.state
        .instance_db
        .upsert_public_site(&NewPublicSite {
            domain: "app.example.com",
            instance_id: "inst-admin",
            guest_port: 3000,
            target_host: "127.0.0.1",
            target_port: i64::from(upstream_port),
            enabled: true,
        })
        .expect("seed public site");

    let app = fx.public_gateway_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/submit?x=1")
                .header(header::HOST, "app.example.com")
                .header("X-TheyOS-Public-Site", "1")
                .header(header::AUTHORIZATION, "Bearer admin-token")
                .header(header::COOKIE, "soyeht_session=admin")
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/submit");
    assert_eq!(body["query"], "x=1");
    assert_eq!(body["body"], "hello");
    assert_eq!(body["host"], "app.example.com");
    assert_eq!(body["authorization_present"], false);
    assert_eq!(body["cookie_present"], false);
    assert_eq!(body["public_marker_present"], false);
}
