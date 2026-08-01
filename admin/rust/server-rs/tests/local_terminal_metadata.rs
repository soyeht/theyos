//! E5 — session metadata for broker-owned local PTY sessions.
//!
//! Covers the brief's acceptance criteria directly: create returns
//! `slave_tty_path`, and `GET /api/v1/terminals/local` lists live sessions
//! with their metadata (`slave_tty_path`, `pgid`, `cwd`, `is_connected`).
//! Also covers the `reconnected` field @jovian asked to fold into E5: a
//! second create against the same `conversation_id` while the session is
//! still alive must report `reconnected: true` (and the identical
//! `slave_tty_path`, since it's the same underlying session, not a new
//! spawn) — the app needs this to say "conversation restored" honestly
//! rather than always claiming it.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::{Router, body::Body};
use axum_test::TestServer;
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::auth::AuthUser;
use server_rs::handlers_terminal::{
    handle_local_terminal_create, handle_local_terminal_delete, handle_local_terminal_list,
    handle_local_terminal_pty,
};
use server_rs::ratelimit::Limiter;
use server_rs::state::{AppState, SharedState};
use session_rs::SessionStore;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store_rs::InstanceDb;
use terminal_rs::pty::PtyManager;
use vmrunner_rs::VmRunner;

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

fn fixture() -> (Router, SharedState) {
    let sessions = SessionStore::open(":memory:").expect("session store");
    let jobs = JobsStore::new(":memory:").expect("jobs store");
    let instance_db = InstanceDb::open(":memory:").expect("instance db");
    let rate_limiter = Limiter::new(":memory:", 100).expect("rate limiter");

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

    let conv_dir = tempfile::TempDir::new().expect("conv tempdir");
    let conv_path = conv_dir.path().to_path_buf();
    std::mem::forget(conv_dir);
    let pty_mgr = Arc::new(PtyManager::new("/nonexistent-ctl", conv_path));

    set_test_env("FIRECRACKER_STATE_DIR", "/tmp");
    set_test_env("FIRECRACKER_BIN", "/tmp/fc");
    set_test_env("FIRECRACKER_KERNEL_IMAGE", "/tmp/vmlinux");
    set_test_env("FIRECRACKER_BASE_ROOTFS", "/tmp/rootfs.ext4");
    set_test_env("FIRECRACKER_SSH_KEY", "/tmp/id_rsa");
    set_test_env("FIRECRACKER_SSH_PUBKEY", "/tmp/id_rsa.pub");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open("/tmp/rootfs.ext4");
    let vm_runner = Arc::new(VmRunner::from_env().expect("vm runner"));

    let claw_dir = tempfile::TempDir::new().expect("claw tempdir");
    let claw_path = claw_dir.path().join("installed_claws.json");
    std::mem::forget(claw_dir);

    let state: SharedState = Arc::new(AppState {
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
        claw_store: claw_rs::ClawStore::new(&claw_path).expect("claw store"),
        theyos_dir: std::path::PathBuf::from("/tmp/theyos-test"),
        locks_dir: std::path::PathBuf::from("/tmp/theyos-test-locks"),
        capacity_lock: tokio::sync::Mutex::new(()),
        llm_proxy_client: server_rs::handlers_llm::ProxyClient::from_env(),
    });

    let auth = AuthUser {
        user_id: "user-alpha".to_string(),
        username: "user-alpha".to_string(),
        role: store_rs::UserRole::User,
    };
    let app = Router::new()
        .route(
            "/api/v1/terminals/local",
            get(handle_local_terminal_list).post(handle_local_terminal_create),
        )
        .route(
            "/api/v1/terminals/local/{conversation_id}/pty",
            get(handle_local_terminal_pty),
        )
        .route(
            "/api/v1/terminals/local/{conversation_id}",
            delete(handle_local_terminal_delete),
        )
        .layer(middleware::from_fn_with_state(auth, inject_auth))
        .with_state(state.clone());

    (app, state)
}

async fn inject_auth(State(user): State<AuthUser>, mut req: Request<Body>, next: Next) -> Response {
    req.extensions_mut().insert(user);
    next.run(req).await
}

async fn wait_for_alive(state: &SharedState, conv_id: &str) {
    for _ in 0..200 {
        if let Some(sess) = state.pty_mgr.get_local(conv_id) {
            if !sess.is_closed() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("session {conv_id} never became alive");
}

#[tokio::test]
async fn create_reconnect_and_list_report_session_metadata() {
    let (app, state) = fixture();
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");

    let conv_id = "conv-e5-meta";
    // /bin/sleep is an absolute path — no PATH lookup needed (spec.env is
    // empty here, and start_pty_session_local clears the child's env).
    let create_body = serde_json::json!({
        "conversation_id": conv_id,
        "argv": ["/bin/sleep", "1000"],
        "cols": 80,
        "rows": 24,
    });

    // ── First create: fresh spawn ──
    let first = server
        .post("/api/v1/terminals/local")
        .json(&create_body)
        .await;
    assert_eq!(first.status_code(), StatusCode::OK, "{}", first.text());
    let first_json: serde_json::Value = first.json();
    assert_eq!(
        first_json["reconnected"], false,
        "fresh spawn must not be reported as reconnected"
    );
    let tty_path = first_json["slave_tty_path"]
        .as_str()
        .expect("slave_tty_path must be present on create")
        .to_string();
    assert!(
        tty_path.starts_with("/dev/"),
        "slave_tty_path must be a real TTY device path, got {tty_path}"
    );

    wait_for_alive(&state, conv_id).await;

    // ── Second create, same conversation_id, session still alive: must be
    // reported as reconnected, with the SAME slave_tty_path (same session,
    // no new process spawned). ──
    let second = server
        .post("/api/v1/terminals/local")
        .json(&create_body)
        .await;
    assert_eq!(second.status_code(), StatusCode::OK, "{}", second.text());
    let second_json: serde_json::Value = second.json();
    assert_eq!(
        second_json["reconnected"], true,
        "a live existing session must be reported as reconnected"
    );
    assert_eq!(
        second_json["slave_tty_path"], tty_path,
        "reconnect must return the SAME session, not a new spawn"
    );

    // ── List must show the live session with matching metadata. ──
    let list = server.get("/api/v1/terminals/local").await;
    assert_eq!(list.status_code(), StatusCode::OK);
    let list_json: serde_json::Value = list.json();
    let items = list_json["data"].as_array().expect("data array");
    let entry = items
        .iter()
        .find(|i| i["conversation_id"] == conv_id)
        .expect("session must appear in the list");
    assert_eq!(entry["slave_tty_path"], tty_path);
    assert_eq!(entry["is_connected"], true);
    assert!(
        entry["pgid"].as_i64().expect("pgid must be an integer") > 0,
        "pgid must be a real positive process group id"
    );
    assert!(
        !entry["cwd"]
            .as_str()
            .expect("cwd must be a string")
            .is_empty(),
        "cwd must be populated"
    );

    // ── After delete, the session must drop out of the list. ──
    let del = server
        .delete(&format!("/api/v1/terminals/local/{conv_id}"))
        .await;
    assert_eq!(del.status_code(), StatusCode::NO_CONTENT);

    let list_after = server.get("/api/v1/terminals/local").await;
    let list_after_json: serde_json::Value = list_after.json();
    let items_after = list_after_json["data"].as_array().expect("data array");
    assert!(
        !items_after.iter().any(|i| i["conversation_id"] == conv_id),
        "deleted session must not appear in the list anymore"
    );
}
