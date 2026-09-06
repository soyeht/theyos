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
use axum::routing::get;
use axum::{Router, body::Body};
use axum_test::TestServer;
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::auth::AuthUser;
use server_rs::handlers_terminal::{
    handle_local_terminal_create, handle_local_terminal_delete, handle_local_terminal_get,
    handle_local_terminal_list, handle_local_terminal_pty,
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
    fixture_with_supervisor(None)
}

fn fixture_with_supervisor(
    local_pty_supervisor: Option<terminal_rs::supervisor_client::SupervisorClient>,
) -> (Router, SharedState) {
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
        local_pty_supervisor,
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
            get(handle_local_terminal_get).delete(handle_local_terminal_delete),
        )
        .route(
            "/api/v1/terminals/local/{conversation_id}/intents/{intent_id}/cancel",
            axum::routing::post(server_rs::handlers_terminal::handle_local_terminal_cancel_create),
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

struct SupervisorTask(tokio::task::JoinHandle<std::io::Result<()>>);

impl Drop for SupervisorTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn supervisor_http_contract_preserves_sessions_and_fences_stale_mutations() {
    use std::os::unix::fs::PermissionsExt;
    use terminal_rs::supervisor_client::SupervisorClient;
    use terminal_rs::supervisor_wire::Control;
    let root = tempfile::Builder::new()
        .prefix("pty-http-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.path().join("socket");
    let directory = root.path().join("state");
    let service_socket = socket.clone();
    let service = SupervisorTask(tokio::spawn(async move {
        terminal_rs::supervisor::serve(&service_socket, &directory).await
    }));
    let client = SupervisorClient::new(socket);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client.request(Control::List).await.is_ok() {
                break;
            }
            assert!(!service.0.is_finished());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (app, state) = fixture_with_supervisor(Some(client.clone()));
    let server = TestServer::builder().http_transport().build(app).unwrap();
    let path = "/api/v1/terminals/local/supervised-pane";
    let mut body = serde_json::json!({
        "conversation_id": "supervised-pane", "cwd": "/tmp",
        "argv": ["/bin/bash", "--noprofile", "--norc", "-i"],
        "env": [["PS1", ""], ["PATH", "/usr/bin:/bin"]], "cols": 80, "rows": 24,
    });
    let rejected = server.post("/api/v1/terminals/local").json(&body).await;
    assert_eq!(rejected.status_code(), StatusCode::PRECONDITION_FAILED);
    body["intent_id"] = serde_json::json!("00000000-0000-4000-8000-000000000001");
    let exchange = std::env::var_os("SOYEHT_TERMINAL_CONTRACT_DIR").map(std::path::PathBuf::from);
    if let Some(exchange) = &exchange {
        body =
            serde_json::from_slice(&std::fs::read(exchange.join("request.json")).unwrap()).unwrap();
        assert_eq!(body["conversation_id"], "supervised-pane");
    }
    let created = server.post("/api/v1/terminals/local").json(&body).await;
    assert_eq!(created.status_code(), StatusCode::OK, "{}", created.text());
    let first: serde_json::Value = created.json();
    let instance = first["session_instance_id"].as_str().unwrap();
    let etag = format!("\"{instance}\"");
    assert_eq!(first["reconnected"], false);
    let again = server.post("/api/v1/terminals/local").json(&body).await;
    let again: serde_json::Value = again.json();
    assert_eq!(again["session_instance_id"], instance);
    assert_eq!(again["reconnected"], true);
    assert!(
        state.pty_mgr.get_local("supervised-pane").is_none(),
        "must not create a legacy PTY"
    );
    assert_eq!(
        server.delete(path).await.status_code(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        server
            .get_websocket(&format!("{path}/pty"))
            .await
            .status_code(),
        StatusCode::PRECONDITION_FAILED
    );

    let stream_path =
        format!("{path}/pty?session_instance_id={instance}&stream_protocol=1&next_offset=0");
    let response = server.get_websocket(&stream_path).await;
    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let mut ws = response.into_websocket().await;
    let attached: serde_json::Value = ws.receive_json().await;
    assert_eq!(attached["type"], "attached");
    assert_eq!(attached["info"]["session_instance_id"], instance);
    // Exercise binary input and the actual UTF-8 JSON shape sent by the Mac.
    ws.send_message(axum_test::WsMessage::Binary(
        b"stty -echo\n".to_vec().into(),
    ))
    .await;
    let input = exchange.as_ref().map_or_else(
        || serde_json::json!({"type": "input", "data": "printf '\\143\\162\\157\\163\\163\\055\\142\\157\\165\\156\\144\\141\\162\\171\\055\\157\\153\\n'\n"}).to_string(),
        |directory| std::fs::read_to_string(directory.join("input.json")).unwrap(),
    );
    ws.send_message(axum_test::WsMessage::Text(input.into()))
        .await;
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.receive_message().await {
                axum_test::WsMessage::Binary(frame) => {
                    assert!(frame.starts_with(server_rs::supervised_terminals::OUTPUT_PREFIX));
                    let header = server_rs::supervised_terminals::OUTPUT_PREFIX.len();
                    let offset = u64::from_be_bytes(frame[header..header + 8].try_into().unwrap());
                    assert_eq!(offset, output.len() as u64);
                    output.extend_from_slice(&frame[header + 8..]);
                    frames.push(frame.to_vec());
                    if output
                        .windows(b"cross-boundary-ok".len())
                        .any(|bytes| bytes == b"cross-boundary-ok")
                    {
                        break;
                    }
                }
                axum_test::WsMessage::Text(text) => {
                    let event: serde_json::Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(event["type"], "replay_end");
                }
                other => panic!("unexpected WebSocket event: {other:?}"),
            }
        }
    })
    .await
    .expect("output through HTTP bridge");
    ws.close().await;
    assert_eq!(
        server.get(path).await.json::<serde_json::Value>()["is_connected"],
        true
    );
    // Drop the entire HTTP adapter and reconnect through a fresh one while
    // the independent owner remains. This is not an engine-process kill test.
    drop(server);
    drop(state);
    let (app, _) = fixture_with_supervisor(Some(client));
    let server = TestServer::builder().http_transport().build(app).unwrap();
    let restored: serde_json::Value = server.get(path).await.json();
    assert_eq!(restored["pid"], first["pid"]);
    assert_eq!(restored["session_instance_id"], instance);
    if let Some(exchange) = exchange {
        let result = serde_json::json!({"created": first, "restored": restored, "attached": attached, "frames": frames});
        std::fs::write(
            exchange.join("response.json"),
            serde_json::to_vec(&result).unwrap(),
        )
        .unwrap();
    }
    let closed = server
        .delete(path)
        .add_header(
            axum::http::header::IF_MATCH,
            etag.parse::<axum::http::HeaderValue>().unwrap(),
        )
        .await;
    assert_eq!(closed.status_code(), StatusCode::NO_CONTENT);
    body["intent_id"] = serde_json::json!("00000000-0000-4000-8000-000000000002");
    let replacement: serde_json::Value = server
        .post("/api/v1/terminals/local")
        .json(&body)
        .await
        .json();
    assert_ne!(replacement["session_instance_id"], instance);
    let stale = server
        .delete(path)
        .add_header(
            axum::http::header::IF_MATCH,
            etag.parse::<axum::http::HeaderValue>().unwrap(),
        )
        .await;
    assert_eq!(stale.status_code(), StatusCode::PRECONDITION_FAILED);
    let stale_attach = server.get_websocket(&stream_path).await;
    assert_eq!(stale_attach.status_code(), StatusCode::PRECONDITION_FAILED);
    let stale_cancel = format!("{path}/intents/00000000-0000-4000-8000-000000000001/cancel");
    for _ in 0..2 {
        assert_eq!(
            server.post(&stale_cancel).await.status_code(),
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        server.get(path).await.json::<serde_json::Value>()["is_connected"],
        true
    );
    service.0.abort();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        server.get(path).await.status_code(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        server
            .post("/api/v1/terminals/local")
            .json(&body)
            .await
            .status_code(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
