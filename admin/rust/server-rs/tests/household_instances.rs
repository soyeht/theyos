use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{
    Extension, Router,
    routing::{delete, get, patch, post},
};
use axum_test::TestServer;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use core_rs::env::set_test_env;
use executor_rs::{Executor, FlowConfig};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::SignOwnerOptions;
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert};
use jobs_rs::Store as JobsStore;
use server_rs::auth::AuthUser;
use server_rs::handlers_household_claws::{self, HouseholdClawsState};
use server_rs::handlers_instances;
use server_rs::handlers_terminal;
use server_rs::household_attach_token::{
    HOUSEHOLD_ATTACH_TOKEN_TTL, HouseholdAttachScope, HouseholdAttachTokenStore,
};
use server_rs::household_state::HouseholdState;
use server_rs::ratelimit::Limiter;
use server_rs::state::{AppState, SharedState};
use session_rs::SessionStore;
use store_rs::{InstanceDb, InstanceStatus, NewInstance, StatusUpdate};
use terminal_rs::pty::PtyManager;
use tower::ServiceExt;
use vmrunner_rs::VmRunner;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

struct Fixture {
    app: Router,
    person: P256Keypair,
    shared: SharedState,
    household_id: String,
    machine_id: String,
    attach_tokens: Arc<HouseholdAttachTokenStore>,
}

fn fixture() -> Fixture {
    let state_dir = tempfile::tempdir().expect("household state");
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("mac-alpha".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let household_id = identity.record.hh_id.to_string();
    let machine_id = identity.cert.m_id.to_string();
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
    let owner_auth = HouseholdAuthState::new(&identity.record, cert);
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::new(identity_for_state(&identity)),
        Some(Arc::new(owner_auth)),
    );
    let shared = shared_state();
    let attach_tokens = Arc::new(HouseholdAttachTokenStore::new());
    let claws_state = HouseholdClawsState {
        shared: Arc::clone(&shared),
        household,
        attach_tokens: Arc::clone(&attach_tokens),
    };
    let app = Router::new()
        .route(
            "/api/v1/household/instances",
            get(handlers_household_claws::handle_household_list_instances),
        )
        .route(
            "/api/v1/household/instances/{id}/status",
            get(handlers_household_claws::handle_household_instance_status),
        )
        .route(
            "/api/v1/household/instances/{id}/stop",
            post(handlers_household_claws::handle_household_stop_instance),
        )
        .route(
            "/api/v1/household/instances/{id}/restart",
            post(handlers_household_claws::handle_household_restart_instance),
        )
        .route(
            "/api/v1/household/instances/{id}/rebuild",
            post(handlers_household_claws::handle_household_rebuild_instance),
        )
        .route(
            "/api/v1/household/instances/{id}",
            delete(handlers_household_claws::handle_household_delete_instance),
        )
        .route(
            "/api/v1/household/terminals/{container}/workspaces",
            get(handlers_household_claws::handle_household_list_workspaces)
                .post(handlers_household_claws::handle_household_create_workspace),
        )
        .route(
            "/api/v1/household/terminals/{container}/workspaces/{id}",
            patch(handlers_household_claws::handle_household_rename_workspace)
                .delete(handlers_household_claws::handle_household_delete_workspace),
        )
        .route(
            "/api/v1/household/terminals/{container}/attach-token",
            post(handlers_household_claws::handle_household_mint_attach_token),
        )
        .route(
            "/api/v1/household/terminals/{container}/pty",
            get(handlers_household_claws::handle_household_terminal_pty),
        )
        .with_state(claws_state);

    Fixture {
        app,
        person,
        shared,
        household_id,
        machine_id,
        attach_tokens,
    }
}

async fn inject_auth(State(user): State<AuthUser>, mut req: Request<Body>, next: Next) -> Response {
    req.extensions_mut().insert(user);
    next.run(req).await
}

fn identity_for_state(identity: &household_rs::LoadedIdentity) -> household_rs::LoadedIdentity {
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

fn shared_state() -> SharedState {
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
    let pty_mgr = Arc::new(PtyManager::new(&fake_bin, conv_path));

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

    Arc::new(AppState {
        sessions,
        jobs,
        ver_cache: std::sync::RwLock::default(),
        instance_db,
        rate_limiter,
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
    })
}

fn pop_header(person: &P256Keypair, path: &str, body: &[u8]) -> String {
    pop_header_for_method(person, "GET", path, body)
}

fn pop_header_for_method(person: &P256Keypair, method: &str, path: &str, body: &[u8]) -> String {
    let ts = unix_now();
    let ctx = RequestSigningContext::new(method, path, ts, body);
    let sig = person.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        ts,
        B64URL.encode(sig.as_bytes())
    )
}

fn insert_instance(
    db: &InstanceDb,
    id: &'static str,
    household_id: Option<&str>,
    machine_id: Option<&str>,
) {
    let name = id.strip_prefix("inst-").unwrap_or(id);
    let container = format!("picoclaw-{name}");
    db.insert(&NewInstance {
        id,
        name,
        container: &container,
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id,
        household_machine_id: machine_id,
    })
    .expect("insert instance");
    db.update_status(&StatusUpdate {
        id,
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .expect("mark active");
}

async fn get_json(
    app: Router,
    person: &P256Keypair,
    path: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, pop_header(person, path, b""))
                .extension(ConnectInfo(allowed_peer_addr()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

async fn request_json(
    app: Router,
    person: &P256Keypair,
    method: Method,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    request_json_with_peer(app, person, method, path, body, Some(allowed_peer_addr())).await
}

async fn request_json_with_peer(
    app: Router,
    person: &P256Keypair,
    method: Method,
    path: &str,
    body: serde_json::Value,
    peer: Option<SocketAddr>,
) -> (StatusCode, serde_json::Value) {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let mut builder = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(
            header::AUTHORIZATION,
            pop_header_for_method(person, method.as_str(), path, &bytes),
        )
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(peer) = peer {
        builder = builder.extension(ConnectInfo(peer));
    }
    let resp = app
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

async fn request_json_without_auth(
    app: Router,
    method: Method,
    path: &str,
    body: serde_json::Value,
) -> StatusCode {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let resp = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(allowed_peer_addr()))
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

fn attach_scope(
    household_id: &str,
    container: &str,
    session_id: &str,
    actor_person_id: &str,
) -> HouseholdAttachScope {
    HouseholdAttachScope {
        household_id: household_id.to_string(),
        container: container.to_string(),
        session_id: session_id.to_string(),
        actor_person_id: actor_person_id.to_string(),
    }
}

fn allowed_peer_addr() -> SocketAddr {
    "127.0.0.1:41001".parse().unwrap()
}

fn remote_peer_addr() -> SocketAddr {
    "192.0.2.10:41001".parse().unwrap()
}

fn tailnet_peer_addr() -> SocketAddr {
    "100.64.0.10:41001".parse().unwrap()
}

fn tailnet_ipv6_peer_addr() -> SocketAddr {
    "[fd7a:115c:a1e0::10]:41001".parse().unwrap()
}

async fn get_household_pty(app: Router, path: &str, token: Option<&str>) -> StatusCode {
    get_household_pty_with_peer(app, path, token, Some(allowed_peer_addr())).await
}

async fn get_household_pty_with_peer(
    app: Router,
    path: &str,
    token: Option<&str>,
    peer: Option<SocketAddr>,
) -> StatusCode {
    let app = match peer {
        Some(peer) => app.layer(Extension(ConnectInfo(peer))),
        None => app,
    };
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");
    let mut request = server.get_websocket(path);
    if let Some(token) = token {
        request = request.add_header("X-Soyeht-Household-Attach-Token", token);
    }
    request.await.status_code()
}

#[tokio::test]
async fn household_instances_list_filters_by_household_and_deleted_state() {
    let fx = fixture();
    let other_hh = household_rs::derive_household_id(&P256Keypair::generate().public()).to_string();

    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    insert_instance(
        &fx.shared.instance_db,
        "inst-other-household",
        Some(&other_hh),
        Some(&fx.machine_id),
    );
    insert_instance(&fx.shared.instance_db, "inst-legacy", None, None);
    insert_instance(
        &fx.shared.instance_db,
        "inst-deleted",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    fx.shared
        .instance_db
        .soft_delete("inst-deleted")
        .expect("soft delete");

    let (status, json) = get_json(fx.app, &fx.person, "/api/v1/household/instances").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().expect("data array");
    let ids: Vec<_> = data.iter().filter_map(|item| item["id"].as_str()).collect();
    assert_eq!(ids, vec!["inst-household-alpha"]);
}

#[tokio::test]
async fn household_workspaces_list_requires_pop_authorization() {
    let fx = fixture();
    let resp = fx
        .app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/terminals/picoclaw-household-alpha/workspaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn household_workspaces_list_scopes_by_household_and_actor_namespace() {
    let fx = fixture();
    let other_hh = household_rs::derive_household_id(&P256Keypair::generate().public()).to_string();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;

    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    insert_instance(
        &fx.shared.instance_db,
        "inst-other-household",
        Some(&other_hh),
        Some(&fx.machine_id),
    );
    insert_instance(&fx.shared.instance_db, "inst-legacy", None, None);

    fx.shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();
    fx.shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", "other-actor", "Other Workspace")
        .unwrap();

    let (status, json) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/terminals/picoclaw-household-alpha/workspaces",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["container"], "picoclaw-household-alpha");
    assert_eq!(data[0]["display_name"], "Dev Workspace");

    let (status, _) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/terminals/picoclaw-other-household/workspaces",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/terminals/picoclaw-legacy/workspaces",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn household_workspaces_create_rename_and_delete_use_household_scope() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );

    let path = "/api/v1/household/terminals/picoclaw-household-alpha/workspaces";
    let (status, json) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::POST,
        path,
        serde_json::json!({"display_name": "Dev Workspace"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let workspace_id = json["workspace"]["id"]
        .as_str()
        .expect("workspace id")
        .to_string();
    assert_eq!(json["workspace"]["container"], "picoclaw-household-alpha");
    assert_eq!(json["workspace"]["display_name"], "Dev Workspace");

    let created = fx
        .shared
        .instance_db
        .list_conversations("picoclaw-household-alpha", &actor_username)
        .unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].id, workspace_id);

    let workspace_path =
        format!("/api/v1/household/terminals/picoclaw-household-alpha/workspaces/{workspace_id}");
    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::PATCH,
        &workspace_path,
        serde_json::json!({"display_name": "Renamed Workspace"}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let renamed = fx
        .shared
        .instance_db
        .get_conversation(&workspace_id)
        .unwrap()
        .expect("renamed workspace");
    assert_eq!(renamed.display_name, "Renamed Workspace");

    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::DELETE,
        &workspace_path,
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        fx.shared
            .instance_db
            .get_conversation(&workspace_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn household_attach_token_mint_requires_pop_authorization() {
    let fx = fixture();
    let status = request_json_without_auth(
        fx.app,
        Method::POST,
        "/api/v1/household/terminals/picoclaw-household-alpha/attach-token",
        serde_json::json!({"workspace_id": "ws-alpha"}),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn household_attach_token_mint_requires_loopback_or_tailnet_peer() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();

    for peer in [None, Some(remote_peer_addr())] {
        let (status, _) = request_json_with_peer(
            fx.app.clone(),
            &fx.person,
            Method::POST,
            "/api/v1/household/terminals/picoclaw-household-alpha/attach-token",
            serde_json::json!({"workspace_id": workspace.id}),
            peer,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "peer={peer:?}");
    }

    for peer in [tailnet_peer_addr(), tailnet_ipv6_peer_addr()] {
        let (status, json) = request_json_with_peer(
            fx.app.clone(),
            &fx.person,
            Method::POST,
            "/api/v1/household/terminals/picoclaw-household-alpha/attach-token",
            serde_json::json!({"workspace_id": workspace.id}),
            Some(peer),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "peer={peer:?}");
        assert!(
            json["token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
    }
}

#[tokio::test]
async fn household_attach_token_mint_rejects_unscoped_or_missing_targets() {
    let fx = fixture();
    let other_hh = household_rs::derive_household_id(&P256Keypair::generate().public()).to_string();

    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    insert_instance(
        &fx.shared.instance_db,
        "inst-other-household",
        Some(&other_hh),
        Some(&fx.machine_id),
    );
    insert_instance(&fx.shared.instance_db, "inst-legacy", None, None);
    insert_instance(
        &fx.shared.instance_db,
        "inst-deleted",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    fx.shared
        .instance_db
        .soft_delete("inst-deleted")
        .expect("soft delete");

    for container in [
        "picoclaw-missing",
        "picoclaw-other-household",
        "picoclaw-legacy",
        "picoclaw-deleted",
    ] {
        let path = format!("/api/v1/household/terminals/{container}/attach-token");
        let (status, _) = request_json(
            fx.app.clone(),
            &fx.person,
            Method::POST,
            &path,
            serde_json::json!({"workspace_id": "ws-alpha"}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{container}");
    }
}

#[tokio::test]
async fn household_attach_token_mint_rejects_workspace_outside_actor_namespace() {
    let fx = fixture();
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", "person-beta", "Other Workspace")
        .unwrap();

    let (status, _) = request_json(
        fx.app,
        &fx.person,
        Method::POST,
        "/api/v1/household/terminals/picoclaw-household-alpha/attach-token",
        serde_json::json!({"workspace_id": workspace.id}),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn household_attach_token_mint_returns_single_use_token_without_opening_pty() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();

    let (status, json) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::POST,
        "/api/v1/household/terminals/picoclaw-household-alpha/attach-token",
        serde_json::json!({"workspace_id": workspace.id}),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let token = json["token"].as_str().expect("token");
    assert!(!token.is_empty());
    assert!(json["expires_at"].as_u64().unwrap_or_default() > 0);
    assert!(
        fx.shared
            .pty_mgr
            .get("picoclaw-household-alpha", workspace.id.as_str())
            .is_none()
    );
}

#[tokio::test]
async fn household_terminal_pty_rejects_missing_bad_expired_or_reused_attach_tokens() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();
    let path = format!(
        "/api/v1/household/terminals/picoclaw-household-alpha/pty?session={}&cols=80&rows=24",
        workspace.id
    );

    let status = get_household_pty(fx.app.clone(), &path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let status = get_household_pty(fx.app.clone(), &path, Some("bad-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let expired = fx.attach_tokens.mint_with_ttl(
        attach_scope(
            &fx.household_id,
            "picoclaw-household-alpha",
            &workspace.id,
            &actor_username,
        ),
        std::time::Duration::from_secs(0),
    );
    let status = get_household_pty(fx.app.clone(), &path, Some(&expired.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let reused = fx.attach_tokens.mint_with_ttl(
        attach_scope(
            &fx.household_id,
            "picoclaw-household-alpha",
            &workspace.id,
            &actor_username,
        ),
        HOUSEHOLD_ATTACH_TOKEN_TTL,
    );
    assert!(fx.attach_tokens.consume(&reused.token).is_some());
    let status = get_household_pty(fx.app, &path, Some(&reused.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn household_terminal_pty_requires_loopback_or_tailnet_peer_without_consuming_token() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();
    let path = format!(
        "/api/v1/household/terminals/picoclaw-household-alpha/pty?session={}&cols=80&rows=24",
        workspace.id
    );

    let remote = fx.attach_tokens.mint(attach_scope(
        &fx.household_id,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let status = get_household_pty_with_peer(
        fx.app.clone(),
        &path,
        Some(&remote.token),
        Some(remote_peer_addr()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        fx.attach_tokens.consume(&remote.token).is_some(),
        "peer guard must run before token consume"
    );

    let missing = fx.attach_tokens.mint(attach_scope(
        &fx.household_id,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let status = get_household_pty_with_peer(fx.app, &path, Some(&missing.token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        fx.attach_tokens.consume(&missing.token).is_some(),
        "missing ConnectInfo must fail closed before token consume"
    );
}

#[tokio::test]
async fn household_terminal_pty_redeem_revalidates_current_household_and_scope() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    let other_hh = household_rs::derive_household_id(&P256Keypair::generate().public()).to_string();
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();
    let path = format!(
        "/api/v1/household/terminals/picoclaw-household-alpha/pty?session={}&cols=80&rows=24",
        workspace.id
    );

    let rehomed = fx.attach_tokens.mint(attach_scope(
        &other_hh,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let status = get_household_pty(fx.app.clone(), &path, Some(&rehomed.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let wrong_container = fx.attach_tokens.mint(attach_scope(
        &fx.household_id,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let wrong_container_path = format!(
        "/api/v1/household/terminals/picoclaw-household-beta/pty?session={}&cols=80&rows=24",
        workspace.id
    );
    let status = get_household_pty(
        fx.app.clone(),
        &wrong_container_path,
        Some(&wrong_container.token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let wrong_session = fx.attach_tokens.mint(attach_scope(
        &fx.household_id,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let status = get_household_pty(
        fx.app,
        "/api/v1/household/terminals/picoclaw-household-alpha/pty?session=ws-beta&cols=80&rows=24",
        Some(&wrong_session.token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn household_terminal_pty_valid_token_upgrades_to_websocket() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();
    let minted = fx.attach_tokens.mint(attach_scope(
        &fx.household_id,
        "picoclaw-household-alpha",
        &workspace.id,
        &actor_username,
    ));
    let path = format!(
        "/api/v1/household/terminals/picoclaw-household-alpha/pty?session={}&cols=80&rows=24",
        workspace.id
    );
    let server = TestServer::builder()
        .http_transport()
        .build(fx.app.layer(Extension(ConnectInfo(tailnet_peer_addr()))))
        .expect("test server");
    let response = server
        .get_websocket(&path)
        .add_header("X-Soyeht-Household-Attach-Token", &minted.token)
        .await;

    assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
    let websocket = response.into_websocket().await;
    websocket.close().await;
    assert_eq!(fx.attach_tokens.consume(&minted.token), None);
}

#[tokio::test]
async fn admin_terminal_pty_preserves_session_owner_check_after_helper_extraction() {
    let fx = fixture();
    let auth = AuthUser {
        user_id: "admin-alpha".to_string(),
        username: "admin-alpha".to_string(),
        role: store_rs::UserRole::Admin,
    };
    insert_instance(&fx.shared.instance_db, "inst-admin-alpha", None, None);
    let workspace = fx
        .shared
        .instance_db
        .create_conversation("picoclaw-admin-alpha", "person-beta", "Other Workspace")
        .unwrap();
    let app = Router::new()
        .route(
            "/api/v1/terminals/{container}/pty",
            get(handlers_terminal::handle_terminal_pty),
        )
        .layer(middleware::from_fn_with_state(auth, inject_auth))
        .with_state(fx.shared);
    let path = format!(
        "/api/v1/terminals/picoclaw-admin-alpha/pty?session={}&cols=80&rows=24",
        workspace.id
    );
    let server = TestServer::builder()
        .http_transport()
        .build(app)
        .expect("test server");
    let resp = server.get_websocket(&path).await;

    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn household_instances_list_requires_pop_authorization() {
    let fx = fixture();
    let resp = fx
        .app
        .oneshot(
            Request::builder()
                .uri("/api/v1/household/instances")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn household_instance_status_allows_legacy_and_matching_household_rows_only() {
    let fx = fixture();
    let other_hh = household_rs::derive_household_id(&P256Keypair::generate().public()).to_string();

    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        None,
    );
    insert_instance(&fx.shared.instance_db, "inst-legacy", None, None);
    insert_instance(
        &fx.shared.instance_db,
        "inst-other-household",
        Some(&other_hh),
        Some(&fx.machine_id),
    );
    insert_instance(
        &fx.shared.instance_db,
        "inst-deleted",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    fx.shared
        .instance_db
        .soft_delete("inst-deleted")
        .expect("soft delete");

    let (status, json) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/instances/inst-household-alpha/status",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "active");

    let (status, json) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/instances/inst-legacy/status",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "active");

    for id in ["inst-other-household", "inst-deleted", "inst-missing"] {
        let path = format!("/api/v1/household/instances/{id}/status");
        let (status, _) = get_json(fx.app.clone(), &fx.person, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id}");
    }
}

#[tokio::test]
async fn household_instance_actions_reject_legacy_unscoped_rows() {
    let fx = fixture();
    insert_instance(&fx.shared.instance_db, "inst-legacy", None, None);

    let cases = [
        (Method::POST, "/api/v1/household/instances/inst-legacy/stop"),
        (
            Method::POST,
            "/api/v1/household/instances/inst-legacy/restart",
        ),
        (
            Method::POST,
            "/api/v1/household/instances/inst-legacy/rebuild",
        ),
        (Method::DELETE, "/api/v1/household/instances/inst-legacy"),
    ];

    for (method, path) in cases {
        let (status, _) = request_json(
            fx.app.clone(),
            &fx.person,
            method,
            path,
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn household_instance_use_actions_mutate_scoped_rows() {
    let fx = fixture();
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );

    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::POST,
        "/api/v1/household/instances/inst-household-alpha/stop",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-household-alpha")
        .unwrap()
        .expect("stopped row");
    assert_eq!(row.status, InstanceStatus::Stopped);
    assert_eq!(row.desired_state.as_deref(), Some("stopped"));

    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::POST,
        "/api/v1/household/instances/inst-household-alpha/restart",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-household-alpha")
        .unwrap()
        .expect("restarted row");
    assert_eq!(row.status, InstanceStatus::Active);
    assert_eq!(row.desired_state.as_deref(), Some("running"));

    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::POST,
        "/api/v1/household/instances/inst-household-alpha/rebuild",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-household-alpha")
        .unwrap()
        .expect("rebuilt row");
    assert_eq!(row.status, InstanceStatus::Active);
}

#[tokio::test]
async fn household_instance_delete_soft_deletes_cleans_workspaces_and_hides_from_household() {
    let fx = fixture();
    let actor_username = household_rs::derive_person_id(&fx.person.public()).0;
    insert_instance(
        &fx.shared.instance_db,
        "inst-household-alpha",
        Some(&fx.household_id),
        Some(&fx.machine_id),
    );
    fx.shared
        .instance_db
        .create_conversation("picoclaw-household-alpha", &actor_username, "Dev Workspace")
        .unwrap();

    let (status, _) = request_json(
        fx.app.clone(),
        &fx.person,
        Method::DELETE,
        "/api/v1/household/instances/inst-household-alpha",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let row = fx
        .shared
        .instance_db
        .get("inst-household-alpha")
        .unwrap()
        .expect("soft-deleted row remains for audit");
    assert!(row.deleted_at.is_some());
    assert_eq!(row.desired_state.as_deref(), Some("deleted"));
    assert!(
        fx.shared
            .instance_db
            .list_conversations("picoclaw-household-alpha", &actor_username)
            .unwrap()
            .is_empty()
    );

    let (status, _) = get_json(
        fx.app.clone(),
        &fx.person,
        "/api/v1/household/instances/inst-household-alpha/status",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, json) = get_json(fx.app, &fx.person, "/api/v1/household/instances").await;
    assert_eq!(status, StatusCode::OK);
    let data = json["data"].as_array().expect("data array");
    assert!(data.is_empty());
}

#[tokio::test]
async fn admin_instance_actions_preserve_effects_after_refactor() {
    let fx = fixture();
    let auth = AuthUser {
        user_id: "admin-alpha".to_string(),
        username: "admin-alpha".to_string(),
        role: store_rs::UserRole::Admin,
    };
    insert_instance(&fx.shared.instance_db, "inst-admin-alpha", None, None);
    fx.shared
        .instance_db
        .create_conversation("picoclaw-admin-alpha", &auth.username, "Admin Workspace")
        .unwrap();

    let status = handlers_instances::handle_stop_instance(
        State(fx.shared.clone()),
        auth.clone(),
        Path("inst-admin-alpha".to_string()),
    )
    .await
    .expect("admin stop");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-admin-alpha")
        .unwrap()
        .expect("stopped admin row");
    assert_eq!(row.status, InstanceStatus::Stopped);
    assert_eq!(row.desired_state.as_deref(), Some("stopped"));

    let status = handlers_instances::handle_restart_instance(
        State(fx.shared.clone()),
        auth.clone(),
        Path("inst-admin-alpha".to_string()),
    )
    .await
    .expect("admin restart");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-admin-alpha")
        .unwrap()
        .expect("restarted admin row");
    assert_eq!(row.status, InstanceStatus::Active);
    assert_eq!(row.desired_state.as_deref(), Some("running"));

    let status = handlers_instances::handle_rebuild_instance(
        State(fx.shared.clone()),
        auth.clone(),
        Path("inst-admin-alpha".to_string()),
    )
    .await
    .expect("admin rebuild");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-admin-alpha")
        .unwrap()
        .expect("rebuilt admin row");
    assert_eq!(row.status, InstanceStatus::Active);

    let status = handlers_instances::handle_delete_instance(
        State(fx.shared.clone()),
        auth.clone(),
        Path("inst-admin-alpha".to_string()),
    )
    .await
    .expect("admin delete");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let row = fx
        .shared
        .instance_db
        .get("inst-admin-alpha")
        .unwrap()
        .expect("soft-deleted admin row");
    assert!(row.deleted_at.is_some());
    assert_eq!(row.desired_state.as_deref(), Some("deleted"));
    assert!(
        fx.shared
            .instance_db
            .list_conversations("picoclaw-admin-alpha", &auth.username)
            .unwrap()
            .is_empty()
    );
}
