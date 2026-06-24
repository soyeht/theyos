use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use claw_rs::{ClawCatalogResponse, ClawStatus};
use core_rs::{
    availability::{
        ClawAvailability, Degradation, HostProjection, InstallProjection, InstallStatus,
        OverallState, UnavailReason,
    },
    env::set_test_env,
    error::ApiError,
    manifest::UnavailableReasonCode,
};
use executor_rs::{Executor, FlowConfig};
use household_rs::{
    BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert,
    keys::{IdentityKey, P256Keypair},
    person_cert::SignOwnerOptions,
    pop::RequestSigningContext,
};
use jobs_rs::Store as JobsStore;
use serde_json::{Value, json};
use server_rs::{
    auth::require_auth,
    claw_store_service, handlers_claws, handlers_household_claws,
    handlers_household_claws::HouseholdClawsState,
    handlers_instances, handlers_mobile, handlers_terminal,
    household_attach_token::HouseholdAttachTokenStore,
    household_state::HouseholdState,
    ratelimit::Limiter,
    responses::{ClawDetailResponse, ClawJobResponse, ClawListItemResponse, ListResponse},
    state::{AppState, SharedState},
};
use session_rs::SessionStore;
use store_rs::{InstanceDb, NewInstance, UserRole};
use terminal_rs::pty::PtyManager;
use tower::ServiceExt;
use vmrunner_rs::VmRunner;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn contract_fixtures() -> &'static serde_json::Map<String, Value> {
    static FIXTURES: std::sync::OnceLock<serde_json::Map<String, Value>> =
        std::sync::OnceLock::new();
    FIXTURES.get_or_init(|| {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../contracts/claw-store/v1/contract.json"
        ))
        .expect("claw-store v1 contract must parse");
        contract["fixtures"]
            .as_object()
            .expect("fixtures must be an object")
            .clone()
    })
}

fn fixture(id: &str) -> &'static Value {
    contract_fixtures()
        .get(id)
        .unwrap_or_else(|| panic!("missing fixture {id}"))
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

fn default_claw_store() -> claw_rs::ClawStore {
    let claw_dir = tempfile::TempDir::new().expect("claw tempdir");
    let claw_path = claw_dir.path().join("installed_claws.json");
    std::mem::forget(claw_dir);
    claw_rs::ClawStore::new(&claw_path).expect("claw store")
}

fn shared_state() -> SharedState {
    shared_state_with_claw_store(default_claw_store())
}

fn shared_state_with_claw_store(claw_store: claw_rs::ClawStore) -> SharedState {
    let _env_guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let sessions = SessionStore::open(":memory:").expect("session store");
    let jobs = JobsStore::new(":memory:").expect("jobs store");
    let instance_db = InstanceDb::open(":memory:").expect("instance db");
    let rate_limiter = Limiter::new(":memory:", 100).expect("rate limiter");

    let fake_bin = fake_ipc_bin();
    let vm_dir = tempfile::TempDir::new().expect("vm tempdir");
    let vm_path = vm_dir.path().to_path_buf();
    std::fs::write(vm_path.join("rootfs.ext4"), b"rootfs").expect("base rootfs");
    std::mem::forget(vm_dir);

    let flow_config = FlowConfig {
        vmrunner_bin: fake_bin.clone(),
        store_bin: fake_bin.clone(),
        terminal_bin: fake_bin.clone(),
        firecracker_state_dir: vm_path.to_string_lossy().into_owned(),
        firecracker_bin: vm_path.join("fake-fc").to_string_lossy().into_owned(),
        kernel_image: vm_path.join("vmlinux").to_string_lossy().into_owned(),
        base_rootfs: vm_path.join("rootfs.ext4").to_string_lossy().into_owned(),
        ssh_key: vm_path.join("ssh_key").to_string_lossy().into_owned(),
        ssh_pubkey: vm_path.join("ssh_key.pub").to_string_lossy().into_owned(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    };
    let executor = Executor::new(flow_config).expect("fake executor");

    let conv_dir = tempfile::TempDir::new().expect("conv tempdir");
    let conv_path = conv_dir.path().to_path_buf();
    std::mem::forget(conv_dir);
    let pty_mgr = Arc::new(PtyManager::new(&fake_bin, conv_path));

    let state_dir = vm_path.to_string_lossy().into_owned();
    let fc_bin = vm_path.join("fake-fc").to_string_lossy().into_owned();
    let kernel = vm_path.join("vmlinux").to_string_lossy().into_owned();
    let base_rootfs = vm_path.join("rootfs.ext4").to_string_lossy().into_owned();
    let ssh_key = vm_path.join("ssh_key").to_string_lossy().into_owned();
    let ssh_pubkey = vm_path.join("ssh_key.pub").to_string_lossy().into_owned();

    set_test_env("FIRECRACKER_STATE_DIR", &state_dir);
    set_test_env("FIRECRACKER_BIN", &fc_bin);
    set_test_env("FIRECRACKER_KERNEL_IMAGE", &kernel);
    set_test_env("FIRECRACKER_BASE_ROOTFS", &base_rootfs);
    set_test_env("FIRECRACKER_SSH_KEY", &ssh_key);
    set_test_env("FIRECRACKER_SSH_PUBKEY", &ssh_pubkey);
    let vm_runner = Arc::new(VmRunner::from_env().expect("vm runner"));

    let theyos_dir = tempfile::TempDir::new().expect("theyos dir");
    let theyos_path = theyos_dir.path().to_path_buf();
    std::mem::forget(theyos_dir);

    let locks_dir = tempfile::TempDir::new().expect("locks dir");
    let locks_path = locks_dir.path().to_path_buf();
    std::mem::forget(locks_dir);

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
        claw_store,
        theyos_dir: theyos_path,
        locks_dir: locks_path,
        capacity_lock: tokio::sync::Mutex::new(()),
        llm_proxy_client: server_rs::handlers_llm::ProxyClient::from_env(),
    })
}

fn admin_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/claws", get(handlers_claws::handle_list_claws))
        .route(
            "/api/v1/claws/{name}/availability",
            get(handlers_claws::handle_claw_availability),
        )
        .route(
            "/api/v1/claws/{name}/install",
            post(handlers_claws::handle_install_claw),
        )
        .route(
            "/api/v1/claws/{name}/uninstall",
            post(handlers_claws::handle_uninstall_claw),
        )
        .with_state(state)
}

fn admin_auth_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/claws", get(handlers_claws::handle_list_claws))
        .route(
            "/api/v1/instances",
            post(handlers_instances::handle_create_instance_body),
        )
        .route(
            "/api/v1/terminals/{container}/workspaces",
            get(handlers_terminal::handle_list_conversations)
                .post(handlers_terminal::handle_create_conversation),
        )
        .route(
            "/api/v1/terminals/{container}/workspaces/{id}",
            patch(handlers_terminal::handle_rename_conversation)
                .delete(handlers_terminal::handle_delete_conversation),
        )
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(state)
}

fn mobile_router(state: SharedState) -> Router {
    Router::new()
        .route(
            "/api/v1/mobile/claws",
            get(handlers_mobile::handle_mobile_claws),
        )
        .route(
            "/api/v1/mobile/claws/{name}/availability",
            get(handlers_mobile::handle_mobile_claw_availability),
        )
        .route(
            "/api/v1/mobile/claws/{name}/install",
            post(handlers_mobile::handle_mobile_install_claw),
        )
        .route(
            "/api/v1/mobile/claws/{name}/uninstall",
            post(handlers_mobile::handle_mobile_uninstall_claw),
        )
        .route(
            "/api/v1/mobile/instances",
            get(handlers_mobile::handle_mobile_instances)
                .post(handlers_mobile::handle_mobile_create_instance),
        )
        .route(
            "/api/v1/mobile/instances/{id}/status",
            get(handlers_mobile::handle_mobile_instance_status),
        )
        .with_state(state)
}

struct HouseholdFixture {
    app: Router,
    person: P256Keypair,
    shared: SharedState,
}

fn household_fixture() -> HouseholdFixture {
    let state_dir = tempfile::tempdir().expect("household state");
    let identity = household_rs::bootstrap_or_load(
        state_dir.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("mac-alpha".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap household");

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
    .expect("sign owner");
    let owner_auth = HouseholdAuthState::new(&identity.record, cert);
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::new(identity_for_state(&identity)),
        Some(Arc::new(owner_auth)),
    );
    let shared = shared_state();
    let claws_state = HouseholdClawsState {
        shared: Arc::clone(&shared),
        household,
        attach_tokens: Arc::new(HouseholdAttachTokenStore::new()),
    };

    let app = Router::new()
        .route(
            "/api/v1/household/claws",
            get(handlers_household_claws::handle_household_list_claws),
        )
        .route(
            "/api/v1/household/claws/{name}/availability",
            get(handlers_household_claws::handle_household_claw_availability),
        )
        .route(
            "/api/v1/household/claws/{name}/install",
            post(handlers_household_claws::handle_household_install_claw),
        )
        .route(
            "/api/v1/household/claws/{name}/uninstall",
            post(handlers_household_claws::handle_household_uninstall_claw),
        )
        .route(
            "/api/v1/household/instances",
            get(handlers_household_claws::handle_household_list_instances)
                .post(handlers_household_claws::handle_household_create_instance),
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
        .with_state(claws_state);

    HouseholdFixture {
        app,
        person,
        shared,
    }
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
                    .and_then(|key| key.as_software_secret())
                    .expect("software hh_priv in single-machine household"),
            )
            .expect("copy hh key"),
        )),
        m_priv: Box::new(
            P256Keypair::from_secret_scalar(identity.m_priv.as_software_secret().unwrap())
                .expect("copy machine key"),
        ),
        backing: identity.backing,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn loopback_peer_addr() -> SocketAddr {
    "127.0.0.1:8091".parse().expect("loopback peer")
}

fn pop_header(person: &P256Keypair, method: &Method, path: &str, body: &[u8]) -> String {
    let ts = unix_now();
    let ctx = RequestSigningContext::new(method.as_str(), path, ts, body);
    let sig = person
        .sign(&ctx.canonical_bytes().expect("canonical bytes"))
        .expect("sign request");
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        household_rs::derive_person_id(&person.public()).0,
        ts,
        B64URL.encode(sig.as_bytes())
    )
}

fn admin_mobile_token(state: &SharedState) -> String {
    mobile_token_for_role(state, "admin", UserRole::Admin)
}

fn mobile_token_for_role(state: &SharedState, username: &str, role: UserRole) -> String {
    state
        .instance_db
        .create_user(username, role, None)
        .expect("create mobile user");
    state
        .mobile_sessions
        .create_session(username)
        .expect("create mobile session")
        .0
}

fn insert_picoclaw_instance(state: &SharedState) {
    state
        .instance_db
        .insert(&NewInstance {
            id: "inst-contract",
            name: "Contract Instance",
            container: "contract-container",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .expect("insert picoclaw instance");
}

fn assert_fixture_body(status: StatusCode, body: &Value, expected: StatusCode, fixture_id: &str) {
    assert_eq!(status, expected);
    assert_eq!(body, fixture(fixture_id));
}

fn assert_list_envelope(body: &Value) {
    assert!(body["data"].is_array(), "list data must be an array");
    assert_eq!(body["has_more"], false);
    assert_eq!(body["next_cursor"], Value::Null);
}

fn claw_list_item<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["data"]
        .as_array()
        .expect("list data array")
        .iter()
        .find(|item| item["name"] == name)
        .unwrap_or_else(|| panic!("missing claw list item {name}"))
}

fn ready_picoclaw_availability(installed_at: &str) -> ClawAvailability {
    ClawAvailability {
        name: "picoclaw".to_string(),
        install: InstallProjection {
            status: InstallStatus::Succeeded,
            progress: None,
            installed_at: Some(installed_at.to_string()),
            error: None,
            job_id: None,
        },
        host: HostProjection {
            cold_path_ready: true,
            has_golden: false,
            has_base_rootfs: true,
            maintenance_blocked: false,
            maintenance_retry_after_secs: None,
        },
        overall: OverallState::Creatable,
        reasons: Vec::new(),
        degradations: Vec::new(),
    }
}

fn assert_picoclaw_ready_availability(item: &Value) -> &Value {
    let availability = item
        .get("availability")
        .unwrap_or_else(|| panic!("{} must include availability", item["name"]));
    assert_eq!(availability["name"], "picoclaw");
    assert_eq!(availability["install"]["status"], "succeeded");
    assert_eq!(availability["install"]["progress"], Value::Null);
    assert!(
        availability["install"]["installed_at"].as_str().is_some(),
        "ready availability must include installed_at"
    );
    assert_eq!(availability["install"]["error"], Value::Null);
    assert_eq!(availability["install"]["job_id"], Value::Null);
    assert_eq!(availability["host"]["cold_path_ready"], true);
    assert_eq!(availability["host"]["has_golden"], false);
    assert_eq!(availability["host"]["has_base_rootfs"], true);
    assert_eq!(availability["host"]["maintenance_blocked"], false);
    assert_eq!(
        availability["host"]["maintenance_retry_after_secs"],
        Value::Null
    );
    assert_eq!(availability["overall"]["state"], "creatable");
    assert_eq!(availability["reasons"], json!([]));
    assert_eq!(availability["degradations"], json!([]));
    availability
}

fn assert_queued_job_schema(status: StatusCode, body: &Value, fixture_id: &str) {
    assert_eq!(status, StatusCode::OK);
    let schema = fixture(fixture_id);
    assert_eq!(
        schema["schema"], "claw_job_response_pattern",
        "{fixture_id} must declare the queued response schema class"
    );
    assert_eq!(
        schema["job_id_pattern"], "^job_[0-9a-f]{16}$",
        "{fixture_id} must pin the current generated job id shape"
    );
    assert_eq!(body["message"], schema["message"]);

    let object = body
        .as_object()
        .expect("queued response body must be object");
    assert_eq!(object.len(), 2, "queued response must stay flat");
    let job_id = body["job_id"].as_str().expect("queued job_id string");
    assert_eq!(job_id.len(), "job_".len() + 16);
    assert!(job_id.starts_with("job_"));
    assert!(
        job_id["job_".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "queued job_id must stay lowercase hex after job_ prefix: {job_id}"
    );
}

async fn request(
    app: Router,
    method: Method,
    path: &str,
    body: Vec<u8>,
    auth: Option<String>,
) -> (StatusCode, Vec<u8>, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }

    let response = app
        .oneshot(builder.body(Body::from(body)).expect("request body"))
        .await
        .expect("route response");
    response_parts(response).await
}

async fn response_parts(response: Response) -> (StatusCode, Vec<u8>, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body")
        .to_vec();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("response JSON")
    };
    (status, bytes, json)
}

async fn household_request(
    app: Router,
    person: &P256Keypair,
    method: Method,
    path: &str,
) -> (StatusCode, Vec<u8>, Value) {
    let body = Vec::new();
    let response = app
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(path)
                .header(
                    header::AUTHORIZATION,
                    pop_header(person, &method, path, &body),
                )
                .body(Body::from(body))
                .expect("household request"),
        )
        .await
        .expect("household response");
    response_parts(response).await
}

#[test]
fn typed_response_serializers_match_claw_store_v1_fixtures() {
    let list_item = ClawListItemResponse {
        catalog: ClawCatalogResponse {
            name: "picoclaw".to_string(),
            description: "Tiny test claw".to_string(),
            language: "rust".to_string(),
            buildable: true,
            version: "1.0.0".to_string(),
            binary_size_mb: 10,
            min_ram_mb: 512,
            license: "MIT".to_string(),
            distribution: "prebuilt".to_string(),
            status: ClawStatus::Ready,
            installed_at: None,
            job_id: None,
            error: None,
            verify_status: None,
            verify_error: None,
            tier: "supported".to_string(),
            stars: 0,
            source: String::new(),
            last_updated: String::new(),
            reviewed_upstream_commit: String::new(),
            latest_upstream_commit: String::new(),
            install_plan_source: "builtin".to_string(),
            installable: true,
            unavailable_reason_code: None,
            unavailable_reason: None,
        },
        availability: Some(ready_picoclaw_availability("2026-06-20T00:00:00Z")),
    };
    let item_json = serde_json::to_value(&list_item).expect("serialize list item");
    assert_eq!(&item_json, fixture("list_item_ready"));

    let list_json =
        serde_json::to_value(ListResponse::all(vec![list_item])).expect("serialize list");
    assert_eq!(&list_json, fixture("list_envelope_ready"));

    let detail_json = serde_json::to_value(ClawDetailResponse {
        name: "picoclaw".to_string(),
        description: "Tiny test claw".to_string(),
        language: "rust".to_string(),
        buildable: true,
        status: "ready".to_string(),
        installed_at: Some("2026-06-20T00:00:00Z".to_string()),
        job_id: Some("job-alpha".to_string()),
        error: None,
    })
    .expect("serialize detail");
    assert_eq!(&detail_json, fixture("detail_ready"));

    let action_json = serde_json::to_value(ClawJobResponse {
        job_id: "job-alpha".to_string(),
        message: "install already in progress".to_string(),
    })
    .expect("serialize action");
    assert_eq!(&action_json, fixture("already_installing_job_body"));
}

#[test]
fn c4_1_instance_lifecycle_fixtures_pin_nested_and_flat_shapes() {
    let admin_create = fixture("admin_instance_create_accepted");
    assert_eq!(admin_create["instance"]["id"], "inst-alpha");
    assert_eq!(admin_create["instance"]["claw_type"], "picoclaw");
    assert_eq!(admin_create["instance"]["status"], "provisioning");
    assert_eq!(admin_create["job_id"], "job-alpha");
    assert!(
        admin_create["message"]
            .as_str()
            .is_some_and(|message| message.contains("/api/v1/jobs/job-alpha")),
        "admin create fixture must keep the nested job-polling message shape"
    );

    let flat_create = fixture("mobile_instance_create_accepted");
    assert_eq!(flat_create["id"], "inst-alpha");
    assert_eq!(flat_create["container"], "picoclaw-alpha");
    assert_eq!(flat_create["claw_type"], "picoclaw");
    assert_eq!(flat_create["status"], "provisioning");
    assert_eq!(flat_create["job_id"], "job-alpha");
    assert!(
        flat_create.get("instance").is_none(),
        "mobile/household create fixture must stay flat"
    );

    let admin_status = fixture("admin_instance_status_active");
    assert_eq!(admin_status["instance"]["id"], "inst-alpha");
    assert_eq!(admin_status["instance"]["status"], "active");
    assert_eq!(admin_status["instance"]["guest_os"], "linux");
    assert_eq!(admin_status["job"], Value::Null);

    let flat_status = fixture("mobile_household_instance_status_active");
    assert_eq!(flat_status["status"], "active");
    assert_eq!(flat_status["provisioning_message"], Value::Null);
    assert_eq!(flat_status["provisioning_error"], Value::Null);
    assert_eq!(flat_status["provisioning_phase"], Value::Null);
    assert!(
        flat_status.get("instance").is_none(),
        "mobile/household status fixture must stay flat"
    );

    assert_eq!(fixture("instance_not_found_error")["code"], "NOT_FOUND");
}

#[test]
fn c4_2a_workspace_fixtures_pin_json_shapes() {
    let list = fixture("workspace_list_empty");
    assert_eq!(list["data"], json!([]));
    assert_eq!(list["has_more"], false);
    assert_eq!(list["next_cursor"], Value::Null);

    let created = fixture("workspace_created");
    let workspace = &created["workspace"];
    assert_eq!(workspace["id"], "ws-alpha");
    assert_eq!(workspace["session_id"], "ws-alpha");
    assert_eq!(workspace["container"], "picoclaw-alpha");
    assert_eq!(workspace["display_name"], "Dev Workspace");
    assert_eq!(workspace["status"], "active");
    assert!(
        created.get("data").is_none(),
        "workspace create fixture must keep the nested workspace envelope"
    );
}

#[test]
fn c4_2b_1_attach_token_fixture_pins_json_shape() {
    let minted = fixture("household_attach_token_minted");
    assert_eq!(minted["token"], "attach-token-alpha");
    assert_eq!(minted["expires_at"], 1_810_000_000_u64);
    assert!(
        minted.get("workspace_id").is_none(),
        "attach-token mint fixture must not expose workspace scope internals"
    );
}

#[test]
fn c4_2b_2_websocket_routes_pin_upgrade_shape_without_success_bodies() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../contracts/claw-store/v1/contract.json"
    ))
    .expect("claw-store v1 contract must parse");
    let routes = contract["routes"]
        .as_array()
        .expect("routes must be an array");
    let route = |id: &str| {
        routes
            .iter()
            .find(|route| route["id"] == id)
            .unwrap_or_else(|| panic!("missing route {id}"))
    };

    let admin = route("admin_terminal_pty");
    assert_eq!(admin["kind"], "websocket_upgrade");
    assert_eq!(admin["auth_kind"], "admin_stream_auth");
    assert_eq!(admin["expectations"]["upgrade"]["status"], 101);
    assert_eq!(admin["expectations"]["upgrade"]["protocol"], "websocket");
    assert!(
        admin["expectations"].get("success").is_none(),
        "admin PTY websocket must not declare a JSON success body"
    );
    assert!(
        admin["expectations"]["upgrade"].get("fixture").is_none(),
        "admin PTY websocket upgrade must not point at a fixture"
    );

    let household = route("household_terminal_pty");
    assert_eq!(household["kind"], "websocket_upgrade");
    assert_eq!(household["auth_kind"], "household_attach_token");
    assert_eq!(
        household["attach_token_header"],
        "x-soyeht-household-attach-token"
    );
    assert_eq!(household["peer_guard"], true);
    assert_eq!(household["expectations"]["upgrade"]["status"], 101);
    assert_eq!(
        household["expectations"]["upgrade"]["protocol"],
        "websocket"
    );
    assert_eq!(household["expectations"]["peer_rejected"]["status"], 403);
    assert_eq!(household["expectations"]["auth_error"]["status"], 401);
    assert!(
        household["expectations"].get("success").is_none(),
        "household PTY websocket must not declare a JSON success body"
    );
    assert!(
        household["expectations"]["upgrade"]
            .get("fixture")
            .is_none(),
        "household PTY websocket upgrade must not point at a fixture"
    );
    assert!(
        household["expectations"]["auth_error"]
            .get("fixture")
            .is_none(),
        "household attach-token PTY auth failure is bodyless"
    );
}

#[test]
fn claw_list_item_omits_missing_availability_for_optional_dto_path() {
    let list_item = ClawListItemResponse {
        catalog: ClawCatalogResponse {
            name: "picoclaw".to_string(),
            description: "Tiny test claw".to_string(),
            language: "rust".to_string(),
            buildable: true,
            version: "1.0.0".to_string(),
            binary_size_mb: 10,
            min_ram_mb: 512,
            license: "MIT".to_string(),
            distribution: "prebuilt".to_string(),
            status: ClawStatus::Ready,
            installed_at: None,
            job_id: None,
            error: None,
            verify_status: None,
            verify_error: None,
            tier: "supported".to_string(),
            stars: 0,
            source: String::new(),
            last_updated: String::new(),
            reviewed_upstream_commit: String::new(),
            latest_upstream_commit: String::new(),
            install_plan_source: "builtin".to_string(),
            installable: true,
            unavailable_reason_code: None,
            unavailable_reason: None,
        },
        availability: None,
    };

    let value = serde_json::to_value(&list_item).expect("serialize list item");
    assert_eq!(value.get("availability"), None);
}

#[test]
fn unknown_availability_serializer_matches_claw_store_v1_fixture() {
    let availability = ClawAvailability {
        name: "unknown-claw".to_string(),
        install: InstallProjection::default_not_installed(),
        host: HostProjection {
            cold_path_ready: false,
            has_golden: false,
            has_base_rootfs: false,
            maintenance_blocked: false,
            maintenance_retry_after_secs: None,
        },
        overall: OverallState::Unknown,
        reasons: vec![UnavailReason::UnknownType],
        degradations: Vec::<Degradation>::new(),
    };

    let value = serde_json::to_value(availability).expect("serialize availability");
    assert_eq!(&value, fixture("unknown_availability"));
}

#[test]
fn catalog_only_list_item_serializer_matches_claw_store_v1_fixture() {
    // Drive the DTO from the REAL compiled manifest + catalog builder so the
    // golden locks the product's actual wire row for a catalog-only claw, not
    // hand-authored values. `claude-claw` is tier=catalog in claws/manifest.yml,
    // so `ManifestEntry::installability()` yields Unavailable { CatalogOnly, .. }
    // and `ClawStore::catalog_with_status_merged` emits installable=false plus the
    // manifest's `skip_install_reason`. A fresh (empty) ClawStore and no
    // verify-results path => status=NotInstalled with no install/verify history,
    // so every other field comes straight from the manifest entry.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store =
        claw_rs::ClawStore::new(&dir.path().join("installed_claws.json")).expect("claw store");
    let claude = store
        .catalog_with_status_merged(None)
        .into_iter()
        .find(|c| c.name == "claude-claw")
        .expect("claude-claw present in compiled manifest");

    // Focus of this slice: the catalog gate the UI keys off, derived by the
    // builder from `ManifestEntry::installability()`.
    assert!(
        !claude.installable,
        "claude-claw must be catalog-only (not installable)"
    );
    assert_eq!(
        claude.unavailable_reason_code,
        Some(UnavailableReasonCode::CatalogOnly)
    );
    assert!(
        claude.unavailable_reason.is_some(),
        "catalog-only row must carry a human-readable reason from skip_install_reason"
    );

    // Availability is the independent host/install projection. For a not-installed
    // claw the (overall, reasons) verdict is produced by the real `compute_overall`
    // fusion; the host projection is the one runtime-derived input, fixed here to a
    // normal host (shared base rootfs present, no per-claw golden).
    let install = InstallProjection::default_not_installed();
    let host = HostProjection {
        cold_path_ready: true,
        has_golden: false,
        has_base_rootfs: true,
        maintenance_blocked: false,
        maintenance_retry_after_secs: None,
    };
    let (overall, reasons) = core_rs::availability::compute_overall(&install, &host);
    let list_item = ClawListItemResponse {
        availability: Some(ClawAvailability {
            name: claude.name.clone(),
            install,
            host,
            overall,
            reasons,
            degradations: Vec::<Degradation>::new(),
        }),
        catalog: claude,
    };

    let value = serde_json::to_value(&list_item).expect("serialize catalog-only list item");
    assert_eq!(&value, fixture("list_item_catalog_only"));
}

#[tokio::test]
async fn api_error_bad_request_reasons_matches_claw_store_v1_fixture() {
    let response = ApiError::bad_request_with_reasons(
        "blocked",
        json!({ "unavailable_reason_code": "catalog_only" }),
    )
    .into_response();
    let (status, _bytes, body) = response_parts(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(&body, fixture("api_error_bad_request_reasons"));
}

#[tokio::test]
async fn auth_and_admin_required_errors_match_declared_claw_store_v1_fixtures() {
    let admin_state = shared_state();
    let (status, _bytes, body) = request(
        admin_auth_router(Arc::clone(&admin_state)),
        Method::GET,
        "/api/v1/claws",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::UNAUTHORIZED,
        "admin_auth_unauthorized",
    );

    let create_body = br#"{"name":"contract-instance","claw_type":"picoclaw"}"#.to_vec();
    let (status, _bytes, body) = request(
        admin_auth_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/instances",
        create_body.clone(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::UNAUTHORIZED,
        "admin_auth_unauthorized",
    );

    for (method, path) in [
        (Method::GET, "/api/v1/terminals/picoclaw-alpha/workspaces"),
        (Method::POST, "/api/v1/terminals/picoclaw-alpha/workspaces"),
        (
            Method::PATCH,
            "/api/v1/terminals/picoclaw-alpha/workspaces/ws-alpha",
        ),
        (
            Method::DELETE,
            "/api/v1/terminals/picoclaw-alpha/workspaces/ws-alpha",
        ),
    ] {
        let (status, _bytes, body) = request(
            admin_auth_router(Arc::clone(&admin_state)),
            method,
            path,
            Vec::new(),
            None,
        )
        .await;
        assert_fixture_body(
            status,
            &body,
            StatusCode::UNAUTHORIZED,
            "admin_auth_unauthorized",
        );
    }

    let mobile_state = shared_state();
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::UNAUTHORIZED,
        "mobile_missing_auth",
    );

    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/instances",
        create_body.clone(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::UNAUTHORIZED,
        "mobile_missing_auth",
    );

    let member_token = mobile_token_for_role(&mobile_state, "member", UserRole::User);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/install",
        Vec::new(),
        Some(format!("Bearer {member_token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::FORBIDDEN,
        "mobile_admin_required",
    );

    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/instances",
        create_body,
        Some(format!("Bearer {member_token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::FORBIDDEN,
        "mobile_admin_required",
    );
}

#[tokio::test]
async fn admin_and_mobile_lists_share_typed_shape_while_mobile_tier_filter_stays_active() {
    let state = shared_state();
    state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark picoclaw ready");
    let token = admin_mobile_token(&state);

    let (status, _bytes, admin_body) = request(
        admin_router(Arc::clone(&state)),
        Method::GET,
        "/api/v1/claws",
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_list_envelope(&admin_body);

    let (status, _bytes, mobile_body) = request(
        mobile_router(Arc::clone(&state)),
        Method::GET,
        "/api/v1/mobile/claws",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_list_envelope(&mobile_body);

    let admin_picoclaw = claw_list_item(&admin_body, "picoclaw");
    let mobile_picoclaw = claw_list_item(&mobile_body, "picoclaw");
    assert_eq!(mobile_picoclaw, admin_picoclaw);
    assert_eq!(mobile_picoclaw["tier"], "supported");
    assert_eq!(
        assert_picoclaw_ready_availability(mobile_picoclaw),
        assert_picoclaw_ready_availability(admin_picoclaw)
    );

    let (status, _bytes, supported_body) = request(
        mobile_router(Arc::clone(&state)),
        Method::GET,
        "/api/v1/mobile/claws?tier=supported",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_list_envelope(&supported_body);
    assert!(
        supported_body["data"]
            .as_array()
            .expect("supported data array")
            .iter()
            .all(|item| item["tier"] == "supported"),
        "mobile tier=supported must keep filtering active"
    );
    let _ = claw_list_item(&supported_body, "picoclaw");

    let (status, _bytes, catalog_body) = request(
        mobile_router(Arc::clone(&state)),
        Method::GET,
        "/api/v1/mobile/claws?tier=catalog",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_list_envelope(&catalog_body);
    assert!(
        catalog_body["data"]
            .as_array()
            .expect("catalog data array")
            .iter()
            .all(|item| item["tier"] == "catalog"),
        "mobile tier=catalog must keep filtering active"
    );
    let _ = claw_list_item(&catalog_body, "claude-claw");
}

#[tokio::test]
async fn household_list_matches_admin_availability_after_pop_authorization() {
    let household = household_fixture();
    household
        .shared
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark picoclaw ready");

    let (admin_status, _admin_bytes, admin_body) = request(
        admin_router(Arc::clone(&household.shared)),
        Method::GET,
        "/api/v1/claws",
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(admin_status, StatusCode::OK);
    assert_list_envelope(&admin_body);

    let (status, _bytes, household_body) = household_request(
        household.app.clone(),
        &household.person,
        Method::GET,
        "/api/v1/household/claws",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_list_envelope(&household_body);

    let admin_picoclaw = claw_list_item(&admin_body, "picoclaw");
    let household_picoclaw = claw_list_item(&household_body, "picoclaw");
    assert_eq!(household_picoclaw, admin_picoclaw);
    assert_eq!(
        assert_picoclaw_ready_availability(household_picoclaw),
        assert_picoclaw_ready_availability(admin_picoclaw)
    );
}

#[tokio::test]
async fn unknown_claw_action_errors_match_declared_claw_store_v1_fixture() {
    let admin_state = shared_state();
    let admin_app = admin_router(Arc::clone(&admin_state));
    for path in [
        "/api/v1/claws/unknown-claw/install",
        "/api/v1/claws/unknown-claw/uninstall",
    ] {
        let (status, _bytes, body) =
            request(admin_app.clone(), Method::POST, path, Vec::new(), None).await;
        assert_fixture_body(status, &body, StatusCode::NOT_FOUND, "unknown_claw_error");
    }

    let mobile_state = shared_state();
    let token = admin_mobile_token(&mobile_state);
    let mobile_app = mobile_router(Arc::clone(&mobile_state));
    for path in [
        "/api/v1/mobile/claws/unknown-claw/install",
        "/api/v1/mobile/claws/unknown-claw/uninstall",
    ] {
        let (status, _bytes, body) = request(
            mobile_app.clone(),
            Method::POST,
            path,
            Vec::new(),
            Some(format!("Bearer {token}")),
        )
        .await;
        assert_fixture_body(status, &body, StatusCode::NOT_FOUND, "unknown_claw_error");
    }

    let household = household_fixture();
    for path in [
        "/api/v1/household/claws/unknown-claw/install",
        "/api/v1/household/claws/unknown-claw/uninstall",
    ] {
        let (status, _bytes, body) =
            household_request(household.app.clone(), &household.person, Method::POST, path).await;
        assert_fixture_body(status, &body, StatusCode::NOT_FOUND, "unknown_claw_error");
    }
}

#[tokio::test]
async fn already_ready_install_errors_match_declared_claw_store_v1_fixture() {
    let admin_state = shared_state();
    admin_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark admin ready");
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "already_ready_error",
    );

    let mobile_state = shared_state();
    mobile_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark mobile ready");
    let token = admin_mobile_token(&mobile_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/install",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "already_ready_error",
    );

    let household = household_fixture();
    household
        .shared
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark household ready");
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/install",
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "already_ready_error",
    );
}

#[tokio::test]
async fn uninstall_not_ready_errors_match_declared_claw_store_v1_fixture() {
    let admin_state = shared_state();
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/uninstall",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "not_installed_error",
    );

    let mobile_state = shared_state();
    let token = admin_mobile_token(&mobile_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/uninstall",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "not_installed_error",
    );

    let household = household_fixture();
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/uninstall",
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "not_installed_error",
    );
}

#[tokio::test]
async fn uninstall_instances_exist_errors_match_declared_claw_store_v1_fixture() {
    let admin_state = shared_state();
    admin_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark admin ready");
    insert_picoclaw_instance(&admin_state);
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/uninstall",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "uninstall_instances_exist_error",
    );

    let mobile_state = shared_state();
    mobile_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark mobile ready");
    insert_picoclaw_instance(&mobile_state);
    let token = admin_mobile_token(&mobile_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/uninstall",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "uninstall_instances_exist_error",
    );

    let household = household_fixture();
    household
        .shared
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark household ready");
    insert_picoclaw_instance(&household.shared);
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/uninstall",
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "uninstall_instances_exist_error",
    );
}

#[tokio::test]
async fn queued_action_responses_match_declared_claw_store_v1_schemas() {
    let admin_install_state = shared_state();
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_install_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_queued_job_schema(status, &body, "install_queued_job_schema");

    let mobile_install_state = shared_state();
    let token = admin_mobile_token(&mobile_install_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_install_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/install",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_queued_job_schema(status, &body, "install_queued_job_schema");

    let household_install = household_fixture();
    let (status, _bytes, body) = household_request(
        household_install.app,
        &household_install.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/install",
    )
    .await;
    assert_queued_job_schema(status, &body, "install_queued_job_schema");

    let admin_uninstall_state = shared_state();
    admin_uninstall_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark admin ready");
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_uninstall_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/uninstall",
        Vec::new(),
        None,
    )
    .await;
    assert_queued_job_schema(status, &body, "uninstall_queued_job_schema");

    let mobile_uninstall_state = shared_state();
    mobile_uninstall_state
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark mobile ready");
    let token = admin_mobile_token(&mobile_uninstall_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_uninstall_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/uninstall",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_queued_job_schema(status, &body, "uninstall_queued_job_schema");

    let household_uninstall = household_fixture();
    household_uninstall
        .shared
        .claw_store
        .mark_ready("picoclaw")
        .expect("mark household ready");
    let (status, _bytes, body) = household_request(
        household_uninstall.app,
        &household_uninstall.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/uninstall",
    )
    .await;
    assert_queued_job_schema(status, &body, "uninstall_queued_job_schema");
}

#[tokio::test]
async fn already_installing_status_split_is_pinned() {
    let service_state = shared_state();
    service_state
        .claw_store
        .mark_installing("picoclaw", "job-alpha")
        .expect("mark service installing");
    let service_outcome = claw_store_service::install_claw(&service_state, "picoclaw".to_string())
        .await
        .expect("service already installing");
    assert!(
        service_outcome.is_already_installing(),
        "shared service must surface already-installing as an adapter-mapped outcome"
    );
    let service_body = serde_json::to_value(service_outcome.into_job_response())
        .expect("serialize service already-installing body");
    assert_eq!(&service_body, fixture("already_installing_job_body"));

    let admin_state = shared_state();
    admin_state
        .claw_store
        .mark_installing("picoclaw", "job-alpha")
        .expect("mark admin installing");
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/picoclaw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body, fixture("already_installing_job_body"));

    let mobile_state = shared_state();
    mobile_state
        .claw_store
        .mark_installing("picoclaw", "job-alpha")
        .expect("mark mobile installing");
    let token = admin_mobile_token(&mobile_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/picoclaw/install",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(&body, fixture("already_installing_job_body"));

    let household = household_fixture();
    household
        .shared
        .claw_store
        .mark_installing("picoclaw", "job-alpha")
        .expect("mark household installing");
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::POST,
        "/api/v1/household/claws/picoclaw/install",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body, fixture("already_installing_job_body"));
}

#[tokio::test]
async fn unknown_availability_is_200_unknown_on_all_claw_store_surfaces() {
    let admin_state = shared_state();
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::GET,
        "/api/v1/claws/unknown-claw/availability",
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["overall"]["state"], "unknown");
    assert_eq!(body["reasons"][0]["type"], "unknown_type");

    let mobile_state = shared_state();
    let (token, _) = mobile_state
        .mobile_sessions
        .create_session("admin")
        .expect("mobile session");
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::GET,
        "/api/v1/mobile/claws/unknown-claw/availability",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["overall"]["state"], "unknown");
    assert_eq!(body["reasons"][0]["type"], "unknown_type");

    let household = household_fixture();
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::GET,
        "/api/v1/household/claws/unknown-claw/availability",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["overall"]["state"], "unknown");
    assert_eq!(body["reasons"][0]["type"], "unknown_type");
}

#[tokio::test]
async fn install_unavailable_errors_match_declared_claw_store_v1_fixture() {
    let service_state = shared_state();
    let service_error = claw_store_service::install_claw(&service_state, "claude-claw".to_string())
        .await
        .expect_err("service install unavailable");
    let (status, _bytes, body) = response_parts(service_error.into_response()).await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "install_unavailable_reasons_object",
    );

    let admin_state = shared_state();
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/claude-claw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "install_unavailable_reasons_object",
    );

    let mobile_state = shared_state();
    let token = admin_mobile_token(&mobile_state);
    let (status, _bytes, body) = request(
        mobile_router(Arc::clone(&mobile_state)),
        Method::POST,
        "/api/v1/mobile/claws/claude-claw/install",
        Vec::new(),
        Some(format!("Bearer {token}")),
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "install_unavailable_reasons_object",
    );

    let household = household_fixture();
    let (status, _bytes, body) = household_request(
        household.app,
        &household.person,
        Method::POST,
        "/api/v1/household/claws/claude-claw/install",
    )
    .await;
    assert_fixture_body(
        status,
        &body,
        StatusCode::BAD_REQUEST,
        "install_unavailable_reasons_object",
    );
}

#[tokio::test]
async fn household_pop_auth_failure_is_empty_401() {
    let household = household_fixture();
    for (method, path) in [
        (Method::GET, "/api/v1/household/claws"),
        (Method::POST, "/api/v1/household/claws/picoclaw/install"),
        (Method::POST, "/api/v1/household/instances"),
        (Method::GET, "/api/v1/household/instances/inst-alpha/status"),
        (Method::POST, "/api/v1/household/instances/inst-alpha/stop"),
        (
            Method::POST,
            "/api/v1/household/instances/inst-alpha/restart",
        ),
        (
            Method::POST,
            "/api/v1/household/instances/inst-alpha/rebuild",
        ),
        (Method::DELETE, "/api/v1/household/instances/inst-alpha"),
        (
            Method::GET,
            "/api/v1/household/terminals/picoclaw-alpha/workspaces",
        ),
        (
            Method::POST,
            "/api/v1/household/terminals/picoclaw-alpha/workspaces",
        ),
        (
            Method::PATCH,
            "/api/v1/household/terminals/picoclaw-alpha/workspaces/ws-alpha",
        ),
        (
            Method::DELETE,
            "/api/v1/household/terminals/picoclaw-alpha/workspaces/ws-alpha",
        ),
    ] {
        let response = household
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let (status, bytes, body) = response_parts(response).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            bytes.is_empty(),
            "household auth failure body must stay empty"
        );
        assert_eq!(body, Value::Null);
    }

    let response = household
        .app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/household/claws")
                .header(header::AUTHORIZATION, "PoP bad")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let (status, bytes, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        bytes.is_empty(),
        "household auth failure body must stay empty"
    );
    assert_eq!(body, Value::Null);
}

#[tokio::test]
async fn household_attach_token_peer_rejection_is_bodyless_403() {
    let household = household_fixture();
    let method = Method::POST;
    let path = "/api/v1/household/terminals/picoclaw-alpha/attach-token";
    let body_bytes = br#"{"workspace_id":"ws-alpha"}"#.to_vec();
    let response = household
        .app
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    pop_header(&household.person, &method, path, &body_bytes),
                )
                .body(Body::from(body_bytes))
                .expect("request"),
        )
        .await
        .expect("response");
    let (status, bytes, body) = response_parts(response).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        bytes.is_empty(),
        "attach-token peer rejection body must stay empty"
    );
    assert_eq!(body, Value::Null);
}

#[tokio::test]
async fn household_attach_token_auth_failure_is_empty_401_when_peer_is_allowed() {
    let household = household_fixture();
    let path = "/api/v1/household/terminals/picoclaw-alpha/attach-token";
    let response = household
        .app
        .layer(Extension(ConnectInfo(loopback_peer_addr())))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(br#"{"workspace_id":"ws-alpha"}"#.to_vec()))
                .expect("request"),
        )
        .await
        .expect("response");
    let (status, bytes, body) = response_parts(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        bytes.is_empty(),
        "attach-token auth failure body must stay empty"
    );
    assert_eq!(body, Value::Null);
}

// ─── Job-leak rollback + ClawStore atomicity (install / uninstall) ─────────────

/// A `ClawStore` whose state-file parent *component* is a regular file, so every
/// `persist()` fails with `NotADirectory` (deterministic, root-safe — no seam).
fn bad_path_claw_store() -> claw_rs::ClawStore {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").expect("write blocker file");
    let state_file = blocker.join("installed_claws.json");
    std::mem::forget(dir);
    claw_rs::ClawStore::new(&state_file).expect("ClawStore::new is lazy")
}

/// `picoclaw` Ready (persisted to a valid path), after which a parent path
/// component is swapped from a directory to a file so the *next* `persist()` (the
/// `mark_uninstalling` transition) fails.
fn ready_store_then_break_parent() -> claw_rs::ClawStore {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sub = dir.path().join("run");
    std::fs::create_dir_all(&sub).expect("mkdir run");
    let state_file = sub.join("installed_claws.json");
    let store = claw_rs::ClawStore::new(&state_file).expect("ClawStore::new");
    store
        .mark_ready("picoclaw")
        .expect("mark_ready on a valid path");
    std::mem::forget(dir);
    std::fs::remove_dir_all(&sub).expect("rm run");
    std::fs::write(&sub, b"x").expect("replace run dir with a file");
    store
}

/// Install: when `mark_installing` fails after the job is created, the orphaned
/// job is rolled back AND the claw stays `NotInstalled` (atomic `set_state`).
#[tokio::test]
async fn install_claw_rolls_back_job_and_preserves_status_on_persist_failure() {
    let state = shared_state_with_claw_store(bad_path_claw_store());
    assert_eq!(
        state.claw_store.get_status("picoclaw"),
        ClawStatus::NotInstalled
    );

    let res = server_rs::claw_store_service::install_claw(&state, "picoclaw".to_string()).await;
    assert!(
        res.is_err(),
        "install_claw must fail when mark_installing's persist fails"
    );

    assert!(
        state.jobs.list_recent(0).expect("list_recent").is_empty(),
        "no orphaned job may remain (list_recent)"
    );
    assert!(
        state
            .jobs
            .list_by_instance("picoclaw", 0)
            .expect("list_by_instance")
            .is_empty(),
        "no orphaned job may remain (list_by_instance)"
    );
    assert_eq!(
        state.claw_store.get_status("picoclaw"),
        ClawStatus::NotInstalled,
        "claw status must be preserved (no drift to Installing)"
    );
}

/// Uninstall: when `mark_uninstalling` fails after the job is created, the
/// orphaned job is rolled back AND the claw stays `Ready` (atomic `set_state`).
#[tokio::test]
async fn uninstall_claw_rolls_back_job_and_preserves_status_on_persist_failure() {
    let state = shared_state_with_claw_store(ready_store_then_break_parent());
    assert_eq!(state.claw_store.get_status("picoclaw"), ClawStatus::Ready);

    let res = server_rs::claw_store_service::uninstall_claw(&state, "picoclaw".to_string()).await;
    assert!(
        res.is_err(),
        "uninstall_claw must fail when mark_uninstalling's persist fails"
    );

    assert!(
        state.jobs.list_recent(0).expect("list_recent").is_empty(),
        "no orphaned job may remain (list_recent)"
    );
    assert!(
        state
            .jobs
            .list_by_instance("picoclaw", 0)
            .expect("list_by_instance")
            .is_empty(),
        "no orphaned job may remain (list_by_instance)"
    );
    assert_eq!(
        state.claw_store.get_status("picoclaw"),
        ClawStatus::Ready,
        "claw status must be preserved (no drift to Uninstalling)"
    );
}
