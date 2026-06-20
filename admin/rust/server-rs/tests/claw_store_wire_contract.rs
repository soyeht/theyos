use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use claw_rs::{ClawCatalogResponse, ClawStatus};
use core_rs::{
    availability::{
        ClawAvailability, Degradation, HostProjection, InstallProjection, OverallState,
        UnavailReason,
    },
    env::set_test_env,
    error::ApiError,
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
    handlers_claws, handlers_household_claws,
    handlers_household_claws::HouseholdClawsState,
    handlers_mobile,
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

fn shared_state() -> SharedState {
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

    let claw_dir = tempfile::TempDir::new().expect("claw tempdir");
    let claw_path = claw_dir.path().join("installed_claws.json");
    std::mem::forget(claw_dir);

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
        claw_store: claw_rs::ClawStore::new(&claw_path).expect("claw store"),
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
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(state)
}

fn mobile_router(state: SharedState) -> Router {
    Router::new()
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
        availability: None,
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
    assert_eq!(&action_json, fixture("action_job_body"));
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
async fn already_installing_status_split_is_pinned() {
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
    assert_eq!(&body, fixture("action_job_body"));

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
    assert_eq!(&body, fixture("action_job_body"));

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
    assert_eq!(&body, fixture("action_job_body"));
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
async fn install_unavailable_reason_shape_is_object_not_availability_reason_list() {
    let admin_state = shared_state();
    let (status, _bytes, body) = request(
        admin_router(Arc::clone(&admin_state)),
        Method::POST,
        "/api/v1/claws/claude-claw/install",
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["code"],
        fixture("install_unavailable_reasons_object")["code"]
    );
    assert!(
        body["reasons"].is_object(),
        "admin reasons must stay object"
    );
    assert_eq!(
        body["reasons"]["unavailable_reason_code"],
        fixture("install_unavailable_reasons_object")["reasons"]["unavailable_reason_code"]
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
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["code"],
        fixture("install_unavailable_reasons_object")["code"]
    );
    assert!(
        body["reasons"].is_object(),
        "mobile reasons must stay object"
    );
    assert_eq!(
        body["reasons"]["unavailable_reason_code"],
        fixture("install_unavailable_reasons_object")["reasons"]["unavailable_reason_code"]
    );
}

#[tokio::test]
async fn household_pop_auth_failure_is_empty_401() {
    let household = household_fixture();
    let response = household
        .app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/household/claws/picoclaw/install")
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
