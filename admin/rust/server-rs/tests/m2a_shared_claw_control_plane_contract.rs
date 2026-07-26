//! M2-A shared-Claw control-plane contract proof only; VPN demo remains 0/1.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::claw_share::ClawShareSlotStore;
use household_rs::household_mesh_log::{
    LogEntry, MeshEvent, MeshLogStore, MeshMembership, ProjectedState,
};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::member_identity::MemberDeviceBinding;
use household_rs::person_cert::{PersonCert, SignOwnerOptions};
use household_rs::pop::RequestSigningContext;
use household_rs::{BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, derive_person_id};
use serde::{Deserialize, Serialize};
use server_rs::claw_share_relay_offer_challenge::RelayOfferChallengeTable;
use server_rs::claw_share_relay_stream_abuse::RelayAbuseState;
use server_rs::handlers_claw_share::{self, ClawShareRouterState};
use server_rs::household_state::HouseholdState;
use tower::ServiceExt;

const INVITE_TO_CLAW_PATH: &str = "/api/v1/claw-share/invite-to-claw";
const GROUP_OP_PATH: &str = "/api/v1/claw-share/group-op";
const GROUP_ID: &str = "m2a_group";
const CLAW_A: &str = "m2a_claw_a";
const CLAW_B: &str = "m2a_claw_b";

struct Fixture {
    app: axum::Router,
    owner: P256Keypair,
    mesh_log: Arc<MeshLogStore>,
    _state_dir: tempfile::TempDir,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("current time is after Unix epoch")
        .as_secs()
}

fn fixture() -> Fixture {
    let state_dir = tempfile::tempdir().expect("temporary household state");
    let identity = Arc::new(
        household_rs::bootstrap_or_load(
            state_dir.path(),
            BootstrapOpts {
                household_name: "M2-A control-plane test".to_string(),
                hostname_label: Some("m2a-test-engine".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap household"),
    );
    let owner = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("single-machine test household holds hh_priv"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: owner.public(),
            display_name: "M2-A owner".to_string(),
            issued_at: identity.record.created_at,
        },
    )
    .expect("sign owner certificate");
    let household = HouseholdState::loaded_with_owner_auth(
        Arc::clone(&identity),
        Some(Arc::new(HouseholdAuthState::new(&identity.record, cert))),
    );
    let mesh_log = Arc::new(MeshLogStore::new());
    let app = handlers_claw_share::router(ClawShareRouterState {
        household,
        slot_store: Arc::new(ClawShareSlotStore::new()),
        mesh_log: Arc::clone(&mesh_log),
        engine_relay_npub: None,
        state_dir: state_dir.path().to_path_buf(),
        relay_offer_challenges: Arc::new(RelayOfferChallengeTable::new()),
        relay_offer_abuse: Arc::new(std::sync::Mutex::new(RelayAbuseState::default())),
    });
    Fixture {
        app,
        owner,
        mesh_log,
        _state_dir: state_dir,
    }
}

fn owner_pop(owner: &P256Keypair, path: &str, body: &[u8]) -> String {
    let timestamp = unix_now();
    let context = RequestSigningContext::new("POST", path, timestamp, body);
    let signature = owner
        .sign(
            &context
                .canonical_bytes()
                .expect("canonical owner PoP request"),
        )
        .expect("sign owner PoP");
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        derive_person_id(&owner.public()).0,
        timestamp,
        B64URL.encode(signature.as_bytes())
    )
}

async fn post_owner_cbor(
    app: &axum::Router,
    owner: &P256Keypair,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/cbor")
                .header(header::AUTHORIZATION, owner_pop(owner, path, &body))
                .body(Body::from(body))
                .expect("build owner request"),
        )
        .await
        .expect("router response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body")
        .to_vec();
    (status, headers, body)
}

#[derive(Serialize)]
struct InviteToClawRequest<'a> {
    #[serde(rename = "v")]
    version: u8,
    group_id: &'a str,
    group_name: &'a str,
    member_id: &'a str,
    label: &'a str,
    claw_id: &'a str,
}

#[derive(Serialize)]
struct GroupOpRequest<'a> {
    #[serde(rename = "v")]
    version: u8,
    op: GroupOp<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum GroupOp<'a> {
    AddMember {
        group_id: &'a str,
        member_id: &'a str,
        label: &'a str,
    },
    EnrollMemberDevice {
        binding: &'a MemberDeviceBinding,
    },
}

fn invite_body(member_id: &str, label: &str, claw_id: &str) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&InviteToClawRequest {
        version: 1,
        group_id: GROUP_ID,
        group_name: "M2-A shared group",
        member_id,
        label,
        claw_id,
    })
    .expect("canonical invite-to-claw request")
}

fn enroll_member_device_body(binding: &MemberDeviceBinding) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&GroupOpRequest {
        version: 1,
        op: GroupOp::EnrollMemberDevice { binding },
    })
    .expect("canonical group-op request")
}

fn add_member_body(member_id: &str, label: &str) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&GroupOpRequest {
        version: 1,
        op: GroupOp::AddMember {
            group_id: GROUP_ID,
            member_id,
            label,
        },
    })
    .expect("canonical add-member request")
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    #[serde(rename = "v")]
    version: u8,
    code: String,
    #[serde(default)]
    message: Option<String>,
}

struct MeshObservation {
    projection: ProjectedState,
    entries: Vec<LogEntry>,
    digest: [u8; 32],
    len: usize,
    group_revision: u64,
}

fn observe_mesh(mesh_log: &MeshLogStore) -> MeshObservation {
    let projection = mesh_log.project();
    let group_revision = projection
        .groups
        .get(GROUP_ID)
        .expect("M2-A group exists")
        .revision;
    MeshObservation {
        entries: mesh_log.snapshot(),
        digest: mesh_log.state_digest(),
        len: mesh_log.len(),
        projection,
        group_revision,
    }
}

fn assert_no_mesh_effect(mesh_log: &MeshLogStore, before: &MeshObservation) {
    let after = observe_mesh(mesh_log);
    assert_eq!(
        after.entries, before.entries,
        "failed request appended no log event"
    );
    assert_eq!(
        after.len, before.len,
        "failed request changed no log length"
    );
    assert_eq!(
        after.digest, before.digest,
        "failed request changed no log digest"
    );
    assert_eq!(
        after.projection, before.projection,
        "failed request changed no projection"
    );
    assert_eq!(
        after.group_revision, before.group_revision,
        "failed request changed no group revision"
    );
}

async fn assert_scope_conflict(
    app: &axum::Router,
    owner: &P256Keypair,
    mesh_log: &MeshLogStore,
    before: &MeshObservation,
    body: Vec<u8>,
) {
    let (status, headers, response) = post_owner_cbor(app, owner, INVITE_TO_CLAW_PATH, body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/cbor")
    );
    let error: ErrorEnvelope = household_rs::cbor::from_canonical_slice(&response)
        .expect("canonical CBOR conflict envelope");
    assert_eq!(error.version, 1);
    assert_eq!(error.code, "group_scopes_other_claws");
    assert!(
        error.message.is_some(),
        "conflict includes its typed context"
    );
    assert_no_mesh_effect(mesh_log, before);
}

#[tokio::test]
async fn m2a_owner_pop_invite_rejects_cross_claw_scope_without_effect() {
    let Fixture {
        app,
        owner,
        mesh_log,
        _state_dir,
    } = fixture();
    let timestamp = unix_now();
    let member_one = P256Keypair::from_secret_scalar(&[0x21u8; 32]).expect("member one key");
    let device_one = P256Keypair::from_secret_scalar(&[0x31u8; 32]).expect("device one key");
    let member_two = P256Keypair::from_secret_scalar(&[0x41u8; 32]).expect("member two key");
    let device_two = P256Keypair::from_secret_scalar(&[0x51u8; 32]).expect("device two key");
    let binding_one = MemberDeviceBinding::sign(
        &member_one,
        device_one.public(),
        "m2a_member_one_npub".to_string(),
        timestamp,
    )
    .expect("member one binding");
    let binding_two = MemberDeviceBinding::sign(
        &member_two,
        device_two.public(),
        "m2a_member_two_npub".to_string(),
        timestamp,
    )
    .expect("member two binding");
    binding_one.verify().expect("member one binding verifies");
    binding_two.verify().expect("member two binding verifies");

    // `invite-to-claw` deliberately appends GrantClaw for every request. Use it
    // once to create the group and its single Claw A grant, then add the second
    // member through the owner-authenticated primitive so the durable setup is
    // exactly one grant rather than a same-second deduplication accident.
    let (status, _, response) = post_owner_cbor(
        &app,
        &owner,
        INVITE_TO_CLAW_PATH,
        invite_body(&binding_one.member_id, "member one", CLAW_A),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "invite response: {response:?}"
    );

    let (status, _, response) = post_owner_cbor(
        &app,
        &owner,
        GROUP_OP_PATH,
        add_member_body(&binding_two.member_id, "member two"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "add-member response: {response:?}"
    );

    for binding in [&binding_one, &binding_two] {
        let (status, _, response) = post_owner_cbor(
            &app,
            &owner,
            GROUP_OP_PATH,
            enroll_member_device_body(binding),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "enrol response: {response:?}"
        );
    }

    let before = observe_mesh(&mesh_log);
    let group = before
        .projection
        .groups
        .get(GROUP_ID)
        .expect("group projected");
    assert_eq!(
        group.granted_claws.get(CLAW_A),
        Some(&MeshMembership::Active)
    );
    assert_eq!(group.granted_claws.get(CLAW_B), None);
    assert_eq!(
        before
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.event,
                    MeshEvent::GroupClawGranted { group_id, claw_id }
                        if group_id == GROUP_ID && claw_id == CLAW_A
                )
            })
            .count(),
        1,
        "the shared Claw A setup leaves one durable group grant, not merely one projected grant"
    );
    assert_eq!(
        group.members.get(&binding_one.member_id),
        Some(&MeshMembership::Active)
    );
    assert_eq!(
        group.members.get(&binding_two.member_id),
        Some(&MeshMembership::Active)
    );
    assert_eq!(
        before.projection.members_authorized_for_claw(CLAW_A).len(),
        2,
        "both member/device pairs are in the Claw A projection"
    );
    assert!(
        before
            .projection
            .members_authorized_for_claw(CLAW_B)
            .is_empty()
    );
    assert_eq!(
        before.projection.member_devices[&binding_one.member_id]
            .get(&binding_one.device_pub.as_bytes()[..]),
        Some(&household_rs::household_mesh_log::ProjectedMemberDevice {
            participant_npub: binding_one.participant_npub.clone(),
            status: MeshMembership::Active,
        })
    );
    assert_eq!(
        before.projection.member_devices[&binding_two.member_id]
            .get(&binding_two.device_pub.as_bytes()[..]),
        Some(&household_rs::household_mesh_log::ProjectedMemberDevice {
            participant_npub: binding_two.participant_npub.clone(),
            status: MeshMembership::Active,
        })
    );

    assert_scope_conflict(
        &app,
        &owner,
        &mesh_log,
        &before,
        invite_body(&binding_one.member_id, "member one", CLAW_B),
    )
    .await;
    assert_scope_conflict(
        &app,
        &owner,
        &mesh_log,
        &before,
        invite_body(&binding_two.member_id, "member two", CLAW_B),
    )
    .await;
}

#[test]
fn m2a_default_feature_iptunnel_resource_is_compiled_out_externally() {
    // This integration crate consumes server-rs as a normal default-feature
    // dependency, outside the library's `cfg(test)` build.
    let resource_compiled =
        server_rs::claw_share_relay_stream_offer_store::IP_TUNNEL_RESOURCE_COMPILED;
    assert!(
        !resource_compiled,
        "M2-A control-plane proof must keep the VPN demo at 0/1"
    );
}
