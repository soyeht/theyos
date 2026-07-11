//! Cross-language success-wire contract for the inert mobile Claw VPN
//! owner-present flow. All wrapper types in this file are test-only. Embedded
//! execution/context/approval values use the production household encoders.

use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    fs,
    path::Path,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::owner_approval_v2::{
    MobileClawVpnDevE2eExecutionTupleV1, OwnerApprovalContextV2, OwnerApprovalV2,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned, ser::SerializeMap as _};
use serde_bytes::ByteBuf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{RequestChallengeResponse, Url};
use webauthn_rs_core::{WebauthnCore, proto::AuthenticationState};

const SUCCESS_FIXTURE: &str =
    include_str!("../../../contracts/mobile-claw-vpn/v1/owner_present_success_wire_v1.json");
const EXECUTION_FIXTURE: &str =
    include_str!("../../../contracts/mobile-claw-vpn/v1/owner_approval_v2_execution_vectors.json");
const ASSERTION_FIELDS_FIXTURE: &str =
    include_str!("../../../contracts/owner-approval/v2/owner_approval_v2_assertion_fields_v1.json");
const WEBAUTHN_STATE_FIXTURE: &str =
    include_str!("data/mobile_claw_vpn_owner_present_webauthn_state_v1.json");
const API_SHAPES_FIXTURE: &str =
    include_str!("../../../contracts/mobile-claw-vpn/v1/api_shapes.json");

const EXECUTION_FIXTURE_SHA256: &str =
    "c47ebb5d9f9a1309e45647dedcdcb20fd7abd47a46e6f31f5541d8f2711c316c";
const ASSERTION_FIELDS_FIXTURE_SHA256: &str =
    "4d514d04377462b00d397ca64192ecd97681516b20d334b152296817acb3f1c9";
const WEBAUTHN_STATE_FIXTURE_SHA256: &str =
    "8224d194871c919c2876bceb3cc0aacc3d122891b924675c55e43ea269177fd9";
const API_SHAPES_FIXTURE_SHA256: &str =
    "7d31e66fd6172c9e7340455e73d0c2b06629b491442428a14c53edd45f49b7a6";
const SUCCESS_FIXTURE_SHA256: &str =
    "ff9ad533567e29261ecbd8e11e84e9490f1829bd4d2e5b50fe8783dc82b000d1";

const EXPECTED_RP_ID: &str = "owner.dev.example.test";
const EXPECTED_RP_ORIGIN: &str = "https://owner.dev.example.test/";
const OWNER_PRESENT_MODE: &str = "mesh_c_owner_present_offer_control";
const OWNER_PRESENT_OPERATION: &str = "owner_present_mint_offer";

#[derive(Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    scope: String,
    about: Vec<String>,
    dependencies: Vec<Dependency>,
    format: FormatContract,
    endpoint_profiles: BTreeMap<String, EndpointProfile>,
    server_selector_bindings: Vec<ServerSelectorBinding>,
    flows: Vec<FlowVector>,
    start_requests: Vec<StartRequestVector>,
    start_responses: Vec<StartResponseVector>,
    finish_requests: Vec<FinishRequestVector>,
    finish_responses: Vec<FinishResponseVector>,
    mint_requests: Vec<MintRequestVector>,
    mint_responses: Vec<MintResponseVector>,
    negative_contract: NegativeContract,
    runtime_requirements_not_implemented_by_c1: Vec<String>,
}

#[derive(Deserialize)]
struct ServerSelectorBinding {
    claw_alias: String,
    server_claw_id: String,
}

#[derive(Deserialize)]
struct FlowVector {
    id: String,
    start_request_id: String,
    start_response_id: String,
    finish_request_id: String,
    finish_response_id: String,
    mint_request_id: String,
    mint_response_id: String,
}

#[derive(Deserialize)]
struct Dependency {
    id: String,
    theyos_path: String,
    ios_path: String,
    sha256: String,
    used_for: Vec<String>,
}

#[derive(Deserialize)]
struct FormatContract {
    media_type: String,
    canonical_cbor: String,
    byte_fields: Vec<String>,
    challenge_id: String,
    proof_token: String,
    run_claims: String,
    owner_credential_allowlist: String,
    webauthn_binding: String,
    error_contract: String,
}

#[derive(Deserialize)]
struct EndpointProfile {
    method: String,
    path: String,
    auth: String,
    gate: String,
    request_content_type: String,
    response_content_type: String,
    success_status: u16,
    request_max_bytes: usize,
    response_max_bytes: usize,
}

#[derive(Deserialize)]
struct StartRequestVector {
    id: String,
    input: StartRequestInput,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct StartRequestInput {
    #[serde(rename = "v")]
    version: u8,
    claw_alias: String,
    run_claims: RunClaimsInput,
}

#[derive(Deserialize)]
struct RunClaimsInput {
    attempt_id: String,
    readiness_run_id: String,
    source_artifact_git_sha1_hex: String,
    execution_manifest_sha256_hex: String,
    device_binding_claim_sha256_hex: String,
    execution_run_id: String,
    execution_claim_sha256_hex: String,
}

#[derive(Deserialize)]
struct StartResponseVector {
    id: String,
    start_request_id: String,
    challenge_id: String,
    execution_template_fixture_id: String,
    context_template_fixture_id: String,
    expected_rp_id: String,
    options: Value,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct FinishRequestVector {
    id: String,
    start_response_id: String,
    assertion_fixture_id: String,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct FinishResponseVector {
    id: String,
    finish_request_id: String,
    proof_token_hex: String,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct MintRequestVector {
    id: String,
    finish_response_id: String,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct MintResponseVector {
    id: String,
    mint_request_id: String,
    status_fixture_path: String,
    offer_token: String,
    canonical_cbor_hex: String,
}

#[derive(Deserialize)]
struct NegativeContract {
    expected_rejection: String,
    forbidden_start_request_keys: Vec<String>,
    start_request_to_execution_fields: Vec<String>,
    strict_options_mutations: Vec<String>,
    raw_cbor_cases: Vec<RawNegativeCase>,
    semantic_cases: Vec<String>,
}

#[derive(Deserialize)]
struct RawNegativeCase {
    id: String,
    envelope: EnvelopeKind,
    expected_reason: String,
    raw_cbor_hex: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnvelopeKind {
    StartRequest,
    StartResponse,
    FinishRequest,
    FinishResponse,
    MintRequest,
    MintResponse,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequestWire {
    #[serde(rename = "v")]
    version: u8,
    claw_alias: String,
    run_claims: RunClaimsWire,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunClaimsWire {
    attempt_id: String,
    readiness_run_id: String,
    #[serde(with = "serde_bytes")]
    source_artifact_git_sha1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    execution_manifest_sha256: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_binding_claim_sha256: Vec<u8>,
    execution_run_id: String,
    #[serde(with = "serde_bytes")]
    execution_claim_sha256: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartResponseWire {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    execution: MobileClawVpnDevE2eExecutionTupleV1,
    context: OwnerApprovalContextV2,
    options: OwnerPresentOptionsWire,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPresentOptionsWire {
    #[serde(rename = "publicKey")]
    public_key: OwnerPresentPublicKeyOptionsWire,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPresentPublicKeyOptionsWire {
    challenge: String,
    timeout: u64,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<OwnerPresentCredentialDescriptorWire>,
    #[serde(rename = "userVerification")]
    user_verification: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPresentCredentialDescriptorWire {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequestWire {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishResponseWire {
    #[serde(rename = "v")]
    version: u8,
    proof_token: ByteBuf,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintRequestWire {
    #[serde(rename = "v")]
    version: u8,
    proof_token: ByteBuf,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintResponseWire {
    #[serde(rename = "v")]
    version: u8,
    product: String,
    mode: String,
    production_activation: bool,
    operation: String,
    owner_approval_consumed: bool,
    offer_token: String,
    status: StatusWire,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StatusWire {
    product: String,
    mode: String,
    production_activation: bool,
    state: String,
    snapshot_present: bool,
    enrolled_device_count: usize,
    available_claw_count: usize,
    grant_count: usize,
    offer_count: usize,
    session_count: usize,
}

struct InjectedStartRequest<'a> {
    start: &'a StartRequestWire,
    key: &'a str,
}

impl Serialize for InjectedStartRequest<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("v", &self.start.version)?;
        map.serialize_entry("claw_alias", &self.start.claw_alias)?;
        map.serialize_entry("run_claims", &self.start.run_claims)?;
        map.serialize_entry(self.key, "injected")?;
        map.end()
    }
}

fn fixture() -> Fixture {
    serde_json::from_str(SUCCESS_FIXTURE).expect("success wire fixture must parse")
}

fn dependency_value(bytes: &str) -> Value {
    serde_json::from_str(bytes).expect("dependency fixture must parse")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

fn unhex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex must decode")
}

fn execution_from_dependency(id: &str) -> MobileClawVpnDevE2eExecutionTupleV1 {
    let value = dependency_value(EXECUTION_FIXTURE);
    let vector = value["mobile_claw_vpn_dev_e2e_execution_tuple_v1"]
        .as_array()
        .expect("execution vectors")
        .iter()
        .find(|vector| vector["id"] == id)
        .expect("referenced execution vector");
    let bytes = unhex(
        vector["canonical_cbor_hex"]
            .as_str()
            .expect("execution canonical bytes"),
    );
    MobileClawVpnDevE2eExecutionTupleV1::from_canonical_bytes(&bytes)
        .expect("production execution decoder must accept dependency")
}

fn context_from_dependency(id: &str) -> OwnerApprovalContextV2 {
    let value = dependency_value(EXECUTION_FIXTURE);
    let vector = value["owner_approval_context_v2"]
        .as_array()
        .expect("context vectors")
        .iter()
        .find(|vector| vector["id"] == id)
        .expect("referenced context vector");
    let bytes = unhex(
        vector["canonical_cbor_hex"]
            .as_str()
            .expect("context canonical bytes"),
    );
    OwnerApprovalContextV2::from_canonical_bytes(&bytes)
        .expect("production context decoder must accept dependency")
}

fn approval_from_dependency(
    assertion_id: &str,
    context: OwnerApprovalContextV2,
) -> OwnerApprovalV2 {
    let value = dependency_value(ASSERTION_FIELDS_FIXTURE);
    let input = value["assertions"]
        .as_array()
        .expect("assertion fields")
        .iter()
        .find(|vector| vector["id"] == assertion_id)
        .expect("referenced assertion vector");
    OwnerApprovalV2 {
        version: 2,
        context,
        credential_id: ByteBuf::from(unhex(input["credential_id_hex"].as_str().unwrap())),
        authenticator_data: ByteBuf::from(unhex(input["authenticator_data_hex"].as_str().unwrap())),
        client_data_json: ByteBuf::from(unhex(input["client_data_json_hex"].as_str().unwrap())),
        signature: ByteBuf::from(unhex(input["signature_hex"].as_str().unwrap())),
        user_handle: input["user_handle_hex"]
            .as_str()
            .map(unhex)
            .map(ByteBuf::from),
    }
}

fn verification_state_from_dependency(id: &str) -> AuthenticationState {
    let value = dependency_value(WEBAUTHN_STATE_FIXTURE);
    let state = value["states"]
        .as_array()
        .expect("Rust-only WebAuthn states")
        .iter()
        .find(|vector| vector["assertion_id"] == id)
        .expect("referenced Rust-only verification state");
    serde_json::from_value(state["authentication_state"].clone())
        .expect("assertion verification state")
}

fn start_request_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a StartRequestVector {
    fixture
        .start_requests
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced start request")
}

fn start_response_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a StartResponseVector {
    fixture
        .start_responses
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced start response")
}

fn finish_request_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a FinishRequestVector {
    fixture
        .finish_requests
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced finish request")
}

fn finish_response_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a FinishResponseVector {
    fixture
        .finish_responses
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced finish response")
}

fn mint_request_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a MintRequestVector {
    fixture
        .mint_requests
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced mint request")
}

fn mint_response_vector<'a>(fixture: &'a Fixture, id: &str) -> &'a MintResponseVector {
    fixture
        .mint_responses
        .iter()
        .find(|vector| vector.id == id)
        .expect("referenced mint response")
}

fn status_from_dependency(path: &str) -> StatusWire {
    assert_eq!(path, "responses.mint_offer.status");
    let value = dependency_value(API_SHAPES_FIXTURE);
    serde_json::from_value(value["responses"]["mint_offer"]["status"].clone())
        .expect("configured status fixture must match count-only status")
}

fn start_request(vector: &StartRequestVector) -> StartRequestWire {
    StartRequestWire {
        version: vector.input.version,
        claw_alias: vector.input.claw_alias.clone(),
        run_claims: RunClaimsWire {
            attempt_id: vector.input.run_claims.attempt_id.clone(),
            readiness_run_id: vector.input.run_claims.readiness_run_id.clone(),
            source_artifact_git_sha1: unhex(&vector.input.run_claims.source_artifact_git_sha1_hex),
            execution_manifest_sha256: unhex(
                &vector.input.run_claims.execution_manifest_sha256_hex,
            ),
            device_binding_claim_sha256: unhex(
                &vector.input.run_claims.device_binding_claim_sha256_hex,
            ),
            execution_run_id: vector.input.run_claims.execution_run_id.clone(),
            execution_claim_sha256: unhex(&vector.input.run_claims.execution_claim_sha256_hex),
        },
    }
}

fn project_owner_present_options(value: &Value) -> Result<OwnerPresentOptionsWire, &'static str> {
    let production: RequestChallengeResponse =
        serde_json::from_value(value.clone()).map_err(|_| "production_options_decode")?;
    let projected = serde_json::to_value(production).map_err(|_| "production_options_encode")?;
    strict_options_from_json(&projected)
}

fn strict_options_from_json(value: &Value) -> Result<OwnerPresentOptionsWire, &'static str> {
    let top = value.as_object().ok_or("options_map")?;
    if top.keys().map(String::as_str).collect::<HashSet<_>>() != HashSet::from(["publicKey"]) {
        return Err("options_keys");
    }
    let public_key = top["publicKey"].as_object().ok_or("public_key_map")?;
    let expected = HashSet::from([
        "challenge",
        "timeout",
        "rpId",
        "allowCredentials",
        "userVerification",
    ]);
    if public_key
        .keys()
        .map(String::as_str)
        .collect::<HashSet<_>>()
        != expected
    {
        return Err("public_key_keys");
    }
    let challenge = public_key["challenge"]
        .as_str()
        .ok_or("challenge_type")?
        .to_string();
    let timeout = public_key["timeout"].as_u64().ok_or("timeout_type")?;
    let rp_id = public_key["rpId"].as_str().ok_or("rp_id_type")?.to_string();
    let user_verification = public_key["userVerification"]
        .as_str()
        .ok_or("user_verification_type")?
        .to_string();
    let descriptors = public_key["allowCredentials"]
        .as_array()
        .ok_or("allow_credentials_type")?;
    let mut allow_credentials = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let descriptor = descriptor.as_object().ok_or("descriptor_map")?;
        if descriptor
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>()
            != HashSet::from(["type", "id"])
        {
            return Err("descriptor_keys");
        }
        allow_credentials.push(OwnerPresentCredentialDescriptorWire {
            kind: descriptor["type"]
                .as_str()
                .ok_or("descriptor_type")?
                .to_string(),
            id: descriptor["id"]
                .as_str()
                .ok_or("descriptor_id")?
                .to_string(),
        });
    }
    let options = OwnerPresentOptionsWire {
        public_key: OwnerPresentPublicKeyOptionsWire {
            challenge,
            timeout,
            rp_id,
            allow_credentials,
            user_verification,
        },
    };
    validate_options(&options, EXPECTED_RP_ID)?;
    Ok(options)
}

fn start_response(fixture: &Fixture, vector: &StartResponseVector) -> StartResponseWire {
    assert_eq!(vector.expected_rp_id, EXPECTED_RP_ID);
    let request = start_request(start_request_vector(fixture, &vector.start_request_id));
    let mut execution = execution_from_dependency(&vector.execution_template_fixture_id);
    let selector = fixture
        .server_selector_bindings
        .iter()
        .find(|binding| binding.claw_alias == request.claw_alias)
        .expect("server-owned selector binding");
    execution.claw_alias.clone_from(&request.claw_alias);
    execution.claw_id.clone_from(&selector.server_claw_id);
    execution
        .attempt_id
        .clone_from(&request.run_claims.attempt_id);
    execution
        .readiness_run_id
        .clone_from(&request.run_claims.readiness_run_id);
    execution.source_artifact_git_sha1 =
        ByteBuf::from(request.run_claims.source_artifact_git_sha1.clone());
    execution.execution_manifest_sha256 =
        ByteBuf::from(request.run_claims.execution_manifest_sha256.clone());
    execution.device_binding =
        ByteBuf::from(request.run_claims.device_binding_claim_sha256.clone());
    execution
        .execution_run_id
        .clone_from(&request.run_claims.execution_run_id);
    execution.execution_claim_sha256 =
        ByteBuf::from(request.run_claims.execution_claim_sha256.clone());
    let mut context = context_from_dependency(&vector.context_template_fixture_id);
    context.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(
        execution
            .execution_hash()
            .expect("derived execution must hash")
            .to_vec(),
    ));
    StartResponseWire {
        version: 1,
        challenge_id: vector.challenge_id.clone(),
        execution,
        context,
        options: project_owner_present_options(&vector.options)
            .expect("production options must project into strict owner-present profile"),
    }
}

fn verify_owner_present_assertion(
    start: &StartResponseWire,
    finish: &FinishRequestWire,
    assertion_id: &str,
) -> Result<(), &'static str> {
    if finish.challenge_id != start.challenge_id
        || household_rs::cbor::to_canonical_vec(&finish.approval.context).map_err(|_| "context")?
            != household_rs::cbor::to_canonical_vec(&start.context).map_err(|_| "context")?
    {
        return Err("finish_binding");
    }
    let allowed_ids = start
        .options
        .public_key
        .allow_credentials
        .iter()
        .map(|descriptor| {
            B64URL
                .decode(descriptor.id.as_bytes())
                .map_err(|_| "credential_allowlist")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if allowed_ids.len() != 1 || allowed_ids[0] != finish.approval.credential_id.as_ref() {
        return Err("credential_allowlist");
    }

    let client_data: Value = serde_json::from_slice(finish.approval.client_data_json.as_ref())
        .map_err(|_| "client_data")?;
    if client_data["type"] != "webauthn.get"
        || client_data["challenge"] != start.options.public_key.challenge
        || client_data["origin"] != EXPECTED_RP_ORIGIN
    {
        return Err("client_data_binding");
    }

    let assertion = finish
        .approval
        .to_public_key_credential()
        .map_err(|_| "public_key_credential")?;
    let state = verification_state_from_dependency(assertion_id);
    let core = WebauthnCore::new_unsafe_experts_only(
        "Owner DEV",
        EXPECTED_RP_ID,
        vec![Url::parse(EXPECTED_RP_ORIGIN).map_err(|_| "rp_origin")?],
        Duration::from_secs(60),
        Some(false),
        Some(false),
    );
    core.authenticate_credential(&assertion, &state)
        .map_err(|_| "webauthn_assertion")?;
    Ok(())
}

fn finish_request(fixture: &Fixture, vector: &FinishRequestVector) -> FinishRequestWire {
    let start = start_response(
        fixture,
        start_response_vector(fixture, &vector.start_response_id),
    );
    FinishRequestWire {
        version: 1,
        challenge_id: start.challenge_id,
        approval: approval_from_dependency(&vector.assertion_fixture_id, start.context),
    }
}

fn finish_response(vector: &FinishResponseVector) -> FinishResponseWire {
    FinishResponseWire {
        version: 1,
        proof_token: ByteBuf::from(unhex(&vector.proof_token_hex)),
    }
}

fn mint_request(fixture: &Fixture, vector: &MintRequestVector) -> MintRequestWire {
    let finish = finish_response(finish_response_vector(fixture, &vector.finish_response_id));
    MintRequestWire {
        version: 1,
        proof_token: finish.proof_token,
    }
}

fn mint_response(vector: &MintResponseVector) -> MintResponseWire {
    MintResponseWire {
        version: 1,
        product: "product_a_mobile_claw_vpn".to_string(),
        mode: OWNER_PRESENT_MODE.to_string(),
        production_activation: false,
        operation: OWNER_PRESENT_OPERATION.to_string(),
        owner_approval_consumed: true,
        offer_token: vector.offer_token.clone(),
        status: status_from_dependency(&vector.status_fixture_path),
    }
}

fn strict_decode<T>(bytes: &[u8]) -> Result<T, &'static str>
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T = household_rs::cbor::from_canonical_slice(bytes).map_err(|_| "decode")?;
    let canonical = household_rs::cbor::to_canonical_vec(&decoded).map_err(|_| "encode")?;
    if canonical != bytes {
        return Err("non_canonical");
    }
    Ok(decoded)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn validate_start_request(request: &StartRequestWire) -> Result<(), &'static str> {
    if request.version != 1 || !matches!(request.claw_alias.as_str(), "Claw-M" | "Claw-L") {
        return Err("start_discriminator");
    }
    let claims = &request.run_claims;
    if !is_canonical_uuid(&claims.attempt_id)
        || !is_canonical_uuid(&claims.readiness_run_id)
        || !is_canonical_uuid(&claims.execution_run_id)
        || claims.source_artifact_git_sha1.len() != 20
        || claims.execution_manifest_sha256.len() != 32
        || claims.device_binding_claim_sha256.len() != 32
        || claims.execution_claim_sha256.len() != 32
    {
        return Err("run_claim_shape");
    }
    Ok(())
}

fn validate_options(
    options: &OwnerPresentOptionsWire,
    expected_rp_id: &str,
) -> Result<(), &'static str> {
    let public_key = &options.public_key;
    if public_key.rp_id != expected_rp_id
        || public_key.user_verification != "required"
        || public_key.timeout == 0
        || public_key.allow_credentials.is_empty()
    {
        return Err("options_policy");
    }
    let challenge = B64URL
        .decode(public_key.challenge.as_bytes())
        .map_err(|_| "challenge_base64url")?;
    if challenge.len() != 32 || B64URL.encode(&challenge) != public_key.challenge {
        return Err("challenge_shape");
    }
    let mut credential_ids = HashSet::new();
    for descriptor in &public_key.allow_credentials {
        if descriptor.kind != "public-key" {
            return Err("credential_type");
        }
        let id = B64URL
            .decode(descriptor.id.as_bytes())
            .map_err(|_| "credential_base64url")?;
        if id.is_empty() || id.len() > 1_024 || B64URL.encode(&id) != descriptor.id {
            return Err("credential_shape");
        }
        if !credential_ids.insert(id) {
            return Err("credential_duplicate");
        }
    }
    Ok(())
}

fn validate_start_response(response: &StartResponseWire) -> Result<(), &'static str> {
    if response.version != 1 || !is_lower_hex(&response.challenge_id, 32) {
        return Err("start_response_discriminator");
    }
    response
        .execution
        .validate_shape()
        .map_err(|_| "execution")?;
    response.context.validate_shape().map_err(|_| "context")?;
    let execution_hash = response
        .execution
        .execution_hash()
        .map_err(|_| "execution_hash")?;
    if response
        .context
        .mobile_claw_vpn_execution_hash
        .as_ref()
        .map(|digest| digest.as_slice())
        != Some(execution_hash.as_slice())
        || response.context.hh_id != response.execution.hh_id
        || response.context.issued_at != response.execution.issued_at
        || response.context.expires_at != response.execution.expires_at
    {
        return Err("execution_context_binding");
    }
    validate_options(&response.options, EXPECTED_RP_ID)?;
    let context_digest = response
        .context
        .challenge_digest()
        .map_err(|_| "context_digest")?;
    let challenge = B64URL
        .decode(response.options.public_key.challenge.as_bytes())
        .map_err(|_| "challenge_base64url")?;
    if challenge == context_digest {
        return Err("context_digest_is_not_rp_challenge");
    }
    Ok(())
}

fn request_matches_execution(
    request: &StartRequestWire,
    execution: &MobileClawVpnDevE2eExecutionTupleV1,
) -> bool {
    let claims = &request.run_claims;
    request.claw_alias == execution.claw_alias
        && claims.attempt_id == execution.attempt_id
        && claims.readiness_run_id == execution.readiness_run_id
        && claims.source_artifact_git_sha1 == execution.source_artifact_git_sha1.as_ref()
        && claims.execution_manifest_sha256 == execution.execution_manifest_sha256.as_ref()
        && claims.device_binding_claim_sha256 == execution.device_binding.as_ref()
        && claims.execution_run_id == execution.execution_run_id
        && claims.execution_claim_sha256 == execution.execution_claim_sha256.as_ref()
}

fn selector_matches_server_binding(
    fixture: &Fixture,
    execution: &MobileClawVpnDevE2eExecutionTupleV1,
) -> bool {
    fixture.server_selector_bindings.iter().any(|binding| {
        binding.claw_alias == execution.claw_alias && binding.server_claw_id == execution.claw_id
    })
}

fn validate_finish_request(request: &FinishRequestWire) -> Result<(), &'static str> {
    if request.version != 1 || !is_lower_hex(&request.challenge_id, 32) {
        return Err("finish_discriminator");
    }
    request.approval.validate_shape().map_err(|_| "approval")
}

fn validate_finish_response(response: &FinishResponseWire) -> Result<(), &'static str> {
    if response.version == 1 && response.proof_token.len() == 32 {
        Ok(())
    } else {
        Err("finish_response_shape")
    }
}

fn validate_mint_request(request: &MintRequestWire) -> Result<(), &'static str> {
    if request.version == 1 && request.proof_token.len() == 32 {
        Ok(())
    } else {
        Err("mint_request_shape")
    }
}

fn validate_mint_response(response: &MintResponseWire) -> Result<(), &'static str> {
    if response.version != 1
        || response.product != "product_a_mobile_claw_vpn"
        || response.mode != OWNER_PRESENT_MODE
        || response.production_activation
        || response.operation != OWNER_PRESENT_OPERATION
        || !response.owner_approval_consumed
        || !is_lower_hex(&response.offer_token, 32)
        || response.status.product != "product_a_mobile_claw_vpn"
        || response.status.mode != "mesh_c_status_only"
        || response.status.production_activation
        || response.status.state != "configured"
        || !response.status.snapshot_present
    {
        return Err("mint_response_shape");
    }
    Ok(())
}

fn assert_or_print_golden(id: &str, expected: &str, bytes: &[u8]) {
    if std::env::var_os("PRINT_OWNER_PRESENT_GOLDENS").is_some() {
        println!("GOLDEN {id} {}", hex_bytes(bytes));
        return;
    }
    assert!(!expected.is_empty(), "{id}: missing canonical_cbor_hex");
    assert_eq!(hex_bytes(bytes), expected, "{id}: canonical bytes drifted");
}

fn append_canonical<T: Serialize>(output: &mut Vec<u8>, value: &T) {
    output.extend(household_rs::cbor::to_canonical_vec(value).expect("canonical CBOR fragment"));
}

fn raw_start_response_options(response: &StartResponseWire, mutation: &'static str) -> Vec<u8> {
    let public_key = &response.options.public_key;
    let mut output = vec![0xa5];
    append_canonical(&mut output, &"v");
    append_canonical(&mut output, &response.version);
    append_canonical(&mut output, &"context");
    append_canonical(&mut output, &response.context);
    append_canonical(&mut output, &"options");
    output.push(0xa1);
    append_canonical(&mut output, &"publicKey");

    output.push(match mutation {
        "duplicate_rp_id" | "unknown_key" => 0xa6,
        "noncanonical_order" | "null_allow_credentials" => 0xa5,
        _ => unreachable!(),
    });
    if mutation == "unknown_key" {
        append_canonical(&mut output, &"x");
        append_canonical(&mut output, &true);
    }
    if mutation == "noncanonical_order" {
        append_canonical(&mut output, &"challenge");
        append_canonical(&mut output, &public_key.challenge);
    }
    append_canonical(&mut output, &"rpId");
    append_canonical(&mut output, &public_key.rp_id);
    if mutation == "duplicate_rp_id" {
        append_canonical(&mut output, &"rpId");
        append_canonical(&mut output, &public_key.rp_id);
    }
    append_canonical(&mut output, &"timeout");
    append_canonical(&mut output, &public_key.timeout);
    if mutation != "noncanonical_order" {
        append_canonical(&mut output, &"challenge");
        append_canonical(&mut output, &public_key.challenge);
    }
    append_canonical(&mut output, &"allowCredentials");
    if mutation == "null_allow_credentials" {
        output.push(0xf6);
    } else {
        append_canonical(&mut output, &public_key.allow_credentials);
    }
    append_canonical(&mut output, &"userVerification");
    append_canonical(&mut output, &public_key.user_verification);

    append_canonical(&mut output, &"execution");
    append_canonical(&mut output, &response.execution);
    append_canonical(&mut output, &"challenge_id");
    append_canonical(&mut output, &response.challenge_id);
    output
}

fn append_mint_response_fields(output: &mut Vec<u8>, response: &MintResponseWire) {
    append_canonical(output, &"mode");
    append_canonical(output, &response.mode);
    append_canonical(output, &"status");
    append_canonical(output, &response.status);
    append_canonical(output, &"product");
    append_canonical(output, &response.product);
    append_canonical(output, &"operation");
    append_canonical(output, &response.operation);
    append_canonical(output, &"offer_token");
    append_canonical(output, &response.offer_token);
    append_canonical(output, &"production_activation");
    append_canonical(output, &response.production_activation);
    append_canonical(output, &"owner_approval_consumed");
    append_canonical(output, &response.owner_approval_consumed);
}

fn raw_negative_goldens(fixture: &Fixture) -> BTreeMap<&'static str, Vec<u8>> {
    let start = start_request(&fixture.start_requests[0]);
    let start_response = start_response(fixture, &fixture.start_responses[0]);
    let finish = finish_request(fixture, &fixture.finish_requests[0]);
    let finish_response = finish_response(&fixture.finish_responses[0]);
    let mint_request = mint_request(fixture, &fixture.mint_requests[0]);
    let mint_response = mint_response(&fixture.mint_responses[0]);
    let proof = finish_response.proof_token.to_vec();
    let mut vectors = BTreeMap::new();

    let canonical_start = household_rs::cbor::to_canonical_vec(&start).unwrap();
    assert_eq!(&canonical_start[..4], &[0xa3, 0x61, 0x76, 0x01]);
    let mut duplicate_start = vec![0xa4];
    duplicate_start.extend_from_slice(&canonical_start[1..4]);
    duplicate_start.extend_from_slice(&canonical_start[1..4]);
    duplicate_start.extend_from_slice(&canonical_start[4..]);
    vectors.insert("start-request-duplicate-key", duplicate_start);

    let mut noncanonical_start = vec![0xa3];
    append_canonical(&mut noncanonical_start, &"run_claims");
    append_canonical(&mut noncanonical_start, &start.run_claims);
    append_canonical(&mut noncanonical_start, &"v");
    append_canonical(&mut noncanonical_start, &start.version);
    append_canonical(&mut noncanonical_start, &"claw_alias");
    append_canonical(&mut noncanonical_start, &start.claw_alias);
    vectors.insert("start-request-noncanonical-order", noncanonical_start);

    vectors.insert(
        "start-response-options-duplicate-rp-id",
        raw_start_response_options(&start_response, "duplicate_rp_id"),
    );
    vectors.insert(
        "start-response-options-noncanonical-order",
        raw_start_response_options(&start_response, "noncanonical_order"),
    );
    vectors.insert(
        "start-response-options-null-allow-credentials",
        raw_start_response_options(&start_response, "null_allow_credentials"),
    );
    vectors.insert(
        "start-response-options-unknown-key",
        raw_start_response_options(&start_response, "unknown_key"),
    );

    let mut indefinite_finish = vec![0xbf];
    append_canonical(&mut indefinite_finish, &"v");
    append_canonical(&mut indefinite_finish, &finish.version);
    append_canonical(&mut indefinite_finish, &"approval");
    append_canonical(&mut indefinite_finish, &finish.approval);
    append_canonical(&mut indefinite_finish, &"challenge_id");
    append_canonical(&mut indefinite_finish, &finish.challenge_id);
    indefinite_finish.push(0xff);
    vectors.insert("finish-request-indefinite-map", indefinite_finish);

    let mut nonminimal_finish = vec![0xa3];
    append_canonical(&mut nonminimal_finish, &"v");
    nonminimal_finish.extend_from_slice(&[0x18, 0x01]);
    append_canonical(&mut nonminimal_finish, &"approval");
    append_canonical(&mut nonminimal_finish, &finish.approval);
    append_canonical(&mut nonminimal_finish, &"challenge_id");
    append_canonical(&mut nonminimal_finish, &finish.challenge_id);
    vectors.insert("finish-request-nonminimal-version", nonminimal_finish);

    let canonical_finish_response = household_rs::cbor::to_canonical_vec(&finish_response).unwrap();
    assert_eq!(&canonical_finish_response[..4], &[0xa2, 0x61, 0x76, 0x01]);
    let mut duplicate_finish_response = vec![0xa3];
    duplicate_finish_response.extend_from_slice(&canonical_finish_response[1..4]);
    duplicate_finish_response.extend_from_slice(&canonical_finish_response[1..4]);
    duplicate_finish_response.extend_from_slice(&canonical_finish_response[4..]);
    vectors.insert("finish-response-duplicate-key", duplicate_finish_response);

    let mut noncanonical_finish_response = vec![0xa2];
    append_canonical(&mut noncanonical_finish_response, &"proof_token");
    append_canonical(
        &mut noncanonical_finish_response,
        &finish_response.proof_token,
    );
    append_canonical(&mut noncanonical_finish_response, &"v");
    append_canonical(&mut noncanonical_finish_response, &finish_response.version);
    vectors.insert(
        "finish-response-noncanonical-order",
        noncanonical_finish_response,
    );

    let mut trailing_finish_response = canonical_finish_response.clone();
    trailing_finish_response.push(0x00);
    vectors.insert("finish-response-trailing-byte", trailing_finish_response);

    let mut nonminimal_finish_response = vec![0xa2];
    append_canonical(&mut nonminimal_finish_response, &"v");
    nonminimal_finish_response.extend_from_slice(&[0x18, 0x01]);
    append_canonical(&mut nonminimal_finish_response, &"proof_token");
    append_canonical(
        &mut nonminimal_finish_response,
        &finish_response.proof_token,
    );
    vectors.insert(
        "finish-response-nonminimal-version",
        nonminimal_finish_response,
    );

    let mut unknown_finish_response = vec![0xa3];
    append_canonical(&mut unknown_finish_response, &"v");
    append_canonical(&mut unknown_finish_response, &finish_response.version);
    append_canonical(&mut unknown_finish_response, &"x");
    append_canonical(&mut unknown_finish_response, &true);
    append_canonical(&mut unknown_finish_response, &"proof_token");
    append_canonical(&mut unknown_finish_response, &finish_response.proof_token);
    vectors.insert("finish-response-unknown-key", unknown_finish_response);

    let mut null_finish_proof = vec![0xa2];
    append_canonical(&mut null_finish_proof, &"v");
    append_canonical(&mut null_finish_proof, &1_u8);
    append_canonical(&mut null_finish_proof, &"proof_token");
    null_finish_proof.push(0xf6);
    vectors.insert("finish-response-null-proof", null_finish_proof);

    let mut text_finish_proof = vec![0xa2];
    append_canonical(&mut text_finish_proof, &"v");
    append_canonical(&mut text_finish_proof, &1_u8);
    append_canonical(&mut text_finish_proof, &"proof_token");
    append_canonical(
        &mut text_finish_proof,
        &String::from_utf8(proof.clone()).expect("fixture token is ASCII"),
    );
    vectors.insert("finish-response-text-proof", text_finish_proof);

    for (id, length) in [
        ("finish-response-short-proof", 31_usize),
        ("finish-response-long-proof", 33_usize),
    ] {
        let mut sized_proof = vec![0xa2];
        append_canonical(&mut sized_proof, &"v");
        append_canonical(&mut sized_proof, &1_u8);
        append_canonical(&mut sized_proof, &"proof_token");
        sized_proof.extend_from_slice(&[0x58, u8::try_from(length).unwrap()]);
        sized_proof.extend(std::iter::repeat_n(0x44, length));
        vectors.insert(id, sized_proof);
    }

    vectors.insert(
        "finish-response-wrong-major-type",
        household_rs::cbor::to_canonical_vec(&vec![finish_response.clone()]).unwrap(),
    );

    let mut trailing_mint = household_rs::cbor::to_canonical_vec(&mint_request).unwrap();
    trailing_mint.push(0x00);
    vectors.insert("mint-request-trailing-byte", trailing_mint);

    let mut null_proof = vec![0xa2];
    append_canonical(&mut null_proof, &"v");
    append_canonical(&mut null_proof, &1_u8);
    append_canonical(&mut null_proof, &"proof_token");
    null_proof.push(0xf6);
    vectors.insert("mint-request-null-proof", null_proof);

    let mut text_proof = vec![0xa2];
    append_canonical(&mut text_proof, &"v");
    append_canonical(&mut text_proof, &1_u8);
    append_canonical(&mut text_proof, &"proof_token");
    append_canonical(
        &mut text_proof,
        &String::from_utf8(proof.clone()).expect("fixture token is ASCII"),
    );
    vectors.insert("mint-request-text-proof", text_proof);

    let mut short_proof = vec![0xa2];
    append_canonical(&mut short_proof, &"v");
    append_canonical(&mut short_proof, &1_u8);
    append_canonical(&mut short_proof, &"proof_token");
    short_proof.extend_from_slice(&[0x58, 0x1f]);
    short_proof.extend_from_slice(&proof[..31]);
    vectors.insert("mint-request-short-proof", short_proof);

    let mut selector_mint = vec![0xa3];
    append_canonical(&mut selector_mint, &"v");
    append_canonical(&mut selector_mint, &1_u8);
    append_canonical(&mut selector_mint, &"selector");
    append_canonical(&mut selector_mint, &"Claw-M");
    append_canonical(&mut selector_mint, &"proof_token");
    append_canonical(&mut selector_mint, &ByteBuf::from(proof));
    vectors.insert("mint-request-unknown-selector", selector_mint);

    let canonical_mint_response = household_rs::cbor::to_canonical_vec(&mint_response).unwrap();
    assert_eq!(&canonical_mint_response[..4], &[0xa8, 0x61, 0x76, 0x01]);
    let mut duplicate_mint_response = vec![0xa9];
    duplicate_mint_response.extend_from_slice(&canonical_mint_response[1..4]);
    duplicate_mint_response.extend_from_slice(&canonical_mint_response[1..4]);
    duplicate_mint_response.extend_from_slice(&canonical_mint_response[4..]);
    vectors.insert("mint-response-duplicate-key", duplicate_mint_response);

    let mut noncanonical_mint_response = vec![0xa8];
    append_canonical(&mut noncanonical_mint_response, &"product");
    append_canonical(&mut noncanonical_mint_response, &mint_response.product);
    append_canonical(&mut noncanonical_mint_response, &"v");
    append_canonical(&mut noncanonical_mint_response, &mint_response.version);
    append_canonical(&mut noncanonical_mint_response, &"mode");
    append_canonical(&mut noncanonical_mint_response, &mint_response.mode);
    append_canonical(&mut noncanonical_mint_response, &"status");
    append_canonical(&mut noncanonical_mint_response, &mint_response.status);
    append_canonical(&mut noncanonical_mint_response, &"operation");
    append_canonical(&mut noncanonical_mint_response, &mint_response.operation);
    append_canonical(&mut noncanonical_mint_response, &"offer_token");
    append_canonical(&mut noncanonical_mint_response, &mint_response.offer_token);
    append_canonical(&mut noncanonical_mint_response, &"production_activation");
    append_canonical(
        &mut noncanonical_mint_response,
        &mint_response.production_activation,
    );
    append_canonical(&mut noncanonical_mint_response, &"owner_approval_consumed");
    append_canonical(
        &mut noncanonical_mint_response,
        &mint_response.owner_approval_consumed,
    );
    vectors.insert(
        "mint-response-noncanonical-order",
        noncanonical_mint_response,
    );

    let mut trailing_mint_response = canonical_mint_response.clone();
    trailing_mint_response.push(0x00);
    vectors.insert("mint-response-trailing-byte", trailing_mint_response);

    let mut nonminimal_mint_response = vec![0xa8];
    append_canonical(&mut nonminimal_mint_response, &"v");
    nonminimal_mint_response.extend_from_slice(&[0x18, 0x01]);
    append_mint_response_fields(&mut nonminimal_mint_response, &mint_response);
    vectors.insert("mint-response-nonminimal-version", nonminimal_mint_response);

    let mut unknown_mint_response = vec![0xa9];
    append_canonical(&mut unknown_mint_response, &"v");
    append_canonical(&mut unknown_mint_response, &mint_response.version);
    append_canonical(&mut unknown_mint_response, &"x");
    append_canonical(&mut unknown_mint_response, &true);
    append_mint_response_fields(&mut unknown_mint_response, &mint_response);
    vectors.insert("mint-response-unknown-key", unknown_mint_response);

    vectors.insert(
        "mint-response-wrong-major-type",
        household_rs::cbor::to_canonical_vec(&vec![mint_response]).unwrap(),
    );

    vectors
}

#[test]
fn success_fixture_metadata_dependencies_and_endpoint_profiles_are_closed() {
    let fixture = fixture();
    assert_eq!(
        fixture.contract,
        "soyeht-mobile-claw-vpn-owner-present-success-wire-v1"
    );
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.scope, "success-wire-only-pre-effect");
    assert_eq!(fixture.about.len(), 4);
    assert!(
        fixture
            .about
            .iter()
            .any(|line| line.contains("no route, handler, runtime, RP, adapter, or effect path"))
    );
    assert!(
        fixture
            .about
            .iter()
            .any(|line| line.contains("owner_present_error_wire_v1.json"))
    );
    assert_eq!(fixture.dependencies.len(), 3);
    assert_eq!(fixture.server_selector_bindings.len(), 2);
    assert_eq!(
        fixture
            .server_selector_bindings
            .iter()
            .map(|binding| (binding.claw_alias.as_str(), binding.server_claw_id.as_str()))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("Claw-L", "claw-l-alpha"), ("Claw-M", "claw-m-alpha")])
    );

    let expected = BTreeMap::from([
        (
            "mobile_owner_approval_execution_v1",
            (
                "admin/contracts/mobile-claw-vpn/v1/owner_approval_v2_execution_vectors.json",
                "Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/owner_approval_v2_execution_vectors.json",
                EXECUTION_FIXTURE_SHA256,
                EXECUTION_FIXTURE.as_bytes(),
            ),
        ),
        (
            "owner_approval_v2_assertion_fields_v1",
            (
                "admin/contracts/owner-approval/v2/owner_approval_v2_assertion_fields_v1.json",
                "Packages/SoyehtCore/Tests/SoyehtCoreTests/HouseholdFixtures/OwnerApprovalV2/owner_approval_v2_assertion_fields_v1.json",
                ASSERTION_FIELDS_FIXTURE_SHA256,
                ASSERTION_FIELDS_FIXTURE.as_bytes(),
            ),
        ),
        (
            "mobile_claw_vpn_api_shapes_v1",
            (
                "admin/contracts/mobile-claw-vpn/v1/api_shapes.json",
                "Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/mobile-claw-vpn/v1/api_shapes.json",
                API_SHAPES_FIXTURE_SHA256,
                API_SHAPES_FIXTURE.as_bytes(),
            ),
        ),
    ]);
    for dependency in &fixture.dependencies {
        let (theyos_path, ios_path, digest, bytes) = expected
            .get(dependency.id.as_str())
            .expect("unexpected dependency");
        assert_eq!(&dependency.theyos_path, theyos_path);
        assert_eq!(&dependency.ios_path, ios_path);
        assert_eq!(&dependency.sha256, digest);
        assert!(!dependency.used_for.is_empty());
        assert_eq!(sha256_hex(bytes), *digest);
        let mut mutated = bytes.to_vec();
        mutated[0] ^= 1;
        assert_ne!(sha256_hex(&mutated), *digest);
    }

    let assertion_fixture = dependency_value(ASSERTION_FIELDS_FIXTURE);
    assert_eq!(
        assertion_fixture["contract"],
        "soyeht-owner-approval-v2-assertion-fields-v1"
    );
    assert_eq!(assertion_fixture["version"], 1);
    let assertions = assertion_fixture["assertions"].as_array().unwrap();
    assert_eq!(assertions.len(), 2);
    for assertion in assertions {
        assert_eq!(
            assertion
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>(),
            HashSet::from([
                "id",
                "credential_id_hex",
                "authenticator_data_hex",
                "client_data_json_hex",
                "signature_hex",
                "user_handle_hex",
            ])
        );
    }
    assert!(assertion_fixture.get("owner_approvals").is_none());
    for implementation_detail in [
        "verification_state",
        "authentication_state",
        "EC_EC2",
        "Self_",
        "allow_backup_eligible_upgrade",
    ] {
        assert!(
            !ASSERTION_FIELDS_FIXTURE.contains(implementation_detail),
            "cross-repo assertion fields leaked Rust detail: {implementation_detail}"
        );
    }

    assert_eq!(
        sha256_hex(WEBAUTHN_STATE_FIXTURE.as_bytes()),
        WEBAUTHN_STATE_FIXTURE_SHA256
    );
    let mut mutated_state = WEBAUTHN_STATE_FIXTURE.as_bytes().to_vec();
    mutated_state[0] ^= 1;
    assert_ne!(sha256_hex(&mutated_state), WEBAUTHN_STATE_FIXTURE_SHA256);
    let verification_fixture = dependency_value(WEBAUTHN_STATE_FIXTURE);
    assert_eq!(
        verification_fixture["contract"],
        "soyeht-mobile-claw-vpn-owner-present-webauthn-state-v1"
    );
    assert_eq!(
        verification_fixture["scope"],
        "rust-test-only-public-verification-state"
    );
    assert_eq!(verification_fixture["states"].as_array().unwrap().len(), 2);
    assert!(!WEBAUTHN_STATE_FIXTURE.contains("private_key"));

    assert_eq!(
        sha256_hex(SUCCESS_FIXTURE.as_bytes()),
        SUCCESS_FIXTURE_SHA256
    );
    let mut mutated_fixture = SUCCESS_FIXTURE.as_bytes().to_vec();
    mutated_fixture[0] ^= 1;
    assert_ne!(sha256_hex(&mutated_fixture), SUCCESS_FIXTURE_SHA256);

    assert_eq!(fixture.format.media_type, "application/cbor");
    assert!(fixture.format.canonical_cbor.contains("byte-identical"));
    assert_eq!(fixture.format.byte_fields.len(), 5);
    assert!(
        fixture
            .format
            .challenge_id
            .contains("only public challenge handle")
    );
    assert!(
        fixture
            .format
            .proof_token
            .contains("never enters summary, UI, debug, or logs")
    );
    assert!(fixture.format.run_claims.contains("never authorize"));
    assert!(fixture.format.run_claims.contains("mismatch must burn"));
    assert!(
        fixture
            .format
            .owner_credential_allowlist
            .contains("server-side enrollment")
    );
    assert!(
        fixture
            .format
            .webauthn_binding
            .contains("random RP challenge")
    );
    assert!(
        fixture
            .format
            .webauthn_binding
            .contains("consumes it at finish")
    );
    assert!(
        fixture
            .format
            .error_contract
            .contains("no handler or client may land")
    );
    assert_eq!(
        fixture
            .runtime_requirements_not_implemented_by_c1
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>(),
        HashSet::from([
            "trusted_dev_config",
            "structural_dev_bundle",
            "real_owner_webauthn_rp",
            "owner_authority_anchor",
            "active_owner_credential_allowlist",
            "owner_present_error_wire_v1",
            "single_use_challenge_and_proof_stores",
            "RevalidatedCapability_by_value_into_locked_Mesh_sink",
        ])
    );

    assert_eq!(fixture.endpoint_profiles.len(), 3);
    for (name, profile) in &fixture.endpoint_profiles {
        assert_eq!(profile.method, "POST", "{name}");
        assert!(
            profile
                .path
                .starts_with("/api/v1/mobile/claw-vpn/owner-present/")
        );
        assert_eq!(profile.auth, "mobile_bearer");
        assert_eq!(profile.gate, "dev_default_off");
        assert_eq!(profile.request_content_type, "application/cbor");
        assert_eq!(profile.response_content_type, "application/cbor");
        assert_eq!(profile.success_status, 200);
        assert!(profile.request_max_bytes > 0);
        assert!(profile.response_max_bytes > 0);
    }
    assert_eq!(
        fixture.endpoint_profiles["start"].path,
        "/api/v1/mobile/claw-vpn/owner-present/start"
    );
    assert_eq!(
        fixture.endpoint_profiles["finish"].path,
        "/api/v1/mobile/claw-vpn/owner-present/finish"
    );
    assert_eq!(
        fixture.endpoint_profiles["mint_offer"].path,
        "/api/v1/mobile/claw-vpn/owner-present/offers"
    );
}

#[test]
fn thirteen_success_envelopes_are_production_canonical_and_strictly_validated() {
    let fixture = fixture();
    assert_eq!(fixture.start_requests.len(), 2);
    for vector in &fixture.start_requests {
        let value = start_request(vector);
        validate_start_request(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["start"].request_max_bytes);
        let decoded: StartRequestWire = strict_decode(&bytes).unwrap();
        validate_start_request(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }

    assert_eq!(fixture.start_responses.len(), 3);
    for vector in &fixture.start_responses {
        let value = start_response(&fixture, vector);
        validate_start_response(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["start"].response_max_bytes);
        let decoded: StartResponseWire = strict_decode(&bytes).unwrap();
        validate_start_response(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }
    assert_eq!(
        fixture.start_responses[0].context_template_fixture_id,
        fixture.start_responses[2].context_template_fixture_id
    );
    assert_eq!(fixture.start_responses[0].start_request_id, "start-claw-m");
    assert_eq!(fixture.start_responses[1].start_request_id, "start-claw-l");
    assert_eq!(fixture.start_responses[2].start_request_id, "start-claw-m");
    assert_eq!(
        household_rs::cbor::to_canonical_vec(
            &start_response(&fixture, &fixture.start_responses[0]).context
        )
        .unwrap(),
        household_rs::cbor::to_canonical_vec(
            &start_response(&fixture, &fixture.start_responses[2]).context
        )
        .unwrap()
    );
    assert_ne!(
        start_response(&fixture, &fixture.start_responses[0])
            .options
            .public_key
            .challenge,
        start_response(&fixture, &fixture.start_responses[2])
            .options
            .public_key
            .challenge
    );

    for vector in &fixture.finish_requests {
        let value = finish_request(&fixture, vector);
        validate_finish_request(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["finish"].request_max_bytes);
        let decoded: FinishRequestWire = strict_decode(&bytes).unwrap();
        validate_finish_request(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }

    for vector in &fixture.finish_responses {
        let value = finish_response(vector);
        validate_finish_response(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["finish"].response_max_bytes);
        let decoded: FinishResponseWire = strict_decode(&bytes).unwrap();
        validate_finish_response(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }

    for vector in &fixture.mint_requests {
        let value = mint_request(&fixture, vector);
        validate_mint_request(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["mint_offer"].request_max_bytes);
        let decoded: MintRequestWire = strict_decode(&bytes).unwrap();
        validate_mint_request(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }

    for vector in &fixture.mint_responses {
        let value = mint_response(vector);
        validate_mint_response(&value).unwrap();
        let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
        assert!(bytes.len() <= fixture.endpoint_profiles["mint_offer"].response_max_bytes);
        let decoded: MintResponseWire = strict_decode(&bytes).unwrap();
        validate_mint_response(&decoded).unwrap();
        assert_or_print_golden(&vector.id, &vector.canonical_cbor_hex, &bytes);
    }
}

#[test]
fn explicit_flow_graph_binds_selectors_challenge_context_and_proof_end_to_end() {
    let fixture = fixture();
    assert_eq!(fixture.flows.len(), 2);
    let mut aliases = HashSet::new();
    let mut selector_ids = BTreeMap::new();
    let mut referenced_start_responses = HashSet::new();

    for flow in &fixture.flows {
        assert!(matches!(
            flow.id.as_str(),
            "claw-m-owner-present-flow" | "claw-l-owner-present-flow"
        ));
        let start_request_vector = start_request_vector(&fixture, &flow.start_request_id);
        let start_response_vector = start_response_vector(&fixture, &flow.start_response_id);
        let finish_request_vector = finish_request_vector(&fixture, &flow.finish_request_id);
        let finish_response_vector = finish_response_vector(&fixture, &flow.finish_response_id);
        let mint_request_vector = mint_request_vector(&fixture, &flow.mint_request_id);
        let mint_response_vector = mint_response_vector(&fixture, &flow.mint_response_id);

        assert_eq!(
            start_response_vector.start_request_id,
            start_request_vector.id
        );
        assert_eq!(
            finish_request_vector.start_response_id,
            start_response_vector.id
        );
        assert_eq!(
            finish_response_vector.finish_request_id,
            finish_request_vector.id
        );
        assert_eq!(
            mint_request_vector.finish_response_id,
            finish_response_vector.id
        );
        assert_eq!(mint_response_vector.mint_request_id, mint_request_vector.id);

        let start_request = start_request(start_request_vector);
        let start_response = start_response(&fixture, start_response_vector);
        let finish_request = finish_request(&fixture, finish_request_vector);
        let finish_response = finish_response(finish_response_vector);
        let mint_request = mint_request(&fixture, mint_request_vector);

        assert!(request_matches_execution(
            &start_request,
            &start_response.execution
        ));
        assert!(aliases.insert(start_response.execution.claw_alias.clone()));
        assert!(
            selector_ids
                .insert(
                    start_response.execution.claw_alias.clone(),
                    start_response.execution.claw_id.clone(),
                )
                .is_none()
        );
        assert!(referenced_start_responses.insert(start_response_vector.id.clone()));
        assert_eq!(finish_request.challenge_id, start_response.challenge_id);
        assert_eq!(
            household_rs::cbor::to_canonical_vec(&finish_request.approval.context).unwrap(),
            household_rs::cbor::to_canonical_vec(&start_response.context).unwrap()
        );
        assert_eq!(finish_response.proof_token, mint_request.proof_token);
        verify_owner_present_assertion(
            &start_response,
            &finish_request,
            &finish_request_vector.assertion_fixture_id,
        )
        .unwrap();

        validate_start_request(&start_request).unwrap();
        validate_start_response(&start_response).unwrap();
        validate_finish_request(&finish_request).unwrap();
        validate_finish_response(&finish_response).unwrap();
        validate_mint_request(&mint_request).unwrap();
        validate_mint_response(&mint_response(mint_response_vector)).unwrap();
    }

    assert_eq!(
        aliases,
        HashSet::from(["Claw-M".to_string(), "Claw-L".to_string()])
    );
    assert_eq!(
        selector_ids,
        BTreeMap::from([
            ("Claw-L".to_string(), "claw-l-alpha".to_string()),
            ("Claw-M".to_string(), "claw-m-alpha".to_string()),
        ])
    );
    assert_ne!(selector_ids["Claw-M"], selector_ids["Claw-L"]);

    let start_m = start_response(&fixture, &fixture.start_responses[0]);
    assert!(selector_matches_server_binding(
        &fixture,
        &start_m.execution
    ));
    let mut alias_only_swap = start_m.execution.clone();
    alias_only_swap.claw_alias = "Claw-L".to_string();
    assert!(!selector_matches_server_binding(&fixture, &alias_only_swap));
    let mut id_only_swap = start_m.execution.clone();
    id_only_swap.claw_id = "claw-l-alpha".to_string();
    assert!(!selector_matches_server_binding(&fixture, &id_only_swap));

    let finish_m = finish_request(&fixture, &fixture.finish_requests[0]);
    let start_l = start_response(&fixture, &fixture.start_responses[1]);
    let finish_l = finish_request(&fixture, &fixture.finish_requests[1]);
    let mut challenge_swap = finish_m.clone();
    challenge_swap.approval.authenticator_data = finish_l.approval.authenticator_data.clone();
    challenge_swap.approval.client_data_json = finish_l.approval.client_data_json.clone();
    challenge_swap.approval.signature = finish_l.approval.signature.clone();
    assert_eq!(
        verify_owner_present_assertion(
            &start_m,
            &challenge_swap,
            &fixture.finish_requests[0].assertion_fixture_id,
        ),
        Err("client_data_binding")
    );
    let mut rp_state_challenge_swap = start_m.clone();
    rp_state_challenge_swap.options.public_key.challenge =
        start_l.options.public_key.challenge.clone();
    assert_eq!(
        verify_owner_present_assertion(
            &rp_state_challenge_swap,
            &challenge_swap,
            &fixture.finish_requests[0].assertion_fixture_id,
        ),
        Err("webauthn_assertion")
    );
    let mut credential_swap = finish_m;
    credential_swap.approval.credential_id = ByteBuf::from(vec![0x61; 32]);
    assert_eq!(
        verify_owner_present_assertion(
            &start_m,
            &credential_swap,
            &fixture.finish_requests[0].assertion_fixture_id,
        ),
        Err("credential_allowlist")
    );
    let mut untrusted_allowlist = start_m.clone();
    untrusted_allowlist.options.public_key.allow_credentials[0].id = B64URL.encode([0x61; 32]);
    assert_eq!(
        verify_owner_present_assertion(
            &untrusted_allowlist,
            &credential_swap,
            &fixture.finish_requests[0].assertion_fixture_id,
        ),
        Err("webauthn_assertion")
    );
    assert!(
        verify_owner_present_assertion(
            &start_l,
            &finish_l,
            &fixture.finish_requests[1].assertion_fixture_id,
        )
        .is_ok()
    );
    assert_eq!(referenced_start_responses.len(), 2);
    assert!(!referenced_start_responses.contains("start-response-claw-m-challenge-b-same-context"));
    assert_eq!(
        fixture
            .flows
            .iter()
            .map(|flow| flow.start_request_id.as_str())
            .collect::<HashSet<_>>(),
        fixture
            .start_requests
            .iter()
            .map(|vector| vector.id.as_str())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        fixture
            .flows
            .iter()
            .map(|flow| flow.finish_request_id.as_str())
            .collect::<HashSet<_>>(),
        fixture
            .finish_requests
            .iter()
            .map(|vector| vector.id.as_str())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        fixture
            .flows
            .iter()
            .map(|flow| flow.finish_response_id.as_str())
            .collect::<HashSet<_>>(),
        fixture
            .finish_responses
            .iter()
            .map(|vector| vector.id.as_str())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        fixture
            .flows
            .iter()
            .map(|flow| flow.mint_request_id.as_str())
            .collect::<HashSet<_>>(),
        fixture
            .mint_requests
            .iter()
            .map(|vector| vector.id.as_str())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        fixture
            .flows
            .iter()
            .map(|flow| flow.mint_response_id.as_str())
            .collect::<HashSet<_>>(),
        fixture
            .mint_responses
            .iter()
            .map(|vector| vector.id.as_str())
            .collect::<HashSet<_>>()
    );
    let semantic_cases = fixture
        .negative_contract
        .semantic_cases
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for required in [
        "flow_selector_mismatch",
        "flow_selector_server_id_mismatch",
        "finish_challenge_or_context_mismatch",
        "finish_response_proof_mismatch",
        "finish_assertion_rp_challenge_mismatch",
        "finish_assertion_credential_not_allowlisted",
    ] {
        assert!(
            semantic_cases.contains(required),
            "missing graph tooth: {required}"
        );
    }
}

#[test]
fn start_request_has_no_authority_fields_and_claims_match_before_review() {
    let fixture = fixture();
    assert_eq!(
        fixture.negative_contract.expected_rejection,
        "invalid_envelope"
    );
    assert_eq!(
        fixture.negative_contract.forbidden_start_request_keys.len(),
        15
    );
    assert_eq!(
        fixture
            .negative_contract
            .start_request_to_execution_fields
            .len(),
        8
    );
    let request = start_request(&fixture.start_requests[0]);
    let response = start_response(&fixture, &fixture.start_responses[0]);
    assert!(request_matches_execution(&request, &response.execution));

    for key in &fixture.negative_contract.forbidden_start_request_keys {
        let bytes = household_rs::cbor::to_canonical_vec(&InjectedStartRequest {
            start: &request,
            key,
        })
        .unwrap();
        assert!(strict_decode::<StartRequestWire>(&bytes).is_err(), "{key}");
    }

    let mut mutations = Vec::new();
    let mut execution = response.execution.clone();
    execution.claw_alias = "Claw-L".to_string();
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.attempt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string();
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.readiness_run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string();
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.source_artifact_git_sha1 = ByteBuf::from(vec![0xa1; 20]);
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.execution_manifest_sha256 = ByteBuf::from(vec![0xb1; 32]);
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.device_binding = ByteBuf::from(vec![0xc1; 32]);
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.execution_run_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string();
    mutations.push(execution);
    let mut execution = response.execution.clone();
    execution.execution_claim_sha256 = ByteBuf::from(vec![0xd1; 32]);
    mutations.push(execution);
    assert_eq!(mutations.len(), 8);
    for mutation in mutations {
        assert!(!request_matches_execution(&request, &mutation));
    }
}

#[test]
fn server_binding_carries_reject_context_and_execution_drift_before_owner_effects() {
    let fixture = fixture();
    let response = start_response(&fixture, &fixture.start_responses[0]);

    let mut wrong_hash = response.clone();
    wrong_hash.context.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x45; 32]));
    assert_eq!(
        validate_start_response(&wrong_hash),
        Err("execution_context_binding")
    );

    let mut wrong_time = response.clone();
    wrong_time.context.expires_at += 1;
    assert_eq!(
        validate_start_response(&wrong_time),
        Err("execution_context_binding")
    );

    let mut digest_as_challenge = response.clone();
    digest_as_challenge.options.public_key.challenge = B64URL.encode(
        response
            .context
            .challenge_digest()
            .expect("valid owner-approval context"),
    );
    assert_eq!(
        validate_start_response(&digest_as_challenge),
        Err("context_digest_is_not_rp_challenge")
    );

    let finish = finish_request(&fixture, &fixture.finish_requests[0]);
    let expected = start_response(
        &fixture,
        start_response_vector(&fixture, &fixture.finish_requests[0].start_response_id),
    )
    .context;
    assert_eq!(
        finish.approval.require_expected_context(&expected).unwrap(),
        expected.challenge_digest().unwrap()
    );
    let mut reconstructed_drift = expected.clone();
    reconstructed_drift.replay_nonce = ByteBuf::from(vec![0x47; 32]);
    assert!(
        finish
            .approval
            .require_expected_context(&reconstructed_drift)
            .is_err()
    );

    let semantic_cases = fixture
        .negative_contract
        .semantic_cases
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for required in [
        "start_response_run_claim_mismatch",
        "start_response_execution_context_hash_mismatch",
        "start_response_execution_context_time_mismatch",
        "start_response_context_digest_used_as_rp_challenge",
        "finish_submitted_context_mismatch",
    ] {
        assert!(
            semantic_cases.contains(required),
            "missing semantic carry: {required}"
        );
    }
}

#[test]
fn owner_present_options_profile_rejects_every_permissive_fallback() {
    let fixture = fixture();
    let baseline = fixture.start_responses[0].options.clone();
    let expected_mutations = HashSet::from([
        "wrong_rp_id",
        "challenge_padded_base64url",
        "challenge_wrong_length",
        "user_verification_missing",
        "user_verification_preferred",
        "allow_credentials_missing",
        "allow_credentials_null",
        "allow_credentials_empty",
        "allow_credentials_duplicate_decoded_id",
        "descriptor_wrong_type",
        "descriptor_extra_transports",
        "public_key_extra_extensions",
    ]);
    assert_eq!(
        fixture
            .negative_contract
            .strict_options_mutations
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>(),
        expected_mutations
    );

    for mutation in expected_mutations {
        let mut value = baseline.clone();
        let public_key = value["publicKey"].as_object_mut().unwrap();
        match mutation {
            "wrong_rp_id" => {
                public_key.insert("rpId".into(), Value::String("other.example.test".into()))
            }
            "challenge_padded_base64url" => {
                let challenge = public_key["challenge"].as_str().unwrap().to_string() + "=";
                public_key.insert("challenge".into(), Value::String(challenge))
            }
            "challenge_wrong_length" => {
                public_key.insert("challenge".into(), Value::String("AQ".into()))
            }
            "user_verification_missing" => public_key.remove("userVerification"),
            "user_verification_preferred" => {
                public_key.insert("userVerification".into(), Value::String("preferred".into()))
            }
            "allow_credentials_missing" => public_key.remove("allowCredentials"),
            "allow_credentials_null" => public_key.insert("allowCredentials".into(), Value::Null),
            "allow_credentials_empty" => {
                public_key.insert("allowCredentials".into(), Value::Array(vec![]))
            }
            "allow_credentials_duplicate_decoded_id" => {
                let first = public_key["allowCredentials"][0].clone();
                public_key.insert(
                    "allowCredentials".into(),
                    Value::Array(vec![first.clone(), first]),
                )
            }
            "descriptor_wrong_type" => {
                public_key["allowCredentials"][0]["type"] = Value::String("not-public-key".into());
                None
            }
            "descriptor_extra_transports" => {
                public_key["allowCredentials"][0]["transports"] =
                    Value::Array(vec![Value::String("internal".into())]);
                None
            }
            "public_key_extra_extensions" => {
                public_key.insert("extensions".into(), serde_json::json!({"uvm": true}))
            }
            _ => unreachable!(),
        };
        assert!(strict_options_from_json(&value).is_err(), "{mutation}");
    }
}

#[test]
fn normal_mint_response_and_extra_capability_fields_cannot_validate_as_owner_present() {
    let fixture = fixture();
    let api = dependency_value(API_SHAPES_FIXTURE);
    let normal = &api["responses"]["mint_offer"];
    let normal_cbor = household_rs::cbor::to_canonical_vec(normal).unwrap();
    assert!(strict_decode::<MintResponseWire>(&normal_cbor).is_err());

    let owner_present = mint_response(&fixture.mint_responses[0]);
    validate_mint_response(&owner_present).unwrap();
    assert_ne!(owner_present.mode, normal["mode"].as_str().unwrap());
    assert_ne!(
        owner_present.operation,
        normal["operation"].as_str().unwrap()
    );
    assert!(owner_present.owner_approval_consumed);

    let mut normal_mode = owner_present.clone();
    normal_mode.mode = normal["mode"].as_str().unwrap().to_string();
    assert_eq!(
        validate_mint_response(&normal_mode),
        Err("mint_response_shape")
    );
    let mut normal_operation = owner_present.clone();
    normal_operation.operation = normal["operation"].as_str().unwrap().to_string();
    assert_eq!(
        validate_mint_response(&normal_operation),
        Err("mint_response_shape")
    );
    let mut approval_not_consumed = owner_present.clone();
    approval_not_consumed.owner_approval_consumed = false;
    assert_eq!(
        validate_mint_response(&approval_not_consumed),
        Err("mint_response_shape")
    );
    let mut production_enabled = owner_present.clone();
    production_enabled.production_activation = true;
    assert_eq!(
        validate_mint_response(&production_enabled),
        Err("mint_response_shape")
    );

    for extra in [
        "session_id",
        "proof_token",
        "selector",
        "device_id",
        "claw_id",
    ] {
        let mut injected = serde_json::to_value(&owner_present).unwrap();
        injected
            .as_object_mut()
            .unwrap()
            .insert(extra.to_string(), Value::String("injected".to_string()));
        let bytes = household_rs::cbor::to_canonical_vec(&injected).unwrap();
        assert!(
            strict_decode::<MintResponseWire>(&bytes).is_err(),
            "{extra}"
        );
    }

    let semantic_cases = fixture
        .negative_contract
        .semantic_cases
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    assert!(semantic_cases.contains("normal_mint_response_as_owner_present"));
    assert!(semantic_cases.contains("mint_response_normal_mode"));
    assert!(semantic_cases.contains("mint_response_normal_operation"));
    assert!(semantic_cases.contains("mint_response_owner_approval_not_consumed"));
    assert!(semantic_cases.contains("mint_response_production_activation"));
    assert!(semantic_cases.contains("mint_request_with_selector_or_ids"));
    assert!(semantic_cases.contains("mint_response_with_session_id_or_proof_token"));
}

#[test]
fn raw_cbor_negatives_are_delivered_to_the_wrapper_decoder() {
    let fixture = fixture();
    let generated = raw_negative_goldens(&fixture);
    assert_eq!(fixture.negative_contract.raw_cbor_cases.len(), 29);
    assert_eq!(generated.len(), 29);
    for vector in &fixture.negative_contract.raw_cbor_cases {
        let expected = generated
            .get(vector.id.as_str())
            .expect("known raw negative");
        if std::env::var_os("PRINT_OWNER_PRESENT_RAW_GOLDENS").is_some() {
            println!("RAW_GOLDEN {} {}", vector.id, hex_bytes(expected));
            continue;
        }
        assert!(
            !vector.raw_cbor_hex.is_empty(),
            "{} missing raw bytes",
            vector.id
        );
        let bytes = unhex(&vector.raw_cbor_hex);
        assert_eq!(&bytes, expected, "{} raw bytes drifted", vector.id);
        let result = match vector.envelope {
            EnvelopeKind::StartRequest => strict_decode::<StartRequestWire>(&bytes)
                .and_then(|value| validate_start_request(&value)),
            EnvelopeKind::StartResponse => strict_decode::<StartResponseWire>(&bytes)
                .and_then(|value| validate_start_response(&value)),
            EnvelopeKind::FinishRequest => strict_decode::<FinishRequestWire>(&bytes)
                .and_then(|value| validate_finish_request(&value)),
            EnvelopeKind::FinishResponse => strict_decode::<FinishResponseWire>(&bytes)
                .and_then(|value| validate_finish_response(&value)),
            EnvelopeKind::MintRequest => strict_decode::<MintRequestWire>(&bytes)
                .and_then(|value| validate_mint_request(&value)),
            EnvelopeKind::MintResponse => strict_decode::<MintResponseWire>(&bytes)
                .and_then(|value| validate_mint_response(&value)),
        };
        if std::env::var_os("PRINT_OWNER_PRESENT_RAW_REASONS").is_some() {
            println!("RAW_REASON {} {}", vector.id, result.unwrap_err());
            continue;
        }
        assert_eq!(
            result,
            Err(vector.expected_reason.as_str()),
            "{} rejection drifted",
            vector.id
        );
    }
}

fn collect_rs_sources(path: &Path, output: &mut String) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_rs_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push_str(&fs::read_to_string(path).expect("Rust source"));
        }
    }
}

#[test]
fn success_contract_is_pre_effect_and_the_durable_runtime_gate_is_registered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = root.join("../../..");
    assert!(
        !root
            .join("../../contracts/mobile-claw-vpn/v1/owner_present_runtime_activation_v1.json")
            .exists()
    );
    let mut sources = String::new();
    collect_rs_sources(&root.join("src"), &mut sources);
    for forbidden in [
        "/api/v1/mobile/claw-vpn/owner-present/start",
        "/api/v1/mobile/claw-vpn/owner-present/finish",
        "/api/v1/mobile/claw-vpn/owner-present/offers",
        "handle_mobile_claw_vpn_owner_present",
        "pub mod mobile_claw_vpn_owner_present_foundation",
    ] {
        assert!(
            !sources.contains(forbidden),
            "shipping source contains {forbidden}"
        );
    }
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    assert!(lib.contains("mod mobile_claw_vpn_owner_present_foundation;"));
    assert!(!lib.contains("pub mod mobile_claw_vpn_owner_present_foundation;"));

    for script in [
        ".github/scripts/check-mobile-claw-vpn-owner-present-runtime-gate.sh",
        ".github/scripts/test-mobile-claw-vpn-owner-present-runtime-gate.sh",
    ] {
        assert!(
            repo.join(script).is_file(),
            "missing durable gate: {script}"
        );
    }
    let workflow =
        fs::read_to_string(repo.join(".github/workflows/owner-present-runtime-gate.yml"))
            .expect("runtime-gate workflow");
    for required in [
        "admin/rust/server-rs/src/**",
        "admin/rust/household-rs/src/**",
        "check-mobile-claw-vpn-owner-present-runtime-gate.sh",
        "test-mobile-claw-vpn-owner-present-runtime-gate.sh",
    ] {
        assert!(workflow.contains(required), "workflow misses {required}");
    }
    let contracts_workflow =
        fs::read_to_string(repo.join(".github/workflows/contracts-cross-repo-sync.yml"))
            .expect("cross-repo workflow");
    for runtime_only in [
        "admin/rust/server-rs/src/**",
        "admin/rust/household-rs/src/**",
        "check-mobile-claw-vpn-owner-present-runtime-gate.sh",
        "test-mobile-claw-vpn-owner-present-runtime-gate.sh",
    ] {
        assert!(
            !contracts_workflow.contains(runtime_only),
            "contract sync must not freeze unrelated Rust changes through {runtime_only}"
        );
    }
}
