//! Owner approval Protocol-v2 primitives.
//!
//! This module is intentionally inert: it defines the signed context and
//! `WebAuthn` challenge binding used by S2, but does not enforce it on any
//! endpoint yet.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::error::HouseholdError;
use crate::ids::{HouseholdId, MachineId, derive_machine_id};
use crate::keys::P256PublicKey;
use crate::machine_cert::PersonId;
use crate::pair_machine::{
    JoinRequest, JoinTransport, PairMachineState, PairMachineWindowSnapshot, join_request_hash,
    verify_join_request,
};

pub const OWNER_APPROVAL_V2_VERSION: u8 = 2;
pub const OWNER_APPROVAL_V2_PURPOSE: &str = "owner-approval-v2";
pub const OWNER_APPROVAL_V2_CHALLENGE_DOMAIN: &[u8] = b"soyeht-owner-approval-v2\0";
pub const MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_VERSION: u8 = 1;
pub const MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_PURPOSE: &str = "mobile-claw-vpn-dev-e2e-execution";
pub const MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_DOMAIN: &[u8] =
    b"soyeht-mobile-claw-vpn-dev-e2e-execution-v1\0";
pub const MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID: &str = "com.soyeht.app.dev";
pub const MOBILE_CLAW_VPN_DEV_E2E_CAPABILITY: &str = "mobile-claw-vpn-dev-e2e-execute";
pub const MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS: u64 = 120;

#[derive(Debug, Error)]
pub enum OwnerApprovalV2Error {
    #[error("unsupported owner approval context version: {0}")]
    UnsupportedVersion(u8),
    #[error("owner approval context purpose mismatch: {0}")]
    PurposeMismatch(String),
    #[error("owner approval context missing required field: {0}")]
    MissingField(&'static str),
    #[error("owner approval context field is not allowed for this operation: {0}")]
    UnexpectedField(&'static str),
    #[error("owner approval context field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("owner approval context expires before it is issued")]
    InvalidTimeWindow,
    #[error("owner approval context expired at {expires_at}, now {now}")]
    Expired { now: u64, expires_at: u64 },
    #[error("owner approval capabilities must be sorted")]
    CapabilitiesNotSorted,
    #[error("owner approval capabilities must not contain duplicates: {0}")]
    DuplicateCapability(String),
    #[error("owner approval context is not canonical CBOR")]
    NonCanonical,
    #[error("owner approval context CBOR error: {0}")]
    Cbor(String),
    #[error("owner approval trusted state mismatch: {0}")]
    TrustedState(&'static str),
    #[error("owner approval cached join request invalid: {0}")]
    JoinRequest(String),
    #[error("owner approval assertion field is invalid: {0}")]
    AssertionField(&'static str),
    #[error("owner approval context does not match trusted server state")]
    ContextMismatch,
}

impl From<HouseholdError> for OwnerApprovalV2Error {
    fn from(value: HouseholdError) -> Self {
        Self::Cbor(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerOperation {
    PairMachineApprove,
    BootstrapInitialize,
    BootstrapTeardown,
    PairDeviceConfirm,
    RevokeCredential,
    ProvisionRecoveryCode,
    AddCredential,
    RecoverCredential,
    MobileClawVpnDevE2eExecute,
}

/// Canonical, versioned tuple bound into the DEV-only mobile Claw VPN owner
/// approval. CBOR supplies unambiguous length-delimited field boundaries; the
/// execution hash adds an operation-specific domain before hashing those bytes.
///
/// This type is inert. It does not authenticate a caller, start `WebAuthn`, mint
/// a capability, or authorize a mobile endpoint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileClawVpnDevE2eExecutionTupleV1 {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub op: OwnerOperation,
    pub hh_id: HouseholdId,
    /// Per-Engine-instance audience chosen by the server. This prevents a
    /// future approval capability from moving between Engine instances.
    pub engine_audience: ByteBuf,
    /// Mobile member/principal derived by the server from the bearer session.
    pub member_id: String,
    pub attempt_id: String,
    pub readiness_run_id: String,
    /// The reviewed source commit, represented as the 20 raw Git SHA-1 bytes.
    pub source_artifact_git_sha1: ByteBuf,
    /// Digest of the immutable execution manifest (helper, app, tests, xctestrun).
    pub execution_manifest_sha256: ByteBuf,
    /// Correlation claim from tooling; not a device attestation by itself.
    pub device_binding: ByteBuf,
    pub execution_run_id: String,
    /// Digest of the executor's single-use claim; not an authority by itself.
    pub execution_claim_sha256: ByteBuf,
    pub bundle_id: String,
    pub device_id: String,
    pub claw_id: String,
    pub device_alias: String,
    pub claw_alias: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Fresh CSPRNG nonce generated by the server for this tuple.
    pub server_nonce: ByteBuf,
}

impl fmt::Debug for MobileClawVpnDevE2eExecutionTupleV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnDevE2eExecutionTupleV1")
            .field("version", &self.version)
            .field("purpose", &self.purpose)
            .field("op", &self.op)
            .field("private_fields", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl MobileClawVpnDevE2eExecutionTupleV1 {
    #[must_use]
    pub fn new(input: MobileClawVpnDevE2eExecutionTupleInput) -> Self {
        Self {
            version: MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_VERSION,
            purpose: MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_PURPOSE.to_string(),
            op: OwnerOperation::MobileClawVpnDevE2eExecute,
            hh_id: input.hh_id,
            engine_audience: ByteBuf::from(input.engine_audience.to_vec()),
            member_id: input.member_id,
            attempt_id: input.attempt_id,
            readiness_run_id: input.readiness_run_id,
            source_artifact_git_sha1: ByteBuf::from(input.source_artifact_git_sha1.to_vec()),
            execution_manifest_sha256: ByteBuf::from(input.execution_manifest_sha256.to_vec()),
            device_binding: ByteBuf::from(input.device_binding.to_vec()),
            execution_run_id: input.execution_run_id,
            execution_claim_sha256: ByteBuf::from(input.execution_claim_sha256.to_vec()),
            bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID.to_string(),
            device_id: input.device_id,
            claw_id: input.claw_id,
            device_alias: input.device_alias,
            claw_alias: input.claw_alias,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            server_nonce: ByteBuf::from(input.server_nonce.to_vec()),
        }
    }

    pub fn validate_shape(&self) -> Result<(), OwnerApprovalV2Error> {
        if self.version != MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_VERSION {
            return Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.v",
            ));
        }
        if self.purpose != MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_PURPOSE {
            return Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.purpose",
            ));
        }
        if self.op != OwnerOperation::MobileClawVpnDevE2eExecute {
            return Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.op",
            ));
        }
        if !HouseholdId::is_well_formed(self.hh_id.as_str()) {
            return Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.hh_id",
            ));
        }
        require_len(&self.engine_audience, 32, "engine_audience")?;
        require_ascii_identifier(&self.member_id, "member_id")?;
        require_canonical_uuid(&self.attempt_id, "attempt_id")?;
        require_canonical_uuid(&self.readiness_run_id, "readiness_run_id")?;
        require_len(
            &self.source_artifact_git_sha1,
            20,
            "source_artifact_git_sha1",
        )?;
        require_len(
            &self.execution_manifest_sha256,
            32,
            "execution_manifest_sha256",
        )?;
        require_len(&self.device_binding, 32, "device_binding")?;
        require_canonical_uuid(&self.execution_run_id, "execution_run_id")?;
        require_len(&self.execution_claim_sha256, 32, "execution_claim_sha256")?;
        if self.bundle_id != MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID {
            return Err(OwnerApprovalV2Error::InvalidField("bundle_id"));
        }
        require_ascii_identifier(&self.device_id, "device_id")?;
        require_ascii_identifier(&self.claw_id, "claw_id")?;
        if self.device_alias != "Device-D" {
            return Err(OwnerApprovalV2Error::InvalidField("device_alias"));
        }
        if !matches!(self.claw_alias.as_str(), "Claw-M" | "Claw-L") {
            return Err(OwnerApprovalV2Error::InvalidField("claw_alias"));
        }
        let ttl = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or(OwnerApprovalV2Error::InvalidTimeWindow)?;
        if ttl == 0 || ttl > MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS {
            return Err(OwnerApprovalV2Error::InvalidTimeWindow);
        }
        require_len(&self.server_nonce, 32, "server_nonce")
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, OwnerApprovalV2Error> {
        self.validate_shape()?;
        crate::cbor::to_canonical_vec(self).map_err(OwnerApprovalV2Error::from)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnerApprovalV2Error> {
        let decoded: Self = crate::cbor::from_canonical_slice(bytes)
            .map_err(|error| OwnerApprovalV2Error::Cbor(error.to_string()))?;
        let canonical = decoded.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(OwnerApprovalV2Error::NonCanonical);
        }
        Ok(decoded)
    }

    pub fn execution_hash(&self) -> Result<[u8; 32], OwnerApprovalV2Error> {
        let canonical = self.to_canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(MOBILE_CLAW_VPN_DEV_E2E_EXECUTION_DOMAIN);
        hasher.update(&canonical);
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApprovalContextV2 {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub op: OwnerOperation,
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m_id: Option<MachineId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<JoinTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_request_hash: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_credential_id: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_head_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_head_hash: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_active_credential_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_head_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_head_hash: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_credential_binding_hash: Option<ByteBuf>,
    /// Required only for `MobileClawVpnDevE2eExecute`. The RP challenge is
    /// random. The server binds it to the stored canonical
    /// context containing this tuple hash and requires exact context equality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile_claw_vpn_execution_hash: Option<ByteBuf>,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: ByteBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApprovalV2 {
    #[serde(rename = "v")]
    pub version: u8,
    pub context: OwnerApprovalContextV2,
    pub credential_id: ByteBuf,
    pub authenticator_data: ByteBuf,
    pub client_data_json: ByteBuf,
    pub signature: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<ByteBuf>,
}

impl OwnerApprovalV2 {
    pub fn validate_shape(&self) -> Result<(), OwnerApprovalV2Error> {
        if self.version != OWNER_APPROVAL_V2_VERSION {
            return Err(OwnerApprovalV2Error::UnsupportedVersion(self.version));
        }
        self.context.validate_shape()?;
        if self.credential_id.is_empty() {
            return Err(OwnerApprovalV2Error::AssertionField("credential_id"));
        }
        if self.authenticator_data.is_empty() {
            return Err(OwnerApprovalV2Error::AssertionField("authenticator_data"));
        }
        if self.client_data_json.is_empty() {
            return Err(OwnerApprovalV2Error::AssertionField("client_data_json"));
        }
        if self.signature.is_empty() {
            return Err(OwnerApprovalV2Error::AssertionField("signature"));
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, OwnerApprovalV2Error> {
        self.validate_shape()?;
        crate::cbor::to_canonical_vec(self).map_err(OwnerApprovalV2Error::from)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnerApprovalV2Error> {
        let decoded: Self = crate::cbor::from_canonical_slice(bytes)
            .map_err(|e| OwnerApprovalV2Error::Cbor(e.to_string()))?;
        let canonical = decoded.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(OwnerApprovalV2Error::NonCanonical);
        }
        Ok(decoded)
    }

    pub fn require_expected_context(
        &self,
        expected: &OwnerApprovalContextV2,
    ) -> Result<[u8; 32], OwnerApprovalV2Error> {
        self.validate_shape()?;
        let submitted = self.context.to_canonical_bytes()?;
        let expected_bytes = expected.to_canonical_bytes()?;
        if submitted != expected_bytes {
            return Err(OwnerApprovalV2Error::ContextMismatch);
        }
        expected.challenge_digest()
    }

    /// Convert the embedded assertion into the public `webauthn-rs` credential
    /// type. This does not verify the assertion; callers must pass the result
    /// to `OwnerWebauthnRp::finish_owner_approval_assertion`.
    pub fn to_public_key_credential(&self) -> Result<PublicKeyCredential, OwnerApprovalV2Error> {
        self.validate_shape()?;

        let credential_id = data_encoding::BASE64URL_NOPAD.encode(self.credential_id.as_ref());
        let assertion = serde_json::json!({
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "authenticatorData": data_encoding::BASE64URL_NOPAD
                    .encode(self.authenticator_data.as_ref()),
                "clientDataJSON": data_encoding::BASE64URL_NOPAD
                    .encode(self.client_data_json.as_ref()),
                "signature": data_encoding::BASE64URL_NOPAD
                    .encode(self.signature.as_ref()),
                "userHandle": self
                    .user_handle
                    .as_ref()
                    .map(|user_handle| data_encoding::BASE64URL_NOPAD.encode(user_handle.as_ref())),
            },
            "type": "public-key",
        });

        serde_json::from_value(assertion)
            .map_err(|_| OwnerApprovalV2Error::AssertionField("public_key_credential"))
    }
}

impl OwnerApprovalContextV2 {
    #[must_use]
    pub fn pair_machine_approve(input: PairMachineApprovalContextInput) -> Self {
        Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::PairMachineApprove,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor: Some(input.cursor),
            m_id: Some(input.m_id),
            addr: Some(input.addr),
            transport: Some(input.transport),
            ttl_unix: Some(input.ttl_unix),
            nonce: Some(ByteBuf::from(input.nonce.to_vec())),
            join_request_hash: Some(ByteBuf::from(input.join_request_hash.to_vec())),
            target_credential_id: None,
            authority_head_sequence: None,
            authority_head_hash: None,
            pre_active_credential_count: None,
            recovery_head_sequence: None,
            recovery_head_hash: None,
            new_credential_binding_hash: None,
            mobile_claw_vpn_execution_hash: None,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
    }

    #[must_use]
    pub fn revoke_credential(input: RevokeCredentialContextInput) -> Self {
        Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::RevokeCredential,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor: None,
            m_id: None,
            addr: None,
            transport: None,
            ttl_unix: None,
            nonce: None,
            join_request_hash: None,
            target_credential_id: Some(ByteBuf::from(input.target_credential_id)),
            authority_head_sequence: Some(input.authority_head_sequence),
            authority_head_hash: Some(ByteBuf::from(input.authority_head_hash.to_vec())),
            pre_active_credential_count: Some(input.pre_active_credential_count),
            recovery_head_sequence: None,
            recovery_head_hash: None,
            new_credential_binding_hash: None,
            mobile_claw_vpn_execution_hash: None,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
    }

    #[must_use]
    pub fn provision_recovery_code(input: ProvisionRecoveryCodeContextInput) -> Self {
        Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::ProvisionRecoveryCode,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor: None,
            m_id: None,
            addr: None,
            transport: None,
            ttl_unix: None,
            nonce: None,
            join_request_hash: None,
            target_credential_id: None,
            authority_head_sequence: Some(input.authority_head_sequence),
            authority_head_hash: Some(ByteBuf::from(input.authority_head_hash.to_vec())),
            pre_active_credential_count: Some(input.pre_active_credential_count),
            recovery_head_sequence: input.recovery_head.map(|head| head.sequence),
            recovery_head_hash: input
                .recovery_head
                .map(|head| ByteBuf::from(head.head_hash.to_vec())),
            new_credential_binding_hash: None,
            mobile_claw_vpn_execution_hash: None,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
    }

    #[must_use]
    pub fn add_credential(input: AddCredentialContextInput) -> Self {
        Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::AddCredential,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor: None,
            m_id: None,
            addr: None,
            transport: None,
            ttl_unix: None,
            nonce: None,
            join_request_hash: None,
            target_credential_id: None,
            authority_head_sequence: Some(input.authority_head_sequence),
            authority_head_hash: Some(ByteBuf::from(input.authority_head_hash.to_vec())),
            pre_active_credential_count: Some(input.pre_active_credential_count),
            recovery_head_sequence: None,
            recovery_head_hash: None,
            new_credential_binding_hash: Some(ByteBuf::from(
                input.new_credential_binding_hash.to_vec(),
            )),
            mobile_claw_vpn_execution_hash: None,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
    }

    #[must_use]
    pub fn recover_credential(input: RecoverCredentialContextInput) -> Self {
        Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::RecoverCredential,
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor: None,
            m_id: None,
            addr: None,
            transport: None,
            ttl_unix: None,
            nonce: None,
            join_request_hash: None,
            target_credential_id: None,
            authority_head_sequence: Some(input.authority_head_sequence),
            authority_head_hash: Some(ByteBuf::from(input.authority_head_hash.to_vec())),
            pre_active_credential_count: Some(input.pre_active_credential_count),
            recovery_head_sequence: Some(input.recovery_head.sequence),
            recovery_head_hash: Some(ByteBuf::from(input.recovery_head.head_hash.to_vec())),
            new_credential_binding_hash: Some(ByteBuf::from(
                input.new_credential_binding_hash.to_vec(),
            )),
            mobile_claw_vpn_execution_hash: None,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
    }

    pub fn mobile_claw_vpn_dev_e2e_execute(
        input: MobileClawVpnDevE2eApprovalContextInput<'_>,
    ) -> Result<Self, OwnerApprovalV2Error> {
        input.execution.validate_shape()?;
        let execution_hash = input.execution.execution_hash()?;
        let context = Self {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::MobileClawVpnDevE2eExecute,
            hh_id: input.execution.hh_id.clone(),
            owner_p_id: input.owner_p_id,
            cursor: None,
            m_id: None,
            addr: None,
            transport: None,
            ttl_unix: None,
            nonce: None,
            join_request_hash: None,
            target_credential_id: None,
            authority_head_sequence: None,
            authority_head_hash: None,
            pre_active_credential_count: None,
            recovery_head_sequence: None,
            recovery_head_hash: None,
            new_credential_binding_hash: None,
            mobile_claw_vpn_execution_hash: Some(ByteBuf::from(execution_hash.to_vec())),
            capabilities: vec![MOBILE_CLAW_VPN_DEV_E2E_CAPABILITY.to_string()],
            issued_at: input.execution.issued_at,
            expires_at: input.execution.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        };
        context.validate_shape()?;
        Ok(context)
    }

    pub fn validate_shape(&self) -> Result<(), OwnerApprovalV2Error> {
        if self.version != OWNER_APPROVAL_V2_VERSION {
            return Err(OwnerApprovalV2Error::UnsupportedVersion(self.version));
        }
        if self.purpose != OWNER_APPROVAL_V2_PURPOSE {
            return Err(OwnerApprovalV2Error::PurposeMismatch(self.purpose.clone()));
        }
        if self.expires_at < self.issued_at {
            return Err(OwnerApprovalV2Error::InvalidTimeWindow);
        }
        validate_capabilities(&self.capabilities)?;

        if self.op != OwnerOperation::MobileClawVpnDevE2eExecute {
            self.require_absent_mobile_claw_vpn_fields()?;
        }

        match self.op {
            OwnerOperation::PairMachineApprove => {
                require_some(self.cursor.as_ref(), "cursor")?;
                require_some(self.m_id.as_ref(), "m_id")?;
                require_some(self.addr.as_ref(), "addr")?;
                require_some(self.transport.as_ref(), "transport")?;
                require_some(self.ttl_unix.as_ref(), "ttl_unix")?;
                require_some(self.nonce.as_ref(), "nonce")?;
                require_some(self.join_request_hash.as_ref(), "join_request_hash")?;
                self.require_absent_revoke_fields()?;
                self.require_absent_recovery_fields()?;
                self.require_absent_add_credential_fields()?;
            }
            OwnerOperation::RevokeCredential => {
                self.require_absent_pair_machine_fields()?;
                self.require_absent_recovery_fields()?;
                self.require_absent_add_credential_fields()?;
                let target =
                    require_some(self.target_credential_id.as_ref(), "target_credential_id")?;
                if target.is_empty() {
                    return Err(OwnerApprovalV2Error::InvalidField("target_credential_id"));
                }
                require_some(
                    self.authority_head_sequence.as_ref(),
                    "authority_head_sequence",
                )?;
                let head_hash =
                    require_some(self.authority_head_hash.as_ref(), "authority_head_hash")?;
                if head_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"));
                }
                let count = require_some(
                    self.pre_active_credential_count.as_ref(),
                    "pre_active_credential_count",
                )?;
                if *count == 0 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "pre_active_credential_count",
                    ));
                }
            }
            OwnerOperation::ProvisionRecoveryCode => {
                self.require_absent_pair_machine_fields()?;
                require_none(self.target_credential_id.as_ref(), "target_credential_id")?;
                require_some(
                    self.authority_head_sequence.as_ref(),
                    "authority_head_sequence",
                )?;
                let head_hash =
                    require_some(self.authority_head_hash.as_ref(), "authority_head_hash")?;
                if head_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"));
                }
                let count = require_some(
                    self.pre_active_credential_count.as_ref(),
                    "pre_active_credential_count",
                )?;
                if *count == 0 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "pre_active_credential_count",
                    ));
                }
                match (
                    self.recovery_head_sequence.as_ref(),
                    self.recovery_head_hash.as_ref(),
                ) {
                    (None, None) => {}
                    (Some(_), Some(hash)) if hash.len() == 32 => {}
                    (Some(_), Some(_)) => {
                        return Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"));
                    }
                    (Some(_), None) => {
                        return Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"));
                    }
                    (None, Some(_)) => {
                        return Err(OwnerApprovalV2Error::MissingField("recovery_head_sequence"));
                    }
                }
                self.require_absent_add_credential_fields()?;
            }
            OwnerOperation::AddCredential => {
                self.require_absent_pair_machine_fields()?;
                require_none(self.target_credential_id.as_ref(), "target_credential_id")?;
                self.require_absent_recovery_fields()?;
                require_some(
                    self.authority_head_sequence.as_ref(),
                    "authority_head_sequence",
                )?;
                let head_hash =
                    require_some(self.authority_head_hash.as_ref(), "authority_head_hash")?;
                if head_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"));
                }
                let count = require_some(
                    self.pre_active_credential_count.as_ref(),
                    "pre_active_credential_count",
                )?;
                if *count == 0 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "pre_active_credential_count",
                    ));
                }
                let binding_hash = require_some(
                    self.new_credential_binding_hash.as_ref(),
                    "new_credential_binding_hash",
                )?;
                if binding_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "new_credential_binding_hash",
                    ));
                }
            }
            OwnerOperation::RecoverCredential => {
                self.require_absent_pair_machine_fields()?;
                require_none(self.target_credential_id.as_ref(), "target_credential_id")?;
                require_some(
                    self.authority_head_sequence.as_ref(),
                    "authority_head_sequence",
                )?;
                let head_hash =
                    require_some(self.authority_head_hash.as_ref(), "authority_head_hash")?;
                if head_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"));
                }
                require_some(
                    self.pre_active_credential_count.as_ref(),
                    "pre_active_credential_count",
                )?;
                match (
                    self.recovery_head_sequence.as_ref(),
                    self.recovery_head_hash.as_ref(),
                ) {
                    (Some(_), Some(hash)) if hash.len() == 32 => {}
                    (Some(_), Some(_)) => {
                        return Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"));
                    }
                    (Some(_), None) => {
                        return Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"));
                    }
                    (None, Some(_) | None) => {
                        return Err(OwnerApprovalV2Error::MissingField("recovery_head_sequence"));
                    }
                }
                let binding_hash = require_some(
                    self.new_credential_binding_hash.as_ref(),
                    "new_credential_binding_hash",
                )?;
                if binding_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "new_credential_binding_hash",
                    ));
                }
            }
            OwnerOperation::MobileClawVpnDevE2eExecute => {
                self.require_absent_pair_machine_fields()?;
                self.require_absent_revoke_fields()?;
                self.require_absent_recovery_fields()?;
                self.require_absent_add_credential_fields()?;
                let execution_hash = require_some(
                    self.mobile_claw_vpn_execution_hash.as_ref(),
                    "mobile_claw_vpn_execution_hash",
                )?;
                if execution_hash.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField(
                        "mobile_claw_vpn_execution_hash",
                    ));
                }
                if self.capabilities != [MOBILE_CLAW_VPN_DEV_E2E_CAPABILITY] {
                    return Err(OwnerApprovalV2Error::InvalidField("capabilities"));
                }
                if self.replay_nonce.len() != 32 {
                    return Err(OwnerApprovalV2Error::InvalidField("replay_nonce"));
                }
                if !HouseholdId::is_well_formed(self.hh_id.as_str()) {
                    return Err(OwnerApprovalV2Error::InvalidField("hh_id"));
                }
                if !PersonId::is_well_formed(&self.owner_p_id.0) {
                    return Err(OwnerApprovalV2Error::InvalidField("owner_p_id"));
                }
                let ttl = self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .ok_or(OwnerApprovalV2Error::InvalidTimeWindow)?;
                if ttl == 0 || ttl > MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS {
                    return Err(OwnerApprovalV2Error::InvalidTimeWindow);
                }
            }
            OwnerOperation::BootstrapInitialize
            | OwnerOperation::BootstrapTeardown
            | OwnerOperation::PairDeviceConfirm => {
                self.require_absent_pair_machine_fields()?;
                self.require_absent_revoke_fields()?;
                self.require_absent_recovery_fields()?;
                self.require_absent_add_credential_fields()?;
            }
        }
        Ok(())
    }

    fn require_absent_pair_machine_fields(&self) -> Result<(), OwnerApprovalV2Error> {
        require_none(self.cursor.as_ref(), "cursor")?;
        require_none(self.m_id.as_ref(), "m_id")?;
        require_none(self.addr.as_ref(), "addr")?;
        require_none(self.transport.as_ref(), "transport")?;
        require_none(self.ttl_unix.as_ref(), "ttl_unix")?;
        require_none(self.nonce.as_ref(), "nonce")?;
        require_none(self.join_request_hash.as_ref(), "join_request_hash")
    }

    fn require_absent_revoke_fields(&self) -> Result<(), OwnerApprovalV2Error> {
        require_none(self.target_credential_id.as_ref(), "target_credential_id")?;
        require_none(
            self.authority_head_sequence.as_ref(),
            "authority_head_sequence",
        )?;
        require_none(self.authority_head_hash.as_ref(), "authority_head_hash")?;
        require_none(
            self.pre_active_credential_count.as_ref(),
            "pre_active_credential_count",
        )?;
        self.require_absent_recovery_fields()?;
        self.require_absent_add_credential_fields()
    }

    fn require_absent_recovery_fields(&self) -> Result<(), OwnerApprovalV2Error> {
        require_none(
            self.recovery_head_sequence.as_ref(),
            "recovery_head_sequence",
        )?;
        require_none(self.recovery_head_hash.as_ref(), "recovery_head_hash")
    }

    fn require_absent_add_credential_fields(&self) -> Result<(), OwnerApprovalV2Error> {
        require_none(
            self.new_credential_binding_hash.as_ref(),
            "new_credential_binding_hash",
        )
    }

    fn require_absent_mobile_claw_vpn_fields(&self) -> Result<(), OwnerApprovalV2Error> {
        require_none(
            self.mobile_claw_vpn_execution_hash.as_ref(),
            "mobile_claw_vpn_execution_hash",
        )
    }

    pub fn validate_at(&self, now_unix: u64) -> Result<(), OwnerApprovalV2Error> {
        self.validate_shape()?;
        if now_unix > self.expires_at {
            return Err(OwnerApprovalV2Error::Expired {
                now: now_unix,
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, OwnerApprovalV2Error> {
        self.validate_shape()?;
        crate::cbor::to_canonical_vec(self).map_err(OwnerApprovalV2Error::from)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnerApprovalV2Error> {
        let decoded: Self = crate::cbor::from_canonical_slice(bytes)
            .map_err(|e| OwnerApprovalV2Error::Cbor(e.to_string()))?;
        let canonical = decoded.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(OwnerApprovalV2Error::NonCanonical);
        }
        Ok(decoded)
    }

    pub fn challenge_digest(&self) -> Result<[u8; 32], OwnerApprovalV2Error> {
        let canonical = self.to_canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(OWNER_APPROVAL_V2_CHALLENGE_DOMAIN);
        hasher.update(&canonical);
        Ok(hasher.finalize().into())
    }

    pub fn pair_machine_approve_from_trusted_state(
        input: PairMachineTrustedContextInput<'_>,
    ) -> Result<Self, OwnerApprovalV2Error> {
        let snapshot = input.snapshot;
        if snapshot.state != PairMachineState::AwaitingOwner {
            return Err(OwnerApprovalV2Error::TrustedState(
                "window not awaiting owner",
            ));
        }
        let cursor = snapshot
            .owner_event_cursor
            .ok_or(OwnerApprovalV2Error::TrustedState(
                "missing owner event cursor",
            ))?;
        let cached_join_request =
            snapshot
                .cached_join_request
                .as_ref()
                .ok_or(OwnerApprovalV2Error::TrustedState(
                    "missing cached join request",
                ))?;
        let join_request: JoinRequest = crate::cbor::from_canonical_slice(cached_join_request)
            .map_err(|e| OwnerApprovalV2Error::JoinRequest(e.to_string()))?;
        verify_join_request(&join_request)
            .map_err(|e| OwnerApprovalV2Error::JoinRequest(e.to_string()))?;

        require_snapshot_match(
            snapshot.m_pub.as_ref().map(ByteBuf::as_ref),
            join_request.m_pub.as_ref(),
            "m_pub mismatch",
        )?;
        require_snapshot_match(
            snapshot.nonce.as_ref().map(ByteBuf::as_ref),
            join_request.nonce.as_ref(),
            "nonce mismatch",
        )?;
        if snapshot.transport != Some(join_request.transport) {
            return Err(OwnerApprovalV2Error::TrustedState("transport mismatch"));
        }
        if snapshot.addr_hint.as_deref() != Some(join_request.addr.as_str()) {
            return Err(OwnerApprovalV2Error::TrustedState("addr mismatch"));
        }

        let expiry = snapshot
            .expiry
            .ok_or(OwnerApprovalV2Error::TrustedState("missing expiry"))?;
        let expires_at = input
            .issued_at
            .saturating_add(input.challenge_ttl_secs)
            .min(expiry);
        if expires_at < input.issued_at {
            return Err(OwnerApprovalV2Error::InvalidTimeWindow);
        }

        let m_pub: [u8; 33] = join_request
            .m_pub
            .as_ref()
            .try_into()
            .map_err(|_| OwnerApprovalV2Error::JoinRequest("m_pub length".into()))?;
        let m_pub = P256PublicKey::from_bytes(&m_pub)
            .map_err(|e| OwnerApprovalV2Error::JoinRequest(e.to_string()))?;
        let m_id = derive_machine_id(&m_pub);
        let join_hash = join_request_hash(cached_join_request);
        let nonce: [u8; 32] = join_request
            .nonce
            .as_ref()
            .try_into()
            .map_err(|_| OwnerApprovalV2Error::JoinRequest("nonce length".into()))?;

        let context = Self::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id: input.hh_id,
            owner_p_id: input.owner_p_id,
            cursor,
            m_id,
            addr: join_request.addr,
            transport: join_request.transport,
            ttl_unix: expiry,
            nonce,
            join_request_hash: join_hash,
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at,
            replay_nonce: input.replay_nonce,
        });
        context.validate_shape()?;
        Ok(context)
    }
}

pub struct PairMachineApprovalContextInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub cursor: u64,
    pub m_id: MachineId,
    pub addr: String,
    pub transport: JoinTransport,
    pub ttl_unix: u64,
    pub nonce: [u8; 32],
    pub join_request_hash: [u8; 32],
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: [u8; 32],
}

pub struct RevokeCredentialContextInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub target_credential_id: Vec<u8>,
    pub authority_head_sequence: u64,
    pub authority_head_hash: [u8; 32],
    pub pre_active_credential_count: u64,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAuthorityHeadInput {
    pub sequence: u64,
    pub head_hash: [u8; 32],
}

pub struct ProvisionRecoveryCodeContextInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub authority_head_sequence: u64,
    pub authority_head_hash: [u8; 32],
    pub pre_active_credential_count: u64,
    pub recovery_head: Option<RecoveryAuthorityHeadInput>,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: [u8; 32],
}

pub struct AddCredentialContextInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub new_credential_binding_hash: [u8; 32],
    pub authority_head_sequence: u64,
    pub authority_head_hash: [u8; 32],
    pub pre_active_credential_count: u64,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: [u8; 32],
}

pub struct RecoverCredentialContextInput {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub new_credential_binding_hash: [u8; 32],
    pub authority_head_sequence: u64,
    pub authority_head_hash: [u8; 32],
    pub pre_active_credential_count: u64,
    pub recovery_head: RecoveryAuthorityHeadInput,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: [u8; 32],
}

pub struct MobileClawVpnDevE2eExecutionTupleInput {
    pub hh_id: HouseholdId,
    pub engine_audience: [u8; 32],
    pub member_id: String,
    pub attempt_id: String,
    pub readiness_run_id: String,
    pub source_artifact_git_sha1: [u8; 20],
    pub execution_manifest_sha256: [u8; 32],
    pub device_binding: [u8; 32],
    pub execution_run_id: String,
    pub execution_claim_sha256: [u8; 32],
    pub device_id: String,
    pub claw_id: String,
    pub device_alias: String,
    pub claw_alias: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub server_nonce: [u8; 32],
}

pub struct MobileClawVpnDevE2eApprovalContextInput<'a> {
    pub owner_p_id: PersonId,
    pub execution: &'a MobileClawVpnDevE2eExecutionTupleV1,
    pub replay_nonce: [u8; 32],
}

pub struct PairMachineTrustedContextInput<'a> {
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub snapshot: &'a PairMachineWindowSnapshot,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub challenge_ttl_secs: u64,
    pub replay_nonce: [u8; 32],
}

fn require_snapshot_match(
    snapshot_value: Option<&[u8]>,
    request_value: &[u8],
    label: &'static str,
) -> Result<(), OwnerApprovalV2Error> {
    if snapshot_value == Some(request_value) {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::TrustedState(label))
    }
}

fn require_some<'a, T>(
    value: Option<&'a T>,
    field: &'static str,
) -> Result<&'a T, OwnerApprovalV2Error> {
    match value {
        Some(value) => Ok(value),
        None => Err(OwnerApprovalV2Error::MissingField(field)),
    }
}

fn require_none<T>(value: Option<&T>, field: &'static str) -> Result<(), OwnerApprovalV2Error> {
    if value.is_none() {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::UnexpectedField(field))
    }
}

fn require_len(
    value: &[u8],
    expected: usize,
    field: &'static str,
) -> Result<(), OwnerApprovalV2Error> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::InvalidField(field))
    }
}

fn require_ascii_identifier(value: &str, field: &'static str) -> Result<(), OwnerApprovalV2Error> {
    if !value.is_empty()
        && value.len() <= 512
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::InvalidField(field))
    }
}

fn require_canonical_uuid(value: &str, field: &'static str) -> Result<(), OwnerApprovalV2Error> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        });
    if valid {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::InvalidField(field))
    }
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), OwnerApprovalV2Error> {
    for pair in capabilities.windows(2) {
        if pair[0] > pair[1] {
            return Err(OwnerApprovalV2Error::CapabilitiesNotSorted);
        }
        if pair[0] == pair[1] {
            return Err(OwnerApprovalV2Error::DuplicateCapability(pair[0].clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
