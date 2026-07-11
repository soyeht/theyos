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
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::machine_cert::Platform;
    use crate::owner_webauthn::{OwnerWebauthnConfig, OwnerWebauthnRp};
    use crate::pair_machine::{JoinChallenge, PAIR_MACHINE_VERSION};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{Url, Uuid};

    const NOW: u64 = 1_800_000_000;

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn machine_id() -> MachineId {
        MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
    }

    fn person_id() -> PersonId {
        PersonId("p_owner-alpha".to_string())
    }

    fn sample_context() -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            cursor: 7,
            m_id: machine_id(),
            addr: "192.0.2.10:8091".to_string(),
            transport: JoinTransport::Lan,
            ttl_unix: 1_800,
            nonce: [0x11; 32],
            join_request_hash: [0x22; 32],
            capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
            issued_at: 1_000,
            expires_at: 1_600,
            replay_nonce: [0x33; 32],
        })
    }

    fn sample_revoke_context() -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::revoke_credential(RevokeCredentialContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            target_credential_id: b"AAECgP9_".to_vec(),
            authority_head_sequence: 24,
            authority_head_hash: [0x44; 32],
            pre_active_credential_count: 2,
            capabilities: vec!["owner-auth-revoke".to_string()],
            issued_at: 1_000,
            expires_at: 1_600,
            replay_nonce: [0x55; 32],
        })
    }

    fn sample_provision_recovery_context() -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::provision_recovery_code(ProvisionRecoveryCodeContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            authority_head_sequence: 24,
            authority_head_hash: [0x44; 32],
            pre_active_credential_count: 2,
            recovery_head: Some(RecoveryAuthorityHeadInput {
                sequence: 0,
                head_hash: [0x77; 32],
            }),
            capabilities: vec!["owner-auth-recovery-provision".to_string()],
            issued_at: 1_000,
            expires_at: 1_600,
            replay_nonce: [0x55; 32],
        })
    }

    fn sample_add_credential_context() -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::add_credential(AddCredentialContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            new_credential_binding_hash: *b"AAECgP9_AAECgP9_AAECgP9_AAECgP9_",
            authority_head_sequence: 24,
            authority_head_hash: [0x44; 32],
            pre_active_credential_count: 2,
            capabilities: vec!["owner-auth-add-credential".to_string()],
            issued_at: 1_000,
            expires_at: 1_600,
            replay_nonce: [0x55; 32],
        })
    }

    fn sample_recover_credential_context() -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::recover_credential(RecoverCredentialContextInput {
            hh_id: household_id(),
            owner_p_id: person_id(),
            new_credential_binding_hash: *b"RECgP9_RECgP9_RECgP9_RECgP9_RECg",
            authority_head_sequence: 42,
            authority_head_hash: [0x66; 32],
            pre_active_credential_count: 0,
            recovery_head: RecoveryAuthorityHeadInput {
                sequence: 7,
                head_hash: [0x77; 32],
            },
            capabilities: vec!["owner-auth-recovery-consume".to_string()],
            issued_at: 2_000,
            expires_at: 2_600,
            replay_nonce: [0x88; 32],
        })
    }

    fn sample_mobile_claw_vpn_execution() -> MobileClawVpnDevE2eExecutionTupleV1 {
        MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
            hh_id: household_id(),
            engine_audience: [0x90; 32],
            member_id: "member-alpha".to_string(),
            attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
            readiness_run_id: "22222222-2222-4222-8222-222222222222".to_string(),
            source_artifact_git_sha1: [0xaa; 20],
            execution_manifest_sha256: [0xbb; 32],
            device_binding: [0xcc; 32],
            execution_run_id: "33333333-3333-4333-8333-333333333333".to_string(),
            execution_claim_sha256: [0xdd; 32],
            device_id: "device-alpha".to_string(),
            claw_id: "claw-alpha".to_string(),
            device_alias: "Device-D".to_string(),
            claw_alias: "Claw-M".to_string(),
            issued_at: 1_000,
            expires_at: 1_060,
            server_nonce: [0xee; 32],
        })
    }

    fn sample_mobile_claw_vpn_context() -> OwnerApprovalContextV2 {
        let execution = sample_mobile_claw_vpn_execution();
        OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id: person_id(),
                execution: &execution,
                replay_nonce: [0xf0; 32],
            },
        )
        .unwrap()
    }

    fn sample_approval(context: OwnerApprovalContextV2) -> OwnerApprovalV2 {
        OwnerApprovalV2 {
            version: OWNER_APPROVAL_V2_VERSION,
            context,
            credential_id: ByteBuf::from(vec![0xA1; 16]),
            authenticator_data: ByteBuf::from(vec![0xA2; 37]),
            client_data_json: ByteBuf::from(br#"{"type":"webauthn.get"}"#.to_vec()),
            signature: ByteBuf::from(vec![0xA3; 64]),
            user_handle: None,
        }
    }

    fn owner_webauthn_rp() -> OwnerWebauthnRp {
        let config = OwnerWebauthnConfig::new(
            "alpha.example.test",
            Url::parse("https://alpha.example.test").unwrap(),
            "Soyeht Alpha",
        )
        .unwrap();
        OwnerWebauthnRp::new(config).unwrap()
    }

    fn register_softpasskey(
        rp: &mut OwnerWebauthnRp,
        rng: &mut StdRng,
    ) -> (
        crate::owner_webauthn::OwnerWebauthnCredential,
        WebauthnAuthenticator<SoftPasskey>,
    ) {
        let (challenge_id, challenge) = rp
            .start_registration(rng, NOW, Uuid::new_v4(), "owner-alpha", "Owner Alpha", &[])
            .unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = authenticator
            .do_registration(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();
        let credential = rp
            .finish_registration(NOW, &challenge_id, &response)
            .unwrap();
        (credential, authenticator)
    }

    fn approval_from_assertion(
        context: OwnerApprovalContextV2,
        assertion: &PublicKeyCredential,
    ) -> OwnerApprovalV2 {
        OwnerApprovalV2 {
            version: OWNER_APPROVAL_V2_VERSION,
            context,
            credential_id: ByteBuf::from(assertion.raw_id.as_slice().to_vec()),
            authenticator_data: ByteBuf::from(
                assertion.response.authenticator_data.as_slice().to_vec(),
            ),
            client_data_json: ByteBuf::from(
                assertion.response.client_data_json.as_slice().to_vec(),
            ),
            signature: ByteBuf::from(assertion.response.signature.as_slice().to_vec()),
            user_handle: assertion
                .response
                .user_handle
                .as_ref()
                .map(|user_handle| ByteBuf::from(user_handle.as_slice().to_vec())),
        }
    }

    fn signed_join_request() -> (P256Keypair, JoinRequest, Vec<u8>) {
        let kp = P256Keypair::generate();
        let m_pub = *kp.public().as_bytes();
        let nonce = [0x44; 32];
        let challenge = JoinChallenge::build(&m_pub, &nonce, "linux-alpha", Platform::LinuxNix);
        let canonical = challenge.to_canonical_bytes().unwrap();
        let sig = kp.sign(&canonical).unwrap();
        let request = JoinRequest {
            version: PAIR_MACHINE_VERSION,
            m_pub: ByteBuf::from(m_pub.to_vec()),
            hostname: "linux-alpha".into(),
            platform: Platform::LinuxNix,
            nonce: ByteBuf::from(nonce.to_vec()),
            addr: "192.0.2.10:8091".into(),
            transport: JoinTransport::Lan,
            challenge_sig: ByteBuf::from(sig.0.to_vec()),
        };
        let bytes = request.to_canonical_bytes().unwrap();
        (kp, request, bytes)
    }

    fn awaiting_owner_snapshot(
        request: &JoinRequest,
        request_bytes: &[u8],
    ) -> PairMachineWindowSnapshot {
        PairMachineWindowSnapshot {
            version: PAIR_MACHINE_VERSION,
            state: PairMachineState::AwaitingOwner,
            m_pub: Some(request.m_pub.clone()),
            nonce: Some(request.nonce.clone()),
            expiry: Some(1_600),
            transport: Some(request.transport),
            addr_hint: Some(request.addr.clone()),
            fingerprint: Some("fp-neutral".into()),
            owner_event_cursor: Some(7),
            cached_join_request: Some(ByteBuf::from(request_bytes.to_vec())),
            cached_response: None,
            anchor_secret: None,
            pinned_hh_pub: None,
            pinned_hh_id: None,
            approval_claim: None,
        }
    }

    #[test]
    fn pair_machine_context_canonical_bytes_are_stable() {
        let ctx = sample_context();
        let bytes = ctx.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, ctx);
        assert_eq!(
            hex::encode(bytes),
            concat!(
                "b0617602626f7074706169722d6d616368696e652d617070726f766564616464726f3139",
                "322e302e322e31303a38303931646d5f696478366d5f6262626262626262626262626262",
                "626262626262626262626262626262626262626262626262626262626262626262626262",
                "62626568685f6964783768685f6161616161616161616161616161616161616161616161",
                "6161616161616161616161616161616161616161616161616161616161656e6f6e636558",
                "201111111111111111111111111111111111111111111111111111111111111111666375",
                "72736f720767707572706f7365716f776e65722d617070726f76616c2d76326874746c5f",
                "756e6978190708696973737565645f61741903e8697472616e73706f7274636c616e6a65",
                "7870697265735f61741906406a6f776e65725f705f69646d705f6f776e65722d616c7068",
                "616c6361706162696c6974696573826c6d616368696e652d636572746a7368616d69722d",
                "3270636c7265706c61795f6e6f6e63655820333333333333333333333333333333333333",
                "3333333333333333333333333333716a6f696e5f726571756573745f6861736858202222",
                "222222222222222222222222222222222222222222222222222222222222"
            )
        );
    }

    #[test]
    fn challenge_digest_changes_when_bound_fields_change() {
        let baseline = sample_context().challenge_digest().unwrap();

        let mut changed_op = sample_context();
        changed_op.op = OwnerOperation::BootstrapTeardown;
        changed_op.cursor = None;
        changed_op.m_id = None;
        changed_op.addr = None;
        changed_op.transport = None;
        changed_op.ttl_unix = None;
        changed_op.nonce = None;
        changed_op.join_request_hash = None;
        assert_ne!(changed_op.challenge_digest().unwrap(), baseline);

        let mut changed_addr = sample_context();
        changed_addr.addr = Some("198.51.100.10:8091".to_string());
        assert_ne!(changed_addr.challenge_digest().unwrap(), baseline);

        let mut changed_transport = sample_context();
        changed_transport.transport = Some(JoinTransport::Tailscale);
        assert_ne!(changed_transport.challenge_digest().unwrap(), baseline);

        let mut changed_ttl = sample_context();
        changed_ttl.ttl_unix = Some(1_801);
        assert_ne!(changed_ttl.challenge_digest().unwrap(), baseline);

        let mut changed_nonce = sample_context();
        changed_nonce.nonce = Some(ByteBuf::from(vec![0x44; 32]));
        assert_ne!(changed_nonce.challenge_digest().unwrap(), baseline);

        let mut changed_machine = sample_context();
        changed_machine.m_id = Some(MachineId::parse(format!("m_{}", "c".repeat(52))).unwrap());
        assert_ne!(changed_machine.challenge_digest().unwrap(), baseline);

        let mut changed_join_hash = sample_context();
        changed_join_hash.join_request_hash = Some(ByteBuf::from(vec![0x55; 32]));
        assert_ne!(changed_join_hash.challenge_digest().unwrap(), baseline);

        let mut changed_capabilities = sample_context();
        changed_capabilities.capabilities =
            vec!["machine-cert".to_string(), "push-token".to_string()];
        assert_ne!(changed_capabilities.challenge_digest().unwrap(), baseline);
    }

    #[test]
    fn mobile_claw_vpn_execution_tuple_round_trips_and_hashes_canonical_cbor() {
        let execution = sample_mobile_claw_vpn_execution();
        let canonical = execution.to_canonical_bytes().unwrap();
        let decoded =
            MobileClawVpnDevE2eExecutionTupleV1::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(decoded, execution);
        assert_eq!(execution.execution_hash().unwrap().len(), 32);
    }

    #[test]
    fn mobile_claw_vpn_execution_hash_changes_for_every_mutable_tuple_field() {
        let baseline = sample_mobile_claw_vpn_execution();
        let baseline_bytes = baseline.to_canonical_bytes().unwrap();
        let baseline_hash = baseline.execution_hash().unwrap();
        let baseline_context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id: person_id(),
                execution: &baseline,
                replay_nonce: [0xf0; 32],
            },
        )
        .unwrap();
        let baseline_challenge = baseline_context.challenge_digest().unwrap();
        let mut mutations = Vec::new();

        let mut value = baseline.clone();
        value.hh_id = HouseholdId::parse(format!("hh_{}", "c".repeat(52))).unwrap();
        mutations.push(("hh_id", value));
        let mut value = baseline.clone();
        value.engine_audience = ByteBuf::from(vec![0x91; 32]);
        mutations.push(("engine_audience", value));
        let mut value = baseline.clone();
        value.member_id = "member-beta".to_string();
        mutations.push(("member_id", value));
        let mut value = baseline.clone();
        value.attempt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string();
        mutations.push(("attempt_id", value));
        let mut value = baseline.clone();
        value.readiness_run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string();
        mutations.push(("readiness_run_id", value));
        let mut value = baseline.clone();
        value.source_artifact_git_sha1 = ByteBuf::from(vec![0xa1; 20]);
        mutations.push(("source_artifact_git_sha1", value));
        let mut value = baseline.clone();
        value.execution_manifest_sha256 = ByteBuf::from(vec![0xb1; 32]);
        mutations.push(("execution_manifest_sha256", value));
        let mut value = baseline.clone();
        value.device_binding = ByteBuf::from(vec![0xc1; 32]);
        mutations.push(("device_binding", value));
        let mut value = baseline.clone();
        value.execution_run_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string();
        mutations.push(("execution_run_id", value));
        let mut value = baseline.clone();
        value.execution_claim_sha256 = ByteBuf::from(vec![0xd1; 32]);
        mutations.push(("execution_claim_sha256", value));
        let mut value = baseline.clone();
        value.device_id = "device-beta".to_string();
        mutations.push(("device_id", value));
        let mut value = baseline.clone();
        value.claw_id = "claw-beta".to_string();
        mutations.push(("claw_id", value));
        let mut value = baseline.clone();
        value.claw_alias = "Claw-L".to_string();
        mutations.push(("claw_alias", value));
        let mut value = baseline.clone();
        value.issued_at = 1_001;
        mutations.push(("issued_at", value));
        let mut value = baseline.clone();
        value.expires_at = 1_061;
        mutations.push(("expires_at", value));
        let mut value = baseline.clone();
        value.server_nonce = ByteBuf::from(vec![0xe1; 32]);
        mutations.push(("server_nonce", value));

        for (field, mutation) in mutations {
            assert_ne!(
                mutation.to_canonical_bytes().unwrap(),
                baseline_bytes,
                "{field}: canonical tuple bytes did not change"
            );
            assert_ne!(
                mutation.execution_hash().unwrap(),
                baseline_hash,
                "{field}: execution hash did not change"
            );
            let mutated_context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
                MobileClawVpnDevE2eApprovalContextInput {
                    owner_p_id: person_id(),
                    execution: &mutation,
                    replay_nonce: [0xf0; 32],
                },
            )
            .unwrap();
            assert_ne!(
                mutated_context.challenge_digest().unwrap(),
                baseline_challenge,
                "{field}: owner approval challenge did not change"
            );
        }
    }

    #[test]
    fn mobile_claw_vpn_execution_hash_is_domain_separated_and_length_delimited() {
        let baseline = sample_mobile_claw_vpn_execution();
        let canonical = baseline.to_canonical_bytes().unwrap();
        let undomained: [u8; 32] = Sha256::digest(&canonical).into();
        assert_ne!(baseline.execution_hash().unwrap(), undomained);

        let mut left = baseline.clone();
        left.member_id = "a".to_string();
        left.device_id = "bc".to_string();
        let mut right = baseline;
        right.member_id = "ab".to_string();
        right.device_id = "c".to_string();
        assert_ne!(
            left.to_canonical_bytes().unwrap(),
            right.to_canonical_bytes().unwrap()
        );
        assert_ne!(
            left.execution_hash().unwrap(),
            right.execution_hash().unwrap()
        );
    }

    #[test]
    fn mobile_claw_vpn_execution_tuple_rejects_fixed_field_and_length_drift() {
        let baseline = sample_mobile_claw_vpn_execution();

        let mut invalid = baseline.clone();
        invalid.version = 2;
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.v"
            ))
        ));
        let mut invalid = baseline.clone();
        invalid.purpose = "other".to_string();
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.purpose"
            ))
        ));
        let mut invalid = baseline.clone();
        invalid.op = OwnerOperation::PairMachineApprove;
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.op"
            ))
        ));
        let mut invalid = baseline.clone();
        invalid.bundle_id = "com.soyeht.app".to_string();
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("bundle_id"))
        ));
        let mut invalid = baseline.clone();
        invalid.hh_id = HouseholdId("hh_test".to_string());
        assert!(matches!(
            invalid.to_canonical_bytes(),
            Err(OwnerApprovalV2Error::InvalidField(
                "mobile_claw_vpn_execution.hh_id"
            ))
        ));
        let mut invalid = baseline.clone();
        invalid.device_alias = "Device-X".to_string();
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("device_alias"))
        ));
        let mut invalid = baseline.clone();
        invalid.source_artifact_git_sha1 = ByteBuf::from(vec![0xaa; 19]);
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "source_artifact_git_sha1"
            ))
        ));
        let mut invalid = baseline;
        invalid.server_nonce = ByteBuf::from(vec![0xee; 33]);
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("server_nonce"))
        ));
    }

    #[test]
    fn mobile_claw_vpn_context_requires_exact_operation_specific_hash() {
        let context = sample_mobile_claw_vpn_context();
        let expected_hash = sample_mobile_claw_vpn_execution().execution_hash().unwrap();
        assert_eq!(
            context
                .mobile_claw_vpn_execution_hash
                .as_ref()
                .unwrap()
                .as_ref(),
            expected_hash.as_slice()
        );
        assert_eq!(context.capabilities, [MOBILE_CLAW_VPN_DEV_E2E_CAPABILITY]);

        let baseline_challenge = context.challenge_digest().unwrap();
        let mut changed_hash = context.clone();
        changed_hash.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x45; 32]));
        assert_ne!(changed_hash.challenge_digest().unwrap(), baseline_challenge);

        let mut context_mutations = Vec::new();
        let mut mutation = context.clone();
        mutation.hh_id = HouseholdId::parse(format!("hh_{}", "c".repeat(52))).unwrap();
        context_mutations.push(("hh_id", mutation));
        let mut mutation = context.clone();
        mutation.owner_p_id = PersonId("p_owner-beta".to_string());
        context_mutations.push(("owner_p_id", mutation));
        let mut mutation = context.clone();
        mutation.issued_at = 1_001;
        context_mutations.push(("issued_at", mutation));
        let mut mutation = context.clone();
        mutation.expires_at = 1_059;
        context_mutations.push(("expires_at", mutation));
        let mut mutation = context.clone();
        mutation.replay_nonce = ByteBuf::from(vec![0xf1; 32]);
        context_mutations.push(("replay_nonce", mutation));
        for (field, mutation) in context_mutations {
            assert_ne!(
                mutation.challenge_digest().unwrap(),
                baseline_challenge,
                "{field}: owner approval challenge did not change"
            );
        }

        let mut wrong_operation = context.clone();
        wrong_operation.op = OwnerOperation::PairMachineApprove;
        assert!(wrong_operation.to_canonical_bytes().is_err());
        assert!(wrong_operation.challenge_digest().is_err());
        let wrong_operation_bytes = crate::cbor::to_canonical_vec(&wrong_operation).unwrap();
        assert!(
            OwnerApprovalContextV2::from_canonical_bytes(&wrong_operation_bytes).is_err(),
            "cross-op execution hash must fail during canonical decode"
        );

        let mut missing = context.clone();
        missing.mobile_claw_vpn_execution_hash = None;
        assert!(matches!(
            missing.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "mobile_claw_vpn_execution_hash"
            ))
        ));
        assert!(missing.to_canonical_bytes().is_err());
        let missing_bytes = crate::cbor::to_canonical_vec(&missing).unwrap();
        assert!(
            OwnerApprovalContextV2::from_canonical_bytes(&missing_bytes).is_err(),
            "execute without tuple hash must fail during canonical decode"
        );

        for length in [31, 33] {
            let mut invalid = context.clone();
            invalid.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x44; length]));
            assert!(matches!(
                invalid.validate_shape(),
                Err(OwnerApprovalV2Error::InvalidField(
                    "mobile_claw_vpn_execution_hash"
                ))
            ));
            assert!(invalid.to_canonical_bytes().is_err());
            let invalid_bytes = crate::cbor::to_canonical_vec(&invalid).unwrap();
            assert!(
                OwnerApprovalContextV2::from_canonical_bytes(&invalid_bytes).is_err(),
                "{length}-byte execution hash must fail during canonical decode"
            );
        }

        let mut zero_ttl = context.clone();
        zero_ttl.expires_at = zero_ttl.issued_at;
        assert!(matches!(
            zero_ttl.challenge_digest(),
            Err(OwnerApprovalV2Error::InvalidTimeWindow)
        ));
        let mut excessive_ttl = context.clone();
        excessive_ttl.expires_at = excessive_ttl.issued_at + 121;
        assert!(matches!(
            excessive_ttl.challenge_digest(),
            Err(OwnerApprovalV2Error::InvalidTimeWindow)
        ));

        let mut invalid_household = context.clone();
        invalid_household.hh_id = HouseholdId("hh_test".to_string());
        assert!(matches!(
            invalid_household.challenge_digest(),
            Err(OwnerApprovalV2Error::InvalidField("hh_id"))
        ));
        let mut invalid_owner = context.clone();
        invalid_owner.owner_p_id = PersonId("owner-alpha".to_string());
        assert!(matches!(
            invalid_owner.challenge_digest(),
            Err(OwnerApprovalV2Error::InvalidField("owner_p_id"))
        ));

        let mut injected = sample_context();
        injected.mobile_claw_vpn_execution_hash = Some(ByteBuf::from(vec![0x44; 32]));
        assert!(matches!(
            injected.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "mobile_claw_vpn_execution_hash"
            ))
        ));
    }

    #[test]
    fn pair_machine_required_fields_are_enforced() {
        let mut missing = sample_context();
        missing.join_request_hash = None;
        assert!(matches!(
            missing.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("join_request_hash"))
        ));
    }

    #[test]
    fn pair_machine_rejects_revoke_fields() {
        let mut invalid = sample_context();
        invalid.target_credential_id = Some(ByteBuf::from(vec![0x41]));
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "target_credential_id"
            ))
        ));
    }

    #[test]
    fn revoke_credential_context_round_trips_as_canonical_cbor() {
        let ctx = sample_revoke_context();
        let bytes = ctx.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, ctx);

        let hex = hex::encode(&bytes);
        assert!(hex.contains("717265766f6b652d63726564656e7469616c"));
        assert!(hex.contains("747461726765745f63726564656e7469616c5f696448414145436750395f"));
        assert!(
            !hex.contains("6461646472"),
            "revoke context must not carry pair-machine addr",
        );
        assert!(
            !hex.contains("716a6f696e5f726571756573745f68617368"),
            "revoke context must not carry pair-machine join_request_hash",
        );
    }

    #[test]
    fn revoke_credential_required_fields_are_enforced() {
        let mut missing_target = sample_revoke_context();
        missing_target.target_credential_id = None;
        assert!(matches!(
            missing_target.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("target_credential_id"))
        ));

        let mut missing_sequence = sample_revoke_context();
        missing_sequence.authority_head_sequence = None;
        assert!(matches!(
            missing_sequence.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "authority_head_sequence"
            ))
        ));

        let mut missing_hash = sample_revoke_context();
        missing_hash.authority_head_hash = None;
        assert!(matches!(
            missing_hash.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
        ));

        let mut missing_count = sample_revoke_context();
        missing_count.pre_active_credential_count = None;
        assert!(matches!(
            missing_count.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "pre_active_credential_count"
            ))
        ));
    }

    #[test]
    fn revoke_credential_rejects_invalid_field_values() {
        let mut empty_target = sample_revoke_context();
        empty_target.target_credential_id = Some(ByteBuf::from(vec![]));
        assert!(matches!(
            empty_target.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("target_credential_id"))
        ));

        let mut short_hash = sample_revoke_context();
        short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
        assert!(matches!(
            short_hash.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
        ));

        let mut zero_count = sample_revoke_context();
        zero_count.pre_active_credential_count = Some(0);
        assert!(matches!(
            zero_count.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "pre_active_credential_count"
            ))
        ));
    }

    #[test]
    fn revoke_credential_rejects_pair_machine_fields() {
        let mut invalid = sample_revoke_context();
        invalid.cursor = Some(7);
        assert!(matches!(
            invalid.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
        ));
    }

    #[test]
    fn provision_recovery_code_context_round_trips_as_canonical_cbor() {
        let ctx = sample_provision_recovery_context();
        let bytes = ctx.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, ctx);

        let hex = hex::encode(&bytes);
        assert!(hex.contains("7770726f766973696f6e2d7265636f766572792d636f6465"));
        assert!(hex.contains("727265636f766572795f686561645f686173685820"));
        assert!(
            !hex.contains("747461726765745f63726564656e7469616c5f6964"),
            "provision recovery context must not carry revoke target",
        );
        assert!(
            !hex.contains("716a6f696e5f726571756573745f68617368"),
            "provision recovery context must not carry pair-machine join_request_hash",
        );
    }

    #[test]
    fn provision_recovery_code_required_fields_are_enforced() {
        let mut missing_sequence = sample_provision_recovery_context();
        missing_sequence.authority_head_sequence = None;
        assert!(matches!(
            missing_sequence.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "authority_head_sequence"
            ))
        ));

        let mut missing_hash = sample_provision_recovery_context();
        missing_hash.authority_head_hash = None;
        assert!(matches!(
            missing_hash.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
        ));

        let mut missing_count = sample_provision_recovery_context();
        missing_count.pre_active_credential_count = None;
        assert!(matches!(
            missing_count.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "pre_active_credential_count"
            ))
        ));
    }

    #[test]
    fn provision_recovery_code_rejects_invalid_values_and_foreign_fields() {
        let mut short_hash = sample_provision_recovery_context();
        short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
        assert!(matches!(
            short_hash.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
        ));

        let mut zero_count = sample_provision_recovery_context();
        zero_count.pre_active_credential_count = Some(0);
        assert!(matches!(
            zero_count.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "pre_active_credential_count"
            ))
        ));

        let mut half_head = sample_provision_recovery_context();
        half_head.recovery_head_hash = None;
        assert!(matches!(
            half_head.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"))
        ));

        let mut with_revoke_field = sample_provision_recovery_context();
        with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
        assert!(matches!(
            with_revoke_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "target_credential_id"
            ))
        ));

        let mut with_pair_field = sample_provision_recovery_context();
        with_pair_field.cursor = Some(7);
        assert!(matches!(
            with_pair_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
        ));
    }

    #[test]
    fn non_recovery_contexts_reject_recovery_fields() {
        let mut pair_machine = sample_context();
        pair_machine.recovery_head_sequence = Some(0);
        assert!(matches!(
            pair_machine.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "recovery_head_sequence"
            ))
        ));

        let mut revoke = sample_revoke_context();
        revoke.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
        assert!(matches!(
            revoke.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
        ));
    }

    #[test]
    fn add_credential_context_round_trips_as_canonical_cbor() {
        let ctx = sample_add_credential_context();
        let bytes = ctx.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, ctx);

        let hex = hex::encode(&bytes);
        assert!(hex.contains("6e6164642d63726564656e7469616c"));
        assert!(hex.contains("781b6e65775f63726564656e7469616c5f62696e64696e675f686173685820"));
        assert!(
            !hex.contains("747461726765745f63726564656e7469616c5f6964"),
            "add credential context must not carry revoke target",
        );
        assert!(
            !hex.contains("727265636f766572795f686561645f68617368"),
            "add credential context must not carry recovery head",
        );
    }

    #[test]
    fn add_credential_required_fields_are_enforced() {
        let mut missing_binding = sample_add_credential_context();
        missing_binding.new_credential_binding_hash = None;
        assert!(matches!(
            missing_binding.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "new_credential_binding_hash"
            ))
        ));

        let mut missing_sequence = sample_add_credential_context();
        missing_sequence.authority_head_sequence = None;
        assert!(matches!(
            missing_sequence.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "authority_head_sequence"
            ))
        ));

        let mut missing_hash = sample_add_credential_context();
        missing_hash.authority_head_hash = None;
        assert!(matches!(
            missing_hash.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
        ));

        let mut missing_count = sample_add_credential_context();
        missing_count.pre_active_credential_count = None;
        assert!(matches!(
            missing_count.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "pre_active_credential_count"
            ))
        ));
    }

    #[test]
    fn add_credential_rejects_invalid_values_and_foreign_fields() {
        let mut short_binding = sample_add_credential_context();
        short_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
        assert!(matches!(
            short_binding.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "new_credential_binding_hash"
            ))
        ));

        let mut short_hash = sample_add_credential_context();
        short_hash.authority_head_hash = Some(ByteBuf::from(vec![0x44; 31]));
        assert!(matches!(
            short_hash.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
        ));

        let mut zero_count = sample_add_credential_context();
        zero_count.pre_active_credential_count = Some(0);
        assert!(matches!(
            zero_count.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "pre_active_credential_count"
            ))
        ));

        let mut with_revoke_field = sample_add_credential_context();
        with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
        assert!(matches!(
            with_revoke_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "target_credential_id"
            ))
        ));

        let mut with_recovery_field = sample_add_credential_context();
        with_recovery_field.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 32]));
        assert!(matches!(
            with_recovery_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("recovery_head_hash"))
        ));

        let mut with_pair_field = sample_add_credential_context();
        with_pair_field.cursor = Some(7);
        assert!(matches!(
            with_pair_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
        ));
    }

    #[test]
    fn non_add_contexts_reject_add_credential_fields() {
        let mut pair_machine = sample_context();
        pair_machine.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
        assert!(matches!(
            pair_machine.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "new_credential_binding_hash"
            ))
        ));

        let mut revoke = sample_revoke_context();
        revoke.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
        assert!(matches!(
            revoke.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "new_credential_binding_hash"
            ))
        ));

        let mut recovery = sample_provision_recovery_context();
        recovery.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 32]));
        assert!(matches!(
            recovery.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "new_credential_binding_hash"
            ))
        ));
    }

    #[test]
    fn recover_credential_context_round_trips_as_canonical_cbor() {
        let ctx = sample_recover_credential_context();
        let bytes = ctx.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalContextV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, ctx);

        let hex = hex::encode(&bytes);
        assert!(hex.contains("727265636f7665722d63726564656e7469616c"));
        assert!(hex.contains("727265636f766572795f686561645f686173685820"));
        assert!(hex.contains("781b6e65775f63726564656e7469616c5f62696e64696e675f686173685820"));
        assert!(
            !hex.contains("747461726765745f63726564656e7469616c5f6964"),
            "recover credential context must not carry revoke target",
        );
        assert!(
            !hex.contains("716a6f696e5f726571756573745f68617368"),
            "recover credential context must not carry pair-machine join_request_hash",
        );
    }

    #[test]
    fn recover_credential_required_fields_are_enforced() {
        let mut missing_binding = sample_recover_credential_context();
        missing_binding.new_credential_binding_hash = None;
        assert!(matches!(
            missing_binding.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "new_credential_binding_hash"
            ))
        ));

        let mut missing_sequence = sample_recover_credential_context();
        missing_sequence.authority_head_sequence = None;
        assert!(matches!(
            missing_sequence.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "authority_head_sequence"
            ))
        ));

        let mut missing_hash = sample_recover_credential_context();
        missing_hash.authority_head_hash = None;
        assert!(matches!(
            missing_hash.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("authority_head_hash"))
        ));

        let mut missing_count = sample_recover_credential_context();
        missing_count.pre_active_credential_count = None;
        assert!(matches!(
            missing_count.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField(
                "pre_active_credential_count"
            ))
        ));

        let mut missing_recovery_sequence = sample_recover_credential_context();
        missing_recovery_sequence.recovery_head_sequence = None;
        assert!(matches!(
            missing_recovery_sequence.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("recovery_head_sequence"))
        ));

        let mut missing_recovery_hash = sample_recover_credential_context();
        missing_recovery_hash.recovery_head_hash = None;
        assert!(matches!(
            missing_recovery_hash.validate_shape(),
            Err(OwnerApprovalV2Error::MissingField("recovery_head_hash"))
        ));
    }

    #[test]
    fn recover_credential_allows_zero_active_count_as_telemetry() {
        let mut context = sample_recover_credential_context();
        context.pre_active_credential_count = Some(0);
        context.validate_shape().unwrap();
    }

    #[test]
    fn recover_credential_rejects_invalid_values_and_foreign_fields() {
        let mut short_binding = sample_recover_credential_context();
        short_binding.new_credential_binding_hash = Some(ByteBuf::from(vec![0x41; 31]));
        assert!(matches!(
            short_binding.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField(
                "new_credential_binding_hash"
            ))
        ));

        let mut short_authority_hash = sample_recover_credential_context();
        short_authority_hash.authority_head_hash = Some(ByteBuf::from(vec![0x66; 31]));
        assert!(matches!(
            short_authority_hash.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("authority_head_hash"))
        ));

        let mut short_recovery_hash = sample_recover_credential_context();
        short_recovery_hash.recovery_head_hash = Some(ByteBuf::from(vec![0x77; 31]));
        assert!(matches!(
            short_recovery_hash.validate_shape(),
            Err(OwnerApprovalV2Error::InvalidField("recovery_head_hash"))
        ));

        let mut with_revoke_field = sample_recover_credential_context();
        with_revoke_field.target_credential_id = Some(ByteBuf::from(vec![0x41]));
        assert!(matches!(
            with_revoke_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField(
                "target_credential_id"
            ))
        ));

        let mut with_pair_field = sample_recover_credential_context();
        with_pair_field.cursor = Some(7);
        assert!(matches!(
            with_pair_field.validate_shape(),
            Err(OwnerApprovalV2Error::UnexpectedField("cursor"))
        ));
    }

    #[test]
    fn expired_context_is_rejected() {
        let ctx = sample_context();
        assert!(matches!(
            ctx.validate_at(1_601),
            Err(OwnerApprovalV2Error::Expired {
                now: 1_601,
                expires_at: 1_600
            })
        ));
    }

    #[test]
    fn capabilities_must_be_sorted_and_unique() {
        let mut unsorted = sample_context();
        unsorted.capabilities = vec!["shamir-2pc".to_string(), "machine-cert".to_string()];
        assert!(matches!(
            unsorted.validate_shape(),
            Err(OwnerApprovalV2Error::CapabilitiesNotSorted)
        ));

        let mut duplicate = sample_context();
        duplicate.capabilities = vec!["machine-cert".to_string(), "machine-cert".to_string()];
        assert!(matches!(
            duplicate.validate_shape(),
            Err(OwnerApprovalV2Error::DuplicateCapability(cap))
                if cap == "machine-cert"
        ));
    }

    #[test]
    fn none_fields_are_omitted_for_non_pair_machine_operations() {
        let ctx = OwnerApprovalContextV2 {
            version: OWNER_APPROVAL_V2_VERSION,
            purpose: OWNER_APPROVAL_V2_PURPOSE.to_string(),
            op: OwnerOperation::BootstrapTeardown,
            hh_id: household_id(),
            owner_p_id: person_id(),
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
            mobile_claw_vpn_execution_hash: None,
            capabilities: vec![],
            issued_at: 1_000,
            expires_at: 1_100,
            replay_nonce: ByteBuf::from(vec![0x77; 32]),
        };

        let bytes = ctx.to_canonical_bytes().unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("context encodes as map");
        };
        let keys: Vec<String> = entries
            .into_iter()
            .map(|(key, _)| match key {
                ciborium::value::Value::Text(text) => text,
                other => panic!("unexpected key: {other:?}"),
            })
            .collect();

        for omitted in [
            "cursor",
            "m_id",
            "addr",
            "transport",
            "ttl_unix",
            "nonce",
            "join_request_hash",
            "target_credential_id",
            "authority_head_sequence",
            "authority_head_hash",
            "pre_active_credential_count",
        ] {
            assert!(!keys.iter().any(|key| key == omitted), "{omitted} encoded");
        }
    }

    #[test]
    fn owner_approval_body_requires_expected_context_byte_equality() {
        let expected = sample_context();
        let approval = sample_approval(expected.clone());
        assert_eq!(
            approval.require_expected_context(&expected).unwrap(),
            expected.challenge_digest().unwrap()
        );

        let mut tampered = expected.clone();
        tampered.addr = Some("198.51.100.10:8091".to_string());
        let err = approval.require_expected_context(&tampered).unwrap_err();
        assert!(matches!(err, OwnerApprovalV2Error::ContextMismatch));
    }

    #[test]
    fn owner_approval_body_rejects_empty_assertion_fields() {
        let mut approval = sample_approval(sample_context());
        approval.signature = ByteBuf::from(vec![]);
        assert!(matches!(
            approval.validate_shape(),
            Err(OwnerApprovalV2Error::AssertionField("signature"))
        ));
    }

    #[test]
    fn owner_approval_body_converts_to_webauthn_public_key_credential() {
        let mut rp = owner_webauthn_rp();
        let mut rng = StdRng::seed_from_u64(61);
        let (mut credential, mut authenticator) = register_softpasskey(&mut rp, &mut rng);
        let expected_context = sample_context();

        let (challenge_id, challenge) = rp
            .start_owner_approval_assertion(
                &mut rng,
                NOW + 1,
                &[credential.clone()],
                &expected_context,
            )
            .unwrap();
        let assertion = authenticator
            .do_authentication(Url::parse("https://alpha.example.test").unwrap(), challenge)
            .unwrap();
        let approval = approval_from_assertion(expected_context.clone(), &assertion);

        let converted = approval.to_public_key_credential().unwrap();
        assert_eq!(
            converted.id,
            data_encoding::BASE64URL_NOPAD.encode(approval.credential_id.as_ref())
        );
        assert_eq!(converted.type_, "public-key");
        assert_eq!(converted.raw_id.as_slice(), assertion.raw_id.as_slice());
        assert_eq!(
            converted.response.authenticator_data.as_slice(),
            assertion.response.authenticator_data.as_slice()
        );
        assert_eq!(
            converted.response.client_data_json.as_slice(),
            assertion.response.client_data_json.as_slice()
        );
        assert_eq!(
            converted.response.signature.as_slice(),
            assertion.response.signature.as_slice()
        );
        assert_eq!(
            converted
                .response
                .user_handle
                .as_ref()
                .map(|user_handle| user_handle.as_slice()),
            assertion
                .response
                .user_handle
                .as_ref()
                .map(|user_handle| user_handle.as_slice())
        );

        rp.finish_owner_approval_assertion(
            NOW + 1,
            &challenge_id,
            &converted,
            &mut credential,
            &expected_context,
        )
        .unwrap();
    }

    #[test]
    fn owner_approval_body_omits_absent_user_handle() {
        let approval = sample_approval(sample_context());
        let bytes = approval.to_canonical_bytes().unwrap();
        let decoded = OwnerApprovalV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, approval);

        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("approval body encodes as map");
        };
        let keys: Vec<String> = entries
            .into_iter()
            .map(|(key, _)| match key {
                ciborium::value::Value::Text(text) => text,
                other => panic!("unexpected key: {other:?}"),
            })
            .collect();
        assert!(
            !keys.iter().any(|key| key == "user_handle"),
            "user_handle encoded"
        );
    }

    #[test]
    fn pair_machine_context_uses_trusted_snapshot_and_cached_join_request() {
        let (_kp, request, request_bytes) = signed_join_request();
        let snapshot = awaiting_owner_snapshot(&request, &request_bytes);
        let ctx = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
            PairMachineTrustedContextInput {
                hh_id: household_id(),
                owner_p_id: person_id(),
                snapshot: &snapshot,
                capabilities: vec!["machine-cert".into(), "shamir-2pc".into()],
                issued_at: 1_000,
                challenge_ttl_secs: 120,
                replay_nonce: [0x55; 32],
            },
        )
        .unwrap();

        assert_eq!(ctx.cursor, Some(7));
        assert_eq!(ctx.addr.as_deref(), Some("192.0.2.10:8091"));
        assert_eq!(ctx.transport, Some(JoinTransport::Lan));
        assert_eq!(ctx.ttl_unix, Some(1_600));
        assert_eq!(ctx.expires_at, 1_120);
        assert_eq!(
            ctx.join_request_hash.as_ref().map(ByteBuf::as_ref),
            Some(join_request_hash(&request_bytes).as_slice())
        );
        assert_eq!(
            ctx.nonce.as_ref().map(ByteBuf::as_ref),
            Some(request.nonce.as_ref())
        );
    }

    #[test]
    fn pair_machine_context_rejects_snapshot_request_mismatch() {
        let (_kp, request, request_bytes) = signed_join_request();
        let mut snapshot = awaiting_owner_snapshot(&request, &request_bytes);
        snapshot.addr_hint = Some("198.51.100.10:8091".into());

        let err = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
            PairMachineTrustedContextInput {
                hh_id: household_id(),
                owner_p_id: person_id(),
                snapshot: &snapshot,
                capabilities: vec!["machine-cert".into()],
                issued_at: 1_000,
                challenge_ttl_secs: 120,
                replay_nonce: [0x55; 32],
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("addr mismatch")
        ));
    }

    #[test]
    fn pair_machine_context_requires_awaiting_owner_window() {
        let (_kp, request, request_bytes) = signed_join_request();
        let mut snapshot = awaiting_owner_snapshot(&request, &request_bytes);
        snapshot.state = PairMachineState::Staging;

        let err = OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
            PairMachineTrustedContextInput {
                hh_id: household_id(),
                owner_p_id: person_id(),
                snapshot: &snapshot,
                capabilities: vec!["machine-cert".into()],
                issued_at: 1_000,
                challenge_ttl_secs: 120,
                replay_nonce: [0x55; 32],
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("window not awaiting owner")
        ));
    }
}
