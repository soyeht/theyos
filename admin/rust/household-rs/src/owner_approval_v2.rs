//! Owner approval Protocol-v2 primitives.
//!
//! This module is intentionally inert: it defines the signed context and
//! `WebAuthn` challenge binding used by S2, but does not enforce it on any
//! endpoint yet.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
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
            capabilities: input.capabilities,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            replay_nonce: ByteBuf::from(input.replay_nonce.to_vec()),
        }
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
            }
            OwnerOperation::RevokeCredential => {
                self.require_absent_pair_machine_fields()?;
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
            OwnerOperation::BootstrapInitialize
            | OwnerOperation::BootstrapTeardown
            | OwnerOperation::PairDeviceConfirm => {
                self.require_absent_pair_machine_fields()?;
                self.require_absent_revoke_fields()?;
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
