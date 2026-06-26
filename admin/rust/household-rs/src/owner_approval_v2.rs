//! Owner approval Protocol-v2 primitives.
//!
//! This module is intentionally inert: it defines the signed context and
//! WebAuthn challenge binding used by S2, but does not enforce it on any
//! endpoint yet.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::HouseholdError;
use crate::ids::{HouseholdId, MachineId};
use crate::machine_cert::PersonId;
use crate::pair_machine::JoinTransport;

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
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: ByteBuf,
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

        if self.op == OwnerOperation::PairMachineApprove {
            require_some(self.cursor, "cursor")?;
            require_some(self.m_id.as_ref(), "m_id")?;
            require_some(self.addr.as_ref(), "addr")?;
            require_some(self.transport, "transport")?;
            require_some(self.ttl_unix, "ttl_unix")?;
            require_some(self.nonce.as_ref(), "nonce")?;
            require_some(self.join_request_hash.as_ref(), "join_request_hash")?;
        }
        Ok(())
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

fn require_some<T>(value: Option<T>, field: &'static str) -> Result<(), OwnerApprovalV2Error> {
    if value.is_some() {
        Ok(())
    } else {
        Err(OwnerApprovalV2Error::MissingField(field))
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
        ] {
            assert!(!keys.iter().any(|key| key == omitted), "{omitted} encoded");
        }
    }
}
