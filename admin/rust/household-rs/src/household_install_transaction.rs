//! Durable transaction boundary for a Pair-Machine candidate installing a
//! previously absent household.
//!
//! The transaction breadcrumb lives in the stable state root, not below
//! `household/`.  It binds the candidate lifecycle generation and the exact
//! canonical `household_record.cbor` bytes that will be the install commit
//! marker.  Directory visibility is never used as commit evidence.
//!
//! A caller must hold the same [`LifecycleWriteGuard`] from `begin` through its
//! staging attempt.  Restart recovery reacquires lifecycle-exclusive, reads the
//! breadcrumb, and decides from the exact commit marker:
//!
//! - marker absent at the recorded generation: partial install, rollback only;
//! - marker byte-identical and required artifacts valid: terminally rotate the
//!   generation, then durably clear the breadcrumb;
//! - any mismatch: quarantine/fail closed.
//!
//! A successful install also retains one bounded latest-install-only finalize
//! result in the stable root. Its `Prepared` form (request fingerprint,
//! identity, and exact canonical Ack) is durable before G0 rotates; its `Final`
//! form additionally binds G1. The breadcrumb cannot be cleared until that
//! final record is durable. Ack delivery never deletes the result, so an exact
//! retry after restart returns the retained bytes instead of reinstalling or
//! rotating again. A later lifecycle generation makes the old result inactive.
//!
//! As with the lifecycle lock itself, directory-entry exclusion assumes the
//! state directory's same-UID participants cooperate through this crate.  A
//! same-UID process that mutates entries directly is a deployment violation,
//! not an attacker this pathname-based transaction can exclude.

use std::fs::File;
use std::io::{Read, Write};

use rand::{RngCore, rngs::OsRng};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::household_lifecycle::{
    HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError, LifecycleWriteGuard,
};
use crate::household_record::HouseholdRecord;
use crate::ids::{HouseholdId, MachineId, derive_machine_id};
use crate::keys::P256PublicKey;

/// Stable state-root breadcrumb for a Pair-Machine candidate install.
pub const HOUSEHOLD_INSTALL_TRANSACTION_FILENAME: &str = ".household-install-transaction-v1.cbor";
/// Bounded latest-install-only terminal result retained for exact retries.
pub const HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME: &str =
    ".household-install-finalize-terminal-v1.cbor";
/// Latest-install-only evidence that returning the exact retained Ack may
/// already have affected the peer and must therefore be replayed, never
/// reconstructed or treated as a fresh install.
pub const HOUSEHOLD_INSTALL_FINALIZE_DELIVERY_FILENAME: &str =
    ".household-install-finalize-delivery-v1.cbor";

const TRANSACTION_VERSION: u8 = 1;
const TRANSACTION_KIND: &str = "soyeht/pair-machine-candidate-install/v1";
const TRANSACTION_TMP_PREFIX: &str = ".household-install-transaction-v1.tmp.";
const TERMINAL_RESULT_VERSION: u8 = 1;
const TERMINAL_RESULT_KIND: &str = "soyeht/pair-machine-finalize-terminal/v1";
const TERMINAL_RESULT_TMP_PREFIX: &str = ".household-install-finalize-terminal-v1.tmp.";
const DELIVERY_RECORD_VERSION: u8 = 1;
const DELIVERY_RECORD_KIND: &str = "soyeht/pair-machine-finalize-delivery/v1";
const DELIVERY_RECORD_TMP_PREFIX: &str = ".household-install-finalize-delivery-v1.tmp.";
const MAX_TRANSACTION_BYTES: u64 = 1 << 20;
const MAX_TERMINAL_RESULT_BYTES: u64 = 1 << 20;
const MAX_DELIVERY_RECORD_BYTES: u64 = 2 << 20;
const MAX_COMMIT_MARKER_BYTES: usize = 1 << 20;
const MAX_FINALIZE_ACK_BYTES: usize = 1 << 20;
const MAX_JOIN_REQUEST_BYTES: usize = 1 << 20;

/// Failure while establishing, recovering, or terminalizing an install.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HouseholdInstallTransactionError {
    #[error("household lifecycle operation failed: {0}")]
    Lifecycle(#[from] HouseholdLifecycleLockError),
    #[error("household install transaction I/O failed")]
    Io,
    #[error("household install transaction state is malformed or mismatched")]
    Quarantined,
    #[error("a household install transaction already requires recovery")]
    RecoveryRequired,
    #[error("the candidate lifecycle generation is no longer current")]
    CandidateGenerationChanged,
    #[error("canonical household authority already exists")]
    HouseholdAlreadyInstalled,
    #[error("the canonical household commit marker is absent; rollback is required")]
    CommitMarkerAbsent,
    #[error("the canonical household commit marker differs from the transaction")]
    CommitMarkerMismatch,
    #[error("required install artifacts failed validation: {0}")]
    RequiredArtifactsInvalid(String),
    #[error("the committed install needs lifecycle-rotation recovery")]
    TerminalRotationNeedsRecovery,
    #[error("the terminally rotated install needs breadcrumb cleanup recovery")]
    TerminalCleanupNeedsRecovery,
    #[error("the committed install needs terminal-result publication recovery")]
    TerminalResultPublicationNeedsRecovery,
    #[error("the rotated install needs terminal-result finalization recovery")]
    TerminalResultFinalizationNeedsRecovery,
    #[error("breadcrumb publication may have taken effect and requires recovery")]
    BreadcrumbPublicationNeedsRecovery,
    #[error("finalize Ack delivery breadcrumb may have taken effect and requires exact recovery")]
    FinalizeAckDeliveryMayHaveTakenEffect,
}

/// BLAKE3-256 of the exact canonical finalize request body.
///
/// It identifies the request/transaction whose retained Ack may be replayed;
/// it is not household authority by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeRequestFingerprintV1([u8; 32]);

impl FinalizeRequestFingerprintV1 {
    #[must_use]
    pub fn for_canonical_request_bytes(bytes: &[u8]) -> Self {
        Self(marker_digest(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact Ack material committed into both the install breadcrumb and terminal
/// result before any household staging write begins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeTerminalIntent {
    request_fingerprint: FinalizeRequestFingerprintV1,
    join_request_bytes: Vec<u8>,
    ack_version: u8,
    ack_m_id: MachineId,
    ack_machine_cert_hash: [u8; 32],
    ack_bytes: Vec<u8>,
}

impl FinalizeTerminalIntent {
    /// Validate and retain an exact canonical [`crate::pair_machine::FinalizeAck`].
    pub fn from_exact_ack_bytes(
        request_fingerprint: FinalizeRequestFingerprintV1,
        expected_m_id: &MachineId,
        exact_join_request_bytes: &[u8],
        exact_ack_bytes: &[u8],
    ) -> Result<Self, HouseholdInstallTransactionError> {
        if exact_join_request_bytes.is_empty()
            || exact_join_request_bytes.len() > MAX_JOIN_REQUEST_BYTES
            || exact_ack_bytes.is_empty()
            || exact_ack_bytes.len() > MAX_FINALIZE_ACK_BYTES
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let join_request: crate::pair_machine::JoinRequest =
            crate::cbor::from_canonical_slice_strict(exact_join_request_bytes)
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        crate::pair_machine::verify_join_request(&join_request)
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let m_pub: [u8; 33] = join_request
            .m_pub
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let m_pub = P256PublicKey::from_bytes(&m_pub)
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        if &derive_machine_id(&m_pub) != expected_m_id {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let ack: crate::pair_machine::FinalizeAck =
            crate::cbor::from_canonical_slice_strict(exact_ack_bytes)
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let ack_m_id = MachineId::parse(&ack.m_id)
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let ack_machine_cert_hash: [u8; 32] = ack
            .machine_cert_hash
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        if ack.version != crate::pair_machine::PAIR_MACHINE_VERSION || &ack_m_id != expected_m_id {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        Ok(Self {
            request_fingerprint,
            join_request_bytes: exact_join_request_bytes.to_vec(),
            ack_version: ack.version,
            ack_m_id,
            ack_machine_cert_hash,
            ack_bytes: exact_ack_bytes.to_vec(),
        })
    }

    #[must_use]
    pub const fn request_fingerprint(&self) -> FinalizeRequestFingerprintV1 {
        self.request_fingerprint
    }

    /// Exact canonical request that created the candidate G0 window.
    ///
    /// These bytes are anchored in the stable transaction before G0 rotates,
    /// so a cold G1 process never has to rediscover a listener coordinate or
    /// trust a generation directory that rotation has already swept.
    #[must_use]
    pub fn join_request_bytes(&self) -> &[u8] {
        &self.join_request_bytes
    }

    #[must_use]
    pub fn ack_bytes(&self) -> &[u8] {
        &self.ack_bytes
    }
}

/// Durable, final latest-install result suitable for a byte-identical retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeTerminalResult {
    request_fingerprint: FinalizeRequestFingerprintV1,
    join_request_bytes: Vec<u8>,
    candidate_generation: HouseholdLifecycleGenerationV1,
    terminal_generation: HouseholdLifecycleGenerationV1,
    hh_id: HouseholdId,
    m_id: MachineId,
    commit_marker_blake3_256: [u8; 32],
    ack_version: u8,
    ack_m_id: MachineId,
    ack_machine_cert_hash: [u8; 32],
    ack_bytes: Vec<u8>,
}

impl FinalizeTerminalResult {
    #[must_use]
    pub const fn request_fingerprint(&self) -> &FinalizeRequestFingerprintV1 {
        &self.request_fingerprint
    }

    /// Exact canonical JoinRequest durably anchored before lifecycle rotation.
    #[must_use]
    pub fn join_request_bytes(&self) -> &[u8] {
        &self.join_request_bytes
    }

    #[must_use]
    pub const fn terminal_generation(&self) -> &HouseholdLifecycleGenerationV1 {
        &self.terminal_generation
    }

    #[must_use]
    pub const fn hh_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub const fn m_id(&self) -> &MachineId {
        &self.m_id
    }

    #[must_use]
    pub const fn ack_version(&self) -> u8 {
        self.ack_version
    }

    #[must_use]
    pub const fn ack_m_id(&self) -> &MachineId {
        &self.ack_m_id
    }

    #[must_use]
    pub const fn ack_machine_cert_hash(&self) -> &[u8; 32] {
        &self.ack_machine_cert_hash
    }

    /// Exact canonical Ack bytes retained across process restart and delivery
    /// failure. They are never reconstructed on retry.
    #[must_use]
    pub fn ack_bytes(&self) -> &[u8] {
        &self.ack_bytes
    }
}

/// Lookup result for an exact retry under lifecycle-exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeTerminalLookupOutcome {
    /// No result is active for the current lifecycle generation and canonical
    /// household identity. A stale result from an older install is inactive.
    Absent,
    /// The active result exactly matches the supplied request and identity.
    Exact(Box<FinalizeTerminalResult>),
    /// An active result exists for this identity/generation, but the supplied
    /// fingerprint or expected identity diverges. No Ack is disclosed.
    Divergent,
}

/// Durable classification of the exact retained Ack delivery cut.
///
/// There is deliberately no `Delivered` variant. A local body poll, socket
/// write, or successful HTTP response is not proof that the peer processed the
/// Ack. Once this breadcrumb exists, restart recovery conservatively remains
/// `MayHaveTakenEffect` and serves only the byte-identical retained result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeAckDeliveryRecoveryOutcome {
    /// No delivery attempt has crossed the named durable boundary yet.
    Absent,
    /// The exact retained result may already have reached the peer.
    MayHaveTakenEffect(Box<FinalizeTerminalResult>),
}

/// Error returned by the caller's exact required-artifact validator.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{detail}")]
pub struct RequiredInstallArtifactsError {
    detail: String,
}

impl RequiredInstallArtifactsError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Closed expectation recovered from the durable transaction breadcrumb.
///
/// This value is descriptive, not a filesystem capability.  Every mutating
/// operation rereads the breadcrumb and the lifecycle generation while the
/// caller retains lifecycle-exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HouseholdInstallExpectation {
    candidate_generation: HouseholdLifecycleGenerationV1,
    terminal_generation: HouseholdLifecycleGenerationV1,
    expected_hh_id: HouseholdId,
    expected_m_id: MachineId,
    commit_marker_blake3_256: [u8; 32],
    commit_marker_bytes: Vec<u8>,
    terminal_intent: FinalizeTerminalIntent,
}

impl HouseholdInstallExpectation {
    #[must_use]
    pub const fn candidate_generation(&self) -> HouseholdLifecycleGenerationV1 {
        self.candidate_generation
    }

    /// Exact successor token reserved before any install staging begins.
    #[must_use]
    pub const fn terminal_generation(&self) -> HouseholdLifecycleGenerationV1 {
        self.terminal_generation
    }

    #[must_use]
    pub const fn expected_hh_id(&self) -> &HouseholdId {
        &self.expected_hh_id
    }

    #[must_use]
    pub const fn expected_m_id(&self) -> &MachineId {
        &self.expected_m_id
    }

    #[must_use]
    pub const fn commit_marker_blake3_256(&self) -> &[u8; 32] {
        &self.commit_marker_blake3_256
    }

    /// Exact canonical bytes that must occupy `household_record.cbor`.
    #[must_use]
    pub fn commit_marker_bytes(&self) -> &[u8] {
        &self.commit_marker_bytes
    }

    #[must_use]
    pub const fn terminal_intent(&self) -> &FinalizeTerminalIntent {
        &self.terminal_intent
    }
}

/// Rollback ticket returned only when the exact canonical commit marker is
/// absent and the candidate generation is still current.
#[derive(Debug)]
pub struct HouseholdInstallRollbackTicket {
    expectation: HouseholdInstallExpectation,
}

impl HouseholdInstallRollbackTicket {
    #[must_use]
    pub const fn expectation(&self) -> &HouseholdInstallExpectation {
        &self.expectation
    }
}

/// Result of boot/retry recovery under lifecycle-exclusive.
#[derive(Debug)]
pub enum HouseholdInstallRecoveryOutcome {
    NotApplicable,
    PartialNeedsRollback(HouseholdInstallRollbackTicket),
    RotatedAndCleared {
        generation: HouseholdLifecycleGenerationV1,
        terminal_result: FinalizeTerminalResult,
    },
    AlreadyRotatedAndCleared {
        generation: HouseholdLifecycleGenerationV1,
        terminal_result: FinalizeTerminalResult,
    },
}

/// Result of terminalizing the successful attempt that created the breadcrumb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HouseholdInstallFinalizeOutcome {
    RotatedAndCleared {
        generation: HouseholdLifecycleGenerationV1,
        terminal_result: FinalizeTerminalResult,
    },
    AlreadyRotatedAndCleared {
        generation: HouseholdLifecycleGenerationV1,
        terminal_result: FinalizeTerminalResult,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HouseholdInstallBreadcrumbV1 {
    version: u8,
    kind: String,
    candidate_generation: ByteBuf,
    terminal_generation: ByteBuf,
    expected_hh_id: HouseholdId,
    expected_m_id: MachineId,
    commit_marker_blake3_256: ByteBuf,
    commit_marker_bytes: ByteBuf,
    request_fingerprint_blake3_256: ByteBuf,
    join_request_bytes: ByteBuf,
    ack_version: u8,
    ack_m_id: MachineId,
    ack_machine_cert_hash: ByteBuf,
    ack_bytes: ByteBuf,
}

impl HouseholdInstallBreadcrumbV1 {
    fn from_expectation(expectation: &HouseholdInstallExpectation) -> Self {
        Self {
            version: TRANSACTION_VERSION,
            kind: TRANSACTION_KIND.to_string(),
            candidate_generation: ByteBuf::from(
                expectation.candidate_generation.token_bytes().to_vec(),
            ),
            terminal_generation: ByteBuf::from(
                expectation.terminal_generation.token_bytes().to_vec(),
            ),
            expected_hh_id: expectation.expected_hh_id.clone(),
            expected_m_id: expectation.expected_m_id.clone(),
            commit_marker_blake3_256: ByteBuf::from(expectation.commit_marker_blake3_256.to_vec()),
            commit_marker_bytes: ByteBuf::from(expectation.commit_marker_bytes.clone()),
            request_fingerprint_blake3_256: ByteBuf::from(
                expectation.terminal_intent.request_fingerprint.0.to_vec(),
            ),
            join_request_bytes: ByteBuf::from(
                expectation.terminal_intent.join_request_bytes.clone(),
            ),
            ack_version: expectation.terminal_intent.ack_version,
            ack_m_id: expectation.terminal_intent.ack_m_id.clone(),
            ack_machine_cert_hash: ByteBuf::from(
                expectation.terminal_intent.ack_machine_cert_hash.to_vec(),
            ),
            ack_bytes: ByteBuf::from(expectation.terminal_intent.ack_bytes.clone()),
        }
    }

    fn into_expectation(
        self,
    ) -> Result<HouseholdInstallExpectation, HouseholdInstallTransactionError> {
        if self.version != TRANSACTION_VERSION
            || self.kind != TRANSACTION_KIND
            || !HouseholdId::is_well_formed(self.expected_hh_id.as_str())
            || !MachineId::is_well_formed(self.expected_m_id.as_str())
            || self.commit_marker_bytes.is_empty()
            || self.commit_marker_bytes.len() > MAX_COMMIT_MARKER_BYTES
            || self.join_request_bytes.is_empty()
            || self.join_request_bytes.len() > MAX_JOIN_REQUEST_BYTES
            || self.ack_bytes.is_empty()
            || self.ack_bytes.len() > MAX_FINALIZE_ACK_BYTES
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let candidate_generation =
            HouseholdLifecycleGenerationV1::from_token_bytes(self.candidate_generation.as_ref())
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let terminal_generation =
            HouseholdLifecycleGenerationV1::from_token_bytes(self.terminal_generation.as_ref())
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        if terminal_generation == candidate_generation {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let commit_marker_blake3_256: [u8; 32] = self
            .commit_marker_blake3_256
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let request_fingerprint: [u8; 32] = self
            .request_fingerprint_blake3_256
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let ack_machine_cert_hash: [u8; 32] = self
            .ack_machine_cert_hash
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        if marker_digest(self.commit_marker_bytes.as_ref()) != commit_marker_blake3_256 {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let record: HouseholdRecord =
            crate::cbor::from_canonical_slice_strict(self.commit_marker_bytes.as_ref())
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        record
            .validate()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        if record.hh_id != self.expected_hh_id
            || !record
                .members
                .iter()
                .any(|member| member == &self.expected_m_id)
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let terminal_intent = FinalizeTerminalIntent::from_exact_ack_bytes(
            FinalizeRequestFingerprintV1(request_fingerprint),
            &self.expected_m_id,
            self.join_request_bytes.as_ref(),
            self.ack_bytes.as_ref(),
        )?;
        if terminal_intent.ack_version != self.ack_version
            || terminal_intent.ack_m_id != self.ack_m_id
            || terminal_intent.ack_machine_cert_hash != ack_machine_cert_hash
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        Ok(HouseholdInstallExpectation {
            candidate_generation,
            terminal_generation,
            expected_hh_id: self.expected_hh_id,
            expected_m_id: self.expected_m_id,
            commit_marker_blake3_256,
            commit_marker_bytes: self.commit_marker_bytes.into_vec(),
            terminal_intent,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FinalizeTerminalPhaseV1 {
    Prepared,
    Final,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FinalizeAckDeliveryClassificationV1 {
    MayHaveTakenEffect,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FinalizeAckDeliveryRecordV1 {
    version: u8,
    kind: String,
    classification: FinalizeAckDeliveryClassificationV1,
    terminal_result: FinalizeTerminalResultRecordV1,
}

impl FinalizeAckDeliveryRecordV1 {
    fn may_have_taken_effect(terminal: &FinalizeTerminalResult) -> Self {
        Self {
            version: DELIVERY_RECORD_VERSION,
            kind: DELIVERY_RECORD_KIND.to_string(),
            classification: FinalizeAckDeliveryClassificationV1::MayHaveTakenEffect,
            terminal_result: FinalizeTerminalResultRecordV1::from_final_result(terminal),
        }
    }

    fn validate(self) -> Result<Self, HouseholdInstallTransactionError> {
        if self.version != DELIVERY_RECORD_VERSION || self.kind != DELIVERY_RECORD_KIND {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let terminal_result = self.terminal_result.validate()?;
        if terminal_result.phase != FinalizeTerminalPhaseV1::Final {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        Ok(Self {
            terminal_result,
            ..self
        })
    }

    fn into_terminal_result(
        self,
    ) -> Result<FinalizeTerminalResult, HouseholdInstallTransactionError> {
        self.validate()?.terminal_result.into_final_result()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FinalizeTerminalResultRecordV1 {
    version: u8,
    kind: String,
    phase: FinalizeTerminalPhaseV1,
    request_fingerprint_blake3_256: ByteBuf,
    join_request_bytes: ByteBuf,
    candidate_generation: ByteBuf,
    terminal_generation: Option<ByteBuf>,
    hh_id: HouseholdId,
    m_id: MachineId,
    commit_marker_blake3_256: ByteBuf,
    ack_version: u8,
    ack_m_id: MachineId,
    ack_machine_cert_hash: ByteBuf,
    ack_bytes: ByteBuf,
}

impl FinalizeTerminalResultRecordV1 {
    fn from_final_result(result: &FinalizeTerminalResult) -> Self {
        Self {
            version: TERMINAL_RESULT_VERSION,
            kind: TERMINAL_RESULT_KIND.to_string(),
            phase: FinalizeTerminalPhaseV1::Final,
            request_fingerprint_blake3_256: ByteBuf::from(result.request_fingerprint.0.to_vec()),
            join_request_bytes: ByteBuf::from(result.join_request_bytes.clone()),
            candidate_generation: ByteBuf::from(result.candidate_generation.token_bytes().to_vec()),
            terminal_generation: Some(ByteBuf::from(
                result.terminal_generation.token_bytes().to_vec(),
            )),
            hh_id: result.hh_id.clone(),
            m_id: result.m_id.clone(),
            commit_marker_blake3_256: ByteBuf::from(result.commit_marker_blake3_256.to_vec()),
            ack_version: result.ack_version,
            ack_m_id: result.ack_m_id.clone(),
            ack_machine_cert_hash: ByteBuf::from(result.ack_machine_cert_hash.to_vec()),
            ack_bytes: ByteBuf::from(result.ack_bytes.clone()),
        }
    }

    fn prepared(expectation: &HouseholdInstallExpectation) -> Self {
        Self {
            version: TERMINAL_RESULT_VERSION,
            kind: TERMINAL_RESULT_KIND.to_string(),
            phase: FinalizeTerminalPhaseV1::Prepared,
            request_fingerprint_blake3_256: ByteBuf::from(
                expectation.terminal_intent.request_fingerprint.0.to_vec(),
            ),
            join_request_bytes: ByteBuf::from(
                expectation.terminal_intent.join_request_bytes.clone(),
            ),
            candidate_generation: ByteBuf::from(
                expectation.candidate_generation.token_bytes().to_vec(),
            ),
            terminal_generation: Some(ByteBuf::from(
                expectation.terminal_generation.token_bytes().to_vec(),
            )),
            hh_id: expectation.expected_hh_id.clone(),
            m_id: expectation.expected_m_id.clone(),
            commit_marker_blake3_256: ByteBuf::from(expectation.commit_marker_blake3_256.to_vec()),
            ack_version: expectation.terminal_intent.ack_version,
            ack_m_id: expectation.terminal_intent.ack_m_id.clone(),
            ack_machine_cert_hash: ByteBuf::from(
                expectation.terminal_intent.ack_machine_cert_hash.to_vec(),
            ),
            ack_bytes: ByteBuf::from(expectation.terminal_intent.ack_bytes.clone()),
        }
    }

    fn finalized(
        expectation: &HouseholdInstallExpectation,
        terminal_generation: HouseholdLifecycleGenerationV1,
    ) -> Self {
        debug_assert_eq!(terminal_generation, expectation.terminal_generation);
        let mut record = Self::prepared(expectation);
        record.phase = FinalizeTerminalPhaseV1::Final;
        record.terminal_generation =
            Some(ByteBuf::from(terminal_generation.token_bytes().to_vec()));
        record
    }

    fn validate(self) -> Result<Self, HouseholdInstallTransactionError> {
        if self.version != TERMINAL_RESULT_VERSION
            || self.kind != TERMINAL_RESULT_KIND
            || !HouseholdId::is_well_formed(self.hh_id.as_str())
            || !MachineId::is_well_formed(self.m_id.as_str())
            || self.join_request_bytes.is_empty()
            || self.join_request_bytes.len() > MAX_JOIN_REQUEST_BYTES
            || self.ack_bytes.is_empty()
            || self.ack_bytes.len() > MAX_FINALIZE_ACK_BYTES
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let request_fingerprint: [u8; 32] = self
            .request_fingerprint_blake3_256
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let candidate_generation =
            HouseholdLifecycleGenerationV1::from_token_bytes(self.candidate_generation.as_ref())
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let terminal_generation = match (&self.phase, &self.terminal_generation) {
            (FinalizeTerminalPhaseV1::Prepared | FinalizeTerminalPhaseV1::Final, Some(bytes)) => {
                Some(
                    HouseholdLifecycleGenerationV1::from_token_bytes(bytes.as_ref())
                        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?,
                )
            }
            _ => return Err(HouseholdInstallTransactionError::Quarantined),
        };
        if terminal_generation == Some(candidate_generation) {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let _: [u8; 32] = self
            .commit_marker_blake3_256
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let ack_hash: [u8; 32] = self
            .ack_machine_cert_hash
            .as_ref()
            .try_into()
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let intent = FinalizeTerminalIntent::from_exact_ack_bytes(
            FinalizeRequestFingerprintV1(request_fingerprint),
            &self.m_id,
            self.join_request_bytes.as_ref(),
            self.ack_bytes.as_ref(),
        )?;
        if intent.ack_version != self.ack_version
            || intent.ack_m_id != self.ack_m_id
            || intent.ack_machine_cert_hash != ack_hash
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        Ok(self)
    }

    fn matches_expectation(&self, expectation: &HouseholdInstallExpectation) -> bool {
        self.request_fingerprint_blake3_256.as_ref()
            == expectation.terminal_intent.request_fingerprint.0
            && self.candidate_generation.as_ref() == expectation.candidate_generation.token_bytes()
            && self.terminal_generation.as_ref().map(ByteBuf::as_ref)
                == Some(expectation.terminal_generation.token_bytes().as_slice())
            && self.join_request_bytes.as_ref() == expectation.terminal_intent.join_request_bytes
            && self.hh_id == expectation.expected_hh_id
            && self.m_id == expectation.expected_m_id
            && self.commit_marker_blake3_256.as_ref() == expectation.commit_marker_blake3_256
            && self.ack_version == expectation.terminal_intent.ack_version
            && self.ack_m_id == expectation.terminal_intent.ack_m_id
            && self.ack_machine_cert_hash.as_ref()
                == expectation.terminal_intent.ack_machine_cert_hash
            && self.ack_bytes.as_ref() == expectation.terminal_intent.ack_bytes
    }

    fn into_final_result(self) -> Result<FinalizeTerminalResult, HouseholdInstallTransactionError> {
        let validated = self.validate()?;
        if validated.phase != FinalizeTerminalPhaseV1::Final {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let request_fingerprint = FinalizeRequestFingerprintV1(
            validated
                .request_fingerprint_blake3_256
                .as_ref()
                .try_into()
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?,
        );
        let candidate_generation = HouseholdLifecycleGenerationV1::from_token_bytes(
            validated.candidate_generation.as_ref(),
        )
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        let terminal_generation = HouseholdLifecycleGenerationV1::from_token_bytes(
            validated
                .terminal_generation
                .as_ref()
                .ok_or(HouseholdInstallTransactionError::Quarantined)?
                .as_ref(),
        )
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
        Ok(FinalizeTerminalResult {
            request_fingerprint,
            join_request_bytes: validated.join_request_bytes.into_vec(),
            candidate_generation,
            terminal_generation,
            hh_id: validated.hh_id,
            m_id: validated.m_id,
            commit_marker_blake3_256: validated
                .commit_marker_blake3_256
                .as_ref()
                .try_into()
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?,
            ack_version: validated.ack_version,
            ack_m_id: validated.ack_m_id,
            ack_machine_cert_hash: validated
                .ack_machine_cert_hash
                .as_ref()
                .try_into()
                .map_err(|_| HouseholdInstallTransactionError::Quarantined)?,
            ack_bytes: validated.ack_bytes.into_vec(),
        })
    }
}

/// Durably record intent before the first install staging write.
///
/// `candidate_generation` must be the exact token carried by the candidate
/// pair window.  This function never rotates it.  Rotation is terminal and
/// occurs only after the exact final marker and all required artifacts validate.
pub fn begin_household_install_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
    candidate_generation: HouseholdLifecycleGenerationV1,
    expected_record: &HouseholdRecord,
    expected_m_id: &MachineId,
    terminal_intent: &FinalizeTerminalIntent,
) -> Result<HouseholdInstallExpectation, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    if lifecycle.lifecycle_generation()? != Some(candidate_generation) {
        return Err(HouseholdInstallTransactionError::CandidateGenerationChanged);
    }
    if read_breadcrumb(&state_dir)?.is_some() {
        return Err(HouseholdInstallTransactionError::RecoveryRequired);
    }
    if read_terminal_record(&state_dir)?
        .is_some_and(|record| record.phase == FinalizeTerminalPhaseV1::Prepared)
    {
        // Prepared without its breadcrumb is an impossible torn transaction,
        // not a stale completed result that a new install may replace.
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if read_commit_marker(&state_dir)?.is_some() {
        return Err(HouseholdInstallTransactionError::HouseholdAlreadyInstalled);
    }
    let terminal_generation = lifecycle.reserve_next_lifecycle_generation(candidate_generation)?;
    expected_record
        .validate()
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    if !MachineId::is_well_formed(expected_m_id.as_str())
        || terminal_intent.ack_m_id != *expected_m_id
        || !expected_record
            .members
            .iter()
            .any(|member| member == expected_m_id)
    {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let commit_marker_bytes = crate::cbor::to_canonical_vec(expected_record)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    if commit_marker_bytes.len() > MAX_COMMIT_MARKER_BYTES {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let expectation = HouseholdInstallExpectation {
        candidate_generation,
        terminal_generation,
        expected_hh_id: expected_record.hh_id.clone(),
        expected_m_id: expected_m_id.clone(),
        commit_marker_blake3_256: marker_digest(&commit_marker_bytes),
        commit_marker_bytes,
        terminal_intent: terminal_intent.clone(),
    };
    write_breadcrumb(
        &state_dir,
        &HouseholdInstallBreadcrumbV1::from_expectation(&expectation),
    )?;
    Ok(expectation)
}

/// Terminalize a successful install without trusting the caller's in-memory
/// view.  The durable breadcrumb and exact final marker are reread first.
pub fn finish_household_install_under_lifecycle<F>(
    lifecycle: &LifecycleWriteGuard,
    expected: &HouseholdInstallExpectation,
    validate_required_artifacts: F,
) -> Result<HouseholdInstallFinalizeOutcome, HouseholdInstallTransactionError>
where
    F: FnOnce(&HouseholdInstallExpectation) -> Result<(), RequiredInstallArtifactsError>,
{
    let state_dir = prepare_state_dir(lifecycle)?;
    let durable =
        read_breadcrumb(&state_dir)?.ok_or(HouseholdInstallTransactionError::RecoveryRequired)?;
    if &durable != expected {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    match recover_durable(lifecycle, &state_dir, durable, validate_required_artifacts)? {
        HouseholdInstallRecoveryOutcome::RotatedAndCleared {
            generation,
            terminal_result,
        } => Ok(HouseholdInstallFinalizeOutcome::RotatedAndCleared {
            generation,
            terminal_result,
        }),
        HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared {
            generation,
            terminal_result,
        } => Ok(HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
            generation,
            terminal_result,
        }),
        HouseholdInstallRecoveryOutcome::PartialNeedsRollback(_) => {
            Err(HouseholdInstallTransactionError::CommitMarkerAbsent)
        }
        HouseholdInstallRecoveryOutcome::NotApplicable => {
            Err(HouseholdInstallTransactionError::RecoveryRequired)
        }
    }
}

/// Recover an interrupted install while lifecycle-exclusive is retained.
pub fn recover_household_install_under_lifecycle<F>(
    lifecycle: &LifecycleWriteGuard,
    validate_required_artifacts: F,
) -> Result<HouseholdInstallRecoveryOutcome, HouseholdInstallTransactionError>
where
    F: FnOnce(&HouseholdInstallExpectation) -> Result<(), RequiredInstallArtifactsError>,
{
    let state_dir = prepare_state_dir(lifecycle)?;
    let Some(expectation) = read_breadcrumb(&state_dir)? else {
        return Ok(HouseholdInstallRecoveryOutcome::NotApplicable);
    };
    recover_durable(
        lifecycle,
        &state_dir,
        expectation,
        validate_required_artifacts,
    )
}

/// Look up the latest exact finalize result without reconstructing its Ack.
///
/// A retained result is active only while its terminal lifecycle generation
/// and canonical household identity still match the current installation.
/// Thus a teardown/reinstall makes an old result [`FinalizeTerminalLookupOutcome::Absent`]
/// rather than allowing its Ack to escape. A different request fingerprint
/// against an active result is [`FinalizeTerminalLookupOutcome::Divergent`].
pub fn lookup_finalize_terminal_result_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
    request_fingerprint: FinalizeRequestFingerprintV1,
    expected_hh_id: &HouseholdId,
    expected_m_id: &MachineId,
) -> Result<FinalizeTerminalLookupOutcome, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    let Some(result) = active_terminal_result(lifecycle, &state_dir)? else {
        return Ok(FinalizeTerminalLookupOutcome::Absent);
    };
    if result.request_fingerprint != request_fingerprint
        || &result.hh_id != expected_hh_id
        || &result.m_id != expected_m_id
    {
        return Ok(FinalizeTerminalLookupOutcome::Divergent);
    }
    Ok(FinalizeTerminalLookupOutcome::Exact(Box::new(result)))
}

/// Whether a final retained result is active for the current lifecycle and
/// exact installed marker.
///
/// This intentionally exposes no request fingerprint or Ack bytes. Startup
/// uses it only to repair the install-specific restart-required bootstrap
/// state after a crash between breadcrumb cleanup and state publication.
pub fn has_active_finalize_terminal_result_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
) -> Result<bool, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    Ok(active_terminal_result(lifecycle, &state_dir)?.is_some())
}

/// Load the active terminal result for cold exact-replay recovery.
///
/// The returned JoinRequest and Ack were both anchored in the stable state
/// root before G0 rotated. The active-generation and installed-marker checks
/// are identical to exact finalize lookup; no generation-scoped pairing
/// snapshot is treated as authority here.
pub fn load_active_finalize_terminal_result_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
) -> Result<Option<FinalizeTerminalResult>, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    active_terminal_result(lifecycle, &state_dir)
}

/// Establish the named conservative delivery boundary for an exact terminal
/// result before any response body can be exposed.
///
/// The caller must supply the *entire* validated result it intends to replay.
/// Equality is intentionally derived over every field, so adding a future
/// authority field automatically strengthens this comparison. A stale
/// generation, a same-generation divergent result, or a breadcrumb bound to
/// different bytes fails closed.
pub fn prepare_finalize_ack_delivery_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
    expected: &FinalizeTerminalResult,
) -> Result<FinalizeAckDeliveryRecoveryOutcome, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    let active = active_terminal_result(lifecycle, &state_dir)?
        .ok_or(HouseholdInstallTransactionError::Quarantined)?;
    if &active != expected {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if let Some(record) = read_delivery_record(&state_dir)? {
        let retained = record.into_terminal_result()?;
        if retained == active {
            return Ok(FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(
                Box::new(retained),
            ));
        }
        if retained.terminal_generation == active.terminal_generation {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        // A completed delivery breadcrumb from an inactive installation is
        // bounded latest-only state. The current full terminal result may
        // replace it, but a divergent record in the current generation is
        // quarantine evidence and is never overwritten.
    }

    let record = FinalizeAckDeliveryRecordV1::may_have_taken_effect(&active);
    write_delivery_record(&state_dir, &record)?;
    let retained = read_delivery_record(&state_dir)?
        .ok_or(HouseholdInstallTransactionError::Quarantined)?
        .into_terminal_result()?;
    if retained != active {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(
        Box::new(retained),
    ))
}

/// Load and cross-check the named delivery boundary against the active full
/// terminal result and current lifecycle generation.
pub fn load_finalize_ack_delivery_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
) -> Result<FinalizeAckDeliveryRecoveryOutcome, HouseholdInstallTransactionError> {
    let state_dir = prepare_state_dir(lifecycle)?;
    let Some(record) = read_delivery_record(&state_dir)? else {
        return Ok(FinalizeAckDeliveryRecoveryOutcome::Absent);
    };
    let retained = record.into_terminal_result()?;
    let active = active_terminal_result(lifecycle, &state_dir)?
        .ok_or(HouseholdInstallTransactionError::Quarantined)?;
    if retained.terminal_generation != active.terminal_generation {
        return Ok(FinalizeAckDeliveryRecoveryOutcome::Absent);
    }
    if retained != active {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(
        Box::new(retained),
    ))
}

fn active_terminal_result(
    lifecycle: &LifecycleWriteGuard,
    state_dir: &File,
) -> Result<Option<FinalizeTerminalResult>, HouseholdInstallTransactionError> {
    let Some(record) = read_terminal_record(state_dir)? else {
        return Ok(None);
    };
    if record.phase != FinalizeTerminalPhaseV1::Final {
        return Ok(None);
    }
    let result = record.into_final_result()?;
    let current = lifecycle
        .lifecycle_generation()?
        .ok_or(HouseholdInstallTransactionError::Quarantined)?;
    if result.terminal_generation != current {
        return Ok(None);
    }
    let Some((marker_bytes, marker)) = read_commit_marker(state_dir)? else {
        return Ok(None);
    };
    if marker_digest(&marker_bytes) != result.commit_marker_blake3_256
        || marker.hh_id != result.hh_id
        || !marker.members.iter().any(|member| member == &result.m_id)
    {
        return Ok(None);
    }
    Ok(Some(result))
}

/// Clear the breadcrumb only after the caller has durably removed every
/// partial/staged artifact.  The supplied validator proves that cleanup, and
/// the exact marker is rechecked absent before the breadcrumb disappears.
pub fn complete_partial_install_rollback_under_lifecycle<F>(
    lifecycle: &LifecycleWriteGuard,
    ticket: HouseholdInstallRollbackTicket,
    validate_rollback_complete: F,
) -> Result<(), HouseholdInstallTransactionError>
where
    F: FnOnce(&HouseholdInstallExpectation) -> Result<(), RequiredInstallArtifactsError>,
{
    let state_dir = prepare_state_dir(lifecycle)?;
    let HouseholdInstallRollbackTicket { expectation } = ticket;
    let durable =
        read_breadcrumb(&state_dir)?.ok_or(HouseholdInstallTransactionError::RecoveryRequired)?;
    if durable != expectation {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if lifecycle.lifecycle_generation()? != Some(durable.candidate_generation) {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if read_commit_marker(&state_dir)?.is_some() {
        return Err(HouseholdInstallTransactionError::CommitMarkerMismatch);
    }
    validate_rollback_complete(&durable).map_err(|error| {
        HouseholdInstallTransactionError::RequiredArtifactsInvalid(error.to_string())
    })?;
    clear_breadcrumb(&state_dir)
}

fn recover_durable<F>(
    lifecycle: &LifecycleWriteGuard,
    state_dir: &File,
    expectation: HouseholdInstallExpectation,
    validate_required_artifacts: F,
) -> Result<HouseholdInstallRecoveryOutcome, HouseholdInstallTransactionError>
where
    F: FnOnce(&HouseholdInstallExpectation) -> Result<(), RequiredInstallArtifactsError>,
{
    let current = lifecycle
        .lifecycle_generation()?
        .ok_or(HouseholdInstallTransactionError::Quarantined)?;
    let Some((marker_bytes, marker_record)) = read_commit_marker(state_dir)? else {
        if current != expectation.candidate_generation {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        return Ok(HouseholdInstallRecoveryOutcome::PartialNeedsRollback(
            HouseholdInstallRollbackTicket { expectation },
        ));
    };
    if marker_bytes != expectation.commit_marker_bytes
        || marker_digest(&marker_bytes) != expectation.commit_marker_blake3_256
        || marker_record.hh_id != expectation.expected_hh_id
        || !marker_record
            .members
            .iter()
            .any(|member| member == &expectation.expected_m_id)
    {
        return Err(HouseholdInstallTransactionError::CommitMarkerMismatch);
    }
    validate_required_artifacts(&expectation).map_err(|error| {
        HouseholdInstallTransactionError::RequiredArtifactsInvalid(error.to_string())
    })?;

    if install_fail_injection::take_before_terminal_result() {
        return Err(HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery);
    }
    if current != expectation.candidate_generation && current != expectation.terminal_generation {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let terminal_record = ensure_terminal_result_prepared(state_dir, &expectation, current)?;
    let rotated_now = current == expectation.candidate_generation;
    let terminal_generation = if terminal_record.phase == FinalizeTerminalPhaseV1::Final {
        let result = terminal_record.clone().into_final_result()?;
        if result.terminal_generation != current
            || result.terminal_generation != expectation.terminal_generation
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        current
    } else if rotated_now {
        if install_fail_injection::take_before_rotation() {
            return Err(HouseholdInstallTransactionError::TerminalRotationNeedsRecovery);
        }
        lifecycle
            .commit_reserved_lifecycle_generation(
                expectation.candidate_generation,
                expectation.terminal_generation,
            )
            .map_err(|_| HouseholdInstallTransactionError::TerminalRotationNeedsRecovery)?
    } else {
        if current != expectation.terminal_generation {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        current
    };
    if terminal_record.phase != FinalizeTerminalPhaseV1::Final {
        if install_fail_injection::take_before_terminal_finalize() {
            return Err(HouseholdInstallTransactionError::TerminalResultFinalizationNeedsRecovery);
        }
        let final_record =
            FinalizeTerminalResultRecordV1::finalized(&expectation, terminal_generation);
        write_terminal_record(state_dir, &final_record).map_err(|error| match error {
            HouseholdInstallTransactionError::Quarantined => error,
            _ => HouseholdInstallTransactionError::TerminalResultFinalizationNeedsRecovery,
        })?;
    }
    let terminal_result = read_terminal_record(state_dir)?
        .ok_or(HouseholdInstallTransactionError::TerminalResultFinalizationNeedsRecovery)?;
    if !terminal_result.matches_expectation(&expectation)
        || terminal_result.phase != FinalizeTerminalPhaseV1::Final
    {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let terminal_result = terminal_result.into_final_result()?;
    if terminal_result.terminal_generation != terminal_generation {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if install_fail_injection::take_before_clear() {
        return Err(HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery);
    }
    clear_breadcrumb(state_dir)?;
    if rotated_now {
        Ok(HouseholdInstallRecoveryOutcome::RotatedAndCleared {
            generation: terminal_generation,
            terminal_result,
        })
    } else {
        Ok(HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared {
            generation: terminal_generation,
            terminal_result,
        })
    }
}

fn ensure_terminal_result_prepared(
    state_dir: &File,
    expectation: &HouseholdInstallExpectation,
    current: HouseholdLifecycleGenerationV1,
) -> Result<FinalizeTerminalResultRecordV1, HouseholdInstallTransactionError> {
    if current != expectation.candidate_generation && current != expectation.terminal_generation {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    if let Some(existing) = read_terminal_record(state_dir)? {
        if existing.matches_expectation(expectation) {
            return Ok(existing);
        }
        // One bounded latest-only result may survive teardown. It is safe to
        // atomically replace only a completed result that is inactive in this
        // candidate generation. An unresolved prepared result remains
        // quarantine evidence and is never overwritten.
        if existing.phase != FinalizeTerminalPhaseV1::Final
            || current != expectation.candidate_generation
        {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        let old = existing.into_final_result()?;
        if old.terminal_generation == current {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
    } else if current != expectation.candidate_generation {
        // Materialization is mandatory before rotation. If G1 is visible but
        // the prepared result is absent, no Ack authority can be reconstructed.
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let prepared = FinalizeTerminalResultRecordV1::prepared(expectation);
    write_terminal_record(state_dir, &prepared).map_err(|error| match error {
        HouseholdInstallTransactionError::Quarantined => error,
        _ => HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery,
    })?;
    let durable = read_terminal_record(state_dir)?
        .ok_or(HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery)?;
    if durable != prepared {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(durable)
}

fn marker_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn prepare_state_dir(
    lifecycle: &LifecycleWriteGuard,
) -> Result<File, HouseholdInstallTransactionError> {
    let state_path = lifecycle.clone_state_path()?;
    let state_dir = lifecycle.clone_state_dir()?;
    sweep_install_temps(&state_path, &state_dir)?;
    Ok(state_dir)
}

/// Remove only exact, bounded nonce temporary files left by a dead writer.
///
/// Enumeration uses the spelling already revalidated by the lifecycle guard;
/// every candidate is then reopened fd-relative with `O_NOFOLLOW`, checked
/// against the retained state-root descriptor, and removed fd-relative. An
/// unsafe exact-name entry quarantines instead of being followed or ignored.
fn sweep_install_temps(
    state_path: &std::path::Path,
    state_dir: &File,
) -> Result<(), HouseholdInstallTransactionError> {
    let entries =
        std::fs::read_dir(state_path).map_err(|_| HouseholdInstallTransactionError::Io)?;
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|_| HouseholdInstallTransactionError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(max_len) = install_tmp_max_len(name) else {
            continue;
        };
        let file = match rustix::fs::openat(
            state_dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => continue,
            Err(Errno::LOOP) => return Err(HouseholdInstallTransactionError::Quarantined),
            Err(_) => return Err(HouseholdInstallTransactionError::Io),
        };
        validate_regular_file(state_dir, &file, max_len)?;
        if !named_file_matches(state_dir, name, &file) {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        match rustix::fs::unlinkat(state_dir, name, AtFlags::empty()) {
            Ok(()) => removed = true,
            Err(Errno::NOENT) => {}
            Err(_) => return Err(HouseholdInstallTransactionError::Io),
        }
    }
    if removed {
        state_dir
            .sync_all()
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
    }
    Ok(())
}

fn install_tmp_max_len(name: &str) -> Option<u64> {
    for (prefix, max_len) in [
        (TRANSACTION_TMP_PREFIX, MAX_TRANSACTION_BYTES),
        (TERMINAL_RESULT_TMP_PREFIX, MAX_TERMINAL_RESULT_BYTES),
        (DELIVERY_RECORD_TMP_PREFIX, MAX_DELIVERY_RECORD_BYTES),
    ] {
        let Some(suffix) = name.strip_prefix(prefix) else {
            continue;
        };
        if suffix.len() == 32
            && suffix
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Some(max_len);
        }
    }
    None
}

fn write_breadcrumb(
    state_dir: &File,
    breadcrumb: &HouseholdInstallBreadcrumbV1,
) -> Result<(), HouseholdInstallTransactionError> {
    let bytes = crate::cbor::to_canonical_vec(breadcrumb)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    let tmp_name = format!("{TRANSACTION_TMP_PREFIX}{}", hex::encode(nonce));
    let fd = rustix::fs::openat(
        state_dir,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(map_errno)?;
    let mut tmp = File::from(fd);
    let mut renamed = false;
    let result = (|| {
        tmp.write_all(&bytes)
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        tmp.sync_all()
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        validate_transaction_file(state_dir, &tmp)?;
        match rustix::fs::statat(
            state_dir,
            HOUSEHOLD_INSTALL_TRANSACTION_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(HouseholdInstallTransactionError::RecoveryRequired),
            Err(Errno::NOENT) => {}
            Err(_) => return Err(HouseholdInstallTransactionError::Io),
        }
        if !named_file_matches(state_dir, tmp_name.as_str(), &tmp) {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        rustix::fs::renameat(
            state_dir,
            tmp_name.as_str(),
            state_dir,
            HOUSEHOLD_INSTALL_TRANSACTION_FILENAME,
        )
        .map_err(map_errno)?;
        renamed = true;
        if install_fail_injection::take_after_breadcrumb_rename() {
            return Err(HouseholdInstallTransactionError::BreadcrumbPublicationNeedsRecovery);
        }
        state_dir
            .sync_all()
            .map_err(|_| HouseholdInstallTransactionError::BreadcrumbPublicationNeedsRecovery)?;
        if read_breadcrumb(state_dir)?.as_ref() != Some(&breadcrumb.clone().into_expectation()?) {
            return Err(HouseholdInstallTransactionError::BreadcrumbPublicationNeedsRecovery);
        }
        Ok(())
    })();
    if !renamed {
        let _ = rustix::fs::unlinkat(state_dir, tmp_name.as_str(), AtFlags::empty());
    }
    result
}

fn write_terminal_record(
    state_dir: &File,
    record: &FinalizeTerminalResultRecordV1,
) -> Result<(), HouseholdInstallTransactionError> {
    let record = record.clone().validate()?;
    let bytes = crate::cbor::to_canonical_vec(&record)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    if bytes.len() as u64 > MAX_TERMINAL_RESULT_BYTES {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    let tmp_name = format!("{TERMINAL_RESULT_TMP_PREFIX}{}", hex::encode(nonce));
    let fd = rustix::fs::openat(
        state_dir,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(map_errno)?;
    let mut tmp = File::from(fd);
    let mut renamed = false;
    let result = (|| {
        tmp.write_all(&bytes)
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        tmp.sync_all()
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        validate_regular_file(state_dir, &tmp, MAX_TERMINAL_RESULT_BYTES)?;
        if !named_file_matches(state_dir, tmp_name.as_str(), &tmp) {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        rustix::fs::renameat(
            state_dir,
            tmp_name.as_str(),
            state_dir,
            HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME,
        )
        .map_err(map_errno)?;
        renamed = true;
        if install_fail_injection::take_after_terminal_result_rename() {
            return Err(HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery);
        }
        state_dir.sync_all().map_err(|_| {
            HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery
        })?;
        if read_terminal_record(state_dir)?.as_ref() != Some(&record) {
            return Err(HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery);
        }
        Ok(())
    })();
    if !renamed {
        let _ = rustix::fs::unlinkat(state_dir, tmp_name.as_str(), AtFlags::empty());
    }
    result
}

fn write_delivery_record(
    state_dir: &File,
    record: &FinalizeAckDeliveryRecordV1,
) -> Result<(), HouseholdInstallTransactionError> {
    let record = record.clone().validate()?;
    let bytes = crate::cbor::to_canonical_vec(&record)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    if bytes.len() as u64 > MAX_DELIVERY_RECORD_BYTES {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    let tmp_name = format!("{DELIVERY_RECORD_TMP_PREFIX}{}", hex::encode(nonce));
    let fd = rustix::fs::openat(
        state_dir,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(map_errno)?;
    let mut tmp = File::from(fd);
    let mut renamed = false;
    let result = (|| {
        tmp.write_all(&bytes)
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        tmp.sync_all()
            .map_err(|_| HouseholdInstallTransactionError::Io)?;
        validate_regular_file(state_dir, &tmp, MAX_DELIVERY_RECORD_BYTES)?;
        if !named_file_matches(state_dir, tmp_name.as_str(), &tmp) {
            return Err(HouseholdInstallTransactionError::Quarantined);
        }
        rustix::fs::renameat(
            state_dir,
            tmp_name.as_str(),
            state_dir,
            HOUSEHOLD_INSTALL_FINALIZE_DELIVERY_FILENAME,
        )
        .map_err(map_errno)?;
        renamed = true;
        state_dir
            .sync_all()
            .map_err(|_| HouseholdInstallTransactionError::FinalizeAckDeliveryMayHaveTakenEffect)?;
        let readback = read_delivery_record(state_dir).map_err(|error| match error {
            HouseholdInstallTransactionError::Quarantined => error,
            _ => HouseholdInstallTransactionError::FinalizeAckDeliveryMayHaveTakenEffect,
        })?;
        if readback.as_ref() != Some(&record) {
            return Err(HouseholdInstallTransactionError::FinalizeAckDeliveryMayHaveTakenEffect);
        }
        Ok(())
    })();
    if !renamed {
        let _ = rustix::fs::unlinkat(state_dir, tmp_name.as_str(), AtFlags::empty());
    }
    result
}

fn read_breadcrumb(
    state_dir: &File,
) -> Result<Option<HouseholdInstallExpectation>, HouseholdInstallTransactionError> {
    let Some(mut file) = open_optional_stabilized(
        state_dir,
        HOUSEHOLD_INSTALL_TRANSACTION_FILENAME,
        MAX_TRANSACTION_BYTES,
    )?
    else {
        return Ok(None);
    };
    let bytes = read_bounded(&mut file, MAX_TRANSACTION_BYTES)?;
    let breadcrumb: HouseholdInstallBreadcrumbV1 = crate::cbor::from_canonical_slice_strict(&bytes)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    breadcrumb.into_expectation().map(Some)
}

fn read_terminal_record(
    state_dir: &File,
) -> Result<Option<FinalizeTerminalResultRecordV1>, HouseholdInstallTransactionError> {
    let Some(mut file) = open_optional_stabilized(
        state_dir,
        HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME,
        MAX_TERMINAL_RESULT_BYTES,
    )?
    else {
        return Ok(None);
    };
    let bytes = read_bounded(&mut file, MAX_TERMINAL_RESULT_BYTES)?;
    let record: FinalizeTerminalResultRecordV1 =
        crate::cbor::from_canonical_slice_strict(&bytes)
            .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    record.validate().map(Some)
}

fn read_delivery_record(
    state_dir: &File,
) -> Result<Option<FinalizeAckDeliveryRecordV1>, HouseholdInstallTransactionError> {
    let Some(mut file) = open_optional_stabilized(
        state_dir,
        HOUSEHOLD_INSTALL_FINALIZE_DELIVERY_FILENAME,
        MAX_DELIVERY_RECORD_BYTES,
    )?
    else {
        return Ok(None);
    };
    let bytes = read_bounded(&mut file, MAX_DELIVERY_RECORD_BYTES)?;
    let record: FinalizeAckDeliveryRecordV1 = crate::cbor::from_canonical_slice_strict(&bytes)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    record.validate().map(Some)
}

fn clear_breadcrumb(state_dir: &File) -> Result<(), HouseholdInstallTransactionError> {
    match rustix::fs::unlinkat(
        state_dir,
        HOUSEHOLD_INSTALL_TRANSACTION_FILENAME,
        AtFlags::empty(),
    ) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(_) => return Err(HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery),
    }
    state_dir
        .sync_all()
        .map_err(|_| HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery)?;
    match rustix::fs::statat(
        state_dir,
        HOUSEHOLD_INSTALL_TRANSACTION_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(Errno::NOENT) => Ok(()),
        _ => Err(HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery),
    }
}

fn read_commit_marker(
    state_dir: &File,
) -> Result<Option<(Vec<u8>, HouseholdRecord)>, HouseholdInstallTransactionError> {
    let household = match rustix::fs::openat(
        state_dir,
        crate::storage::HOUSEHOLD_SUBDIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => {
            state_dir
                .sync_all()
                .map_err(|_| HouseholdInstallTransactionError::Io)?;
            return match rustix::fs::openat(
                state_dir,
                crate::storage::HOUSEHOLD_SUBDIR,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Err(Errno::NOENT) => Ok(None),
                Ok(_) => Err(HouseholdInstallTransactionError::Quarantined),
                Err(_) => Err(HouseholdInstallTransactionError::Io),
            };
        }
        Err(Errno::LOOP) => return Err(HouseholdInstallTransactionError::Quarantined),
        Err(_) => return Err(HouseholdInstallTransactionError::Io),
    };
    validate_directory(state_dir, &household)?;
    let Some(mut marker) = open_optional_stabilized(
        &household,
        "household_record.cbor",
        MAX_COMMIT_MARKER_BYTES as u64,
    )?
    else {
        return Ok(None);
    };
    let bytes = read_bounded(&mut marker, MAX_COMMIT_MARKER_BYTES as u64)?;
    let record: HouseholdRecord = crate::cbor::from_canonical_slice_strict(&bytes)
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    record
        .validate()
        .map_err(|_| HouseholdInstallTransactionError::Quarantined)?;
    Ok(Some((bytes, record)))
}

fn open_optional_stabilized(
    parent: &File,
    name: &str,
    max_len: u64,
) -> Result<Option<File>, HouseholdInstallTransactionError> {
    let open = || {
        rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    let fd = match open() {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            parent
                .sync_all()
                .map_err(|_| HouseholdInstallTransactionError::Io)?;
            match open() {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(Errno::LOOP) => {
                    return Err(HouseholdInstallTransactionError::Quarantined);
                }
                Err(_) => return Err(HouseholdInstallTransactionError::Io),
            }
        }
        Err(Errno::LOOP) => return Err(HouseholdInstallTransactionError::Quarantined),
        Err(_) => return Err(HouseholdInstallTransactionError::Io),
    };
    let file = File::from(fd);
    validate_regular_file(parent, &file, max_len)?;
    file.sync_all()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    parent
        .sync_all()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    if !named_file_matches(parent, name, &file) {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(Some(file))
}

fn read_bounded(
    file: &mut File,
    max_len: u64,
) -> Result<Vec<u8>, HouseholdInstallTransactionError> {
    let mut bytes = Vec::new();
    file.take(max_len + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    if bytes.len() as u64 > max_len {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(bytes)
}

fn validate_transaction_file(
    state_dir: &File,
    file: &File,
) -> Result<(), HouseholdInstallTransactionError> {
    validate_regular_file(state_dir, file, MAX_TRANSACTION_BYTES)
}

fn validate_regular_file(
    parent: &File,
    file: &File,
    max_len: u64,
) -> Result<(), HouseholdInstallTransactionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent_meta = parent
        .metadata()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != parent_meta.uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > max_len
    {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(())
}

fn validate_directory(parent: &File, dir: &File) -> Result<(), HouseholdInstallTransactionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent_meta = parent
        .metadata()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    let metadata = dir
        .metadata()
        .map_err(|_| HouseholdInstallTransactionError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != parent_meta.uid()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() < 1
    {
        return Err(HouseholdInstallTransactionError::Quarantined);
    }
    Ok(())
}

fn named_file_matches(parent: &File, name: &str, file: &File) -> bool {
    let Ok(named) = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    let Ok(opened) = rustix::fs::fstat(file) else {
        return false;
    };
    named.st_dev == opened.st_dev && named.st_ino == opened.st_ino
}

fn map_errno(error: Errno) -> HouseholdInstallTransactionError {
    if error == Errno::LOOP {
        HouseholdInstallTransactionError::Quarantined
    } else {
        HouseholdInstallTransactionError::Io
    }
}

#[cfg(test)]
mod install_fail_injection {
    use std::cell::Cell;

    thread_local! {
        static AFTER_BREADCRUMB_RENAME: Cell<bool> = const { Cell::new(false) };
        static BEFORE_TERMINAL_RESULT: Cell<bool> = const { Cell::new(false) };
        static AFTER_TERMINAL_RESULT_RENAME: Cell<bool> = const { Cell::new(false) };
        static BEFORE_ROTATION: Cell<bool> = const { Cell::new(false) };
        static BEFORE_TERMINAL_FINALIZE: Cell<bool> = const { Cell::new(false) };
        static BEFORE_CLEAR: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn arm_after_breadcrumb_rename() {
        AFTER_BREADCRUMB_RENAME.with(|armed| armed.set(true));
    }

    pub(super) fn arm_before_rotation() {
        BEFORE_ROTATION.with(|armed| armed.set(true));
    }

    pub(super) fn arm_before_terminal_result() {
        BEFORE_TERMINAL_RESULT.with(|armed| armed.set(true));
    }

    pub(super) fn arm_after_terminal_result_rename() {
        AFTER_TERMINAL_RESULT_RENAME.with(|armed| armed.set(true));
    }

    pub(super) fn arm_before_terminal_finalize() {
        BEFORE_TERMINAL_FINALIZE.with(|armed| armed.set(true));
    }

    pub(super) fn arm_before_clear() {
        BEFORE_CLEAR.with(|armed| armed.set(true));
    }

    pub(super) fn take_after_breadcrumb_rename() -> bool {
        AFTER_BREADCRUMB_RENAME.with(|armed| armed.replace(false))
    }

    pub(super) fn take_before_rotation() -> bool {
        BEFORE_ROTATION.with(|armed| armed.replace(false))
    }

    pub(super) fn take_before_terminal_result() -> bool {
        BEFORE_TERMINAL_RESULT.with(|armed| armed.replace(false))
    }

    pub(super) fn take_after_terminal_result_rename() -> bool {
        AFTER_TERMINAL_RESULT_RENAME.with(|armed| armed.replace(false))
    }

    pub(super) fn take_before_terminal_finalize() -> bool {
        BEFORE_TERMINAL_FINALIZE.with(|armed| armed.replace(false))
    }

    pub(super) fn take_before_clear() -> bool {
        BEFORE_CLEAR.with(|armed| armed.replace(false))
    }
}

#[cfg(not(test))]
mod install_fail_injection {
    pub(super) const fn take_after_breadcrumb_rename() -> bool {
        false
    }

    pub(super) const fn take_before_rotation() -> bool {
        false
    }

    pub(super) const fn take_before_terminal_result() -> bool {
        false
    }

    pub(super) const fn take_after_terminal_result_rename() -> bool {
        false
    }

    pub(super) const fn take_before_terminal_finalize() -> bool {
        false
    }

    pub(super) const fn take_before_clear() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;
    use crate::household_lifecycle::HouseholdLifecycleLock;
    use crate::ids::{derive_household_id, derive_machine_id};
    use crate::keys::{IdentityKey, P256Keypair};

    fn record() -> (HouseholdRecord, MachineId, P256Keypair) {
        let household = P256Keypair::generate();
        let machine = P256Keypair::generate();
        let hh_pub = household.public();
        let m_id = derive_machine_id(&machine.public());
        (
            HouseholdRecord {
                version: HouseholdRecord::SCHEMA_VERSION,
                hh_id: derive_household_id(&hh_pub),
                hh_pub,
                name: "Install transaction test".into(),
                created_at: 1_714_972_800,
                shamir_k: 0,
                shamir_n: 0,
                members: vec![m_id.clone()],
                is_follower: true,
            },
            m_id,
            machine,
        )
    }

    fn install_exact_marker(state: &TempDir, expectation: &HouseholdInstallExpectation) {
        let household = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
        fs::create_dir(&household).unwrap();
        fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = household.join("household_record.cbor");
        fs::write(&marker, expectation.commit_marker_bytes()).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        File::open(&marker).unwrap().sync_all().unwrap();
        File::open(&household).unwrap().sync_all().unwrap();
        File::open(state.path()).unwrap().sync_all().unwrap();
    }

    fn terminal_intent(machine: &P256Keypair, request: &[u8]) -> FinalizeTerminalIntent {
        let m_pub = machine.public();
        let m_id = derive_machine_id(&m_pub);
        let nonce = [0x3a; 32];
        let challenge = crate::pair_machine::JoinChallenge::build(
            m_pub.as_bytes(),
            &nonce,
            "install-transaction-test",
            crate::machine_cert::Platform::LinuxNix,
        );
        let challenge_bytes = challenge.to_canonical_bytes().unwrap();
        let challenge_sig = machine.sign(&challenge_bytes).unwrap();
        let join_request = crate::pair_machine::JoinRequest {
            version: crate::pair_machine::PAIR_MACHINE_VERSION,
            m_pub: ByteBuf::from(m_pub.as_bytes().to_vec()),
            hostname: "install-transaction-test".into(),
            platform: crate::machine_cert::Platform::LinuxNix,
            nonce: ByteBuf::from(nonce.to_vec()),
            addr: "192.0.2.44:18091".into(),
            transport: crate::pair_machine::JoinTransport::Lan,
            challenge_sig: ByteBuf::from(challenge_sig.0.to_vec()),
        };
        let join_request_bytes = join_request.to_canonical_bytes().unwrap();
        let ack = crate::pair_machine::FinalizeAck {
            version: crate::pair_machine::PAIR_MACHINE_VERSION,
            m_id: m_id.to_string(),
            machine_cert_hash: ByteBuf::from(vec![0x5a; 32]),
        };
        let ack_bytes = ack.to_canonical_bytes().unwrap();
        FinalizeTerminalIntent::from_exact_ack_bytes(
            FinalizeRequestFingerprintV1::for_canonical_request_bytes(request),
            &m_id,
            &join_request_bytes,
            &ack_bytes,
        )
        .unwrap()
    }

    fn begin<'a>(
        state: &TempDir,
        lifecycle: &'a HouseholdLifecycleLock,
    ) -> (
        crate::household_lifecycle::LifecycleWriteGuard,
        HouseholdInstallExpectation,
    ) {
        let guard = lifecycle.lock_exclusive().unwrap();
        let generation = guard.ensure_lifecycle_generation().unwrap();
        let (record, m_id, machine) = record();
        let terminal_intent = terminal_intent(&machine, b"canonical request");
        let expectation = begin_household_install_under_lifecycle(
            &guard,
            generation,
            &record,
            &m_id,
            &terminal_intent,
        )
        .unwrap();
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists()
        );
        (guard, expectation)
    }

    #[test]
    fn breadcrumb_lost_parent_ack_is_recovered_after_restart_without_reinstall() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let generation = guard.ensure_lifecycle_generation().unwrap();
        let (record, m_id, machine) = record();
        let terminal_intent = terminal_intent(&machine, b"lost breadcrumb ack");
        install_fail_injection::arm_after_breadcrumb_rename();
        assert_eq!(
            begin_household_install_under_lifecycle(
                &guard,
                generation,
                &record,
                &m_id,
                &terminal_intent,
            )
            .unwrap_err(),
            HouseholdInstallTransactionError::BreadcrumbPublicationNeedsRecovery
        );
        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        assert!(matches!(
            recover_household_install_under_lifecycle(&guard, |_| {
                panic!("partial recovery must not validate committed artifacts")
            })
            .unwrap(),
            HouseholdInstallRecoveryOutcome::PartialNeedsRollback(_)
        ));
    }

    #[test]
    fn partial_install_never_rotates_and_clears_only_after_rollback_proof() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let before = guard.lifecycle_generation().unwrap().unwrap();
        let residual = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
        fs::create_dir(&residual).unwrap();
        fs::set_permissions(&residual, fs::Permissions::from_mode(0o700)).unwrap();
        File::open(state.path()).unwrap().sync_all().unwrap();
        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let outcome = recover_household_install_under_lifecycle(&guard, |_| {
            panic!("partial recovery must not validate committed artifacts")
        })
        .unwrap();
        let HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket) = outcome else {
            panic!("expected partial rollback")
        };
        assert_eq!(ticket.expectation(), &expectation);
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(before));
        complete_partial_install_rollback_under_lifecycle(&guard, ticket, |_| Ok(())).unwrap();
        assert!(
            !state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists()
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(before));
    }

    #[test]
    fn partial_breadcrumb_from_an_old_generation_is_quarantined_not_rolled_back() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        let other = guard.rotate_lifecycle_generation().unwrap();
        assert_ne!(other, g0);
        assert_eq!(
            recover_household_install_under_lifecycle(&guard, |_| {
                panic!("an absent marker from a foreign generation is never committed")
            })
            .unwrap_err(),
            HouseholdInstallTransactionError::Quarantined
        );
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists(),
            "quarantine preserves evidence and never authorizes cleanup"
        );
    }

    #[test]
    fn committed_pre_rotate_failure_is_typed_and_retry_rotates_never_rolls_back() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        install_exact_marker(&state, &expectation);
        install_fail_injection::arm_before_rotation();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalRotationNeedsRecovery
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
        let state_dir = guard.clone_state_dir().unwrap();
        let prepared = read_terminal_record(&state_dir).unwrap().unwrap();
        assert_eq!(prepared.phase, FinalizeTerminalPhaseV1::Prepared);
        assert_eq!(
            prepared.join_request_bytes.as_ref(),
            expectation.terminal_intent().join_request_bytes()
        );
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists(),
            "post-commit failure must preserve recovery evidence"
        );
        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let outcome = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap();
        let HouseholdInstallRecoveryOutcome::RotatedAndCleared { generation, .. } = outcome else {
            panic!("retry must terminally rotate")
        };
        assert_ne!(generation, g0);
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(generation));
        assert_eq!(
            load_active_finalize_terminal_result_under_lifecycle(&guard)
                .unwrap()
                .unwrap()
                .join_request_bytes(),
            expectation.terminal_intent().join_request_bytes()
        );
    }

    #[test]
    fn crash_after_rotate_before_clear_converges_without_second_rotation() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        install_exact_marker(&state, &expectation);
        install_fail_injection::arm_before_clear();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery
        );
        let g1 = guard.lifecycle_generation().unwrap().unwrap();
        assert_ne!(g1, g0);
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists()
        );
        let state_dir = guard.clone_state_dir().unwrap();
        let retained = read_terminal_record(&state_dir).unwrap().unwrap();
        assert_eq!(retained.phase, FinalizeTerminalPhaseV1::Final);
        assert_eq!(
            retained.join_request_bytes.as_ref(),
            expectation.terminal_intent().join_request_bytes()
        );
        assert!(matches!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                expectation.terminal_intent().request_fingerprint(),
                expectation.expected_hh_id(),
                expectation.expected_m_id(),
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Exact(_)
        ));
        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let outcome = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap();
        assert!(matches!(
            outcome,
            HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared { generation, .. }
                if generation == g1
        ));
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g1));
    }

    #[test]
    fn canonical_marker_mismatch_quarantines_without_rotation_or_cleanup() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        let (other, _, _) = record();
        let household = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
        fs::create_dir(&household).unwrap();
        fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
        crate::storage::atomic_write_cbor(
            &crate::storage::household_record_path(state.path()),
            &other,
        )
        .unwrap();
        assert_eq!(
            recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::CommitMarkerMismatch
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists()
        );
    }

    #[test]
    fn required_artifact_failure_never_crosses_terminal_rotation() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        install_exact_marker(&state, &expectation);
        assert_eq!(
            recover_household_install_under_lifecycle(&guard, |_| {
                Err(RequiredInstallArtifactsError::new("candidate cert missing"))
            })
            .unwrap_err(),
            HouseholdInstallTransactionError::RequiredArtifactsInvalid(
                "candidate cert missing".into()
            )
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
    }

    #[test]
    fn crash_between_commit_and_terminal_result_recovers_exact_ack_before_rotation() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        let expected_ack = expectation.terminal_intent().ack_bytes().to_vec();
        let fingerprint = expectation.terminal_intent().request_fingerprint();
        install_exact_marker(&state, &expectation);

        install_fail_injection::arm_before_terminal_result();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
        assert!(
            !state
                .path()
                .join(HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME)
                .exists()
        );
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists()
        );

        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let HouseholdInstallRecoveryOutcome::RotatedAndCleared {
            generation,
            terminal_result,
        } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
        else {
            panic!("commit-to-result recovery must rotate exactly once")
        };
        assert_ne!(generation, g0);
        assert_eq!(*terminal_result.terminal_generation(), generation);
        assert_eq!(terminal_result.ack_bytes(), expected_ack);
        assert_eq!(terminal_result.ack_m_id(), expectation.expected_m_id());
        assert_eq!(terminal_result.ack_machine_cert_hash(), &[0x5a; 32]);
        assert!(matches!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                fingerprint,
                expectation.expected_hh_id(),
                expectation.expected_m_id(),
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Exact(ref exact)
                if exact.ack_bytes() == expected_ack
        ));
    }

    #[test]
    fn lost_terminal_result_parent_ack_is_recovered_without_reinstall() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        install_exact_marker(&state, &expectation);

        install_fail_injection::arm_after_terminal_result_rename();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
        let state_dir = guard.clone_state_dir().unwrap();
        let prepared = read_terminal_record(&state_dir).unwrap().unwrap();
        assert_eq!(prepared.phase, FinalizeTerminalPhaseV1::Prepared);
        assert_eq!(
            prepared.join_request_bytes.as_ref(),
            expectation.terminal_intent().join_request_bytes()
        );

        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let HouseholdInstallRecoveryOutcome::RotatedAndCleared {
            terminal_result, ..
        } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
        else {
            panic!("visible prepared result must converge")
        };
        assert_eq!(
            terminal_result.ack_bytes(),
            expectation.terminal_intent().ack_bytes()
        );
    }

    #[test]
    fn crash_after_rotation_before_terminal_finalize_never_rotates_twice() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let g0 = expectation.candidate_generation();
        install_exact_marker(&state, &expectation);

        install_fail_injection::arm_before_terminal_finalize();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalResultFinalizationNeedsRecovery
        );
        let g1 = guard.lifecycle_generation().unwrap().unwrap();
        assert_ne!(g1, g0);
        let state_dir = guard.clone_state_dir().unwrap();
        assert_eq!(
            read_terminal_record(&state_dir).unwrap().unwrap().phase,
            FinalizeTerminalPhaseV1::Prepared
        );

        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared {
            generation,
            terminal_result,
        } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
        else {
            panic!("post-rotation recovery must not rotate twice")
        };
        assert_eq!(generation, g1);
        assert_eq!(*terminal_result.terminal_generation(), g1);
        assert_eq!(
            terminal_result.join_request_bytes(),
            expectation.terminal_intent().join_request_bytes()
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(g1));
    }

    #[test]
    fn exact_retry_is_byte_identical_and_divergent_retry_fails_closed() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let fingerprint = expectation.terminal_intent().request_fingerprint();
        let expected_ack = expectation.terminal_intent().ack_bytes().to_vec();
        install_exact_marker(&state, &expectation);
        let finalized =
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
        let terminal_result = match finalized {
            HouseholdInstallFinalizeOutcome::RotatedAndCleared {
                terminal_result, ..
            }
            | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
                terminal_result, ..
            } => terminal_result,
        };
        assert_eq!(terminal_result.ack_bytes(), expected_ack);
        assert_eq!(
            crate::cbor::to_canonical_vec(
                &crate::cbor::from_canonical_slice_strict::<crate::pair_machine::FinalizeAck>(
                    terminal_result.ack_bytes()
                )
                .unwrap()
            )
            .unwrap(),
            expected_ack
        );

        drop(guard);
        drop(lifecycle);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let exact = lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            fingerprint,
            expectation.expected_hh_id(),
            expectation.expected_m_id(),
        )
        .unwrap();
        assert!(matches!(
            exact,
            FinalizeTerminalLookupOutcome::Exact(ref result)
                if result.ack_bytes() == expected_ack
        ));
        assert_eq!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                FinalizeRequestFingerprintV1::for_canonical_request_bytes(b"other request"),
                expectation.expected_hh_id(),
                expectation.expected_m_id(),
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Divergent
        );
        let (_, other_m_id, _) = record();
        assert_eq!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                fingerprint,
                expectation.expected_hh_id(),
                &other_m_id,
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Divergent
        );
    }

    #[test]
    fn old_terminal_result_is_inactive_after_lifecycle_generation_changes() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        let fingerprint = expectation.terminal_intent().request_fingerprint();
        install_exact_marker(&state, &expectation);
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
        fs::remove_dir_all(state.path().join(crate::storage::HOUSEHOLD_SUBDIR)).unwrap();
        File::open(state.path()).unwrap().sync_all().unwrap();
        let replacement_generation = guard.rotate_lifecycle_generation().unwrap();
        assert_ne!(replacement_generation, expectation.candidate_generation());
        assert_eq!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                fingerprint,
                expectation.expected_hh_id(),
                expectation.expected_m_id(),
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Absent,
            "an old Ack never survives teardown/reinstall generation change"
        );
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME)
                .exists(),
            "bounded latest-only retention leaves replacement atomic, never erase-first"
        );

        let (replacement_record, replacement_m_id, replacement_machine) = record();
        let replacement_intent = terminal_intent(&replacement_machine, b"replacement request");
        let replacement = begin_household_install_under_lifecycle(
            &guard,
            replacement_generation,
            &replacement_record,
            &replacement_m_id,
            &replacement_intent,
        )
        .unwrap();
        install_exact_marker(&state, &replacement);
        let replacement_result =
            finish_household_install_under_lifecycle(&guard, &replacement, |_| Ok(())).unwrap();
        let replacement_terminal = match replacement_result {
            HouseholdInstallFinalizeOutcome::RotatedAndCleared {
                terminal_result, ..
            }
            | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
                terminal_result, ..
            } => terminal_result,
        };
        assert_eq!(
            replacement_terminal.ack_bytes(),
            replacement_intent.ack_bytes()
        );
        assert!(matches!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                replacement_intent.request_fingerprint(),
                &replacement_record.hh_id,
                &replacement_m_id,
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Exact(_)
        ));
        let terminal_entries = fs::read_dir(state.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".household-install-finalize-terminal-v1")
            })
            .count();
        assert_eq!(
            terminal_entries, 1,
            "latest-only result is physically bounded"
        );
    }

    #[test]
    fn foreign_rotation_after_prepared_is_quarantined_not_adopted() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        install_exact_marker(&state, &expectation);

        install_fail_injection::arm_before_rotation();
        assert_eq!(
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::TerminalRotationNeedsRecovery
        );
        let foreign = guard.rotate_lifecycle_generation().unwrap();
        assert_ne!(foreign, expectation.candidate_generation());
        assert_ne!(foreign, expectation.terminal_generation());

        assert_eq!(
            recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap_err(),
            HouseholdInstallTransactionError::Quarantined
        );
        assert_eq!(guard.lifecycle_generation().unwrap(), Some(foreign));
        assert!(
            state
                .path()
                .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
                .exists(),
            "foreign generation preserves quarantine evidence"
        );
    }

    #[test]
    fn delivery_boundary_accepts_only_the_full_current_terminal_result() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let (guard, expectation) = begin(&state, &lifecycle);
        install_exact_marker(&state, &expectation);
        let outcome =
            finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
        let terminal = match outcome {
            HouseholdInstallFinalizeOutcome::RotatedAndCleared {
                terminal_result, ..
            }
            | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
                terminal_result, ..
            } => terminal_result,
        };

        assert!(matches!(
            prepare_finalize_ack_delivery_under_lifecycle(&guard, &terminal).unwrap(),
            FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref retained)
                if retained.as_ref() == &terminal
        ));
        assert!(matches!(
            load_finalize_ack_delivery_under_lifecycle(&guard).unwrap(),
            FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref retained)
                if retained.as_ref() == &terminal
        ));

        let mut same_generation_but_divergent = terminal.clone();
        same_generation_but_divergent.ack_bytes.push(0);
        assert_eq!(
            prepare_finalize_ack_delivery_under_lifecycle(&guard, &same_generation_but_divergent,)
                .unwrap_err(),
            HouseholdInstallTransactionError::Quarantined
        );

        let replacement_generation = guard.rotate_lifecycle_generation().unwrap();
        assert_ne!(replacement_generation, *terminal.terminal_generation());
        assert_eq!(
            prepare_finalize_ack_delivery_under_lifecycle(&guard, &terminal).unwrap_err(),
            HouseholdInstallTransactionError::Quarantined
        );
    }

    #[test]
    fn exact_nonce_temps_are_swept_and_physically_bounded() {
        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        guard.ensure_lifecycle_generation().unwrap();
        for index in 0..8_u8 {
            for prefix in [
                TRANSACTION_TMP_PREFIX,
                TERMINAL_RESULT_TMP_PREFIX,
                DELIVERY_RECORD_TMP_PREFIX,
            ] {
                let path = state.path().join(format!("{prefix}{index:032x}"));
                fs::write(&path, b"orphan").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        assert_eq!(
            lookup_finalize_terminal_result_under_lifecycle(
                &guard,
                FinalizeRequestFingerprintV1::for_canonical_request_bytes(b"absent"),
                &HouseholdId::parse("hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .unwrap(),
                &MachineId::parse("m_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .unwrap(),
            )
            .unwrap(),
            FinalizeTerminalLookupOutcome::Absent
        );
        let leftovers = fs::read_dir(state.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                install_tmp_max_len(&name).is_some()
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn exact_nonce_symlink_quarantines_without_deleting_target() {
        use std::os::unix::fs::symlink;

        let state = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        guard.ensure_lifecycle_generation().unwrap();
        let target = state.path().join("do-not-delete");
        fs::write(&target, b"authority").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let trap = state
            .path()
            .join(format!("{TRANSACTION_TMP_PREFIX}{}", "a".repeat(32)));
        symlink(&target, &trap).unwrap();

        assert_eq!(
            has_active_finalize_terminal_result_under_lifecycle(&guard).unwrap_err(),
            HouseholdInstallTransactionError::Quarantined
        );
        assert_eq!(fs::read(&target).unwrap(), b"authority");
        assert!(trap.symlink_metadata().unwrap().file_type().is_symlink());
    }
}
