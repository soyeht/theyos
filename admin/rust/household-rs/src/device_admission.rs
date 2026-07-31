//! R0a Fatia D2a — `HouseholdDeviceAdmissionAuthorityV1`.
//!
//! The durable home of the owner-device profile (R0a §8, decision D2). It is a
//! single-file, generationed, atomic object of the household's identity, kept
//! deliberately separate from the ephemeral `DevicePairingStore`,
//! `directory_devices`, DP2/owner-site state, rendezvous, and tunnel config.
//!
//! Per D2-B this is its own owner-mesh store: it does not reuse another
//! product's log schema, authority, or semantics, and it does not share the
//! machine roster's record format. The only cross-module reuse is the typed
//! [`crate::device_cert::DeviceCert`] verifier and the closed caveat-narrowing
//! proof, both of which are identity checks rather than storage authority.
//!
//! Properties this module is responsible for:
//!
//! - **durable single-file** — one canonical CBOR record is the whole authority;
//!   consumers read one snapshot rather than composing independent stores.
//! - **persist-before-memory** — the in-memory projection is advanced only
//!   after a durable write has been fsynced, renamed, and read back byte for
//!   byte. Any failure invalidates the projection instead of publishing it.
//! - **fail-closed** — a missing object, a zero generation, an unreadable
//!   record, or a non-canonical record yields no admission at all.
//! - **generation** — monotonic and non-zero; every state-changing add or
//!   revoke increments it atomically with the persisted bytes.
//! - **active/revoked** — revocation is a tombstone. A revoked `d_id` is never
//!   reopened by a replayed or late add.
//! - **snapshot digest** — a domain-separated digest over the whole canonical
//!   record, so a consumer can prove two reads saw the same authority.
//! - **seal/recheck** — [`SealedDeviceAdmissionV1`] is opaque and move-only;
//!   consuming it re-reads the live authority and requires every sealed digest,
//!   the generation, and the revocation cursor to still match.
//!
//! Inert-complete (R0a §11): the machinery compiles and is exercised end to end
//! by tests, but this module installs no production provider, route, or setter.
//! Without a caller there is no runtime effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::caveats::{self, Caveat, Operation};
use crate::cbor;
use crate::device_cert::{DeviceCert, DeviceCertError};
use crate::ids::HouseholdId;
use crate::keys::{P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::{DeviceId, PersonId};
use crate::person_cert::PersonCert;

const SUBDIR: &str = "device_admission";
const RECORD_FILENAME: &str = "authority_v1.cbor";
const LOCK_FILENAME: &str = "authority_v1.lock";
const RECORD_VERSION: u8 = 1;
const LOCK_TIMEOUT: Duration = Duration::from_millis(5_000);
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

const ROOT_DIGEST_DOMAIN: &[u8] = b"soyeht/household-device-admission-root/v1\x00";
const SNAPSHOT_DOMAIN: &[u8] = b"soyeht/household-device-admission-snapshot/v1\x00";
/// Distinct from [`SNAPSHOT_DOMAIN`]: a `PersonCert` digest and a record digest
/// are different objects and must not share a separator, even though neither
/// currently decodes as the other.
const PERSON_CERT_DIGEST_DOMAIN: &[u8] = b"soyeht/household-device-admission-person-cert/v1\x00";
const REVOCATION_DOMAIN: &[u8] = b"soyeht/household-device-admission-revocation/v1\x00";
const ADD_POP_DOMAIN: &[u8] = b"soyeht/household-device-admission-add-pop/v1\x00";
const OWNER_REVOKE_POP_DOMAIN: &[u8] = b"soyeht/household-device-admission-owner-revoke-pop/v1\x00";
const SELF_REVOKE_POP_DOMAIN: &[u8] = b"soyeht/household-device-admission-self-revoke-pop/v1\x00";
const PERSON_REVOKE_POP_DOMAIN: &[u8] =
    b"soyeht/household-device-admission-person-revoke-pop/v1\x00";

// ─── Byte-string serde helpers (local; the store is deliberately its own) ────

mod bstr32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        let bytes = bytes.into_vec();
        if bytes.len() != 32 {
            return Err(D::Error::custom("expected a 32-byte string"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// A 32-byte digest or nonce on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes32(#[serde(with = "bstr32")] pub [u8; 32]);

// ─── Pair roles ─────────────────────────────────────────────────────────────

/// Which side of a device pair a member sits on.
///
/// The two sides are **not** interchangeable. A pair fact is sealed for one
/// ordering and authorizes only that ordering, so a caller cannot present the
/// responder where the initiator is expected.
///
/// The role also travels with every pair refusal. Without it, an initiator-side
/// and a responder-side failure of the same kind would be the same value, and a
/// negative test aimed at one side could pass because the *other* side refused
/// first — the refusal would be real but the test would be vacuous.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PairRole {
    Initiator,
    Responder,
}

impl PairRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

impl std::fmt::Display for PairRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ─── Closed error surface ───────────────────────────────────────────────────

/// Every way this authority can decline. There is no variant that means
/// "proceed without checking": absence, corruption, and staleness are all
/// terminal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceAdmissionError {
    #[error("device admission authority is absent; nothing is admitted")]
    Unavailable,
    #[error("device admission authority already exists")]
    AlreadyProvisioned,
    #[error("device admission record is not canonical or is corrupt")]
    RecordCorrupt,
    #[error("device admission generation is zero")]
    GenerationZero,
    #[error("device admission record belongs to another household or root")]
    WrongHousehold,
    #[error("device admission store I/O failed")]
    Io,
    #[error("device admission store lock could not be acquired")]
    LockTimeout,
    #[error("device admission store path is unsafe")]
    UnsafePath,
    #[error("owner person cert did not verify against the household root")]
    OwnerCertInvalid,
    #[error("owner person cert lacks the required capability")]
    OwnerCapabilityMissing,
    #[error("owner person is revoked")]
    PersonRevoked,
    #[error("device cert rejected: {0}")]
    DeviceCert(#[from] DeviceCertError),
    #[error("proof of possession did not verify")]
    PopInvalid,
    #[error("device is not present in the durable authority")]
    DeviceNotListed,
    #[error("device was revoked; a tombstone is never reopened")]
    DeviceRevoked,
    #[error("device is already admitted under a different binding")]
    BindingConflict,
    #[error("device is not a descendant of this person")]
    NotDescendant,
    #[error("owner person cert has expired")]
    PersonCertExpired,
    #[error("peer identity does not match the sealed admission byte for byte")]
    PeerIdentityMismatch,
    #[error("live authority moved since the admission was sealed")]
    StaleSeal,
    #[error("device admission encoding failed")]
    Encoding,
    /// A pair named one device twice, or named two `d_id`s that resolve to the
    /// same admitted key. Either way there is no second party, so there is no
    /// pair to authorize.
    #[error("a device pair must name two distinct admitted devices")]
    PairSameDevice,
    /// One side of a pair refused. The role is carried so the refusal is
    /// attributable: `cause` alone cannot say which device failed.
    #[error("pair {role} refused: {cause}")]
    PairMember {
        role: PairRole,
        cause: Box<DeviceAdmissionError>,
    },
}

impl DeviceAdmissionError {
    /// Attribute this refusal to one side of a pair.
    ///
    /// Private, and never applied to a [`Self::PairMember`], so the wrapping is
    /// exactly one level deep and [`Self::pair_member`] is total.
    fn at(self, role: PairRole) -> Self {
        debug_assert!(
            !matches!(self, Self::PairMember { .. }),
            "a pair refusal is attributed once"
        );
        Self::PairMember {
            role,
            cause: Box::new(self),
        }
    }

    /// The side that refused and why, when this is a pair refusal.
    ///
    /// Tests assert on this pair rather than on the bare cause: two sides can
    /// fail the same way, and only the role distinguishes them.
    #[must_use]
    pub fn pair_member(&self) -> Option<(PairRole, &DeviceAdmissionError)> {
        match self {
            Self::PairMember { role, cause } => Some((*role, cause)),
            _ => None,
        }
    }
}

/// Why a `consume_with_effect` call produced nothing.
///
/// The two arms are kept apart so a caller can never mistake "the authority
/// refused" for "your effect failed". `Admission` means the effect was never
/// invoked at all.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsumeError<E> {
    /// The fence rejected. `effect` was not called and nothing was authorized.
    #[error("device admission refused: {0}")]
    Admission(DeviceAdmissionError),
    /// The fence passed and `effect` itself failed. Whatever the effect did
    /// before failing is the effect's own business to unwind.
    #[error("authorized effect failed")]
    Effect(E),
}

impl<E> ConsumeError<E> {
    fn admission(error: DeviceAdmissionError) -> Self {
        Self::Admission(error)
    }

    /// The admission failure, if the fence is what refused.
    #[must_use]
    pub fn as_admission(&self) -> Option<&DeviceAdmissionError> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Effect(_) => None,
        }
    }
}

// ─── Durable record ─────────────────────────────────────────────────────────

/// Whether a `d_id` is currently admitted. `Revoked` is a tombstone: it is a
/// terminal state for that `d_id`, not a state an add can leave.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// One durable device row. Every field a consumer needs to bind an admission is
/// here, so no consumer has to reach into a second store.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAdmissionEntryV1 {
    pub d_pub: P256PublicKey,
    pub device_cert_digest: Bytes32,
    pub p_id: PersonId,
    pub person_cert_digest: Bytes32,
    pub narrowing_digest: Bytes32,
    /// The `DeviceCert`'s caveat set, copied exactly and never normalized.
    ///
    /// `narrowing_digest` proves a set narrowed correctly but does not say what
    /// the set *is*, so a consumer holding only the digest cannot evaluate an
    /// operation for this device — it cannot even tell an unattenuated device
    /// from an attenuated one. Storing the set itself is what makes a delegated
    /// authorization decidable from one snapshot.
    ///
    /// The `None` / `Some([])` distinction is load-bearing and must survive:
    /// `None` is "no attenuation declared, inherit the `PersonCert`", while
    /// `Some([])` is "attenuated to nothing". Collapsing them would erase an
    /// authorization decision. Storing a bool or marker instead would lose the
    /// set; storing the whole cert would duplicate an authority that
    /// `device_cert_digest` already binds.
    #[serde(deserialize_with = "deserialize_present_device_caveats")]
    pub device_caveats: Option<Vec<Caveat>>,
    /// Effective validity limit inherited from the owner `PersonCert`, when it
    /// has one. No device-level TTL is invented (R0a §6).
    pub person_not_after: Option<u64>,
    pub status: DeviceStatus,
    pub admitted_at_generation: u64,
    pub revoked_at_generation: Option<u64>,
}

/// Decode `device_caveats`, requiring the key to be **present**.
///
/// `Option<T>` alone is not enough: `serde`'s `missing_field` helper answers a
/// missing key by handing the field a deserializer that supports only
/// `deserialize_option`, so a plain `Option` field silently becomes `None` when
/// the key is absent. For this field that is the dangerous direction — `None`
/// means "no attenuation declared, inherit the `PersonCert`", so a dropped key
/// would read as an *unattenuated* device.
///
/// Dispatching through `deserialize_any` instead of `deserialize_option` is what
/// makes the key required: the missing-field deserializer cannot answer
/// `deserialize_any`, so an absent key is an error. Present values keep their
/// exact meaning — `null` is `None`, `[]` is `Some([])`, a list is `Some(list)`
/// — and serialization is untouched, so the encoded bytes and `RECORD_VERSION`
/// are unchanged.
fn deserialize_present_device_caveats<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<Caveat>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PresentCaveats;

    impl<'de> serde::de::Visitor<'de> for PresentCaveats {
        type Value = Option<Vec<Caveat>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("null or an array of caveats")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            Vec::<Caveat>::deserialize(deserializer).map(Some)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut caveats = Vec::new();
            while let Some(caveat) = seq.next_element::<Caveat>()? {
                caveats.push(caveat);
            }
            Ok(Some(caveats))
        }
    }

    deserializer.deserialize_any(PresentCaveats)
}

/// The single durable object. One file holds the whole authority.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAdmissionRecordV1 {
    #[serde(rename = "v")]
    pub version: u8,
    pub hh_id: HouseholdId,
    pub hh_root_digest: Bytes32,
    pub generation: u64,
    pub revocation_cursor: u64,
    pub revocation_digest: Bytes32,
    pub devices: BTreeMap<String, DeviceAdmissionEntryV1>,
    pub revoked_persons: BTreeSet<String>,
}

/// An atomic read of the authority plus the digest that identifies it.
///
/// A consumer reads one of these; it never composes root, cert, roster, and
/// revocation facts from independent reads (R0a §10).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceAdmissionSnapshotV1 {
    record: DeviceAdmissionRecordV1,
    snapshot_digest: [u8; 32],
}

impl DeviceAdmissionSnapshotV1 {
    #[must_use]
    pub fn record(&self) -> &DeviceAdmissionRecordV1 {
        &self.record
    }

    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.record.generation
    }

    #[must_use]
    pub fn entry(&self, d_id: &DeviceId) -> Option<&DeviceAdmissionEntryV1> {
        self.record.devices.get(&d_id.0)
    }

    #[must_use]
    pub fn is_person_revoked(&self, p_id: &PersonId) -> bool {
        self.record.revoked_persons.contains(&p_id.0)
    }
}

/// Which step of the durable write was reached. The partition into "before the
/// rename" and "from the rename onward" is the whole point of this type: it is
/// what lets a failure be reported as *provably* no-effect instead of merely
/// hoped to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitStage {
    // ── strictly before `fs::rename` returns Ok: the target is untouched ──
    TmpStat,
    TmpOpen,
    TmpWrite,
    TmpFlush,
    TmpSync,
    /// `fs::rename` itself failed. `rename(2)` is atomic, so the target either
    /// was replaced or was not; an error means it was not.
    Rename,
    // ── from `fs::rename` Ok onward: the new bytes may already be visible ──
    ParentOpen,
    ParentSync,
    Readback,
    ReadbackMismatch,
}

impl CommitStage {
    /// True when reaching this stage proves the target was never replaced.
    ///
    /// Deliberately an exhaustive `match` rather than `matches!`: a new stage
    /// must be classified here before the crate compiles. Silently defaulting a
    /// new stage to either side is precisely how a post-rename failure would
    /// start being reported as no-effect again.
    #[must_use]
    pub fn is_pre_rename(self) -> bool {
        match self {
            Self::TmpStat
            | Self::TmpOpen
            | Self::TmpWrite
            | Self::TmpFlush
            | Self::TmpSync
            | Self::Rename => true,
            Self::ParentOpen | Self::ParentSync | Self::Readback | Self::ReadbackMismatch => false,
        }
    }
}

/// The honest result of one durable write.
///
/// There is deliberately no `Result<(), _>` here. Collapsing this into
/// `Err` is what let an add that had already replaced the record be reported to
/// its caller as a failure (R0a §12 "falha sempre produz zero efeito", violated
/// in the dangerous direction).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DurableCommit {
    /// Renamed, parent-fsynced, and read back byte-identical.
    Committed,
    /// Failed strictly before the rename. The target is untouched.
    NotCommitted { stage: CommitStage },
    /// The rename succeeded and a later step did not. The new bytes are
    /// observable now and may or may not survive a crash — between `rename` Ok
    /// and the parent-directory fsync, either version may persist. This is
    /// never "no effect".
    CommitUncertain { stage: CommitStage },
}

/// The result of a mutation. `Idempotent` means the durable bytes and the
/// generation were both left untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MutationOutcome {
    Applied {
        generation: u64,
    },
    Idempotent {
        generation: u64,
    },
    /// The mutation may have taken effect. It carries no claim either way on
    /// purpose — there is no `applied: bool` to read the wrong way. The caller
    /// must re-read the live authority before reporting anything to a user.
    ///
    /// Reconciliation, per operation:
    ///
    /// - **add** — entry `Active` with the same `device_cert_digest` ⇒ treat as
    ///   applied. Absent ⇒ mint a fresh `PoP` against the *current* generation
    ///   and retry. A stale `PoP` can never re-apply, which makes retry safe.
    /// - **revoke** (owner / self / person) — status `Revoked` ⇒ treat as
    ///   applied. Otherwise retry freely: revoke is fail-safe and idempotent.
    /// - **provision** — a valid record at generation 1 under the same root ⇒
    ///   treat as provisioned. Never re-provision blindly.
    Uncertain {
        attempted_generation: u64,
        stage: CommitStage,
    },
}

impl MutationOutcome {
    /// The generation the caller may rely on. `None` for [`Self::Uncertain`],
    /// because no generation is known to be durable until the caller re-reads.
    #[must_use]
    pub fn generation(self) -> Option<u64> {
        match self {
            Self::Applied { generation } | Self::Idempotent { generation } => Some(generation),
            Self::Uncertain { .. } => None,
        }
    }

    /// True when the durable state is known to hold the intended transition.
    #[must_use]
    pub fn is_settled(self) -> bool {
        matches!(self, Self::Applied { .. } | Self::Idempotent { .. })
    }
}

// ─── Sealed admission fact ──────────────────────────────────────────────────

/// A server-local, opaque, once-consumable admission fact (R0a §4).
///
/// Deliberately not `Clone`, `Copy`, `Default`, `Serialize`, `Deserialize`, or
/// convertible from any untrusted type: cloning it would multiply an
/// authorization, and serializing it would turn a capability into a wire
/// format. It is produced only by [`HouseholdDeviceAdmissionAuthorityV1::seal`]
/// and accepted only by [`HouseholdDeviceAdmissionAuthorityV1::consume`], which
/// takes it by value so it cannot be presented twice.
pub struct SealedDeviceAdmissionV1 {
    contract_version: u8,
    hh_id: HouseholdId,
    d_id: DeviceId,
    p_id: PersonId,
    peer_identity_pub_sec1: [u8; 33],
    device_cert_digest: [u8; 32],
    person_cert_digest: [u8; 32],
    narrowing_digest: [u8; 32],
    hh_root_digest: [u8; 32],
    generation: u64,
    revocation_cursor: u64,
    revocation_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    person_not_after: Option<u64>,
    verified_at: u64,
}

impl SealedDeviceAdmissionV1 {
    pub const CONTRACT_VERSION: u8 = 1;

    /// The full 33-byte SEC1 point this fact admits. Never truncated to x-only
    /// and never replaced by a target, endpoint, or router decision (R0a §5).
    #[must_use]
    pub fn peer_identity_pub_sec1(&self) -> &[u8; 33] {
        &self.peer_identity_pub_sec1
    }

    #[must_use]
    pub fn d_id(&self) -> &DeviceId {
        &self.d_id
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

impl std::fmt::Debug for SealedDeviceAdmissionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SealedDeviceAdmissionV1(REDACTED)")
    }
}

/// Proof that a sealed admission was rechecked against the live authority and
/// consumed at the same atomic point that authorizes the effect. Also opaque
/// and move-only.
pub struct ConsumedDeviceAdmissionV1 {
    d_id: DeviceId,
    peer_identity_pub_sec1: [u8; 33],
    generation: u64,
    snapshot_digest: [u8; 32],
    consumed_at: u64,
}

impl ConsumedDeviceAdmissionV1 {
    #[must_use]
    pub fn peer_identity_pub_sec1(&self) -> &[u8; 33] {
        &self.peer_identity_pub_sec1
    }

    #[must_use]
    pub fn d_id(&self) -> &DeviceId {
        &self.d_id
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn consumed_at(&self) -> u64 {
        self.consumed_at
    }
}

impl std::fmt::Debug for ConsumedDeviceAdmissionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConsumedDeviceAdmissionV1(REDACTED)")
    }
}

// ─── Pair effect outcome — closed, fieldless, non-deferrable ────────────────

/// Why an authorized pair effect did not apply.
///
/// **Fieldless on purpose, and this is load-bearing.** Any caller-chosen type
/// in this position reopens the deferral channel the pair fence exists to
/// close. It is not enough to pin the *success* type to `()`: the error arm is
/// returned by value after the lock has dropped, so with a generic `E` a caller
/// writes
///
/// ```text
/// let r = auth.consume_pair_with_effect(sealed, a, b, now, |_| Err(async move { dial().await }));
/// if let Err(ConsumePairError::Effect(fut)) = r { fut.await; }   // after the fence
/// ```
///
/// and defers exactly as `Ok(async move { … })` would have — only the arm
/// changed. Measured against the previous head: that shape compiled and ran,
/// returning its value after the lock was released. There is no trait bound
/// that excludes a lazily-evaluated type, and a source guard cannot help
/// because the type is chosen at the call site in another crate. So the type
/// itself is closed rather than bounded.
///
/// Carrying detail is therefore the caller's own business, on the caller's own
/// side of the fence: map a private error into one of these variants and log,
/// wrap, or store the detail before returning.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum PairEffectFailure {
    /// The effect did not apply. Nothing was changed.
    #[error("the authorized pair effect did not apply")]
    NotApplied,
    /// The caller's own policy declined, after the fence had already passed.
    #[error("the authorized pair effect was declined by the caller")]
    Declined,
    /// The effect applied partially. The caller must reconcile; the authority
    /// itself is untouched either way, since the fence never writes.
    #[error("the authorized pair effect applied partially and needs reconciliation")]
    Incomplete,
}

/// Why a `consume_pair_with_effect` call produced nothing.
///
/// Non-generic in both arms, unlike [`ConsumeError`]. The two arms stay apart
/// so a caller can never mistake "the authority refused" for "your effect
/// failed": [`Self::Admission`] means the effect was never invoked at all.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ConsumePairError {
    /// The fence rejected. `effect` was not called and nothing was authorized.
    #[error("device pair admission refused: {0}")]
    Admission(DeviceAdmissionError),
    /// The fence passed and `effect` itself declined.
    #[error("authorized pair effect failed: {0}")]
    Effect(PairEffectFailure),
}

impl ConsumePairError {
    fn admission(error: DeviceAdmissionError) -> Self {
        Self::Admission(error)
    }

    /// The admission failure, if the fence is what refused.
    #[must_use]
    pub fn as_admission(&self) -> Option<&DeviceAdmissionError> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Effect(_) => None,
        }
    }
}

// ─── Sealed device-pair admission fact ──────────────────────────────────────

/// One side of a pair, as read from the authority.
///
/// Deliberately carries **no** generation, revocation cursor, revocation
/// digest, snapshot digest, or root digest. Those live exactly once, on the
/// pair itself. That absence is the atomicity guarantee expressed in the type:
/// there is no way to represent a pair whose two members came from different
/// snapshots, because there is nowhere to put the second snapshot.
///
/// Also not `Clone`/`Copy`/`Default`/`Serialize`/`Deserialize`: a member
/// binding is part of a capability, not a wire format, and copying one would
/// let a pair be re-assembled out of halves.
pub struct PairMemberBindingV1 {
    role: PairRole,
    d_id: DeviceId,
    p_id: PersonId,
    peer_identity_pub_sec1: [u8; 33],
    device_cert_digest: [u8; 32],
    person_cert_digest: [u8; 32],
    narrowing_digest: [u8; 32],
    person_not_after: Option<u64>,
}

impl PairMemberBindingV1 {
    #[must_use]
    pub fn role(&self) -> PairRole {
        self.role
    }

    #[must_use]
    pub fn d_id(&self) -> &DeviceId {
        &self.d_id
    }

    #[must_use]
    pub fn p_id(&self) -> &PersonId {
        &self.p_id
    }

    /// The full 33-byte SEC1 point this side admits. Never truncated to x-only
    /// and never replaced by a target, endpoint, or router decision (R0a §5).
    #[must_use]
    pub fn peer_identity_pub_sec1(&self) -> &[u8; 33] {
        &self.peer_identity_pub_sec1
    }

    #[must_use]
    pub fn person_not_after(&self) -> Option<u64> {
        self.person_not_after
    }
}

impl std::fmt::Debug for PairMemberBindingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairMemberBindingV1(REDACTED)")
    }
}

/// A server-local, opaque, once-consumable fact that **two** devices were
/// admitted together, under one generation, read under one lock.
///
/// # Why this is not two singular facts
///
/// [`HouseholdDeviceAdmissionAuthorityV1::seal`] and
/// [`HouseholdDeviceAdmissionAuthorityV1::consume_with_effect`] each authorize
/// exactly one device. Composing them for two devices is not a weaker version
/// of this type — it is a different and unsound one:
///
/// - **it proves nothing about simultaneity.** Each singular consume takes the
///   store lock, runs its recheck, and *releases* it. A revoke landing between
///   the two consumes leaves both of them returning success, so a caller that
///   treats "A authorized" plus "B authorized" as "the pair is authorized"
///   authorizes a pair in which one side is already revoked. There is no
///   instant at which both facts were true.
/// - **it cannot be fixed by nesting.** Calling the second consume from inside
///   the first one's effect deadlocks: `flock(2)` binds to the open file
///   description and every acquire opens a fresh descriptor, so the inner
///   acquire blocks for the whole [`LOCK_TIMEOUT`] and then fails.
///
/// Both are exercised by
/// `composing_two_singular_admissions_authorizes_a_pair_the_atomic_fence_refuses`
/// and `nested_singular_consume_deadlocks_rather_than_composing`.
///
/// The single `generation` / `revocation_cursor` / `revocation_digest` /
/// `snapshot_digest` set below is what closes that hole structurally: both
/// members are read out of one snapshot, so "same generation" is not a check
/// that can be forgotten — it is the only representable state.
///
/// Opacity rules match [`SealedDeviceAdmissionV1`]: not `Clone`, `Copy`,
/// `Default`, `Serialize`, `Deserialize`, or constructible from any untrusted
/// input. It is produced only by
/// [`HouseholdDeviceAdmissionAuthorityV1::seal_pair`] and accepted only by
/// [`HouseholdDeviceAdmissionAuthorityV1::consume_pair_with_effect`], which
/// takes it by value so it cannot be presented twice.
pub struct SealedDevicePairAdmissionV1 {
    contract_version: u8,
    hh_id: HouseholdId,
    hh_root_digest: [u8; 32],
    initiator: PairMemberBindingV1,
    responder: PairMemberBindingV1,
    generation: u64,
    revocation_cursor: u64,
    revocation_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    verified_at: u64,
}

impl SealedDevicePairAdmissionV1 {
    pub const CONTRACT_VERSION: u8 = 1;

    #[must_use]
    pub fn initiator(&self) -> &PairMemberBindingV1 {
        &self.initiator
    }

    #[must_use]
    pub fn responder(&self) -> &PairMemberBindingV1 {
        &self.responder
    }

    #[must_use]
    pub fn member(&self, role: PairRole) -> &PairMemberBindingV1 {
        match role {
            PairRole::Initiator => &self.initiator,
            PairRole::Responder => &self.responder,
        }
    }

    /// The one generation both sides were admitted under.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The one snapshot digest both sides were read from.
    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

impl std::fmt::Debug for SealedDevicePairAdmissionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SealedDevicePairAdmissionV1(REDACTED)")
    }
}

/// Proof that a sealed pair was rechecked against the live authority and
/// consumed at the same atomic point that authorizes the effect.
///
/// The member bindings are **moved** out of the sealed fact rather than copied,
/// so the sealed pair is destroyed by consuming it. Also opaque and move-only.
pub struct ConsumedDevicePairAdmissionV1 {
    initiator: PairMemberBindingV1,
    responder: PairMemberBindingV1,
    generation: u64,
    snapshot_digest: [u8; 32],
    consumed_at: u64,
}

impl ConsumedDevicePairAdmissionV1 {
    #[must_use]
    pub fn initiator(&self) -> &PairMemberBindingV1 {
        &self.initiator
    }

    #[must_use]
    pub fn responder(&self) -> &PairMemberBindingV1 {
        &self.responder
    }

    #[must_use]
    pub fn member(&self, role: PairRole) -> &PairMemberBindingV1 {
        match role {
            PairRole::Initiator => &self.initiator,
            PairRole::Responder => &self.responder,
        }
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    #[must_use]
    pub fn consumed_at(&self) -> u64 {
        self.consumed_at
    }
}

impl std::fmt::Debug for ConsumedDevicePairAdmissionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConsumedDevicePairAdmissionV1(REDACTED)")
    }
}

// ─── Proof-of-possession preimages ──────────────────────────────────────────

/// Add-PoP preimage. It binds the current `generation`, which is what makes the
/// proof fresh *per add* without an unbounded nonce ledger: a successful add
/// increments the generation, so the same signature can never authorize a
/// second one. It also binds `d_id`, `d_pub`, and both cert digests, so a `PoP`
/// minted for one device cannot admit another.
#[derive(Serialize)]
struct AddPopPreimage {
    hh_id: String,
    generation: u64,
    d_id: String,
    d_pub: P256PublicKey,
    device_cert_digest: Bytes32,
    person_cert_digest: Bytes32,
    nonce: Bytes32,
}

/// Revoke-PoP preimages deliberately do NOT bind the generation. Revocation is
/// fail-safe — it removes authority and never grants it — so a replayed revoke
/// must be idempotent rather than rejected (R0a §8 D2-A).
#[derive(Serialize)]
struct OwnerRevokePopPreimage {
    hh_id: String,
    d_id: String,
    nonce: Bytes32,
}

#[derive(Serialize)]
struct SelfRevokePopPreimage {
    hh_id: String,
    d_id: String,
    d_pub: P256PublicKey,
    nonce: Bytes32,
}

#[derive(Serialize)]
struct PersonRevokePopPreimage {
    hh_id: String,
    p_id: String,
    nonce: Bytes32,
}

#[derive(Serialize)]
struct RevocationEvent {
    kind: &'static str,
    subject: String,
    generation: u64,
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn preimage_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], DeviceAdmissionError> {
    let bytes = cbor::to_canonical_vec(value).map_err(|_| DeviceAdmissionError::Encoding)?;
    Ok(domain_digest(domain, &bytes))
}

/// Digest of the household root public key. Used as the record's root binding
/// so a record cannot be moved under a different root.
#[must_use]
pub fn household_root_digest(hh_pub: &P256PublicKey) -> [u8; 32] {
    domain_digest(ROOT_DIGEST_DOMAIN, hh_pub.as_bytes())
}

fn snapshot_digest_of(record: &DeviceAdmissionRecordV1) -> Result<[u8; 32], DeviceAdmissionError> {
    preimage_digest(SNAPSHOT_DOMAIN, record)
}

// ─── Store paths and lock ───────────────────────────────────────────────────

fn store_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(SUBDIR)
}

fn record_path(state_dir: &Path) -> PathBuf {
    store_dir(state_dir).join(RECORD_FILENAME)
}

fn lock_file_path(state_dir: &Path) -> PathBuf {
    store_dir(state_dir).join(LOCK_FILENAME)
}

/// RAII exclusive lock over the whole read-modify-write of the single record.
struct StoreLock {
    _file: File,
}

impl StoreLock {
    fn acquire(state_dir: &Path) -> Result<Self, DeviceAdmissionError> {
        let dir = store_dir(state_dir);
        fs::create_dir_all(&dir).map_err(|_| DeviceAdmissionError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::symlink_metadata(&dir).map_err(|_| DeviceAdmissionError::Io)?;
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(DeviceAdmissionError::UnsafePath);
            }
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| DeviceAdmissionError::Io)?;
        }

        let path = lock_file_path(state_dir);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
                return Err(DeviceAdmissionError::UnsafePath);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DeviceAdmissionError::Io),
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| DeviceAdmissionError::Io)?;

        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(DeviceAdmissionError::LockTimeout);
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(_) => return Err(DeviceAdmissionError::Io),
            }
        }
        Ok(Self { _file: file })
    }
}

/// Write `canonical` over `target` atomically and report honestly how far it
/// got.
///
/// Every early return before `fs::rename` returns `Ok` is
/// [`DurableCommit::NotCommitted`] — the target is provably untouched. Every
/// failure at or after that point is [`DurableCommit::CommitUncertain`], never
/// an error, because the replacement is already observable. Only the readback
/// compare licenses [`DurableCommit::Committed`], and only that licenses
/// advancing the in-memory projection.
fn atomic_replace(target: &Path, canonical: &[u8]) -> DurableCommit {
    let not_committed = |stage| DurableCommit::NotCommitted { stage };

    let Some(parent) = target.parent() else {
        return not_committed(CommitStage::TmpStat);
    };
    let Some(file_name) = target.file_name().and_then(|name| name.to_str()) else {
        return not_committed(CommitStage::TmpStat);
    };
    let tmp = parent.join(format!("{file_name}.tmp"));

    #[cfg(test)]
    if fail_injection::take(CommitStage::TmpStat) {
        return not_committed(CommitStage::TmpStat);
    }
    match fs::symlink_metadata(&tmp) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
            return not_committed(CommitStage::TmpStat);
        }
        Ok(_) => {
            if fs::remove_file(&tmp).is_err() {
                return not_committed(CommitStage::TmpStat);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return not_committed(CommitStage::TmpStat),
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(test)]
    if fail_injection::take(CommitStage::TmpOpen) {
        return not_committed(CommitStage::TmpOpen);
    }
    let Ok(mut file) = opts.open(&tmp) else {
        return not_committed(CommitStage::TmpOpen);
    };

    #[cfg(test)]
    if fail_injection::take(CommitStage::TmpWrite) {
        return not_committed(CommitStage::TmpWrite);
    }
    if file.write_all(canonical).is_err() {
        return not_committed(CommitStage::TmpWrite);
    }
    #[cfg(test)]
    if fail_injection::take(CommitStage::TmpFlush) {
        return not_committed(CommitStage::TmpFlush);
    }
    if file.flush().is_err() {
        return not_committed(CommitStage::TmpFlush);
    }
    #[cfg(test)]
    if fail_injection::take(CommitStage::TmpSync) {
        return not_committed(CommitStage::TmpSync);
    }
    if file.sync_all().is_err() {
        return not_committed(CommitStage::TmpSync);
    }
    drop(file);

    // ── the boundary ────────────────────────────────────────────────────────
    // Everything above leaves `target` untouched. Everything below has already
    // replaced it.
    #[cfg(test)]
    if fail_injection::take(CommitStage::Rename) {
        return not_committed(CommitStage::Rename);
    }
    if fs::rename(&tmp, target).is_err() {
        return not_committed(CommitStage::Rename);
    }

    let uncertain = |stage| DurableCommit::CommitUncertain { stage };

    #[cfg(test)]
    if fail_injection::take(CommitStage::ParentOpen) {
        return uncertain(CommitStage::ParentOpen);
    }
    let Ok(dir) = File::open(parent) else {
        return uncertain(CommitStage::ParentOpen);
    };
    #[cfg(test)]
    if fail_injection::take(CommitStage::ParentSync) {
        return uncertain(CommitStage::ParentSync);
    }
    if dir.sync_all().is_err() {
        return uncertain(CommitStage::ParentSync);
    }

    #[cfg(test)]
    if fail_injection::take(CommitStage::Readback) {
        return uncertain(CommitStage::Readback);
    }
    let Ok(readback) = fs::read(target) else {
        return uncertain(CommitStage::Readback);
    };
    #[cfg(test)]
    if fail_injection::take(CommitStage::ReadbackMismatch) {
        return uncertain(CommitStage::ReadbackMismatch);
    }
    if readback != canonical {
        return uncertain(CommitStage::ReadbackMismatch);
    }
    DurableCommit::Committed
}

/// Deterministic, per-stage failure injection for the durable writer.
///
/// Thread-local and one-shot, so a test arms exactly one stage and the next
/// write past that stage runs normally. `std` only — no new dependency. Kept in
/// its own `#[cfg(test)]` module so the R0a scope guard can excise it as a
/// delimited region rather than having attributes scattered at file scope.
#[cfg(test)]
mod fail_injection {
    use super::CommitStage;

    thread_local! {
        static ARMED: std::cell::Cell<Option<CommitStage>> = const { std::cell::Cell::new(None) };
    }

    /// Disarms on drop so one test cannot leak an armed stage into another.
    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            ARMED.with(|slot| slot.set(None));
        }
    }

    pub(super) fn arm(stage: CommitStage) -> Armed {
        ARMED.with(|slot| slot.set(Some(stage)));
        Armed
    }

    /// Consume the arming if it matches `stage`.
    pub(super) fn take(stage: CommitStage) -> bool {
        ARMED.with(|slot| {
            if slot.get() == Some(stage) {
                slot.set(None);
                true
            } else {
                false
            }
        })
    }
}

/// Decode the durable record, requiring byte-exact canonical form.
fn decode_record(bytes: &[u8]) -> Result<DeviceAdmissionRecordV1, DeviceAdmissionError> {
    let record: DeviceAdmissionRecordV1 =
        cbor::from_canonical_slice(bytes).map_err(|_| DeviceAdmissionError::RecordCorrupt)?;
    if record.version != RECORD_VERSION {
        return Err(DeviceAdmissionError::RecordCorrupt);
    }
    let re_encoded =
        cbor::to_canonical_vec(&record).map_err(|_| DeviceAdmissionError::RecordCorrupt)?;
    if re_encoded != bytes {
        return Err(DeviceAdmissionError::RecordCorrupt);
    }
    Ok(record)
}

// ─── The authority ──────────────────────────────────────────────────────────

/// The durable device admission authority for one household.
pub struct HouseholdDeviceAdmissionAuthorityV1 {
    state_dir: PathBuf,
    hh_id: HouseholdId,
    hh_pub: P256PublicKey,
    hh_root_digest: [u8; 32],
    /// Last projection known to be durable. Advanced only after a successful
    /// persist + readback, cleared on any failure — never ahead of disk.
    projection: Mutex<Option<DeviceAdmissionSnapshotV1>>,
}

impl HouseholdDeviceAdmissionAuthorityV1 {
    /// Bind an authority to a state directory and a household root.
    #[must_use]
    pub fn new(state_dir: &Path, hh_id: HouseholdId, hh_pub: P256PublicKey) -> Self {
        let hh_root_digest = household_root_digest(&hh_pub);
        Self {
            state_dir: state_dir.to_path_buf(),
            hh_id,
            hh_pub,
            hh_root_digest,
            projection: Mutex::new(None),
        }
    }

    /// Create the durable object with generation 1 and no devices.
    ///
    /// Provisioning is explicit: a missing object is never auto-created as an
    /// empty-but-usable authority, because "no file" and "an authority that
    /// admits nobody yet" must not be the same observable state.
    pub fn provision(&self) -> Result<MutationOutcome, DeviceAdmissionError> {
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let path = record_path(&self.state_dir);
        if path.exists() {
            return Err(DeviceAdmissionError::AlreadyProvisioned);
        }
        let record = DeviceAdmissionRecordV1 {
            version: RECORD_VERSION,
            hh_id: self.hh_id.clone(),
            hh_root_digest: Bytes32(self.hh_root_digest),
            generation: 1,
            revocation_cursor: 0,
            revocation_digest: Bytes32(domain_digest(REVOCATION_DOMAIN, b"genesis")),
            devices: BTreeMap::new(),
            revoked_persons: BTreeSet::new(),
        };
        self.settle(&record)
    }

    /// Read the live authority from disk. Every authorization and every consume
    /// goes through this — the cached projection is never a substitute.
    pub fn live_snapshot(&self) -> Result<DeviceAdmissionSnapshotV1, DeviceAdmissionError> {
        let path = record_path(&self.state_dir);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.clear_projection();
                return Err(DeviceAdmissionError::Unavailable);
            }
            Err(_) => {
                self.clear_projection();
                return Err(DeviceAdmissionError::Io);
            }
        };
        let record = decode_record(&bytes).inspect_err(|_| self.clear_projection())?;
        if record.generation == 0 {
            self.clear_projection();
            return Err(DeviceAdmissionError::GenerationZero);
        }
        if record.hh_id != self.hh_id || record.hh_root_digest.0 != self.hh_root_digest {
            self.clear_projection();
            return Err(DeviceAdmissionError::WrongHousehold);
        }
        let snapshot_digest = snapshot_digest_of(&record)?;
        Ok(DeviceAdmissionSnapshotV1 {
            record,
            snapshot_digest,
        })
    }

    /// The last projection proven durable, if any. Never advanced past disk.
    #[must_use]
    pub fn durable_projection(&self) -> Option<DeviceAdmissionSnapshotV1> {
        self.projection.lock().ok().and_then(|guard| guard.clone())
    }

    fn clear_projection(&self) {
        if let Ok(mut guard) = self.projection.lock() {
            *guard = None;
        }
    }

    /// Persist-before-memory: encode, write durably, read back, and only then
    /// publish the projection.
    ///
    /// The projection is cleared *before* the write and re-published only on
    /// [`DurableCommit::Committed`], so it is never ahead of disk — and under
    /// `CommitUncertain` it stays cleared, forcing the next read to go to disk.
    fn persist(
        &self,
        record: &DeviceAdmissionRecordV1,
    ) -> Result<DurableCommit, DeviceAdmissionError> {
        let canonical =
            cbor::to_canonical_vec(record).map_err(|_| DeviceAdmissionError::Encoding)?;
        let snapshot_digest = snapshot_digest_of(record)?;
        self.clear_projection();
        let commit = atomic_replace(&record_path(&self.state_dir), &canonical);
        if commit == DurableCommit::Committed {
            if let Ok(mut guard) = self.projection.lock() {
                *guard = Some(DeviceAdmissionSnapshotV1 {
                    record: record.clone(),
                    snapshot_digest,
                });
            }
        }
        Ok(commit)
    }

    /// Persist `record` and translate the commit into an honest outcome.
    ///
    /// A pre-rename failure becomes `Err` — the caller may treat that, and only
    /// that, as zero effect. A post-rename failure becomes
    /// [`MutationOutcome::Uncertain`], never an error.
    fn settle(
        &self,
        record: &DeviceAdmissionRecordV1,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        match self.persist(record)? {
            DurableCommit::Committed => Ok(MutationOutcome::Applied {
                generation: record.generation,
            }),
            DurableCommit::NotCommitted { stage } => Err(if stage == CommitStage::TmpStat {
                DeviceAdmissionError::UnsafePath
            } else {
                DeviceAdmissionError::Io
            }),
            DurableCommit::CommitUncertain { stage } => Ok(MutationOutcome::Uncertain {
                attempted_generation: record.generation,
                stage,
            }),
        }
    }

    /// Verify the owner `PersonCert` against the live household root and
    /// require an explicit capability. The household root stays the only root
    /// of trust; the person key only signs the `DeviceCert` (R0a §8 D2-A).
    fn verify_owner(
        &self,
        person_cert: &PersonCert,
        required: &Operation,
        now: u64,
    ) -> Result<(), DeviceAdmissionError> {
        person_cert
            .verify(&self.hh_id, &self.hh_pub, now)
            .map_err(|_| DeviceAdmissionError::OwnerCertInvalid)?;
        if !caveats::permits(&person_cert.caveats, required) {
            return Err(DeviceAdmissionError::OwnerCapabilityMissing);
        }
        Ok(())
    }

    // ── Add ────────────────────────────────────────────────────────────────

    /// Admit a device (R0a §8 D2-A "Add").
    ///
    /// Requires a current owner `PersonCert`, a fresh domain-separated `PoP` for
    /// *this* add, and a `DeviceCert` signed by the person key and validated in
    /// full — including the closed caveat narrowing. The new device never signs
    /// its own admission: the only signature that authorizes this call is the
    /// owner's, over a preimage the device cannot substitute.
    ///
    /// The capability required is `household.add_device`, checked by the
    /// narrowing verifier. `household.add_machine` is a different operation and
    /// never reaches this surface.
    pub fn admit_device(
        &self,
        person_cert: &PersonCert,
        device_cert: &DeviceCert,
        owner_pop: &P256Signature,
        pop_nonce: &[u8; 32],
        now: u64,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let snapshot = self.live_snapshot()?;

        // The owner cert must be valid under the live root before anything else
        // is considered. `household.revoke` is not required to add.
        person_cert
            .verify(&self.hh_id, &self.hh_pub, now)
            .map_err(|_| DeviceAdmissionError::OwnerCertInvalid)?;
        if snapshot.is_person_revoked(&person_cert.p_id) {
            return Err(DeviceAdmissionError::PersonRevoked);
        }

        // Full device-cert validation, including the explicit
        // `household.add_device` grant and the closed narrowing order.
        let narrowing = device_cert.verify_against_person_cert(person_cert)?;
        let device_cert_digest = device_cert
            .digest()
            .map_err(|_| DeviceAdmissionError::Encoding)?;
        let person_cert_digest = person_cert_digest(person_cert)?;

        // Fresh, domain-separated owner PoP bound to this generation and this
        // exact device. Verified under the person key — never the device key.
        let preimage = AddPopPreimage {
            hh_id: self.hh_id.0.clone(),
            generation: snapshot.generation(),
            d_id: device_cert.d_id.0.clone(),
            d_pub: device_cert.d_pub.clone(),
            device_cert_digest: Bytes32(device_cert_digest),
            person_cert_digest: Bytes32(person_cert_digest),
            nonce: Bytes32(*pop_nonce),
        };
        let challenge = preimage_digest(ADD_POP_DOMAIN, &preimage)?;
        verify_signature(&person_cert.p_pub, &challenge, owner_pop)
            .map_err(|_| DeviceAdmissionError::PopInvalid)?;

        let mut record = snapshot.record.clone();
        if let Some(existing) = record.devices.get(&device_cert.d_id.0) {
            // A tombstone is terminal: a replayed or late add never reopens it.
            if existing.status == DeviceStatus::Revoked {
                return Err(DeviceAdmissionError::DeviceRevoked);
            }
            // The caveat set is compared directly, not merely via
            // `device_cert_digest`. The digest covers the caveats of the cert
            // being *presented*; comparing the stored set as well means a
            // durable entry whose caveats disagree with that cert can never
            // ride a matching digest into an idempotent no-op.
            let same_binding = existing.d_pub == device_cert.d_pub
                && existing.device_cert_digest.0 == device_cert_digest
                && existing.p_id == person_cert.p_id
                && existing.person_cert_digest.0 == person_cert_digest
                && existing.device_caveats == device_cert.caveats;
            if same_binding {
                return Ok(MutationOutcome::Idempotent {
                    generation: record.generation,
                });
            }
            return Err(DeviceAdmissionError::BindingConflict);
        }

        record.generation += 1;
        record.devices.insert(
            device_cert.d_id.0.clone(),
            DeviceAdmissionEntryV1 {
                d_pub: device_cert.d_pub.clone(),
                device_cert_digest: Bytes32(device_cert_digest),
                p_id: person_cert.p_id.clone(),
                person_cert_digest: Bytes32(person_cert_digest),
                narrowing_digest: Bytes32(*narrowing.digest()),
                // Copied exactly: `None` stays `None`, `Some([])` stays
                // `Some([])`. Normalizing either way would erase a decision.
                device_caveats: device_cert.caveats.clone(),
                person_not_after: person_cert.not_after,
                status: DeviceStatus::Active,
                admitted_at_generation: record.generation,
                revoked_at_generation: None,
            },
        );
        self.settle(&record)
    }

    // ── Revoke ─────────────────────────────────────────────────────────────

    /// Owner-authorized revocation of a descendant device.
    pub fn revoke_device_as_owner(
        &self,
        person_cert: &PersonCert,
        d_id: &DeviceId,
        owner_pop: &P256Signature,
        pop_nonce: &[u8; 32],
        now: u64,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let snapshot = self.live_snapshot()?;
        self.verify_owner(person_cert, &Operation::HouseholdRevoke, now)?;

        let entry = snapshot
            .entry(d_id)
            .ok_or(DeviceAdmissionError::DeviceNotListed)?;
        if entry.p_id != person_cert.p_id {
            return Err(DeviceAdmissionError::NotDescendant);
        }

        let preimage = OwnerRevokePopPreimage {
            hh_id: self.hh_id.0.clone(),
            d_id: d_id.0.clone(),
            nonce: Bytes32(*pop_nonce),
        };
        let challenge = preimage_digest(OWNER_REVOKE_POP_DOMAIN, &preimage)?;
        verify_signature(&person_cert.p_pub, &challenge, owner_pop)
            .map_err(|_| DeviceAdmissionError::PopInvalid)?;

        self.apply_device_revocation(snapshot.record.clone(), d_id, "device-owner")
    }

    /// A device revokes itself, and only itself, by proving possession of the
    /// same `d_pub` the authority already holds.
    ///
    /// This surface cannot add a device, revoke a sibling, revoke a person,
    /// revoke a machine, or widen a caveat — none of those operations exist
    /// here, and the `PoP` is checked against the target entry's own stored key,
    /// so a signature from any other key fails.
    pub fn self_revoke_device(
        &self,
        d_id: &DeviceId,
        device_pop: &P256Signature,
        pop_nonce: &[u8; 32],
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let snapshot = self.live_snapshot()?;
        let entry = snapshot
            .entry(d_id)
            .ok_or(DeviceAdmissionError::DeviceNotListed)?;

        let preimage = SelfRevokePopPreimage {
            hh_id: self.hh_id.0.clone(),
            d_id: d_id.0.clone(),
            d_pub: entry.d_pub.clone(),
            nonce: Bytes32(*pop_nonce),
        };
        let challenge = preimage_digest(SELF_REVOKE_POP_DOMAIN, &preimage)?;
        verify_signature(&entry.d_pub, &challenge, device_pop)
            .map_err(|_| DeviceAdmissionError::PopInvalid)?;

        self.apply_device_revocation(snapshot.record.clone(), d_id, "device-self")
    }

    /// Owner-authorized revocation of a person, cascading to every descendant
    /// device (R0a §8 D2-A).
    pub fn revoke_person_as_owner(
        &self,
        person_cert: &PersonCert,
        target_p_id: &PersonId,
        owner_pop: &P256Signature,
        pop_nonce: &[u8; 32],
        now: u64,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let snapshot = self.live_snapshot()?;
        self.verify_owner(person_cert, &Operation::HouseholdRevoke, now)?;

        let preimage = PersonRevokePopPreimage {
            hh_id: self.hh_id.0.clone(),
            p_id: target_p_id.0.clone(),
            nonce: Bytes32(*pop_nonce),
        };
        let challenge = preimage_digest(PERSON_REVOKE_POP_DOMAIN, &preimage)?;
        verify_signature(&person_cert.p_pub, &challenge, owner_pop)
            .map_err(|_| DeviceAdmissionError::PopInvalid)?;

        let mut record = snapshot.record.clone();
        let cascade: Vec<String> = record
            .devices
            .iter()
            .filter(|(_, entry)| entry.p_id == *target_p_id && entry.status == DeviceStatus::Active)
            .map(|(d_id, _)| d_id.clone())
            .collect();
        if record.revoked_persons.contains(&target_p_id.0) && cascade.is_empty() {
            return Ok(MutationOutcome::Idempotent {
                generation: record.generation,
            });
        }

        record.generation += 1;
        record.revoked_persons.insert(target_p_id.0.clone());
        for d_id in &cascade {
            if let Some(entry) = record.devices.get_mut(d_id) {
                entry.status = DeviceStatus::Revoked;
                entry.revoked_at_generation = Some(record.generation);
            }
        }
        record.revocation_cursor += 1;
        record.revocation_digest = Bytes32(chain_revocation(
            &record.revocation_digest.0,
            "person",
            &target_p_id.0,
            record.generation,
        )?);
        self.settle(&record)
    }

    /// Shared revoke tail. Replay is idempotent and never reopens admission.
    fn apply_device_revocation(
        &self,
        mut record: DeviceAdmissionRecordV1,
        d_id: &DeviceId,
        kind: &'static str,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let Some(entry) = record.devices.get(&d_id.0) else {
            return Err(DeviceAdmissionError::DeviceNotListed);
        };
        if entry.status == DeviceStatus::Revoked {
            return Ok(MutationOutcome::Idempotent {
                generation: record.generation,
            });
        }
        record.generation += 1;
        if let Some(entry) = record.devices.get_mut(&d_id.0) {
            entry.status = DeviceStatus::Revoked;
            entry.revoked_at_generation = Some(record.generation);
        }
        record.revocation_cursor += 1;
        record.revocation_digest = Bytes32(chain_revocation(
            &record.revocation_digest.0,
            kind,
            &d_id.0,
            record.generation,
        )?);
        self.settle(&record)
    }

    // ── Seal / recheck ─────────────────────────────────────────────────────

    /// Produce a sealed admission fact for `d_id`, bound to the exact peer
    /// identity the caller intends to reach.
    ///
    /// All facts come from one atomic snapshot; nothing here is composed from
    /// independent reads.
    pub fn seal(
        &self,
        d_id: &DeviceId,
        peer_identity_pub_sec1: &[u8; 33],
        now: u64,
    ) -> Result<SealedDeviceAdmissionV1, DeviceAdmissionError> {
        let snapshot = self.live_snapshot()?;
        let entry = snapshot
            .entry(d_id)
            .ok_or(DeviceAdmissionError::DeviceNotListed)?;
        if entry.status != DeviceStatus::Active {
            return Err(DeviceAdmissionError::DeviceRevoked);
        }
        if snapshot.is_person_revoked(&entry.p_id) {
            return Err(DeviceAdmissionError::PersonRevoked);
        }
        if entry.person_not_after.is_some_and(|limit| now >= limit) {
            return Err(DeviceAdmissionError::PersonCertExpired);
        }
        // Direct subject-key equality (R0a §9 D3): the admitted identity is the
        // certified point itself, compared over all 33 bytes.
        if entry.d_pub.as_bytes() != peer_identity_pub_sec1 {
            return Err(DeviceAdmissionError::PeerIdentityMismatch);
        }
        Ok(SealedDeviceAdmissionV1 {
            contract_version: SealedDeviceAdmissionV1::CONTRACT_VERSION,
            hh_id: self.hh_id.clone(),
            d_id: d_id.clone(),
            p_id: entry.p_id.clone(),
            peer_identity_pub_sec1: *peer_identity_pub_sec1,
            device_cert_digest: entry.device_cert_digest.0,
            person_cert_digest: entry.person_cert_digest.0,
            narrowing_digest: entry.narrowing_digest.0,
            hh_root_digest: self.hh_root_digest,
            generation: snapshot.generation(),
            revocation_cursor: snapshot.record.revocation_cursor,
            revocation_digest: snapshot.record.revocation_digest.0,
            snapshot_digest: snapshot.snapshot_digest,
            person_not_after: entry.person_not_after,
            verified_at: now,
        })
    }

    /// Consume-time fence, atomic with the effect it authorizes (R0a §10).
    ///
    /// Takes the sealed fact **by value** so it cannot be presented twice,
    /// requires byte-exact equality with the peer the caller is about to reach,
    /// then — while holding the store lock — re-reads the live authority and
    /// requires the root, subject, both cert digests, the narrowing digest, the
    /// non-zero generation, the revocation cursor and digest, and the whole
    /// snapshot digest to be unchanged. `effect` runs inside that same lock, so
    /// no revoke can interleave between the recheck and the decision. Any drift
    /// produces no effect and `effect` is never called.
    ///
    /// # Point-in-time semantics — read this before wiring a caller
    ///
    /// This closes the window between *verify* and *the local decision or
    /// record* of that verification. It does **not** invalidate sessions that
    /// are already running: a dial authorized at generation `G` keeps running
    /// after a revoke at `G+1` unless something else tears it down. Continuous
    /// enforcement over a live session is a separate mechanism and is not
    /// provided here.
    ///
    /// # Why a closure and not a guard
    ///
    /// A returned guard holding the lock would be `Send` (it owns a `File`), so
    /// a caller could hold it across an `.await` and pin the lock behind network
    /// I/O. `effect` is a synchronous `FnOnce`, so `.await` is *syntactically*
    /// impossible inside it. Never widen this to an async closure.
    ///
    /// `effect` receives only `&ConsumedDeviceAdmissionV1` — never `&self` —
    /// both so the token cannot escape the critical section and because
    /// re-entering any method that takes the store lock would deadlock:
    /// `flock(2)` binds to the open file description and every acquire opens a
    /// fresh descriptor, so a nested acquire blocks for the full
    /// `LOCK_TIMEOUT`.
    ///
    /// # Caller shape
    ///
    /// Run the whole call inside `tokio::task::spawn_blocking`, `.await` the
    /// join handle, and only then serialize and publish the response body. The
    /// lock is acquired and released entirely inside the blocking task; it is
    /// never held while a body is produced or streamed.
    // `needless_pass_by_value` is wrong here: taking `sealed` by value is the
    // single-use property, not an oversight. The body only reads it, but the
    // move is what stops the caller presenting the same fact twice. Borrowing
    // it to satisfy the lint would defeat the capability.
    #[allow(clippy::needless_pass_by_value)]
    pub fn consume_with_effect<T, E>(
        &self,
        sealed: SealedDeviceAdmissionV1,
        expected_peer_pub_sec1: &[u8; 33],
        now: u64,
        effect: impl FnOnce(&ConsumedDeviceAdmissionV1) -> Result<T, E>,
    ) -> Result<T, ConsumeError<E>> {
        // Identity first: a fact sealed for peer A must never authorize peer B,
        // however well the endpoint, label, or hint may match. Cheap and
        // lock-free — a mismatch here never needed the store at all.
        if sealed.peer_identity_pub_sec1 != *expected_peer_pub_sec1 {
            return Err(ConsumeError::admission(
                DeviceAdmissionError::PeerIdentityMismatch,
            ));
        }
        if sealed.contract_version != SealedDeviceAdmissionV1::CONTRACT_VERSION
            || sealed.hh_id != self.hh_id
            || sealed.hh_root_digest != self.hh_root_digest
        {
            return Err(ConsumeError::admission(DeviceAdmissionError::StaleSeal));
        }

        // Everything from here to the end of `effect` is one critical section.
        let _lock = StoreLock::acquire(&self.state_dir).map_err(ConsumeError::admission)?;
        let snapshot = self.live_snapshot().map_err(ConsumeError::admission)?;
        let consumed =
            Self::recheck_sealed(&sealed, &snapshot, now).map_err(ConsumeError::admission)?;
        effect(&consumed).map_err(ConsumeError::Effect)
    }

    /// The §10 recheck itself, factored out so the lock discipline above stays
    /// readable. Pure: it reads the snapshot it is given and nothing else.
    fn recheck_sealed(
        sealed: &SealedDeviceAdmissionV1,
        snapshot: &DeviceAdmissionSnapshotV1,
        now: u64,
    ) -> Result<ConsumedDeviceAdmissionV1, DeviceAdmissionError> {
        if snapshot.snapshot_digest != sealed.snapshot_digest
            || snapshot.generation() != sealed.generation
            || snapshot.record.revocation_cursor != sealed.revocation_cursor
            || snapshot.record.revocation_digest.0 != sealed.revocation_digest
            || snapshot.record.hh_root_digest.0 != sealed.hh_root_digest
        {
            return Err(DeviceAdmissionError::StaleSeal);
        }
        if sealed.generation == 0 {
            return Err(DeviceAdmissionError::GenerationZero);
        }

        let entry = snapshot
            .entry(&sealed.d_id)
            .ok_or(DeviceAdmissionError::DeviceNotListed)?;
        if entry.status != DeviceStatus::Active {
            return Err(DeviceAdmissionError::DeviceRevoked);
        }
        if snapshot.is_person_revoked(&entry.p_id) {
            return Err(DeviceAdmissionError::PersonRevoked);
        }
        if entry.p_id != sealed.p_id
            || entry.device_cert_digest.0 != sealed.device_cert_digest
            || entry.person_cert_digest.0 != sealed.person_cert_digest
            || entry.narrowing_digest.0 != sealed.narrowing_digest
            || entry.d_pub.as_bytes() != &sealed.peer_identity_pub_sec1
        {
            return Err(DeviceAdmissionError::StaleSeal);
        }
        if entry.person_not_after != sealed.person_not_after {
            return Err(DeviceAdmissionError::StaleSeal);
        }
        if sealed.person_not_after.is_some_and(|limit| now >= limit) {
            return Err(DeviceAdmissionError::PersonCertExpired);
        }

        Ok(ConsumedDeviceAdmissionV1 {
            d_id: sealed.d_id.clone(),
            peer_identity_pub_sec1: sealed.peer_identity_pub_sec1,
            generation: sealed.generation,
            snapshot_digest: sealed.snapshot_digest,
            consumed_at: now,
        })
    }

    // ── Pair seal / recheck ────────────────────────────────────────────────

    /// Seal the fact that **two** distinct devices are admitted together, under
    /// one generation, read under one lock.
    ///
    /// This is the pair primitive, not a convenience wrapper: there is
    /// deliberately no path that builds a pair out of two
    /// [`SealedDeviceAdmissionV1`] values. See
    /// [`SealedDevicePairAdmissionV1`] for why composing the singular surface
    /// twice is unsound rather than merely weaker.
    ///
    /// One [`StoreLock`] acquire and one [`Self::live_snapshot`] read serve both
    /// members, so "same generation" and "same authority snapshot" hold by
    /// construction rather than by comparison.
    ///
    /// Refusals are attributed to a [`PairRole`], so an initiator-side failure
    /// and a responder-side failure of the same kind are distinguishable.
    ///
    /// Both sides must be listed, `Active`, owned by an unrevoked person, within
    /// any inherited person limit, and must match the exact 33-byte SEC1 point
    /// the caller intends to reach. The two must also be genuinely distinct —
    /// both by `d_id` and by admitted key.
    pub fn seal_pair(
        &self,
        initiator_d_id: &DeviceId,
        initiator_peer_pub_sec1: &[u8; 33],
        responder_d_id: &DeviceId,
        responder_peer_pub_sec1: &[u8; 33],
        now: u64,
    ) -> Result<SealedDevicePairAdmissionV1, DeviceAdmissionError> {
        // A pair of one is not a pair. Checked before the store is touched: it
        // is a caller contract error, not a fact about the authority.
        if initiator_d_id == responder_d_id {
            return Err(DeviceAdmissionError::PairSameDevice);
        }

        // One lock, one read. Everything below is derived from `snapshot`, so
        // there is no second observation to disagree with the first.
        let _lock = StoreLock::acquire(&self.state_dir)?;
        let snapshot = self.live_snapshot()?;

        let initiator = Self::bind_pair_member(
            &snapshot,
            PairRole::Initiator,
            initiator_d_id,
            initiator_peer_pub_sec1,
            now,
        )?;
        let responder = Self::bind_pair_member(
            &snapshot,
            PairRole::Responder,
            responder_d_id,
            responder_peer_pub_sec1,
            now,
        )?;

        // Distinct `d_id`s can still resolve to one admitted key if the record
        // was tampered with. Two names for one key is one party, so it is the
        // same refusal as naming one device twice.
        if initiator.peer_identity_pub_sec1 == responder.peer_identity_pub_sec1 {
            return Err(DeviceAdmissionError::PairSameDevice);
        }

        Ok(SealedDevicePairAdmissionV1 {
            contract_version: SealedDevicePairAdmissionV1::CONTRACT_VERSION,
            hh_id: self.hh_id.clone(),
            hh_root_digest: self.hh_root_digest,
            initiator,
            responder,
            generation: snapshot.generation(),
            revocation_cursor: snapshot.record.revocation_cursor,
            revocation_digest: snapshot.record.revocation_digest.0,
            snapshot_digest: snapshot.snapshot_digest,
            verified_at: now,
        })
    }

    /// Resolve and validate one side of a pair against an already-read snapshot.
    ///
    /// Takes the snapshot by reference and reads nothing else, so both members
    /// are provably bound to the same authority state.
    fn bind_pair_member(
        snapshot: &DeviceAdmissionSnapshotV1,
        role: PairRole,
        d_id: &DeviceId,
        peer_identity_pub_sec1: &[u8; 33],
        now: u64,
    ) -> Result<PairMemberBindingV1, DeviceAdmissionError> {
        let entry = snapshot
            .entry(d_id)
            .ok_or_else(|| DeviceAdmissionError::DeviceNotListed.at(role))?;
        if entry.status != DeviceStatus::Active {
            return Err(DeviceAdmissionError::DeviceRevoked.at(role));
        }
        if snapshot.is_person_revoked(&entry.p_id) {
            return Err(DeviceAdmissionError::PersonRevoked.at(role));
        }
        if entry.person_not_after.is_some_and(|limit| now >= limit) {
            return Err(DeviceAdmissionError::PersonCertExpired.at(role));
        }
        // Direct subject-key equality (R0a §9 D3) over all 33 bytes.
        if entry.d_pub.as_bytes() != peer_identity_pub_sec1 {
            return Err(DeviceAdmissionError::PeerIdentityMismatch.at(role));
        }
        Ok(PairMemberBindingV1 {
            role,
            d_id: d_id.clone(),
            p_id: entry.p_id.clone(),
            peer_identity_pub_sec1: *peer_identity_pub_sec1,
            device_cert_digest: entry.device_cert_digest.0,
            person_cert_digest: entry.person_cert_digest.0,
            narrowing_digest: entry.narrowing_digest.0,
            person_not_after: entry.person_not_after,
        })
    }

    /// Consume-time fence for a pair, atomic with the effect it authorizes.
    ///
    /// Takes the sealed pair **by value** and moves its member bindings into the
    /// token handed to `effect`, so one pair fact can authorize exactly one
    /// effect. Requires byte-exact equality with both peers the caller is about
    /// to reach, **in position** — a fact sealed for `(A, B)` never authorizes
    /// the dial `(B, A)`. Then, while holding the store lock, it re-reads the
    /// live authority once and requires the root, both subjects, every cert and
    /// narrowing digest, the non-zero generation, the revocation cursor and
    /// digest, and the whole snapshot digest to be unchanged. `effect` runs
    /// inside that same lock, so no revoke of *either* side can interleave
    /// between the recheck and the decision.
    ///
    /// Any drift produces no effect and `effect` is never called. The fence
    /// mutates nothing: a refusal leaves the durable record byte-identical.
    ///
    /// # Single use
    ///
    /// Single use is enforced by the move, exactly as for the singular fact —
    /// this is a server-local capability (R0a §4), not a durable ledger entry.
    /// Consuming does not write, so a restart does not "un-consume" anything;
    /// it only means a fresh fact must be sealed, which re-runs every check.
    ///
    /// # Point-in-time semantics — read this before wiring a caller
    ///
    /// This closes the window between *verify* and *the local decision or
    /// record* of that verification, for both sides at once. It does **not**
    /// invalidate sessions that are already running: a pair authorized at
    /// generation `G` keeps running after either side is revoked at `G+1`
    /// unless something else tears it down. Continuous enforcement over a live
    /// session is a separate mechanism and is not provided here.
    ///
    /// # Why a closure, and why its success type is `()`
    ///
    /// A returned guard would be `Send` and could be held across an `.await`,
    /// pinning the lock behind network I/O. `effect` is a synchronous `FnOnce`,
    /// so `.await` is *syntactically* impossible inside it, and it receives only
    /// `&ConsumedDevicePairAdmissionV1` — never `&self` — so the token cannot
    /// escape the critical section and no locking method can be re-entered.
    ///
    /// A synchronous closure is necessary but **not sufficient**. A generic type
    /// anywhere in the output lets the effect return a *lazy* value and defer
    /// the real work past the fence:
    ///
    /// ```text
    /// consume_pair_with_effect(sealed, a, b, now, |_| Ok(async move { dial().await }))
    /// //                                              ^ runs after the lock is gone
    /// ```
    ///
    /// The returned future — or closure, or iterator — is constructed under the
    /// lock and evaluated after it, so the revocation fence would guard nothing.
    ///
    /// **Both arms must be closed, not just the success arm.** Pinning the
    /// success type to `()` while leaving the error type generic moves the hole
    /// rather than closing it: `Err(async move { … })` is returned by value once
    /// the lock has dropped and is awaited outside it, deferring identically.
    /// That was measured on an earlier revision of this function — the shape
    /// compiled and ran, producing its value after the lock was released. No
    /// trait bound excludes a lazily-evaluated type, and no source guard can
    /// help, because the type would be chosen at a call site in another crate.
    /// So this signature carries **no type parameters at all**: `()` on success
    /// and the closed, fieldless [`PairEffectFailure`] on failure.
    ///
    /// This is why the pair surface deliberately does not mirror the singular
    /// [`Self::consume_with_effect`], which keeps `<T, E>`.
    ///
    /// # Honest residual
    ///
    /// This closes the *return* channel in both arms. It does not close every
    /// channel: arbitrary synchronous code inside `effect` can still capture
    /// state and spawn or enqueue work that runs later, and no signature can
    /// prevent that. The contract for callers is therefore explicit: perform
    /// the authorized mutation, or record the authorized decision,
    /// **before returning from `effect`**.
    ///
    /// One further channel, named for completeness rather than because it is a
    /// defect: `panic_any` plus `catch_unwind` still carries a caller-chosen
    /// `'static` payload out, since `_lock` is released by RAII during the
    /// unwind. The guarantees above hold as written — they name `Ok` and `Err`
    /// specifically — the token still cannot escape, and the authority never
    /// becomes inconsistent because this fence does not write.
    ///
    /// What is guaranteed structurally: the token reference cannot escape (the
    /// borrow is higher-ranked, so it cannot be stored into the fixed return
    /// type), the lock is held for the whole call, and **no lazily-evaluated
    /// value can leave through `Ok` or through `Err`.**
    pub fn consume_pair_with_effect(
        &self,
        sealed: SealedDevicePairAdmissionV1,
        expected_initiator_pub_sec1: &[u8; 33],
        expected_responder_pub_sec1: &[u8; 33],
        now: u64,
        effect: impl FnOnce(&ConsumedDevicePairAdmissionV1) -> Result<(), PairEffectFailure>,
    ) -> Result<(), ConsumePairError> {
        // Identity first, in position, and lock-free: a pair sealed for one
        // ordering must never authorize the swap, however well endpoints,
        // labels, or hints may match.
        if sealed.initiator.peer_identity_pub_sec1 != *expected_initiator_pub_sec1 {
            return Err(ConsumePairError::admission(
                DeviceAdmissionError::PeerIdentityMismatch.at(PairRole::Initiator),
            ));
        }
        if sealed.responder.peer_identity_pub_sec1 != *expected_responder_pub_sec1 {
            return Err(ConsumePairError::admission(
                DeviceAdmissionError::PeerIdentityMismatch.at(PairRole::Responder),
            ));
        }
        if sealed.contract_version != SealedDevicePairAdmissionV1::CONTRACT_VERSION
            || sealed.hh_id != self.hh_id
            || sealed.hh_root_digest != self.hh_root_digest
        {
            return Err(ConsumePairError::admission(DeviceAdmissionError::StaleSeal));
        }

        // Everything from here to the end of `effect` is one critical section,
        // and one live read serves both members.
        let _lock = StoreLock::acquire(&self.state_dir).map_err(ConsumePairError::admission)?;
        let snapshot = self.live_snapshot().map_err(ConsumePairError::admission)?;
        Self::recheck_sealed_pair(&sealed, &snapshot, now).map_err(ConsumePairError::admission)?;

        // The bindings move out of the sealed fact: consuming destroys it.
        let SealedDevicePairAdmissionV1 {
            initiator,
            responder,
            generation,
            snapshot_digest,
            ..
        } = sealed;
        let consumed = ConsumedDevicePairAdmissionV1 {
            initiator,
            responder,
            generation,
            snapshot_digest,
            consumed_at: now,
        };
        effect(&consumed).map_err(ConsumePairError::Effect)
    }

    /// The §10 recheck for a pair. Pure: it reads the snapshot it is given and
    /// nothing else, so both sides are rechecked against one authority state.
    fn recheck_sealed_pair(
        sealed: &SealedDevicePairAdmissionV1,
        snapshot: &DeviceAdmissionSnapshotV1,
        now: u64,
    ) -> Result<(), DeviceAdmissionError> {
        // Whole-snapshot fence first. Any change to either member — status,
        // caveats, key, person revocation — is inside this digest, so this is
        // what actually catches drift; the per-member recheck below is a closed
        // backstop, not the primary defence.
        if snapshot.snapshot_digest != sealed.snapshot_digest
            || snapshot.generation() != sealed.generation
            || snapshot.record.revocation_cursor != sealed.revocation_cursor
            || snapshot.record.revocation_digest.0 != sealed.revocation_digest
            || snapshot.record.hh_root_digest.0 != sealed.hh_root_digest
        {
            return Err(DeviceAdmissionError::StaleSeal);
        }
        if sealed.generation == 0 {
            return Err(DeviceAdmissionError::GenerationZero);
        }

        Self::recheck_pair_member(&sealed.initiator, snapshot, now)?;
        Self::recheck_pair_member(&sealed.responder, snapshot, now)?;

        // Two names for one key is one party. Re-asserted here so the property
        // is enforced at the point of use, not only at the point of sealing.
        if sealed.initiator.d_id == sealed.responder.d_id
            || sealed.initiator.peer_identity_pub_sec1 == sealed.responder.peer_identity_pub_sec1
        {
            return Err(DeviceAdmissionError::PairSameDevice);
        }
        Ok(())
    }

    /// Recheck one sealed side against the live snapshot.
    fn recheck_pair_member(
        member: &PairMemberBindingV1,
        snapshot: &DeviceAdmissionSnapshotV1,
        now: u64,
    ) -> Result<(), DeviceAdmissionError> {
        let role = member.role;
        let entry = snapshot
            .entry(&member.d_id)
            .ok_or_else(|| DeviceAdmissionError::DeviceNotListed.at(role))?;
        if entry.status != DeviceStatus::Active {
            return Err(DeviceAdmissionError::DeviceRevoked.at(role));
        }
        if snapshot.is_person_revoked(&entry.p_id) {
            return Err(DeviceAdmissionError::PersonRevoked.at(role));
        }
        if entry.p_id != member.p_id
            || entry.device_cert_digest.0 != member.device_cert_digest
            || entry.person_cert_digest.0 != member.person_cert_digest
            || entry.narrowing_digest.0 != member.narrowing_digest
            || entry.d_pub.as_bytes() != &member.peer_identity_pub_sec1
            || entry.person_not_after != member.person_not_after
        {
            return Err(DeviceAdmissionError::StaleSeal.at(role));
        }
        // Wall-clock revalidation: reachable without any authority change,
        // because `now` advances on its own.
        if member.person_not_after.is_some_and(|limit| now >= limit) {
            return Err(DeviceAdmissionError::PersonCertExpired.at(role));
        }
        Ok(())
    }
}

fn person_cert_digest(person_cert: &PersonCert) -> Result<[u8; 32], DeviceAdmissionError> {
    let bytes = cbor::to_canonical_vec(person_cert).map_err(|_| DeviceAdmissionError::Encoding)?;
    Ok(domain_digest(PERSON_CERT_DIGEST_DOMAIN, &bytes))
}

fn chain_revocation(
    previous: &[u8; 32],
    kind: &'static str,
    subject: &str,
    generation: u64,
) -> Result<[u8; 32], DeviceAdmissionError> {
    let event = RevocationEvent {
        kind,
        subject: subject.to_string(),
        generation,
    };
    let bytes = cbor::to_canonical_vec(&event).map_err(|_| DeviceAdmissionError::Encoding)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVOCATION_DOMAIN);
    hasher.update(previous);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

// ─── Signing helpers for the R0a test seam ──────────────────────────────────
//
// The seam injects whole snapshots and complete proofs, never loose fields. It
// is a test harness, not a production authority (R0a §11).

/// Compute the add-PoP challenge an owner must sign. Exposed so a caller can
/// mint the proof without reimplementing the preimage; it grants nothing on its
/// own.
pub fn add_pop_challenge(
    hh_id: &HouseholdId,
    generation: u64,
    device_cert: &DeviceCert,
    device_cert_digest: &[u8; 32],
    person_cert_digest: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 32], DeviceAdmissionError> {
    preimage_digest(
        ADD_POP_DOMAIN,
        &AddPopPreimage {
            hh_id: hh_id.0.clone(),
            generation,
            d_id: device_cert.d_id.0.clone(),
            d_pub: device_cert.d_pub.clone(),
            device_cert_digest: Bytes32(*device_cert_digest),
            person_cert_digest: Bytes32(*person_cert_digest),
            nonce: Bytes32(*nonce),
        },
    )
}

/// Compute the owner-revoke challenge for a device.
pub fn owner_revoke_challenge(
    hh_id: &HouseholdId,
    d_id: &DeviceId,
    nonce: &[u8; 32],
) -> Result<[u8; 32], DeviceAdmissionError> {
    preimage_digest(
        OWNER_REVOKE_POP_DOMAIN,
        &OwnerRevokePopPreimage {
            hh_id: hh_id.0.clone(),
            d_id: d_id.0.clone(),
            nonce: Bytes32(*nonce),
        },
    )
}

/// Compute the self-revoke challenge for a device.
pub fn self_revoke_challenge(
    hh_id: &HouseholdId,
    d_id: &DeviceId,
    d_pub: &P256PublicKey,
    nonce: &[u8; 32],
) -> Result<[u8; 32], DeviceAdmissionError> {
    preimage_digest(
        SELF_REVOKE_POP_DOMAIN,
        &SelfRevokePopPreimage {
            hh_id: hh_id.0.clone(),
            d_id: d_id.0.clone(),
            d_pub: d_pub.clone(),
            nonce: Bytes32(*nonce),
        },
    )
}

/// Compute the person-revoke challenge.
pub fn person_revoke_challenge(
    hh_id: &HouseholdId,
    p_id: &PersonId,
    nonce: &[u8; 32],
) -> Result<[u8; 32], DeviceAdmissionError> {
    preimage_digest(
        PERSON_REVOKE_POP_DOMAIN,
        &PersonRevokePopPreimage {
            hh_id: hh_id.0.clone(),
            p_id: p_id.0.clone(),
            nonce: Bytes32(*nonce),
        },
    )
}

/// The digest the authority stores for an owner `PersonCert`.
pub fn owner_person_cert_digest(
    person_cert: &PersonCert,
) -> Result<[u8; 32], DeviceAdmissionError> {
    person_cert_digest(person_cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveats::Caveat;
    use crate::device_cert::{SignOptions, derive_device_id};
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::person_cert::SignOwnerOptions;

    const NOW: u64 = 1_714_972_800;

    struct Fixture {
        _dir: tempfile::TempDir,
        state_dir: PathBuf,
        hh: P256Keypair,
        person: P256Keypair,
        device: P256Keypair,
        owner: PersonCert,
        cert: DeviceCert,
    }

    fn owner_cert(hh: &P256Keypair, person: &P256Keypair) -> PersonCert {
        let hh_id = derive_household_id(&hh.public());
        let mut cert = PersonCert::sign_owner(
            hh,
            SignOwnerOptions {
                hh_id,
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: NOW,
            },
        )
        .unwrap();
        // R0a Fatia N: the owner template never grants `household.add_device`,
        // so an admissible owner carries it explicitly. The caveat list is
        // covered by the household signature, so the cert is re-signed rather
        // than mutated in place — an unsigned edit would not survive
        // `PersonCert::verify` against the live root.
        cert.caveats
            .push(Caveat::new(Operation::HouseholdAddDevice, None));
        let signing = cert.signing_bytes().unwrap();
        cert.signature = hh.sign(&signing).unwrap();
        cert
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let owner = owner_cert(&hh, &person);
        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        Fixture {
            _dir: dir,
            state_dir,
            hh,
            person,
            device,
            owner,
            cert,
        }
    }

    fn authority(fx: &Fixture) -> HouseholdDeviceAdmissionAuthorityV1 {
        HouseholdDeviceAdmissionAuthorityV1::new(
            &fx.state_dir,
            derive_household_id(&fx.hh.public()),
            fx.hh.public(),
        )
    }

    fn admit(
        fx: &Fixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        nonce: u8,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let generation = auth.live_snapshot()?.generation();
        let device_cert_digest = fx.cert.digest().unwrap();
        let person_cert_digest = owner_person_cert_digest(&fx.owner)?;
        let nonce = [nonce; 32];
        let challenge = add_pop_challenge(
            &derive_household_id(&fx.hh.public()),
            generation,
            &fx.cert,
            &device_cert_digest,
            &person_cert_digest,
            &nonce,
        )?;
        let pop = fx.person.sign(&challenge).unwrap();
        auth.admit_device(&fx.owner, &fx.cert, &pop, &nonce, NOW)
    }

    /// What the effect closure observed, copied out so assertions can run after
    /// the lock is released.
    #[derive(Debug)]
    struct ConsumedProbe {
        peer: [u8; 33],
        generation: u64,
        consumed_at: u64,
    }

    /// Consume with a trivial effect. `Infallible` as the effect error makes the
    /// `Effect` arm unreachable, so this surfaces `DeviceAdmissionError`
    /// directly and the tests stay about admission, not about plumbing.
    fn consume_probe(
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        sealed: SealedDeviceAdmissionV1,
        peer: &[u8; 33],
        now: u64,
    ) -> Result<ConsumedProbe, DeviceAdmissionError> {
        auth.consume_with_effect(sealed, peer, now, |consumed| {
            Ok::<_, std::convert::Infallible>(ConsumedProbe {
                peer: *consumed.peer_identity_pub_sec1(),
                generation: consumed.generation(),
                consumed_at: consumed.consumed_at(),
            })
        })
        .map_err(|error| match error {
            ConsumeError::Admission(error) => error,
            ConsumeError::Effect(never) => match never {},
        })
    }

    fn owner_revoke(
        fx: &Fixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        nonce: u8,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let nonce = [nonce; 32];
        let challenge =
            owner_revoke_challenge(&derive_household_id(&fx.hh.public()), &fx.cert.d_id, &nonce)?;
        let pop = fx.person.sign(&challenge).unwrap();
        auth.revoke_device_as_owner(&fx.owner, &fx.cert.d_id, &pop, &nonce, NOW)
    }

    fn self_revoke(
        fx: &Fixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        signer: &P256Keypair,
        nonce: u8,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let nonce = [nonce; 32];
        let challenge = self_revoke_challenge(
            &derive_household_id(&fx.hh.public()),
            &fx.cert.d_id,
            &fx.device.public(),
            &nonce,
        )?;
        let pop = signer.sign(&challenge).unwrap();
        auth.self_revoke_device(&fx.cert.d_id, &pop, &nonce)
    }

    // ── fail-closed ────────────────────────────────────────────────────────

    #[test]
    fn absent_authority_admits_nobody() {
        let fx = fixture();
        let auth = authority(&fx);
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
        assert_eq!(
            auth.seal(&fx.cert.d_id, fx.device.public().as_bytes(), NOW)
                .unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
        assert_eq!(
            admit(&fx, &auth, 1).unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
    }

    #[test]
    fn provision_is_explicit_and_not_repeatable() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        assert_eq!(
            auth.provision().unwrap_err(),
            DeviceAdmissionError::AlreadyProvisioned
        );
    }

    #[test]
    fn provisioned_generation_is_non_zero() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        assert_eq!(auth.live_snapshot().unwrap().generation(), 1);
    }

    #[test]
    fn zero_generation_on_disk_fails_closed() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        let path = record_path(&fx.state_dir);
        let mut record = decode_record(&fs::read(&path).unwrap()).unwrap();
        record.generation = 0;
        fs::write(&path, cbor::to_canonical_vec(&record).unwrap()).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::GenerationZero
        );
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        fs::write(record_path(&fx.state_dir), b"not cbor at all").unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::RecordCorrupt
        );
    }

    #[test]
    fn non_canonical_record_bytes_are_rejected() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        let path = record_path(&fx.state_dir);
        let record = decode_record(&fs::read(&path).unwrap()).unwrap();
        // Re-encode with reversed map order: decodes, but is not the canonical
        // byte form, so the authority must refuse it.
        let canonical = cbor::to_canonical_vec(&record).unwrap();
        let value: ciborium::value::Value =
            ciborium::de::from_reader(canonical.as_slice()).unwrap();
        let ciborium::value::Value::Map(mut entries) = value else {
            panic!("record is a map");
        };
        entries.reverse();
        let mut reordered = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut reordered).unwrap();
        assert_ne!(reordered, canonical);
        fs::write(&path, &reordered).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::RecordCorrupt
        );
    }

    #[test]
    fn record_under_a_foreign_root_is_rejected() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        let foreign = P256Keypair::generate();
        let other = HouseholdDeviceAdmissionAuthorityV1::new(
            &fx.state_dir,
            derive_household_id(&fx.hh.public()),
            foreign.public(),
        );
        assert_eq!(
            other.live_snapshot().unwrap_err(),
            DeviceAdmissionError::WrongHousehold
        );
    }

    // ── add ────────────────────────────────────────────────────────────────

    #[test]
    fn admit_increments_generation_and_persists() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        assert_eq!(
            admit(&fx, &auth, 1).unwrap(),
            MutationOutcome::Applied { generation: 2 }
        );

        // A fresh authority over the same directory sees the same durable state.
        let reopened = authority(&fx);
        let snapshot = reopened.live_snapshot().unwrap();
        assert_eq!(snapshot.generation(), 2);
        let entry = snapshot.entry(&fx.cert.d_id).unwrap();
        assert_eq!(entry.status, DeviceStatus::Active);
        assert_eq!(entry.d_pub, fx.device.public());
    }

    #[test]
    fn persist_before_memory_projection_matches_disk() {
        let fx = fixture();
        let auth = authority(&fx);
        // Nothing durable yet, so nothing is projected.
        assert!(auth.durable_projection().is_none());
        auth.provision().unwrap();
        let projected = auth.durable_projection().unwrap();
        let on_disk = auth.live_snapshot().unwrap();
        assert_eq!(projected, on_disk);
        assert_eq!(projected.snapshot_digest(), on_disk.snapshot_digest());
    }

    #[test]
    fn failed_persist_leaves_no_projection_ahead_of_disk() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        let before = auth.live_snapshot().unwrap();

        // Make the record path a directory so the rename cannot land.
        let path = record_path(&fx.state_dir);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(admit(&fx, &auth, 1).is_err());
        assert!(
            auth.durable_projection().is_none(),
            "a projection must never survive a failed persist"
        );

        // Restore and confirm the durable generation never advanced.
        fs::remove_dir(&path).unwrap();
        fs::write(&path, cbor::to_canonical_vec(before.record()).unwrap()).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap().generation(),
            before.generation()
        );
    }

    #[test]
    fn replayed_add_pop_cannot_admit_twice() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();

        let generation = auth.live_snapshot().unwrap().generation();
        let device_cert_digest = fx.cert.digest().unwrap();
        let person_cert_digest = owner_person_cert_digest(&fx.owner).unwrap();
        let nonce = [7u8; 32];
        let challenge = add_pop_challenge(
            &derive_household_id(&fx.hh.public()),
            generation,
            &fx.cert,
            &device_cert_digest,
            &person_cert_digest,
            &nonce,
        )
        .unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        auth.admit_device(&fx.owner, &fx.cert, &pop, &nonce, NOW)
            .unwrap();

        // Same signature, but the generation has moved: the PoP is stale. The
        // idempotent path is not reached because the PoP is checked first.
        let second = HouseholdDeviceAdmissionAuthorityV1::new(
            &fx.state_dir,
            derive_household_id(&fx.hh.public()),
            fx.hh.public(),
        );
        assert_eq!(
            second
                .admit_device(&fx.owner, &fx.cert, &pop, &nonce, NOW)
                .unwrap_err(),
            DeviceAdmissionError::PopInvalid
        );
    }

    #[test]
    fn identical_re_admission_with_a_fresh_pop_is_idempotent() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        assert_eq!(
            admit(&fx, &auth, 2).unwrap(),
            MutationOutcome::Idempotent { generation: 2 }
        );
    }

    #[test]
    fn the_device_cannot_sign_its_own_admission() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();

        let generation = auth.live_snapshot().unwrap().generation();
        let device_cert_digest = fx.cert.digest().unwrap();
        let person_cert_digest = owner_person_cert_digest(&fx.owner).unwrap();
        let nonce = [3u8; 32];
        let challenge = add_pop_challenge(
            &derive_household_id(&fx.hh.public()),
            generation,
            &fx.cert,
            &device_cert_digest,
            &person_cert_digest,
            &nonce,
        )
        .unwrap();
        // Signed by the device key rather than the owner key.
        let pop = fx.device.sign(&challenge).unwrap();
        assert_eq!(
            auth.admit_device(&fx.owner, &fx.cert, &pop, &nonce, NOW)
                .unwrap_err(),
            DeviceAdmissionError::PopInvalid
        );
    }

    #[test]
    fn add_machine_grant_does_not_admit_a_device() {
        let dir = tempfile::tempdir().unwrap();
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        // Stock owner template: it carries `household.add_machine` but never
        // `household.add_device`.
        let owner = PersonCert::sign_owner(
            &hh,
            SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: NOW,
            },
        )
        .unwrap();
        assert!(caveats::permits(
            &owner.caveats,
            &Operation::HouseholdAddMachine
        ));
        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        let auth = HouseholdDeviceAdmissionAuthorityV1::new(dir.path(), hh_id.clone(), hh.public());
        auth.provision().unwrap();
        let nonce = [1u8; 32];
        let challenge = add_pop_challenge(
            &hh_id,
            1,
            &cert,
            &cert.digest().unwrap(),
            &owner_person_cert_digest(&owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = person.sign(&challenge).unwrap();
        assert_eq!(
            auth.admit_device(&owner, &cert, &pop, &nonce, NOW)
                .unwrap_err(),
            DeviceAdmissionError::DeviceCert(DeviceCertError::Narrowing(
                crate::caveat_narrowing::CaveatNarrowingError::GrantMissing
            ))
        );
    }

    #[test]
    fn foreign_household_owner_cert_is_rejected() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        let foreign_hh = P256Keypair::generate();
        let foreign_owner = owner_cert(&foreign_hh, &fx.person);
        let nonce = [9u8; 32];
        let challenge = add_pop_challenge(
            &derive_household_id(&fx.hh.public()),
            1,
            &fx.cert,
            &fx.cert.digest().unwrap(),
            &owner_person_cert_digest(&foreign_owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        assert_eq!(
            auth.admit_device(&foreign_owner, &fx.cert, &pop, &nonce, NOW)
                .unwrap_err(),
            DeviceAdmissionError::OwnerCertInvalid
        );
    }

    // ── revoke ─────────────────────────────────────────────────────────────

    #[test]
    fn owner_revoke_tombstones_and_bumps_cursor() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let before = auth.live_snapshot().unwrap();

        assert_eq!(
            owner_revoke(&fx, &auth, 2).unwrap(),
            MutationOutcome::Applied { generation: 3 }
        );
        let after = auth.live_snapshot().unwrap();
        assert_eq!(
            after.entry(&fx.cert.d_id).unwrap().status,
            DeviceStatus::Revoked
        );
        assert_eq!(
            after.record().revocation_cursor,
            before.record().revocation_cursor + 1
        );
        assert_ne!(
            after.record().revocation_digest,
            before.record().revocation_digest
        );
        assert_ne!(after.snapshot_digest(), before.snapshot_digest());
    }

    #[test]
    fn revoke_beats_a_late_add_and_never_reopens() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        owner_revoke(&fx, &auth, 2).unwrap();
        // A well-formed, freshly-signed add for the same d_id still fails.
        assert_eq!(
            admit(&fx, &auth, 3).unwrap_err(),
            DeviceAdmissionError::DeviceRevoked
        );
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&fx.cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn revoked_tombstone_survives_a_reopened_authority() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        owner_revoke(&fx, &auth, 2).unwrap();
        // Simulates crash/restart: brand-new in-memory state, same file.
        let reopened = authority(&fx);
        assert_eq!(
            reopened
                .live_snapshot()
                .unwrap()
                .entry(&fx.cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked
        );
        assert_eq!(
            admit(&fx, &reopened, 4).unwrap_err(),
            DeviceAdmissionError::DeviceRevoked
        );
    }

    #[test]
    fn self_revoke_requires_the_devices_own_key() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // Owner key is not the device key: self-revoke must reject it.
        assert_eq!(
            self_revoke(&fx, &auth, &fx.person, 2).unwrap_err(),
            DeviceAdmissionError::PopInvalid
        );
        let stranger = P256Keypair::generate();
        assert_eq!(
            self_revoke(&fx, &auth, &stranger, 3).unwrap_err(),
            DeviceAdmissionError::PopInvalid
        );
        assert_eq!(
            self_revoke(&fx, &auth, &fx.device, 4).unwrap(),
            MutationOutcome::Applied { generation: 3 }
        );
    }

    #[test]
    fn self_revoke_replay_is_idempotent_and_does_not_reopen() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        assert_eq!(
            self_revoke(&fx, &auth, &fx.device, 2).unwrap(),
            MutationOutcome::Applied { generation: 3 }
        );
        let after_first = auth.live_snapshot().unwrap();
        // Exactly the same PoP again.
        assert_eq!(
            self_revoke(&fx, &auth, &fx.device, 2).unwrap(),
            MutationOutcome::Idempotent { generation: 3 }
        );
        let after_replay = auth.live_snapshot().unwrap();
        assert_eq!(after_first, after_replay, "replay must not move the record");
        assert_eq!(
            after_replay.entry(&fx.cert.d_id).unwrap().status,
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn a_device_cannot_self_revoke_a_sibling() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // Admit a sibling under the same person.
        let sibling_key = P256Keypair::generate();
        let sibling = DeviceCert::sign(
            &fx.person,
            SignOptions {
                p_pub: fx.person.public(),
                d_pub: sibling_key.public(),
                device_name: "iPad Pro".into(),
                platform: "ipados".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        let hh_id = derive_household_id(&fx.hh.public());
        let generation = auth.live_snapshot().unwrap().generation();
        let nonce = [5u8; 32];
        let challenge = add_pop_challenge(
            &hh_id,
            generation,
            &sibling,
            &sibling.digest().unwrap(),
            &owner_person_cert_digest(&fx.owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        auth.admit_device(&fx.owner, &sibling, &pop, &nonce, NOW)
            .unwrap();

        // The first device signs a self-revoke aimed at the sibling's d_id.
        let nonce = [6u8; 32];
        let challenge =
            self_revoke_challenge(&hh_id, &sibling.d_id, &sibling_key.public(), &nonce).unwrap();
        let forged = fx.device.sign(&challenge).unwrap();
        assert_eq!(
            auth.self_revoke_device(&sibling.d_id, &forged, &nonce)
                .unwrap_err(),
            DeviceAdmissionError::PopInvalid
        );
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&sibling.d_id)
                .unwrap()
                .status,
            DeviceStatus::Active
        );
    }

    #[test]
    fn person_revocation_cascades_to_descendant_devices() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let hh_id = derive_household_id(&fx.hh.public());
        let nonce = [8u8; 32];
        let challenge = person_revoke_challenge(&hh_id, &fx.owner.p_id, &nonce).unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        auth.revoke_person_as_owner(&fx.owner, &fx.owner.p_id, &pop, &nonce, NOW)
            .unwrap();

        let snapshot = auth.live_snapshot().unwrap();
        assert!(snapshot.is_person_revoked(&fx.owner.p_id));
        assert_eq!(
            snapshot.entry(&fx.cert.d_id).unwrap().status,
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn revoke_of_a_device_from_another_person_is_refused() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // A second, unrelated owner in the same household.
        let other_person = P256Keypair::generate();
        let other_owner = owner_cert(&fx.hh, &other_person);
        let nonce = [4u8; 32];
        let challenge =
            owner_revoke_challenge(&derive_household_id(&fx.hh.public()), &fx.cert.d_id, &nonce)
                .unwrap();
        let pop = other_person.sign(&challenge).unwrap();
        assert_eq!(
            auth.revoke_device_as_owner(&other_owner, &fx.cert.d_id, &pop, &nonce, NOW)
                .unwrap_err(),
            DeviceAdmissionError::NotDescendant
        );
    }

    // ── seal / recheck ─────────────────────────────────────────────────────

    #[test]
    fn seal_then_consume_round_trips() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        assert_eq!(sealed.peer_identity_pub_sec1(), &peer);
        assert_eq!(sealed.generation(), 2);
        let consumed = consume_probe(&auth, sealed, &peer, NOW).unwrap();
        assert_eq!(consumed.peer, peer);
        assert_eq!(consumed.generation, 2);
    }

    #[test]
    fn a_fact_sealed_for_peer_a_never_authorizes_peer_b() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer_a = *fx.device.public().as_bytes();
        let peer_b = *P256Keypair::generate().public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer_a, NOW).unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &peer_b, NOW).unwrap_err(),
            DeviceAdmissionError::PeerIdentityMismatch
        );
    }

    #[test]
    fn sealing_against_a_key_the_authority_did_not_admit_fails() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let other = *P256Keypair::generate().public().as_bytes();
        assert_eq!(
            auth.seal(&fx.cert.d_id, &other, NOW).unwrap_err(),
            DeviceAdmissionError::PeerIdentityMismatch
        );
    }

    #[test]
    fn a_seal_taken_before_a_revoke_is_stale_at_consume() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        // The authority moves between seal and consume.
        owner_revoke(&fx, &auth, 2).unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
    }

    #[test]
    fn a_seal_is_stale_after_any_unrelated_generation_change() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();

        // Admit an unrelated sibling — this device is untouched, but the
        // snapshot the fact was sealed against no longer exists.
        let sibling_key = P256Keypair::generate();
        let sibling = DeviceCert::sign(
            &fx.person,
            SignOptions {
                p_pub: fx.person.public(),
                d_pub: sibling_key.public(),
                device_name: "iPad Pro".into(),
                platform: "ipados".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        let hh_id = derive_household_id(&fx.hh.public());
        let generation = auth.live_snapshot().unwrap().generation();
        let nonce = [5u8; 32];
        let challenge = add_pop_challenge(
            &hh_id,
            generation,
            &sibling,
            &sibling.digest().unwrap(),
            &owner_person_cert_digest(&fx.owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        auth.admit_device(&fx.owner, &sibling, &pop, &nonce, NOW)
            .unwrap();

        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
    }

    #[test]
    fn consume_fails_closed_when_the_authority_disappears() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        fs::remove_file(record_path(&fx.state_dir)).unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
    }

    #[test]
    fn sealed_fact_is_move_only_and_consumed_once() {
        // Compile-time properties: no Clone/Copy/Default/serde on the sealed
        // fact, and `consume` takes it by value. This test documents the intent;
        // the enforcement is the absence of those impls, checked by the R0a
        // scope guard.
        fn assert_not_clone<T>() {}
        assert_not_clone::<SealedDeviceAdmissionV1>();

        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        let consumed = consume_probe(&auth, sealed, &peer, NOW).unwrap();
        // `sealed` has been moved; a second consume cannot compile.
        assert_eq!(consumed.consumed_at, NOW);
    }

    #[test]
    fn debug_output_does_not_leak_the_sealed_fact() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        let rendered = format!("{sealed:?}");
        assert_eq!(rendered, "SealedDeviceAdmissionV1(REDACTED)");
        assert!(!rendered.contains(&hex::encode(peer)));
    }

    #[test]
    fn expired_person_cert_limit_blocks_seal_and_consume() {
        let dir = tempfile::tempdir().unwrap();
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let hh_id = derive_household_id(&hh.public());
        let mut owner = PersonCert::sign_owner(
            &hh,
            SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: NOW,
            },
        )
        .unwrap();
        owner
            .caveats
            .push(Caveat::new(Operation::HouseholdAddDevice, None));
        owner.not_after = Some(NOW + 100);
        // Re-sign so the cert still verifies with the new not_after.
        let signing = owner.signing_bytes().unwrap();
        owner.signature = hh.sign(&signing).unwrap();

        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        let auth = HouseholdDeviceAdmissionAuthorityV1::new(dir.path(), hh_id.clone(), hh.public());
        auth.provision().unwrap();
        let nonce = [1u8; 32];
        let challenge = add_pop_challenge(
            &hh_id,
            1,
            &cert,
            &cert.digest().unwrap(),
            &owner_person_cert_digest(&owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = person.sign(&challenge).unwrap();
        auth.admit_device(&owner, &cert, &pop, &nonce, NOW).unwrap();

        let peer = *device.public().as_bytes();
        // Inside the window it seals.
        let sealed = auth.seal(&cert.d_id, &peer, NOW + 10).unwrap();
        // Past it, consume refuses even though nothing else moved.
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW + 200).unwrap_err(),
            DeviceAdmissionError::PersonCertExpired
        );
        // And a fresh seal past the limit is refused outright.
        assert_eq!(
            auth.seal(&cert.d_id, &peer, NOW + 200).unwrap_err(),
            DeviceAdmissionError::PersonCertExpired
        );
    }

    #[test]
    fn snapshot_digest_binds_every_field_of_the_record() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let snapshot = auth.live_snapshot().unwrap();

        let mut mutated = snapshot.record().clone();
        mutated.revocation_cursor += 1;
        assert_ne!(
            snapshot_digest_of(&mutated).unwrap(),
            *snapshot.snapshot_digest()
        );

        let mut mutated = snapshot.record().clone();
        if let Some(entry) = mutated.devices.get_mut(&fx.cert.d_id.0) {
            entry.status = DeviceStatus::Revoked;
        }
        assert_ne!(
            snapshot_digest_of(&mutated).unwrap(),
            *snapshot.snapshot_digest()
        );
    }

    #[test]
    fn one_snapshot_carries_every_fact_a_consumer_needs() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let snapshot = auth.live_snapshot().unwrap();
        let record = snapshot.record();
        let entry = snapshot.entry(&fx.cert.d_id).unwrap();

        // R0a §8: household id, root digest, generation, the d_id → binding map,
        // revocation cursor/digest, person revocation, and the whole-snapshot
        // digest all come from this single read.
        assert_eq!(record.hh_id, derive_household_id(&fx.hh.public()));
        assert_eq!(
            record.hh_root_digest.0,
            household_root_digest(&fx.hh.public())
        );
        assert!(record.generation > 0);
        assert_eq!(entry.d_pub.as_bytes().len(), 33);
        assert_eq!(entry.device_cert_digest.0, fx.cert.digest().unwrap());
        assert_eq!(entry.p_id, fx.owner.p_id);
        assert_eq!(
            entry.person_cert_digest.0,
            owner_person_cert_digest(&fx.owner).unwrap()
        );
        assert_eq!(entry.status, DeviceStatus::Active);
        assert!(!snapshot.is_person_revoked(&fx.owner.p_id));
        assert_eq!(snapshot.snapshot_digest().len(), 32);
    }

    #[test]
    fn pop_domains_are_mutually_distinct() {
        let fx = fixture();
        let hh_id = derive_household_id(&fx.hh.public());
        let nonce = [1u8; 32];
        let add = add_pop_challenge(
            &hh_id,
            1,
            &fx.cert,
            &fx.cert.digest().unwrap(),
            &owner_person_cert_digest(&fx.owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let owner = owner_revoke_challenge(&hh_id, &fx.cert.d_id, &nonce).unwrap();
        let self_rev =
            self_revoke_challenge(&hh_id, &fx.cert.d_id, &fx.device.public(), &nonce).unwrap();
        let person = person_revoke_challenge(&hh_id, &fx.owner.p_id, &nonce).unwrap();

        let all = [add, owner, self_rev, person];
        let distinct: BTreeSet<[u8; 32]> = all.iter().copied().collect();
        assert_eq!(distinct.len(), 4, "each PoP domain must be separated");
    }

    // ── D2b-A: honest commit outcomes ──────────────────────────────────────

    /// Every pre-rename stage `atomic_replace` can actually produce. Kept in
    /// step with the enum by `commit_stage_partition_is_exhaustive_and_disjoint`,
    /// which is what caught a declared-but-unreachable stage during D2b-A.
    const PRE_RENAME_STAGES: [CommitStage; 6] = [
        CommitStage::TmpStat,
        CommitStage::TmpOpen,
        CommitStage::TmpWrite,
        CommitStage::TmpFlush,
        CommitStage::TmpSync,
        CommitStage::Rename,
    ];

    const POST_RENAME_STAGES: [CommitStage; 4] = [
        CommitStage::ParentOpen,
        CommitStage::ParentSync,
        CommitStage::Readback,
        CommitStage::ReadbackMismatch,
    ];

    fn record_bytes(fx: &Fixture) -> Vec<u8> {
        fs::read(record_path(&fx.state_dir)).unwrap()
    }

    #[test]
    fn commit_stage_partition_is_exhaustive_and_disjoint() {
        for stage in PRE_RENAME_STAGES {
            assert!(stage.is_pre_rename(), "{stage:?} must be pre-rename");
        }
        for stage in POST_RENAME_STAGES {
            assert!(!stage.is_pre_rename(), "{stage:?} must be post-rename");
        }
        let all: BTreeSet<String> = PRE_RENAME_STAGES
            .iter()
            .chain(POST_RENAME_STAGES.iter())
            .map(|stage| format!("{stage:?}"))
            .collect();
        assert_eq!(
            all.len(),
            PRE_RENAME_STAGES.len() + POST_RENAME_STAGES.len(),
            "the two sets must be disjoint"
        );
    }

    #[test]
    fn pre_rename_failure_leaves_disk_and_generation_untouched() {
        for stage in PRE_RENAME_STAGES {
            let fx = fixture();
            let auth = authority(&fx);
            auth.provision().unwrap();
            let before_bytes = record_bytes(&fx);
            let before_generation = auth.live_snapshot().unwrap().generation();

            let _armed = fail_injection::arm(stage);
            let result = admit(&fx, &auth, 1);

            assert!(
                result.is_err(),
                "{stage:?}: a provably pre-rename failure must be Err, not an outcome"
            );
            assert_eq!(
                record_bytes(&fx),
                before_bytes,
                "{stage:?}: the target must be byte-identical"
            );
            assert_eq!(
                auth.live_snapshot().unwrap().generation(),
                before_generation,
                "{stage:?}: generation must not advance"
            );
            assert!(
                auth.live_snapshot().unwrap().entry(&fx.cert.d_id).is_none(),
                "{stage:?}: the device must not be admitted"
            );
        }
    }

    #[test]
    fn post_rename_failure_reports_uncertain_and_the_new_bytes_are_observable() {
        for stage in POST_RENAME_STAGES {
            let fx = fixture();
            let auth = authority(&fx);
            auth.provision().unwrap();
            let before_bytes = record_bytes(&fx);

            let _armed = fail_injection::arm(stage);
            let outcome = admit(&fx, &auth, 1).unwrap_or_else(|error| {
                panic!("{stage:?}: post-rename must not be Err, got {error:?}")
            });

            assert_eq!(
                outcome,
                MutationOutcome::Uncertain {
                    attempted_generation: 2,
                    stage,
                },
                "{stage:?}: outcome must be Uncertain and name the stage"
            );
            assert!(!outcome.is_settled());
            assert_eq!(
                outcome.generation(),
                None,
                "{stage:?}: claims no generation"
            );

            // The whole point: the write DID land. Reporting this as "no effect"
            // is the lie D2b-A removes.
            assert_ne!(
                record_bytes(&fx),
                before_bytes,
                "{stage:?}: the new bytes must be observable on disk"
            );
            let snapshot = auth.live_snapshot().unwrap();
            assert_eq!(snapshot.generation(), 2, "{stage:?}");
            assert_eq!(
                snapshot.entry(&fx.cert.d_id).unwrap().status,
                DeviceStatus::Active,
                "{stage:?}: the device really is admitted"
            );
        }
    }

    #[test]
    fn uncertain_leaves_no_projection_ahead_of_disk() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();

        let _armed = fail_injection::arm(CommitStage::ParentSync);
        let outcome = admit(&fx, &auth, 1).unwrap();
        assert!(matches!(outcome, MutationOutcome::Uncertain { .. }));
        assert!(
            auth.durable_projection().is_none(),
            "an unverified commit must not publish a projection"
        );
    }

    #[test]
    fn reconciling_an_uncertain_add_finds_it_applied_and_a_retry_is_idempotent() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();

        let _armed = fail_injection::arm(CommitStage::Readback);
        let outcome = admit(&fx, &auth, 1).unwrap();
        assert!(matches!(outcome, MutationOutcome::Uncertain { .. }));

        // Documented rule: re-read; entry Active with the same cert digest means
        // the add applied.
        let entry = auth
            .live_snapshot()
            .unwrap()
            .entry(&fx.cert.d_id)
            .cloned()
            .expect("the device is present after an uncertain add");
        assert_eq!(entry.status, DeviceStatus::Active);
        assert_eq!(entry.device_cert_digest.0, fx.cert.digest().unwrap());

        // And a retry with a PoP minted against the CURRENT generation is
        // idempotent rather than a second admission.
        assert_eq!(
            admit(&fx, &auth, 2).unwrap(),
            MutationOutcome::Idempotent { generation: 2 }
        );
    }

    #[test]
    fn an_uncertain_revoke_is_reconciled_as_revoked() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let _armed = fail_injection::arm(CommitStage::ParentOpen);
        let outcome = owner_revoke(&fx, &auth, 2).unwrap();
        assert!(matches!(outcome, MutationOutcome::Uncertain { .. }));
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&fx.cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked,
            "revoke is fail-safe: an uncertain revoke that landed stays landed"
        );
    }

    #[test]
    fn an_uncertain_provision_really_provisioned() {
        let fx = fixture();
        let auth = authority(&fx);
        let _armed = fail_injection::arm(CommitStage::ParentSync);
        let outcome = auth.provision().unwrap();
        assert!(matches!(outcome, MutationOutcome::Uncertain { .. }));
        // Rule: re-read; a valid record at generation 1 under this root means
        // provisioned. Re-provisioning would now be refused.
        assert_eq!(auth.live_snapshot().unwrap().generation(), 1);
        assert_eq!(
            auth.provision().unwrap_err(),
            DeviceAdmissionError::AlreadyProvisioned
        );
    }

    // ── D2b-A: consume is atomic with the effect ───────────────────────────

    #[test]
    fn the_effect_is_never_invoked_when_the_fence_refuses() {
        use std::cell::Cell;

        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        owner_revoke(&fx, &auth, 2).unwrap();

        let invoked = Cell::new(false);
        let error = auth
            .consume_with_effect(sealed, &peer, NOW, |_consumed| {
                invoked.set(true);
                Ok::<(), std::convert::Infallible>(())
            })
            .unwrap_err();
        assert_eq!(
            error.as_admission(),
            Some(&DeviceAdmissionError::StaleSeal),
            "a stale seal must refuse before authorizing anything"
        );
        assert!(!invoked.get(), "the effect ran despite a refused fence");
    }

    #[test]
    fn an_effect_failure_is_distinguishable_from_an_admission_refusal() {
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        let error = auth
            .consume_with_effect(sealed, &peer, NOW, |_consumed| {
                Err::<(), _>("effect blew up")
            })
            .unwrap_err();
        assert_eq!(error, ConsumeError::Effect("effect blew up"));
        assert!(
            error.as_admission().is_none(),
            "an effect failure must not read as an admission refusal"
        );
    }

    /// The R0a §10.10 property: a revoke cannot interleave between the recheck
    /// and the decision the recheck authorizes.
    #[test]
    fn a_revoke_cannot_cross_a_consume_decision_and_lands_after_it() {
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let fx = fixture();
        let auth = Arc::new(authority(&fx));
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();

        // Pre-mint the revoke inputs so the revoker thread moves plain data only.
        let hh_id = derive_household_id(&fx.hh.public());
        let nonce = [42u8; 32];
        let challenge = owner_revoke_challenge(&hh_id, &fx.cert.d_id, &nonce).unwrap();
        let revoke_pop = fx.person.sign(&challenge).unwrap();
        let owner_cert = fx.owner.clone();
        let target_d_id = fx.cert.d_id.clone();

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let state_dir = fx.state_dir.clone();
        let observed_d_id = fx.cert.d_id.0.clone();
        let consumer_auth = Arc::clone(&auth);
        let consumer = std::thread::spawn(move || {
            consumer_auth.consume_with_effect(sealed, &peer, NOW, move |consumed| {
                entered_tx.send(consumed.generation()).unwrap();
                // Block inside the critical section while a revoke tries to land.
                release_rx.recv().unwrap();
                // Read the durable record directly: if a revoke had crossed the
                // decision, this is where it would already be visible.
                let on_disk = decode_record(&fs::read(record_path(&state_dir)).unwrap()).unwrap();
                assert_eq!(on_disk.generation, 2, "generation moved under the decision");
                assert_eq!(
                    on_disk.devices.get(&observed_d_id).unwrap().status,
                    DeviceStatus::Active,
                    "a revoke crossed the consume decision"
                );
                Ok::<_, std::convert::Infallible>(consumed.generation())
            })
        });

        // The effect is now running inside the critical section.
        assert_eq!(entered_rx.recv().unwrap(), 2);

        let revoker_auth = Arc::clone(&auth);
        let revoker = std::thread::spawn(move || {
            revoker_auth.revoke_device_as_owner(&owner_cert, &target_d_id, &revoke_pop, &nonce, NOW)
        });

        // Well inside LOCK_TIMEOUT (5s), so blocking here is contention, not a
        // timeout. The revoker polls every 10ms, so 250ms is many attempts.
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            !revoker.is_finished(),
            "the revoke completed while the consume decision was still open"
        );

        release_tx.send(()).unwrap();
        let consumed_generation = consumer.join().unwrap().unwrap();
        assert_eq!(consumed_generation, 2);

        // ...and the lock really is released: the revoke now lands, after.
        let outcome = revoker.join().unwrap().unwrap();
        assert_eq!(outcome, MutationOutcome::Applied { generation: 3 });
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&fx.cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked
        );
    }

    #[test]
    fn the_sealed_fence_checks_survive_the_closure_api() {
        // Peer, generation/snapshot drift, and revocation are all still enforced
        // through `consume_with_effect` — the atomicity change must not have
        // quietly relaxed the §10 recheck.
        let fx = fixture();
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let peer = *fx.device.public().as_bytes();

        let wrong_peer = *P256Keypair::generate().public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &wrong_peer, NOW).unwrap_err(),
            DeviceAdmissionError::PeerIdentityMismatch
        );

        // Generation drift via an unrelated admission.
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        let sibling_key = P256Keypair::generate();
        let sibling = DeviceCert::sign(
            &fx.person,
            SignOptions {
                p_pub: fx.person.public(),
                d_pub: sibling_key.public(),
                device_name: "iPad Pro".into(),
                platform: "ipados".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap();
        let hh_id = derive_household_id(&fx.hh.public());
        let generation = auth.live_snapshot().unwrap().generation();
        let nonce = [77u8; 32];
        let challenge = add_pop_challenge(
            &hh_id,
            generation,
            &sibling,
            &sibling.digest().unwrap(),
            &owner_person_cert_digest(&fx.owner).unwrap(),
            &nonce,
        )
        .unwrap();
        let pop = fx.person.sign(&challenge).unwrap();
        auth.admit_device(&fx.owner, &sibling, &pop, &nonce, NOW)
            .unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );

        // Revocation.
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();
        owner_revoke(&fx, &auth, 3).unwrap();
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
    }

    // ── D2b-A: post-rename honesty across EVERY public mutator ─────────────

    fn person_revoke(
        fx: &Fixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        nonce: u8,
    ) -> Result<MutationOutcome, DeviceAdmissionError> {
        let nonce = [nonce; 32];
        let challenge = person_revoke_challenge(
            &derive_household_id(&fx.hh.public()),
            &fx.owner.p_id,
            &nonce,
        )?;
        let pop = fx.person.sign(&challenge).unwrap();
        auth.revoke_person_as_owner(&fx.owner, &fx.owner.p_id, &pop, &nonce, NOW)
    }

    /// Every public mutation entry point. `revoke_person_as_owner` matters
    /// separately from the device revokes because it does not share
    /// `apply_device_revocation` — it owns an independent `settle` call, so
    /// covering the device revokes says nothing about it.
    #[derive(Clone, Copy, Debug)]
    enum Mutator {
        Provision,
        Admit,
        OwnerRevoke,
        SelfRevoke,
        PersonRevoke,
    }

    impl Mutator {
        const ALL: [Self; 5] = [
            Self::Provision,
            Self::Admit,
            Self::OwnerRevoke,
            Self::SelfRevoke,
            Self::PersonRevoke,
        ];
    }

    /// The load-bearing coverage claim: for EVERY public mutator and EVERY
    /// post-rename stage, a write that already landed is reported as
    /// `Uncertain` — never as an error, never as a settled generation.
    ///
    /// Each case builds fresh isolated state, arms exactly one stage on this
    /// thread, and drives the real entry point, so the outcome crosses
    /// `settle` → `persist` → `atomic_replace` for real. Nothing here
    /// fabricates an `Uncertain`.
    #[test]
    fn every_mutator_reports_uncertain_honestly_at_every_post_rename_stage() {
        for mutator in Mutator::ALL {
            for stage in POST_RENAME_STAGES {
                let case = format!("{mutator:?}/{stage:?}");
                let fx = fixture();
                let auth = authority(&fx);

                // Preconditions commit normally — nothing is armed yet.
                let expected_generation = match mutator {
                    Mutator::Provision => 1,
                    Mutator::Admit => {
                        auth.provision().unwrap();
                        2
                    }
                    Mutator::OwnerRevoke | Mutator::SelfRevoke | Mutator::PersonRevoke => {
                        auth.provision().unwrap();
                        admit(&fx, &auth, 1).unwrap();
                        3
                    }
                };

                let result = {
                    let _armed = fail_injection::arm(stage);
                    match mutator {
                        Mutator::Provision => auth.provision(),
                        Mutator::Admit => admit(&fx, &auth, 2),
                        Mutator::OwnerRevoke => owner_revoke(&fx, &auth, 2),
                        Mutator::SelfRevoke => self_revoke(&fx, &auth, &fx.device, 2),
                        Mutator::PersonRevoke => person_revoke(&fx, &auth, 2),
                    }
                };
                let outcome = result.unwrap_or_else(|error| {
                    panic!("{case}: a post-rename failure must not be Err, got {error:?}")
                });

                // 1. Exact outcome, naming the stage and the attempted generation.
                assert_eq!(
                    outcome,
                    MutationOutcome::Uncertain {
                        attempted_generation: expected_generation,
                        stage,
                    },
                    "{case}: outcome must be Uncertain naming this stage"
                );
                assert!(!outcome.is_settled(), "{case}");
                assert_eq!(
                    outcome.generation(),
                    None,
                    "{case}: Uncertain must claim no generation"
                );

                // 2. The projection must not be published for an unverified write.
                assert!(
                    auth.durable_projection().is_none(),
                    "{case}: projection must stay cleared"
                );

                // 3. A direct disk reread must observe the intended new state —
                //    this is what makes "no effect" a lie.
                let on_disk =
                    decode_record(&fs::read(record_path(&fx.state_dir)).unwrap()).unwrap();
                assert_eq!(
                    on_disk.generation, expected_generation,
                    "{case}: the durable generation really advanced"
                );
                match mutator {
                    Mutator::Provision => {
                        assert!(on_disk.devices.is_empty(), "{case}");
                        assert_eq!(on_disk.revocation_cursor, 0, "{case}");
                    }
                    Mutator::Admit => {
                        let entry = on_disk
                            .devices
                            .get(&fx.cert.d_id.0)
                            .unwrap_or_else(|| panic!("{case}: device must be on disk"));
                        assert_eq!(entry.status, DeviceStatus::Active, "{case}");
                        assert_eq!(entry.admitted_at_generation, expected_generation, "{case}");
                    }
                    Mutator::OwnerRevoke | Mutator::SelfRevoke => {
                        let entry = on_disk.devices.get(&fx.cert.d_id.0).unwrap();
                        assert_eq!(entry.status, DeviceStatus::Revoked, "{case}");
                        assert_eq!(
                            entry.revoked_at_generation,
                            Some(expected_generation),
                            "{case}"
                        );
                        assert_eq!(on_disk.revocation_cursor, 1, "{case}");
                    }
                    Mutator::PersonRevoke => {
                        assert!(
                            on_disk.revoked_persons.contains(&fx.owner.p_id.0),
                            "{case}: the person must be revoked on disk"
                        );
                        let entry = on_disk.devices.get(&fx.cert.d_id.0).unwrap();
                        assert_eq!(
                            entry.status,
                            DeviceStatus::Revoked,
                            "{case}: person revocation must have cascaded"
                        );
                        assert_eq!(on_disk.revocation_cursor, 1, "{case}");
                    }
                }

                // 4. Reconciliation per the documented rule settles the outcome.
                match mutator {
                    Mutator::Provision => {
                        assert_eq!(
                            auth.provision().unwrap_err(),
                            DeviceAdmissionError::AlreadyProvisioned,
                            "{case}: re-provisioning must be refused, never repeated"
                        );
                    }
                    Mutator::Admit
                    | Mutator::OwnerRevoke
                    | Mutator::SelfRevoke
                    | Mutator::PersonRevoke => {
                        let reconciled = match mutator {
                            Mutator::Admit => admit(&fx, &auth, 3),
                            Mutator::OwnerRevoke => owner_revoke(&fx, &auth, 3),
                            Mutator::SelfRevoke => self_revoke(&fx, &auth, &fx.device, 3),
                            Mutator::PersonRevoke => person_revoke(&fx, &auth, 3),
                            Mutator::Provision => unreachable!(),
                        }
                        .unwrap_or_else(|error| {
                            panic!("{case}: reconciliation must succeed, got {error:?}")
                        });
                        assert_eq!(
                            reconciled,
                            MutationOutcome::Idempotent {
                                generation: expected_generation
                            },
                            "{case}: retrying must be idempotent, not a second mutation"
                        );
                        assert!(reconciled.is_settled(), "{case}");
                    }
                }
            }
        }
    }

    // ── D2c-0: the durable entry carries the device's exact caveat set ─────

    fn fixture_with_device_caveats(caveats: Option<Vec<Caveat>>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        let hh = P256Keypair::generate();
        let person = P256Keypair::generate();
        let device = P256Keypair::generate();
        let owner = owner_cert(&hh, &person);
        let cert = DeviceCert::sign(
            &person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: "iPhone 15".into(),
                platform: "ios".into(),
                added_at: NOW,
                caveats,
            },
        )
        .unwrap();
        Fixture {
            _dir: dir,
            state_dir,
            hh,
            person,
            device,
            owner,
            cert,
        }
    }

    /// A device caveat that narrows the owner's `ClawsList` (scope `All`) to a
    /// single claw. `caveats::permits` rejects a non-`All` scope for this
    /// operation, so the stored set is what decides — which is the whole reason
    /// D2c-0 exists.
    fn restrictive_device_caveats() -> Vec<Caveat> {
        vec![Caveat::new(
            Operation::ClawsList,
            Some(crate::caveats::Scope::Specific {
                specific: vec!["c_one".into()],
            }),
        )]
    }

    fn admitted_entry(
        fx: &Fixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
    ) -> DeviceAdmissionEntryV1 {
        auth.live_snapshot()
            .unwrap()
            .entry(&fx.cert.d_id)
            .cloned()
            .expect("device admitted")
    }

    #[test]
    fn entry_keyset_and_canonical_roundtrip_include_device_caveats() {
        let fx = fixture_with_device_caveats(None);
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // The key must be present on the wire under its explicit name.
        let bytes = record_bytes(&fx);
        let value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let ciborium::value::Value::Map(record) = value else {
            panic!("record is a CBOR map");
        };
        let devices = record
            .iter()
            .find(|(k, _)| k == &ciborium::value::Value::Text("devices".into()))
            .map(|(_, v)| v.clone())
            .expect("devices map");
        let ciborium::value::Value::Map(devices) = devices else {
            panic!("devices is a CBOR map");
        };
        let ciborium::value::Value::Map(entry) = devices[0].1.clone() else {
            panic!("entry is a CBOR map");
        };
        let mut keys = entry
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(t) => t.clone(),
                _ => panic!("entry keys are text"),
            })
            .collect::<Vec<_>>();
        keys.sort();
        assert!(
            keys.contains(&"device_caveats".to_string()),
            "the durable entry must carry device_caveats: {keys:?}"
        );

        // And the record still round-trips byte-exactly through the strict decoder.
        let decoded = decode_record(&bytes).unwrap();
        assert_eq!(cbor::to_canonical_vec(&decoded).unwrap(), bytes);
    }

    #[test]
    fn none_and_empty_device_caveats_are_distinct_and_survive_reopen() {
        let none_fx = fixture_with_device_caveats(None);
        let none_auth = authority(&none_fx);
        none_auth.provision().unwrap();
        admit(&none_fx, &none_auth, 1).unwrap();

        let empty_fx = fixture_with_device_caveats(Some(Vec::new()));
        let empty_auth = authority(&empty_fx);
        empty_auth.provision().unwrap();
        admit(&empty_fx, &empty_auth, 1).unwrap();

        // `None` means "no attenuation declared, inherit the PersonCert";
        // `Some([])` means "attenuated to nothing". Collapsing them would erase
        // an authorization decision, so the bytes must differ.
        let none_entry = admitted_entry(&none_fx, &none_auth);
        let empty_entry = admitted_entry(&empty_fx, &empty_auth);
        assert_eq!(none_entry.device_caveats, None);
        assert_eq!(empty_entry.device_caveats, Some(Vec::new()));
        assert_ne!(
            cbor::to_canonical_vec(&none_entry).unwrap(),
            cbor::to_canonical_vec(&empty_entry).unwrap(),
            "None and Some([]) must not encode identically"
        );

        // Both survive a crash/reopen unchanged.
        assert_eq!(
            admitted_entry(&none_fx, &authority(&none_fx)).device_caveats,
            None
        );
        assert_eq!(
            admitted_entry(&empty_fx, &authority(&empty_fx)).device_caveats,
            Some(Vec::new())
        );
    }

    #[test]
    fn restrictive_device_caveats_survive_reopen_and_permits_reflects_them() {
        let fx = fixture_with_device_caveats(Some(restrictive_device_caveats()));
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // Reopened from disk, not from the in-memory projection.
        let entry = admitted_entry(&fx, &authority(&fx));
        let stored = entry.device_caveats.as_ref().expect("caveats stored");
        assert_eq!(stored, &restrictive_device_caveats());

        // The stored set is what a delegated authorizer would evaluate, and it
        // really does deny what the owner's own set would have allowed.
        assert!(
            !caveats::permits(stored, &Operation::ClawsList),
            "a Specific scope must not satisfy ClawsList"
        );
        assert!(
            caveats::permits(&fx.owner.caveats, &Operation::ClawsList),
            "the owner's own set still allows it — the device is strictly narrower"
        );
    }

    #[test]
    fn re_admitting_with_a_different_caveat_binding_is_not_idempotent() {
        let fx = fixture_with_device_caveats(None);
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        // Tamper only the stored caveat set, leaving d_pub and both digests
        // intact. A digest-only binding check would call this idempotent.
        let path = record_path(&fx.state_dir);
        let mut record = decode_record(&fs::read(&path).unwrap()).unwrap();
        record
            .devices
            .get_mut(&fx.cert.d_id.0)
            .unwrap()
            .device_caveats = Some(restrictive_device_caveats());
        fs::write(&path, cbor::to_canonical_vec(&record).unwrap()).unwrap();

        let entry = admitted_entry(&fx, &auth);
        assert_eq!(entry.device_cert_digest.0, fx.cert.digest().unwrap());
        assert_eq!(entry.d_pub, fx.device.public());
        assert_eq!(
            admit(&fx, &auth, 2).unwrap_err(),
            DeviceAdmissionError::BindingConflict,
            "a caveat set that disagrees with the presented cert is a conflict, \
             never an idempotent no-op"
        );
    }

    #[test]
    fn a_sealed_token_is_refused_after_device_caveat_drift() {
        let fx = fixture_with_device_caveats(None);
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();

        let peer = *fx.device.public().as_bytes();
        let sealed = auth.seal(&fx.cert.d_id, &peer, NOW).unwrap();

        let path = record_path(&fx.state_dir);
        let mut record = decode_record(&fs::read(&path).unwrap()).unwrap();
        record
            .devices
            .get_mut(&fx.cert.d_id.0)
            .unwrap()
            .device_caveats = Some(restrictive_device_caveats());
        fs::write(&path, cbor::to_canonical_vec(&record).unwrap()).unwrap();

        // The field is inside the record, so it is inside the snapshot digest;
        // the consume fence must not ignore that drift.
        assert_eq!(
            consume_probe(&auth, sealed, &peer, NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
    }

    #[test]
    fn corrupt_device_caveats_field_fails_closed() {
        let fx = fixture_with_device_caveats(Some(restrictive_device_caveats()));
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let path = record_path(&fx.state_dir);
        let good = fs::read(&path).unwrap();

        let rewrite_entry =
            |mutate: &dyn Fn(&mut Vec<(ciborium::value::Value, ciborium::value::Value)>)| {
                let value: ciborium::value::Value =
                    ciborium::de::from_reader(good.as_slice()).unwrap();
                let ciborium::value::Value::Map(mut record) = value else {
                    panic!("map");
                };
                for slot in &mut record {
                    if slot.0 != ciborium::value::Value::Text("devices".into()) {
                        continue;
                    }
                    let ciborium::value::Value::Map(devices) = &mut slot.1 else {
                        panic!("devices map");
                    };
                    let ciborium::value::Value::Map(entry) = &mut devices[0].1 else {
                        panic!("entry map");
                    };
                    mutate(entry);
                }
                let mut out = Vec::new();
                ciborium::ser::into_writer(&ciborium::value::Value::Map(record), &mut out).unwrap();
                out
            };

        // Missing: the field is required, so an entry without it is not a v1 entry.
        let missing = rewrite_entry(&|entry| {
            entry.retain(|(k, _)| k != &ciborium::value::Value::Text("device_caveats".into()));
        });
        fs::write(&path, &missing).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::RecordCorrupt,
            "a missing device_caveats key must fail closed"
        );

        // Unknown sibling key: deny_unknown_fields.
        let unknown = rewrite_entry(&|entry| {
            entry.push((
                ciborium::value::Value::Text("device_caveats_v2".into()),
                ciborium::value::Value::Null,
            ));
        });
        fs::write(&path, &unknown).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::RecordCorrupt
        );

        // Non-canonical ordering of the entry map.
        let reordered = rewrite_entry(&|entry| entry.reverse());
        assert_ne!(reordered, good);
        fs::write(&path, &reordered).unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap_err(),
            DeviceAdmissionError::RecordCorrupt
        );

        // The good bytes still load, so the three negatives above are not
        // passing because the fixture was broken to begin with.
        fs::write(&path, &good).unwrap();
        assert!(auth.live_snapshot().is_ok());
    }

    /// Decode a single `DeviceAdmissionEntryV1` **typed and in isolation**.
    ///
    /// `corrupt_device_caveats_field_fails_closed` goes through
    /// `decode_record`, whose canonical re-encode byte-compare backstops
    /// everything: with that compare in place, a missing or unknown entry key is
    /// rejected even if the typed schema would have accepted it. That test
    /// therefore says nothing about the two serde-level defences. Measured:
    /// adding `#[serde(default)]` to the field, or dropping
    /// `deny_unknown_fields` from the entry, left it green.
    ///
    /// This test removes that backstop by construction — it never calls
    /// `decode_record` and never compares bytes. `cbor::from_canonical_slice`
    /// is a plain typed decode that performs no ordering or byte-equality
    /// check, so the *only* thing that can reject these inputs is the entry's
    /// own schema. Each negative is paired with a generic-`Value` decode of the
    /// same bytes, which must succeed: that proves the bytes are well-formed
    /// CBOR and the rejection is attributable to the typed schema alone.
    #[test]
    fn entry_typed_decode_requires_device_caveats_and_rejects_unknown_keys() {
        let fx = fixture_with_device_caveats(Some(restrictive_device_caveats()));
        let auth = authority(&fx);
        auth.provision().unwrap();
        admit(&fx, &auth, 1).unwrap();
        let entry = admitted_entry(&fx, &auth);

        // Canonical bytes of the entry alone — no surrounding record.
        let canonical = cbor::to_canonical_vec(&entry).unwrap();

        // Positive control: the untouched entry decodes typed. Without this the
        // two negatives below could pass for the wrong reason.
        let decoded: DeviceAdmissionEntryV1 =
            cbor::from_canonical_slice(&canonical).expect("a well-formed entry must decode typed");
        assert_eq!(decoded, entry);

        let entry_map = |bytes: &[u8]| -> Vec<(ciborium::value::Value, ciborium::value::Value)> {
            let value: ciborium::value::Value = ciborium::de::from_reader(bytes).unwrap();
            match value {
                ciborium::value::Value::Map(map) => map,
                _ => panic!("an entry encodes as a CBOR map"),
            }
        };
        let encode = |map: Vec<(ciborium::value::Value, ciborium::value::Value)>| {
            let mut out = Vec::new();
            ciborium::ser::into_writer(&ciborium::value::Value::Map(map), &mut out).unwrap();
            out
        };

        // ── missing `device_caveats` ───────────────────────────────────────
        let mut map = entry_map(&canonical);
        map.retain(|(k, _)| k != &ciborium::value::Value::Text("device_caveats".into()));
        let missing = encode(map);
        assert!(
            ciborium::de::from_reader::<ciborium::value::Value, _>(missing.as_slice()).is_ok(),
            "the missing-field bytes must still be well-formed CBOR, so the \
             rejection below is the typed schema and not a parse failure"
        );
        assert!(
            cbor::from_canonical_slice::<DeviceAdmissionEntryV1>(&missing).is_err(),
            "the entry schema must require device_caveats; a defaulted field \
             would silently turn an absent set into None"
        );

        // ── unknown sibling key ────────────────────────────────────────────
        let mut map = entry_map(&canonical);
        map.push((
            ciborium::value::Value::Text("device_caveats_v2".into()),
            ciborium::value::Value::Null,
        ));
        let unknown = encode(map);
        assert!(
            ciborium::de::from_reader::<ciborium::value::Value, _>(unknown.as_slice()).is_ok(),
            "the unknown-key bytes must still be well-formed CBOR"
        );
        assert!(
            cbor::from_canonical_slice::<DeviceAdmissionEntryV1>(&unknown).is_err(),
            "the entry schema must deny unknown fields at the entry level, not \
             only via the record's canonical byte-compare"
        );
    }

    // ── D2d: atomic two-device pair admission ──────────────────────────────

    /// Two distinct devices under one household, plus everything needed to
    /// admit and revoke either of them.
    ///
    /// A second person is carried so a person-scoped failure can be aimed at
    /// exactly one side of a pair: with both devices under one person, a
    /// person-level refusal would hit whichever side is checked first and a
    /// test aimed at the other side would pass vacuously.
    struct PairFixture {
        _dir: tempfile::TempDir,
        state_dir: PathBuf,
        hh: P256Keypair,
        person_a: P256Keypair,
        owner_a: PersonCert,
        person_b: P256Keypair,
        owner_b: PersonCert,
        a_key: P256Keypair,
        a_cert: DeviceCert,
        b_key: P256Keypair,
        b_cert: DeviceCert,
    }

    fn device_cert_for(person: &P256Keypair, device: &P256Keypair, name: &str) -> DeviceCert {
        DeviceCert::sign(
            person,
            SignOptions {
                p_pub: person.public(),
                d_pub: device.public(),
                device_name: name.into(),
                platform: "ios".into(),
                added_at: NOW,
                caveats: None,
            },
        )
        .unwrap()
    }

    impl PairFixture {
        /// `b_not_after` bounds the *second* person only, so an expiry can be
        /// aimed at the responder without touching the initiator.
        fn build(b_not_after: Option<u64>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let state_dir = dir.path().to_path_buf();
            let hh = P256Keypair::generate();
            let person_a = P256Keypair::generate();
            let person_b = P256Keypair::generate();
            let owner_a = owner_cert(&hh, &person_a);
            let mut owner_b = owner_cert(&hh, &person_b);
            if let Some(limit) = b_not_after {
                owner_b.not_after = Some(limit);
                // Re-signed: `not_after` is covered by the household signature,
                // so an unsigned edit would not survive verification.
                let signing = owner_b.signing_bytes().unwrap();
                owner_b.signature = hh.sign(&signing).unwrap();
            }
            let a_key = P256Keypair::generate();
            let b_key = P256Keypair::generate();
            let a_cert = device_cert_for(&person_a, &a_key, "iPhone 15");
            let b_cert = device_cert_for(&person_b, &b_key, "iPad Pro");
            Self {
                _dir: dir,
                state_dir,
                hh,
                person_a,
                owner_a,
                person_b,
                owner_b,
                a_key,
                a_cert,
                b_key,
                b_cert,
            }
        }

        fn hh_id(&self) -> HouseholdId {
            derive_household_id(&self.hh.public())
        }

        fn authority(&self) -> HouseholdDeviceAdmissionAuthorityV1 {
            HouseholdDeviceAdmissionAuthorityV1::new(
                &self.state_dir,
                self.hh_id(),
                self.hh.public(),
            )
        }

        fn a_peer(&self) -> [u8; 33] {
            *self.a_key.public().as_bytes()
        }

        fn b_peer(&self) -> [u8; 33] {
            *self.b_key.public().as_bytes()
        }

        fn admit(
            &self,
            auth: &HouseholdDeviceAdmissionAuthorityV1,
            owner: &PersonCert,
            person: &P256Keypair,
            cert: &DeviceCert,
            nonce: u8,
        ) -> Result<MutationOutcome, DeviceAdmissionError> {
            let generation = auth.live_snapshot()?.generation();
            let nonce = [nonce; 32];
            let challenge = add_pop_challenge(
                &self.hh_id(),
                generation,
                cert,
                &cert.digest().unwrap(),
                &owner_person_cert_digest(owner)?,
                &nonce,
            )?;
            let pop = person.sign(&challenge).unwrap();
            auth.admit_device(owner, cert, &pop, &nonce, NOW)
        }

        fn revoke(
            &self,
            auth: &HouseholdDeviceAdmissionAuthorityV1,
            owner: &PersonCert,
            person: &P256Keypair,
            d_id: &DeviceId,
            nonce: u8,
        ) -> Result<MutationOutcome, DeviceAdmissionError> {
            let nonce = [nonce; 32];
            let challenge = owner_revoke_challenge(&self.hh_id(), d_id, &nonce)?;
            let pop = person.sign(&challenge).unwrap();
            auth.revoke_device_as_owner(owner, d_id, &pop, &nonce, NOW)
        }

        fn revoke_a(
            &self,
            auth: &HouseholdDeviceAdmissionAuthorityV1,
            nonce: u8,
        ) -> Result<MutationOutcome, DeviceAdmissionError> {
            self.revoke(
                auth,
                &self.owner_a,
                &self.person_a,
                &self.a_cert.d_id,
                nonce,
            )
        }

        fn revoke_b(
            &self,
            auth: &HouseholdDeviceAdmissionAuthorityV1,
            nonce: u8,
        ) -> Result<MutationOutcome, DeviceAdmissionError> {
            self.revoke(
                auth,
                &self.owner_b,
                &self.person_b,
                &self.b_cert.d_id,
                nonce,
            )
        }

        fn read_record(&self) -> DeviceAdmissionRecordV1 {
            decode_record(&fs::read(record_path(&self.state_dir)).unwrap()).unwrap()
        }

        fn write_record(&self, record: &DeviceAdmissionRecordV1) {
            fs::write(
                record_path(&self.state_dir),
                cbor::to_canonical_vec(record).unwrap(),
            )
            .unwrap();
        }

        fn bytes(&self) -> Vec<u8> {
            fs::read(record_path(&self.state_dir)).unwrap()
        }
    }

    /// A provisioned authority with both devices admitted. Generation is 3:
    /// provision, admit A, admit B.
    fn pair_ready(b_not_after: Option<u64>) -> (PairFixture, HouseholdDeviceAdmissionAuthorityV1) {
        let fx = PairFixture::build(b_not_after);
        let auth = fx.authority();
        auth.provision().unwrap();
        fx.admit(&auth, &fx.owner_a, &fx.person_a, &fx.a_cert, 1)
            .unwrap();
        fx.admit(&auth, &fx.owner_b, &fx.person_b, &fx.b_cert, 2)
            .unwrap();
        assert_eq!(
            auth.live_snapshot().unwrap().generation(),
            3,
            "the pair fixture must be at a known generation"
        );
        (fx, auth)
    }

    fn seal_ab(
        fx: &PairFixture,
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        now: u64,
    ) -> Result<SealedDevicePairAdmissionV1, DeviceAdmissionError> {
        auth.seal_pair(
            &fx.a_cert.d_id,
            &fx.a_peer(),
            &fx.b_cert.d_id,
            &fx.b_peer(),
            now,
        )
    }

    /// What the pair effect observed, copied out so assertions can run after the
    /// lock is released.
    #[derive(Debug)]
    struct PairProbe {
        initiator_peer: [u8; 33],
        responder_peer: [u8; 33],
        roles: (PairRole, PairRole),
        generation: u64,
        snapshot_digest: [u8; 32],
        consumed_at: u64,
    }

    /// Consume a pair, recording what the effect saw.
    ///
    /// The observation is written into a captured cell rather than returned:
    /// the effect's success type is `()` on purpose, so that a caller cannot
    /// hand a lazily-evaluated value back across the fence. This helper is
    /// therefore also the worked example of the intended caller shape — do the
    /// work inside, publish nothing deferred.
    ///
    /// The effect always succeeds here, so the `Effect` arm is unreachable in
    /// practice and this surfaces `DeviceAdmissionError` directly, keeping the
    /// tests about admission rather than plumbing.
    fn consume_pair_probe(
        auth: &HouseholdDeviceAdmissionAuthorityV1,
        sealed: SealedDevicePairAdmissionV1,
        initiator: &[u8; 33],
        responder: &[u8; 33],
        now: u64,
    ) -> Result<PairProbe, DeviceAdmissionError> {
        use std::cell::RefCell;

        let observed: RefCell<Option<PairProbe>> = RefCell::new(None);
        auth.consume_pair_with_effect(sealed, initiator, responder, now, |consumed| {
            *observed.borrow_mut() = Some(PairProbe {
                initiator_peer: *consumed.initiator().peer_identity_pub_sec1(),
                responder_peer: *consumed.responder().peer_identity_pub_sec1(),
                roles: (consumed.initiator().role(), consumed.responder().role()),
                generation: consumed.generation(),
                snapshot_digest: *consumed.snapshot_digest(),
                consumed_at: consumed.consumed_at(),
            });
            Ok(())
        })
        .map_err(|error| match error {
            ConsumePairError::Admission(error) => error,
            ConsumePairError::Effect(failure) => {
                panic!("the probe effect never fails, got {failure:?}")
            }
        })?;
        Ok(observed
            .into_inner()
            .expect("a successful consume must have run the effect"))
    }

    #[test]
    fn seal_pair_then_consume_pair_round_trips() {
        let (fx, auth) = pair_ready(None);
        let live = auth.live_snapshot().unwrap();

        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        // One generation and one snapshot digest for BOTH sides — the atomicity
        // claim, read off the fact itself.
        assert_eq!(sealed.generation(), live.generation());
        assert_eq!(sealed.snapshot_digest(), live.snapshot_digest());
        assert_eq!(sealed.verified_at(), NOW);
        assert_eq!(sealed.initiator().d_id(), &fx.a_cert.d_id);
        assert_eq!(sealed.responder().d_id(), &fx.b_cert.d_id);
        assert_eq!(
            sealed.member(PairRole::Initiator).role(),
            PairRole::Initiator
        );
        assert_eq!(
            sealed.member(PairRole::Responder).role(),
            PairRole::Responder
        );

        let probe = consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap();
        assert_eq!(probe.initiator_peer, fx.a_peer());
        assert_eq!(probe.responder_peer, fx.b_peer());
        assert_eq!(probe.roles, (PairRole::Initiator, PairRole::Responder));
        assert_eq!(probe.generation, live.generation());
        assert_eq!(probe.snapshot_digest, *live.snapshot_digest());
        assert_eq!(probe.consumed_at, NOW);
    }

    #[test]
    fn a_pair_must_name_two_distinct_devices() {
        let (fx, auth) = pair_ready(None);

        // Positive control first: the same fixture DOES seal a genuine pair, so
        // the refusals below are about sameness and not a broken fixture.
        assert!(seal_ab(&fx, &auth, NOW).is_ok());

        for (label, d_id, peer) in [
            ("initiator twice", &fx.a_cert.d_id, fx.a_peer()),
            ("responder twice", &fx.b_cert.d_id, fx.b_peer()),
        ] {
            assert_eq!(
                auth.seal_pair(d_id, &peer, d_id, &peer, NOW).unwrap_err(),
                DeviceAdmissionError::PairSameDevice,
                "{label}: one device named twice is not a pair"
            );
        }
    }

    #[test]
    fn two_d_ids_that_resolve_to_one_key_are_not_a_pair() {
        let (fx, auth) = pair_ready(None);
        // Positive control: distinct keys seal.
        assert!(seal_ab(&fx, &auth, NOW).is_ok());

        // Tamper so B's entry carries A's admitted key. The two `d_id`s still
        // differ, so a name-only distinctness check would pass this.
        let mut record = fx.read_record();
        record.devices.get_mut(&fx.b_cert.d_id.0).unwrap().d_pub = fx.a_key.public();
        fx.write_record(&record);

        assert_eq!(
            auth.seal_pair(
                &fx.a_cert.d_id,
                &fx.a_peer(),
                &fx.b_cert.d_id,
                &fx.a_peer(),
                NOW
            )
            .unwrap_err(),
            DeviceAdmissionError::PairSameDevice,
            "two names for one admitted key is one party, not a pair"
        );
    }

    /// The non-vacuity control for every pair refusal.
    ///
    /// Each failure kind is produced once on the initiator side and once on the
    /// responder side, and the assertion is on `(role, cause)` rather than on
    /// `cause` alone. Without the role, a test aimed at the responder could pass
    /// because the *initiator* refused first — a real refusal, but not the one
    /// under test. The paired cases also prove neither side's guard is missing:
    /// a check present on only one side shows up here as a mismatched role.
    #[test]
    fn pair_refusals_name_the_side_that_failed() {
        #[derive(Clone, Copy, Debug)]
        enum Break {
            NotListed,
            Revoked,
            PersonRevoked,
            WrongKey,
        }

        for kind in [
            Break::NotListed,
            Break::Revoked,
            Break::PersonRevoked,
            Break::WrongKey,
        ] {
            for role in [PairRole::Initiator, PairRole::Responder] {
                let case = format!("{kind:?}/{role:?}");
                let (fx, auth) = pair_ready(None);

                // Positive control per case: this fixture seals before it is
                // broken, so the refusal below is attributable to the break.
                assert!(seal_ab(&fx, &auth, NOW).is_ok(), "{case}: control");

                let stranger = *P256Keypair::generate().public().as_bytes();
                let missing = derive_device_id(&P256Keypair::generate().public());
                let (mut a_id, mut a_peer) = (fx.a_cert.d_id.clone(), fx.a_peer());
                let (mut b_id, mut b_peer) = (fx.b_cert.d_id.clone(), fx.b_peer());

                let expected = match kind {
                    Break::NotListed => {
                        match role {
                            PairRole::Initiator => a_id = missing,
                            PairRole::Responder => b_id = missing,
                        }
                        DeviceAdmissionError::DeviceNotListed
                    }
                    Break::Revoked => {
                        match role {
                            PairRole::Initiator => fx.revoke_a(&auth, 7).unwrap(),
                            PairRole::Responder => fx.revoke_b(&auth, 7).unwrap(),
                        };
                        DeviceAdmissionError::DeviceRevoked
                    }
                    Break::PersonRevoked => {
                        // Revoke the person WITHOUT cascading to the device, so
                        // the person check is what refuses rather than the
                        // status check that normally fires first. The API always
                        // cascades, so this state is only reachable by writing
                        // it — and a record whose cascade is incomplete must
                        // still fail closed.
                        let mut record = fx.read_record();
                        let p_id = match role {
                            PairRole::Initiator => fx.owner_a.p_id.0.clone(),
                            PairRole::Responder => fx.owner_b.p_id.0.clone(),
                        };
                        record.revoked_persons.insert(p_id);
                        fx.write_record(&record);
                        DeviceAdmissionError::PersonRevoked
                    }
                    Break::WrongKey => {
                        match role {
                            PairRole::Initiator => a_peer = stranger,
                            PairRole::Responder => b_peer = stranger,
                        }
                        DeviceAdmissionError::PeerIdentityMismatch
                    }
                };

                let error = auth
                    .seal_pair(&a_id, &a_peer, &b_id, &b_peer, NOW)
                    .unwrap_err();
                assert_eq!(
                    error.pair_member(),
                    Some((role, &expected)),
                    "{case}: the refusal must name the side that failed"
                );
            }
        }
    }

    #[test]
    fn a_pair_sealed_before_a_revoke_of_either_side_is_stale_at_consume() {
        for role in [PairRole::Initiator, PairRole::Responder] {
            let (fx, auth) = pair_ready(None);
            let sealed = seal_ab(&fx, &auth, NOW).unwrap();

            match role {
                PairRole::Initiator => fx.revoke_a(&auth, 9).unwrap(),
                PairRole::Responder => fx.revoke_b(&auth, 9).unwrap(),
            };

            assert_eq!(
                consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap_err(),
                DeviceAdmissionError::StaleSeal,
                "{role:?}: revoking either side must invalidate the pair"
            );
        }
    }

    #[test]
    fn a_pair_is_stale_after_any_unrelated_generation_change() {
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();

        // A third device, unrelated to both members: neither side changed, but
        // the snapshot the pair was sealed against no longer exists.
        let third_key = P256Keypair::generate();
        let third = device_cert_for(&fx.person_a, &third_key, "MacBook");
        fx.admit(&auth, &fx.owner_a, &fx.person_a, &third, 11)
            .unwrap();

        assert_eq!(
            consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
    }

    #[test]
    fn a_pair_sealed_for_one_ordering_never_authorizes_the_swap() {
        let (fx, auth) = pair_ready(None);

        // Swapped presentation: the initiator slot is offered the responder key.
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        let error = consume_pair_probe(&auth, sealed, &fx.b_peer(), &fx.a_peer(), NOW).unwrap_err();
        assert_eq!(
            error.pair_member(),
            Some((
                PairRole::Initiator,
                &DeviceAdmissionError::PeerIdentityMismatch
            )),
            "a pair sealed for (A, B) must not authorize the dial (B, A)"
        );

        // Responder slot substituted for a third key, initiator left correct —
        // so the responder-side check is what refuses.
        let stranger = *P256Keypair::generate().public().as_bytes();
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        let error = consume_pair_probe(&auth, sealed, &fx.a_peer(), &stranger, NOW).unwrap_err();
        assert_eq!(
            error.pair_member(),
            Some((
                PairRole::Responder,
                &DeviceAdmissionError::PeerIdentityMismatch
            ))
        );

        // Control: the correct ordering still consumes, so the two refusals are
        // about position and not about a fixture that cannot consume at all.
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        assert!(consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).is_ok());
    }

    /// Wall-clock revalidation is the one member-level fence reachable at
    /// consume without any authority change: `now` advances on its own, so the
    /// snapshot digest still matches while the limit has passed.
    #[test]
    fn consume_pair_refuses_once_a_members_person_limit_passes() {
        let limit = NOW + 100;
        let (fx, auth) = pair_ready(Some(limit));

        // Control: inside the window the pair seals AND consumes.
        let sealed = seal_ab(&fx, &auth, NOW + 10).unwrap();
        assert!(
            consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW + 10).is_ok(),
            "inside the window the pair must consume"
        );

        // Sealed inside the window, consumed past it: nothing on disk moved.
        let sealed = seal_ab(&fx, &auth, NOW + 10).unwrap();
        let before = fx.bytes();
        let error =
            consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), limit + 1).unwrap_err();
        assert_eq!(
            error.pair_member(),
            Some((
                PairRole::Responder,
                &DeviceAdmissionError::PersonCertExpired
            )),
            "only the responder's person is bounded, so only it may expire"
        );
        assert_eq!(fx.bytes(), before, "the fence must not write");

        // And a fresh seal past the limit is refused outright, on the same side.
        let error = seal_ab(&fx, &auth, limit + 1).unwrap_err();
        assert_eq!(
            error.pair_member(),
            Some((
                PairRole::Responder,
                &DeviceAdmissionError::PersonCertExpired
            ))
        );
    }

    #[test]
    fn pair_seal_and_consume_fail_closed_when_the_authority_disappears() {
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        fs::remove_file(record_path(&fx.state_dir)).unwrap();

        assert_eq!(
            consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
        assert_eq!(
            seal_ab(&fx, &auth, NOW).unwrap_err(),
            DeviceAdmissionError::Unavailable
        );
    }

    #[test]
    fn pair_seal_fails_closed_on_a_zero_generation_record() {
        let (fx, auth) = pair_ready(None);
        let mut record = fx.read_record();
        record.generation = 0;
        fx.write_record(&record);
        assert_eq!(
            seal_ab(&fx, &auth, NOW).unwrap_err(),
            DeviceAdmissionError::GenerationZero
        );
    }

    #[test]
    fn a_pair_sealed_under_one_root_is_refused_by_another() {
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();

        // Same directory, same household id, different root key: the sealed
        // root digest no longer matches the authority being asked.
        let foreign = HouseholdDeviceAdmissionAuthorityV1::new(
            &fx.state_dir,
            fx.hh_id(),
            P256Keypair::generate().public(),
        );
        assert_eq!(
            consume_pair_probe(&foreign, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal
        );
        assert_eq!(
            seal_ab(&fx, &foreign, NOW).unwrap_err(),
            DeviceAdmissionError::WrongHousehold
        );
    }

    /// The effect must run exactly once on success and never on a refusal.
    #[test]
    fn the_pair_effect_runs_exactly_once_and_never_on_a_refusal() {
        use std::cell::Cell;

        // Success: exactly one invocation.
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        let calls = Cell::new(0u32);
        auth.consume_pair_with_effect(sealed, &fx.a_peer(), &fx.b_peer(), NOW, |_consumed| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1, "the effect must run exactly once");

        // Every refusal shape: zero invocations.
        let stranger = *P256Keypair::generate().public().as_bytes();
        for label in ["swapped", "stranger", "revoked", "absent"] {
            let (fx, auth) = pair_ready(None);
            let sealed = seal_ab(&fx, &auth, NOW).unwrap();
            let (initiator, responder) = match label {
                "swapped" => (fx.b_peer(), fx.a_peer()),
                "stranger" => (fx.a_peer(), stranger),
                "revoked" => {
                    fx.revoke_b(&auth, 5).unwrap();
                    (fx.a_peer(), fx.b_peer())
                }
                _ => {
                    fs::remove_file(record_path(&fx.state_dir)).unwrap();
                    (fx.a_peer(), fx.b_peer())
                }
            };
            let calls = Cell::new(0u32);
            let error = auth
                .consume_pair_with_effect(sealed, &initiator, &responder, NOW, |_consumed| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap_err();
            assert!(
                error.as_admission().is_some(),
                "{label}: the fence must be what refused"
            );
            assert_eq!(calls.get(), 0, "{label}: the effect ran despite a refusal");
        }
    }

    #[test]
    fn a_pair_effect_failure_is_distinguishable_from_an_admission_refusal() {
        let (fx, auth) = pair_ready(None);

        // Every failure the closed type can express stays distinguishable from
        // an admission refusal, and each round-trips as itself.
        for failure in [
            PairEffectFailure::NotApplied,
            PairEffectFailure::Declined,
            PairEffectFailure::Incomplete,
        ] {
            let sealed = seal_ab(&fx, &auth, NOW).unwrap();
            let error = auth
                .consume_pair_with_effect(sealed, &fx.a_peer(), &fx.b_peer(), NOW, |_consumed| {
                    Err(failure)
                })
                .unwrap_err();
            assert_eq!(error, ConsumePairError::Effect(failure));
            assert!(
                error.as_admission().is_none(),
                "{failure:?}: an effect failure must not read as an admission refusal"
            );
        }

        // Control: an admission refusal is the other arm, so the assertions
        // above are not simply "everything is an Effect".
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        let stranger = *P256Keypair::generate().public().as_bytes();
        let error = auth
            .consume_pair_with_effect(sealed, &stranger, &fx.b_peer(), NOW, |_consumed| Ok(()))
            .unwrap_err();
        assert!(error.as_admission().is_some());
    }

    /// The failure type is closed and fieldless, so nothing lazily-evaluated can
    /// leave through the `Err` arm.
    ///
    /// This is the CFX the independent auditor raised: an earlier revision fixed
    /// the success type to `()` but left the error type a caller-chosen `E`, and
    /// `Err(async move { … })` — or `Err(move || …)` — was returned by value
    /// after the lock dropped and evaluated outside it. Measured against that
    /// revision: the shape compiled and ran, producing its value with the fence
    /// already released. Pinning one arm moved the hole rather than closing it.
    ///
    /// The property is now a type fact, not a test: `PairEffectFailure` has
    /// three fieldless variants, so there is no position in the signature where
    /// a caller-chosen type — lazy or otherwise — can appear. A future, closure,
    /// or iterator is simply not one of these values, and no `impl` can make it
    /// one. What is asserted here is that the type really is closed and
    /// fieldless, which is what makes that argument hold.
    #[test]
    fn the_pair_effect_failure_type_is_closed_and_carries_no_payload() {
        // Fieldless: each variant is a value, constructible with no arguments,
        // and `Copy` — none of which a deferred computation can be.
        let all = [
            PairEffectFailure::NotApplied,
            PairEffectFailure::Declined,
            PairEffectFailure::Incomplete,
        ];
        let distinct: BTreeSet<String> = all.iter().map(|f| format!("{f:?}")).collect();
        assert_eq!(distinct.len(), 3, "the variants must stay distinct");

        // `Copy` + `Eq` hold, so the value is plain data with no interior state
        // to carry a computation.
        let failure = PairEffectFailure::Declined;
        let copied = failure;
        assert_eq!(failure, copied);

        // Every variant carries a distinct, non-empty message, so a caller has
        // somewhere to put meaning without a payload channel.
        for failure in all {
            assert!(
                !failure.to_string().is_empty(),
                "{failure:?} has no message"
            );
        }
    }

    /// The pair fence authorizes; it never mutates. A refusal must leave the
    /// durable record byte-identical and must not publish a projection.
    #[test]
    fn the_pair_fence_never_mutates_the_durable_record() {
        let (fx, auth) = pair_ready(None);
        let before = fx.bytes();
        let projection = auth.durable_projection();

        // Success path.
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap();
        assert_eq!(fx.bytes(), before, "a successful consume must not write");
        assert_eq!(
            auth.durable_projection(),
            projection,
            "a successful consume must not move the projection"
        );

        // Refusal paths.
        let stranger = *P256Keypair::generate().public().as_bytes();
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        assert!(consume_pair_probe(&auth, sealed, &stranger, &fx.b_peer(), NOW).is_err());
        assert_eq!(fx.bytes(), before);

        assert!(
            auth.seal_pair(
                &fx.a_cert.d_id,
                &fx.a_peer(),
                &fx.a_cert.d_id,
                &fx.a_peer(),
                NOW
            )
            .is_err()
        );
        assert_eq!(fx.bytes(), before, "a refused seal must not write");
        assert_eq!(auth.durable_projection(), projection);
    }

    /// R0a §10.10 for a pair: a revoke of *either* side cannot interleave
    /// between the recheck and the decision it authorizes.
    #[test]
    fn a_revoke_of_the_responder_cannot_cross_a_pair_consume_decision() {
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let (fx, auth) = pair_ready(None);
        let auth = Arc::new(auth);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();

        // Pre-mint the revoke inputs so the revoker thread moves plain data.
        let nonce = [43u8; 32];
        let challenge = owner_revoke_challenge(&fx.hh_id(), &fx.b_cert.d_id, &nonce).unwrap();
        let revoke_pop = fx.person_b.sign(&challenge).unwrap();
        let owner_b = fx.owner_b.clone();
        let target = fx.b_cert.d_id.clone();

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let state_dir = fx.state_dir.clone();
        let a_key = fx.a_cert.d_id.0.clone();
        let b_key = fx.b_cert.d_id.0.clone();
        let peers = (fx.a_peer(), fx.b_peer());
        let consumer_auth = Arc::clone(&auth);
        let consumer = std::thread::spawn(move || {
            consumer_auth.consume_pair_with_effect(
                sealed,
                &peers.0,
                &peers.1,
                NOW,
                move |consumed| {
                    entered_tx.send(consumed.generation()).unwrap();
                    release_rx.recv().unwrap();
                    // Read the durable record directly: a revoke that crossed
                    // the decision would already be visible here.
                    let on_disk =
                        decode_record(&fs::read(record_path(&state_dir)).unwrap()).unwrap();
                    assert_eq!(on_disk.generation, 3, "generation moved under the decision");
                    for key in [&a_key, &b_key] {
                        assert_eq!(
                            on_disk.devices.get(key).unwrap().status,
                            DeviceStatus::Active,
                            "a revoke crossed the pair decision"
                        );
                    }
                    Ok(())
                },
            )
        });

        // The generation the effect observed arrives over the channel, not as a
        // return value: the effect's success type is `()` so that nothing
        // lazily-evaluated can cross the fence.
        assert_eq!(entered_rx.recv().unwrap(), 3);

        let revoker_auth = Arc::clone(&auth);
        let revoker = std::thread::spawn(move || {
            revoker_auth.revoke_device_as_owner(&owner_b, &target, &revoke_pop, &nonce, NOW)
        });

        // Well inside LOCK_TIMEOUT, and the revoker polls every 10ms, so this is
        // contention rather than a timeout.
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            !revoker.is_finished(),
            "the revoke completed while the pair decision was still open"
        );

        release_tx.send(()).unwrap();
        consumer.join().unwrap().unwrap();

        // ...and the lock really is released: the revoke lands after.
        assert_eq!(
            revoker.join().unwrap().unwrap(),
            MutationOutcome::Applied { generation: 4 }
        );
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&fx.b_cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked
        );
    }

    /// `seal_pair` and `consume_pair_with_effect` really do share one lock: a
    /// seal cannot observe the authority while a pair decision is open.
    #[test]
    fn seal_pair_and_consume_pair_share_one_lock() {
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let (fx, auth) = pair_ready(None);
        let auth = Arc::new(auth);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let peers = (fx.a_peer(), fx.b_peer());
        let consumer_auth = Arc::clone(&auth);
        let consumer = std::thread::spawn(move || {
            consumer_auth.consume_pair_with_effect(
                sealed,
                &peers.0,
                &peers.1,
                NOW,
                move |_consumed| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                },
            )
        });
        entered_rx.recv().unwrap();

        let sealer_auth = Arc::clone(&auth);
        let (a_id, a_peer) = (fx.a_cert.d_id.clone(), fx.a_peer());
        let (b_id, b_peer) = (fx.b_cert.d_id.clone(), fx.b_peer());
        let sealer = std::thread::spawn(move || {
            sealer_auth
                .seal_pair(&a_id, &a_peer, &b_id, &b_peer, NOW)
                .map(|sealed| sealed.generation())
        });

        std::thread::sleep(Duration::from_millis(250));
        assert!(
            !sealer.is_finished(),
            "seal_pair observed the authority while a pair decision held the lock"
        );

        release_tx.send(()).unwrap();
        consumer.join().unwrap().unwrap();
        assert_eq!(sealer.join().unwrap().unwrap(), 3);
    }

    /// The load-bearing reason this slice exists.
    ///
    /// Two singular admissions, each individually correct, compose into a
    /// "pair" in which one side is already revoked — because each singular
    /// consume takes the lock, checks, and *releases* it, so nothing binds the
    /// two decisions to one instant. The atomic fence refuses the same
    /// situation.
    #[test]
    fn composing_two_singular_admissions_authorizes_a_pair_the_atomic_fence_refuses() {
        // ── the composed path: both singular consumes report success ────────
        let (fx, auth) = pair_ready(None);

        let sealed_a = auth.seal(&fx.a_cert.d_id, &fx.a_peer(), NOW).unwrap();
        assert!(
            consume_probe(&auth, sealed_a, &fx.a_peer(), NOW).is_ok(),
            "A is authorized at generation 3"
        );

        // Between the two singular decisions, A is revoked.
        fx.revoke_a(&auth, 21).unwrap();

        let sealed_b = auth.seal(&fx.b_cert.d_id, &fx.b_peer(), NOW).unwrap();
        assert!(
            consume_probe(&auth, sealed_b, &fx.b_peer(), NOW).is_ok(),
            "B is authorized at generation 4"
        );

        // Both singular calls succeeded, so a caller composing them holds
        // "A authorized" and "B authorized" — while A is revoked. There was no
        // instant at which both were true.
        assert_eq!(
            auth.live_snapshot()
                .unwrap()
                .entry(&fx.a_cert.d_id)
                .unwrap()
                .status,
            DeviceStatus::Revoked,
            "the composed path authorized a revoked device as half of a pair"
        );

        // ── the atomic path refuses the same situation ──────────────────────
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        fx.revoke_a(&auth, 22).unwrap();
        assert_eq!(
            consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap_err(),
            DeviceAdmissionError::StaleSeal,
            "a pair sealed before the revoke must not consume after it"
        );
        // ...and a fresh pair seal names the side that is now gone.
        assert_eq!(
            seal_ab(&fx, &auth, NOW).unwrap_err().pair_member(),
            Some((PairRole::Initiator, &DeviceAdmissionError::DeviceRevoked))
        );
    }

    /// The other half of "composition is not an option": nesting the singular
    /// consumes to force simultaneity deadlocks instead.
    ///
    /// `flock(2)` binds to the open file description, and every acquire opens a
    /// fresh descriptor, so the inner acquire cannot see that this thread
    /// already holds the lock. It blocks for the whole `LOCK_TIMEOUT` and then
    /// fails — which is why this test is deliberately slow.
    #[test]
    fn nested_singular_consume_deadlocks_rather_than_composing() {
        use std::sync::Arc;

        let (fx, auth) = pair_ready(None);
        let auth = Arc::new(auth);

        let sealed_a = auth.seal(&fx.a_cert.d_id, &fx.a_peer(), NOW).unwrap();
        let sealed_b = auth.seal(&fx.b_cert.d_id, &fx.b_peer(), NOW).unwrap();

        let inner_auth = Arc::clone(&auth);
        let b_peer = fx.b_peer();
        let started = Instant::now();
        let inner = auth
            .consume_with_effect(sealed_a, &fx.a_peer(), NOW, move |_consumed| {
                // Still inside the first critical section.
                Ok::<_, std::convert::Infallible>(consume_probe(
                    &inner_auth,
                    sealed_b,
                    &b_peer,
                    NOW,
                ))
            })
            .unwrap();
        assert_eq!(
            inner.unwrap_err(),
            DeviceAdmissionError::LockTimeout,
            "nesting the singular consumes to force simultaneity deadlocks"
        );
        assert!(
            started.elapsed() >= LOCK_TIMEOUT,
            "the inner acquire must actually have blocked for the full timeout"
        );

        // The atomic pair surface does the same job without blocking at all.
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        assert!(consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).is_ok());
    }

    /// Single use, as far as a runtime test can show it: the fact is moved into
    /// the consume, so the value is gone afterwards and a second presentation
    /// does not compile.
    ///
    /// The *negative* half — that the pair types gain no `Clone`, `Copy`,
    /// `Default`, `Serialize`, or `Deserialize` — is deliberately NOT asserted
    /// here. A generic `fn assert_not_clone<T>() {}` compiles for every `T`,
    /// including one that derives `Clone`, so calling it would prove nothing
    /// while reading as proof. Rust has no stable negative trait bound, so that
    /// property is pinned at the source level by
    /// `r0a_d2a_sealed_fact_is_opaque_and_move_only`, whose needles are
    /// themselves proven by `r0a_opacity_check_rejects_a_derived_capability`.
    #[test]
    fn a_sealed_pair_is_move_only_and_consumed_once() {
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();
        let probe = consume_pair_probe(&auth, sealed, &fx.a_peer(), &fx.b_peer(), NOW).unwrap();
        // `sealed` has been moved; a second consume cannot compile.
        assert_eq!(probe.consumed_at, NOW);

        // A *fresh* fact for the same pair is a different capability and is
        // accepted — so single use is about the fact, not about the pair.
        let again = seal_ab(&fx, &auth, NOW).unwrap();
        assert!(consume_pair_probe(&auth, again, &fx.a_peer(), &fx.b_peer(), NOW).is_ok());
    }

    #[test]
    fn pair_debug_output_does_not_leak_the_sealed_fact() {
        let (fx, auth) = pair_ready(None);
        let sealed = seal_ab(&fx, &auth, NOW).unwrap();

        let rendered = format!("{sealed:?}");
        assert_eq!(rendered, "SealedDevicePairAdmissionV1(REDACTED)");
        assert!(!rendered.contains(&hex::encode(fx.a_peer())));
        assert!(!rendered.contains(&hex::encode(fx.b_peer())));
        assert_eq!(
            format!("{:?}", sealed.initiator()),
            "PairMemberBindingV1(REDACTED)"
        );

        auth.consume_pair_with_effect(sealed, &fx.a_peer(), &fx.b_peer(), NOW, |consumed| {
            let rendered = format!("{consumed:?}");
            assert_eq!(rendered, "ConsumedDevicePairAdmissionV1(REDACTED)");
            assert!(!rendered.contains(&hex::encode(fx.a_peer())));
            assert_eq!(
                format!("{:?}", consumed.responder()),
                "PairMemberBindingV1(REDACTED)"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn pair_refusals_are_attributed_exactly_once() {
        let (fx, auth) = pair_ready(None);
        let missing = derive_device_id(&P256Keypair::generate().public());
        let error = auth
            .seal_pair(&missing, &fx.a_peer(), &fx.b_cert.d_id, &fx.b_peer(), NOW)
            .unwrap_err();
        let (role, cause) = error.pair_member().expect("a pair refusal is attributed");
        assert_eq!(role, PairRole::Initiator);
        assert_eq!(cause, &DeviceAdmissionError::DeviceNotListed);
        assert!(
            cause.pair_member().is_none(),
            "the attribution must be exactly one level deep"
        );
        // A pair-level fact is not attributed to a side at all.
        assert!(
            DeviceAdmissionError::PairSameDevice.pair_member().is_none(),
            "PairSameDevice is a property of the pair, not of one member"
        );
        assert_eq!(PairRole::Initiator.to_string(), "initiator");
        assert_eq!(PairRole::Responder.to_string(), "responder");
    }
}
