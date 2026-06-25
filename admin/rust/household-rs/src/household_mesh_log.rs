//! Household mesh log — append-only signed event log with deterministic
//! projection and remove-wins semantics.
//!
//! Replaces the current ad-hoc `ClawShareSlotStore` for multi-device
//! owners: any device that holds the log can project the same slot table
//! and guest-credential roster, regardless of the order events arrive.
//!
//! Conflict resolution:
//! - Each event has a `(timestamp, event_id)` ordering key; ties on
//!   timestamp break by `event_id` (BLAKE3 over the canonical entry CBOR).
//! - **Remove-wins**: a `Revoke` for a target always dominates an `Add`
//!   for that target, regardless of which event has the later timestamp.
//!   The mathematical justification: in a CRDT context, remove-wins is
//!   stronger than last-writer-wins for revocation semantics — once an
//!   owner says "this guest is out", a delayed concurrent "this guest is
//!   in" must NOT silently re-add them.
//!
//! Snapshot/compaction:
//! - The log can be compacted by minting a signed `Snapshot` entry that
//!   replaces the prefix of the log with a digest. Receivers verify the
//!   snapshot's signature and replay forward from there.
//! - Slice scope: types + projection only. Snapshot mint/verify lands
//!   in the next slice.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::claw_share::SlotId;
use crate::error::HouseholdError;
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};

// ─── Event types ─────────────────────────────────────────────────────────────

/// The event body — what actually happened. Adding new variants extends
/// the log without breaking older replicas (they ignore unknown variants
/// for projection but still preserve the bytes via the signed envelope).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshEvent {
    /// Owner minted a claw-share slot.
    ClawShareSlotMinted {
        slot_id: SlotId,
        claw_id: String,
        expires_at: u64,
    },
    /// Owner revoked a claw-share slot. **Wins** against any prior or
    /// concurrent `ClawShareSlotMinted` or `ClawShareSlotConsumed` for
    /// the same slot.
    ClawShareSlotRevoked { slot_id: SlotId },
    /// Engine consumed a slot for a specific guest.
    ClawShareSlotConsumed {
        slot_id: SlotId,
        guest_device_pub: P256PublicKey,
        claw_id: String,
        expires_at: u64,
        /// The guest's per-device MESH npub (x-only hex), bound at claim time
        /// from the SIGNED `ClawShareClaim.participant_npub`. This is the
        /// keystone that lets the roster be *share-derived*: a guest is a
        /// member of a claw's FIPS roster iff they hold >=1 active (consumed,
        /// non-revoked, non-expired) share whose `participant_npub` is set.
        /// OPTIONAL and
        /// skipped-when-`None` so the canonical CBOR (and thus the owner
        /// signature over the entry) of a pre-mesh / ferry-only / legacy
        /// consume stays byte-identical to before this field existed — old
        /// logs keep verifying. A consume with `None` here is explicitly
        /// EXCLUDED from the FIPS roster (no mesh identity to route to).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        participant_npub: Option<String>,
    },
    /// Owner revoked a specific guest's access to a specific claw. The
    /// revoke binds to `(guest_device_pub, claw_id)` so a single device
    /// can be revoked from one claw without losing access to others.
    GuestRevoked {
        guest_device_pub: P256PublicKey,
        claw_id: String,
    },
    /// Engine recorded a foreign contact (Alice). Emitted on first
    /// successful claim from a previously-unseen `guest_device_pub`.
    /// The `contact_id` is local to the household; it does not leak to
    /// other households (different `hh_id` projections derive their
    /// own `contact_id`s for the same Alice pubkey).
    ForeignContactRecorded {
        guest_device_pub: P256PublicKey,
        contact_id: String,
        display_name: String,
        /// Slot id of the invite Alice redeemed first. Used as
        /// `trust_origin` so the owner UI can answer "where did this
        /// person come from?".
        trust_origin_slot_id: SlotId,
    },
    /// Owner soft-deleted a foreign contact. The contact's existing
    /// guest credentials are NOT auto-revoked by this event — callers
    /// must emit `GuestRevoked` per `(guest_device_pub, claw_id)` to
    /// actually rescind access. This event is presentation-only.
    ForeignContactRemoved { contact_id: String },
    /// Owner adds an additional device under the same household
    /// `mesh_directory`. Used so Alice can discover Carlos's new
    /// iPhone without a new invite.
    DirectoryDeviceAdded {
        device_pub: P256PublicKey,
        label: String,
    },
    /// Owner removed a device from the household directory. Other
    /// engines stop accepting writes signed by that device.
    DirectoryDeviceRemoved { device_pub: P256PublicKey },
    // ── Fase E1: first-class private-VPN groups + stable member identity ──────
    // All owner-signed; folded with the SAME remove-wins / monotonic discipline
    // as the mesh-participant ops. A group is a NAMED set of members that can be
    // granted access to >=1 claw (many-to-many). Members are stable `member_id`s
    // ([`crate::member_identity`]); each member's devices enroll separately so the
    // routing identity stays the per-device npub, never the member id.
    /// Owner created a named group. First creation for a `group_id` wins.
    GroupCreated { group_id: String, name: String },
    /// Owner renamed a group. Last-writer-wins by `(timestamp, entry_id)`; the
    /// `group_id` never changes, so a rename never affects membership or grants.
    GroupRenamed { group_id: String, name: String },
    /// Owner added a member (stable `member_id`) to a group. Re-adding a
    /// previously-removed member with a strictly-newer timestamp re-activates;
    /// an older add can never resurrect past a newer removal.
    GroupMemberAdded {
        group_id: String,
        member_id: String,
        label: String,
    },
    /// Owner removed a member from a group. Remove-wins on tie.
    GroupMemberRemoved { group_id: String, member_id: String },
    /// Owner granted a group access to a claw. >=1 grant per group; a claw may be
    /// granted by >=1 group (many-to-many).
    GroupClawGranted { group_id: String, claw_id: String },
    /// Owner revoked a group's grant to a claw (whole-group cut for that claw).
    /// Remove-wins on tie.
    GroupClawRevoked { group_id: String, claw_id: String },
    /// A member enrolled a device under its stable id: this `(device_pub,
    /// participant_npub)` belongs to `member_id`. The engine records it only
    /// after verifying the member-signed [`crate::member_identity::MemberDeviceBinding`].
    /// `participant_npub` is the per-device mesh identity the roster routes to;
    /// `member_id` stays engine-internal and never appears in a published roster.
    MeshMemberDeviceEnrolled {
        member_id: String,
        device_pub: P256PublicKey,
        participant_npub: String,
    },
    /// Owner or member retired a device (lost phone / rotation). Keyed by
    /// `device_pub`; remove-wins. Drops the device's npub from every claw the
    /// member's groups grant, on the next projection.
    MeshMemberDeviceRetired {
        member_id: String,
        device_pub: P256PublicKey,
    },
    /// Fase E3: owner published a claw's `ClawSite` as PUBLIC — anyone may dial it
    /// (no per-guest slot/group). Gated ONLY by this explicit flag; absence ⇒
    /// private. Re-publishing after an unpublish requires a strictly-newer
    /// timestamp (publish/unpublish use the same remove-wins-on-tie discipline).
    ClawSitePublished { claw_id: String },
    /// Fase E3: owner unpublished a claw — the public kill switch. Wins over a
    /// publish at the same-or-earlier timestamp; the dial gate fails closed for
    /// public offers on the next open.
    ClawSiteUnpublished { claw_id: String },
}

/// Signed log entry — the unit of replication. `entry_id` is BLAKE3 over
/// the canonical CBOR of `(timestamp, issuer_pub, event)`; recipients
/// verify the signature against that tuple, not against an arbitrary
/// caller-supplied id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Schema version.
    pub v: u8,
    /// Domain separator (`"household-mesh-log/v1"`).
    pub kind: String,
    /// 32-byte BLAKE3 digest of canonical CBOR over the signed fields.
    /// Computed by the issuer, re-derived by verifiers, used as the
    /// stable identifier for dedup + tie-breaking.
    pub entry_id: [u8; 32],
    /// Unix seconds at issue time.
    pub timestamp: u64,
    /// Public key of the device that issued the entry (one of the
    /// owner's machines).
    pub issuer_pub: P256PublicKey,
    pub event: MeshEvent,
    /// P-256 ECDSA over the canonical CBOR of
    /// (v, kind, `entry_id`, timestamp, `issuer_pub`, event).
    pub signature: P256Signature,
}

const LOG_KIND: &str = "household-mesh-log/v1";
const LOG_VERSION: u8 = 1;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LogEntryUnsigned<'a> {
    v: u8,
    kind: &'a str,
    entry_id: &'a serde_bytes::Bytes,
    timestamp: u64,
    issuer_pub: &'a P256PublicKey,
    event: &'a MeshEvent,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EntryIdInput<'a> {
    kind: &'a str,
    timestamp: u64,
    issuer_pub: &'a P256PublicKey,
    event: &'a MeshEvent,
    v: u8,
}

impl LogEntry {
    /// Mint a fresh signed entry. The id is derived from the canonical
    /// CBOR of the signed body; signing is over the same id-included
    /// bytes so any tamper invalidates the signature.
    pub fn sign(
        timestamp: u64,
        issuer_pub: P256PublicKey,
        event: MeshEvent,
        issuer_key: &dyn IdentityKey,
    ) -> Result<Self, MeshLogError> {
        if issuer_key.public() != issuer_pub {
            return Err(MeshLogError::IssuerKeyMismatch);
        }
        let id_input = EntryIdInput {
            kind: LOG_KIND,
            timestamp,
            issuer_pub: &issuer_pub,
            event: &event,
            v: LOG_VERSION,
        };
        let id_bytes = cbor::to_canonical_vec(&id_input).map_err(MeshLogError::Cbor)?;
        let entry_id: [u8; 32] = blake3::hash(&id_bytes).into();

        let unsigned = LogEntryUnsigned {
            v: LOG_VERSION,
            kind: LOG_KIND,
            entry_id: serde_bytes::Bytes::new(&entry_id),
            timestamp,
            issuer_pub: &issuer_pub,
            event: &event,
        };
        let sign_bytes = cbor::to_canonical_vec(&unsigned).map_err(MeshLogError::Cbor)?;
        let signature = issuer_key.sign(&sign_bytes).map_err(MeshLogError::Sign)?;

        Ok(Self {
            v: LOG_VERSION,
            kind: LOG_KIND.to_string(),
            entry_id,
            timestamp,
            issuer_pub,
            event,
            signature,
        })
    }

    /// Verify schema, derived id, and signature. Membership / authority
    /// is the caller's concern (they decide which `issuer_pub`s are
    /// allowed to write to a given household's log).
    pub fn verify(&self) -> Result<(), MeshLogError> {
        if self.v != LOG_VERSION {
            return Err(MeshLogError::VersionUnsupported(self.v));
        }
        if self.kind != LOG_KIND {
            return Err(MeshLogError::KindMismatch(self.kind.clone()));
        }

        // Re-derive id from the signed body fields and compare.
        let id_input = EntryIdInput {
            kind: &self.kind,
            timestamp: self.timestamp,
            issuer_pub: &self.issuer_pub,
            event: &self.event,
            v: self.v,
        };
        let id_bytes = cbor::to_canonical_vec(&id_input).map_err(MeshLogError::Cbor)?;
        let derived: [u8; 32] = blake3::hash(&id_bytes).into();
        if derived != self.entry_id {
            return Err(MeshLogError::EntryIdMismatch);
        }

        let unsigned = LogEntryUnsigned {
            v: self.v,
            kind: &self.kind,
            entry_id: serde_bytes::Bytes::new(&self.entry_id),
            timestamp: self.timestamp,
            issuer_pub: &self.issuer_pub,
            event: &self.event,
        };
        let sign_bytes = cbor::to_canonical_vec(&unsigned).map_err(MeshLogError::Cbor)?;
        verify_signature(&self.issuer_pub, &sign_bytes, &self.signature)
            .map_err(|_| MeshLogError::SignatureRejected)
    }
}

/// Emit a `DirectoryDeviceRemoved` revocation into the mesh log, signed by the
/// local machine key, and append it.
///
/// This arms the issuer kill switch that
/// [`crate::issuer_trust::is_machine_issuer_active`] reads via
/// [`ProjectedState::directory_devices`]: once the entry projects, an offer
/// signed by `device_pub` fails closed with `DeviceRemoved`.
///
/// Scope: this only mints and appends a self-consistent, signed entry. It does
/// NOT decide owner/admin authorization (a future live cut owns the owner
/// action and its auth), it does not touch `issuer_trust`, and it builds no
/// separate CRL store or gossip. The signer is the LOCAL machine key, so
/// `issuer_pub` must equal `issuer_key.public()` (enforced by `LogEntry::sign`,
/// else `IssuerKeyMismatch`). `append` verifies the entry before recording it.
///
/// Idempotent / remove-wins: re-emitting for the same device leaves the
/// projection `Removed` (a byte-identical re-emit dedups on `entry_id`; any
/// later removal still folds to `Removed`).
///
/// CARRY (multi-device replication, out of scope here): `ProjectedState::project`
/// folds a `DirectoryDeviceRemoved` regardless of who signed it - `LogEntry::verify`
/// proves only self-consistency, not issuer authority. A replicated consumer
/// must authorize each entry's `issuer_pub` (machine cert + membership) before
/// folding, else a forged removal could revoke a legitimate machine. Single
/// engine-local emit (this function) is unaffected.
pub fn emit_directory_device_removed(
    mesh_log: &MeshLogStore,
    issuer_key: &dyn IdentityKey,
    issuer_pub: &P256PublicKey,
    device_pub: &P256PublicKey,
    now: u64,
) -> Result<LogEntry, MeshLogError> {
    let entry = LogEntry::sign(
        now,
        issuer_pub.clone(),
        MeshEvent::DirectoryDeviceRemoved {
            device_pub: device_pub.clone(),
        },
        issuer_key,
    )?;
    mesh_log.append(entry.clone())?;
    Ok(entry)
}

// ─── Projected state ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedSlot {
    pub slot_id: SlotId,
    pub claw_id: String,
    pub expires_at: u64,
    pub status: SlotProjectedStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotProjectedStatus {
    Open,
    Consumed {
        guest_device_pub: P256PublicKey,
        consumed_at: u64,
        /// Bound guest mesh npub (hex) carried by the consume event. `None`
        /// for legacy / ferry-only consumes that bound no mesh identity —
        /// those are excluded from the share-derived FIPS roster.
        participant_npub: Option<String>,
    },
    Revoked {
        revoked_at: u64,
        /// R81-1: the bound guest mesh npub carried by the consume that this
        /// revoke superseded, preserved so the deny-list (routing hygiene) can
        /// name the npub to drop. `None` when the slot was revoked while still
        /// open (no consume), or when the consume bound no mesh identity.
        participant_npub: Option<String>,
    },
}

/// Deterministic projection of the log. Independent replicas projecting
/// the same set of entries (in any order) MUST produce equal states.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProjectedState {
    pub slots: BTreeMap<SlotId, ProjectedSlot>,
    /// `(guest_device_pub_bytes, claw_id)` pairs explicitly revoked.
    pub revoked_guests: BTreeSet<(Vec<u8>, String)>,
    /// Foreign contacts (Alices) keyed by their device pubkey bytes.
    pub foreign_contacts: BTreeMap<Vec<u8>, ProjectedForeignContact>,
    /// Household devices (Carlos's iPhones / Macs) that share the
    /// mesh directory. Keyed by device pubkey bytes.
    pub directory_devices: BTreeMap<Vec<u8>, ProjectedDirectoryDevice>,
    /// Fase E1: first-class groups keyed by `group_id`.
    pub groups: BTreeMap<String, ProjectedGroup>,
    /// Fase E1: stable members' enrolled devices: `member_id` → (device pubkey
    /// bytes → device). The roster join resolves group members to their active
    /// device npubs through this map.
    pub member_devices: BTreeMap<String, BTreeMap<Vec<u8>, ProjectedMemberDevice>>,
    /// Fase E3: per-claw public-site flag (`claw_id` → Active = published). Absent
    /// ⇒ private. The Public `relay_stream` dial gate requires Active here.
    pub published_claws: BTreeMap<String, MeshMembership>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedForeignContact {
    pub contact_id: String,
    pub display_name: String,
    pub trust_origin_slot_id: SlotId,
    pub status: ForeignContactStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignContactStatus {
    Active,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedDirectoryDevice {
    pub label: String,
    pub status: DirectoryDeviceStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryDeviceStatus {
    Active,
    Removed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshMembership {
    Active,
    Removed,
}

/// Fase E1: a projected first-class group — a named set of members granted
/// access to >=1 claw. Members and grants are tombstoned (remove-wins) so a
/// late, older add can't resurrect them. `revision` is the max op timestamp on
/// the group (monotonic with time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedGroup {
    pub group_id: String,
    pub name: String,
    /// `member_id` → membership status (reuses [`MeshMembership`]).
    pub members: BTreeMap<String, MeshMembership>,
    /// `claw_id` → grant status (reuses [`MeshMembership`]).
    pub granted_claws: BTreeMap<String, MeshMembership>,
    pub revision: u64,
}

/// Fase E1: a member's enrolled device. Keyed (in [`ProjectedState::member_devices`])
/// by the device pubkey bytes — the stable per-device key the enroll/retire ops
/// name. `participant_npub` is the routing identity folded into rosters; the
/// `member_id` it lives under stays engine-internal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedMemberDevice {
    pub participant_npub: String,
    pub status: MeshMembership,
}

impl ProjectedState {
    #[must_use]
    pub fn project(entries: &[LogEntry]) -> Self {
        // Local accumulators for the Fase E1 first-class groups + member-device
        // enrollment pass below. Defined here (before the first statement) so
        // they exist from the start of the function scope.
        struct AddRemAcc {
            // (timestamp, payload) of the latest add — payload is the member
            // label or the device npub, carried through to the resolved value.
            latest_add: Option<(u64, String)>,
            latest_remove_ts: Option<u64>,
            max_ts: u64,
        }
        impl AddRemAcc {
            fn new() -> Self {
                Self {
                    latest_add: None,
                    latest_remove_ts: None,
                    max_ts: 0,
                }
            }
            fn add(&mut self, ts: u64, payload: &str) {
                if self.latest_add.as_ref().is_none_or(|(t, _)| ts >= *t) {
                    self.latest_add = Some((ts, payload.to_string()));
                }
                self.max_ts = self.max_ts.max(ts);
            }
            fn remove(&mut self, ts: u64) {
                self.latest_remove_ts = Some(self.latest_remove_ts.map_or(ts, |t| t.max(ts)));
                self.max_ts = self.max_ts.max(ts);
            }
            // (status, payload-of-latest-add) — remove-wins on tie.
            fn resolve(&self) -> (MeshMembership, String) {
                let add_ts = self.latest_add.as_ref().map(|(t, _)| *t);
                let removed = match (self.latest_remove_ts, add_ts) {
                    (Some(r), Some(a)) => r >= a,
                    // (None, None) is defensive; an acc always has >=1 op.
                    (Some(_) | None, None) => true,
                    (None, Some(_)) => false,
                };
                let payload = self
                    .latest_add
                    .as_ref()
                    .map(|(_, p)| p.clone())
                    .unwrap_or_default();
                (
                    if removed {
                        MeshMembership::Removed
                    } else {
                        MeshMembership::Active
                    },
                    payload,
                )
            }
        }
        struct GroupAcc {
            name_lww: Option<(u64, String)>,
            members: BTreeMap<String, AddRemAcc>,
            grants: BTreeMap<String, AddRemAcc>,
            max_ts: u64,
        }
        impl GroupAcc {
            fn new() -> Self {
                Self {
                    name_lww: None,
                    members: BTreeMap::new(),
                    grants: BTreeMap::new(),
                    max_ts: 0,
                }
            }
            fn bump_name(&mut self, ts: u64, name: &str) {
                if self.name_lww.as_ref().is_none_or(|(t, _)| ts >= *t) {
                    self.name_lww = Some((ts, name.to_string()));
                }
                self.max_ts = self.max_ts.max(ts);
            }
        }

        // Stable canonical ordering: (timestamp, entry_id). Cloning ids
        // into a Vec of (key, &entry) keeps comparison cheap.
        let mut order: Vec<(u64, [u8; 32], &LogEntry)> = entries
            .iter()
            .map(|e| (e.timestamp, e.entry_id, e))
            .collect();
        order.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let mut state = ProjectedState::default();

        // First pass: apply Add events (mint, consume).
        // Second pass: apply Remove events (revoke). Remove-wins guarantee:
        // any revoke seen in the log wipes the matching add at projection
        // time, even if the revoke was earlier in real time.
        for (_, _, entry) in &order {
            match &entry.event {
                MeshEvent::ClawShareSlotMinted {
                    slot_id,
                    claw_id,
                    expires_at,
                } => {
                    state.slots.entry(slot_id.clone()).or_insert(ProjectedSlot {
                        slot_id: slot_id.clone(),
                        claw_id: claw_id.clone(),
                        expires_at: *expires_at,
                        status: SlotProjectedStatus::Open,
                    });
                }
                MeshEvent::ClawShareSlotConsumed {
                    slot_id,
                    guest_device_pub,
                    claw_id,
                    expires_at,
                    participant_npub,
                } => {
                    // Two-CAS races where two devices both report a
                    // Consume win the EARLIEST one by (timestamp, id) —
                    // they ARE sorted, so the first one to appear here
                    // sticks; subsequent ones see status != Open and
                    // skip.
                    let slot = state.slots.entry(slot_id.clone()).or_insert(ProjectedSlot {
                        slot_id: slot_id.clone(),
                        claw_id: claw_id.clone(),
                        expires_at: *expires_at,
                        status: SlotProjectedStatus::Open,
                    });
                    if matches!(slot.status, SlotProjectedStatus::Open) {
                        slot.status = SlotProjectedStatus::Consumed {
                            guest_device_pub: guest_device_pub.clone(),
                            consumed_at: entry.timestamp,
                            participant_npub: participant_npub.clone(),
                        };
                    }
                }
                MeshEvent::ForeignContactRecorded {
                    guest_device_pub,
                    contact_id,
                    display_name,
                    trust_origin_slot_id,
                } => {
                    state
                        .foreign_contacts
                        .entry(guest_device_pub.as_bytes().to_vec())
                        .or_insert(ProjectedForeignContact {
                            contact_id: contact_id.clone(),
                            display_name: display_name.clone(),
                            trust_origin_slot_id: trust_origin_slot_id.clone(),
                            status: ForeignContactStatus::Active,
                        });
                }
                MeshEvent::DirectoryDeviceAdded { device_pub, label } => {
                    state
                        .directory_devices
                        .entry(device_pub.as_bytes().to_vec())
                        .or_insert(ProjectedDirectoryDevice {
                            label: label.clone(),
                            status: DirectoryDeviceStatus::Active,
                        });
                }
                MeshEvent::ClawShareSlotRevoked { .. }
                | MeshEvent::GuestRevoked { .. }
                | MeshEvent::ForeignContactRemoved { .. }
                | MeshEvent::DirectoryDeviceRemoved { .. }
                // Fase E1 group + member-device ops are folded in the fourth pass.
                | MeshEvent::GroupCreated { .. }
                | MeshEvent::GroupRenamed { .. }
                | MeshEvent::GroupMemberAdded { .. }
                | MeshEvent::GroupMemberRemoved { .. }
                | MeshEvent::GroupClawGranted { .. }
                | MeshEvent::GroupClawRevoked { .. }
                | MeshEvent::MeshMemberDeviceEnrolled { .. }
                | MeshEvent::MeshMemberDeviceRetired { .. }
                | MeshEvent::ClawSitePublished { .. }
                | MeshEvent::ClawSiteUnpublished { .. } => {
                    // Remove events (and group / publish ops) processed below.
                }
            }
        }

        for (_, _, entry) in &order {
            match &entry.event {
                MeshEvent::ClawShareSlotRevoked { slot_id } => {
                    if let Some(slot) = state.slots.get_mut(slot_id) {
                        // Preserve the bound consume npub (if any) on the Revoked
                        // status so the deny-list (routing hygiene) can name the
                        // npub to drop — the projection otherwise loses it.
                        let participant_npub = match &slot.status {
                            SlotProjectedStatus::Consumed {
                                participant_npub, ..
                            } => participant_npub.clone(),
                            _ => None,
                        };
                        slot.status = SlotProjectedStatus::Revoked {
                            revoked_at: entry.timestamp,
                            participant_npub,
                        };
                    } else {
                        // A revoke arrived before the mint event in the
                        // local view. Record a tombstone so a later
                        // mint won't sneak in. Slice scope: synthesize
                        // a Revoked slot with placeholder fields so the
                        // projection stays deterministic.
                        state.slots.insert(
                            slot_id.clone(),
                            ProjectedSlot {
                                slot_id: slot_id.clone(),
                                claw_id: String::new(),
                                expires_at: 0,
                                status: SlotProjectedStatus::Revoked {
                                    revoked_at: entry.timestamp,
                                    participant_npub: None,
                                },
                            },
                        );
                    }
                }
                MeshEvent::GuestRevoked {
                    guest_device_pub,
                    claw_id,
                } => {
                    state
                        .revoked_guests
                        .insert((guest_device_pub.as_bytes().to_vec(), claw_id.clone()));
                }
                MeshEvent::ForeignContactRemoved { contact_id } => {
                    // Mark every matching contact as Removed. Multiple
                    // pubkeys can in theory share a contact_id under
                    // future linkage; today they don't.
                    for c in state.foreign_contacts.values_mut() {
                        if c.contact_id == *contact_id {
                            c.status = ForeignContactStatus::Removed;
                        }
                    }
                }
                MeshEvent::DirectoryDeviceRemoved { device_pub } => {
                    let key = device_pub.as_bytes().to_vec();
                    if let Some(d) = state.directory_devices.get_mut(&key) {
                        d.status = DirectoryDeviceStatus::Removed;
                    } else {
                        // Tombstone for out-of-order arrival.
                        state.directory_devices.insert(
                            key,
                            ProjectedDirectoryDevice {
                                label: String::new(),
                                status: DirectoryDeviceStatus::Removed,
                            },
                        );
                    }
                }
                _ => {}
            }
        }

        // Third pass: Fase E1 first-class groups + member-device enrollments.
        // Ordered remove-wins-on-tie discipline: an add re-activates only with a
        // strictly-newer timestamp than the last removal; a same-or-older add
        // can never resurrect past a removal.
        // (Helper accumulators `AddRemAcc`/`GroupAcc` are defined at the top of
        // this function.)
        let mut groups: BTreeMap<String, GroupAcc> = BTreeMap::new();
        // member_id -> (device pubkey bytes -> add/remove acc carrying the npub).
        let mut member_devs: BTreeMap<String, BTreeMap<Vec<u8>, AddRemAcc>> = BTreeMap::new();
        // Fase E3: claw_id -> publish/unpublish acc (publish=add, unpublish=remove).
        let mut published: BTreeMap<String, AddRemAcc> = BTreeMap::new();
        for (_, _, entry) in &order {
            match &entry.event {
                MeshEvent::GroupCreated { group_id, name }
                | MeshEvent::GroupRenamed { group_id, name } => {
                    groups
                        .entry(group_id.clone())
                        .or_insert_with(GroupAcc::new)
                        .bump_name(entry.timestamp, name);
                }
                MeshEvent::GroupMemberAdded {
                    group_id,
                    member_id,
                    label,
                } => {
                    let g = groups.entry(group_id.clone()).or_insert_with(GroupAcc::new);
                    g.members
                        .entry(member_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .add(entry.timestamp, label);
                    g.max_ts = g.max_ts.max(entry.timestamp);
                }
                MeshEvent::GroupMemberRemoved {
                    group_id,
                    member_id,
                } => {
                    let g = groups.entry(group_id.clone()).or_insert_with(GroupAcc::new);
                    g.members
                        .entry(member_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .remove(entry.timestamp);
                    g.max_ts = g.max_ts.max(entry.timestamp);
                }
                MeshEvent::GroupClawGranted { group_id, claw_id } => {
                    let g = groups.entry(group_id.clone()).or_insert_with(GroupAcc::new);
                    g.grants
                        .entry(claw_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .add(entry.timestamp, "");
                    g.max_ts = g.max_ts.max(entry.timestamp);
                }
                MeshEvent::GroupClawRevoked { group_id, claw_id } => {
                    let g = groups.entry(group_id.clone()).or_insert_with(GroupAcc::new);
                    g.grants
                        .entry(claw_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .remove(entry.timestamp);
                    g.max_ts = g.max_ts.max(entry.timestamp);
                }
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id,
                    device_pub,
                    participant_npub,
                } => {
                    member_devs
                        .entry(member_id.clone())
                        .or_default()
                        .entry(device_pub.as_bytes().to_vec())
                        .or_insert_with(AddRemAcc::new)
                        .add(entry.timestamp, participant_npub);
                }
                MeshEvent::MeshMemberDeviceRetired {
                    member_id,
                    device_pub,
                } => {
                    member_devs
                        .entry(member_id.clone())
                        .or_default()
                        .entry(device_pub.as_bytes().to_vec())
                        .or_insert_with(AddRemAcc::new)
                        .remove(entry.timestamp);
                }
                MeshEvent::ClawSitePublished { claw_id } => {
                    published
                        .entry(claw_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .add(entry.timestamp, "");
                }
                MeshEvent::ClawSiteUnpublished { claw_id } => {
                    published
                        .entry(claw_id.clone())
                        .or_insert_with(AddRemAcc::new)
                        .remove(entry.timestamp);
                }
                _ => {}
            }
        }
        for (group_id, acc) in groups {
            let name = acc.name_lww.map(|(_, n)| n).unwrap_or_default();
            let members = acc
                .members
                .into_iter()
                .map(|(mid, m)| (mid, m.resolve().0))
                .collect();
            let granted_claws = acc
                .grants
                .into_iter()
                .map(|(cid, gr)| (cid, gr.resolve().0))
                .collect();
            state.groups.insert(
                group_id.clone(),
                ProjectedGroup {
                    group_id,
                    name,
                    members,
                    granted_claws,
                    revision: acc.max_ts,
                },
            );
        }
        for (member_id, devs) in member_devs {
            let resolved = devs
                .into_iter()
                .map(|(dpub, acc)| {
                    let (status, participant_npub) = acc.resolve();
                    (
                        dpub,
                        ProjectedMemberDevice {
                            participant_npub,
                            status,
                        },
                    )
                })
                .collect();
            state.member_devices.insert(member_id, resolved);
        }
        for (claw_id, acc) in published {
            state.published_claws.insert(claw_id, acc.resolve().0);
        }

        state
    }

    /// R81-1: list `guest_device_pub`'s ACTIVE shares for any claw — consumed,
    /// non-revoked, non-expired (`expires_at > now`) slots redeemed by this guest
    /// device. Pure + order-independent (`slots` is a `BTreeMap`). Used to answer
    /// "which claws does this device still hold a live share for?" without
    /// trusting any mutable session state.
    #[must_use]
    pub fn shares_for_guest(&self, guest_device_pub: &[u8], now: u64) -> Vec<ProjectedSlot> {
        self.slots
            .values()
            .filter(|s| s.expires_at > now)
            .filter(|s| match &s.status {
                SlotProjectedStatus::Consumed {
                    guest_device_pub: gp,
                    ..
                } => gp.as_bytes() == guest_device_pub,
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// Fase E1: the set of `member_id`s that are Active in at least one group
    /// with an Active grant to `claw_id`. Pure + order-independent (`BTreeMaps`).
    /// Resolves to MEMBER ids (engine-internal); use
    /// [`group_member_npubs_for_claw`] for the routable device npubs.
    ///
    /// [`group_member_npubs_for_claw`]: ProjectedState::group_member_npubs_for_claw
    #[must_use]
    pub fn members_authorized_for_claw(&self, claw_id: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for group in self.groups.values() {
            if matches!(
                group.granted_claws.get(claw_id),
                Some(MeshMembership::Active)
            ) {
                for (member_id, status) in &group.members {
                    if *status == MeshMembership::Active {
                        out.insert(member_id.clone());
                    }
                }
            }
        }
        out
    }

    /// Fase E1: the Active device npubs (hex) of every member authorized for
    /// `claw_id` via the group path. This is what folds into the published
    /// roster. `member_id` never appears — only per-device npubs route.
    #[must_use]
    pub fn group_member_npubs_for_claw(&self, claw_id: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for member_id in self.members_authorized_for_claw(claw_id) {
            if let Some(devices) = self.member_devices.get(&member_id) {
                for device in devices.values() {
                    if device.status == MeshMembership::Active {
                        out.insert(device.participant_npub.clone());
                    }
                }
            }
        }
        out
    }

    /// Fase E3: whether `claw_id`'s `ClawSite` is currently published as PUBLIC.
    /// The Public `relay_stream` dial gate requires this to be true.
    #[must_use]
    pub fn is_claw_published(&self, claw_id: &str) -> bool {
        matches!(
            self.published_claws.get(claw_id),
            Some(MeshMembership::Active)
        )
    }
}

// ─── In-memory store + gossip helpers ────────────────────────────────────────

/// Per-device mesh log store. Holds the local copy of the signed log
/// with an optional append-only file backing so engine restarts don't
/// reopen consumed or revoked invites.
///
/// On disk format: NDJSON, one entry per line, each line is the
/// base64-no-pad-URL-safe encoding of the canonical CBOR of one
/// `LogEntry`. Append-only with `fsync` per write so a power loss
/// caps the loss at the most recent partial write (which fails
/// signature re-verify on reload and is dropped).
pub struct MeshLogStore {
    inner: std::sync::Mutex<MeshLogStoreInner>,
}

impl Default for MeshLogStore {
    fn default() -> Self {
        Self::new()
    }
}

struct MeshLogStoreInner {
    entries: Vec<LogEntry>,
    seen: std::collections::HashSet<[u8; 32]>,
    /// When present, every successful `append` is also written to this
    /// file before returning. `None` means in-memory only (tests).
    backing: Option<std::path::PathBuf>,
}

impl MeshLogStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MeshLogStoreInner {
                entries: Vec::new(),
                seen: std::collections::HashSet::new(),
                backing: None,
            }),
        }
    }

    /// Open (or create) a persistent log at `path`. On open, every
    /// existing entry in the file is re-verified before being
    /// re-applied; lines that fail to parse, decode, or verify are
    /// dropped silently (the next caller's `append` writes past them).
    ///
    /// # Errors
    ///
    /// Returns `MeshLogError::Io` if the file can't be opened or
    /// read.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned during construction
    /// (cannot happen — fresh mutex).
    pub fn open(path: &std::path::Path) -> Result<Self, MeshLogError> {
        use std::io::Read;
        let store = Self::new();
        let mut guard = store.inner.lock().expect("mesh log mutex");
        guard.backing = Some(path.to_path_buf());

        // Read existing file if present.
        match std::fs::File::open(path) {
            Ok(mut f) => {
                let mut text = String::new();
                f.read_to_string(&mut text).map_err(MeshLogError::Io)?;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let Ok(bytes) = base64_url_no_pad_decode(trimmed) else {
                        // Last-line corruption tolerated.
                        continue;
                    };
                    let Ok(entry) = cbor::from_canonical_slice::<LogEntry>(&bytes) else {
                        continue;
                    };
                    if entry.verify().is_err() {
                        continue;
                    }
                    if guard.seen.contains(&entry.entry_id) {
                        continue;
                    }
                    guard.seen.insert(entry.entry_id);
                    guard.entries.push(entry);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fresh log; ensure the parent directory exists so the
                // first `append` can create the file.
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(MeshLogError::Io)?;
                    }
                }
            }
            Err(e) => return Err(MeshLogError::Io(e)),
        }
        drop(guard);
        Ok(store)
    }

    /// Append a locally-issued entry. Re-applying the same entry twice
    /// (by `entry_id`) is a no-op.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn append(&self, entry: LogEntry) -> Result<bool, MeshLogError> {
        entry.verify()?;
        let mut guard = self.inner.lock().expect("mesh log mutex");
        if guard.seen.contains(&entry.entry_id) {
            return Ok(false);
        }
        if let Some(path) = guard.backing.clone() {
            let bytes = cbor::to_canonical_vec(&entry).map_err(MeshLogError::Cbor)?;
            let line = base64_url_no_pad(&bytes);
            append_line_durable(&path, &line).map_err(MeshLogError::Io)?;
        }
        guard.seen.insert(entry.entry_id);
        guard.entries.push(entry);
        Ok(true)
    }

    /// Ingest a batch of remote entries (gossip in). Each is verified
    /// before being recorded; tampered or unsigned entries are
    /// rejected. Duplicates are silently skipped. Returns the count of
    /// new entries actually persisted.
    pub fn ingest_remote(&self, entries: &[LogEntry]) -> Result<usize, MeshLogError> {
        let mut added = 0usize;
        for entry in entries {
            if self.append(entry.clone())? {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Snapshot the current entries (clone). Used to gossip out.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.inner.lock().expect("mesh log mutex").entries.clone()
    }

    /// Deterministic projection of the current log.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn project(&self) -> ProjectedState {
        let guard = self.inner.lock().expect("mesh log mutex");
        ProjectedState::project(&guard.entries)
    }

    /// BLAKE3 digest over the lex-sorted set of `entry_id`s currently in
    /// the store. Two engines that have ingested the same set of
    /// entries (regardless of arrival order) produce identical
    /// digests; multi-engine sync layers compare digests cheaply
    /// before exchanging full snapshots.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn state_digest(&self) -> [u8; 32] {
        let guard = self.inner.lock().expect("mesh log mutex");
        let mut ids: Vec<[u8; 32]> = guard.entries.iter().map(|e| e.entry_id).collect();
        ids.sort_unstable();
        let mut hasher = blake3::Hasher::new();
        for id in &ids {
            hasher.update(id);
        }
        hasher.finalize().into()
    }

    /// Number of entries held locally.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("mesh log mutex").entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Helper: mint a signed `ClawShareSlotRevoked` event ready to append.
pub fn build_slot_revoke_event(
    slot_id: SlotId,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::ClawShareSlotRevoked { slot_id },
        issuer_key,
    )
}

/// Helper: mint a signed `ClawShareSlotMinted` event ready to append.
pub fn build_slot_mint_event(
    slot_id: SlotId,
    claw_id: String,
    expires_at: u64,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::ClawShareSlotMinted {
            slot_id,
            claw_id,
            expires_at,
        },
        issuer_key,
    )
}

/// Helper: mint a signed `ClawShareSlotConsumed` event ready to append. Pass
/// the guest's bound mesh npub as `participant_npub` (or `None` for a
/// ferry-only / legacy consume that never enters the FIPS roster).
#[allow(clippy::too_many_arguments)]
pub fn build_slot_consume_event(
    slot_id: SlotId,
    guest_device_pub: P256PublicKey,
    claw_id: String,
    expires_at: u64,
    participant_npub: Option<String>,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::ClawShareSlotConsumed {
            slot_id,
            guest_device_pub,
            claw_id,
            expires_at,
            participant_npub,
        },
        issuer_key,
    )
}

/// Helper: mint a signed `GuestRevoked` event ready to append.
pub fn build_guest_revoke_event(
    guest_device_pub: P256PublicKey,
    claw_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GuestRevoked {
            guest_device_pub,
            claw_id,
        },
        issuer_key,
    )
}

// ── Fase E1: signed group + member-device event minters (owner-only at the
//    HTTP/control trigger). ──────────────────────────────────────────────────

/// Mint a signed `GroupCreated` event ready to append.
pub fn build_group_created_event(
    group_id: String,
    name: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupCreated { group_id, name },
        issuer_key,
    )
}

/// Mint a signed `GroupRenamed` event ready to append.
pub fn build_group_renamed_event(
    group_id: String,
    name: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupRenamed { group_id, name },
        issuer_key,
    )
}

/// Mint a signed `GroupMemberAdded` event ready to append.
pub fn build_group_member_add_event(
    group_id: String,
    member_id: String,
    label: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupMemberAdded {
            group_id,
            member_id,
            label,
        },
        issuer_key,
    )
}

/// Mint a signed `GroupMemberRemoved` event ready to append.
pub fn build_group_member_remove_event(
    group_id: String,
    member_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupMemberRemoved {
            group_id,
            member_id,
        },
        issuer_key,
    )
}

/// Mint a signed `GroupClawGranted` event ready to append.
pub fn build_group_claw_grant_event(
    group_id: String,
    claw_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupClawGranted { group_id, claw_id },
        issuer_key,
    )
}

/// Mint a signed `GroupClawRevoked` event ready to append.
pub fn build_group_claw_revoke_event(
    group_id: String,
    claw_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::GroupClawRevoked { group_id, claw_id },
        issuer_key,
    )
}

/// Mint a signed `MeshMemberDeviceEnrolled` event ready to append. The caller
/// MUST first verify the member-signed `MemberDeviceBinding` that vouches for
/// `(device_pub, participant_npub)` under `member_id`.
pub fn build_member_device_enroll_event(
    member_id: String,
    device_pub: P256PublicKey,
    participant_npub: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::MeshMemberDeviceEnrolled {
            member_id,
            device_pub,
            participant_npub,
        },
        issuer_key,
    )
}

/// Mint a signed `MeshMemberDeviceRetired` event ready to append.
pub fn build_member_device_retire_event(
    member_id: String,
    device_pub: P256PublicKey,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::MeshMemberDeviceRetired {
            member_id,
            device_pub,
        },
        issuer_key,
    )
}

/// Fase E3: mint a signed `ClawSitePublished` event ready to append.
pub fn build_claw_site_published_event(
    claw_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::ClawSitePublished { claw_id },
        issuer_key,
    )
}

/// Fase E3: mint a signed `ClawSiteUnpublished` event ready to append.
pub fn build_claw_site_unpublished_event(
    claw_id: String,
    timestamp: u64,
    issuer_pub: P256PublicKey,
    issuer_key: &dyn IdentityKey,
) -> Result<LogEntry, MeshLogError> {
    LogEntry::sign(
        timestamp,
        issuer_pub,
        MeshEvent::ClawSiteUnpublished { claw_id },
        issuer_key,
    )
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MeshLogError {
    #[error("unsupported schema version: {0}")]
    VersionUnsupported(u8),
    #[error("envelope kind mismatch: {0}")]
    KindMismatch(String),
    #[error("issuer key did not match the bound public key")]
    IssuerKeyMismatch,
    #[error("entry_id did not match the derived BLAKE3 digest")]
    EntryIdMismatch,
    #[error("signature verification failed")]
    SignatureRejected,
    #[error("CBOR encoding error: {0}")]
    Cbor(#[source] HouseholdError),
    #[error("signing failed: {0}")]
    Sign(#[source] crate::error::KeystoreError),
    #[error("persistent log I/O error: {0}")]
    Io(#[source] std::io::Error),
}

// ─── Persistent backing helpers ──────────────────────────────────────────────

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_url_no_pad_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ())
}

/// Append a single line + newline to `path` and fsync the data. Atomic
/// at the line-boundary on POSIX (a torn write only corrupts the
/// trailing line, which the next `open` drops on signature failure).
fn append_line_durable(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_data()?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_share::SlotId;
    use crate::household_record::HouseholdRecord;
    use crate::ids::{derive_household_id, derive_machine_id};
    use crate::issuer_trust::{MachineIssuerError, is_machine_issuer_active};
    use crate::keys::P256Keypair;
    use crate::machine_cert::{MachineCert, Platform, SignOptions};

    fn mint(key: &P256Keypair, ts: u64, event: MeshEvent) -> LogEntry {
        LogEntry::sign(ts, key.public(), event, key as &dyn IdentityKey).expect("sign")
    }

    // ── Fase E1: first-class group + member-device projection ────────────────

    #[test]
    fn group_grant_authorizes_member_device_npubs_for_claw() {
        let owner = P256Keypair::generate();
        let alice_dev = P256Keypair::generate().public();
        let entries = vec![
            mint(
                &owner,
                1_000,
                MeshEvent::GroupCreated {
                    group_id: "grp_family".into(),
                    name: "Família".into(),
                },
            ),
            mint(
                &owner,
                1_100,
                MeshEvent::GroupMemberAdded {
                    group_id: "grp_family".into(),
                    member_id: "g_alice".into(),
                    label: "Alice".into(),
                },
            ),
            mint(
                &owner,
                1_200,
                MeshEvent::GroupClawGranted {
                    group_id: "grp_family".into(),
                    claw_id: "claw_home".into(),
                },
            ),
            mint(
                &owner,
                1_300,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_alice".into(),
                    device_pub: alice_dev,
                    participant_npub: "npub_alice_phone".into(),
                },
            ),
        ];
        let s = ProjectedState::project(&entries);
        assert!(
            s.members_authorized_for_claw("claw_home")
                .contains("g_alice")
        );
        assert!(
            s.group_member_npubs_for_claw("claw_home")
                .contains("npub_alice_phone")
        );
        // No grant ⇒ no authorization for another claw.
        assert!(s.members_authorized_for_claw("claw_other").is_empty());
    }

    #[test]
    fn group_member_removed_drops_from_claw() {
        let owner = P256Keypair::generate();
        let dev = P256Keypair::generate().public();
        let mut entries = vec![
            mint(
                &owner,
                1,
                MeshEvent::GroupCreated {
                    group_id: "g".into(),
                    name: "G".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::GroupMemberAdded {
                    group_id: "g".into(),
                    member_id: "g_a".into(),
                    label: String::new(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::GroupClawGranted {
                    group_id: "g".into(),
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                4,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: dev,
                    participant_npub: "n".into(),
                },
            ),
        ];
        assert!(
            ProjectedState::project(&entries)
                .group_member_npubs_for_claw("c")
                .contains("n")
        );
        entries.push(mint(
            &owner,
            5,
            MeshEvent::GroupMemberRemoved {
                group_id: "g".into(),
                member_id: "g_a".into(),
            },
        ));
        let s = ProjectedState::project(&entries);
        assert!(s.members_authorized_for_claw("c").is_empty());
        assert!(s.group_member_npubs_for_claw("c").is_empty());
    }

    #[test]
    fn group_claw_revoked_drops_grant() {
        let owner = P256Keypair::generate();
        let dev = P256Keypair::generate().public();
        let entries = vec![
            mint(
                &owner,
                1,
                MeshEvent::GroupCreated {
                    group_id: "g".into(),
                    name: "G".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::GroupMemberAdded {
                    group_id: "g".into(),
                    member_id: "g_a".into(),
                    label: String::new(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::GroupClawGranted {
                    group_id: "g".into(),
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                4,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: dev,
                    participant_npub: "n".into(),
                },
            ),
            mint(
                &owner,
                5,
                MeshEvent::GroupClawRevoked {
                    group_id: "g".into(),
                    claw_id: "c".into(),
                },
            ),
        ];
        let s = ProjectedState::project(&entries);
        assert!(s.members_authorized_for_claw("c").is_empty());
        assert!(s.group_member_npubs_for_claw("c").is_empty());
    }

    #[test]
    fn member_in_two_groups_remove_one_keeps_other() {
        let owner = P256Keypair::generate();
        let dev = P256Keypair::generate().public();
        let entries = vec![
            mint(
                &owner,
                1,
                MeshEvent::GroupCreated {
                    group_id: "fam".into(),
                    name: "Família".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::GroupCreated {
                    group_id: "work".into(),
                    name: "Trabalho".into(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::GroupMemberAdded {
                    group_id: "fam".into(),
                    member_id: "g_a".into(),
                    label: String::new(),
                },
            ),
            mint(
                &owner,
                4,
                MeshEvent::GroupMemberAdded {
                    group_id: "work".into(),
                    member_id: "g_a".into(),
                    label: String::new(),
                },
            ),
            mint(
                &owner,
                5,
                MeshEvent::GroupClawGranted {
                    group_id: "fam".into(),
                    claw_id: "claw_fam".into(),
                },
            ),
            mint(
                &owner,
                6,
                MeshEvent::GroupClawGranted {
                    group_id: "work".into(),
                    claw_id: "claw_work".into(),
                },
            ),
            mint(
                &owner,
                7,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: dev,
                    participant_npub: "n".into(),
                },
            ),
            mint(
                &owner,
                8,
                MeshEvent::GroupMemberRemoved {
                    group_id: "work".into(),
                    member_id: "g_a".into(),
                },
            ),
        ];
        let s = ProjectedState::project(&entries);
        assert!(s.group_member_npubs_for_claw("claw_fam").contains("n"));
        assert!(s.group_member_npubs_for_claw("claw_work").is_empty());
    }

    #[test]
    fn member_device_retired_drops_npub_but_keeps_member() {
        let owner = P256Keypair::generate();
        let phone = P256Keypair::generate().public();
        let laptop = P256Keypair::generate().public();
        let entries = vec![
            mint(
                &owner,
                1,
                MeshEvent::GroupCreated {
                    group_id: "g".into(),
                    name: "G".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::GroupMemberAdded {
                    group_id: "g".into(),
                    member_id: "g_a".into(),
                    label: String::new(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::GroupClawGranted {
                    group_id: "g".into(),
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                4,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: phone.clone(),
                    participant_npub: "n_phone".into(),
                },
            ),
            mint(
                &owner,
                5,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: laptop,
                    participant_npub: "n_laptop".into(),
                },
            ),
            mint(
                &owner,
                6,
                MeshEvent::MeshMemberDeviceRetired {
                    member_id: "g_a".into(),
                    device_pub: phone,
                },
            ),
        ];
        let s = ProjectedState::project(&entries);
        let npubs = s.group_member_npubs_for_claw("c");
        assert!(!npubs.contains("n_phone"));
        assert!(npubs.contains("n_laptop"));
        // Member is still authorized (only one of two devices retired).
        assert!(s.members_authorized_for_claw("c").contains("g_a"));
    }

    #[test]
    fn group_projection_is_order_independent_and_rename_lww() {
        let owner = P256Keypair::generate();
        let dev = P256Keypair::generate().public();
        let entries = vec![
            mint(
                &owner,
                1,
                MeshEvent::GroupCreated {
                    group_id: "g".into(),
                    name: "G".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::GroupMemberAdded {
                    group_id: "g".into(),
                    member_id: "g_a".into(),
                    label: "A".into(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::GroupClawGranted {
                    group_id: "g".into(),
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                4,
                MeshEvent::MeshMemberDeviceEnrolled {
                    member_id: "g_a".into(),
                    device_pub: dev,
                    participant_npub: "n".into(),
                },
            ),
            mint(
                &owner,
                5,
                MeshEvent::GroupRenamed {
                    group_id: "g".into(),
                    name: "G2".into(),
                },
            ),
        ];
        let forward = ProjectedState::project(&entries);
        let mut reversed = entries.clone();
        reversed.reverse();
        let backward = ProjectedState::project(&reversed);
        assert_eq!(forward, backward, "group projection diverged by order");
        // Rename is last-writer-wins by timestamp regardless of log order.
        assert_eq!(forward.groups["g"].name, "G2");
    }

    #[test]
    fn claw_site_publish_unpublish_is_remove_wins_and_republishable() {
        let owner = P256Keypair::generate();
        // Publish then unpublish (newer ts) → not published.
        let s1 = ProjectedState::project(&[
            mint(
                &owner,
                1,
                MeshEvent::ClawSitePublished {
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::ClawSiteUnpublished {
                    claw_id: "c".into(),
                },
            ),
        ]);
        assert!(!s1.is_claw_published("c"));
        // Re-publish with a strictly-newer ts → published again.
        let s2 = ProjectedState::project(&[
            mint(
                &owner,
                1,
                MeshEvent::ClawSitePublished {
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                2,
                MeshEvent::ClawSiteUnpublished {
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                3,
                MeshEvent::ClawSitePublished {
                    claw_id: "c".into(),
                },
            ),
        ]);
        assert!(s2.is_claw_published("c"));
        assert!(!s2.is_claw_published("other"));
        // Same-ts unpublish wins over publish (remove-wins-on-tie kill switch).
        let s3 = ProjectedState::project(&[
            mint(
                &owner,
                5,
                MeshEvent::ClawSitePublished {
                    claw_id: "c".into(),
                },
            ),
            mint(
                &owner,
                5,
                MeshEvent::ClawSiteUnpublished {
                    claw_id: "c".into(),
                },
            ),
        ]);
        assert!(!s3.is_claw_published("c"));
    }

    fn member_machine_cert(hh: &P256Keypair, m: &P256Keypair) -> MachineCert {
        MachineCert::sign(
            hh,
            &m.public(),
            &SignOptions {
                hh_id: derive_household_id(&hh.public()),
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .expect("machine cert")
    }

    fn household_record_with_member(hh: &P256Keypair, m: &P256Keypair) -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh.public()),
            hh_pub: hh.public(),
            name: "home".into(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&m.public())],
            is_follower: false,
        }
    }

    #[test]
    fn entry_verify_round_trip() {
        let key = P256Keypair::generate();
        let entry = mint(
            &key,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000,
            },
        );
        entry.verify().expect("verify");
    }

    #[test]
    fn tampered_entry_fails_verify() {
        let key = P256Keypair::generate();
        let mut entry = mint(
            &key,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_a".to_string(),
                expires_at: 2_000,
            },
        );
        // Change a body field — entry_id and signature both invalidate.
        entry.timestamp = 9_999;
        let err = entry.verify().expect_err("must reject");
        assert!(matches!(err, MeshLogError::EntryIdMismatch));
    }

    #[test]
    fn projection_is_order_independent() {
        let owner = P256Keypair::generate();
        let slot_a = SlotId::random();
        let slot_b = SlotId::random();
        let mint_a = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot_a.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
            },
        );
        let mint_b = mint(
            &owner,
            2_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot_b.clone(),
                claw_id: "claw_b".to_string(),
                expires_at: 5_000,
            },
        );
        let consume_a = mint(
            &owner,
            3_000,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: slot_a.clone(),
                guest_device_pub: P256Keypair::generate().public(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
                participant_npub: None,
            },
        );

        let order_1 = vec![mint_a.clone(), mint_b.clone(), consume_a.clone()];
        let order_2 = vec![consume_a.clone(), mint_b.clone(), mint_a.clone()];
        let order_3 = vec![mint_b.clone(), consume_a.clone(), mint_a.clone()];

        let s1 = ProjectedState::project(&order_1);
        let s2 = ProjectedState::project(&order_2);
        let s3 = ProjectedState::project(&order_3);

        assert_eq!(s1, s2, "shuffle 2 diverged");
        assert_eq!(s1, s3, "shuffle 3 diverged");
        assert_eq!(s1.slots.len(), 2);
    }

    #[test]
    fn remove_wins_for_slot_revoke() {
        let owner = P256Keypair::generate();
        let slot_a = SlotId::random();
        // Mint at ts=1000, revoke at ts=500 (revoke is EARLIER in real
        // time — remove-wins must still apply).
        let mint_evt = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot_a.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
            },
        );
        let revoke_evt = mint(
            &owner,
            500,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: slot_a.clone(),
            },
        );
        // Then a Consume tries to land — should also lose to revoke.
        let consume_evt = mint(
            &owner,
            900,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: slot_a.clone(),
                guest_device_pub: P256Keypair::generate().public(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
                participant_npub: None,
            },
        );

        let state = ProjectedState::project(&[mint_evt, revoke_evt, consume_evt]);
        let projected = state.slots.get(&slot_a).expect("slot present");
        assert!(matches!(
            projected.status,
            SlotProjectedStatus::Revoked { .. }
        ));
    }

    #[test]
    fn store_dedups_by_entry_id() {
        let owner = P256Keypair::generate();
        let entry = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_d".to_string(),
                expires_at: 2_000,
            },
        );
        let store = MeshLogStore::new();
        assert!(store.append(entry.clone()).expect("first append"));
        assert!(!store.append(entry).expect("second append"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_rejects_tampered_remote_entries() {
        let owner = P256Keypair::generate();
        let mut entry = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_d".to_string(),
                expires_at: 2_000,
            },
        );
        entry.timestamp = 9_999;
        let store = MeshLogStore::new();
        let err = store
            .ingest_remote(&[entry])
            .expect_err("tampered must reject");
        assert!(matches!(err, MeshLogError::EntryIdMismatch));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn two_device_gossip_converges_after_revoke() {
        // Device A mints a slot. Device B (same owner key, different
        // physical machine) revokes the same slot. They each ingest
        // the other's entries via gossip and end up with the same
        // projected state — both see the slot as Revoked.
        //
        // This is the slice's revocation-propagation correctness
        // proof: the projection commutes with gossip order.
        let owner = P256Keypair::generate();
        let slot_id = SlotId::random();
        let store_a = MeshLogStore::new();
        let store_b = MeshLogStore::new();

        let mint_evt = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot_id.clone(),
                claw_id: "claw_g".to_string(),
                expires_at: 5_000,
            },
        );
        let revoke_evt = mint(
            &owner,
            1_500,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: slot_id.clone(),
            },
        );

        store_a.append(mint_evt.clone()).expect("a mint");
        store_b.append(revoke_evt.clone()).expect("b revoke");

        // Gossip A → B and B → A. Both directions delivered exactly
        // once; duplicate ingests should be silent no-ops.
        store_b
            .ingest_remote(&store_a.snapshot())
            .expect("b ingests a");
        store_a
            .ingest_remote(&store_b.snapshot())
            .expect("a ingests b");
        // Re-ingest is idempotent:
        let added = store_a
            .ingest_remote(&store_b.snapshot())
            .expect("a re-ingests b");
        assert_eq!(added, 0);

        let state_a = store_a.project();
        let state_b = store_b.project();
        assert_eq!(state_a, state_b, "two-device projection diverged");

        let slot_state = state_a.slots.get(&slot_id).expect("slot present");
        assert!(
            matches!(slot_state.status, SlotProjectedStatus::Revoked { .. }),
            "expected Revoked, got {:?}",
            slot_state.status,
        );
    }

    #[test]
    fn persistent_store_survives_restart() {
        // Engine restart correctness: write a mint event to a real
        // file, drop the store, reopen against the same path, and
        // confirm the projection shows the slot as Open with the
        // same id.
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        // Remove the tempfile-created empty file so MeshLogStore::open
        // exercises its "fresh log" branch on first open.
        std::fs::remove_file(&path).ok();

        let owner = P256Keypair::generate();
        let slot_id = SlotId::random();

        {
            let store = MeshLogStore::open(&path).expect("open fresh");
            assert!(store.is_empty(), "fresh store should be empty");
            let entry = mint(
                &owner,
                1_000,
                MeshEvent::ClawShareSlotMinted {
                    slot_id: slot_id.clone(),
                    claw_id: "claw_persist".to_string(),
                    expires_at: 5_000,
                },
            );
            store.append(entry).expect("append");
            assert_eq!(store.len(), 1);
        }

        // Simulate engine restart: reopen against the same file.
        let reopened = MeshLogStore::open(&path).expect("reopen");
        assert_eq!(reopened.len(), 1, "restart lost the entry");

        let state = reopened.project();
        let slot = state.slots.get(&slot_id).expect("slot present");
        assert!(matches!(slot.status, SlotProjectedStatus::Open));
        assert_eq!(slot.claw_id, "claw_persist");
    }

    #[test]
    fn persistent_store_does_not_reopen_revoked_slot() {
        // The acceptance criterion that motivates this: "Engine deve
        // recuperar após restart sem reabrir invite consumido/revogado."
        let tmp = tempfile::NamedTempFile::new().expect("temp");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let owner = P256Keypair::generate();
        let slot_id = SlotId::random();

        {
            let store = MeshLogStore::open(&path).expect("open");
            store
                .append(mint(
                    &owner,
                    1_000,
                    MeshEvent::ClawShareSlotMinted {
                        slot_id: slot_id.clone(),
                        claw_id: "claw_r".to_string(),
                        expires_at: 5_000,
                    },
                ))
                .expect("mint");
            store
                .append(mint(
                    &owner,
                    1_100,
                    MeshEvent::ClawShareSlotRevoked {
                        slot_id: slot_id.clone(),
                    },
                ))
                .expect("revoke");
        }

        let reopened = MeshLogStore::open(&path).expect("reopen");
        let state = reopened.project();
        let slot = state
            .slots
            .get(&slot_id)
            .expect("slot present after reload");
        assert!(
            matches!(slot.status, SlotProjectedStatus::Revoked { .. }),
            "revoked slot must stay revoked across restart, got {:?}",
            slot.status,
        );
    }

    #[test]
    fn persistent_store_does_not_reopen_consumed_slot() {
        let tmp = tempfile::NamedTempFile::new().expect("temp");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();

        let owner = P256Keypair::generate();
        let guest = P256Keypair::generate();
        let slot_id = SlotId::random();

        {
            let store = MeshLogStore::open(&path).expect("open");
            store
                .append(mint(
                    &owner,
                    1_000,
                    MeshEvent::ClawShareSlotMinted {
                        slot_id: slot_id.clone(),
                        claw_id: "claw_c".to_string(),
                        expires_at: 5_000,
                    },
                ))
                .expect("mint");
            store
                .append(mint(
                    &owner,
                    1_500,
                    MeshEvent::ClawShareSlotConsumed {
                        slot_id: slot_id.clone(),
                        guest_device_pub: guest.public(),
                        claw_id: "claw_c".to_string(),
                        expires_at: 5_000,
                        participant_npub: None,
                    },
                ))
                .expect("consume");
        }

        let reopened = MeshLogStore::open(&path).expect("reopen");
        let state = reopened.project();
        let slot = state
            .slots
            .get(&slot_id)
            .expect("slot present after reload");
        assert!(
            matches!(slot.status, SlotProjectedStatus::Consumed { .. }),
            "consumed slot must stay consumed across restart, got {:?}",
            slot.status,
        );
    }

    #[test]
    fn state_digest_matches_when_same_set_arrived_in_any_order() {
        let owner = P256Keypair::generate();
        let e1 = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
            },
        );
        let e2 = mint(
            &owner,
            2_000,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: SlotId::random(),
            },
        );
        let store_a = MeshLogStore::new();
        store_a.append(e1.clone()).unwrap();
        store_a.append(e2.clone()).unwrap();
        let store_b = MeshLogStore::new();
        store_b.append(e2).unwrap();
        store_b.append(e1).unwrap();
        assert_eq!(
            store_a.state_digest(),
            store_b.state_digest(),
            "digest must be order-independent",
        );
    }

    #[test]
    fn state_digest_differs_when_one_engine_misses_an_entry() {
        let owner = P256Keypair::generate();
        let e1 = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: SlotId::random(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
            },
        );
        let store_a = MeshLogStore::new();
        store_a.append(e1.clone()).unwrap();
        let store_b = MeshLogStore::new();
        // store_b never sees e1
        assert_ne!(store_a.state_digest(), store_b.state_digest());
    }

    #[test]
    fn foreign_contact_recorded_and_projected() {
        let owner = P256Keypair::generate();
        let alice = P256Keypair::generate();
        let slot_id = SlotId::random();
        let evt = mint(
            &owner,
            1_000,
            MeshEvent::ForeignContactRecorded {
                guest_device_pub: alice.public(),
                contact_id: "c_alice_local".to_string(),
                display_name: "Alice".to_string(),
                trust_origin_slot_id: slot_id.clone(),
            },
        );
        let state = ProjectedState::project(&[evt]);
        let contact = state
            .foreign_contacts
            .get(&alice.public().as_bytes().to_vec())
            .expect("contact present");
        assert_eq!(contact.contact_id, "c_alice_local");
        assert_eq!(contact.display_name, "Alice");
        assert_eq!(contact.trust_origin_slot_id, slot_id);
        assert!(matches!(contact.status, ForeignContactStatus::Active));
    }

    #[test]
    fn foreign_contact_removed_marks_status() {
        let owner = P256Keypair::generate();
        let alice = P256Keypair::generate();
        let add = mint(
            &owner,
            1_000,
            MeshEvent::ForeignContactRecorded {
                guest_device_pub: alice.public(),
                contact_id: "c_a".to_string(),
                display_name: "Alice".to_string(),
                trust_origin_slot_id: SlotId::random(),
            },
        );
        let remove = mint(
            &owner,
            2_000,
            MeshEvent::ForeignContactRemoved {
                contact_id: "c_a".to_string(),
            },
        );
        let state = ProjectedState::project(&[add, remove]);
        let c = state
            .foreign_contacts
            .get(&alice.public().as_bytes().to_vec())
            .expect("contact present");
        assert!(matches!(c.status, ForeignContactStatus::Removed));
    }

    #[test]
    fn directory_device_lifecycle() {
        let owner = P256Keypair::generate();
        let new_phone = P256Keypair::generate();
        let add = mint(
            &owner,
            1_000,
            MeshEvent::DirectoryDeviceAdded {
                device_pub: new_phone.public(),
                label: "Carlos iPhone 17".to_string(),
            },
        );
        let state = ProjectedState::project(&[add.clone()]);
        let dev = state
            .directory_devices
            .get(&new_phone.public().as_bytes().to_vec())
            .expect("device present");
        assert!(matches!(dev.status, DirectoryDeviceStatus::Active));
        assert_eq!(dev.label, "Carlos iPhone 17");

        let remove = mint(
            &owner,
            2_000,
            MeshEvent::DirectoryDeviceRemoved {
                device_pub: new_phone.public(),
            },
        );
        let state2 = ProjectedState::project(&[add, remove]);
        let dev2 = state2
            .directory_devices
            .get(&new_phone.public().as_bytes().to_vec())
            .expect("present");
        assert!(matches!(dev2.status, DirectoryDeviceStatus::Removed));
    }

    #[test]
    fn emit_directory_device_removed_appends_verified_entry_and_projects_removed() {
        let issuer = P256Keypair::generate();
        let device = P256Keypair::generate();
        let store = MeshLogStore::new();

        let entry = emit_directory_device_removed(
            &store,
            &issuer,
            &issuer.public(),
            &device.public(),
            1_000,
        )
        .expect("emit");

        entry.verify().expect("entry verifies");
        assert_eq!(store.len(), 1);
        assert_eq!(entry.issuer_pub, issuer.public());
        assert!(matches!(
            entry.event,
            MeshEvent::DirectoryDeviceRemoved { ref device_pub }
                if *device_pub == device.public()
        ));

        let state = store.project();
        let projected = state
            .directory_devices
            .get(&device.public().as_bytes().to_vec())
            .expect("removed device projected");
        assert!(matches!(projected.status, DirectoryDeviceStatus::Removed));
    }

    #[test]
    fn emit_directory_device_removed_is_remove_wins_when_reemitted() {
        let issuer = P256Keypair::generate();
        let device = P256Keypair::generate();
        let store = MeshLogStore::new();

        emit_directory_device_removed(&store, &issuer, &issuer.public(), &device.public(), 1_000)
            .expect("first removal");
        emit_directory_device_removed(&store, &issuer, &issuer.public(), &device.public(), 1_001)
            .expect("second removal");

        let state = store.project();
        let projected = state
            .directory_devices
            .get(&device.public().as_bytes().to_vec())
            .expect("removed device projected");
        assert!(matches!(projected.status, DirectoryDeviceStatus::Removed));
    }

    #[test]
    fn emit_directory_device_removed_arms_machine_issuer_kill_switch() {
        let hh = P256Keypair::generate();
        let m = P256Keypair::generate();
        let cert = member_machine_cert(&hh, &m);
        let record = household_record_with_member(&hh, &m);
        let store = MeshLogStore::new();

        is_machine_issuer_active(&record, &cert, Some(&store.project()), &m.public())
            .expect("member machine active before removal");

        emit_directory_device_removed(&store, &m, &m.public(), &m.public(), 1_000)
            .expect("emit removal");

        let err = is_machine_issuer_active(&record, &cert, Some(&store.project()), &m.public())
            .expect_err("removed issuer must fail closed");
        assert!(matches!(err, MachineIssuerError::DeviceRemoved));
    }

    #[test]
    fn emit_directory_device_removed_rejects_issuer_key_mismatch() {
        let issuer = P256Keypair::generate();
        let other_issuer = P256Keypair::generate();
        let device = P256Keypair::generate();
        let store = MeshLogStore::new();

        let err = emit_directory_device_removed(
            &store,
            &issuer,
            &other_issuer.public(),
            &device.public(),
            1_000,
        )
        .expect_err("issuer key mismatch must reject");

        assert!(matches!(err, MeshLogError::IssuerKeyMismatch));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn revoked_guest_is_tracked() {
        let owner = P256Keypair::generate();
        let guest = P256Keypair::generate();
        let revoke = mint(
            &owner,
            1_000,
            MeshEvent::GuestRevoked {
                guest_device_pub: guest.public(),
                claw_id: "claw_x".to_string(),
            },
        );
        let state = ProjectedState::project(&[revoke]);
        assert!(
            state
                .revoked_guests
                .contains(&(guest.public().as_bytes().to_vec(), "claw_x".to_string()))
        );
    }

    // ─── R76: participant_npub keystone + share-derived roster ──────────────

    /// R76-2: the SIGNED `participant_npub` on a consume flows into the
    /// projected slot's `Consumed` status (the keystone the roster reads).
    #[test]
    fn consume_carries_participant_npub_into_projection() {
        let owner = P256Keypair::generate();
        let slot = SlotId::random();
        let log = MeshLogStore::new();
        log.append(
            build_slot_mint_event(
                slot.clone(),
                "claw_a".into(),
                5_000,
                1_000,
                owner.public(),
                &owner as &dyn IdentityKey,
            )
            .unwrap(),
        )
        .unwrap();
        log.append(
            build_slot_consume_event(
                slot.clone(),
                P256Keypair::generate().public(),
                "claw_a".into(),
                5_000,
                Some("npub_alice".into()),
                2_000,
                owner.public(),
                &owner as &dyn IdentityKey,
            )
            .unwrap(),
        )
        .unwrap();
        let st = log.project();
        match &st.slots[&slot].status {
            SlotProjectedStatus::Consumed {
                participant_npub, ..
            } => {
                assert_eq!(participant_npub.as_deref(), Some("npub_alice"));
            }
            other => panic!("expected Consumed, got {other:?}"),
        }
    }

    /// R76-2: a consume with `participant_npub: None` serialises WITHOUT the
    /// field (skip_serializing_if) so canonical CBOR — and thus the owner
    /// signature over the entry — stays byte-identical to a pre-mesh consume.
    /// A `Some(..)` consume includes it and round-trips intact.
    #[test]
    fn consume_npub_is_skipped_when_none_for_backward_compat() {
        let none = MeshEvent::ClawShareSlotConsumed {
            slot_id: SlotId([1u8; 16]),
            guest_device_pub: P256Keypair::from_secret_scalar(&[2u8; 32])
                .unwrap()
                .public(),
            claw_id: "claw_a".into(),
            expires_at: 5_000,
            participant_npub: None,
        };
        let bytes_none = crate::cbor::to_canonical_vec(&none).unwrap();
        let needle = b"participant_npub";
        assert!(
            !bytes_none.windows(needle.len()).any(|w| w == needle),
            "None consume must NOT encode the participant_npub key (backward compat)",
        );
        let back: MeshEvent = crate::cbor::from_canonical_slice(&bytes_none).unwrap();
        assert_eq!(back, none);

        let some = MeshEvent::ClawShareSlotConsumed {
            slot_id: SlotId([1u8; 16]),
            guest_device_pub: P256Keypair::from_secret_scalar(&[2u8; 32])
                .unwrap()
                .public(),
            claw_id: "claw_a".into(),
            expires_at: 5_000,
            participant_npub: Some("npub_z".into()),
        };
        let bytes_some = crate::cbor::to_canonical_vec(&some).unwrap();
        assert!(
            bytes_some.windows(needle.len()).any(|w| w == needle),
            "Some consume must encode the participant_npub key",
        );
        let back_some: MeshEvent = crate::cbor::from_canonical_slice(&bytes_some).unwrap();
        assert_eq!(back_some, some);
    }

    // ─── R81-1: shares_for_guest (routing hygiene) ──────────────────────────

    /// R81-1: `shares_for_guest` lists ONLY the guest's consumed, non-revoked,
    /// non-expired slots; revoked/expired/other-guest/open slots are excluded.
    #[test]
    fn shares_for_guest_lists_only_active_nonrevoked() {
        let owner = P256Keypair::generate();
        let k = &owner as &dyn IdentityKey;
        let log = MeshLogStore::new();
        let exp = 10_000u64;
        let alice = P256Keypair::from_secret_scalar(&[0x11; 32])
            .unwrap()
            .public();
        let mallory = P256Keypair::from_secret_scalar(&[0x22; 32])
            .unwrap()
            .public();

        // Alice: one active share on claw_a.
        let s_active = SlotId::random();
        log.append(
            build_slot_mint_event(s_active.clone(), "claw_a".into(), exp, 1, owner.public(), k)
                .unwrap(),
        )
        .unwrap();
        log.append(
            build_slot_consume_event(
                s_active.clone(),
                alice.clone(),
                "claw_a".into(),
                exp,
                Some("npub_alice".into()),
                2,
                owner.public(),
                k,
            )
            .unwrap(),
        )
        .unwrap();
        // Alice: one revoked share on claw_b.
        let s_rev = SlotId::random();
        log.append(
            build_slot_mint_event(s_rev.clone(), "claw_b".into(), exp, 3, owner.public(), k)
                .unwrap(),
        )
        .unwrap();
        log.append(
            build_slot_consume_event(
                s_rev.clone(),
                alice.clone(),
                "claw_b".into(),
                exp,
                Some("npub_alice".into()),
                4,
                owner.public(),
                k,
            )
            .unwrap(),
        )
        .unwrap();
        log.append(build_slot_revoke_event(s_rev, 5, owner.public(), k).unwrap())
            .unwrap();
        // Alice: one expired share on claw_c.
        let s_exp = SlotId::random();
        log.append(
            build_slot_mint_event(s_exp.clone(), "claw_c".into(), 50, 6, owner.public(), k)
                .unwrap(),
        )
        .unwrap();
        log.append(
            build_slot_consume_event(
                s_exp,
                alice.clone(),
                "claw_c".into(),
                50,
                Some("npub_alice".into()),
                7,
                owner.public(),
                k,
            )
            .unwrap(),
        )
        .unwrap();
        // Mallory: an active share — must not leak into Alice's list.
        let s_other = SlotId::random();
        log.append(
            build_slot_mint_event(s_other.clone(), "claw_a".into(), exp, 8, owner.public(), k)
                .unwrap(),
        )
        .unwrap();
        log.append(
            build_slot_consume_event(
                s_other,
                mallory,
                "claw_a".into(),
                exp,
                Some("npub_mallory".into()),
                9,
                owner.public(),
                k,
            )
            .unwrap(),
        )
        .unwrap();
        // An OPEN slot (minted, never consumed) — excluded.
        let s_open = SlotId::random();
        log.append(
            build_slot_mint_event(s_open, "claw_a".into(), exp, 10, owner.public(), k).unwrap(),
        )
        .unwrap();

        let now = 100u64; // past s_exp (50), before exp (10_000)
        let st = log.project();
        let shares = st.shares_for_guest(alice.as_bytes(), now);
        assert_eq!(
            shares.len(),
            1,
            "only the single active non-revoked share, got {shares:?}"
        );
        assert_eq!(shares[0].slot_id, s_active);
        assert_eq!(shares[0].claw_id, "claw_a");
        // Order-independence: a second projection of the same log yields equal.
        assert_eq!(
            log.project().shares_for_guest(alice.as_bytes(), now),
            shares
        );
    }
}
