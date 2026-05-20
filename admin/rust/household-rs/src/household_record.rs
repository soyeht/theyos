//! `HouseholdRecord` — the on-disk root of a household's identity.
//!
//! See `contracts/cbor-schemas.md` and `data-model.md`.

use serde::{Deserialize, Serialize};

use crate::error::HouseholdError;
use crate::ids::{HouseholdId, MachineId, derive_household_id};
use crate::keys::P256PublicKey;

/// Wire / on-disk schema for the household root record.
///
/// Wire field name is `"v"` (not `"version"`) for parity with the `MachineCert`
/// schema (`docs/household-protocol.md` §5).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct HouseholdRecord {
    #[serde(rename = "v")]
    pub version: u8,
    pub hh_id: HouseholdId,
    pub hh_pub: P256PublicKey,
    pub name: String,
    pub created_at: u64,
    pub shamir_k: u8,
    pub shamir_n: u8,
    pub members: Vec<MachineId>,
    /// True when this engine joined a household whose `HH_priv` is held by an
    /// owner device instead of local engine storage.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_follower: bool,
}

impl HouseholdRecord {
    pub const SCHEMA_VERSION: u8 = 1;

    /// Validate every household-record invariant. Returns the typed error on
    /// the first failure (caller is expected to surface
    /// `error.kind`/`error.hint`).
    ///
    /// Phase 1 ships with `(k=1, n=1)` and a single member. Phase 3 admits a
    /// second machine and produces `(k=2, n=2)` with two members. The
    /// `members.len() == n` invariant therefore holds across both phases, and
    /// the validator here MUST accept both shapes — Phase-1-only validators
    /// would panic the daemon on the next restart after a Phase-3 commit.
    pub fn validate(&self) -> Result<(), HouseholdError> {
        if self.version != Self::SCHEMA_VERSION {
            return Err(HouseholdError::InvalidRecord(format!(
                "version {} unsupported (supported: {})",
                self.version,
                Self::SCHEMA_VERSION
            )));
        }
        P256PublicKey::from_bytes(self.hh_pub.as_bytes())?;
        let recomputed = derive_household_id(&self.hh_pub);
        if recomputed != self.hh_id {
            return Err(HouseholdError::IdentifierMismatch {
                expected: recomputed.to_string(),
                actual: self.hh_id.to_string(),
            });
        }
        validate_household_name(&self.name)?;
        if self.members.is_empty() {
            return Err(HouseholdError::InvalidRecord(
                "members[] must be non-empty".into(),
            ));
        }
        if self.is_follower {
            if self.shamir_k != 0 || self.shamir_n != 0 {
                return Err(HouseholdError::InvalidRecord(format!(
                    "follower records must use shamir_k/n = 0/0 (got {}/{})",
                    self.shamir_k, self.shamir_n
                )));
            }
        } else {
            // Shamir invariants:
            //   1 <= k <= n
            //   members.len() == n
            // Phase 1: (1, 1). Phase 3: (2, 2). Larger n reserved for later phases.
            if self.shamir_k == 0 || self.shamir_n == 0 || self.shamir_k > self.shamir_n {
                return Err(HouseholdError::InvalidRecord(format!(
                    "shamir_k/n must satisfy 1 <= k <= n (got {}/{})",
                    self.shamir_k, self.shamir_n
                )));
            }
            if self.members.len() != usize::from(self.shamir_n) {
                return Err(HouseholdError::InvalidRecord(format!(
                    "members.len()={} != shamir_n={}",
                    self.members.len(),
                    self.shamir_n
                )));
            }
        }
        for m in &self.members {
            if !MachineId::is_well_formed(m.as_str()) {
                return Err(HouseholdError::InvalidRecord(format!(
                    "members[] entry '{}' malformed",
                    m.as_str()
                )));
            }
        }
        // Reject duplicates so that members.len() == shamir_n carries
        // the intended meaning ("n distinct member machines") rather
        // than degenerating to "n entries, possibly the same machine
        // referenced multiple times". Detecting at validate-time is
        // cheap (n is tiny) and prevents Phase 4/5 replication paths
        // from quietly accepting an ill-formed record.
        for i in 0..self.members.len() {
            for j in (i + 1)..self.members.len() {
                if self.members[i] == self.members[j] {
                    return Err(HouseholdError::InvalidRecord(format!(
                        "members[] contains duplicate entry '{}'",
                        self.members[i].as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn has_local_household_private_key(&self) -> bool {
        !self.is_follower && self.shamir_n == 1
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// Spec invariant: name length 1..=64 **UTF-8 bytes** (not grapheme clusters);
/// printable Unicode (no control codes). The byte-length bound is intentional
/// — it bounds the on-disk and on-wire CBOR size deterministically across
/// implementations. Operators using emoji-heavy names should size accordingly.
pub fn validate_household_name(name: &str) -> Result<(), HouseholdError> {
    if name.is_empty() {
        return Err(HouseholdError::InvalidRecord(
            "household name must be non-empty".into(),
        ));
    }
    if name.len() > 64 {
        return Err(HouseholdError::InvalidRecord(format!(
            "household name must be <= 64 UTF-8 bytes (got {} bytes — emoji and \
             multi-byte characters take more than one byte each)",
            name.len()
        )));
    }
    for ch in name.chars() {
        if ch.is_control() {
            return Err(HouseholdError::InvalidRecord(
                "household name contains control character".into(),
            ));
        }
    }
    Ok(())
}
