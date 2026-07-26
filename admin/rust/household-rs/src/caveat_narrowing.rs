//! R0a Fatia N: closed caveat narrowing proof and explicit `HouseholdAddDevice`
//! grant verification. This module produces only an opaque narrowing proof; it
//! does not create `DeviceCert`, storage, snapshots, capabilities, sinks, or any
//! admission authority.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::caveats::{Caveat, ConstraintValue, Constraints, Operation, Scope, ScopeClosedError};
use crate::cbor;

const NARROWING_DOMAIN: &[u8] = b"soyeht-r0a-device-caveat-narrowing-v1\n";

#[derive(Serialize)]
struct NarrowingPreimage<'a> {
    person: &'a [Caveat],
    device: Option<&'a [Caveat]>,
}

/// Closed failures produced by the R0a narrowing verifier. N-1 and N-2 are
/// the explicit None-vs-restricted mismatch negatives, not ordering labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CaveatNarrowingError {
    #[error("duplicate caveat operation")]
    DuplicateOperation,
    #[error("scope all must be true")]
    ScopeAllFalse,
    #[error("scope owned_by_self must be true")]
    ScopeOwnedBySelfFalse,
    #[error("specific scope must be non-empty, ordered, and unique")]
    InvalidSpecific,
    #[error("scope presence mismatch (N-1)")]
    ScopePresenceMismatch,
    #[error("constraint presence mismatch (N-2)")]
    ConstraintPresenceMismatch,
    #[error("unknown constraint")]
    UnknownConstraint,
    #[error("invalid constraint")]
    InvalidConstraint,
    #[error("operation is not a subset of the parent")]
    OperationWidening,
    #[error("scope is wider than the parent")]
    ScopeWidening,
    #[error("machines constraint is wider than the parent")]
    MachinesWidening,
    #[error("expiry is wider than the parent")]
    ExpiryWidening,
    #[error("explicit HouseholdAddDevice grant is missing")]
    GrantMissing,
    #[error("narrowing proof digest failed")]
    ProofDigest,
}

/// Opaque proof that a device caveat set narrows a person caveat set under the
/// closed R0a order. Move-only: no Copy, Clone, Default, serde, or conversion.
pub struct DeviceCaveatNarrowingProofV1 {
    digest: [u8; 32],
}

impl DeviceCaveatNarrowingProofV1 {
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for DeviceCaveatNarrowingProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceCaveatNarrowingProofV1(REDACTED)")
    }
}

/// Verify the explicit `HouseholdAddDevice` grant and closed narrowing. This is
/// deliberately separate from `owner_caveats`, `owner_capability_names`, and
/// `permits`: the owner template never grants `HouseholdAddDevice`.
pub fn verify_explicit_household_add_device_grant(
    person_caveats: &[Caveat],
    device_caveats: Option<&[Caveat]>,
) -> Result<DeviceCaveatNarrowingProofV1, CaveatNarrowingError> {
    validate_caveat_list(person_caveats)?;
    if !has_explicit_household_add_device_grant(person_caveats) {
        return Err(CaveatNarrowingError::GrantMissing);
    }
    if let Some(device_caveats) = device_caveats {
        validate_caveat_list(device_caveats)?;
        for child in device_caveats {
            let parent = person_caveats
                .iter()
                .find(|candidate| candidate.op == child.op)
                .ok_or(CaveatNarrowingError::OperationWidening)?;
            compare_scope(parent.scope.as_ref(), child.scope.as_ref())?;
            compare_constraints(parent.constraints.as_ref(), child.constraints.as_ref())?;
        }
    }

    let preimage = NarrowingPreimage {
        person: person_caveats,
        device: device_caveats,
    };
    let bytes = cbor::to_canonical_vec(&preimage).map_err(|_| CaveatNarrowingError::ProofDigest)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(NARROWING_DOMAIN);
    hasher.update(&bytes);
    Ok(DeviceCaveatNarrowingProofV1 {
        digest: hasher.finalize().into(),
    })
}

fn has_explicit_household_add_device_grant(caveats: &[Caveat]) -> bool {
    caveats
        .iter()
        .any(|caveat| caveat.op == Operation::HouseholdAddDevice && caveat.scope.is_none())
}

fn validate_caveat_list(caveats: &[Caveat]) -> Result<(), CaveatNarrowingError> {
    let mut operations = BTreeSet::new();
    for caveat in caveats {
        if !operations.insert(caveat.op.clone()) {
            return Err(CaveatNarrowingError::DuplicateOperation);
        }
        caveat
            .scope
            .as_ref()
            .map_or(Ok(()), Scope::validate_closed)
            .map_err(map_scope_error)?;
        if let Some(constraints) = &caveat.constraints {
            validate_constraints(constraints)?;
        }
    }
    Ok(())
}

fn map_scope_error(error: ScopeClosedError) -> CaveatNarrowingError {
    match error {
        ScopeClosedError::AllFalse => CaveatNarrowingError::ScopeAllFalse,
        ScopeClosedError::OwnedBySelfFalse => CaveatNarrowingError::ScopeOwnedBySelfFalse,
        ScopeClosedError::SpecificEmpty | ScopeClosedError::SpecificNotOrderedUnique => {
            CaveatNarrowingError::InvalidSpecific
        }
    }
}

fn validate_constraints(constraints: &Constraints) -> Result<(), CaveatNarrowingError> {
    for (key, value) in constraints.as_map() {
        match (key.as_str(), value) {
            ("machines", ConstraintValue::Machines(values)) => {
                validate_ordered_unique_non_empty(values)?;
            }
            ("expires_at", ConstraintValue::ExpiresAt(_)) => {}
            ("machines" | "expires_at", _) => {
                return Err(CaveatNarrowingError::InvalidConstraint);
            }
            _ => return Err(CaveatNarrowingError::UnknownConstraint),
        }
    }
    Ok(())
}

fn validate_ordered_unique_non_empty(values: &[String]) -> Result<(), CaveatNarrowingError> {
    if values.is_empty() || !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(CaveatNarrowingError::InvalidConstraint);
    }
    Ok(())
}

fn compare_scope(
    parent: Option<&Scope>,
    child: Option<&Scope>,
) -> Result<(), CaveatNarrowingError> {
    match (parent, child) {
        (None, None)
        | (Some(Scope::All { all: true }), Some(_))
        | (Some(Scope::OwnedBySelf { .. }), Some(Scope::OwnedBySelf { .. })) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(CaveatNarrowingError::ScopePresenceMismatch),
        (
            Some(Scope::Specific {
                specific: parent_values,
            }),
            Some(Scope::Specific {
                specific: child_values,
            }),
        ) if is_subset(child_values, parent_values) => Ok(()),
        (Some(Scope::OwnedBySelf { .. } | Scope::Specific { .. }), Some(_)) => {
            Err(CaveatNarrowingError::ScopeWidening)
        }
        (Some(Scope::All { .. }), _) => Err(CaveatNarrowingError::InvalidSpecific),
    }
}

fn compare_constraints(
    parent: Option<&Constraints>,
    child: Option<&Constraints>,
) -> Result<(), CaveatNarrowingError> {
    match (parent, child) {
        (None, None) => Ok(()),
        (None, Some(child)) => validate_constraints(child),
        (Some(_), None) => Err(CaveatNarrowingError::ConstraintPresenceMismatch),
        (Some(parent), Some(child)) => {
            validate_constraints(parent)?;
            validate_constraints(child)?;
            compare_machines(parent, child)?;
            compare_expires_at(parent, child)
        }
    }
}

fn compare_machines(parent: &Constraints, child: &Constraints) -> Result<(), CaveatNarrowingError> {
    match (
        parent.as_map().get("machines"),
        child.as_map().get("machines"),
    ) {
        (None, None | Some(_)) => Ok(()),
        (Some(_), None) => Err(CaveatNarrowingError::ConstraintPresenceMismatch),
        (
            Some(ConstraintValue::Machines(parent_values)),
            Some(ConstraintValue::Machines(child_values)),
        ) if is_subset(child_values, parent_values) => Ok(()),
        _ => Err(CaveatNarrowingError::MachinesWidening),
    }
}

fn compare_expires_at(
    parent: &Constraints,
    child: &Constraints,
) -> Result<(), CaveatNarrowingError> {
    match (
        parent.as_map().get("expires_at"),
        child.as_map().get("expires_at"),
    ) {
        (None, None | Some(_)) => Ok(()),
        (Some(_), None) => Err(CaveatNarrowingError::ConstraintPresenceMismatch),
        (
            Some(ConstraintValue::ExpiresAt(parent_value)),
            Some(ConstraintValue::ExpiresAt(child_value)),
        ) if child_value <= parent_value => Ok(()),
        _ => Err(CaveatNarrowingError::ExpiryWidening),
    }
}

fn is_subset(child: &[String], parent: &[String]) -> bool {
    child
        .iter()
        .all(|value| parent.binary_search(value).is_ok())
}
