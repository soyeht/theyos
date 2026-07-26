//! Phase 2 capability caveats for the first owner `PersonCert`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Operation namespace carried in `PersonCert` caveats.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Operation {
    #[serde(rename = "claws.list")]
    ClawsList,
    #[serde(rename = "claws.create")]
    ClawsCreate,
    #[serde(rename = "claws.delete")]
    ClawsDelete,
    #[serde(rename = "claws.use")]
    ClawsUse,
    #[serde(rename = "claws.assign")]
    ClawsAssign,
    #[serde(rename = "household.invite")]
    HouseholdInvite,
    #[serde(rename = "household.revoke")]
    HouseholdRevoke,
    #[serde(rename = "household.add_machine")]
    HouseholdAddMachine,
    #[serde(rename = "household.add_device")]
    HouseholdAddDevice,
    #[serde(rename = "owner_auth.enroll_initial")]
    OwnerAuthEnrollInitial,
}

impl Operation {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClawsList => "claws.list",
            Self::ClawsCreate => "claws.create",
            Self::ClawsDelete => "claws.delete",
            Self::ClawsUse => "claws.use",
            Self::ClawsAssign => "claws.assign",
            Self::HouseholdInvite => "household.invite",
            Self::HouseholdRevoke => "household.revoke",
            Self::HouseholdAddMachine => "household.add_machine",
            Self::HouseholdAddDevice => "household.add_device",
            Self::OwnerAuthEnrollInitial => "owner_auth.enroll_initial",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Operation {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "claws.list" => Ok(Self::ClawsList),
            "claws.create" => Ok(Self::ClawsCreate),
            "claws.delete" => Ok(Self::ClawsDelete),
            "claws.use" => Ok(Self::ClawsUse),
            "claws.assign" => Ok(Self::ClawsAssign),
            "household.invite" => Ok(Self::HouseholdInvite),
            "household.revoke" => Ok(Self::HouseholdRevoke),
            "household.add_machine" => Ok(Self::HouseholdAddMachine),
            "household.add_device" => Ok(Self::HouseholdAddDevice),
            "owner_auth.enroll_initial" => Ok(Self::OwnerAuthEnrollInitial),
            other => Err(format!("unknown operation {other:?}")),
        }
    }
}

/// Closed constraint value for R0a narrowing. The outer `Option` on
/// [`Caveat::constraints`] remains the only `None`; this enum has no `None`.
/// `machines=[text...]` and `expires_at=u64` keep the legacy CBOR shapes.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum ConstraintValue {
    Machines(Vec<String>),
    ExpiresAt(u64),
}

/// Closed constraint map. Only the `machines` and `expires_at` keys are valid,
/// with matching value shapes. Deserialization rejects every other key/shape;
/// valid legacy `machines` bytes stay byte-exact.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Constraints(std::collections::BTreeMap<String, ConstraintValue>);

impl Constraints {
    #[must_use]
    pub fn as_map(&self) -> &std::collections::BTreeMap<String, ConstraintValue> {
        &self.0
    }
}

impl Serialize for Constraints {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Constraints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ConstraintsVisitor;

        impl<'de> serde::de::Visitor<'de> for ConstraintsVisitor {
            type Value = Constraints;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed constraints map without duplicate keys")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut map = std::collections::BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, ConstraintValue>()? {
                    if map.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate constraint {key:?}"
                        )));
                    }
                }
                validate_closed_map(&map).map_err(serde::de::Error::custom)?;
                Ok(Constraints(map))
            }
        }

        deserializer.deserialize_map(ConstraintsVisitor)
    }
}

impl TryFrom<std::collections::BTreeMap<String, ConstraintValue>> for Constraints {
    type Error = String;

    fn try_from(
        map: std::collections::BTreeMap<String, ConstraintValue>,
    ) -> Result<Self, Self::Error> {
        validate_closed_map(&map)?;
        Ok(Self(map))
    }
}

fn validate_closed_map(
    map: &std::collections::BTreeMap<String, ConstraintValue>,
) -> Result<(), String> {
    for (key, value) in map {
        let valid = matches!(
            (key.as_str(), value),
            ("machines", ConstraintValue::Machines(_))
                | ("expires_at", ConstraintValue::ExpiresAt(_))
        );
        if !valid {
            return Err(format!("invalid constraint {key:?}"));
        }
    }
    Ok(())
}

/// Closed-scope validation failures (false booleans and malformed Specific).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeClosedError {
    #[error("scope all must be true")]
    AllFalse,
    #[error("scope owned_by_self must be true")]
    OwnedBySelfFalse,
    #[error("specific scope must be non-empty")]
    SpecificEmpty,
    #[error("specific scope entries must be ordered and unique")]
    SpecificNotOrderedUnique,
}

/// Caveat scope. Owner template only uses `All` for Claw operations and
/// `None` for household operations in Phase 2.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum Scope {
    All { all: bool },
    OwnedBySelf { owned_by_self: bool },
    Specific { specific: Vec<String> },
}

impl Scope {
    #[must_use]
    pub fn all() -> Self {
        Self::All { all: true }
    }

    #[must_use]
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All { all: true })
    }

    /// Validate the closed R0a scope shape: booleans must be true, Specific
    /// must be non-empty, ordered, unique, and closed text. This rejects; it
    /// never normalizes.
    pub fn validate_closed(&self) -> Result<(), ScopeClosedError> {
        match self {
            Self::All { all } if !all => Err(ScopeClosedError::AllFalse),
            Self::OwnedBySelf { owned_by_self } if !owned_by_self => {
                Err(ScopeClosedError::OwnedBySelfFalse)
            }
            Self::Specific { specific } => validate_specific(specific),
            Self::All { .. } | Self::OwnedBySelf { .. } => Ok(()),
        }
    }
}

fn validate_specific(values: &[String]) -> Result<(), ScopeClosedError> {
    if values.is_empty() {
        return Err(ScopeClosedError::SpecificEmpty);
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ScopeClosedError::SpecificNotOrderedUnique);
    }
    Ok(())
}

/// `PersonCert` caveat.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Caveat {
    pub op: Operation,
    pub scope: Option<Scope>,
    /// Phase 2 owner template has no constraints. R0a keeps this outer
    /// `Option` as the only `None` and closes values to
    /// `machines=[text...]`/`expires_at=u64` without changing legacy bytes.
    pub constraints: Option<Constraints>,
}

impl Caveat {
    #[must_use]
    pub fn new(op: Operation, scope: Option<Scope>) -> Self {
        Self {
            op,
            scope,
            constraints: None,
        }
    }
}

#[must_use]
pub fn owner_caveats() -> Vec<Caveat> {
    vec![
        Caveat::new(Operation::ClawsList, Some(Scope::all())),
        Caveat::new(Operation::ClawsCreate, Some(Scope::all())),
        Caveat::new(Operation::ClawsDelete, Some(Scope::all())),
        Caveat::new(Operation::ClawsUse, Some(Scope::all())),
        Caveat::new(Operation::ClawsAssign, Some(Scope::all())),
        Caveat::new(Operation::HouseholdInvite, None),
        Caveat::new(Operation::HouseholdRevoke, None),
        Caveat::new(Operation::HouseholdAddMachine, None),
    ]
}

#[must_use]
pub fn owner_capability_names() -> Vec<String> {
    owner_caveats()
        .into_iter()
        .map(|c| c.op.as_str().to_string())
        .collect()
}

#[must_use]
pub fn permits(caveats: &[Caveat], op: &Operation) -> bool {
    caveats.iter().any(|c| {
        if &c.op != op || c.constraints.is_some() {
            return false;
        }
        match op {
            Operation::ClawsList
            | Operation::ClawsCreate
            | Operation::ClawsDelete
            | Operation::ClawsUse
            | Operation::ClawsAssign => c.scope.as_ref().is_some_and(Scope::is_all),
            Operation::HouseholdInvite
            | Operation::HouseholdRevoke
            | Operation::HouseholdAddMachine
            | Operation::OwnerAuthEnrollInitial => c.scope.is_none(),
            // R0a: HouseholdAddDevice is granted only by the explicit narrowing
            // verifier, never by the owner template, capability names, or permits.
            Operation::HouseholdAddDevice => false,
        }
    })
}
