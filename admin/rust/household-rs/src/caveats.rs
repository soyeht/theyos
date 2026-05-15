//! Phase 2 capability caveats for the first owner `PersonCert`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Operation namespace carried in `PersonCert` caveats.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
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
            other => Err(format!("unknown operation {other:?}")),
        }
    }
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
}

/// `PersonCert` caveat.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Caveat {
    pub op: Operation,
    pub scope: Option<Scope>,
    /// Phase 2 owner template has no constraints. Future phases can extend
    /// this shape under a new validated semantics without changing `PersonCert`.
    pub constraints: Option<std::collections::BTreeMap<String, Vec<String>>>,
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
            | Operation::HouseholdAddMachine => c.scope.is_none(),
        }
    })
}
