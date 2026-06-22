//! Typed, versioned IPC protocol identifiers — Block B, slice B1 (additive).
//!
//! The JSON-RPC envelope ([`crate::ipc::wire`]) dispatches on a bare
//! `method: String` and the runner/store binaries `match method.as_str()`.
//! Method names and lease `owner_type` / `lease_kind` therefore cross the wire
//! as loose string literals duplicated across producers and consumers.
//!
//! This module introduces typed identifiers that mirror those wire strings
//! **exactly** (round-trip tested below), so later slices can migrate call
//! sites to `Op::as_str()` / parse with `FromStr` without changing the wire.
//!
//! B1 is purely **additive**: it adds these types + tests and touches neither
//! [`crate::ipc::wire::Request`]/[`Response`] nor any dispatch `match` arm.
//! Wiring [`PROTOCOL_VERSION`] onto the envelope and migrating producers is
//! deliberately deferred (slices B2+).

use serde::{Deserialize, Serialize};

/// Current IPC protocol version.
///
/// The envelope is presently **unversioned on the wire**; this constant is the
/// anchor for a future optional, skip-when-absent `version` field (added in a
/// later slice so existing payloads stay byte-identical). Nothing on the wire
/// changes today.
pub const PROTOCOL_VERSION: u32 = 1;

/// Returned by `FromStr` when a wire string does not name a known identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownIpcOp {
    /// The identifier kind that failed to parse (e.g. `"VmRunnerOp"`).
    pub kind: &'static str,
    /// The unrecognized wire value.
    pub value: String,
}

impl std::fmt::Display for UnknownIpcOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown {} IPC identifier: {:?}", self.kind, self.value)
    }
}

impl std::error::Error for UnknownIpcOp {}

/// Define an IPC op enum whose on-the-wire string is identical to the variant
/// name (`PascalCase` methods). `as_str` and serde both yield the variant name,
/// so there is no separate string literal to drift from the variant.
macro_rules! pascal_ipc_ops {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($variant:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        $vis enum $name { $($variant),+ }

        impl $name {
            /// Every variant, in wire/dispatch order.
            $vis const ALL: &'static [$name] = &[$($name::$variant),+];

            /// Exact on-the-wire method string (identical to the variant name).
            #[must_use]
            $vis fn as_str(&self) -> &'static str {
                match self { $($name::$variant => stringify!($variant)),+ }
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = UnknownIpcOp;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(stringify!($variant) => Ok($name::$variant),)+
                    other => Err(UnknownIpcOp {
                        kind: stringify!($name),
                        value: other.to_string(),
                    }),
                }
            }
        }
    };
}

/// Define an IPC enum whose wire string is an explicit `snake_case` literal
/// (lease `owner_type` / `lease_kind`), mirroring `store_rs`'s existing enums.
macro_rules! snake_ipc_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($variant:ident => $wire:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        $vis enum $name { $($variant),+ }

        impl $name {
            /// Every variant.
            $vis const ALL: &'static [$name] = &[$($name::$variant),+];

            /// Exact on-the-wire string.
            #[must_use]
            $vis fn as_str(&self) -> &'static str {
                match self { $($name::$variant => $wire),+ }
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = UnknownIpcOp;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($wire => Ok($name::$variant),)+
                    other => Err(UnknownIpcOp {
                        kind: stringify!($name),
                        value: other.to_string(),
                    }),
                }
            }
        }
    };
}

pascal_ipc_ops! {
    /// Methods dispatched by the Linux VM runner IPC server
    /// (`vmrunner-rs/src/bin/vmrunner_ipc.rs`) — the shared lifecycle vocabulary
    /// also pinned by `vmrunner-common-rs/tests/cross_runner_parity.rs`.
    pub enum VmRunnerOp {
        Create,
        Stop,
        Delete,
        Restart,
        Rebuild,
        CleanupSystemd,
        CleanupFs,
        FetchLogs,
        TakeBaseSnapshot,
        WarmPoolInit,
        WarmPoolRefill,
        WarmPoolStatus,
        WarmPoolDrain,
    }
}

pascal_ipc_ops! {
    /// Methods dispatched by the store IPC server
    /// (`store-rs/src/bin/store_ipc.rs`).
    pub enum StoreOp {
        InstanceDbInit,
        InstanceDbInsert,
        InstanceDbFindConflict,
        InstanceDbGet,
        InstanceDbList,
        InstanceDbUpdateStatus,
        InstanceDbUpdatePort,
        InstanceDbClearPort,
        InstanceDbSetVmNetwork,
        InstanceDbDelete,
        InstanceDbSetJobId,
        InstanceDbGetCfHostnameId,
        ResourceLeaseCreate,
        ResourceLeaseRelease,
        ResourceLeaseReleaseAll,
        ResourceLeaseExtend,
        ResourceLeaseFinalize,
        RecordInstanceEvent,
        SetDesiredState,
        SetObservedState,
        SoftDelete,
    }
}

snake_ipc_enum! {
    /// Owner of a `resource_leases` row. Mirrors `store_rs::instance_db::OwnerType`
    /// (kept as a shared core-rs mirror in B1; the two are unified in B4).
    pub enum LeaseOwnerType {
        Instance => "instance",
        WarmPool => "warm_pool",
    }
}

snake_ipc_enum! {
    /// Resource dimension a lease reserves. Mirrors `store_rs::instance_db::LeaseKind`.
    pub enum LeaseKind {
        Runtime => "runtime",
        Storage => "storage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn protocol_version_is_pinned() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn vmrunner_ops_match_wire_strings_exactly() {
        // Wire strings are the REAL dispatch literals from
        // vmrunner-rs/src/bin/vmrunner_ipc.rs (independent of the variant names),
        // so a variant-name typo is caught here, not only by self-consistency.
        let table = [
            (VmRunnerOp::Create, "Create"),
            (VmRunnerOp::Stop, "Stop"),
            (VmRunnerOp::Delete, "Delete"),
            (VmRunnerOp::Restart, "Restart"),
            (VmRunnerOp::Rebuild, "Rebuild"),
            (VmRunnerOp::CleanupSystemd, "CleanupSystemd"),
            (VmRunnerOp::CleanupFs, "CleanupFs"),
            (VmRunnerOp::FetchLogs, "FetchLogs"),
            (VmRunnerOp::TakeBaseSnapshot, "TakeBaseSnapshot"),
            (VmRunnerOp::WarmPoolInit, "WarmPoolInit"),
            (VmRunnerOp::WarmPoolRefill, "WarmPoolRefill"),
            (VmRunnerOp::WarmPoolStatus, "WarmPoolStatus"),
            (VmRunnerOp::WarmPoolDrain, "WarmPoolDrain"),
        ];
        assert_eq!(
            table.len(),
            VmRunnerOp::ALL.len(),
            "table must cover every VmRunnerOp variant"
        );
        for (op, wire) in table {
            assert_eq!(op.as_str(), wire);
            assert_eq!(serde_json::to_value(op).unwrap(), json!(wire));
            assert_eq!(VmRunnerOp::from_str(wire).unwrap(), op);
        }
        assert!(VmRunnerOp::from_str("WarmPoolReflll").is_err());
    }

    #[test]
    fn store_ops_match_wire_strings_exactly() {
        let table = [
            (StoreOp::InstanceDbInit, "InstanceDbInit"),
            (StoreOp::InstanceDbInsert, "InstanceDbInsert"),
            (StoreOp::InstanceDbFindConflict, "InstanceDbFindConflict"),
            (StoreOp::InstanceDbGet, "InstanceDbGet"),
            (StoreOp::InstanceDbList, "InstanceDbList"),
            (StoreOp::InstanceDbUpdateStatus, "InstanceDbUpdateStatus"),
            (StoreOp::InstanceDbUpdatePort, "InstanceDbUpdatePort"),
            (StoreOp::InstanceDbClearPort, "InstanceDbClearPort"),
            (StoreOp::InstanceDbSetVmNetwork, "InstanceDbSetVmNetwork"),
            (StoreOp::InstanceDbDelete, "InstanceDbDelete"),
            (StoreOp::InstanceDbSetJobId, "InstanceDbSetJobId"),
            (
                StoreOp::InstanceDbGetCfHostnameId,
                "InstanceDbGetCfHostnameId",
            ),
            (StoreOp::ResourceLeaseCreate, "ResourceLeaseCreate"),
            (StoreOp::ResourceLeaseRelease, "ResourceLeaseRelease"),
            (StoreOp::ResourceLeaseReleaseAll, "ResourceLeaseReleaseAll"),
            (StoreOp::ResourceLeaseExtend, "ResourceLeaseExtend"),
            (StoreOp::ResourceLeaseFinalize, "ResourceLeaseFinalize"),
            (StoreOp::RecordInstanceEvent, "RecordInstanceEvent"),
            (StoreOp::SetDesiredState, "SetDesiredState"),
            (StoreOp::SetObservedState, "SetObservedState"),
            (StoreOp::SoftDelete, "SoftDelete"),
        ];
        assert_eq!(
            table.len(),
            StoreOp::ALL.len(),
            "table must cover every StoreOp variant"
        );
        for (op, wire) in table {
            assert_eq!(op.as_str(), wire);
            assert_eq!(serde_json::to_value(op).unwrap(), json!(wire));
            assert_eq!(StoreOp::from_str(wire).unwrap(), op);
        }
        assert!(StoreOp::from_str("ResourceLeaseCreat").is_err());
    }

    #[test]
    fn lease_owner_type_matches_store_rs_wire() {
        let table = [
            (LeaseOwnerType::Instance, "instance"),
            (LeaseOwnerType::WarmPool, "warm_pool"),
        ];
        assert_eq!(table.len(), LeaseOwnerType::ALL.len());
        for (v, wire) in table {
            assert_eq!(v.as_str(), wire);
            assert_eq!(serde_json::to_value(v).unwrap(), json!(wire));
            assert_eq!(LeaseOwnerType::from_str(wire).unwrap(), v);
        }
        assert!(LeaseOwnerType::from_str("warmpool").is_err());
    }

    #[test]
    fn lease_kind_matches_store_rs_wire() {
        let table = [
            (LeaseKind::Runtime, "runtime"),
            (LeaseKind::Storage, "storage"),
        ];
        assert_eq!(table.len(), LeaseKind::ALL.len());
        for (v, wire) in table {
            assert_eq!(v.as_str(), wire);
            assert_eq!(serde_json::to_value(v).unwrap(), json!(wire));
            assert_eq!(LeaseKind::from_str(wire).unwrap(), v);
        }
        assert!(LeaseKind::from_str("disk").is_err());
    }
}
