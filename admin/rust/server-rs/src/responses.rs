//! Typed API response structs that match `frontend/src/lib/types.ts` exactly.
//!
//! Using `#[derive(Serialize)]` with `#[serde(rename_all = "snake_case")]` ensures
//! field names match the API convention without manual `json!()` construction.

use serde::Serialize;
use store_rs::InstanceRow;

/// Standard list envelope: `{"data": [...], "has_more": false, "next_cursor": null}`.
#[derive(Debug, Serialize)]
pub struct ListResponse<T: Serialize> {
    pub data: Vec<T>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

impl<T: Serialize> ListResponse<T> {
    /// Wrap a complete (non-paginated) result set.
    #[must_use]
    pub fn all(items: Vec<T>) -> Self {
        Self {
            data: items,
            has_more: false,
            next_cursor: None,
        }
    }

    /// Build a paginated response.
    #[must_use]
    pub fn page(data: Vec<T>, has_more: bool, next_cursor: Option<String>) -> Self {
        Self {
            data,
            has_more,
            next_cursor,
        }
    }
}

/// Matches frontend `Instance` type in `types.ts`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct InstanceResponse {
    pub id: String,
    pub name: String,
    pub container: String,
    pub claw_type: String,
    pub status: String,
    pub tokens_24h: i64,
    pub memory_mb: i64,
    pub cpu_pct: f64,
    pub uptime_hours: i64,
    pub auto_update: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Guest OS type: `"linux"` or `"macos"`. Present on all instances; existing API
    /// consumers are unaffected (JSON is additive).
    pub guest_os: String,
    /// CPU cores allocated to this instance (1-4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<i64>,
    /// RAM allocated to this instance in MB (512-8192).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ram_config_mb: Option<i64>,
    /// Disk allocated to this instance in GB (5-50).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<i64>,
    /// Instance owner, if assigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerInfo>,
    /// Desired state: what the user wants (`"running"`, `"stopped"`, `"deleted"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_state: Option<String>,
}

/// Abbreviated owner info included in instance responses.
#[derive(Debug, Serialize)]
pub struct OwnerInfo {
    pub id: String,
    pub username: String,
}

impl InstanceResponse {
    /// Build from an `InstanceRow` (`SQLite`).
    #[must_use]
    pub fn from_row(row: InstanceRow) -> Self {
        InstanceResponse {
            id: row.id,
            name: row.name,
            container: row.container,
            claw_type: row.claw_type,
            status: row.status.to_string(),
            tokens_24h: 0,
            memory_mb: 0,
            cpu_pct: 0.0,
            uptime_hours: 0,
            auto_update: row.auto_update.unwrap_or(false),
            created_at: row.created_at,
            provisioning_message: row.provisioning_message.filter(|s| !s.is_empty()),
            provisioning_error: row.provisioning_error.filter(|s| !s.is_empty()),
            provisioning_phase: row.provisioning_phase.filter(|s| !s.is_empty()),
            job_id: row.job_id.filter(|s| !s.is_empty()),
            guest_os: row.guest_os,
            cpu_cores: row.cpu_cores,
            ram_config_mb: row.ram_config_mb,
            disk_gb: row.disk_gb,
            owner: None, // Caller can set this via set_owner()
            desired_state: row.desired_state,
        }
    }

    /// Attach owner info to the response.
    #[must_use]
    pub fn with_owner(mut self, owner: Option<OwnerInfo>) -> Self {
        self.owner = owner;
        self
    }
}
