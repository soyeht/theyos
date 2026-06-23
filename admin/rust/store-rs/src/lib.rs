//! store-rs — SQLite-backed instance persistence.

pub mod instance_db;
pub mod legacy_migration;

// ─── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum StoreError {
    #[error("instance not found")]
    InstanceNotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

impl core_rs::error::AppError for StoreError {
    fn code(&self) -> core_rs::error::ErrorCode {
        match self {
            StoreError::InstanceNotFound => core_rs::error::ErrorCode::NotFound,
            StoreError::Internal(_) => core_rs::error::ErrorCode::Internal,
        }
    }
}

// ─── Log entry (for API responses) ───────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub level: String,
    pub component: String,
    pub message: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

// ─── Re-exports ──────────────────────────────────────────────────────────────

pub use core_rs::slug::normalize_slug;
pub use instance_db::{
    AuditEvent, CloudflareConfigRow, DesiredState, InstanceDb, InstanceEvent, InstanceRow,
    InstanceStatus, InviteRow, NewInstance, NewInstanceEvent, NewLease, NewPublicSite,
    ObservedState, PublicSiteRow, ResourceLease, StatusUpdate, TerminalConversation, UserRole,
    UserRow, WarmPoolSlotId,
};
pub use legacy_migration::{
    LegacyDetection, LegacyTable, drop_legacy_at_path_if_present, drop_legacy_atomic,
    has_legacy_tables,
};
