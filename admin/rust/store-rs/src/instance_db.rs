//! SQLite-backed persistence for the instances table.

use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use rusqlite::{Connection, OptionalExtension, params};
use std::str::FromStr;

use crate::StoreError;

/// Column list for instance SELECT queries (shared across `list`, `list_paginated`, etc.).
const INSTANCE_COLS: &str = "id, name, container, claw_type, host_port, status, \
    provisioning_message, provisioning_error, provisioning_phase, job_id, auto_update, \
    custom_domain, cf_hostname_id, created_at, updated_at, \
    vm_id, pid, snapshot_path, config_json, \
    vm_ip, vm_mac, efi_store_path, cidata_iso_path, disk_path, \
    guest_os, aux_storage_path, owner_id, \
    cpu_cores, ram_config_mb, disk_gb, \
    desired_state, observed_state, deleted_at, household_id, household_machine_id, \
    provisioning_failure_code";

/// User role within the multi-tenant system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UserRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

/// A row from the `users` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub created_at: String,
    pub created_by: Option<String>,
}

/// Typed instance lifecycle status — eliminates string comparisons at 20+ sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Provisioning,
    Active,
    Stopped,
    Failed,
}

impl InstanceStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InstanceStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "stopped" => Ok(Self::Stopped),
            "failed" | "error" => Ok(Self::Failed),
            other => Err(format!("unknown status: {other}")),
        }
    }
}

// ── Resource Lease Types ─────────────────────────────────────────────────────

// `OwnerType` / `LeaseKind` lived here as unused duplicates of
// `core_rs::ipc::protocol::{LeaseOwnerType, LeaseKind}` (B1 mirrored the wire
// strings; nothing referenced these). B4b deletes them and types the lease API
// below directly on the core-rs identifiers (imported at the top of this file).

/// Desired instance state (what the user wants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesiredState {
    Running,
    Stopped,
    Deleted,
}

impl DesiredState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Deleted => "deleted",
        }
    }
}

impl std::fmt::Display for DesiredState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DesiredState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "running" => Ok(Self::Running),
            "stopped" => Ok(Self::Stopped),
            "deleted" => Ok(Self::Deleted),
            other => Err(format!("unknown desired_state: {other}")),
        }
    }
}

/// Observed instance state (what the system sees).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservedState {
    Provisioning,
    Active,
    Stopped,
    Failed,
    Unknown,
    Deleting,
}

impl ObservedState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Deleting => "deleting",
        }
    }
}

impl std::fmt::Display for ObservedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ObservedState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "stopped" => Ok(Self::Stopped),
            "failed" => Ok(Self::Failed),
            "unknown" => Ok(Self::Unknown),
            "deleting" => Ok(Self::Deleting),
            other => Err(format!("unknown observed_state: {other}")),
        }
    }
}

/// A row from the `resource_leases` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceLease {
    pub id: String,
    pub owner_type: String,
    pub owner_id: String,
    pub lease_kind: String,
    pub cpu_cores: i64,
    pub ram_mb: i64,
    pub disk_gb: i64,
    pub acquired_at: i64,
    pub expires_at: Option<i64>,
    pub released_at: Option<i64>,
}

/// Canonical identity of a claw type's single warm-pool slot — the `owner_id`
/// of its warm-pool lease.
///
/// Wire format (unchanged): `"{claw_type}:slot:0"`. Centralizing it keeps every
/// warm-pool lease producer byte-identical and removes the scattered
/// `format!("{claw_type}:slot:0")` duplication across store-rs and server-rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarmPoolSlotId<'a> {
    claw_type: &'a str,
}

impl<'a> WarmPoolSlotId<'a> {
    /// The single warm-pool slot (index 0) for `claw_type`.
    #[must_use]
    pub fn new(claw_type: &'a str) -> Self {
        Self { claw_type }
    }

    /// The warm-pool lease `owner_id`: `"{claw_type}:slot:0"`.
    #[must_use]
    pub fn owner_id(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for WarmPoolSlotId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:slot:0", self.claw_type)
    }
}

#[cfg(test)]
mod warm_pool_slot_id_tests {
    use super::WarmPoolSlotId;

    #[test]
    fn owner_id_is_byte_identical_to_legacy_inline_format() {
        // For every claw_type the helper must emit exactly the old
        // `format!("{claw_type}:slot:0")` string the producers built inline.
        for ct in [
            "picoclaw",
            "microclaw",
            "claude-claw",
            "mac-host",
            "a",
            "x-y-z",
            "claw_underscore",
            "",
        ] {
            let legacy = format!("{ct}:slot:0");
            assert_eq!(WarmPoolSlotId::new(ct).owner_id(), legacy);
            assert_eq!(WarmPoolSlotId::new(ct).to_string(), legacy);
        }
        // Pin the exact literal used by the hand-written test fixtures.
        assert_eq!(
            WarmPoolSlotId::new("picoclaw").owner_id(),
            "picoclaw:slot:0"
        );
    }
}

/// Parameters for creating a new resource lease.
///
/// `owner_type`/`lease_kind` are the typed identifiers from
/// `core_rs::ipc::protocol`; the SQL writes their `.as_str()` values unchanged.
pub struct NewLease<'a> {
    pub owner_type: LeaseOwnerType,
    pub owner_id: &'a str,
    pub lease_kind: LeaseKind,
    pub cpu_cores: i64,
    pub ram_mb: i64,
    pub disk_gb: i64,
    pub expires_at: Option<i64>,
}

/// A row from the `instance_events` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstanceEvent {
    pub id: i64,
    pub instance_id: Option<String>,
    pub event_type: String,
    pub actor: String,
    pub detail: Option<String>,
    pub resource_snapshot: Option<String>,
    pub created_at: i64,
}

/// Parameters for recording a new instance event.
pub struct NewInstanceEvent<'a> {
    pub instance_id: Option<&'a str>,
    pub event_type: &'a str,
    pub actor: &'a str,
    pub detail: Option<&'a str>,
    pub resource_snapshot: Option<&'a str>,
}

/// Named fields for `update_status` — prevents silent argument reordering.
pub struct StatusUpdate<'a> {
    pub id: &'a str,
    pub status: InstanceStatus,
    pub message: &'a str,
    pub error: &'a str,
    pub job_id: &'a str,
    /// Provisioning phase for Live Activity: `"queuing"`, `"pulling"`, `"starting"`.
    /// Empty string → stores `NULL` in the database.
    pub phase: &'a str,
}

pub struct InstanceDb {
    conn: std::sync::Mutex<Connection>,
}

/// A row from `shareable_apps` — the Share's own identity authority (D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareableAppRow {
    pub app_id: String,
    pub instance_id: String,
    pub household_id: String,
    pub display_name: String,
    pub resource: String,
    pub retired_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// The only resource this cycle mints Share bindings for.
pub const SHAREABLE_APP_RESOURCE_CLAWSITE: &str = "clawsite";

const SHAREABLE_APP_DISPLAY_NAME_MAX_CHARS: usize = 128;

fn validate_shareable_display_name(display_name: &str) -> Result<(), StoreError> {
    let len = display_name.chars().count();
    if len == 0 || len > SHAREABLE_APP_DISPLAY_NAME_MAX_CHARS || display_name.trim().is_empty() {
        return Err(StoreError::Internal(
            "shareable_app display_name must be nonempty and length-bounded".to_string(),
        ));
    }
    Ok(())
}

/// `app_` + 32 lowercase hex = 128 bits CSPRNG (pinned format). Never derived
/// from any name, so delete+recreate always yields a different id.
fn generate_shareable_app_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.r#gen();
    let mut id = String::with_capacity(4 + 32);
    id.push_str("app_");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

fn shareable_app_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShareableAppRow> {
    Ok(ShareableAppRow {
        app_id: row.get(0)?,
        instance_id: row.get(1)?,
        household_id: row.get(2)?,
        display_name: row.get(3)?,
        resource: row.get(4)?,
        retired_at: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

/// A row from the `audit_events` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub instance_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub detail: Option<String>,
    pub created_at: String,
}

/// A row from the `invites` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InviteRow {
    pub id: String,
    pub token: String,
    pub instance_id: String,
    pub created_by: String,
    pub expires_at: String,
    pub redeemed_by: Option<String>,
    pub redeemed_at: Option<String>,
    pub created_at: String,
}

/// A public HTTP site routed from a user-owned domain to a claw instance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PublicSiteRow {
    pub domain: String,
    pub instance_id: String,
    pub guest_port: i64,
    pub target_host: String,
    pub target_port: i64,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    /// Cloudflare DNS record id of the auto-created CNAME (when the operator
    /// configured Cloudflare via Settings). `None` for sites added before the
    /// auto-CNAME flow shipped or for hosts where Cloudflare is not configured
    /// (e.g. Caddy-fronted setups). Used to delete the right record on
    /// remove/disconnect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_dns_record_id: Option<String>,
}

/// Named fields for creating or updating a public site mapping.
pub struct NewPublicSite<'a> {
    pub domain: &'a str,
    pub instance_id: &'a str,
    pub guest_port: i64,
    pub target_host: &'a str,
    pub target_port: i64,
    pub enabled: bool,
}

/// Persistent record of the operator's Cloudflare tunnel binding (single row).
/// Survives restarts so the backend can call the API and reload cloudflared
/// without re-prompting the operator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CloudflareConfigRow {
    pub account_id: String,
    pub zone_id: String,
    pub zone_name: String,
    pub tunnel_id: String,
    pub tunnel_name: String,
    pub configured_at: String,
}

/// Named fields for inserting a new instance — prevents silent field reordering.
pub struct NewInstance<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub container: &'a str,
    pub claw_type: &'a str,
    pub sunset_date: &'a str,
    /// Guest OS: `"linux"` (default) or `"macos"`. `None` → uses DB default `'linux'`.
    pub guest_os: Option<&'a str>,
    /// macOS guest only: path to `VZMacAuxiliaryStorage` file. `None` for Linux guests.
    pub aux_storage_path: Option<&'a str>,
    /// CPU cores (1-4). `None` uses DB default (2).
    pub cpu_cores: Option<i64>,
    /// RAM in MB (512-8192). `None` uses DB default (2048).
    pub ram_config_mb: Option<i64>,
    /// Disk size in GB (5-50). `None` uses DB default (10).
    pub disk_gb: Option<i64>,
    /// Household id stamped for instances created through household `PoP` routes.
    pub household_id: Option<&'a str>,
    /// Engine machine id stamped for instances created through household `PoP` routes.
    pub household_machine_id: Option<&'a str>,
}

/// A row from the instances table, as returned by queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstanceRow {
    pub id: String,
    pub name: String,
    pub container: String,
    pub claw_type: String,
    pub host_port: Option<i64>,
    pub status: InstanceStatus,
    pub provisioning_message: Option<String>,
    pub provisioning_error: Option<String>,
    /// Sanitized machine-readable failure reason (a `snake_case`
    /// `InstanceFailureCode`), stamped when `status == Failed`. `None` for rows
    /// that were never stamped (older rows / non-failed). The raw human detail
    /// stays in `provisioning_error`.
    pub provisioning_failure_code: Option<String>,
    /// Provisioning phase for mobile Live Activity (`"queuing"`, `"pulling"`, `"starting"`).
    pub provisioning_phase: Option<String>,
    pub job_id: Option<String>,
    pub auto_update: Option<bool>,
    pub custom_domain: Option<String>,
    pub cf_hostname_id: Option<String>,
    /// macOS-specific: VZ VM identifier (UUID)
    pub vm_id: Option<String>,
    /// macOS-specific: VZ process PID
    pub pid: Option<i64>,
    /// macOS-specific: Warm pool snapshot path
    pub snapshot_path: Option<String>,
    /// macOS-specific: Serialized VM configuration
    pub config_json: Option<String>,
    /// macOS-specific: DHCP-assigned VZ NAT IP (e.g. 192.168.64.5)
    pub vm_ip: Option<String>,
    /// macOS-specific: VM MAC address used for DHCP lookup
    pub vm_mac: Option<String>,
    /// macOS-specific: Path to EFI variable store (.nvram)
    pub efi_store_path: Option<String>,
    /// macOS-specific: Path to cloud-init cidata ISO
    pub cidata_iso_path: Option<String>,
    /// macOS-specific: Path to per-instance raw disk image
    pub disk_path: Option<String>,
    /// Guest OS type: `'linux'` (default) or `'macos'`.
    /// Set by migration `002_add_guest_os.sql`.
    pub guest_os: String,
    /// macOS guest only: path to `VZMacAuxiliaryStorage` file (~1 MB `.auxstorage`).
    pub aux_storage_path: Option<String>,
    /// User who owns this instance. `None` = unassigned (admin-only).
    pub owner_id: Option<String>,
    /// CPU cores configured for this instance VM.
    pub cpu_cores: Option<i64>,
    /// RAM in MB configured for this instance VM.
    pub ram_config_mb: Option<i64>,
    /// Disk size in GB configured for this instance VM.
    pub disk_gb: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
    /// What the user wants: `"running"`, `"stopped"`, `"deleted"`.
    pub desired_state: Option<String>,
    /// What the system sees: `"provisioning"`, `"active"`, `"stopped"`, `"failed"`, etc.
    pub observed_state: Option<String>,
    /// Unix timestamp when the instance was soft-deleted. `None` = not deleted.
    pub deleted_at: Option<i64>,
    /// Household id for household-created instances. `None` for legacy/admin rows.
    pub household_id: Option<String>,
    /// Engine machine id for household-created instances. `None` for legacy/admin rows.
    pub household_machine_id: Option<String>,
}

impl InstanceDb {
    /// Lock the inner connection, converting a `PoisonError` to `StoreError::Internal`.
    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn
            .lock()
            .map_err(|_| StoreError::Internal("instance_db lock poisoned".into()))
    }

    /// Open (or create) the `SQLite` database at `db_path` and initialize the schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the schema fails to initialize.
    pub fn open(db_path: &str) -> Result<Self, StoreError> {
        let conn = core_rs::db::open_wal(std::path::Path::new(db_path))
            .map_err(|e| StoreError::Internal(format!("open db: {e}")))?;

        Self::init_schema(&conn)?;

        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    fn init_schema(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(r"
            CREATE TABLE IF NOT EXISTS instances (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                container TEXT UNIQUE NOT NULL,
                claw_type TEXT NOT NULL,
                host_port INTEGER UNIQUE,
                internal_port INTEGER DEFAULT 8080,
                status TEXT DEFAULT 'provisioning',
                tls_cert TEXT DEFAULT 'wildcard',
                sunset_port_direct_date DATE,
                job_id TEXT,
                provisioning_message TEXT,
                provisioning_error TEXT,
                tokens_24h INTEGER DEFAULT 0,
                memory_mb INTEGER DEFAULT 128,
                cpu_pct REAL DEFAULT 0.0,
                uptime_hours INTEGER DEFAULT 0,
                auto_update BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_instances_status ON instances(status);
            CREATE INDEX IF NOT EXISTS idx_instances_host_port ON instances(host_port) WHERE host_port IS NOT NULL;

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_audit_events_instance ON audit_events(instance_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor);
        ").map_err(|e| StoreError::Internal(format!("schema: {e}")))?;

        // Migration: add custom domain columns (idempotent)
        Self::migrate_custom_domain(conn)?;
        // Migration: add terminal workspaces table (idempotent)
        Self::migrate_terminal_conversations(conn)?;
        // Migration: add macOS VM columns (idempotent)
        Self::migrate_macos_columns(conn)?;
        // Migration: add vm_snapshots table (idempotent)
        Self::migrate_vm_snapshots(conn)?;
        // Migration 002: add guest_os and aux_storage_path columns (idempotent)
        Self::migrate_guest_os_columns(conn)?;
        // Migration: add users table (idempotent)
        Self::migrate_users_table(conn)?;
        // Migration: add owner_id column to instances (idempotent)
        Self::migrate_owner_id(conn)?;
        // Migration: add invites table (idempotent)
        Self::migrate_invites_table(conn)?;
        // Migration: add resource config columns (cpu_cores, ram_config_mb, disk_gb)
        Self::migrate_resource_config(conn)?;
        // Migration: add provisioning_phase column for mobile Live Activity
        Self::migrate_provisioning_phase(conn)?;
        // Migration: add resource_leases table
        Self::migrate_resource_leases(conn)?;
        // Migration: add instance_events table
        Self::migrate_instance_events(conn)?;
        // Migration: add desired_state, observed_state, deleted_at columns
        Self::migrate_desired_observed_state(conn)?;
        // Migration: add household instance scope columns
        Self::migrate_household_scope(conn)?;
        // Migration: add public claw site mappings
        Self::migrate_public_sites(conn)?;
        // Migration: add Cloudflare tunnel config (single-row table for the
        // operator's API-driven setup)
        Self::migrate_cloudflare_config(conn)?;
        // Migration: add provisioning_failure_code column (idempotent)
        Self::migrate_provisioning_failure_code(conn)?;
        // Migration: add the shareable_apps Share identity authority (D6)
        Self::migrate_shareable_apps(conn)?;
        Ok(())
    }

    /// Single-row table holding the operator's Cloudflare tunnel binding.
    /// `CHECK(id = 1)` enforces "at most one config" — this MVP supports one
    /// tunnel per host. The API token itself is NOT stored here; it lives on
    /// disk under `cfg.secretsDir` so it can be revoked by file deletion.
    fn migrate_cloudflare_config(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cloudflare_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                account_id TEXT NOT NULL,
                zone_id TEXT NOT NULL,
                zone_name TEXT NOT NULL,
                tunnel_id TEXT NOT NULL,
                tunnel_name TEXT NOT NULL,
                configured_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .map_err(|e| StoreError::Internal(format!("migrate cloudflare_config: {e}")))?;
        Ok(())
    }

    /// Add household scope columns for rows created through household `PoP` routes.
    fn migrate_household_scope(conn: &Connection) -> Result<(), StoreError> {
        let has_household_id: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='household_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check household_id column: {e}")))?;
        let has_household_machine_id: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='household_machine_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                StoreError::Internal(format!("check household_machine_id column: {e}"))
            })?;

        if !has_household_id {
            conn.execute_batch("ALTER TABLE instances ADD COLUMN household_id TEXT;")
                .map_err(|e| StoreError::Internal(format!("migrate household_id: {e}")))?;
        }
        if !has_household_machine_id {
            conn.execute_batch("ALTER TABLE instances ADD COLUMN household_machine_id TEXT;")
                .map_err(|e| StoreError::Internal(format!("migrate household_machine_id: {e}")))?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_instances_household_scope \
                 ON instances(household_id, created_at, id) \
                 WHERE household_id IS NOT NULL AND deleted_at IS NULL;",
        )
        .map_err(|e| StoreError::Internal(format!("migrate household_scope index: {e}")))?;

        Ok(())
    }

    /// Add `custom_domain` and `cf_hostname_id` columns if they don't exist.
    fn migrate_custom_domain(conn: &Connection) -> Result<(), StoreError> {
        // Check if columns already exist by inspecting table_info
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='custom_domain'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check custom_domain column: {e}")))?;

        if !has_col {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN custom_domain TEXT;
                 ALTER TABLE instances ADD COLUMN cf_hostname_id TEXT;
                 CREATE UNIQUE INDEX IF NOT EXISTS idx_instances_custom_domain \
                     ON instances(custom_domain) WHERE custom_domain IS NOT NULL;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate custom_domain: {e}")))?;
        }

        Ok(())
    }

    /// Add macOS VM-specific columns if they don't exist (idempotent).
    fn migrate_macos_columns(conn: &Connection) -> Result<(), StoreError> {
        // Check if vm_id column already exists
        let has_vm_id: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='vm_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check vm_id column: {e}")))?;

        if !has_vm_id {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN vm_id TEXT;
                 ALTER TABLE instances ADD COLUMN pid INTEGER;
                 ALTER TABLE instances ADD COLUMN snapshot_path TEXT;
                 ALTER TABLE instances ADD COLUMN config_json TEXT;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate macos_columns: {e}")))?;
        }

        // Migration 002: add VZ NAT networking + disk path columns (idempotent)
        let needs_vz_network: bool = !conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='vm_ip'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check vm_ip column: {e}")))?;

        if needs_vz_network {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN vm_ip TEXT;
                 ALTER TABLE instances ADD COLUMN vm_mac TEXT;
                 ALTER TABLE instances ADD COLUMN efi_store_path TEXT;
                 ALTER TABLE instances ADD COLUMN cidata_iso_path TEXT;
                 ALTER TABLE instances ADD COLUMN disk_path TEXT;
                 CREATE UNIQUE INDEX IF NOT EXISTS idx_instances_vm_mac \
                     ON instances(vm_mac) WHERE vm_mac IS NOT NULL;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate vz_network_columns: {e}")))?;
        }

        Ok(())
    }

    /// Add the `provisioning_failure_code` column if it doesn't exist (idempotent).
    fn migrate_provisioning_failure_code(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') \
                 WHERE name='provisioning_failure_code'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                StoreError::Internal(format!("check provisioning_failure_code column: {e}"))
            })?;
        if !has_col {
            conn.execute_batch("ALTER TABLE instances ADD COLUMN provisioning_failure_code TEXT;")
                .map_err(|e| {
                    StoreError::Internal(format!("migrate provisioning_failure_code: {e}"))
                })?;
        }
        Ok(())
    }

    /// Add `guest_os` and `aux_storage_path` columns if they don't exist (idempotent).
    ///
    /// Implements migration 002 (`002_add_guest_os.sql`).
    fn migrate_guest_os_columns(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='guest_os'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check guest_os column: {e}")))?;

        if !has_col {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN guest_os TEXT NOT NULL DEFAULT 'linux';
                 ALTER TABLE instances ADD COLUMN aux_storage_path TEXT;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate guest_os_columns: {e}")))?;
        }

        Ok(())
    }

    /// Add `users` table if it doesn't exist (idempotent).
    fn migrate_users_table(conn: &Connection) -> Result<(), StoreError> {
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='users'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check users table: {e}")))?;

        if !table_exists {
            conn.execute_batch(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT
                );
                 CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate users_table: {e}")))?;
        }

        Ok(())
    }

    /// Add `owner_id` column to instances if it doesn't exist (idempotent).
    fn migrate_owner_id(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='owner_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check owner_id column: {e}")))?;

        if !has_col {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN owner_id TEXT REFERENCES users(id);
                 CREATE INDEX IF NOT EXISTS idx_instances_owner ON instances(owner_id);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate owner_id: {e}")))?;
        }

        Ok(())
    }

    /// Add `invites` table if it doesn't exist (idempotent).
    fn migrate_invites_table(conn: &Connection) -> Result<(), StoreError> {
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='invites'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check invites table: {e}")))?;

        if !table_exists {
            conn.execute_batch(
                "CREATE TABLE invites (
                    id TEXT PRIMARY KEY,
                    token TEXT UNIQUE NOT NULL,
                    instance_id TEXT NOT NULL REFERENCES instances(id),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    expires_at DATETIME NOT NULL,
                    redeemed_by TEXT REFERENCES users(id),
                    redeemed_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                 CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate invites_table: {e}")))?;
        }

        Ok(())
    }

    /// Add `cpu_cores`, `ram_config_mb`, and `disk_gb` columns to instances (idempotent).
    fn migrate_resource_config(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='cpu_cores'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check cpu_cores column: {e}")))?;

        if !has_col {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN cpu_cores INTEGER DEFAULT 2;
                 ALTER TABLE instances ADD COLUMN ram_config_mb INTEGER DEFAULT 2048;
                 ALTER TABLE instances ADD COLUMN disk_gb INTEGER DEFAULT 10;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate resource config: {e}")))?;
        }

        Ok(())
    }

    /// Add `provisioning_phase` column to instances (idempotent).
    fn migrate_provisioning_phase(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='provisioning_phase'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check provisioning_phase column: {e}")))?;

        if !has_col {
            conn.execute_batch("ALTER TABLE instances ADD COLUMN provisioning_phase TEXT;")
                .map_err(|e| StoreError::Internal(format!("migrate provisioning_phase: {e}")))?;
        }

        Ok(())
    }

    /// Create the `resource_leases` table (idempotent).
    fn migrate_resource_leases(conn: &Connection) -> Result<(), StoreError> {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='resource_leases'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check resource_leases table: {e}")))?;

        if !exists {
            conn.execute_batch(
                "CREATE TABLE resource_leases (
                    id TEXT PRIMARY KEY,
                    owner_type TEXT NOT NULL CHECK (owner_type IN ('instance', 'warm_pool')),
                    owner_id TEXT NOT NULL,
                    lease_kind TEXT NOT NULL CHECK (lease_kind IN ('runtime', 'storage')),
                    cpu_cores INTEGER NOT NULL CHECK (cpu_cores >= 0),
                    ram_mb INTEGER NOT NULL CHECK (ram_mb >= 0),
                    disk_gb INTEGER NOT NULL DEFAULT 0 CHECK (disk_gb >= 0),
                    acquired_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    released_at INTEGER,
                    CHECK (expires_at IS NULL OR expires_at >= acquired_at),
                    CHECK (released_at IS NULL OR released_at >= acquired_at)
                );
                CREATE UNIQUE INDEX ux_active_lease_per_owner
                    ON resource_leases(owner_type, owner_id, lease_kind)
                    WHERE released_at IS NULL;
                CREATE INDEX ix_resource_leases_active
                    ON resource_leases(released_at, expires_at);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate resource_leases: {e}")))?;
        }

        Ok(())
    }

    /// Create the `instance_events` table (idempotent).
    fn migrate_instance_events(conn: &Connection) -> Result<(), StoreError> {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='instance_events'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check instance_events table: {e}")))?;

        if !exists {
            conn.execute_batch(
                "CREATE TABLE instance_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id TEXT,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT,
                    resource_snapshot TEXT,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch())
                );
                CREATE INDEX ix_instance_events_instance ON instance_events(instance_id);
                CREATE INDEX ix_instance_events_type ON instance_events(event_type);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate instance_events: {e}")))?;
        }

        Ok(())
    }

    /// Add `desired_state`, `observed_state`, and `deleted_at` columns to instances (idempotent).
    /// Also backfills existing rows based on their `status` column.
    fn migrate_desired_observed_state(conn: &Connection) -> Result<(), StoreError> {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name='desired_state'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check desired_state column: {e}")))?;

        if !has_col {
            conn.execute_batch(
                "ALTER TABLE instances ADD COLUMN desired_state TEXT;
                 ALTER TABLE instances ADD COLUMN observed_state TEXT;
                 ALTER TABLE instances ADD COLUMN deleted_at INTEGER;",
            )
            .map_err(|e| StoreError::Internal(format!("migrate desired_observed_state: {e}")))?;
        }

        // Backfill: set desired/observed for any existing rows that are still NULL
        conn.execute_batch(
            "UPDATE instances SET desired_state = 'running', observed_state = 'active'
             WHERE status = 'active' AND desired_state IS NULL;
             UPDATE instances SET desired_state = 'running', observed_state = 'provisioning'
             WHERE status = 'provisioning' AND desired_state IS NULL;
             UPDATE instances SET desired_state = 'stopped', observed_state = 'stopped'
             WHERE status = 'stopped' AND desired_state IS NULL;
             UPDATE instances SET desired_state = 'stopped', observed_state = 'failed'
             WHERE status IN ('failed', 'error') AND desired_state IS NULL;",
        )
        .map_err(|e| StoreError::Internal(format!("backfill desired_observed_state: {e}")))?;

        Ok(())
    }

    /// Create the `public_sites` table (idempotent).
    fn migrate_public_sites(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS public_sites (
                domain TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                guest_port INTEGER NOT NULL DEFAULT 3000,
                target_host TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(instance_id) REFERENCES instances(id)
            );
            CREATE INDEX IF NOT EXISTS idx_public_sites_instance
                ON public_sites(instance_id);
            CREATE INDEX IF NOT EXISTS idx_public_sites_enabled_domain
                ON public_sites(enabled, domain);
            CREATE INDEX IF NOT EXISTS idx_public_sites_target_port
                ON public_sites(target_port);",
        )
        .map_err(|e| StoreError::Internal(format!("migrate public_sites: {e}")))?;

        // Idempotent ADD COLUMN for cloudflare_dns_record_id. Stores the id of
        // the auto-created CNAME so we can delete the right one on remove or
        // when the operator disconnects Cloudflare entirely.
        let has_cf_col: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('public_sites') \
                 WHERE name='cloudflare_dns_record_id'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                StoreError::Internal(format!("check cloudflare_dns_record_id col: {e}"))
            })?;
        if !has_cf_col {
            conn.execute_batch(
                "ALTER TABLE public_sites ADD COLUMN cloudflare_dns_record_id TEXT;",
            )
            .map_err(|e| StoreError::Internal(format!("add cloudflare_dns_record_id col: {e}")))?;
        }
        Ok(())
    }

    // ── User CRUD ─────────────────────────────────────────────────────────────

    /// Seed the bootstrap admin if no admin user exists yet. Idempotent.
    ///
    /// Returns the admin user's id (existing or newly created).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL fails.
    pub fn seed_admin(&self, username: &str) -> Result<String, StoreError> {
        let conn = self.conn()?;
        // Check for existing admin
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM users WHERE role = 'admin' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("seed_admin check: {e}")))?;

        if let Some(id) = existing {
            return Ok(id);
        }

        let id = core_rs::id::generate_id("usr");
        conn.execute(
            "INSERT INTO users (id, username, role, created_at) \
             VALUES (?1, ?2, 'admin', CURRENT_TIMESTAMP)",
            params![id, username],
        )
        .map_err(|e| StoreError::Internal(format!("seed_admin insert: {e}")))?;

        Ok(id)
    }

    /// Seed the `mac-host` instance and ensure it stays `active`. Idempotent.
    /// Only meaningful on macOS backends; `owner_id` must be the admin user's id.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or any SQL query fails.
    pub fn seed_mac_host_instance(&self, owner_id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM instances WHERE container = 'mac-host'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("seed_mac_host check: {e}")))?;
        if exists {
            // Always re-assert active status — the reconciler may have flipped it to Stopped.
            conn.execute(
                "UPDATE instances SET status = 'active', updated_at = CURRENT_TIMESTAMP \
                 WHERE container = 'mac-host' AND status != 'active'",
                [],
            )
            .map_err(|e| StoreError::Internal(format!("seed_mac_host restore: {e}")))?;
            return Ok(());
        }
        conn.execute(
            "INSERT INTO instances \
             (id, name, container, claw_type, status, guest_os, owner_id, created_at, updated_at) \
             VALUES ('inst-mac-host', 'Mac Host', 'mac-host', 'mac-host', 'active', 'macos', ?1, \
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![owner_id],
        )
        .map_err(|e| StoreError::Internal(format!("seed_mac_host insert: {e}")))?;
        Ok(())
    }

    /// Give the seeded `mac-host` row the household scope it was born without.
    ///
    /// `seed_mac_host_instance` runs at engine start (main.rs, before the
    /// household is loaded at `bootstrap_household`), so it cannot know the
    /// household id and inserts the row unscoped. `list_for_household` filters
    /// on `household_id`, so the row is invisible to the owner's Share picker —
    /// which is why sharing an app shows "No apps to share yet" on a machine
    /// that plainly has a running mac-host.
    ///
    /// Stamping rather than widening the query is deliberate: an unscoped row
    /// belongs to no household, and `list_for_household` should keep saying so.
    /// The row is given an owner here, once, when one is actually known.
    ///
    /// Only stamps a row that is still fully unscoped — both columns null. A
    /// row already carrying a household, or one carrying a machine id without a
    /// household, is left alone and reported as not stamped: a partially scoped
    /// row is ambiguous, and guessing at its owner is exactly the mistake this
    /// is meant to prevent.
    ///
    /// Returns whether a row was stamped.
    pub fn stamp_mac_host_household(
        &self,
        household_id: &str,
        household_machine_id: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let changed = conn
            .execute(
                "UPDATE instances SET household_id = ?1, household_machine_id = ?2, \
                 updated_at = CURRENT_TIMESTAMP \
                 WHERE container = 'mac-host' \
                   AND household_id IS NULL AND household_machine_id IS NULL \
                   AND deleted_at IS NULL",
                params![household_id, household_machine_id],
            )
            .map_err(|e| StoreError::Internal(format!("stamp_mac_host_household: {e}")))?;
        Ok(changed > 0)
    }

    // ── Shareable app identity authority (D6) ─────────────────────────────

    /// Pinned D6 schema: the Share's own identity authority. `app_id` is
    /// CSPRNG-random, immutable, and NEVER derived from any name; the partial
    /// unique index keeps at most one LIVE binding per instance while letting
    /// a tombstone coexist with a fresh binding. `host_port` deliberately
    /// stays out: it is runtime readiness, read live from `instances`.
    fn migrate_shareable_apps(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS shareable_apps (
                app_id       TEXT PRIMARY KEY,
                instance_id  TEXT NOT NULL,
                household_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                resource     TEXT NOT NULL,
                retired_at   INTEGER,
                created_at   INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_shareable_apps_live_instance
                ON shareable_apps(instance_id) WHERE retired_at IS NULL;
            CREATE INDEX IF NOT EXISTS ix_shareable_apps_household
                ON shareable_apps(household_id);",
        )
        .map_err(|e| StoreError::Internal(format!("migrate shareable_apps: {e}")))?;
        Ok(())
    }

    /// Lazily bind a household-scoped instance to a stable Share identity.
    ///
    /// The instance's OWN row is the authority, proven inside this same
    /// transaction BEFORE any binding decision: the row must be live
    /// (`deleted_at IS NULL`) and stamped with exactly this `household_id`.
    /// Unknown, deleted, unscoped, or foreign instances are one uniform
    /// fail-closed `InstanceNotFound` — they never create a binding and they
    /// never tombstone someone else's. After that proof, a LIVE binding in
    /// the same household is returned read-through (`display_name` is never
    /// re-synced from `instances.name`); a live binding from a DIFFERENT
    /// household is stale (the instance was re-scoped, e.g. after a re-pair)
    /// and is tombstoned here before a fresh `app_id` is minted. A tombstoned
    /// binding is never revived. The initial `display_name` derives from the
    /// instance row's name ONCE; the resource is pinned to `clawsite`.
    pub fn ensure_shareable_app(
        &self,
        instance_id: &str,
        household_id: &str,
    ) -> Result<ShareableAppRow, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app begin: {e}")))?;
        // 1. Prove instance authority FIRST, in the same tx: live row scoped
        //    to exactly this household. Anything else is uniform fail-closed.
        let instance = tx
            .query_row(
                &format!(
                    "SELECT {INSTANCE_COLS} FROM instances \
                     WHERE id = ?1 AND deleted_at IS NULL"
                ),
                params![instance_id],
                row_to_instance,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app instance: {e}")))?;
        let instance = match instance {
            Some(row) if row.household_id.as_deref() == Some(household_id) => row,
            _ => return Err(StoreError::InstanceNotFound),
        };
        // 2. Only now may a binding decision happen.
        let live = tx
            .query_row(
                "SELECT app_id, instance_id, household_id, display_name, resource, \
                        retired_at, created_at, updated_at \
                 FROM shareable_apps WHERE instance_id = ?1 AND retired_at IS NULL",
                params![instance_id],
                shareable_app_from_row,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app lookup: {e}")))?;
        if let Some(binding) = live {
            if binding.household_id == household_id {
                tx.commit()
                    .map_err(|e| StoreError::Internal(format!("ensure_shareable_app commit: {e}")))?;
                return Ok(binding);
            }
            // Household-stale binding: tombstone before minting the fresh one.
            tx.execute(
                "UPDATE shareable_apps SET retired_at = unixepoch(), updated_at = unixepoch() \
                 WHERE app_id = ?1 AND retired_at IS NULL",
                params![binding.app_id],
            )
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app stale tombstone: {e}")))?;
        }
        let app_id = generate_shareable_app_id();
        tx.execute(
            "INSERT INTO shareable_apps \
             (app_id, instance_id, household_id, display_name, resource, retired_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, unixepoch(), unixepoch())",
            params![
                app_id,
                instance_id,
                household_id,
                instance.name,
                SHAREABLE_APP_RESOURCE_CLAWSITE
            ],
        )
        .map_err(|e| StoreError::Internal(format!("ensure_shareable_app insert: {e}")))?;
        let row = tx
            .query_row(
                "SELECT app_id, instance_id, household_id, display_name, resource, \
                        retired_at, created_at, updated_at \
                 FROM shareable_apps WHERE app_id = ?1",
                params![app_id],
                shareable_app_from_row,
            )
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app reread: {e}")))?;
        tx.commit()
            .map_err(|e| StoreError::Internal(format!("ensure_shareable_app commit: {e}")))?;
        Ok(row)
    }

    /// Strict resolution for the dial/mint path, one JOIN as pinned: `Some`
    /// only when the binding is LIVE, its household matches BOTH the caller
    /// and the instance's current scope, and the instance is not deleted.
    /// Unknown, retired, foreign, stale-scoped, or deleted are one
    /// indistinguishable fail-closed `None` — terminal. Readiness
    /// (`host_port`, status) is NOT filtered: it rides the instance row for
    /// the caller to classify as recoverable-unavailable, never terminal.
    pub fn resolve_live_shareable_app(
        &self,
        app_id: &str,
        household_id: &str,
    ) -> Result<Option<(ShareableAppRow, InstanceRow)>, StoreError> {
        let conn = self.conn()?;
        let instance_cols = INSTANCE_COLS
            .split(',')
            .map(|col| format!("i.{}", col.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        let row = conn
            .query_row(
                &format!(
                    "SELECT s.app_id, s.instance_id, s.household_id, s.display_name, s.resource, \
                            s.retired_at, s.created_at, s.updated_at, {instance_cols} \
                     FROM shareable_apps s \
                     JOIN instances i ON i.id = s.instance_id \
                     WHERE s.app_id = ?1 AND s.household_id = ?2 AND s.retired_at IS NULL \
                       AND i.deleted_at IS NULL AND i.household_id = ?2"
                ),
                params![app_id, household_id],
                |row| {
                    Ok((
                        shareable_app_from_row(row)?,
                        row_to_instance_offset(row, 8)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("resolve_shareable_app: {e}")))?;
        Ok(row)
    }

    /// The ONLY way to change a binding's display name. Scoped by household
    /// and restricted to live bindings; unknown, retired, or foreign is an
    /// indistinguishable fail-closed `InstanceNotFound`.
    pub fn rename_shareable_app(
        &self,
        app_id: &str,
        household_id: &str,
        new_display_name: &str,
    ) -> Result<(), StoreError> {
        validate_shareable_display_name(new_display_name)?;
        let conn = self.conn()?;
        let rows = conn
            .execute(
                "UPDATE shareable_apps SET display_name = ?3, updated_at = unixepoch() \
                 WHERE app_id = ?1 AND household_id = ?2 AND retired_at IS NULL",
                params![app_id, household_id, new_display_name],
            )
            .map_err(|e| StoreError::Internal(format!("rename_shareable_app: {e}")))?;
        if rows == 0 {
            return Err(StoreError::InstanceNotFound);
        }
        Ok(())
    }

    /// Look up a user by username.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_user_by_username(&self, username: &str) -> Result<Option<UserRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT id, username, role, created_at, created_by FROM users WHERE username = ?1",
            params![username],
            row_to_user,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_user_by_username: {e}")))
    }

    /// Look up a user by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_user(&self, id: &str) -> Result<Option<UserRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT id, username, role, created_at, created_by FROM users WHERE id = ?1",
            params![id],
            row_to_user,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_user: {e}")))
    }

    /// Create a new user. Returns the created `UserRow`.
    ///
    /// # Errors
    ///
    /// Returns an error if the username already exists, the lock is poisoned, or SQL fails.
    pub fn create_user(
        &self,
        username: &str,
        role: UserRole,
        created_by: Option<&str>,
    ) -> Result<UserRow, StoreError> {
        let conn = self.conn()?;
        let id = core_rs::id::generate_id("usr");
        conn.execute(
            "INSERT INTO users (id, username, role, created_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            params![id, username, role.as_str(), created_by],
        )
        .map_err(|e| StoreError::Internal(format!("create_user: {e}")))?;

        // Read back the row using the same connection (avoid re-locking)
        conn.query_row(
            "SELECT id, username, role, created_at, created_by FROM users WHERE id = ?1",
            params![id],
            row_to_user,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("create_user readback: {e}")))?
        .ok_or_else(|| StoreError::Internal("create_user: inserted row not found".into()))
    }

    /// List all users ordered by `created_at` ASC.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_users(&self) -> Result<Vec<UserRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT id, username, role, created_at, created_by FROM users ORDER BY created_at ASC")
            .map_err(|e| StoreError::Internal(format!("list_users prepare: {e}")))?;

        let rows = stmt
            .query_map([], row_to_user)
            .map_err(|e| StoreError::Internal(format!("list_users query: {e}")))?;

        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_users row: {e}"))))
            .collect()
    }

    /// Add `vm_snapshots` table if it doesn't exist (idempotent).
    fn migrate_vm_snapshots(conn: &Connection) -> Result<(), StoreError> {
        // Check if table already exists
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='vm_snapshots'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("check vm_snapshots table: {e}")))?;

        if !table_exists {
            conn.execute_batch(
                "CREATE TABLE vm_snapshots (
                    id TEXT PRIMARY KEY,
                    claw_type TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used DATETIME,
                    size_bytes INTEGER NOT NULL
                );
                 CREATE INDEX IF NOT EXISTS idx_snapshots_claw_type ON vm_snapshots(claw_type);
                 CREATE INDEX IF NOT EXISTS idx_snapshots_state ON vm_snapshots(state);",
            )
            .map_err(|e| StoreError::Internal(format!("migrate vm_snapshots: {e}")))?;
        }

        Ok(())
    }

    /// Insert a new instance row.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL insert fails (e.g. duplicate key).
    pub fn insert(&self, inst: &NewInstance<'_>) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let guest_os = inst.guest_os.unwrap_or("linux");
        conn.execute(
            "INSERT INTO instances (id, name, container, claw_type, status, \
             sunset_port_direct_date, guest_os, aux_storage_path, \
             cpu_cores, ram_config_mb, disk_gb, \
             household_id, household_machine_id, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                inst.id,
                inst.name,
                inst.container,
                inst.claw_type,
                inst.sunset_date,
                guest_os,
                inst.aux_storage_path,
                inst.cpu_cores,
                inst.ram_config_mb,
                inst.disk_gb,
                inst.household_id,
                inst.household_machine_id,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("insert: {e}")))?;
        Ok(())
    }

    /// Check if an instance exists by id or name. Returns the existing id if found.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn find_conflict(&self, id: &str, name: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn()?;
        let result: Option<String> = conn
            .query_row(
                "SELECT id FROM instances WHERE id = ?1 OR name = ?2",
                params![id, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("find_conflict: {e}")))?;
        Ok(result)
    }

    /// Get a single instance by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get(&self, id: &str) -> Result<Option<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                &format!("SELECT {INSTANCE_COLS} FROM instances WHERE id = ?1"),
                params![id],
                row_to_instance,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("get: {e}")))?;
        Ok(result)
    }

    /// Get a single instance by container name.
    ///
    /// The `container` column has a UNIQUE constraint, so this returns at most one row.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_by_container(&self, container: &str) -> Result<Option<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            &format!("SELECT {INSTANCE_COLS} FROM instances WHERE container = ?1"),
            params![container],
            row_to_instance,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_by_container: {e}")))
    }

    /// Get a non-deleted instance by container when it belongs to the local household.
    ///
    /// The container column is globally unique in the local DB, but household
    /// routes must not use the unscoped `get_by_container` helper. Missing,
    /// foreign-household, legacy-unscoped, and soft-deleted rows all return
    /// `Ok(None)` so callers can expose a uniform 404.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_for_household_by_container(
        &self,
        container: &str,
        household_id: &str,
    ) -> Result<Option<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            &format!(
                "SELECT {INSTANCE_COLS} FROM instances \
                 WHERE container = ?1 AND household_id = ?2 AND deleted_at IS NULL"
            ),
            params![container, household_id],
            row_to_instance,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_for_household_by_container: {e}")))
    }

    /// Get a non-deleted instance by id when it belongs to the local household.
    ///
    /// Mutating household routes use this stricter helper instead of the
    /// status helper, so legacy/unscoped rows remain readable by the Fase 2
    /// fallback but cannot be mutated through owner-`PoP`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_for_household_by_id(
        &self,
        id: &str,
        household_id: &str,
    ) -> Result<Option<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            &format!(
                "SELECT {INSTANCE_COLS} FROM instances \
                 WHERE id = ?1 AND household_id = ?2 AND deleted_at IS NULL"
            ),
            params![id, household_id],
            row_to_instance,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_for_household_by_id: {e}")))
    }

    /// List all instances ordered by `created_at` DESC.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list(&self) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {INSTANCE_COLS} FROM instances \
                 WHERE deleted_at IS NULL ORDER BY created_at DESC"
            ))
            .map_err(|e| StoreError::Internal(format!("list prepare: {e}")))?;

        let rows = stmt
            .query_map([], row_to_instance)
            .map_err(|e| StoreError::Internal(format!("list query: {e}")))?;

        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list row: {e}"))))
            .collect()
    }

    /// List non-deleted instances stamped for a household on this local engine DB.
    ///
    /// The DB itself is local to one engine/machine. `household_machine_id` is
    /// persisted as metadata and defense-in-depth, but list membership is scoped
    /// by `household_id` only so restored/imported local rows from the same
    /// household remain visible.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_for_household(&self, household_id: &str) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {INSTANCE_COLS} FROM instances \
                 WHERE household_id = ?1 AND deleted_at IS NULL \
                 ORDER BY created_at DESC"
            ))
            .map_err(|e| StoreError::Internal(format!("list_for_household prepare: {e}")))?;

        let rows = stmt
            .query_map(params![household_id], row_to_instance)
            .map_err(|e| StoreError::Internal(format!("list_for_household query: {e}")))?;

        rows.map(|row| {
            row.map_err(|e| StoreError::Internal(format!("list_for_household row: {e}")))
        })
        .collect()
    }

    /// Get a non-deleted instance when it is scoped to the supplied household.
    ///
    /// Strict rule (security verdict, 2026-08): a row without `household_id`
    /// belongs to NO household — unscoped rows are hidden here exactly as
    /// [`Self::list_for_household`] hides them, so status and listing answer
    /// the same question the same way by construction. Legacy unscoped rows
    /// regain visibility only by being stamped via
    /// [`Self::stamp_mac_host_household`] once the household is
    /// loaded and the assignment is unambiguous.
    ///
    /// Partially-scoped rows and rows scoped to another household are hidden.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_for_household_status(
        &self,
        id: &str,
        household_id: &str,
    ) -> Result<Option<InstanceRow>, StoreError> {
        let Some(row) = self.get(id)? else {
            return Ok(None);
        };
        if row.deleted_at.is_some() {
            return Ok(None);
        }
        match &row.household_id {
            Some(row_household) if row_household == household_id => Ok(Some(row)),
            _ => Ok(None),
        }
    }

    /// List all instances including soft-deleted ones. For admin/audit views.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_including_deleted(&self) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {INSTANCE_COLS} FROM instances ORDER BY created_at DESC"
            ))
            .map_err(|e| StoreError::Internal(format!("list_including_deleted prepare: {e}")))?;

        let rows = stmt
            .query_map([], row_to_instance)
            .map_err(|e| StoreError::Internal(format!("list_including_deleted query: {e}")))?;

        rows.map(|row| {
            row.map_err(|e| StoreError::Internal(format!("list_including_deleted row: {e}")))
        })
        .collect()
    }

    /// Paginated instance list for admins. Returns up to `limit + 1` rows
    /// so the caller can detect `has_more`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_paginated(
        &self,
        limit: usize,
        cursor: Option<(&str, &str)>,
    ) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let fetch = limit + 1;
        if let Some((created_at, id)) = cursor {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {INSTANCE_COLS} FROM instances \
                     WHERE deleted_at IS NULL AND (created_at, id) < (?1, ?2) \
                     ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| StoreError::Internal(format!("list_paginated prepare: {e}")))?;
            let rows = stmt
                .query_map(params![created_at, id], row_to_instance)
                .map_err(|e| StoreError::Internal(format!("list_paginated query: {e}")))?;
            rows.map(|r| r.map_err(|e| StoreError::Internal(format!("list_paginated row: {e}"))))
                .collect()
        } else {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {INSTANCE_COLS} FROM instances \
                     WHERE deleted_at IS NULL \
                     ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| StoreError::Internal(format!("list_paginated prepare: {e}")))?;
            let rows = stmt
                .query_map([], row_to_instance)
                .map_err(|e| StoreError::Internal(format!("list_paginated query: {e}")))?;
            rows.map(|r| r.map_err(|e| StoreError::Internal(format!("list_paginated row: {e}"))))
                .collect()
        }
    }

    /// Update instance status fields and `job_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn update_status(&self, update: &StatusUpdate<'_>) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let msg = non_empty(update.message);
        let err_msg = non_empty(update.error);
        let jid = non_empty(update.job_id);
        // Map InstanceStatus → observed_state string
        let observed = match update.status {
            InstanceStatus::Provisioning => "provisioning",
            InstanceStatus::Active => "active",
            InstanceStatus::Stopped => "stopped",
            InstanceStatus::Failed => "failed",
        };
        conn.execute(
            // `provisioning_failure_code=NULL` clears any stamped code on every
            // status transition; a dedicated setter re-stamps it on failure.
            "UPDATE instances SET status=?1, provisioning_message=?2, provisioning_error=?3, \
             provisioning_phase=?4, job_id=?5, observed_state=?7, \
             provisioning_failure_code=NULL, \
             updated_at=CURRENT_TIMESTAMP WHERE id=?6",
            params![
                update.status.as_str(),
                msg,
                err_msg,
                non_empty(update.phase),
                jid,
                update.id,
                observed
            ],
        )
        .map_err(|e| StoreError::Internal(format!("update_status: {e}")))?;
        Ok(())
    }

    /// Stamp (or clear) the sanitized `provisioning_failure_code` for an
    /// instance. Independent of [`update_status`] so the failure-code stamp
    /// never masks the primary status update: callers mark the instance Failed
    /// first, then best-effort attach the code.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the UPDATE fails.
    pub fn set_provisioning_failure_code(
        &self,
        id: &str,
        code: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET provisioning_failure_code=?1 WHERE id=?2",
            params![code, id],
        )
        .map_err(|e| StoreError::Internal(format!("set_provisioning_failure_code: {e}")))?;
        Ok(())
    }

    /// Persist the `host_port` for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn update_port(&self, id: &str, port: i64) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET host_port=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2",
            params![port, id],
        )
        .map_err(|e| StoreError::Internal(format!("update_port: {e}")))?;
        Ok(())
    }

    /// Clear the `host_port` for an instance (e.g. on VM creation failure).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn clear_port(&self, id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET host_port=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![id],
        )
        .map_err(|e| StoreError::Internal(format!("clear_port: {e}")))?;
        Ok(())
    }

    // ── Resource allocation queries ─────────────────────────────────────
    //
    // NOTE: CPU/RAM/disk allocation is now tracked via `resource_leases` table.
    // See `sum_active_runtime_leases()`, `sum_active_storage_leases()`, and
    // `count_active_runtime_leases_by_guest_os()` in the Resource Lease section.

    /// Count instances in runtime state (provisioning + active).
    ///
    /// # Errors
    /// Returns [`StoreError`] if the query fails.
    pub fn count_active_instances(&self) -> Result<i64, StoreError> {
        let conn = self.conn()?;
        let count = conn
            .query_row(
                "SELECT COUNT(*) FROM instances \
                 WHERE status IN ('provisioning', 'active') AND deleted_at IS NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| StoreError::Internal(format!("count_active_instances: {e}")))?;
        Ok(count)
    }

    /// Delete an instance row.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Internal(format!("delete begin: {e}")))?;
        // Tombstone any live Share bindings atomically BEFORE the row removal
        // (D6): there is no bare-delete path, so a hard delete can never leave
        // a resolvable binding pointing at a gone — or future same-id —
        // instance.
        tx.execute(
            "UPDATE shareable_apps SET retired_at = unixepoch(), updated_at = unixepoch() \
             WHERE instance_id = ?1 AND retired_at IS NULL",
            params![id],
        )
        .map_err(|e| StoreError::Internal(format!("delete binding tombstone: {e}")))?;
        tx.execute("DELETE FROM invites WHERE instance_id = ?1", params![id])
            .map_err(|e| StoreError::Internal(format!("delete invites: {e}")))?;
        tx.execute("DELETE FROM instances WHERE id = ?1", params![id])
            .map_err(|e| StoreError::Internal(format!("delete instance: {e}")))?;
        tx.commit()
            .map_err(|e| StoreError::Internal(format!("delete commit: {e}")))?;
        Ok(())
    }

    // ── Invite CRUD ───────────────────────────────────────────────────────

    /// Create a new invite for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL insert fails.
    pub fn create_invite(
        &self,
        instance_id: &str,
        created_by: &str,
        ttl_secs: u64,
    ) -> Result<InviteRow, StoreError> {
        let conn = self.conn()?;
        let id = core_rs::id::generate_id("inv");
        let token = generate_random_token();
        let ttl_str = format!("+{ttl_secs} seconds");
        conn.execute(
            "INSERT INTO invites (id, token, instance_id, created_by, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, datetime('now', ?5), CURRENT_TIMESTAMP)",
            params![id, token, instance_id, created_by, ttl_str],
        )
        .map_err(|e| StoreError::Internal(format!("create_invite: {e}")))?;

        conn.query_row(
            "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
             FROM invites WHERE id = ?1",
            params![id],
            row_to_invite,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("create_invite readback: {e}")))?
        .ok_or_else(|| StoreError::Internal("create_invite: inserted row not found".into()))
    }

    /// List all invites ordered by `created_at` DESC.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_invites(&self) -> Result<Vec<InviteRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
                 FROM invites ORDER BY created_at DESC",
            )
            .map_err(|e| StoreError::Internal(format!("list_invites prepare: {e}")))?;

        let rows = stmt
            .query_map([], row_to_invite)
            .map_err(|e| StoreError::Internal(format!("list_invites query: {e}")))?;

        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_invites row: {e}"))))
            .collect()
    }

    /// Paginated invite list. Returns up to `limit + 1` rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_invites_paginated(
        &self,
        limit: usize,
        cursor: Option<(&str, &str)>,
    ) -> Result<Vec<InviteRow>, StoreError> {
        let conn = self.conn()?;
        let fetch = limit + 1;
        if let Some((created_at, id)) = cursor {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
                     FROM invites WHERE (created_at, id) < (?1, ?2) \
                     ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| StoreError::Internal(format!("list_invites_paginated prepare: {e}")))?;
            let rows = stmt
                .query_map(params![created_at, id], row_to_invite)
                .map_err(|e| StoreError::Internal(format!("list_invites_paginated query: {e}")))?;
            rows.map(|r| {
                r.map_err(|e| StoreError::Internal(format!("list_invites_paginated row: {e}")))
            })
            .collect()
        } else {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
                     FROM invites ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| StoreError::Internal(format!("list_invites_paginated prepare: {e}")))?;
            let rows = stmt
                .query_map([], row_to_invite)
                .map_err(|e| StoreError::Internal(format!("list_invites_paginated query: {e}")))?;
            rows.map(|r| {
                r.map_err(|e| StoreError::Internal(format!("list_invites_paginated row: {e}")))
            })
            .collect()
        }
    }

    /// Look up an invite by its token.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_invite_by_token(&self, token: &str) -> Result<Option<InviteRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
             FROM invites WHERE token = ?1",
            params![token],
            row_to_invite,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_invite_by_token: {e}")))
    }

    /// Delete an invite (only if not already redeemed).
    ///
    /// Returns `true` if a row was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn delete_invite(&self, id: &str) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "DELETE FROM invites WHERE id = ?1 AND redeemed_by IS NULL",
                params![id],
            )
            .map_err(|e| StoreError::Internal(format!("delete_invite: {e}")))?;
        Ok(affected > 0)
    }

    /// Atomically redeem an invite: create user, assign instance, mark invite redeemed.
    ///
    /// Returns `(UserRow, InviteRow)` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the invite is expired/redeemed, or any DB operation fails.
    pub fn redeem_invite_atomic(
        &self,
        token: &str,
        username: &str,
        created_by: &str,
    ) -> Result<(UserRow, InviteRow), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Internal(format!("redeem_invite begin: {e}")))?;

        // 1. Find and validate invite
        let invite: InviteRow = tx
            .query_row(
                "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
                 FROM invites WHERE token = ?1",
                params![token],
                row_to_invite,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("redeem_invite lookup: {e}")))?
            .ok_or(StoreError::InstanceNotFound)?;

        if invite.redeemed_by.is_some() {
            return Err(StoreError::Internal("invite already redeemed".into()));
        }
        // Check expiry: expires_at is in SQLite datetime format
        let expired: bool = tx
            .query_row(
                "SELECT datetime(?1) < datetime('now')",
                params![invite.expires_at],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("redeem_invite expiry check: {e}")))?;
        if expired {
            return Err(StoreError::Internal("invite expired".into()));
        }

        // 2. Create user
        let user_id = core_rs::id::generate_id("usr");
        tx.execute(
            "INSERT INTO users (id, username, role, created_by, created_at) \
             VALUES (?1, ?2, 'user', ?3, CURRENT_TIMESTAMP)",
            params![user_id, username, created_by],
        )
        .map_err(|e| StoreError::Internal(format!("redeem_invite create_user: {e}")))?;

        // 3. Assign instance to new user
        tx.execute(
            "UPDATE instances SET owner_id = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![user_id, invite.instance_id],
        )
        .map_err(|e| StoreError::Internal(format!("redeem_invite set_owner: {e}")))?;

        // 4. Mark invite redeemed
        tx.execute(
            "UPDATE invites SET redeemed_by = ?1, redeemed_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![user_id, invite.id],
        )
        .map_err(|e| StoreError::Internal(format!("redeem_invite mark: {e}")))?;

        // Read back
        let user = tx
            .query_row(
                "SELECT id, username, role, created_at, created_by FROM users WHERE id = ?1",
                params![user_id],
                row_to_user,
            )
            .map_err(|e| StoreError::Internal(format!("redeem_invite readback user: {e}")))?;

        let updated_invite = tx
            .query_row(
                "SELECT id, token, instance_id, created_by, expires_at, redeemed_by, redeemed_at, created_at \
                 FROM invites WHERE id = ?1",
                params![invite.id],
                row_to_invite,
            )
            .map_err(|e| StoreError::Internal(format!("redeem_invite readback invite: {e}")))?;

        tx.commit()
            .map_err(|e| StoreError::Internal(format!("redeem_invite commit: {e}")))?;

        Ok((user, updated_invite))
    }

    // ── Instance ownership ─────────────────────────────────────────────────

    /// Set or clear the owner of an instance.
    ///
    /// Pass `None` to unassign. Returns `true` if a row was updated.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_owner(&self, instance_id: &str, owner_id: Option<&str>) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE instances SET owner_id = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
                params![owner_id, instance_id],
            )
            .map_err(|e| StoreError::Internal(format!("set_owner: {e}")))?;
        Ok(affected > 0)
    }

    /// Get the `owner_id` for an instance looked up by container name.
    ///
    /// Returns:
    /// - `Ok(Some(None))` — instance exists, unassigned
    /// - `Ok(Some(Some(id)))` — instance exists, owned by `id`
    /// - `Ok(None)` — no such container
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_owner_id_by_container(
        &self,
        container: &str,
    ) -> Result<Option<Option<String>>, StoreError> {
        let conn = self.conn()?;
        // We must distinguish "no row" from "row with NULL owner_id".
        // Using `optional()`: None = no row; Some(val) = row found.
        let result: Option<Option<String>> = conn
            .query_row(
                "SELECT owner_id FROM instances WHERE container = ?1",
                params![container],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("get_owner_id_by_container: {e}")))?;
        Ok(result)
    }

    /// List instances owned by a specific user.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_for_user(&self, user_id: &str) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {INSTANCE_COLS} FROM instances \
                 WHERE owner_id = ?1 AND deleted_at IS NULL \
                 ORDER BY created_at DESC"
            ))
            .map_err(|e| StoreError::Internal(format!("list_for_user prepare: {e}")))?;

        let rows = stmt
            .query_map(params![user_id], row_to_instance)
            .map_err(|e| StoreError::Internal(format!("list_for_user query: {e}")))?;

        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_for_user row: {e}"))))
            .collect()
    }

    /// Paginated instance list for a specific user.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_for_user_paginated(
        &self,
        user_id: &str,
        limit: usize,
        cursor: Option<(&str, &str)>,
    ) -> Result<Vec<InstanceRow>, StoreError> {
        let conn = self.conn()?;
        let fetch = limit + 1;
        if let Some((created_at, id)) = cursor {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {INSTANCE_COLS} FROM instances \
                     WHERE owner_id = ?1 AND deleted_at IS NULL AND (created_at, id) < (?2, ?3) \
                     ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| {
                    StoreError::Internal(format!("list_for_user_paginated prepare: {e}"))
                })?;
            let rows = stmt
                .query_map(params![user_id, created_at, id], row_to_instance)
                .map_err(|e| StoreError::Internal(format!("list_for_user_paginated query: {e}")))?;
            rows.map(|r| {
                r.map_err(|e| StoreError::Internal(format!("list_for_user_paginated row: {e}")))
            })
            .collect()
        } else {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {INSTANCE_COLS} FROM instances \
                     WHERE owner_id = ?1 AND deleted_at IS NULL \
                     ORDER BY created_at DESC, id DESC LIMIT {fetch}"
                ))
                .map_err(|e| {
                    StoreError::Internal(format!("list_for_user_paginated prepare: {e}"))
                })?;
            let rows = stmt
                .query_map(params![user_id], row_to_instance)
                .map_err(|e| StoreError::Internal(format!("list_for_user_paginated query: {e}")))?;
            rows.map(|r| {
                r.map_err(|e| StoreError::Internal(format!("list_for_user_paginated row: {e}")))
            })
            .collect()
        }
    }

    /// List containers accessible to a user based on their role.
    ///
    /// - Admin: sees containers of unassigned (`owner_id` IS NULL) active instances
    /// - User: sees containers of their own active instances
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_accessible_containers(
        &self,
        user_id: &str,
        role: UserRole,
    ) -> Result<Vec<String>, StoreError> {
        let conn = self.conn()?;
        let sql = match role {
            UserRole::Admin => {
                "SELECT DISTINCT container FROM instances \
                 WHERE owner_id IS NULL AND status = 'active' AND deleted_at IS NULL"
            }
            UserRole::User => {
                "SELECT DISTINCT container FROM instances \
                 WHERE owner_id = ?1 AND status = 'active' AND deleted_at IS NULL"
            }
        };
        let mut stmt = conn.prepare(sql).map_err(|e| {
            StoreError::Internal(format!("list_accessible_containers prepare: {e}"))
        })?;

        let err = |e| StoreError::Internal(format!("list_accessible_containers: {e}"));
        let mut result = Vec::new();
        match role {
            UserRole::Admin => {
                let mut rows = stmt.query([]).map_err(err)?;
                while let Some(row) = rows.next().map_err(err)? {
                    result.push(row.get::<_, String>(0).map_err(err)?);
                }
            }
            UserRole::User => {
                let mut rows = stmt.query(params![user_id]).map_err(err)?;
                while let Some(row) = rows.next().map_err(err)? {
                    result.push(row.get::<_, String>(0).map_err(err)?);
                }
            }
        }
        Ok(result)
    }

    /// Get the `host_port` for an instance (returns 0 if NULL).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_host_port(&self, id: &str) -> Result<i64, StoreError> {
        let conn = self.conn()?;
        let result: Option<i64> = conn
            .query_row(
                "SELECT COALESCE(host_port, 0) FROM instances WHERE id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("get_host_port: {e}")))?;
        Ok(result.unwrap_or(0))
    }

    /// Update the `job_id` for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_job_id(&self, id: &str, job_id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET job_id=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2",
            params![job_id, id],
        )
        .map_err(|e| StoreError::Internal(format!("set_job_id: {e}")))?;
        Ok(())
    }

    /// Set the custom domain and Cloudflare hostname ID for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_custom_domain(
        &self,
        id: &str,
        custom_domain: &str,
        cf_hostname_id: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET custom_domain=?1, cf_hostname_id=?2, \
             updated_at=CURRENT_TIMESTAMP WHERE id=?3",
            params![custom_domain, cf_hostname_id, id],
        )
        .map_err(|e| StoreError::Internal(format!("set_custom_domain: {e}")))?;
        Ok(())
    }

    /// Clear the custom domain and Cloudflare hostname ID for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn clear_custom_domain(&self, id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET custom_domain=NULL, cf_hostname_id=NULL, \
             updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![id],
        )
        .map_err(|e| StoreError::Internal(format!("clear_custom_domain: {e}")))?;
        Ok(())
    }

    /// Look up the host port for an active instance by its custom domain.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn lookup_custom_domain_port(
        &self,
        custom_domain: &str,
    ) -> Result<Option<i64>, StoreError> {
        let conn = self.conn()?;
        let result: Option<i64> = conn
            .query_row(
                "SELECT host_port FROM instances \
                 WHERE custom_domain=?1 AND status='active'",
                params![custom_domain],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("lookup_custom_domain_port: {e}")))?;
        Ok(result)
    }

    // ── Public claw sites ────────────────────────────────────────────────────

    /// Insert or update a public site mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL upsert/readback fails.
    pub fn upsert_public_site(
        &self,
        site: &NewPublicSite<'_>,
    ) -> Result<PublicSiteRow, StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO public_sites \
             (domain, instance_id, guest_port, target_host, target_port, enabled, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
             ON CONFLICT(domain) DO UPDATE SET \
                instance_id=excluded.instance_id, \
                guest_port=excluded.guest_port, \
                target_host=excluded.target_host, \
                target_port=excluded.target_port, \
                enabled=excluded.enabled, \
                updated_at=CURRENT_TIMESTAMP",
            params![
                site.domain,
                site.instance_id,
                site.guest_port,
                site.target_host,
                site.target_port,
                i32::from(site.enabled),
            ],
        )
        .map_err(|e| StoreError::Internal(format!("upsert_public_site: {e}")))?;

        conn.query_row(
            "SELECT domain, instance_id, guest_port, target_host, target_port, enabled, \
             created_at, updated_at, cloudflare_dns_record_id FROM public_sites WHERE domain = ?1",
            params![site.domain],
            row_to_public_site,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("upsert_public_site readback: {e}")))?
        .ok_or_else(|| StoreError::Internal("upsert_public_site: inserted row not found".into()))
    }

    /// Return a public site by domain, regardless of enabled status or instance state.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_public_site(&self, domain: &str) -> Result<Option<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT domain, instance_id, guest_port, target_host, target_port, enabled, \
             created_at, updated_at, cloudflare_dns_record_id FROM public_sites WHERE domain = ?1",
            params![domain],
            row_to_public_site,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_public_site: {e}")))
    }

    /// List public sites configured for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_public_sites_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT domain, instance_id, guest_port, target_host, target_port, enabled, \
                 created_at, updated_at, cloudflare_dns_record_id FROM public_sites \
                 WHERE instance_id = ?1 ORDER BY domain ASC",
            )
            .map_err(|e| StoreError::Internal(format!("list_public_sites prepare: {e}")))?;
        let rows = stmt
            .query_map(params![instance_id], row_to_public_site)
            .map_err(|e| StoreError::Internal(format!("list_public_sites query: {e}")))?;
        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_public_sites row: {e}"))))
            .collect()
    }

    /// Find any enabled public site already targeting an instance guest port.
    ///
    /// Useful for sharing one Linux hostfwd across multiple domains.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn find_public_site_for_instance_guest_port(
        &self,
        instance_id: &str,
        guest_port: i64,
    ) -> Result<Option<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT domain, instance_id, guest_port, target_host, target_port, enabled, \
             created_at, updated_at, cloudflare_dns_record_id FROM public_sites \
             WHERE instance_id = ?1 AND guest_port = ?2 AND enabled = 1 \
             ORDER BY updated_at DESC LIMIT 1",
            params![instance_id, guest_port],
            row_to_public_site,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("find_public_site_for_instance_guest_port: {e}")))
    }

    /// Look up the enabled public site target for an active, non-deleted instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn lookup_public_site_target(
        &self,
        domain: &str,
    ) -> Result<Option<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT ps.domain, ps.instance_id, ps.guest_port, ps.target_host, ps.target_port, \
                    ps.enabled, ps.created_at, ps.updated_at, ps.cloudflare_dns_record_id \
             FROM public_sites ps \
             JOIN instances i ON i.id = ps.instance_id \
             WHERE ps.domain = ?1 \
               AND ps.enabled = 1 \
               AND i.status = 'active' \
               AND i.deleted_at IS NULL",
            params![domain],
            row_to_public_site,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("lookup_public_site_target: {e}")))
    }

    /// List host target ports already assigned to enabled public site mappings.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_public_site_target_ports(&self) -> Result<Vec<i64>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT target_port FROM public_sites \
                 WHERE enabled = 1 ORDER BY target_port ASC",
            )
            .map_err(|e| {
                StoreError::Internal(format!("list_public_site_target_ports prepare: {e}"))
            })?;
        let rows = stmt.query_map([], |row| row.get(0)).map_err(|e| {
            StoreError::Internal(format!("list_public_site_target_ports query: {e}"))
        })?;
        rows.map(|row| {
            row.map_err(|e| StoreError::Internal(format!("list_public_site_target_ports row: {e}")))
        })
        .collect()
    }

    /// Delete a public site mapping for an instance.
    ///
    /// Returns `Some(row)` with the deleted row when it existed (so the caller
    /// can call Cloudflare to remove the matching CNAME), or `None` if no row
    /// matched.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL fails.
    pub fn delete_public_site(
        &self,
        instance_id: &str,
        domain: &str,
    ) -> Result<Option<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        // Read-then-delete instead of DELETE ... RETURNING so we stay portable
        // with the rusqlite version pinned in the workspace.
        let row = conn
            .query_row(
                "SELECT domain, instance_id, guest_port, target_host, target_port, enabled, \
                 created_at, updated_at, cloudflare_dns_record_id FROM public_sites \
                 WHERE instance_id = ?1 AND domain = ?2",
                params![instance_id, domain],
                row_to_public_site,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("delete_public_site read: {e}")))?;
        if row.is_none() {
            return Ok(None);
        }
        conn.execute(
            "DELETE FROM public_sites WHERE instance_id = ?1 AND domain = ?2",
            params![instance_id, domain],
        )
        .map_err(|e| StoreError::Internal(format!("delete_public_site: {e}")))?;
        Ok(row)
    }

    /// Set the Cloudflare DNS record id for an existing public site row.
    ///
    /// Called after the upsert succeeded and we successfully created the CNAME
    /// in Cloudflare. Two-step (upsert → create CNAME → set id) keeps the
    /// invariant: the column is only populated when a real CNAME exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_public_site_cloudflare_record(
        &self,
        domain: &str,
        record_id: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE public_sites SET cloudflare_dns_record_id = ?1 WHERE domain = ?2",
            params![record_id, domain],
        )
        .map_err(|e| StoreError::Internal(format!("set_public_site_cloudflare_record: {e}")))?;
        Ok(())
    }

    /// Null out `cloudflare_dns_record_id` for every public site. Called when
    /// the operator disconnects Cloudflare — we don't drop the rows themselves
    /// (sites can survive without a public route, as 502s) but the stored
    /// record ids point at a tunnel that no longer exists.
    ///
    /// Returns the list of (domain, `record_id`) pairs that were cleared, so the
    /// caller can attempt to delete them via the Cloudflare API before dropping
    /// the API token.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL fails.
    pub fn clear_all_public_site_cloudflare_records(
        &self,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT domain, cloudflare_dns_record_id FROM public_sites \
                 WHERE cloudflare_dns_record_id IS NOT NULL",
            )
            .map_err(|e| StoreError::Internal(format!("clear_all_cf_records prep: {e}")))?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| StoreError::Internal(format!("clear_all_cf_records query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Internal(format!("clear_all_cf_records collect: {e}")))?;
        conn.execute(
            "UPDATE public_sites SET cloudflare_dns_record_id = NULL \
             WHERE cloudflare_dns_record_id IS NOT NULL",
            [],
        )
        .map_err(|e| StoreError::Internal(format!("clear_all_cf_records update: {e}")))?;
        Ok(rows)
    }

    // ── Cloudflare config CRUD ────────────────────────────────────────────────

    /// Read the operator's Cloudflare binding (or `None` if not yet
    /// configured). Single-row table — the SELECT is bounded.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_cloudflare_config(&self) -> Result<Option<CloudflareConfigRow>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT account_id, zone_id, zone_name, tunnel_id, tunnel_name, configured_at \
             FROM cloudflare_config WHERE id = 1",
            [],
            |row| {
                Ok(CloudflareConfigRow {
                    account_id: row.get(0)?,
                    zone_id: row.get(1)?,
                    zone_name: row.get(2)?,
                    tunnel_id: row.get(3)?,
                    tunnel_name: row.get(4)?,
                    configured_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_cloudflare_config: {e}")))
    }

    /// Insert or replace the single Cloudflare config row. Idempotent — a
    /// re-setup overwrites the previous binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL upsert fails.
    pub fn upsert_cloudflare_config(&self, cfg: &CloudflareConfigRow) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO cloudflare_config \
             (id, account_id, zone_id, zone_name, tunnel_id, tunnel_name, configured_at) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP) \
             ON CONFLICT(id) DO UPDATE SET \
                account_id = excluded.account_id, \
                zone_id    = excluded.zone_id, \
                zone_name  = excluded.zone_name, \
                tunnel_id  = excluded.tunnel_id, \
                tunnel_name = excluded.tunnel_name, \
                configured_at = CURRENT_TIMESTAMP",
            params![
                cfg.account_id,
                cfg.zone_id,
                cfg.zone_name,
                cfg.tunnel_id,
                cfg.tunnel_name
            ],
        )
        .map_err(|e| StoreError::Internal(format!("upsert_cloudflare_config: {e}")))?;
        Ok(())
    }

    /// Drop the Cloudflare config row. Used by the disconnect flow after the
    /// caller has already torn down the tunnel and removed the CNAMEs via API.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn clear_cloudflare_config(&self) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM cloudflare_config WHERE id = 1", [])
            .map_err(|e| StoreError::Internal(format!("clear_cloudflare_config: {e}")))?;
        Ok(())
    }

    /// All enabled public sites whose backing instance still exists (not soft-deleted).
    ///
    /// Used by the cloudflared sync to regenerate the ingress block. Stopped or
    /// failed instances are still included: cloudflared will return 502 until the
    /// instance is restarted, which is preferable to silently dropping the entry
    /// and breaking the public URL on every status flap.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_all_enabled_public_sites(&self) -> Result<Vec<PublicSiteRow>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT ps.domain, ps.instance_id, ps.guest_port, ps.target_host, ps.target_port, \
                        ps.enabled, ps.created_at, ps.updated_at, ps.cloudflare_dns_record_id \
                 FROM public_sites ps \
                 JOIN instances i ON i.id = ps.instance_id \
                 WHERE ps.enabled = 1 AND i.deleted_at IS NULL \
                 ORDER BY ps.domain ASC",
            )
            .map_err(|e| {
                StoreError::Internal(format!("list_all_enabled_public_sites prepare: {e}"))
            })?;
        let rows = stmt.query_map([], row_to_public_site).map_err(|e| {
            StoreError::Internal(format!("list_all_enabled_public_sites query: {e}"))
        })?;
        rows.map(|row| {
            row.map_err(|e| StoreError::Internal(format!("list_all_enabled_public_sites row: {e}")))
        })
        .collect()
    }

    /// Get the `cf_hostname_id` for an instance, if one is set.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_cf_hostname_id(&self, id: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn()?;
        let result: Option<Option<String>> = conn
            .query_row(
                "SELECT cf_hostname_id FROM instances WHERE id=?1",
                params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("get_cf_hostname_id: {e}")))?;
        // Flatten: None (no row) or Some(None) (NULL column) → None
        Ok(result.flatten())
    }

    /// Update `auto_update` flag for an instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn update_auto_update(&self, id: &str, enabled: bool) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET auto_update=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2",
            params![enabled, id],
        )
        .map_err(|e| StoreError::Internal(format!("update_auto_update: {e}")))?;
        Ok(())
    }

    /// Check if any instance row has the given container name.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn has_container(&self, container: &str) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let result: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM instances WHERE container = ?1)",
                params![container],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("has_container: {e}")))?;
        Ok(result)
    }

    /// List unique container names from all instance rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_containers(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT container FROM instances WHERE deleted_at IS NULL ORDER BY container")
            .map_err(|e| StoreError::Internal(format!("list_containers prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| StoreError::Internal(format!("list_containers query: {e}")))?;
        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_containers row: {e}"))))
            .collect()
    }

    /// Count instances with the given claw type (any status).
    ///
    /// Used by the uninstall handler to prevent removing a claw type that still
    /// has instances (D7).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn count_by_claw_type(&self, claw_type: &str) -> Result<i64, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT COUNT(*) FROM instances WHERE claw_type = ?1 AND deleted_at IS NULL",
            params![claw_type],
            |row| row.get(0),
        )
        .map_err(|e| StoreError::Internal(format!("count_by_claw_type: {e}")))
    }

    /// List unique container names from active instance rows only.
    ///
    /// Filters to `status = 'active'` so the terminals page only shows
    /// containers that are actually reachable via SSH.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_active_containers(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT container FROM instances \
                 WHERE status = 'active' AND deleted_at IS NULL ORDER BY container",
            )
            .map_err(|e| StoreError::Internal(format!("list_active_containers prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| StoreError::Internal(format!("list_active_containers query: {e}")))?;
        rows.map(|row| {
            row.map_err(|e| StoreError::Internal(format!("list_active_containers row: {e}")))
        })
        .collect()
    }

    /// List audit events ordered by id DESC, limited to `limit` rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, instance_id, actor, action, detail, created_at \
                 FROM audit_events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| StoreError::Internal(format!("list_audit_events prepare: {e}")))?;
        #[allow(clippy::cast_possible_wrap)]
        // NOTE: limit is bounded by caller; i64 range is sufficient
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    instance_id: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    detail: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| StoreError::Internal(format!("list_audit_events query: {e}")))?;
        rows.map(|row| row.map_err(|e| StoreError::Internal(format!("list_audit_events row: {e}"))))
            .collect()
    }

    /// Set the VZ NAT DHCP IP and MAC address for a VM instance (macOS).
    ///
    /// Called once after the VM boots and its IP is resolved from DHCP leases.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_vm_network(&self, container: &str, ip: &str, mac: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET vm_ip=?1, vm_mac=?2, updated_at=CURRENT_TIMESTAMP \
             WHERE container=?3",
            params![ip, mac, container],
        )
        .map_err(|e| StoreError::Internal(format!("set_vm_network: {e}")))?;
        Ok(())
    }

    /// Get the DHCP-assigned VM IP for a container (macOS).
    ///
    /// Returns `None` if the VM has not yet been assigned an IP.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_vm_ip(&self, container: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn()?;
        let result: Option<Option<String>> = conn
            .query_row(
                "SELECT vm_ip FROM instances WHERE container=?1",
                params![container],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("get_vm_ip: {e}")))?;
        Ok(result.flatten())
    }

    /// Set the disk, EFI store, and cidata ISO paths for a VM instance (macOS).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_disk_paths(
        &self,
        container: &str,
        disk: &str,
        efi: &str,
        cidata: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET disk_path=?1, efi_store_path=?2, cidata_iso_path=?3, \
             updated_at=CURRENT_TIMESTAMP WHERE container=?4",
            params![disk, efi, cidata, container],
        )
        .map_err(|e| StoreError::Internal(format!("set_disk_paths: {e}")))?;
        Ok(())
    }

    /// Record an audit event (Phase 3d).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL insert fails.
    pub fn record_audit_event(
        &self,
        instance_id: Option<&str>,
        actor: &str,
        action: &str,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO audit_events (instance_id, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
            params![instance_id, actor, action, detail],
        )
        .map_err(|e| StoreError::Internal(format!("record_audit_event: {e}")))?;
        Ok(())
    }

    // ── Desired/Observed State ──────────────────────────────────────────────

    /// Set the desired state for an instance.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the update fails.
    pub fn set_desired_state(&self, id: &str, state: DesiredState) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET desired_state = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![state.as_str(), id],
        )
        .map_err(|e| StoreError::Internal(format!("set_desired_state: {e}")))?;
        Ok(())
    }

    /// Set the observed state for an instance.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the update fails.
    pub fn set_observed_state(&self, id: &str, state: ObservedState) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE instances SET observed_state = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
            params![state.as_str(), id],
        )
        .map_err(|e| StoreError::Internal(format!("set_observed_state: {e}")))?;
        Ok(())
    }

    /// Soft-delete an instance: set `desired_state=deleted`, `observed_state=deleted`,
    /// `deleted_at=unixepoch()`. The row stays for audit history.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the update fails.
    pub fn soft_delete(&self, id: &str) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Internal(format!("soft_delete begin: {e}")))?;
        let rows = tx
            .execute(
                "UPDATE instances SET desired_state = 'deleted', observed_state = 'deleted', \
             deleted_at = unixepoch(), status = 'stopped', \
             updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                params![id],
            )
            .map_err(|e| StoreError::Internal(format!("soft_delete: {e}")))?;
        if rows == 0 {
            return Err(StoreError::InstanceNotFound);
        }
        // Tombstone any live Share bindings in the SAME transaction: a deleted
        // instance must never resolve, and a same-name recreate must mint a
        // fresh app_id rather than inheriting this one's identity.
        tx.execute(
            "UPDATE shareable_apps SET retired_at = unixepoch(), updated_at = unixepoch() \
             WHERE instance_id = ?1 AND retired_at IS NULL",
            params![id],
        )
        .map_err(|e| StoreError::Internal(format!("soft_delete binding tombstone: {e}")))?;
        tx.commit()
            .map_err(|e| StoreError::Internal(format!("soft_delete commit: {e}")))?;
        Ok(())
    }

    // ── Resource Lease Operations ─────────────────────────────────────────────

    /// Create a new resource lease. Returns the generated lease id.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the insert fails (e.g. unique index violation for
    /// duplicate active lease on the same owner+kind).
    pub fn create_lease(&self, lease: &NewLease<'_>) -> Result<String, StoreError> {
        self.create_lease_str(
            lease.owner_type.as_str(),
            lease.owner_id,
            lease.lease_kind.as_str(),
            lease.cpu_cores,
            lease.ram_mb,
            lease.disk_gb,
            lease.expires_at,
        )
    }

    /// Raw `&str` create used by the store IPC receive-side, which must stay
    /// lenient — it forwards whatever wire string it was handed without
    /// rejecting unknown values. Producers should prefer the typed
    /// [`Self::create_lease`].
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the insert fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_lease_str(
        &self,
        owner_type: &str,
        owner_id: &str,
        lease_kind: &str,
        cpu_cores: i64,
        ram_mb: i64,
        disk_gb: i64,
        expires_at: Option<i64>,
    ) -> Result<String, StoreError> {
        let id = core_rs::id::generate_id("lease");
        let now = now_unix();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                owner_type,
                owner_id,
                lease_kind,
                cpu_cores,
                ram_mb,
                disk_gb,
                now,
                expires_at,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("create_lease: {e}")))?;
        Ok(id)
    }

    /// Release an active lease by setting `released_at`. Returns whether a row was affected.
    ///
    /// Idempotent: returns `false` if no matching active lease exists.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn release_lease(
        &self,
        owner_type: LeaseOwnerType,
        owner_id: &str,
        lease_kind: LeaseKind,
    ) -> Result<bool, StoreError> {
        self.release_lease_str(owner_type.as_str(), owner_id, lease_kind.as_str())
    }

    /// Raw `&str` release used by the store IPC receive-side (kept lenient).
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn release_lease_str(
        &self,
        owner_type: &str,
        owner_id: &str,
        lease_kind: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE resource_leases SET released_at = unixepoch() \
                 WHERE owner_type = ?1 AND owner_id = ?2 AND lease_kind = ?3 \
                 AND released_at IS NULL",
                params![owner_type, owner_id, lease_kind],
            )
            .map_err(|e| StoreError::Internal(format!("release_lease: {e}")))?;
        Ok(affected > 0)
    }

    /// Release all active leases for an owner. Returns the number of leases released.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn release_all_leases(
        &self,
        owner_type: LeaseOwnerType,
        owner_id: &str,
    ) -> Result<u32, StoreError> {
        self.release_all_leases_str(owner_type.as_str(), owner_id)
    }

    /// Raw `&str` release-all used by the store IPC receive-side (kept lenient).
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn release_all_leases_str(
        &self,
        owner_type: &str,
        owner_id: &str,
    ) -> Result<u32, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE resource_leases SET released_at = unixepoch() \
                 WHERE owner_type = ?1 AND owner_id = ?2 AND released_at IS NULL",
                params![owner_type, owner_id],
            )
            .map_err(|e| StoreError::Internal(format!("release_all_leases: {e}")))?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(affected as u32)
    }

    /// Extend a lease's expiration time. Returns whether a row was affected.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn extend_lease(
        &self,
        owner_type: &str,
        owner_id: &str,
        lease_kind: &str,
        new_expires_at: i64,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE resource_leases SET expires_at = ?4 \
                 WHERE owner_type = ?1 AND owner_id = ?2 AND lease_kind = ?3 \
                 AND released_at IS NULL",
                params![owner_type, owner_id, lease_kind, new_expires_at],
            )
            .map_err(|e| StoreError::Internal(format!("extend_lease: {e}")))?;
        Ok(affected > 0)
    }

    /// Finalize a lease by clearing its expiration (provisioning complete). Returns whether
    /// a row was affected.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn finalize_lease(
        &self,
        owner_type: &str,
        owner_id: &str,
        lease_kind: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE resource_leases SET expires_at = NULL \
                 WHERE owner_type = ?1 AND owner_id = ?2 AND lease_kind = ?3 \
                 AND released_at IS NULL",
                params![owner_type, owner_id, lease_kind],
            )
            .map_err(|e| StoreError::Internal(format!("finalize_lease: {e}")))?;
        Ok(affected > 0)
    }

    /// Sum CPU and RAM of all active runtime leases (unreleased and unexpired).
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn sum_active_runtime_leases(&self) -> Result<(i64, i64), StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT COALESCE(SUM(cpu_cores), 0), COALESCE(SUM(ram_mb), 0) \
             FROM resource_leases \
             WHERE released_at IS NULL AND lease_kind = 'runtime' \
             AND (expires_at IS NULL OR expires_at > unixepoch())",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|e| StoreError::Internal(format!("sum_active_runtime_leases: {e}")))
    }

    /// Sum disk GB of all active storage leases (unreleased).
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn sum_active_storage_leases(&self) -> Result<i64, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT COALESCE(SUM(disk_gb), 0) \
             FROM resource_leases \
             WHERE released_at IS NULL AND lease_kind = 'storage'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| StoreError::Internal(format!("sum_active_storage_leases: {e}")))
    }

    /// Count active runtime leases for instances with the given `guest_os`.
    /// Used for macOS 2-VM slot enforcement.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn count_active_runtime_leases_by_guest_os(
        &self,
        guest_os: &str,
    ) -> Result<i64, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT COUNT(*) FROM resource_leases rl \
             LEFT JOIN instances i \
               ON rl.owner_type = 'instance' AND rl.owner_id = i.id \
             WHERE rl.released_at IS NULL AND rl.lease_kind = 'runtime' \
             AND (rl.expires_at IS NULL OR rl.expires_at > unixepoch()) \
             AND ( \
               (rl.owner_type = 'instance' AND i.guest_os = ?1) \
               OR (rl.owner_type = 'warm_pool' AND ?1 = 'macos') \
             )",
            params![guest_os],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| StoreError::Internal(format!("count_active_runtime_leases_by_guest_os: {e}")))
    }

    /// Fetch all active leases for a specific owner.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn active_leases_for_owner(
        &self,
        owner_type: &str,
        owner_id: &str,
    ) -> Result<Vec<ResourceLease>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, \
                 acquired_at, expires_at, released_at \
                 FROM resource_leases \
                 WHERE owner_type = ?1 AND owner_id = ?2 AND released_at IS NULL",
            )
            .map_err(|e| StoreError::Internal(format!("active_leases_for_owner prepare: {e}")))?;
        let rows = stmt
            .query_map(params![owner_type, owner_id], row_to_lease)
            .map_err(|e| StoreError::Internal(format!("active_leases_for_owner query: {e}")))?;
        let mut leases = Vec::new();
        for row in rows {
            leases.push(row.map_err(|e| StoreError::Internal(format!("lease row parse: {e}")))?);
        }
        Ok(leases)
    }

    /// Find expired runtime leases (unreleased but past their expiration time).
    /// Used by the provisioning reaper.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn expired_runtime_leases(&self) -> Result<Vec<ResourceLease>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, \
                 acquired_at, expires_at, released_at \
                 FROM resource_leases \
                 WHERE released_at IS NULL AND lease_kind = 'runtime' \
                 AND expires_at IS NOT NULL AND expires_at <= unixepoch()",
            )
            .map_err(|e| StoreError::Internal(format!("expired_runtime_leases prepare: {e}")))?;
        let rows = stmt
            .query_map([], row_to_lease)
            .map_err(|e| StoreError::Internal(format!("expired_runtime_leases query: {e}")))?;
        let mut leases = Vec::new();
        for row in rows {
            leases.push(row.map_err(|e| StoreError::Internal(format!("lease row parse: {e}")))?);
        }
        Ok(leases)
    }

    /// Check whether an active lease exists for a specific owner+kind.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn has_active_lease(
        &self,
        owner_type: LeaseOwnerType,
        owner_id: &str,
        lease_kind: LeaseKind,
    ) -> Result<bool, StoreError> {
        self.has_active_lease_str(owner_type.as_str(), owner_id, lease_kind.as_str())
    }

    /// Raw `&str` active-lease check. Used by tests to assert the exact stored
    /// wire bytes; not reached by IPC.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn has_active_lease_str(
        &self,
        owner_type: &str,
        owner_id: &str,
        lease_kind: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM resource_leases \
             WHERE owner_type = ?1 AND owner_id = ?2 AND lease_kind = ?3 \
             AND released_at IS NULL \
             AND (expires_at IS NULL OR expires_at > unixepoch())",
            params![owner_type, owner_id, lease_kind],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|e| StoreError::Internal(format!("has_active_lease: {e}")))
    }

    /// Return `owner_id` values for all active warm pool leases.
    ///
    /// Used by the reconciler to detect orphaned leases (claw types that are
    /// no longer installed).
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn active_warm_pool_lease_owners(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT owner_id FROM resource_leases \
                 WHERE owner_type = 'warm_pool' AND released_at IS NULL \
                 AND (expires_at IS NULL OR expires_at > unixepoch())",
            )
            .map_err(|e| StoreError::Internal(format!("active_warm_pool_lease_owners: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StoreError::Internal(format!("active_warm_pool_lease_owners: {e}")))?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// Atomically insert an instance and create its runtime + storage leases.
    ///
    /// The runtime lease gets an expiration TTL (in seconds) for provisioning timeout.
    /// The storage lease has no expiration.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if any step fails (entire transaction is rolled back).
    pub fn insert_with_leases(
        &self,
        inst: &NewInstance<'_>,
        ttl_secs: i64,
        resource_snapshot: Option<&str>,
    ) -> Result<String, StoreError> {
        let conn = self.conn()?;
        let now = now_unix();
        let guest_os = inst.guest_os.unwrap_or("linux");
        let cpu = inst.cpu_cores.unwrap_or(2);
        let ram = inst.ram_config_mb.unwrap_or(2048);
        let disk = inst.disk_gb.unwrap_or(10);
        let runtime_lease_id = core_rs::id::generate_id("lease");
        let storage_lease_id = core_rs::id::generate_id("lease");
        let expires_at = now + ttl_secs;

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::Internal(format!("insert_with_leases begin: {e}")))?;

        // Insert instance row with desired_state=running, observed_state=provisioning
        tx.execute(
            "INSERT INTO instances (id, name, container, claw_type, status, \
             sunset_port_direct_date, guest_os, aux_storage_path, \
             cpu_cores, ram_config_mb, disk_gb, \
             desired_state, observed_state, \
             household_id, household_machine_id, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, \
             'running', 'provisioning', ?11, ?12, \
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                inst.id,
                inst.name,
                inst.container,
                inst.claw_type,
                inst.sunset_date,
                guest_os,
                inst.aux_storage_path,
                cpu,
                ram,
                disk,
                inst.household_id,
                inst.household_machine_id,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_leases instance: {e}")))?;

        // Create runtime lease (with TTL for provisioning)
        tx.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at, expires_at) \
             VALUES (?1, 'instance', ?2, 'runtime', ?3, ?4, 0, ?5, ?6)",
            params![runtime_lease_id, inst.id, cpu, ram, now, expires_at],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_leases runtime lease: {e}")))?;

        // Create storage lease (no expiration)
        tx.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at) \
             VALUES (?1, 'instance', ?2, 'storage', 0, 0, ?3, ?4)",
            params![storage_lease_id, inst.id, disk, now],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_leases storage lease: {e}")))?;

        // Record event
        tx.execute(
            "INSERT INTO instance_events (instance_id, event_type, actor, detail, resource_snapshot, created_at) \
             VALUES (?1, 'create_started', 'system', ?2, ?3, ?4)",
            params![
                inst.id,
                format!(
                    "cpu={cpu} ram={ram}MB disk={disk}GB claw={}",
                    inst.claw_type
                ),
                resource_snapshot,
                now,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_leases event: {e}")))?;

        tx.commit()
            .map_err(|e| StoreError::Internal(format!("insert_with_leases commit: {e}")))?;

        Ok(inst.id.to_string())
    }

    /// Atomically insert an instance, create its storage lease, and transfer an
    /// existing warm-pool runtime lease to the instance.
    ///
    /// This is used when admission already matched a warm-pool slot, so the
    /// create path should not allocate additional CPU/RAM. The transferred
    /// runtime lease keeps a provisioning TTL so the reaper can clean up stuck
    /// creates.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if any step fails or if the warm-pool lease is no
    /// longer present.
    pub fn insert_with_warm_pool_leases(
        &self,
        inst: &NewInstance<'_>,
        ttl_secs: i64,
        resource_snapshot: Option<&str>,
    ) -> Result<String, StoreError> {
        let conn = self.conn()?;
        let now = now_unix();
        let guest_os = inst.guest_os.unwrap_or("linux");
        let cpu = inst.cpu_cores.unwrap_or(2);
        let ram = inst.ram_config_mb.unwrap_or(2048);
        let disk = inst.disk_gb.unwrap_or(10);
        let runtime_lease_id = core_rs::id::generate_id("lease");
        let storage_lease_id = core_rs::id::generate_id("lease");
        let expires_at = now + ttl_secs;
        let warm_owner_id = WarmPoolSlotId::new(inst.claw_type).owner_id();

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::Internal(format!("insert_with_warm_pool begin: {e}")))?;

        tx.execute(
            "INSERT INTO instances (id, name, container, claw_type, status, \
             sunset_port_direct_date, guest_os, aux_storage_path, \
             cpu_cores, ram_config_mb, disk_gb, \
             desired_state, observed_state, \
             household_id, household_machine_id, \
             created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, \
             'running', 'provisioning', ?11, ?12, \
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                inst.id,
                inst.name,
                inst.container,
                inst.claw_type,
                inst.sunset_date,
                guest_os,
                inst.aux_storage_path,
                cpu,
                ram,
                disk,
                inst.household_id,
                inst.household_machine_id,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_warm_pool instance: {e}")))?;

        let released = tx
            .execute(
                "UPDATE resource_leases SET released_at = ?2 \
                 WHERE owner_type = 'warm_pool' AND owner_id = ?1 AND lease_kind = 'runtime' \
                 AND released_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())",
                params![warm_owner_id, now],
            )
            .map_err(|e| {
                StoreError::Internal(format!("insert_with_warm_pool release warm lease: {e}"))
            })?;
        if released == 0 {
            return Err(StoreError::Internal(format!(
                "insert_with_warm_pool: no active warm-pool lease for {}",
                inst.claw_type
            )));
        }

        tx.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at, expires_at) \
             VALUES (?1, 'instance', ?2, 'runtime', ?3, ?4, 0, ?5, ?6)",
            params![runtime_lease_id, inst.id, cpu, ram, now, expires_at],
        )
        .map_err(|e| {
            StoreError::Internal(format!("insert_with_warm_pool runtime lease: {e}"))
        })?;

        tx.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at) \
             VALUES (?1, 'instance', ?2, 'storage', 0, 0, ?3, ?4)",
            params![storage_lease_id, inst.id, disk, now],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_warm_pool storage lease: {e}")))?;

        tx.execute(
            "INSERT INTO instance_events (instance_id, event_type, actor, detail, resource_snapshot, created_at) \
             VALUES (?1, 'create_started', 'system', ?2, ?3, ?4)",
            params![
                inst.id,
                format!(
                    "cpu={cpu} ram={ram}MB disk={disk}GB claw={} warm_pool=true",
                    inst.claw_type
                ),
                resource_snapshot,
                now,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("insert_with_warm_pool event: {e}")))?;

        tx.commit()
            .map_err(|e| StoreError::Internal(format!("insert_with_warm_pool commit: {e}")))?;

        Ok(inst.id.to_string())
    }

    /// Transfer a warm pool lease to an instance (ownership swap in one transaction).
    ///
    /// Releases the `warm_pool` runtime lease for the given claw type and creates
    /// a new instance runtime lease with the same resources.
    ///
    /// Returns `false` if no `warm_pool` lease was found to transfer.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the transaction fails.
    pub fn transfer_warm_pool_lease(
        &self,
        claw_type: &str,
        instance_id: &str,
        cpu: i64,
        ram: i64,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let now = now_unix();
        let warm_owner_id = WarmPoolSlotId::new(claw_type).owner_id();
        let new_lease_id = core_rs::id::generate_id("lease");

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StoreError::Internal(format!("transfer_warm_pool begin: {e}")))?;

        // Release warm pool lease
        let released = tx
            .execute(
                "UPDATE resource_leases SET released_at = ?2 \
                 WHERE owner_type = 'warm_pool' AND owner_id = ?1 AND lease_kind = 'runtime' \
                 AND released_at IS NULL",
                params![warm_owner_id, now],
            )
            .map_err(|e| StoreError::Internal(format!("transfer_warm_pool release: {e}")))?;

        if released == 0 {
            tx.commit().map_err(|e| {
                StoreError::Internal(format!("transfer_warm_pool commit (noop): {e}"))
            })?;
            return Ok(false);
        }

        // Create instance runtime lease
        tx.execute(
            "INSERT INTO resource_leases \
             (id, owner_type, owner_id, lease_kind, cpu_cores, ram_mb, disk_gb, acquired_at) \
             VALUES (?1, 'instance', ?2, 'runtime', ?3, ?4, 0, ?5)",
            params![new_lease_id, instance_id, cpu, ram, now],
        )
        .map_err(|e| StoreError::Internal(format!("transfer_warm_pool create: {e}")))?;

        tx.commit()
            .map_err(|e| StoreError::Internal(format!("transfer_warm_pool commit: {e}")))?;

        Ok(true)
    }

    // ── Instance Events ───────────────────────────────────────────────────────

    /// Record an instance event in the append-only audit trail.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the insert fails.
    pub fn record_instance_event(&self, event: &NewInstanceEvent<'_>) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO instance_events \
             (instance_id, event_type, actor, detail, resource_snapshot) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.instance_id,
                event.event_type,
                event.actor,
                event.detail,
                event.resource_snapshot,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("record_instance_event: {e}")))?;
        Ok(())
    }

    /// List instance events for a specific instance, newest first.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the query fails.
    pub fn list_instance_events(
        &self,
        instance_id: &str,
        limit: usize,
    ) -> Result<Vec<InstanceEvent>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, instance_id, event_type, actor, detail, resource_snapshot, created_at \
                 FROM instance_events WHERE instance_id = ?1 \
                 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(|e| StoreError::Internal(format!("list_instance_events prepare: {e}")))?;
        let rows = stmt
            .query_map(params![instance_id, limit], |row| {
                Ok(InstanceEvent {
                    id: row.get(0)?,
                    instance_id: row.get(1)?,
                    event_type: row.get(2)?,
                    actor: row.get(3)?,
                    detail: row.get(4)?,
                    resource_snapshot: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| StoreError::Internal(format!("list_instance_events query: {e}")))?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| StoreError::Internal(format!("event row parse: {e}")))?);
        }
        Ok(events)
    }
}

/// Parse a `resource_leases` row.
fn row_to_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResourceLease> {
    Ok(ResourceLease {
        id: row.get(0)?,
        owner_type: row.get(1)?,
        owner_id: row.get(2)?,
        lease_kind: row.get(3)?,
        cpu_cores: row.get(4)?,
        ram_mb: row.get(5)?,
        disk_gb: row.get(6)?,
        acquired_at: row.get(7)?,
        expires_at: row.get(8)?,
        released_at: row.get(9)?,
    })
}

/// Current Unix timestamp in seconds.
#[allow(clippy::cast_possible_wrap)] // Unix seconds won't exceed i64::MAX until year 292 billion
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─── Terminal Workspaces ─────────────────────────────────────────────────────

/// A row from the `terminal_conversations` table (v2 — replaces legacy
/// `terminal_conversations`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TerminalConversation {
    pub id: String,
    pub container: String,
    pub username: String,
    pub status: String,
    pub created_at: String,
    pub last_attach_at: Option<String>,
    pub last_detach_at: Option<String>,
    pub last_activity_at: Option<String>,
    pub display_name: String,
    pub log_path: String,
}

impl InstanceDb {
    /// Idempotent schema migration for the `terminal_conversations` table.
    ///
    /// Rows persist across backend restarts (per the persistent-conversation
    /// contract from PR #16). The migration only creates the table + index
    /// when missing; it must not drop existing rows.
    ///
    /// Older installs predating v3 had a different schema; they are not in
    /// production. If we ever need to upgrade an older schema in place, add
    /// a one-shot ALTER TABLE path here.
    fn migrate_terminal_conversations(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS terminal_conversations (
                 id TEXT PRIMARY KEY,
                 container TEXT NOT NULL,
                 username TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'active',
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                 last_attach_at DATETIME,
                 last_detach_at DATETIME,
                 last_activity_at DATETIME,
                 display_name TEXT NOT NULL DEFAULT '',
                 log_path TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_tc_container_user
                 ON terminal_conversations(container, username);",
        )
        .map_err(|e| StoreError::Internal(format!("migrate terminal_conversations: {e}")))?;

        Ok(())
    }

    /// Resume an existing workspace or create a new one for `(container, username)`.
    ///
    /// When multiple workspaces exist (v2), returns the most recently attached
    /// one. Returns the workspace row with `last_attach_at` updated.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn resume_or_create_conversation(
        &self,
        container: &str,
        username: &str,
    ) -> Result<TerminalConversation, StoreError> {
        let conn = self.conn()?;

        // Try to find existing active conversation (most recently attached first).
        let existing: Option<TerminalConversation> = conn
            .query_row(
                "SELECT id, container, username, status, \
                 created_at, last_attach_at, last_detach_at, last_activity_at, display_name, log_path \
                 FROM terminal_conversations \
                 WHERE container = ?1 AND username = ?2 AND status = 'active' \
                 ORDER BY last_attach_at DESC LIMIT 1",
                params![container, username],
                row_to_conversation,
            )
            .optional()
            .map_err(|e| StoreError::Internal(format!("resume_or_create select: {e}")))?;

        if let Some(mut ws) = existing {
            // Touch last_attach_at.
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = CURRENT_TIMESTAMP WHERE id = ?1",
                params![ws.id],
            )
            .map_err(|e| StoreError::Internal(format!("resume_or_create update: {e}")))?;
            ws.last_attach_at = Some(chrono_now_str());
            return Ok(ws);
        }

        // Create new conversation.
        let id = generate_conversation_id();
        conn.execute(
            "INSERT INTO terminal_conversations (id, container, username, display_name, status, \
             created_at, last_attach_at) \
             VALUES (?1, ?2, ?3, '', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![id, container, username],
        )
        .map_err(|e| StoreError::Internal(format!("resume_or_create insert: {e}")))?;

        let ws = conn
            .query_row(
                "SELECT id, container, username, status, \
                 created_at, last_attach_at, last_detach_at, last_activity_at, display_name, log_path \
                 FROM terminal_conversations WHERE id = ?1",
                params![id],
                row_to_conversation,
            )
            .map_err(|e| StoreError::Internal(format!("resume_or_create get: {e}")))?;
        Ok(ws)
    }

    /// Update `last_attach_at = CURRENT_TIMESTAMP` for a specific active workspace.
    ///
    /// Returns the number of rows affected (0 if the workspace doesn't exist or
    /// isn't active — callers that need to enforce existence should check this).
    ///
    /// Used by the "continue on iPhone" flow where `handle_mobile_auth` attaches
    /// a mobile client to a pre-existing workspace without going through
    /// `resume_or_create_conversation` (which would pick the most-recent workspace
    /// instead of the specific one encoded in the QR token).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn touch_conversation_attached(&self, conversation_id: &str) -> Result<usize, StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE terminal_conversations SET last_attach_at = CURRENT_TIMESTAMP \
             WHERE id = ?1 AND status = 'active'",
            params![conversation_id],
        )
        .map_err(|e| StoreError::Internal(format!("touch_conversation_attached: {e}")))
    }

    /// Mark a workspace as detached (set `last_detach_at`).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn detach_conversation(&self, id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE terminal_conversations SET last_detach_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![id],
        )
        .map_err(|e| StoreError::Internal(format!("detach_conversation: {e}")))?;
        Ok(())
    }

    /// Delete all workspaces for a given container (cascade on instance delete).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn delete_conversations_for_container(&self, container: &str) -> Result<usize, StoreError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "DELETE FROM terminal_conversations WHERE container = ?1",
                params![container],
            )
            .map_err(|e| {
                StoreError::Internal(format!("delete_conversations_for_container: {e}"))
            })?;
        Ok(n)
    }

    /// Check that a workspace exists, is active, and is owned by the given user.
    ///
    /// Returns `Ok(true)` if the workspace matches all three criteria,
    /// `Ok(false)` otherwise (wrong user, wrong container, expired, or missing).
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn verify_conversation_owner(
        &self,
        conversation_id: &str,
        container: &str,
        username: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM terminal_conversations \
                 WHERE id = ?1 AND container = ?2 AND username = ?3 AND status = 'active')",
                params![conversation_id, container, username],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Internal(format!("verify_conversation_owner: {e}")))?;
        Ok(exists)
    }

    /// Create a new workspace for `(container, username)` with a display name.
    ///
    /// Unlike `resume_or_create_conversation`, this always creates a new workspace,
    /// allowing multiple workspaces per `(container, username)` pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn create_conversation(
        &self,
        container: &str,
        username: &str,
        display_name: &str,
    ) -> Result<TerminalConversation, StoreError> {
        let conn = self.conn()?;
        let id = generate_conversation_id();
        conn.execute(
            "INSERT INTO terminal_conversations (id, container, username, display_name, status, \
             created_at, last_attach_at) \
             VALUES (?1, ?2, ?3, ?4, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![id, container, username, display_name],
        )
        .map_err(|e| StoreError::Internal(format!("create_conversation insert: {e}")))?;

        let ws = conn
            .query_row(
                "SELECT id, container, username, status, \
                 created_at, last_attach_at, last_detach_at, last_activity_at, display_name, log_path \
                 FROM terminal_conversations WHERE id = ?1",
                params![id],
                row_to_conversation,
            )
            .map_err(|e| StoreError::Internal(format!("create_conversation get: {e}")))?;
        Ok(ws)
    }

    /// List all active and inactive workspaces for `(container, username)`.
    ///
    /// Returns workspaces ordered by `last_attach_at DESC` (most recently
    /// attached first). Expired workspaces are excluded.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn list_conversations(
        &self,
        container: &str,
        username: &str,
    ) -> Result<Vec<TerminalConversation>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, container, username, status, \
                 created_at, last_attach_at, last_detach_at, last_activity_at, display_name, log_path \
                 FROM terminal_conversations \
                 WHERE container = ?1 AND username = ?2 AND status IN ('active', 'inactive') \
                 ORDER BY last_attach_at DESC",
            )
            .map_err(|e| StoreError::Internal(format!("list_conversations prepare: {e}")))?;

        let rows = stmt
            .query_map(params![container, username], row_to_conversation)
            .map_err(|e| StoreError::Internal(format!("list_conversations query: {e}")))?;

        let mut workspaces = Vec::new();
        for row in rows {
            workspaces.push(
                row.map_err(|e| StoreError::Internal(format!("list_conversations row: {e}")))?,
            );
        }
        Ok(workspaces)
    }

    /// Rename a workspace's display name.
    ///
    /// Returns `true` if the workspace existed and was updated, `false` if
    /// the workspace ID was not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn rename_conversation(
        &self,
        conversation_id: &str,
        display_name: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "UPDATE terminal_conversations SET display_name = ?1 WHERE id = ?2",
                params![display_name, conversation_id],
            )
            .map_err(|e| StoreError::Internal(format!("rename_conversation: {e}")))?;
        Ok(n > 0)
    }

    /// Update `last_activity_at` to the current timestamp for the given workspace.
    ///
    /// Called periodically from the WebSocket loop when the user sends input,
    /// so the mobile app can show relative "last active" times.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn touch_activity(&self, conversation_id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE terminal_conversations SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![conversation_id],
        )
        .map_err(|e| StoreError::Internal(format!("touch_activity: {e}")))?;
        Ok(())
    }

    /// Delete a workspace (hard delete).
    ///
    /// Returns `true` if the workspace existed and was deleted, `false` if
    /// the workspace ID was not found.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL delete fails.
    pub fn delete_conversation(&self, conversation_id: &str) -> Result<bool, StoreError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "DELETE FROM terminal_conversations WHERE id = ?1",
                params![conversation_id],
            )
            .map_err(|e| StoreError::Internal(format!("delete_conversation: {e}")))?;
        Ok(n > 0)
    }

    /// Get a workspace by ID.
    ///
    /// Returns `None` if the workspace does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL query fails.
    pub fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<TerminalConversation>, StoreError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT id, container, username, status, \
             created_at, last_attach_at, last_detach_at, last_activity_at, display_name, log_path \
             FROM terminal_conversations WHERE id = ?1",
            params![conversation_id],
            row_to_conversation,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("get_conversation: {e}")))
    }

    /// Update the on-disk log path for a conversation. Called by the server
    /// when a PTY is lazily opened for the first time.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn set_conversation_log_path(
        &self,
        conversation_id: &str,
        log_path: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE terminal_conversations SET log_path = ?1 WHERE id = ?2",
            params![log_path, conversation_id],
        )
        .map_err(|e| StoreError::Internal(format!("set_conversation_log_path: {e}")))?;
        Ok(())
    }

    /// Execute a raw SQL statement with string parameters.
    ///
    /// **Test-only helper** — allows integration tests in other crates to
    /// manipulate data (e.g. backdating timestamps) without exposing the
    /// underlying `Mutex<Connection>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL statement fails.
    pub fn execute_raw(&self, sql: &str, params: &[&str]) -> Result<usize, StoreError> {
        let conn = self.conn()?;
        let p: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        conn.execute(sql, p.as_slice())
            .map_err(|e| StoreError::Internal(format!("execute_raw: {e}")))
    }

    /// Mark workspaces as inactive or expired based on two idle thresholds.
    ///
    /// - Tier 1: active workspaces idle > `inactive_days` → status `"inactive"`
    /// - Tier 2: active/inactive workspaces idle > `expired_days` → status `"expired"`
    ///
    /// Returns `(inactive_count, expired_count)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn cleanup_stale_conversations_tiered(
        &self,
        inactive_days: u32,
        expired_days: u32,
    ) -> Result<(usize, usize), StoreError> {
        let conn = self.conn()?;

        // Tier 2 first: promote to expired (active or inactive → expired).
        let expired = conn
            .execute(
                "UPDATE terminal_conversations SET status = 'expired' \
                 WHERE status IN ('active', 'inactive') \
                 AND COALESCE(last_attach_at, created_at) < datetime('now', ?1)",
                params![format!("-{expired_days} days")],
            )
            .map_err(|e| StoreError::Internal(format!("cleanup_tiered expired: {e}")))?;

        // Tier 1: promote active → inactive (only those not already expired above).
        let inactive = conn
            .execute(
                "UPDATE terminal_conversations SET status = 'inactive' \
                 WHERE status = 'active' \
                 AND COALESCE(last_attach_at, created_at) < datetime('now', ?1)",
                params![format!("-{inactive_days} days")],
            )
            .map_err(|e| StoreError::Internal(format!("cleanup_tiered inactive: {e}")))?;

        Ok((inactive, expired))
    }

    /// Mark workspaces idle for more than `max_idle_days` as `"expired"`.
    ///
    /// Returns the number of workspaces expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the SQL update fails.
    pub fn cleanup_stale_conversations(&self, max_idle_days: u32) -> Result<usize, StoreError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "UPDATE terminal_conversations SET status = 'expired' \
                 WHERE status = 'active' \
                 AND COALESCE(last_attach_at, created_at) < datetime('now', ?1)",
                params![format!("-{max_idle_days} days")],
            )
            .map_err(|e| StoreError::Internal(format!("cleanup_stale_conversations: {e}")))?;
        Ok(n)
    }
}

fn row_to_conversation(row: &rusqlite::Row<'_>) -> rusqlite::Result<TerminalConversation> {
    Ok(TerminalConversation {
        id: row.get(0)?,
        container: row.get(1)?,
        username: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        last_attach_at: row.get(5)?,
        last_detach_at: row.get(6)?,
        last_activity_at: row.get(7)?,
        display_name: row.get(8)?,
        log_path: row.get(9)?,
    })
}

/// Generate a short, unique workspace ID (16 hex chars).
fn generate_conversation_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let r: u64 = rng.r#gen();
    format!("{r:016x}")
}

/// Return current UTC timestamp as a rough ISO-8601 string for in-memory updates.
fn chrono_now_str() -> String {
    // Approximation — the real value comes from SQLite CURRENT_TIMESTAMP.
    "now".to_string()
}

/// Returns `Some(s)` if `s` is non-empty, `None` otherwise.
fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

/// Generate a 32-byte base64url random token (43 chars, no padding).
fn generate_random_token() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Combine time, counter, and stack address for uniqueness
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let mut bytes = [0u8; 32];
    for (i, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut h = DefaultHasher::new();
        ts.hash(&mut h);
        n.hash(&mut h);
        (i as u64).hash(&mut h);
        (&raw const n as u64).hash(&mut h);
        let digest = h.finish();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&digest.to_le_bytes()[..len]);
    }

    // base64url encode without padding
    let mut out = String::with_capacity(43);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(CHARS[(n & 0x3F) as usize] as char);
        }
    }
    out
}

/// Shared row mapper for invite queries.
fn row_to_invite(row: &rusqlite::Row<'_>) -> rusqlite::Result<InviteRow> {
    Ok(InviteRow {
        id: row.get(0)?,
        token: row.get(1)?,
        instance_id: row.get(2)?,
        created_by: row.get(3)?,
        expires_at: row.get(4)?,
        redeemed_by: row.get(5)?,
        redeemed_at: row.get(6)?,
        created_at: row.get(7)?,
    })
}

/// Shared row mapper for user queries.
fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserRow> {
    let role_str: String = row.get(2)?;
    let role = role_str.parse::<UserRole>().unwrap_or(UserRole::User);
    Ok(UserRow {
        id: row.get(0)?,
        username: row.get(1)?,
        role,
        created_at: row.get(3)?,
        created_by: row.get(4)?,
    })
}

/// Shared row mapper for public site queries. Callers must SELECT the columns
/// in the order: domain, `instance_id`, `guest_port`, `target_host`, `target_port`,
/// enabled, `created_at`, `updated_at`, `cloudflare_dns_record_id`.
fn row_to_public_site(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicSiteRow> {
    let enabled: i64 = row.get(5)?;
    Ok(PublicSiteRow {
        domain: row.get(0)?,
        instance_id: row.get(1)?,
        guest_port: row.get(2)?,
        target_host: row.get(3)?,
        target_port: row.get(4)?,
        enabled: enabled != 0,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        cloudflare_dns_record_id: row.get(8)?,
    })
}

/// Shared row mapper for instance queries.
fn row_to_instance(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstanceRow> {
    row_to_instance_offset(row, 0)
}

/// Same mapping as [`row_to_instance`] but reading the instance columns at an
/// offset, for JOINs that prepend other columns (e.g. the `shareable_apps`
/// resolution JOIN).
fn row_to_instance_offset(row: &rusqlite::Row<'_>, o: usize) -> rusqlite::Result<InstanceRow> {
    let status_str: String = row.get(o + 5)?;
    let status = status_str
        .parse::<InstanceStatus>()
        .unwrap_or(InstanceStatus::Provisioning);
    Ok(InstanceRow {
        id: row.get(o)?,
        name: row.get(o + 1)?,
        container: row.get(o + 2)?,
        claw_type: row.get(o + 3)?,
        host_port: row.get(o + 4)?,
        status,
        provisioning_message: row.get(o + 6)?,
        provisioning_error: row.get(o + 7)?,
        provisioning_phase: row.get(o + 8)?,
        job_id: row.get(o + 9)?,
        auto_update: row.get(o + 10)?,
        custom_domain: row.get(o + 11)?,
        cf_hostname_id: row.get(o + 12)?,
        vm_id: row.get(o + 15)?,
        pid: row.get(o + 16)?,
        snapshot_path: row.get(o + 17)?,
        config_json: row.get(o + 18)?,
        vm_ip: row.get(o + 19)?,
        vm_mac: row.get(o + 20)?,
        efi_store_path: row.get(o + 21)?,
        cidata_iso_path: row.get(o + 22)?,
        disk_path: row.get(o + 23)?,
        guest_os: row
            .get::<_, Option<String>>(24)?
            .unwrap_or_else(|| "linux".to_string()),
        aux_storage_path: row.get(o + 25)?,
        owner_id: row.get(o + 26)?,
        cpu_cores: row.get(o + 27)?,
        ram_config_mb: row.get(o + 28)?,
        disk_gb: row.get(o + 29)?,
        created_at: row.get(o + 13)?,
        updated_at: row.get(o + 14)?,
        desired_state: row.get(o + 30)?,
        observed_state: row.get(o + 31)?,
        deleted_at: row.get(o + 32)?,
        household_id: row.get(o + 33)?,
        household_machine_id: row.get(o + 34)?,
        provisioning_failure_code: row.get(o + 35)?,
    })
}

#[cfg(test)]
mod instance_db_tests {
    use super::*;

    fn open_temp() -> InstanceDb {
        InstanceDb::open(":memory:").expect("open :memory:")
    }

    fn instance_column_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn household_scope_migration_repairs_partial_columns() {
        for schema in [
            "CREATE TABLE instances (
                id TEXT PRIMARY KEY,
                created_at DATETIME,
                deleted_at DATETIME,
                household_id TEXT
            );",
            "CREATE TABLE instances (
                id TEXT PRIMARY KEY,
                created_at DATETIME,
                deleted_at DATETIME,
                household_machine_id TEXT
            );",
        ] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(schema).unwrap();

            InstanceDb::migrate_household_scope(&conn).unwrap();

            assert!(instance_column_exists(&conn, "household_id"));
            assert!(instance_column_exists(&conn, "household_machine_id"));
            let index_exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master \
                     WHERE type = 'index' AND name = 'idx_instances_household_scope'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(index_exists);
        }
    }

    fn foo_inst() -> NewInstance<'static> {
        NewInstance {
            id: "inst-foo",
            name: "foo",
            container: "picoclaw-foo",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.id, "inst-foo");
        assert_eq!(row.name, "foo");
        assert_eq!(row.status, InstanceStatus::Provisioning);
        assert_eq!(row.host_port, None);
    }

    #[test]
    fn fresh_row_has_no_provisioning_failure_code() {
        // The migration ran (else the SELECT would fail); a fresh row is NULL.
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        assert_eq!(
            db.get("inst-foo")
                .unwrap()
                .unwrap()
                .provisioning_failure_code,
            None
        );
    }

    #[test]
    fn set_and_clear_provisioning_failure_code() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.set_provisioning_failure_code("inst-foo", Some("host_vm_limit_reached"))
            .unwrap();
        assert_eq!(
            db.get("inst-foo")
                .unwrap()
                .unwrap()
                .provisioning_failure_code,
            Some("host_vm_limit_reached".to_string())
        );
        db.set_provisioning_failure_code("inst-foo", None).unwrap();
        assert_eq!(
            db.get("inst-foo")
                .unwrap()
                .unwrap()
                .provisioning_failure_code,
            None
        );
    }

    #[test]
    fn update_status_clears_failure_code_then_restamp() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.set_provisioning_failure_code("inst-foo", Some("snapshot_failed"))
            .unwrap();
        // Any status transition clears the stale code.
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        assert_eq!(
            db.get("inst-foo")
                .unwrap()
                .unwrap()
                .provisioning_failure_code,
            None
        );
        // The mark_failed order: update_status(Failed) clears, then re-stamp.
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Failed,
            message: "",
            error: "boom",
            job_id: "",
            phase: "",
        })
        .unwrap();
        db.set_provisioning_failure_code("inst-foo", Some("vm_start_failed"))
            .unwrap();
        let row = db.get("inst-foo").unwrap().unwrap();
        assert_eq!(
            row.provisioning_failure_code,
            Some("vm_start_failed".to_string())
        );
        assert_eq!(row.provisioning_error, Some("boom".to_string()));
    }

    #[test]
    fn test_find_conflict() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        // Conflict by id
        assert!(db.find_conflict("inst-foo", "other").unwrap().is_some());
        // Conflict by name
        assert!(db.find_conflict("inst-other", "foo").unwrap().is_some());
        // No conflict
        assert!(db.find_conflict("inst-new", "new").unwrap().is_none());
    }

    #[test]
    fn test_find_conflict_different_name_no_match() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        // A different id and name should NOT conflict
        assert!(db.find_conflict("inst-bar", "bar").unwrap().is_none());
        // But same name should still conflict
        assert!(db.find_conflict("inst-bar", "foo").unwrap().is_some());
    }

    #[test]
    fn test_update_status() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.status, InstanceStatus::Active);
        assert_eq!(row.provisioning_message, None);
    }

    #[test]
    fn test_update_port() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_port("inst-foo", 35000).unwrap();
        let port = db.get_host_port("inst-foo").unwrap();
        assert_eq!(port, 35000);
    }

    #[test]
    fn test_clear_port() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_port("inst-foo", 35000).unwrap();
        db.clear_port("inst-foo").unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.host_port, None);
    }

    #[test]
    fn test_list() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-a",
            name: "alpha",
            container: "picoclaw-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-b",
            name: "beta",
            container: "picoclaw-beta",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        let rows = db.list().unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn household_list_includes_only_matching_active_household_rows() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-household-alpha",
            name: "household-alpha",
            container: "picoclaw-household-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-household-beta",
            name: "household-beta",
            container: "picoclaw-household-beta",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_beta"),
            household_machine_id: Some("m_beta"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-legacy",
            name: "legacy",
            container: "picoclaw-legacy",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-household-deleted",
            name: "household-deleted",
            container: "picoclaw-household-deleted",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.soft_delete("inst-household-deleted").unwrap();

        let rows = db.list_for_household("hh_alpha").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "inst-household-alpha");
        assert_eq!(rows[0].household_id.as_deref(), Some("hh_alpha"));
        assert_eq!(rows[0].household_machine_id.as_deref(), Some("m_alpha"));
    }

    #[test]
    fn household_status_accepts_matching_household_independent_of_machine_metadata() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-household-alpha",
            name: "household-alpha",
            container: "picoclaw-household-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: None,
        })
        .unwrap();

        let row = db
            .get_for_household_status("inst-household-alpha", "hh_alpha")
            .unwrap()
            .expect("matching household row");
        assert_eq!(row.id, "inst-household-alpha");
    }

    #[test]
    fn household_status_rejects_unscoped_rows() {
        // INVERTED from `household_status_accepts_legacy_unscoped_rows` by the
        // 2026-08 security verdict (option (b), strict): a row without
        // household_id belongs to NO household. Status and listing must agree
        // by rule — unscoped rows are hidden from both until stamped via
        // `stamp_mac_host_household`. Kept (not deleted) so the rule
        // change is visible in review.
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-legacy",
            name: "legacy",
            container: "picoclaw-legacy",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();

        assert!(
            db.get_for_household_status("inst-legacy", "hh_alpha")
                .unwrap()
                .is_none(),
            "unscoped rows must be hidden from household status under the strict rule"
        );
    }

    #[test]
    fn household_status_and_list_agree_for_the_same_row() {
        // The two read paths must answer the SAME question for the SAME row —
        // the original bug was status accepting rows the listing excluded.
        let db = open_temp();
        let insert = |id: &str, hh: Option<&str>, m: Option<&str>| {
            db.insert(&NewInstance {
                id,
                name: id,
                container: &format!("c-{id}"),
                claw_type: "picoclaw",
                sunset_date: "2026-12-31",
                guest_os: None,
                aux_storage_path: None,
                cpu_cores: None,
                ram_config_mb: None,
                disk_gb: None,
                household_id: hh,
                household_machine_id: m,
            })
            .unwrap();
        };
        insert("inst-scoped", Some("hh_alpha"), Some("m_alpha"));
        insert("inst-unscoped", None, None);
        insert("inst-machine-only", None, Some("m_alpha"));
        insert("inst-other-household", Some("hh_beta"), Some("m_beta"));
        insert("inst-deleted", Some("hh_alpha"), Some("m_alpha"));
        db.soft_delete("inst-deleted").unwrap();

        let listed: Vec<String> = db
            .list_for_household("hh_alpha")
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        for id in [
            "inst-scoped",
            "inst-unscoped",
            "inst-machine-only",
            "inst-other-household",
            "inst-deleted",
        ] {
            let in_status = db
                .get_for_household_status(id, "hh_alpha")
                .unwrap()
                .is_some();
            let in_list = listed.iter().any(|listed_id| listed_id == id);
            assert_eq!(
                in_status, in_list,
                "status and list disagree for row {id} (status={in_status}, list={in_list})"
            );
        }
        assert_eq!(listed, vec!["inst-scoped".to_string()]);
    }

    #[test]
    fn stamp_mac_host_household_makes_seeded_mac_host_visible() {
        // Boot-order reproduction: the mac-host seed runs BEFORE the household
        // identity loads, so the row is born unscoped and invisible. Stamping
        // after bootstrap is what puts it in the sharing picker.
        let db = open_temp();
        let admin_id = db.seed_admin("admin").unwrap();
        db.seed_mac_host_instance(&admin_id).unwrap();

        let mac_host = db.get("inst-mac-host").unwrap().expect("seeded row");
        assert!(mac_host.household_id.is_none());
        assert!(mac_host.household_machine_id.is_none());
        assert!(db.list_for_household("hh_alpha").unwrap().is_empty());
        assert!(
            db.get_for_household_status("inst-mac-host", "hh_alpha")
                .unwrap()
                .is_none()
        );

        let stamped = db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap();
        assert!(stamped, "mac-host seed row must be stamped");

        let mac_host = db.get("inst-mac-host").unwrap().expect("seeded row");
        assert_eq!(mac_host.household_id.as_deref(), Some("hh_alpha"));
        assert_eq!(mac_host.household_machine_id.as_deref(), Some("m_alpha"));
        let listed: Vec<String> = db
            .list_for_household("hh_alpha")
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(listed, vec!["inst-mac-host".to_string()]);
        assert!(
            db.get_for_household_status("inst-mac-host", "hh_alpha")
                .unwrap()
                .is_some()
        );

        // Idempotent: a second stamp (next boot) touches nothing.
        assert!(!db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap());
    }

    #[test]
    fn stamp_mac_host_household_fails_closed_on_ambiguous_or_foreign_rows() {
        // Narrow stamping (security verdict, 2026-08): ONLY the mac-host seed
        // row is eligible. A fully-unscoped NON-mac-host row — possibly a
        // leftover from a previous household — must NOT be adopted by the
        // current one. Partial scope (ambiguous provenance), another
        // household's rows, and soft-deleted rows are likewise untouched.
        let db = open_temp();
        let insert = |id: &str, container: &str, hh: Option<&str>, m: Option<&str>| {
            db.insert(&NewInstance {
                id,
                name: id,
                container,
                claw_type: "picoclaw",
                sunset_date: "2026-12-31",
                guest_os: None,
                aux_storage_path: None,
                cpu_cores: None,
                ram_config_mb: None,
                disk_gb: None,
                household_id: hh,
                household_machine_id: m,
            })
            .unwrap();
        };
        insert("inst-legacy-unscoped", "picoclaw-legacy", None, None);
        insert(
            "inst-machine-only",
            "picoclaw-m-only",
            None,
            Some("m_unknown"),
        );
        insert(
            "inst-household-only",
            "picoclaw-h-only",
            Some("hh_alpha"),
            None,
        );
        insert(
            "inst-other-household",
            "picoclaw-other",
            Some("hh_beta"),
            Some("m_beta"),
        );
        insert("mac-host-lookalike", "mac-host-impostor", None, None);

        let stamped = db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap();
        assert!(!stamped, "no row here is eligible for stamping");

        let legacy = db.get("inst-legacy-unscoped").unwrap().unwrap();
        assert!(
            legacy.household_id.is_none() && legacy.household_machine_id.is_none(),
            "unscoped non-mac-host rows must NOT be adopted by the current household"
        );
        let machine_only = db.get("inst-machine-only").unwrap().unwrap();
        assert!(machine_only.household_id.is_none());
        assert_eq!(
            machine_only.household_machine_id.as_deref(),
            Some("m_unknown")
        );
        let household_only = db.get("inst-household-only").unwrap().unwrap();
        assert_eq!(household_only.household_id.as_deref(), Some("hh_alpha"));
        assert!(household_only.household_machine_id.is_none());
        let other = db.get("inst-other-household").unwrap().unwrap();
        assert_eq!(other.household_id.as_deref(), Some("hh_beta"));
        let lookalike = db.get("mac-host-lookalike").unwrap().unwrap();
        assert!(
            lookalike.household_id.is_none(),
            "only the exact mac-host container is eligible"
        );
    }

    #[test]
    fn household_status_hides_machine_only_partial_scope() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-machine-only",
            name: "machine-only",
            container: "picoclaw-machine-only",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();

        assert!(
            db.get_for_household_status("inst-machine-only", "hh_alpha")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn household_status_hides_deleted_or_other_household_rows() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-other-household",
            name: "other-household",
            container: "picoclaw-other-household",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_beta"),
            household_machine_id: Some("m_beta"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-deleted",
            name: "deleted",
            container: "picoclaw-deleted",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.soft_delete("inst-deleted").unwrap();

        assert!(
            db.get_for_household_status("inst-other-household", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_status("inst-deleted", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_status("inst-missing", "hh_alpha")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_delete() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.delete("inst-foo").unwrap();
        assert!(db.get("inst-foo").unwrap().is_none());
    }

    #[test]
    fn test_delete_with_unredeemed_invite() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        let admin_id = db.seed_admin("admin").unwrap();
        db.create_invite("inst-foo", &admin_id, 3600).unwrap();

        db.delete("inst-foo").unwrap();
        assert!(db.get("inst-foo").unwrap().is_none());
        assert!(db.list_invites().unwrap().is_empty());
    }

    #[test]
    fn test_delete_with_redeemed_invite() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        let admin_id = db.seed_admin("admin").unwrap();
        let invite = db.create_invite("inst-foo", &admin_id, 3600).unwrap();

        db.redeem_invite_atomic(&invite.token, "guest", &admin_id)
            .unwrap();

        db.delete("inst-foo").unwrap();
        assert!(db.get("inst-foo").unwrap().is_none());
        assert!(db.list_invites().unwrap().is_empty());
    }

    #[test]
    fn test_set_job_id() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.set_job_id("inst-foo", "job-123").unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.job_id, Some("job-123".to_string()));
    }

    #[test]
    fn test_set_custom_domain() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.set_custom_domain("inst-foo", "meunegocio.com.br", "cf-abc123")
            .unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.custom_domain, Some("meunegocio.com.br".to_string()));
        assert_eq!(row.cf_hostname_id, Some("cf-abc123".to_string()));
    }

    #[test]
    fn test_clear_custom_domain() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.set_custom_domain("inst-foo", "app.example.com", "cf-xyz")
            .unwrap();
        db.clear_custom_domain("inst-foo").unwrap();
        let row = db.get("inst-foo").unwrap().expect("row");
        assert_eq!(row.custom_domain, None);
        assert_eq!(row.cf_hostname_id, None);
    }

    #[test]
    fn test_lookup_custom_domain_port() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        db.update_port("inst-foo", 35002).unwrap();
        db.set_custom_domain("inst-foo", "app.example.com", "cf-id")
            .unwrap();
        let port = db.lookup_custom_domain_port("app.example.com").unwrap();
        assert_eq!(port, Some(35002));
    }

    #[test]
    fn test_lookup_custom_domain_port_not_active() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_port("inst-foo", 35003).unwrap();
        db.set_custom_domain("inst-foo", "app.example.com", "cf-id")
            .unwrap();
        // Instance is "provisioning", not "active"
        let port = db.lookup_custom_domain_port("app.example.com").unwrap();
        assert_eq!(port, None);
    }

    #[test]
    fn test_public_site_upsert_list_lookup_delete() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();

        let site = db
            .upsert_public_site(&NewPublicSite {
                domain: "app.example.com",
                instance_id: "inst-foo",
                guest_port: 3000,
                target_host: "127.0.0.1",
                target_port: 24001,
                enabled: true,
            })
            .unwrap();
        assert_eq!(site.domain, "app.example.com");
        assert_eq!(site.guest_port, 3000);
        assert_eq!(site.target_port, 24001);
        assert!(site.enabled);

        let list = db.list_public_sites_for_instance("inst-foo").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].domain, "app.example.com");

        let target = db
            .lookup_public_site_target("app.example.com")
            .unwrap()
            .expect("active public site target");
        assert_eq!(target.instance_id, "inst-foo");
        assert_eq!(target.target_host, "127.0.0.1");

        let by_guest_port = db
            .find_public_site_for_instance_guest_port("inst-foo", 3000)
            .unwrap()
            .expect("site for guest port");
        assert_eq!(by_guest_port.target_port, 24001);

        let ports = db.list_public_site_target_ports().unwrap();
        assert_eq!(ports, vec![24001]);

        assert!(
            db.delete_public_site("inst-foo", "app.example.com")
                .unwrap()
                .is_some()
        );
        assert!(
            db.lookup_public_site_target("app.example.com")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_lookup_public_site_target_not_active_or_disabled() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.upsert_public_site(&NewPublicSite {
            domain: "app.example.com",
            instance_id: "inst-foo",
            guest_port: 3000,
            target_host: "127.0.0.1",
            target_port: 24002,
            enabled: true,
        })
        .unwrap();

        assert!(
            db.lookup_public_site_target("app.example.com")
                .unwrap()
                .is_none()
        );

        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        db.upsert_public_site(&NewPublicSite {
            domain: "app.example.com",
            instance_id: "inst-foo",
            guest_port: 3000,
            target_host: "127.0.0.1",
            target_port: 24002,
            enabled: false,
        })
        .unwrap();

        assert!(
            db.lookup_public_site_target("app.example.com")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_get_cf_hostname_id() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        assert_eq!(db.get_cf_hostname_id("inst-foo").unwrap(), None);
        db.set_custom_domain("inst-foo", "app.example.com", "cf-999")
            .unwrap();
        assert_eq!(
            db.get_cf_hostname_id("inst-foo").unwrap(),
            Some("cf-999".to_string())
        );
    }

    #[test]
    fn test_custom_domain_unique_constraint() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        db.insert(&NewInstance {
            id: "inst-bar",
            name: "bar",
            container: "picoclaw-bar",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.set_custom_domain("inst-foo", "app.example.com", "cf-1")
            .unwrap();
        // Second instance trying to claim the same custom_domain should fail
        let err = db
            .set_custom_domain("inst-bar", "app.example.com", "cf-2")
            .unwrap_err();
        assert!(
            err.to_string().contains("UNIQUE"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    #[test]
    fn test_list_active_containers() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-a",
            name: "alpha",
            container: "picoclaw-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-b",
            name: "beta",
            container: "picoclaw-beta",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();

        // Both start as "provisioning" — no active containers yet
        assert!(db.list_active_containers().unwrap().is_empty());

        // Activate alpha
        db.update_status(&StatusUpdate {
            id: "inst-a",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let active = db.list_active_containers().unwrap();
        assert_eq!(active, vec!["picoclaw-alpha"]);

        // Activate beta too
        db.update_status(&StatusUpdate {
            id: "inst-b",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let active = db.list_active_containers().unwrap();
        assert_eq!(active, vec!["picoclaw-alpha", "picoclaw-beta"]);

        // Stop alpha — only beta remains
        db.update_status(&StatusUpdate {
            id: "inst-a",
            status: InstanceStatus::Stopped,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let active = db.list_active_containers().unwrap();
        assert_eq!(active, vec!["picoclaw-beta"]);

        // Delete beta — empty again
        db.delete("inst-b").unwrap();
        assert!(db.list_active_containers().unwrap().is_empty());
    }

    #[test]
    fn get_by_container_found_and_not_found() {
        let db = open_temp();
        db.insert(&foo_inst()).unwrap();
        let row = db.get_by_container("picoclaw-foo").unwrap().unwrap();
        assert_eq!(row.id, "inst-foo");
        assert_eq!(row.container, "picoclaw-foo");
        assert!(db.get_by_container("nonexistent").unwrap().is_none());
    }

    #[test]
    fn get_for_household_by_container_filters_household_and_deleted_state() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-household-alpha",
            name: "household-alpha",
            container: "picoclaw-household-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-other-household",
            name: "other-household",
            container: "picoclaw-other-household",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_beta"),
            household_machine_id: Some("m_beta"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-legacy",
            name: "legacy",
            container: "picoclaw-legacy",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-deleted",
            name: "deleted",
            container: "picoclaw-deleted",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.soft_delete("inst-deleted").unwrap();

        let row = db
            .get_for_household_by_container("picoclaw-household-alpha", "hh_alpha")
            .unwrap()
            .expect("matching household row");
        assert_eq!(row.id, "inst-household-alpha");
        assert!(
            db.get_for_household_by_container("picoclaw-other-household", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_container("picoclaw-legacy", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_container("picoclaw-deleted", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_container("picoclaw-missing", "hh_alpha")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_for_household_by_id_filters_household_and_deleted_state() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-household-alpha",
            name: "household-alpha",
            container: "picoclaw-household-alpha",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-other-household",
            name: "other-household",
            container: "picoclaw-other-household",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_beta"),
            household_machine_id: Some("m_beta"),
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-legacy",
            name: "legacy",
            container: "picoclaw-legacy",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-deleted",
            name: "deleted",
            container: "picoclaw-deleted",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        })
        .unwrap();
        db.soft_delete("inst-deleted").unwrap();

        let row = db
            .get_for_household_by_id("inst-household-alpha", "hh_alpha")
            .unwrap()
            .expect("matching household row");
        assert_eq!(row.container, "picoclaw-household-alpha");
        assert!(
            db.get_for_household_by_id("inst-other-household", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_id("inst-legacy", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_id("inst-deleted", "hh_alpha")
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_for_household_by_id("inst-missing", "hh_alpha")
                .unwrap()
                .is_none()
        );
    }

    // ── Terminal workspace tests ─────────────────────────────────────────────

    #[test]
    fn workspace_create_and_resume() {
        let db = open_temp();
        let ws1 = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert_eq!(ws1.container, "picoclaw-foo");
        assert_eq!(ws1.username, "admin");
        assert_eq!(ws1.status, "active");
        assert!(!ws1.id.is_empty());

        // Resume returns the same workspace.
        let ws2 = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert_eq!(ws1.id, ws2.id);
    }

    #[test]
    fn workspace_different_users_get_different_workspaces() {
        let db = open_temp();
        let ws1 = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        let ws2 = db
            .resume_or_create_conversation("picoclaw-foo", "mobile")
            .unwrap();
        assert_ne!(ws1.id, ws2.id);
        assert_ne!(ws1.id, ws2.id);
    }

    #[test]
    fn workspace_unique_constraint() {
        let db = open_temp();
        db.resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        // Same user + container should resume, not create duplicate.
        let ws2 = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        // Verify only one row exists.
        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM terminal_conversations WHERE container='picoclaw-foo' AND username='admin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        drop(conn);
        assert_eq!(ws2.status, "active");
    }

    #[test]
    fn workspace_cascade_delete() {
        let db = open_temp();
        db.resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        db.resume_or_create_conversation("picoclaw-foo", "mobile")
            .unwrap();
        let n = db
            .delete_conversations_for_container("picoclaw-foo")
            .unwrap();
        assert_eq!(n, 2);
        // Resume after delete creates a new workspace.
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert_eq!(ws.status, "active");
    }

    #[test]
    fn workspace_detach() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        db.detach_conversation(&ws.id).unwrap();
        // Verify last_detach_at is set.
        let conn = db.conn.lock().unwrap();
        let detached: Option<String> = conn
            .query_row(
                "SELECT last_detach_at FROM terminal_conversations WHERE id = ?1",
                params![ws.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(detached.is_some());
    }

    #[test]
    fn workspace_cleanup_stale() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        // Manually set last_attach_at to 100 days ago.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-100 days') WHERE id = ?1",
                params![ws.id],
            )
            .unwrap();
        }
        let n = db.cleanup_stale_conversations(90).unwrap();
        assert_eq!(n, 1);
        // Verify it's expired now — resume creates a new one.
        let conn = db.conn.lock().unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM terminal_conversations WHERE id = ?1",
                params![ws.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "expired");
    }

    #[test]
    fn workspace_verify_owner_valid() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert!(
            db.verify_conversation_owner(&ws.id, "picoclaw-foo", "admin")
                .unwrap()
        );
    }

    #[test]
    fn workspace_verify_owner_wrong_user() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert!(
            !db.verify_conversation_owner(&ws.id, "picoclaw-foo", "other")
                .unwrap()
        );
    }

    #[test]
    fn workspace_verify_owner_wrong_container() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert!(
            !db.verify_conversation_owner(&ws.id, "picoclaw-bar", "admin")
                .unwrap()
        );
    }

    #[test]
    fn workspace_verify_owner_expired() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        // Mark as expired.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET status = 'expired' WHERE id = ?1",
                params![ws.id],
            )
            .unwrap();
        }
        assert!(
            !db.verify_conversation_owner(&ws.id, "picoclaw-foo", "admin")
                .unwrap()
        );
    }

    // ── Multi-workspace tests (v2) ──────────────────────────────────────────

    #[test]
    fn workspace_create_multiple_same_user_container() {
        let db = open_temp();
        let ws1 = db
            .create_conversation("picoclaw-foo", "admin", "Dev Principal")
            .unwrap();
        let ws2 = db
            .create_conversation("picoclaw-foo", "admin", "Debug DB")
            .unwrap();
        assert_ne!(ws1.id, ws2.id);
        assert_ne!(ws1.id, ws2.id);
        assert_eq!(ws1.display_name, "Dev Principal");
        assert_eq!(ws2.display_name, "Debug DB");
    }

    #[test]
    fn workspace_display_name_in_create() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Debug DB")
            .unwrap();
        assert_eq!(ws.display_name, "Debug DB");
        assert_eq!(ws.container, "picoclaw-foo");
        assert_eq!(ws.username, "admin");
        assert_eq!(ws.status, "active");
        assert!(!ws.id.is_empty());
    }

    #[test]
    fn workspace_list_returns_only_users_workspaces() {
        let db = open_temp();
        db.create_conversation("picoclaw-foo", "admin", "WS 1")
            .unwrap();
        db.create_conversation("picoclaw-foo", "admin", "WS 2")
            .unwrap();
        db.create_conversation("picoclaw-foo", "other", "Other WS")
            .unwrap();
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|w| w.username == "admin"));
    }

    #[test]
    fn workspace_list_includes_inactive_excludes_expired() {
        let db = open_temp();
        let ws_active = db
            .create_conversation("picoclaw-foo", "admin", "Active")
            .unwrap();
        let ws_inactive = db
            .create_conversation("picoclaw-foo", "admin", "Inactive")
            .unwrap();
        let ws_expired = db
            .create_conversation("picoclaw-foo", "admin", "Expired")
            .unwrap();
        // Mark statuses via raw SQL.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET status = 'inactive' WHERE id = ?1",
                params![ws_inactive.id],
            )
            .unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET status = 'expired' WHERE id = ?1",
                params![ws_expired.id],
            )
            .unwrap();
        }
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert_eq!(list.len(), 2);
        let ids: Vec<&str> = list.iter().map(|w| w.id.as_str()).collect();
        assert!(ids.contains(&ws_active.id.as_str()));
        assert!(ids.contains(&ws_inactive.id.as_str()));
        assert!(!ids.contains(&ws_expired.id.as_str()));
    }

    #[test]
    fn workspace_list_empty_when_none() {
        let db = open_temp();
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn workspace_list_ordered_by_last_attach() {
        let db = open_temp();
        let ws1 = db
            .create_conversation("picoclaw-foo", "admin", "First")
            .unwrap();
        let ws2 = db
            .create_conversation("picoclaw-foo", "admin", "Second")
            .unwrap();
        let ws3 = db
            .create_conversation("picoclaw-foo", "admin", "Third")
            .unwrap();
        // Make ws2 the most recently attached.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '+1 minute') WHERE id = ?1",
                params![ws2.id],
            ).unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-10 minutes') WHERE id = ?1",
                params![ws1.id],
            ).unwrap();
        }
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert_eq!(list.len(), 3);
        // Most recently attached first.
        assert_eq!(list[0].id, ws2.id);
        // ws3 was created after ws1 (with default CURRENT_TIMESTAMP), so ws3 > ws1.
        assert_eq!(list[1].id, ws3.id);
        assert_eq!(list[2].id, ws1.id);
    }

    #[test]
    fn workspace_get_returns_workspace_with_display_name() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Dev Principal")
            .unwrap();
        let got = db
            .get_conversation(&ws.id)
            .unwrap()
            .expect("workspace exists");
        assert_eq!(got.id, ws.id);
        assert_eq!(got.container, "picoclaw-foo");
        assert_eq!(got.username, "admin");
        assert_eq!(got.display_name, "Dev Principal");
        assert_eq!(got.status, "active");
        assert!(!got.id.is_empty());
    }

    #[test]
    fn workspace_get_nonexistent_returns_none() {
        let db = open_temp();
        assert!(db.get_conversation("nonexistent-id").unwrap().is_none());
    }

    #[test]
    fn workspace_rename_updates_display_name() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Old Name")
            .unwrap();
        let updated = db.rename_conversation(&ws.id, "Dev Principal").unwrap();
        assert!(updated);
        let got = db.get_conversation(&ws.id).unwrap().unwrap();
        assert_eq!(got.display_name, "Dev Principal");
    }

    #[test]
    fn workspace_rename_nonexistent_returns_false() {
        let db = open_temp();
        let updated = db.rename_conversation("nonexistent-id", "Name").unwrap();
        assert!(!updated);
    }

    #[test]
    fn workspace_delete_removes_row() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "To Delete")
            .unwrap();
        let deleted = db.delete_conversation(&ws.id).unwrap();
        assert!(deleted);
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn workspace_delete_nonexistent_returns_false() {
        let db = open_temp();
        let deleted = db.delete_conversation("nonexistent-id").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn workspace_resume_or_create_returns_most_recent() {
        let db = open_temp();
        let _ws1 = db
            .create_conversation("picoclaw-foo", "admin", "First")
            .unwrap();
        let ws2 = db
            .create_conversation("picoclaw-foo", "admin", "Second")
            .unwrap();
        // Make ws2 the most recently attached.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '+1 minute') WHERE id = ?1",
                params![ws2.id],
            ).unwrap();
        }
        // resume_or_create should return the most recently attached (ws2), not create a new one.
        let resumed = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert_eq!(resumed.id, ws2.id);
        // Verify no extra row was created.
        let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn workspace_resume_or_create_creates_when_none() {
        let db = open_temp();
        let ws = db
            .resume_or_create_conversation("picoclaw-foo", "admin")
            .unwrap();
        assert_eq!(ws.container, "picoclaw-foo");
        assert_eq!(ws.username, "admin");
        assert_eq!(ws.status, "active");
        // display_name should default to empty string.
        assert_eq!(ws.display_name, "");
    }

    #[test]
    fn workspace_cleanup_tiered_7d_marks_inactive() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Old")
            .unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-10 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
        }
        let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
        assert_eq!(inactive, 1);
        assert_eq!(expired, 0);
        let got = db.get_conversation(&ws.id).unwrap().unwrap();
        assert_eq!(got.status, "inactive");
    }

    #[test]
    fn workspace_cleanup_tiered_30d_marks_expired() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Very Old")
            .unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-35 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
        }
        let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
        assert_eq!(inactive, 0);
        assert_eq!(expired, 1);
        let got = db.get_conversation(&ws.id).unwrap().unwrap();
        assert_eq!(got.status, "expired");
    }

    #[test]
    fn workspace_cleanup_tiered_preserves_recent() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Recent")
            .unwrap();
        // last_attach_at is CURRENT_TIMESTAMP (just created), so 3 days ago is fine.
        // But let's set it explicitly to 3 days ago.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-3 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
        }
        let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
        assert_eq!(inactive, 0);
        assert_eq!(expired, 0);
        let got = db.get_conversation(&ws.id).unwrap().unwrap();
        assert_eq!(got.status, "active");
    }

    #[test]
    fn workspace_cleanup_tiered_inactive_to_expired() {
        let db = open_temp();
        let ws = db
            .create_conversation("picoclaw-foo", "admin", "Will Expire")
            .unwrap();
        // Set as inactive with last_attach_at 35 days ago.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE terminal_conversations SET status = 'inactive', last_attach_at = datetime('now', '-35 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
        }
        let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
        assert_eq!(inactive, 0);
        assert_eq!(expired, 1);
        let got = db.get_conversation(&ws.id).unwrap().unwrap();
        assert_eq!(got.status, "expired");
    }

    #[test]
    fn workspace_migration_v2_idempotent() {
        // Opening the DB twice runs migrations twice — should not error.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap();
        {
            let _db1 = InstanceDb::open(path_str).unwrap();
        }
        {
            let db2 = InstanceDb::open(path_str).unwrap();
            // Verify we can still create multi-workspaces (v2 migration applied).
            let ws1 = db2
                .create_conversation("picoclaw-foo", "admin", "A")
                .unwrap();
            let ws2 = db2
                .create_conversation("picoclaw-foo", "admin", "B")
                .unwrap();
            assert_ne!(ws1.id, ws2.id);
        }
    }

    #[test]
    fn terminal_conversations_survive_reopen() {
        // Regression for PR #16 follow-up: the migration must not wipe rows
        // across backend restarts. Insert a row, close the DB, re-open (which
        // re-runs migrations), and assert the row is still there.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap();

        let conv_id = {
            let db1 = InstanceDb::open(path_str).unwrap();
            let ws = db1
                .create_conversation("picoclaw-foo", "admin", "persistent")
                .unwrap();
            ws.id
        };

        let db2 = InstanceDb::open(path_str).unwrap();
        let got = db2
            .get_conversation(&conv_id)
            .unwrap()
            .expect("conversation row must survive DB reopen");
        assert_eq!(got.id, conv_id);
        assert_eq!(got.container, "picoclaw-foo");
        assert_eq!(got.username, "admin");
        assert_eq!(got.display_name, "persistent");
    }

    #[test]
    fn test_count_by_claw_type() {
        let db = open_temp();
        // No instances yet
        assert_eq!(db.count_by_claw_type("picoclaw").unwrap(), 0);

        // Insert two picoclaw instances and one zeroclaw
        db.insert(&foo_inst()).unwrap(); // picoclaw-foo
        db.insert(&NewInstance {
            id: "inst-bar",
            name: "bar",
            container: "picoclaw-bar",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.insert(&NewInstance {
            id: "inst-zc",
            name: "zc",
            container: "zeroclaw-zc",
            claw_type: "zeroclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();

        assert_eq!(db.count_by_claw_type("picoclaw").unwrap(), 2);
        assert_eq!(db.count_by_claw_type("zeroclaw").unwrap(), 1);
        assert_eq!(db.count_by_claw_type("nanobot").unwrap(), 0);
    }

    // ── User tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_seed_admin_creates_user() {
        let db = open_temp();
        let id = db.seed_admin("admin").unwrap();
        assert!(id.starts_with("usr_"));

        let user = db.get_user_by_username("admin").unwrap().unwrap();
        assert_eq!(user.id, id);
        assert_eq!(user.role, UserRole::Admin);
        assert!(user.created_by.is_none());
    }

    #[test]
    fn test_seed_admin_idempotent() {
        let db = open_temp();
        let id1 = db.seed_admin("admin").unwrap();
        let id2 = db.seed_admin("admin").unwrap();
        assert_eq!(id1, id2);

        // Even with a different username, seed_admin returns existing admin
        let id3 = db.seed_admin("otheradmin").unwrap();
        assert_eq!(id1, id3);

        // Only one admin exists
        let users = db.list_users().unwrap();
        assert_eq!(users.len(), 1);
    }

    #[test]
    fn test_get_user_by_username_not_found() {
        let db = open_temp();
        assert!(db.get_user_by_username("nobody").unwrap().is_none());
    }

    #[test]
    fn test_create_user() {
        let db = open_temp();
        let admin_id = db.seed_admin("admin").unwrap();

        let user = db
            .create_user("alice", UserRole::User, Some(&admin_id))
            .unwrap();
        assert!(user.id.starts_with("usr_"));
        assert_eq!(user.username, "alice");
        assert_eq!(user.role, UserRole::User);
        assert_eq!(user.created_by.as_deref(), Some(admin_id.as_str()));

        // Lookup by id
        let found = db.get_user(&user.id).unwrap().unwrap();
        assert_eq!(found.username, "alice");
    }

    #[test]
    fn test_create_user_duplicate_username() {
        let db = open_temp();
        db.seed_admin("admin").unwrap();
        // "admin" already exists
        assert!(db.create_user("admin", UserRole::User, None).is_err());
    }

    // ── Ownership tests ────────────────────────────────────────────────────

    #[test]
    fn test_set_owner_and_list_for_user() {
        let db = open_temp();
        let admin_id = db.seed_admin("admin").unwrap();
        let alice = db
            .create_user("alice", UserRole::User, Some(&admin_id))
            .unwrap();

        db.insert(&foo_inst()).unwrap();

        // Initially unassigned
        assert!(db.get("inst-foo").unwrap().unwrap().owner_id.is_none());
        assert!(db.list_for_user(&alice.id).unwrap().is_empty());

        // Assign
        assert!(db.set_owner("inst-foo", Some(&alice.id)).unwrap());
        let rows = db.list_for_user(&alice.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].owner_id.as_deref(), Some(alice.id.as_str()));

        // Unassign
        assert!(db.set_owner("inst-foo", None).unwrap());
        assert!(db.list_for_user(&alice.id).unwrap().is_empty());
    }

    #[test]
    fn test_get_owner_id_by_container() {
        let db = open_temp();
        let admin_id = db.seed_admin("admin").unwrap();
        let alice = db
            .create_user("alice", UserRole::User, Some(&admin_id))
            .unwrap();

        db.insert(&foo_inst()).unwrap();

        // Unassigned
        assert_eq!(
            db.get_owner_id_by_container("picoclaw-foo").unwrap(),
            Some(None)
        );

        // Assigned
        db.set_owner("inst-foo", Some(&alice.id)).unwrap();
        assert_eq!(
            db.get_owner_id_by_container("picoclaw-foo").unwrap(),
            Some(Some(alice.id.clone()))
        );

        // No such container
        assert!(
            db.get_owner_id_by_container("nonexistent")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_list_accessible_containers() {
        let db = open_temp();
        let admin_id = db.seed_admin("admin").unwrap();
        let alice = db
            .create_user("alice", UserRole::User, Some(&admin_id))
            .unwrap();

        db.insert(&foo_inst()).unwrap();
        db.update_status(&StatusUpdate {
            id: "inst-foo",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();

        // Admin sees unassigned
        let admin_ctrs = db
            .list_accessible_containers(&admin_id, UserRole::Admin)
            .unwrap();
        assert_eq!(admin_ctrs, vec!["picoclaw-foo"]);
        // User sees nothing (not owned)
        let alice_ctrs = db
            .list_accessible_containers(&alice.id, UserRole::User)
            .unwrap();
        assert!(alice_ctrs.is_empty());

        // Assign to alice
        db.set_owner("inst-foo", Some(&alice.id)).unwrap();
        // Admin no longer sees it
        let admin_ctrs = db
            .list_accessible_containers(&admin_id, UserRole::Admin)
            .unwrap();
        assert!(admin_ctrs.is_empty());
        // Alice sees it
        let alice_ctrs = db
            .list_accessible_containers(&alice.id, UserRole::User)
            .unwrap();
        assert_eq!(alice_ctrs, vec!["picoclaw-foo"]);
    }

    #[test]
    fn test_list_users() {
        let db = open_temp();
        db.seed_admin("admin").unwrap();
        db.create_user("alice", UserRole::User, None).unwrap();
        db.create_user("bob", UserRole::User, None).unwrap();

        let users = db.list_users().unwrap();
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].username, "admin");
    }

    // ── Resource Lease Tests ────────────────────────────────────────────────

    #[test]
    fn lease_create_and_query() {
        let db = open_temp();
        let id = db
            .create_lease(&NewLease {
                owner_type: LeaseOwnerType::Instance,
                owner_id: "inst-1",
                lease_kind: LeaseKind::Runtime,
                cpu_cores: 2,
                ram_mb: 2048,
                disk_gb: 0,
                expires_at: None,
            })
            .unwrap();
        assert!(id.starts_with("lease_"));

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 2);
        assert_eq!(ram, 2048);
    }

    #[test]
    fn lease_unique_index_prevents_duplicate_active() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        // Second active lease for same owner+kind should fail
        let result = db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 4,
            ram_mb: 4096,
            disk_gb: 0,
            expires_at: None,
        });
        assert!(result.is_err(), "duplicate active lease should fail");
    }

    #[test]
    fn lease_release_idempotent() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        assert!(
            db.release_lease_str("instance", "inst-1", "runtime")
                .unwrap()
        );
        // Second release should return false (already released)
        assert!(
            !db.release_lease_str("instance", "inst-1", "runtime")
                .unwrap()
        );
    }

    #[test]
    fn lease_released_excluded_from_sum() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 2);
        assert_eq!(ram, 2048);

        db.release_lease_str("instance", "inst-1", "runtime")
            .unwrap();

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 0);
        assert_eq!(ram, 0);
    }

    #[test]
    fn lease_after_release_can_create_new() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        db.release_lease_str("instance", "inst-1", "runtime")
            .unwrap();

        // After release, creating a new lease for the same owner+kind should work
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 4,
            ram_mb: 4096,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 4);
        assert_eq!(ram, 4096);
    }

    #[test]
    fn lease_release_all() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Storage,
            cpu_cores: 0,
            ram_mb: 0,
            disk_gb: 10,
            expires_at: None,
        })
        .unwrap();

        let count = db.release_all_leases_str("instance", "inst-1").unwrap();
        assert_eq!(count, 2);

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 0);
        assert_eq!(ram, 0);
        let disk = db.sum_active_storage_leases().unwrap();
        assert_eq!(disk, 0);
    }

    #[test]
    fn lease_storage_sum() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Storage,
            cpu_cores: 0,
            ram_mb: 0,
            disk_gb: 10,
            expires_at: None,
        })
        .unwrap();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-2",
            lease_kind: LeaseKind::Storage,
            cpu_cores: 0,
            ram_mb: 0,
            disk_gb: 20,
            expires_at: None,
        })
        .unwrap();

        let disk = db.sum_active_storage_leases().unwrap();
        assert_eq!(disk, 30);
    }

    #[test]
    fn lease_finalize_clears_expiry() {
        let db = open_temp();
        let now = now_unix();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: Some(now + 600),
        })
        .unwrap();

        assert!(db.finalize_lease("instance", "inst-1", "runtime").unwrap());

        let leases = db.active_leases_for_owner("instance", "inst-1").unwrap();
        assert_eq!(leases.len(), 1);
        assert!(leases[0].expires_at.is_none());
    }

    #[test]
    fn lease_extend_updates_expiry() {
        let db = open_temp();
        let now = now_unix();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: Some(now + 600),
        })
        .unwrap();

        let new_expiry = now + 1200;
        assert!(
            db.extend_lease("instance", "inst-1", "runtime", new_expiry)
                .unwrap()
        );

        let leases = db.active_leases_for_owner("instance", "inst-1").unwrap();
        assert_eq!(leases[0].expires_at, Some(new_expiry));
    }

    #[test]
    fn lease_has_active() {
        let db = open_temp();
        assert!(
            !db.has_active_lease_str("instance", "inst-1", "runtime")
                .unwrap()
        );

        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        assert!(
            db.has_active_lease_str("instance", "inst-1", "runtime")
                .unwrap()
        );

        db.release_lease_str("instance", "inst-1", "runtime")
            .unwrap();
        assert!(
            !db.has_active_lease_str("instance", "inst-1", "runtime")
                .unwrap()
        );
    }

    #[test]
    fn lease_warm_pool_mixed_with_instance() {
        let db = open_temp();
        // Instance lease
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        // Warm pool lease
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        // Sum includes both
        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 4);
        assert_eq!(ram, 4096);
    }

    #[test]
    fn insert_with_leases_atomic() {
        let db = open_temp();
        let id = db.insert_with_leases(&foo_inst(), 600, None).unwrap();
        assert_eq!(id, "inst-foo");

        // Verify instance exists
        let row = db.get("inst-foo").unwrap().expect("instance");
        assert_eq!(row.status, InstanceStatus::Provisioning);

        // Verify 2 leases created
        let leases = db.active_leases_for_owner("instance", "inst-foo").unwrap();
        assert_eq!(leases.len(), 2);

        let runtime = leases.iter().find(|l| l.lease_kind == "runtime").unwrap();
        assert_eq!(runtime.cpu_cores, 2); // default from NewInstance
        assert_eq!(runtime.ram_mb, 2048);
        assert!(runtime.expires_at.is_some()); // TTL set

        let storage = leases.iter().find(|l| l.lease_kind == "storage").unwrap();
        assert_eq!(storage.disk_gb, 10); // default
        assert!(storage.expires_at.is_none()); // no TTL

        // Verify event recorded
        let events = db.list_instance_events("inst-foo", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "create_started");
    }

    #[test]
    fn insert_with_warm_pool_leases_transfers_runtime_atomically() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let id = db
            .insert_with_warm_pool_leases(&foo_inst(), 600, None)
            .unwrap();
        assert_eq!(id, "inst-foo");

        assert!(
            !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap()
        );

        let leases = db.active_leases_for_owner("instance", "inst-foo").unwrap();
        assert_eq!(leases.len(), 2);
        let runtime = leases.iter().find(|l| l.lease_kind == "runtime").unwrap();
        assert_eq!(runtime.cpu_cores, 2);
        assert_eq!(runtime.ram_mb, 2048);
        assert!(runtime.expires_at.is_some());

        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 2);
        assert_eq!(ram, 2048);
    }

    #[test]
    fn transfer_warm_pool_lease_works() {
        let db = open_temp();
        // Create a warm pool lease
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        // Also need an instance row for the guest_os join
        db.insert(&foo_inst()).unwrap();

        // Transfer to instance
        let transferred = db
            .transfer_warm_pool_lease("picoclaw", "inst-foo", 2, 2048)
            .unwrap();
        assert!(transferred);

        // Warm pool lease should be released
        assert!(
            !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap()
        );

        // Instance lease should exist
        assert!(
            db.has_active_lease_str("instance", "inst-foo", "runtime")
                .unwrap()
        );

        // Total runtime should still be 2 CPU / 2048 MB (ownership transfer, not addition)
        let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 2);
        assert_eq!(ram, 2048);
    }

    #[test]
    fn transfer_warm_pool_lease_returns_false_when_no_lease() {
        let db = open_temp();
        let transferred = db
            .transfer_warm_pool_lease("picoclaw", "inst-foo", 2, 2048)
            .unwrap();
        assert!(!transferred);
    }

    #[test]
    fn count_active_runtime_leases_by_guest_os_includes_macos_warm_pool() {
        let db = open_temp();
        db.insert(&NewInstance {
            id: "inst-mac",
            name: "inst-mac",
            container: "picoclaw-inst-mac",
            claw_type: "picoclaw",
            sunset_date: "",
            guest_os: Some("macos"),
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .unwrap();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-mac",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let count = db.count_active_runtime_leases_by_guest_os("macos").unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn instance_event_record_and_list() {
        let db = open_temp();
        db.record_instance_event(&NewInstanceEvent {
            instance_id: Some("inst-1"),
            event_type: "stopped",
            actor: "admin",
            detail: Some("user requested stop"),
            resource_snapshot: None,
        })
        .unwrap();
        db.record_instance_event(&NewInstanceEvent {
            instance_id: Some("inst-1"),
            event_type: "started",
            actor: "admin",
            detail: None,
            resource_snapshot: Some(r#"{"cpu":2}"#),
        })
        .unwrap();

        let events = db.list_instance_events("inst-1", 10).unwrap();
        assert_eq!(events.len(), 2);
        // Newest first
        assert_eq!(events[0].event_type, "started");
        assert_eq!(events[1].event_type, "stopped");
    }

    #[test]
    fn migration_idempotent() {
        // Opening twice on same :memory: path simulates re-running migrations
        let db = open_temp();
        drop(db);
        let db2 = InstanceDb::open(":memory:").expect("second open");
        // Should succeed without errors
        let (cpu, ram) = db2.sum_active_runtime_leases().unwrap();
        assert_eq!(cpu, 0);
        assert_eq!(ram, 0);
    }

    /// B4b byte-identity: the typed lease API and the raw `_str` layer agree on
    /// the exact wire bytes, both directions. A lease created with the typed
    /// `LeaseOwnerType`/`LeaseKind` is found by a raw string query using the
    /// historical literals, and a raw-string-created lease is found by a typed
    /// query — proving the typed producers still write `warm_pool`/`instance`/
    /// `runtime` unchanged.
    #[test]
    fn typed_lease_api_is_byte_identical_to_raw_str() {
        let db = open_temp();

        // Typed CREATE -> raw string query finds it with the old literals.
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        assert!(
            db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap(),
            "typed create must write the literal wire bytes 'warm_pool'/'runtime'"
        );

        // Raw string CREATE -> typed query finds it.
        db.create_lease_str("instance", "inst-1", "runtime", 1, 512, 0, None)
            .unwrap();
        assert!(
            db.has_active_lease(LeaseOwnerType::Instance, "inst-1", LeaseKind::Runtime)
                .unwrap(),
            "typed query must read leases written with the literal wire bytes"
        );
    }

    // ── P3: lease ownership invariants ──────────────────────────────────────

    /// `ux_active_lease_per_owner`: at most one ACTIVE lease per
    /// `(owner_type, owner_id, lease_kind)`. A second active lease for the same
    /// triple is rejected; after release a fresh one is allowed; a different
    /// `lease_kind` for the same owner is a distinct triple (allowed).
    #[test]
    fn inv_at_most_one_active_lease_per_owner_kind() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        // Second ACTIVE runtime lease for the same owner triple → rejected.
        assert!(
            db.create_lease(&NewLease {
                owner_type: LeaseOwnerType::Instance,
                owner_id: "i1",
                lease_kind: LeaseKind::Runtime,
                cpu_cores: 1,
                ram_mb: 512,
                disk_gb: 0,
                expires_at: None,
            })
            .is_err(),
            "a second active runtime lease for the same owner must be rejected"
        );
        // A different kind (storage) for the same owner_id is a distinct triple.
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Storage,
            cpu_cores: 0,
            ram_mb: 0,
            disk_gb: 10,
            expires_at: None,
        })
        .unwrap();
        // After releasing the runtime lease, a fresh one is allowed again.
        db.release_lease(LeaseOwnerType::Instance, "i1", LeaseKind::Runtime)
            .unwrap();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
    }

    /// DB `CHECK` constraints reject invalid lease rows: non-negative resources
    /// and `expires_at >= acquired_at`.
    #[test]
    fn inv_db_checks_reject_invalid_lease() {
        let db = open_temp();
        let mk = |cpu: i64, ram: i64, disk: i64, expires: Option<i64>| NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: cpu,
            ram_mb: ram,
            disk_gb: disk,
            expires_at: expires,
        };
        assert!(
            db.create_lease(&mk(-1, 0, 0, None)).is_err(),
            "cpu_cores >= 0"
        );
        assert!(db.create_lease(&mk(0, -1, 0, None)).is_err(), "ram_mb >= 0");
        assert!(
            db.create_lease(&mk(0, 0, -1, None)).is_err(),
            "disk_gb >= 0"
        );
        // expires_at in the past (< acquired_at = now) violates the temporal CHECK.
        assert!(
            db.create_lease(&mk(1, 1, 0, Some(1))).is_err(),
            "expires_at must be >= acquired_at"
        );
        // A valid lease still succeeds — the CHECKs don't reject good input.
        db.create_lease(&mk(1, 1, 0, None)).unwrap();
    }

    /// `transfer_warm_pool_lease` is atomic and conserves allocation: the warm
    /// lease is released and an instance lease created in one transaction; the
    /// total active runtime allocation is unchanged.
    #[test]
    fn inv_transfer_warm_pool_lease_is_atomic_and_conserves_allocation() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));
        assert!(
            db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap()
        );

        assert!(
            db.transfer_warm_pool_lease("picoclaw", "i1", 2, 2048)
                .unwrap()
        );
        assert!(
            !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap()
        );
        assert!(
            db.has_active_lease_str("instance", "i1", "runtime")
                .unwrap()
        );
        // Allocation conserved — still exactly one active runtime lease.
        assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));

        // No warm-pool lease left → no-op transfer returns false.
        assert!(
            !db.transfer_warm_pool_lease("picoclaw", "i2", 2, 2048)
                .unwrap()
        );
    }

    /// `transfer_warm_pool_lease` rolls back fully when its internal instance
    /// INSERT would violate `ux_active_lease_per_owner` — the warm lease is NOT
    /// released and the pre-existing instance lease is untouched.
    #[test]
    fn inv_transfer_warm_pool_lease_rolls_back_on_conflict() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        // The target instance ALREADY holds an active runtime lease.
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 1,
            ram_mb: 512,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        assert!(
            db.transfer_warm_pool_lease("picoclaw", "i1", 2, 2048)
                .is_err(),
            "transfer onto an instance that already holds a runtime lease must fail"
        );
        // Rollback: warm lease still active; i1's original lease intact.
        assert!(
            db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
                .unwrap()
        );
        assert!(
            db.has_active_lease_str("instance", "i1", "runtime")
                .unwrap()
        );
    }

    /// Releasing a runtime lease drops the allocation with no leak. This is the
    /// mechanism the reaper (expired) and reconcile (dead instance) use; pure
    /// clock-expiry is intentionally not fabricated (the DB `CHECK
    /// (expires_at >= acquired_at)` forbids a past-expiry row via the API, and we
    /// do not bypass schema).
    #[test]
    fn inv_release_drops_runtime_allocation_no_leak() {
        let db = open_temp();
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));
        db.release_lease(LeaseOwnerType::Instance, "i1", LeaseKind::Runtime)
            .unwrap();
        assert_eq!(
            db.sum_active_runtime_leases().unwrap(),
            (0, 0),
            "released lease must not leak into allocation"
        );
    }

    // ── shareable_apps: the Share's own identity authority (D6) ────────────

    fn scoped_inst<'a>(id: &'a str, name: &'a str, container: &'a str) -> NewInstance<'a> {
        NewInstance {
            id,
            name,
            container,
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: Some("hh_alpha"),
            household_machine_id: Some("m_alpha"),
        }
    }

    #[test]
    fn shareable_ensure_is_idempotent_and_never_resyncs_display_name() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let first = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
        assert!(first.app_id.starts_with("app_"));
        assert_eq!(first.app_id.len(), 4 + 32);
        assert_eq!(first.display_name, "alpha");
        assert_eq!(first.resource, SHAREABLE_APP_RESOURCE_CLAWSITE);

        // Instance renamed in the catalog AFTER the binding exists.
        let conn = db.conn().unwrap();
        conn.execute(
            "UPDATE instances SET name = 'alpha-renamed' WHERE id = 'inst-alpha'",
            [],
        )
        .unwrap();
        drop(conn);

        let second = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
        assert_eq!(second.app_id, first.app_id, "ensure must reuse the live binding");
        assert_eq!(
            second.display_name, "alpha",
            "ensure must NEVER re-sync display_name from instances.name"
        );
    }

    #[test]
    fn shareable_ensure_proves_instance_authority_before_any_binding() {
        let db = open_temp();
        // Unknown instance: no binding, uniform fail-closed.
        assert!(matches!(
            db.ensure_shareable_app("inst-ghost", "hh_alpha"),
            Err(StoreError::InstanceNotFound)
        ));
        // Unscoped instance (household NULL): same.
        db.insert(&NewInstance {
            household_id: None,
            household_machine_id: None,
            ..scoped_inst("inst-unscoped", "unscoped", "picoclaw-unscoped")
        })
        .unwrap();
        assert!(matches!(
            db.ensure_shareable_app("inst-unscoped", "hh_alpha"),
            Err(StoreError::InstanceNotFound)
        ));
        // Foreign-scoped instance: same, and nothing was ever written.
        db.insert(&NewInstance {
            household_id: Some("hh_other"),
            ..scoped_inst("inst-foreign", "foreign", "picoclaw-foreign")
        })
        .unwrap();
        assert!(matches!(
            db.ensure_shareable_app("inst-foreign", "hh_alpha"),
            Err(StoreError::InstanceNotFound)
        ));
        let conn = db.conn().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM shareable_apps", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "failed authority proofs must never write bindings");
    }

    #[test]
    fn shareable_foreign_ensure_cannot_tombstone_another_households_binding() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        // A caller naming a DIFFERENT household while the row is still
        // hh_alpha-scoped is rejected BEFORE touching the binding.
        assert!(matches!(
            db.ensure_shareable_app("inst-alpha", "hh_evil"),
            Err(StoreError::InstanceNotFound)
        ));
        let (binding, _) = db
            .resolve_live_shareable_app(&app.app_id, "hh_alpha")
            .unwrap()
            .expect("the live binding must survive the foreign attempt");
        assert_eq!(binding.app_id, app.app_id);
        assert!(binding.retired_at.is_none());
    }

    #[test]
    fn shareable_same_display_name_bindings_resolve_independently() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-one", "one", "picoclaw-one")).unwrap();
        db.insert(&scoped_inst("inst-two", "two", "picoclaw-two")).unwrap();
        let app_one = db.ensure_shareable_app("inst-one", "hh_alpha").unwrap();
        let app_two = db.ensure_shareable_app("inst-two", "hh_alpha").unwrap();
        assert_ne!(app_one.app_id, app_two.app_id);

        // BOTH renamed to the same display name: identity/routing never keys on it.
        db.rename_shareable_app(&app_one.app_id, "hh_alpha", "Study")
            .unwrap();
        db.rename_shareable_app(&app_two.app_id, "hh_alpha", "Study")
            .unwrap();
        db.update_port("inst-one", 8101).unwrap();
        db.update_port("inst-two", 8202).unwrap();

        let (binding_one, instance_one) = db
            .resolve_live_shareable_app(&app_one.app_id, "hh_alpha")
            .unwrap()
            .expect("app one resolves");
        let (binding_two, instance_two) = db
            .resolve_live_shareable_app(&app_two.app_id, "hh_alpha")
            .unwrap()
            .expect("app two resolves");
        assert_eq!(binding_one.display_name, binding_two.display_name);
        assert_eq!(instance_one.host_port, Some(8101));
        assert_eq!(instance_two.host_port, Some(8202));
        assert_ne!(instance_one.id, instance_two.id);
    }

    #[test]
    fn shareable_rename_preserves_identity_and_is_scoped_fail_closed() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        db.rename_shareable_app(&app.app_id, "hh_alpha", "French 101")
            .unwrap();
        let (binding, _) = db
            .resolve_live_shareable_app(&app.app_id, "hh_alpha")
            .unwrap()
            .unwrap();
        assert_eq!(binding.app_id, app.app_id);
        assert_eq!(binding.display_name, "French 101");

        // Foreign household and invalid names all fail closed.
        assert!(matches!(
            db.rename_shareable_app(&app.app_id, "hh_other", "nope"),
            Err(StoreError::InstanceNotFound)
        ));
        assert!(db.rename_shareable_app(&app.app_id, "hh_alpha", "").is_err());
        assert!(db.rename_shareable_app(&app.app_id, "hh_alpha", "   ").is_err());
        assert!(db
            .rename_shareable_app(&app.app_id, "hh_alpha", &"x".repeat(129))
            .is_err());
    }

    #[test]
    fn shareable_soft_delete_tombstones_and_recreate_mints_fresh_id() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let old = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        db.soft_delete("inst-alpha").unwrap();
        assert!(
            db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
                .unwrap()
                .is_none(),
            "deleted instance must fail closed"
        );
        {
            let conn = db.conn().unwrap();
            let retired: Option<i64> = conn
                .query_row(
                    "SELECT retired_at FROM shareable_apps WHERE app_id = ?1",
                    params![old.app_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                retired.is_some(),
                "soft delete must tombstone the binding in the SAME transaction"
            );
        }

        // Hard delete frees the name/id; recreate with the SAME technical slug.
        db.delete("inst-alpha").unwrap();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let new = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
        assert_ne!(
            old.app_id, new.app_id,
            "delete+recreate must yield a different app_id"
        );
        assert!(
            db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
                .unwrap()
                .is_none(),
            "the old binding stays tombstoned forever"
        );
        assert!(
            db.resolve_live_shareable_app(&new.app_id, "hh_alpha")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn shareable_hard_delete_never_leaves_a_live_binding() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        // The provisioning rollback path: succeeds AND leaves nothing resolvable.
        db.delete("inst-alpha").unwrap();
        assert!(
            db.resolve_live_shareable_app(&app.app_id, "hh_alpha")
                .unwrap()
                .is_none()
        );
        let conn = db.conn().unwrap();
        let retired: Option<i64> = conn
            .query_row(
                "SELECT retired_at FROM shareable_apps WHERE app_id = ?1",
                params![app.app_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(retired.is_some(), "hard delete must tombstone in the same tx");
    }

    #[test]
    fn shareable_resolve_is_household_scoped_and_readiness_is_not_terminal() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        // Foreign household: indistinguishable fail-closed None.
        assert!(
            db.resolve_live_shareable_app(&app.app_id, "hh_other")
                .unwrap()
                .is_none()
        );
        // No host_port yet: identity VALID, readiness absent — Some, not terminal.
        let (_, instance) = db
            .resolve_live_shareable_app(&app.app_id, "hh_alpha")
            .unwrap()
            .expect("identity resolves even without host_port");
        assert_eq!(instance.host_port, None);
    }

    #[test]
    fn shareable_repair_retires_stale_binding_only_after_row_rescope() {
        let db = open_temp();
        db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
            .unwrap();
        let old = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

        // While the row is still hh_alpha-scoped, an hh_beta ensure is rejected
        // and the live binding is untouched.
        assert!(matches!(
            db.ensure_shareable_app("inst-alpha", "hh_beta"),
            Err(StoreError::InstanceNotFound)
        ));
        assert!(
            db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
                .unwrap()
                .is_some()
        );

        // Re-pair: the row itself is re-scoped to hh_beta. The JOIN pin makes
        // the old identity stop resolving IMMEDIATELY (scope moved), and only
        // NOW may ensure tombstone the stale binding and re-mint.
        let conn = db.conn().unwrap();
        conn.execute(
            "UPDATE instances SET household_id = 'hh_beta', household_machine_id = 'm_beta' \
             WHERE id = 'inst-alpha'",
            [],
        )
        .unwrap();
        drop(conn);
        assert!(
            db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
                .unwrap()
                .is_none(),
            "re-scoped instance must strand the old identity at once"
        );
        let new = db.ensure_shareable_app("inst-alpha", "hh_beta").unwrap();
        assert_ne!(old.app_id, new.app_id);
        assert_eq!(new.household_id, "hh_beta");
        assert!(
            db.resolve_live_shareable_app(&old.app_id, "hh_beta")
                .unwrap()
                .is_none(),
            "the stale binding must not resolve under any household"
        );
        assert!(
            db.resolve_live_shareable_app(&new.app_id, "hh_beta")
                .unwrap()
                .is_some()
        );
    }
}
