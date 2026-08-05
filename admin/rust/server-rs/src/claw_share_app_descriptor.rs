//! The Share's stable app contract (Slice B, D6): typed app identity, the
//! descriptor the picker/guest surfaces carry, and the terminal-vs-recoverable
//! resolution boundary.
//!
//! Two namespaces exist this cycle and are kept apart BY TYPE, not by
//! convention: [`DeviceShareAppId`] (the Share's own authority, minted by
//! `shareable_apps` in store-rs) and [`LegacyClawId`] (the pre-D6 namespace
//! Group/Public/dev flows still use). The wire field `claw_id: String` remains
//! for compatibility, but conversion to a raw string happens ONLY at the
//! signed edge — no internal call site accepts an ambiguous raw claw string.

use store_rs::instance_db::InstanceDb;
use store_rs::{InstanceStatus, StoreError};

/// The Share's own stable app identity: `app_` + 32 lowercase hex (128 bits
/// CSPRNG, pinned format). Random, immutable, never name-derived — a
/// delete+recreate of the same app always yields a different one. NOT a
/// secret/capability: authorization stays with the owner signature and the
/// live gate; this is routing/identity only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceShareAppId(String);

/// Rejection for a raw string that is not the pinned id shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceShareAppIdError;

const DEVICE_SHARE_APP_ID_PREFIX: &str = "app_";
const DEVICE_SHARE_APP_ID_HEX_LEN: usize = 32;

impl DeviceShareAppId {
    /// Borrow the pinned string for the SIGNED wire edge only
    /// (`offer.claw_id`, the signed presentation). Internal routing uses the
    /// typed value, never this string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Owned form of the signed-edge string.
    #[must_use]
    pub fn into_wire_string(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for DeviceShareAppId {
    type Error = DeviceShareAppIdError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let hex = raw
            .strip_prefix(DEVICE_SHARE_APP_ID_PREFIX)
            .ok_or(DeviceShareAppIdError)?;
        if hex.len() != DEVICE_SHARE_APP_ID_HEX_LEN
            || !hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(DeviceShareAppIdError);
        }
        Ok(Self(raw.to_string()))
    }
}

/// The pre-D6 claw namespace: Group/Public offers and dev fixtures keep using
/// it this cycle, unchanged. Typed so no API can accidentally accept it where
/// a [`DeviceShareAppId`] is required (or vice versa).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegacyClawId(String);

/// Rejection for an empty or oversized legacy claw string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyClawIdError;

const LEGACY_CLAW_ID_MAX_CHARS: usize = 128;

impl LegacyClawId {
    /// Borrow the legacy string for the wire edge of the LEGACY paths only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LegacyClawId {
    type Error = LegacyClawIdError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let len = raw.chars().count();
        if len == 0 || len > LEGACY_CLAW_ID_MAX_CHARS || raw.trim().is_empty() {
            return Err(LegacyClawIdError);
        }
        Ok(Self(raw))
    }
}

/// Readiness of a shared app: RUNTIME state, deliberately separate from
/// identity. Identity lives or dies terminally; readiness recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareReadiness {
    Running,
    Starting,
    Stopped,
    Unavailable,
}

/// The stable cross-repo descriptor (D3: no icon this cycle — the UI renders
/// a generic local symbol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareableAppDescriptor {
    pub app_id: DeviceShareAppId,
    /// Semantically distinct from `app_id` even though the two coincide in
    /// the current model: the signed offer's `claw_id` pins this value, and
    /// the resolver pins `offer.claw_id == app_id`.
    pub claw_id: DeviceShareAppId,
    pub display_name: String,
    /// This cycle mints `ClawSite` only; kept as a field (not an assumption) so
    /// a future resource never rides in silently.
    pub resource: ShareAppResource,
    pub readiness: ShareReadiness,
}

/// Resources a shared app may serve this cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareAppResource {
    ClawSite,
}

/// A resolved app that is actually dialable: the descriptor PLUS the backend
/// port the caller must connect to. The port rides the `Ready` result because
/// the readiness decision already had to look at it — a caller that re-queried
/// the store for the port would be reading a row that may have changed since
/// the decision, which is the race this type exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareReadyApp {
    pub descriptor: ShareableAppDescriptor,
    /// Present, in `u16` range, and nonzero — the exact precondition `Ready`
    /// asserts. Unrepresentable otherwise, so `Ready` cannot be constructed
    /// without one.
    pub backend_port: u16,
}

/// The terminal-vs-recoverable boundary, typed so no caller can confuse them:
/// `Unavailable` is a VALID identity in a recoverable runtime state (D1);
/// `Terminal` is fail-closed and deliberately carries no detail — unknown,
/// retired, foreign, and deleted must stay indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareResolution {
    Ready(ShareReadyApp),
    Unavailable(ShareableAppDescriptor),
    Terminal,
}

impl ShareResolution {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal)
    }
}

/// Narrow the stored `host_port` (`INTEGER`, so an unconstrained `i64`) to a
/// port that can actually be dialed. `u16::try_from` rejects negatives and
/// anything above 65535 in one step — no lossy cast — and port 0 is rejected
/// because it means "let the OS choose", never a reachable backend.
fn valid_backend_port(host_port: Option<i64>) -> Option<u16> {
    host_port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
}

/// Readiness is derived from the ALREADY-VALIDATED port, not from the raw
/// column. Taking `Option<u16>` here is what keeps `descriptor.readiness` and
/// the `ShareResolution` variant from disagreeing: there is no way to report
/// `Running` for a port that `valid_backend_port` rejected.
fn readiness_of(status: InstanceStatus, backend_port: Option<u16>) -> ShareReadiness {
    match status {
        // Running requires a backend to actually reach: an Active row without
        // a usable host port is recoverable-unavailable, not running.
        InstanceStatus::Active if backend_port.is_some() => ShareReadiness::Running,
        InstanceStatus::Active | InstanceStatus::Failed => ShareReadiness::Unavailable,
        InstanceStatus::Provisioning => ShareReadiness::Starting,
        InstanceStatus::Stopped => ShareReadiness::Stopped,
    }
}

/// Resolve a Device Share identity for the dial/mint path. The SQL authority
/// (`resolve_live_shareable_app`) already collapsed every terminal case into
/// `None`; this layer only classifies readiness for live identities.
pub fn resolve_device_share_app(
    db: &InstanceDb,
    app_id: &DeviceShareAppId,
    household_id: &str,
) -> Result<ShareResolution, StoreError> {
    let Some((binding, instance)) = db.resolve_live_shareable_app(app_id.as_str(), household_id)?
    else {
        return Ok(ShareResolution::Terminal);
    };
    // Non-ClawSite bindings are fail-closed terminal: a corrupted/legacy/
    // hand-written row must never become ClawSite by constant. Deliberately
    // indistinguishable from unknown/retired/foreign/deleted.
    if binding.resource != store_rs::instance_db::SHAREABLE_APP_RESOURCE_CLAWSITE {
        return Ok(ShareResolution::Terminal);
    }
    let backend_port = valid_backend_port(instance.host_port);
    let readiness = readiness_of(instance.status, backend_port);
    let descriptor = ShareableAppDescriptor {
        app_id: app_id.clone(),
        claw_id: app_id.clone(),
        display_name: binding.display_name,
        resource: ShareAppResource::ClawSite,
        readiness,
    };
    // Pairing the two is what makes "Ready implies a port" structural rather
    // than a comment: `Running` is only reachable with `Some(port)` above, and
    // the unreachable `(Running, None)` still falls closed to `Unavailable`.
    Ok(match (readiness, backend_port) {
        (ShareReadiness::Running, Some(backend_port)) => ShareResolution::Ready(ShareReadyApp {
            descriptor,
            backend_port,
        }),
        _ => ShareResolution::Unavailable(descriptor),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use store_rs::instance_db::{InstanceDb, NewInstance};

    fn open_temp() -> InstanceDb {
        InstanceDb::open(":memory:").expect("open :memory:")
    }

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

    fn bound_db(name: &str) -> (InstanceDb, DeviceShareAppId) {
        let db = open_temp();
        let container = format!("picoclaw-{name}");
        db.insert(&scoped_inst("inst-app", name, &container)).unwrap();
        let binding = db.ensure_shareable_app("inst-app", "hh_alpha").unwrap();
        let app_id = DeviceShareAppId::try_from(binding.app_id.as_str()).unwrap();
        (db, app_id)
    }

    #[test]
    fn device_share_app_id_accepts_only_the_pinned_shape() {
        let valid = format!("app_{:032x}", 0xabc123_u128);
        assert!(DeviceShareAppId::try_from(valid.as_str()).is_ok());
        for bad in [
            "",
            "claw_alpha",
            "app_short",
            "app_0123456789abcdef0123456789abcg",   // non-hex tail
            "app_0123456789ABCDEF0123456789abcdef", // uppercase hex
            "app_0123456789abcdef0123456789abcdef0", // 33 hex chars
            "app-0123456789abcdef0123456789abcdef", // wrong separator
        ] {
            assert!(
                DeviceShareAppId::try_from(bad).is_err(),
                "must reject: {bad:?}"
            );
        }
    }

    #[test]
    fn legacy_claw_id_is_nonempty_and_bounded() {
        assert!(LegacyClawId::try_from("claw_alpha".to_string()).is_ok());
        assert!(LegacyClawId::try_from(String::new()).is_err());
        assert!(LegacyClawId::try_from("   ".to_string()).is_err());
        assert!(LegacyClawId::try_from("x".repeat(129)).is_err());
    }

    #[test]
    fn unknown_app_id_is_terminal_and_detail_free() {
        let db = open_temp();
        let missing = DeviceShareAppId::try_from(format!("app_{:032x}", 7_u128).as_str()).unwrap();
        let resolution = resolve_device_share_app(&db, &missing, "hh_alpha").unwrap();
        assert_eq!(resolution, ShareResolution::Terminal);
        assert!(resolution.is_terminal());
    }

    #[test]
    fn ready_requires_host_port_and_active_status() {
        let (db, app_id) = bound_db("alpha");
        db.update_port("inst-app", 8080).unwrap();
        db.update_status(&store_rs::instance_db::StatusUpdate {
            id: "inst-app",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let ShareResolution::Ready(ready) =
            resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap()
        else {
            panic!("active instance with a port must be Ready");
        };
        // The whole point of the typed Ready: the dial port rides the decision,
        // so the router never re-queries a row that may have moved since.
        assert_eq!(
            ready.backend_port, 8080,
            "Ready must carry the exact stored port"
        );
        let descriptor = ready.descriptor;
        assert_eq!(descriptor.app_id, app_id);
        assert_eq!(descriptor.claw_id, app_id);
        assert_eq!(descriptor.display_name, "alpha");
        assert_eq!(descriptor.resource, ShareAppResource::ClawSite);
        assert_eq!(descriptor.readiness, ShareReadiness::Running);
    }

    /// Set an Active instance's port to `stored` and resolve it.
    fn resolve_active_with_port(stored: i64) -> (ShareResolution, DeviceShareAppId) {
        let (db, app_id) = bound_db("alpha");
        db.update_port("inst-app", stored).unwrap();
        db.update_status(&store_rs::instance_db::StatusUpdate {
            id: "inst-app",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let resolution = resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap();
        (resolution, app_id)
    }

    #[test]
    fn out_of_range_and_zero_ports_are_unavailable_never_ready() {
        // 0 means "OS picks one", negatives cannot be dialed, and anything past
        // u16::MAX cannot be a TCP port. All are recoverable, never terminal.
        for stored in [0_i64, -1, i64::from(u16::MAX) + 1, 70_000, i64::MAX] {
            let (resolution, app_id) = resolve_active_with_port(stored);
            let ShareResolution::Unavailable(descriptor) = resolution else {
                panic!("stored port {stored} must not resolve to Ready");
            };
            // Zelia's pin: the descriptor's own readiness must agree with the
            // variant, or the HTTP list would advertise `running` for an app
            // the mint path treats as unavailable.
            assert_eq!(
                descriptor.readiness,
                ShareReadiness::Unavailable,
                "stored port {stored} must report Unavailable readiness too"
            );
            assert_eq!(descriptor.app_id, app_id);
        }
    }

    #[test]
    fn non_active_status_stays_unavailable_even_with_a_valid_port() {
        // A dialable port must not promote a Stopped/Provisioning/Failed row:
        // status leads, the port only ever demotes.
        for status in [
            InstanceStatus::Stopped,
            InstanceStatus::Provisioning,
            InstanceStatus::Failed,
        ] {
            let (db, app_id) = bound_db("alpha");
            db.update_port("inst-app", 8080).unwrap();
            db.update_status(&store_rs::instance_db::StatusUpdate {
                id: "inst-app",
                status,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .unwrap();
            let resolution = resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap();
            assert!(
                matches!(resolution, ShareResolution::Unavailable(_)),
                "{status:?} with a valid port must stay Unavailable, got {resolution:?}"
            );
        }
    }

    #[test]
    fn boundary_ports_one_and_u16_max_stay_ready() {
        // The rejection is nonzero + in-range, nothing narrower: the two
        // extremes of the valid range must survive.
        for stored in [1_i64, i64::from(u16::MAX)] {
            let (resolution, _) = resolve_active_with_port(stored);
            let ShareResolution::Ready(ready) = resolution else {
                panic!("stored port {stored} is dialable and must be Ready");
            };
            assert_eq!(
                u64::from(ready.backend_port),
                u64::try_from(stored).unwrap()
            );
            assert_eq!(ready.descriptor.readiness, ShareReadiness::Running);
        }
    }

    #[test]
    fn missing_host_port_is_recoverable_unavailable_not_terminal() {
        let (db, app_id) = bound_db("alpha");
        db.update_status(&store_rs::instance_db::StatusUpdate {
            id: "inst-app",
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let ShareResolution::Unavailable(descriptor) =
            resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap()
        else {
            panic!("no host_port must be recoverable Unavailable, never terminal");
        };
        assert_eq!(descriptor.readiness, ShareReadiness::Unavailable);
        assert_eq!(descriptor.app_id, app_id);
    }

    #[test]
    fn stopped_and_provisioning_are_recoverable_states() {
        let (db, app_id) = bound_db("alpha");
        // Fresh insert is Provisioning → Starting.
        let ShareResolution::Unavailable(descriptor) =
            resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap()
        else {
            panic!("provisioning must classify as Starting/unavailable");
        };
        assert_eq!(descriptor.readiness, ShareReadiness::Starting);

        db.update_status(&store_rs::instance_db::StatusUpdate {
            id: "inst-app",
            status: InstanceStatus::Stopped,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let ShareResolution::Unavailable(descriptor) =
            resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap()
        else {
            panic!("stopped must classify as Stopped/unavailable");
        };
        assert_eq!(descriptor.readiness, ShareReadiness::Stopped);

        // Failed is a recoverable identity state too — Unavailable, never
        // terminal (the binding lives; the app may come back) and never Ready.
        db.update_status(&store_rs::instance_db::StatusUpdate {
            id: "inst-app",
            status: InstanceStatus::Failed,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
        let ShareResolution::Unavailable(descriptor) =
            resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap()
        else {
            panic!("failed must classify as Unavailable, not Ready/Terminal");
        };
        assert_eq!(descriptor.readiness, ShareReadiness::Unavailable);
        assert_eq!(descriptor.app_id, app_id);
    }

    #[test]
    fn non_clawsite_binding_resource_is_terminal() {
        // File-backed db so the test can corrupt the binding row from a raw
        // second connection (the store exposes no resource-mutation API).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("share-test.db");
        let db = InstanceDb::open(path.to_str().unwrap()).unwrap();
        db.insert(&scoped_inst("inst-app", "alpha", "picoclaw-alpha"))
            .unwrap();
        let binding = db.ensure_shareable_app("inst-app", "hh_alpha").unwrap();
        let app_id = DeviceShareAppId::try_from(binding.app_id.as_str()).unwrap();
        db.update_port("inst-app", 8080).unwrap();

        // Corrupted/legacy/hand-written row: a live binding whose resource is
        // not clawsite must fail closed, never become ClawSite by constant.
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute(
            "UPDATE shareable_apps SET resource = 'pty' WHERE retired_at IS NULL",
            [],
        )
        .unwrap();
        drop(raw);

        let resolution = resolve_device_share_app(&db, &app_id, "hh_alpha").unwrap();
        assert_eq!(resolution, ShareResolution::Terminal);
    }

    #[test]
    fn foreign_household_is_terminal() {
        let (db, app_id) = bound_db("alpha");
        let resolution = resolve_device_share_app(&db, &app_id, "hh_other").unwrap();
        assert_eq!(resolution, ShareResolution::Terminal);
    }
}
