//! `bootstrap_or_load` — orchestrates first-install vs idempotent paths.
//!
//! Emits the FR-014 stage set:
//!
//! ```text
//! bootstrap.start
//! bootstrap.key_gen.household
//! bootstrap.key_gen.machine
//! bootstrap.keystore.write   { which = "household" | "machine" }
//! bootstrap.persist.household_record
//! bootstrap.persist.machine_cert
//! ```
//!
//! Or, on idempotent rerun, a single `bootstrap.skip` line.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tracing::{error, info};

/// Convert an `Instant` elapsed duration to whole milliseconds without
/// overflowing `u64`. The duration would have to exceed ~584 million years
/// to overflow, which is impossible in any realistic bootstrap scenario;
/// `u64::MAX` is the saturating sentinel.
fn elapsed_ms_clamped(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn unix_now(stage: &'static str) -> Result<u64, BootstrapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| BootstrapError::Clock {
            stage,
            message: e.to_string(),
        })
}

fn log_ts() -> String {
    core_rs::time::format_iso(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

use crate::chain::verify_loaded_chain;
use crate::error::{BootstrapError, HouseholdError, KeystoreError, StorageError};
use crate::household_record::{HouseholdRecord, validate_household_name};
use crate::ids::{HouseholdId, MachineId, derive_household_id, derive_machine_id};
use crate::keys::{IdentityKey, P256Keypair, P256PublicKey, P256Signature, verify_signature};
use crate::keystore;
use crate::machine_cert::{MachineCert, Platform, SignOptions};
use crate::storage::{
    self, atomic_write_cbor, household_record_path, machine_cert_for, self_m_id_marker_path,
};

/// Caller-supplied options for a fresh bootstrap.
#[derive(Clone)]
pub struct BootstrapOpts {
    pub household_name: String,
    /// Optional explicit hostname label; if `None`, the OS hostname is used.
    pub hostname_label: Option<String>,
}

/// Selects the backing keystore for identity material.
///
/// Production binaries call [`KeyBackingPolicy::from_env`] once at startup so
/// the `THEYOS_FORCE_SOFTWARE_KEYS=1` operator override is honored. Tests pass
/// [`KeyBackingPolicy::ForceSoftware`] explicitly, which avoids any
/// process-wide env mutation (UB under Rust 2024 with the parallel test
/// runner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBackingPolicy {
    /// OS default: Secure Enclave on macOS, file-fallback on Linux.
    OsDefault,
    /// Force the file-backed software keystore regardless of OS — covers
    /// macOS without SE access, Intel pre-T2 hardware, and CI runners.
    ForceSoftware,
}

impl KeyBackingPolicy {
    /// Read `THEYOS_FORCE_SOFTWARE_KEYS=1` from the process environment.
    ///
    /// This is the only place that touches env vars for keystore selection;
    /// callers that already know the policy (tests, fuzzers) MUST construct
    /// the variant directly.
    #[must_use]
    pub fn from_env() -> Self {
        if std::env::var("THEYOS_FORCE_SOFTWARE_KEYS")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            Self::ForceSoftware
        } else {
            Self::OsDefault
        }
    }

    #[must_use]
    pub fn is_force_software(self) -> bool {
        matches!(self, Self::ForceSoftware)
    }
}

/// Loaded identity material — owned by the long-running server.
///
/// `hh_priv` is `Some` only while the household is in single-machine
/// (sole-shard) mode (`record.shamir_n == 1`). Once the Phase 3 Shamir
/// transition commits, the keystore custody of `HH_priv` is destroyed by
/// [`destroy_household_keystore_material`], the next `try_load_existing`
/// observes `record.shamir_n > 1`, and `hh_priv` is delivered as `None`.
/// Handlers that sign under the household root MUST gate on
/// `record.shamir_n == 1` AND `hh_priv.is_some()`; both checks are required
/// because the in-memory state may briefly trail the on-disk record between
/// startup and bootstrap completion.
pub struct LoadedIdentity {
    pub record: HouseholdRecord,
    pub cert: MachineCert,
    pub hh_priv: Option<Box<dyn IdentityKey>>,
    pub m_priv: Box<dyn IdentityKey>,
    /// `secure_enclave` on macOS, `software` everywhere else
    /// (also reflected in `key_gen.*` log lines).
    pub backing: &'static str,
}

/// Server-start path: load identity if both files are present and the chain
/// verifies. Returns `Ok(None)` if no record/cert exist (uninitialized state),
/// `Err` if the files are partially present or corrupted (refuse-to-start
/// per US1 acceptance C6).
pub fn try_load_existing(
    state_dir: &Path,
    policy: KeyBackingPolicy,
) -> Result<Option<LoadedIdentity>, BootstrapError> {
    // R6.4: run the boot-time migrations + recovery probes BEFORE
    // reading the record. The server boot path enters here
    // (`bootstrap_household → try_load_existing`), not through
    // `bootstrap_or_load`, so without this call the Phase-3
    // recovery primitives (`recover_partial_phase3_commit`,
    // `recover_post_join_sole_shard`, `recover_self_m_id_marker`,
    // legacy file migrations) never run on a real server reboot.
    // The probes are idempotent — steady-state boots see no `.staged`
    // siblings and return immediately.
    storage::load_state_dir(state_dir).map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "load.migrate_state_dir",
    })?;

    let record_path = household_record_path(state_dir);

    let existing_record: Option<HouseholdRecord> = storage::read_optional_cbor(&record_path)
        .map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "load.household_record",
        })?;
    let existing_cert: Option<MachineCert> = crate::machine_cert::load_self_cert(state_dir)
        .map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "load.machine_cert",
        })?;

    match (existing_record, existing_cert) {
        (Some(record), Some(cert)) => {
            verify_loaded_chain(&record, &cert).map_err(|e| BootstrapError::Encoding {
                source: e,
                stage: "load.verify_chain",
            })?;
            info!(
                ts = %log_ts(),
                stage = "bootstrap.skip",
                elapsed_ms = 0_u64,
                result = "ok",
                hh_id = %record.hh_id,
                name = %record.name,
                created_at = record.created_at,
            );
            let m_priv = read_existing_machine_key(state_dir, &cert.m_id, policy)?;
            ensure_loaded_key_matches(
                "keystore.read.machine",
                m_priv.as_ref(),
                &cert.m_pub,
                "machine",
            )?;
            let (hh_priv, backing) = if record.has_local_household_private_key() {
                let hh_priv = read_existing_household_key(state_dir, &record.hh_id, policy)?;
                ensure_loaded_key_matches(
                    "keystore.read.household",
                    hh_priv.as_ref(),
                    &record.hh_pub,
                    "household",
                )?;
                let backing = hh_priv.backing();
                (Some(hh_priv), backing)
            } else {
                // Post-Shamir: the keystore custody of `HH_priv` was
                // destroyed at commit time. Carry the machine-key backing
                // so observability stays consistent.
                //
                // Idempotently re-attempt destruction here as the
                // boot-time safety net for the B1 invariant: when
                // `CeremonyTxn::commit` ran into a transient keystore
                // error post `staged.commit()`, the household record on
                // disk is already `shamir_n > 1` but the keystore entry
                // for `HH_priv` may still exist. `destroy_household_…`
                // primitives map `NotFound -> Ok(())` per backend, so
                // the steady-state re-call is a no-op. A failure here
                // is logged at WARN and not propagated — the load must
                // succeed even if the residual cleanup hasn't, because
                // the household has already grown to N=2 and refusing
                // to start would be worse than a logged residue.
                if !record.is_follower {
                    if let Err(e) =
                        destroy_household_keystore_material(state_dir, &record.hh_id, policy)
                    {
                        tracing::warn!(
                            stage = "bootstrap.post_shamir_destroy_retry",
                            hh_id = %record.hh_id,
                            error = %e,
                            "boot-time HH_priv keystore destruction retry failed; \
                             ceremony already committed, residue persists until next boot",
                        );
                    } else {
                        tracing::info!(
                            stage = "bootstrap.post_shamir_destroy_retry",
                            hh_id = %record.hh_id,
                            "boot-time HH_priv keystore destruction retry: idempotent (NotFound or freshly destroyed)",
                        );
                    }
                }
                (None, m_priv.backing())
            };
            Ok(Some(LoadedIdentity {
                record,
                cert,
                hh_priv,
                m_priv,
                backing,
            }))
        }
        (Some(record), None) if record.is_follower => Ok(None),
        (Some(_), None) => Err(BootstrapError::CertMissingButRecordPresent),
        (None, Some(_)) => Err(BootstrapError::RecordMissingButCertPresent),
        (None, None) => Ok(None),
    }
}

/// Idempotent install entry point. Either loads existing identity from disk,
/// or performs a fresh bootstrap.
pub fn bootstrap_or_load(
    state_dir: &Path,
    opts: BootstrapOpts,
    policy: KeyBackingPolicy,
) -> Result<LoadedIdentity, BootstrapError> {
    let bootstrap_started = Instant::now();
    info!(
        ts = %log_ts(),
        stage = "bootstrap.start",
        elapsed_ms = 0_u64,
        result = "ok",
        state_dir = %state_dir.display(),
    );

    // Run idempotent file-layout migrations once at boot (Phase 3 T005/T005a).
    // No-op for fresh installs.
    storage::load_state_dir(state_dir).map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "load.migrate_state_dir",
    })?;

    let record_path = household_record_path(state_dir);

    let existing_record: Option<HouseholdRecord> = storage::read_optional_cbor(&record_path)
        .map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "load.household_record",
        })?;
    let existing_cert: Option<MachineCert> = crate::machine_cert::load_self_cert(state_dir)
        .map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "load.machine_cert",
        })?;

    match (existing_record, existing_cert) {
        (Some(record), Some(cert)) => {
            verify_loaded_chain(&record, &cert).map_err(|e| BootstrapError::Encoding {
                source: e,
                stage: "load.verify_chain",
            })?;
            info!(
                ts = %log_ts(),
                stage = "bootstrap.skip",
                elapsed_ms = elapsed_ms_clamped(bootstrap_started),
                result = "ok",
                hh_id = %record.hh_id,
                name = %record.name,
                created_at = record.created_at,
            );
            let m_priv = read_existing_machine_key(state_dir, &cert.m_id, policy)?;
            ensure_loaded_key_matches(
                "keystore.read.machine",
                m_priv.as_ref(),
                &cert.m_pub,
                "machine",
            )?;
            let (hh_priv, backing) = if record.has_local_household_private_key() {
                let hh_priv = read_existing_household_key(state_dir, &record.hh_id, policy)?;
                ensure_loaded_key_matches(
                    "keystore.read.household",
                    hh_priv.as_ref(),
                    &record.hh_pub,
                    "household",
                )?;
                let backing = hh_priv.backing();
                (Some(hh_priv), backing)
            } else {
                // Boot-time B1 invariant retry — see equivalent comment
                // in `try_load_existing` above.
                if !record.is_follower {
                    if let Err(e) =
                        destroy_household_keystore_material(state_dir, &record.hh_id, policy)
                    {
                        tracing::warn!(
                            stage = "bootstrap.post_shamir_destroy_retry",
                            hh_id = %record.hh_id,
                            error = %e,
                            "boot-time HH_priv keystore destruction retry failed; \
                             ceremony already committed, residue persists until next boot",
                        );
                    } else {
                        tracing::info!(
                            stage = "bootstrap.post_shamir_destroy_retry",
                            hh_id = %record.hh_id,
                            "boot-time HH_priv keystore destruction retry: idempotent (NotFound or freshly destroyed)",
                        );
                    }
                }
                (None, m_priv.backing())
            };
            Ok(LoadedIdentity {
                record,
                cert,
                hh_priv,
                m_priv,
                backing,
            })
        }
        (Some(record), None) if record.is_follower => Err(BootstrapError::InvalidOption(
            "accept-household follower record is awaiting confirm".into(),
        )),
        (Some(_), None) => Err(BootstrapError::CertMissingButRecordPresent),
        (None, Some(_)) => Err(BootstrapError::RecordMissingButCertPresent),
        (None, None) => {
            drop_legacy_tables_before_first_bootstrap(state_dir)?;
            fresh_bootstrap(state_dir, opts, policy, bootstrap_started)
        }
    }
}

fn drop_legacy_tables_before_first_bootstrap(state_dir: &Path) -> Result<(), BootstrapError> {
    let db_path = std::env::var("THEYOS_SQLITE_DB")
        .ok()
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    drop_legacy_tables_before_first_bootstrap_with_options(
        state_dir,
        db_path.as_deref(),
        should_skip_legacy_migration(),
    )
}

fn should_skip_legacy_migration() -> bool {
    std::env::var("THEYOS_SKIP_LEGACY_MIGRATION")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn drop_legacy_tables_before_first_bootstrap_with_options(
    state_dir: &Path,
    db_path: Option<&Path>,
    skip_legacy_migration: bool,
) -> Result<(), BootstrapError> {
    if household_record_path(state_dir).exists() {
        return Ok(());
    }
    if skip_legacy_migration {
        return Ok(());
    }
    let Some(db_path) = db_path else {
        return Ok(());
    };
    let detection = store_rs::drop_legacy_at_path_if_present(db_path).map_err(|e| {
        BootstrapError::InvalidOption(format!(
            "legacy schema migration failed for {}: {e}",
            db_path.display()
        ))
    })?;
    if !detection.is_empty() {
        info!(
            ts = %log_ts(),
            stage = "migration.legacy_checked",
            tables = ?detection.names(),
            row_counts = ?detection.row_counts(),
            result = "ok",
        );
    }
    Ok(())
}

fn fresh_bootstrap(
    state_dir: &Path,
    opts: BootstrapOpts,
    policy: KeyBackingPolicy,
    bootstrap_started: Instant,
) -> Result<LoadedIdentity, BootstrapError> {
    validate_household_name(&opts.household_name).map_err(|e| BootstrapError::Encoding {
        source: e,
        stage: "opts.household_name",
    })?;

    let platform = Platform::detect()
        .ok_or_else(|| BootstrapError::PlatformUnsupported(std::env::consts::OS.to_string()))?;

    // Resolve hostname.
    let hostname = opts
        .hostname_label
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());

    let backing = key_backing(policy);

    // Generate household key.
    let t0 = Instant::now();
    let hh_kp = create_identity_key("household", policy).map_err(|e| BootstrapError::Keystore {
        source: e,
        stage: "key_gen.household",
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.key_gen.household",
        elapsed_ms = elapsed_ms_clamped(t0),
        result = "ok",
        backing,
    );

    // Generate machine key.
    let t1 = Instant::now();
    let m_kp = create_identity_key("machine", policy).map_err(|e| BootstrapError::Keystore {
        source: e,
        stage: "key_gen.machine",
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.key_gen.machine",
        elapsed_ms = elapsed_ms_clamped(t1),
        result = "ok",
        backing,
    );

    let hh_pub = hh_kp.public();
    let m_pub = m_kp.public();
    let hh_id: HouseholdId = derive_household_id(&hh_pub);
    let m_id: MachineId = derive_machine_id(&m_pub);

    let now = unix_now("bootstrap.clock")?;

    let cert = MachineCert::sign(
        hh_kp.as_ref(),
        &m_pub,
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname,
            platform,
            joined_at: now,
        },
    )
    .map_err(|e| BootstrapError::Keystore {
        source: e,
        stage: "sign.machine_cert",
    })?;

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: hh_id.clone(),
        hh_pub: hh_pub.clone(),
        name: opts.household_name,
        created_at: now,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m_id.clone()],
        is_follower: false,
    };
    record.validate().map_err(|e| BootstrapError::Encoding {
        source: e,
        stage: "validate.household_record",
    })?;

    // Persist private key references / scalars.
    let t2 = Instant::now();
    persist_household_key(state_dir, &hh_id, hh_kp.as_ref(), policy).map_err(|e| {
        BootstrapError::Keystore {
            source: e,
            stage: "keystore.write.household",
        }
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.keystore.write",
        which = "household",
        elapsed_ms = elapsed_ms_clamped(t2),
        result = "ok",
    );

    let t3 = Instant::now();
    persist_machine_key(state_dir, &m_id, m_kp.as_ref(), policy).map_err(|e| {
        BootstrapError::Keystore {
            source: e,
            stage: "keystore.write.machine",
        }
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.keystore.write",
        which = "machine",
        elapsed_ms = elapsed_ms_clamped(t3),
        result = "ok",
    );

    // Persist identity records.
    let t4 = Instant::now();
    atomic_write_cbor(&household_record_path(state_dir), &record).map_err(|e| {
        BootstrapError::Storage {
            source: e,
            stage: "persist.household_record",
        }
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.persist.household_record",
        elapsed_ms = elapsed_ms_clamped(t4),
        result = "ok",
        path = %household_record_path(state_dir).display(),
    );
    let t5 = Instant::now();
    crate::machine_cert::save_self_cert(state_dir, &cert).map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "persist.machine_cert",
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.persist.machine_cert",
        elapsed_ms = elapsed_ms_clamped(t5),
        result = "ok",
        path = %storage::machine_cert_for(state_dir, &cert.m_id.to_string()).display(),
    );

    info!(
        ts = %log_ts(),
        stage = "bootstrap.complete",
        elapsed_ms = elapsed_ms_clamped(bootstrap_started),
        result = "ok",
    );

    Ok(LoadedIdentity {
        record,
        cert,
        hh_priv: Some(hh_kp),
        m_priv: m_kp,
        backing,
    })
}

/// Caller-supplied inputs for accepting an existing household from an owner
/// device that holds `HH_priv`.
pub struct AcceptHouseholdPrepareOpts {
    pub household_name: String,
    pub hh_id: HouseholdId,
    pub hh_pub: P256PublicKey,
    pub invitation_token_hash: [u8; 32],
}

/// Canonical challenge bytes returned by `POST /bootstrap/accept-household`
/// and signed by the owner device's household key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct AcceptHouseholdJoinChallenge {
    #[serde(rename = "v")]
    pub version: u8,
    pub hh_id: HouseholdId,
    pub m_pub: ByteBuf,
    pub machine_nonce: ByteBuf,
    pub timestamp: u64,
}

impl AcceptHouseholdJoinChallenge {
    #[must_use]
    pub fn build(
        hh_id: HouseholdId,
        m_pub: &[u8; 33],
        machine_nonce: &[u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            version: 1,
            hh_id,
            m_pub: ByteBuf::from(m_pub.to_vec()),
            machine_nonce: ByteBuf::from(machine_nonce.to_vec()),
            timestamp,
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, crate::error::HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }
}

/// Durable pending state between `accept-household` and
/// `accept-household/confirm`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct PendingAcceptHousehold {
    #[serde(rename = "v")]
    pub version: u8,
    pub hh_id: HouseholdId,
    pub hh_pub: P256PublicKey,
    pub hh_name: String,
    pub m_id: MachineId,
    pub m_pub: P256PublicKey,
    pub machine_nonce: ByteBuf,
    pub timestamp: u64,
    pub invitation_token_hash: ByteBuf,
}

impl PendingAcceptHousehold {
    pub fn join_challenge(&self) -> Result<AcceptHouseholdJoinChallenge, HouseholdError> {
        let nonce = <[u8; 32]>::try_from(self.machine_nonce.as_ref())
            .map_err(|_| HouseholdError::InvalidRecord("machine_nonce must be 32 bytes".into()))?;
        Ok(AcceptHouseholdJoinChallenge::build(
            self.hh_id.clone(),
            self.m_pub.as_bytes(),
            &nonce,
            self.timestamp,
        ))
    }

    pub fn invitation_token_hash_bytes(&self) -> Result<[u8; 32], HouseholdError> {
        <[u8; 32]>::try_from(self.invitation_token_hash.as_ref()).map_err(|_| {
            HouseholdError::InvalidRecord("invitation_token_hash must be 32 bytes".into())
        })
    }
}

pub struct PreparedAcceptHousehold {
    pub record: HouseholdRecord,
    pub m_id: MachineId,
    pub m_pub: P256PublicKey,
    pub join_challenge_cbor: Vec<u8>,
    pub backing: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptHouseholdConfirmError {
    #[error("pending accept-household state is missing")]
    PendingMissing,
    #[error("pending accept-household state mismatch: {0}")]
    Mismatch(&'static str),
    #[error("crypto validation failed: {0}")]
    Crypto(#[from] HouseholdError),
    #[error("keystore failure during {stage}: {source}")]
    Keystore {
        #[source]
        source: KeystoreError,
        stage: &'static str,
    },
    #[error("storage failure during {stage}: {source}")]
    Storage {
        #[source]
        source: StorageError,
        stage: &'static str,
    },
}

#[must_use]
pub fn pending_accept_household_path(state_dir: &Path) -> PathBuf {
    storage::household_dir(state_dir)
        .join("pending")
        .join("accept_household.cbor")
}

pub fn load_pending_accept_household(
    state_dir: &Path,
) -> Result<Option<PendingAcceptHousehold>, StorageError> {
    storage::read_optional_cbor(&pending_accept_household_path(state_dir))
}

pub fn clear_pending_accept_household(state_dir: &Path) -> Result<(), StorageError> {
    let path = pending_accept_household_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StorageError::Io {
            path,
            kind: e.kind().to_string(),
            hint: e.to_string(),
        }),
    }
}

pub fn prepare_accept_household(
    state_dir: &Path,
    opts: AcceptHouseholdPrepareOpts,
    policy: KeyBackingPolicy,
) -> Result<PreparedAcceptHousehold, BootstrapError> {
    validate_household_name(&opts.household_name).map_err(|e| BootstrapError::Encoding {
        source: e,
        stage: "accept_household.opts.household_name",
    })?;
    let recomputed = derive_household_id(&opts.hh_pub);
    if recomputed != opts.hh_id {
        return Err(BootstrapError::Encoding {
            source: HouseholdError::IdentifierMismatch {
                expected: recomputed.to_string(),
                actual: opts.hh_id.to_string(),
            },
            stage: "accept_household.hh_id",
        });
    }

    storage::load_state_dir(state_dir).map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "accept_household.load_state_dir",
    })?;
    let existing_record: Option<HouseholdRecord> =
        storage::read_optional_cbor(&household_record_path(state_dir)).map_err(|e| {
            BootstrapError::Storage {
                source: e,
                stage: "accept_household.existing_record",
            }
        })?;
    let existing_cert =
        crate::machine_cert::load_self_cert(state_dir).map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "accept_household.existing_cert",
        })?;
    if existing_record.is_some() || existing_cert.is_some() {
        return Err(BootstrapError::InvalidOption(
            "household identity already exists or accept-household is pending".into(),
        ));
    }

    let backing = key_backing(policy);
    let t0 = Instant::now();
    let m_kp = create_identity_key("machine", policy).map_err(|e| BootstrapError::Keystore {
        source: e,
        stage: "accept_household.key_gen.machine",
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.key_gen.machine",
        elapsed_ms = elapsed_ms_clamped(t0),
        result = "ok",
        backing,
    );

    let m_pub = m_kp.public();
    let m_id = derive_machine_id(&m_pub);
    let now = unix_now("accept_household.clock")?;
    let mut machine_nonce = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut machine_nonce);

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: opts.hh_id.clone(),
        hh_pub: opts.hh_pub.clone(),
        name: opts.household_name,
        created_at: now,
        shamir_k: 0,
        shamir_n: 0,
        members: vec![m_id.clone()],
        is_follower: true,
    };
    record.validate().map_err(|e| BootstrapError::Encoding {
        source: e,
        stage: "accept_household.validate_record",
    })?;

    let t1 = Instant::now();
    persist_machine_key(state_dir, &m_id, m_kp.as_ref(), policy).map_err(|e| {
        BootstrapError::Keystore {
            source: e,
            stage: "accept_household.keystore.write.machine",
        }
    })?;
    info!(
        ts = %log_ts(),
        stage = "bootstrap.keystore.write",
        which = "machine",
        elapsed_ms = elapsed_ms_clamped(t1),
        result = "ok",
    );

    let challenge = AcceptHouseholdJoinChallenge::build(
        opts.hh_id.clone(),
        m_pub.as_bytes(),
        &machine_nonce,
        now,
    );
    let challenge_cbor = challenge
        .to_canonical_bytes()
        .map_err(|e| BootstrapError::Encoding {
            source: e,
            stage: "accept_household.encode_challenge",
        })?;
    let pending = PendingAcceptHousehold {
        version: 1,
        hh_id: opts.hh_id,
        hh_pub: opts.hh_pub,
        hh_name: record.name.clone(),
        m_id: m_id.clone(),
        m_pub: m_pub.clone(),
        machine_nonce: ByteBuf::from(machine_nonce.to_vec()),
        timestamp: now,
        invitation_token_hash: ByteBuf::from(opts.invitation_token_hash.to_vec()),
    };
    let record_bytes =
        crate::cbor::to_canonical_vec(&record).map_err(|e| BootstrapError::Encoding {
            source: e,
            stage: "accept_household.encode_record",
        })?;
    let pending_bytes =
        crate::cbor::to_canonical_vec(&pending).map_err(|e| BootstrapError::Encoding {
            source: e,
            stage: "accept_household.encode_pending",
        })?;
    let staged = storage::stage_commit_files(&[
        (household_record_path(state_dir), record_bytes),
        (pending_accept_household_path(state_dir), pending_bytes),
    ])
    .map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "accept_household.stage_pending",
    })?;
    staged.commit().map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "accept_household.commit_pending",
    })?;

    Ok(PreparedAcceptHousehold {
        record,
        m_id,
        m_pub,
        join_challenge_cbor: challenge_cbor,
        backing,
    })
}

pub fn confirm_accept_household(
    state_dir: &Path,
    m_id: &MachineId,
    machine_cert: MachineCert,
    challenge_sig: &P256Signature,
    policy: KeyBackingPolicy,
) -> Result<LoadedIdentity, AcceptHouseholdConfirmError> {
    let pending = load_pending_accept_household(state_dir).map_err(|e| {
        AcceptHouseholdConfirmError::Storage {
            source: e,
            stage: "accept_household.load_pending",
        }
    })?;
    let Some(pending) = pending else {
        return Err(AcceptHouseholdConfirmError::PendingMissing);
    };
    if &pending.m_id != m_id {
        return Err(AcceptHouseholdConfirmError::Mismatch("m_id"));
    }
    if pending.version != 1 {
        return Err(AcceptHouseholdConfirmError::Mismatch("pending.version"));
    }

    let challenge = pending.join_challenge()?;
    let challenge_cbor = challenge.to_canonical_bytes()?;
    verify_signature(&pending.hh_pub, &challenge_cbor, challenge_sig)?;

    if machine_cert.hh_id != pending.hh_id {
        return Err(AcceptHouseholdConfirmError::Mismatch("machine_cert.hh_id"));
    }
    if machine_cert.m_id != pending.m_id {
        return Err(AcceptHouseholdConfirmError::Mismatch("machine_cert.m_id"));
    }
    if machine_cert.m_pub != pending.m_pub {
        return Err(AcceptHouseholdConfirmError::Mismatch("machine_cert.m_pub"));
    }
    // TODO(cert-rotation): validate expiry/revocation metadata once MachineCert
    // carries it. For now accept the current structure after issuer, subject,
    // and signature checks.
    machine_cert.verify(&pending.hh_pub)?;

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: pending.hh_id.clone(),
        hh_pub: pending.hh_pub.clone(),
        name: pending.hh_name.clone(),
        created_at: pending.timestamp,
        shamir_k: 0,
        shamir_n: 0,
        members: vec![pending.m_id.clone()],
        is_follower: true,
    };
    crate::chain::verify_loaded_chain(&record, &machine_cert)?;

    let m_priv =
        read_existing_machine_key(state_dir, &pending.m_id, policy).map_err(|e| match e {
            BootstrapError::Keystore { source, stage } => {
                AcceptHouseholdConfirmError::Keystore { source, stage }
            }
            BootstrapError::Storage { source, stage } => {
                AcceptHouseholdConfirmError::Storage { source, stage }
            }
            BootstrapError::Encoding { source, .. } => AcceptHouseholdConfirmError::Crypto(source),
            other => AcceptHouseholdConfirmError::Crypto(HouseholdError::InvalidRecord(
                other.to_string(),
            )),
        })?;
    ensure_loaded_key_matches(
        "accept_household.keystore.read.machine",
        m_priv.as_ref(),
        &pending.m_pub,
        "machine",
    )
    .map_err(|e| match e {
        BootstrapError::Keystore { source, stage } => {
            AcceptHouseholdConfirmError::Keystore { source, stage }
        }
        BootstrapError::Storage { source, stage } => {
            AcceptHouseholdConfirmError::Storage { source, stage }
        }
        BootstrapError::Encoding { source, .. } => AcceptHouseholdConfirmError::Crypto(source),
        other => {
            AcceptHouseholdConfirmError::Crypto(HouseholdError::InvalidRecord(other.to_string()))
        }
    })?;

    let record_bytes = crate::cbor::to_canonical_vec(&record)?;
    let cert_bytes = crate::cbor::to_canonical_vec(&machine_cert)?;
    let mut marker_bytes = pending.m_id.to_string().into_bytes();
    marker_bytes.push(b'\n');
    let staged = storage::stage_commit_files(&[
        (household_record_path(state_dir), record_bytes),
        (
            machine_cert_for(state_dir, pending.m_id.as_str()),
            cert_bytes,
        ),
        (self_m_id_marker_path(state_dir), marker_bytes),
    ])
    .map_err(|e| AcceptHouseholdConfirmError::Storage {
        source: e,
        stage: "accept_household.stage_confirm",
    })?;
    staged
        .commit()
        .map_err(|e| AcceptHouseholdConfirmError::Storage {
            source: e,
            stage: "accept_household.commit_confirm",
        })?;
    clear_pending_accept_household(state_dir).map_err(|e| {
        AcceptHouseholdConfirmError::Storage {
            source: e,
            stage: "accept_household.clear_pending",
        }
    })?;

    let backing = m_priv.backing();
    Ok(LoadedIdentity {
        record,
        cert: machine_cert,
        hh_priv: None,
        m_priv,
        backing,
    })
}

/// Destroy the keystore custody of the household's `HH_priv`. Called by the
/// Phase 3 Shamir transition (`CeremonyTxn::commit`) after staged files
/// have been promoted but before the sole-shard plaintext is unlinked.
///
/// Order of destruction across the three sources of `HH_priv`:
///
/// 1. **Keystore custody** — this function. Removes the SE Keychain entry
///    on macOS, the Secret-Service entry on Linux, or the file-fallback
///    `<state_dir>/household/secrets/<account>.bin` under the
///    `THEYOS_FORCE_SOFTWARE_KEYS=1` operator override.
/// 2. **Sole-shard plaintext** — `household_root_sole.cbor`, deleted as the
///    final step of `commit()` per `contracts/shamir-transition.md`.
/// 3. **In-memory `LoadedIdentity.hh_priv`** — replaced with `None` by the
///    handler that reloads `HouseholdState` after commit.
///
/// Idempotent: returns `Ok(())` when the entry is already absent.
pub fn destroy_household_keystore_material(
    state_dir: &Path,
    hh_id: &HouseholdId,
    policy: KeyBackingPolicy,
) -> Result<(), KeystoreError> {
    if policy.is_force_software() {
        return keystore::software_fallback::delete_secret_scalar(
            state_dir,
            &keystore::hh_priv_account(hh_id),
        );
    }
    #[cfg(target_os = "linux")]
    {
        match keystore::linux::delete_secret_scalar(&keystore::hh_priv_account(hh_id)) {
            // Treat NotFound as already-destroyed (idempotency).
            Ok(()) | Err(KeystoreError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = hh_id;
        crate::keys_se::destroy_by_label(&keystore::se_bootstrap_label("household"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (state_dir, hh_id);
        Err(KeystoreError::Unavailable {
            hint: format!("destroy unsupported on {}", std::env::consts::OS),
        })
    }
}

/// Pick the right backing string for the running platform under `policy`.
fn key_backing(policy: KeyBackingPolicy) -> &'static str {
    #[cfg(target_os = "macos")]
    {
        if policy.is_force_software() {
            "software"
        } else {
            "secure_enclave"
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = policy;
        "software"
    }
}

#[allow(unused_variables, clippy::unnecessary_wraps)]
fn create_identity_key(
    which: &str,
    policy: KeyBackingPolicy,
) -> Result<Box<dyn IdentityKey>, KeystoreError> {
    #[cfg(target_os = "macos")]
    {
        if policy.is_force_software() {
            return Ok(Box::new(P256Keypair::generate()));
        }
        // Real SE-backed key creation — implemented in keys_se.rs.
        let kp = crate::keys_se::P256SeKeypair::create(
            &keystore::se_bootstrap_label(which),
            true, /* for_subject_signing */
        )?;
        Ok(Box::new(kp))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Box::new(P256Keypair::generate()))
    }
}

fn persist_household_key(
    state_dir: &Path,
    hh_id: &HouseholdId,
    key: &dyn IdentityKey,
    policy: KeyBackingPolicy,
) -> Result<(), KeystoreError> {
    if policy.is_force_software() {
        let scalar = key.as_software_secret().ok_or_else(|| {
            KeystoreError::SigningFailed(
                "THEYOS_FORCE_SOFTWARE_KEYS=1 set but key is not software-backed".into(),
            )
        })?;
        keystore::software_fallback::write_secret_scalar(
            state_dir,
            &keystore::hh_priv_account(hh_id),
            scalar,
        )?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let scalar = key.as_software_secret().ok_or_else(|| {
            KeystoreError::SigningFailed(
                "key is not software-backed; cannot persist private scalar on Linux".into(),
            )
        })?;
        keystore::linux::write_secret_scalar(&keystore::hh_priv_account(hh_id), scalar)?;
    }
    #[cfg(target_os = "macos")]
    {
        // SE-resident keys persist via the Keychain on creation; nothing to do.
        let _ = key.public();
    }
    Ok(())
}

fn persist_machine_key(
    state_dir: &Path,
    m_id: &MachineId,
    key: &dyn IdentityKey,
    policy: KeyBackingPolicy,
) -> Result<(), KeystoreError> {
    if policy.is_force_software() {
        let scalar = key.as_software_secret().ok_or_else(|| {
            KeystoreError::SigningFailed(
                "THEYOS_FORCE_SOFTWARE_KEYS=1 set but key is not software-backed".into(),
            )
        })?;
        keystore::software_fallback::write_secret_scalar(
            state_dir,
            &keystore::m_priv_account(m_id),
            scalar,
        )?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let scalar = key.as_software_secret().ok_or_else(|| {
            KeystoreError::SigningFailed(
                "key is not software-backed; cannot persist private scalar on Linux".into(),
            )
        })?;
        keystore::linux::write_secret_scalar(&keystore::m_priv_account(m_id), scalar)?;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = key.public();
    }
    Ok(())
}

fn read_existing_household_key(
    state_dir: &Path,
    hh_id: &HouseholdId,
    policy: KeyBackingPolicy,
) -> Result<Box<dyn IdentityKey>, BootstrapError> {
    if policy.is_force_software() {
        let scalar = keystore::software_fallback::read_secret_scalar(
            state_dir,
            &keystore::hh_priv_account(hh_id),
        )
        .map_err(|e| BootstrapError::Keystore {
            source: e,
            stage: "keystore.read.household",
        })?;
        let kp =
            P256Keypair::from_secret_scalar(&scalar).map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.household",
            })?;
        return Ok(Box::new(kp));
    }
    #[cfg(target_os = "linux")]
    {
        let scalar = keystore::linux::read_secret_scalar(&keystore::hh_priv_account(hh_id))
            .map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.household",
            })?;
        let kp =
            P256Keypair::from_secret_scalar(&scalar).map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.household",
            })?;
        Ok(Box::new(kp))
    }
    #[cfg(target_os = "macos")]
    {
        let kp = crate::keys_se::P256SeKeypair::load(&keystore::se_bootstrap_label("household"))
            .map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.household",
            })?;
        Ok(Box::new(kp))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (hh_id, state_dir);
        Err(BootstrapError::PlatformUnsupported(
            std::env::consts::OS.to_string(),
        ))
    }
}

fn read_existing_machine_key(
    state_dir: &Path,
    m_id: &MachineId,
    policy: KeyBackingPolicy,
) -> Result<Box<dyn IdentityKey>, BootstrapError> {
    if policy.is_force_software() {
        let scalar = keystore::software_fallback::read_secret_scalar(
            state_dir,
            &keystore::m_priv_account(m_id),
        )
        .map_err(|e| BootstrapError::Keystore {
            source: e,
            stage: "keystore.read.machine",
        })?;
        let kp =
            P256Keypair::from_secret_scalar(&scalar).map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.machine",
            })?;
        return Ok(Box::new(kp));
    }
    #[cfg(target_os = "linux")]
    {
        let scalar =
            keystore::linux::read_secret_scalar(&keystore::m_priv_account(m_id)).map_err(|e| {
                BootstrapError::Keystore {
                    source: e,
                    stage: "keystore.read.machine",
                }
            })?;
        let kp =
            P256Keypair::from_secret_scalar(&scalar).map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.machine",
            })?;
        Ok(Box::new(kp))
    }
    #[cfg(target_os = "macos")]
    {
        let kp = crate::keys_se::P256SeKeypair::load(&keystore::se_bootstrap_label("machine"))
            .map_err(|e| BootstrapError::Keystore {
                source: e,
                stage: "keystore.read.machine",
            })?;
        Ok(Box::new(kp))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (m_id, state_dir);
        Err(BootstrapError::PlatformUnsupported(
            std::env::consts::OS.to_string(),
        ))
    }
}

fn ensure_loaded_key_matches(
    stage: &'static str,
    key: &dyn IdentityKey,
    expected: &crate::keys::P256PublicKey,
    which: &str,
) -> Result<(), BootstrapError> {
    let actual = key.public();
    if &actual == expected {
        return Ok(());
    }
    Err(BootstrapError::Keystore {
        source: KeystoreError::InvalidKeyMaterial(format!(
            "{which} private key public component does not match persisted public key"
        )),
        stage,
    })
}

/// Mint or load the candidate machine keypair used by `theyos install
/// --pair-machine`. The candidate has no household identity yet, so this
/// path bypasses the full bootstrap flow: it produces (or recovers) the
/// `M_priv`/`M_pub` pair that the candidate signs the [`crate::pair_machine::JoinChallenge`]
/// with at install time.
///
/// Behavior:
/// - On macOS (`OsDefault` policy): backed by the Secure Enclave under the
///   fixed `se_bootstrap_label("machine")` label. `create` returns the
///   existing handle if one is already provisioned.
/// - On Linux or `ForceSoftware`: software-backed, scalar persisted via
///   `keystore::software_fallback` keyed by the derived `m_id`. A second
///   invocation re-derives `m_id` from the persisted `m_pub_at_rest.bin`
///   marker and reloads.
///
/// The returned [`IdentityKey`] survives the join ceremony unchanged; once
/// M1 issues the candidate's `MachineCert` and the candidate persists it
/// under `machine_certs/<m_id>.cbor`, the standard
/// [`read_existing_machine_key`] path picks it up on subsequent boots.
pub fn ensure_candidate_machine_keypair(
    state_dir: &Path,
    policy: KeyBackingPolicy,
) -> Result<Box<dyn IdentityKey>, BootstrapError> {
    let marker = state_dir.join("household").join("candidate_m_pub.bin");

    if marker.exists() {
        let bytes = std::fs::read(&marker).map_err(|e| BootstrapError::Storage {
            source: StorageError::Io {
                path: marker.clone(),
                kind: format!("{:?}", e.kind()),
                hint: e.to_string(),
            },
            stage: "candidate.read_pub_marker",
        })?;
        if bytes.len() != 33 {
            return Err(BootstrapError::Encoding {
                source: crate::error::HouseholdError::PublicKeyMalformed,
                stage: "candidate.read_pub_marker",
            });
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        let m_pub =
            crate::keys::P256PublicKey::from_bytes(&arr).map_err(|e| BootstrapError::Encoding {
                source: e,
                stage: "candidate.decode_pub_marker",
            })?;
        let m_id = derive_machine_id(&m_pub);
        return read_existing_machine_key(state_dir, &m_id, policy);
    }

    let kp = create_identity_key("machine", policy).map_err(|e| BootstrapError::Keystore {
        source: e,
        stage: "candidate.key_gen.machine",
    })?;
    let m_pub = kp.public();
    let m_id = derive_machine_id(&m_pub);
    persist_machine_key(state_dir, &m_id, kp.as_ref(), policy).map_err(|e| {
        BootstrapError::Keystore {
            source: e,
            stage: "candidate.keystore.write.machine",
        }
    })?;

    let staged = crate::storage::stage_commit_files(&[(marker.clone(), m_pub.as_bytes().to_vec())])
        .map_err(|e| BootstrapError::Storage {
            source: e,
            stage: "candidate.stage_pub_marker",
        })?;
    staged.commit().map_err(|e| BootstrapError::Storage {
        source: e,
        stage: "candidate.commit_pub_marker",
    })?;

    Ok(kp)
}

/// Bootstrap-emit-error helper for the binary entrypoint.
pub fn log_error(err: &BootstrapError) {
    error!(
        ts = %log_ts(),
        error.stage = err.stage(),
        error.kind = err.kind(),
        error.hint = %err.hint(),
        result = "error",
        "bootstrap failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn fresh_then_idempotent() {
        let td = tempdir().unwrap();
        let opts = BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        };
        // Force software keys explicitly via the typed policy — never mutate
        // env vars in tests (UB under Rust 2024 with parallel test runner).
        let policy = KeyBackingPolicy::ForceSoftware;
        let first = bootstrap_or_load(td.path(), opts.clone(), policy).unwrap();
        let second = bootstrap_or_load(td.path(), opts, policy);
        match second {
            Ok(loaded) => {
                assert_eq!(first.record.hh_id, loaded.record.hh_id);
                assert_eq!(first.record.created_at, loaded.record.created_at);
            }
            Err(e) => {
                assert!(
                    matches!(&e, BootstrapError::Keystore { stage, .. }
                        if stage.starts_with("keystore.read")),
                    "unexpected error: {e:?}"
                );
            }
        }
    }

    #[test]
    fn loaded_private_keys_must_match_persisted_public_keys() {
        let td = tempdir().unwrap();
        let opts = BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        };
        let policy = KeyBackingPolicy::ForceSoftware;
        let first = bootstrap_or_load(td.path(), opts.clone(), policy).unwrap();

        let replacement = P256Keypair::generate();
        keystore::software_fallback::write_secret_scalar(
            td.path(),
            &keystore::hh_priv_account(&first.record.hh_id),
            replacement.as_software_secret().unwrap(),
        )
        .unwrap();

        let Err(err) = bootstrap_or_load(td.path(), opts, policy) else {
            panic!("expected key/public mismatch to fail bootstrap load");
        };
        assert!(
            matches!(
                err,
                BootstrapError::Keystore {
                    stage: "keystore.read.household",
                    source: KeystoreError::InvalidKeyMaterial(_),
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn accept_household_prepare_and_confirm_loads_follower_without_hh_priv() {
        let td = tempdir().unwrap();
        let policy = KeyBackingPolicy::ForceSoftware;
        let hh = P256Keypair::generate();
        let hh_pub = hh.public();
        let hh_id = derive_household_id(&hh_pub);

        let prepared = prepare_accept_household(
            td.path(),
            AcceptHouseholdPrepareOpts {
                household_name: "Existing Home".into(),
                hh_id: hh_id.clone(),
                hh_pub: hh_pub.clone(),
                invitation_token_hash: [0x11; 32],
            },
            policy,
        )
        .unwrap();
        assert!(prepared.record.is_follower);
        assert_eq!(prepared.record.shamir_n, 0);
        assert!(
            try_load_existing(td.path(), policy).unwrap().is_none(),
            "pending follower without cert should not load as initialized"
        );

        let sig = hh.sign(&prepared.join_challenge_cbor).unwrap();
        let cert = MachineCert::sign(
            &hh,
            &prepared.m_pub,
            &SignOptions {
                hh_id: hh_id.clone(),
                hostname: "test-mac".into(),
                platform: Platform::Macos,
                joined_at: unix_now("test.now").unwrap(),
            },
        )
        .unwrap();
        let loaded =
            confirm_accept_household(td.path(), &prepared.m_id, cert, &sig, policy).unwrap();
        assert!(loaded.record.is_follower);
        assert!(loaded.hh_priv.is_none());

        let reloaded = try_load_existing(td.path(), policy)
            .unwrap()
            .expect("confirmed follower should load");
        assert!(reloaded.record.is_follower);
        assert!(reloaded.hh_priv.is_none());
    }

    #[test]
    fn skip_legacy_migration_preserves_legacy_tables() {
        let td = tempdir().unwrap();
        let db_path = td.path().join("theyos.db");
        create_legacy_db(&db_path);

        drop_legacy_tables_before_first_bootstrap_with_options(td.path(), Some(&db_path), true)
            .unwrap();

        assert!(table_exists(&db_path, "users"));
        assert!(table_exists(&db_path, "mobile_sessions"));
        assert!(table_exists(&db_path, "invites"));
    }

    #[test]
    fn legacy_migration_runs_without_skip_flag() {
        let td = tempdir().unwrap();
        let db_path = td.path().join("theyos.db");
        create_legacy_db(&db_path);

        drop_legacy_tables_before_first_bootstrap_with_options(td.path(), Some(&db_path), false)
            .unwrap();

        assert!(!table_exists(&db_path, "users"));
        assert!(!table_exists(&db_path, "mobile_sessions"));
        assert!(!table_exists(&db_path, "invites"));
    }

    fn create_legacy_db(db_path: &Path) {
        let conn = Connection::open(db_path).unwrap();
        conn.execute_batch(
            r"
            CREATE TABLE users (id INTEGER PRIMARY KEY, value TEXT);
            CREATE TABLE mobile_sessions (id INTEGER PRIMARY KEY, value TEXT);
            CREATE TABLE invites (id INTEGER PRIMARY KEY, value TEXT);
            INSERT INTO users (value) VALUES ('user');
            INSERT INTO mobile_sessions (value) VALUES ('session');
            INSERT INTO invites (value) VALUES ('invite');
            ",
        )
        .unwrap();
    }

    fn table_exists(db_path: &Path, table: &str) -> bool {
        let conn = Connection::open(db_path).unwrap();
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )
        .unwrap()
    }
}
