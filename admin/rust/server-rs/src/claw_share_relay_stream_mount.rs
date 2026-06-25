//! Bootstrap mount for the Product A `relay_stream` live wiring (default-off).
//!
//! C6.2. This is the thin glue that lets `assemble_relay_stream_live` (C6) run
//! inside the engine: it is called from household bootstrap right after the live
//! `claw_share` mesh log and slot store are created, and passes those SAME live
//! `Arc`s in, so the `relay_stream` pool shares one slot store with the
//! data-tunnel revoke-poll (the M2b invariant) and one mesh log with the rest of
//! the engine.
//!
//! Default-OFF is the #1 property: gated by the `THEYOS_RELAY_STREAM_LIVE` env
//! var, OFF (unset/false) returns before reading the household, creating a
//! keystore, building inputs, or spawning anything. ON, it builds a real PTY
//! target factory, a fail-closed `ClawSite` placeholder (no invented endpoint),
//! and a dedicated Noise keystore, then assembles and keeps the handles alive in
//! a process-lifetime `OnceLock`.
//!
//! It announces nothing public: no advertise, no inbound listener bind, no
//! claim-ack, no guest/iOS. With an empty offer store, ON is a serving no-op.
//!
//! Carries (out of scope here): the `relay_stream` mount uses its OWN
//! `ReplayGuard` (unify with the direct data-tunnel listener pre-live); `ClawSite`
//! has no real endpoint yet (placeholder fail-closed); the Noise key uses a
//! `FileKeystore` (live keychain hardening later); handles live in a `OnceLock`
//! rather than a graceful `AppState` holder.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use household_rs::claw_share::{ClawShareSlotStore, GuestCredential};
use household_rs::claw_share_data_tunnel::{
    ClawTargetRouter, DataTunnelError, ReplayGuard, TargetSession, TcpStreamRouter,
};
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::keys::{IdentityKey, P256PublicKey};
use keystore_rs::FileKeystore;
use tokio::sync::Notify;

use crate::claw_share_pty_target::{PtyPolicy, PtyTargetRouter};
use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamOfferContract, RelayStreamResource,
};
use crate::claw_share_relay_stream_issuer_trust::{
    RelayStreamIssuerTrust, RelayStreamTrustContext,
};
use crate::claw_share_relay_stream_noise_keystore::{
    DEFAULT_RELAY_STREAM_NOISE_KEY_ID, RelayStreamNoiseKeyStore,
};
use crate::claw_share_relay_stream_offer_store::{
    RelayStreamOfferStore, RelayStreamOfferStoreError,
};
use crate::claw_share_relay_stream_provision::{
    RelayStreamProvisionError, provision_relay_stream_group_offer, provision_relay_stream_offer,
    provision_relay_stream_public_offer,
};
use crate::claw_share_relay_stream_runtime::{
    RelayStreamLiveConfig, RelayStreamLiveError, RelayStreamLiveHandles, RelayStreamLiveInputs,
    assemble_relay_stream_live,
};
use crate::household_state::HouseholdState;

/// Env var that opts the `relay_stream` live path IN. Absent or non-truthy = OFF.
const RELAY_STREAM_LIVE_ENV: &str = "THEYOS_RELAY_STREAM_LIVE";

/// Stable keystore service + subdir for the `relay_stream` Noise static key. This
/// is a SEPARATE X25519 key, not the household machine signing key.
const RELAY_STREAM_KEYSTORE_SERVICE: &str = "com.soyeht.theyos.relay-stream";
const RELAY_STREAM_KEYSTORE_SUBDIR: &str = "relay_stream_keystore";

/// Env var for the relay endpoint shared by the offer's `relay_endpoint` and the
/// pool's reverse-connect dial address, so the two never diverge. Default is the
/// loopback responder bind.
const RELAY_STREAM_RELAY_ENDPOINT_ENV: &str = "THEYOS_RELAY_STREAM_RELAY_ENDPOINT";
const DEFAULT_RELAY_STREAM_RELAY_ENDPOINT: &str = "127.0.0.1:49152";
const RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL_ENV: &str =
    "THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL";

/// Env var pointing the `ClawSite` resource at the claw's local site backend (an
/// HTTP server), e.g. `127.0.0.1:8080`. Unset = `ClawSite` fails closed (no
/// invented endpoint), preserving the prior placeholder behavior.
const RELAY_STREAM_CLAWSITE_BACKEND_ENV: &str = "THEYOS_RELAY_STREAM_CLAWSITE_BACKEND";

/// Env var selecting the resource a provisioned offer is minted for: `pty`
/// (default) or `clawsite`.
const RELAY_STREAM_RESOURCE_ENV: &str = "THEYOS_RELAY_STREAM_RESOURCE";

/// The single source for the relay address (`host:port`). The provisioned offer
/// stores it as `relay-stream://<addr>`; the pool dials it as a `SocketAddr`.
/// Both read this, so the offer endpoint and the pool dial target cannot drift.
pub(crate) fn relay_stream_relay_endpoint() -> String {
    std::env::var(RELAY_STREAM_RELAY_ENDPOINT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_STREAM_RELAY_ENDPOINT.to_string())
}

/// Process-lifetime holder so the spawned driver/pool are not Drop-aborted right
/// after the mount returns. A graceful `AppState` holder is a future carry.
static LIVE_HANDLES: OnceLock<RelayStreamLiveHandles> = OnceLock::new();

/// `ClawSite` target router.
///
/// Forwards the authorized `relay_stream` tunnel to the claw's local site backend
/// (an HTTP server) over TCP, reusing the proven [`TcpStreamRouter`] byte
/// forwarder — the engine then splices the guest's tunnel bytes to/from the
/// backend, so the guest speaks plain HTTP/1.1 end-to-end. The backend address
/// comes from `THEYOS_RELAY_STREAM_CLAWSITE_BACKEND`. When it is unset the router
/// fails closed with the same `TargetUnavailable` reason as the prior
/// placeholder — no invented endpoint.
///
/// Per-claw backend routing (mapping `target_id`/`claw_id` to a specific site)
/// is a follow-up; today it is one operator-configured backend.
pub struct RelayStreamClawSiteRouter {
    backend_addr: Option<String>,
}

impl RelayStreamClawSiteRouter {
    /// Read the configured backend address from the environment (trimmed,
    /// non-empty). Absent/blank ⇒ unconfigured ⇒ fail-closed.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            backend_addr: std::env::var(RELAY_STREAM_CLAWSITE_BACKEND_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
    }
}

impl ClawTargetRouter for RelayStreamClawSiteRouter {
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        match &self.backend_addr {
            Some(addr) => TcpStreamRouter::new(addr.clone()).open(target_id).await,
            None => Err(DataTunnelError::TargetUnavailable(
                "relay-stream-clawsite-not-configured".to_string(),
            )),
        }
    }
}

/// Resource a provisioned offer is minted for. Default `Pty`; `clawsite` (any
/// case) selects `ClawSite`.
fn parse_resource(value: Option<&str>) -> RelayStreamResource {
    match value.map(str::trim) {
        Some("clawsite" | "ClawSite" | "CLAWSITE") => RelayStreamResource::ClawSite,
        _ => RelayStreamResource::Pty,
    }
}

fn relay_stream_resource_from_env() -> RelayStreamResource {
    parse_resource(std::env::var(RELAY_STREAM_RESOURCE_ENV).ok().as_deref())
}

fn parse_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "TRUE"))
}

fn relay_stream_live_enabled_from_env() -> bool {
    parse_enabled(std::env::var(RELAY_STREAM_LIVE_ENV).ok().as_deref())
}

/// Bootstrap entry: mount the `relay_stream` live path if enabled by env.
///
/// Default-OFF: when the env flag is absent/false this returns immediately,
/// before any household read, keystore creation, input build, or task spawn.
/// Idempotent: a second call after a successful mount is a no-op (never spawns a
/// second set of components). Failures are surfaced to the caller, which should
/// log and continue — a `relay_stream` mount failure must not break bootstrap.
pub async fn mount_relay_stream_live_if_enabled(
    state_dir: PathBuf,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
) -> Result<(), RelayStreamMountError> {
    if !relay_stream_live_enabled_from_env() {
        return Ok(());
    }
    if LIVE_HANDLES.get().is_some() {
        tracing::warn!(stage = "claw_share.relay_stream.mount.already_mounted");
        return Ok(());
    }

    let mut config = RelayStreamLiveConfig {
        enabled: true,
        ..RelayStreamLiveConfig::default()
    };
    // Single-source the relay address so the pool dials the same endpoint the
    // provisioned offers advertise. A malformed override keeps the default.
    if let Ok(addr) = relay_stream_relay_endpoint().parse::<SocketAddr>() {
        config.reverse_connect.relay_addr = addr;
    }
    if parse_enabled(
        std::env::var(RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL_ENV)
            .ok()
            .as_deref(),
    ) {
        tracing::warn!(
            stage = "claw_share.relay_stream.mount.public_relay_dial_enabled",
            relay_addr = %config.reverse_connect.relay_addr,
            "THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL=1 — allowing relay_stream reverse-connect to a non-loopback relay endpoint for a dev smoke"
        );
        config.reverse_connect.allow_non_loopback_relay_addr = true;
    }
    match mount_relay_stream_live(state_dir, household, mesh_log, slots, replay, config).await? {
        Some(handles) => {
            tracing::info!(
                stage = "claw_share.relay_stream.mount.enabled",
                offer_count = handles.offer_count(),
                pool_tasks = handles.pool_task_count(),
            );
            if LIVE_HANDLES.set(handles).is_err() {
                tracing::warn!(stage = "claw_share.relay_stream.mount.race_already_set");
            }
        }
        None => {
            tracing::warn!(stage = "claw_share.relay_stream.mount.assemble_returned_none");
        }
    }
    Ok(())
}

/// Build the live inputs from the injected handles and assemble.
///
/// Separated from the env/`OnceLock` wrapper so it is deterministically testable
/// without process-global state. With `config.enabled == false` it returns
/// `Ok(None)` BEFORE creating the keystore directory or reading the household,
/// preserving the default-off zero-side-effect property.
async fn mount_relay_stream_live(
    state_dir: PathBuf,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    config: RelayStreamLiveConfig,
) -> Result<Option<RelayStreamLiveHandles>, RelayStreamMountError> {
    if !config.enabled {
        return Ok(None);
    }

    let Some(identity) = household.current().await else {
        tracing::warn!(stage = "claw_share.relay_stream.mount.no_identity");
        return Ok(None);
    };
    let household_id = identity.record.hh_id.clone();

    let keystore_dir = state_dir
        .join("claw_share")
        .join(RELAY_STREAM_KEYSTORE_SUBDIR);
    let keystore = FileKeystore::new(&keystore_dir, RELAY_STREAM_KEYSTORE_SERVICE);

    let now_unix: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
        crate::time_util::unix_now_secs_checked("claw_share.relay_stream.mount").unwrap_or(0)
    });

    let inputs = RelayStreamLiveInputs {
        state_dir,
        household,
        mesh_log,
        keystore_backend: &keystore,
        household_id,
        slots,
        replay,
        pty_router_factory: Arc::new(|| PtyTargetRouter::new(PtyPolicy::from_env())),
        clawsite_router_factory: Arc::new(RelayStreamClawSiteRouter::from_env),
        refresh_trigger: Arc::new(Notify::new()),
        now_unix,
    };

    Ok(assemble_relay_stream_live(inputs, config).await?)
}

/// Best-effort: when the live path is enabled, mint + store a `relay_stream` offer
/// for a just-consumed claim, so the pool can serve it after a restart/
/// re-assemble. Called from BOTH claim paths AFTER the `SlotConsumed` log is
/// durable, BEFORE the ack. A failure here NEVER affects the claim - it is logged
/// and swallowed.
///
/// Default-OFF via the same `THEYOS_RELAY_STREAM_LIVE` flag as the mount: OFF
/// returns before any household read / keystore / store access.
///
/// NOTE: the running pool is a static-offer-set snapshot taken at assemble. An
/// offer provisioned here is durable on disk but is not served until the pool is
/// re-assembled (restart) or a future dynamic re-sync - out of scope here.
pub(crate) async fn try_provision_relay_stream_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    credential: &GuestCredential,
    now: u64,
) -> Option<RelayStreamOfferContract> {
    if !relay_stream_live_enabled_from_env() {
        return None;
    }
    match provision_relay_stream_offer_for_claim(
        state_dir, household, mesh_log, owner_key, credential, now,
    )
    .await
    {
        Ok(offer) => Some(offer),
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.claim_provision_failed",
                error = %error,
                "relay_stream claim provisioning failed; claim unaffected",
            );
            None
        }
    }
}

/// Gated wrapper around [`provision_group_offer_for_claw`] for the Path-A Group
/// claim handler. Returns `None` when `THEYOS_RELAY_STREAM_LIVE` is unset
/// (default-off, same gate as [`try_provision_relay_stream_offer_for_claim`]) or
/// on provision failure, so the caller can fail closed without emitting an ack.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_provision_group_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Option<RelayStreamOfferContract> {
    if !relay_stream_live_enabled_from_env() {
        return None;
    }
    match provision_group_offer_for_claw(
        state_dir,
        household,
        mesh_log,
        owner_key,
        group_id,
        member_id,
        member_device_pub,
        claw_id,
        not_after,
        now,
    )
    .await
    {
        Ok(offer) => Some(offer),
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.group_provision_failed",
                error = %error,
                "relay_stream group offer provisioning failed; no ack emitted",
            );
            None
        }
    }
}

/// Deterministic core of [`try_provision_relay_stream_offer_for_claim`], split
/// out (no env / no global) so it is unit-testable. Builds a FRESH trust seam
/// from the live household record/cert + mesh-log projection (not the mount's
/// handles, which may be off/absent), resolves the claw static key from the SAME
/// keystore the responder mount uses, and provisions a Pty offer bounded by the
/// credential's expiry.
/// Shared loading for live-engine `relay_stream` offer provisioning: the live
/// trust seam (household record/cert + mesh-log projection), the responder's own
/// claw static Noise key, the relay endpoint, and the on-disk offer store. Used
/// by the claim (Device), group, and public provisioning paths so they all mint
/// against the SAME keystore key, endpoint, and store.
async fn relay_stream_provision_context(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    now: u64,
) -> Result<
    (
        RelayStreamIssuerTrust,
        RelayStreamClawStaticPublicKey,
        String,
        RelayStreamOfferStore,
    ),
    RelayStreamClaimProvisionError,
> {
    let Some(identity) = household.current().await else {
        return Err(RelayStreamClaimProvisionError::NoIdentity);
    };
    let record = identity.record.clone();
    let cert = identity.cert.clone();
    let projection = mesh_log.project();
    let trust = RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
        record: record.clone(),
        cert: cert.clone(),
        projection: projection.clone(),
    });

    // Same keystore/service/key_id the responder mount uses, so the offer's
    // claw_static_pub is the key the responder will actually present.
    let keystore_dir = state_dir
        .join("claw_share")
        .join(RELAY_STREAM_KEYSTORE_SUBDIR);
    let keystore = FileKeystore::new(&keystore_dir, RELAY_STREAM_KEYSTORE_SERVICE);
    let keypair = RelayStreamNoiseKeyStore::new(&keystore)
        .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
        .map_err(|error| RelayStreamClaimProvisionError::Keystore(error.to_string()))?;
    let claw_static_pub = keypair.public_key().clone();

    let relay_endpoint = format!("relay-stream://{}", relay_stream_relay_endpoint());
    let store = RelayStreamOfferStore::load(state_dir, &trust, now)?;
    Ok((trust, claw_static_pub, relay_endpoint, store))
}

async fn provision_relay_stream_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    credential: &GuestCredential,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_offer(
        &mut store,
        credential,
        relay_stream_resource_from_env(),
        claw_static_pub,
        relay_endpoint,
        credential.expires_at,
        owner_key,
        &trust,
        now,
    )?;
    Ok(offer)
}

/// Fase E2.5: mint + store a GROUP `relay_stream` offer for one member device in
/// the live engine. Loads the same trust/keystore/store/endpoint as the claim
/// path. Authorized at DIAL time by live group membership; this only delivers it
/// to the store so the reverse-connect pool serves it. The TRIGGER (who calls
/// this — a member-request or dev-mint endpoint) and the secure delivery of the
/// returned offer to the dialer are the remaining E2.5 wiring.
#[allow(clippy::too_many_arguments)]
pub async fn provision_group_offer_for_claw(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_group_offer(
        &mut store,
        group_id,
        member_id,
        member_device_pub,
        claw_id,
        relay_stream_resource_from_env(),
        claw_static_pub,
        relay_endpoint,
        not_after,
        owner_key,
        &trust,
        now,
    )?;
    Ok(offer)
}

/// Fase E3: mint + store a PUBLIC `relay_stream` offer for one dialer device in the
/// live engine. Authorized at DIAL time by the live published flag.
#[allow(clippy::too_many_arguments)]
pub async fn provision_public_offer_for_claw(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_public_offer(
        &mut store,
        dialer_device_pub,
        claw_id,
        relay_stream_resource_from_env(),
        claw_static_pub,
        relay_endpoint,
        not_after,
        owner_key,
        &trust,
        now,
    )?;
    Ok(offer)
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamClaimProvisionError {
    #[error("no loaded household identity")]
    NoIdentity,

    #[error("relay stream noise keystore error: {0}")]
    Keystore(String),

    #[error("relay stream offer store error: {0}")]
    Store(#[from] RelayStreamOfferStoreError),

    #[error("relay stream provision error: {0}")]
    Provision(#[from] RelayStreamProvisionError),
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamMountError {
    #[error("relay stream live assembly failed: {0}")]
    Assemble(#[from] RelayStreamLiveError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::claw_share_relay_stream_offer_store::relay_stream_offer_store_path;
    use crate::claw_share_relay_stream_test_support::{
        attacker_signer, data_tunnel_credential, now_unix, owner_signer,
        relay_stream_household_state, relay_stream_issuer_trust,
    };

    #[test]
    fn env_flag_parses_only_explicit_truthy_values() {
        assert!(parse_enabled(Some("1")));
        assert!(parse_enabled(Some("true")));
        assert!(parse_enabled(Some("TRUE")));
        assert!(!parse_enabled(Some("0")));
        assert!(!parse_enabled(Some("false")));
        assert!(!parse_enabled(Some("yes")));
        assert!(!parse_enabled(Some("")));
        assert!(!parse_enabled(None));
    }

    #[tokio::test]
    async fn clawsite_router_unconfigured_fails_closed() {
        let router = RelayStreamClawSiteRouter { backend_addr: None };
        // `TargetSession` is not `Debug`, so match instead of `unwrap_err`.
        let error = match router.open("claw_alpha").await {
            Ok(_) => panic!("unconfigured clawsite router must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DataTunnelError::TargetUnavailable(reason)
                if reason == "relay-stream-clawsite-not-configured"
        ));
    }

    #[tokio::test]
    async fn clawsite_router_configured_forwards_to_backend() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A backend that echoes a prefix proves the router splices bytes both ways.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let mut response = b"SITE:".to_vec();
                response.extend_from_slice(&buf[..n]);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });

        let router = RelayStreamClawSiteRouter {
            backend_addr: Some(addr),
        };
        let mut session = router.open("claw_alpha").await.unwrap();
        session.writer.write_all(b"ping").await.unwrap();
        session.writer.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = session.reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"SITE:ping");
    }

    #[test]
    fn resource_env_parses_clawsite_else_pty() {
        assert_eq!(
            parse_resource(Some("clawsite")),
            RelayStreamResource::ClawSite
        );
        assert_eq!(
            parse_resource(Some(" ClawSite ")),
            RelayStreamResource::ClawSite
        );
        assert_eq!(
            parse_resource(Some("CLAWSITE")),
            RelayStreamResource::ClawSite
        );
        assert_eq!(parse_resource(Some("pty")), RelayStreamResource::Pty);
        assert_eq!(parse_resource(Some("garbage")), RelayStreamResource::Pty);
        assert_eq!(parse_resource(None), RelayStreamResource::Pty);
    }

    #[tokio::test]
    async fn mount_disabled_config_is_noop_and_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let config = RelayStreamLiveConfig::default(); // enabled == false

        let result = mount_relay_stream_live(
            dir.path().to_path_buf(),
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
        )
        .await
        .unwrap();

        assert!(result.is_none());
        // Disabled path must not create the keystore subdir or the offer store.
        assert!(
            !dir.path()
                .join("claw_share")
                .join(RELAY_STREAM_KEYSTORE_SUBDIR)
                .exists()
        );
        assert!(!relay_stream_offer_store_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn mount_enabled_empty_store_returns_live_handles() {
        let dir = tempfile::tempdir().unwrap();
        // Bind+drop a loopback port so the pool's dial target is closed; with an
        // empty store there are zero offers/workers anyway, so nothing dials.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut config = RelayStreamLiveConfig {
            enabled: true,
            ..RelayStreamLiveConfig::default()
        };
        config.reverse_connect.relay_addr = relay_addr;

        let handles = mount_relay_stream_live(
            dir.path().to_path_buf(),
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(handles.offer_count(), 0);
        assert_eq!(handles.pool_task_count(), 0);
        handles.trust_runtime().ensure_healthy(now_unix()).unwrap();
        handles.shutdown();
    }

    #[tokio::test]
    async fn claim_provision_stores_offer_with_responder_static_key() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = data_tunnel_credential();
        let now = now_unix();

        let returned = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            &credential,
            now,
        )
        .await
        .unwrap();

        // The offer is durable and active for the pool to pick up.
        let trust = relay_stream_issuer_trust();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        let active = store.list_active(&trust, now).unwrap();
        assert_eq!(active.len(), 1);
        let offer = &active[0];
        assert_eq!(offer.payload.resource, RelayStreamResource::Pty);
        assert_eq!(
            offer.payload.relay_endpoint,
            format!("relay-stream://{}", relay_stream_relay_endpoint())
        );

        // claw_static_pub is the key the responder mount's keystore would present.
        let keystore = FileKeystore::new(
            dir.path()
                .join("claw_share")
                .join(RELAY_STREAM_KEYSTORE_SUBDIR),
            RELAY_STREAM_KEYSTORE_SERVICE,
        );
        let expected = RelayStreamNoiseKeyStore::new(&keystore)
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        assert_eq!(offer.payload.claw_static_pub, *expected.public_key());

        // The returned offer is the EXACT one persisted (same mint, no re-mint):
        // the relay path delivers THIS offer in the ack.
        assert_eq!(&returned, offer);
        // It serializes to opaque canonical CBOR that decodes back intact - the
        // bytes the relay path puts in ClawShareAck.relay_stream_offer.
        let bytes = household_rs::cbor::to_canonical_vec(&returned).unwrap();
        let decoded: RelayStreamOfferContract =
            household_rs::cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded, returned);
    }

    #[tokio::test]
    async fn provision_group_and_public_offers_store_with_audience() {
        use crate::claw_share_relay_stream_contract::RelayStreamAudience;

        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let now = now_unix();
        let member_dev = household_rs::keys::P256Keypair::generate().public();
        let dialer_dev = household_rs::keys::P256Keypair::generate().public();

        let group_offer = provision_group_offer_for_claw(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            "g".to_string(),
            "g_a".to_string(),
            member_dev,
            "claw_alpha".to_string(),
            now + 600,
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            group_offer.payload.audience(),
            RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "g_a".to_string(),
            }
        );

        let public_offer = provision_public_offer_for_claw(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            dialer_dev,
            "claw_pub".to_string(),
            now + 600,
            now,
        )
        .await
        .unwrap();
        assert_eq!(public_offer.payload.audience(), RelayStreamAudience::Public);

        // Both durable + active for the reverse-connect pool (no slot collision).
        let trust = relay_stream_issuer_trust();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        assert_eq!(store.list_active(&trust, now).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn claim_provision_errors_gracefully_on_owner_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = data_tunnel_credential();
        let now = now_unix();

        // attacker_signer() is not the credential's owner key: the mint rejects,
        // an error is returned (not a panic), and nothing is persisted - the
        // outer best-effort wrapper would log and let the claim proceed.
        let result = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &attacker_signer(),
            &credential,
            now,
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamClaimProvisionError::Provision(_))
        ));
        let trust = relay_stream_issuer_trust();
        let store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn shared_replay_guard_rejects_cross_path_nonce() {
        // The engine threads ONE Arc<ReplayGuard> into both the direct
        // data-tunnel listener and the relay_stream mount. A single-use auth
        // nonce burned on one path must then be rejected on the other.
        let guard = Arc::new(ReplayGuard::new());
        let nonce = b"shared-replay-nonce";
        let now = 1_800_000_000u64;
        let expires_at = now + 60;

        // Path A burns the nonce.
        guard.check_and_record(nonce, expires_at, now).unwrap();
        // Path B (same shared guard) sees the replay.
        let error = guard.check_and_record(nonce, expires_at, now).unwrap_err();
        assert!(matches!(
            error,
            DataTunnelError::TokenRejected(reason) if reason == "token-replayed"
        ));
    }
}
