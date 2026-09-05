//! Facts for household address selection. The iPhone's SoyehtCore policy
//! ranks these candidates; the engine never guesses the phone's reachability.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use household_rs::{bootstrap_state::BootstrapState, pair_device::PairDeviceWindow};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::sync::RwLock;

use crate::{
    household_listener::{BoundSet, HouseholdExposurePolicy, InterfaceClass, PairingWindow},
    household_state::HouseholdState,
    local_network_visibility::LocalNetworkVisibility,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingInstallation {
    pub profile: String,
    pub bootstrap_port: u16,
}

impl PairingInstallation {
    /// Both sources are explicit installation configuration. The service port
    /// is never used to infer whether an invitation belongs to Dev or release.
    pub fn configured(port: u16) -> Option<Self> {
        let profile =
            std::env::var("SOYEHT_INSTALL_PROFILE").ok().or_else(|| {
                match std::env::var("THEYOS_SECURE_UPGRADE_APP_ATTEST_BUNDLE_ID")
                    .ok()
                    .as_deref()
                {
                    Some("com.soyeht.app.dev") => Some("dev".into()),
                    Some("com.soyeht.app") => Some("release".into()),
                    _ => None,
                }
            })?;
        Self::new(profile, port)
    }

    pub fn new(profile: String, port: u16) -> Option<Self> {
        if port == 0 || !matches!(profile.as_str(), "release" | "dev") {
            return None;
        }
        Some(Self {
            profile,
            bootstrap_port: port,
        })
    }
}

#[derive(Clone)]
pub struct PairingAddressesState {
    pub bound: BoundSet,
    pub bootstrap: Arc<RwLock<BootstrapState>>,
    pub household: HouseholdState,
    pub window: Arc<PairDeviceWindow>,
    pub visibility: Arc<LocalNetworkVisibility>,
    pub installation: Option<PairingInstallation>,
    boot_id: [u8; 16],
}

impl PairingAddressesState {
    pub fn new(
        bound: BoundSet,
        bootstrap: Arc<RwLock<BootstrapState>>,
        household: HouseholdState,
        window: Arc<PairDeviceWindow>,
        visibility: Arc<LocalNetworkVisibility>,
        installation: Option<PairingInstallation>,
    ) -> Self {
        let mut boot_id = [0; 16];
        OsRng.fill_bytes(&mut boot_id);
        Self {
            bound,
            bootstrap,
            household,
            window,
            visibility,
            installation,
            boot_id,
        }
    }

    pub async fn snapshot(&self) -> Result<PairingAddressesResponse, &'static str> {
        let installation = self.installation.clone().ok_or("profile_missing")?;
        let state = *self.bootstrap.read().await;
        let window = PairingWindow::observe(&self.window, &self.visibility).await;
        let identity = self.household.current().await;
        let owner = self.household.current_owner_auth().await;
        let authority = PairingAuthority {
            household_id: identity.as_ref().map(|i| i.record.hh_id.to_string()),
            owner_person_id: owner.as_ref().map(|a| a.owner_person_cert.p_id.0.clone()),
            owner_public_key: owner
                .as_ref()
                .map(|a| ByteBuf::from(a.owner_person_cert.p_pub.as_bytes().to_vec())),
        };
        let token_expiry = self
            .window
            .current_token()
            .await
            .map(|token| token.expires_at_unix);
        let visibility_expiry = self.visibility.expires_at_unix().await;
        let lan_expiry = token_expiry.into_iter().chain(visibility_expiry).max();
        let mut targets = self.bound.snapshot_targets().await;
        targets.sort_by_key(|(ip, _)| *ip);
        let mut candidates = Vec::new();
        for (ip, class) in targets {
            let transport = match class {
                InterfaceClass::Tailscale => "tailnet",
                InterfaceClass::Lan => "lan",
                InterfaceClass::Loopback | InterfaceClass::Mesh => continue,
            };
            if !HouseholdExposurePolicy::allows_with(state, class, window) {
                continue;
            }
            let operations = operations_for(state, owner.is_some());
            if operations.is_empty() {
                continue;
            }
            candidates.push(PairingAddressCandidate {
                url: format!(
                    "http://{}",
                    SocketAddr::new(ip, installation.bootstrap_port)
                ),
                transport,
                operations,
                availability: "listening",
                expires_at_unix: if class == InterfaceClass::Lan
                    && !matches!(
                        state,
                        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming
                    ) {
                    lan_expiry
                } else {
                    None
                },
            });
        }
        // Stable for an unchanged snapshot and different across process
        // restarts, authority changes, bind changes or window deadlines.
        let material = serde_json::to_vec(&(&installation, &authority, &candidates))
            .map_err(|_| "encoding_failed")?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.boot_id);
        hasher.update(&material);
        Ok(PairingAddressesResponse {
            version: 1,
            installation,
            generation: hasher.finalize().to_hex().to_string(),
            candidates,
            authority,
        })
    }
}

fn operations_for(state: BootstrapState, owner_present: bool) -> Vec<&'static str> {
    match (state, owner_present) {
        (BootstrapState::Uninitialized | BootstrapState::ReadyForNaming, false) => {
            vec!["initialize", "accept_household"]
        }
        (BootstrapState::NamedAwaitingPair, false) => vec!["first_owner"],
        (BootstrapState::Ready, true) => vec!["add_device"],
        _ => Vec::new(),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PairingAuthority {
    pub household_id: Option<String>,
    pub owner_person_id: Option<String>,
    pub owner_public_key: Option<ByteBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairingAddressCandidate {
    pub url: String,
    pub transport: &'static str,
    pub operations: Vec<&'static str>,
    pub availability: &'static str,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PairingAddressesResponse {
    #[serde(rename = "v")]
    pub version: u8,
    pub installation: PairingInstallation,
    pub generation: String,
    pub candidates: Vec<PairingAddressCandidate>,
    pub authority: PairingAuthority,
}

async fn get_addresses(
    State(state): State<PairingAddressesState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    let bootstrap = *state.bootstrap.read().await;
    let window = PairingWindow::observe(&state.window, &state.visibility).await;
    let peer_class = if peer.ip().is_loopback() {
        InterfaceClass::Loopback
    } else if crate::tailnet_address::is_tailnet_ip(peer.ip()) {
        InterfaceClass::Tailscale
    } else {
        InterfaceClass::Lan
    };
    if !HouseholdExposurePolicy::allows_with(bootstrap, peer_class, window) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.snapshot().await {
        Ok(snapshot) => crate::handlers_bootstrap::cbor_ok(snapshot),
        Err(reason) => {
            tracing::warn!(stage = "pairing.addresses.unavailable", reason);
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub fn router(state: PairingAddressesState) -> Router {
    Router::new()
        .route("/bootstrap/pairing-addresses", get(get_addresses))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_admission_depends_on_owner_authority_not_device_count() {
        assert_eq!(
            operations_for(BootstrapState::NamedAwaitingPair, false),
            vec!["first_owner"]
        );
        assert!(operations_for(BootstrapState::NamedAwaitingPair, true).is_empty());
        assert_eq!(
            operations_for(BootstrapState::Ready, true),
            vec!["add_device"]
        );
        assert!(operations_for(BootstrapState::Ready, false).is_empty());
    }

    #[test]
    fn installation_does_not_infer_profile_from_port() {
        assert!(PairingInstallation::new("unknown".into(), 8101).is_none());
        assert!(PairingInstallation::new("dev".into(), 0).is_none());
        assert_ne!(
            PairingInstallation::new("dev".into(), 8101),
            PairingInstallation::new("release".into(), 8101)
        );
    }
}
