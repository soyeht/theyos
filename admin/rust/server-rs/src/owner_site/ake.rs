//! Owner-site A2 handshake and test-only record-confirmation seam.
//!
//! The route which reaches this module is intentionally fail-closed in a
//! production process: no reviewed machine/roster provider is installed yet.
//! The only admitting provider is a crate-test harness.  That lets this slice
//! exercise the reviewed A2 wire and ordering without turning a socket address,
//! a CIDR, or an HTTP header into a remote principal.  The harness can also
//! exercise the A2-R1 S2/C3 record confirmation, but it still closes before
//! any peer, dial, proxy, or site-byte effect exists.
//!
//! Production remains fail-closed because it has no admitting provider.  In
//! particular, this module must never substitute a plaintext success response
//! for A2-R1's encrypted record confirmation, nor manufacture a
//! `VerifiedMeshPeer`, backend dial, proxy, or site bytes.

use std::net::SocketAddr;

use axum::extract::ws::WebSocket;
use futures_util::SinkExt;

use crate::owner_site::capability::OwnerSiteResource;

/// Maximum canonical A2-R1 record envelope accepted by the WebSocket boundary.
///
/// The envelope is `canonical-CBOR([1, ciphertext])`, where ciphertext is at
/// most 16,384 bytes including the Noise `ChaChaPoly` tag.
pub(crate) const OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES: usize = 16_389;

/// Provider seam for the one-WebSocket A2 handshake.
///
/// S2 PAIR-1 PROMOTION — declaration (counted criterion, 1 of 2 real pairs):
/// * *Before:* `#[cfg(not(test))]` returned `false` unconditionally — a layer
///   that does nothing rejects everything perfectly.
/// * *After:* the `cfg(not(test))` block is **deleted, deliberately** — not
///   as a side effect of lifting test code. Production now evaluates the
///   shared roster arm, and with `roster: None` (nothing installed) that
///   evaluates to `false`: **the old production behavior is preserved
///   exactly until the startup install lands.** The only cfg fork left is
///   the harness early-return, additions-only.
/// * *Why this arm may change:* S2 installs the first production provider
///   (the startup install is its own named increment; this commit lands the
///   arm and the shape, still unreachable from production wiring).
/// * The roster arm holds NO address-derived input: identity facts only —
///   the server-owned resource and the observation produced by
///   `owner_site_roster_adapter` (co-possession authority; see its
///   five-element declaration).
#[derive(Clone)]
pub(crate) struct OwnerSiteAkeProvider {
    #[cfg(test)]
    harness: Option<std::sync::Arc<OwnerSiteAkeHarness>>,
    roster: Option<OwnerSiteRosterArm>,
}

/// The production arm's roster-backed admission state: which resources this
/// provider serves (the admitted claw set, by name), and the latest
/// observation the adapter produced. The observation arrives through a
/// refresh loop (the roster coordinator does blocking file I/O, so it never
/// runs inline in an admission check).
#[derive(Clone)]
pub(crate) struct OwnerSiteRosterArm {
    admitted: std::sync::Arc<std::sync::RwLock<std::collections::BTreeSet<String>>>,
    latest: std::sync::Arc<
        std::sync::RwLock<Option<crate::owner_site::authority::OwnerSiteAuthorityObservation>>,
    >,
}

// Consumed by the refresh loop when the startup install lands (named
// increment); the allows come off then — same pattern as
// OwnerSitePromotionWitness.
#[allow(dead_code)]
impl OwnerSiteRosterArm {
    /// Single-resource arm (the pair-1 shape): a set of one.
    #[must_use]
    pub(crate) fn new(resource: &OwnerSiteResource) -> Self {
        Self::with_admitted([resource.as_str().to_string()])
    }

    /// The admitted set is COARSE gating only — "is this claw served at
    /// all". The EXACT binding check is downstream (pair 2), so a claw name
    /// present here never implies admission of any intent against it.
    #[must_use]
    pub(crate) fn with_admitted(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            admitted: std::sync::Arc::new(std::sync::RwLock::new(names.into_iter().collect())),
            latest: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Handle for the refresh loop: replace the latest observation. The loop
    /// replaces on success and leaves the previous value in place on failure
    /// — a roster that goes dark does NOT clear a previously good
    /// observation; admission freshness lives inside `observe()` itself
    /// (the coordinator rejects stale checkpoints at query time).
    #[must_use]
    pub(crate) fn observation_slot(
        &self,
    ) -> std::sync::Arc<
        std::sync::RwLock<Option<crate::owner_site::authority::OwnerSiteAuthorityObservation>>,
    > {
        std::sync::Arc::clone(&self.latest)
    }

    #[must_use]
    fn admits(&self, resource: &OwnerSiteResource) -> bool {
        let in_set = self
            .admitted
            .read()
            .map(|set| set.contains(resource.as_str()))
            .unwrap_or(false);
        if !in_set {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        self.latest
            .read()
            .map(|guard| {
                guard
                    .as_ref()
                    .is_some_and(|observation| observation.is_fresh_at(now))
            })
            .unwrap_or(false)
    }
}

impl OwnerSiteAkeProvider {
    /// Tests are the only current source of an admitting A2 provider.  The
    /// production router never installs this extension.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(harness: OwnerSiteAkeHarness) -> Self {
        Self {
            harness: Some(std::sync::Arc::new(harness)),
            roster: None,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn harness_for_test(&self) -> Option<std::sync::Arc<OwnerSiteAkeHarness>> {
        self.harness.clone()
    }

    /// The first production-shaped provider: roster-backed, no address
    /// inputs. Still NOT installed by any production wiring — the startup
    /// install is a separate named increment.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn for_roster(resource: &OwnerSiteResource) -> Self {
        Self {
            #[cfg(test)]
            harness: None,
            roster: Some(OwnerSiteRosterArm::new(resource)),
        }
    }

    /// The production install shape: one provider serving the admitted claw
    /// set (coarse gate; exact binding checks are downstream).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn for_roster_set(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            #[cfg(test)]
            harness: None,
            roster: Some(OwnerSiteRosterArm::with_admitted(names)),
        }
    }

    /// The roster arm, for the refresh loop to feed (and for tests to
    /// observe). `None` for the harness provider.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn roster_arm(&self) -> Option<&OwnerSiteRosterArm> {
        self.roster.as_ref()
    }

    /// Checks the server-owned resource before accepting a WebSocket upgrade.
    #[must_use]
    pub(crate) fn admits_resource(&self, resource: &OwnerSiteResource) -> bool {
        #[cfg(test)]
        {
            if let Some(harness) = &self.harness {
                return harness.admits_resource(resource);
            }
        }
        self.roster.as_ref().is_some_and(|arm| arm.admits(resource))
    }

    /// Drives the test-only A2 handshake and S2/C3 confirmation on one WebSocket.
    ///
    /// The post-C3 result remains intentionally silent and ephemeral until a
    /// later reviewed peer-promotion and dial slice exists.
    pub(crate) async fn serve(
        &self,
        socket: WebSocket,
        resource: OwnerSiteResource,
        peer: Option<SocketAddr>,
    ) {
        #[cfg(test)]
        {
            if let Some(harness) = &self.harness {
                harness.serve(socket, resource, peer).await;
                return;
            }
        }

        let _ = (resource, peer);
        let mut socket = socket;
        let _ = socket.close().await;
    }
}

/// Test-only A2 authority and protocol harness.
///
/// Its implementation lands with the M1/M2/M3 state machine below.  Keeping
/// the type private to crate tests makes the uninstalled production seam deny
/// by default while still allowing route-real red-team coverage.
#[cfg(test)]
mod harness;

#[cfg(test)]
pub(crate) use harness::{OwnerSiteAkeEffectSnapshot, OwnerSiteAkeFixture, OwnerSiteAkeHarness};

#[cfg(test)]
mod pair1_promotion_tests {
    //! RED for the pair-1 promotion: the roster arm preserves default-deny
    //! until an observation exists, admits only the exact server-owned
    //! resource, and never admits on resource mismatch. The observation is
    //! injected through the refresh-loop slot — the same path production
    //! uses, not a test backdoor into the decision.

    use super::*;
    use crate::owner_site::authority::OwnerSiteAuthorityObservation;

    fn resource(name: &str) -> OwnerSiteResource {
        OwnerSiteResource::from_route_claw(name).expect("valid resource")
    }

    fn observation() -> OwnerSiteAuthorityObservation {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        OwnerSiteAuthorityObservation::from_roster_adapter(
            "hh-test".to_string(),
            1,
            [7u8; 32],
            1,
            0,
            [3u8; 33],
            now,
            now + 86_400,
        )
        .expect("non-degenerate observation")
    }

    #[test]
    fn roster_arm_denies_everything_until_an_observation_exists() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        assert!(
            !provider.admits_resource(&resource("claw-a")),
            "default-deny must hold until the adapter produces an observation"
        );
    }

    #[test]
    fn roster_arm_admits_the_exact_resource_once_observing() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider
            .roster_arm()
            .expect("roster arm present")
            .observation_slot();
        *slot.write().expect("slot write") = Some(observation());

        assert!(provider.admits_resource(&resource("claw-a")));
        assert!(
            !provider.admits_resource(&resource("claw-b")),
            "resource mismatch must still refuse, observation or not"
        );
    }

    #[test]
    fn replacing_the_slot_with_none_closes_again() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider
            .roster_arm()
            .expect("roster arm present")
            .observation_slot();
        *slot.write().expect("slot write") = Some(observation());
        assert!(provider.admits_resource(&resource("claw-a")));
        *slot.write().expect("slot write") = None;
        assert!(!provider.admits_resource(&resource("claw-a")));
    }
}

#[cfg(test)]
mod refresh_budget_tests {
    //! THE REFRESH-FAILURE-BUDGET RED (the coordinator's condition for the
    //! staleness term): the refresh loop stopped (slot holds an OLD
    //! observation whose checkpoint `not_after` is far in the future) and
    //! admission must REFUSE once the observation is older than
    //! REFRESH_FAILURE_BUDGET_SECS — measured at the decision, which is the
    //! effect this module owns. Without this pin the staleness term is
    //! decoration and a future "simplification" removes it.

    use super::*;
    use crate::owner_site::authority::{
        OwnerSiteAuthorityObservation, REFRESH_FAILURE_BUDGET_SECS,
    };

    fn resource(name: &str) -> OwnerSiteResource {
        OwnerSiteResource::from_route_claw(name).expect("valid resource")
    }

    fn observation_observed_at(
        observed_at: u64,
        checkpoint_not_after: u64,
    ) -> OwnerSiteAuthorityObservation {
        OwnerSiteAuthorityObservation::from_roster_adapter(
            "hh".to_string(),
            1,
            [7u8; 32],
            1,
            0,
            [3u8; 33],
            observed_at,
            checkpoint_not_after,
        )
        .expect("non-degenerate observation")
    }

    #[test]
    fn a_fresh_observation_admits() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider.roster_arm().unwrap().observation_slot();
        *slot.write().unwrap() = Some(observation_observed_at(now, now + 86_400));
        assert!(provider.admits_resource(&resource("claw-a")));
    }

    #[test]
    fn refresh_stopped_with_future_checkpoint_still_refuses_after_the_budget() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // The checkpoint is valid for another DAY (authority's not_after is
        // far away), but the observation is TEN MINUTES old — the refresh
        // loop has been dead for ten minutes.
        let stale_observation = observation_observed_at(now - 600, now + 86_400);
        assert!(
            !stale_observation.is_fresh_at(now),
            "observed_at + 300s budget has passed: not fresh even with a day of checkpoint validity"
        );
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider.roster_arm().unwrap().observation_slot();
        *slot.write().unwrap() = Some(stale_observation);
        assert!(
            !provider.admits_resource(&resource("claw-a")),
            "refresh stopped + future not_after must STILL refuse after the budget"
        );
    }

    #[test]
    fn the_authority_ceiling_is_never_exceeded() {
        // not_after is BEFORE observed_at + budget: the min picks the
        // authority, never the budget.
        let obs = observation_observed_at(1_000, 1_100);
        assert!(!obs.is_fresh_at(1_101), "the authority ceiling rules");
        assert!(obs.is_fresh_at(1_100));
    }
}
