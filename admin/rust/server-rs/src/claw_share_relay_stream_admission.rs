//! Per-connection admission gate for the Product A `relay_stream` responder.
//!
//! C4c building block. Long-lived responder components hold this factory, not a
//! raw [`RelayStreamIssuerTrust`]. Each accepted connection must call
//! [`RelayStreamAdmission::admit`] with the current time; unhealthy trust context
//! state fails closed before Noise handshake or data-tunnel authorization starts.
//!
//! Out of scope: reverse-connect pools, refresh timers, bootstrap/app-state
//! wiring, claim ack, iOS, public listeners, and mid-session issuer-health
//! polling. A session admitted while healthy keeps using its per-connection
//! trust seam; slot/share revocation remains enforced by the data tunnel.

use std::fmt;
use std::sync::Arc;

use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextHealthError, RelayStreamTrustContextRuntime,
};

#[derive(Clone)]
pub struct RelayStreamAdmission {
    runtime: Arc<RelayStreamTrustContextRuntime>,
}

impl RelayStreamAdmission {
    #[must_use]
    pub fn new(runtime: Arc<RelayStreamTrustContextRuntime>) -> Self {
        Self { runtime }
    }

    /// Gate one accepted connection. The returned trust seam is intentionally
    /// per-connection; long-lived components should keep this admission factory
    /// and re-run this method for every new connection.
    pub fn admit(
        &self,
        now_unix: u64,
    ) -> Result<RelayStreamIssuerTrust, RelayStreamAdmissionError> {
        self.runtime
            .issuer_trust_if_healthy(now_unix)
            .map_err(RelayStreamAdmissionError::Health)
    }
}

impl fmt::Debug for RelayStreamAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamAdmission")
            .field("runtime", &"redacted")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamAdmissionError {
    #[error("relay stream admission rejected: {0}")]
    Health(#[from] RelayStreamTrustContextHealthError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use household_rs::LoadedIdentity;
    use household_rs::household_mesh_log::MeshLogStore;
    use household_rs::household_record::HouseholdRecord;
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::keys::IdentityKey;
    use household_rs::machine_cert::{MachineCert, Platform, SignOptions};

    use crate::claw_share_relay_stream_test_support::{
        household_root_signer, now_unix, owner_signer, relay_stream_offer, rendezvous_token,
    };
    use crate::claw_share_relay_stream_trust_context_health::{
        RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
    };
    use crate::household_state::HouseholdState;

    const NOW: u64 = 1_800_000_000;

    fn record() -> HouseholdRecord {
        let hh = household_root_signer();
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh.public()),
            hh_pub: hh.public(),
            name: "home".to_string(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&owner_signer().public())],
            is_follower: false,
        }
    }

    fn machine_cert() -> MachineCert {
        let hh = household_root_signer();
        MachineCert::sign(
            &hh,
            &owner_signer().public(),
            &SignOptions {
                hh_id: derive_household_id(&hh.public()),
                hostname: "engine-mac".to_string(),
                platform: Platform::Macos,
                joined_at: NOW - 1_000,
            },
        )
        .unwrap()
    }

    fn household() -> HouseholdState {
        HouseholdState::loaded(Arc::new(LoadedIdentity {
            record: record(),
            cert: machine_cert(),
            hh_priv: None,
            m_priv: Box::new(owner_signer()),
            backing: "software",
        }))
    }

    fn policy() -> RelayStreamTrustContextRefreshPolicy {
        RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(60), 2).unwrap()
    }

    async fn admission_loaded_at(
        last_success_unix: u64,
        policy: RelayStreamTrustContextRefreshPolicy,
    ) -> RelayStreamAdmission {
        let runtime = RelayStreamTrustContextRuntime::load(
            &household(),
            &MeshLogStore::new(),
            last_success_unix,
            policy,
        )
        .await
        .unwrap();
        RelayStreamAdmission::new(Arc::new(runtime))
    }

    #[tokio::test]
    async fn relay_stream_admission_healthy_produces_machine_issuer_trust() {
        let verify_now = now_unix();
        let admission = admission_loaded_at(verify_now, policy()).await;
        let trust = admission.admit(verify_now).unwrap();
        let keypair =
            crate::claw_share_relay_stream_noise::generate_relay_stream_noise_static_keypair()
                .unwrap();
        let offer = relay_stream_offer(rendezvous_token(0xA1), &keypair);

        trust.verify_offer(&offer, verify_now).unwrap();
    }

    #[tokio::test]
    async fn relay_stream_admission_rejects_stale_context() {
        let admission = admission_loaded_at(NOW, policy()).await;

        let error = admission.admit(NOW + 61).unwrap_err();

        assert!(matches!(
            error,
            RelayStreamAdmissionError::Health(RelayStreamTrustContextHealthError::Stale { .. })
        ));
    }

    #[tokio::test]
    async fn relay_stream_admission_rejects_after_failure_limit() {
        let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(60), 1).unwrap();
        let runtime =
            RelayStreamTrustContextRuntime::load(&household(), &MeshLogStore::new(), NOW, policy)
                .await
                .unwrap();
        runtime
            .refresh_now(&HouseholdState::empty(), &MeshLogStore::new(), NOW)
            .await
            .unwrap_err();
        let admission = RelayStreamAdmission::new(Arc::new(runtime));

        let error = admission.admit(NOW).unwrap_err();

        assert!(matches!(
            error,
            RelayStreamAdmissionError::Health(
                RelayStreamTrustContextHealthError::RefreshFailing { .. }
            )
        ));
    }

    #[tokio::test]
    async fn relay_stream_admission_rechecks_health_per_connection() {
        let admission = admission_loaded_at(NOW, policy()).await;
        admission.admit(NOW).unwrap();

        let error = admission.admit(NOW + 61).unwrap_err();

        assert!(matches!(
            error,
            RelayStreamAdmissionError::Health(RelayStreamTrustContextHealthError::Stale { .. })
        ));
    }

    #[tokio::test]
    async fn relay_stream_admission_debug_and_errors_do_not_leak_secret() {
        let admission = admission_loaded_at(NOW, policy()).await;
        let debug = format!("{admission:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("token"));
        assert!(!debug.contains("secret"));

        let error = RelayStreamAdmissionError::Health(RelayStreamTrustContextHealthError::Stale {
            stale_secs: 99,
            max_stale_secs: 60,
        });
        let error_debug = format!("{error:?}");
        let error_display = error.to_string();
        for text in [error_debug, error_display] {
            assert!(!text.contains("private"));
            assert!(!text.contains("token"));
            assert!(!text.contains("secret"));
        }
    }
}
