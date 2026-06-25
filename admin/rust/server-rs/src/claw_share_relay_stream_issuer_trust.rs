//! Required machine-issuer trust source for the Claw/engine side of `relay_stream`.
//!
//! [`RelayStreamIssuerTrust`] is the seam the `relay_stream` building blocks (offer
//! store, target router, Noise responder) use instead of a pinned
//! `expected_owner_pub`. It bundles the household trust inputs and delegates to
//! [`RelayStreamOfferContract::verify_with_trust`], which authorizes the offer's
//! own `signer_pub` as an active machine issuer — the engine signs offers with
//! `identity.m_priv`, not the Shamir-split household root.
//!
//! The trust source is REQUIRED and LIVE: it is a closure that produces a full
//! [`RelayStreamTrustContext`] on every call, so the household record/members and
//! the directory-device revocation overlay are re-read per verification — a kill
//! switch (`DirectoryDeviceRemoved`) can never go inert behind a stale snapshot.
//! There is no `None`/no-projection default. C4 will supply a closure over
//! `HouseholdState.current()` + a cached/invalidated `mesh_log.project()`; this
//! cut does not wire those live values.

use std::fmt;
use std::sync::Arc;

use household_rs::household_mesh_log::ProjectedState;
use household_rs::household_record::HouseholdRecord;
use household_rs::machine_cert::MachineCert;

use crate::claw_share_relay_stream_contract::{
    RelayStreamContractError, RelayStreamNoisePrologue, RelayStreamOfferContract,
};

/// The live household trust inputs for one verification.
///
/// `record` and `projection` are produced fresh on every verification; `cert` is
/// the engine's own machine cert and may be cloned from a stable identity.
#[derive(Clone)]
pub struct RelayStreamTrustContext {
    pub record: HouseholdRecord,
    pub cert: MachineCert,
    pub projection: ProjectedState,
}

/// Required, live machine-issuer trust source for Claw/engine-side `relay_stream`
/// verification. Clone-cheap (`Arc` inside) and `Send + Sync` for use across
/// tasks and long-lived routers.
#[derive(Clone)]
pub struct RelayStreamIssuerTrust {
    source: Arc<dyn Fn() -> RelayStreamTrustContext + Send + Sync>,
}

impl RelayStreamIssuerTrust {
    /// Build the seam from a required trust-context source. The source MUST
    /// return a real [`RelayStreamTrustContext`] (with a live projection) on
    /// every call — there is no projection-less variant, so the revocation
    /// overlay can never be silently inert.
    pub fn new(source: impl Fn() -> RelayStreamTrustContext + Send + Sync + 'static) -> Self {
        Self {
            source: Arc::new(source),
        }
    }

    /// Authorize and verify an offer for Claw-side consumption: the offer's
    /// signer must be an active household machine issuer and its signature must
    /// verify against that key. The trust context is refreshed on every call.
    pub fn verify_offer(
        &self,
        offer: &RelayStreamOfferContract,
        now_unix: u64,
    ) -> Result<(), RelayStreamContractError> {
        let ctx = (self.source)();
        offer.verify_with_trust(&ctx.record, &ctx.cert, &ctx.projection, now_unix)
    }

    /// Fase E2: like [`verify_offer`] but returns the SAME live trust context it
    /// verified against, so the Group dial-path can run its membership check on
    /// the EXACT projection that gated the signer — never a second snapshot.
    /// This single-snapshot rule is the #1 fail-closed property of the group
    /// model: a `GroupMemberRemoved`/`GroupClawRevoked` takes effect on the next
    /// open with the same latency and guarantee as the directory kill switch.
    pub fn verify_offer_with_context(
        &self,
        offer: &RelayStreamOfferContract,
        now_unix: u64,
    ) -> Result<RelayStreamTrustContext, RelayStreamContractError> {
        let ctx = (self.source)();
        offer.verify_with_trust(&ctx.record, &ctx.cert, &ctx.projection, now_unix)?;
        Ok(ctx)
    }

    /// Derive the Claw-side Noise prologue after machine-issuer verification.
    /// Byte-identical to the guest's `to_noise_prologue_for_audience` for the
    /// same offer/signer; only the gate differs, never the transcript.
    pub fn to_noise_prologue(
        &self,
        offer: &RelayStreamOfferContract,
        now_unix: u64,
    ) -> Result<RelayStreamNoisePrologue, RelayStreamContractError> {
        let ctx = (self.source)();
        offer.to_noise_prologue_with_trust(&ctx.record, &ctx.cert, &ctx.projection, now_unix)
    }
}

impl fmt::Debug for RelayStreamIssuerTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamIssuerTrust")
            .field("source", &"redacted")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use household_rs::claw_share::SlotId;
    use household_rs::household_mesh_log::{DirectoryDeviceStatus, ProjectedDirectoryDevice};
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::issuer_trust::MachineIssuerError;
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::machine_cert::{Platform, SignOptions};

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferPayload,
        RelayStreamResource,
    };
    use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

    const NOW: u64 = 1_800_000_000;

    fn hh() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn machine() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x22; 32]).unwrap()
    }

    fn attacker() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
    }

    fn guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x33; 32])
            .unwrap()
            .public()
    }

    fn machine_cert() -> MachineCert {
        MachineCert::sign(
            &hh(),
            &machine().public(),
            &SignOptions {
                hh_id: derive_household_id(&hh().public()),
                hostname: "engine-mac".into(),
                platform: Platform::Macos,
                joined_at: NOW - 1_000,
            },
        )
        .unwrap()
    }

    fn record() -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh().public()),
            hh_pub: hh().public(),
            name: "home".into(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&machine().public())],
            is_follower: false,
        }
    }

    fn offer(signer: &P256Keypair) -> RelayStreamOfferContract {
        let payload = RelayStreamOfferPayload::new(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap(),
            NOW + 60,
        );
        RelayStreamOfferContract::sign(payload, signer).unwrap()
    }

    fn trust_with(projection: ProjectedState) -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: record(),
            cert: machine_cert(),
            projection: projection.clone(),
        })
    }

    fn trust_live(state: Arc<Mutex<ProjectedState>>) -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: record(),
            cert: machine_cert(),
            projection: state.lock().unwrap().clone(),
        })
    }

    #[test]
    fn issuer_trust_accepts_machine_signed_offer() {
        let trust = trust_with(ProjectedState::default());

        trust.verify_offer(&offer(&machine()), NOW).unwrap();
    }

    #[test]
    fn issuer_trust_rejects_offer_signed_by_unauthorized_key_opaquely() {
        // Signed by an attacker key that is neither the household root (no root
        // fallback) nor the certified machine issuer: cert.m_pub (machine) !=
        // signer (attacker) => SignerMismatch, mapped to opaque IssuerUnauthorized.
        let trust = trust_with(ProjectedState::default());

        let err = trust.verify_offer(&offer(&attacker()), NOW).unwrap_err();

        assert!(matches!(
            err,
            RelayStreamContractError::IssuerUnauthorized(MachineIssuerError::SignerMismatch)
        ));
    }

    #[test]
    fn issuer_trust_refreshes_projection_per_call_so_revocation_takes_effect() {
        let state = Arc::new(Mutex::new(ProjectedState::default()));
        let trust = trust_live(Arc::clone(&state));
        let offer = offer(&machine());

        // First call: no removal in the directory overlay -> accepted.
        trust.verify_offer(&offer, NOW).unwrap();

        // Revoke the issuing machine in the live projection; the next call must
        // observe it (the source is re-read each time, never snapshotted).
        state.lock().unwrap().directory_devices.insert(
            machine().public().as_bytes().to_vec(),
            ProjectedDirectoryDevice {
                label: "engine-mac".to_string(),
                status: DirectoryDeviceStatus::Removed,
            },
        );

        let err = trust.verify_offer(&offer, NOW).unwrap_err();
        assert!(matches!(
            err,
            RelayStreamContractError::IssuerUnauthorized(MachineIssuerError::DeviceRemoved)
        ));
    }

    #[test]
    fn issuer_trust_prologue_matches_guest_audience_prologue_bytes() {
        let trust = trust_with(ProjectedState::default());
        let offer = offer(&machine());

        let via_trust = trust.to_noise_prologue(&offer, NOW).unwrap();
        let via_audience = offer
            .to_noise_prologue_for_audience(&offer.signer_pub, &guest_pub(), NOW)
            .unwrap();

        assert_eq!(via_trust.as_bytes(), via_audience.as_bytes());
    }
}
