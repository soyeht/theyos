//! S2 roster adapter — the single producer of `OwnerSiteAuthorityObservation`.
//!
//! ## Declaration required by the N1d decision (five elements, gate criterion 7)
//!
//! * **Question this primitive answers:** "do these two devices CO-POSSESS?"
//!   — a SESSION question.
//! * **Subject:** a pair of devices in an A2 handshake.
//! * **Authority:** co-possession, from the live roster authority
//!   (`household_rs::machine_roster_*`).
//! * **Why this is NOT the provider's primitive:** the provider (Phase 3)
//!   answers "may this peer exist on this mesh interface?" — a TRANSPORT
//!   question about a machine, answered before the socket, under roster
//!   authority of its own. Different layer, different subject, different
//!   authority. Neither imports from the other; a future unification is its
//!   own slice with explicit authorization, never a side effect.
//! * **What revocation in the OTHER layer does NOT cover:** roster (machine)
//!   and co-possession (device) are DIFFERENT authorities with DIFFERENT
//!   revocations. A machine alive in the roster with its device revoked in
//!   co-possession is admitted by the transport and refused by the session —
//!   coherent because the subjects differ, and said in writing because
//!   coherent is not the same as declared. Symmetrically, a co-possession
//!   refusal does NOT tear down any transport interface: that lifecycle is
//!   the provider's, and this layer never touches it. The window between the
//!   two revocations is explicit here so nobody builds on unstated reach.
//!
//! ## Seam discipline (design g1 §1)
//!
//! One producer (this adapter), two subscribers (the S2 glue feeding
//! `admits_pre_effect` and the S4 watcher). **No consumer constructs its own
//! view** — a watcher that builds its own observation is a second adapter,
//! the exact duplication this seam exists to prevent.
//!
//! ## What this module deliberately does NOT take as input
//!
//! No `ConnectInfo`, no CIDR, no interface name, no address classification.
//! An IP range is not an identity; the binding resolution consumes identity
//! facts only (`binding_id`, `member_device`, keys) via
//! `OwnerSiteRosterBinding::resolves`.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::owner_site_authority::OwnerSiteAuthorityObservation;

/// Refresh cadence for the observation loop: the observation must stay
/// fresher than the shortest challenge window the A2 issues (60 s), so 30 s.
/// Declared, not tuned: changing it is a freshness-budget decision, not a
/// performance tweak.
pub(crate) const OBSERVATION_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the observation refresh loop (the install increment). The loop:
///
/// - waits until BOTH the household identity and the owner auth are loaded
///   (before that, the roster cannot be read and the slot stays empty —
///   default-deny);
/// - re-observes every [`OBSERVATION_REFRESH_INTERVAL`] via `spawn_blocking`
///   (the roster coordinator takes a cross-process file lock and does
///   blocking file I/O — it never runs on the async executor);
/// - on success REPLACES the slot; on failure KEEPS the previous value — a
///   roster that goes dark does not clear a good observation, and freshness
///   is enforced inside `observe()` itself (the coordinator rejects stale
///   checkpoints at query time).
///
/// The loop has no shutdown handle of its own: it is a daemon task whose
/// lifetime is the process's, like the interface sync loops.
#[allow(dead_code)] // wired by bootstrap_household in this same increment
pub(crate) fn spawn_observation_refresh(
    household: crate::household_state::HouseholdState,
    state_dir: std::path::PathBuf,
    slot: Arc<RwLock<Option<OwnerSiteAuthorityObservation>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let identity = household.current().await;
            let auth = household.current_owner_auth().await;
            if let (Some(identity), Some(auth)) = (identity, auth) {
                let record = identity.record.clone();
                let m_id = identity.cert.m_id.clone();
                let dir = state_dir.clone();
                let observed = tokio::task::spawn_blocking(move || {
                    OwnerSiteRosterAdapter::new(&dir).observe(&record, &auth, &m_id)
                })
                .await;
                if let Ok(Ok(observation)) = observed {
                    *slot
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observation);
                }
            }
            tokio::time::sleep(OBSERVATION_REFRESH_INTERVAL).await;
        }
    })
}

/// Rejections while producing an observation from the live roster authority.
/// Every variant fails closed: no observation is produced.
// Increment 1 lands the seam before its consumers; the allows come off as the
// S2 glue installs the adapter (same pattern as OwnerSitePromotionWitness).
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum OwnerSiteRosterAdapterError {
    /// The roster authority could not be read or failed its own validation.
    AuthorityUnavailable(String),
    /// The authority read succeeded but the projected fields failed the
    /// adapter's own checks (zero digest, zero generation).
    ProjectionRejected(&'static str),
}

/// The roster adapter. Holds exactly what the observation needs and nothing
/// more: the state dir where the durable roster authority lives.
#[allow(dead_code)]
pub(crate) struct OwnerSiteRosterAdapter {
    state_dir: std::path::PathBuf,
}

#[allow(dead_code)]
impl OwnerSiteRosterAdapter {
    #[must_use]
    pub(crate) fn new(state_dir: &Path) -> Self {
        Self {
            state_dir: state_dir.to_path_buf(),
        }
    }

    /// Produce one typed observation from the LIVE roster authority.
    ///
    /// Projection (declared for audit):
    /// - `household` ← the validated record's `hh_id`;
    /// - `roster_digest` ← **`state_evidence_digest()`** of the evidence
    ///   snapshot — the body WITHOUT `floor_secs`. The floor is a
    ///   PER-MACHINE wall-clock floor (`machine_roster_store.rs` floor
    ///   observation), so `full_snapshot_digest()` (body WITH floor) makes
    ///   two machines with a byte-identical roster produce DIFFERENT
    ///   digests — the property this projection needs (parties agree on the
    ///   same roster) holds only for the floor-less digest. The wrong choice
    ///   is the plausible one ("it is the digest the route serves"); the
    ///   double-floor RED below pins the right one. A third digest lives on
    ///   this path (`OwnerSiteAuthorityGeneration.digest`, the AKE's
    ///   comparison target): the glue maps like-to-like — floor-less to
    ///   floor-less.
    /// - `authz_epoch` and `provider_generation` ← the accepted checkpoint's
    ///   `checkpoint_sequence`. DECLARED, not fixed (audit finding 2): the
    ///   two coincide in this increment because the roster authority is the
    ///   ONLY producer, so the producer's coordinate IS the roster's
    ///   monotonic. They would separate the day a second producer or a
    ///   durable/cached provider exists — `provider_generation` is the
    ///   PRODUCER's coordinate and a durable provider must reject rollback,
    ///   so then it must come from the producer's own monotonic, not from
    ///   the roster. Choice of coordinate, also declared: the checkpoint
    ///   carries both `checkpoint_sequence` and `event_sequence`; this
    ///   projection pins the AUTHORITY coordinate (the accepted checkpoint),
    ///   not the log position.
    /// - `cancellation_generation` ← max `sequence` among the checkpoint's
    ///   revocations (0 when none);
    /// - `household_root` ← the record's `hh_pub` (compressed P-256);
    /// - `observed_at` ← now.
    ///
    /// Fails closed: an unavailable roster, a missing snapshot, an
    /// undecodable checkpoint, or a degenerate projection yields NO
    /// observation. No `ConnectInfo`, no CIDR, no address classification is
    /// read anywhere on this path.
    pub(crate) fn observe(
        &self,
        record: &household_rs::HouseholdRecord,
        auth: &household_rs::HouseholdAuthState,
        signer_m_id: &household_rs::ids::MachineId,
    ) -> Result<OwnerSiteAuthorityObservation, OwnerSiteRosterAdapterError> {
        use household_rs::machine_roster_store::MachineRosterCoordinator;

        let coordinator =
            MachineRosterCoordinator::from_validated_household(&self.state_dir, record, auth)
                .map_err(|e| {
                    OwnerSiteRosterAdapterError::AuthorityUnavailable(format!("coordinator: {e}"))
                })?;
        let (outcome, snapshot) = coordinator
            .query_roster_evidence(signer_m_id)
            .map_err(|e| {
                OwnerSiteRosterAdapterError::AuthorityUnavailable(format!("evidence query: {e}"))
            })?;
        if !outcome.is_available() {
            return Err(OwnerSiteRosterAdapterError::AuthorityUnavailable(format!(
                "roster unavailable: {}",
                outcome.wire_str()
            )));
        }
        let snapshot = snapshot.ok_or_else(|| {
            OwnerSiteRosterAdapterError::AuthorityUnavailable(
                "available outcome carried no snapshot".into(),
            )
        })?;
        let roster_digest = snapshot.state_evidence_digest().map_err(|e| {
            OwnerSiteRosterAdapterError::AuthorityUnavailable(format!("snapshot digest: {e}"))
        })?;

        let checkpoint_bytes = snapshot.accepted_checkpoint.as_deref().ok_or_else(|| {
            OwnerSiteRosterAdapterError::AuthorityUnavailable(
                "roster has no accepted checkpoint (genesis-less)".into(),
            )
        })?;
        let checkpoint: household_rs::machine_roster_authority::MachineRosterCheckpointV1 =
            household_rs::cbor::from_canonical_slice(checkpoint_bytes).map_err(|_e| {
                OwnerSiteRosterAdapterError::ProjectionRejected("checkpoint does not decode")
            })?;
        let cancellation_generation = checkpoint
            .revocations
            .iter()
            .map(|revocation| revocation.sequence)
            .max()
            .unwrap_or(0);
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| OwnerSiteRosterAdapterError::AuthorityUnavailable(format!("clock: {e}")))?
            .as_secs();

        OwnerSiteAuthorityObservation::from_roster_adapter(
            record.hh_id.0.clone(),
            checkpoint.checkpoint_sequence,
            roster_digest,
            checkpoint.checkpoint_sequence,
            cancellation_generation,
            *record.hh_pub.as_bytes(),
            observed_at,
            checkpoint.not_after,
        )
        .ok_or(OwnerSiteRosterAdapterError::ProjectionRejected(
            "degenerate projection (zero digest, zero generation, or empty household)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_site_authority::OwnerSiteAuthorityObservation;

    /// The constructor discipline, pinned at the seam itself: degenerate
    /// projections are NOT observations (zero digest, zero generation, empty
    /// household each fail closed).
    #[test]
    fn from_roster_adapter_rejects_degenerate_projections() {
        let base = || {
            OwnerSiteAuthorityObservation::from_roster_adapter(
                "hh".to_string(),
                1,
                [7u8; 32],
                1,
                0,
                [3u8; 33],
                100,
                9_999_999,
            )
        };
        assert!(base().is_some());
        assert!(
            OwnerSiteAuthorityObservation::from_roster_adapter(
                "hh".to_string(),
                1,
                [0u8; 32],
                1,
                0,
                [3u8; 33],
                100,
                9_999_999,
            )
            .is_none(),
            "zero digest must not be an observation"
        );
        assert!(
            OwnerSiteAuthorityObservation::from_roster_adapter(
                "hh".to_string(),
                1,
                [7u8; 32],
                0,
                0,
                [3u8; 33],
                100,
                9_999_999,
            )
            .is_none(),
            "zero generation must not be an observation"
        );
        assert!(
            OwnerSiteAuthorityObservation::from_roster_adapter(
                String::new(),
                1,
                [7u8; 32],
                1,
                0,
                [3u8; 33],
                100,
                9_999_999,
            )
            .is_none(),
            "empty household must not be an observation"
        );
    }

    /// THE DOUBLE-FLOOR RED (permanent pin): two snapshots of the SAME
    /// roster state with deliberately different wall-clock floors must
    /// produce the SAME projection digest — because the digest is the
    /// floor-less `state_evidence_digest`. This bites if anyone ever
    /// "optimizes" back to `full_snapshot_digest` with the plausible
    /// argument "it is the digest the route serves": the with-floor digest
    /// differs across machines for a byte-identical roster, and a
    /// single-machine fixture would stay green while the first two-machine
    /// A2 broke in the field. The defect was invisible in exactly this kind
    /// of test environment, so the pin lives here.
    #[test]
    fn double_floor_same_roster_state_yields_the_same_projection_digest() {
        use household_rs::machine_roster_evidence::RosterEvidenceSnapshot;

        let base = RosterEvidenceSnapshot {
            hh_id: household_rs::ids::HouseholdId("hh-test".to_string()),
            state_kind: 1,
            floor_secs: 1_000,
            genesis_checkpoint: Some(vec![0xAA; 64]),
            accepted_checkpoint: Some(vec![0xBB; 64]),
            predecessor_checkpoint: None,
            conflicting_checkpoint: None,
        };
        let other_floor = RosterEvidenceSnapshot {
            floor_secs: 9_999,
            ..base.clone()
        };

        let digest_a = base
            .state_evidence_digest()
            .expect("floor-less digest computes");
        let digest_b = other_floor
            .state_evidence_digest()
            .expect("floor-less digest computes");
        assert_eq!(
            digest_a, digest_b,
            "the projection digest must not depend on the per-machine clock floor"
        );

        // And the pin names the trap it guards: the with-floor digest DOES
        // move across the same two floors — that asymmetry is why the
        // projection must be floor-less, and why "the digest the route
        // serves" is the wrong choice here.
        let with_floor_a = base
            .full_snapshot_digest()
            .expect("with-floor digest computes");
        let with_floor_b = other_floor
            .full_snapshot_digest()
            .expect("with-floor digest computes");
        assert_ne!(
            with_floor_a, with_floor_b,
            "the with-floor digest moving across floors is exactly the defect being pinned"
        );
    }

    /// Bootstrapped household + strong-tier owner cert, mirroring the roster
    /// currency fixture (the coordinator accepts only a strong tier with
    /// verified provenance).
    struct Fx {
        state_dir: tempfile::TempDir,
        record: household_rs::HouseholdRecord,
        auth: std::sync::Arc<household_rs::HouseholdAuthState>,
        m_id: household_rs::ids::MachineId,
    }

    fn fixture() -> Fx {
        let state_dir = tempfile::tempdir().expect("household state");
        let identity = household_rs::bootstrap_or_load(
            state_dir.path(),
            household_rs::BootstrapOpts {
                household_name: "S2 Adapter Home".into(),
                hostname_label: Some("mac-alpha".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap");
        let owner = household_rs::P256Keypair::generate();
        use household_rs::keys::IdentityKey as _;
        let cert = household_rs::PersonCert::sign_owner_with_verified_provenance(
            identity
                .hh_priv
                .as_deref()
                .expect("hh_priv present in single-machine household"),
            household_rs::person_cert::SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: owner.public(),
                display_name: "Owner".into(),
                issued_at: identity.record.created_at,
            },
            household_rs::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .expect("owner cert");
        let m_id = identity
            .record
            .members
            .first()
            .expect("one machine")
            .clone();
        let auth = std::sync::Arc::new(household_rs::HouseholdAuthState::new(
            &identity.record,
            cert,
        ));
        Fx {
            state_dir,
            record: identity.record,
            auth,
            m_id,
        }
    }

    /// Fail-closed path 1: a bootstrapped household whose roster was never
    /// provisioned yields NO observation — the adapter must not fabricate.
    #[test]
    fn observe_fails_closed_when_the_roster_was_never_provisioned() {
        let fx = fixture();
        let adapter = OwnerSiteRosterAdapter::new(fx.state_dir.path());
        let err = adapter
            .observe(&fx.record, &fx.auth, &fx.m_id)
            .expect_err("unprovisioned roster must not produce an observation");
        assert!(
            matches!(err, OwnerSiteRosterAdapterError::AuthorityUnavailable(_)),
            "expected AuthorityUnavailable, got: {err:?}"
        );
    }

    /// Fail-closed path 2: a provisioned but genesis-less roster is a
    /// legitimate state and STILL yields no observation.
    #[test]
    fn observe_fails_closed_on_a_provisioned_but_genesis_less_roster() {
        let fx = fixture();
        let coordinator =
            household_rs::machine_roster_store::MachineRosterCoordinator::from_validated_household(
                fx.state_dir.path(),
                &fx.record,
                &fx.auth,
            )
            .expect("coordinator");
        coordinator.provision_no_genesis().expect("provision");

        let adapter = OwnerSiteRosterAdapter::new(fx.state_dir.path());
        let err = adapter
            .observe(&fx.record, &fx.auth, &fx.m_id)
            .expect_err("genesis-less roster must not produce an observation");
        assert!(
            matches!(err, OwnerSiteRosterAdapterError::AuthorityUnavailable(_)),
            "expected AuthorityUnavailable, got: {err:?}"
        );
    }
}
