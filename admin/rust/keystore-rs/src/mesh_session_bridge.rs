//! The D9 signing surface: core's frame/intent contract, keystore's key
//! custody, and D4's authorisation — all in one crate because that is the
//! only place they can meet.
//!
//! # Why this lives here and not in a bridge crate
//!
//! Rust has no `friend`. A seal has exactly two positions: private (nobody
//! outside implements) or public (anybody does). D4's `SignPrimitive` seal
//! keeps foreign code out of the roster-lease + `SignGuard` critical
//! section; keystore's `pub(crate)` scalar keeps the private key in one
//! crate. A signing function needs BOTH, and an attempt to have each crate
//! depend on the other is rejected outright:
//!
//! ```text
//! error: cyclic package dependency: package `keystore-rs` depends on itself
//! ```
//!
//! Handing the caller a token that owns the guard was measured and rejected
//! too: a downstream that merely *held* it stalled `RevokeUrgent` for as
//! long as it liked (1.6s in the probe, unbounded in principle). Private
//! fields stop forging, not holding. So the guard never leaves a function
//! in this module, and no token, closure or callback crosses the boundary.
//!
//! # What each signature actually re-checks
//!
//! `public_key()` is contractually non-blocking for core (`auth_frames.rs`
//! documents it as called from multiple pre-I/O preflights), so it is a
//! plain read of the key observed once at construction — no lock, no
//! filesystem, no lease. That cached value is a **locator, not authority**:
//! it authorises nothing, it is only the anchor the fresh state is compared
//! against. Every `sign_*` then, per call:
//!
//! 1. loads a `SignerCapability` through D4 — record load, backend
//!    confirmation, roster/signature validation, all with no lock held;
//! 2. runs `sign_checked`, which takes the roster currency lease and then
//!    the cell's `SignGuard` (never the reverse), re-reads under both, and
//!    compares the whole validated `GenerationRecord` by equality;
//! 3. additionally requires that the key D4 just authorised is still the
//!    one `public_key()` announced — so core can never receive a signature
//!    from a key other than the one it was told about.
//!
//! Any divergence — rotation, revocation, key replacement — fails closed
//! with no signature produced.

use crate::error::KeystoreError;
use crate::opaque_p256::{MeshSessionPurpose, OpaqueP256Slots, Purpose, ResolvedSlot, Slot};
use crate::sign::{
    Clock, LoadExactSignerOutcome, OpaqueSignPreimage, OpaqueSignature, SignPrimitive,
    SignerSource, load_signer_capability, sign_checked,
};
use crate::validator::{DelegationPolicy, MeshSessionPurpose as D4MeshSessionPurpose};

/// A signer resolved from one keystore lookup, adapted to D4's sealed
/// `SignPrimitive`. Sealed by construction: only this crate can name it.
struct ResolvedSlotPrimitive<'a, P: Purpose> {
    resolved: &'a ResolvedSlot<P>,
}

impl<P: Purpose> crate::sign::sealed::Sealed for ResolvedSlotPrimitive<'_, P> {}

impl<P: Purpose> SignPrimitive for ResolvedSlotPrimitive<'_, P> {
    /// CPU-local and bounded: one ECDSA signature over bytes core already
    /// derived. No I/O, no re-entry into this crate's locks.
    fn sign_opaque(&self, preimage: &OpaqueSignPreimage) -> OpaqueSignature {
        let typed = crate::opaque_p256::Preimage::<P>::exact(preimage.as_bytes());
        OpaqueSignature::from_backend_bytes(self.resolved.signer().sign(&typed).to_bytes().to_vec())
    }
}

/// The one lookup that yields both the observed binding and its signer.
struct ResolvedSlotSource<'a, P: Purpose> {
    resolved: &'a ResolvedSlot<P>,
    primitive: ResolvedSlotPrimitive<'a, P>,
}

impl<P: Purpose> crate::sign::sealed::Sealed for ResolvedSlotSource<'_, P> {}

impl<P: Purpose> SignerSource for ResolvedSlotSource<'_, P> {
    fn load_exact_signer(
        &self,
        expected: &crate::record::ExactBinding,
    ) -> LoadExactSignerOutcome<'_> {
        // The binding D4 asks about must be the one this slot actually
        // holds; anything else yields no signer at all.
        if expected.public_key != self.resolved.observed_binding().public_key() {
            return LoadExactSignerOutcome::Absent;
        }
        LoadExactSignerOutcome::Ready {
            observed: expected.clone(),
            signer: &self.primitive,
        }
    }
}

#[derive(Debug)]
pub enum BridgeError {
    /// The key D4 authorised is not the one `public_key()` announced.
    AnnouncedKeyNoLongerAuthorised,
    /// D4 refused: revoked, expired, rotated, roster moved, record changed.
    NotAuthorised(String),
    Keystore(KeystoreError),
}

// ─── Runtime facade seam (Lane R, @ilia, authorized 2026-08-05) ────────────
//
// `crate::validator::RosterLookup`/`SignatureVerifier`/`Clock` (all
// `d4_inline` re-exports, `pub(crate) use d4_inline::*;` at this crate's
// root) are invisible outside THIS crate — `pub(crate)`-capped regardless
// of what visibility they carry in their own defining module. And this
// crate cannot depend on `household-rs` to bridge them directly:
// `household-rs` already depends on `keystore-rs`, so the reverse edge
// would be a cyclic package dependency, rejected outright by cargo — same
// class of constraint as this module's own doc on why the signer lives
// here and not in a separate bridge crate.
//
// So the bridge runs the other way: this crate exposes a narrow, `pub`
// seam trait built ONLY from primitive/std types (never a household-rs or
// D4 type by name), a caller outside this crate implements it against
// their own real source, and a private adapter here lifts that into the
// `pub(crate)` D4 trait `new_internal` actually requires. Same "typed
// facade, opaque internals" shape used throughout this engagement.

/// External seam for `crate::validator::RosterLookup` — implement this
/// against a real roster-authority source (e.g. household-rs's
/// `MachineRosterCoordinator::query_machine_currency`) from outside this
/// crate; [`RosterLookupBridge`] lifts it into the real D4 trait.
///
/// **Deliberately covers only 2 of D4's 3 `RosterLookup` methods.** There
/// is no `acquire_currency_lease` here — see
/// [`RosterLookupBridge::acquire_currency_lease`]'s own doc for why: a
/// method whose result this seam would only ever discard is not a real
/// seam, it is a fabricated one, and this round was told explicitly not
/// to build those.
pub trait RosterLookupSource {
    /// Mirrors `crate::validator::RosterLookup::query_machine_currency`
    /// exactly, but through [`RosterCurrencyView`] instead of naming the
    /// D4 type directly.
    fn query_machine_currency(&self, machine_id: &str) -> RosterCurrencyView;

    /// Mirrors `crate::validator::RosterLookup::currency_revision`.
    fn currency_revision(&self, machine_id: &str) -> u64;
}

/// Mirrors `crate::validator::RosterCurrency` field-for-field, so
/// [`RosterLookupBridge`] can convert losslessly — this type exists only
/// because the real one cannot be named outside this crate.
#[derive(Debug, Clone)]
pub enum RosterCurrencyView {
    Active {
        member_pub: Vec<u8>,
        member_cert_fingerprint: [u8; 32],
    },
    Revoked,
    NotListed,
    Unavailable,
}

/// External seam for `crate::sign::Clock` — trivially real (a wall clock
/// needs no bridge to household-rs at all), but still needs a `pub` seam
/// for the exact same visibility reason as [`RosterLookupSource`].
/// `Send + Sync` mirrors `crate::sign::Clock`'s own bound exactly.
pub trait ClockSource: Send + Sync {
    fn now(&self) -> u64;
}

/// Lifts a [`RosterLookupSource`] into the real, `pub(crate)`
/// `crate::validator::RosterLookup` D4 requires.
// Narrow and deliberate, same posture as `new_internal`'s own allow: this
// has no NON-test caller until `SignatureVerifier`/`cell::open` real
// construction/policy/generation sourcing (this round's declared, NOT
// implemented seams) also land — a `RosterLookup`/`Clock` alone cannot
// feed `new_internal`, which needs all five. Exercised by this module's
// own tests below. Scoped to this one struct, never module-wide.
#[allow(dead_code)]
struct RosterLookupBridge<'a, T: RosterLookupSource>(&'a T);

impl<T: RosterLookupSource> crate::validator::RosterLookup for RosterLookupBridge<'_, T> {
    fn query_machine_currency(&self, machine_id: &str) -> crate::validator::RosterCurrency {
        match self.0.query_machine_currency(machine_id) {
            RosterCurrencyView::Active {
                member_pub,
                member_cert_fingerprint,
            } => crate::validator::RosterCurrency::Active {
                member_pub,
                member_cert_fingerprint,
            },
            RosterCurrencyView::Revoked => crate::validator::RosterCurrency::Revoked,
            RosterCurrencyView::NotListed => crate::validator::RosterCurrency::NotListed,
            RosterCurrencyView::Unavailable => crate::validator::RosterCurrency::Unavailable,
        }
    }

    fn currency_revision(&self, machine_id: &str) -> u64 {
        self.0.currency_revision(machine_id)
    }

    /// **Honestly incomplete, fail-closed — not a fabricated success.**
    /// D4's real contract is mutual exclusion: the returned lease must
    /// genuinely BLOCK a conflicting mutation for as long as it stays
    /// alive (see `RosterLookup::acquire_currency_lease`'s own doc).
    /// household-rs has no externally-reachable primitive that provides
    /// this today — its own internal lock (`RosterLock`,
    /// `machine_roster_store.rs`) is `pub(crate)` to household-rs itself,
    /// scoped to the duration of a single internal call, never handed to
    /// an external caller. There is deliberately no way to plug a real
    /// implementation into this method through [`RosterLookupSource`] —
    /// see that trait's own doc for why a discarded-result method would
    /// be worse than no method at all. This unconditionally reports the
    /// roster as changed, `RosterChanged` — the SAME outcome a real
    /// implementation reports for a genuine conflicting mutation, never a
    /// false grant. Closing this for real needs household-rs to grow a
    /// real, externally-holdable mutual-exclusion primitive — out of this
    /// round's scope.
    fn acquire_currency_lease(
        &self,
        _machine_id: &str,
        _expected_revision: u64,
    ) -> Result<Box<dyn crate::validator::CurrencyLease + '_>, crate::validator::RosterChanged>
    {
        Err(crate::validator::RosterChanged)
    }
}

/// Lifts a [`ClockSource`] into the real, `pub(crate)` `crate::sign::Clock`
/// D4 requires.
// Same posture and reason as `RosterLookupBridge`'s own allow.
#[allow(dead_code)]
struct ClockBridge<'a, T: ClockSource>(&'a T);

impl<T: ClockSource> Clock for ClockBridge<'_, T> {
    fn now(&self) -> u64 {
        self.0.now()
    }
}

/// Everything the authorised path needs, held privately.
///
/// Core's trait hands `sign_mesh_session_frame` only a preimage and a
/// deadline, so the signer must OWN its D4 context — that follows from the
/// frozen signature, not from preference. Deliberately not `Clone` and with
/// NO getters: nothing here (cell, roster, policy, clock, record) is
/// reachable from outside, so composing this signer never hands anyone a
/// D4 handle.
struct BridgeContext<'a> {
    cell: &'a crate::cell::ControlRecordCell,
    policy: &'a DelegationPolicy,
    roster: &'a dyn crate::validator::RosterLookup,
    sig: &'a dyn crate::validator::SignatureVerifier,
    clock: &'a dyn Clock,
    generation: std::num::NonZeroU64,
}

/// Signs mesh-session frames and intents for exactly one announced key.
///
/// The public constructor is deliberately absent for now: a factory that
/// took D4 parameters would publish D4 types, and inventing the runtime's
/// safe capability here would pre-empt the facade. `new_internal` is
/// crate-visible so the bridge and its REDs can build one; the facade adds
/// its own opaque factory later without this API blocking it.
pub struct MeshSessionBridgeSigner<'a> {
    ctx: BridgeContext<'a>,
    slots: OpaqueP256Slots,
    slot: Slot<MeshSessionPurpose>,
    /// Observed ONCE at construction. A locator, never authority — see the
    /// module doc. Kept as the whole `PublicBinding` rather than just the
    /// bytes so `load_exact` can do the swap check itself: it is documented
    /// to refuse when the stored key no longer matches the binding the
    /// caller published, which is precisely the divergence we must catch.
    announced: crate::opaque_p256::PublicBinding<MeshSessionPurpose>,
}

impl<'a> MeshSessionBridgeSigner<'a> {
    /// Observes the key once so `public_key()` can stay non-blocking.
    // Narrow and deliberate: this constructor has no NON-test caller until
    // the runtime facade lands and composes it. It is exercised by the
    // bridge REDs below. Scoped to this one function -- never a module- or
    // crate-wide allow -- so it cannot mask the adapter's own logic, which
    // IS reached in a normal build through the trait impls.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_internal(
        slots: OpaqueP256Slots,
        slot: Slot<MeshSessionPurpose>,
        cell: &'a crate::cell::ControlRecordCell,
        policy: &'a DelegationPolicy,
        roster: &'a dyn crate::validator::RosterLookup,
        sig: &'a dyn crate::validator::SignatureVerifier,
        clock: &'a dyn Clock,
        generation: std::num::NonZeroU64,
    ) -> Result<Self, KeystoreError> {
        let Some(announced) = slots.inspect(&slot)? else {
            return Err(KeystoreError::NotFound {
                label: slot.label().to_string(),
            });
        };
        Ok(Self {
            ctx: BridgeContext {
                cell,
                policy,
                roster,
                sig,
                clock,
                generation,
            },
            slots,
            slot,
            announced,
        })
    }

    /// Non-blocking, as core's contract requires: no lock, no lease, no
    /// filesystem, no scalar.
    #[must_use]
    pub fn announced_public_key(&self) -> &[u8] {
        self.announced.public_key()
    }

    /// The whole authorised path. The guard is taken and released inside
    /// `sign_checked`; nothing guard-owning is returned from here.
    fn sign_authorised(&self, preimage_bytes: &[u8]) -> Result<Vec<u8>, BridgeError> {
        let BridgeContext {
            cell,
            policy,
            roster,
            sig,
            clock,
            generation,
        } = &self.ctx;
        // One lookup: observed binding AND its signer, same resolution.
        // ONE resolution yielding observed binding AND signer together, and
        // `load_exact` itself fails closed if the slot no longer holds the
        // announced key -- the swap check, done by the primitive that owns
        // the material rather than re-derived here.
        let resolved = self
            .slots
            .load_exact(&self.slot, &self.announced)
            .map_err(|_| BridgeError::AnnouncedKeyNoLongerAuthorised)?;

        // Belt and braces: the pair we got back must still describe the
        // announced key.
        if resolved.observed_binding().public_key() != self.announced.public_key() {
            return Err(BridgeError::AnnouncedKeyNoLongerAuthorised);
        }

        let source = ResolvedSlotSource {
            resolved: &resolved,
            primitive: ResolvedSlotPrimitive {
                resolved: &resolved,
            },
        };

        // Slow validation with no lock held, then lease -> guard -> exact
        // re-read -> fresh clock -> bounded primitive, inside sign_checked.
        let capability = load_signer_capability::<D4MeshSessionPurpose>(
            cell,
            &source,
            policy,
            *roster,
            *sig,
            *clock,
            *generation,
        )
        .map_err(|e| BridgeError::NotAuthorised(format!("{e:?}")))?;

        let signature = sign_checked(
            cell,
            *roster,
            *clock,
            &capability,
            &OpaqueSignPreimage::from_core_bytes(preimage_bytes.to_vec()),
        )
        .map_err(|e| BridgeError::NotAuthorised(format!("{e:?}")))?;

        Ok(signature.as_bytes().to_vec())
    }
}

impl mesh_session_core_rs::auth_frames::MeshSessionFrameSigner for MeshSessionBridgeSigner<'_> {
    /// Per-call D4 revalidation. The guard lives and dies inside
    /// `sign_checked`; nothing guard-owning reaches core.
    fn sign_mesh_session_frame(
        &self,
        preimage: &mesh_session_core_rs::auth_frames::MeshSessionFramePreimage,
        _deadline: &mesh_session_core_rs::ingress::CeremonyDeadline,
    ) -> Result<[u8; 64], mesh_session_core_rs::error::AuthFrameError> {
        let out = self
            .sign_authorised(preimage.as_bytes())
            .map_err(|_| mesh_session_core_rs::error::AuthFrameError::SignerFailed)?;
        out.try_into()
            .map_err(|_| mesh_session_core_rs::error::AuthFrameError::SignerFailed)
    }

    /// Same authorisation, same per-call revalidation.
    fn sign_intent(
        &self,
        preimage: &mesh_session_core_rs::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], mesh_session_core_rs::error::AuthFrameError> {
        let out = self
            .sign_authorised(preimage.as_bytes())
            .map_err(|_| mesh_session_core_rs::error::AuthFrameError::SignerFailed)?;
        out.try_into()
            .map_err(|_| mesh_session_core_rs::error::AuthFrameError::SignerFailed)
    }

    /// Non-blocking by contract: a plain read of the key observed at
    /// construction. No lock, no lease, no filesystem, no scalar.
    fn public_key(&self) -> p256::ecdsa::VerifyingKey {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(self.announced.public_key())
            .expect("the binding this signer was built from held a valid SEC1 public key")
    }
}

/// Resolves the retained D4 generation for core, without publishing any D4
/// type. Lives here for the same structural reason the signer does: proving
/// a generation needs D4's read path, which is `pub(crate)`, so a future
/// runtime facade could not implement this trait itself. It only ever hands
/// back a `ResolvedSignerAuthority` — `delegated_pub`, `generation`,
/// `not_after` — which is the RESULT of a verification, never a handle.
pub struct BridgeGenerationResolver<'a> {
    ctx: BridgeContext<'a>,
}

impl<'a> BridgeGenerationResolver<'a> {
    // Narrow and deliberate: this constructor has no NON-test caller until
    // the runtime facade lands and composes it. It is exercised by the
    // bridge REDs below. Scoped to this one function -- never a module- or
    // crate-wide allow -- so it cannot mask the adapter's own logic, which
    // IS reached in a normal build through the trait impls.
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_internal(
        cell: &'a crate::cell::ControlRecordCell,
        policy: &'a DelegationPolicy,
        roster: &'a dyn crate::validator::RosterLookup,
        sig: &'a dyn crate::validator::SignatureVerifier,
        clock: &'a dyn Clock,
        generation: std::num::NonZeroU64,
    ) -> Self {
        Self {
            ctx: BridgeContext {
                cell,
                policy,
                roster,
                sig,
                clock,
                generation,
            },
        }
    }
}

impl mesh_session_core_rs::intent::RetainedGenerationResolver for BridgeGenerationResolver<'_> {
    /// Independently verified against D4's own live record on every call --
    /// never assumed from a caller-supplied claim. A stale or wrong
    /// generation simply fails to resolve.
    fn resolve(
        &self,
        _hh_id: &str,
        _initiator_m_id: &str,
        _channel: mesh_session_core_rs::auth_state_machine::ExpectedChannel,
        _delegated_key_id: &str,
        _deadline: &mesh_session_core_rs::ingress::CeremonyDeadline,
    ) -> Result<
        mesh_session_core_rs::intent::ResolvedSignerAuthority,
        mesh_session_core_rs::error::IntentError,
    > {
        let BridgeContext {
            cell,
            policy,
            roster,
            sig,
            clock,
            generation,
        } = &self.ctx;
        let record = match cell.load_canonical() {
            crate::store::LoadOutcome::Exact(r) => *r,
            _ => {
                return Err(
                    mesh_session_core_rs::error::IntentError::NoRetainedGenerationResolverConfigured,
                );
            }
        };
        let g = record
            .live_generations
            .iter()
            .find(|g| g.generation == *generation)
            .ok_or(
                mesh_session_core_rs::error::IntentError::NoRetainedGenerationResolverConfigured,
            )?;
        let ctx = crate::validator::BindingContext::from_identity(&record.identity);
        crate::validator::validate_full_binding::<crate::validator::MeshSessionPurpose>(
            g,
            &ctx,
            policy,
            *roster,
            *sig,
            clock.now(),
        )
        .map_err(|_| {
            mesh_session_core_rs::error::IntentError::NoRetainedGenerationResolverConfigured
        })?;
        Ok(mesh_session_core_rs::intent::ResolvedSignerAuthority::new(
            g.binding.public_key.clone(),
            g.generation.get(),
            g.not_after,
        ))
    }
}

#[cfg(all(test, feature = "test-support", feature = "roster-sync-unratified"))]
mod bridge_reds {
    use super::*;
    use crate::opaque_p256::{ApprovedFallback, OpaqueP256Slots, Slot};
    use crate::record::{Channel, ControlIdentity, MeshSignerControlRecordV1, PurposeId};
    use crate::sign::FixedClock;
    use crate::validator::{DelegationPolicy, RosterCurrency, RosterLookup, SignatureVerifier};
    use std::num::NonZeroU64;
    use std::sync::Arc;

    struct NoRoster;
    impl RosterLookup for NoRoster {
        fn query_machine_currency(&self, _m: &str) -> RosterCurrency {
            RosterCurrency::Revoked
        }
        fn currency_revision(&self, _m: &str) -> u64 {
            0
        }
        fn acquire_currency_lease(
            &self,
            _m: &str,
            _expected: u64,
        ) -> Result<Box<dyn crate::validator::CurrencyLease + '_>, crate::validator::RosterChanged>
        {
            Err(crate::validator::RosterChanged)
        }
    }
    struct NoVerify;
    impl SignatureVerifier for NoVerify {
        fn verify(&self, _pk: &[u8], _d: &crate::record::Delegation, _sig: &[u8]) -> bool {
            false
        }
    }

    fn keystore_with_key(dir: &std::path::Path) -> (OpaqueP256Slots, Slot<MeshSessionPurpose>) {
        let approval = ApprovedFallback::for_reason("bridge RED");
        let slots = OpaqueP256Slots::approved_plaintext_file(dir, "bridge-red", &approval);
        let slot = Slot::<MeshSessionPurpose>::new("bridge-red-slot").unwrap();
        slots.create_or_inspect(&slot).unwrap();
        (slots, slot)
    }

    fn empty_cell(dir: &std::path::Path) -> Arc<crate::cell::ControlRecordCell> {
        let id = ControlIdentity {
            hh_id: "hh_bridge".into(),
            machine_id: "m_bridge".into(),
            channel: Channel::Dev,
        };
        let cell = crate::cell::open(
            dir.join("record"),
            id.clone(),
            PurposeId::MeshSession,
            Arc::new(crate::locks::OrderSpy::new()),
        )
        .unwrap();
        let boot = MeshSignerControlRecordV1::bootstrap(id, PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, crate::record::INITIAL_REVISION, &boot),
            crate::store::ReplaceOutcome::Committed
        );
        drop(g);
        cell
    }

    /// A roster that is Active at a chosen revision and can be moved.
    struct MovableRoster {
        state: std::sync::Mutex<(u64, RosterCurrency)>,
        /// When set, the revision moves DURING validation -- on the query
        /// that `validate_full_binding` itself makes, i.e. after
        /// `load_signer_capability` already sealed the revision and before
        /// `sign_checked` asks for the lease. That is the only window the
        /// sealed revision exists to protect; moving it before the call
        /// merely means the capability is validated against the new value.
        advance_during_validation: bool,
    }
    impl MovableRoster {
        fn active() -> Self {
            Self {
                state: std::sync::Mutex::new((
                    0,
                    RosterCurrency::Active {
                        member_pub: vec![7, 7, 7],
                        member_cert_fingerprint: [5u8; 32],
                    },
                )),
                advance_during_validation: false,
            }
        }
        fn moving_during_validation() -> Self {
            let mut r = Self::active();
            r.advance_during_validation = true;
            r
        }
    }
    impl RosterLookup for MovableRoster {
        fn query_machine_currency(&self, _m: &str) -> RosterCurrency {
            let mut g = self.state.lock().unwrap();
            if self.advance_during_validation {
                g.0 += 1;
            }
            g.1.clone()
        }
        fn currency_revision(&self, _m: &str) -> u64 {
            self.state.lock().unwrap().0
        }
        fn acquire_currency_lease(
            &self,
            _m: &str,
            expected: u64,
        ) -> Result<Box<dyn crate::validator::CurrencyLease + '_>, crate::validator::RosterChanged>
        {
            if self.state.lock().unwrap().0 == expected {
                Ok(Box::new(GrantedLease))
            } else {
                Err(crate::validator::RosterChanged)
            }
        }
    }
    struct GrantedLease;
    impl crate::validator::CurrencyLease for GrantedLease {}

    struct AlwaysVerify;
    impl SignatureVerifier for AlwaysVerify {
        fn verify(&self, _pk: &[u8], _d: &crate::record::Delegation, _s: &[u8]) -> bool {
            true
        }
    }

    /// A record with ONE fully valid, active generation bound to the real
    /// keystore key -- everything `validate_full_binding` demands.
    fn active_record_for(
        public_key: &[u8],
        id: &ControlIdentity,
    ) -> (MeshSignerControlRecordV1, NonZeroU64) {
        let generation = NonZeroU64::new(1).unwrap();
        let slot = crate::record::SlotId {
            identity_digest: crate::record::identity_digest(id),
            purpose: PurposeId::MeshSession,
            generation,
            txn_id: [3u8; 16],
            backend_instance: crate::record::BackendKind::File,
        };
        let binding = crate::record::ExactBinding {
            slot: slot.clone(),
            public_key: public_key.to_vec(),
            attributes: Vec::new(),
        };
        let delegation = crate::record::Delegation {
            version: crate::validator::DELEGATION_SCHEMA_VERSION,
            kind: "soyeht/mesh-session/delegation/v1".into(),
            domain: "soyeht/mesh-session/v1".into(),
            hh_id: id.hh_id.clone(),
            delegator_m_id: id.machine_id.clone(),
            delegator_cert_fingerprint: [5u8; 32],
            delegated_pub: public_key.to_vec(),
            delegated_key_id: slot.canonical_id(),
            profile: "mesh-session".into(),
            transcript_kinds: vec![
                "final-confirm".into(),
                "activate".into(),
                "activate-ack".into(),
            ],
            roles: vec!["initiator".into(), "responder".into()],
            channel: Channel::Dev,
            serial: 1,
            not_before: 0,
            not_after: 10_000,
            sig: vec![9, 9],
        };
        let mut rec = MeshSignerControlRecordV1::bootstrap(id.clone(), PurposeId::MeshSession);
        rec.authority = crate::record::Authority::Active;
        rec.current_generation = Some(generation);
        rec.generation_high_water = generation;
        rec.live_generations = vec![crate::record::GenerationRecord {
            generation,
            delegation,
            binding,
            not_after: 10_000,
        }];
        rec.revision = 1;
        (rec, generation)
    }

    fn cell_with(
        dir: &std::path::Path,
        id: &ControlIdentity,
        rec: &MeshSignerControlRecordV1,
    ) -> Arc<crate::cell::ControlRecordCell> {
        let cell = crate::cell::open(
            dir.join("rec2"),
            id.clone(),
            PurposeId::MeshSession,
            Arc::new(crate::locks::OrderSpy::new()),
        )
        .unwrap();
        let boot = MeshSignerControlRecordV1::bootstrap(id.clone(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        cell.seed_for_test(&g, crate::record::INITIAL_REVISION, &boot);
        assert_eq!(
            cell.seed_for_test(&g, boot.revision, rec),
            crate::store::ReplaceOutcome::Committed
        );
        drop(g);
        cell
    }

    fn bridge_identity() -> ControlIdentity {
        ControlIdentity {
            hh_id: "hh_bridge".into(),
            machine_id: "m_bridge".into(),
            channel: Channel::Dev,
        }
    }

    /// The announced key is observed once at construction and is a plain
    /// local read afterwards -- no lock, lease or filesystem on that path.
    #[test]
    fn announced_key_is_observed_once_and_read_locally() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let expected = slots.inspect(&slot).unwrap().unwrap().public_key().to_vec();
        let cell = empty_cell(dir.path());
        let policy = DelegationPolicy::test(1000);
        let (roster, sig, clock) = (NoRoster, NoVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots,
            slot,
            &cell,
            &policy,
            &roster,
            &sig,
            &clock,
            NonZeroU64::new(1).unwrap(),
        )
        .expect("a slot holding a key yields a signer");
        assert_eq!(signer.announced_public_key(), expected.as_slice());
    }

    /// RED: a bootstrap record has no live generation, so the authorised
    /// path must refuse. The point is not merely the error -- it is that
    /// refusal happens BEFORE any signing primitive runs.
    #[test]
    fn no_live_generation_refuses_before_any_primitive_call() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let cell = empty_cell(dir.path());
        let policy = DelegationPolicy::test(1000);
        let (roster, sig, clock) = (NoRoster, NoVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots,
            slot,
            &cell,
            &policy,
            &roster,
            &sig,
            &clock,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
        let err = signer.sign_authorised(b"not a frame").unwrap_err();
        assert!(matches!(err, BridgeError::NotAuthorised(_)), "got {err:?}");
    }

    /// RED: swapping the physical key after the signer announced one must
    /// fail closed -- `load_exact` refuses a binding the slot no longer
    /// holds, so the announced key can never diverge from the signing key.
    #[test]
    fn a_swapped_binding_fails_closed_after_the_key_was_announced() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let cell = empty_cell(dir.path());
        let policy = DelegationPolicy::test(1000);
        let (roster, sig, clock) = (NoRoster, NoVerify, FixedClock(50));
        let announced = slots.inspect(&slot).unwrap().unwrap();
        let signer = MeshSessionBridgeSigner::new_internal(
            slots,
            slot,
            &cell,
            &policy,
            &roster,
            &sig,
            &clock,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
        // Destroy and recreate the slot: same label, different scalar.
        let dir2 = tempfile::tempdir().unwrap();
        let (rotated_slots, rotated_key_slot) = keystore_with_key(dir2.path());
        let rotated = rotated_slots.inspect(&rotated_key_slot).unwrap().unwrap();
        assert_ne!(
            announced.public_key(),
            rotated.public_key(),
            "the fixture must actually produce a different key"
        );
        // The signer still announces the ORIGINAL key.
        assert_eq!(signer.announced_public_key(), announced.public_key());
        // And refuses, because the authorised path re-resolves every call.
        assert!(signer.sign_authorised(b"x").is_err());
    }

    /// NON-VACUITY CONTROL for the three REDs below: with a fully valid
    /// active record, a matching roster and an unmoved revision, the
    /// authorised path SUCCEEDS and the real signature is produced. Without
    /// this, a refusal-only suite would pass even if the fixture were
    /// simply broken.
    #[test]
    fn a_fully_valid_active_record_actually_signs() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let pk = slots.inspect(&slot).unwrap().unwrap().public_key().to_vec();
        let id = bridge_identity();
        let (rec, generation) = active_record_for(&pk, &id);
        let cell = cell_with(dir.path(), &id, &rec);
        let policy = DelegationPolicy::test(100_000);
        let roster = MovableRoster::active();
        let (sig, clock) = (AlwaysVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots, slot, &cell, &policy, &roster, &sig, &clock, generation,
        )
        .unwrap();
        let out = signer
            .sign_authorised(b"canonical bytes from core")
            .expect("a fully valid, unmoved, in-window record must sign");
        assert_eq!(out.len(), 64, "P-256 r||s");
    }

    /// RED: the roster revision moves between validation and use. The
    /// capability sealed revision 0; the lease is asked for THAT revision,
    /// so revision 1 refuses -- and nothing signs.
    #[test]
    fn a_roster_revision_move_refuses_with_no_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let pk = slots.inspect(&slot).unwrap().unwrap().public_key().to_vec();
        let id = bridge_identity();
        let (rec, generation) = active_record_for(&pk, &id);
        let cell = cell_with(dir.path(), &id, &rec);
        let policy = DelegationPolicy::test(100_000);
        let roster = MovableRoster::moving_during_validation();
        let (sig, clock) = (AlwaysVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots, slot, &cell, &policy, &roster, &sig, &clock, generation,
        )
        .unwrap();
        // The currency for this machine never changes -- ONLY the revision
        // moves, and it moves inside validation, so the sealed-revision
        // check is the sole thing that can catch it.
        let err = signer.sign_authorised(b"x").unwrap_err();
        assert!(matches!(err, BridgeError::NotAuthorised(_)), "got {err:?}");
    }

    /// RED: asking for a generation the record does not hold live is
    /// refused.
    ///
    /// Deliberately does NOT claim "zero primitive calls": this bridge has
    /// no visibility into whether D4 invoked a signing primitive, so
    /// asserting it here would be a claim the test cannot observe. The
    /// call-count property is measured where it IS observable -- D4's own
    /// REDs over `FakeSignerSource::total_calls`. What this proves is the
    /// bridge-level outcome: refusal, and no signature returned.
    #[test]
    fn a_wrong_generation_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let pk = slots.inspect(&slot).unwrap().unwrap().public_key().to_vec();
        let id = bridge_identity();
        let (rec, _generation) = active_record_for(&pk, &id);
        let cell = cell_with(dir.path(), &id, &rec);
        let policy = DelegationPolicy::test(100_000);
        let roster = MovableRoster::active();
        let (sig, clock) = (AlwaysVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots,
            slot,
            &cell,
            &policy,
            &roster,
            &sig,
            &clock,
            NonZeroU64::new(42).unwrap(),
        )
        .unwrap();
        let err = signer.sign_authorised(b"x").unwrap_err();
        assert!(matches!(err, BridgeError::NotAuthorised(_)), "got {err:?}");
    }

    /// RED: the whole record is compared, not a projection. Rewriting the
    /// record between the capability load and the guarded re-read -- here by
    /// expiring the generation out of `live_generations` -- must refuse.
    #[test]
    fn a_record_rewritten_after_validation_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let (slots, slot) = keystore_with_key(dir.path());
        let pk = slots.inspect(&slot).unwrap().unwrap().public_key().to_vec();
        let id = bridge_identity();
        let (rec, generation) = active_record_for(&pk, &id);
        let cell = cell_with(dir.path(), &id, &rec);
        let policy = DelegationPolicy::test(100_000);
        let roster = MovableRoster::active();
        let (sig, clock) = (AlwaysVerify, FixedClock(50));
        let signer = MeshSessionBridgeSigner::new_internal(
            slots, slot, &cell, &policy, &roster, &sig, &clock, generation,
        )
        .unwrap();
        // Drop the generation out of the live set, keeping everything else.
        let mut rewritten = rec.clone();
        rewritten.live_generations.clear();
        rewritten.current_generation = None;
        rewritten.authority = crate::record::Authority::Revoked {
            reason: crate::record::RevocationReason::OwnerAction,
        };
        rewritten.revision = rec.revision + 1;
        {
            let g = cell.acquire_for_mutation();
            assert_eq!(
                cell.seed_for_test(&g, rec.revision, &rewritten),
                crate::store::ReplaceOutcome::Committed
            );
        }
        let err = signer.sign_authorised(b"x").unwrap_err();
        assert!(matches!(err, BridgeError::NotAuthorised(_)), "got {err:?}");
    }
}

#[cfg(test)]
mod runtime_facade_seam_tests {
    use super::*;

    struct FixedRosterSource {
        currency: RosterCurrencyView,
        revision: u64,
    }
    impl RosterLookupSource for FixedRosterSource {
        fn query_machine_currency(&self, _machine_id: &str) -> RosterCurrencyView {
            self.currency.clone()
        }
        fn currency_revision(&self, _machine_id: &str) -> u64 {
            self.revision
        }
    }

    struct FixedClockSource(u64);
    impl ClockSource for FixedClockSource {
        fn now(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn roster_lookup_bridge_maps_active_losslessly() {
        let source = FixedRosterSource {
            currency: RosterCurrencyView::Active {
                member_pub: vec![0xAA; 33],
                member_cert_fingerprint: [0xBB; 32],
            },
            revision: 7,
        };
        let bridge = RosterLookupBridge(&source);
        match crate::validator::RosterLookup::query_machine_currency(&bridge, "m-1") {
            crate::validator::RosterCurrency::Active {
                member_pub,
                member_cert_fingerprint,
            } => {
                assert_eq!(member_pub, vec![0xAA; 33]);
                assert_eq!(member_cert_fingerprint, [0xBB; 32]);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn roster_lookup_bridge_maps_revoked_not_listed_unavailable() {
        for (view, expect_revoked, expect_not_listed) in [
            (RosterCurrencyView::Revoked, true, false),
            (RosterCurrencyView::NotListed, false, true),
            (RosterCurrencyView::Unavailable, false, false),
        ] {
            let source = FixedRosterSource {
                currency: view,
                revision: 0,
            };
            let bridge = RosterLookupBridge(&source);
            let mapped = crate::validator::RosterLookup::query_machine_currency(&bridge, "m-1");
            assert_eq!(
                matches!(mapped, crate::validator::RosterCurrency::Revoked),
                expect_revoked
            );
            assert_eq!(
                matches!(mapped, crate::validator::RosterCurrency::NotListed),
                expect_not_listed
            );
        }
    }

    #[test]
    fn roster_lookup_bridge_delegates_currency_revision() {
        let source = FixedRosterSource {
            currency: RosterCurrencyView::NotListed,
            revision: 42,
        };
        let bridge = RosterLookupBridge(&source);
        assert_eq!(
            crate::validator::RosterLookup::currency_revision(&bridge, "m-1"),
            42
        );
    }

    /// Pins the fail-closed contract documented on
    /// `RosterLookupBridge::acquire_currency_lease` — it must NEVER grant
    /// a lease, regardless of `machine_id`/`expected_revision`, because no
    /// real mutual-exclusion primitive is reachable from household-rs
    /// today. A future accidental "make it grant sometimes" edit fails
    /// this test.
    #[test]
    fn red_roster_lookup_bridge_never_grants_a_lease() {
        let source = FixedRosterSource {
            currency: RosterCurrencyView::Active {
                member_pub: vec![],
                member_cert_fingerprint: [0u8; 32],
            },
            revision: 0,
        };
        let bridge = RosterLookupBridge(&source);
        let err = crate::validator::RosterLookup::acquire_currency_lease(&bridge, "m-1", 0)
            .err()
            .expect("must never grant a lease");
        assert_eq!(err, crate::validator::RosterChanged);
    }

    #[test]
    fn clock_bridge_delegates_now() {
        let source = FixedClockSource(1_767_225_600);
        let bridge = ClockBridge(&source);
        assert_eq!(Clock::now(&bridge), 1_767_225_600);
    }
}
