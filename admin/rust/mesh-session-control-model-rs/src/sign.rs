//! Round 6, wave 9: the typed, sealed signing operation that replaces
//! `activate::with_authorized_use`.
//!
//! # Why the closure form is gone
//!
//! Wave 8 exposed `with_authorized_use(cell, .., use_: impl FnOnce(&AuthorizedUse) -> R)`.
//! An independent audit of `6bd957a4` showed it still failed the property it
//! claimed, by three separate mechanisms:
//!
//! - **The authorization was still detachable.** `AuthorizedUse::binding()`
//!   returned `&ExactBinding`, which is `pub` and `Clone`, and the closure
//!   could return any `R`. So `with_authorized_use(.., |a| a.binding().clone())`
//!   compiled and handed a "validated" locator straight out of the locks.
//!   Narrowing the payload from a record to a binding did not fix the shape;
//!   the shape was the bug.
//! - **The authorization was not tied to the signer that would actually be
//!   used.** The closure could ignore its `AuthorizedUse` argument entirely
//!   and sign with a signer it had captured from the surrounding scope. The
//!   gate only ever validated `current_generation`, and never loaded the
//!   epoch at all — so after a rotate or a revoke→reactivate, an old
//!   in-memory signer could sign while the gate happily validated the *new*
//!   current generation. The same defect made the legitimate overlap case
//!   impossible: a signer on an older generation, still live until its
//!   `not_after`, had no way to ask for authorization for *its own*
//!   generation.
//! - **The closure was unbounded and could self-deadlock.** It held the
//!   roster lease and the cell's `SignGuard` for its entire body, so it could
//!   sleep, do unrelated I/O, or capture `cell` and call `cell.commit(..)` —
//!   which asks for `access` exclusive on a thread already holding it shared,
//!   deadlocking itself while holding the writer turnstile.
//!
//! The corrected shape, per the audit's sucessor direction: authorization is
//! bound to a **capability** that names the exact signer, loaded outside the
//! locks and sealed with the exact tuple
//! `(identity, purpose, generation, epoch, slot, binding)`; the operation
//! under the guard is a **single typed method on a sealed trait**, not
//! caller-supplied code.
//!
//! # What is and is not a mechanism here
//!
//! Stated plainly, because this crate has twice shipped a doc comment in
//! place of a control:
//!
//! - **Mechanism.** `SignPrimitive` is sealed: no downstream crate can
//!   implement it, so no foreign code can run inside the critical section.
//!   The primitive receives only an opaque preimage — never the cell, the
//!   record, the guards, or the roster — so it *cannot* re-enter this crate's
//!   locks and cannot self-deadlock. Nothing this operation returns carries
//!   an `ExactBinding`, a record, or the signer.
//! - **Mechanism.** The tuple check under the guard is exact and total: a
//!   mismatch in identity, purpose, authority, epoch, generation, slot or
//!   binding is a hard error before the primitive is ever reached.
//! - **Not a mechanism, and not claimed as one.** This crate cannot force an
//!   arbitrary implementation to return within a time bound. The bound comes
//!   from the seal plus the fact that every implementation that exists is
//!   concrete and internal; `WATCHDOG_BUDGET` *detects* an overrun after the
//!   fact and fails the operation, but cannot preempt one. The production
//!   surface stays closed until the real bridge lands: in a default build no
//!   type implements `SignPrimitive` at all, so `sign_checked` is
//!   unreachable by construction rather than merely discouraged.
//!
//! # The one lock order (see also `activate`'s `AuthorizedUse` history)
//!
//! 1. All slow I/O — `load_canonical`, `backend.load_exact`,
//!    `roster.query_machine_currency`, `sig.verify` — in
//!    `load_signer_capability`, with **no lock of any kind held**.
//! 2. Confirm the loaded tuple's delegator against the pre-lease peek.
//! 3. The roster currency lease, for that **exact** delegator machine.
//! 4. The cell's `SignGuard`.
//! 5. A cheap exact re-read compared field-for-field against the sealed tuple.
//! 6. A **fresh** clock sample, taken under both locks.
//! 7. The bounded, CPU-local signing primitive.
//! 8. Release, in reverse.
//!
//! Never cell → roster.

use crate::cell::ControlRecordCell;
use crate::record::{
    Authority, ControlIdentity, ExactBinding, GenerationRecord, MeshSignerControlRecordV1,
    PurposeId,
};
use crate::store::LoadOutcome;
use crate::validator::{
    BindingContext, DelegationPolicy, PurposeMarker, RosterChanged, RosterLookup,
    SignatureVerifier, ValidationError, validate_full_binding,
};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// Wall-clock source. Round 6, wave 9 (P0-2): the predecessor took a single
/// scalar `now` from the caller, sampled once *before* the slow backend and
/// roster I/O and never re-read. Time is not part of the record, so the
/// "record unchanged" re-read could not detect it: a delegation validated at
/// `not_after - 1` still ran the authorized operation well after
/// `not_after`. The clock is now injected and **re-sampled under both locks,
/// immediately before the primitive runs**.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// The bytes to be signed. This model deliberately does **not** define the
/// B-SESSAO wire preimage — inventing one here is exactly the "modeled from
/// prose" failure this crate has already committed twice. The real preimage
/// is built by the core/keystore bridge and arrives here opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueSignPreimage(Vec<u8>);

impl OpaqueSignPreimage {
    /// Round 6, wave 10 (item 5): there is NO public constructor, and in a
    /// default build no constructor at all — the field is private and the
    /// only way in is the `test-support` door below.
    ///
    /// Not a current blocker: a default build has no
    /// `SignPrimitive`/`SignerSource` implementation, so no capability can
    /// exist and `sign_checked` is unreachable regardless. It is
    /// constrained now so the FUTURE bridge cannot quietly become a signing
    /// oracle — with a real signer wired up, a public constructor here
    /// would let any caller present arbitrary self-chosen bytes for
    /// signature. When the bridge lands it must mint this from a typed,
    /// domain-separated preimage of its own, never from caller-supplied
    /// bytes. No wire format is invented here; that stays core/keystore's
    /// to define.
    /// Crate-internal constructor for the co-located bridge adapter, which
    /// wraps bytes core already derived from a sealed frame body. Never
    /// public: outside callers still have no way to mint a preimage.
    #[must_use]
    pub(crate) fn from_core_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Opaque signature bytes — same reasoning as `OpaqueSignPreimage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueSignature(Vec<u8>);

impl OpaqueSignature {
    /// Crate-internal constructor for the co-located bridge adapter, which
    /// returns what the keystore signer actually produced.
    #[must_use]
    pub(crate) fn from_backend_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) mod sealed {
    /// Not nameable outside this crate, so `SignPrimitive` cannot be
    /// implemented outside it either. This is the mechanism that keeps
    /// arbitrary caller code out of the critical section.
    pub trait Sealed {}
}

/// One physical entry, resolved once: the observed binding AND the signer
/// that belongs to it, from the SAME lookup.
///
/// Round 6, wave 10 (P0-1 successor): the wave-9 shape confirmed the binding
/// through `backend.load_exact` and then signed with a `SignPrimitive` the
/// CALLER passed in as a separate argument. Nothing tied the two together,
/// so a caller could validate binding B and sign with signer A — the wave-9
/// P0-1 defect surviving in a narrower form, because "the signer is inside
/// the capability" is not the same claim as "the signer is the one that was
/// validated". Sealing the tuple did not help: the signer was never in the
/// tuple.
///
/// The fix is derivation, not comparison. There is no signer parameter any
/// more. A capability can only be born from this one call, which returns the
/// signer of the very entry whose binding it just observed, so a mismatched
/// pair has no spelling. A self-reported `bound_public_key()` on the
/// primitive was deliberately NOT used: that is a check that trusts the
/// implementation to describe itself honestly, where this is a structure
/// that never lets the two diverge.
pub enum LoadExactSignerOutcome<'a> {
    /// The entry exists and this is its binding together with its signer.
    Ready {
        observed: ExactBinding,
        signer: &'a dyn SignPrimitive,
    },
    /// No such entry, or it does not match what was expected. Deliberately
    /// carries no signer at all.
    Absent,
}

/// Sealed like [`SignPrimitive`] and for the same reason — a downstream
/// implementation could hand back a signer unrelated to the binding it
/// reports, reopening by the back door exactly what removing the parameter
/// closed at the front.
pub trait SignerSource: sealed::Sealed + Send + Sync {
    /// ONE operation: confirm the physical entry for `expected` and yield
    /// that entry's own signer. Never two lookups, never two arguments.
    fn load_exact_signer(&self, expected: &ExactBinding) -> LoadExactSignerOutcome<'_>;
}

/// The single physical operation allowed to run while the roster lease and
/// the cell's `SignGuard` are held.
///
/// Sealed on purpose (see module doc): one method, no I/O, no access to the
/// cell/record/guards, so it can neither block indefinitely on external work
/// nor re-enter this crate's locks. In a default build **no type implements
/// this trait**, which is what keeps the production signing surface closed
/// until the real keystore bridge lands.
pub trait SignPrimitive: sealed::Sealed + Send + Sync {
    /// Must be CPU-local and bounded. Must not perform I/O, sleep, or call
    /// back into this crate.
    fn sign_opaque(&self, preimage: &OpaqueSignPreimage) -> OpaqueSignature;
}

/// A signer, already loaded and fully validated **outside** every lock, and
/// sealed to the exact tuple it was validated against.
///
/// Deliberately exposes no accessor for its binding, slot, record or
/// primitive: the wave-8 predecessor's whole defect was that the thing it
/// handed back could be cloned out and used later. Nothing here can be
/// detached, so there is no "validated" value to go stale.
pub struct SignerCapability<'a> {
    /// Derived from the validated entry, never supplied by the caller —
    /// see [`SignerSource`].
    primitive: &'a dyn SignPrimitive,
    identity: ControlIdentity,
    purpose: PurposeId,
    epoch: NonZeroU64,
    /// The WHOLE validated generation record, not a projection of it.
    ///
    /// Round 6, wave 10 (P0-3 successor): the wave-9 recheck compared an
    /// enumerated subset (slot, binding, delegator, not_after) while
    /// `validate_full_binding` had validated the entire delegation
    /// including its signature. Anything outside that hand-written list —
    /// `delegation.sig` most obviously — could change between validation
    /// and use and still pass. An enumerated list also silently goes stale
    /// the moment someone adds a field to `Delegation`. One struct equality
    /// covers everything the validator actually saw and cannot drift.
    validated_generation: GenerationRecord,
    /// Sampled BEFORE the slow roster query and sealed here, so
    /// `sign_checked` can ask "has the roster changed since validation?"
    /// rather than the self-satisfying "is the current revision the current
    /// revision?" — see `sign_checked`.
    roster_revision_at_validation: u64,
}

impl std::fmt::Debug for SignerCapability<'_> {
    /// Deliberately opaque: printing the sealed binding/slot would be one
    /// more way to get a locator out of this type.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerCapability")
            .field("generation", &self.validated_generation.generation)
            .finish_non_exhaustive()
    }
}

impl SignerCapability<'_> {
    /// The generation this capability is sealed to. A scalar, deliberately
    /// the only thing readable back out — it identifies *which* signer this
    /// is, and carries no authority on its own.
    #[must_use]
    pub fn generation(&self) -> NonZeroU64 {
        self.validated_generation.generation
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignerCapabilityError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error("record authority is not Active")]
    NotActive,
    #[error("the requested generation is not among this record's live generations")]
    GenerationNotLive,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("the requested generation's delegation has already expired at load time")]
    Expired,
}

#[derive(Debug, thiserror::Error)]
pub enum SignCheckedError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(transparent)]
    RosterChanged(#[from] RosterChanged),
    #[error(
        "the delegator machine changed between the capability load and the lease -- the lease would have been taken for the wrong machine"
    )]
    DelegatorMismatch,
    #[error("record authority is no longer Active")]
    NotActive,
    #[error("record identity or purpose no longer matches the sealed capability")]
    IdentityOrPurposeMismatch,
    #[error(
        "record epoch no longer matches the sealed capability -- a revoke/reactivate cycle happened after this signer was loaded"
    )]
    EpochMismatch,
    #[error("the capability's generation is no longer live in this record")]
    GenerationNotLive,
    #[error(
        "the live generation record is no longer bit-identical to the one that was validated (binding, slot, delegator, not_after, or any delegation field including its signature)"
    )]
    GenerationChanged,
    #[error("the delegation expired before the signing primitive could run")]
    Expired,
    #[error("the signing primitive exceeded its latency budget")]
    WatchdogTripped,
}

/// Detection budget for the sealed primitive. Not preemption — see the
/// module doc's "what is and is not a mechanism".
const WATCHDOG_BUDGET: Duration = Duration::from_millis(250);

fn live_generation(
    record: &MeshSignerControlRecordV1,
    generation: NonZeroU64,
) -> Option<&GenerationRecord> {
    record
        .live_generations
        .iter()
        .find(|g| g.generation == generation)
}

/// Step 1 of the lock order: every slow call, with **no lock held**.
///
/// `requested_generation` is explicit and is NOT forced to be
/// `current_generation`: a signer on an older generation that is still live
/// (still present in `live_generations`, still inside its `not_after`) is a
/// legitimate overlap case that the predecessor made impossible to express.
pub fn load_signer_capability<'a, P: PurposeMarker>(
    cell: &ControlRecordCell,
    signer_source: &'a dyn SignerSource,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    clock: &dyn Clock,
    requested_generation: NonZeroU64,
) -> Result<SignerCapability<'a>, SignerCapabilityError> {
    let record = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(SignerCapabilityError::NoRecord),
        LoadOutcome::Corrupt => return Err(SignerCapabilityError::RecordCorrupt),
    };
    if record.purpose != P::PURPOSE_ID {
        return Err(ValidationError::PurposeMismatch.into());
    }
    if record.authority != Authority::Active {
        return Err(SignerCapabilityError::NotActive);
    }
    let g = live_generation(&record, requested_generation)
        .ok_or(SignerCapabilityError::GenerationNotLive)?;

    let now = clock.now();
    if now >= g.not_after {
        return Err(SignerCapabilityError::Expired);
    }

    // Sampled BEFORE the slow roster query below, and sealed into the
    // capability. `sign_checked` must compare against THIS value: a
    // revision sampled at use time would only ever be compared with
    // itself, so the lease could never report a change (wave-9 defect).
    let roster_revision_at_validation = roster.currency_revision(&g.delegation.delegator_m_id);

    // Slow, and the ONE place the signer can come from: this single call
    // confirms the physical entry and yields that same entry's signer.
    let LoadExactSignerOutcome::Ready { observed, signer } =
        signer_source.load_exact_signer(&g.binding)
    else {
        return Err(ValidationError::PhysicalKeyNotConfirmed.into());
    };
    if observed != g.binding {
        return Err(ValidationError::PhysicalKeyNotConfirmed.into());
    }

    let ctx = BindingContext::from_identity(&record.identity);
    validate_full_binding::<P>(g, &ctx, policy, roster, sig, now)?;

    Ok(SignerCapability {
        primitive: signer,
        identity: record.identity.clone(),
        purpose: record.purpose,
        epoch: record.epoch_high_water,
        validated_generation: g.clone(),
        roster_revision_at_validation,
    })
}

/// Steps 2–8 of the lock order: confirm the delegator, take the roster lease
/// then the cell guard, re-read and compare the sealed tuple exactly,
/// re-sample the clock, and only then run the sealed primitive.
///
/// Returns opaque signature bytes and nothing else — no record, no binding,
/// no locator, no signer.
pub fn sign_checked(
    cell: &ControlRecordCell,
    roster: &dyn RosterLookup,
    clock: &dyn Clock,
    capability: &SignerCapability<'_>,
    preimage: &OpaqueSignPreimage,
) -> Result<OpaqueSignature, SignCheckedError> {
    // ---- step 2: the delegator the lease will be taken for must be the
    // one this capability was actually validated against (CFX-4). ----
    let peek = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(SignCheckedError::NoRecord),
        LoadOutcome::Corrupt => return Err(SignCheckedError::RecordCorrupt),
    };
    let sealed_delegator = &capability.validated_generation.delegation.delegator_m_id;
    let peek_delegator = live_generation(&peek, capability.generation())
        .ok_or(SignCheckedError::GenerationNotLive)?
        .delegation
        .delegator_m_id
        .clone();
    if peek_delegator != *sealed_delegator {
        return Err(SignCheckedError::DelegatorMismatch);
    }

    // ---- step 3: roster lease, for that exact machine, against the
    // revision observed AT VALIDATION -- never the current one. If the
    // roster moved since the capability was validated (e.g. this delegator
    // was revoked), the lease is refused and nothing is signed.
    let _lease = roster
        .acquire_currency_lease(sealed_delegator, capability.roster_revision_at_validation)?;
    // ---- step 4: THEN the cell guard. Never the reverse. ----
    let _sign = cell.acquire_for_sign_internal();

    // ---- step 5: cheap exact re-read, compared field-for-field. ----
    let fresh = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(SignCheckedError::NoRecord),
        LoadOutcome::Corrupt => return Err(SignCheckedError::RecordCorrupt),
    };
    if fresh.identity != capability.identity || fresh.purpose != capability.purpose {
        return Err(SignCheckedError::IdentityOrPurposeMismatch);
    }
    if fresh.authority != Authority::Active {
        return Err(SignCheckedError::NotActive);
    }
    // A revoke→reactivate cycle strictly increases `epoch_high_water`, so a
    // signer loaded before that cycle fails here even though a brand-new
    // generation may be perfectly live.
    if fresh.epoch_high_water != capability.epoch {
        return Err(SignCheckedError::EpochMismatch);
    }
    let g = live_generation(&fresh, capability.generation())
        .ok_or(SignCheckedError::GenerationNotLive)?;
    // ONE equality over the WHOLE validated record -- not an enumerated
    // projection. Covers slot, binding, delegator, not_after, the entire
    // delegation and its signature, and stays correct when `Delegation`
    // grows a field.
    if *g != capability.validated_generation {
        return Err(SignCheckedError::GenerationChanged);
    }

    // ---- step 6: a FRESH clock sample, under both locks. ----
    let now = clock.now();
    if now >= g.not_after {
        return Err(SignCheckedError::Expired);
    }

    // ---- step 7: the sealed, bounded, CPU-local primitive. ----
    let started = Instant::now();
    let signature = capability.primitive.sign_opaque(preimage);
    if started.elapsed() > WATCHDOG_BUDGET {
        return Err(SignCheckedError::WatchdogTripped);
    }
    Ok(signature)
    // ---- step 8: `_sign` then `_lease` drop here, in reverse order. ----
}

/// The only implementations of `SignPrimitive`/`SignerSource` that exist
/// anywhere, and both are gated out of the default build entirely — which
/// is what "the production signing surface stays closed until the bridge"
/// means concretely, rather than as a promise.
#[cfg(feature = "test-support")]
pub struct FakeSignPrimitive {
    tag: u8,
    pub calls: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "test-support")]
impl FakeSignPrimitive {
    #[must_use]
    pub fn new(tag: u8) -> Self {
        Self {
            tag,
            calls: std::sync::atomic::AtomicU64::new(0),
        }
    }
    #[must_use]
    pub fn call_count(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "test-support")]
impl sealed::Sealed for FakeSignPrimitive {}

#[cfg(feature = "test-support")]
impl SignPrimitive for FakeSignPrimitive {
    fn sign_opaque(&self, preimage: &OpaqueSignPreimage) -> OpaqueSignature {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut out = vec![self.tag];
        out.extend_from_slice(preimage.as_bytes());
        OpaqueSignature(out)
    }
}

/// Holds TWO physically distinct signers keyed by their own bindings, so a
/// test can validate binding B and prove that signer A is never reachable —
/// the whole point of deriving the signer instead of accepting one.
#[cfg(feature = "test-support")]
pub struct FakeSignerSource {
    entries: Vec<(ExactBinding, FakeSignPrimitive)>,
}

#[cfg(feature = "test-support")]
impl FakeSignerSource {
    #[must_use]
    pub fn new(entries: Vec<(ExactBinding, FakeSignPrimitive)>) -> Self {
        Self { entries }
    }

    /// Call count of the signer registered for `binding`, or `None` if this
    /// source has no such entry.
    #[must_use]
    pub fn calls_for(&self, binding: &ExactBinding) -> Option<u64> {
        self.entries
            .iter()
            .find(|(b, _)| b == binding)
            .map(|(_, p)| p.call_count())
    }

    /// Total calls across every signer this source owns — lets a test assert
    /// "no signer at all ran", not merely "the expected one did not".
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.entries.iter().map(|(_, p)| p.call_count()).sum()
    }
}

#[cfg(feature = "test-support")]
impl sealed::Sealed for FakeSignerSource {}

#[cfg(feature = "test-support")]
impl SignerSource for FakeSignerSource {
    fn load_exact_signer(&self, expected: &ExactBinding) -> LoadExactSignerOutcome<'_> {
        match self.entries.iter().find(|(b, _)| b == expected) {
            Some((observed, signer)) => LoadExactSignerOutcome::Ready {
                observed: observed.clone(),
                signer,
            },
            None => LoadExactSignerOutcome::Absent,
        }
    }
}

/// Fixed clock for tests that do not care about time.
#[cfg(feature = "test-support")]
pub struct FixedClock(pub u64);

#[cfg(feature = "test-support")]
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// A clock a test can advance deterministically, including from inside a
/// rendezvous during the slow load step.
#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct SteppableClock(std::sync::atomic::AtomicU64);

#[cfg(feature = "test-support")]
impl SteppableClock {
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(start))
    }
    pub fn set(&self, v: u64) {
        self.0.store(v, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-support")]
impl Clock for SteppableClock {
    fn now(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Test instrumentation for observing the critical section from outside.
///
/// `sign_checked` samples the clock at step 6 — under BOTH the roster lease
/// and the `SignGuard`, immediately before the primitive. A test that wants
/// to prove something is blocked *while those locks are held* needs a real
/// observable rendezvous at exactly that point, not a `sleep`. This clock
/// announces its Nth sample and then parks until released, pinning the
/// caller inside the critical section for as long as the test needs.
#[cfg(feature = "test-support")]
pub struct RendezvousClock {
    value: std::sync::atomic::AtomicU64,
    park_on_call: u64,
    calls: std::sync::atomic::AtomicU64,
    ready_tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    proceed_rx: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

#[cfg(feature = "test-support")]
impl RendezvousClock {
    /// `park_on_call` is 1-based: 1 parks on the very first sample (the one
    /// in `load_signer_capability`, outside the locks), 2 parks on
    /// `sign_checked`'s in-critical-section sample.
    #[must_use]
    pub fn new(
        start: u64,
        park_on_call: u64,
        ready_tx: std::sync::mpsc::Sender<()>,
        proceed_rx: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self {
            value: std::sync::atomic::AtomicU64::new(start),
            park_on_call,
            calls: std::sync::atomic::AtomicU64::new(0),
            ready_tx: std::sync::Mutex::new(Some(ready_tx)),
            proceed_rx: std::sync::Mutex::new(Some(proceed_rx)),
        }
    }
    pub fn set(&self, v: u64) {
        self.value.store(v, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-support")]
impl Clock for RendezvousClock {
    fn now(&self) -> u64 {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if n == self.park_on_call {
            if let Some(tx) = self.ready_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.proceed_rx.lock().unwrap().take() {
                rx.recv().unwrap();
            }
        }
        self.value.load(std::sync::atomic::Ordering::SeqCst)
    }
}
