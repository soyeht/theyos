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
    PurposeId, SlotId,
};
use crate::secret_backend::{LoadExactOutcome, SecretBackend};
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
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
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
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

mod sealed {
    /// Not nameable outside this crate, so `SignPrimitive` cannot be
    /// implemented outside it either. This is the mechanism that keeps
    /// arbitrary caller code out of the critical section.
    pub trait Sealed {}
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
    primitive: &'a dyn SignPrimitive,
    identity: ControlIdentity,
    purpose: PurposeId,
    generation: NonZeroU64,
    epoch: NonZeroU64,
    slot: SlotId,
    binding: ExactBinding,
    delegator_m_id: String,
    not_after: u64,
}

impl std::fmt::Debug for SignerCapability<'_> {
    /// Deliberately opaque: printing the sealed binding/slot would be one
    /// more way to get a locator out of this type.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerCapability")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl SignerCapability<'_> {
    /// The generation this capability is sealed to. A scalar, deliberately
    /// the only thing readable back out — it identifies *which* signer this
    /// is, and carries no authority on its own.
    #[must_use]
    pub fn generation(&self) -> NonZeroU64 {
        self.generation
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
    #[error("the live generation's slot or binding no longer matches the sealed capability")]
    BindingMismatch,
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
#[allow(clippy::too_many_arguments)]
pub fn load_signer_capability<'a, P: PurposeMarker>(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    clock: &dyn Clock,
    primitive: &'a dyn SignPrimitive,
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

    // Slow: physical key confirmation, then the full validator (roster
    // query + signature verify). No lock is held for either.
    match backend.load_exact(&g.binding.slot, &g.binding.public_key) {
        LoadExactOutcome::Ready(observed) if observed == g.binding => {}
        _ => return Err(ValidationError::PhysicalKeyNotConfirmed.into()),
    }
    let ctx = BindingContext::from_identity(&record.identity);
    validate_full_binding::<P>(g, &ctx, policy, roster, sig, now)?;

    Ok(SignerCapability {
        primitive,
        identity: record.identity.clone(),
        purpose: record.purpose,
        generation: g.generation,
        epoch: record.epoch_high_water,
        slot: g.binding.slot.clone(),
        binding: g.binding.clone(),
        delegator_m_id: g.delegation.delegator_m_id.clone(),
        not_after: g.not_after,
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
    let peek_delegator = live_generation(&peek, capability.generation)
        .ok_or(SignCheckedError::GenerationNotLive)?
        .delegation
        .delegator_m_id
        .clone();
    if peek_delegator != capability.delegator_m_id {
        return Err(SignCheckedError::DelegatorMismatch);
    }
    let roster_revision_before = roster.currency_revision(&capability.delegator_m_id);

    // ---- step 3: roster lease, for that exact machine. ----
    let _lease =
        roster.acquire_currency_lease(&capability.delegator_m_id, roster_revision_before)?;
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
    let g = live_generation(&fresh, capability.generation)
        .ok_or(SignCheckedError::GenerationNotLive)?;
    if g.binding.slot != capability.slot || g.binding != capability.binding {
        return Err(SignCheckedError::BindingMismatch);
    }
    if g.delegation.delegator_m_id != capability.delegator_m_id {
        return Err(SignCheckedError::DelegatorMismatch);
    }

    // ---- step 6: a FRESH clock sample, under both locks. ----
    let now = clock.now();
    if now >= g.not_after || now >= capability.not_after {
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

/// The only implementation of `SignPrimitive` that exists anywhere, and it
/// is gated out of the default build entirely — which is what "the
/// production signing surface stays closed until the bridge" means
/// concretely, rather than as a promise.
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
}

#[cfg(feature = "test-support")]
impl sealed::Sealed for FakeSignPrimitive {}

#[cfg(feature = "test-support")]
impl SignPrimitive for FakeSignPrimitive {
    fn sign_opaque(&self, preimage: &OpaqueSignPreimage) -> OpaqueSignature {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut out = vec![self.tag];
        out.extend_from_slice(preimage.as_bytes());
        OpaqueSignature::new(out)
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
