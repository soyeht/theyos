//! Opaque secret backend. Fixes the v11 sweep finding directly: the trait
//! signature itself must make it impossible for a caller to supply or
//! receive raw key material. `create_or_inspect` takes **no** value
//! parameter — the backend decides internally whether to generate fresh
//! material or return the existing item; the caller never has bytes to
//! pass in the first place.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO,
//! findings 6/9): every method now takes a real `&SlotId` instead of a
//! stringified `slot_id: &str` — "inspect tipado". The prior
//! `synth_binding(slot_id: &str)` fabricated a fresh, disconnected `SlotId`
//! (hardcoded `generation=1`, `txn_id=[0;16]`) inside the returned
//! `ExactBinding`, unrelated to whatever slot was actually being created
//! for; taking the real `SlotId` and echoing it back verbatim closes that.
//! `gc_best_effort` now actually compares against `expected_binding` before
//! removing anything — the prior parameter was named `_expected_binding`
//! and never read.

use crate::record::{ExactBinding, SlotId};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatedOrExisting {
    Created,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome {
    Unique {
        created_or_existing: CreatedOrExisting,
        binding: ExactBinding,
    },
    /// The account exists but does not match `expected_binding` when one
    /// was supplied for idempotent recovery (see `create_or_inspect`'s
    /// `expected` parameter) — never silently treated as `Existing`.
    Conflict,
    MissingRetry,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadExactOutcome {
    Ready(ExactBinding),
    Missing,
    CardinalityConflict,
    PublicKeyMismatch,
    Unavailable,
}

/// Second-round fix: `inspect` used to return `Option<ExactBinding>`, which
/// cannot distinguish "queried and confirmed nothing is there" from "the
/// query itself did not complete" (a transient SE/TPM outage, a timeout).
/// GC's `AbsentUnconfirmed` → `Absent` step exists specifically to guard
/// against a backend that is eventually consistent — if `inspect` cannot
/// report indeterminacy, two failed/timed-out calls in a row would look
/// identical to two genuine confirmed-absent observations, and GC would
/// wrongly promote the entry to terminal `Absent` during an outage instead
/// of leaving it pending for a later, real inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectOutcome {
    Present(ExactBinding),
    Absent,
    /// The query did not complete (outage, timeout) — must never be
    /// treated as an absence observation.
    Indeterminate,
    /// More than one candidate was observed at a slot that should hold at
    /// most one item — an ambiguity, not an absence.
    Conflict,
}

/// Opaque secret backend contract. No method here can accept or return raw
/// key material — `ExactBinding` carries only the public key and slot
/// metadata (see `record::ExactBinding`), never a private scalar.
pub trait SecretBackend: Send + Sync {
    /// Idempotent by slot: a second call on the same slot, whether or not
    /// the first call's ack was lost, returns `Existing` with the SAME
    /// binding — it never generates new material for an already-occupied
    /// slot. `expected_binding` is `None` on a genuinely first attempt and
    /// `Some` when resuming a recovery whose earlier `KeyObserved` write
    /// may or may not have committed; if the slot holds something that
    /// does not match `expected_binding`, the backend must report
    /// `Conflict`, never silently accept a mismatched item as `Existing`.
    fn create_or_inspect(
        &self,
        slot: &SlotId,
        expected_binding: Option<&ExactBinding>,
    ) -> CreateOutcome;

    fn load_exact(&self, slot: &SlotId, expected_public_key: &[u8]) -> LoadExactOutcome;

    /// Pure read-only inspection: does *anything* exist at this slot, with
    /// no expected public key required and no side effect either way. This
    /// is what GC's `AwaitingInspection` step must call — `load_exact`
    /// requires the caller to already know the public key it expects,
    /// which is exactly the thing an `AwaitingInspection` entry does not
    /// yet have; `create_or_inspect` has the create-on-absence side effect
    /// GC must never trigger. Returns a typed `InspectOutcome`, not
    /// `Option`, so a transient failure can never be conflated with a
    /// confirmed absence — see `InspectOutcome`'s doc comment.
    fn inspect(&self, slot: &SlotId) -> InspectOutcome;

    /// Best-effort destroy. Physical delete is hygiene, not authority —
    /// revocation happens in the control record
    /// (`transition::RecordTransition::RevokeUrgent`) and blocks `sign`
    /// before any GC runs. Must verify `expected_binding` against whatever
    /// is actually present before destroying it; a mismatch is reported
    /// (`residual: true`), never silently treated as either "nothing to
    /// do" or "destroyed the expected item" — a caller sees this on the
    /// returned `GcReport` and quarantines the GC entry rather than
    /// resolving it as clean.
    fn gc_best_effort(&self, slot: &SlotId, expected_binding: &ExactBinding) -> GcReport;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    pub attempted: bool,
    pub residual: bool,
    pub observation_complete: bool,
    /// `true` only when something was observed at the slot but it did not
    /// match `expected_binding` — a distinct, stronger signal than generic
    /// `residual` (which can also mean "destroy attempted, something
    /// unidentified is still there"). A caller must route `mismatch` to
    /// `GcState::Quarantine`, never treat it as an ordinary retry case.
    pub mismatch: bool,
}

/// In-memory fake — the only backend this crate implements. Real
/// Secure-Enclave/TPM/File adapters live outside this crate's boundary
/// (they need `keystore-rs`/`security-framework`, which a standalone model
/// crate must not depend on); this fake exists so the control state
/// machine and its lost-ack/idempotency invariants are testable without
/// any real OS integration, matching "backend abstrato testável, sem APIs
/// externas inventadas."
#[derive(Default)]
pub struct FakeSecretBackend {
    items: Mutex<HashMap<SlotId, ExactBinding>>,
}

impl FakeSecretBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretBackend for FakeSecretBackend {
    fn create_or_inspect(
        &self,
        slot: &SlotId,
        expected_binding: Option<&ExactBinding>,
    ) -> CreateOutcome {
        // Round 5, item B5: an `expected_binding` whose OWN `.slot` field
        // does not match the `slot` parameter it is being inserted under
        // is nonsensical and must never be accepted verbatim -- without
        // this, the fake could store a binding keyed under slot S whose
        // own `.slot` claims T, corrupting exactly the kind of
        // slot-identity consistency `KeyObserved`'s own binding-slot check
        // (transition.rs) depends on the backend never producing.
        if let Some(exp) = expected_binding
            && exp.slot != *slot
        {
            return CreateOutcome::Conflict;
        }
        let mut items = self.items.lock().unwrap();
        if let Some(existing) = items.get(slot) {
            return match expected_binding {
                Some(exp) if exp != existing => CreateOutcome::Conflict,
                _ => CreateOutcome::Unique {
                    created_or_existing: CreatedOrExisting::Existing,
                    binding: existing.clone(),
                },
            };
        }
        let binding = expected_binding
            .cloned()
            .unwrap_or_else(|| synth_binding(slot));
        items.insert(slot.clone(), binding.clone());
        CreateOutcome::Unique {
            created_or_existing: CreatedOrExisting::Created,
            binding,
        }
    }

    fn load_exact(&self, slot: &SlotId, expected_public_key: &[u8]) -> LoadExactOutcome {
        let items = self.items.lock().unwrap();
        match items.get(slot) {
            None => LoadExactOutcome::Missing,
            Some(b) if b.public_key == expected_public_key => LoadExactOutcome::Ready(b.clone()),
            Some(_) => LoadExactOutcome::PublicKeyMismatch,
        }
    }

    fn inspect(&self, slot: &SlotId) -> InspectOutcome {
        match self.items.lock().unwrap().get(slot).cloned() {
            Some(b) => InspectOutcome::Present(b),
            None => InspectOutcome::Absent,
        }
    }

    fn gc_best_effort(&self, slot: &SlotId, expected_binding: &ExactBinding) -> GcReport {
        let mut items = self.items.lock().unwrap();
        match items.get(slot) {
            None => GcReport {
                attempted: true,
                residual: false,
                observation_complete: true,
                mismatch: false,
            },
            Some(actual) if actual == expected_binding => {
                items.remove(slot);
                GcReport {
                    attempted: true,
                    residual: false,
                    observation_complete: true,
                    mismatch: false,
                }
            }
            Some(_mismatched) => GcReport {
                attempted: true,
                residual: true,
                observation_complete: true,
                mismatch: true,
            },
        }
    }
}

fn synth_binding(slot: &SlotId) -> ExactBinding {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(slot.canonical_id().as_bytes());
    ExactBinding {
        slot: slot.clone(),
        public_key: digest.to_vec(),
        attributes: Vec::new(),
    }
}
