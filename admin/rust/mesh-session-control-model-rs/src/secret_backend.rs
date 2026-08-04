//! Opaque secret backend. Fixes the v11 sweep finding directly: the trait
//! signature itself must make it impossible for a caller to supply or
//! receive raw key material. `create_or_inspect` takes **no** value
//! parameter — the backend decides internally whether to generate fresh
//! material or return the existing item; the caller never has bytes to
//! pass in the first place.

use crate::record::ExactBinding;
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
        slot_id: &str,
        expected_binding: Option<&ExactBinding>,
    ) -> CreateOutcome;

    fn load_exact(&self, slot_id: &str, expected_public_key: &[u8]) -> LoadExactOutcome;

    /// Pure read-only inspection: does *anything* exist at this slot, with
    /// no expected public key required and no side effect either way. This
    /// is what GC's `AwaitingInspection` step must call — `load_exact`
    /// requires the caller to already know the public key it expects,
    /// which is exactly the thing an `AwaitingInspection` entry does not
    /// yet have; `create_or_inspect` has the create-on-absence side effect
    /// GC must never trigger.
    fn inspect(&self, slot_id: &str) -> Option<ExactBinding>;

    /// Best-effort destroy. Physical delete is hygiene, not authority —
    /// revocation happens in the control record (`transition::RecordTransition::RevokeUrgent`)
    /// and blocks `sign` before any GC runs.
    fn gc_best_effort(&self, slot_id: &str, expected_binding: &ExactBinding) -> GcReport;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    pub attempted: bool,
    pub residual: bool,
    pub observation_complete: bool,
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
    items: Mutex<HashMap<String, ExactBinding>>,
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
        slot_id: &str,
        expected_binding: Option<&ExactBinding>,
    ) -> CreateOutcome {
        let mut items = self.items.lock().unwrap();
        if let Some(existing) = items.get(slot_id) {
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
            .unwrap_or_else(|| synth_binding(slot_id));
        items.insert(slot_id.to_string(), binding.clone());
        CreateOutcome::Unique {
            created_or_existing: CreatedOrExisting::Created,
            binding,
        }
    }

    fn load_exact(&self, slot_id: &str, expected_public_key: &[u8]) -> LoadExactOutcome {
        let items = self.items.lock().unwrap();
        match items.get(slot_id) {
            None => LoadExactOutcome::Missing,
            Some(b) if b.public_key == expected_public_key => LoadExactOutcome::Ready(b.clone()),
            Some(_) => LoadExactOutcome::PublicKeyMismatch,
        }
    }

    fn inspect(&self, slot_id: &str) -> Option<ExactBinding> {
        self.items.lock().unwrap().get(slot_id).cloned()
    }

    fn gc_best_effort(&self, slot_id: &str, _expected_binding: &ExactBinding) -> GcReport {
        let mut items = self.items.lock().unwrap();
        let _existed = items.remove(slot_id).is_some();
        GcReport {
            attempted: true,
            residual: false,
            // The fake backend is always authoritative about its own
            // in-memory map, whether or not the slot was already gone —
            // there is no ambiguous/unreachable case to model here.
            observation_complete: true,
        }
    }
}

fn synth_binding(slot_id: &str) -> ExactBinding {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(slot_id.as_bytes());
    ExactBinding {
        slot: crate::record::SlotId {
            identity_digest: digest.into(),
            purpose: crate::record::PurposeId::MeshSession,
            generation: std::num::NonZeroU64::new(1).unwrap(),
            txn_id: [0u8; 16],
            backend_instance: crate::record::BackendKind::File,
        },
        public_key: digest.to_vec(),
        attributes: Vec::new(),
    }
}
