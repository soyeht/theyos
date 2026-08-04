//! Purpose-bound P-256 slots whose private scalar never crosses this
//! module's API.
//!
//! This is a NARROW, separate surface — deliberately not an extension of the
//! generic `(service, account) -> bytes` [`KeystoreBackend`]. That trait is
//! byte-oriented by design and a caller holding it can read or overwrite any
//! value; a signing key needs the opposite property, so it gets its own type
//! whose entire public vocabulary is *slot*, *public binding*, and
//! *signature*.
//!
//! ## What the API cannot do
//!
//! There is no method anywhere on [`OpaqueP256Slots`], [`PublicBinding`],
//! [`SlotHandle`] or [`P256Signature`] that returns the private scalar, the
//! sealed ciphertext, the on-disk path, or the storage account name. The
//! scalar is generated inside [`OpaqueP256Slots::create_or_inspect`], is
//! zeroized before that call returns, and is only ever re-materialised
//! transiently inside [`OpaqueP256Slots::sign`] — again zeroized before
//! returning. `compile_fail` doctests below assert that the obvious
//! extraction attempts do not typecheck.
//!
//! This is a containment boundary, not a claim of exfiltration-proofness: a
//! caller in the same address space can always read this process's memory.
//! What it does buy is that no *ordinary* use — and no downstream crate
//! holding this type — can obtain key material, so a scalar cannot leak by
//! accident, by refactor, or by a caller reaching for a convenient accessor
//! that shouldn't exist.
//!
//! ## Where the scalar rests
//!
//! At rest the scalar is whatever the injected [`KeystoreBackend`] makes of
//! it, which is why the constructor is explicit about the trade:
//!
//! | Constructor | At-rest protection |
//! |---|---|
//! | [`OpaqueP256Slots::with_sealing_backend`] | the backend's own encryption (e.g. `TpmKeystore`, which seals to the host TPM before anything reaches disk) |
//! | [`OpaqueP256Slots::with_approved_plaintext_fallback`] | **none** — the scalar sits in a `0600` file. Requires an explicit [`ApprovedFallback`] token so this can never be reached by default or by accident. |
//!
//! A Secure Enclave backing, where the scalar would never exist outside
//! dedicated hardware at all, is NOT implemented here — see
//! [`SeBacking`] for why it is a gate rather than a claim.

use zeroize::Zeroize;

use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey, signature::Signer};

use crate::{CreateOutcome, KeystoreBackend, KeystoreError};

/// Length of a SEC1-compressed P-256 public key, matching the wire contract
/// already used elsewhere in theyOS (`household-rs::keys::P256PublicKey`).
pub const P256_PUBLIC_KEY_LEN: usize = 33;

/// Length of a raw `r || s` ECDSA P-256 signature (NOT DER), matching the
/// same existing wire contract.
pub const P256_SIGNATURE_LEN: usize = 64;

/// Compile-time purpose tag. Distinct purposes derive distinct storage slots
/// and cannot be interchanged at a call site, so a key minted for one role
/// cannot be used to sign for another by passing a different string.
///
/// ```
/// use keystore_rs::opaque_p256::Purpose;
/// struct MeshSession;
/// impl Purpose for MeshSession {
///     const PURPOSE: &'static str = "mesh-session";
/// }
/// ```
pub trait Purpose {
    /// Stable, domain-separating label. Part of the storage slot identity —
    /// changing it orphans existing keys, so treat it as a wire constant.
    const PURPOSE: &'static str;
}

/// Opaque handle to one purpose-bound slot. Carries no key material: it is
/// only the coordinates of a slot, safe to log, clone, and pass around.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlotHandle {
    purpose: &'static str,
    label: String,
}

impl SlotHandle {
    /// The purpose this slot is bound to.
    #[must_use]
    pub fn purpose(&self) -> &'static str {
        self.purpose
    }

    /// The caller-chosen label within that purpose.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Storage account name. Deliberately private: the account name is the
    /// coordinate a byte-oriented `KeystoreBackend::get` would need in order
    /// to read the scalar out from underneath this module, so it is exactly
    /// the thing the opaque surface must not hand out.
    fn account(&self) -> String {
        format!("p256.{}.{}", self.purpose, self.label)
    }
}

/// What the caller may know about a slot: which purpose it serves and its
/// public key. No scalar, no ciphertext, no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBinding {
    slot: SlotHandle,
    public_key: [u8; P256_PUBLIC_KEY_LEN],
    backing: Backing,
}

impl PublicBinding {
    #[must_use]
    pub fn slot(&self) -> &SlotHandle {
        &self.slot
    }

    /// SEC1-compressed public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; P256_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// How the private scalar is protected at rest — part of the binding so
    /// a relying party can refuse a key that is only software-protected when
    /// its policy requires hardware.
    #[must_use]
    pub fn backing(&self) -> Backing {
        self.backing
    }
}

/// At-rest protection actually in force for a slot. Reported honestly:
/// [`Backing::PlaintextFallback`] means the scalar is in a `0600` file with
/// no encryption, and a caller that cares must check rather than assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// The injected backend encrypts before anything reaches disk.
    SealedByBackend,
    /// Explicitly-approved plaintext-at-rest fallback.
    PlaintextFallback,
}

/// Raw `r || s` ECDSA P-256 signature, always canonical low-S.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256Signature([u8; P256_SIGNATURE_LEN]);

impl P256Signature {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; P256_SIGNATURE_LEN] {
        self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; P256_SIGNATURE_LEN] {
        &self.0
    }
}

/// Explicit opt-in to storing private scalars as plaintext at rest.
///
/// Deliberately awkward to obtain and impossible to produce by `Default`, so
/// the unprotected path cannot be reached without a call site that names it.
/// The `reason` is retained for logging: an operator reading a warning about
/// plaintext keys should be able to see which code path asked for it and why.
#[derive(Debug, Clone)]
pub struct ApprovedFallback {
    reason: &'static str,
}

impl ApprovedFallback {
    /// Approve plaintext-at-rest for a stated reason.
    ///
    /// Legitimate reasons are narrow: a CI runner with no keystore, or a
    /// pre-T2 Intel Mac with no Secure Enclave. Production hardware with a
    /// working sealing backend must not use this.
    #[must_use]
    pub fn for_reason(reason: &'static str) -> Self {
        Self { reason }
    }

    #[must_use]
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

/// Secure Enclave backing: not implemented, and deliberately represented as
/// an uninhabited type rather than a stub.
///
/// A stub that silently degraded to software would be worse than nothing —
/// callers would believe scalars were in hardware when they were in a file.
/// Because this enum has no variants, no value of it can ever exist, so
/// "this build has SE-backed slots" is unrepresentable rather than merely
/// untrue. Implementing it needs `SecKeyCreateRandomKey` with
/// `kSecAttrTokenIDSecureEnclave`, an access-control policy, and measurement
/// on real SE hardware — none of which has been done or verified here.
#[derive(Debug)]
pub enum SeBacking {}

/// Purpose-bound P-256 slots over an injected byte backend.
///
/// The backend is used ONLY through [`KeystoreBackend::create_only`] and
/// [`KeystoreBackend::get`], with account names this module derives; it never
/// sees a caller-supplied account, and callers never see the backend.
#[derive(Debug)]
pub struct OpaqueP256Slots<B: KeystoreBackend> {
    backend: B,
    backing: Backing,
}

impl<B: KeystoreBackend> OpaqueP256Slots<B> {
    /// Slots whose scalars are encrypted at rest by `backend` itself — e.g.
    /// `TpmKeystore`, which seals to the host TPM before any byte reaches
    /// the filesystem.
    ///
    /// This module does not verify that the backend actually encrypts (it
    /// cannot: the trait is opaque bytes in, opaque bytes out). Passing a
    /// non-encrypting backend here would report [`Backing::SealedByBackend`]
    /// while storing plaintext — which is exactly why the plaintext path has
    /// its own separate, explicitly-named constructor rather than being the
    /// same call with a different backend.
    pub fn with_sealing_backend(backend: B) -> Self {
        Self {
            backend,
            backing: Backing::SealedByBackend,
        }
    }

    /// Slots whose scalars rest as plaintext in `0600` files, gated behind an
    /// explicit [`ApprovedFallback`].
    pub fn with_approved_plaintext_fallback(backend: B, approval: &ApprovedFallback) -> Self {
        tracing::warn!(
            reason = approval.reason(),
            "P-256 private scalars will rest as PLAINTEXT (no backend encryption); \
             this is only appropriate where no sealing backend exists"
        );
        Self {
            backend,
            backing: Backing::PlaintextFallback,
        }
    }

    /// Bind a label to a compile-time purpose.
    pub fn slot<P: Purpose>(&self, label: impl Into<String>) -> SlotHandle {
        SlotHandle {
            purpose: P::PURPOSE,
            label: label.into(),
        }
    }

    /// Create the slot's key if absent, or report the existing one — never
    /// overwriting either way.
    ///
    /// The scalar is generated HERE, from the OS RNG, and is zeroized before
    /// this function returns; the caller receives only a [`PublicBinding`].
    /// Because installation goes through [`KeystoreBackend::create_only`],
    /// two racing callers cannot both believe they minted the slot: exactly
    /// one observes [`SlotOutcome::Created`], and the loser's freshly
    /// generated scalar is discarded without ever being persisted.
    pub fn create_or_inspect(
        &self,
        slot: &SlotHandle,
    ) -> Result<(SlotOutcome, PublicBinding), KeystoreError> {
        let account = slot.account();

        // Generated inside; never returned, never logged.
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let mut scalar = signing.to_bytes();

        let outcome = self.backend.create_only(&account, scalar.as_slice());
        scalar.zeroize();

        match outcome? {
            CreateOutcome::CreatedDurable => {
                let binding = self.binding_from_verifying_key(slot, signing.verifying_key())?;
                Ok((SlotOutcome::Created, binding))
            }
            // Another caller's key is already installed (or our own from an
            // earlier attempt). The scalar we just generated is dead; report
            // the binding of what is ACTUALLY stored, never our discarded
            // candidate — otherwise a caller would hold a public key whose
            // private half no longer exists anywhere.
            CreateOutcome::ExistingExactDurable | CreateOutcome::Conflict => {
                let binding = self.public_binding(slot)?;
                Ok((SlotOutcome::AlreadyExisted, binding))
            }
            // Nothing was installed and the cause is known — surface it
            // rather than inventing a binding.
            CreateOutcome::KnownNoEffect => Err(KeystoreError::Io {
                kind: "create-only had no effect".into(),
                hint: format!("slot {}/{} was not created", slot.purpose, slot.label),
            }),
            // Genuinely unresolved: refuse to mint a binding for a slot whose
            // stored state is unknown. A retry converges.
            CreateOutcome::MayHaveTakenEffect => Err(KeystoreError::Io {
                kind: "create-only outcome unresolved".into(),
                hint: format!(
                    "slot {}/{} may or may not hold a key; retry to converge before use",
                    slot.purpose, slot.label
                ),
            }),
        }
    }

    /// Public binding of an existing slot.
    pub fn public_binding(&self, slot: &SlotHandle) -> Result<PublicBinding, KeystoreError> {
        let mut scalar = self.load_scalar(slot)?;
        let signing = SigningKey::from_slice(&scalar)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("p256 from_slice: {e}")));
        scalar.zeroize();
        let signing = signing?;
        self.binding_from_verifying_key(slot, signing.verifying_key())
    }

    /// Sign `message` with the slot's key.
    ///
    /// The scalar is loaded, used, and zeroized within this call. The
    /// signature is normalised to canonical low-S: P-256 accepts both `s`
    /// and `n - s` for the same message and key, so without normalisation a
    /// third party could produce a second, equally-valid encoding of any
    /// signature. Anything that identifies or dedupes by signature bytes —
    /// a revocation list, a transcript digest, an idempotency key — would
    /// then be trivially bypassable.
    pub fn sign(&self, slot: &SlotHandle, message: &[u8]) -> Result<P256Signature, KeystoreError> {
        let mut scalar = self.load_scalar(slot)?;
        let signing = SigningKey::from_slice(&scalar)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("p256 from_slice: {e}")));
        scalar.zeroize();
        let signing = signing?;

        let sig: EcdsaSignature = signing.sign(message);
        // `normalize_s` returns Some only when the input was high-S.
        let sig = sig.normalize_s().unwrap_or(sig);

        let raw = sig.to_bytes();
        let mut out = [0u8; P256_SIGNATURE_LEN];
        out.copy_from_slice(raw.as_slice());
        Ok(P256Signature(out))
    }

    /// Load the raw scalar. PRIVATE — this is the one function in the module
    /// that materialises key material, and every caller of it zeroizes
    /// immediately after use.
    fn load_scalar(&self, slot: &SlotHandle) -> Result<Vec<u8>, KeystoreError> {
        let bytes = self.backend.get(&slot.account())?;
        if bytes.len() != 32 {
            // Do not echo the content in the error.
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "slot {}/{} holds {} bytes, expected a 32-byte P-256 scalar",
                slot.purpose,
                slot.label,
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    fn binding_from_verifying_key(
        &self,
        slot: &SlotHandle,
        verifying: &VerifyingKey,
    ) -> Result<PublicBinding, KeystoreError> {
        let encoded = verifying.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        if bytes.len() != P256_PUBLIC_KEY_LEN {
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "expected {P256_PUBLIC_KEY_LEN}-byte SEC1 public key, got {}",
                bytes.len()
            )));
        }
        let mut public_key = [0u8; P256_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(bytes);
        Ok(PublicBinding {
            slot: slot.clone(),
            public_key,
            backing: self.backing,
        })
    }
}

/// Whether [`OpaqueP256Slots::create_or_inspect`] minted the key or found one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutcome {
    /// This call generated and durably installed the key.
    Created,
    /// A key was already present; this call left it untouched. The returned
    /// binding describes the STORED key, not the candidate this call
    /// generated and discarded.
    AlreadyExisted,
}

/// The private scalar must not be reachable through any public API.
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueP256Slots, Purpose};
/// use keystore_rs::FileKeystore;
/// struct P;
/// impl Purpose for P { const PURPOSE: &'static str = "p"; }
/// let slots = OpaqueP256Slots::with_sealing_backend(FileKeystore::new("/tmp", "s"));
/// let slot = slots.slot::<P>("l");
/// // There is no scalar accessor.
/// let _scalar = slots.scalar(&slot);
/// ```
///
/// (Verified non-vacuous: flipping this fence to a normal doctest fails with
/// `E0599: no method named 'scalar'` — i.e. it really is the missing
/// accessor that rejects it, not an incidental typo or import error, which a
/// `compile_fail` block would otherwise happily accept as a pass.)
///
/// Nor through the binding:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::PublicBinding;
/// fn leak(b: &PublicBinding) -> &[u8; 32] {
///     b.private_key()
/// }
/// ```
///
/// Nor may the storage account name be recovered, which would let a caller
/// read the scalar out through the byte-oriented backend:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::SlotHandle;
/// fn leak(s: &SlotHandle) -> String {
///     s.account()
/// }
/// ```
#[cfg(doctest)]
struct ScalarIsUnreachable;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::FileKeystore;

    struct MeshSession;
    impl Purpose for MeshSession {
        const PURPOSE: &'static str = "mesh-session";
    }

    struct RosterSync;
    impl Purpose for RosterSync {
        const PURPOSE: &'static str = "roster-sync";
    }

    fn slots(dir: &std::path::Path) -> OpaqueP256Slots<FileKeystore> {
        OpaqueP256Slots::with_approved_plaintext_fallback(
            FileKeystore::new(dir, "opaque-p256-test"),
            &ApprovedFallback::for_reason("unit test"),
        )
    }

    #[test]
    fn create_then_reinspect_is_stable_and_never_overwrites() {
        let td = tempfile::tempdir().unwrap();
        let s = slots(td.path());
        let slot = s.slot::<MeshSession>("device-a");

        let (outcome, first) = s.create_or_inspect(&slot).unwrap();
        assert_eq!(outcome, SlotOutcome::Created);

        let (outcome, again) = s.create_or_inspect(&slot).unwrap();
        assert_eq!(
            outcome,
            SlotOutcome::AlreadyExisted,
            "a second create must never mint a new key over the first"
        );
        assert_eq!(
            first.public_key(),
            again.public_key(),
            "the binding must describe the STORED key, not the discarded candidate"
        );
    }

    #[test]
    fn distinct_purposes_never_share_a_key() {
        let td = tempfile::tempdir().unwrap();
        let s = slots(td.path());

        let mesh = s.slot::<MeshSession>("same-label");
        let roster = s.slot::<RosterSync>("same-label");

        let (_, mesh_binding) = s.create_or_inspect(&mesh).unwrap();
        let (outcome, roster_binding) = s.create_or_inspect(&roster).unwrap();

        assert_eq!(
            outcome,
            SlotOutcome::Created,
            "an identical label under a different purpose is a different slot"
        );
        assert_ne!(mesh_binding.public_key(), roster_binding.public_key());
    }

    #[test]
    fn signature_verifies_against_the_published_binding() {
        use p256::ecdsa::signature::Verifier;

        let td = tempfile::tempdir().unwrap();
        let s = slots(td.path());
        let slot = s.slot::<MeshSession>("signer");
        let (_, binding) = s.create_or_inspect(&slot).unwrap();

        let message = b"transcript bytes to be signed";
        let sig = s.sign(&slot, message).unwrap();

        let vk = VerifyingKey::from_sec1_bytes(binding.public_key()).unwrap();
        let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
        vk.verify(message, &parsed)
            .expect("signature must verify against the binding the API published");
    }

    /// Every signature this API emits must be canonical low-S. Without it,
    /// `(r, n-s)` is an equally valid second encoding of the same signature,
    /// and anything keyed on signature bytes (revocation, dedupe, transcript
    /// identity) can be bypassed by presenting the other form.
    #[test]
    fn every_signature_is_canonical_low_s() {
        let td = tempfile::tempdir().unwrap();
        let s = slots(td.path());
        let slot = s.slot::<MeshSession>("low-s");
        s.create_or_inspect(&slot).unwrap();

        for i in 0..64 {
            let sig = s.sign(&slot, format!("message-{i}").as_bytes()).unwrap();
            let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
            assert!(
                parsed.normalize_s().is_none(),
                "signature {i} was high-S; normalisation did not run"
            );
        }
    }

    #[test]
    fn signing_an_absent_slot_fails_rather_than_minting_one() {
        let td = tempfile::tempdir().unwrap();
        let s = slots(td.path());
        let slot = s.slot::<MeshSession>("never-created");

        match s.sign(&slot, b"x") {
            Err(KeystoreError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_slot_content_is_rejected_without_echoing_it() {
        let td = tempfile::tempdir().unwrap();
        let backend = FileKeystore::new(td.path(), "opaque-p256-test");
        let s = OpaqueP256Slots::with_approved_plaintext_fallback(
            FileKeystore::new(td.path(), "opaque-p256-test"),
            &ApprovedFallback::for_reason("unit test"),
        );
        let slot = s.slot::<MeshSession>("corrupt");

        // Plant a wrong-length value through the byte API underneath.
        backend
            .set("p256.mesh-session.corrupt", b"too short")
            .unwrap();

        match s.sign(&slot, b"x") {
            Err(KeystoreError::InvalidKeyMaterial(msg)) => {
                assert!(msg.contains("expected a 32-byte P-256 scalar"), "msg={msg}");
                assert!(
                    !msg.contains("too short"),
                    "the error must not echo slot content: {msg}"
                );
            }
            other => panic!("expected InvalidKeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_creation_yields_exactly_one_key_and_one_agreed_binding() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let s = Arc::new(slots(td.path()));
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));

        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let s = s.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let slot = s.slot::<MeshSession>("raced");
                    barrier.wait();
                    s.create_or_inspect(&slot).unwrap()
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .filter(|(o, _)| *o == SlotOutcome::Created)
                .count(),
            1,
            "exactly one racer may mint the key"
        );
        // Every racer, winner or loser, must end up describing the SAME key.
        let first = results[0].1.public_key();
        for (_, binding) in &results {
            assert_eq!(
                binding.public_key(),
                first,
                "racers disagreed about which key the slot holds"
            );
        }
    }

    #[test]
    fn backing_is_reported_honestly() {
        let td = tempfile::tempdir().unwrap();
        let plaintext = slots(td.path());
        let slot = plaintext.slot::<MeshSession>("backing");
        let (_, binding) = plaintext.create_or_inspect(&slot).unwrap();
        assert_eq!(
            binding.backing(),
            Backing::PlaintextFallback,
            "a plaintext fallback must never report itself as sealed"
        );

        let sealed = OpaqueP256Slots::with_sealing_backend(FileKeystore::new(td.path(), "sealed"));
        let slot = sealed.slot::<MeshSession>("backing");
        let (_, binding) = sealed.create_or_inspect(&slot).unwrap();
        assert_eq!(binding.backing(), Backing::SealedByBackend);
    }
}
