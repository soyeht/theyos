//! Purpose-bound P-256 slots whose private scalar never crosses this
//! module's API.
//!
//! ## Why the storage backend is not a type parameter
//!
//! An earlier revision of this module was generic over
//! `B: KeystoreBackend` and handed the freshly generated scalar to that
//! backend. Since `KeystoreBackend` is public, any downstream type could
//! implement it and simply record the scalar it was handed — the whole
//! opacity claim collapsed for any caller willing to supply their own
//! backend. It also let a plaintext [`FileKeystore`] be passed to a
//! constructor that then reported the slot as sealed.
//!
//! So the store is now a CLOSED set, chosen by which constructor you call,
//! and the constructors take a directory and a service name rather than a
//! backend object:
//!
//! | Constructor | Store | At-rest |
//! |---|---|---|
//! | [`OpaqueP256Slots::sealed_tpm`] (Linux) | `TpmKeystore` | sealed to the host TPM before any byte reaches disk |
//! | [`OpaqueP256Slots::approved_plaintext_file`] | `FileKeystore` | **plaintext** in a `0600` file; requires an [`ApprovedFallback`] |
//!
//! [`Backing`] is derived from which variant is in play, never from a
//! caller's assertion, so a plaintext store cannot report itself as sealed.
//!
//! ## What the API cannot do
//!
//! - No method returns the private scalar, the sealed ciphertext, the
//!   on-disk path, or the storage account name.
//! - Signing requires an [`OpaqueSigner<P>`] obtained from
//!   [`OpaqueP256Slots::load_exact`], which re-derives the public key from
//!   what is actually stored and refuses if it no longer matches the
//!   [`PublicBinding<P>`] the caller holds — so a key silently replaced
//!   underneath (A swapped for B through the generic byte API) is caught
//!   before it can sign anything.
//! - Signing takes a [`Preimage<P>`], not raw bytes, and a `Preimage<P>`
//!   can only be built for one purpose. Cross-purpose signing and raw-byte
//!   signing do not compile.
//!
//! This is containment against *accidental* leakage through the API — a
//! caller sharing this process's address space can still read its memory.
//! What it buys is that no ordinary use, refactor, or downstream crate can
//! obtain key material.

use std::marker::PhantomData;

use zeroize::Zeroize;

use p256::ecdsa::{
    Signature as EcdsaSignature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

use crate::{CreateOutcome, FileKeystore, KeystoreBackend, KeystoreError};

/// SEC1-compressed P-256 public key length, matching the wire contract used
/// elsewhere in theyOS (`household-rs::keys::P256PublicKey`).
pub const P256_PUBLIC_KEY_LEN: usize = 33;

/// Raw `r || s` ECDSA P-256 signature length (NOT DER), same contract.
pub const P256_SIGNATURE_LEN: usize = 64;

/// Compile-time purpose tag. Distinct purposes derive distinct slots AND
/// distinct signing preimages, so a key minted for one role cannot sign for
/// another — not by passing a different string, and not by reusing bytes.
pub trait Purpose {
    /// Stable, domain-separating label. Part of both the storage slot
    /// identity and the signed preimage, so changing it both orphans
    /// existing keys and invalidates existing signatures. Treat as a wire
    /// constant.
    const PURPOSE: &'static str;
}

/// Percent-encode a slot component so that concatenating components is
/// injective.
///
/// `format!("p256.{purpose}.{label}")` on raw components is NOT injective:
/// `("a", "b.c")` and `("a.b", "c")` both render `p256.a.b.c`, so two
/// distinct slots would share one key. (This is the same non-injectivity
/// class as the path-segment bug fixed in `file_backend`, reintroduced one
/// layer up — encoding has to be applied at every layer that concatenates,
/// not just the last one.) Encoding `%` and `.` makes the join injective.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '.' => out.push_str("%2E"),
            _ => out.push(ch),
        }
    }
    out
}

/// Maximum accepted slot-label length. Bounded so a caller cannot drive an
/// unbounded filename or account string through this API.
const MAX_LABEL_LEN: usize = 128;

/// A slot, bound at the type level to one [`Purpose`].
///
/// Typed rather than carrying a `&'static str`: an untyped handle would let
/// a slot minted for one purpose be passed to a signing call for another and
/// still compile.
pub struct Slot<P: Purpose> {
    label: String,
    _purpose: PhantomData<fn() -> P>,
}

// Manual impls throughout this module rather than `#[derive]`: a derive adds
// a `P: Trait` bound, which would force every marker type implementing
// [`Purpose`] to also implement Debug/Clone/Eq purely so these wrappers can.
// The marker is phantom — it carries no data — so the bound is unnecessary.
impl<P: Purpose> std::fmt::Debug for Slot<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("purpose", &P::PURPOSE)
            .field("label", &self.label)
            .finish()
    }
}
impl<P: Purpose> Clone for Slot<P> {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            _purpose: PhantomData,
        }
    }
}
impl<P: Purpose> PartialEq for Slot<P> {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
    }
}
impl<P: Purpose> Eq for Slot<P> {}
impl<P: Purpose> std::hash::Hash for Slot<P> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        P::PURPOSE.hash(state);
        self.label.hash(state);
    }
}

impl<P: Purpose> Slot<P> {
    /// Bind `label` to this purpose.
    ///
    /// Rejects an over-long label rather than truncating: truncation would
    /// silently merge two distinct slots.
    pub fn new(label: impl Into<String>) -> Result<Self, KeystoreError> {
        let label = label.into();
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "slot label must be 1..={MAX_LABEL_LEN} bytes, got {}",
                label.len()
            )));
        }
        Ok(Self {
            label,
            _purpose: PhantomData,
        })
    }

    /// The caller-chosen label. The PURPOSE is deliberately not exposed as a
    /// runtime string here, and neither is the storage account: together
    /// those are exactly the coordinates a byte-oriented
    /// [`KeystoreBackend::get`] would need to read the scalar out from
    /// underneath this module.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    fn account(&self) -> String {
        format!(
            "p256.{}.{}",
            encode_component(P::PURPOSE),
            encode_component(&self.label)
        )
    }
}

/// At-rest protection actually in force. Derived from which store variant is
/// in use — never from a caller's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// Sealed by the store itself before anything reaches disk.
    SealedTpm,
    /// Plaintext in a `0600` file, explicitly approved.
    ApprovedPlaintextFile,
}

/// What a caller may know about a slot: purpose, label, public key, backing,
/// and which store instance holds it. No scalar, no ciphertext, no path.
///
/// The store identity is part of the binding so that
/// [`OpaqueP256Slots::load_exact`] can refuse a binding that was published
/// by a *different* store — otherwise a binding from a plaintext fallback
/// store could be presented to a TPM-backed one and vice versa.
pub struct PublicBinding<P: Purpose> {
    label: String,
    public_key: [u8; P256_PUBLIC_KEY_LEN],
    backing: Backing,
    store_id: String,
    _purpose: PhantomData<fn() -> P>,
}

impl<P: Purpose> std::fmt::Debug for PublicBinding<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicBinding")
            .field("purpose", &P::PURPOSE)
            .field("label", &self.label)
            .field("backing", &self.backing)
            .field("store_id", &self.store_id)
            .finish_non_exhaustive()
    }
}
impl<P: Purpose> Clone for PublicBinding<P> {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            public_key: self.public_key,
            backing: self.backing,
            store_id: self.store_id.clone(),
            _purpose: PhantomData,
        }
    }
}
impl<P: Purpose> PartialEq for PublicBinding<P> {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
            && self.public_key == other.public_key
            && self.backing == other.backing
            && self.store_id == other.store_id
    }
}
impl<P: Purpose> Eq for PublicBinding<P> {}

impl<P: Purpose> PublicBinding<P> {
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// SEC1-compressed public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; P256_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    #[must_use]
    pub fn backing(&self) -> Backing {
        self.backing
    }

    /// Opaque identifier of the store that published this binding.
    #[must_use]
    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    /// Verify `signature` over `preimage` against this binding's public key.
    pub fn verify(
        &self,
        preimage: &Preimage<P>,
        signature: &P256Signature<P>,
    ) -> Result<(), KeystoreError> {
        let vk = VerifyingKey::from_sec1_bytes(&self.public_key)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("sec1: {e}")))?;
        let sig = EcdsaSignature::from_slice(&signature.bytes)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("signature: {e}")))?;
        vk.verify(&preimage.bytes, &sig)
            .map_err(|_| KeystoreError::SigningFailed("signature does not verify".into()))
    }
}

/// Bytes to be signed, sealed to one [`Purpose`].
///
/// Constructed only through [`Preimage::seal`], which prefixes the purpose,
/// so the same message under two purposes produces different signed bytes.
/// Signing takes this type rather than `&[u8]`, which is what makes raw-byte
/// signing fail to compile.
pub struct Preimage<P: Purpose> {
    bytes: Vec<u8>,
    _purpose: PhantomData<fn() -> P>,
}

impl<P: Purpose> std::fmt::Debug for Preimage<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Preimage")
            .field("purpose", &P::PURPOSE)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl<P: Purpose> Clone for Preimage<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _purpose: PhantomData,
        }
    }
}

impl<P: Purpose> Preimage<P> {
    /// Domain-separate `message` under this purpose.
    #[must_use]
    pub fn seal(message: &[u8]) -> Self {
        let purpose = P::PURPOSE.as_bytes();
        let mut bytes = Vec::with_capacity(purpose.len() + 1 + message.len());
        bytes.extend_from_slice(purpose);
        // A zero separator that cannot occur in the purpose (a Rust &str
        // constant may contain NUL in principle, so the length prefix below
        // is what actually makes this unambiguous).
        bytes.push(0);
        bytes.extend_from_slice(message);
        Self {
            bytes,
            _purpose: PhantomData,
        }
    }
}

/// Raw `r || s` ECDSA P-256 signature, always canonical low-S, typed by the
/// purpose it was produced for.
pub struct P256Signature<P: Purpose> {
    bytes: [u8; P256_SIGNATURE_LEN],
    _purpose: PhantomData<fn() -> P>,
}

impl<P: Purpose> std::fmt::Debug for P256Signature<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256Signature")
            .field("purpose", &P::PURPOSE)
            .finish_non_exhaustive()
    }
}
impl<P: Purpose> Clone for P256Signature<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _purpose: PhantomData,
        }
    }
}
impl<P: Purpose> PartialEq for P256Signature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl<P: Purpose> Eq for P256Signature<P> {}

impl<P: Purpose> P256Signature<P> {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; P256_SIGNATURE_LEN] {
        self.bytes
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; P256_SIGNATURE_LEN] {
        &self.bytes
    }
}

/// Explicit opt-in to storing private scalars as plaintext at rest.
///
/// Impossible to obtain by `Default` and awkward on purpose, so the
/// unprotected path cannot be reached without a call site that names it.
#[derive(Debug, Clone)]
pub struct ApprovedFallback {
    reason: &'static str,
}

impl ApprovedFallback {
    /// Approve plaintext-at-rest for a stated reason. Legitimate reasons are
    /// narrow: a CI runner with no keystore, or pre-T2 Intel hardware with
    /// no Secure Enclave. Production hardware with a working sealing store
    /// must not use this.
    #[must_use]
    pub fn for_reason(reason: &'static str) -> Self {
        Self { reason }
    }

    #[must_use]
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

/// Secure Enclave backing: deliberately uninhabited rather than stubbed.
///
/// A stub that silently degraded to software would be worse than nothing —
/// callers would believe scalars were in hardware while they sat in a file.
/// With no variants, "this build has SE-backed slots" is unrepresentable
/// rather than merely untrue. Real support needs `SecKeyCreateRandomKey`
/// with `kSecAttrTokenIDSecureEnclave`, an access-control policy, and
/// measurement on SE hardware — none of which is done or verified here.
/// Note also that `MacosSystemKeystore` is Keychain, NOT Secure Enclave.
#[derive(Debug)]
pub enum SeBacking {}

/// Closed set of stores. Not public, and not extensible from outside this
/// crate — that is the point.
#[derive(Debug)]
enum SlotStore {
    #[cfg(target_os = "linux")]
    SealedTpm(crate::tpm_backend::TpmKeystore),
    ApprovedFile(FileKeystore),
}

impl SlotStore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.get(account),
            Self::ApprovedFile(s) => s.get(account),
        }
    }

    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.create_only(account, value),
            Self::ApprovedFile(s) => s.create_only(account, value),
        }
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.delete(account),
            Self::ApprovedFile(s) => s.delete(account),
        }
    }

    fn backing(&self) -> Backing {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(_) => Backing::SealedTpm,
            Self::ApprovedFile(_) => Backing::ApprovedPlaintextFile,
        }
    }
}

/// Purpose-bound P-256 slots.
#[derive(Debug)]
pub struct OpaqueP256Slots {
    store: SlotStore,
    store_id: String,
}

impl OpaqueP256Slots {
    /// Slots sealed to the host TPM. The scalar is encrypted by
    /// `systemd-creds` before any byte reaches the filesystem.
    ///
    /// Uses a service namespace distinct from the plaintext store's, so a
    /// TPM-sealed blob and a plaintext scalar can never land on the same
    /// path and be told apart only by a decrypt failure.
    #[cfg(target_os = "linux")]
    pub fn sealed_tpm(state_dir: impl AsRef<std::path::Path>, service: &str) -> Self {
        let namespaced = format!("{service}.p256-tpm");
        Self {
            store: SlotStore::SealedTpm(crate::tpm_backend::TpmKeystore::new(
                state_dir,
                namespaced.clone(),
            )),
            store_id: format!("tpm:{namespaced}"),
        }
    }

    /// Slots whose scalars rest as PLAINTEXT in `0600` files.
    #[must_use]
    pub fn approved_plaintext_file(
        state_dir: impl AsRef<std::path::Path>,
        service: &str,
        approval: &ApprovedFallback,
    ) -> Self {
        tracing::warn!(
            reason = approval.reason(),
            "P-256 private scalars will rest as PLAINTEXT; only appropriate where no \
             sealing store exists"
        );
        let namespaced = format!("{service}.p256-file");
        Self {
            store: SlotStore::ApprovedFile(FileKeystore::new(state_dir, namespaced.clone())),
            store_id: format!("file:{namespaced}"),
        }
    }

    /// At-rest protection in force for this store.
    #[must_use]
    pub fn backing(&self) -> Backing {
        self.store.backing()
    }

    /// Return the slot's binding, creating the key only if absent. Never
    /// overwrites.
    ///
    /// Inspects FIRST. That is what makes this converge after an ambiguous
    /// write: the durably stored key is authoritative and this call's freshly
    /// generated candidate is disposable, so a retry after a lost
    /// acknowledgement simply finds whatever landed instead of needing the
    /// original candidate to be preserved anywhere. A genuinely unresolved
    /// store state is reported as [`SlotOutcome::Unresolved`] rather than
    /// flattened into an I/O error, so a caller knows to retry rather than
    /// to give up.
    pub fn create_or_inspect<P: Purpose>(
        &self,
        slot: &Slot<P>,
    ) -> Result<(SlotOutcome, Option<PublicBinding<P>>), KeystoreError> {
        // 1. Already there?
        match self.try_binding(slot) {
            Ok(Some(binding)) => return Ok((SlotOutcome::AlreadyExisted, Some(binding))),
            Ok(None) => {}
            Err(e) => return Err(e),
        }

        // 2. Absent: mint. Generated here, zeroized before returning.
        let account = slot.account();
        let signing = SigningKey::random(&mut rand_core::OsRng);
        let mut scalar = signing.to_bytes();
        let outcome = self.store.create_only(&account, scalar.as_slice());
        scalar.zeroize();

        match outcome? {
            CreateOutcome::CreatedDurable => {
                let binding = self.binding_for(slot, signing.verifying_key())?;
                Ok((SlotOutcome::Created, Some(binding)))
            }
            // Someone else won, or our own earlier attempt did. Report what
            // is ACTUALLY stored, never our discarded candidate.
            CreateOutcome::ExistingExactDurable | CreateOutcome::Conflict => {
                match self.try_binding(slot)? {
                    Some(binding) => Ok((SlotOutcome::AlreadyExisted, Some(binding))),
                    None => Ok((SlotOutcome::Unresolved, None)),
                }
            }
            // Nothing landed; a retry may succeed.
            CreateOutcome::KnownNoEffect => Ok((SlotOutcome::Unresolved, None)),
            // Truly unresolved — refuse to mint a binding for a slot whose
            // stored state is unknown. Retry converges via the inspect-first
            // path above.
            CreateOutcome::MayHaveTakenEffect => match self.try_binding(slot)? {
                Some(binding) => Ok((SlotOutcome::AlreadyExisted, Some(binding))),
                None => Ok((SlotOutcome::Unresolved, None)),
            },
        }
    }

    /// Obtain a signer for a slot, proving it still holds the exact key
    /// described by `binding`.
    ///
    /// This is the ONLY way to sign. A key replaced underneath — for example
    /// by someone writing a different scalar through the generic byte API —
    /// derives a different public key, so the comparison fails and no
    /// signature is produced under a binding the caller published earlier.
    pub fn load_exact<P: Purpose>(
        &self,
        slot: &Slot<P>,
        binding: &PublicBinding<P>,
    ) -> Result<OpaqueSigner<P>, KeystoreError> {
        if binding.store_id != self.store_id {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: format!(
                    "binding was published by store {}, not {}",
                    binding.store_id, self.store_id
                ),
            });
        }
        if binding.backing != self.store.backing() {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: "binding's at-rest backing does not match this store".into(),
            });
        }
        if binding.label != slot.label {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: "binding describes a different slot label".into(),
            });
        }

        let signing = self.load_signing_key(slot)?;
        let derived = self.binding_for(slot, signing.verifying_key())?;
        if derived.public_key != binding.public_key {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: "stored key no longer matches the published binding — it was replaced".into(),
            });
        }
        Ok(OpaqueSigner {
            signing,
            _purpose: PhantomData,
        })
    }

    /// Best-effort removal of a slot's key.
    ///
    /// Reports what it observed rather than returning a bare unit: a caller
    /// revoking a key needs to distinguish "there was one and it is gone"
    /// from "there was nothing", because only the first is evidence that a
    /// revocation actually took effect.
    pub fn gc_best_effort<P: Purpose>(&self, slot: &Slot<P>) -> Result<GcReport, KeystoreError> {
        let existed = self.try_binding(slot)?.is_some();
        self.store.delete(&slot.account())?;
        let still_there = self.try_binding(slot)?.is_some();
        Ok(GcReport {
            existed_before: existed,
            present_after: still_there,
        })
    }

    /// Binding for a slot if it currently holds a usable key.
    fn try_binding<P: Purpose>(
        &self,
        slot: &Slot<P>,
    ) -> Result<Option<PublicBinding<P>>, KeystoreError> {
        match self.load_signing_key(slot) {
            Ok(signing) => Ok(Some(self.binding_for(slot, signing.verifying_key())?)),
            Err(KeystoreError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Materialise the signing key. PRIVATE, and the only place key material
    /// exists; every path zeroizes, including the error paths — a
    /// wrong-length buffer may still be a truncated real scalar, so dropping
    /// it unzeroized would leave key material in freed memory.
    fn load_signing_key<P: Purpose>(&self, slot: &Slot<P>) -> Result<SigningKey, KeystoreError> {
        let mut bytes = self.store.get(&slot.account())?;
        if bytes.len() != 32 {
            let len = bytes.len();
            bytes.zeroize();
            return Err(KeystoreError::InvalidKeyMaterial(format!(
                "slot holds {len} bytes, expected a 32-byte P-256 scalar"
            )));
        }
        let parsed = SigningKey::from_slice(&bytes);
        bytes.zeroize();
        parsed.map_err(|e| KeystoreError::InvalidKeyMaterial(format!("p256 from_slice: {e}")))
    }

    fn binding_for<P: Purpose>(
        &self,
        slot: &Slot<P>,
        verifying: &VerifyingKey,
    ) -> Result<PublicBinding<P>, KeystoreError> {
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
            label: slot.label.clone(),
            public_key,
            backing: self.store.backing(),
            store_id: self.store_id.clone(),
            _purpose: PhantomData,
        })
    }
}

/// A signer bound to one slot, obtained only from
/// [`OpaqueP256Slots::load_exact`] — so every signature is produced under a
/// key already proven to match a published binding.
pub struct OpaqueSigner<P: Purpose> {
    signing: SigningKey,
    _purpose: PhantomData<fn() -> P>,
}

impl<P: Purpose> std::fmt::Debug for OpaqueSigner<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material, not even accidentally through a
        // derived Debug on a struct that contains it.
        f.debug_struct("OpaqueSigner").finish_non_exhaustive()
    }
}

impl<P: Purpose> OpaqueSigner<P> {
    /// Sign a purpose-sealed preimage.
    ///
    /// Normalised to canonical low-S: P-256 accepts both `s` and `n - s` for
    /// the same message and key, so without this a third party could produce
    /// a second, equally valid encoding of any signature — and anything that
    /// identifies or dedupes by signature bytes (a revocation list, a
    /// transcript digest, an idempotency key) would be bypassable.
    #[must_use]
    pub fn sign(&self, preimage: &Preimage<P>) -> P256Signature<P> {
        let sig: EcdsaSignature = self.signing.sign(&preimage.bytes);
        let sig = sig.normalize_s().unwrap_or(sig);
        let raw = sig.to_bytes();
        let mut bytes = [0u8; P256_SIGNATURE_LEN];
        bytes.copy_from_slice(raw.as_slice());
        P256Signature {
            bytes,
            _purpose: PhantomData,
        }
    }
}

/// Outcome of [`OpaqueP256Slots::create_or_inspect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutcome {
    /// This call generated and durably installed the key.
    Created,
    /// A key was already present; this call left it untouched.
    AlreadyExisted,
    /// The store's state could not be resolved. Nothing usable was
    /// returned; retry with the same slot to converge.
    Unresolved,
}

/// What [`OpaqueP256Slots::gc_best_effort`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    /// A usable key was present before the removal.
    pub existed_before: bool,
    /// A usable key is STILL present afterwards — removal did not take
    /// effect, so a caller must not treat this as a completed revocation.
    pub present_after: bool,
}

/// The private scalar must not be reachable through any public API.
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueP256Slots, ApprovedFallback, Slot, Purpose};
/// struct P;
/// impl Purpose for P { const PURPOSE: &'static str = "p"; }
/// let a = ApprovedFallback::for_reason("t");
/// let s = OpaqueP256Slots::approved_plaintext_file("/tmp", "svc", &a);
/// let slot = Slot::<P>::new("l").unwrap();
/// let _ = s.scalar(&slot);
/// ```
///
/// A caller-supplied backend must not be injectable — that is how a spy
/// backend would capture the scalar:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::OpaqueP256Slots;
/// use keystore_rs::FileKeystore;
/// let _ = OpaqueP256Slots::with_sealing_backend(FileKeystore::new("/tmp", "s"));
/// ```
///
/// Raw bytes must not be signable — only a purpose-sealed preimage:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueSigner, Purpose};
/// struct P;
/// impl Purpose for P { const PURPOSE: &'static str = "p"; }
/// fn go(signer: &OpaqueSigner<P>) {
///     let _ = signer.sign(b"raw bytes");
/// }
/// ```
///
/// And a preimage sealed for one purpose must not be signable by another's
/// signer:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueSigner, Preimage, Purpose};
/// struct A;
/// impl Purpose for A { const PURPOSE: &'static str = "a"; }
/// struct B;
/// impl Purpose for B { const PURPOSE: &'static str = "b"; }
/// fn go(signer: &OpaqueSigner<A>) {
///     let other: Preimage<B> = Preimage::seal(b"m");
///     let _ = signer.sign(&other);
/// }
/// ```
#[cfg(doctest)]
struct ScalarIsUnreachable;

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct MeshSession;
    impl Purpose for MeshSession {
        const PURPOSE: &'static str = "mesh-session";
    }

    struct RosterSync;
    impl Purpose for RosterSync {
        const PURPOSE: &'static str = "roster-sync";
    }

    fn store(dir: &std::path::Path) -> OpaqueP256Slots {
        OpaqueP256Slots::approved_plaintext_file(
            dir,
            "opaque-p256-test",
            &ApprovedFallback::for_reason("unit test"),
        )
    }

    #[test]
    fn create_then_reinspect_is_stable_and_never_overwrites() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("device-a").unwrap();

        let (outcome, first) = s.create_or_inspect(&slot).unwrap();
        assert_eq!(outcome, SlotOutcome::Created);
        let first = first.unwrap();

        let (outcome, again) = s.create_or_inspect(&slot).unwrap();
        assert_eq!(outcome, SlotOutcome::AlreadyExisted);
        assert_eq!(first.public_key(), again.unwrap().public_key());
    }

    /// The store is a closed set: a plaintext file store reports plaintext,
    /// and there is no constructor that lets a caller assert otherwise.
    /// (The previous revision had a test of this same name that passed a
    /// plaintext `FileKeystore` into a `with_sealing_backend` constructor
    /// and asserted it reported SEALED — a test whose name claimed honesty
    /// while encoding the exact dishonesty. That constructor no longer
    /// exists.)
    #[test]
    fn backing_is_derived_from_the_store_not_from_a_caller_claim() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        assert_eq!(s.backing(), Backing::ApprovedPlaintextFile);

        let slot = Slot::<MeshSession>::new("backing").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        assert_eq!(binding.unwrap().backing(), Backing::ApprovedPlaintextFile);
    }

    #[test]
    fn distinct_purposes_never_share_a_key() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());

        let mesh = Slot::<MeshSession>::new("same-label").unwrap();
        let roster = Slot::<RosterSync>::new("same-label").unwrap();

        let (_, m) = s.create_or_inspect(&mesh).unwrap();
        let (outcome, r) = s.create_or_inspect(&roster).unwrap();
        assert_eq!(outcome, SlotOutcome::Created);
        assert_ne!(m.unwrap().public_key(), r.unwrap().public_key());
    }

    /// `("a", "b.c")` and `("a.b", "c")` must not collide. The unencoded
    /// join `p256.{purpose}.{label}` produced the same account for both.
    #[test]
    fn purpose_label_join_is_injective() {
        struct A;
        impl Purpose for A {
            const PURPOSE: &'static str = "a";
        }
        struct AB;
        impl Purpose for AB {
            const PURPOSE: &'static str = "a.b";
        }

        let one = Slot::<A>::new("b.c").unwrap().account();
        let two = Slot::<AB>::new("c").unwrap().account();
        assert_ne!(
            one, two,
            "distinct (purpose, label) pairs collided on one account: {one}"
        );
    }

    #[test]
    fn over_long_label_is_rejected_rather_than_truncated() {
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(Slot::<MeshSession>::new(long).is_err());
        assert!(Slot::<MeshSession>::new("").is_err());
    }

    #[test]
    fn signature_verifies_and_is_canonical_low_s() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("signer").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();
        let signer = s.load_exact(&slot, &binding).unwrap();

        for i in 0..32 {
            let pre = Preimage::<MeshSession>::seal(format!("m-{i}").as_bytes());
            let sig = signer.sign(&pre);
            binding.verify(&pre, &sig).unwrap();

            let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
            assert!(parsed.normalize_s().is_none(), "signature {i} was high-S");
        }
    }

    /// A signature made for one purpose must not verify as another, even
    /// with the same key — the preimage is domain-separated.
    #[test]
    fn signature_does_not_transfer_across_purposes() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("xfer").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();
        let signer = s.load_exact(&slot, &binding).unwrap();

        let sig = signer.sign(&Preimage::<MeshSession>::seal(b"message"));

        // Same key, same message bytes, different purpose framing.
        let vk = VerifyingKey::from_sec1_bytes(binding.public_key()).unwrap();
        let other = Preimage::<RosterSync>::seal(b"message");
        let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
        assert!(
            vk.verify(&other.bytes, &parsed).is_err(),
            "a mesh-session signature must not verify as roster-sync"
        );
    }

    /// P0-4: a key swapped underneath through the generic byte API must be
    /// caught before it can sign under the old published binding.
    #[test]
    fn replacement_underneath_is_refused_by_load_exact() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("replaced").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();

        // Swap A for B behind the module's back.
        let raw = FileKeystore::new(td.path(), "opaque-p256-test.p256-file");
        let other = SigningKey::random(&mut rand_core::OsRng);
        raw.set(&slot.account(), other.to_bytes().as_slice())
            .unwrap();

        match s.load_exact(&slot, &binding) {
            Err(KeystoreError::SecurityViolation { hint, .. }) => {
                assert!(hint.contains("replaced"), "hint={hint}");
            }
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
    }

    #[test]
    fn binding_from_a_different_store_is_refused() {
        let td = tempfile::tempdir().unwrap();
        let a = store(td.path());
        let b = OpaqueP256Slots::approved_plaintext_file(
            td.path(),
            "other-service",
            &ApprovedFallback::for_reason("unit test"),
        );
        let slot = Slot::<MeshSession>::new("cross").unwrap();
        let (_, binding) = a.create_or_inspect(&slot).unwrap();

        match b.load_exact(&slot, &binding.unwrap()) {
            Err(KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
    }

    #[test]
    fn gc_reports_what_it_observed() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("gc").unwrap();

        let absent = s.gc_best_effort(&slot).unwrap();
        assert_eq!(
            absent,
            GcReport {
                existed_before: false,
                present_after: false
            }
        );

        s.create_or_inspect(&slot).unwrap();
        let removed = s.gc_best_effort(&slot).unwrap();
        assert_eq!(
            removed,
            GcReport {
                existed_before: true,
                present_after: false
            },
            "a real revocation must be distinguishable from a no-op"
        );
    }

    #[test]
    fn corrupt_slot_is_rejected_without_echoing_content() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("corrupt").unwrap();

        let raw = FileKeystore::new(td.path(), "opaque-p256-test.p256-file");
        raw.set(&slot.account(), b"too short").unwrap();

        match s.create_or_inspect(&slot) {
            Err(KeystoreError::InvalidKeyMaterial(msg)) => {
                assert!(msg.contains("expected a 32-byte P-256 scalar"), "msg={msg}");
                assert!(!msg.contains("too short"), "must not echo content: {msg}");
            }
            other => panic!("expected InvalidKeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_creation_agrees_on_one_key() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let s = Arc::new(store(td.path()));
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));

        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let s = s.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let slot = Slot::<MeshSession>::new("raced").unwrap();
                    barrier.wait();
                    s.create_or_inspect(&slot).unwrap()
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let keys: Vec<_> = results
            .iter()
            .filter_map(|(_, b)| b.as_ref().map(PublicBinding::public_key))
            .collect();
        assert!(!keys.is_empty(), "at least one racer must resolve a key");
        for k in &keys {
            assert_eq!(*k, keys[0], "racers disagreed about the slot's key");
        }
    }
}
