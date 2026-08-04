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

use crate::file_backend::DeleteOutcome;
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
    /// Stable label that domain-separates STORAGE: it is hashed into the
    /// canonical slot id, so changing it orphans existing keys. Treat it as
    /// a wire constant.
    ///
    /// It is NOT part of the signed preimage. [`Preimage::exact`] signs the
    /// caller's canonical bytes verbatim, because theyOS wire formats
    /// freeze the signed preimage and any framing added here would produce
    /// signatures no verifier accepts. (An earlier revision did prepend
    /// `PURPOSE || 0x00` and this doc still described that behaviour after
    /// the code stopped doing it — a stale claim of cryptographic domain
    /// separation is worse than none, because a caller would rely on it.)
    ///
    /// Cross-purpose misuse is prevented at COMPILE time instead: a
    /// `Preimage<A>` cannot reach an `OpaqueSigner<B>`. Two purposes
    /// signing identical bytes with the same key therefore produce
    /// identical signatures; where a protocol needs cryptographic
    /// separation, that protocol must put it in the bytes it hands here.
    const PURPOSE: &'static str;
}

// The percent-encoding helper that used to live here is gone: the
// canonical slot id (see `Slot::account`) now digests LENGTH-PREFIXED
// components, which is injective by construction rather than by escaping
// rules that have to be applied correctly at every layer that
// concatenates. Deleted rather than left behind, so nothing can call a
// weaker encoding by mistake.

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

    /// Canonical versioned slot id: `p256.v1.<64 hex>`.
    ///
    /// Fixed-width regardless of purpose or label length, and injective
    /// because the digest is taken over LENGTH-PREFIXED components — the
    /// concatenation `purpose || label` on its own is not injective, which
    /// is the same defect that produced colliding accounts earlier in this
    /// module and colliding paths one layer below it. Length prefixes make
    /// `("a","b.c")` and `("a.b","c")` distinct preimages by construction
    /// rather than by escaping rules that have to be got right at every
    /// layer.
    ///
    /// Fixed width also removes truncation as a failure mode: an over-long
    /// label is rejected at [`Slot::new`] rather than silently shortened
    /// into a collision with another slot.
    fn account(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            &u64::try_from(P::PURPOSE.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(P::PURPOSE.as_bytes());
        hasher.update(
            &u64::try_from(self.label.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.label.as_bytes());
        format!("p256.v1.{}", hasher.finalize().to_hex())
    }
}

/// Account name of the store-identity marker. Inside the reserved
/// namespace, so it is unreachable through the public byte API.
const STORE_IDENTITY_ACCOUNT: &str = "store-identity.v1";

/// Prefix tagging the marker's contents with its format version, so a
/// future format is a recognisable mismatch rather than a silent
/// misinterpretation.
const STORE_IDENTITY_PREFIX: &str = "storeidv1:";

/// A store's durable identity: 256 random bits, written once and read back
/// on every restart.
///
/// This is what a [`PublicBinding`] is scoped to. Device+inode was used
/// before and is the wrong tool for the job: it is a fine handle guard
/// WHILE an operation is in flight (it detects a directory swapped under
/// an open fd) but it is not stable across a remount or a restore, so a
/// binding scoped to it would spuriously stop validating after either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreIdentityV1(String);

impl StoreIdentityV1 {
    fn generate() -> Self {
        use rand_core::RngCore;
        let mut raw = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut raw);
        let hex = raw.iter().fold(String::with_capacity(64), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        Self(format!("{STORE_IDENTITY_PREFIX}{hex}"))
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let hex = text.strip_prefix(STORE_IDENTITY_PREFIX)?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(text.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
/// Carries the caller's canonical bytes VERBATIM — this type adds no
/// framing of its own, because theyOS wire formats freeze the signed
/// preimage exactly and anything extra yields a signature no verifier
/// accepts. The purpose binding is at the type level: signing takes
/// `Preimage<P>` rather than `&[u8]`, so raw-byte signing and cross-purpose
/// signing both fail to compile.
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
    /// Accept the EXACT bytes a protocol says are to be signed, adding
    /// nothing.
    ///
    /// An earlier revision prepended `PURPOSE || 0x00` here as home-made
    /// domain separation. That was wrong on two counts. It produced
    /// signatures over bytes no verifier expects — theyOS wire formats
    /// freeze the signed preimage exactly (`type_byte || canonical_cbor`),
    /// so extra framing yields a signature that simply fails against the
    /// real contract. And the separation it claimed was not sound anyway:
    /// the doc justified it by a length prefix that was never implemented,
    /// and a `PURPOSE` containing NUL would have collided regardless.
    ///
    /// Purpose separation here is by TYPE — a `Preimage<A>` cannot be handed
    /// to an `OpaqueSigner<B>` — which prevents the mistake at compile time
    /// without inventing bytes. Where a protocol needs *cryptographic*
    /// domain separation it must define that framing itself, and the caller
    /// passes the already-canonical result in here.
    #[must_use]
    pub fn exact(canonical_bytes: &[u8]) -> Self {
        Self {
            bytes: canonical_bytes.to_vec(),
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
    /// Read a slot's stored material through the HARDENED, durability-proving
    /// path — never [`KeystoreBackend::get`], which opens by pathname,
    /// follows a final symlink, is uncapped, and proves nothing about
    /// durability. Using it here is what let a symlinked slot load
    /// successfully and let a merely-visible key be reported as an existing
    /// one.
    ///
    /// `Ok(None)` means genuinely absent. Anything unproven is an error, not
    /// a value.
    fn secure_durable_get(&self, account: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => {
                // Fetch and prove the CIPHERTEXT through the same hardened
                // path the file store uses, then decrypt. The decrypt must
                // not be what decides existence.
                match s.file_store().secure_durable_get(account)? {
                    Some(ciphertext) => {
                        match crate::tpm_backend::TpmKeystore::decrypt_blob(account, &ciphertext) {
                            Ok(plain) => Ok(Some(plain)),
                            // A blob that is present and durable but will not
                            // decrypt is a PERMANENT condition — corruption,
                            // a cleared or replaced TPM, a host migration —
                            // not the transient ambiguity a caller should
                            // retry through. Surfacing it as a security
                            // violation keeps it distinguishable from
                            // "unresolved, try again", which would otherwise
                            // spin forever against material that will never
                            // decrypt on this host.
                            Err(e) => Err(KeystoreError::SecurityViolation {
                                label: account.to_string(),
                                hint: format!(
                                    "sealed material exists and is durable but does not decrypt \
                                     on this host ({}); this does not resolve by retrying — the \
                                     credential must be re-added",
                                    e.kind()
                                ),
                            }),
                        }
                    }
                    None => Ok(None),
                }
            }
            Self::ApprovedFile(s) => s.secure_durable_get(account),
        }
    }

    /// Interpret raw stored bytes as plaintext key material: identity for
    /// the file store, decryption for TPM.
    // Infallible on targets where the only variant is the plain file store,
    // but the TPM arm decrypts and genuinely can fail. Keeping one
    // signature across targets beats a cfg-split return type.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
    fn interpret(&self, account: &str, stored: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(_) => crate::tpm_backend::TpmKeystore::decrypt_blob(account, stored),
            Self::ApprovedFile(_) => {
                let _ = account;
                Ok(stored.to_vec())
            }
        }
    }

    fn delete_exact_locked(
        &self,
        account: &str,
        matches: impl FnOnce(&[u8]) -> Result<bool, KeystoreError>,
    ) -> Result<DeleteOutcome, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.file_store().delete_exact_locked(account, matches),
            Self::ApprovedFile(s) => s.delete_exact_locked(account, matches),
        }
    }

    fn has_entries_besides(&self, exclude: &str) -> Result<bool, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.file_store().has_entries_besides(exclude),
            Self::ApprovedFile(s) => s.has_entries_besides(exclude),
        }
    }

    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.create_only(account, value),
            Self::ApprovedFile(s) => s.create_only(account, value),
        }
    }

    // An unconditional `delete` shim used to sit here and is gone on
    // purpose: every removal in this module must go through
    // `delete_exact_locked`, which compares and unlinks as one locked,
    // durably-synced operation. Leaving a plain delete reachable is how the
    // check-then-act GC race existed in the first place.

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
    /// Resolved once per handle. Caching matters for correctness as well as
    /// I/O: the quarantine rule keys off "material exists but no marker
    /// does", so re-deriving it repeatedly during a single logical
    /// operation would be both wasteful and easy to get wrong.
    identity: std::sync::OnceLock<StoreIdentityV1>,
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
        let namespaced = format!(
            "{service}{}-tpm",
            crate::file_backend::RESERVED_OPAQUE_NAMESPACE_MARKER
        );
        Self {
            store: SlotStore::SealedTpm(
                crate::tpm_backend::TpmKeystore::new_for_reserved_namespace(
                    state_dir,
                    namespaced.clone(),
                ),
            ),
            store_id: format!("tpm:{namespaced}"),
            identity: std::sync::OnceLock::new(),
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
        // Reserved namespace + the `pub(crate)` capability constructor: a
        // downstream can name this service but every operation from a
        // publicly-built handle fails closed, so the scalar is not
        // reachable through the generic byte API.
        let namespaced = format!(
            "{service}{}-file",
            crate::file_backend::RESERVED_OPAQUE_NAMESPACE_MARKER
        );
        Self {
            store: SlotStore::ApprovedFile(FileKeystore::new_for_reserved_namespace(
                state_dir,
                namespaced.clone(),
            )),
            store_id: format!("file:{namespaced}"),
            identity: std::sync::OnceLock::new(),
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
        // 0. Establish the store's durable identity BEFORE any key material
        //    can exist. Ordering is load-bearing, not tidiness: the
        //    quarantine rule refuses to mint a marker over existing
        //    material, so resolving it after creating the first slot would
        //    quarantine every brand-new store on its own first write.
        //
        //    An I/O failure here means the store's identity could not be
        //    committed, so nothing usable can be returned — but that is
        //    ambiguity, not absence, and it is retryable, so it maps to
        //    Unresolved. A SecurityViolation (quarantine) is NOT retryable
        //    and must keep propagating: it needs a human, not another
        //    attempt.
        if let Err(e) = self.resolve_identity() {
            match e {
                KeystoreError::Io { .. } => return Ok((SlotOutcome::Unresolved, None)),
                other => return Err(other),
            }
        }

        // 1. Already there? `try_binding` goes through the hardened,
        //    durability-proving reader, so reaching a binding here means the
        //    stored key was proven durable on the same descriptors it was
        //    read from — not merely that a file was visible. That
        //    distinction is the whole point: an audit showed this shortcut
        //    reporting AlreadyExisted for a key that existed only because a
        //    directory barrier had failed, which is exactly the
        //    visibility-is-not-durability error this crate exists to avoid
        //    one layer down.
        //
        //    An entry that cannot be proven durable surfaces as an error
        //    from the reader and is mapped to Unresolved below, never to a
        //    usable binding.
        match self.try_binding(slot) {
            Ok(Some(binding)) => return Ok((SlotOutcome::AlreadyExisted, Some(binding))),
            Ok(None) => {}
            Err(KeystoreError::Io { .. }) => return Ok((SlotOutcome::Unresolved, None)),
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
                match self.binding_or_unresolved(slot)? {
                    Some(binding) => Ok((SlotOutcome::AlreadyExisted, Some(binding))),
                    None => Ok((SlotOutcome::Unresolved, None)),
                }
            }
            // Nothing landed; a retry may succeed.
            CreateOutcome::KnownNoEffect => Ok((SlotOutcome::Unresolved, None)),
            // Truly unresolved — refuse to mint a binding for a slot whose
            // stored state is unknown. Retry converges via the inspect-first
            // path above.
            CreateOutcome::MayHaveTakenEffect => match self.binding_or_unresolved(slot)? {
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
        let expected_store = self.composed_store_id()?;
        if binding.store_id != expected_store {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: format!(
                    "binding was published by store {}, not {expected_store}",
                    binding.store_id
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
    /// Remove a slot's key ONLY if it still holds exactly the key described
    /// by `expected`.
    ///
    /// Conditional rather than unconditional on purpose. An unconditional
    /// `gc(slot)` collecting generation A will happily destroy generation B
    /// if B replaced A in the meantime — the caller asked to retire one key
    /// and silently destroyed a different, possibly live one. A mismatch is
    /// therefore reported, never deleted: refusing is recoverable, deleting
    /// a key nobody has a copy of is not.
    pub fn gc_exact<P: Purpose>(
        &self,
        slot: &Slot<P>,
        expected: &PublicBinding<P>,
    ) -> Result<GcReport, KeystoreError> {
        // Compare and remove as ONE locked operation. Comparing here and
        // deleting afterwards was check-then-act: a writer installing B
        // between the two destroyed B, and the resulting absence was not
        // durable either.
        let expected_key = *expected.public_key();
        let outcome = self.store.delete_exact_locked(&slot.account(), |stored| {
            let material = Self::interpret_stored(&self.store, &slot.account(), stored)?;
            let Some(signing) = material else {
                return Ok(false);
            };
            let encoded = signing.verifying_key().to_encoded_point(true);
            Ok(encoded.as_bytes() == expected_key.as_slice())
        })?;

        Ok(match outcome {
            DeleteOutcome::Removed => GcReport {
                existed_before: true,
                matched_expected: true,
                present_after: false,
            },
            DeleteOutcome::Absent => GcReport {
                existed_before: false,
                matched_expected: false,
                present_after: false,
            },
            DeleteOutcome::Mismatch => GcReport {
                existed_before: true,
                matched_expected: false,
                present_after: true,
            },
        })
    }

    /// Turn stored bytes into a signing key, applying the store's own
    /// interpretation (TPM ciphertext must be decrypted first). Returns
    /// `None` when the bytes are not usable key material at all.
    fn interpret_stored(
        store: &SlotStore,
        account: &str,
        stored: &[u8],
    ) -> Result<Option<SigningKey>, KeystoreError> {
        let mut plain = store.interpret(account, stored)?;
        if plain.len() != 32 {
            plain.zeroize();
            return Ok(None);
        }
        let parsed = SigningKey::from_slice(&plain);
        plain.zeroize();
        Ok(parsed.ok())
    }

    /// This store's full identity: namespace plus its durable
    /// [`StoreIdentityV1`].
    ///
    /// Deliberately NOT device+inode. That is a good handle guard while an
    /// operation is in flight — [`FileKeystore::secure_durable_get`] still
    /// uses it to detect a directory or file swapped under an open fd — but
    /// it is not stable across a remount or a restore, so a binding scoped
    /// to it would stop validating after either, for no security reason.
    fn composed_store_id(&self) -> Result<String, KeystoreError> {
        Ok(format!("{}|{}", self.store_id, self.resolve_identity()?.0))
    }

    /// Read this store's durable identity, creating it exactly once for a
    /// genuinely empty store.
    ///
    /// Restore policy, stated explicitly because the failure modes differ
    /// sharply:
    ///
    /// - Marker present and well-formed → that identity, so a backup
    ///   restored WITH its marker keeps its bindings valid.
    /// - Marker absent and the store holds no material → mint one, commit
    ///   it durably via `create_only`.
    /// - Marker absent or malformed while material EXISTS → quarantine,
    ///   fail closed. Minting a fresh marker over existing key material
    ///   would silently re-identify keys that were bound to a different
    ///   store, which is exactly the confusion the identity exists to
    ///   prevent; refusing is recoverable, re-identifying is not.
    fn resolve_identity(&self) -> Result<StoreIdentityV1, KeystoreError> {
        if let Some(cached) = self.identity.get() {
            return Ok(cached.clone());
        }
        let resolved = self.resolve_identity_uncached()?;
        // A concurrent resolve may have won; either value is the same
        // durable marker, so ignore the race loser.
        let _ = self.identity.set(resolved.clone());
        Ok(resolved)
    }

    fn resolve_identity_uncached(&self) -> Result<StoreIdentityV1, KeystoreError> {
        if let Some(raw) = self.store.secure_durable_get(STORE_IDENTITY_ACCOUNT)? {
            return StoreIdentityV1::parse(&raw).ok_or_else(|| KeystoreError::SecurityViolation {
                label: STORE_IDENTITY_ACCOUNT.into(),
                hint: "store identity marker is present but malformed; refusing to guess an \
                       identity for existing key material (quarantine)"
                    .into(),
            });
        }

        if self.store.has_entries_besides(STORE_IDENTITY_ACCOUNT)? {
            return Err(KeystoreError::SecurityViolation {
                label: STORE_IDENTITY_ACCOUNT.into(),
                hint: "store holds key material but no identity marker; refusing to mint a new \
                       one over it (quarantine) — restore the marker alongside the material"
                    .into(),
            });
        }

        let minted = StoreIdentityV1::generate();
        match self
            .store
            .create_only(STORE_IDENTITY_ACCOUNT, minted.0.as_bytes())?
        {
            CreateOutcome::CreatedDurable => Ok(minted),
            // Someone else minted first — theirs wins; read it back.
            CreateOutcome::ExistingExactDurable | CreateOutcome::Conflict => {
                match self.store.secure_durable_get(STORE_IDENTITY_ACCOUNT)? {
                    Some(raw) => StoreIdentityV1::parse(&raw).ok_or_else(|| {
                        KeystoreError::SecurityViolation {
                            label: STORE_IDENTITY_ACCOUNT.into(),
                            hint: "concurrently-written store identity marker is malformed".into(),
                        }
                    }),
                    None => Err(KeystoreError::Io {
                        kind: "store identity vanished".into(),
                        hint: "identity marker disappeared immediately after being written".into(),
                    }),
                }
            }
            CreateOutcome::KnownNoEffect | CreateOutcome::MayHaveTakenEffect => {
                Err(KeystoreError::Io {
                    kind: "store identity not committed".into(),
                    hint: "could not durably commit a store identity marker; retry".into(),
                })
            }
        }
    }

    /// Report a slot's binding WITHOUT ever creating one.
    ///
    /// Separate from [`Self::create_or_inspect`] because "tell me what is
    /// there" and "make sure something is there" are different
    /// authorisations: a caller auditing or validating must not be able to
    /// mint key material as a side effect of looking.
    pub fn inspect<P: Purpose>(
        &self,
        slot: &Slot<P>,
    ) -> Result<Option<PublicBinding<P>>, KeystoreError> {
        self.try_binding(slot)
    }

    /// [`Self::try_binding`], with an unprovable store state folded into
    /// `Unresolved` instead of escaping as an error.
    ///
    /// Every branch of `create_or_inspect` needs this, not just the first:
    /// the post-create branches re-inspect too, and propagating there let
    /// exactly the ambiguity this is meant to contain leak out as an `Io`
    /// error instead of the typed outcome a caller can retry on.
    fn binding_or_unresolved<P: Purpose>(
        &self,
        slot: &Slot<P>,
    ) -> Result<Option<PublicBinding<P>>, KeystoreError> {
        match self.try_binding(slot) {
            Ok(found) => Ok(found),
            Err(KeystoreError::Io { .. }) => Ok(None),
            Err(e) => Err(e),
        }
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
        let Some(mut bytes) = self.store.secure_durable_get(&slot.account())? else {
            return Err(KeystoreError::NotFound {
                label: slot.label.clone(),
            });
        };
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
            // Physical identity (dev+ino of the secrets directory), resolved
            // now rather than baked in at construction from a service string:
            // two stores sharing a service name under different state roots
            // used to produce identical ids, so one's binding validated
            // against the other's key material.
            store_id: self.composed_store_id()?,
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

/// What [`OpaqueP256Slots::gc_exact`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    /// A usable key was present before the removal.
    pub existed_before: bool,
    /// The key present matched the binding the caller expected to collect.
    /// When false with `existed_before` true, a DIFFERENT key occupies the
    /// slot and was deliberately left alone.
    pub matched_expected: bool,
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
///     let other: Preimage<B> = Preimage::exact(b"m");
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

    /// A handle into the reserved namespace, for tests that must simulate
    /// tampering with stored key material.
    ///
    /// These tests deliberately need the `pub(crate)` capability
    /// constructor now: the same tampering used to be possible with the
    /// PUBLIC `FileKeystore::new`, which is exactly the hole the
    /// reservation closes. That these adversarial fixtures no longer
    /// compile against the public API is itself evidence the boundary
    /// holds — and it also names the residual threat model honestly, since
    /// this stands in for an actor who can write the files directly rather
    /// than one merely holding the crate's public types.
    fn raw_reserved(dir: &std::path::Path, service_base: &str) -> FileKeystore {
        FileKeystore::new_for_reserved_namespace(
            dir,
            format!(
                "{service_base}{}-file",
                crate::file_backend::RESERVED_OPAQUE_NAMESPACE_MARKER
            ),
        )
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
            let pre = Preimage::<MeshSession>::exact(format!("m-{i}").as_bytes());
            let sig = signer.sign(&pre);
            binding.verify(&pre, &sig).unwrap();

            let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
            assert!(parsed.normalize_s().is_none(), "signature {i} was high-S");
        }
    }

    /// The signed bytes must be EXACTLY what the caller supplied.
    ///
    /// theyOS wire formats freeze the signed preimage precisely
    /// (`type_byte || canonical_cbor`), so any framing this crate adds of
    /// its own produces a signature that no real verifier accepts. A
    /// previous revision prepended `PURPOSE || 0x00` as home-made domain
    /// separation and had a test asserting that a signature did not
    /// transfer across purposes — which passed, but only because of bytes
    /// that broke the actual contract. The honest guarantee is narrower and
    /// is asserted here: nothing is added.
    ///
    /// Cross-purpose misuse is prevented at COMPILE time instead (a
    /// `Preimage<A>` cannot reach an `OpaqueSigner<B>`; see the
    /// `compile_fail` doctests). Where a protocol needs cryptographic
    /// domain separation, that protocol defines the framing and hands the
    /// canonical result in.
    #[test]
    fn preimage_signs_exactly_the_supplied_bytes_and_adds_no_framing() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("exact-bytes").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();
        let signer = s.load_exact(&slot, &binding).unwrap();

        let wire = b"\x07canonical-cbor-body";
        let sig = signer.sign(&Preimage::<MeshSession>::exact(wire));

        // A verifier that knows only the protocol's own bytes must accept —
        // it would not if we had prepended anything.
        let vk = VerifyingKey::from_sec1_bytes(binding.public_key()).unwrap();
        let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
        vk.verify(wire.as_slice(), &parsed)
            .expect("signature must be over the caller's exact bytes, with no added framing");
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
        let raw = raw_reserved(td.path(), "opaque-p256-test");
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

    /// Ported verbatim from the independent audit's RED for b3849669. Two
    /// stores under different state roots that merely share a service name
    /// used to produce identical `store_id`s, so a binding published by one
    /// validated against key material copied into the other.
    #[test]
    fn binding_is_scoped_to_physical_store_not_only_service_name() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let approval = ApprovedFallback::for_reason("audit-only fixture");
        let a = OpaqueP256Slots::approved_plaintext_file(a_dir.path(), "same-service", &approval);
        let b = OpaqueP256Slots::approved_plaintext_file(b_dir.path(), "same-service", &approval);
        let slot = Slot::<MeshSession>::new("copied").unwrap();
        let (_, binding) = a.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();

        let raw_a = raw_reserved(a_dir.path(), "same-service");
        let raw_b = raw_reserved(b_dir.path(), "same-service");
        let scalar = raw_a.get(&slot.account()).unwrap();
        raw_b.set(&slot.account(), &scalar).unwrap();

        assert!(
            b.load_exact(&slot, &binding).is_err(),
            "binding from one state root was accepted by a different physical store"
        );
    }

    /// Ported verbatim from the independent audit's RED for b3849669. Opaque
    /// loads went through the legacy path-based `get`, which follows a
    /// final-component symlink — letting a same-UID actor redirect a
    /// supposedly store-scoped slot at bytes outside the store while the
    /// content still matched the published binding.
    #[test]
    fn load_exact_rejects_symlinked_slot_even_when_bytes_match() {
        use std::os::unix::fs::symlink;

        let td = tempfile::tempdir().unwrap();
        let approval = ApprovedFallback::for_reason("audit-only fixture");
        let slots = OpaqueP256Slots::approved_plaintext_file(td.path(), "symlink", &approval);
        let slot = Slot::<MeshSession>::new("redirected").unwrap();
        let (_, binding) = slots.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();

        let raw = raw_reserved(td.path(), "symlink");
        let scalar = raw.get(&slot.account()).unwrap();
        let account_path = raw.path_for(&slot.account());
        let outside = td.path().join("outside-scalar");
        std::fs::write(&outside, scalar).unwrap();
        std::fs::remove_file(&account_path).unwrap();
        symlink(&outside, &account_path).unwrap();

        assert!(
            slots.load_exact(&slot, &binding).is_err(),
            "load_exact followed a final-component symlink outside the store"
        );
    }

    /// THE containment test. A downstream holds the public byte API and the
    /// slot coordinates are deterministic, so before the namespace was
    /// reserved it could simply rebuild the store and read the scalar —
    /// which made the `compile_fail` "no accessor" proofs beside the point.
    /// Every operation from a publicly-constructed handle must now fail
    /// closed on the reserved namespace.
    #[test]
    fn reserved_namespace_is_unreachable_through_the_public_byte_api() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("contained").unwrap();
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        assert!(binding.is_some(), "fixture must actually create a key");

        // Reconstruct exactly what the opaque store uses, the way a
        // determined downstream would.
        let reserved_service = format!(
            "opaque-p256-test{}-file",
            crate::file_backend::RESERVED_OPAQUE_NAMESPACE_MARKER
        );
        let attacker = FileKeystore::new(td.path(), &reserved_service);

        for outcome in [
            attacker.get(&slot.account()).err(),
            attacker.set(&slot.account(), b"overwrite").err(),
            attacker.delete(&slot.account()).err(),
            attacker.create_only(&slot.account(), b"x").err(),
        ] {
            match outcome {
                Some(KeystoreError::Unsupported { hint }) => {
                    assert!(hint.contains("reserved"), "hint={hint}");
                }
                other => panic!("reserved namespace was reachable: {other:?}"),
            }
        }

        // And the key is untouched: the opaque API still loads it.
        assert!(s.try_binding(&slot).unwrap().is_some());
    }

    /// The reservation must not break the rest of the crate: ordinary
    /// services keep working exactly as before.
    #[test]
    fn ordinary_services_are_unaffected_by_the_reservation() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "ordinary-service");
        ks.set("acct", b"value").unwrap();
        assert_eq!(ks.get("acct").unwrap(), b"value");
    }

    #[test]
    fn gc_reports_what_it_observed() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("gc").unwrap();

        // Nothing there: a binding is still required, so mint-and-collect.
        let (_, binding) = s.create_or_inspect(&slot).unwrap();
        let binding = binding.unwrap();

        let removed = s.gc_exact(&slot, &binding).unwrap();
        assert_eq!(
            removed,
            GcReport {
                existed_before: true,
                matched_expected: true,
                present_after: false
            },
            "a real revocation must be distinguishable from a no-op"
        );

        let again = s.gc_exact(&slot, &binding).unwrap();
        assert_eq!(
            again,
            GcReport {
                existed_before: false,
                matched_expected: false,
                present_after: false
            }
        );
    }

    /// Collecting generation A must NOT destroy generation B if B replaced
    /// A in the meantime. Refusing is recoverable; deleting a live key that
    /// nobody else holds a copy of is not.
    #[test]
    fn gc_refuses_to_collect_a_different_generation() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("wrong-generation").unwrap();

        let (_, gen_a) = s.create_or_inspect(&slot).unwrap();
        let gen_a = gen_a.unwrap();

        // B replaces A behind the module's back.
        let raw = raw_reserved(td.path(), "opaque-p256-test");
        let other = SigningKey::random(&mut rand_core::OsRng);
        raw.set(&slot.account(), other.to_bytes().as_slice())
            .unwrap();

        let report = s.gc_exact(&slot, &gen_a).unwrap();
        assert_eq!(
            report,
            GcReport {
                existed_before: true,
                matched_expected: false,
                present_after: true
            },
            "collecting A must leave B alone"
        );
        // And B really is still there.
        assert!(s.try_binding(&slot).unwrap().is_some());
    }

    #[test]
    fn corrupt_slot_is_rejected_without_echoing_content() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());

        // Initialise the store first so its identity marker exists.
        // Otherwise planting material into a marker-less store trips the
        // quarantine rule and we would be testing that instead of the
        // corrupt-slot handling we mean to exercise.
        s.create_or_inspect(&Slot::<MeshSession>::new("initialiser").unwrap())
            .unwrap();

        let slot = Slot::<MeshSession>::new("corrupt").unwrap();
        let raw = raw_reserved(td.path(), "opaque-p256-test");
        raw.set(&slot.account(), b"too short").unwrap();

        match s.create_or_inspect(&slot) {
            Err(KeystoreError::InvalidKeyMaterial(msg)) => {
                assert!(msg.contains("expected a 32-byte P-256 scalar"), "msg={msg}");
                assert!(!msg.contains("too short"), "must not echo content: {msg}");
            }
            other => panic!("expected InvalidKeyMaterial, got {other:?}"),
        }
    }

    /// Restore policy, all three arms.
    #[test]
    fn store_identity_restore_policy() {
        let td = tempfile::tempdir().unwrap();
        let slot = Slot::<MeshSession>::new("identity").unwrap();

        // Empty store mints once and is stable across reopen.
        let first = store(td.path());
        let (_, binding) = first.create_or_inspect(&slot).unwrap();
        let original = binding.unwrap();

        let reopened = store(td.path());
        let after_restart = reopened.inspect(&slot).unwrap().unwrap();
        assert_eq!(
            original, after_restart,
            "binding must be reconstructible after restart: marker + material preserved together"
        );

        // Marker removed while material remains → quarantine, never a
        // freshly minted identity over existing keys.
        let raw = raw_reserved(td.path(), "opaque-p256-test");
        raw.delete(STORE_IDENTITY_ACCOUNT).unwrap();
        let orphaned = store(td.path());
        match orphaned.inspect(&slot) {
            Err(KeystoreError::SecurityViolation { hint, .. }) => {
                assert!(hint.contains("quarantine"), "hint={hint}");
            }
            other => panic!("expected quarantine, got {other:?}"),
        }

        // Malformed marker is equally refused, not guessed at.
        raw.set(STORE_IDENTITY_ACCOUNT, b"not-a-store-identity")
            .unwrap();
        let malformed = store(td.path());
        assert!(matches!(
            malformed.inspect(&slot),
            Err(KeystoreError::SecurityViolation { .. })
        ));
    }

    /// `inspect` must never create.
    #[test]
    fn inspect_never_creates() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("never-made").unwrap();

        assert!(s.inspect(&slot).unwrap().is_none());
        assert!(
            s.inspect(&slot).unwrap().is_none(),
            "a second inspect must still find nothing — inspecting is not creating"
        );
    }

    /// The slot id must be fixed-width and injective over length-prefixed
    /// components, so no pair of (purpose, label) can collide.
    #[test]
    fn slot_id_is_fixed_width_and_injective() {
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
        assert_ne!(one, two);
        assert_eq!(one.len(), two.len(), "slot ids must be fixed width");
        assert!(one.len() <= 128, "slot id must fit the 128-byte bound");

        let long = Slot::<A>::new("x".repeat(MAX_LABEL_LEN)).unwrap().account();
        assert_eq!(long.len(), one.len(), "width must not vary with label size");
    }

    /// GC must compare and remove atomically. A key swapped in after the
    /// caller's binding was published must never be destroyed by a GC aimed
    /// at the older generation — and the previous check-then-delete shape
    /// could do exactly that.
    #[test]
    fn gc_is_atomic_and_durable() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("atomic-gc").unwrap();

        let (_, gen_a) = s.create_or_inspect(&slot).unwrap();
        let gen_a = gen_a.unwrap();

        // Swap in B, then try to collect A.
        let raw = raw_reserved(td.path(), "opaque-p256-test");
        let other = SigningKey::random(&mut rand_core::OsRng);
        raw.set(&slot.account(), other.to_bytes().as_slice())
            .unwrap();

        let report = s.gc_exact(&slot, &gen_a).unwrap();
        assert!(!report.matched_expected, "must not claim it collected A");
        assert!(report.present_after, "B must survive a GC aimed at A");
        assert!(
            s.inspect(&slot).unwrap().is_some(),
            "B must still be loadable"
        );
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
