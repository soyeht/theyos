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

/// Compile-time purpose tag. Distinct purposes derive distinct STORAGE
/// slots, and the type system stops a key minted for one role from signing
/// for another. It does NOT alter the signed bytes — see the note on
/// [`Purpose::PURPOSE`], which this summary previously contradicted by also
/// claiming distinct signing preimages.
pub(crate) mod purpose_sealed {
    /// Not nameable outside this crate, so `Purpose` cannot be implemented
    /// outside it either.
    pub trait Sealed {}
}

/// The ratified signing/storage purpose, declared HERE by the crate that
/// owns the slot namespace — the only place that can guarantee the property
/// the whole type-level separation rests on: two distinct `Purpose` types
/// never share a `PURPOSE` string.
///
/// Before the seal, a downstream crate could declare its own type with
/// `PURPOSE = "mesh-session"` and reach the SAME physical key, because the
/// string is hashed into the canonical slot id. It could then mint a
/// `Preimage` for its own type and sign arbitrary bytes with the real key,
/// bypassing D4. Measured, not theorised: an external probe read the
/// identical public key through a forged purpose and signed attacker-chosen
/// bytes.
///
/// `RosterSync` is deliberately absent — D6 has ratified no authority model
/// for it, so it gets no purpose type.
pub struct MeshSessionPurpose;
impl purpose_sealed::Sealed for MeshSessionPurpose {}
impl Purpose for MeshSessionPurpose {
    const PURPOSE: &'static str = "mesh-session";
}

pub trait Purpose: purpose_sealed::Sealed {
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

    /// Canonical versioned slot id: `p256.v1.<64 hex>`, an account name
    /// PRIVATE to this crate.
    ///
    /// Two separate properties, which an earlier version of this comment
    /// wrongly merged into one by calling the result "injective by
    /// construction":
    ///
    /// 1. The digest PREIMAGE is unambiguous. Components are
    ///    LENGTH-PREFIXED, so `("a","b.c")` and `("a.b","c")` are distinct
    ///    inputs by construction — unlike a bare `purpose || label` join,
    ///    which produced the colliding accounts this module had earlier and
    ///    the colliding paths one layer below it.
    /// 2. The MAPPING to the id is collision-RESISTANT, not injective. A
    ///    256-bit digest over an unbounded domain cannot be injective;
    ///    distinct slots are believed distinct because finding a BLAKE3
    ///    collision is infeasible, not because a collision is impossible.
    ///    Claiming injectivity would assert something mathematically false,
    ///    and the guarantee actually relied upon is the weaker one.
    ///
    /// Fixed width also removes truncation as a failure mode: an over-long
    /// label is rejected at [`Slot::new`] rather than silently shortened
    /// into a collision with another slot.
    ///
    /// NOTE for the D4 adapter integration: this `p256.v1.*` account is
    /// internal storage addressing and is not the public
    /// `delegated_key_id`. That identifier belongs to a DISTINCT namespace
    /// label which this crate re-hashes into a slot; the two layers must
    /// not share the `p256.v1.` prefix, or a public identifier and a
    /// private storage address become confusable.
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
    /// Against a handle the caller already holds, so several reads can be
    /// proven to describe the same store. Fetch and prove the stored bytes
    /// through the hardened path, then interpret — the decrypt must not be
    /// what decides existence.
    fn secure_durable_get_in(
        &self,
        dir: &crate::file_backend::DirHandle,
        account: &str,
    ) -> Result<Option<Vec<u8>>, KeystoreError> {
        let raw = self.file_backing().secure_durable_get_in(dir, account)?;
        self.interpret_read(account, raw)
    }

    /// The file store underneath either backing.
    ///
    /// The TPM variant still rests its ciphertext in the very same hardened
    /// file store; only the interpretation of the bytes differs. Naming that
    /// once keeps the two read paths from drifting apart — they previously
    /// duplicated the dispatch, which is how one of them could acquire a
    /// retained handle while the other kept re-resolving by path.
    fn file_backing(&self) -> &FileKeystore {
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(s) => s.file_store(),
            Self::ApprovedFile(s) => s,
        }
    }

    /// Turn proven-durable stored bytes into plaintext material.
    ///
    /// Shared by both read paths so the TPM classification cannot drift: a
    /// blob that is present and durable but will not decrypt is a PERMANENT
    /// condition — corruption, a cleared or replaced TPM, a host migration —
    /// not the transient ambiguity a caller should retry through. Surfacing
    /// it as a security violation keeps it distinguishable from "unresolved,
    /// try again", which would otherwise spin forever against material that
    /// will never decrypt on this host.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
    fn interpret_read(
        &self,
        account: &str,
        raw: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, KeystoreError> {
        let Some(stored) = raw else {
            return Ok(None);
        };
        match self {
            #[cfg(target_os = "linux")]
            Self::SealedTpm(_) => {
                match crate::tpm_backend::TpmKeystore::decrypt_blob(account, &stored) {
                    Ok(plain) => Ok(Some(plain)),
                    Err(e) => Err(KeystoreError::SecurityViolation {
                        label: account.to_string(),
                        hint: format!(
                            "sealed material exists and is durable but does not decrypt on this \
                             host ({}); this does not resolve by retrying — the credential must \
                             be re-added",
                            e.kind()
                        ),
                    }),
                }
            }
            Self::ApprovedFile(_) => {
                let _ = account;
                Ok(Some(stored))
            }
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

    fn has_entries_besides_in(
        &self,
        dir: &crate::file_backend::DirHandle,
        exclude: &str,
    ) -> Result<bool, KeystoreError> {
        self.file_backing().has_entries_besides_in(dir, exclude)
    }

    /// Resolve the store once for a whole operation. `open_session` creates
    /// the hierarchy (writers); `open_session_existing` never does
    /// (observers).
    fn open_session(&self) -> Result<crate::file_backend::DirHandle, KeystoreError> {
        self.file_backing().open_session()
    }

    fn open_session_existing(
        &self,
    ) -> Result<Option<crate::file_backend::DirHandle>, KeystoreError> {
        self.file_backing().open_session_existing()
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
        //
        //    The whole operation runs against ONE resolution of the store,
        //    opened here. Identity, the inspect-first read, and the binding
        //    built afterwards all go through this handle, so they cannot
        //    describe different directories.
        let dir = match self.store.open_session() {
            Ok(dir) => dir,
            Err(KeystoreError::Io { .. }) => return Ok((SlotOutcome::Unresolved, None)),
            Err(other) => return Err(other),
        };

        if let Err(e) = self.resolve_identity(&dir) {
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
        match self.try_binding(&dir, slot) {
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
                let binding = self.binding_for(&dir, slot, signing.verifying_key())?;
                Ok((SlotOutcome::Created, Some(binding)))
            }
            // Someone else won, or our own earlier attempt did. Report what
            // is ACTUALLY stored, never our discarded candidate.
            CreateOutcome::ExistingExactDurable | CreateOutcome::Conflict => {
                match self.binding_or_unresolved(&dir, slot)? {
                    Some(binding) => Ok((SlotOutcome::AlreadyExisted, Some(binding))),
                    None => Ok((SlotOutcome::Unresolved, None)),
                }
            }
            // Nothing landed; a retry may succeed.
            CreateOutcome::KnownNoEffect => Ok((SlotOutcome::Unresolved, None)),
            // Truly unresolved — refuse to mint a binding for a slot whose
            // stored state is unknown. Retry converges via the inspect-first
            // path above.
            CreateOutcome::MayHaveTakenEffect => match self.binding_or_unresolved(&dir, slot)? {
                Some(binding) => Ok((SlotOutcome::AlreadyExisted, Some(binding))),
                None => Ok((SlotOutcome::Unresolved, None)),
            },
        }
    }

    /// Resolve a slot ONCE, returning both what was actually observed there
    /// and the signer for that same key material.
    ///
    /// This is the ONLY way to sign. A key replaced underneath — for example
    /// by someone writing a different scalar through the generic byte API —
    /// derives a different public key, so the comparison fails and no
    /// signature is produced under a binding the caller published earlier.
    ///
    /// # Why this returns a pair rather than a bare signer
    ///
    /// It used to return only `OpaqueSigner<P>`, having derived the observed
    /// binding on this very handle and then thrown it away. A caller that
    /// needed to know WHICH key it was about to sign with therefore had to
    /// ask again — `inspect`, or a remembered earlier binding — and that
    /// second question is a second physical resolution of the store.
    ///
    /// Two resolutions can straddle a replacement. The caller then holds a
    /// binding describing key A and a signer holding key B, with nothing in
    /// the type system objecting, and publishes a signature attributed to a
    /// key that did not produce it. Neither resolution is individually
    /// wrong, which is what makes it hard to see.
    ///
    /// So the seam does not offer the separable form at all. There is no way
    /// to obtain an owned `OpaqueSigner` without the [`PublicBinding`] that
    /// was derived from the same bytes at the same instant, and no way to
    /// construct a [`ResolvedSlot`] pairing an arbitrary binding with an
    /// arbitrary signer.
    pub fn load_exact<P: Purpose>(
        &self,
        slot: &Slot<P>,
        binding: &PublicBinding<P>,
    ) -> Result<ResolvedSlot<P>, KeystoreError> {
        // One resolution for the whole check. The scope validation reads the
        // store identity and the comparison below reads the material; taken
        // through separate path descents those two could describe different
        // stores, which is the same class of gap the binding scope exists to
        // close in the first place.
        let dir = self.store.open_session()?;
        self.validate_binding_scope(&dir, slot, binding)?;

        let signing = self.load_signing_key(&dir, slot)?;
        let observed = self.binding_for(&dir, slot, signing.verifying_key())?;
        if observed.public_key != binding.public_key {
            return Err(KeystoreError::SecurityViolation {
                label: slot.label.clone(),
                hint: "stored key no longer matches the published binding — it was replaced".into(),
            });
        }
        // `observed` and `signing` are derived from ONE read of ONE handle:
        // `observed` is computed from `signing`'s own verifying key, so they
        // cannot describe different keys even in principle. Handing them
        // back together is what makes that fact available to the caller
        // instead of being re-established by a second, separable lookup.
        Ok(ResolvedSlot {
            observed,
            signer: OpaqueSigner {
                signing,
                _purpose: PhantomData,
            },
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
        // The binding must belong to THIS store and THIS slot before it can
        // authorise destroying anything. Matching on the public key alone
        // was not enough: a binding published by a different store, or for
        // a different slot, would authorise a delete here as soon as the
        // same scalar existed in both places — and copying a scalar between
        // stores is exactly the scenario the store identity exists for.
        // Same checks `load_exact` makes before it will sign, against one
        // resolution of the store.
        let dir = self.store.open_session()?;
        self.validate_binding_scope(&dir, slot, expected)?;

        // Compare and remove as ONE locked operation. Comparing then
        // deleting was check-then-act: a writer installing B between the
        // two destroyed B, and the resulting absence was not durable.
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

    /// Confirm a binding actually describes THIS store and THIS slot.
    ///
    /// Shared by [`Self::load_exact`] and [`Self::gc_exact`] rather than
    /// written twice: signing under a foreign binding and destroying a key
    /// under a foreign binding are the same authorisation question, and
    /// having one of them implement a weaker check than the other is
    /// precisely how `gc_exact` came to accept any binding whose public key
    /// happened to match.
    fn validate_binding_scope<P: Purpose>(
        &self,
        dir: &crate::file_backend::DirHandle,
        slot: &Slot<P>,
        binding: &PublicBinding<P>,
    ) -> Result<(), KeystoreError> {
        let expected_store = self.composed_store_id(dir)?;
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
        Ok(())
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
    fn composed_store_id(
        &self,
        dir: &crate::file_backend::DirHandle,
    ) -> Result<String, KeystoreError> {
        Ok(format!(
            "{}|{}",
            self.store_id,
            self.resolve_identity(dir)?.0
        ))
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
    fn resolve_identity(
        &self,
        dir: &crate::file_backend::DirHandle,
    ) -> Result<StoreIdentityV1, KeystoreError> {
        if let Some(cached) = self.identity.get() {
            return Ok(cached.clone());
        }
        let resolved = self.resolve_identity_uncached(dir)?;
        // A concurrent resolve may have won; either value is the same
        // durable marker, so ignore the race loser.
        let _ = self.identity.set(resolved.clone());
        Ok(resolved)
    }

    /// Read the store's identity without ever WRITING one.
    ///
    /// `resolve_identity` mints and durably commits a marker for a store
    /// that has none — correct for a writer establishing an identity before
    /// its first key, and unacceptable for an observer. `inspect` must be
    /// able to report on a store without changing it.
    ///
    /// `Ok(None)` means "no marker and no material" — an empty store, which
    /// has nothing to report and nothing to quarantine. The quarantine arm
    /// is preserved exactly: material with a missing or malformed marker is
    /// still a `SecurityViolation`, never a silent repair.
    ///
    /// On success this populates the same cache `resolve_identity` uses.
    /// That is load-bearing, not an optimisation: it means a later
    /// `composed_store_id` on this handle returns from the cache and cannot
    /// reach the minting branch at all. The read-only guarantee is then a
    /// property of the code path rather than a claim about which branch
    /// happens to be taken.
    fn resolve_identity_readonly(
        &self,
        dir: &crate::file_backend::DirHandle,
    ) -> Result<Option<StoreIdentityV1>, KeystoreError> {
        if let Some(cached) = self.identity.get() {
            return Ok(Some(cached.clone()));
        }
        if let Some(raw) = self
            .store
            .secure_durable_get_in(dir, STORE_IDENTITY_ACCOUNT)?
        {
            let parsed =
                StoreIdentityV1::parse(&raw).ok_or_else(|| KeystoreError::SecurityViolation {
                    label: STORE_IDENTITY_ACCOUNT.into(),
                    hint: "store identity marker is present but malformed; refusing to guess an \
                           identity for existing key material (quarantine)"
                        .into(),
                })?;
            let _ = self.identity.set(parsed.clone());
            return Ok(Some(parsed));
        }
        if self
            .store
            .has_entries_besides_in(dir, STORE_IDENTITY_ACCOUNT)?
        {
            return Err(KeystoreError::SecurityViolation {
                label: STORE_IDENTITY_ACCOUNT.into(),
                hint: "store holds key material but no identity marker; refusing to mint a new \
                       one over it (quarantine) — restore the marker alongside the material"
                    .into(),
            });
        }
        Ok(None)
    }

    fn resolve_identity_uncached(
        &self,
        dir: &crate::file_backend::DirHandle,
    ) -> Result<StoreIdentityV1, KeystoreError> {
        if let Some(raw) = self
            .store
            .secure_durable_get_in(dir, STORE_IDENTITY_ACCOUNT)?
        {
            return StoreIdentityV1::parse(&raw).ok_or_else(|| KeystoreError::SecurityViolation {
                label: STORE_IDENTITY_ACCOUNT.into(),
                hint: "store identity marker is present but malformed; refusing to guess an \
                       identity for existing key material (quarantine)"
                    .into(),
            });
        }

        if self
            .store
            .has_entries_besides_in(dir, STORE_IDENTITY_ACCOUNT)?
        {
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
                match self
                    .store
                    .secure_durable_get_in(dir, STORE_IDENTITY_ACCOUNT)?
                {
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
        // Open the store WITHOUT creating it. A store that does not exist
        // has no slot and no quarantine condition, and an observer must be
        // able to learn that without leaving a `0700` store directory behind
        // on a host that had none — "is there a key here?" must not answer
        // by starting a store.
        let Some(dir) = self.store.open_session_existing()? else {
            return Ok(None);
        };

        // Resolve identity FIRST, even though an absent slot needs no
        // binding. Otherwise a store whose marker is missing or corrupt
        // while material exists reports a clean `None` for any slot that
        // happens not to exist — hiding a quarantine condition behind an
        // ordinary-looking answer, and letting a caller conclude "no key
        // here" about a store that should not be trusted at all.
        //
        // Both reads go through the one handle opened above, so the identity
        // that decides trust and the material that answers the question are
        // provably the same store.
        //
        // `None` here is an empty store: no marker AND no material. There is
        // no slot to report and nothing to quarantine — and, critically, no
        // marker is minted to reach that conclusion.
        if self.resolve_identity_readonly(&dir)?.is_none() {
            return Ok(None);
        }
        self.try_binding(&dir, slot)
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
        dir: &crate::file_backend::DirHandle,
        slot: &Slot<P>,
    ) -> Result<Option<PublicBinding<P>>, KeystoreError> {
        match self.try_binding(dir, slot) {
            Ok(found) => Ok(found),
            Err(KeystoreError::Io { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Binding for a slot if it currently holds a usable key.
    ///
    /// Takes the operation's retained handle so the material read here and
    /// the store identity that scopes the binding come from the SAME
    /// resolved directory. Reading them through two independent path
    /// descents left a window in which the store could be replaced between
    /// them, and the resulting binding would carry one store's identity over
    /// another store's key.
    fn try_binding<P: Purpose>(
        &self,
        dir: &crate::file_backend::DirHandle,
        slot: &Slot<P>,
    ) -> Result<Option<PublicBinding<P>>, KeystoreError> {
        match self.load_signing_key(dir, slot) {
            Ok(signing) => Ok(Some(self.binding_for(
                dir,
                slot,
                signing.verifying_key(),
            )?)),
            Err(KeystoreError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Materialise the signing key. PRIVATE, and the only place key material
    /// exists; every path zeroizes, including the error paths — a
    /// wrong-length buffer may still be a truncated real scalar, so dropping
    /// it unzeroized would leave key material in freed memory.
    fn load_signing_key<P: Purpose>(
        &self,
        dir: &crate::file_backend::DirHandle,
        slot: &Slot<P>,
    ) -> Result<SigningKey, KeystoreError> {
        let Some(mut bytes) = self.store.secure_durable_get_in(dir, &slot.account())? else {
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
        dir: &crate::file_backend::DirHandle,
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
            store_id: self.composed_store_id(dir)?,
            _purpose: PhantomData,
        })
    }
}

/// One physical resolution of a slot: the binding actually OBSERVED there
/// and the signer for that same key material.
///
/// Produced only by [`OpaqueP256Slots::load_exact`]. The fields are private
/// and there is no constructor, so this cannot be forged and cannot be
/// assembled from a binding and a signer that came from different reads —
/// which is the whole point. The two are computed from a single read of a
/// single retained handle, `observed` being derived from `signer`'s own
/// verifying key.
///
/// The signer is reachable only by reference. There is deliberately no
/// `into_signer()`: an owned signer that has been separated from its
/// observed binding is exactly the value whose existence lets a caller
/// attribute a signature to the wrong key, and offering the split as a
/// convenience would put it back.
pub struct ResolvedSlot<P: Purpose> {
    observed: PublicBinding<P>,
    signer: OpaqueSigner<P>,
}

impl<P: Purpose> std::fmt::Debug for ResolvedSlot<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSlot")
            .field("observed", &self.observed)
            .finish_non_exhaustive()
    }
}

impl<P: Purpose> ResolvedSlot<P> {
    /// What this slot actually held at the instant it was resolved.
    ///
    /// Not "what the caller expected" — `load_exact` refuses when those
    /// differ — but what was read. A caller publishing or logging which key
    /// signed something must use THIS, never a binding it happens to be
    /// holding from an earlier lookup.
    #[must_use]
    pub fn observed_binding(&self) -> &PublicBinding<P> {
        &self.observed
    }

    /// The signer for the key `observed_binding` describes.
    #[must_use]
    pub fn signer(&self) -> &OpaqueSigner<P> {
        &self.signer
    }
}

/// A signer bound to one slot, obtained only through
/// [`ResolvedSlot`] from [`OpaqueP256Slots::load_exact`] — so every
/// signature is produced under a key already proven to match a published
/// binding, and always alongside the binding actually observed for it.
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
/// A `ResolvedSlot` must not be forgeable — its fields are private, so a
/// binding and a signer from different reads cannot be paired up:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueSigner, PublicBinding, Purpose, ResolvedSlot};
/// struct P;
/// impl Purpose for P { const PURPOSE: &'static str = "p"; }
/// fn go(observed: PublicBinding<P>, signer: OpaqueSigner<P>) {
///     let _ = ResolvedSlot { observed, signer };
/// }
/// ```
///
/// And the signer must not be extractable from the pair — an owned signer
/// separated from its observed binding is the value that lets a signature be
/// attributed to the wrong key:
///
/// ```compile_fail
/// use keystore_rs::opaque_p256::{OpaqueSigner, Purpose, ResolvedSlot};
/// struct P;
/// impl Purpose for P { const PURPOSE: &'static str = "p"; }
/// fn go(resolved: ResolvedSlot<P>) -> OpaqueSigner<P> {
///     resolved.into_signer()
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
    impl super::purpose_sealed::Sealed for MeshSession {}
    impl Purpose for MeshSession {
        const PURPOSE: &'static str = "mesh-session";
    }

    struct RosterSync;
    impl super::purpose_sealed::Sealed for RosterSync {}
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
    /// join `p256.{purpose}.{label}` produced the same account for both —
    /// an ambiguous preimage, which length-prefixing now rules out.
    #[test]
    fn ambiguous_purpose_label_join_no_longer_collides() {
        struct A;
        impl super::purpose_sealed::Sealed for A {}
        impl Purpose for A {
            const PURPOSE: &'static str = "a";
        }
        struct AB;
        impl super::purpose_sealed::Sealed for AB {}
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
        let resolved = s.load_exact(&slot, &binding).unwrap();

        for i in 0..32 {
            let pre = Preimage::<MeshSession>::exact(format!("m-{i}").as_bytes());
            let sig = resolved.signer().sign(&pre);
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
        let resolved = s.load_exact(&slot, &binding).unwrap();

        let wire = b"\x07canonical-cbor-body";
        let sig = resolved
            .signer()
            .sign(&Preimage::<MeshSession>::exact(wire));

        // A verifier that knows only the protocol's own bytes must accept —
        // it would not if we had prepended anything.
        let vk = VerifyingKey::from_sec1_bytes(binding.public_key()).unwrap();
        let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
        vk.verify(wire.as_slice(), &parsed)
            .expect("signature must be over the caller's exact bytes, with no added framing");
    }

    // -- B3: one resolution yields the observed binding AND its signer -----

    /// RED (3): the pair really is a pair.
    ///
    /// `observed_binding()` must equal the expected binding field-by-field,
    /// and the signer must hold the key that binding describes — proven by
    /// verifying against a key parsed from the OBSERVED bytes, not from the
    /// caller's copy.
    #[test]
    fn resolved_slot_observed_binding_matches_expected_and_its_own_signer() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("resolved-pair").unwrap();
        let (_, expected) = s.create_or_inspect(&slot).unwrap();
        let expected = expected.unwrap();

        let resolved = s.load_exact(&slot, &expected).unwrap();
        let observed = resolved.observed_binding();

        // Field by field, not just `==`, so a future `PartialEq` that stops
        // comparing one of them cannot make this pass vacuously.
        assert_eq!(observed.public_key(), expected.public_key());
        assert_eq!(observed.label(), expected.label());
        assert_eq!(observed.backing(), expected.backing());
        assert_eq!(observed.store_id(), expected.store_id());
        assert_eq!(observed, &expected);

        // And the signer belongs to the OBSERVED key: verify with a key
        // rebuilt from the observed bytes.
        let pre = Preimage::<MeshSession>::exact(b"pair-proof");
        let sig = resolved.signer().sign(&pre);
        let vk = VerifyingKey::from_sec1_bytes(observed.public_key()).unwrap();
        let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
        p256::ecdsa::signature::Verifier::verify(&vk, b"pair-proof", &parsed)
            .expect("signer must produce a signature under the observed key");
    }

    /// RED (1): a replacement landing between two resolutions must never
    /// leave a caller holding binding A alongside signer B.
    ///
    /// The old seam returned a bare `OpaqueSigner`, so learning WHICH key
    /// was about to sign meant asking a second time. This walks the exact
    /// interleaving: resolve, let the key be replaced, resolve again — and
    /// requires that no resolution ever reports a binding that disagrees
    /// with the signer it came back with.
    #[test]
    fn replacement_between_resolutions_never_yields_binding_a_with_signer_b() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        let slot = Slot::<MeshSession>::new("straddle").unwrap();
        let (_, binding_a) = s.create_or_inspect(&slot).unwrap();
        let binding_a = binding_a.unwrap();

        let first = s.load_exact(&slot, &binding_a).unwrap();
        assert_eq!(
            first.observed_binding().public_key(),
            binding_a.public_key()
        );

        // Replace A with B behind the module's back, exactly as the generic
        // byte API path would.
        let raw = raw_reserved(td.path(), "opaque-p256-test");
        let key_b = SigningKey::random(&mut rand_core::OsRng);
        raw.set(&slot.account(), key_b.to_bytes().as_slice())
            .unwrap();

        // The stale binding is refused outright — no signer for B is handed
        // out under A's binding.
        match s.load_exact(&slot, &binding_a) {
            Err(KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("stale binding must be refused, got {other:?}"),
        }

        // Resolving with B's real binding succeeds, and what comes back
        // describes B — never A.
        let binding_b = s.inspect(&slot).unwrap().unwrap();
        assert_ne!(
            binding_b.public_key(),
            binding_a.public_key(),
            "the fixture must actually have replaced the key"
        );
        let second = s.load_exact(&slot, &binding_b).unwrap();
        let observed = second.observed_binding();
        assert_eq!(observed.public_key(), binding_b.public_key());
        assert_ne!(
            observed.public_key(),
            binding_a.public_key(),
            "a resolution must never report the superseded binding"
        );

        // The decisive check: each resolution's signer agrees with THAT
        // resolution's own observed binding. Holding both at once, the pairs
        // never cross.
        for (label, r) in [("first", &first), ("second", &second)] {
            let pre = Preimage::<MeshSession>::exact(b"straddle-proof");
            let sig = r.signer().sign(&pre);
            let vk = VerifyingKey::from_sec1_bytes(r.observed_binding().public_key()).unwrap();
            let parsed = EcdsaSignature::from_slice(sig.as_bytes()).unwrap();
            p256::ecdsa::signature::Verifier::verify(&vk, b"straddle-proof", &parsed)
                .unwrap_or_else(|e| panic!("{label} resolution's pair disagreed: {e}"));
        }
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
        assert!(s.inspect(&slot).unwrap().is_some());
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
        assert!(s.inspect(&slot).unwrap().is_some());
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

        // The above is all this test used to assert, and it passed while
        // `inspect` was still materialising the whole store: the creating
        // descent ran `mkdirat` + `fsync` + `fchmod` down to the secrets
        // directory, and an empty store then had an identity marker MINTED
        // and durably committed just to answer "is there a key here?".
        //
        // Observing that no SLOT appeared never covered any of that. So
        // assert the real property — the observation left no trace at all.
        let after_inspect = tree(td.path());
        assert!(
            after_inspect.is_empty(),
            "inspect must create no hierarchy, marker or lock; found {after_inspect:?}"
        );

        // Positive control, in the same test: the walker must be capable of
        // seeing the things whose absence is being asserted. Without this,
        // a walker that silently returned nothing would make the assertion
        // above pass for the wrong reason.
        s.create_or_inspect(&slot).unwrap();
        let after_create = tree(td.path());
        assert!(
            after_create.iter().any(|p| p.contains("store-identity")),
            "the walker must observe what a real create leaves behind — including the very \
             identity marker asserted absent above; found {after_create:?}"
        );
    }

    /// Every path under `root`, relative and sorted. Used to assert that a
    /// read-only operation left the filesystem untouched.
    fn tree(root: &std::path::Path) -> Vec<String> {
        fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
            let Ok(listing) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in listing.flatten() {
                let path = entry.path();
                out.push(
                    path.strip_prefix(base)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
                if path.is_dir() {
                    walk(&path, base, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// The slot id must be fixed-width, and distinct `(purpose, label)`
    /// pairs must map to distinct ids.
    ///
    /// Named for what is actually checked: these are DISTINCT INPUTS
    /// producing distinct outputs. That is not injectivity — a 256-bit
    /// digest over an unbounded domain cannot be injective — and no test
    /// could establish injectivity anyway. What the length-prefixing buys
    /// is an unambiguous preimage; what the hash buys is collision
    /// resistance.
    #[test]
    fn slot_id_is_fixed_width_and_separates_distinct_inputs() {
        struct A;
        impl super::purpose_sealed::Sealed for A {}
        impl Purpose for A {
            const PURPOSE: &'static str = "a";
        }
        struct AB;
        impl super::purpose_sealed::Sealed for AB {}
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

    /// A binding from ANOTHER store must not authorise deleting a key
    /// here, even when the same scalar (hence the same public key) exists
    /// in both places. Comparing only the public key made GC accept any
    /// binding that happened to match — and copying a scalar between stores
    /// is the exact scenario store identity exists to catch.
    #[test]
    fn gc_refuses_a_binding_from_another_store_even_with_matching_key() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let approval = ApprovedFallback::for_reason("audit-only fixture");
        let a = OpaqueP256Slots::approved_plaintext_file(a_dir.path(), "same-service", &approval);
        let b = OpaqueP256Slots::approved_plaintext_file(b_dir.path(), "same-service", &approval);
        let slot = Slot::<MeshSession>::new("shared-scalar").unwrap();

        let (_, a_binding) = a.create_or_inspect(&slot).unwrap();
        let a_binding = a_binding.unwrap();
        // Initialise B, then copy A's scalar into it so the public keys match.
        b.create_or_inspect(&Slot::<MeshSession>::new("init").unwrap())
            .unwrap();
        let raw_a = raw_reserved(a_dir.path(), "same-service");
        let raw_b = raw_reserved(b_dir.path(), "same-service");
        let scalar = raw_a.get(&slot.account()).unwrap();
        raw_b.set(&slot.account(), &scalar).unwrap();

        match b.gc_exact(&slot, &a_binding) {
            Err(KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("a foreign binding authorised deletion: {other:?}"),
        }
        assert!(
            b.inspect(&slot).unwrap().is_some(),
            "the key in B must survive a GC authorised by A's binding"
        );
    }

    /// A quarantine condition must not be hidden behind a clean `None` just
    /// because the slot being inspected happens not to exist.
    #[test]
    fn inspect_surfaces_quarantine_even_for_an_absent_slot() {
        let td = tempfile::tempdir().unwrap();
        let s = store(td.path());
        s.create_or_inspect(&Slot::<MeshSession>::new("material").unwrap())
            .unwrap();

        // Remove the identity marker, leaving material behind.
        raw_reserved(td.path(), "opaque-p256-test")
            .delete(STORE_IDENTITY_ACCOUNT)
            .unwrap();

        let reopened = store(td.path());
        let absent = Slot::<MeshSession>::new("never-existed").unwrap();
        match reopened.inspect(&absent) {
            Err(KeystoreError::SecurityViolation { hint, .. }) => {
                assert!(hint.contains("quarantine"), "hint={hint}");
            }
            other => panic!("quarantine hidden behind an absent slot: {other:?}"),
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
