# Data Model — Phase 1 Cryptographic Skeleton

**Feature**: 001-phase-1-crypto-skeleton
**Date**: 2026-05-06

This document defines the Rust types, derivation rules, and persistence layout introduced by Phase 1. CBOR wire schemas are in `contracts/cbor-schemas.md`; the HTTP contract is in `contracts/identity-endpoint.md`.

---

## Identifiers

All identifiers are derived from public keys via the household hash convention:

```rust
// in household-rs/src/ids.rs

/// 32-byte truncated BLAKE3-256 hash of the public key, encoded URL-safe
/// base32 (RFC 4648, lowercase, no padding). Stable string form ~52 chars.
pub struct HouseholdId(pub String);   // "hh_..."
pub struct MachineId(pub String);     // "m_..."

pub fn derive_household_id(hh_pub: &P256PublicKey) -> HouseholdId;
pub fn derive_machine_id(m_pub: &P256PublicKey) -> MachineId;
```

**Validation**:
- The string form MUST match `^(hh|m)_[a-z2-7]{52}$`.
- On deserialization, the prefix and length are checked; decoding failures abort with a typed error.

**Stability invariant**: an identifier is a function of its public key only. The same public key always yields the same identifier; identifiers MUST NOT depend on time, hostname, or any operator-supplied value.

---

## Identity keypair (`P256Keypair` / `P256SeKeypair`)

Two backing implementations coexist behind the same trait `IdentityKey`:

```rust
// in household-rs/src/keys.rs

/// 33-byte SEC1-compressed P-256 public key.
pub struct P256PublicKey(pub [u8; 33]);

/// 64-byte raw `r || s` ECDSA P-256 signature.
pub struct P256Signature(pub [u8; 64]);

pub trait IdentityKey {
    fn public(&self) -> P256PublicKey;
    fn sign(&self, message: &[u8]) -> Result<P256Signature, KeystoreError>;
}

/// Software-resident keypair (Linux + tests). Private scalar lives in process
/// memory; `Drop` zeroes the buffer.
pub struct P256Keypair {
    pub(crate) public: P256PublicKey,
    pub(crate) secret: P256SecretScalar,    // 32 bytes — zeroized on Drop
}

impl P256Keypair {
    pub fn generate() -> Self;                         // p256::SecretKey::random
}
impl IdentityKey for P256Keypair { /* sign via p256 crate */ }

/// Secure Enclave-resident keypair (macOS only). Holds a `SecKey` reference.
/// The private scalar NEVER materializes in process memory; `sign` calls
/// `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` and the SE returns
/// the 64-byte raw `r || s` (DER-decoded by the wrapper).
#[cfg(target_os = "macos")]
pub struct P256SeKeypair {
    sec_key_ref: SecKey,                   // private; never exposed
    public: P256PublicKey,                 // cached SEC1 export
}

#[cfg(target_os = "macos")]
impl P256SeKeypair {
    /// Creates a new SE-resident key. Uses `SecKeyCreateRandomKey` with
    /// `kSecAttrTokenIDSecureEnclave` and access control
    /// `kSecAccessControlBiometryCurrentSet | .privateKeyUsage` (biometry
    /// requirement is gated by the `for_subject_signing` flag — Phase 1
    /// enables it for `HH_priv` and `M_priv`; future PersonCert keys will
    /// always require biometry).
    pub fn create(label: &str, for_subject_signing: bool) -> Result<Self, KeystoreError>;
}
#[cfg(target_os = "macos")]
impl IdentityKey for P256SeKeypair { /* sign via SecKeyCreateSignature */ }
```

**Selection rule**: `P256SeKeypair` is the default on macOS; `P256Keypair` is the default everywhere else. Forcing the software path on macOS is allowed only via env var `THEYOS_FORCE_SOFTWARE_KEYS=1` (used exclusively by CI on intel-only runners and by tests that need deterministic seeds).

**Validation rules**:
- `P256Keypair`: secret scalar MUST be zeroed on `Drop` (`zeroize` crate). No `Clone` impl.
- `P256SeKeypair`: `sec_key_ref` is `pub(crate)`; external callers can only obtain `IdentityKey` references for signing. The wrapper MUST hold a single non-`Clone` `SecKey` so accidental duplication is a compile error.
- Public-key encoding round-trip: SEC1 compressed bytes ↔ `p256::PublicKey` ↔ `SecKey` (macOS) MUST be lossless. Tested on every CI run.
- Signature output is always 64-byte raw `r || s`. The macOS path uses `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` which returns DER and then strips the DER header to produce the raw form.

---

## `HouseholdRecord` (CBOR-persisted)

Mirrors protocol spec §4 in Rust form.

```rust
// in household-rs/src/household_record.rs

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct HouseholdRecord {
    pub version: u8,                       // = 1 in this phase
    pub hh_id: HouseholdId,                // derived; persisted for read-only verification
    pub hh_pub: P256PublicKey,          // 33 bytes (SEC1 compressed P-256)
    pub name: String,                      // operator-supplied at install
    pub created_at: u64,                   // Unix seconds
    pub shamir_k: u8,                      // = 1 in sole-shard mode
    pub shamir_n: u8,                      // = 1 in sole-shard mode
    pub members: Vec<MachineId>,           // exactly one member in this phase
}
```

**Validation rules** (`HouseholdRecord::validate`):
- `version == 1`.
- `derive_household_id(&hh_pub) == hh_id` — refuses any record whose `hh_id` doesn't recompute.
- `name.len() >= 1 && name.len() <= 64`; only printable Unicode characters (no control codes).
- `shamir_k <= shamir_n`; in Phase 1 both equal 1.
- `members` non-empty; each entry well-formed per `MachineId` regex.

**State transitions**: Phase 1 has no transitions — the record is created once at bootstrap and read-only afterwards. Phase 3 will add `member_added` mutations that re-write the file with new `members[]` and updated `shamir_n`.

---

## `MachineCert` (CBOR-persisted)

Mirrors protocol spec §5, partial — only the self-signed founding-member case in this phase.

```rust
// in household-rs/src/machine_cert.rs

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct MachineCert {
    pub version: u8,                       // = 1
    pub cert_type: CertType,               // = CertType::Machine
    pub hh_id: HouseholdId,                // copy from HouseholdRecord
    pub m_id: MachineId,                   // derived from m_pub
    pub m_pub: P256PublicKey,           // 33 bytes (SEC1 compressed P-256)
    pub hostname: String,                  // operator override or OS hostname
    pub platform: Platform,                // macos | linux-nix | linux-other
    pub joined_at: u64,                    // Unix seconds
    pub issued_by: SubjectId,              // Phase 1: MUST equal hh_id (root self-issued); future phases allow Person/Device subjects (delegation)
    pub caveats: Vec<Caveat>,              // Phase 1: MUST be empty Vec; future phases (US4/US5/US7/US10/US11) carry capability caveats
    pub signature: P256Signature,       // over canonical bytes excluding `signature` field
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum CertType { Machine, Person, Device }   // only Machine used in Phase 1

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum Platform { Macos, LinuxNix, LinuxOther }

/// Polymorphic subject identifier. Tagged by prefix:
/// - `hh_…` = `HouseholdId` (root issuer)
/// - `p_…`  = `PersonId` (Phase 5+)
/// - `d_…`  = `DeviceId` (Phase 5+)
/// - `m_…`  = `MachineId` (Phase 1+, but never an issuer in Phase 1)
///
/// Phase 1 only ever sees `hh_…` here. The type is polymorphic now to lock the
/// CBOR format so Phase 5 (capability delegation, user stories 4/5/7/10/11) does
/// not require a breaking schema change.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum SubjectId {
    Household(HouseholdId),
    Person(PersonId),       // Phase 5+
    Device(DeviceId),       // Phase 5+
    Machine(MachineId),     // never issuer in Phase 1
}

/// Caveats attenuate a cert's authority (macaroon/biscuit style).
///
/// Phase 1: MachineCert.caveats MUST be the empty Vec; the field is reserved.
/// Phase 5+ examples: `Caveat::ClawsCreate`, `Caveat::ClawsUseSpecific(claw_id)`,
/// `Caveat::ExpiresAt(unix_seconds)`, `Caveat::ScopeMember(person_id)`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum Caveat {
    // intentionally empty in Phase 1; future variants land with Phase 5
}

// Forward declarations for Phase 5+ identifier types (newtype around String, same
// derivation rule as HouseholdId/MachineId — base32(BLAKE3(public_key))).
pub struct PersonId(pub String);   // "p_..."
pub struct DeviceId(pub String);   // "d_..."
```

**Validation rules** (`MachineCert::verify`):
- `cert_type == CertType::Machine`.
- `derive_machine_id(&m_pub) == m_id`.
- `issued_by == SubjectId::Household(hh_id)` (Phase 1 invariant — the only allowed issuer is the household root).
- `caveats.is_empty()` (Phase 1 invariant — capabilities arrive in Phase 5).
- `P256::ECDSA::verify(canonical_cbor_excluding_signature(), signature, &hh_pub)` is `Ok` (raw `r || s`, 33-byte SEC1 verifier key).
- `hostname` length 1..=255; printable Unicode.
- `platform` matches one of the three variants exactly.

**Signature canonical bytes**: deterministic CBOR encoding of all fields **except** `signature`, per RFC 8949 §4.2.1 (sorted map keys, definite-length, shortest integers).

**Hostname / platform derivation** (per FR-016 and Q5):
- `hostname`: `--hostname-label` operator value if provided; else OS hostname (`gethostname()`).
- `platform`:
  - `Platform::Macos` if `cfg!(target_os = "macos")`.
  - `Platform::LinuxNix` if Linux and `Path::new("/etc/NIXOS").exists()`.
  - `Platform::LinuxOther` otherwise on Linux.
  - Other targets: bootstrap aborts with `error.kind = "platform.unsupported"`.

**State transitions**: read-only after creation. A future "relabel" operation (deferred to a later phase) re-signs and replaces, but is out of scope here.

---

## Persistence Layout

```
$THEYOS_STATE_DIR/household/
├── household_record.cbor    (mode 0600, atomically written)
└── machine_cert.cbor        (mode 0600, atomically written)
```

**Atomic write** (`household-rs/src/storage.rs`):
```rust
pub fn atomic_write_cbor<T: Serialize>(path: &Path, value: &T) -> Result<()>;
// implementation: write *.cbor.tmp, fsync(tmp), rename(tmp, path), fsync(parent dir)
```

**Read** (`household-rs/src/storage.rs`):
```rust
pub fn read_household_record(state_dir: &Path) -> Result<Option<HouseholdRecord>>;
pub fn read_machine_cert(state_dir: &Path) -> Result<Option<MachineCert>>;
// Returns Ok(None) if the file is absent (= "not bootstrapped yet").
// Returns Err on file-present-but-unreadable, parse failure, or validation failure.
```

---

## Keystore Layout (private keys)

The OS keystore (`keyring` crate) is keyed by `(service, account)` strings. Phase 1 uses:

### macOS (Secure Enclave-resident)

The private scalar lives inside the SE; what's "stored" outside is the `SecKey` reference (a tagged identifier the SE recognizes).

| Keychain attribute | Value | Purpose |
|---|---|---|
| `kSecClass` | `kSecClassKey` | |
| `kSecAttrKeyType` | `kSecAttrKeyTypeECSECPrimeRandom` | P-256 |
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` | hardware residency |
| `kSecAttrLabel` | `com.soyeht.theyos.household.<hh_id>` or `…machine.<m_id>` | lookup |
| `kSecAttrAccessControl` | `.privateKeyUsage` (Phase 1) | biometric flag added in later phases |

Errors:
- SE unavailable on the running Mac (`errSecNotAvailable`) → `error.kind = "se.unavailable"`, `error.hint = "Phase 1 requires Secure Enclave (Apple Silicon or T2-equipped Mac). Run on supported hardware or set THEYOS_FORCE_SOFTWARE_KEYS=1 only for CI."`
- Keychain access denied → `error.kind = "se.permission_denied"`, `error.hint = "Allow theyos to access the Keychain in System Settings → Privacy & Security."`

### Linux (kernel keyring or Secret Service)

| Service | Account | Stored secret | Lifetime |
|---|---|---|---|
| `com.soyeht.theyos` | `household.private_key.<hh_id>` | 32-byte P-256 private scalar, base64 | until household destroyed |
| `com.soyeht.theyos` | `machine.private_key.<m_id>` | 32-byte P-256 private scalar, base64 | until machine removed |

Write/read via `keyring::Entry::new(service, account)`. Errors translate to:
- Secret Service unavailable → `error.kind = "keystore.unavailable"`, `error.hint = "Install gnome-keyring or set THEYOS_KEYRING=kernel."`

**Read semantics across platforms**: missing entry on a bootstrapped install is a hard error (refuse to start, FR-012).

---

## Bootstrap orchestration (`household-rs/src/bootstrap.rs`)

Pseudocode:

```rust
pub fn bootstrap_or_load(state_dir: &Path, opts: BootstrapOpts) -> Result<LoadedIdentity> {
    let existing = read_household_record(state_dir)?;
    match existing {
        Some(record) => {
            let cert = read_machine_cert(state_dir)?
                .ok_or(BootstrapError::CertMissingButRecordPresent)?;
            cert.verify(&record.hh_pub)?;
            emit_log!("bootstrap.skip", hh_id=record.hh_id, name=record.name, created_at=record.created_at);
            Ok(LoadedIdentity { record, cert, m_priv: keystore.read(...)?, hh_priv: keystore.read(...)? })
        }
        None => {
            // first install
            run_legacy_migration_if_needed(state_dir)?;
            // SE-backed on macOS, software on Linux (selected via `cfg!(target_os)` and the
            // THEYOS_FORCE_SOFTWARE_KEYS escape hatch for CI).
            let hh_kp: Box<dyn IdentityKey> = identity_key::create_for_subject("household")?;
            emit_log!("bootstrap.key_gen.household", elapsed_ms=..., backing="secure_enclave"|"software");
            let m_kp:  Box<dyn IdentityKey> = identity_key::create_for_subject("machine")?;
            emit_log!("bootstrap.key_gen.machine",   elapsed_ms=..., backing="secure_enclave"|"software");
            let record = HouseholdRecord { ..opts.into() };
            let cert   = MachineCert::sign(&hh_kp, &m_kp.public, &opts);
            // On macOS the SE call (above) already persisted the private scalar inside the
            // Secure Enclave; what we record here is only the lookup label binding. On Linux
            // we write the 32-byte scalar to the kernel keyring / Secret Service.
            keystore.persist_reference(hh_priv_account(&record.hh_id), &hh_kp)?; emit_log!("bootstrap.keystore.write", which="household");
            keystore.persist_reference(m_priv_account(&cert.m_id),     &m_kp)?;  emit_log!("bootstrap.keystore.write", which="machine");
            atomic_write_cbor(state_dir.join("household_record.cbor"), &record)?; emit_log!("bootstrap.persist.household_record");
            atomic_write_cbor(state_dir.join("machine_cert.cbor"), &cert)?;       emit_log!("bootstrap.persist.machine_cert");
            Ok(LoadedIdentity { record, cert, m_priv: m_kp.secret, hh_priv: hh_kp.secret })
        }
    }
}
```

The `LoadedIdentity` struct is the value passed into `server-rs` startup; it owns the only references to the secret keys, which are consumed by signing operations and dropped (zeroed) when the process exits.
