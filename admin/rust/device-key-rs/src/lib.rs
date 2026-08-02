//! Product A — S1: one static X25519 device key per install, platform-owned.
//!
//! Design: `product-a-s1-device-x25519-design-g3` (58024695). The rules that
//! shaped this file, and the mechanisms that enforce them:
//!
//! * **No constructor accepts key material.** Callers can `generate()`,
//!   `load(..)` from a keystore backend, `persist(..)`, and read the public
//!   half — nothing else. The private [`DeviceStaticSecret::from_scalar`] has
//!   no visibility modifier, so it is bound to this module and travels with
//!   the type (g3 §1.3). Enforced by the source guard in
//!   `tests/s1_design_guards.rs` (a GUARD — Rust cannot express "no
//!   constructor may ever be added").
//! * **No accessor exposes the scalar — borrowed or owned.** `[u8; 32]` is
//!   `Copy`, so even a `&[u8; 32]` accessor would hand out an untracked copy
//!   (g3 §2, CFX-S1-2). Only the 32 public bytes leave the type.
//! * **No `Clone`, no `Copy`** on the secret: then there is no second copy
//!   for a `Drop` to miss — the only property-grade zeroization argument
//!   (g3 §2). The `Drop`-observer test is evidence, not proof.
//! * **The account name is derived inside the type.** `load`/`persist` take
//!   NO account parameter: a caller-chosen name would re-open cross-type
//!   confusion with no P-256 type in any signature — read the household
//!   identity's account and clamping turns the P-256 scalar into a valid
//!   X25519 key (g3 §1.4, the caller-chosen-universal-value class).
//! * **The name carries NO per-identity component.** One device static per
//!   install, and taking `HouseholdId`/`MachineId` would drag the household-rs
//!   dependency — the crate that exports the P-256 identity types — and with
//!   it kill the dependency-edge property (g3 §1.4a).
//! * **Dev/Release isolation lives in the account name and nowhere else**,
//!   derived from a COMPILE-TIME channel constant. The only default that can
//!   ever fire is dev, and only in a `debug_assertions` (dev-context) build;
//!   anything else — a release-shaped build with nothing explicit, or a
//!   release profile carrying dev explicitly — is a build error, closed by
//!   the `compile_error!` arm and the `build.rs` PROFILE check together (g3 §3.3).
//!
//! This crate deliberately does NOT depend on `household-rs`: the P-256
//! identity type names must not resolve here (dependency-edge PROPERTY).

use keystore_rs::{KeystoreBackend, KeystoreError};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(theyos_channel = "dev")]
const CHANNEL: &str = "dev";
#[cfg(theyos_channel = "release")]
const CHANNEL: &str = "release";
// Unset channel: the ONLY default that can ever fire is dev, and only under
// debug_assertions — the correct value in the correct context (a dev build
// IS a dev-context binary). Anything else must say what it is: a non-debug
// build with nothing explicit is a compile error below, and build.rs
// independently refuses PROFILE=release without an explicit channel, so
// "release silently carrying dev" stays inexpressible on both paths.
#[cfg(all(
    not(any(theyos_channel = "dev", theyos_channel = "release")),
    debug_assertions
))]
const CHANNEL: &str = "dev";
#[cfg(all(
    not(any(theyos_channel = "dev", theyos_channel = "release")),
    not(debug_assertions)
))]
compile_error!(
    "theyos_channel unresolved in a non-debug build: set THEYOS_CHANNEL=release \
     explicitly. The dev channel is only a debug-context default; anything \
     else must say what it is (S1 g3 §3.3)."
);

// Channel-present-and-wrong is closed by TWO layers, each stated with its
// exact scope — the claim must not be wider than the mechanism:
//
// 1. `build.rs` refuses `PROFILE=release` with the dev channel, derived from
//    cargo's own PROFILE — NOT from the `debug_assertions` proxy, which an
//    operator can legitimately enable in release as a hardening practice
//    (`[profile.release] debug-assertions = true`), and which would silently
//    reopen the hole (reopening T1d, measured by @delia).
// 2. The cfg arm below refuses ANY build without `debug_assertions` that
//    carries the dev channel — this covers release-LIKE profiles not named
//    "release" (build.rs's PROFILE check does not see those).
//
// What neither layer covers, said out loud rather than rounded up: a custom
// dev-like profile with `debug_assertions` on carrying the dev channel gets
// dev semantics — accepted, because such a profile IS a dev build. The
// dangerous direction — a binary meant for release reading and writing the
// DEVELOPMENT device-static account — is closed on both paths above.
#[cfg(all(not(debug_assertions), theyos_channel = "dev"))]
compile_error!(
    "build without debug_assertions resolved the dev channel: set \
     THEYOS_CHANNEL=release. A release binary must not read or write the dev \
     device-static account (S1 g3 §3.2)."
);

/// Keystore account namespace for the device static. Follows the house
/// dot-namespaced convention (`llm.api_key.<provider>`); the channel is the
/// final component and the ONLY place the channel appears (g3 §3.1).
const ACCOUNT_PREFIX: &str = "device.static_x25519";

/// Derive the account name for an explicit channel. Module-private: tests in
/// this file exercise both channels while production callers only ever see
/// the compile-time [`CHANNEL`] via [`derive_account`].
fn derive_account_for(channel: &str) -> String {
    format!("{ACCOUNT_PREFIX}.{channel}")
}

fn derive_account() -> String {
    derive_account_for(CHANNEL)
}

/// Errors from the device-static key path.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError {
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    /// A stored value that is not exactly 32 bytes is rejected outright —
    /// never truncated and never padded into a "valid" key.
    #[error("stored device secret has invalid length: {len} bytes (expected 32)")]
    InvalidStoredLength { len: usize },
}

/// The public half of the device static. 32 bytes OUT is fine (g3 §1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceStaticPublic(pub [u8; 32]);

impl DeviceStaticPublic {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One static X25519 device secret per install.
///
/// No `Clone`, no `Copy`, no scalar accessor — see the module docs. The
/// derive pair below follows the codebase precedent
/// (`household-rs/src/keys.rs` `P256SecretScalar`): volatile zeroization of
/// the scalar when the value drops.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceStaticSecret {
    scalar: [u8; 32],
}

impl DeviceStaticSecret {
    /// Generate a fresh device static from the OS CSPRNG.
    pub fn generate() -> Result<Self, DeviceKeyError> {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        Ok(Self::from_scalar(secret.to_bytes()))
    }

    /// Load the persisted device static, if one exists. Takes the STORE, not
    /// the bytes (g3 §1.3), and NO account parameter (g3 §1.4).
    ///
    /// # Errors
    /// [`DeviceKeyError::InvalidStoredLength`] when the stored value is not
    /// exactly 32 bytes; [`DeviceKeyError::Keystore`] on backend failures
    /// other than not-found.
    pub fn load(backend: &dyn KeystoreBackend) -> Result<Option<Self>, DeviceKeyError> {
        match backend.get(&derive_account()) {
            Ok(bytes) => {
                // The shared trait hands back a plain Vec<u8> with no
                // zeroization guarantee (g3 §2, site 2). Wrap it immediately
                // so the copy we parse from is scrubbed on every exit path.
                let bytes = Zeroizing::new(bytes);
                let scalar: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeviceKeyError::InvalidStoredLength { len: bytes.len() })?;
                Ok(Some(Self::from_scalar(scalar)))
            }
            Err(KeystoreError::NotFound { .. }) => Ok(None),
            Err(e) => Err(DeviceKeyError::Keystore(e)),
        }
    }

    /// Persist the device static under the derived account name.
    pub fn persist(&self, backend: &dyn KeystoreBackend) -> Result<(), DeviceKeyError> {
        backend.set(&derive_account(), &self.scalar)?;
        Ok(())
    }

    /// The 32 public bytes. This is the ONLY value that leaves the type.
    #[must_use]
    pub fn public(&self) -> DeviceStaticPublic {
        let secret = x25519_dalek::StaticSecret::from(self.scalar);
        DeviceStaticPublic(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }

    /// Module-private on purpose (NO visibility modifier): bound to this
    /// module, travels with the type across any future crate split (g3 §1.3).
    fn from_scalar(bytes: [u8; 32]) -> Self {
        Self { scalar: bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names_differ_across_channels() {
        assert_ne!(
            derive_account_for("dev"),
            derive_account_for("release"),
            "dev/release isolation lives in the account name"
        );
    }

    #[test]
    fn channel_name_is_stable_and_carries_no_identity_component() {
        // Positive control: same channel derives the SAME name twice — two
        // builds of one channel share the item (g3 §3.2 requires this control
        // so the isolation test cannot be measuring something else).
        assert_eq!(derive_account_for("dev"), derive_account_for("dev"));
        assert!(
            !derive_account_for("dev").is_empty()
                && derive_account_for("dev")
                    .chars()
                    .all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || c == '.'
                        || c == '_'
                        || c == '-'),
            "account name must stay inside the sanitizer-identity charset [a-z0-9._-]"
        );
    }

    #[test]
    fn derived_name_survives_the_file_backend_sanitizer_unchanged() {
        // Effect-site pin (g3 §3.2, the sibling of brother 5):
        // sanitize_path_segment maps '/', '\\' and NUL to '_', so the
        // composition sanitize ∘ derive must be the IDENTITY for every
        // channel name or two channels could collide as one file. Asserted
        // where it matters — the filename the file backend ACTUALLY
        // creates — for each channel, not just the compiled one.
        let tmp = tempfile::tempdir().unwrap();
        let store = keystore_rs::FileKeystore::new(tmp.path(), "test.service");
        let service_dir = tmp.path().join("secrets").join("test.service");
        for channel in ["dev", "release"] {
            let account = derive_account_for(channel);
            store.set(&account, b"pin").unwrap();
            let on_disk = service_dir.join(format!("{account}.bin"));
            assert!(
                on_disk.exists(),
                "channel {channel:?}: the on-disk filename must equal the \
                 derived account name byte for byte (sanitize(name) == name)"
            );
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn drop_observer_zeroizes_the_scalar() {
        // Evidence, not proof (g3 §2): this observes THAT value's Drop firing.
        // It does NOT prove no copy escaped, and it INVERTS if someone adds
        // Clone — a clone makes this test pass more easily, not harder — so
        // the Clone ban itself is pinned by the source guard, not here.
        //
        // A test that asserts on memory must PIN THE ADDRESS it observes.
        // `drop(x)` MOVES the value into `mem::drop` and runs Drop on the
        // moved copy at a NEW address — the plain form of this test watched
        // the old slot, saw the untouched bytes, and failed while the
        // zeroization was actually correct. Do not "simplify" this back to
        // `drop(secret)`: the test would keep passing/failing on a slot
        // nothing ever zeroizes, i.e. it becomes decorative without turning
        // red. `drop_in_place` runs Drop at the address we observe; `forget`
        // keeps the (now-zeroed) allocation so the read is not use-after-free.
        let mut secret = Box::new(DeviceStaticSecret::generate().unwrap());
        let ptr: *const [u8; 32] = &raw const secret.scalar;
        assert_ne!(unsafe { ptr.read_volatile() }, [0u8; 32]);
        unsafe { std::ptr::drop_in_place(&raw mut *secret) };
        let after = unsafe { ptr.read_volatile() };
        std::mem::forget(secret);
        assert_eq!(
            after, [0u8; 32],
            "ZeroizeOnDrop must scrub the scalar when the secret drops"
        );
    }

    #[test]
    fn generate_is_not_constant() {
        // The round-trip test CANNOT bite a constant-secret mutant (g3 §4):
        // distinctness needs its own assertion.
        let a = DeviceStaticSecret::generate().unwrap();
        let b = DeviceStaticSecret::generate().unwrap();
        assert_ne!(
            a.public().as_bytes(),
            b.public().as_bytes(),
            "two generate() calls must produce different secrets"
        );
    }
}
