//! macOS Keychain Services backend for generic-password entries.
//!
//! Wraps `security-framework`'s generic-password API. Distinct from the
//! Secure Enclave key store used by `household-rs::keys_se` — that path is
//! for cryptographic key material that must never leave the SE; this backend
//! is for opaque byte secrets (LLM API keys, OAuth tokens, etc.).
//!
//! ## Security properties
//!
//! Entries are written to the user's Login Keychain via `SecItemAdd`
//! (through the `security-framework` safe wrapper). The properties this
//! provides — for the Aurora "claw must never see the host's keys" threat
//! model — are:
//!
//! 1. **Encrypted at rest.** On Apple Silicon Macs (M1+) and T2-era Intel
//!    Macs, the Login Keychain key is wrapped by the Secure Enclave at
//!    rest. The plaintext value never lands on the flash storage in
//!    readable form; only an unlocked user session has access.
//! 2. **No iCloud sync.** The high-level `set_generic_password` call does
//!    not set `kSecAttrSynchronizable`, so entries stay on this Mac —
//!    they don't appear on the user's iPad / other Macs via iCloud
//!    Keychain.
//! 3. **Per-binary access ACL.** macOS gates Keychain reads by the
//!    calling binary's code signature. A different binary running as the
//!    same user has to prompt before it can read theyOS entries.
//! 4. **Loopback-only exposure.** The credential value never leaves the
//!    host: the proxy reads it here and injects it into outbound requests
//!    on the host side. The claw VM sees only the proxy loopback URL.
//!
//! ## Known limitations
//!
//! - Entries CAN be included in an encrypted Time Machine backup; an
//!   attacker who restores that backup onto another Mac signed in to the
//!   same Apple ID can recover them. `kSecAttrAccessibleWhenUnlocked-
//!   ThisDeviceOnly` would close this, but security-framework 2.11's
//!   safe wrapper doesn't expose access control for generic passwords —
//!   raw `SecItemAdd` via FFI would be required. Deferred to the
//!   followup; the Aurora threat model treats backup-restore-elsewhere
//!   as an upstream key rotation event, not as a host compromise.
//! - macOS pre-T2 Intel Macs encrypt the Login Keychain in software
//!   only. No hardware seal. theyOS does not currently target those
//!   hosts.
//!
//! ## Keychain layout
//!
//! Entries appear in the user's login keychain under
//! `Service = self.service` and `Account = <account>`. Default service is
//! [`crate::SERVICE`] (`com.soyeht.theyos`). Use Keychain Access.app to
//! audit, rotate, or remove entries manually if needed.
//!
//! ## Permission prompts
//!
//! On first read the user may see a Keychain Access prompt to grant the
//! calling binary access. theyOS distributes its CLIs signed with a stable
//! identity, so the prompt only appears once per binary. When denied, the
//! mapping returns [`crate::KeystoreError::PermissionDenied`] with the
//! documented hint.

use crate::{CreateOutcome, KeystoreBackend, KeystoreError, SERVICE, macos_keychain_denied_error};

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework::passwords_options::PasswordOptions;
use security_framework_sys::base::errSecDuplicateItem;
use security_framework_sys::item::kSecValueData;
use security_framework_sys::keychain_item::SecItemAdd;

/// macOS system keystore backed by Keychain Services. See module-level docs.
#[derive(Debug, Clone)]
pub struct MacosSystemKeystore {
    service: String,
}

impl Default for MacosSystemKeystore {
    fn default() -> Self {
        Self::new(SERVICE)
    }
}

impl MacosSystemKeystore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl KeystoreBackend for MacosSystemKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        match get_generic_password(&self.service, account) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(map_keychain_err(e, account)),
        }
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        set_generic_password(&self.service, account, value)
            .map_err(|e| map_keychain_err(e, account))
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        match delete_generic_password(&self.service, account) {
            Ok(()) => Ok(()),
            // `errSecItemNotFound` is the Keychain "no such entry" code; we
            // treat best-effort delete as success when there's nothing to
            // delete.
            Err(e) if is_not_found(e) => Ok(()),
            Err(e) => Err(map_keychain_err(e, account)),
        }
    }

    /// Adds a generic-password item iff one does not already exist for
    /// `(service, account)`, using the raw `SecItemAdd` primitive directly.
    ///
    /// [`set_generic_password`] cannot be reused here: its
    /// `set_password_internal` (security-framework 2.11.1's own
    /// `src/passwords.rs`) calls `SecItemAdd` and, on `errSecDuplicateItem`,
    /// falls through to `SecItemUpdate` — that's create-or-update, not
    /// create-only. This mirrors that same internal implementation up to
    /// the duplicate check, then stops on `errSecDuplicateItem` instead of
    /// overwriting.
    ///
    /// This is an intentionally NARROWER gate than the File/TPM backends'
    /// full 5-way [`CreateOutcome`]. `SecItemAdd`'s `OSStatus` is a
    /// synchronous, authoritative response from a local daemon (securityd) —
    /// there is no separate "did the write survive a crash" fsync step the
    /// way there is for a raw filesystem write, so a clean success genuinely
    /// is [`CreateOutcome::CreatedDurable`] with no extra proof needed. But
    /// for any `OSStatus` other than success or the well-defined
    /// `errSecDuplicateItem`, this deliberately does NOT attempt to classify
    /// the failure as `KnownNoEffect` vs. `MayHaveTakenEffect` — Apple's
    /// retry-safety semantics across the full `OSStatus` space are not
    /// something this crate has independently verified, and guessing would
    /// be exactly the kind of invented guarantee this backend must not make.
    /// Those cases stay a plain [`KeystoreError`], same as before this
    /// change. Also does not attempt to model Secure Enclave cardinality or
    /// return an opaque signer handle — this remains the generic
    /// `(service, account) -> bytes` API described in the module docs; SE
    /// identity material stays in `household-rs::keys_se`.
    #[allow(unsafe_code)]
    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        let mut options = PasswordOptions::new_generic_password(&self.service, account);
        options.query.push((
            // SAFETY: `kSecValueData` is a process-lifetime CF constant
            // owned by the Security framework; `wrap_under_get_rule` takes
            // a +0 (borrowed) reference, matching how `security-framework`
            // itself uses this exact constant in `passwords.rs`.
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(value).into_CFType(),
        ));
        let params = CFDictionary::from_CFType_pairs(&options.query);

        let mut result = std::ptr::null();
        // SAFETY: `params` is a fully-owned CFDictionary built the same way
        // `security-framework`'s own `set_password_internal` builds its
        // query (service + account + class + kSecValueData). We pass no
        // `kSecReturn*` attribute, so Keychain Services does not populate
        // `result` on success and there is nothing to release; `SecItemAdd`
        // is documented safe to call with a null-initialized out-param.
        let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &raw mut result) };

        if status == 0 {
            return Ok(CreateOutcome::CreatedDurable);
        }
        if status == errSecDuplicateItem {
            // Duplicate alone doesn't say whose value is there — compare
            // content, same as File/TPM's reinspection step.
            return match get_generic_password(&self.service, account) {
                Ok(existing) if existing == value => Ok(CreateOutcome::ExistingExactDurable),
                Ok(_) => Ok(CreateOutcome::Conflict),
                Err(e) => Err(map_keychain_err(e, account)),
            };
        }
        Err(map_keychain_err(
            security_framework::base::Error::from_code(status),
            account,
        ))
    }
}

fn is_not_found(e: security_framework::base::Error) -> bool {
    // OSStatus -25300 is errSecItemNotFound.
    e.code() == -25300
}

fn map_keychain_err(e: security_framework::base::Error, account: &str) -> KeystoreError {
    if is_not_found(e) {
        return KeystoreError::NotFound {
            label: account.to_string(),
        };
    }
    // -128  errUserCanceled (user dismissed the access prompt)
    // -25308 errSecInteractionNotAllowed (no UI session to prompt in)
    // -25293 errSecAuthFailed
    let code = e.code();
    if code == -128 || code == -25308 || code == -25293 {
        return macos_keychain_denied_error();
    }
    KeystoreError::Io {
        kind: format!("OSStatus {code}"),
        hint: e.to_string(),
    }
}

// Real Login Keychain round-trip tests. `#[ignore]`d for the same reason
// `tests/roundtrip.rs` keeps System-keystore coverage out of the default
// `cargo test` run: this hits a real user-session Keychain daemon, which a
// CI sandbox or headless host does not have. Run explicitly on a workstation
// with `cargo test -- --ignored`; each test deletes its own random-suffixed
// account on the way out (RAII guard below) even on assertion panic, so
// repeated local runs never collide with leftover state from a prior run.
#[cfg(test)]
mod tests {
    use super::*;

    struct CleanupGuard<'a> {
        ks: &'a MacosSystemKeystore,
        account: String,
    }

    impl Drop for CleanupGuard<'_> {
        fn drop(&mut self) {
            let _ = self.ks.delete(&self.account);
        }
    }

    fn random_account(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{prefix}.{}.{nanos}.{n}", std::process::id())
    }

    #[test]
    #[ignore = "hits the real macOS Login Keychain; run manually on a workstation"]
    fn create_only_round_trips_then_conflicts_then_recreates() {
        let ks = MacosSystemKeystore::new("com.soyeht.theyos.test.create_only");
        let account = random_account("create-only");
        let _cleanup = CleanupGuard {
            ks: &ks,
            account: account.clone(),
        };

        assert_eq!(
            ks.create_only(&account, b"first-writer-wins").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(ks.get(&account).unwrap(), b"first-writer-wins");

        assert_eq!(
            ks.create_only(&account, b"second-writer-loses").unwrap(),
            CreateOutcome::Conflict,
            "different content must report a real Conflict"
        );
        // Loser must not have clobbered the winner.
        assert_eq!(ks.get(&account).unwrap(), b"first-writer-wins");

        assert_eq!(
            ks.create_only(&account, b"first-writer-wins").unwrap(),
            CreateOutcome::ExistingExactDurable,
            "resubmitting the SAME content must converge, not conflict"
        );

        ks.delete(&account).unwrap();
        assert_eq!(
            ks.create_only(&account, b"recreated-after-delete").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(ks.get(&account).unwrap(), b"recreated-after-delete");
    }
}
