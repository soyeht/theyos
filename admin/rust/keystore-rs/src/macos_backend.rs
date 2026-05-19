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

use crate::{KeystoreBackend, KeystoreError, SERVICE, macos_keychain_denied_error};

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

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
}

fn is_not_found(e: security_framework::base::Error) -> bool {
    // OSStatus -25300 is errSecItemNotFound.
    e.code() == -25300
}

fn map_keychain_err(
    e: security_framework::base::Error,
    account: &str,
) -> KeystoreError {
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
