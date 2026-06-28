//! macOS local-engine caller authentication boundary.
//!
//! M1 intentionally ships fail-closed: production wiring has no permissive
//! verifier. A future M1b verifier must derive the peer identity from the
//! accepted UDS connection and verify a stable designated requirement before
//! any local enrollment route can succeed.

use thiserror::Error;

pub const SOYEHT_TEAM_ID: &str = "W7677A5BK2";
pub const SOYEHT_MACOS_PROD_BUNDLE_ID: &str = "com.soyeht.mac";
pub const SOYEHT_MACOS_DEV_BUNDLE_ID: &str = "com.soyeht.mac.dev";

#[derive(Debug, Error)]
pub enum MacosLocalCallerAuthError {
    #[error("macOS local caller verifier unavailable")]
    Unavailable,
    #[error("macOS local caller rejected")]
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacosLocalPeer {
    audit_token_words: [u32; 8],
}

impl MacosLocalPeer {
    #[must_use]
    pub fn from_audit_token_words(audit_token_words: [u32; 8]) -> Self {
        Self { audit_token_words }
    }

    #[must_use]
    pub fn audit_token_words(&self) -> [u32; 8] {
        self.audit_token_words
    }

    #[must_use]
    pub fn audit_token_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, word) in self.audit_token_words.iter().enumerate() {
            bytes[index * 4..(index + 1) * 4].copy_from_slice(&word.to_ne_bytes());
        }
        bytes
    }
}

pub struct MacosLocalCallerAuthRequest<'a> {
    pub peer: &'a MacosLocalPeer,
}

pub trait MacosLocalCallerAuth: Send + Sync {
    fn authorize(
        &self,
        request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError>;
}

#[derive(Debug, Default)]
pub struct FailClosedMacosLocalCallerAuth;

impl MacosLocalCallerAuth for FailClosedMacosLocalCallerAuth {
    fn authorize(
        &self,
        _request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError> {
        Err(MacosLocalCallerAuthError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosLocalAppProfile {
    Production,
    Development,
}

impl MacosLocalAppProfile {
    #[must_use]
    pub fn bundle_id(self) -> &'static str {
        match self {
            Self::Production => SOYEHT_MACOS_PROD_BUNDLE_ID,
            Self::Development => SOYEHT_MACOS_DEV_BUNDLE_ID,
        }
    }

    #[must_use]
    pub fn designated_requirement(self) -> String {
        format!(
            r#"anchor apple generic and certificate leaf[subject.OU] = "{team_id}" and identifier "{bundle_id}""#,
            team_id = SOYEHT_TEAM_ID,
            bundle_id = self.bundle_id(),
        )
    }
}

#[derive(Debug)]
pub struct DesignatedRequirementMacosLocalCallerAuth {
    profile: MacosLocalAppProfile,
}

impl DesignatedRequirementMacosLocalCallerAuth {
    #[must_use]
    pub fn new(profile: MacosLocalAppProfile) -> Self {
        Self { profile }
    }

    #[must_use]
    pub fn profile(&self) -> MacosLocalAppProfile {
        self.profile
    }
}

impl MacosLocalCallerAuth for DesignatedRequirementMacosLocalCallerAuth {
    fn authorize(
        &self,
        request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError> {
        verify_peer_designated_requirement(request.peer, self.profile)
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn verify_peer_designated_requirement(
    peer: &MacosLocalPeer,
    profile: MacosLocalAppProfile,
) -> Result<(), MacosLocalCallerAuthError> {
    use core_foundation::base::{CFRelease, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::code_signing::{
        SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeRef,
        SecRequirementCreateWithString, SecRequirementRef, kSecGuestAttributeAudit,
    };
    use std::ptr;

    let audit_token_bytes = peer.audit_token_bytes();
    let audit_token = CFData::from_buffer(&audit_token_bytes);
    let audit_key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
    let attributes = CFDictionary::from_CFType_pairs(&[(audit_key, audit_token)]);

    let mut code: SecCodeRef = ptr::null_mut();
    let copy_status = unsafe {
        SecCodeCopyGuestWithAttributes(
            ptr::null_mut(),
            attributes.as_concrete_TypeRef(),
            0,
            std::ptr::addr_of_mut!(code),
        )
    };
    if copy_status != 0 || code.is_null() {
        return Err(MacosLocalCallerAuthError::Rejected);
    }

    let requirement_text = CFString::new(&profile.designated_requirement());
    let mut requirement: SecRequirementRef = ptr::null_mut();
    let requirement_status = unsafe {
        SecRequirementCreateWithString(
            requirement_text.as_concrete_TypeRef(),
            0,
            std::ptr::addr_of_mut!(requirement),
        )
    };
    if requirement_status != 0 || requirement.is_null() {
        unsafe {
            CFRelease(code.cast());
        }
        return Err(MacosLocalCallerAuthError::Rejected);
    }

    let check_status = unsafe { SecCodeCheckValidity(code, 0, requirement) };
    unsafe {
        CFRelease(requirement.cast());
        CFRelease(code.cast());
    }

    if check_status == 0 {
        Ok(())
    } else {
        Err(MacosLocalCallerAuthError::Rejected)
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_peer_designated_requirement(
    _peer: &MacosLocalPeer,
    _profile: MacosLocalAppProfile,
) -> Result<(), MacosLocalCallerAuthError> {
    Err(MacosLocalCallerAuthError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_profiles_are_mutually_exclusive() {
        let prod = MacosLocalAppProfile::Production.designated_requirement();
        assert!(prod.contains(SOYEHT_TEAM_ID));
        assert!(prod.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_PROD_BUNDLE_ID)));
        assert!(!prod.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_DEV_BUNDLE_ID)));

        let dev = MacosLocalAppProfile::Development.designated_requirement();
        assert!(dev.contains(SOYEHT_TEAM_ID));
        assert!(dev.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_DEV_BUNDLE_ID)));
        assert!(!dev.contains(&format!(r#"identifier "{}""#, SOYEHT_MACOS_PROD_BUNDLE_ID)));
    }

    #[test]
    fn audit_token_bytes_are_native_order_words() {
        let peer = MacosLocalPeer::from_audit_token_words([1, 2, 3, 4, 5, 6, 7, 8]);
        let bytes = peer.audit_token_bytes();
        assert_eq!(&bytes[0..4], &1u32.to_ne_bytes());
        assert_eq!(&bytes[28..32], &8u32.to_ne_bytes());
    }
}
