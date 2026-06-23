//! Typed bootstrap/onboarding error codes — the `error` wire string carried in
//! the CBOR/JSON error envelope that the iPhone decodes as
//! `BootstrapError.serverError(code, _)`.
//!
//! This is the single source of truth for the bootstrap-domain error-code wire
//! strings emitted by the producers that surface as `BootstrapError` on iOS:
//! `handlers_bootstrap.rs` (the `/bootstrap/*` endpoints) and
//! `handlers_sign_machine_cert.rs` (`/api/v1/household/sign-machine-cert`, whose
//! client decodes errors through the same `BootstrapWire` path). The set is
//! deliberately bounded to that domain; the `/bootstrap/pair-machine/local/stage`
//! daemon/local-stage codes (`no_transport_address`, `stage_failed`,
//! `household_already_paired`, `invalid_request_body`, `unsupported_transport`)
//! are a SEPARATE pair-machine local-stage taxonomy (its client is the macOS
//! daemon, not a `BootstrapWire` consumer) and are intentionally NOT part of this
//! enum.
//!
//! Decoding is fail-soft: any unrecognized / future wire string becomes
//! [`BootstrapErrorCode::Unknown`] so an older binary never rejects a code a
//! newer one introduced.

use serde::{Deserialize, Serialize};

/// A bootstrap/onboarding error code as it appears in the `error` field of the
/// CBOR/JSON error envelope. Serializes to a stable `snake_case` wire string;
/// unknown strings decode to [`Self::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapErrorCode {
    /// The request body was malformed CBOR.
    InvalidCbor,
    /// A required field failed validation (generic 400).
    InvalidRequest,
    /// The household name was invalid.
    InvalidName,
    /// The signing subject was invalid.
    InvalidSubject,
    /// The owner proof-of-possession did not verify.
    InvalidPop,
    /// The caller is not authenticated.
    Unauthorized,
    /// The caller is authenticated but not a member of this household.
    NotAMember,
    /// The request must arrive over the tailnet (source-IP guard).
    TailnetRequired,
    /// The engine is already initialized / set up on this Mac.
    AlreadyInitialized,
    /// The household is not initialized yet.
    HouseholdNotInitialized,
    /// The setup invitation token was not recognized.
    InvitationNotRecognized,
    /// The setup invitation has expired.
    InvitationExpired,
    /// Teardown was requested but there is no household to tear down.
    NoHouseholdToTeardown,
    /// Internal server error.
    InternalError,
    /// Key generation failed during initialization.
    KeygenFailed,
    /// Owner crypto / proof validation failed during accept-household.
    CryptoValidationFailed,
    /// The accept-household invitation has expired or was already spent.
    InvitationExpiredOrSpent,
    /// The accept-household invitation was not found.
    InvitationNotFound,
    /// Accept-household confirm arrived with no pending accept in progress.
    AcceptHouseholdNotPending,
    /// The engine is still starting and not ready to serve yet (HTTP 503).
    /// Emitted by the engine runtime/readiness layer rather than these handlers;
    /// kept here because the iPhone's `BootstrapStatusClient` retries on it and
    /// `BootstrapState` renders copy for it. Legacy / iOS-facing.
    EngineInitializing,
    /// Unrecognized / future code (fail-soft catch-all).
    #[serde(other)]
    Unknown,
}

impl BootstrapErrorCode {
    /// The stable `snake_case` wire string. This is the authoritative producer
    /// representation — handlers emit `BootstrapErrorCode::X.as_str()` so the
    /// wire bytes can never drift from the enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCbor => "invalid_cbor",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidName => "invalid_name",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidPop => "invalid_pop",
            Self::Unauthorized => "unauthorized",
            Self::NotAMember => "not_a_member",
            Self::TailnetRequired => "tailnet_required",
            Self::AlreadyInitialized => "already_initialized",
            Self::HouseholdNotInitialized => "household_not_initialized",
            Self::InvitationNotRecognized => "invitation_not_recognized",
            Self::InvitationExpired => "invitation_expired",
            Self::NoHouseholdToTeardown => "no_household_to_teardown",
            Self::InternalError => "internal_error",
            Self::KeygenFailed => "keygen_failed",
            Self::CryptoValidationFailed => "crypto_validation_failed",
            Self::InvitationExpiredOrSpent => "invitation_expired_or_spent",
            Self::InvitationNotFound => "invitation_not_found",
            Self::AcceptHouseholdNotPending => "accept_household_not_pending",
            Self::EngineInitializing => "engine_initializing",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a wire string fail-soft: unrecognized values become [`Self::Unknown`].
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "invalid_cbor" => Self::InvalidCbor,
            "invalid_request" => Self::InvalidRequest,
            "invalid_name" => Self::InvalidName,
            "invalid_subject" => Self::InvalidSubject,
            "invalid_pop" => Self::InvalidPop,
            "unauthorized" => Self::Unauthorized,
            "not_a_member" => Self::NotAMember,
            "tailnet_required" => Self::TailnetRequired,
            "already_initialized" => Self::AlreadyInitialized,
            "household_not_initialized" => Self::HouseholdNotInitialized,
            "invitation_not_recognized" => Self::InvitationNotRecognized,
            "invitation_expired" => Self::InvitationExpired,
            "no_household_to_teardown" => Self::NoHouseholdToTeardown,
            "internal_error" => Self::InternalError,
            "keygen_failed" => Self::KeygenFailed,
            "crypto_validation_failed" => Self::CryptoValidationFailed,
            "invitation_expired_or_spent" => Self::InvitationExpiredOrSpent,
            "invitation_not_found" => Self::InvitationNotFound,
            "accept_household_not_pending" => Self::AcceptHouseholdNotPending,
            "engine_initializing" => Self::EngineInitializing,
            _ => Self::Unknown,
        }
    }

    /// Every concrete (non-`Unknown`) code, for exhaustiveness tests + fixtures.
    pub const ALL: [Self; 20] = [
        Self::InvalidCbor,
        Self::InvalidRequest,
        Self::InvalidName,
        Self::InvalidSubject,
        Self::InvalidPop,
        Self::Unauthorized,
        Self::NotAMember,
        Self::TailnetRequired,
        Self::AlreadyInitialized,
        Self::HouseholdNotInitialized,
        Self::InvitationNotRecognized,
        Self::InvitationExpired,
        Self::NoHouseholdToTeardown,
        Self::InternalError,
        Self::KeygenFailed,
        Self::CryptoValidationFailed,
        Self::InvitationExpiredOrSpent,
        Self::InvitationNotFound,
        Self::AcceptHouseholdNotPending,
        Self::EngineInitializing,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_and_from_wire_round_trip() {
        for code in BootstrapErrorCode::ALL {
            assert_eq!(
                BootstrapErrorCode::from_wire(code.as_str()),
                code,
                "round-trip failed for {code:?}"
            );
        }
    }

    #[test]
    fn from_wire_is_fail_soft() {
        assert_eq!(
            BootstrapErrorCode::from_wire("already_initialized"),
            BootstrapErrorCode::AlreadyInitialized
        );
        assert_eq!(
            BootstrapErrorCode::from_wire("some_future_code"),
            BootstrapErrorCode::Unknown
        );
        assert_eq!(
            BootstrapErrorCode::from_wire(""),
            BootstrapErrorCode::Unknown
        );
    }

    #[test]
    fn serde_matches_as_str_and_fail_soft() {
        for code in BootstrapErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: BootstrapErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
        // Unknown / future string deserializes fail-soft to Unknown.
        let back: BootstrapErrorCode = serde_json::from_str("\"brand_new_code\"").unwrap();
        assert_eq!(back, BootstrapErrorCode::Unknown);
    }

    #[test]
    fn all_is_exhaustive_over_concrete_variants() {
        // Adding a concrete variant without updating ALL breaks this match.
        for code in BootstrapErrorCode::ALL {
            match code {
                BootstrapErrorCode::InvalidCbor
                | BootstrapErrorCode::InvalidRequest
                | BootstrapErrorCode::InvalidName
                | BootstrapErrorCode::InvalidSubject
                | BootstrapErrorCode::InvalidPop
                | BootstrapErrorCode::Unauthorized
                | BootstrapErrorCode::NotAMember
                | BootstrapErrorCode::TailnetRequired
                | BootstrapErrorCode::AlreadyInitialized
                | BootstrapErrorCode::HouseholdNotInitialized
                | BootstrapErrorCode::InvitationNotRecognized
                | BootstrapErrorCode::InvitationExpired
                | BootstrapErrorCode::NoHouseholdToTeardown
                | BootstrapErrorCode::InternalError
                | BootstrapErrorCode::KeygenFailed
                | BootstrapErrorCode::CryptoValidationFailed
                | BootstrapErrorCode::InvitationExpiredOrSpent
                | BootstrapErrorCode::InvitationNotFound
                | BootstrapErrorCode::AcceptHouseholdNotPending
                | BootstrapErrorCode::EngineInitializing => {}
                BootstrapErrorCode::Unknown => panic!("ALL must not contain Unknown"),
            }
        }
        assert_eq!(BootstrapErrorCode::ALL.len(), 20);
    }
}
