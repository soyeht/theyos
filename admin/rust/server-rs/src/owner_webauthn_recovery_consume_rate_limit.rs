//! Recovery-code consume rate-limit adapter.
//!
//! This is R1-B runtime foundation only: it defines the recovery-specific
//! limiter action, durable subject key, and fail-closed mapping that a future
//! consume handler must use. It intentionally does not expose a route, response
//! type, or authorization decision.

use crate::ratelimit::{Limiter, RateLimitError};
use household_rs::{HouseholdId, PersonId};

const RECOVERY_CONSUME_ACTION: &str = "owner_webauthn_recovery_consume";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryConsumeRateLimitDecision {
    Allowed,
    RejectOpaque,
}

impl RecoveryConsumeRateLimitDecision {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[must_use]
pub fn recovery_consume_rate_limit_subject(hh_id: &HouseholdId, owner_p_id: &PersonId) -> String {
    format!("hh:{hh_id}:owner:{}", owner_p_id.0)
}

/// Record one recovery-code consume attempt.
///
/// The returned decision is deliberately response-agnostic. Future handlers
/// must map `RejectOpaque` to the same generic unauthorized response used for
/// bad code, stale heads, missing anchors, and replay.
#[must_use]
pub fn check_recovery_consume_attempt(
    rate_limiter: &Limiter,
    hh_id: &HouseholdId,
    owner_p_id: &PersonId,
) -> RecoveryConsumeRateLimitDecision {
    let subject = recovery_consume_rate_limit_subject(hh_id, owner_p_id);
    debug_assert_eq!(RECOVERY_CONSUME_ACTION, "owner_webauthn_recovery_consume");
    let result = rate_limiter.check(&subject, "owner_webauthn_recovery_consume");
    map_limiter_result(&result)
}

fn map_limiter_result(result: &Result<bool, RateLimitError>) -> RecoveryConsumeRateLimitDecision {
    match result {
        Ok(true) => RecoveryConsumeRateLimitDecision::Allowed,
        Ok(false) | Err(_) => RecoveryConsumeRateLimitDecision::RejectOpaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn household_id(ch: char) -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", ch.to_string().repeat(52))).unwrap()
    }

    fn owner_p_id(label: &str) -> PersonId {
        PersonId(format!("p_owner-{label}"))
    }

    #[test]
    fn limiter_denials_and_errors_are_the_same_opaque_reject() {
        assert_eq!(
            map_limiter_result(&Ok(true)),
            RecoveryConsumeRateLimitDecision::Allowed
        );
        assert_eq!(
            map_limiter_result(&Ok(false)),
            RecoveryConsumeRateLimitDecision::RejectOpaque
        );
        assert_eq!(
            map_limiter_result(&Err(RateLimitError::Internal("db unavailable".to_string()))),
            RecoveryConsumeRateLimitDecision::RejectOpaque
        );
    }

    #[test]
    fn attempts_are_durable_per_household_owner() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("recovery-consume-ratelimit.db");
        let db_path = db_path.to_str().unwrap();
        let hh = household_id('a');
        let owner = owner_p_id("alpha");

        {
            let limiter = Limiter::new(db_path, 1).unwrap();
            assert!(
                check_recovery_consume_attempt(&limiter, &hh, &owner).is_allowed(),
                "first attempt for a household owner is allowed"
            );
            assert_eq!(
                check_recovery_consume_attempt(&limiter, &hh, &owner),
                RecoveryConsumeRateLimitDecision::RejectOpaque,
                "second attempt in the same window is opaque-rejected"
            );
            assert!(
                check_recovery_consume_attempt(&limiter, &hh, &owner_p_id("beta")).is_allowed(),
                "a different owner has an independent durable bucket"
            );
            assert!(
                check_recovery_consume_attempt(&limiter, &household_id('b'), &owner).is_allowed(),
                "a different household has an independent durable bucket"
            );
        }

        let limiter = Limiter::new(db_path, 1).unwrap();
        assert_eq!(
            check_recovery_consume_attempt(&limiter, &hh, &owner),
            RecoveryConsumeRateLimitDecision::RejectOpaque,
            "the attempt ledger survives limiter recreation"
        );
    }

    #[test]
    fn source_contract_stays_response_agnostic_and_secret_free() {
        let source = include_str!("owner_webauthn_recovery_consume_rate_limit.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let too_many_requests = ["StatusCode::TOO", "_MANY_REQUESTS"].concat();
        let retry_after = ["Retry", "-After"].concat();
        let rate_limit_header = ["X-Rate", "Limit"].concat();
        assert!(!production.contains(&too_many_requests));
        assert!(!production.contains(&retry_after));
        assert!(!production.contains(&rate_limit_header));
        assert!(!production.contains("recovery_code"));
    }
}
