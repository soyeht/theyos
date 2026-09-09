//! Inert classifier helpers for recovery-code consume.
//!
//! These helpers do not authorize a live mutation by themselves. They classify
//! already verified and anchor-classified WebAuthn/recovery authorities so the
//! future R1-B runtime can decide whether to issue a recovery challenge, repair a
//! saved two-anchor commit, or fail closed without granting.

use thiserror::Error;

use crate::owner_webauthn::anchor::{OwnerWebauthnAnchorStatus, OwnerWebauthnAuthorityHead};
use crate::owner_webauthn::authority::OwnerWebauthnAuthority;
use crate::owner_webauthn::recovery::{
    OwnerWebauthnRecoveryAuthority, OwnerWebauthnRecoveryError, OwnerWebauthnRecoveryHead,
};
use crate::owner_webauthn::recovery_anchor::{
    OwnerWebauthnRecoveryAnchor, OwnerWebauthnRecoveryAnchorStatus,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerWebauthnRecoveryConsumeReadiness {
    Consumable {
        webauthn_head: OwnerWebauthnAuthorityHead,
        recovery_head: OwnerWebauthnRecoveryHead,
        pre_active_credential_count: u64,
    },
    RepairRequired {
        webauthn_head: OwnerWebauthnAuthorityHead,
        recovery_head: OwnerWebauthnRecoveryHead,
        pre_active_credential_count: u64,
    },
    NotReady,
}

#[derive(Debug, Error)]
pub enum OwnerWebauthnRecoveryConsumeClassifierError {
    #[error("owner webauthn authority was never enrolled")]
    WebauthnNeverEnrolled,
    #[error("owner webauthn authority anchor status is not eligible for recovery consume")]
    WebauthnAnchorNotEligible,
    #[error("recovery anchor head hash must be 32 bytes")]
    RecoveryAnchorHashLength,
    #[error("owner webauthn recovery: {0}")]
    Recovery(#[from] OwnerWebauthnRecoveryError),
}

/// Classifies the future recovery-code consume/start precondition.
///
/// Preconditions:
/// - The `WebAuthn` authority was reconstructed/verified and its anchor was
///   classified read-only.
/// - The recovery authority was verified and its anchor was classified
///   read-only.
///
/// `pre_active_credential_count` is telemetry only. It may be zero for the
/// deliberate break-glass case where the log is ever-enrolled but no active
/// passkey remains usable.
pub fn classify_owner_webauthn_recovery_consume_readiness(
    webauthn_authority: &OwnerWebauthnAuthority,
    webauthn_anchor_status: &OwnerWebauthnAnchorStatus,
    recovery_authority: &OwnerWebauthnRecoveryAuthority,
    recovery_anchor_status: &OwnerWebauthnRecoveryAnchorStatus,
    pre_active_credential_count: u64,
) -> Result<OwnerWebauthnRecoveryConsumeReadiness, OwnerWebauthnRecoveryConsumeClassifierError> {
    let webauthn_head = eligible_webauthn_head(webauthn_anchor_status)?;
    match recovery_anchor_status {
        OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor => {
            Ok(OwnerWebauthnRecoveryConsumeReadiness::NotReady)
        }
        OwnerWebauthnRecoveryAnchorStatus::Created { head }
        | OwnerWebauthnRecoveryAnchorStatus::Verified { head } => classify_anchored_recovery_head(
            webauthn_authority,
            recovery_authority,
            webauthn_head,
            head,
            pre_active_credential_count,
        ),
        OwnerWebauthnRecoveryAnchorStatus::Advanced { previous, .. } => {
            let previous_head = recovery_head_from_anchor(previous)?;
            if recovery_authority.recovery_head_consumed_by_any_log(
                webauthn_authority,
                previous_head.sequence,
                &previous_head.head_hash,
            ) {
                return Ok(OwnerWebauthnRecoveryConsumeReadiness::RepairRequired {
                    webauthn_head,
                    recovery_head: previous_head,
                    pre_active_credential_count,
                });
            }
            Ok(OwnerWebauthnRecoveryConsumeReadiness::NotReady)
        }
    }
}

fn eligible_webauthn_head(
    status: &OwnerWebauthnAnchorStatus,
) -> Result<OwnerWebauthnAuthorityHead, OwnerWebauthnRecoveryConsumeClassifierError> {
    match status {
        OwnerWebauthnAnchorStatus::Verified { head }
        | OwnerWebauthnAnchorStatus::Advanced { head, .. } => Ok(head.clone()),
        OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor => {
            Err(OwnerWebauthnRecoveryConsumeClassifierError::WebauthnNeverEnrolled)
        }
        OwnerWebauthnAnchorStatus::Migrated { .. } => {
            Err(OwnerWebauthnRecoveryConsumeClassifierError::WebauthnAnchorNotEligible)
        }
    }
}

fn classify_anchored_recovery_head(
    webauthn_authority: &OwnerWebauthnAuthority,
    recovery_authority: &OwnerWebauthnRecoveryAuthority,
    webauthn_head: OwnerWebauthnAuthorityHead,
    anchored_recovery_head: &OwnerWebauthnRecoveryHead,
    pre_active_credential_count: u64,
) -> Result<OwnerWebauthnRecoveryConsumeReadiness, OwnerWebauthnRecoveryConsumeClassifierError> {
    let Some(active_head) = recovery_authority.latest_active_verifier_head()? else {
        return Ok(OwnerWebauthnRecoveryConsumeReadiness::NotReady);
    };
    if active_head != *anchored_recovery_head {
        return Ok(OwnerWebauthnRecoveryConsumeReadiness::NotReady);
    }
    if recovery_authority.recovery_head_consumed_by_any_log(
        webauthn_authority,
        active_head.sequence,
        &active_head.head_hash,
    ) {
        return Ok(OwnerWebauthnRecoveryConsumeReadiness::RepairRequired {
            webauthn_head,
            recovery_head: active_head,
            pre_active_credential_count,
        });
    }
    Ok(OwnerWebauthnRecoveryConsumeReadiness::Consumable {
        webauthn_head,
        recovery_head: active_head,
        pre_active_credential_count,
    })
}

fn recovery_head_from_anchor(
    anchor: &OwnerWebauthnRecoveryAnchor,
) -> Result<OwnerWebauthnRecoveryHead, OwnerWebauthnRecoveryConsumeClassifierError> {
    Ok(OwnerWebauthnRecoveryHead {
        sequence: anchor.sequence(),
        head_hash: anchor
            .head_hash()
            .try_into()
            .map_err(|_| OwnerWebauthnRecoveryConsumeClassifierError::RecoveryAnchorHashLength)?,
    })
}

#[cfg(test)]
mod tests;
