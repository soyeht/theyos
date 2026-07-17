//! Inert owner-site peer-promotion boundary.
//!
//! A successful A2 record confirmation is deliberately not enough to create a
//! remote principal or make a backend connection. This module reserves the
//! nominal capability boundary that a later reviewed data-plane contract will
//! wire to one shared Pending/Promoted/Revoking linearizer.
//!
//! Until that contract defines the exact authority, revoke, liveness, and
//! cancellation inputs, this boundary is deny-only. It has no route, provider
//! extension, socket, wire representation, or backend I/O. In particular,
//! neither opaque type has a production constructor or clone implementation.

// This module intentionally declares an unwired design boundary. Wiring it
// merely to satisfy dead-code analysis would violate the zero-effect slice.
#![allow(dead_code)]

/// Sealed, server-only identity for one exact promoted owner-site channel.
///
/// The future linearizer may construct this only after it has atomically
/// rechecked the channel, authority generation, and revocation state. The
/// deliberately private seal prevents other crate modules from minting it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedMeshPeer(VerifiedMeshPeerSeal);

#[derive(Debug, Eq, PartialEq)]
struct VerifiedMeshPeerSeal;

/// Sealed, single-channel permission that a future worker must validate before
/// any backend dial or byte pump.
///
/// This skeleton intentionally gives it no methods, bearer encoding, or clone
/// path. The future contract must bind it to the same cancellation and
/// authority generation as its [`VerifiedMeshPeer`].
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DialPermit(DialPermitSeal);

#[derive(Debug, Eq, PartialEq)]
struct DialPermitSeal;

/// Atomic future output of the promotion linearizer.
///
/// Keeping peer and permit together records that a future implementation must
/// never issue either independently. No value of this type can be created in
/// the current deny-only slice.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OwnerSitePromotedChannel {
    peer: VerifiedMeshPeer,
    permit: DialPermit,
}

/// Opaque placeholder for server-owned promotion evidence.
///
/// The exact contents intentionally remain unspecified until the security
/// contract fixes the linearizer and revocation inputs. It cannot be created
/// outside this module in production.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OwnerSitePromotionRequest(OwnerSitePromotionRequestSeal);

#[derive(Debug, Eq, PartialEq)]
struct OwnerSitePromotionRequestSeal;

/// The only current result of attempting peer promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSitePromotionRejection {
    ContractUnavailable,
}

/// Deny-only boundary reserved for the later promotion linearizer.
///
/// Constructing this value grants nothing. It is intentionally unwired from
/// A2, routing, and production startup until the reviewed data-plane contract
/// supplies the exact state transition and revoke semantics.
#[derive(Debug, Default)]
pub(crate) struct OwnerSitePromotionBoundary;

impl OwnerSitePromotionBoundary {
    /// Refuses to promote even syntactically shaped test input.
    ///
    /// A future reviewed implementation may replace this rejection with the
    /// one atomic Pending -> Promoted transition. It must retain a failure
    /// path for every unavailable, stale, revoked, or cancelled input.
    pub(crate) fn promote(
        _request: OwnerSitePromotionRequest,
    ) -> Result<OwnerSitePromotedChannel, OwnerSitePromotionRejection> {
        Err(OwnerSitePromotionRejection::ContractUnavailable)
    }
}

#[cfg(test)]
impl OwnerSitePromotionRequest {
    fn injected_for_harness() -> Self {
        Self(OwnerSitePromotionRequestSeal)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OwnerSitePromotionBoundary, OwnerSitePromotionRejection, OwnerSitePromotionRequest,
    };

    #[test]
    fn promotion_boundary_is_deny_only_before_the_data_plane_contract() {
        assert_eq!(
            OwnerSitePromotionBoundary::promote(OwnerSitePromotionRequest::injected_for_harness()),
            Err(OwnerSitePromotionRejection::ContractUnavailable)
        );
    }
}
