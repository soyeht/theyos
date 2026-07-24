//! Owner-site peer-promotion boundary (DP2 Fatia-2).
//!
//! The single promotion path consumes a sealed promotion input through the
//! shared linearizer. A `VerifiedMeshPeer` / `DialPermit` pair becomes
//! reachable ONLY after the linearizer has, in one atomic critical section,
//! rechecked the channel, authority generations, freshness, identity, and
//! one-shot claim and durably persisted the resolution — i.e. only with an
//! `OwnerSitePromotionWitness` in hand. The carriers still have no bearer
//! encoding, clone path, route, socket, or wire, and production has no source
//! of `Pending`, so this boundary remains unreachable in production.

// The carriers and the promoted channel are deliberately unwired to any
// production route in this slice; production has no `Pending` source.
#![allow(dead_code)]

use crate::owner_site_authority::{
    OwnerSitePromotionInput, OwnerSitePromotionLinearizer, OwnerSitePromotionRejection,
    OwnerSitePromotionWitness,
};

/// Sealed, server-only identity for one exact promoted owner-site channel.
///
/// The deliberately private seal prevents other crate modules from minting it;
/// the only construction site is the witness-gated body of [`OwnerSitePromotionBoundary::promote`].
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedMeshPeer(VerifiedMeshPeerSeal);

#[derive(Debug, Eq, PartialEq)]
struct VerifiedMeshPeerSeal;

/// Sealed, single-channel permission that a future worker must validate before
/// any backend dial or byte pump. It is bound to the same promotion witness as
/// its [`VerifiedMeshPeer`].
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DialPermit(DialPermitSeal);

#[derive(Debug, Eq, PartialEq)]
struct DialPermitSeal;

/// Atomic output of the promotion linearizer: peer and permit issued together,
/// never independently, plus the authorizing witness retained by ownership so
/// the authority can derive `Revoking` without a rebind, getter, or clone.
pub(crate) struct OwnerSitePromotedChannel {
    peer: VerifiedMeshPeer,
    permit: DialPermit,
    pub(crate) witness: OwnerSitePromotionWitness,
}

impl std::fmt::Debug for OwnerSitePromotedChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSitePromotedChannel(REDACTED)")
    }
}

/// Boundary carrier for a promotion input. The field permits passing the input
/// between modules; the input remains non-forgeable because its fields and
/// constructor are private to the authority module.
pub(crate) struct OwnerSitePromotionRequest(pub(crate) OwnerSitePromotionInput);

/// Boundary for the single promotion linearizer path.
#[derive(Debug, Default)]
pub(crate) struct OwnerSitePromotionBoundary;

impl OwnerSitePromotionBoundary {
    /// The one promotion path. Consumes the request, runs the linearizer's
    /// atomic authorize (seven rechecks → CAS `Pending -> Promoted` → claim
    /// consume → persist), and only on a returned witness constructs the joint
    /// `VerifiedMeshPeer` + `DialPermit`. Any rejection fails closed with no
    /// carrier and no state change.
    pub(crate) fn promote(
        linearizer: &OwnerSitePromotionLinearizer,
        request: OwnerSitePromotionRequest,
    ) -> Result<OwnerSitePromotedChannel, OwnerSitePromotionRejection> {
        let witness = linearizer.authorize(request.0)?;
        Ok(OwnerSitePromotedChannel {
            peer: VerifiedMeshPeer(VerifiedMeshPeerSeal),
            permit: DialPermit(DialPermitSeal),
            witness,
        })
    }
}
