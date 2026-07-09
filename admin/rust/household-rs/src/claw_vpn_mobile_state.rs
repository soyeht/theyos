//! Pure Product A mobile per-Claw VPN state machine.
//!
//! This module has no storage, relay, TUN/utun, route, `NetworkExtension`, or
//! host mutation side effects. It is the product-state contract for the mobile
//! Claw-control VPN work: callers can use it to keep user-visible state
//! fail-closed while lower layers perform real authorization, relay, route, and
//! teardown work.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Redacted public status labels exposed to UI, audit summaries, and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnMobilePublicStatus {
    Unavailable,
    Available,
    Connecting,
    Connected,
    ConnectedDegradedControl,
    Disconnecting,
    Disconnected,
    Denied,
    Expired,
    Revoked,
    RelayUnavailable,
    Failed,
    RepairRequired,
}

/// Device-side Packet Tunnel product state for one selected Claw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnDeviceTunnelState {
    Unenrolled,
    Enrolling,
    Available,
    ResolvingClaw,
    OfferRequested,
    OfferReady,
    DialingRelay,
    Authenticating,
    InstallingRoute,
    Connected,
    DegradedControl,
    Disconnecting,
    Disconnected,
    Denied,
    Expired,
    Revoked,
    RelayUnavailable,
    Failed,
    FailedTeardown,
    Unavailable,
}

impl ClawVpnDeviceTunnelState {
    #[must_use]
    pub fn public_status(self) -> ClawVpnMobilePublicStatus {
        match self {
            Self::Unenrolled | Self::Unavailable => ClawVpnMobilePublicStatus::Unavailable,
            Self::Available => ClawVpnMobilePublicStatus::Available,
            Self::Enrolling
            | Self::ResolvingClaw
            | Self::OfferRequested
            | Self::OfferReady
            | Self::DialingRelay
            | Self::Authenticating
            | Self::InstallingRoute => ClawVpnMobilePublicStatus::Connecting,
            Self::Connected => ClawVpnMobilePublicStatus::Connected,
            Self::DegradedControl => ClawVpnMobilePublicStatus::ConnectedDegradedControl,
            Self::Disconnecting => ClawVpnMobilePublicStatus::Disconnecting,
            Self::Disconnected => ClawVpnMobilePublicStatus::Disconnected,
            Self::Denied => ClawVpnMobilePublicStatus::Denied,
            Self::Expired => ClawVpnMobilePublicStatus::Expired,
            Self::Revoked => ClawVpnMobilePublicStatus::Revoked,
            Self::RelayUnavailable => ClawVpnMobilePublicStatus::RelayUnavailable,
            Self::Failed => ClawVpnMobilePublicStatus::Failed,
            Self::FailedTeardown => ClawVpnMobilePublicStatus::RepairRequired,
        }
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use ClawVpnDeviceTunnelState as S;
        matches!(
            (self, next),
            (S::Unenrolled, S::Enrolling | S::Unavailable)
                | (S::Enrolling, S::Available | S::Unavailable | S::Failed)
                | (S::Available, S::ResolvingClaw | S::Revoked | S::Unavailable)
                | (S::ResolvingClaw, S::OfferRequested | S::Denied | S::Failed)
                | (S::OfferRequested, S::OfferReady | S::Denied | S::Failed)
                | (
                    S::OfferReady,
                    S::DialingRelay | S::Expired | S::Revoked | S::Failed
                )
                | (
                    S::DialingRelay,
                    S::Authenticating | S::RelayUnavailable | S::Failed
                )
                | (
                    S::Authenticating,
                    S::InstallingRoute | S::Denied | S::Revoked | S::Failed
                )
                | (S::InstallingRoute, S::Connected | S::Failed)
                | (
                    S::Connected,
                    S::DegradedControl | S::Disconnecting | S::Revoked | S::Failed
                )
                | (
                    S::DegradedControl,
                    S::Connected | S::Disconnecting | S::Revoked | S::Failed,
                )
                | (S::Disconnecting, S::Disconnected | S::FailedTeardown)
                | (
                    S::Disconnected | S::Denied | S::Revoked | S::Failed,
                    S::Available | S::Unavailable
                )
                | (
                    S::Expired | S::RelayUnavailable,
                    S::Available | S::OfferRequested
                )
                | (S::FailedTeardown, S::Unavailable)
                | (S::Unavailable, S::Available)
        )
    }
}

/// Claw-side responder product state for one selected session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnResponderState {
    NotInstalled,
    Installed,
    Available,
    OfferArmed,
    DialingRelay,
    Authenticating,
    OpeningInterface,
    Serving,
    Draining,
    Closed,
    Denied,
    Expired,
    Revoked,
    RelayUnavailable,
    Unavailable,
    Failed,
    FailedTeardown,
}

impl ClawVpnResponderState {
    #[must_use]
    pub fn public_status(self) -> ClawVpnMobilePublicStatus {
        match self {
            Self::NotInstalled | Self::Unavailable => ClawVpnMobilePublicStatus::Unavailable,
            Self::Installed | Self::Available => ClawVpnMobilePublicStatus::Available,
            Self::OfferArmed
            | Self::DialingRelay
            | Self::Authenticating
            | Self::OpeningInterface => ClawVpnMobilePublicStatus::Connecting,
            Self::Serving => ClawVpnMobilePublicStatus::Connected,
            Self::Draining => ClawVpnMobilePublicStatus::Disconnecting,
            Self::Closed => ClawVpnMobilePublicStatus::Disconnected,
            Self::Denied => ClawVpnMobilePublicStatus::Denied,
            Self::Expired => ClawVpnMobilePublicStatus::Expired,
            Self::Revoked => ClawVpnMobilePublicStatus::Revoked,
            Self::RelayUnavailable => ClawVpnMobilePublicStatus::RelayUnavailable,
            Self::Failed => ClawVpnMobilePublicStatus::Failed,
            Self::FailedTeardown => ClawVpnMobilePublicStatus::RepairRequired,
        }
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use ClawVpnResponderState as S;
        matches!(
            (self, next),
            (S::NotInstalled, S::Installed)
                | (
                    S::Installed | S::Closed | S::Denied | S::Failed,
                    S::Available | S::Unavailable
                )
                | (S::Available, S::OfferArmed | S::Unavailable | S::Revoked)
                | (S::OfferArmed, S::DialingRelay | S::Expired | S::Revoked)
                | (
                    S::DialingRelay,
                    S::Authenticating | S::RelayUnavailable | S::Failed
                )
                | (
                    S::Authenticating,
                    S::OpeningInterface | S::Denied | S::Revoked | S::Failed
                )
                | (S::OpeningInterface, S::Serving | S::Failed)
                | (S::Serving, S::Draining | S::Revoked | S::Failed)
                | (S::Draining, S::Closed | S::FailedTeardown)
                | (
                    S::Expired | S::RelayUnavailable | S::Unavailable,
                    S::Available
                )
                | (S::Revoked, S::Draining)
                | (S::FailedTeardown, S::Unavailable)
        )
    }
}

/// Mesh/control-plane offer and session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnMeshSessionState {
    NoAcl,
    AclGranted,
    OfferMinted,
    OfferConsumed,
    SessionActive,
    SessionDegraded,
    SessionClosed,
    OfferExpired,
    OfferRevoked,
    AclRevoked,
    SessionRevoked,
    SessionFailed,
}

impl ClawVpnMeshSessionState {
    #[must_use]
    pub fn public_status(self) -> ClawVpnMobilePublicStatus {
        match self {
            Self::NoAcl | Self::AclRevoked => ClawVpnMobilePublicStatus::Denied,
            Self::AclGranted => ClawVpnMobilePublicStatus::Available,
            Self::OfferMinted | Self::OfferConsumed => ClawVpnMobilePublicStatus::Connecting,
            Self::SessionActive => ClawVpnMobilePublicStatus::Connected,
            Self::SessionDegraded => ClawVpnMobilePublicStatus::ConnectedDegradedControl,
            Self::SessionClosed => ClawVpnMobilePublicStatus::Disconnected,
            Self::OfferExpired => ClawVpnMobilePublicStatus::Expired,
            Self::OfferRevoked | Self::SessionRevoked => ClawVpnMobilePublicStatus::Revoked,
            Self::SessionFailed => ClawVpnMobilePublicStatus::Failed,
        }
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use ClawVpnMeshSessionState as S;
        matches!(
            (self, next),
            (S::NoAcl | S::OfferExpired | S::OfferRevoked, S::AclGranted)
                | (S::AclGranted, S::OfferMinted | S::AclRevoked)
                | (
                    S::OfferMinted,
                    S::OfferConsumed | S::OfferExpired | S::OfferRevoked
                )
                | (S::OfferConsumed, S::SessionActive | S::SessionFailed)
                | (
                    S::SessionActive,
                    S::SessionDegraded | S::SessionClosed | S::SessionRevoked
                )
                | (
                    S::SessionDegraded,
                    S::SessionActive | S::SessionClosed | S::SessionRevoked,
                )
                | (
                    S::SessionClosed | S::SessionFailed,
                    S::AclGranted | S::AclRevoked
                )
                | (S::AclRevoked, S::NoAcl)
                | (S::SessionRevoked, S::AclRevoked | S::SessionClosed)
        )
    }
}

/// Redacted transition error for pure model validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnStateTransitionError<S> {
    from: S,
    to: S,
}

impl<S: Copy> ClawVpnStateTransitionError<S> {
    #[must_use]
    pub fn from(&self) -> S {
        self.from
    }

    #[must_use]
    pub fn to(&self) -> S {
        self.to
    }
}

impl<S> fmt::Display for ClawVpnStateTransitionError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Product A mobile VPN state transition")
    }
}

impl<S: fmt::Debug> std::error::Error for ClawVpnStateTransitionError<S> {}

pub fn transition_device_tunnel(
    from: ClawVpnDeviceTunnelState,
    to: ClawVpnDeviceTunnelState,
) -> Result<ClawVpnDeviceTunnelState, ClawVpnStateTransitionError<ClawVpnDeviceTunnelState>> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(ClawVpnStateTransitionError { from, to })
    }
}

pub fn transition_responder(
    from: ClawVpnResponderState,
    to: ClawVpnResponderState,
) -> Result<ClawVpnResponderState, ClawVpnStateTransitionError<ClawVpnResponderState>> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(ClawVpnStateTransitionError { from, to })
    }
}

pub fn transition_mesh_session(
    from: ClawVpnMeshSessionState,
    to: ClawVpnMeshSessionState,
) -> Result<ClawVpnMeshSessionState, ClawVpnStateTransitionError<ClawVpnMeshSessionState>> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(ClawVpnStateTransitionError { from, to })
    }
}

/// Opaque, redacted member identifier for the pure mobile Mesh-C model.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileMemberId(String);

impl fmt::Debug for ClawVpnMobileMemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClawVpnMobileMemberId(<redacted>)")
    }
}

impl ClawVpnMobileMemberId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ClawVpnMobileMeshError> {
        validate_nonempty_trimmed(value.into()).map(Self)
    }
}

/// Opaque, redacted device identifier for the pure mobile Mesh-C model.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileDeviceId(String);

impl fmt::Debug for ClawVpnMobileDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClawVpnMobileDeviceId(<redacted>)")
    }
}

impl ClawVpnMobileDeviceId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ClawVpnMobileMeshError> {
        validate_nonempty_trimmed(value.into()).map(Self)
    }
}

/// Opaque, redacted Claw identifier for the pure mobile Mesh-C model.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileClawId(String);

impl fmt::Debug for ClawVpnMobileClawId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClawVpnMobileClawId(<redacted>)")
    }
}

impl ClawVpnMobileClawId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ClawVpnMobileMeshError> {
        validate_nonempty_trimmed(value.into()).map(Self)
    }
}

/// Pure ACL relation for one mobile Device-D and one selected Claw.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileAclGrant {
    member: ClawVpnMobileMemberId,
    device: ClawVpnMobileDeviceId,
    claw: ClawVpnMobileClawId,
}

impl fmt::Debug for ClawVpnMobileAclGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileAclGrant")
            .field("member", &"<redacted>")
            .field("device", &"<redacted>")
            .field("claw", &"<redacted>")
            .finish()
    }
}

impl ClawVpnMobileAclGrant {
    #[must_use]
    pub fn new(
        member: ClawVpnMobileMemberId,
        device: ClawVpnMobileDeviceId,
        claw: ClawVpnMobileClawId,
    ) -> Self {
        Self {
            member,
            device,
            claw,
        }
    }
}

/// Redacted opaque offer id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileOfferId(u64);

impl fmt::Debug for ClawVpnMobileOfferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClawVpnMobileOfferId(<redacted>)")
    }
}

/// Redacted opaque active-session id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClawVpnMobileSessionId(u64);

impl fmt::Debug for ClawVpnMobileSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClawVpnMobileSessionId(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClawVpnMobileOfferState {
    Minted,
    Consumed,
    Revoked,
}

#[derive(Clone, PartialEq, Eq)]
struct ClawVpnMobileOffer {
    grant: ClawVpnMobileAclGrant,
    expires_at: u64,
    state: ClawVpnMobileOfferState,
}

impl fmt::Debug for ClawVpnMobileOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileOffer")
            .field("grant", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ClawVpnMobileSession {
    grant: ClawVpnMobileAclGrant,
}

impl fmt::Debug for ClawVpnMobileSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileSession")
            .field("grant", &"<redacted>")
            .finish()
    }
}

/// Pure in-memory Mesh-C authorization model for Product A mobile Claw VPN.
///
/// This model grants no real access and opens no relay or tunnel. It exists to
/// make the ACL/offer/session state machine testable before the real storage,
/// iOS Packet Tunnel, and responder integrations exist.
#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnMobileMesh {
    enrolled_devices: HashSet<ClawVpnMobileDeviceId>,
    available_claws: HashSet<ClawVpnMobileClawId>,
    grants: HashSet<ClawVpnMobileAclGrant>,
    offers: HashMap<ClawVpnMobileOfferId, ClawVpnMobileOffer>,
    sessions: HashMap<ClawVpnMobileSessionId, ClawVpnMobileSession>,
    next_offer_id: u64,
    next_session_id: u64,
    offer_ttl_secs: u64,
}

impl fmt::Debug for ClawVpnMobileMesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileMesh")
            .field("enrolled_devices", &self.enrolled_devices.len())
            .field("available_claws", &self.available_claws.len())
            .field("grants", &self.grants.len())
            .field("offers", &self.offers.len())
            .field("sessions", &self.sessions.len())
            .field("next_offer_id", &"<redacted>")
            .field("next_session_id", &"<redacted>")
            .field("offer_ttl_secs", &self.offer_ttl_secs)
            .finish()
    }
}

impl ClawVpnMobileMesh {
    pub fn new(offer_ttl_secs: u64) -> Result<Self, ClawVpnMobileMeshError> {
        if offer_ttl_secs == 0 {
            return Err(ClawVpnMobileMeshError::ZeroOfferTtl);
        }
        Ok(Self {
            enrolled_devices: HashSet::new(),
            available_claws: HashSet::new(),
            grants: HashSet::new(),
            offers: HashMap::new(),
            sessions: HashMap::new(),
            next_offer_id: 1,
            next_session_id: 1,
            offer_ttl_secs,
        })
    }

    #[must_use]
    pub fn enroll_device(&mut self, device: ClawVpnMobileDeviceId) -> bool {
        self.enrolled_devices.insert(device)
    }

    #[must_use]
    pub fn set_claw_available(&mut self, claw: ClawVpnMobileClawId) -> bool {
        self.available_claws.insert(claw)
    }

    #[must_use]
    pub fn set_claw_unavailable(&mut self, claw: &ClawVpnMobileClawId) -> bool {
        self.available_claws.remove(claw)
    }

    #[must_use]
    pub fn grant(&mut self, grant: ClawVpnMobileAclGrant) -> bool {
        self.grants.insert(grant)
    }

    pub fn revoke(&mut self, grant: &ClawVpnMobileAclGrant) -> ClawVpnMobileMeshRevocation {
        let grant_removed = self.grants.remove(grant);
        let mut offer_count = 0usize;
        for offer in self.offers.values_mut() {
            if &offer.grant == grant && offer.state == ClawVpnMobileOfferState::Minted {
                offer.state = ClawVpnMobileOfferState::Revoked;
                offer_count += 1;
            }
        }
        let session_ids: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| (&session.grant == grant).then_some(*session_id))
            .collect();
        let session_count = session_ids.len();
        for session_id in session_ids {
            self.sessions.remove(&session_id);
        }
        ClawVpnMobileMeshRevocation {
            grant_removed,
            revoked_offer_count: offer_count,
            closed_session_count: session_count,
        }
    }

    pub fn mint_offer(
        &mut self,
        grant: &ClawVpnMobileAclGrant,
        now_unix: u64,
    ) -> Result<ClawVpnMobileOfferId, ClawVpnMobileMeshError> {
        self.check_grant_ready(grant)?;
        let expires_at = now_unix
            .checked_add(self.offer_ttl_secs)
            .ok_or(ClawVpnMobileMeshError::TimeOverflow)?;
        let offer_id = ClawVpnMobileOfferId(self.next_offer_id);
        self.next_offer_id = self
            .next_offer_id
            .checked_add(1)
            .ok_or(ClawVpnMobileMeshError::IdExhausted)?;
        self.offers.insert(
            offer_id,
            ClawVpnMobileOffer {
                grant: grant.clone(),
                expires_at,
                state: ClawVpnMobileOfferState::Minted,
            },
        );
        Ok(offer_id)
    }

    pub fn consume_offer(
        &mut self,
        offer_id: ClawVpnMobileOfferId,
        grant: &ClawVpnMobileAclGrant,
        now_unix: u64,
    ) -> Result<ClawVpnMobileSessionId, ClawVpnMobileMeshError> {
        self.check_grant_ready(grant)?;
        let offer = self
            .offers
            .get_mut(&offer_id)
            .ok_or(ClawVpnMobileMeshError::UnknownOffer)?;
        if &offer.grant != grant {
            return Err(ClawVpnMobileMeshError::SelectedClawMismatch);
        }
        match offer.state {
            ClawVpnMobileOfferState::Minted => {}
            ClawVpnMobileOfferState::Consumed => {
                return Err(ClawVpnMobileMeshError::OfferAlreadyConsumed);
            }
            ClawVpnMobileOfferState::Revoked => return Err(ClawVpnMobileMeshError::Revoked),
        }
        if now_unix >= offer.expires_at {
            return Err(ClawVpnMobileMeshError::OfferExpired);
        }
        offer.state = ClawVpnMobileOfferState::Consumed;
        let session_id = ClawVpnMobileSessionId(self.next_session_id);
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(ClawVpnMobileMeshError::IdExhausted)?;
        self.sessions.insert(
            session_id,
            ClawVpnMobileSession {
                grant: grant.clone(),
            },
        );
        Ok(session_id)
    }

    pub fn close_session(
        &mut self,
        session_id: ClawVpnMobileSessionId,
    ) -> Result<(), ClawVpnMobileMeshError> {
        self.sessions
            .remove(&session_id)
            .map(|_| ())
            .ok_or(ClawVpnMobileMeshError::UnknownSession)
    }

    #[must_use]
    pub fn has_active_session(&self, session_id: ClawVpnMobileSessionId) -> bool {
        self.sessions.contains_key(&session_id)
    }

    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    fn check_grant_ready(
        &self,
        grant: &ClawVpnMobileAclGrant,
    ) -> Result<(), ClawVpnMobileMeshError> {
        if !self.enrolled_devices.contains(&grant.device) {
            return Err(ClawVpnMobileMeshError::DeviceNotEnrolled);
        }
        if !self.available_claws.contains(&grant.claw) {
            return Err(ClawVpnMobileMeshError::ClawUnavailable);
        }
        if !self.grants.contains(grant) {
            return Err(ClawVpnMobileMeshError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnMobileMeshRevocation {
    grant_removed: bool,
    revoked_offer_count: usize,
    closed_session_count: usize,
}

impl ClawVpnMobileMeshRevocation {
    #[must_use]
    pub fn grant_removed(&self) -> bool {
        self.grant_removed
    }

    #[must_use]
    pub fn revoked_offer_count(&self) -> usize {
        self.revoked_offer_count
    }

    #[must_use]
    pub fn closed_session_count(&self) -> usize {
        self.closed_session_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnMobileMeshError {
    EmptyId,
    InvalidId,
    ZeroOfferTtl,
    TimeOverflow,
    IdExhausted,
    DeviceNotEnrolled,
    ClawUnavailable,
    Unauthorized,
    UnknownOffer,
    OfferExpired,
    OfferAlreadyConsumed,
    Revoked,
    SelectedClawMismatch,
    UnknownSession,
}

impl fmt::Display for ClawVpnMobileMeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Product A mobile VPN mesh check failed")
    }
}

impl std::error::Error for ClawVpnMobileMeshError {}

fn validate_nonempty_trimmed(value: String) -> Result<String, ClawVpnMobileMeshError> {
    if value.trim().is_empty() {
        return Err(ClawVpnMobileMeshError::EmptyId);
    }
    if value.trim() != value {
        return Err(ClawVpnMobileMeshError::InvalidId);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> ClawVpnMobileMemberId {
        ClawVpnMobileMemberId::try_new("member-alpha").unwrap()
    }

    fn device() -> ClawVpnMobileDeviceId {
        ClawVpnMobileDeviceId::try_new("device-alpha").unwrap()
    }

    fn claw_m() -> ClawVpnMobileClawId {
        ClawVpnMobileClawId::try_new("claw-m").unwrap()
    }

    fn claw_l() -> ClawVpnMobileClawId {
        ClawVpnMobileClawId::try_new("claw-l").unwrap()
    }

    fn grant_for(claw: ClawVpnMobileClawId) -> ClawVpnMobileAclGrant {
        ClawVpnMobileAclGrant::new(member(), device(), claw)
    }

    fn ready_mesh(grant: &ClawVpnMobileAclGrant) -> ClawVpnMobileMesh {
        let mut mesh = ClawVpnMobileMesh::new(60).unwrap();
        assert!(mesh.enroll_device(device()));
        assert!(mesh.set_claw_available(grant.claw.clone()));
        assert!(mesh.grant(grant.clone()));
        mesh
    }

    #[test]
    fn device_connected_is_only_reachable_after_auth_and_route_install() {
        assert!(
            !ClawVpnDeviceTunnelState::Available
                .can_transition_to(ClawVpnDeviceTunnelState::Connected)
        );
        assert!(
            !ClawVpnDeviceTunnelState::OfferReady
                .can_transition_to(ClawVpnDeviceTunnelState::InstallingRoute)
        );
        assert!(
            ClawVpnDeviceTunnelState::Authenticating
                .can_transition_to(ClawVpnDeviceTunnelState::InstallingRoute)
        );
        assert!(
            ClawVpnDeviceTunnelState::InstallingRoute
                .can_transition_to(ClawVpnDeviceTunnelState::Connected)
        );
    }

    #[test]
    fn device_failures_do_not_skip_to_connected_or_leave_success_status() {
        assert_eq!(
            ClawVpnDeviceTunnelState::Denied.public_status(),
            ClawVpnMobilePublicStatus::Denied
        );
        assert_eq!(
            ClawVpnDeviceTunnelState::RelayUnavailable.public_status(),
            ClawVpnMobilePublicStatus::RelayUnavailable
        );
        assert_eq!(
            ClawVpnDeviceTunnelState::FailedTeardown.public_status(),
            ClawVpnMobilePublicStatus::RepairRequired
        );
        assert!(
            !ClawVpnDeviceTunnelState::RelayUnavailable
                .can_transition_to(ClawVpnDeviceTunnelState::Connected)
        );
        assert!(
            !ClawVpnDeviceTunnelState::FailedTeardown
                .can_transition_to(ClawVpnDeviceTunnelState::Available)
        );
    }

    #[test]
    fn responder_serving_requires_auth_and_interface_open() {
        assert!(
            !ClawVpnResponderState::Available.can_transition_to(ClawVpnResponderState::Serving)
        );
        assert!(
            !ClawVpnResponderState::OfferArmed
                .can_transition_to(ClawVpnResponderState::OpeningInterface)
        );
        assert!(
            !ClawVpnResponderState::DialingRelay
                .can_transition_to(ClawVpnResponderState::OpeningInterface)
        );
        assert!(
            ClawVpnResponderState::Authenticating
                .can_transition_to(ClawVpnResponderState::OpeningInterface)
        );
        assert!(
            ClawVpnResponderState::OpeningInterface
                .can_transition_to(ClawVpnResponderState::Serving)
        );
    }

    #[test]
    fn responder_revocation_drains_before_close() {
        assert!(
            ClawVpnResponderState::Authenticating.can_transition_to(ClawVpnResponderState::Revoked)
        );
        assert!(
            !ClawVpnResponderState::Revoked
                .can_transition_to(ClawVpnResponderState::OpeningInterface)
        );
        assert!(ClawVpnResponderState::Serving.can_transition_to(ClawVpnResponderState::Revoked));
        assert!(ClawVpnResponderState::Revoked.can_transition_to(ClawVpnResponderState::Draining));
        assert!(!ClawVpnResponderState::Revoked.can_transition_to(ClawVpnResponderState::Closed));
        assert!(ClawVpnResponderState::Draining.can_transition_to(ClawVpnResponderState::Closed));
    }

    #[test]
    fn mesh_session_requires_acl_and_offer_before_active_session() {
        assert!(
            !ClawVpnMeshSessionState::NoAcl.can_transition_to(ClawVpnMeshSessionState::OfferMinted)
        );
        assert!(
            !ClawVpnMeshSessionState::AclGranted
                .can_transition_to(ClawVpnMeshSessionState::SessionActive)
        );
        assert!(
            ClawVpnMeshSessionState::AclGranted
                .can_transition_to(ClawVpnMeshSessionState::OfferMinted)
        );
        assert!(
            ClawVpnMeshSessionState::OfferMinted
                .can_transition_to(ClawVpnMeshSessionState::OfferConsumed)
        );
        assert!(
            ClawVpnMeshSessionState::OfferConsumed
                .can_transition_to(ClawVpnMeshSessionState::SessionActive)
        );
    }

    #[test]
    fn mesh_offer_and_closed_session_are_not_replayable() {
        assert!(
            !ClawVpnMeshSessionState::OfferConsumed
                .can_transition_to(ClawVpnMeshSessionState::OfferConsumed)
        );
        assert!(
            !ClawVpnMeshSessionState::OfferConsumed
                .can_transition_to(ClawVpnMeshSessionState::OfferMinted)
        );
        assert!(
            !ClawVpnMeshSessionState::SessionClosed
                .can_transition_to(ClawVpnMeshSessionState::SessionActive)
        );
        assert!(
            ClawVpnMeshSessionState::SessionClosed
                .can_transition_to(ClawVpnMeshSessionState::AclGranted)
        );
        assert!(
            ClawVpnMeshSessionState::AclGranted
                .can_transition_to(ClawVpnMeshSessionState::OfferMinted)
        );
    }

    #[test]
    fn mesh_revocation_is_not_a_success_state() {
        assert_eq!(
            ClawVpnMeshSessionState::AclRevoked.public_status(),
            ClawVpnMobilePublicStatus::Denied
        );
        assert_eq!(
            ClawVpnMeshSessionState::SessionRevoked.public_status(),
            ClawVpnMobilePublicStatus::Revoked
        );
        assert!(
            ClawVpnMeshSessionState::SessionActive
                .can_transition_to(ClawVpnMeshSessionState::SessionRevoked)
        );
        assert!(
            ClawVpnMeshSessionState::SessionRevoked
                .can_transition_to(ClawVpnMeshSessionState::AclRevoked)
        );
    }

    #[test]
    fn mobile_mesh_requires_enrollment_availability_and_acl_before_offer() {
        let grant = grant_for(claw_m());
        let mut mesh = ClawVpnMobileMesh::new(60).unwrap();

        assert_eq!(
            mesh.mint_offer(&grant, 10),
            Err(ClawVpnMobileMeshError::DeviceNotEnrolled)
        );
        assert!(mesh.enroll_device(device()));
        assert_eq!(
            mesh.mint_offer(&grant, 10),
            Err(ClawVpnMobileMeshError::ClawUnavailable)
        );
        assert!(mesh.set_claw_available(claw_m()));
        assert_eq!(
            mesh.mint_offer(&grant, 10),
            Err(ClawVpnMobileMeshError::Unauthorized)
        );
        assert!(mesh.grant(grant.clone()));

        let offer = mesh.mint_offer(&grant, 10).unwrap();
        assert_eq!(format!("{offer:?}"), "ClawVpnMobileOfferId(<redacted>)");
    }

    #[test]
    fn mobile_mesh_offer_is_single_use_and_second_connection_needs_new_offer() {
        let grant = grant_for(claw_m());
        let mut mesh = ready_mesh(&grant);
        let first_offer = mesh.mint_offer(&grant, 10).unwrap();
        let first_session = mesh.consume_offer(first_offer, &grant, 20).unwrap();

        assert!(mesh.has_active_session(first_session));
        assert_eq!(mesh.active_session_count(), 1);
        assert_eq!(
            mesh.consume_offer(first_offer, &grant, 21),
            Err(ClawVpnMobileMeshError::OfferAlreadyConsumed)
        );

        mesh.close_session(first_session).unwrap();
        assert!(!mesh.has_active_session(first_session));
        assert_eq!(
            mesh.close_session(first_session),
            Err(ClawVpnMobileMeshError::UnknownSession)
        );

        let second_offer = mesh.mint_offer(&grant, 22).unwrap();
        let second_session = mesh.consume_offer(second_offer, &grant, 23).unwrap();
        assert!(mesh.has_active_session(second_session));
        assert_ne!(first_session, second_session);
    }

    #[test]
    fn mobile_mesh_expired_and_revoked_offers_do_not_start_sessions() {
        let grant = grant_for(claw_m());
        let mut expired_mesh = ready_mesh(&grant);
        let expired_offer = expired_mesh.mint_offer(&grant, 10).unwrap();
        assert_eq!(
            expired_mesh.consume_offer(expired_offer, &grant, 70),
            Err(ClawVpnMobileMeshError::OfferExpired)
        );
        assert_eq!(expired_mesh.active_session_count(), 0);

        let mut revoked_mesh = ready_mesh(&grant);
        let revoked_offer = revoked_mesh.mint_offer(&grant, 10).unwrap();
        let revocation = revoked_mesh.revoke(&grant);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.revoked_offer_count(), 1);
        assert_eq!(revocation.closed_session_count(), 0);
        assert_eq!(
            revoked_mesh.consume_offer(revoked_offer, &grant, 20),
            Err(ClawVpnMobileMeshError::Unauthorized)
        );
        assert_eq!(revoked_mesh.active_session_count(), 0);
    }

    #[test]
    fn mobile_mesh_claw_unavailable_after_mint_denies_consumption() {
        let grant = grant_for(claw_m());
        let mut mesh = ready_mesh(&grant);
        let stale_offer = mesh.mint_offer(&grant, 10).unwrap();

        assert!(mesh.set_claw_unavailable(&claw_m()));
        assert_eq!(
            mesh.consume_offer(stale_offer, &grant, 20),
            Err(ClawVpnMobileMeshError::ClawUnavailable)
        );
        assert_eq!(mesh.active_session_count(), 0);

        assert!(mesh.set_claw_available(claw_m()));
        let fresh_offer = mesh.mint_offer(&grant, 21).unwrap();
        let session = mesh.consume_offer(fresh_offer, &grant, 22).unwrap();
        assert!(mesh.has_active_session(session));
    }

    #[test]
    fn mobile_mesh_selected_claw_mismatch_denies_offer_consumption() {
        let grant_m = grant_for(claw_m());
        let grant_l = grant_for(claw_l());
        let mut mesh = ready_mesh(&grant_m);
        assert!(mesh.set_claw_available(claw_l()));
        assert!(mesh.grant(grant_l.clone()));
        let offer_for_m = mesh.mint_offer(&grant_m, 10).unwrap();

        assert_eq!(
            mesh.consume_offer(offer_for_m, &grant_l, 20),
            Err(ClawVpnMobileMeshError::SelectedClawMismatch)
        );
        let session = mesh.consume_offer(offer_for_m, &grant_m, 21).unwrap();
        assert!(mesh.has_active_session(session));
    }

    #[test]
    fn mobile_mesh_revocation_closes_only_matching_sessions() {
        let grant_m = grant_for(claw_m());
        let grant_l = grant_for(claw_l());
        let mut mesh = ready_mesh(&grant_m);
        assert!(mesh.set_claw_available(claw_l()));
        assert!(mesh.grant(grant_l.clone()));

        let offer_m = mesh.mint_offer(&grant_m, 10).unwrap();
        let offer_l = mesh.mint_offer(&grant_l, 10).unwrap();
        let session_m = mesh.consume_offer(offer_m, &grant_m, 20).unwrap();
        let session_l = mesh.consume_offer(offer_l, &grant_l, 20).unwrap();

        let revocation = mesh.revoke(&grant_m);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert!(!mesh.has_active_session(session_m));
        assert!(mesh.has_active_session(session_l));
        assert_eq!(mesh.active_session_count(), 1);
    }

    #[test]
    fn mobile_mesh_debug_and_errors_do_not_echo_identifiers() {
        let member = ClawVpnMobileMemberId::try_new("member-secret").unwrap();
        let device = ClawVpnMobileDeviceId::try_new("device-secret").unwrap();
        let claw = ClawVpnMobileClawId::try_new("claw-secret").unwrap();
        let grant = ClawVpnMobileAclGrant::new(member, device.clone(), claw.clone());
        let mut mesh = ClawVpnMobileMesh::new(60).unwrap();
        assert!(mesh.enroll_device(device));
        assert!(mesh.set_claw_available(claw));
        assert!(mesh.grant(grant.clone()));
        let offer = mesh.mint_offer(&grant, 10).unwrap();

        let debug = format!("{grant:?} {mesh:?} {offer:?}");
        assert!(!debug.contains("member-secret"));
        assert!(!debug.contains("device-secret"));
        assert!(!debug.contains("claw-secret"));
        assert!(debug.contains("<redacted>"));

        assert_eq!(
            ClawVpnMobileMeshError::Unauthorized.to_string(),
            "Product A mobile VPN mesh check failed"
        );
        assert_eq!(
            ClawVpnMobileDeviceId::try_new(" device-secret"),
            Err(ClawVpnMobileMeshError::InvalidId)
        );
        assert_eq!(
            ClawVpnMobileClawId::try_new(" "),
            Err(ClawVpnMobileMeshError::EmptyId)
        );
    }

    #[test]
    fn invalid_transition_error_is_redacted() {
        let error = transition_device_tunnel(
            ClawVpnDeviceTunnelState::Available,
            ClawVpnDeviceTunnelState::Connected,
        )
        .unwrap_err();
        assert_eq!(error.from(), ClawVpnDeviceTunnelState::Available);
        assert_eq!(error.to(), ClawVpnDeviceTunnelState::Connected);
        assert_eq!(
            error.to_string(),
            "invalid Product A mobile VPN state transition"
        );
    }
}
