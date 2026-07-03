//! Pure packet-policy helpers for the Product A per-Claw VPN.
//!
//! This module intentionally does not create TUN/utun interfaces, routes, or
//! relay sessions. It is the fail-closed packet filter that the future claw VPN
//! agent can call before forwarding an IP packet between a single device and a
//! single claw.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;

use crate::claw_share_data_tunnel::TunnelFrame;
use crate::keys::P256PublicKey;
use sha2::{Digest, Sha256};

/// Conservative v1 inner MTU from the plan. The future runtime can lower this
/// per path, but this shared contract keeps oversized packets from becoming
/// unbounded stream payloads.
pub const CLAW_VPN_V1_INNER_MTU: usize = 1250;
pub const CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW: usize = 1;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;
const CGNAT_START: u32 = u32::from_be_bytes([100, 64, 0, 0]);
const CGNAT_END: u32 = u32::from_be_bytes([100, 127, 255, 255]);
const RFC1918_10_START: u32 = u32::from_be_bytes([10, 0, 0, 0]);
const RFC1918_10_END: u32 = u32::from_be_bytes([10, 255, 255, 255]);
const RFC1918_172_START: u32 = u32::from_be_bytes([172, 16, 0, 0]);
const RFC1918_172_END: u32 = u32::from_be_bytes([172, 31, 255, 255]);
const RFC1918_192_START: u32 = u32::from_be_bytes([192, 168, 0, 0]);
const RFC1918_192_END: u32 = u32::from_be_bytes([192, 168, 255, 255]);

/// The two inner tunnel addresses authorized for one per-Claw VPN session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnSessionAddrs {
    device: Ipv4Addr,
    claw: Ipv4Addr,
}

impl fmt::Debug for ClawVpnSessionAddrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnSessionAddrs")
            .field("device", &"<redacted>")
            .field("claw", &"<redacted>")
            .finish()
    }
}

impl ClawVpnSessionAddrs {
    pub fn try_new(device: Ipv4Addr, claw: Ipv4Addr) -> Result<Self, ClawVpnAddressError> {
        validate_inner_addr(device)?;
        validate_inner_addr(claw)?;
        if device == claw {
            return Err(ClawVpnAddressError::SameAddress);
        }
        Ok(Self { device, claw })
    }

    #[must_use]
    pub fn device(&self) -> Ipv4Addr {
        self.device
    }

    #[must_use]
    pub fn claw(&self) -> Ipv4Addr {
        self.claw
    }
}

/// IPv4 prefix allocator for v1 per-session point-to-point address pairs.
///
/// It rejects prefixes that overlap CGNAT or common home-LAN ranges, because a
/// per-Claw route must not collide with Tailscale or the user's local network.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnIpv4Pool {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl fmt::Debug for ClawVpnIpv4Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnIpv4Pool")
            .field("network", &"<redacted>")
            .field("prefix_len", &self.prefix_len)
            .finish()
    }
}

impl ClawVpnIpv4Pool {
    pub fn try_new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, ClawVpnPoolError> {
        if prefix_len > 30 {
            return Err(ClawVpnPoolError::PrefixTooSmall);
        }
        let mask = ipv4_prefix_mask(prefix_len);
        let network_u32 = u32::from(network);
        if network_u32 & !mask != 0 {
            return Err(ClawVpnPoolError::HostBitsSet);
        }
        let (start, end) = ipv4_prefix_range(network_u32, prefix_len);
        if ranges_overlap(start, end, CGNAT_START, CGNAT_END)
            || ranges_overlap(start, end, RFC1918_10_START, RFC1918_10_END)
            || ranges_overlap(start, end, RFC1918_172_START, RFC1918_172_END)
            || ranges_overlap(start, end, RFC1918_192_START, RFC1918_192_END)
        {
            return Err(ClawVpnPoolError::OverlapsReservedRange);
        }
        validate_inner_addr(network).map_err(|_| ClawVpnPoolError::InvalidNetwork)?;
        Ok(Self {
            network,
            prefix_len,
        })
    }

    #[must_use]
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn allocate_pair(
        &self,
        session_index: u32,
    ) -> Result<ClawVpnSessionAddrs, ClawVpnPoolError> {
        let network = u32::from(self.network);
        let (_, end) = ipv4_prefix_range(network, self.prefix_len);
        let first_usable = network.checked_add(1).ok_or(ClawVpnPoolError::Exhausted)?;
        let offset = session_index
            .checked_mul(2)
            .ok_or(ClawVpnPoolError::Exhausted)?;
        let device = first_usable
            .checked_add(offset)
            .ok_or(ClawVpnPoolError::Exhausted)?;
        let claw = device.checked_add(1).ok_or(ClawVpnPoolError::Exhausted)?;
        if claw >= end {
            return Err(ClawVpnPoolError::Exhausted);
        }
        ClawVpnSessionAddrs::try_new(Ipv4Addr::from(device), Ipv4Addr::from(claw))
            .map_err(|_| ClawVpnPoolError::Exhausted)
    }
}

/// One explicit per-Claw VPN authorization relation.
///
/// This is intentionally separate from `relay_stream` PTY/ClawSite grants: holding
/// another resource capability must not imply VPN access.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnAclKey {
    member_id: String,
    device_pub: P256PublicKey,
    claw_id: String,
}

impl fmt::Debug for ClawVpnAclKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAclKey")
            .field("member_id", &"<redacted>")
            .field("device_pub", &"<redacted>")
            .field("claw_id", &"<redacted>")
            .finish()
    }
}

impl ClawVpnAclKey {
    pub fn try_new(
        member_id: impl Into<String>,
        device_pub: P256PublicKey,
        claw_id: impl Into<String>,
    ) -> Result<Self, ClawVpnAclError> {
        let member_id = member_id.into();
        let claw_id = claw_id.into();
        if member_id.trim().is_empty() {
            return Err(ClawVpnAclError::EmptyMemberId);
        }
        if member_id.trim() != member_id {
            return Err(ClawVpnAclError::InvalidMemberId);
        }
        if claw_id.trim().is_empty() {
            return Err(ClawVpnAclError::EmptyClawId);
        }
        if claw_id.trim() != claw_id {
            return Err(ClawVpnAclError::InvalidClawId);
        }
        Ok(Self {
            member_id,
            device_pub,
            claw_id,
        })
    }

    #[must_use]
    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    #[must_use]
    pub fn device_pub(&self) -> &P256PublicKey {
        &self.device_pub
    }

    #[must_use]
    pub fn claw_id(&self) -> &str {
        &self.claw_id
    }
}

/// In-memory model of the N:N per-Claw VPN ACL.
///
/// This is a pure policy helper for tests and future storage/wiring. It is not a
/// runtime session registry and does not open routes or tunnels.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ClawVpnAcl {
    grants: HashSet<ClawVpnAclKey>,
}

impl fmt::Debug for ClawVpnAcl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAcl")
            .field("grant_count", &self.grants.len())
            .finish()
    }
}

impl ClawVpnAcl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(&mut self, key: ClawVpnAclKey) -> bool {
        self.grants.insert(key)
    }

    pub fn revoke(&mut self, key: &ClawVpnAclKey) -> bool {
        self.grants.remove(key)
    }

    #[must_use]
    pub fn is_authorized(&self, key: &ClawVpnAclKey) -> bool {
        self.grants.contains(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

/// Opaque in-process session id for the future per-Claw VPN runtime.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClawVpnSessionId(u64);

impl fmt::Debug for ClawVpnSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClawVpnSessionId")
            .field(&"<redacted>")
            .finish()
    }
}

/// A single authorized, address-assigned per-Claw VPN session.
///
/// This is still only a policy model: it does not install routes, create a
/// TUN/utun device, or open a relay stream.
#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnSession {
    id: ClawVpnSessionId,
    acl_key: ClawVpnAclKey,
    session_index: u32,
    addrs: ClawVpnSessionAddrs,
}

impl fmt::Debug for ClawVpnSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnSession")
            .field("id", &self.id)
            .field("acl_key", &"<redacted>")
            .field("session_index", &"<redacted>")
            .field("addrs", &"<redacted>")
            .finish()
    }
}

impl ClawVpnSession {
    #[must_use]
    pub fn id(&self) -> ClawVpnSessionId {
        self.id
    }

    #[must_use]
    pub fn acl_key(&self) -> &ClawVpnAclKey {
        &self.acl_key
    }

    #[must_use]
    pub fn addrs(&self) -> ClawVpnSessionAddrs {
        self.addrs
    }

    #[must_use]
    pub fn packet_policy(&self) -> ClawVpnPacketPolicy {
        ClawVpnPacketPolicy::new(self.addrs)
    }
}

/// Result of removing one ACL relation from the in-memory session model.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnAclRevocation {
    grant_removed: bool,
    closed_session_count: usize,
}

impl fmt::Debug for ClawVpnAclRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAclRevocation")
            .field("grant_removed", &self.grant_removed)
            .field("closed_session_count", &self.closed_session_count)
            .finish()
    }
}

impl ClawVpnAclRevocation {
    #[must_use]
    pub fn grant_removed(&self) -> bool {
        self.grant_removed
    }

    #[must_use]
    pub fn closed_session_count(&self) -> usize {
        self.closed_session_count
    }
}

/// Redacted, deterministic audit subject for one `(member, device, claw)`.
///
/// It carries domain-separated hashes rather than raw ids or public keys. The
/// future runtime can use these stable neutral identifiers for counters/events
/// without putting member ids, claw ids, or device keys in logs.
///
/// These hashes are pseudonymous local identifiers, not anonymization. If a
/// future audit backend persists or exports them outside the trusted host
/// boundary, that slice must switch to a keyed/HMAC-style subject derivation or
/// document an equivalent exposure policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnAuditSubject {
    member_id: [u8; 32],
    device_pub: [u8; 32],
    claw_id: [u8; 32],
}

impl fmt::Debug for ClawVpnAuditSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAuditSubject")
            .field("member_id_hash", &"<redacted>")
            .field("device_pub_hash", &"<redacted>")
            .field("claw_id_hash", &"<redacted>")
            .finish()
    }
}

impl ClawVpnAuditSubject {
    #[must_use]
    pub fn from_acl_key(key: &ClawVpnAclKey) -> Self {
        Self {
            member_id: audit_hash(b"member_id", key.member_id().as_bytes()),
            device_pub: audit_hash(b"device_pub", key.device_pub().as_bytes()),
            claw_id: audit_hash(b"claw_id", key.claw_id().as_bytes()),
        }
    }

    #[must_use]
    pub fn member_id_hash(&self) -> [u8; 32] {
        self.member_id
    }

    #[must_use]
    pub fn device_pub_hash(&self) -> [u8; 32] {
        self.device_pub
    }

    #[must_use]
    pub fn claw_id_hash(&self) -> [u8; 32] {
        self.claw_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnAuditAction {
    SessionOpen,
    SessionClose,
    AclRevoke,
    FrameValidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnAuditReason {
    SessionOpened,
    SessionClosed,
    AclRevoked,
    AclRevokeMissing,
    FrameAccepted,
    Unauthorized,
    MemberClawSessionLimitReached,
    ClawSessionLimitReached,
    SessionIdExhausted,
    SessionIndexExhausted,
    PoolRejected,
    UnknownSession,
    PacketTooLarge,
    UnexpectedTunnelFrame,
    PacketPolicyRejected,
}

/// Sanitized audit event emitted by pure helpers only.
///
/// The event is deliberately not tied to any logging backend. It is a typed
/// value future runtime code can choose to persist after applying its own
/// privacy policy. `Debug` never prints raw relation identifiers, subject
/// hashes, session ids, packet bytes, or addresses.
#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnAuditEvent {
    subject: Option<ClawVpnAuditSubject>,
    action: ClawVpnAuditAction,
    reason: ClawVpnAuditReason,
    session_id: Option<ClawVpnSessionId>,
    byte_count: Option<usize>,
    closed_session_count: Option<usize>,
}

impl fmt::Debug for ClawVpnAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAuditEvent")
            .field("subject", &self.subject.map(|_| "<redacted>"))
            .field("action", &self.action)
            .field("reason", &self.reason)
            .field("session_id", &self.session_id.map(|_| "<redacted>"))
            .field("byte_count", &self.byte_count)
            .field("closed_session_count", &self.closed_session_count)
            .finish()
    }
}

impl ClawVpnAuditEvent {
    fn new(
        subject: Option<ClawVpnAuditSubject>,
        action: ClawVpnAuditAction,
        reason: ClawVpnAuditReason,
        session_id: Option<ClawVpnSessionId>,
        byte_count: Option<usize>,
        closed_session_count: Option<usize>,
    ) -> Self {
        Self {
            subject,
            action,
            reason,
            session_id,
            byte_count,
            closed_session_count,
        }
    }

    #[must_use]
    pub fn subject(&self) -> Option<ClawVpnAuditSubject> {
        self.subject
    }

    #[must_use]
    pub fn action(&self) -> ClawVpnAuditAction {
        self.action
    }

    #[must_use]
    pub fn reason(&self) -> ClawVpnAuditReason {
        self.reason
    }

    #[must_use]
    pub fn session_id(&self) -> Option<ClawVpnSessionId> {
        self.session_id
    }

    #[must_use]
    pub fn byte_count(&self) -> Option<usize> {
        self.byte_count
    }

    #[must_use]
    pub fn closed_session_count(&self) -> Option<usize> {
        self.closed_session_count
    }
}

/// Pure in-memory admission/session model for the N:N per-Claw VPN plan.
///
/// It proves the future runtime shape without touching storage, routes, relay
/// processes, or OS packet-tunnel APIs.
#[derive(PartialEq, Eq)]
pub struct ClawVpnSessionRegistry {
    acl: ClawVpnAcl,
    pool: ClawVpnIpv4Pool,
    max_sessions_per_member_claw: usize,
    max_sessions_per_claw: usize,
    next_session_id: u64,
    next_session_index: u32,
    free_session_indices: Vec<u32>,
    sessions: HashMap<ClawVpnSessionId, ClawVpnSession>,
}

impl fmt::Debug for ClawVpnSessionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnSessionRegistry")
            .field("acl", &"<redacted>")
            .field("pool", &"<redacted>")
            .field(
                "max_sessions_per_member_claw",
                &self.max_sessions_per_member_claw,
            )
            .field("max_sessions_per_claw", &self.max_sessions_per_claw)
            .field("next_session_id", &"<redacted>")
            .field("next_session_index", &"<redacted>")
            .field("free_session_indices", &self.free_session_indices.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl ClawVpnSessionRegistry {
    #[must_use]
    pub fn new(acl: ClawVpnAcl, pool: ClawVpnIpv4Pool) -> Self {
        Self {
            acl,
            pool,
            max_sessions_per_member_claw: CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW,
            max_sessions_per_claw: usize::MAX,
            next_session_id: 1,
            next_session_index: 0,
            free_session_indices: Vec::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn with_limits(
        acl: ClawVpnAcl,
        pool: ClawVpnIpv4Pool,
        max_sessions_per_member_claw: usize,
        max_sessions_per_claw: usize,
    ) -> Result<Self, ClawVpnSessionRegistryError> {
        if max_sessions_per_member_claw == 0 || max_sessions_per_claw == 0 {
            return Err(ClawVpnSessionRegistryError::ZeroSessionLimit);
        }
        Ok(Self {
            acl,
            pool,
            max_sessions_per_member_claw,
            max_sessions_per_claw,
            next_session_id: 1,
            next_session_index: 0,
            free_session_indices: Vec::new(),
            sessions: HashMap::new(),
        })
    }

    pub fn grant(&mut self, key: ClawVpnAclKey) -> bool {
        self.acl.grant(key)
    }

    #[must_use]
    pub fn is_authorized(&self, key: &ClawVpnAclKey) -> bool {
        self.acl.is_authorized(key)
    }

    pub fn open(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> Result<ClawVpnSession, ClawVpnSessionRegistryError> {
        if !self.acl.is_authorized(key) {
            return Err(ClawVpnSessionRegistryError::Unauthorized);
        }
        if self.sessions_for_member_claw(key) >= self.max_sessions_per_member_claw {
            return Err(ClawVpnSessionRegistryError::MemberClawSessionLimitReached);
        }
        if self.sessions_for_claw(key.claw_id()) >= self.max_sessions_per_claw {
            return Err(ClawVpnSessionRegistryError::ClawSessionLimitReached);
        }

        let session_id = ClawVpnSessionId(self.next_session_id);
        let next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or(ClawVpnSessionRegistryError::SessionIdExhausted)?;
        let reused_session_index = self.free_session_indices.pop();
        let (session_index, next_session_index) = if let Some(index) = reused_session_index {
            (index, self.next_session_index)
        } else {
            (
                self.next_session_index,
                self.next_session_index
                    .checked_add(1)
                    .ok_or(ClawVpnSessionRegistryError::SessionIndexExhausted)?,
            )
        };
        let addrs = match self.pool.allocate_pair(session_index) {
            Ok(addrs) => addrs,
            Err(error) => {
                if let Some(index) = reused_session_index {
                    self.free_session_indices.push(index);
                }
                return Err(error.into());
            }
        };
        let session = ClawVpnSession {
            id: session_id,
            acl_key: key.clone(),
            session_index,
            addrs,
        };
        self.sessions.insert(session_id, session.clone());
        self.next_session_id = next_session_id;
        self.next_session_index = next_session_index;
        Ok(session)
    }

    pub fn open_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (
        Result<ClawVpnSession, ClawVpnSessionRegistryError>,
        ClawVpnAuditEvent,
    ) {
        let subject = Some(ClawVpnAuditSubject::from_acl_key(key));
        let result = self.open(key);
        let event = match &result {
            Ok(session) => ClawVpnAuditEvent::new(
                subject,
                ClawVpnAuditAction::SessionOpen,
                ClawVpnAuditReason::SessionOpened,
                Some(session.id()),
                None,
                None,
            ),
            Err(error) => ClawVpnAuditEvent::new(
                subject,
                ClawVpnAuditAction::SessionOpen,
                audit_reason_from_registry_error(*error),
                None,
                None,
                None,
            ),
        };
        (result, event)
    }

    pub fn close(&mut self, session_id: ClawVpnSessionId) -> Option<ClawVpnSession> {
        let session = self.sessions.remove(&session_id)?;
        self.free_session_indices.push(session.session_index);
        Some(session)
    }

    pub fn close_with_audit(
        &mut self,
        session_id: ClawVpnSessionId,
    ) -> (Option<ClawVpnSession>, ClawVpnAuditEvent) {
        let result = self.close(session_id);
        let event = match &result {
            Some(session) => ClawVpnAuditEvent::new(
                Some(ClawVpnAuditSubject::from_acl_key(session.acl_key())),
                ClawVpnAuditAction::SessionClose,
                ClawVpnAuditReason::SessionClosed,
                Some(session.id()),
                None,
                None,
            ),
            None => ClawVpnAuditEvent::new(
                None,
                ClawVpnAuditAction::SessionClose,
                ClawVpnAuditReason::UnknownSession,
                Some(session_id),
                None,
                None,
            ),
        };
        (result, event)
    }

    pub fn revoke(&mut self, key: &ClawVpnAclKey) -> ClawVpnAclRevocation {
        let grant_removed = self.acl.revoke(key);
        let session_ids: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| (session.acl_key() == key).then_some(*session_id))
            .collect();
        let mut closed_session_count = 0;
        for session_id in session_ids {
            if let Some(session) = self.sessions.remove(&session_id) {
                self.free_session_indices.push(session.session_index);
                closed_session_count += 1;
            }
        }
        ClawVpnAclRevocation {
            grant_removed,
            closed_session_count,
        }
    }

    pub fn revoke_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (ClawVpnAclRevocation, ClawVpnAuditEvent) {
        let subject = Some(ClawVpnAuditSubject::from_acl_key(key));
        let revocation = self.revoke(key);
        let reason = if revocation.grant_removed() {
            ClawVpnAuditReason::AclRevoked
        } else {
            ClawVpnAuditReason::AclRevokeMissing
        };
        let event = ClawVpnAuditEvent::new(
            subject,
            ClawVpnAuditAction::AclRevoke,
            reason,
            None,
            None,
            Some(revocation.closed_session_count()),
        );
        (revocation, event)
    }

    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn active_sessions_for_key(&self, key: &ClawVpnAclKey) -> usize {
        self.sessions
            .values()
            .filter(|session| session.acl_key() == key)
            .count()
    }

    #[must_use]
    pub fn contains_session(&self, session_id: ClawVpnSessionId) -> bool {
        self.sessions.contains_key(&session_id)
    }

    fn session_addrs(
        &self,
        session_id: ClawVpnSessionId,
    ) -> Result<ClawVpnSessionAddrs, ClawVpnSessionFrameError> {
        self.sessions
            .get(&session_id)
            .map(ClawVpnSession::addrs)
            .ok_or(ClawVpnSessionFrameError::UnknownSession)
    }

    pub fn validate_tunnel_frame_for_session(
        &self,
        session_id: ClawVpnSessionId,
        direction: ClawVpnPacketDirection,
        frame: TunnelFrame,
    ) -> Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(ClawVpnSessionFrameError::UnknownSession)?;
        ClawVpnValidatedPacket::try_from_tunnel_frame(&session.packet_policy(), direction, frame)
            .map_err(Into::into)
    }

    pub fn validate_ipv4_packet_for_session(
        &self,
        session_id: ClawVpnSessionId,
        direction: ClawVpnPacketDirection,
        packet: &[u8],
    ) -> Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(ClawVpnSessionFrameError::UnknownSession)?;
        ClawVpnValidatedPacket::try_from_ipv4_packet(&session.packet_policy(), direction, packet)
            .map_err(Into::into)
    }

    pub fn validate_tunnel_frame_for_session_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        direction: ClawVpnPacketDirection,
        frame: TunnelFrame,
    ) -> (
        Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        let subject = self
            .sessions
            .get(&session_id)
            .map(|session| ClawVpnAuditSubject::from_acl_key(session.acl_key()));
        let result = self.validate_tunnel_frame_for_session(session_id, direction, frame);
        let (reason, byte_count) = audit_frame_validation_result(&result);
        let event = ClawVpnAuditEvent::new(
            subject,
            ClawVpnAuditAction::FrameValidate,
            reason,
            Some(session_id),
            byte_count,
            None,
        );
        (result, event)
    }

    pub fn validate_ipv4_packet_for_session_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        direction: ClawVpnPacketDirection,
        packet: &[u8],
    ) -> (
        Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        let subject = self
            .sessions
            .get(&session_id)
            .map(|session| ClawVpnAuditSubject::from_acl_key(session.acl_key()));
        let result = self.validate_ipv4_packet_for_session(session_id, direction, packet);
        let (reason, byte_count) = audit_frame_validation_result(&result);
        let event = ClawVpnAuditEvent::new(
            subject,
            ClawVpnAuditAction::FrameValidate,
            reason,
            Some(session_id),
            byte_count,
            None,
        );
        (result, event)
    }

    fn sessions_for_member_claw(&self, key: &ClawVpnAclKey) -> usize {
        self.sessions
            .values()
            .filter(|session| same_member_claw(session.acl_key(), key))
            .count()
    }

    fn sessions_for_claw(&self, claw_id: &str) -> usize {
        self.sessions
            .values()
            .filter(|session| session.acl_key().claw_id() == claw_id)
            .count()
    }
}

/// Which side of one point-to-point per-Claw VPN session owns the local
/// interface that is feeding or receiving packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnDatapathSide {
    Device,
    Claw,
}

impl ClawVpnDatapathSide {
    #[must_use]
    pub fn local_to_relay_direction(self) -> ClawVpnPacketDirection {
        match self {
            Self::Device => ClawVpnPacketDirection::DeviceToClaw,
            Self::Claw => ClawVpnPacketDirection::ClawToDevice,
        }
    }

    #[must_use]
    pub fn relay_to_local_direction(self) -> ClawVpnPacketDirection {
        match self {
            Self::Device => ClawVpnPacketDirection::ClawToDevice,
            Self::Claw => ClawVpnPacketDirection::DeviceToClaw,
        }
    }
}

/// Pure packet datapath core for the future TUN/utun agent.
///
/// This owns the session registry so close/revoke decisions are the single
/// authority for packet forwarding. It still does not create interfaces, install
/// routes, open relay sessions, spawn tasks, or persist state.
#[derive(PartialEq, Eq)]
pub struct ClawVpnDatapath {
    registry: ClawVpnSessionRegistry,
}

impl fmt::Debug for ClawVpnDatapath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnDatapath")
            .field("registry", &self.registry)
            .finish()
    }
}

impl ClawVpnDatapath {
    #[must_use]
    pub fn new(registry: ClawVpnSessionRegistry) -> Self {
        Self { registry }
    }

    fn contains_session(&self, session_id: ClawVpnSessionId) -> bool {
        self.registry.contains_session(session_id)
    }

    fn session_addrs(
        &self,
        session_id: ClawVpnSessionId,
    ) -> Result<ClawVpnSessionAddrs, ClawVpnSessionFrameError> {
        self.registry.session_addrs(session_id)
    }

    pub fn open_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (
        Result<ClawVpnSession, ClawVpnSessionRegistryError>,
        ClawVpnAuditEvent,
    ) {
        self.registry.open_with_audit(key)
    }

    pub fn close_with_audit(
        &mut self,
        session_id: ClawVpnSessionId,
    ) -> (Option<ClawVpnSession>, ClawVpnAuditEvent) {
        self.registry.close_with_audit(session_id)
    }

    pub fn revoke_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (ClawVpnAclRevocation, ClawVpnAuditEvent) {
        self.registry.revoke_with_audit(key)
    }

    /// Validate a packet read from the local TUN/utun side before putting it on
    /// the relay stream. A packet that does not match the session's exact
    /// src/dst pair is rejected before any frame is emitted.
    pub fn packet_from_local_interface_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        local_side: ClawVpnDatapathSide,
        packet: &[u8],
    ) -> (
        Result<TunnelFrame, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        let (result, event) = self.registry.validate_ipv4_packet_for_session_with_audit(
            session_id,
            local_side.local_to_relay_direction(),
            packet,
        );
        (result.map(ClawVpnValidatedPacket::into_tunnel_frame), event)
    }

    /// Validate a relay frame before writing the packet to the local TUN/utun
    /// side. Control frames or spoofed IP packets are rejected before a future
    /// runtime can hand bytes to the OS interface.
    pub fn packet_from_relay_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        local_side: ClawVpnDatapathSide,
        frame: TunnelFrame,
    ) -> (
        Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        self.registry.validate_tunnel_frame_for_session_with_audit(
            session_id,
            local_side.relay_to_local_direction(),
            frame,
        )
    }
}

/// Fixed-side core for a future claw VPN agent.
///
/// Unlike `ClawVpnDatapath`, this binds the local side once at construction, so
/// a runtime cannot accidentally choose `Device` or `Claw` per packet. It still
/// does not create interfaces, install routes, open relay sessions, spawn
/// tasks, or persist state.
#[derive(PartialEq, Eq)]
pub struct ClawVpnAgentCore {
    local_side: ClawVpnDatapathSide,
    datapath: ClawVpnDatapath,
}

impl fmt::Debug for ClawVpnAgentCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAgentCore")
            .field("local_side", &self.local_side)
            .field("datapath", &self.datapath)
            .finish()
    }
}

impl ClawVpnAgentCore {
    #[must_use]
    pub fn new(local_side: ClawVpnDatapathSide, registry: ClawVpnSessionRegistry) -> Self {
        Self {
            local_side,
            datapath: ClawVpnDatapath::new(registry),
        }
    }

    #[must_use]
    pub fn local_side(&self) -> ClawVpnDatapathSide {
        self.local_side
    }

    pub fn open_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (
        Result<ClawVpnSession, ClawVpnSessionRegistryError>,
        ClawVpnAuditEvent,
    ) {
        self.datapath.open_with_audit(key)
    }

    pub fn close_with_audit(
        &mut self,
        session_id: ClawVpnSessionId,
    ) -> (Option<ClawVpnSession>, ClawVpnAuditEvent) {
        self.datapath.close_with_audit(session_id)
    }

    pub fn revoke_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (ClawVpnAclRevocation, ClawVpnAuditEvent) {
        self.datapath.revoke_with_audit(key)
    }

    pub fn frame_from_interface_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        packet: &[u8],
    ) -> (
        Result<TunnelFrame, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        self.datapath
            .packet_from_local_interface_with_audit(session_id, self.local_side, packet)
    }

    pub fn packet_from_relay_with_audit(
        &self,
        session_id: ClawVpnSessionId,
        frame: TunnelFrame,
    ) -> (
        Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        self.datapath
            .packet_from_relay_with_audit(session_id, self.local_side, frame)
    }

    #[must_use]
    pub fn contains_session(&self, session_id: ClawVpnSessionId) -> bool {
        self.datapath.contains_session(session_id)
    }

    pub fn into_session_core(
        self,
        session_id: ClawVpnSessionId,
    ) -> Result<ClawVpnAgentSessionCore, ClawVpnSessionFrameError> {
        if self.contains_session(session_id) {
            Ok(ClawVpnAgentSessionCore {
                session_id,
                core: self,
            })
        } else {
            Err(ClawVpnSessionFrameError::UnknownSession)
        }
    }
}

/// Fixed-side, fixed-session core for a future claw VPN packet pump.
///
/// This is one step narrower than `ClawVpnAgentCore`: a future runtime holding
/// this wrapper cannot choose either the local side or the session id per
/// packet. It still does not create interfaces, install routes, open relay
/// sessions, spawn tasks, or persist state.
#[derive(PartialEq, Eq)]
pub struct ClawVpnAgentSessionCore {
    session_id: ClawVpnSessionId,
    core: ClawVpnAgentCore,
}

impl fmt::Debug for ClawVpnAgentSessionCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnAgentSessionCore")
            .field("session_id", &self.session_id)
            .field("core", &self.core)
            .finish()
    }
}

impl ClawVpnAgentSessionCore {
    #[must_use]
    pub fn local_side(&self) -> ClawVpnDatapathSide {
        self.core.local_side()
    }

    pub fn addrs(&self) -> Result<ClawVpnSessionAddrs, ClawVpnSessionFrameError> {
        self.core.datapath.session_addrs(self.session_id)
    }

    pub fn close_with_audit(&mut self) -> (Option<ClawVpnSession>, ClawVpnAuditEvent) {
        self.core.close_with_audit(self.session_id)
    }

    pub fn revoke_with_audit(
        &mut self,
        key: &ClawVpnAclKey,
    ) -> (ClawVpnAclRevocation, ClawVpnAuditEvent) {
        self.core.revoke_with_audit(key)
    }

    pub fn frame_from_interface_with_audit(
        &self,
        packet: &[u8],
    ) -> (
        Result<TunnelFrame, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        self.core
            .frame_from_interface_with_audit(self.session_id, packet)
    }

    pub fn packet_from_relay_with_audit(
        &self,
        frame: TunnelFrame,
    ) -> (
        Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
        ClawVpnAuditEvent,
    ) {
        self.core
            .packet_from_relay_with_audit(self.session_id, frame)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnPacketDirection {
    DeviceToClaw,
    ClawToDevice,
}

/// Fail-closed packet policy for a point-to-point per-Claw VPN session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnPacketPolicy {
    addrs: ClawVpnSessionAddrs,
}

impl fmt::Debug for ClawVpnPacketPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPacketPolicy")
            .field("addrs", &"<redacted>")
            .finish()
    }
}

impl ClawVpnPacketPolicy {
    #[must_use]
    pub fn new(addrs: ClawVpnSessionAddrs) -> Self {
        Self { addrs }
    }

    #[must_use]
    pub fn addrs(&self) -> ClawVpnSessionAddrs {
        self.addrs
    }

    pub fn check_ipv4_packet(
        &self,
        direction: ClawVpnPacketDirection,
        packet: &[u8],
    ) -> Result<(), ClawVpnPacketPolicyError> {
        let header = parse_ipv4_header(packet)?;
        let (expected_src, expected_dst) = match direction {
            ClawVpnPacketDirection::DeviceToClaw => (self.addrs.device(), self.addrs.claw()),
            ClawVpnPacketDirection::ClawToDevice => (self.addrs.claw(), self.addrs.device()),
        };
        if header.src != expected_src {
            return Err(ClawVpnPacketPolicyError::SourceMismatch);
        }
        if header.dst != expected_dst {
            return Err(ClawVpnPacketPolicyError::DestinationMismatch);
        }
        Ok(())
    }
}

/// An IP packet that has already passed the per-session VPN policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnValidatedPacket {
    bytes: Vec<u8>,
}

impl fmt::Debug for ClawVpnValidatedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnValidatedPacket")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl ClawVpnValidatedPacket {
    pub fn try_from_ipv4_packet(
        policy: &ClawVpnPacketPolicy,
        direction: ClawVpnPacketDirection,
        packet: &[u8],
    ) -> Result<Self, ClawVpnValidatedPacketError> {
        if packet.len() > CLAW_VPN_V1_INNER_MTU {
            return Err(ClawVpnValidatedPacketError::PacketTooLarge);
        }
        policy.check_ipv4_packet(direction, packet)?;
        Ok(Self {
            bytes: packet.to_vec(),
        })
    }

    pub fn try_from_tunnel_frame(
        policy: &ClawVpnPacketPolicy,
        direction: ClawVpnPacketDirection,
        frame: TunnelFrame,
    ) -> Result<Self, ClawVpnValidatedPacketError> {
        let TunnelFrame::Data(packet) = frame else {
            return Err(ClawVpnValidatedPacketError::UnexpectedTunnelFrame);
        };
        Self::try_from_ipv4_packet(policy, direction, &packet)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn into_tunnel_frame(self) -> TunnelFrame {
        TunnelFrame::Data(self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnAddressError {
    #[error("claw vpn inner address is unspecified")]
    Unspecified,

    #[error("claw vpn inner address is multicast")]
    Multicast,

    #[error("claw vpn inner addresses must be distinct")]
    SameAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnPoolError {
    #[error("claw vpn pool prefix is too small for a point-to-point pair")]
    PrefixTooSmall,

    #[error("claw vpn pool network address has host bits set")]
    HostBitsSet,

    #[error("claw vpn pool network address is invalid")]
    InvalidNetwork,

    #[error("claw vpn pool overlaps a reserved local or overlay range")]
    OverlapsReservedRange,

    #[error("claw vpn pool is exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnAclError {
    #[error("claw vpn acl member id is empty")]
    EmptyMemberId,

    #[error("claw vpn acl member id is invalid")]
    InvalidMemberId,

    #[error("claw vpn acl claw id is empty")]
    EmptyClawId,

    #[error("claw vpn acl claw id is invalid")]
    InvalidClawId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnSessionRegistryError {
    #[error("claw vpn session limit must be non-zero")]
    ZeroSessionLimit,

    #[error("claw vpn acl entry is not authorized")]
    Unauthorized,

    #[error("claw vpn member/claw session limit reached")]
    MemberClawSessionLimitReached,

    #[error("claw vpn claw session limit reached")]
    ClawSessionLimitReached,

    #[error("claw vpn session id exhausted")]
    SessionIdExhausted,

    #[error("claw vpn session index exhausted")]
    SessionIndexExhausted,

    #[error(transparent)]
    Pool(#[from] ClawVpnPoolError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnSessionFrameError {
    #[error("claw vpn session is not active")]
    UnknownSession,

    #[error(transparent)]
    Packet(#[from] ClawVpnValidatedPacketError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnPacketPolicyError {
    #[error("claw vpn packet is too short")]
    PacketTooShort,

    #[error("claw vpn packet is not IPv4")]
    UnsupportedVersion,

    #[error("claw vpn IPv4 header length is invalid")]
    InvalidHeaderLength,

    #[error("claw vpn IPv4 total length is invalid")]
    InvalidTotalLength,

    #[error("claw vpn packet source address is not authorized")]
    SourceMismatch,

    #[error("claw vpn packet destination address is not authorized")]
    DestinationMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnValidatedPacketError {
    #[error("claw vpn packet exceeds the v1 inner mtu")]
    PacketTooLarge,

    #[error("claw vpn tunnel frame is not an IP packet")]
    UnexpectedTunnelFrame,

    #[error(transparent)]
    Policy(#[from] ClawVpnPacketPolicyError),
}

fn validate_inner_addr(addr: Ipv4Addr) -> Result<(), ClawVpnAddressError> {
    if addr.is_unspecified() {
        return Err(ClawVpnAddressError::Unspecified);
    }
    if addr.is_multicast() {
        return Err(ClawVpnAddressError::Multicast);
    }
    Ok(())
}

fn ipv4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn ipv4_prefix_range(network: u32, prefix_len: u8) -> (u32, u32) {
    let mask = ipv4_prefix_mask(prefix_len);
    let start = network & mask;
    let end = start | !mask;
    (start, end)
}

fn ranges_overlap(a_start: u32, a_end: u32, b_start: u32, b_end: u32) -> bool {
    a_start <= b_end && b_start <= a_end
}

fn same_member_claw(left: &ClawVpnAclKey, right: &ClawVpnAclKey) -> bool {
    left.member_id() == right.member_id() && left.claw_id() == right.claw_id()
}

fn audit_hash(label: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SoyehtClawVpnAuditSubject:v1");
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn audit_reason_from_registry_error(error: ClawVpnSessionRegistryError) -> ClawVpnAuditReason {
    match error {
        ClawVpnSessionRegistryError::Unauthorized => ClawVpnAuditReason::Unauthorized,
        ClawVpnSessionRegistryError::MemberClawSessionLimitReached => {
            ClawVpnAuditReason::MemberClawSessionLimitReached
        }
        ClawVpnSessionRegistryError::ClawSessionLimitReached => {
            ClawVpnAuditReason::ClawSessionLimitReached
        }
        ClawVpnSessionRegistryError::SessionIdExhausted => ClawVpnAuditReason::SessionIdExhausted,
        ClawVpnSessionRegistryError::SessionIndexExhausted => {
            ClawVpnAuditReason::SessionIndexExhausted
        }
        ClawVpnSessionRegistryError::ZeroSessionLimit | ClawVpnSessionRegistryError::Pool(_) => {
            ClawVpnAuditReason::PoolRejected
        }
    }
}

fn audit_reason_from_validated_packet_error(
    error: ClawVpnValidatedPacketError,
) -> ClawVpnAuditReason {
    match error {
        ClawVpnValidatedPacketError::PacketTooLarge => ClawVpnAuditReason::PacketTooLarge,
        ClawVpnValidatedPacketError::UnexpectedTunnelFrame => {
            ClawVpnAuditReason::UnexpectedTunnelFrame
        }
        ClawVpnValidatedPacketError::Policy(_) => ClawVpnAuditReason::PacketPolicyRejected,
    }
}

fn audit_frame_validation_result(
    result: &Result<ClawVpnValidatedPacket, ClawVpnSessionFrameError>,
) -> (ClawVpnAuditReason, Option<usize>) {
    match result {
        Ok(packet) => (
            ClawVpnAuditReason::FrameAccepted,
            Some(packet.as_bytes().len()),
        ),
        Err(ClawVpnSessionFrameError::UnknownSession) => (ClawVpnAuditReason::UnknownSession, None),
        Err(ClawVpnSessionFrameError::Packet(error)) => {
            (audit_reason_from_validated_packet_error(*error), None)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Header {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

fn parse_ipv4_header(packet: &[u8]) -> Result<Ipv4Header, ClawVpnPacketPolicyError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(ClawVpnPacketPolicyError::PacketTooShort);
    }
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return Err(ClawVpnPacketPolicyError::UnsupportedVersion);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || header_len > packet.len() {
        return Err(ClawVpnPacketPolicyError::InvalidHeaderLength);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len != packet.len() {
        return Err(ClawVpnPacketPolicyError::InvalidTotalLength);
    }
    Ok(Ipv4Header {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, P256Keypair};

    fn policy() -> ClawVpnPacketPolicy {
        ClawVpnPacketPolicy::new(
            ClawVpnSessionAddrs::try_new(
                Ipv4Addr::new(198, 51, 100, 10),
                Ipv4Addr::new(198, 51, 100, 20),
            )
            .unwrap(),
        )
    }

    fn pool() -> ClawVpnIpv4Pool {
        ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 24).unwrap()
    }

    fn acl_key(member: &str, device: &P256Keypair, claw: &str) -> ClawVpnAclKey {
        ClawVpnAclKey::try_new(member, device.public(), claw).unwrap()
    }

    fn registry_with_grants(keys: &[ClawVpnAclKey]) -> ClawVpnSessionRegistry {
        let mut acl = ClawVpnAcl::new();
        for key in keys {
            acl.grant(key.clone());
        }
        ClawVpnSessionRegistry::new(acl, pool())
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        packet_with_payload_len(src, dst, 0)
    }

    fn packet_with_payload_len(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; IPV4_MIN_HEADER_LEN + payload_len];
        let total_len = out.len() as u16;
        out[0] = 0x45;
        out[2..4].copy_from_slice(&total_len.to_be_bytes());
        out[8] = 64;
        out[9] = 6;
        out[12..16].copy_from_slice(&src.octets());
        out[16..20].copy_from_slice(&dst.octets());
        out
    }

    #[test]
    fn device_to_claw_accepts_only_the_session_pair() {
        let policy = policy();
        let addrs = policy.addrs();

        policy
            .check_ipv4_packet(
                ClawVpnPacketDirection::DeviceToClaw,
                &packet(addrs.device(), addrs.claw()),
            )
            .unwrap();

        assert_eq!(
            policy.check_ipv4_packet(
                ClawVpnPacketDirection::DeviceToClaw,
                &packet(Ipv4Addr::new(198, 51, 100, 11), addrs.claw()),
            ),
            Err(ClawVpnPacketPolicyError::SourceMismatch)
        );
        assert_eq!(
            policy.check_ipv4_packet(
                ClawVpnPacketDirection::DeviceToClaw,
                &packet(addrs.device(), Ipv4Addr::new(198, 51, 100, 21)),
            ),
            Err(ClawVpnPacketPolicyError::DestinationMismatch)
        );
        assert_eq!(
            policy.check_ipv4_packet(
                ClawVpnPacketDirection::DeviceToClaw,
                &packet(addrs.claw(), addrs.device()),
            ),
            Err(ClawVpnPacketPolicyError::SourceMismatch)
        );
    }

    #[test]
    fn claw_to_device_accepts_only_the_reverse_session_pair() {
        let policy = policy();
        let addrs = policy.addrs();

        policy
            .check_ipv4_packet(
                ClawVpnPacketDirection::ClawToDevice,
                &packet(addrs.claw(), addrs.device()),
            )
            .unwrap();

        assert_eq!(
            policy.check_ipv4_packet(
                ClawVpnPacketDirection::ClawToDevice,
                &packet(addrs.device(), addrs.claw()),
            ),
            Err(ClawVpnPacketPolicyError::SourceMismatch)
        );
    }

    #[test]
    fn malformed_ipv4_packets_fail_closed_before_address_checks() {
        assert_eq!(
            parse_ipv4_header(&[0u8; IPV4_MIN_HEADER_LEN - 1]),
            Err(ClawVpnPacketPolicyError::PacketTooShort)
        );

        let mut ipv6 = packet(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        );
        ipv6[0] = 0x65;
        assert_eq!(
            parse_ipv4_header(&ipv6),
            Err(ClawVpnPacketPolicyError::UnsupportedVersion)
        );

        let mut bad_ihl = packet(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        );
        bad_ihl[0] = 0x44;
        assert_eq!(
            parse_ipv4_header(&bad_ihl),
            Err(ClawVpnPacketPolicyError::InvalidHeaderLength)
        );

        let mut bad_total_len = packet(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        );
        bad_total_len[3] = 19;
        assert_eq!(
            parse_ipv4_header(&bad_total_len),
            Err(ClawVpnPacketPolicyError::InvalidTotalLength)
        );

        let mut claimed_too_long = packet(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        );
        claimed_too_long[3] = 21;
        assert_eq!(
            parse_ipv4_header(&claimed_too_long),
            Err(ClawVpnPacketPolicyError::InvalidTotalLength)
        );
    }

    #[test]
    fn session_addresses_fail_closed_on_invalid_pairs() {
        assert_eq!(
            ClawVpnSessionAddrs::try_new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(198, 51, 100, 20)),
            Err(ClawVpnAddressError::Unspecified)
        );
        assert_eq!(
            ClawVpnSessionAddrs::try_new(
                Ipv4Addr::new(224, 0, 0, 1),
                Ipv4Addr::new(198, 51, 100, 20)
            ),
            Err(ClawVpnAddressError::Multicast)
        );
        assert_eq!(
            ClawVpnSessionAddrs::try_new(
                Ipv4Addr::new(198, 51, 100, 10),
                Ipv4Addr::new(198, 51, 100, 10)
            ),
            Err(ClawVpnAddressError::SameAddress)
        );
    }

    #[test]
    fn ipv4_pool_allocates_unique_point_to_point_pairs() {
        let pool = pool();
        assert_eq!(pool.network(), Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(pool.prefix_len(), 24);

        let first = pool.allocate_pair(0).unwrap();
        assert_eq!(first.device(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(first.claw(), Ipv4Addr::new(198, 18, 0, 2));

        let second = pool.allocate_pair(1).unwrap();
        assert_eq!(second.device(), Ipv4Addr::new(198, 18, 0, 3));
        assert_eq!(second.claw(), Ipv4Addr::new(198, 18, 0, 4));
    }

    #[test]
    fn ipv4_pool_rejects_cgnat_home_lan_and_misaligned_prefixes() {
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(100, 64, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(10, 10, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(172, 20, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 1), 24),
            Err(ClawVpnPoolError::HostBitsSet)
        );
    }

    #[test]
    fn ipv4_pool_fails_closed_when_exhausted() {
        let pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 30).unwrap();
        let only_pair = pool.allocate_pair(0).unwrap();
        assert_eq!(only_pair.device(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(only_pair.claw(), Ipv4Addr::new(198, 18, 0, 2));

        assert_eq!(pool.allocate_pair(1), Err(ClawVpnPoolError::Exhausted));
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 31),
            Err(ClawVpnPoolError::PrefixTooSmall)
        );
    }

    #[test]
    fn acl_is_many_to_many_and_revokes_one_relationship_only() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let device_m3 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let m1_claw_b = acl_key("member-m1", &device_m1, "claw-b");
        let m3_claw_a = acl_key("member-m3", &device_m3, "claw-a");

        let mut acl = ClawVpnAcl::new();
        assert!(acl.is_empty());
        assert!(acl.grant(m1_claw_a.clone()));
        assert!(acl.grant(m2_claw_a.clone()));
        assert!(acl.grant(m1_claw_b.clone()));
        assert_eq!(acl.len(), 3);

        assert!(acl.is_authorized(&m1_claw_a));
        assert!(acl.is_authorized(&m2_claw_a));
        assert!(acl.is_authorized(&m1_claw_b));
        assert!(!acl.is_authorized(&m3_claw_a));

        assert!(acl.revoke(&m2_claw_a));
        assert!(!acl.is_authorized(&m2_claw_a));
        assert!(acl.is_authorized(&m1_claw_a));
        assert!(acl.is_authorized(&m1_claw_b));
        assert_eq!(acl.len(), 2);
    }

    #[test]
    fn acl_key_binds_member_device_and_claw_exactly() {
        let device_a = P256Keypair::generate();
        let device_b = P256Keypair::generate();
        let authorized = acl_key("member-m1", &device_a, "claw-a");
        let wrong_device = acl_key("member-m1", &device_b, "claw-a");
        let wrong_claw = acl_key("member-m1", &device_a, "claw-b");
        let wrong_member = acl_key("member-m2", &device_a, "claw-a");

        let mut acl = ClawVpnAcl::new();
        assert!(acl.grant(authorized.clone()));
        assert!(!acl.grant(authorized.clone()));

        assert!(acl.is_authorized(&authorized));
        assert!(!acl.is_authorized(&wrong_device));
        assert!(!acl.is_authorized(&wrong_claw));
        assert!(!acl.is_authorized(&wrong_member));
    }

    #[test]
    fn acl_key_rejects_empty_member_or_claw_ids() {
        let device = P256Keypair::generate();
        assert_eq!(
            ClawVpnAclKey::try_new(" ", device.public(), "claw-a"),
            Err(ClawVpnAclError::EmptyMemberId)
        );
        assert_eq!(
            ClawVpnAclKey::try_new(" member-m1", device.public(), "claw-a"),
            Err(ClawVpnAclError::InvalidMemberId)
        );
        assert_eq!(
            ClawVpnAclKey::try_new("member-m1", device.public(), ""),
            Err(ClawVpnAclError::EmptyClawId)
        );
        assert_eq!(
            ClawVpnAclKey::try_new("member-m1", device.public(), "claw-a "),
            Err(ClawVpnAclError::InvalidClawId)
        );
    }

    #[test]
    fn session_registry_opens_many_to_many_but_caps_member_claw() {
        let device_m1 = P256Keypair::generate();
        let device_m1_second = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m1_claw_a_second_device = acl_key("member-m1", &device_m1_second, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let m1_claw_b = acl_key("member-m1", &device_m1, "claw-b");
        let mut registry = registry_with_grants(&[
            m1_claw_a.clone(),
            m1_claw_a_second_device.clone(),
            m2_claw_a.clone(),
            m1_claw_b.clone(),
        ]);

        let m1_a_session = registry.open(&m1_claw_a).unwrap();
        let m2_a_session = registry.open(&m2_claw_a).unwrap();
        let m1_b_session = registry.open(&m1_claw_b).unwrap();

        assert_eq!(registry.active_session_count(), 3);
        assert_ne!(m1_a_session.addrs(), m2_a_session.addrs());
        assert_ne!(m1_a_session.addrs(), m1_b_session.addrs());
        assert!(registry.contains_session(m1_a_session.id()));
        assert!(registry.contains_session(m2_a_session.id()));
        assert!(registry.contains_session(m1_b_session.id()));
        assert_eq!(
            registry.open(&m1_claw_a_second_device),
            Err(ClawVpnSessionRegistryError::MemberClawSessionLimitReached)
        );
    }

    #[test]
    fn session_registry_rejects_unauthorized_without_allocating_address_pair() {
        let device_m1 = P256Keypair::generate();
        let device_m3 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m3_claw_a = acl_key("member-m3", &device_m3, "claw-a");
        let mut registry = ClawVpnSessionRegistry::new(ClawVpnAcl::new(), pool());

        assert_eq!(
            registry.open(&m3_claw_a),
            Err(ClawVpnSessionRegistryError::Unauthorized)
        );
        assert_eq!(registry.active_session_count(), 0);

        assert!(registry.grant(m1_claw_a.clone()));
        let session = registry.open(&m1_claw_a).unwrap();
        assert_eq!(session.addrs().device(), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(session.addrs().claw(), Ipv4Addr::new(198, 18, 0, 2));
    }

    #[test]
    fn session_registry_revocation_closes_only_the_exact_acl_relation() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let m1_claw_b = acl_key("member-m1", &device_m1, "claw-b");
        let mut registry =
            registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone(), m1_claw_b.clone()]);
        let m1_a_session = registry.open(&m1_claw_a).unwrap();
        let m2_a_session = registry.open(&m2_claw_a).unwrap();
        let m1_b_session = registry.open(&m1_claw_b).unwrap();

        let revocation = registry.revoke(&m2_claw_a);

        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(registry.active_session_count(), 2);
        assert!(!registry.is_authorized(&m2_claw_a));
        assert_eq!(registry.active_sessions_for_key(&m2_claw_a), 0);
        assert!(!registry.contains_session(m2_a_session.id()));
        assert!(registry.is_authorized(&m1_claw_a));
        assert!(registry.is_authorized(&m1_claw_b));
        assert!(registry.contains_session(m1_a_session.id()));
        assert!(registry.contains_session(m1_b_session.id()));
    }

    #[test]
    fn session_registry_limits_and_pool_exhaustion_fail_closed() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut acl = ClawVpnAcl::new();
        acl.grant(m1_claw_a.clone());
        acl.grant(m2_claw_a.clone());

        assert_eq!(
            ClawVpnSessionRegistry::with_limits(acl.clone(), pool(), 0, 1),
            Err(ClawVpnSessionRegistryError::ZeroSessionLimit)
        );

        let mut claw_limited =
            ClawVpnSessionRegistry::with_limits(acl.clone(), pool(), 1, 1).unwrap();
        claw_limited.open(&m1_claw_a).unwrap();
        assert_eq!(
            claw_limited.open(&m2_claw_a),
            Err(ClawVpnSessionRegistryError::ClawSessionLimitReached)
        );

        let tiny_pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 30).unwrap();
        let mut pool_limited = ClawVpnSessionRegistry::new(acl, tiny_pool);
        pool_limited.open(&m1_claw_a).unwrap();
        assert_eq!(
            pool_limited.open(&m2_claw_a),
            Err(ClawVpnSessionRegistryError::Pool(
                ClawVpnPoolError::Exhausted
            ))
        );
    }

    #[test]
    fn session_registry_distinguishes_member_claw_cap_from_claw_cap() {
        let device_m1_first = P256Keypair::generate();
        let device_m1_second = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a_first = acl_key("member-m1", &device_m1_first, "claw-a");
        let m1_claw_a_second = acl_key("member-m1", &device_m1_second, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut acl = ClawVpnAcl::new();
        acl.grant(m1_claw_a_first.clone());
        acl.grant(m1_claw_a_second.clone());
        acl.grant(m2_claw_a.clone());

        let mut member_limited =
            ClawVpnSessionRegistry::with_limits(acl.clone(), pool(), 1, 3).unwrap();
        member_limited.open(&m1_claw_a_first).unwrap();
        assert_eq!(
            member_limited.open(&m1_claw_a_second),
            Err(ClawVpnSessionRegistryError::MemberClawSessionLimitReached)
        );
        member_limited.open(&m2_claw_a).unwrap();

        let mut claw_limited = ClawVpnSessionRegistry::with_limits(acl, pool(), 3, 2).unwrap();
        claw_limited.open(&m1_claw_a_first).unwrap();
        claw_limited.open(&m1_claw_a_second).unwrap();
        assert_eq!(
            claw_limited.open(&m2_claw_a),
            Err(ClawVpnSessionRegistryError::ClawSessionLimitReached)
        );
    }

    #[test]
    fn session_registry_reuses_address_pairs_after_close_or_revoke() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut acl = ClawVpnAcl::new();
        acl.grant(m1_claw_a.clone());
        acl.grant(m2_claw_a.clone());
        let tiny_pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 30).unwrap();
        let mut registry = ClawVpnSessionRegistry::new(acl, tiny_pool);

        let first = registry.open(&m1_claw_a).unwrap();
        let first_addrs = first.addrs();
        registry.close(first.id()).unwrap();

        let second = registry.open(&m2_claw_a).unwrap();
        assert_eq!(second.addrs(), first_addrs);

        let revocation = registry.revoke(&m2_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);

        let third = registry.open(&m1_claw_a).unwrap();
        assert_eq!(third.addrs(), first_addrs);
    }

    #[test]
    fn session_registry_revokes_one_device_relation_for_same_member_claw() {
        let device_m1_first = P256Keypair::generate();
        let device_m1_second = P256Keypair::generate();
        let m1_claw_a_first = acl_key("member-m1", &device_m1_first, "claw-a");
        let m1_claw_a_second = acl_key("member-m1", &device_m1_second, "claw-a");
        let m1_claw_b = acl_key("member-m1", &device_m1_first, "claw-b");
        let mut acl = ClawVpnAcl::new();
        acl.grant(m1_claw_a_first.clone());
        acl.grant(m1_claw_a_second.clone());
        acl.grant(m1_claw_b.clone());
        let mut registry = ClawVpnSessionRegistry::with_limits(acl, pool(), 2, 4).unwrap();
        let first_a_session = registry.open(&m1_claw_a_first).unwrap();
        let second_a_session = registry.open(&m1_claw_a_second).unwrap();
        let b_session = registry.open(&m1_claw_b).unwrap();

        let revocation = registry.revoke(&m1_claw_a_first);

        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(registry.active_session_count(), 2);
        assert!(!registry.contains_session(first_a_session.id()));
        assert!(registry.contains_session(second_a_session.id()));
        assert!(registry.contains_session(b_session.id()));
        assert!(!registry.is_authorized(&m1_claw_a_first));
        assert!(registry.is_authorized(&m1_claw_a_second));
        assert!(registry.is_authorized(&m1_claw_b));
    }

    #[test]
    fn session_registry_regrant_after_revoke_reopens_exact_relation() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut registry = registry_with_grants(std::slice::from_ref(&m1_claw_a));
        let first = registry.open(&m1_claw_a).unwrap();
        let first_addrs = first.addrs();

        let revocation = registry.revoke(&m1_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(
            registry.open(&m1_claw_a),
            Err(ClawVpnSessionRegistryError::Unauthorized)
        );

        assert!(registry.grant(m1_claw_a.clone()));
        let reopened = registry.open(&m1_claw_a).unwrap();
        assert_eq!(reopened.addrs(), first_addrs);
    }

    #[test]
    fn session_registry_validates_tunnel_frames_only_for_active_sessions() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut registry = registry_with_grants(std::slice::from_ref(&m1_claw_a));
        let session = registry.open(&m1_claw_a).unwrap();
        let addrs = session.addrs();
        let data = TunnelFrame::Data(packet(addrs.device(), addrs.claw()));

        let validated = registry
            .validate_tunnel_frame_for_session(
                session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                data,
            )
            .unwrap();
        assert_eq!(
            validated.as_bytes(),
            packet(addrs.device(), addrs.claw()).as_slice()
        );

        assert_eq!(
            registry.validate_tunnel_frame_for_session(
                session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Data(packet(addrs.claw(), addrs.device())),
            ),
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            registry.validate_tunnel_frame_for_session(
                session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Close,
            ),
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::UnexpectedTunnelFrame
            ))
        );
    }

    #[test]
    fn session_registry_revoked_or_closed_sessions_cannot_forward_packets() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut registry = registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone()]);
        let m1_session = registry.open(&m1_claw_a).unwrap();
        let m2_session = registry.open(&m2_claw_a).unwrap();

        registry.revoke(&m2_claw_a);
        assert_eq!(
            registry.validate_tunnel_frame_for_session(
                m2_session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Data(packet(
                    m2_session.addrs().device(),
                    m2_session.addrs().claw()
                )),
            ),
            Err(ClawVpnSessionFrameError::UnknownSession)
        );

        registry.close(m1_session.id()).unwrap();
        assert_eq!(
            registry.validate_tunnel_frame_for_session(
                m1_session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Data(packet(
                    m1_session.addrs().device(),
                    m1_session.addrs().claw()
                )),
            ),
            Err(ClawVpnSessionFrameError::UnknownSession)
        );
    }

    #[test]
    fn datapath_maps_local_sides_to_authorized_relay_directions() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut datapath =
            ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
        let (opened, open_event) = datapath.open_with_audit(&m1_claw_a);
        let session = opened.unwrap();
        let addrs = session.addrs();
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);

        let device_packet = packet(addrs.device(), addrs.claw());
        let (device_frame, device_event) = datapath.packet_from_local_interface_with_audit(
            session.id(),
            ClawVpnDatapathSide::Device,
            &device_packet,
        );
        assert_eq!(device_frame, Ok(TunnelFrame::Data(device_packet.clone())));
        assert_eq!(device_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (claw_local, claw_local_event) = datapath.packet_from_relay_with_audit(
            session.id(),
            ClawVpnDatapathSide::Claw,
            TunnelFrame::Data(device_packet.clone()),
        );
        assert_eq!(claw_local.unwrap().as_bytes(), device_packet.as_slice());
        assert_eq!(claw_local_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let claw_packet = packet(addrs.claw(), addrs.device());
        let (claw_frame, claw_event) = datapath.packet_from_local_interface_with_audit(
            session.id(),
            ClawVpnDatapathSide::Claw,
            &claw_packet,
        );
        assert_eq!(claw_frame, Ok(TunnelFrame::Data(claw_packet.clone())));
        assert_eq!(claw_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (device_local, device_local_event) = datapath.packet_from_relay_with_audit(
            session.id(),
            ClawVpnDatapathSide::Device,
            TunnelFrame::Data(claw_packet.clone()),
        );
        assert_eq!(device_local.unwrap().as_bytes(), claw_packet.as_slice());
        assert_eq!(
            device_local_event.reason(),
            ClawVpnAuditReason::FrameAccepted
        );
    }

    #[test]
    fn datapath_rejects_direction_swaps_control_frames_and_closed_sessions() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut datapath =
            ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
        let (opened, _) = datapath.open_with_audit(&m1_claw_a);
        let session = opened.unwrap();
        let addrs = session.addrs();

        let wrong_direction = packet(addrs.claw(), addrs.device());
        let (spoofed, spoofed_event) = datapath.packet_from_local_interface_with_audit(
            session.id(),
            ClawVpnDatapathSide::Device,
            &wrong_direction,
        );
        assert_eq!(
            spoofed,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            spoofed_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        let oversized_packet = vec![0u8; CLAW_VPN_V1_INNER_MTU + 1];
        let (oversized, oversized_event) = datapath.packet_from_local_interface_with_audit(
            session.id(),
            ClawVpnDatapathSide::Device,
            &oversized_packet,
        );
        assert_eq!(
            oversized,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::PacketTooLarge
            ))
        );
        assert_eq!(oversized_event.reason(), ClawVpnAuditReason::PacketTooLarge);

        let wrong_relay_to_device = packet(addrs.device(), addrs.claw());
        let (relay_spoofed_device, relay_spoofed_device_event) = datapath
            .packet_from_relay_with_audit(
                session.id(),
                ClawVpnDatapathSide::Device,
                TunnelFrame::Data(wrong_relay_to_device),
            );
        assert_eq!(
            relay_spoofed_device,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            relay_spoofed_device_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        let (control, control_event) = datapath.packet_from_relay_with_audit(
            session.id(),
            ClawVpnDatapathSide::Device,
            TunnelFrame::Close,
        );
        assert_eq!(
            control,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::UnexpectedTunnelFrame
            ))
        );
        assert_eq!(
            control_event.reason(),
            ClawVpnAuditReason::UnexpectedTunnelFrame
        );

        let (closed, close_event) = datapath.close_with_audit(session.id());
        assert_eq!(closed.unwrap().id(), session.id());
        assert_eq!(close_event.reason(), ClawVpnAuditReason::SessionClosed);
        let (after_close, after_close_event) = datapath.packet_from_relay_with_audit(
            session.id(),
            ClawVpnDatapathSide::Claw,
            TunnelFrame::Data(packet(addrs.device(), addrs.claw())),
        );
        assert_eq!(after_close, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(
            after_close_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );
        assert_eq!(after_close_event.subject(), None);
    }

    #[test]
    fn datapath_revoke_removes_only_revoked_session_from_forwarding() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut datapath = ClawVpnDatapath::new(registry_with_grants(&[
            m1_claw_a.clone(),
            m2_claw_a.clone(),
        ]));
        let m1_session = datapath.open_with_audit(&m1_claw_a).0.unwrap();
        let m2_session = datapath.open_with_audit(&m2_claw_a).0.unwrap();

        let (revocation, revoke_event) = datapath.revoke_with_audit(&m2_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(revoke_event.reason(), ClawVpnAuditReason::AclRevoked);

        let m2_addrs = m2_session.addrs();
        assert_eq!(
            datapath
                .packet_from_relay_with_audit(
                    m2_session.id(),
                    ClawVpnDatapathSide::Claw,
                    TunnelFrame::Data(packet(m2_addrs.device(), m2_addrs.claw())),
                )
                .0,
            Err(ClawVpnSessionFrameError::UnknownSession)
        );

        let m1_addrs = m1_session.addrs();
        let (still_open, still_open_event) = datapath.packet_from_relay_with_audit(
            m1_session.id(),
            ClawVpnDatapathSide::Claw,
            TunnelFrame::Data(packet(m1_addrs.device(), m1_addrs.claw())),
        );
        assert_eq!(
            still_open.unwrap().as_bytes(),
            packet(m1_addrs.device(), m1_addrs.claw()).as_slice()
        );
        assert_eq!(still_open_event.reason(), ClawVpnAuditReason::FrameAccepted);
    }

    #[test]
    fn datapath_debug_does_not_print_relation_or_address_material() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut datapath =
            ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
        let session = datapath.open_with_audit(&m1_claw_a).0.unwrap();
        let addrs = session.addrs();
        let session_policy = session.packet_policy();

        for debug in [
            format!("{datapath:?}"),
            format!("{session:?}"),
            format!("{session_policy:?}"),
        ] {
            assert!(!debug.contains("member-m1"));
            assert!(!debug.contains("claw-a"));
            assert!(!debug.contains(&hex::encode(device_m1.public().as_bytes())));
            assert!(!debug.contains(&addrs.device().to_string()));
            assert!(!debug.contains(&addrs.claw().to_string()));
            assert!(debug.contains("<redacted>"));
        }
    }

    #[test]
    fn agent_core_binds_local_side_for_interface_and_relay_paths() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");

        let mut device_core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );
        assert_eq!(device_core.local_side(), ClawVpnDatapathSide::Device);
        let device_session = device_core.open_with_audit(&m1_claw_a).0.unwrap();
        let device_addrs = device_session.addrs();
        let device_to_claw = packet(device_addrs.device(), device_addrs.claw());
        let claw_to_device = packet(device_addrs.claw(), device_addrs.device());

        let (frame, frame_event) =
            device_core.frame_from_interface_with_audit(device_session.id(), &device_to_claw);
        assert_eq!(frame, Ok(TunnelFrame::Data(device_to_claw.clone())));
        assert_eq!(frame_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (wrong_interface_direction, wrong_interface_event) =
            device_core.frame_from_interface_with_audit(device_session.id(), &claw_to_device);
        assert_eq!(
            wrong_interface_direction,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            wrong_interface_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        let (packet_from_relay, relay_event) = device_core.packet_from_relay_with_audit(
            device_session.id(),
            TunnelFrame::Data(claw_to_device.clone()),
        );
        assert_eq!(
            packet_from_relay.unwrap().as_bytes(),
            claw_to_device.as_slice()
        );
        assert_eq!(relay_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (wrong_relay_direction, wrong_relay_event) = device_core.packet_from_relay_with_audit(
            device_session.id(),
            TunnelFrame::Data(device_to_claw.clone()),
        );
        assert_eq!(
            wrong_relay_direction,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            wrong_relay_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        let mut claw_core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Claw,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );
        assert_eq!(claw_core.local_side(), ClawVpnDatapathSide::Claw);
        let claw_session = claw_core.open_with_audit(&m1_claw_a).0.unwrap();
        let claw_addrs = claw_session.addrs();
        let claw_to_device = packet(claw_addrs.claw(), claw_addrs.device());
        let device_to_claw = packet(claw_addrs.device(), claw_addrs.claw());

        let (frame, frame_event) =
            claw_core.frame_from_interface_with_audit(claw_session.id(), &claw_to_device);
        assert_eq!(frame, Ok(TunnelFrame::Data(claw_to_device.clone())));
        assert_eq!(frame_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (packet_from_relay, relay_event) = claw_core.packet_from_relay_with_audit(
            claw_session.id(),
            TunnelFrame::Data(device_to_claw.clone()),
        );
        assert_eq!(
            packet_from_relay.unwrap().as_bytes(),
            device_to_claw.as_slice()
        );
        assert_eq!(relay_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (wrong_relay_direction, wrong_relay_event) = claw_core.packet_from_relay_with_audit(
            claw_session.id(),
            TunnelFrame::Data(claw_to_device.clone()),
        );
        assert_eq!(
            wrong_relay_direction,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            wrong_relay_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );
    }

    #[test]
    fn agent_core_uses_active_registry_for_close_and_revoke() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone()]),
        );
        let m1_session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let m2_session = core.open_with_audit(&m2_claw_a).0.unwrap();

        let (closed, close_event) = core.close_with_audit(m1_session.id());
        assert_eq!(closed.unwrap().id(), m1_session.id());
        assert_eq!(close_event.reason(), ClawVpnAuditReason::SessionClosed);
        let (after_close, after_close_event) = core.frame_from_interface_with_audit(
            m1_session.id(),
            &packet(m1_session.addrs().device(), m1_session.addrs().claw()),
        );
        assert_eq!(after_close, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(
            after_close_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );

        let (revocation, revoke_event) = core.revoke_with_audit(&m2_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(revoke_event.reason(), ClawVpnAuditReason::AclRevoked);
        let (after_revoke, after_revoke_event) = core.packet_from_relay_with_audit(
            m2_session.id(),
            TunnelFrame::Data(packet(
                m2_session.addrs().claw(),
                m2_session.addrs().device(),
            )),
        );
        assert_eq!(after_revoke, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(
            after_revoke_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );
    }

    #[test]
    fn agent_core_debug_does_not_print_relation_or_address_material() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );
        let session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let addrs = session.addrs();

        let debug = format!("{core:?}");
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&hex::encode(device_m1.public().as_bytes())));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn agent_session_core_binds_session_id_for_interface_and_relay_paths() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone()]),
        );
        let m1_session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let m2_session = core.open_with_audit(&m2_claw_a).0.unwrap();
        assert!(core.contains_session(m1_session.id()));
        assert!(core.contains_session(m2_session.id()));

        let bound = core.into_session_core(m1_session.id()).unwrap();
        assert_eq!(bound.local_side(), ClawVpnDatapathSide::Device);
        assert_eq!(bound.addrs().unwrap(), m1_session.addrs());
        assert_ne!(bound.addrs().unwrap(), m2_session.addrs());
        let m1_device_to_claw = packet(m1_session.addrs().device(), m1_session.addrs().claw());
        let m1_claw_to_device = packet(m1_session.addrs().claw(), m1_session.addrs().device());
        let m2_device_to_claw = packet(m2_session.addrs().device(), m2_session.addrs().claw());
        let m2_claw_to_device = packet(m2_session.addrs().claw(), m2_session.addrs().device());

        let (frame, frame_event) = bound.frame_from_interface_with_audit(&m1_device_to_claw);
        assert_eq!(frame, Ok(TunnelFrame::Data(m1_device_to_claw.clone())));
        assert_eq!(frame_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (wrong_session_frame, wrong_session_frame_event) =
            bound.frame_from_interface_with_audit(&m2_device_to_claw);
        assert_eq!(
            wrong_session_frame,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            wrong_session_frame_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        let (packet_from_relay, relay_event) =
            bound.packet_from_relay_with_audit(TunnelFrame::Data(m1_claw_to_device.clone()));
        assert_eq!(
            packet_from_relay.unwrap().as_bytes(),
            m1_claw_to_device.as_slice()
        );
        assert_eq!(relay_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (wrong_session_packet, wrong_session_packet_event) =
            bound.packet_from_relay_with_audit(TunnelFrame::Data(m2_claw_to_device));
        assert_eq!(
            wrong_session_packet,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            wrong_session_packet_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );
    }

    #[test]
    fn agent_session_core_rejects_unknown_session_binding() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );

        assert_eq!(
            core.into_session_core(ClawVpnSessionId(1)),
            Err(ClawVpnSessionFrameError::UnknownSession)
        );
    }

    #[test]
    fn agent_session_core_uses_active_registry_for_close_and_revoke() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone()]),
        );
        let m1_session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let m2_session = core.open_with_audit(&m2_claw_a).0.unwrap();
        let mut bound = core.into_session_core(m1_session.id()).unwrap();

        let (other_revocation, other_revoke_event) = bound.revoke_with_audit(&m2_claw_a);
        assert!(other_revocation.grant_removed());
        assert_eq!(other_revocation.closed_session_count(), 1);
        assert_eq!(other_revoke_event.reason(), ClawVpnAuditReason::AclRevoked);
        let (still_open, still_open_event) = bound.frame_from_interface_with_audit(&packet(
            m1_session.addrs().device(),
            m1_session.addrs().claw(),
        ));
        assert_eq!(
            still_open,
            Ok(TunnelFrame::Data(packet(
                m1_session.addrs().device(),
                m1_session.addrs().claw()
            )))
        );
        assert_eq!(still_open_event.reason(), ClawVpnAuditReason::FrameAccepted);

        let (closed, close_event) = bound.close_with_audit();
        assert_eq!(closed.unwrap().id(), m1_session.id());
        assert_eq!(close_event.reason(), ClawVpnAuditReason::SessionClosed);
        assert_eq!(bound.addrs(), Err(ClawVpnSessionFrameError::UnknownSession));
        let (after_close, after_close_event) = bound.frame_from_interface_with_audit(&packet(
            m1_session.addrs().device(),
            m1_session.addrs().claw(),
        ));
        assert_eq!(after_close, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(
            after_close_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );

        let (already_revoked, already_revoked_event) = bound.revoke_with_audit(&m2_claw_a);
        assert!(!already_revoked.grant_removed());
        assert_eq!(already_revoked.closed_session_count(), 0);
        assert_eq!(
            already_revoked_event.reason(),
            ClawVpnAuditReason::AclRevokeMissing
        );
        assert_ne!(m1_session.id(), m2_session.id());
    }

    #[test]
    fn agent_session_core_revoke_exact_relation_closes_bound_session() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );
        let session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let mut bound = core.into_session_core(session.id()).unwrap();

        let (revocation, revoke_event) = bound.revoke_with_audit(&m1_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert_eq!(revoke_event.reason(), ClawVpnAuditReason::AclRevoked);

        let (after_revoke, after_revoke_event) = bound.frame_from_interface_with_audit(&packet(
            session.addrs().device(),
            session.addrs().claw(),
        ));
        assert_eq!(after_revoke, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(
            after_revoke_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );
        assert_eq!(after_revoke_event.subject(), None);
    }

    #[test]
    fn agent_session_core_debug_does_not_print_relation_or_address_material() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            registry_with_grants(std::slice::from_ref(&m1_claw_a)),
        );
        let session = core.open_with_audit(&m1_claw_a).0.unwrap();
        let addrs = session.addrs();
        let bound = core.into_session_core(session.id()).unwrap();

        let debug = format!("{bound:?}");
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&hex::encode(device_m1.public().as_bytes())));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn audit_subject_hashes_relation_without_raw_identifiers() {
        let device = P256Keypair::generate();
        let other_device = P256Keypair::generate();
        let key = acl_key("member-m1", &device, "claw-a");
        let same_key = acl_key("member-m1", &device, "claw-a");
        let other_device_key = acl_key("member-m1", &other_device, "claw-a");

        let subject = ClawVpnAuditSubject::from_acl_key(&key);
        let same_subject = ClawVpnAuditSubject::from_acl_key(&same_key);
        let other_device_subject = ClawVpnAuditSubject::from_acl_key(&other_device_key);

        assert_eq!(subject, same_subject);
        assert_eq!(
            subject.member_id_hash(),
            other_device_subject.member_id_hash()
        );
        assert_eq!(subject.claw_id_hash(), other_device_subject.claw_id_hash());
        assert_ne!(
            subject.device_pub_hash(),
            other_device_subject.device_pub_hash()
        );

        let debug = format!("{subject:?}");
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains("P256PublicKey"));
        assert!(!debug.contains(&hex::encode(device.public().as_bytes())));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn audit_events_cover_open_close_and_revoke_without_raw_values() {
        let device_m1 = P256Keypair::generate();
        let device_m2 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let m2_claw_a = acl_key("member-m2", &device_m2, "claw-a");
        let mut registry = registry_with_grants(&[m1_claw_a.clone(), m2_claw_a.clone()]);

        let (opened, open_event) = registry.open_with_audit(&m1_claw_a);
        let opened = opened.unwrap();
        assert_eq!(open_event.action(), ClawVpnAuditAction::SessionOpen);
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);
        assert_eq!(open_event.session_id(), Some(opened.id()));
        assert_eq!(
            open_event.subject(),
            Some(ClawVpnAuditSubject::from_acl_key(&m1_claw_a))
        );
        assert_eq!(open_event.byte_count(), None);

        let (second_open, second_open_event) = registry.open_with_audit(&m1_claw_a);
        assert_eq!(
            second_open,
            Err(ClawVpnSessionRegistryError::MemberClawSessionLimitReached)
        );
        assert_eq!(
            second_open_event.reason(),
            ClawVpnAuditReason::MemberClawSessionLimitReached
        );

        let (closed, close_event) = registry.close_with_audit(opened.id());
        assert_eq!(closed.unwrap().id(), opened.id());
        assert_eq!(close_event.action(), ClawVpnAuditAction::SessionClose);
        assert_eq!(close_event.reason(), ClawVpnAuditReason::SessionClosed);
        assert_eq!(close_event.session_id(), Some(opened.id()));

        let (_missing_close, missing_close_event) = registry.close_with_audit(opened.id());
        assert_eq!(
            missing_close_event.reason(),
            ClawVpnAuditReason::UnknownSession
        );
        assert_eq!(missing_close_event.subject(), None);

        let m2_session = registry.open(&m2_claw_a).unwrap();
        let (revocation, revoke_event) = registry.revoke_with_audit(&m2_claw_a);
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert!(!registry.contains_session(m2_session.id()));
        assert_eq!(revoke_event.action(), ClawVpnAuditAction::AclRevoke);
        assert_eq!(revoke_event.reason(), ClawVpnAuditReason::AclRevoked);
        assert_eq!(revoke_event.closed_session_count(), Some(1));

        let (_missing_revoke, missing_revoke_event) = registry.revoke_with_audit(&m2_claw_a);
        assert_eq!(
            missing_revoke_event.reason(),
            ClawVpnAuditReason::AclRevokeMissing
        );
        assert_eq!(missing_revoke_event.closed_session_count(), Some(0));

        let debug = format!("{open_event:?} {close_event:?} {revoke_event:?}");
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("member-m2"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&hex::encode(device_m1.public().as_bytes())));
        assert!(!debug.contains(&hex::encode(device_m2.public().as_bytes())));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn audit_events_cover_frame_validation_without_packet_or_addresses() {
        let device_m1 = P256Keypair::generate();
        let m1_claw_a = acl_key("member-m1", &device_m1, "claw-a");
        let mut registry = registry_with_grants(std::slice::from_ref(&m1_claw_a));
        let session = registry.open(&m1_claw_a).unwrap();
        let addrs = session.addrs();
        let authorized_packet = packet(addrs.device(), addrs.claw());

        let (accepted, accepted_event) = registry.validate_tunnel_frame_for_session_with_audit(
            session.id(),
            ClawVpnPacketDirection::DeviceToClaw,
            TunnelFrame::Data(authorized_packet.clone()),
        );
        assert_eq!(accepted.unwrap().as_bytes(), authorized_packet.as_slice());
        assert_eq!(accepted_event.action(), ClawVpnAuditAction::FrameValidate);
        assert_eq!(accepted_event.reason(), ClawVpnAuditReason::FrameAccepted);
        assert_eq!(accepted_event.session_id(), Some(session.id()));
        assert_eq!(accepted_event.byte_count(), Some(authorized_packet.len()));

        let (control_result, control_event) = registry
            .validate_tunnel_frame_for_session_with_audit(
                session.id(),
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Close,
            );
        assert_eq!(
            control_result,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::UnexpectedTunnelFrame
            ))
        );
        assert_eq!(
            control_event.reason(),
            ClawVpnAuditReason::UnexpectedTunnelFrame
        );

        let (spoof_result, spoof_event) = registry.validate_tunnel_frame_for_session_with_audit(
            session.id(),
            ClawVpnPacketDirection::DeviceToClaw,
            TunnelFrame::Data(packet(addrs.claw(), addrs.device())),
        );
        assert_eq!(
            spoof_result,
            Err(ClawVpnSessionFrameError::Packet(
                ClawVpnValidatedPacketError::Policy(ClawVpnPacketPolicyError::SourceMismatch)
            ))
        );
        assert_eq!(
            spoof_event.reason(),
            ClawVpnAuditReason::PacketPolicyRejected
        );

        registry.close(session.id()).unwrap();
        let (closed_result, closed_event) = registry.validate_tunnel_frame_for_session_with_audit(
            session.id(),
            ClawVpnPacketDirection::DeviceToClaw,
            TunnelFrame::Data(authorized_packet.clone()),
        );
        assert_eq!(closed_result, Err(ClawVpnSessionFrameError::UnknownSession));
        assert_eq!(closed_event.reason(), ClawVpnAuditReason::UnknownSession);
        assert_eq!(closed_event.subject(), None);

        let debug = format!("{accepted_event:?} {control_event:?} {spoof_event:?}");
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn validated_packet_wraps_only_authorized_ipv4_as_tunnel_data() {
        let policy = policy();
        let addrs = policy.addrs();
        let original = packet(addrs.device(), addrs.claw());

        let validated = ClawVpnValidatedPacket::try_from_ipv4_packet(
            &policy,
            ClawVpnPacketDirection::DeviceToClaw,
            &original,
        )
        .unwrap();
        assert_eq!(validated.as_bytes(), original);

        let frame = validated.clone().into_tunnel_frame();
        assert_eq!(frame, TunnelFrame::Data(original.clone()));

        let decoded = ClawVpnValidatedPacket::try_from_tunnel_frame(
            &policy,
            ClawVpnPacketDirection::DeviceToClaw,
            frame,
        )
        .unwrap();
        assert_eq!(decoded.into_bytes(), original);
    }

    #[test]
    fn validated_packet_rejects_spoofed_or_control_frames_before_forwarding() {
        let policy = policy();
        let addrs = policy.addrs();

        assert_eq!(
            ClawVpnValidatedPacket::try_from_ipv4_packet(
                &policy,
                ClawVpnPacketDirection::DeviceToClaw,
                &packet(Ipv4Addr::new(198, 51, 100, 30), addrs.claw()),
            ),
            Err(ClawVpnValidatedPacketError::Policy(
                ClawVpnPacketPolicyError::SourceMismatch
            ))
        );

        assert_eq!(
            ClawVpnValidatedPacket::try_from_tunnel_frame(
                &policy,
                ClawVpnPacketDirection::DeviceToClaw,
                TunnelFrame::Close,
            ),
            Err(ClawVpnValidatedPacketError::UnexpectedTunnelFrame)
        );
    }

    #[test]
    fn adversarial_boundary_probe_172_block() {
        // Just below 172.16.0.0/12 lower bound: must be ALLOWED.
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(172, 15, 255, 0), 24).is_ok());
        // Exactly at the lower bound: must be REJECTED.
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(172, 16, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        // Top of the /12 block: must be REJECTED.
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(172, 31, 255, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        // Just above the /12 block: must be ALLOWED.
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(172, 32, 0, 0), 24).is_ok());
    }

    #[test]
    fn adversarial_boundary_probe_10_and_cgnat_and_192() {
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(9, 255, 255, 0), 24).is_ok());
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(10, 255, 255, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(11, 0, 0, 0), 24).is_ok());

        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(100, 63, 255, 0), 24).is_ok());
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(100, 64, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(100, 127, 255, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(100, 128, 0, 0), 24).is_ok());

        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(192, 167, 255, 0), 24).is_ok());
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(192, 168, 0, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(192, 168, 255, 0), 24),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(192, 169, 0, 0), 24).is_ok());
    }

    #[test]
    fn adversarial_prefix_len_structural_bounds() {
        // /30 is the smallest allowed (exactly enough for one device+claw pair).
        assert!(ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 30).is_ok());
        // /31, /32 rejected as PrefixTooSmall.
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 31),
            Err(ClawVpnPoolError::PrefixTooSmall)
        );
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 32),
            Err(ClawVpnPoolError::PrefixTooSmall)
        );
        // Structurally invalid (>32, IPv4 has no such prefix) must not panic and
        // must be rejected. u8 max is 255; try a few, including 255 (no overflow
        // panic in the shift because the >30 check short-circuits first).
        for bad in [33u8, 40, 63, 64, 100, 200, 255] {
            assert_eq!(
                ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), bad),
                Err(ClawVpnPoolError::PrefixTooSmall),
                "prefix_len={bad} should be rejected without panicking"
            );
        }
        // /0 is not caught by the >30 check, but the only host-bits-zero network
        // for /0 is 0.0.0.0, and that always overlaps every reserved range.
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(0, 0, 0, 0), 0),
            Err(ClawVpnPoolError::OverlapsReservedRange)
        );
        // A non-zero network with prefix_len=0 hits HostBitsSet first.
        assert_eq!(
            ClawVpnIpv4Pool::try_new(Ipv4Addr::new(1, 2, 3, 4), 0),
            Err(ClawVpnPoolError::HostBitsSet)
        );
    }

    #[test]
    fn validated_packet_enforces_v1_inner_mtu() {
        let policy = policy();
        let addrs = policy.addrs();
        let too_large_payload = CLAW_VPN_V1_INNER_MTU + 1 - IPV4_MIN_HEADER_LEN;

        assert_eq!(
            ClawVpnValidatedPacket::try_from_ipv4_packet(
                &policy,
                ClawVpnPacketDirection::DeviceToClaw,
                &packet_with_payload_len(addrs.device(), addrs.claw(), too_large_payload),
            ),
            Err(ClawVpnValidatedPacketError::PacketTooLarge)
        );
    }
}
