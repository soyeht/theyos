//! Pure packet-policy helpers for the Product A per-Claw VPN.
//!
//! This module intentionally does not create TUN/utun interfaces, routes, or
//! relay sessions. It is the fail-closed packet filter that the future claw VPN
//! agent can call before forwarding an IP packet between a single device and a
//! single claw.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;

use crate::claw_share::data_tunnel::TunnelFrame;
use crate::keys::P256PublicKey;
use sha2::{Digest, Sha256};

/// Smallest interface MTU any consumer may configure.
///
/// Not a preference: RFC 8200 §5 makes 1280 the minimum link MTU for IPv6, and
/// `NEPacketTunnelNetworkSettings` on the client side rejects anything below it.
/// Every validator in this workspace already used 1280 as its floor; naming it
/// here stops the next one from picking a different number.
pub const CLAW_VPN_MIN_INTERFACE_MTU: usize = 1280;

/// Largest inner packet the pump forwards. Above this it drops, counted.
///
/// **This is the same quantity as the interface MTU, seen from the other end**,
/// and that is why it must not be smaller than
/// [`CLAW_VPN_MIN_INTERFACE_MTU`]. It was 1250 while nothing consumed it, and
/// then three independent sites started requiring `1280..=9000` — the dev
/// runner's config validator, its session-ack validator, and the iOS
/// `NEPacketTunnelNetworkSettings` builder — while the server announced 1280.
/// The result was an empty set: **every MTU the system accepted exceeded the
/// threshold at which the pump silently dropped.** An interface configured at
/// 1280 hands up 1280-byte packets and 30 bytes of every full-size one went to
/// a drop counter.
///
/// A compile-time assertion below pins the two together, so raising the floor
/// without raising this fails the build rather than reopening the gap. Raising
/// this is safe (the pump forwards more); lowering it below the floor is the
/// defect and is now unrepresentable.
///
/// **Why 1400 and not 1280.** Setting it to the floor would leave exactly one
/// legal MTU, and the value the system actually produced was 1400 — the dev
/// runner's generator default, which every accepting validator allowed. 1400
/// keeps that working and leaves `1280..=1400` as a real range. The original
/// 1250 came from the plan as "conservative pending path measurements", written
/// when the transport was still open; it is TCP over the relay, which segments
/// on its own, so the inner MTU is not bounded by a path MTU the way a datagram
/// tunnel's would be. Revisit with a measurement, not with a smaller guess.
pub const CLAW_VPN_V1_INNER_MTU: usize = 1400;

// The invariant, not a comment about it: a configured interface hands the pump
// packets up to its own MTU, so a pump that forwards less than the smallest
// configurable interface drops traffic no operator can avoid by configuration.
const _: () = assert!(
    CLAW_VPN_V1_INNER_MTU >= CLAW_VPN_MIN_INTERFACE_MTU,
    "the pump must forward at least the smallest interface MTU a consumer can \
     configure, or every valid configuration silently drops full-size packets"
);

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
mod tests;
