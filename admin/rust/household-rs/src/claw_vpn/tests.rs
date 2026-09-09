#![cfg(test)]

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
        ClawVpnSessionAddrs::try_new(Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::new(198, 51, 100, 20)),
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

    let mut claw_limited = ClawVpnSessionRegistry::with_limits(acl.clone(), pool(), 1, 1).unwrap();
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
        .validate_tunnel_frame_for_session(session.id(), ClawVpnPacketDirection::DeviceToClaw, data)
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
    let mut datapath = ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
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
    let mut datapath = ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
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
    let (relay_spoofed_device, relay_spoofed_device_event) = datapath.packet_from_relay_with_audit(
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
    let mut datapath = ClawVpnDatapath::new(registry_with_grants(std::slice::from_ref(&m1_claw_a)));
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

    let (packet_from_relay, relay_event) = claw_core
        .packet_from_relay_with_audit(claw_session.id(), TunnelFrame::Data(device_to_claw.clone()));
    assert_eq!(
        packet_from_relay.unwrap().as_bytes(),
        device_to_claw.as_slice()
    );
    assert_eq!(relay_event.reason(), ClawVpnAuditReason::FrameAccepted);

    let (wrong_relay_direction, wrong_relay_event) = claw_core
        .packet_from_relay_with_audit(claw_session.id(), TunnelFrame::Data(claw_to_device.clone()));
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

    let (after_revoke, after_revoke_event) = bound
        .frame_from_interface_with_audit(&packet(session.addrs().device(), session.addrs().claw()));
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

    let (control_result, control_event) = registry.validate_tunnel_frame_for_session_with_audit(
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
