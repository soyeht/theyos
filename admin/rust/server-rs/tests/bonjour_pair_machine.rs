//! Pure TXT-record coverage for Phase 3 pair-machine Bonjour state.

use std::time::Duration;

use household_rs::pair_device::PairToken;
use household_rs::pair_machine::{PairMachineState, PairMachineWindowSnapshot};
use serde_bytes::ByteBuf;
use server_rs::bonjour_publisher::{HouseholdBonjour, PairMachineBonjourRole, PublishParams};

fn params(role: PairMachineBonjourRole) -> PublishParams {
    PublishParams {
        hh_id: "hh_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr".into(),
        hh_name: "Sample Home".into(),
        m_id: "m_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr".into(),
        port: 8091,
        host_label: "studio".into(),
        host_dns: "studio.local".into(),
        pair_machine_role: Some(role),
        owner_display_name: String::new(),
        device_count: 0,
        bootstrap_state: "ready".into(),
    }
}

fn machine_snapshot(state: PairMachineState) -> PairMachineWindowSnapshot {
    PairMachineWindowSnapshot {
        version: 1,
        state,
        m_pub: Some(ByteBuf::from(vec![0x02; 33])),
        nonce: Some(ByteBuf::from(vec![0x42; 32])),
        expiry: Some(1_714_972_800),
        transport: None,
        addr_hint: None,
        fingerprint: None,
        owner_event_cursor: None,
        cached_join_request: None,
        cached_response: None,
        anchor_secret: None,
        pinned_hh_pub: None,
        pinned_hh_id: None,
    }
}

#[test]
fn pair_machine_founder_txt_reflects_machine_window() {
    let snap = machine_snapshot(PairMachineState::Staging);
    let txt = HouseholdBonjour::txt_for_state(
        &params(PairMachineBonjourRole::Founder),
        None,
        Some(&snap),
    );

    assert_eq!(txt.get("pairing").map(String::as_str), Some("machine"));
    assert_eq!(txt.get("pair_role").map(String::as_str), Some("founder"));
    assert!(txt.contains_key("pair_nonce"));
    assert!(!txt.contains_key("m_pub_b32"));
}

#[test]
fn pair_machine_joiner_txt_includes_m_pub_short() {
    let snap = machine_snapshot(PairMachineState::Staging);
    let txt =
        HouseholdBonjour::txt_for_state(&params(PairMachineBonjourRole::Joiner), None, Some(&snap));

    assert_eq!(txt.get("pairing").map(String::as_str), Some("machine"));
    assert_eq!(txt.get("pair_role").map(String::as_str), Some("joiner"));
    assert_eq!(
        txt.get("m_pub_b32").map(String::as_str),
        Some(household_rs::ids::m_pub_short(&[0x02; 33]).as_str())
    );
}

#[test]
fn idle_pair_machine_window_removes_pairing_txt() {
    let snap = machine_snapshot(PairMachineState::Idle);
    let txt = HouseholdBonjour::txt_for_state(
        &params(PairMachineBonjourRole::Founder),
        None,
        Some(&snap),
    );

    assert!(!txt.contains_key("pairing"));
    assert!(!txt.contains_key("pair_role"));
    assert!(!txt.contains_key("pair_nonce"));
    assert!(!txt.contains_key("m_pub_b32"));
}

#[test]
fn pair_machine_txt_takes_precedence_over_pair_device_txt() {
    let token = PairToken::mint(Duration::from_secs(60), None).unwrap();
    let snap = machine_snapshot(PairMachineState::AwaitingOwner);
    let txt = HouseholdBonjour::txt_for_state(
        &params(PairMachineBonjourRole::Founder),
        Some(token),
        Some(&snap),
    );

    assert_eq!(txt.get("pairing").map(String::as_str), Some("machine"));
    assert_eq!(txt.get("pair_role").map(String::as_str), Some("founder"));
}
