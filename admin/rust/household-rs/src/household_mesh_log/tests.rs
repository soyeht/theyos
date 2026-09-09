#![cfg(test)]

use super::*;
use crate::claw_share::SlotId;
use crate::household_record::HouseholdRecord;
use crate::ids::{derive_household_id, derive_machine_id};
use crate::issuer_trust::{MachineIssuerError, is_machine_issuer_active};
use crate::keys::P256Keypair;
use crate::machine_cert::{MachineCert, Platform, SignOptions};

fn mint(key: &P256Keypair, ts: u64, event: MeshEvent) -> LogEntry {
    LogEntry::sign(ts, key.public(), event, key as &dyn IdentityKey).expect("sign")
}

// ── Slice C1: created_at + revoke idempotence in the projection ──────────

#[test]
fn projected_created_at_comes_from_the_mint_entry_only() {
    let owner = P256Keypair::generate();
    let minted = SlotId::random();
    let orphan_consume = SlotId::random();
    let orphan_revoke = SlotId::random();
    let entries = vec![
        mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: minted.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 5_000,
                app_presentation: None,
            },
        ),
        // Consume with no mint in view, and revoke with no mint in view.
        mint(
            &owner,
            1_100,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: orphan_consume.clone(),
                claw_id: "claw_b".to_string(),
                expires_at: 5_000,
                guest_device_pub: P256Keypair::generate().public(),
                participant_npub: None,
            },
        ),
        mint(
            &owner,
            1_200,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: orphan_revoke.clone(),
            },
        ),
    ];
    let state = ProjectedState::project(&entries);

    assert_eq!(
        state.slots[&minted].created_at,
        Some(1_000),
        "the mint entry's own timestamp is the creation time"
    );
    // The observing event's timestamp is NOT the creation time, and
    // inventing one would be indistinguishable from a real value.
    assert_eq!(state.slots[&orphan_consume].created_at, None);
    assert_eq!(state.slots[&orphan_revoke].created_at, None);
    // Non-vacuity: created_at must not be aliasing expires_at.
    assert_ne!(
        state.slots[&minted].created_at,
        Some(state.slots[&minted].expires_at)
    );
}

#[test]
fn duplicate_revokes_keep_the_first_timestamp_and_what_it_preserved() {
    let owner = P256Keypair::generate();
    let guest = P256Keypair::generate().public();
    let slot = SlotId::random();
    let entries = vec![
        mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 9_000,
                app_presentation: None,
            },
        ),
        mint(
            &owner,
            2_000,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: slot.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 9_000,
                guest_device_pub: guest.clone(),
                participant_npub: Some("npub_alice".to_string()),
            },
        ),
        mint(
            &owner,
            3_000,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: slot.clone(),
            },
        ),
        // A duplicate revoke, LATER. It must be inert — this is also what
        // heals logs that already carry duplicates.
        mint(
            &owner,
            4_000,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: slot.clone(),
            },
        ),
    ];
    let state = ProjectedState::project(&entries);

    assert_eq!(
        state.slots[&slot].status,
        SlotProjectedStatus::Revoked {
            revoked_at: 3_000,
            participant_npub: Some("npub_alice".to_string()),
            accepted_at: Some(2_000),
        },
        "first revoke wins; the second must not move revoked_at nor drop \
             accepted_at/participant_npub"
    );
    assert_eq!(state.slots[&slot].created_at, Some(1_000));
}

#[test]
fn replay_carries_created_at_and_accepted_at_into_the_slot_store() {
    let owner = P256Keypair::generate();
    let guest = P256Keypair::generate().public();
    let slot = SlotId::random();
    let entries = vec![
        mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 9_000,
                app_presentation: None,
            },
        ),
        mint(
            &owner,
            2_000,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: slot.clone(),
                claw_id: "claw_a".to_string(),
                expires_at: 9_000,
                guest_device_pub: guest,
                participant_npub: None,
            },
        ),
        mint(
            &owner,
            3_000,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: slot.clone(),
            },
        ),
    ];
    let state = ProjectedState::project(&entries);
    let store = crate::claw_share::ClawShareSlotStore::seeded_from(&state);
    let record = store.get(&slot).expect("slot rehydrates");

    assert_eq!(record.created_at, Some(1_000));
    assert_eq!(
        record.state,
        crate::claw_share::SlotState::Revoked {
            revoked_at: 3_000,
            accepted_at: Some(2_000),
        }
    );
}

// ── Fase E1: first-class group + member-device projection ────────────────

#[test]
fn group_grant_authorizes_member_device_npubs_for_claw() {
    let owner = P256Keypair::generate();
    let alice_dev = P256Keypair::generate().public();
    let entries = vec![
        mint(
            &owner,
            1_000,
            MeshEvent::GroupCreated {
                group_id: "grp_family".into(),
                name: "Família".into(),
            },
        ),
        mint(
            &owner,
            1_100,
            MeshEvent::GroupMemberAdded {
                group_id: "grp_family".into(),
                member_id: "g_alice".into(),
                label: "Alice".into(),
            },
        ),
        mint(
            &owner,
            1_200,
            MeshEvent::GroupClawGranted {
                group_id: "grp_family".into(),
                claw_id: "claw_home".into(),
            },
        ),
        mint(
            &owner,
            1_300,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_alice".into(),
                device_pub: alice_dev,
                participant_npub: "npub_alice_phone".into(),
            },
        ),
    ];
    let s = ProjectedState::project(&entries);
    assert_eq!(
        s.groups
            .get("grp_family")
            .and_then(|group| group.member_labels.get("g_alice")),
        Some(&"Alice".to_string())
    );
    assert!(
        s.members_authorized_for_claw("claw_home")
            .contains("g_alice")
    );
    assert!(
        s.group_member_npubs_for_claw("claw_home")
            .contains("npub_alice_phone")
    );
    // No grant ⇒ no authorization for another claw.
    assert!(s.members_authorized_for_claw("claw_other").is_empty());
}

#[test]
fn group_projection_retains_member_labels_for_owner_display() {
    let owner = P256Keypair::generate();
    let entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupMemberAdded {
                group_id: "g".into(),
                member_id: "g_a".into(),
                label: "Alice phone".into(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupMemberRemoved {
                group_id: "g".into(),
                member_id: "g_a".into(),
            },
        ),
    ];
    let state = ProjectedState::project(&entries);
    let group = state.groups.get("g").expect("group projected");
    assert_eq!(
        group.member_labels.get("g_a"),
        Some(&"Alice phone".to_string())
    );
    assert_eq!(group.members.get("g_a"), Some(&MeshMembership::Removed));
}

#[test]
fn group_member_removed_drops_from_claw() {
    let owner = P256Keypair::generate();
    let dev = P256Keypair::generate().public();
    let mut entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupMemberAdded {
                group_id: "g".into(),
                member_id: "g_a".into(),
                label: String::new(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupClawGranted {
                group_id: "g".into(),
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            4,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: dev,
                participant_npub: "n".into(),
            },
        ),
    ];
    assert!(
        ProjectedState::project(&entries)
            .group_member_npubs_for_claw("c")
            .contains("n")
    );
    entries.push(mint(
        &owner,
        5,
        MeshEvent::GroupMemberRemoved {
            group_id: "g".into(),
            member_id: "g_a".into(),
        },
    ));
    let s = ProjectedState::project(&entries);
    assert!(s.members_authorized_for_claw("c").is_empty());
    assert!(s.group_member_npubs_for_claw("c").is_empty());
}

#[test]
fn group_claw_revoked_drops_grant() {
    let owner = P256Keypair::generate();
    let dev = P256Keypair::generate().public();
    let entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupMemberAdded {
                group_id: "g".into(),
                member_id: "g_a".into(),
                label: String::new(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupClawGranted {
                group_id: "g".into(),
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            4,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: dev,
                participant_npub: "n".into(),
            },
        ),
        mint(
            &owner,
            5,
            MeshEvent::GroupClawRevoked {
                group_id: "g".into(),
                claw_id: "c".into(),
            },
        ),
    ];
    let s = ProjectedState::project(&entries);
    assert!(s.members_authorized_for_claw("c").is_empty());
    assert!(s.group_member_npubs_for_claw("c").is_empty());
}

#[test]
fn member_in_two_groups_remove_one_keeps_other() {
    let owner = P256Keypair::generate();
    let dev = P256Keypair::generate().public();
    let entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "fam".into(),
                name: "Família".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupCreated {
                group_id: "work".into(),
                name: "Trabalho".into(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupMemberAdded {
                group_id: "fam".into(),
                member_id: "g_a".into(),
                label: String::new(),
            },
        ),
        mint(
            &owner,
            4,
            MeshEvent::GroupMemberAdded {
                group_id: "work".into(),
                member_id: "g_a".into(),
                label: String::new(),
            },
        ),
        mint(
            &owner,
            5,
            MeshEvent::GroupClawGranted {
                group_id: "fam".into(),
                claw_id: "claw_fam".into(),
            },
        ),
        mint(
            &owner,
            6,
            MeshEvent::GroupClawGranted {
                group_id: "work".into(),
                claw_id: "claw_work".into(),
            },
        ),
        mint(
            &owner,
            7,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: dev,
                participant_npub: "n".into(),
            },
        ),
        mint(
            &owner,
            8,
            MeshEvent::GroupMemberRemoved {
                group_id: "work".into(),
                member_id: "g_a".into(),
            },
        ),
    ];
    let s = ProjectedState::project(&entries);
    assert!(s.group_member_npubs_for_claw("claw_fam").contains("n"));
    assert!(s.group_member_npubs_for_claw("claw_work").is_empty());
}

#[test]
fn member_device_retired_drops_npub_but_keeps_member() {
    let owner = P256Keypair::generate();
    let phone = P256Keypair::generate().public();
    let laptop = P256Keypair::generate().public();
    let entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupMemberAdded {
                group_id: "g".into(),
                member_id: "g_a".into(),
                label: String::new(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupClawGranted {
                group_id: "g".into(),
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            4,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: phone.clone(),
                participant_npub: "n_phone".into(),
            },
        ),
        mint(
            &owner,
            5,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: laptop,
                participant_npub: "n_laptop".into(),
            },
        ),
        mint(
            &owner,
            6,
            MeshEvent::MeshMemberDeviceRetired {
                member_id: "g_a".into(),
                device_pub: phone,
            },
        ),
    ];
    let s = ProjectedState::project(&entries);
    let npubs = s.group_member_npubs_for_claw("c");
    assert!(!npubs.contains("n_phone"));
    assert!(npubs.contains("n_laptop"));
    // Member is still authorized (only one of two devices retired).
    assert!(s.members_authorized_for_claw("c").contains("g_a"));
}

#[test]
fn group_projection_is_order_independent_and_rename_lww() {
    let owner = P256Keypair::generate();
    let dev = P256Keypair::generate().public();
    let entries = vec![
        mint(
            &owner,
            1,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::GroupMemberAdded {
                group_id: "g".into(),
                member_id: "g_a".into(),
                label: "A".into(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::GroupClawGranted {
                group_id: "g".into(),
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            4,
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: "g_a".into(),
                device_pub: dev,
                participant_npub: "n".into(),
            },
        ),
        mint(
            &owner,
            5,
            MeshEvent::GroupRenamed {
                group_id: "g".into(),
                name: "G2".into(),
            },
        ),
    ];
    let forward = ProjectedState::project(&entries);
    let mut reversed = entries.clone();
    reversed.reverse();
    let backward = ProjectedState::project(&reversed);
    assert_eq!(forward, backward, "group projection diverged by order");
    // Rename is last-writer-wins by timestamp regardless of log order.
    assert_eq!(forward.groups["g"].name, "G2");
}

#[test]
fn claw_site_publish_unpublish_is_remove_wins_and_republishable() {
    let owner = P256Keypair::generate();
    // Publish then unpublish (newer ts) → not published.
    let s1 = ProjectedState::project(&[
        mint(
            &owner,
            1,
            MeshEvent::ClawSitePublished {
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::ClawSiteUnpublished {
                claw_id: "c".into(),
            },
        ),
    ]);
    assert!(!s1.is_claw_published("c"));
    // Re-publish with a strictly-newer ts → published again.
    let s2 = ProjectedState::project(&[
        mint(
            &owner,
            1,
            MeshEvent::ClawSitePublished {
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            2,
            MeshEvent::ClawSiteUnpublished {
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            3,
            MeshEvent::ClawSitePublished {
                claw_id: "c".into(),
            },
        ),
    ]);
    assert!(s2.is_claw_published("c"));
    assert!(!s2.is_claw_published("other"));
    // Same-ts unpublish wins over publish (remove-wins-on-tie kill switch).
    let s3 = ProjectedState::project(&[
        mint(
            &owner,
            5,
            MeshEvent::ClawSitePublished {
                claw_id: "c".into(),
            },
        ),
        mint(
            &owner,
            5,
            MeshEvent::ClawSiteUnpublished {
                claw_id: "c".into(),
            },
        ),
    ]);
    assert!(!s3.is_claw_published("c"));
}

fn member_machine_cert(hh: &P256Keypair, m: &P256Keypair) -> MachineCert {
    MachineCert::sign(
        hh,
        &m.public(),
        &SignOptions {
            hh_id: derive_household_id(&hh.public()),
            hostname: "studio-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .expect("machine cert")
}

fn household_record_with_member(hh: &P256Keypair, m: &P256Keypair) -> HouseholdRecord {
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh.public()),
        hh_pub: hh.public(),
        name: "home".into(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(&m.public())],
        is_follower: false,
    }
}

#[test]
fn entry_verify_round_trip() {
    let key = P256Keypair::generate();
    let entry = mint(
        &key,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000,
            app_presentation: None,
        },
    );
    entry.verify().expect("verify");
}

#[test]
fn tampered_entry_fails_verify() {
    let key = P256Keypair::generate();
    let mut entry = mint(
        &key,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000,
            app_presentation: None,
        },
    );
    // Change a body field — entry_id and signature both invalidate.
    entry.timestamp = 9_999;
    let err = entry.verify().expect_err("must reject");
    assert!(matches!(err, MeshLogError::EntryIdMismatch));
}

#[test]
fn projection_is_order_independent() {
    let owner = P256Keypair::generate();
    let slot_a = SlotId::random();
    let slot_b = SlotId::random();
    let mint_a = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: slot_a.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let mint_b = mint(
        &owner,
        2_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: slot_b.clone(),
            claw_id: "claw_b".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let consume_a = mint(
        &owner,
        3_000,
        MeshEvent::ClawShareSlotConsumed {
            slot_id: slot_a.clone(),
            guest_device_pub: P256Keypair::generate().public(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            participant_npub: None,
        },
    );

    let order_1 = vec![mint_a.clone(), mint_b.clone(), consume_a.clone()];
    let order_2 = vec![consume_a.clone(), mint_b.clone(), mint_a.clone()];
    let order_3 = vec![mint_b.clone(), consume_a.clone(), mint_a.clone()];

    let s1 = ProjectedState::project(&order_1);
    let s2 = ProjectedState::project(&order_2);
    let s3 = ProjectedState::project(&order_3);

    assert_eq!(s1, s2, "shuffle 2 diverged");
    assert_eq!(s1, s3, "shuffle 3 diverged");
    assert_eq!(s1.slots.len(), 2);
}

#[test]
fn remove_wins_for_slot_revoke() {
    let owner = P256Keypair::generate();
    let slot_a = SlotId::random();
    // Mint at ts=1000, revoke at ts=500 (revoke is EARLIER in real
    // time — remove-wins must still apply).
    let mint_evt = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: slot_a.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let revoke_evt = mint(
        &owner,
        500,
        MeshEvent::ClawShareSlotRevoked {
            slot_id: slot_a.clone(),
        },
    );
    // Then a Consume tries to land — should also lose to revoke.
    let consume_evt = mint(
        &owner,
        900,
        MeshEvent::ClawShareSlotConsumed {
            slot_id: slot_a.clone(),
            guest_device_pub: P256Keypair::generate().public(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            participant_npub: None,
        },
    );

    let state = ProjectedState::project(&[mint_evt, revoke_evt, consume_evt]);
    let projected = state.slots.get(&slot_a).expect("slot present");
    assert!(matches!(
        projected.status,
        SlotProjectedStatus::Revoked { .. }
    ));
}

#[test]
fn store_dedups_by_entry_id() {
    let owner = P256Keypair::generate();
    let entry = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_d".to_string(),
            expires_at: 2_000,
            app_presentation: None,
        },
    );
    let store = MeshLogStore::new();
    assert!(store.append(entry.clone()).expect("first append"));
    assert!(!store.append(entry).expect("second append"));
    assert_eq!(store.len(), 1);
}

#[test]
fn store_rejects_tampered_remote_entries() {
    let owner = P256Keypair::generate();
    let mut entry = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_d".to_string(),
            expires_at: 2_000,
            app_presentation: None,
        },
    );
    entry.timestamp = 9_999;
    let store = MeshLogStore::new();
    let err = store
        .ingest_remote(&[entry])
        .expect_err("tampered must reject");
    assert!(matches!(err, MeshLogError::EntryIdMismatch));
    assert_eq!(store.len(), 0);
}

#[test]
fn two_device_gossip_converges_after_revoke() {
    // Device A mints a slot. Device B (same owner key, different
    // physical machine) revokes the same slot. They each ingest
    // the other's entries via gossip and end up with the same
    // projected state — both see the slot as Revoked.
    //
    // This is the slice's revocation-propagation correctness
    // proof: the projection commutes with gossip order.
    let owner = P256Keypair::generate();
    let slot_id = SlotId::random();
    let store_a = MeshLogStore::new();
    let store_b = MeshLogStore::new();

    let mint_evt = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: slot_id.clone(),
            claw_id: "claw_g".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let revoke_evt = mint(
        &owner,
        1_500,
        MeshEvent::ClawShareSlotRevoked {
            slot_id: slot_id.clone(),
        },
    );

    store_a.append(mint_evt.clone()).expect("a mint");
    store_b.append(revoke_evt.clone()).expect("b revoke");

    // Gossip A → B and B → A. Both directions delivered exactly
    // once; duplicate ingests should be silent no-ops.
    store_b
        .ingest_remote(&store_a.snapshot())
        .expect("b ingests a");
    store_a
        .ingest_remote(&store_b.snapshot())
        .expect("a ingests b");
    // Re-ingest is idempotent:
    let added = store_a
        .ingest_remote(&store_b.snapshot())
        .expect("a re-ingests b");
    assert_eq!(added, 0);

    let state_a = store_a.project();
    let state_b = store_b.project();
    assert_eq!(state_a, state_b, "two-device projection diverged");

    let slot_state = state_a.slots.get(&slot_id).expect("slot present");
    assert!(
        matches!(slot_state.status, SlotProjectedStatus::Revoked { .. }),
        "expected Revoked, got {:?}",
        slot_state.status,
    );
}

#[test]
fn persistent_store_survives_restart() {
    // Engine restart correctness: write a mint event to a real
    // file, drop the store, reopen against the same path, and
    // confirm the projection shows the slot as Open with the
    // same id.
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    let path = tmp.path().to_path_buf();
    // Remove the tempfile-created empty file so MeshLogStore::open
    // exercises its "fresh log" branch on first open.
    std::fs::remove_file(&path).ok();

    let owner = P256Keypair::generate();
    let slot_id = SlotId::random();

    {
        let store = MeshLogStore::open(&path).expect("open fresh");
        assert!(store.is_empty(), "fresh store should be empty");
        let entry = mint(
            &owner,
            1_000,
            MeshEvent::ClawShareSlotMinted {
                slot_id: slot_id.clone(),
                claw_id: "claw_persist".to_string(),
                expires_at: 5_000,
                app_presentation: None,
            },
        );
        store.append(entry).expect("append");
        assert_eq!(store.len(), 1);
    }

    // Simulate engine restart: reopen against the same file.
    let reopened = MeshLogStore::open(&path).expect("reopen");
    assert_eq!(reopened.len(), 1, "restart lost the entry");

    let state = reopened.project();
    let slot = state.slots.get(&slot_id).expect("slot present");
    assert!(matches!(slot.status, SlotProjectedStatus::Open));
    assert_eq!(slot.claw_id, "claw_persist");
}

#[test]
fn persistent_store_does_not_reopen_revoked_slot() {
    // The acceptance criterion that motivates this: "Engine deve
    // recuperar após restart sem reabrir invite consumido/revogado."
    let tmp = tempfile::NamedTempFile::new().expect("temp");
    let path = tmp.path().to_path_buf();
    std::fs::remove_file(&path).ok();

    let owner = P256Keypair::generate();
    let slot_id = SlotId::random();

    {
        let store = MeshLogStore::open(&path).expect("open");
        store
            .append(mint(
                &owner,
                1_000,
                MeshEvent::ClawShareSlotMinted {
                    slot_id: slot_id.clone(),
                    claw_id: "claw_r".to_string(),
                    expires_at: 5_000,
                    app_presentation: None,
                },
            ))
            .expect("mint");
        store
            .append(mint(
                &owner,
                1_100,
                MeshEvent::ClawShareSlotRevoked {
                    slot_id: slot_id.clone(),
                },
            ))
            .expect("revoke");
    }

    let reopened = MeshLogStore::open(&path).expect("reopen");
    let state = reopened.project();
    let slot = state
        .slots
        .get(&slot_id)
        .expect("slot present after reload");
    assert!(
        matches!(slot.status, SlotProjectedStatus::Revoked { .. }),
        "revoked slot must stay revoked across restart, got {:?}",
        slot.status,
    );
}

#[test]
fn persistent_store_does_not_reopen_consumed_slot() {
    let tmp = tempfile::NamedTempFile::new().expect("temp");
    let path = tmp.path().to_path_buf();
    std::fs::remove_file(&path).ok();

    let owner = P256Keypair::generate();
    let guest = P256Keypair::generate();
    let slot_id = SlotId::random();

    {
        let store = MeshLogStore::open(&path).expect("open");
        store
            .append(mint(
                &owner,
                1_000,
                MeshEvent::ClawShareSlotMinted {
                    slot_id: slot_id.clone(),
                    claw_id: "claw_c".to_string(),
                    expires_at: 5_000,
                    app_presentation: None,
                },
            ))
            .expect("mint");
        store
            .append(mint(
                &owner,
                1_500,
                MeshEvent::ClawShareSlotConsumed {
                    slot_id: slot_id.clone(),
                    guest_device_pub: guest.public(),
                    claw_id: "claw_c".to_string(),
                    expires_at: 5_000,
                    participant_npub: None,
                },
            ))
            .expect("consume");
    }

    let reopened = MeshLogStore::open(&path).expect("reopen");
    let state = reopened.project();
    let slot = state
        .slots
        .get(&slot_id)
        .expect("slot present after reload");
    assert!(
        matches!(slot.status, SlotProjectedStatus::Consumed { .. }),
        "consumed slot must stay consumed across restart, got {:?}",
        slot.status,
    );
}

#[test]
fn state_digest_matches_when_same_set_arrived_in_any_order() {
    let owner = P256Keypair::generate();
    let e1 = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let e2 = mint(
        &owner,
        2_000,
        MeshEvent::ClawShareSlotRevoked {
            slot_id: SlotId::random(),
        },
    );
    let store_a = MeshLogStore::new();
    store_a.append(e1.clone()).unwrap();
    store_a.append(e2.clone()).unwrap();
    let store_b = MeshLogStore::new();
    store_b.append(e2).unwrap();
    store_b.append(e1).unwrap();
    assert_eq!(
        store_a.state_digest(),
        store_b.state_digest(),
        "digest must be order-independent",
    );
}

#[test]
fn state_digest_differs_when_one_engine_misses_an_entry() {
    let owner = P256Keypair::generate();
    let e1 = mint(
        &owner,
        1_000,
        MeshEvent::ClawShareSlotMinted {
            slot_id: SlotId::random(),
            claw_id: "claw_a".to_string(),
            expires_at: 5_000,
            app_presentation: None,
        },
    );
    let store_a = MeshLogStore::new();
    store_a.append(e1.clone()).unwrap();
    let store_b = MeshLogStore::new();
    // store_b never sees e1
    assert_ne!(store_a.state_digest(), store_b.state_digest());
}

#[test]
fn foreign_contact_recorded_and_projected() {
    let owner = P256Keypair::generate();
    let alice = P256Keypair::generate();
    let slot_id = SlotId::random();
    let evt = mint(
        &owner,
        1_000,
        MeshEvent::ForeignContactRecorded {
            guest_device_pub: alice.public(),
            contact_id: "c_alice_local".to_string(),
            display_name: "Alice".to_string(),
            trust_origin_slot_id: slot_id.clone(),
        },
    );
    let state = ProjectedState::project(&[evt]);
    let contact = state
        .foreign_contacts
        .get(&alice.public().as_bytes().to_vec())
        .expect("contact present");
    assert_eq!(contact.contact_id, "c_alice_local");
    assert_eq!(contact.display_name, "Alice");
    assert_eq!(contact.trust_origin_slot_id, slot_id);
    assert!(matches!(contact.status, ForeignContactStatus::Active));
}

#[test]
fn foreign_contact_removed_marks_status() {
    let owner = P256Keypair::generate();
    let alice = P256Keypair::generate();
    let add = mint(
        &owner,
        1_000,
        MeshEvent::ForeignContactRecorded {
            guest_device_pub: alice.public(),
            contact_id: "c_a".to_string(),
            display_name: "Alice".to_string(),
            trust_origin_slot_id: SlotId::random(),
        },
    );
    let remove = mint(
        &owner,
        2_000,
        MeshEvent::ForeignContactRemoved {
            contact_id: "c_a".to_string(),
        },
    );
    let state = ProjectedState::project(&[add, remove]);
    let c = state
        .foreign_contacts
        .get(&alice.public().as_bytes().to_vec())
        .expect("contact present");
    assert!(matches!(c.status, ForeignContactStatus::Removed));
}

#[test]
fn directory_device_lifecycle() {
    let owner = P256Keypair::generate();
    let new_phone = P256Keypair::generate();
    let add = mint(
        &owner,
        1_000,
        MeshEvent::DirectoryDeviceAdded {
            device_pub: new_phone.public(),
            label: "Carlos iPhone 17".to_string(),
        },
    );
    let state = ProjectedState::project(&[add.clone()]);
    let dev = state
        .directory_devices
        .get(&new_phone.public().as_bytes().to_vec())
        .expect("device present");
    assert!(matches!(dev.status, DirectoryDeviceStatus::Active));
    assert_eq!(dev.label, "Carlos iPhone 17");

    let remove = mint(
        &owner,
        2_000,
        MeshEvent::DirectoryDeviceRemoved {
            device_pub: new_phone.public(),
        },
    );
    let state2 = ProjectedState::project(&[add, remove]);
    let dev2 = state2
        .directory_devices
        .get(&new_phone.public().as_bytes().to_vec())
        .expect("present");
    assert!(matches!(dev2.status, DirectoryDeviceStatus::Removed));
}

#[test]
fn emit_directory_device_removed_appends_verified_entry_and_projects_removed() {
    let issuer = P256Keypair::generate();
    let device = P256Keypair::generate();
    let store = MeshLogStore::new();

    let entry =
        emit_directory_device_removed(&store, &issuer, &issuer.public(), &device.public(), 1_000)
            .expect("emit");

    entry.verify().expect("entry verifies");
    assert_eq!(store.len(), 1);
    assert_eq!(entry.issuer_pub, issuer.public());
    assert!(matches!(
        entry.event,
        MeshEvent::DirectoryDeviceRemoved { ref device_pub }
            if *device_pub == device.public()
    ));

    let state = store.project();
    let projected = state
        .directory_devices
        .get(&device.public().as_bytes().to_vec())
        .expect("removed device projected");
    assert!(matches!(projected.status, DirectoryDeviceStatus::Removed));
}

#[test]
fn emit_directory_device_removed_is_remove_wins_when_reemitted() {
    let issuer = P256Keypair::generate();
    let device = P256Keypair::generate();
    let store = MeshLogStore::new();

    emit_directory_device_removed(&store, &issuer, &issuer.public(), &device.public(), 1_000)
        .expect("first removal");
    emit_directory_device_removed(&store, &issuer, &issuer.public(), &device.public(), 1_001)
        .expect("second removal");

    let state = store.project();
    let projected = state
        .directory_devices
        .get(&device.public().as_bytes().to_vec())
        .expect("removed device projected");
    assert!(matches!(projected.status, DirectoryDeviceStatus::Removed));
}

#[test]
fn emit_directory_device_removed_arms_machine_issuer_kill_switch() {
    let hh = P256Keypair::generate();
    let m = P256Keypair::generate();
    let cert = member_machine_cert(&hh, &m);
    let record = household_record_with_member(&hh, &m);
    let store = MeshLogStore::new();

    is_machine_issuer_active(&record, &cert, Some(&store.project()), &m.public(), true)
        .expect("member machine active before removal");

    emit_directory_device_removed(&store, &m, &m.public(), &m.public(), 1_000)
        .expect("emit removal");

    let err = is_machine_issuer_active(&record, &cert, Some(&store.project()), &m.public(), true)
        .expect_err("removed issuer must fail closed");
    assert!(matches!(err, MachineIssuerError::DeviceRemoved));
}

#[test]
fn emit_directory_device_removed_rejects_issuer_key_mismatch() {
    let issuer = P256Keypair::generate();
    let other_issuer = P256Keypair::generate();
    let device = P256Keypair::generate();
    let store = MeshLogStore::new();

    let err = emit_directory_device_removed(
        &store,
        &issuer,
        &other_issuer.public(),
        &device.public(),
        1_000,
    )
    .expect_err("issuer key mismatch must reject");

    assert!(matches!(err, MeshLogError::IssuerKeyMismatch));
    assert_eq!(store.len(), 0);
}

#[test]
fn revoked_guest_is_tracked() {
    let owner = P256Keypair::generate();
    let guest = P256Keypair::generate();
    let revoke = mint(
        &owner,
        1_000,
        MeshEvent::GuestRevoked {
            guest_device_pub: guest.public(),
            claw_id: "claw_x".to_string(),
        },
    );
    let state = ProjectedState::project(&[revoke]);
    assert!(
        state
            .revoked_guests
            .contains(&(guest.public().as_bytes().to_vec(), "claw_x".to_string()))
    );
}

// ─── R76: participant_npub keystone + share-derived roster ──────────────

/// R76-2: the SIGNED `participant_npub` on a consume flows into the
/// projected slot's `Consumed` status (the keystone the roster reads).
#[test]
fn consume_carries_participant_npub_into_projection() {
    let owner = P256Keypair::generate();
    let slot = SlotId::random();
    let log = MeshLogStore::new();
    log.append(
        build_slot_mint_event(
            slot.clone(),
            "claw_a".into(),
            5_000,
            1_000,
            owner.public(),
            &owner as &dyn IdentityKey,
        )
        .unwrap(),
    )
    .unwrap();
    log.append(
        build_slot_consume_event(
            slot.clone(),
            P256Keypair::generate().public(),
            "claw_a".into(),
            5_000,
            Some("npub_alice".into()),
            2_000,
            owner.public(),
            &owner as &dyn IdentityKey,
        )
        .unwrap(),
    )
    .unwrap();
    let st = log.project();
    match &st.slots[&slot].status {
        SlotProjectedStatus::Consumed {
            participant_npub, ..
        } => {
            assert_eq!(participant_npub.as_deref(), Some("npub_alice"));
        }
        other => panic!("expected Consumed, got {other:?}"),
    }
}

/// R76-2: a consume with `participant_npub: None` serialises WITHOUT the
/// field (skip_serializing_if) so canonical CBOR — and thus the owner
/// signature over the entry — stays byte-identical to a pre-mesh consume.
/// A `Some(..)` consume includes it and round-trips intact.
#[test]
fn consume_npub_is_skipped_when_none_for_backward_compat() {
    let none = MeshEvent::ClawShareSlotConsumed {
        slot_id: SlotId([1u8; 16]),
        guest_device_pub: P256Keypair::from_secret_scalar(&[2u8; 32])
            .unwrap()
            .public(),
        claw_id: "claw_a".into(),
        expires_at: 5_000,
        participant_npub: None,
    };
    let bytes_none = crate::cbor::to_canonical_vec(&none).unwrap();
    let needle = b"participant_npub";
    assert!(
        !bytes_none.windows(needle.len()).any(|w| w == needle),
        "None consume must NOT encode the participant_npub key (backward compat)",
    );
    let back: MeshEvent = crate::cbor::from_canonical_slice(&bytes_none).unwrap();
    assert_eq!(back, none);

    let some = MeshEvent::ClawShareSlotConsumed {
        slot_id: SlotId([1u8; 16]),
        guest_device_pub: P256Keypair::from_secret_scalar(&[2u8; 32])
            .unwrap()
            .public(),
        claw_id: "claw_a".into(),
        expires_at: 5_000,
        participant_npub: Some("npub_z".into()),
    };
    let bytes_some = crate::cbor::to_canonical_vec(&some).unwrap();
    assert!(
        bytes_some.windows(needle.len()).any(|w| w == needle),
        "Some consume must encode the participant_npub key",
    );
    let back_some: MeshEvent = crate::cbor::from_canonical_slice(&bytes_some).unwrap();
    assert_eq!(back_some, some);
}

// ─── R81-1: shares_for_guest (routing hygiene) ──────────────────────────

/// R81-1: `shares_for_guest` lists ONLY the guest's consumed, non-revoked,
/// non-expired slots; revoked/expired/other-guest/open slots are excluded.
#[test]
fn shares_for_guest_lists_only_active_nonrevoked() {
    let owner = P256Keypair::generate();
    let k = &owner as &dyn IdentityKey;
    let log = MeshLogStore::new();
    let exp = 10_000u64;
    let alice = P256Keypair::from_secret_scalar(&[0x11; 32])
        .unwrap()
        .public();
    let mallory = P256Keypair::from_secret_scalar(&[0x22; 32])
        .unwrap()
        .public();

    // Alice: one active share on claw_a.
    let s_active = SlotId::random();
    log.append(
        build_slot_mint_event(s_active.clone(), "claw_a".into(), exp, 1, owner.public(), k)
            .unwrap(),
    )
    .unwrap();
    log.append(
        build_slot_consume_event(
            s_active.clone(),
            alice.clone(),
            "claw_a".into(),
            exp,
            Some("npub_alice".into()),
            2,
            owner.public(),
            k,
        )
        .unwrap(),
    )
    .unwrap();
    // Alice: one revoked share on claw_b.
    let s_rev = SlotId::random();
    log.append(
        build_slot_mint_event(s_rev.clone(), "claw_b".into(), exp, 3, owner.public(), k).unwrap(),
    )
    .unwrap();
    log.append(
        build_slot_consume_event(
            s_rev.clone(),
            alice.clone(),
            "claw_b".into(),
            exp,
            Some("npub_alice".into()),
            4,
            owner.public(),
            k,
        )
        .unwrap(),
    )
    .unwrap();
    log.append(build_slot_revoke_event(s_rev, 5, owner.public(), k).unwrap())
        .unwrap();
    // Alice: one expired share on claw_c.
    let s_exp = SlotId::random();
    log.append(
        build_slot_mint_event(s_exp.clone(), "claw_c".into(), 50, 6, owner.public(), k).unwrap(),
    )
    .unwrap();
    log.append(
        build_slot_consume_event(
            s_exp,
            alice.clone(),
            "claw_c".into(),
            50,
            Some("npub_alice".into()),
            7,
            owner.public(),
            k,
        )
        .unwrap(),
    )
    .unwrap();
    // Mallory: an active share — must not leak into Alice's list.
    let s_other = SlotId::random();
    log.append(
        build_slot_mint_event(s_other.clone(), "claw_a".into(), exp, 8, owner.public(), k).unwrap(),
    )
    .unwrap();
    log.append(
        build_slot_consume_event(
            s_other,
            mallory,
            "claw_a".into(),
            exp,
            Some("npub_mallory".into()),
            9,
            owner.public(),
            k,
        )
        .unwrap(),
    )
    .unwrap();
    // An OPEN slot (minted, never consumed) — excluded.
    let s_open = SlotId::random();
    log.append(build_slot_mint_event(s_open, "claw_a".into(), exp, 10, owner.public(), k).unwrap())
        .unwrap();

    let now = 100u64; // past s_exp (50), before exp (10_000)
    let st = log.project();
    let shares = st.shares_for_guest(alice.as_bytes(), now);
    assert_eq!(
        shares.len(),
        1,
        "only the single active non-revoked share, got {shares:?}"
    );
    assert_eq!(shares[0].slot_id, s_active);
    assert_eq!(shares[0].claw_id, "claw_a");
    // Order-independence: a second projection of the same log yields equal.
    assert_eq!(
        log.project().shares_for_guest(alice.as_bytes(), now),
        shares
    );
}

// ── Slice B step 4A: durable app presentation snapshot ────────────────

use crate::claw_share::ClawShareSlotStore;
use crate::claw_share::relay_stream_contract::ShareableAppPresentation;

const APP_ID: &str = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Pinned canonical CBOR hex of a ClawShareSlotMinted EVENT (not LogEntry)
// extracted from the clean parent 82019f5b with slot [0x42;16],
// claw_id APP_ID, expires_at 1_700_000_000. A 4A event with
// app_presentation=None MUST produce byte-identical bytes.
const LEGACY_MINTED_EVENT_HEX: &str = "a4646b696e6476636c61775f73686172655f736c6f745f6d696e74656467636c61775f696478246170705f616161616161616161616161616161616161616161616161616161616161616167736c6f745f696450424242424242424242424242424242426a657870697265735f61741a6553f100";

fn test_presentation() -> ShareableAppPresentation {
    ShareableAppPresentation::try_new(APP_ID.to_string(), "Study", "Caio").unwrap()
}

#[test]
fn slot_minted_without_presentation_is_byte_identical_to_legacy() {
    // A 4A event with app_presentation=None must produce the EXACT same
    // canonical CBOR as a pre-4A event. This is the merge-gate: the
    // skip_serializing_if makes the key vanish from the wire.
    let event = MeshEvent::ClawShareSlotMinted {
        slot_id: SlotId([0x42; 16]),
        claw_id: APP_ID.to_string(),
        expires_at: 1_700_000_000,
        app_presentation: None,
    };
    let hex_actual = hex::encode(cbor::to_canonical_vec(&event).unwrap());
    assert_eq!(
        hex_actual, LEGACY_MINTED_EVENT_HEX,
        "a None-presentation event must be byte-identical to pre-4A"
    );
}

#[test]
fn slot_minted_with_presentation_round_trips() {
    let event = MeshEvent::ClawShareSlotMinted {
        slot_id: SlotId([0x42; 16]),
        claw_id: APP_ID.to_string(),
        expires_at: 1_700_000_000,
        app_presentation: Some(test_presentation()),
    };
    let bytes = cbor::to_canonical_vec(&event).unwrap();
    let decoded: MeshEvent = cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn projection_preserves_app_presentation_from_mint() {
    let entry = build_slot_mint_event_with_presentation(
        SlotId([0x42; 16]),
        APP_ID.to_string(),
        1_700_000_000,
        1_600_000_000,
        P256Keypair::from_secret_scalar(&[0x11; 32])
            .unwrap()
            .public(),
        &P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap(),
        Some(test_presentation()),
    )
    .unwrap();
    let state = ProjectedState::project(std::slice::from_ref(&entry));
    let slot = state.slots.get(&SlotId([0x42; 16])).unwrap();
    assert_eq!(slot.app_presentation.as_ref().unwrap().app_id, APP_ID);
}

#[test]
fn seeded_from_reidrates_app_presentation() {
    let keypair = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
    let entry = build_slot_mint_event_with_presentation(
        SlotId([0x42; 16]),
        APP_ID.to_string(),
        1_700_000_000,
        1_600_000_000,
        keypair.public(),
        &keypair,
        Some(test_presentation()),
    )
    .unwrap();
    let state = ProjectedState::project(std::slice::from_ref(&entry));
    let store = ClawShareSlotStore::seeded_from(&state);
    let record = store.get(&SlotId([0x42; 16])).unwrap();
    assert!(record.app_presentation.is_some());
    assert_eq!(
        record.app_presentation.as_ref().unwrap().display_name,
        "Study"
    );
}

#[test]
fn consume_does_not_overwrite_app_presentation() {
    let keypair = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
    let mint = build_slot_mint_event_with_presentation(
        SlotId([0x42; 16]),
        APP_ID.to_string(),
        1_700_000_000,
        1_600_000_000,
        keypair.public(),
        &keypair,
        Some(test_presentation()),
    )
    .unwrap();
    let consume = build_slot_consume_event(
        SlotId([0x42; 16]),
        P256Keypair::from_secret_scalar(&[0x33; 32])
            .unwrap()
            .public(),
        APP_ID.to_string(),
        1_700_000_000,
        None,
        1_600_000_001,
        keypair.public(),
        &keypair,
    )
    .unwrap();
    let state = ProjectedState::project(&[mint, consume]);
    let slot = state.slots.get(&SlotId([0x42; 16])).unwrap();
    assert_eq!(slot.app_presentation.as_ref().unwrap().app_id, APP_ID);
}

#[test]
fn legacy_slot_without_presentation_projects_none() {
    let keypair = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
    let entry = build_slot_mint_event(
        SlotId([0x42; 16]),
        APP_ID.to_string(),
        1_700_000_000,
        1_600_000_000,
        keypair.public(),
        &keypair,
    )
    .unwrap();
    let state = ProjectedState::project(std::slice::from_ref(&entry));
    let slot = state.slots.get(&SlotId([0x42; 16])).unwrap();
    assert!(slot.app_presentation.is_none());
}

#[test]
fn pre_4a_event_decodes_with_default_none() {
    // Decode the PINNED pre-4A hex literal — no app_presentation key on
    // the wire. serde default must hydrate it as None without error.
    let bytes = hex::decode(LEGACY_MINTED_EVENT_HEX).unwrap();
    let decoded: MeshEvent = cbor::from_canonical_slice(&bytes).unwrap();
    match decoded {
        MeshEvent::ClawShareSlotMinted {
            app_presentation, ..
        } => {
            assert!(app_presentation.is_none());
        }
        other => panic!("expected ClawShareSlotMinted, got {other:?}"),
    }
}
