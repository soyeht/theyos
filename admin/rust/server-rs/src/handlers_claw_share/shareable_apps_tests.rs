#![cfg(test)]

use super::*;
use household_rs::claw_share::{SlotRecord, SlotState};
use household_rs::keys::P256Keypair;
use household_rs::{PersonId, derive_household_id};
use store_rs::instance_db::{InstanceDb, InstanceStatus, NewInstance, StatusUpdate};

const HOUSEHOLD: &str = "hh_alpha";

fn instance<'a>(id: &'a str, name: &'a str, container: &'a str) -> NewInstance<'a> {
    NewInstance {
        id,
        name,
        container,
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some(HOUSEHOLD),
        household_machine_id: Some("m_alpha"),
    }
}

// ── Slice C2: Active Shares listing ──────────────────────────────────────

/// A projection holding exactly one slot, so each test states the whole
/// world it asserts on.
fn projection_with(slot: household_rs::household_mesh_log::ProjectedSlot) -> ProjectedState {
    let mut state = ProjectedState::default();
    state.slots.insert(slot.slot_id.clone(), slot);
    state
}

fn c2_slot(
    app_id: &DeviceShareAppId,
    snapshot_name: &str,
    status: SlotProjectedStatus,
    expires_at: u64,
    created_at: Option<u64>,
) -> household_rs::household_mesh_log::ProjectedSlot {
    household_rs::household_mesh_log::ProjectedSlot {
        slot_id: SlotId([0x77; 16]),
        claw_id: app_id.as_str().to_string(),
        expires_at,
        status,
        app_presentation: Some(
            ShareableAppPresentation::try_new(app_id.as_str().to_string(), snapshot_name, "Caio")
                .expect("valid snapshot"),
        ),
        created_at,
    }
}

fn set_instance_status(db: &InstanceDb, status: InstanceStatus) {
    db.update_status(&StatusUpdate {
        id: "inst-app",
        status,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .expect("update status");
}

fn active_shares(
    db: &InstanceDb,
    projection: &ProjectedState,
    now: u64,
) -> Vec<ActiveShareResponse> {
    list_active_shares_core(db, projection, HOUSEHOLD, now).expect("list")
}

#[test]
fn status_and_readiness_are_independent_axes() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    let guest = P256Keypair::generate().public();
    set_instance_status(&db, InstanceStatus::Stopped);

    // WAITING slot + STOPPED app on the same row.
    let rows = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Open,
            9_000,
            Some(1_000),
        )),
        5_000,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "waiting");
    assert_eq!(
        rows[0].readiness, "stopped",
        "readiness must come from the APP, not the slot"
    );
    assert_eq!(rows[0].created_at, 1_000);
    assert_eq!(rows[0].expires_at, 9_000);
    assert_eq!(rows[0].accepted_at, None);
    assert_eq!(rows[0].revoked_at, None);

    // ACCEPTED slot + UNAVAILABLE app on the same row: Active with no host
    // port resolves Unavailable, so the two axes disagree honestly.
    set_instance_status(&db, InstanceStatus::Active);
    let rows = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Consumed {
                guest_device_pub: guest,
                consumed_at: 2_000,
                participant_npub: None,
            },
            9_000,
            Some(1_000),
        )),
        5_000,
    );
    assert_eq!(rows[0].status, "accepted");
    assert_eq!(rows[0].readiness, "unavailable");
}

#[test]
fn status_priority_revoked_beats_expiry_and_accepted_survives_it() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    let guest = P256Keypair::generate().public();

    // Accepted, and ALREADY past expiry: it was accepted, and expiry does
    // not rewrite that.
    let accepted = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Consumed {
                guest_device_pub: guest.clone(),
                consumed_at: 2_000,
                participant_npub: None,
            },
            3_000,
            Some(1_000),
        )),
        9_999,
    );
    assert_eq!(accepted[0].status, "accepted");
    assert_eq!(accepted[0].accepted_at, Some(2_000));

    // Revoked wins over everything, and still reports when it was accepted.
    let revoked = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Revoked {
                revoked_at: 4_000,
                participant_npub: None,
                accepted_at: Some(2_000),
            },
            3_000,
            Some(1_000),
        )),
        9_999,
    );
    assert_eq!(revoked[0].status, "revoked");
    assert_eq!(revoked[0].revoked_at, Some(4_000));
    assert_eq!(revoked[0].accepted_at, Some(2_000));

    // Only a still-open slot expires.
    let expired = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Open,
            3_000,
            Some(1_000),
        )),
        9_999,
    );
    assert_eq!(expired[0].status, "expired");
}

#[test]
fn live_rename_shows_the_current_name_not_the_frozen_snapshot() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    db.rename_shareable_app(app_id.as_str(), HOUSEHOLD, "Renamed")
        .expect("rename");
    let projection = projection_with(c2_slot(
        &app_id,
        "OldSnapshotName",
        SlotProjectedStatus::Open,
        9_000,
        Some(1_000),
    ));

    // BOTH resolution arms must report the CURRENT name, and they are
    // independent code paths — a regression in either alone must fail.
    // The snapshot name is deliberately distinct from the live one, or
    // reading the snapshot would be indistinguishable from resolving.
    //
    // Arm 1, Unavailable: Active with no host port.
    set_instance_status(&db, InstanceStatus::Active);
    let rows = active_shares(&db, &projection, 5_000);
    assert_eq!(rows[0].display_name, "Renamed");
    assert_eq!(rows[0].readiness, "unavailable");

    // Arm 2, Ready: same app, now with a port.
    db.update_port("inst-app", 8080).expect("port");
    let rows = active_shares(&db, &projection, 5_000);
    assert_eq!(
        rows[0].display_name, "Renamed",
        "the list must resolve the CURRENT name, not read the snapshot"
    );
    assert_eq!(rows[0].readiness, "running");
    // A rename touches ONLY the name: status and created_at are untouched...
    assert_eq!(rows[0].status, "waiting");
    assert_eq!(rows[0].created_at, 1_000);
    // ...and the signed snapshot itself stays frozen. Without this the test
    // cannot tell "resolved the current name" from "read the snapshot".
    let slot = projection.slots.values().next().expect("one slot");
    assert_eq!(
        slot.app_presentation.as_ref().unwrap().display_name,
        "OldSnapshotName",
        "the signed snapshot must never be rewritten by a rename"
    );
}

#[test]
fn a_terminal_app_keeps_its_row_with_the_snapshot_name() {
    let db = db_with_instance();
    // An app_id the store does not know: resolution is Terminal, which is
    // detail-free by design (unknown, retired, foreign and deleted are
    // deliberately indistinguishable), so it carries no current name.
    let gone = DeviceShareAppId::try_from(format!("app_{:032x}", 0xdead_u128).as_str())
        .expect("valid shape");

    let rows = active_shares(
        &db,
        &projection_with(c2_slot(
            &gone,
            "FrozenName",
            SlotProjectedStatus::Open,
            9_000,
            Some(1_000),
        )),
        5_000,
    );
    assert_eq!(rows.len(), 1, "a dead app must not erase the owner's row");
    assert_eq!(rows[0].display_name, "FrozenName");
    assert_eq!(rows[0].readiness, "unavailable");
}

#[test]
fn slots_without_a_snapshot_or_without_created_at_are_omitted() {
    let db = db_with_instance();
    let app_id = device_id(&db);

    // Group/Public slot: no snapshot, so not an Active Share.
    let mut legacy = c2_slot(
        &app_id,
        "Study",
        SlotProjectedStatus::Open,
        9_000,
        Some(1_000),
    );
    legacy.app_presentation = None;
    assert!(active_shares(&db, &projection_with(legacy), 5_000).is_empty());

    // Presentation-backed but no created_at: corrupt, omitted, never
    // given an invented timestamp.
    let corrupt = c2_slot(&app_id, "Study", SlotProjectedStatus::Open, 9_000, None);
    assert!(active_shares(&db, &projection_with(corrupt), 5_000).is_empty());
}

#[test]
fn a_snapshot_naming_another_app_is_omitted_not_resolved() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    db.rename_shareable_app(app_id.as_str(), HOUSEHOLD, "RealApp")
        .expect("rename");

    // A well-formed snapshot for the REAL app, but the slot's claw_id says
    // a different one — the shape check alone would let this through and we
    // would list the real app under a foreign slot's identity.
    let mut forged = c2_slot(
        &app_id,
        "Study",
        SlotProjectedStatus::Open,
        9_000,
        Some(1_000),
    );
    forged.claw_id = format!("app_{:032x}", 0xbeef_u128);

    assert!(
        active_shares(&db, &projection_with(forged), 5_000).is_empty(),
        "a snapshot that does not describe THIS slot's claw must be omitted"
    );
}

#[test]
fn the_wire_row_carries_no_bearer_material() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    let guest = P256Keypair::generate().public();
    let rows = active_shares(
        &db,
        &projection_with(c2_slot(
            &app_id,
            "Study",
            SlotProjectedStatus::Consumed {
                guest_device_pub: guest.clone(),
                consumed_at: 2_000,
                participant_npub: Some("npub_alice".to_string()),
            },
            9_000,
            Some(1_000),
        )),
        5_000,
    );
    let encoded =
        cbor::to_canonical_vec(&ListActiveSharesResponse { v: 1, shares: rows }).expect("encode");

    // The guest key and the bound npub are in the projection this row was
    // built from; neither may reach the wire, and there is no invite/URI.
    let guest_bytes = guest.as_bytes();
    assert!(
        !encoded
            .windows(guest_bytes.len())
            .any(|w| w == guest_bytes.as_slice()),
        "guest device key must never reach the Active Shares wire"
    );
    for forbidden in [b"npub_alice".as_slice(), b"claw-share/invite".as_slice()] {
        assert!(
            !encoded.windows(forbidden.len()).any(|w| w == forbidden),
            "no bearer/participant material on the wire"
        );
    }
}

fn db_with_instance() -> InstanceDb {
    let db = InstanceDb::open(":memory:").expect("open in-memory instance db");
    db.insert(&instance("inst-app", "study", "picoclaw-study"))
        .expect("insert instance");
    db
}

fn device_id(db: &InstanceDb) -> DeviceShareAppId {
    let binding = db
        .ensure_shareable_app("inst-app", HOUSEHOLD)
        .expect("ensure binding");
    DeviceShareAppId::try_from(binding.app_id.as_str()).expect("valid app id")
}

#[test]
fn mint_target_requires_exactly_one_typed_namespace() {
    assert_eq!(
        select_mint_target(None, None),
        Err(MintTargetError::NonePresent)
    );
    assert_eq!(
        select_mint_target(Some("legacy".into()), Some(format!("app_{:032x}", 1))),
        Err(MintTargetError::BothPresent)
    );
    assert_eq!(
        select_mint_target(Some("   ".into()), None),
        Err(MintTargetError::ClawIdMalformed)
    );
    assert_eq!(
        select_mint_target(None, Some("inst-study".into())),
        Err(MintTargetError::AppIdMalformed)
    );
    assert!(matches!(
        select_mint_target(Some("legacy".into()), None),
        Ok(MintTargetChoice::Legacy(id)) if id == "legacy"
    ));
    assert!(matches!(
        select_mint_target(None, Some(format!("app_{:032x}", 1))),
        Ok(MintTargetChoice::Device(_))
    ));
}

#[test]
fn list_ensures_once_and_preserves_independent_renames() {
    let db = InstanceDb::open(":memory:").expect("open in-memory instance db");
    db.insert(&instance("inst-one", "one", "picoclaw-one"))
        .unwrap();
    db.insert(&instance("inst-two", "two", "picoclaw-two"))
        .unwrap();

    let first = list_shareable_apps_core(&db, HOUSEHOLD).unwrap();
    assert_eq!(first.len(), 2);
    assert_ne!(first[0].app_id, first[1].app_id);
    for app in &first {
        let app_id = DeviceShareAppId::try_from(app.app_id.as_str()).unwrap();
        rename_shareable_app_core(&db, &app_id, HOUSEHOLD, "Study").unwrap();
    }

    let second = list_shareable_apps_core(&db, HOUSEHOLD).unwrap();
    assert_eq!(second.len(), 2);
    assert!(second.iter().all(|app| app.display_name == "Study"));
    assert_eq!(
        first
            .iter()
            .map(|app| &app.app_id)
            .collect::<std::collections::BTreeSet<_>>(),
        second
            .iter()
            .map(|app| &app.app_id)
            .collect::<std::collections::BTreeSet<_>>(),
        "list read-through must not remint or resync renamed bindings",
    );
    assert!(second.iter().all(|app| app.resource == "clawsite"));
}

#[test]
fn rename_is_household_scoped_and_fail_closed() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    assert!(matches!(
        rename_shareable_app_core(&db, &app_id, "hh_foreign", "Nope"),
        Err(store_rs::StoreError::InstanceNotFound)
    ));
    rename_shareable_app_core(&db, &app_id, HOUSEHOLD, "Current Name").unwrap();
    let listed = list_shareable_apps_core(&db, HOUSEHOLD).unwrap();
    assert_eq!(listed[0].display_name, "Current Name");
}

#[test]
fn stopped_app_mints_the_signed_snapshot_from_binding_and_person_cert() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    rename_shareable_app_core(&db, &app_id, HOUSEHOLD, "Study App").unwrap();
    db.update_status(&StatusUpdate {
        id: "inst-app",
        status: InstanceStatus::Stopped,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();

    let (claw_id, presentation) = resolve_mint_app_core(&db, &app_id, HOUSEHOLD, "Caio").unwrap();
    assert_eq!(claw_id, app_id.as_str());
    assert_eq!(presentation.app_id, app_id.as_str());
    assert_eq!(presentation.display_name, "Study App");
    assert_eq!(presentation.owner_display_name, "Caio");
}

#[test]
fn retired_or_foreign_binding_is_terminal_and_never_reensured() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    assert!(matches!(
        resolve_mint_app_core(&db, &app_id, "hh_foreign", "Caio"),
        Err(MintAppCoreError::Terminal)
    ));

    db.soft_delete("inst-app").unwrap();
    assert!(matches!(
        resolve_mint_app_core(&db, &app_id, HOUSEHOLD, "Caio"),
        Err(MintAppCoreError::Terminal)
    ));
    assert!(matches!(
        db.ensure_shareable_app("inst-app", HOUSEHOLD),
        Err(store_rs::StoreError::InstanceNotFound)
    ));
}

#[test]
fn invalid_owner_presentation_is_an_error_not_a_panic() {
    let db = db_with_instance();
    let app_id = device_id(&db);
    assert!(matches!(
        resolve_mint_app_core(&db, &app_id, HOUSEHOLD, &"x".repeat(129)),
        Err(MintAppCoreError::InvalidPresentation)
    ));
}

#[test]
fn mint_event_carries_the_exact_optional_snapshot() {
    let (store, invite) = invite_and_slot();
    let presentation =
        ShareableAppPresentation::try_new(format!("app_{:032x}", 7), "Study", "Caio").unwrap();
    let event = mint_event_for_invite(&invite, Some(presentation.clone()));
    match event {
        MeshEvent::ClawShareSlotMinted {
            slot_id,
            claw_id,
            app_presentation,
            ..
        } => {
            assert_eq!(slot_id, invite.slot_id);
            assert_eq!(claw_id, invite.claw_id);
            assert_eq!(app_presentation, Some(presentation));
        }
        _ => panic!("mint helper must build ClawShareSlotMinted"),
    }
    assert!(matches!(
        store.get(&invite.slot_id).unwrap().state,
        SlotState::Open
    ));
}

#[test]
fn append_failure_revokes_the_inserted_slot() {
    let (store, invite) = invite_and_slot();
    let event = mint_event_for_invite(&invite, None);
    assert_eq!(
        finalize_mint_with_append(&store, &invite, event, |_| Err(()), 1_800_000_001),
        Err(FinalizeError::AppendFailed)
    );
    assert!(matches!(
        store.get(&invite.slot_id).unwrap().state,
        SlotState::Revoked {
            revoked_at: 1_800_000_001,
            accepted_at: None
        }
    ));
}

/// The end-to-end idempotence property: revoking twice must leave ONE
/// durable event, because the handler re-signs with the canonical timestamp
/// and `entry_id` digests (timestamp, event, issuer) — not the signature.
/// A fresh `now` on the second call must not produce a second entry.
#[test]
fn revoking_twice_appends_exactly_one_log_entry() {
    let (store, invite) = invite_and_slot();
    let owner = P256Keypair::from_secret_scalar(&[0x31; 32]).unwrap();
    let log = MeshLogStore::new();

    // Drives the SAME core the handler calls. Re-implementing the
    // build+append here would let a handler that signs with `now` pass.
    for now in [1_800_000_001_u64, 1_900_000_999] {
        revoke_slot_core(&store, &log, &owner, &invite.slot_id, now)
            .expect("both revocations must succeed");
    }

    assert_eq!(
        log.snapshot()
            .iter()
            .filter(|e| matches!(e.event, MeshEvent::ClawShareSlotRevoked { .. }))
            .count(),
        1,
        "a second revoke must not add a second durable revocation"
    );
    assert!(matches!(
        store.get(&invite.slot_id).unwrap().state,
        SlotState::Revoked {
            revoked_at: 1_800_000_001,
            accepted_at: None
        }
    ));
}

/// Retry after a FAILED append must still persist — and with the original
/// timestamp, so the entry is the one the first attempt would have written.
#[test]
fn retry_after_a_failed_append_persists_with_the_original_timestamp() {
    let (store, invite) = invite_and_slot();
    let owner = P256Keypair::from_secret_scalar(&[0x31; 32]).unwrap();
    let log = MeshLogStore::new();

    // A CONSUMED slot, so the seam closes `accepted_at` as well as the
    // timestamp: a rollback that restored the previous state, or an error
    // arm that cleared the acceptance, both become visible.
    let guest = P256Keypair::generate();
    store
        .consume_atomic(
            &invite.slot_id,
            &invite.claw_id,
            guest.public(),
            1_750_000_000,
        )
        .expect("slot accepted before revoke");

    // FIRST attempt: the append genuinely fails at the seam the production
    // core uses. Skipping the call instead would not distinguish "kept the
    // revoke and reported failure" from "rolled the slot back".
    let mut seen_timestamp = None;
    let failed = revoke_slot_with_append(
        &store,
        &invite.slot_id,
        1_800_000_001,
        |revoked_at, _event| {
            seen_timestamp = Some(revoked_at);
            Err(ClawShareError::SlotNotFound)
        },
    );
    assert!(matches!(failed, Err(RevokeCoreError::LogPersistFailed(_))));
    assert_eq!(seen_timestamp, Some(1_800_000_001));
    assert!(log.snapshot().is_empty(), "nothing may have persisted");
    // The revoke MUST stand, at the canonical timestamp AND still carrying
    // the acceptance. A rollback to the previous state, or an error arm
    // that cleared `accepted_at`, breaks this.
    let expected = SlotState::Revoked {
        revoked_at: 1_800_000_001,
        accepted_at: Some(1_750_000_000),
    };
    assert_eq!(store.get(&invite.slot_id).unwrap().state, expected);

    // RETRY through the real production core, on a LATER clock: it must
    // persist, and carry the ORIGINAL timestamp rather than the retry's.
    revoke_slot_core(&store, &log, &owner, &invite.slot_id, 1_900_000_999)
        .expect("the retry must persist");
    assert_eq!(log.snapshot().len(), 1);
    assert_eq!(log.snapshot()[0].timestamp, 1_800_000_001);
    // ...and both halves are unchanged after the successful retry.
    assert_eq!(store.get(&invite.slot_id).unwrap().state, expected);
}

fn invite_and_slot() -> (ClawShareSlotStore, ClawShareInvite) {
    let owner = P256Keypair::from_secret_scalar(&[0x31; 32]).unwrap();
    let household_id = derive_household_id(&owner.public());
    let slot_id = SlotId::random();
    let invite = ClawShareInvite::sign(
        household_id,
        PersonId(format!("p_{}", "a".repeat(52))),
        owner.public(),
        "legacy".into(),
        slot_id.clone(),
        TunnelHandle::Loopback {
            channel: "test".into(),
        },
        1_800_000_900,
        "relay-npub".into(),
        vec!["wss://relay.invalid".into()],
        &owner,
    )
    .unwrap();
    let store = ClawShareSlotStore::new();
    store
        .insert(SlotRecord {
            slot_id,
            claw_id: invite.claw_id.clone(),
            expires_at: invite.expires_at,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .unwrap();
    (store, invite)
}
