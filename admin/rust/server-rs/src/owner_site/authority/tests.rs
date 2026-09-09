#![cfg(test)]

use super::*;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::SignOptions;
use household_rs::{Platform, derive_household_id};

fn resource() -> OwnerSiteResource {
    OwnerSiteResource::from_route_claw("picoclaw").expect("resource")
}

fn roster_scope() -> OwnerSiteRosterScope {
    OwnerSiteRosterScope::injected_for_harness("household-alpha", "owner-site-mesh")
        .expect("roster scope")
}

fn generation(epoch: u64, fill: u8) -> OwnerSiteAuthorityGeneration {
    OwnerSiteAuthorityGeneration::injected_for_harness(epoch, [fill; 32])
        .expect("nonzero generation")
}

fn signed_member_device(npub: &str) -> MemberDeviceBinding {
    let member = P256Keypair::generate();
    let device = P256Keypair::generate();
    MemberDeviceBinding::sign(&member, device.public(), npub.to_string(), 1_000)
        .expect("signed member-device binding")
}

fn pending_finished_fixture() -> (PendingFinished, AuthenticatedConfidentialChannel) {
    let household_root = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let household = derive_household_id(&household_root.public());
    let machine_cert = MachineCert::sign(
        &household_root,
        &machine.public(),
        &SignOptions {
            hh_id: household.clone(),
            hostname: "pending-secret-host".to_owned(),
            platform: Platform::Macos,
            joined_at: 1_000,
        },
    )
    .expect("machine certificate");
    let device_binding = signed_member_device("npub1pendingsecret");
    let principal_d = OwnerSiteRemotePrincipal::injected_for_harness("npub1pendingsecret")
        .expect("remote principal");
    let exact_resource =
        OwnerSiteResource::from_route_claw("pending-secret-claw").expect("resource");
    let exact_route =
        crate::owner_site::capability::OwnerSiteCanonicalRequest::injected_for_harness(
            crate::owner_site::capability::OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x31; 32],
        )
        .expect("canonical route");
    let ws_instance = OwnerSiteWebSocketInstance::injected_for_harness([0x21; 32]);
    let channel_id = OwnerSiteChannelId::injected_for_harness([0x22; 32]);
    let channel_epoch = OwnerSiteChannelEpoch::injected_for_harness(7).expect("channel epoch");
    let channel_binding = [0x23; 32];
    let channel = AuthenticatedConfidentialChannel::injected_for_harness(
        ws_instance,
        channel_id,
        channel_epoch,
        channel_binding,
    );
    let pending = PendingFinished::injected_for_harness(
        household,
        exact_resource,
        exact_route,
        machine_cert,
        device_binding,
        principal_d,
        ws_instance,
        channel_id,
        channel_epoch,
        channel_binding,
        9,
        [0x24; 32],
        1_060,
        11,
        13,
    )
    .expect("synthetic pending state");
    (pending, channel)
}

#[test]
fn pending_finished_debug_is_redacted_and_does_not_leak_tuple_material() {
    let (pending, channel) = pending_finished_fixture();
    let pending_debug = format!("{pending:?}");
    let channel_debug = format!("{channel:?}");

    assert_eq!(pending_debug, "PendingFinished(REDACTED)");
    assert_eq!(channel_debug, "AuthenticatedConfidentialChannel(REDACTED)");
    for secret in [
        "pending-secret-host",
        "npub1pendingsecret",
        "pending-secret-claw",
        "/api/v1/household/claws",
    ] {
        assert!(!pending_debug.contains(secret));
        assert!(!channel_debug.contains(secret));
    }
}

#[test]
fn generation_comparison_is_pure_and_distinguishes_every_fence() {
    let (pending, _channel) = pending_finished_fixture();
    let expected = pending.generation_vector();
    assert_eq!(
        compare_owner_site_generations(expected, expected),
        OwnerSiteGenerationComparison::Exact
    );

    let authority_changed = OwnerSiteGenerationVector {
        roster_digest: [0x99; 32],
        ..expected
    };
    assert_eq!(
        compare_owner_site_generations(expected, authority_changed),
        OwnerSiteGenerationComparison::AuthorityChanged
    );
    let provider_changed = OwnerSiteGenerationVector {
        provider_generation: expected.provider_generation + 1,
        ..expected
    };
    assert_eq!(
        compare_owner_site_generations(expected, provider_changed),
        OwnerSiteGenerationComparison::ProviderChanged
    );
    let cancellation_changed = OwnerSiteGenerationVector {
        cancellation_generation: expected.cancellation_generation + 1,
        ..expected
    };
    assert_eq!(
        compare_owner_site_generations(expected, cancellation_changed),
        OwnerSiteGenerationComparison::CancellationChanged
    );
}

#[test]
fn pending_can_only_close_and_promotion_is_unreachable_in_this_slice() {
    assert!(owner_site_transition_is_allowed(
        OwnerSiteStateKind::Pending,
        OwnerSiteStateKind::Closing
    ));
    assert!(owner_site_transition_is_allowed(
        OwnerSiteStateKind::Closing,
        OwnerSiteStateKind::Closed
    ));
    assert!(owner_site_transition_is_allowed(
        OwnerSiteStateKind::Closed,
        OwnerSiteStateKind::Closed
    ));
    assert!(!owner_site_transition_is_allowed(
        OwnerSiteStateKind::Pending,
        OwnerSiteStateKind::Promoted
    ));
    assert!(!owner_site_transition_is_allowed(
        OwnerSiteStateKind::Pending,
        OwnerSiteStateKind::Dialing
    ));
    assert!(!owner_site_transition_is_allowed(
        OwnerSiteStateKind::Pending,
        OwnerSiteStateKind::Pumping
    ));

    // Merely naming the future carrier states proves their types compile;
    // no value or construction path for any of them exists in this slice.
    let future_state_types = [
        std::any::type_name::<Promoted>(),
        std::any::type_name::<Dialing>(),
        std::any::type_name::<Pumping>(),
        std::any::type_name::<Revoking>(),
    ];
    assert!(future_state_types.iter().all(|name| !name.is_empty()));

    let (mismatched_pending, _channel) = pending_finished_fixture();
    let mismatched_channel = AuthenticatedConfidentialChannel::injected_for_harness(
        mismatched_pending.ws_instance,
        OwnerSiteChannelId::injected_for_harness([0xff; 32]),
        mismatched_pending.channel_epoch,
        mismatched_pending.channel_binding,
    );
    assert!(matches!(
        Pending::injected_for_harness(mismatched_pending, mismatched_channel),
        Err(OwnerSiteAuthorityError::ChannelProofMismatch)
    ));

    let (pending_finished, channel) = pending_finished_fixture();
    let pending =
        Pending::injected_for_harness(pending_finished, channel).expect("matching channel proof");
    let closed = pending.begin_closing().finish();
    let _still_closed = closed.close();
}

fn binding(id_fill: u8, enrolled_at: OwnerSiteAuthorityGeneration) -> OwnerSiteRosterBinding {
    let channel_auth = P256Keypair::generate();
    let action_pop = P256Keypair::generate();
    OwnerSiteRosterBinding::injected_for_harness(
        OwnerSiteBindingId::injected_for_harness([id_fill; 32]).expect("binding id"),
        OwnerSiteBindingDigest::injected_for_harness([id_fill.wrapping_add(0x40); 32])
            .expect("binding digest"),
        roster_scope(),
        signed_member_device("npub1owneralpha"),
        OwnerSiteMembershipRole::Owner,
        resource(),
        OwnerSiteChannelAuthKey::injected_for_harness("channel-auth-alpha", channel_auth.public())
            .expect("channel auth key"),
        OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
            .expect("action pop key"),
        enrolled_at,
    )
    .expect("roster binding")
}

fn snapshot(
    generation: OwnerSiteAuthorityGeneration,
    bindings: Vec<OwnerSiteRosterBinding>,
    tombstones: Vec<OwnerSiteRevocationTombstone>,
) -> OwnerSiteRosterSnapshot {
    OwnerSiteRosterSnapshot::injected_for_harness(
        roster_scope(),
        generation,
        bindings,
        tombstones,
        1_000,
        1_060,
        "owner-key-alpha",
        vec![0xa5; 64],
    )
    .expect("roster snapshot")
}

#[test]
fn member_device_binding_must_verify_before_it_enters_owner_site_roster_shape() {
    let generation = generation(1, 0x11);
    let mut forged = signed_member_device("npub1owneralpha");
    forged.participant_npub = "npub1forged".to_string();

    assert_eq!(
        OwnerSiteRosterBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([0x01; 32]).expect("binding id"),
            OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).expect("binding digest"),
            roster_scope(),
            forged,
            OwnerSiteMembershipRole::Owner,
            resource(),
            OwnerSiteChannelAuthKey::injected_for_harness(
                "channel-auth-alpha",
                P256Keypair::generate().public(),
            )
            .expect("channel auth key"),
            OwnerSiteActionPopKey::injected_for_harness(
                "action-pop-alpha",
                P256Keypair::generate().public(),
            )
            .expect("action pop key"),
            generation,
        ),
        Err(OwnerSiteAuthorityError::MemberDeviceBindingRejected)
    );
}

#[test]
fn channel_auth_and_action_pop_may_share_one_key() {
    // RATIFIED 2026-08-01: one session key may serve both roles. The
    // separation lives in the transcript preimage (DeviceAuthHash vs
    // OwnerActionHash differ from byte 0), not in the keys — see the
    // substitution RED in glue_constructor_tests.
    let generation = generation(1, 0x12);
    let same_key = P256Keypair::generate();
    assert!(
        OwnerSiteRosterBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([0x02; 32]).expect("binding id"),
            OwnerSiteBindingDigest::injected_for_harness([0x52; 32]).expect("binding digest"),
            roster_scope(),
            signed_member_device("npub1owneralpha"),
            OwnerSiteMembershipRole::Owner,
            resource(),
            OwnerSiteChannelAuthKey::injected_for_harness("channel-auth-alpha", same_key.public(),)
                .expect("channel auth key"),
            OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", same_key.public(),)
                .expect("action pop key"),
            generation,
        )
        .is_ok(),
        "one key must be accepted in both roles after the ratification"
    );
}

#[test]
fn exact_roster_resolution_requires_binding_digest_npub_and_both_key_ids() {
    let generation = generation(1, 0x14);
    let member = P256Keypair::generate();
    let device = P256Keypair::generate();
    let member_device = MemberDeviceBinding::sign(
        &member,
        device.public(),
        "npub1owneralpha".to_string(),
        1_000,
    )
    .expect("member-device binding");
    let actor_id = member_device.member_id.clone();
    let channel_auth = P256Keypair::generate();
    let action_pop = P256Keypair::generate();
    let channel_auth =
        OwnerSiteChannelAuthKey::injected_for_harness("channel-auth-alpha", channel_auth.public())
            .expect("channel auth key");
    let action_pop =
        OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
            .expect("action pop key");
    let expected_channel_auth = channel_auth.key_id.clone();
    let expected_action_pop = action_pop.key_id.clone();
    let expected_channel_auth_public = channel_auth.public_key.clone();
    let expected_action_pop_public = action_pop.public_key.clone();
    let binding_id = OwnerSiteBindingId::injected_for_harness([0x04; 32]).expect("binding id");
    let binding_digest =
        OwnerSiteBindingDigest::injected_for_harness([0x54; 32]).expect("binding digest");
    let binding = OwnerSiteRosterBinding::injected_for_harness(
        binding_id,
        binding_digest,
        roster_scope(),
        member_device,
        OwnerSiteMembershipRole::Owner,
        resource(),
        channel_auth,
        action_pop,
        generation,
    )
    .expect("owner binding");
    let roster = snapshot(generation, vec![binding], Vec::new());
    let intent = OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource())
        .expect("intent");
    let principal =
        OwnerSiteRemotePrincipal::injected_for_harness("npub1owneralpha").expect("principal");

    let resolved = roster
        .resolve_exact(
            &intent,
            &principal,
            binding_id,
            binding_digest,
            &expected_channel_auth,
            &expected_action_pop,
        )
        .expect("exact roster resolution");
    assert_eq!(
        resolved.channel_auth_key().verifying_key(),
        &expected_channel_auth_public
    );
    assert_eq!(
        resolved.action_pop_key().verifying_key(),
        &expected_action_pop_public
    );
    let wrong_digest =
        OwnerSiteBindingDigest::injected_for_harness([0x55; 32]).expect("wrong digest");
    assert!(
        roster
            .resolve_exact(
                &intent,
                &principal,
                binding_id,
                wrong_digest,
                &expected_channel_auth,
                &expected_action_pop,
            )
            .is_none()
    );
    let wrong_principal =
        OwnerSiteRemotePrincipal::injected_for_harness("npub1otherowner").expect("principal");
    assert!(
        roster
            .resolve_exact(
                &intent,
                &wrong_principal,
                binding_id,
                binding_digest,
                &expected_channel_auth,
                &expected_action_pop,
            )
            .is_none()
    );
    let wrong_channel =
        OwnerSiteChannelAuthKeyId::injected_for_harness("other-channel").expect("wrong channel id");
    assert!(
        roster
            .resolve_exact(
                &intent,
                &principal,
                binding_id,
                binding_digest,
                &wrong_channel,
                &expected_action_pop,
            )
            .is_none()
    );
    let wrong_action =
        OwnerSiteActionPopKeyId::injected_for_harness("other-action").expect("wrong action id");
    assert!(
        roster
            .resolve_exact(
                &intent,
                &principal,
                binding_id,
                binding_digest,
                &expected_channel_auth,
                &wrong_action,
            )
            .is_none()
    );
}

#[test]
fn member_role_does_not_resolve_an_owner_site_intent() {
    let generation = generation(1, 0x13);
    let member = P256Keypair::generate();
    let device = P256Keypair::generate();
    let member_device = MemberDeviceBinding::sign(
        &member,
        device.public(),
        "npub1memberalpha".to_string(),
        1_000,
    )
    .expect("member-device binding");
    let actor_id = member_device.member_id.clone();
    let channel_auth = P256Keypair::generate();
    let action_pop = P256Keypair::generate();
    let binding = OwnerSiteRosterBinding::injected_for_harness(
        OwnerSiteBindingId::injected_for_harness([0x03; 32]).expect("binding id"),
        OwnerSiteBindingDigest::injected_for_harness([0x53; 32]).expect("binding digest"),
        roster_scope(),
        member_device,
        OwnerSiteMembershipRole::Member,
        resource(),
        OwnerSiteChannelAuthKey::injected_for_harness("channel-auth-alpha", channel_auth.public())
            .expect("channel auth key"),
        OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
            .expect("action pop key"),
        generation,
    )
    .expect("member binding shape");
    let intent = OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource())
        .expect("owner-site intent");
    let principal =
        OwnerSiteRemotePrincipal::injected_for_harness("npub1memberalpha").expect("principal");

    assert!(binding.resolves(&intent, &principal).is_none());
}

#[test]
fn zero_generation_and_rollback_are_rejected() {
    assert_eq!(
        OwnerSiteAuthorityGeneration::injected_for_harness(0, [0x00; 32]),
        Err(OwnerSiteAuthorityError::ZeroGeneration)
    );

    let current_generation = generation(2, 0x22);
    let current = snapshot(
        current_generation,
        vec![binding(0x02, current_generation)],
        vec![],
    );
    assert_eq!(current.generation(), current_generation);
    let replay_generation = generation(2, 0x23);
    let replay = snapshot(
        replay_generation,
        vec![binding(0x03, replay_generation)],
        vec![],
    );
    assert_eq!(
        replay.is_strict_successor_of(&current),
        Err(OwnerSiteAuthorityError::GenerationDigestConflict)
    );
    let lower_generation = generation(1, 0x24);
    let lower = snapshot(
        lower_generation,
        vec![binding(0x04, lower_generation)],
        vec![],
    );
    assert_eq!(
        lower.is_strict_successor_of(&current),
        Err(OwnerSiteAuthorityError::NonMonotonicGeneration)
    );
}

#[test]
fn nested_generations_reject_same_epoch_with_a_different_digest() {
    let snapshot_generation = generation(7, 0xa1);
    let conflicting_generation = generation(7, 0xb1);

    assert_eq!(
        OwnerSiteRosterSnapshot::injected_for_harness(
            roster_scope(),
            snapshot_generation,
            vec![binding(0x21, conflicting_generation)],
            Vec::new(),
            1_000,
            1_060,
            "owner-key-alpha",
            vec![0xa5; 64],
        ),
        Err(OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch),
        "a conflicting same-epoch binding must never become active"
    );

    let revoked_binding = binding(0x22, generation(6, 0xa2));
    let conflicting_tombstone = OwnerSiteRevocationTombstone::injected_for_harness(
        revoked_binding.binding_id(),
        conflicting_generation,
    );
    assert_eq!(
        OwnerSiteRosterSnapshot::injected_for_harness(
            roster_scope(),
            snapshot_generation,
            Vec::new(),
            vec![conflicting_tombstone],
            1_000,
            1_060,
            "owner-key-alpha",
            vec![0xa5; 64],
        ),
        Err(OwnerSiteAuthorityError::TombstoneAfterSnapshot),
        "a conflicting same-epoch tombstone must never be accepted"
    );
}

#[test]
fn tombstone_wins_and_reenrollment_needs_a_new_binding_at_a_later_epoch() {
    let enrolled = generation(1, 0x31);
    let active = binding(0x01, enrolled);
    let revoked = generation(2, 0x32);
    let tombstone =
        OwnerSiteRevocationTombstone::injected_for_harness(active.binding_id(), revoked);

    assert_eq!(
        OwnerSiteRosterSnapshot::injected_for_harness(
            roster_scope(),
            revoked,
            vec![active.clone()],
            vec![tombstone],
            1_000,
            1_060,
            "owner-key-alpha",
            vec![0xa5; 64],
        ),
        Err(OwnerSiteAuthorityError::RevokedBindingStillActive)
    );

    let reenrolled = generation(3, 0x33);
    let replacement = binding(0x02, reenrolled);
    let next = snapshot(reenrolled, vec![replacement], vec![tombstone]);
    let prior = snapshot(revoked, Vec::new(), vec![tombstone]);
    assert_eq!(next.is_strict_successor_of(&prior), Ok(()));
}

#[test]
fn successors_preserve_tombstones_and_never_resurrect_a_binding_id() {
    let enrolled = generation(1, 0x61);
    let old = binding(0x11, enrolled);
    let revoked = generation(2, 0x62);
    let tombstone = OwnerSiteRevocationTombstone::injected_for_harness(old.binding_id(), revoked);
    let prior = snapshot(revoked, Vec::new(), vec![tombstone]);

    let after_revoke = generation(3, 0x63);
    let dropped = snapshot(after_revoke, Vec::new(), Vec::new());
    assert_eq!(
        dropped.is_strict_successor_of(&prior),
        Err(OwnerSiteAuthorityError::TombstoneDropped)
    );

    // The constructor itself refuses an active reuse of the tombstoned id;
    // a later epoch cannot resurrect it.
    assert_eq!(
        OwnerSiteRosterSnapshot::injected_for_harness(
            roster_scope(),
            after_revoke,
            vec![binding(0x11, after_revoke)],
            vec![tombstone],
            1_000,
            1_060,
            "owner-key-alpha",
            vec![0xa5; 64],
        ),
        Err(OwnerSiteAuthorityError::RevokedBindingStillActive)
    );
}

#[test]
fn only_fresh_typed_harness_authority_can_admit_an_exact_intent() {
    let resource = resource();
    let (actor_id, authority) =
        active_authority_fixture("household-alpha", resource.clone()).expect("fixture");
    let intent = OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource)
        .expect("intent");
    assert!(authority.admits_pre_effect(&intent));
    let wrong_network = OwnerSiteIntent::injected_for_harness_with_request(
        "household-alpha",
        "other-network",
        &actor_id,
        OwnerSiteResource::from_route_claw("picoclaw").expect("resource"),
        crate::owner_site::capability::OwnerSiteCanonicalRequest::injected_for_harness(
            crate::owner_site::capability::OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x42; 32],
        )
        .expect("request"),
    )
    .expect("wrong-network intent");
    assert!(!authority.admits_pre_effect(&wrong_network));
    assert!(!OwnerSiteAuthoritySnapshot::Unavailable.admits_pre_effect(&intent));
    assert!(!OwnerSiteAuthoritySnapshot::Stale.admits_pre_effect(&intent));
    assert!(!OwnerSiteAuthoritySnapshot::Mismatch.admits_pre_effect(&intent));
    assert!(!OwnerSiteAuthoritySnapshot::Revoked.admits_pre_effect(&intent));
}

// ===== Fatia-2 linearizer: happy path + individual recheck negatives =====

#[allow(clippy::type_complexity)]
fn linearizer_fixture() -> (
    tempfile::TempDir,
    OwnerSitePromotionLinearizer,
    Pending,
    String,
    [u8; 33],
) {
    let household_root = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let household = derive_household_id(&household_root.public());
    let machine_cert = MachineCert::sign(
        &household_root,
        &machine.public(),
        &SignOptions {
            hh_id: household.clone(),
            hostname: "linearizer-host".to_owned(),
            platform: Platform::Macos,
            joined_at: 1_000,
        },
    )
    .expect("machine certificate");
    let device_binding = signed_member_device("npub1linearizer");
    let principal_d = OwnerSiteRemotePrincipal::injected_for_harness("npub1linearizer")
        .expect("remote principal");
    let exact_resource = OwnerSiteResource::from_route_claw("linearizer-claw").expect("resource");
    let exact_route =
        crate::owner_site::capability::OwnerSiteCanonicalRequest::injected_for_harness(
            crate::owner_site::capability::OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x31; 32],
        )
        .expect("canonical route");
    let ws_instance = OwnerSiteWebSocketInstance::injected_for_harness([0x21; 32]);
    let channel_id = OwnerSiteChannelId::injected_for_harness([0x22; 32]);
    let channel_epoch = OwnerSiteChannelEpoch::injected_for_harness(7).expect("channel epoch");
    let channel_binding = [0x23; 32];
    let channel = AuthenticatedConfidentialChannel::injected_for_harness(
        ws_instance,
        channel_id,
        channel_epoch,
        channel_binding,
    );
    let pending_finished = PendingFinished::injected_for_harness(
        household.clone(),
        exact_resource,
        exact_route,
        machine_cert,
        device_binding,
        principal_d,
        ws_instance,
        channel_id,
        channel_epoch,
        channel_binding,
        9,
        [0x24; 32],
        1_060,
        11,
        13,
    )
    .expect("synthetic pending state");
    let pending = Pending::injected_for_harness(pending_finished, channel).expect("pending");
    let root = *household_root.public().as_bytes();
    let dir = tempfile::tempdir().expect("tempdir");
    let linearizer = OwnerSitePromotionLinearizer::open(dir.path()).expect("open linearizer");
    (dir, linearizer, pending, household.0, root)
}

#[allow(clippy::too_many_arguments)]
fn run_promotion(
    authz_epoch: u64,
    roster_digest: [u8; 32],
    provider_generation: u64,
    cancellation_generation: u64,
    household_root: Option<[u8; 33]>,
    observed_at: u64,
) -> Result<OwnerSitePromotionWitness, OwnerSitePromotionRejection> {
    let (_dir, linearizer, pending, household, root) = linearizer_fixture();
    let root = household_root.unwrap_or(root);
    linearizer
        .observe_authority_for_harness(
            &household,
            authz_epoch,
            roster_digest,
            provider_generation,
            cancellation_generation,
            root,
            observed_at,
        )
        .expect("observe authority");
    let input = linearizer
        .register_pending(pending)
        .expect("register pending");
    linearizer.authorize(input)
}

#[test]
fn fatia2_happy_path_promotes_and_yields_witness() {
    let result = run_promotion(9, [0x24; 32], 11, 13, None, 1_001);
    assert!(
        matches!(result, Ok(_)),
        "happy path must promote: {result:?}"
    );
}

#[test]
fn fatia2_recheck_authority_exact_negative() {
    assert!(matches!(
        run_promotion(10, [0x24; 32], 11, 13, None, 1_001),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::AuthorityExact
        ))
    ));
    assert!(matches!(
        run_promotion(9, [0x99; 32], 11, 13, None, 1_001),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::AuthorityExact
        ))
    ));
}

#[test]
fn fatia2_recheck_cancellation_fence_negative() {
    assert!(matches!(
        run_promotion(9, [0x24; 32], 11, 14, None, 1_001),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::CancellationFence
        ))
    ));
}

#[test]
fn fatia2_recheck_provider_generation_negative() {
    assert!(matches!(
        run_promotion(9, [0x24; 32], 12, 13, None, 1_001),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::ProviderGeneration
        ))
    ));
}

#[test]
fn fatia2_recheck_freshness_negative() {
    assert!(matches!(
        run_promotion(9, [0x24; 32], 11, 13, None, 1_060),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::Freshness
        ))
    ));
}

#[test]
fn fatia2_recheck_authenticated_identity_negative() {
    let wrong_root = *P256Keypair::generate().public().as_bytes();
    assert!(matches!(
        run_promotion(9, [0x24; 32], 11, 13, Some(wrong_root), 1_001),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::AuthenticatedIdentity
        ))
    ));
}

#[test]
fn fatia2_authorize_without_observed_authority_fails_closed() {
    let (_dir, linearizer, pending, _household, _root) = linearizer_fixture();
    let input = linearizer
        .register_pending(pending)
        .expect("register pending");
    assert!(matches!(
        linearizer.authorize(input),
        Err(OwnerSitePromotionRejection::NoLiveAuthority)
    ));
}

#[test]
fn fatia2_promote_boundary_yields_promoted_channel() {
    let (_dir, linearizer, pending, household, root) = linearizer_fixture();
    linearizer
        .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
        .expect("observe authority");
    let input = linearizer
        .register_pending(pending)
        .expect("register pending");
    let request = crate::owner_site::promotion::OwnerSitePromotionRequest(input);
    let result =
        crate::owner_site::promotion::OwnerSitePromotionBoundary::promote(&linearizer, request);
    assert!(
        matches!(result, Ok(_)),
        "promote must yield a channel: {result:?}"
    );
}

#[test]
fn fatia2_revoke_promoted_channel_closes() {
    let (_dir, linearizer, pending, household, root) = linearizer_fixture();
    linearizer
        .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
        .expect("observe authority");
    let input = linearizer
        .register_pending(pending)
        .expect("register pending");
    let request = crate::owner_site::promotion::OwnerSitePromotionRequest(input);
    let channel =
        crate::owner_site::promotion::OwnerSitePromotionBoundary::promote(&linearizer, request)
            .expect("promote");
    // Revoke follows the §9 order (persist advance -> Revoking -> release ->
    // empty drain -> confirm Closed) and consumes the channel by ownership.
    linearizer
        .revoke(channel, 14)
        .expect("revoke closes the channel");
}

#[test]
fn fatia2_recheck_channel_identity_negative() {
    let (_dir, linearizer, pending, household, root) = linearizer_fixture();
    linearizer
        .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
        .expect("observe authority");
    // The key is never registered, so it has no live record. Rechecks 1-4
    // pass; recheck (5) rejects with ChannelIdentity and mutates nothing.
    // (Two live records for one key are unreachable by the store's
    // key-uniqueness invariant, proved separately in the store tests, so the
    // absent/Closed case is the sufficient and correct negative.)
    let key = owner_site_resolution_key(&pending.pending_finished);
    let input = OwnerSitePromotionInput {
        pending,
        claim: OwnerSitePromotionClaimId([0xEE; 32]),
    };
    assert!(matches!(
        linearizer.authorize(input),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::ChannelIdentity
        ))
    ));
    // Zero carrier (Err, no witness) and zero mutation: no record was
    // created and the claim was never registered or consumed.
    let inner = linearizer.inner.lock().expect("linearizer mutex");
    assert!(
        inner.store.live_record(&key).is_none(),
        "a gate-5 rejection must not create a live record"
    );
    assert!(
        !inner.store.is_claim_present(&[0xEE; 32]),
        "a gate-5 rejection must not register or consume the claim"
    );
}

#[test]
fn fatia2_recheck_one_shot_claim_negative() {
    let (_dir, linearizer, pending, household, root) = linearizer_fixture();
    linearizer
        .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
        .expect("observe authority");
    let key = owner_site_resolution_key(&pending.pending_finished);
    // A live `Pending` record exists (recheck 5 passes), but the input's
    // claim does not belong to the key. Recheck (7)'s store `promote` CAS
    // rejects it as OneShotClaim, with no witness and no state change.
    let mut input = linearizer
        .register_pending(pending)
        .expect("register pending");
    let registered_claim = *input.claim.as_bytes();
    input.claim = OwnerSitePromotionClaimId([0xEE; 32]);
    assert_ne!(
        [0xEE; 32], registered_claim,
        "the divergent test claim must differ from the registered claim"
    );
    assert!(matches!(
        linearizer.authorize(input),
        Err(OwnerSitePromotionRejection::Recheck(
            OwnerSiteRecheck::OneShotClaim
        ))
    ));
    // Zero carrier (Err, no witness) and zero mutation: the record stays a
    // live `Pending`, its registered claim is intact, and the divergent
    // claim was never consumed.
    let inner = linearizer.inner.lock().expect("linearizer mutex");
    let record = inner
        .store
        .live_record(&key)
        .expect("the registered record stays live");
    assert_eq!(
        record.state(),
        crate::owner_site::resolution_store::OwnerSiteResolutionState::Pending,
        "a gate-7 rejection must leave the record Pending"
    );
    assert_eq!(
        record.claim_id(),
        &registered_claim,
        "a gate-7 rejection must leave the registered claim intact"
    );
    assert!(
        !inner.store.is_claim_present(&[0xEE; 32]),
        "the divergent claim must never be consumed"
    );
}
