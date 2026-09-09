#![cfg(test)]

use super::*;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Tiny(u32, String);

// -- 2PC staging: moved here from tests/storage_2pc.rs --------------
//
// These four exercise `stage_commit_files` DIRECTLY, so they had to be
// unit tests once that function became `pub(crate)`: an integration
// target is a separate crate and can only reach `pub` items. They were
// always unit-level — they drive the staging primitive itself, not a
// recovery scenario — so this is where they belonged. The ten recovery
// tests that remain in `tests/storage_2pc.rs` go through public entry
// points and are unaffected.
//
// Assertions are unchanged from the integration file; only the module
// and the import path moved.

fn payload(b: u8) -> Vec<u8> {
    vec![b; 16]
}

#[test]
fn stage_then_commit_promotes_all_files() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let b = household_dir(td.path()).join("b.cbor");
    let staged = stage_commit_files(&[(a.clone(), payload(0xA1)), (b.clone(), payload(0xB2))])
        .expect("stage");
    assert!(staged_path_for(&a).exists());
    assert!(staged_path_for(&b).exists());
    staged.commit().expect("commit");
    assert!(a.exists());
    assert!(b.exists());
    assert!(!staged_path_for(&a).exists());
    assert!(!staged_path_for(&b).exists());
    assert_eq!(fs::read(&a).unwrap(), payload(0xA1));
    assert_eq!(fs::read(&b).unwrap(), payload(0xB2));
}

#[test]
fn stage_then_rollback_removes_staged_files() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let staged = stage_commit_files(&[(a.clone(), payload(0xC3))]).expect("stage");
    assert!(staged_path_for(&a).exists());
    staged.rollback();
    assert!(!staged_path_for(&a).exists());
    assert!(!a.exists());
}

#[test]
fn dropping_uncommitted_staged_commit_cleans_up() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    {
        let _staged = stage_commit_files(&[(a.clone(), payload(0xD4))]).expect("stage");
        assert!(staged_path_for(&a).exists());
        // Drop without commit — best-effort cleanup runs.
    }
    assert!(!staged_path_for(&a).exists());
}

#[test]
fn staged_commit_preserve_on_error_keeps_remaining_staged_on_failure() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let b = household_dir(td.path()).join("b.cbor");
    // Block `b`'s rename target by pre-creating a directory at the
    // final path. fs::rename(file → dir) fails with "Is a directory"
    // (or similar) on POSIX, simulating any mid-loop rename failure.
    fs::create_dir(&b).unwrap();

    let staged = stage_commit_files(&[(a.clone(), payload(0xA1)), (b.clone(), payload(0xB2))])
        .expect("stage");
    let staged_a = staged_path_for(&a);
    let staged_b = staged_path_for(&b);
    assert!(staged_a.exists());
    assert!(staged_b.exists());

    // Partial failure: a was promoted (rename consumed `staged_a`),
    // b's rename failed.
    let result = staged.commit_preserve_on_error();
    assert!(result.is_err());

    // `a` ended up at its final path (rename succeeded for the first
    // item) — its `.staged` is gone because `fs::rename` consumes it.
    assert!(a.is_file());
    assert!(!staged_a.exists());
    // `b`'s `.staged` MUST survive — preserve_on_error disarmed
    // both the explicit rollback AND the Drop cleanup.
    assert!(
        staged_b.exists(),
        "preserve_on_error MUST leave `.staged` on disk so boot-time \
             recovery can find it via the phase3_finalize_ack.marker",
    );
}

type Phase3EvidenceCase = (
    &'static [u8],
    fn(&Path, &[u8]) -> Result<(), StorageError>,
    fn(&Path) -> PathBuf,
);

#[test]
fn atomic_round_trip() {
    let td = tempdir().unwrap();
    let path = td.path().join("nest").join("tiny.cbor");
    let value = Tiny(7, "foo".into());
    atomic_write_cbor(&path, &value).unwrap();
    let back: Option<Tiny> = read_optional_cbor(&path).unwrap();
    assert_eq!(Some(value), back);
}

#[test]
fn claw_vpn_mobile_mesh_snapshot_round_trip_is_private_file() {
    use crate::claw_vpn_mobile_state::{
        ClawVpnMobileAclGrant, ClawVpnMobileClawId, ClawVpnMobileDeviceId, ClawVpnMobileMemberId,
        ClawVpnMobileMesh, ClawVpnMobileOfferToken, ClawVpnMobileRendezvousToken,
    };

    let td = tempdir().unwrap();
    let member = ClawVpnMobileMemberId::try_new("member-alpha").unwrap();
    let device = ClawVpnMobileDeviceId::try_new("device-alpha").unwrap();
    let claw = ClawVpnMobileClawId::try_new("claw-alpha").unwrap();
    let grant = ClawVpnMobileAclGrant::new(member, device.clone(), claw.clone());
    let mut mesh = ClawVpnMobileMesh::new(60).unwrap();
    assert!(mesh.enroll_device(device));
    assert!(mesh.set_claw_available(claw));
    assert!(mesh.grant(grant.clone()));
    let offer_token = ClawVpnMobileOfferToken::try_new("0123456789abcdef0123456789abcdef").unwrap();
    let rendezvous_token =
        ClawVpnMobileRendezvousToken::try_new("abcdef0123456789abcdef0123456789").unwrap();
    mesh.mint_offer_with_token(&grant, 10, offer_token.clone())
        .unwrap();
    let session = mesh
        .consume_offer_token(&offer_token, &grant, 20, rendezvous_token)
        .unwrap();

    let snapshot = mesh.snapshot();
    write_claw_vpn_mobile_mesh_snapshot(td.path(), &snapshot).unwrap();
    let path = claw_vpn_mobile_mesh_path(td.path());
    assert_eq!(
        path.file_name().and_then(std::ffi::OsStr::to_str),
        Some("claw_vpn_mobile_mesh.cbor")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let loaded = read_claw_vpn_mobile_mesh_snapshot(td.path())
        .unwrap()
        .unwrap();
    let restored = ClawVpnMobileMesh::from_snapshot(loaded).unwrap();
    assert!(restored.has_active_session(session));

    delete_claw_vpn_mobile_mesh_snapshot(td.path()).unwrap();
    assert!(
        read_claw_vpn_mobile_mesh_snapshot(td.path())
            .unwrap()
            .is_none()
    );
}

#[test]
fn read_returns_none_when_absent() {
    let td = tempdir().unwrap();
    let path = td.path().join("absent.cbor");
    let v: Option<Tiny> = read_optional_cbor(&path).unwrap();
    assert!(v.is_none());
}

#[test]
fn known_peer_addr_round_trip_and_absent() {
    let td = tempdir().unwrap();
    assert_eq!(read_known_peer_addr(td.path(), "m_abc").unwrap(), None);

    write_known_peer_addr(td.path(), "m_abc", "192.168.1.5:8091").unwrap();
    assert_eq!(
        read_known_peer_addr(td.path(), "m_abc").unwrap(),
        Some("192.168.1.5:8091".to_string())
    );
    // An unrelated m_id still reads as unknown.
    assert_eq!(read_known_peer_addr(td.path(), "m_def").unwrap(), None);

    // A second machine's entry doesn't clobber the first.
    write_known_peer_addr(td.path(), "m_def", "192.168.1.9:8091").unwrap();
    assert_eq!(
        read_known_peer_addr(td.path(), "m_abc").unwrap(),
        Some("192.168.1.5:8091".to_string())
    );
    assert_eq!(
        read_known_peer_addr(td.path(), "m_def").unwrap(),
        Some("192.168.1.9:8091".to_string())
    );
}

#[test]
fn no_orphan_tmp_after_success() {
    let td = tempdir().unwrap();
    let path = td.path().join("ok.cbor");
    atomic_write_cbor(&path, &Tiny(1, "a".into())).unwrap();
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    assert!(!std::path::Path::new(&tmp).exists());
}

#[test]
fn atomic_parent_barrier_failure_reports_effect_and_retry_stabilizes_same_value() {
    let td = tempdir().unwrap();
    let path = td.path().join("authority.cbor");
    let value = Tiny(9, "installed".into());
    storage_fail_injection::arm_atomic_parent_barrier();
    let error = atomic_write_cbor(&path, &value).unwrap_err();
    assert!(matches!(error, StorageError::MayHaveTakenEffect { .. }));
    assert_eq!(
        read_optional_cbor::<Tiny>(&path).unwrap(),
        Some(Tiny(9, "installed".into())),
        "the typed outcome must describe the semantic effect that actually landed"
    );
    atomic_write_cbor(&path, &value).expect("retry rewrites and stabilizes the same value");
    assert_eq!(read_optional_cbor::<Tiny>(&path).unwrap(), Some(value));
}

#[test]
fn phase3_evidence_parent_barrier_failure_blocks_dispatch_until_exact_retry() {
    let td = tempdir().unwrap();
    let cases: [Phase3EvidenceCase; 2] = [
        (
            b"exact canonical JoinResponse",
            write_phase3_pending_join_response,
            phase3_pending_join_response_path,
        ),
        (
            b"m_exact_candidate",
            |state_dir, bytes| {
                let candidate = std::str::from_utf8(bytes).expect("test candidate utf8");
                write_phase3_finalize_ack_marker(state_dir, candidate)
            },
            phase3_finalize_ack_marker_path,
        ),
    ];

    for (exact, write, path_for) in cases {
        storage_fail_injection::arm_phase3_evidence_parent_barrier();
        let error = write(td.path(), exact).unwrap_err();
        assert!(matches!(error, StorageError::MayHaveTakenEffect { .. }));
        assert_eq!(
            fs::read(path_for(td.path())).unwrap(),
            exact,
            "the typed outcome must admit that the rename may already be visible",
        );
        write(td.path(), exact).expect("exact retry must reapply and prove parent durability");
        assert_eq!(fs::read(path_for(td.path())).unwrap(), exact);
    }
}

#[test]
fn oversized_phase3_manifest_fails_closed_before_decode() {
    let td = tempdir().unwrap();
    let path = phase3_recovery_manifest_path(td.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = File::create(&path).unwrap();
    file.set_len(MAX_PHASE3_RECOVERY_MANIFEST_BYTES + 1)
        .unwrap();

    let error = read_phase3_recovery_manifest(td.path()).unwrap_err();
    assert!(matches!(error, StorageError::Encoding(_)));
}

#[test]
fn current_phase3_manifest_owns_staged_files_even_after_record_is_visible_post_shamir() {
    let td = tempdir().unwrap();
    let loaded = crate::bootstrap_or_load(
        td.path(),
        crate::BootstrapOpts {
            household_name: "Manifest Gate".into(),
            hostname_label: Some("manifest-gate".into()),
        },
        crate::KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let mut visible_record = loaded.record.clone();
    visible_record.shamir_k = 2;
    visible_record.shamir_n = 2;
    atomic_write_cbor(&household_record_path(td.path()), &visible_record).unwrap();

    let staged = staged_path_for(&crate::pair_machine::shamir_self_shard_path(td.path()));
    fs::create_dir_all(staged.parent().unwrap()).unwrap();
    fs::write(&staged, b"exact staged evidence").unwrap();
    let manifest = phase3_recovery_manifest_path(td.path());
    fs::write(&manifest, b"reader will quarantine this malformed manifest").unwrap();

    assert_eq!(recover_partial_phase3_commit(td.path()), (0, 0));
    assert!(
        staged.exists(),
        "generic post-Shamir recovery must not consume manifest-owned evidence"
    );
}

#[cfg(unix)]
#[test]
fn dangling_manifest_entry_is_still_a_fail_closed_staged_cleanup_gate() {
    use std::os::unix::fs::symlink;

    let td = tempdir().unwrap();
    let staged = staged_path_for(&crate::pair_machine::shamir_self_shard_path(td.path()));
    fs::create_dir_all(staged.parent().unwrap()).unwrap();
    fs::write(&staged, b"preserve me").unwrap();
    let manifest = phase3_recovery_manifest_path(td.path());
    symlink(td.path().join("missing-target"), &manifest).unwrap();

    assert!(phase3_recovery_manifest_exists(td.path()));
    assert_eq!(recover_partial_phase3_commit(td.path()), (0, 0));
    assert!(staged.exists());
}

#[test]
fn staged_parent_barrier_failure_preserves_remaining_recovery_evidence() {
    let td = tempdir().unwrap();
    let first = td.path().join("first.cbor");
    let second = td.path().join("second.cbor");
    let staged = stage_commit_files(&[
        (first.clone(), b"first".to_vec()),
        (second.clone(), b"second".to_vec()),
    ])
    .unwrap();
    storage_fail_injection::arm_staged_commit_parent_barrier();
    let error = staged.commit().unwrap_err();
    assert!(matches!(error, StorageError::MayHaveTakenEffect { .. }));
    assert_eq!(fs::read(&first).unwrap(), b"first");
    assert!(
        staged_path_for(&second).exists(),
        "Drop must preserve unpromoted staged evidence after any final rename"
    );
    assert!(!second.exists());
}
