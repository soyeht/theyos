use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::SignOwnerOptions;
use household_rs::{
    BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert, bootstrap_or_load,
};
use std::path::{Path, PathBuf};

fn build_state() -> (
    tempfile::TempDir,
    household_rs::LoadedIdentity,
    HouseholdAuthState,
) {
    let td = tempfile::tempdir().unwrap();
    let identity = bootstrap_or_load(
        td.path(),
        BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-test".into()),
        },
        KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    let person = P256Keypair::generate();
    let cert = PersonCert::sign_owner(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        SignOwnerOptions {
            hh_id: identity.record.hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: identity.record.created_at + 1,
        },
    )
    .unwrap();
    let state = HouseholdAuthState::new(&identity.record, cert);
    (td, identity, state)
}

#[test]
fn owner_auth_state_round_trips_and_verifies() {
    let (td, identity, state) = build_state();
    state.save(td.path()).unwrap();
    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert_eq!(loaded, Some(state));
}

#[test]
fn tampered_owner_cert_refuses_to_load() {
    let (td, identity, state) = build_state();
    state.save(td.path()).unwrap();

    let path = household_rs::storage::owner_person_cert_path(td.path());
    let mut cert: PersonCert = household_rs::storage::read_optional_cbor(&path)
        .unwrap()
        .unwrap();
    cert.display_name = "Mallory".into();
    household_rs::storage::atomic_write_cbor(&path, &cert).unwrap();

    HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap_err();
}

#[test]
fn auth_state_primary_repairs_missing_cert_projection() {
    let (td, identity, state) = build_state();
    let auth_path = household_rs::storage::household_auth_state_path(td.path());
    let cert_path = household_rs::storage::owner_person_cert_path(td.path());

    household_rs::storage::atomic_write_cbor(&auth_path, &state).unwrap();
    assert!(!cert_path.exists());

    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert_eq!(loaded, Some(state));
    assert!(cert_path.exists());
}

#[test]
fn auth_state_save_succeeds_when_cert_projection_write_fails() {
    let (td, _identity, state) = build_state();
    block_tmp_write(&household_rs::storage::owner_person_cert_path(td.path()));

    state.save(td.path()).unwrap();

    assert!(household_rs::storage::household_auth_state_path(td.path()).exists());
    assert!(!household_rs::storage::owner_person_cert_path(td.path()).exists());
}

#[test]
fn auth_state_load_ignores_missing_projection_repair_failure() {
    let (td, identity, state) = build_state();
    let auth_path = household_rs::storage::household_auth_state_path(td.path());
    let cert_path = household_rs::storage::owner_person_cert_path(td.path());

    household_rs::storage::atomic_write_cbor(&auth_path, &state).unwrap();
    block_tmp_write(&cert_path);

    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert_eq!(loaded, Some(state));
    assert!(!cert_path.exists());
}

#[test]
fn orphan_cert_projection_is_not_trusted() {
    let (td, identity, state) = build_state();
    let cert_path = household_rs::storage::owner_person_cert_path(td.path());

    household_rs::storage::atomic_write_cbor(&cert_path, &state.owner_person_cert).unwrap();

    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert_eq!(loaded, None);
    assert!(!cert_path.exists());
}

fn block_tmp_write(path: &Path) {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::create_dir_all(PathBuf::from(tmp)).unwrap();
}
