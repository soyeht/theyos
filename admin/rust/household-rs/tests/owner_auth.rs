use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::owner_auth::OwnerAuthError;
use household_rs::owner_webauthn::OwnerWebauthnCredential;
use household_rs::owner_webauthn_authority::OwnerWebauthnAuthority;
use household_rs::person_cert::SignOwnerOptions;
use household_rs::{
    BootstrapOpts, HouseholdAuthState, KeyBackingPolicy, PersonCert, bootstrap_or_load,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use webauthn_rs::prelude::Passkey;

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

fn assert_loaded_matches(
    loaded: Option<HouseholdAuthState>,
    expected: &HouseholdAuthState,
    identity: &household_rs::LoadedIdentity,
) {
    let loaded = loaded.expect("owner auth state should load");
    assert_eq!(loaded.version, expected.version);
    assert_eq!(loaded.hh_id, expected.hh_id);
    assert_eq!(loaded.owner_person_cert, expected.owner_person_cert);
    assert_eq!(loaded.created_at, expected.created_at);
    assert_eq!(loaded.updated_at, expected.updated_at);
    loaded
        .verify(&identity.record, loaded.updated_at)
        .expect("loaded auth state verifies");
    assert_eq!(
        loaded
            .owner_has_active_webauthn_credential(&identity.record)
            .unwrap(),
        expected
            .owner_has_active_webauthn_credential(&identity.record)
            .unwrap()
    );
}

fn synthetic_passkey(id: &[u8]) -> Passkey {
    let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
    serde_json::from_value(json!({
        "cred": {
            "cred_id": encoded_id,
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": data_encoding::BASE64URL_NOPAD.encode(&[1_u8; 32]),
                        "y": data_encoding::BASE64URL_NOPAD.encode(&[2_u8; 32])
                    }
                }
            },
            "counter": 0,
            "transports": null,
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": true,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {
                "data": "None",
                "metadata": "None"
            },
            "attestation_format": "none"
        }
    }))
    .unwrap()
}

fn owner_credential(id: &[u8]) -> OwnerWebauthnCredential {
    OwnerWebauthnCredential::new(synthetic_passkey(id))
}

#[test]
fn owner_auth_state_round_trips_and_verifies() {
    let (td, identity, state) = build_state();
    state.save(td.path()).unwrap();
    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert_loaded_matches(loaded, &state, &identity);
}

#[test]
fn owner_auth_state_round_trips_webauthn_authority() {
    let (td, identity, mut state) = build_state();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &state.owner_person_cert,
        owner_credential(b"owner-passkey-1"),
        state.created_at + 1,
    )
    .unwrap();
    state.owner_webauthn.push_signed(genesis);
    state.updated_at = state.created_at + 1;

    state.verify(&identity.record, state.updated_at).unwrap();
    assert!(
        state
            .owner_has_active_webauthn_credential(&identity.record)
            .unwrap()
    );

    state.save(td.path()).unwrap();
    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.updated_at).unwrap();
    assert_loaded_matches(loaded, &state, &identity);
}

#[test]
fn owner_auth_state_rejects_tampered_webauthn_authority() {
    let (_td, identity, mut state) = build_state();
    let mut genesis = OwnerWebauthnAuthority::sign_genesis(
        identity
            .hh_priv
            .as_deref()
            .expect("hh_priv present in single-machine household"),
        &identity.record,
        &state.owner_person_cert,
        owner_credential(b"owner-passkey-1"),
        state.created_at + 1,
    )
    .unwrap();
    genesis.event.issued_at += 1;
    state.owner_webauthn.push_signed(genesis);
    state.updated_at = state.created_at + 1;

    let err = state
        .verify(&identity.record, state.updated_at)
        .unwrap_err();
    assert!(matches!(err, OwnerAuthError::OwnerWebauthn(_)));
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
    assert_loaded_matches(loaded, &state, &identity);
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
    assert_loaded_matches(loaded, &state, &identity);
    assert!(!cert_path.exists());
}

#[test]
fn orphan_cert_projection_is_not_trusted() {
    let (td, identity, state) = build_state();
    let cert_path = household_rs::storage::owner_person_cert_path(td.path());

    household_rs::storage::atomic_write_cbor(&cert_path, &state.owner_person_cert).unwrap();

    let loaded =
        HouseholdAuthState::load_optional(td.path(), &identity.record, state.created_at).unwrap();
    assert!(loaded.is_none());
    assert!(!cert_path.exists());
}

fn block_tmp_write(path: &Path) {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::create_dir_all(PathBuf::from(tmp)).unwrap();
}
