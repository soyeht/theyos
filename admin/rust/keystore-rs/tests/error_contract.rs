//! Contract tests for the `KeystoreError` shape — these freeze the
//! `error.kind()` strings consumed by the structured-log emitters in
//! server-rs and household-rs. Renaming a kind is a breaking change for log
//! consumers.

use keystore_rs::KeystoreError;

#[test]
fn error_kinds_are_stable() {
    assert_eq!(
        KeystoreError::Unavailable {
            hint: "x".into()
        }
        .kind(),
        "keystore.unavailable"
    );
    assert_eq!(
        KeystoreError::PermissionDenied {
            hint: "x".into()
        }
        .kind(),
        "se.permission_denied"
    );
    assert_eq!(
        KeystoreError::SeUnavailable { hint: "x".into() }.kind(),
        "se.unavailable"
    );
    assert_eq!(
        KeystoreError::NotFound { label: "x".into() }.kind(),
        "keystore.not_found"
    );
    assert_eq!(
        KeystoreError::Io {
            kind: "x".into(),
            hint: "y".into()
        }
        .kind(),
        "keystore.io"
    );
    assert_eq!(
        KeystoreError::SigningFailed("x".into()).kind(),
        "keystore.signing_failed"
    );
    assert_eq!(
        KeystoreError::InvalidKeyMaterial("x".into()).kind(),
        "keystore.invalid_key_material"
    );
}

#[test]
fn hint_surfaces_operator_action() {
    let e = KeystoreError::Unavailable {
        hint: "install gnome-keyring".into(),
    };
    assert_eq!(e.hint(), "install gnome-keyring");

    let e = KeystoreError::NotFound {
        label: "llm.api_key.anthropic".into(),
    };
    assert_eq!(
        e.hint(),
        "entry llm.api_key.anthropic missing from keystore"
    );
}

#[test]
fn macos_keychain_denied_helper_uses_documented_hint() {
    let err = keystore_rs::macos_keychain_denied_error();
    assert_eq!(err.kind(), "se.permission_denied");
    assert!(
        err.hint().contains("Keychain"),
        "hint should mention Keychain: {}",
        err.hint()
    );
}

#[test]
fn linux_secret_service_helper_uses_documented_hint() {
    let err = keystore_rs::linux_secret_service_unavailable_error();
    assert_eq!(err.kind(), "keystore.unavailable");
    assert!(
        err.hint().contains("gnome-keyring") || err.hint().contains("Secret Service"),
        "hint should mention Secret Service: {}",
        err.hint()
    );
}
