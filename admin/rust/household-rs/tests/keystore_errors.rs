use household_rs::KeystoreError;
use household_rs::keystore::{
    LINUX_SECRET_SERVICE_UNAVAILABLE_HINT, MACOS_KEYCHAIN_DENIED_HINT, macos_keychain_denied_error,
};

#[test]
fn mocked_keychain_denied_maps_to_exact_contract_hint() {
    let error = macos_keychain_denied_error();

    assert_eq!(error.kind(), "se.permission_denied");
    assert_eq!(error.hint(), MACOS_KEYCHAIN_DENIED_HINT);
    match error {
        KeystoreError::PermissionDenied { hint } => {
            assert_eq!(hint, MACOS_KEYCHAIN_DENIED_HINT);
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn mocked_linux_keyring_unavailable_maps_to_exact_contract_hint() {
    #[derive(Debug)]
    struct LinuxKeyringUnavailable;

    impl std::fmt::Display for LinuxKeyringUnavailable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("mock Linux keyring unavailable")
        }
    }

    impl std::error::Error for LinuxKeyringUnavailable {}

    let error = household_rs::keystore::map_linux_keyring_error_for_contract(
        keyring::Error::PlatformFailure(Box::new(LinuxKeyringUnavailable)),
    );

    assert_eq!(error.kind(), "keystore.unavailable");
    assert_eq!(error.hint(), LINUX_SECRET_SERVICE_UNAVAILABLE_HINT);
    match error {
        KeystoreError::Unavailable { hint } => {
            assert_eq!(hint, LINUX_SECRET_SERVICE_UNAVAILABLE_HINT);
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_keyring_unavailable_contract_hint_is_stable_on_non_linux() {
    let error = household_rs::keystore::linux_secret_service_unavailable_error();

    assert_eq!(error.kind(), "keystore.unavailable");
    assert_eq!(error.hint(), LINUX_SECRET_SERVICE_UNAVAILABLE_HINT);
}
