#[cfg(target_os = "macos")]
mod macos {
    use household_rs::bootstrap::{BootstrapOpts, KeyBackingPolicy, bootstrap_or_load};
    use household_rs::keys::{IdentityKey, verify_signature};
    use household_rs::{KeystoreError, P256Keypair};
    use tempfile::tempdir;

    #[test]
    fn secure_enclave_keypair_signs_and_verifies_when_available() {
        let keypair = match household_rs::keys_se::P256SeKeypair::create(
            "com.soyeht.theyos.tests.keys_se.sign",
            true,
        ) {
            Ok(keypair) => keypair,
            Err(KeystoreError::SeUnavailable { hint }) => {
                eprintln!("Secure Enclave unavailable; skipping hardware interop: {hint}");
                return;
            }
            Err(error) => panic!("unexpected Secure Enclave creation error: {error:?}"),
        };

        let message = b"theyos secure enclave interop";
        let signature = keypair.sign(message).unwrap();
        verify_signature(&keypair.public(), message, &signature).unwrap();
    }

    #[test]
    fn secure_enclave_debug_formatter_does_not_reveal_scalar_material() {
        let keypair = match household_rs::keys_se::P256SeKeypair::create(
            "com.soyeht.theyos.tests.keys_se.debug",
            true,
        ) {
            Ok(keypair) => keypair,
            Err(KeystoreError::SeUnavailable { hint }) => {
                eprintln!("Secure Enclave unavailable; skipping debug check: {hint}");
                return;
            }
            Err(error) => panic!("unexpected Secure Enclave creation error: {error:?}"),
        };

        let debug = format!("{keypair:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("scalar"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("sec_key_ref"));
    }

    #[test]
    fn force_software_policy_uses_software_keypair() {
        let temp = tempdir().unwrap();
        let loaded = bootstrap_or_load(
            temp.path(),
            BootstrapOpts {
                household_name: "Sample Home".into(),
                hostname_label: Some("studio-mac".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();

        assert_eq!(loaded.backing, "software");
        assert_eq!(
            loaded
                .hh_priv
                .as_deref()
                .expect("hh_priv present in single-machine household")
                .backing(),
            "software"
        );
        assert_eq!(loaded.m_priv.backing(), "software");

        let software = P256Keypair::generate();
        assert_eq!(software.backing(), "software");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn secure_enclave_contract_tests_are_macos_only() {
    // Linux runners compile and report a clean skip for the macOS-only SE path.
}
