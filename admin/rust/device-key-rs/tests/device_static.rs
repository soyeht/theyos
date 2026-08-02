//! S1 g3 integration tests: the keystore round-trip through the PUBLIC API.
//!
//! These tests never touch the scalar — the only comparable value across a
//! persist/load cycle is the public key, which is exactly the seam the
//! design leaves open (g3 §4).

use device_key_rs::DeviceStaticSecret;
use keystore_rs::FileKeystore;

fn fresh_store() -> (tempfile::TempDir, FileKeystore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileKeystore::new(tmp.path(), "com.soyeht.theyos");
    (tmp, store)
}

/// Binds the no-op-persist / always-None-load mutant (CFX-S1-3): a
/// persistence layer that does nothing rejects everything perfectly, so the
/// assertion ties the OUTPUT of `load` to the INPUT of `persist`. Absence
/// after persist is a FAILURE, never a skipped case (CFX-S1-7).
#[test]
fn persist_then_load_returns_the_same_key() {
    let (_tmp, store) = fresh_store();
    let secret = DeviceStaticSecret::generate().unwrap();
    let expected_public = secret.public();

    secret.persist(&store).unwrap();
    let loaded = DeviceStaticSecret::load(&store)
        .unwrap()
        .expect("persisted secret must load — None here is a failed round-trip, not a skip");

    assert_eq!(loaded.public(), expected_public);
}

#[test]
fn load_on_an_empty_store_returns_none() {
    let (_tmp, store) = fresh_store();
    assert!(DeviceStaticSecret::load(&store).unwrap().is_none());
}

/// A stored value that is not exactly 32 bytes must be rejected, never
/// truncated or padded into a "valid" key. The trait is byte-shaped, so the
/// length check is the only type check this layer has.
#[test]
fn load_rejects_a_truncated_stored_value() {
    let (tmp, store) = fresh_store();
    let secret = DeviceStaticSecret::generate().unwrap();
    secret.persist(&store).unwrap();

    // Corrupt the stored entry in place through the backend, at the same
    // derived account the implementation uses. We cannot name the account
    // from outside (by design), so corrupt via the on-disk file the file
    // backend created — the effect site.
    let service_dir = tmp.path().join("secrets").join("com.soyeht.theyos");
    let entries: Vec<_> = std::fs::read_dir(&service_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one stored entry");
    std::fs::write(&entries[0], b"too short").unwrap();

    match DeviceStaticSecret::load(&store) {
        Err(err) => assert!(
            err.to_string().contains("invalid length"),
            "expected InvalidStoredLength, got: {err}"
        ),
        Ok(_) => panic!("a truncated stored value must be rejected, not loaded"),
    }
}

/// Persisting twice replaces, it does not stack: the load returns the LAST
/// persisted key. (One device static per install — g3 §1.4a.)
#[test]
fn persist_twice_replaces_the_stored_key() {
    let (_tmp, store) = fresh_store();
    let first = DeviceStaticSecret::generate().unwrap();
    first.persist(&store).unwrap();

    let second = DeviceStaticSecret::generate().unwrap();
    let second_public = second.public();
    second.persist(&store).unwrap();

    let loaded = DeviceStaticSecret::load(&store)
        .unwrap()
        .expect("persisted secret must load");
    assert_eq!(loaded.public(), second_public);
    assert_ne!(loaded.public(), first.public());
}
