//! Roundtrip tests for the file backend. The OS-keystore backends (Linux
//! keyring, macOS Keychain) hit user-session daemons and can't run in CI
//! sandboxes — they have their own contract tests in household-rs that ARE
//! invoked manually on workstations.

use keystore_rs::{FileKeystore, KeystoreBackend, KeystoreError};
use tempfile::tempdir;

#[test]
fn file_backend_roundtrips_a_value() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    let secret = b"sk-ant-test-key-do-not-use";
    store.set("llm.api_key.anthropic", secret).unwrap();
    let got = store.get("llm.api_key.anthropic").unwrap();
    assert_eq!(got, secret);
}

#[test]
fn file_backend_get_missing_returns_not_found() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    match store.get("never-written") {
        Err(KeystoreError::NotFound { label }) => {
            assert!(label.contains("never-written"), "label={label}");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn file_backend_delete_is_idempotent() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    // Deleting a non-existent account succeeds.
    store.delete("ghost").unwrap();

    // Write, delete, delete again — all succeed.
    store.set("two-delete", b"value").unwrap();
    store.delete("two-delete").unwrap();
    store.delete("two-delete").unwrap();

    // After delete, get returns NotFound.
    match store.get("two-delete") {
        Err(KeystoreError::NotFound { .. }) => {}
        other => panic!("expected NotFound after delete, got {other:?}"),
    }
}

#[test]
fn file_backend_overwrite_replaces_value() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    store.set("rotated", b"old-value").unwrap();
    store.set("rotated", b"new-value").unwrap();
    assert_eq!(store.get("rotated").unwrap(), b"new-value");
}

#[test]
fn file_backend_handles_variable_sized_values() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    // 32-byte scalar (household crypto key shape) — the original primary use.
    let scalar = [7u8; 32];
    store.set("scalar", &scalar).unwrap();
    assert_eq!(store.get("scalar").unwrap(), &scalar[..]);

    // Long string — typical LLM API key shape.
    let api_key = "sk-ant-this-is-a-long-key-".repeat(8);
    store.set("api_key", api_key.as_bytes()).unwrap();
    assert_eq!(store.get("api_key").unwrap(), api_key.as_bytes());

    // Empty value.
    store.set("empty", b"").unwrap();
    assert_eq!(store.get("empty").unwrap(), b"");
}

#[test]
fn file_backend_isolates_services() {
    let dir = tempdir().unwrap();
    let household = FileKeystore::new(dir.path(), "com.soyeht.theyos.household");
    let llm = FileKeystore::new(dir.path(), "com.soyeht.theyos.llm");

    household
        .set("shared-account-name", b"household-value")
        .unwrap();
    llm.set("shared-account-name", b"llm-value").unwrap();

    // Same account label, different services → distinct values.
    assert_eq!(
        household.get("shared-account-name").unwrap(),
        b"household-value"
    );
    assert_eq!(llm.get("shared-account-name").unwrap(), b"llm-value");
}

#[test]
fn file_backend_sanitises_path_traversal_attempts() {
    let dir = tempdir().unwrap();
    let store = FileKeystore::new(dir.path(), "com.soyeht.theyos.test");

    // Adversarial account label that tries to escape the secrets dir.
    let evil = "../../../etc/passwd";
    store.set(evil, b"benign-payload").unwrap();

    // Roundtrip still works (the value is reachable via the same label) ...
    assert_eq!(store.get(evil).unwrap(), b"benign-payload");

    // ... AND the on-disk path stays under the state dir (no traversal).
    let written_path = store.path_for(evil);
    assert!(
        written_path.starts_with(dir.path()),
        "file written outside state dir: {}",
        written_path.display()
    );
}
