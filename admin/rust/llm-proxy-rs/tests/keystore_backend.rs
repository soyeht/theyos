//! Integration test for runtime keystore-backend selection.
//!
//! Covers the v1 durability requirement: a credential written by the
//! `set-credential` CLI subcommand MUST persist across proxy restarts
//! when the file backend is active. The file backend is the production
//! default for headless hosts (NixOS service unit) because kernel-keyring
//! credentials disappear on process restart and Secret Service is not
//! available on those hosts.

use std::path::PathBuf;

use llm_proxy::{KeystoreKind, ProxyConfig, build_credential_store};

/// A credential set via the file backend survives a fresh `ProxyConfig`
/// load — emulating a service restart that re-reads env vars and rebuilds
/// the store from scratch.
#[test]
fn file_backend_persists_credential_across_two_stores() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let dir = tmp.path().to_path_buf();

    let cfg = ProxyConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        profile_dir: PathBuf::from("/unused/in/this/test"),
        audit_log: None,
        keystore_kind: KeystoreKind::File,
        keystore_dir: dir.clone(),
    };

    let writer = build_credential_store(&cfg);
    writer
        .set("llm.api_key.glm", b"sekret-value")
        .expect("write credential");

    // Drop the writer; build a fresh store as a restart would.
    drop(writer);
    let reader = build_credential_store(&cfg);
    let got = reader.get("llm.api_key.glm").expect("read credential back");
    assert_eq!(got, b"sekret-value");

    // Same backend can also delete.
    reader.delete("llm.api_key.glm").expect("delete credential");
    assert!(
        matches!(
            reader.get("llm.api_key.glm"),
            Err(keystore_rs::KeystoreError::NotFound { .. })
        ),
        "deleted credential should report NotFound on read"
    );
}

/// A file-backend write is invisible to a system-backend read (and vice
/// versa). Operators MUST configure both halves the same way — this test
/// codifies the failure mode so a regression that quietly aliases the two
/// backends is caught.
#[test]
fn file_and_system_backends_do_not_share_storage() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let cfg_file = ProxyConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        profile_dir: PathBuf::from("/unused/in/this/test"),
        audit_log: None,
        keystore_kind: KeystoreKind::File,
        keystore_dir: tmp.path().to_path_buf(),
    };
    let store = build_credential_store(&cfg_file);
    store
        .set("llm.api_key.isolated", b"file-only")
        .expect("write to file backend");

    // SystemKeystore on Linux without Secret Service / kernel keyring will
    // fail to read the same account — that failure is the contract: the
    // two backends are not aliases.
    let cfg_system = ProxyConfig {
        keystore_kind: KeystoreKind::System,
        ..cfg_file.clone()
    };
    let system_store = build_credential_store(&cfg_system);
    let res = system_store.get("llm.api_key.isolated");
    assert!(
        res.is_err() || res.as_ref().ok().is_some_and(|v| v != b"file-only"),
        "file backend value must NOT be readable through the system backend"
    );
}
