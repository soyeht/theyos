//! Integration tests for session-rs — covers scenarios that unit tests cannot:
//!
//!   - Pepper rotation across separate stores (env var mutation)
//!   - `hash_password` with different peppers (env var mutation)
//!   - Edge cases not covered by unit tests
//!   - Concurrent session creation (multi-thread safety)
//!
//! Everything else (create/validate/delete cycle, cleanup, credentials) is
//! already covered by unit tests in session-rs/src/lib.rs.

use core_rs::env::{remove_test_env, set_test_env};
use session_rs::SessionStore;
use std::sync::Mutex;

// Serialize all tests that touch process-global env vars (SOYEHT_ADMIN_*,
// THEYOS_SESSION_PEPPER) to prevent cross-test interference.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the `ENV_LOCK`, set credentials, open an in-memory store, return
/// both so the caller holds the guard for the full test duration.
fn open_store(user: &str, pass: &str) -> (SessionStore, std::sync::MutexGuard<'static, ()>) {
    let guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_test_env("SOYEHT_ADMIN_USER", user);
    set_test_env("SOYEHT_ADMIN_PASSWORD", pass);
    let store = SessionStore::open(":memory:").expect("open :memory:");
    (store, guard)
}

// ─── Pepper rotation ─────────────────────────────────────────────────────────

#[test]
fn pepper_rotation_changes_stored_hash() {
    // The password hash is computed at construction time using the current pepper.
    // A store opened with pepper-v1 and another with pepper-v2 store different
    // hashes for the same password.
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    set_test_env("SOYEHT_ADMIN_USER", "rotateuser");
    set_test_env("SOYEHT_ADMIN_PASSWORD", "mypassword");

    // Store #1: opened with pepper-v1
    set_test_env("THEYOS_SESSION_PEPPER", "pepper-v1");
    let store_v1 = SessionStore::open(":memory:").unwrap();

    // Store #2: opened with pepper-v2
    set_test_env("THEYOS_SESSION_PEPPER", "pepper-v2");
    let store_v2 = SessionStore::open(":memory:").unwrap();

    // v1 credentials validate against v1 store when v1 pepper is active.
    set_test_env("THEYOS_SESSION_PEPPER", "pepper-v1");
    assert!(
        store_v1
            .validate_credentials("rotateuser", "mypassword")
            .is_ok(),
        "v1 store + v1 pepper should match"
    );
    // v1 pepper does NOT match v2 store (different stored hash).
    assert!(
        store_v2
            .validate_credentials("rotateuser", "mypassword")
            .is_err(),
        "v1 pepper should NOT match v2 store hash"
    );

    // v2 credentials validate against v2 store when v2 pepper is active.
    set_test_env("THEYOS_SESSION_PEPPER", "pepper-v2");
    assert!(
        store_v2
            .validate_credentials("rotateuser", "mypassword")
            .is_ok(),
        "v2 store + v2 pepper should match"
    );

    remove_test_env("THEYOS_SESSION_PEPPER");
}

#[test]
fn different_peppers_produce_different_hashes() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    set_test_env("THEYOS_SESSION_PEPPER", "alpha");
    let hash_a = session_rs::hash_password("samepassword");

    set_test_env("THEYOS_SESSION_PEPPER", "beta");
    let hash_b = session_rs::hash_password("samepassword");

    assert_ne!(
        hash_a, hash_b,
        "different peppers must produce different hashes for the same password"
    );

    remove_test_env("THEYOS_SESSION_PEPPER");
}

// ─── Edge cases (not covered by unit tests) ──────────────────────────────────

#[test]
fn validate_session_empty_token_returns_none() {
    // Unit tests cover "nonexistent-token" but not the empty string edge case.
    let (store, _g) = open_store("edgeuser", "pw");
    assert!(store.validate_session("").is_none());
}

#[test]
fn delete_session_on_unknown_token_is_noop() {
    // Unit tests cover delete_session("") but not a non-empty, never-created token.
    let (store, _g) = open_store("edgeuser2", "pw");
    assert!(store.delete_session("no-such-token-xyz").is_ok());
}

// ─── Concurrent session creation (multi-thread safety) ───────────────────────

#[test]
fn concurrent_session_creation_is_safe() {
    use std::sync::Arc;
    use std::thread;

    // We own the lock while setting env vars and opening the store.
    // We release it before spawning threads so concurrent_session_creation
    // doesn't block other env-var tests indefinitely.
    let store = {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_test_env("SOYEHT_ADMIN_USER", "concurrent-user");
        set_test_env("SOYEHT_ADMIN_PASSWORD", "pw");
        Arc::new(SessionStore::open(":memory:").unwrap())
        // guard dropped here — env vars no longer matter for the store
    };

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let s = Arc::clone(&store);
            thread::spawn(move || s.create_session("concurrent-user").unwrap())
        })
        .collect();

    let tokens: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All tokens must be unique.
    let unique: std::collections::HashSet<&str> =
        tokens.iter().map(std::string::String::as_str).collect();
    assert_eq!(unique.len(), 10, "all concurrent tokens must be unique");

    // All tokens must be valid.
    for token in &tokens {
        assert!(
            store.validate_session(token).is_some(),
            "concurrent token should be valid: {token}"
        );
    }
}
