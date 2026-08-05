//! household-rs — cryptographic skeleton for the Soyeht Household identity model.
//!
//! Phase 1 surface:
//!
//! - [`ids`] — Household / Machine identifier derivation (`hh_…` / `m_…`) via
//!   BLAKE3-256 over a 33-byte SEC1-compressed P-256 public key, base32 encoded.
//! - [`keys`] — software-backed `P256Keypair` (Linux + tests).
//! - [`keys_se`] — macOS-only `P256SeKeypair` whose private scalar lives inside
//!   the Secure Enclave (`kSecAttrTokenIDSecureEnclave`).
//! - [`cbor`] — deterministic CBOR helpers (sorted map keys, definite-length).
//! - [`keystore`] — OS keystore wrapper (`keyring` crate on Linux, Keychain key
//!   reference on macOS).
//! - [`storage`] — atomic CBOR file I/O under `$THEYOS_STATE_DIR/household/`.
//! - [`household_record`] / [`machine_cert`] — on-disk Rust types matching
//!   `contracts/cbor-schemas.md`.
//! - [`chain`] — round-trip verifier used by US2 acceptance.
//! - [`bootstrap`] — orchestrates `bootstrap_or_load` (idempotent install path).
//! - [`pair_device`] — owner-device pairing token + window state machine
//!   consumed by the `/api/v1/household/pair-device/*` endpoints (FR-018).
//! - [`person_cert`] / [`owner_auth`] / [`pop`] / [`caveats`] — Phase 2 owner
//!   `PersonCert` issuance and Soyeht proof-of-possession validation.
//! - [`qr_render`] — terminal ANSI-block QR renderer for the install-time QR.
//!
//! Phase 1 invariants: see `specs/001-phase-1-crypto-skeleton/spec.md`.

// Single intentional `unsafe` lives in `bootstrap.rs` test code to mutate the
// `THEYOS_FORCE_SOFTWARE_KEYS` env var (Rust 2024 edition makes `set_var`
// unsafe). All production code paths are forbidden from using `unsafe`.
#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod bip39_wordlist;
pub mod bootstrap;
pub mod bootstrap_error;
pub mod bootstrap_state;
pub mod caveat_narrowing;
pub mod caveats;
pub mod cbor;
pub mod chain;
pub mod claw_share;
pub mod claw_share_data_tunnel;
pub mod claw_share_flow;
pub mod claw_share_relay;
pub mod claw_share_relay_stream_contract;
pub mod claw_share_relay_stream_endpoint;
pub mod claw_share_relay_stream_noise;
pub mod claw_share_rendezvous_hello;
pub mod claw_share_rendezvous_token;
pub mod claw_vpn;
#[cfg(test)]
pub mod claw_vpn_mobile_mesh_store;
#[cfg(test)]
pub mod claw_vpn_mobile_state;
/// Test-only park used by the crash-window harness. Not compiled into
/// production: every caller is a `#[cfg(test)]` fail-injection module.
#[cfg(test)]
pub(crate) mod crash_park;
pub mod device_admission;
pub mod device_cert;
pub mod emoji_code;
pub mod error;
pub mod fingerprint;
pub mod household_install_transaction;
pub mod household_lifecycle;
pub mod household_mesh_log;
pub mod household_record;
pub mod ids;
pub mod issuer_trust;
pub mod keys;
#[cfg(target_os = "macos")]
pub mod keys_se;
pub mod keystore;
pub mod machine_cert;
pub mod machine_roster_authority;
pub mod machine_roster_evidence;
pub mod machine_roster_store;
pub mod member_identity;
pub mod mesh_intent_nonce_ledger;
pub mod mesh_session_registry;
pub mod owner_approval_v2;
pub mod owner_auth;
pub mod owner_events;
pub mod owner_mesh_rendezvous_codec;
pub mod owner_webauthn;
pub mod owner_webauthn_anchor;
pub mod owner_webauthn_authority;
pub mod owner_webauthn_recovery;
pub mod owner_webauthn_recovery_anchor;
pub mod owner_webauthn_recovery_consume;
pub mod pair_device;
pub mod pair_machine;
pub mod pair_window_namespace;
pub mod person_cert;
pub mod pop;
pub mod qr_render;
pub mod secure_upgrade;
pub mod shamir;
pub mod shard_at_rest;
pub mod storage;
// S0 — the neutral tunnel wire mechanics that used to be `pub mod tunnel_wire`
// here now live in the `tunnel-wire-rs` crate. Not a rename: while they shared a
// crate with `claw_vpn`, "neutral" was a convention no instrument could check,
// and a crate-root `pub use` (there are ten below) reached claw authority
// without naming it. The dependency edge makes it a property instead.
// Consumers are unaffected: `claw_share_data_tunnel` re-exports the same names.

pub use bootstrap::{
    AcceptHouseholdConfirmError, AcceptHouseholdJoinChallenge, AcceptHouseholdPrepareOpts,
    BootstrapOpts, KeyBackingPolicy, LoadedIdentity, PendingAcceptHousehold, bootstrap_or_load,
    clear_pending_accept_household, confirm_accept_household, destroy_household_keystore_material,
    ensure_candidate_machine_keypair, load_pending_accept_household, pending_accept_household_path,
    prepare_accept_household, try_load_existing,
};
pub use chain::verify_loaded_chain;
pub use error::{BootstrapError, HouseholdError, KeystoreError, StorageError};
pub use household_record::HouseholdRecord;
pub use ids::{HouseholdId, MachineId, derive_household_id, derive_machine_id};
pub use keys::{IdentityKey, P256Keypair, P256PublicKey, P256Signature};
pub use machine_cert::{Caveat, CertType, DeviceId, MachineCert, PersonId, Platform, SubjectId};
pub use member_identity::{MemberDeviceBinding, MemberIdentityError, derive_member_id};
pub use owner_auth::HouseholdAuthState;
pub use person_cert::{PersonCert, derive_person_id};
