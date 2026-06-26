//! Process-wide async mutex covering every handler that mutates
//! bootstrap state (`bootstrap_state.json`) or household identity files
//! (`household_record.cbor`, `machine_cert.cbor`, the self-shard, or the
//! `PairMachineWindow`).
//!
//! Acquiring this lock serialises:
//!
//!   - `POST /bootstrap/initialize`
//!   - `POST /bootstrap/teardown`
//!   - `POST /api/v1/household/pair-device/confirm`
//!   - `POST /bootstrap/accept-household`
//!   - `POST /bootstrap/accept-household/confirm`
//!   - `POST /bootstrap/pair-machine/local/stage`
//!   - `POST /pair-machine/local/anchor` (when served by the daemon)
//!   - `POST /pair-machine/local/finalize` (when served by the daemon)
//!
//! Without serialisation, two of these can land concurrently and
//! overwrite each other's writes — most notably the TOCTOU race between
//! `accept_household_confirm` (which writes the founder's
//! `household_record.cbor` + `machine_cert.cbor`) and
//! `local_finalize_handler` (which writes the candidate's). Holding the
//! same mutex around the state-check + write step makes the second
//! arrival observe the committed state and refuse cleanly with the
//! contract's 401 / 409 surface rather than corrupting on-disk identity.
//!
//! The lock guards the full state transaction: the authoritative state
//! check, disk writes, in-memory state updates, and pairing-window mutation
//! must stay in one critical section. Long-running best-effort work (Bonjour
//! publish, detached cleanup, network probes) must run AFTER the guard is
//! dropped or be explicitly detached so it cannot extend the critical section.
//! See the call sites for the exact shape.

/// Single-process async mutex held by every handler that mutates
/// bootstrap state or household identity files. See module docs.
pub static BOOTSTRAP_MUTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
