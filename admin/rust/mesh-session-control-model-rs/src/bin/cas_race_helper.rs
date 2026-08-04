//! Round 6: a real, separate-process CAS race participant.
//!
//! Exists solely so `tests/model_invariants.rs` can spawn genuinely
//! independent OS processes (not threads within one process, which would
//! all share the SAME process-local `MeshSignerLocks`/cell registry and
//! so could never demonstrate a cross-process race at all) against the
//! SAME record path, each with its own completely independent
//! `FileBackedStore`/`MeshSignerLocks` pair -- exactly the scenario the
//! in-process locking alone cannot protect against.
//!
//! Usage: `cas_race_helper <record-path> <worker-id: u8>`. Attempts one
//! `RevokeUrgent` commit from whatever revision is currently on disk and
//! prints exactly one line to stdout: `COMMITTED`, `NO_RECORD`, or
//! `REJECTED:<debug of the error>`.

use mesh_session_control_model_rs::cell;
use mesh_session_control_model_rs::locks::OrderSpy;
use mesh_session_control_model_rs::record::{
    Channel, ControlIdentity, PurposeId, RevocationReason,
};
use mesh_session_control_model_rs::store::LoadOutcome;
use mesh_session_control_model_rs::transition::RecordTransition;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = std::path::PathBuf::from(&args[1]);
    let worker_id: u8 = args[2].parse().expect("worker id must be a u8");

    let identity = ControlIdentity {
        hh_id: "hh_test".into(),
        machine_id: "m_test".into(),
        channel: Channel::Dev,
    };
    let cell = cell::open(
        path,
        identity,
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .expect("open should not conflict -- same identity/purpose every worker");

    if matches!(cell.load_canonical_for_test(), LoadOutcome::Missing) {
        println!("NO_RECORD");
        return;
    }

    let t = RecordTransition::RevokeUrgent {
        reason: RevocationReason::Compromised,
        txn_id: [worker_id; 16],
    };
    match cell.commit(&t, 1000, 100) {
        Ok(_) => println!("COMMITTED"),
        Err(e) => println!("REJECTED:{e:?}"),
    }
}
