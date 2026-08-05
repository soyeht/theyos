//! Shared fixtures. Extracted so `cas_multiprocess.rs` -- which needs a real
//! `CARGO_BIN_EXE_*` and must stay an integration target -- and
//! `model_invariants.rs` both use ONE definition instead of duplicating.

use mesh_session_control_model_rs::cell::{self, ControlRecordCell};
use mesh_session_control_model_rs::locks::OrderSpy;
use mesh_session_control_model_rs::record::{Channel, ControlIdentity, PurposeId};
use std::sync::Arc;

pub fn identity() -> ControlIdentity {
    ControlIdentity {
        hh_id: "hh_test".into(),
        machine_id: "m_test".into(),
        channel: Channel::Dev,
    }
}
pub fn test_cell(path: std::path::PathBuf) -> Arc<ControlRecordCell> {
    cell::open(
        path,
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .expect("fresh path, no prior live cell registered for it")
}
