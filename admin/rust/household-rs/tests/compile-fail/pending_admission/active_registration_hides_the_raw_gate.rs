// RED-10 (D-1 bounded admission, @kiana audit `caf6d1e4`, D5): the Active
// RAII wrapper must never yield the raw, clonable `SessionGate`. Handing it
// out would hand out an authorization that outlives the single owner whose
// `Drop` is supposed to retire the session.
use household_rs::mesh_session_registry::{ActiveSessionRegistration, RevocableMeshSession};

struct Session;

impl RevocableMeshSession for Session {
    fn send_best_effort_revoke_notice(&self) {}
    fn close(&self) {}
}

fn steal_the_gate(active: &ActiveSessionRegistration<'_, Session>) {
    let _ = &active.gate;
}

fn main() {}
