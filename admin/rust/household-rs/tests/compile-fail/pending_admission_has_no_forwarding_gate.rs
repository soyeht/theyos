use household_rs::mesh_session_registry::{PendingSessionAdmission, RevocableMeshSession};

struct Session;

impl RevocableMeshSession for Session {
    fn send_best_effort_revoke_notice(&self) {}
    fn close(&self) {}
}

fn try_to_forward(admission: &PendingSessionAdmission<'_, Session>) {
    let _ = admission.try_authorize_forwarding();
}

fn main() {}
