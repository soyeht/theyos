use household_rs::mesh_session_registry::{PendingSessionAdmission, RevocableMeshSession};

struct Session;

impl RevocableMeshSession for Session {
    fn send_best_effort_revoke_notice(&self) {}
    fn close(&self) {}
}

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<PendingSessionAdmission<'static, Session>>();
}
