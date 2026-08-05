use std::sync::Weak;

use household_rs::machine_roster_authority::SealedBinding;
use household_rs::mesh_session_registry::{MeshSessionRegistry, RevocableMeshSession};

struct Session;

impl RevocableMeshSession for Session {
    fn send_best_effort_revoke_notice(&self) {}
    fn close(&self) {}
}

fn bypass_ack_boundary(
    registry: &MeshSessionRegistry<Session>,
    binding: &SealedBinding,
    handle: Weak<Session>,
) {
    let _ = registry.register(binding, handle);
}

fn main() {}
