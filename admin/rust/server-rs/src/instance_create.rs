use crate::guest_image_state::GuestImageState;
use crate::state::SharedState;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use serde_json::json;
use store_rs::WarmPoolSlotId;

/// Best-effort cleanup for an instance row inserted before a later step failed.
///
/// This avoids leaving orphaned `provisioning` rows behind when create flows
/// fail after `instances.insert_with_leases()` but before the corresponding job is queued.
/// Releases all resource leases before deleting the row. When the create had
/// already claimed a warm-pool lease but failed before the executor started, the
/// warm-pool lease is restored so capacity accounting still matches reality.
pub async fn rollback_inserted_instance(
    state: &SharedState,
    instance_id: &str,
    failed_step: &str,
    restore_warm_pool_lease: bool,
) {
    let st = state.clone();
    let iid = instance_id.to_string();
    match blocking(move || {
        let row = if restore_warm_pool_lease {
            st.instance_db.get(&iid).ok().flatten()
        } else {
            None
        };

        // Release leases first (best-effort)
        if let Err(e) = st
            .instance_db
            .release_all_leases(LeaseOwnerType::Instance, &iid)
        {
            tracing::warn!(
                "[create-instance] failed to release leases for {iid} during rollback: {e}"
            );
        }

        if restore_warm_pool_lease {
            if let Some(row) = row.as_ref() {
                if let Err(e) = st.instance_db.create_lease(&store_rs::NewLease {
                    owner_type: LeaseOwnerType::WarmPool,
                    owner_id: &WarmPoolSlotId::new(&row.claw_type).owner_id(),
                    lease_kind: LeaseKind::Runtime,
                    cpu_cores: row.cpu_cores.unwrap_or(crate::capacity::SLOT_CPU),
                    ram_mb: row.ram_config_mb.unwrap_or(crate::capacity::SLOT_RAM),
                    disk_gb: 0,
                    expires_at: None,
                }) {
                    tracing::warn!(
                        "[create-instance] failed to restore warm-pool lease for {iid} during rollback: {e}"
                    );
                }
            }
        }
        st.instance_db.delete(&iid).map_err(ApiError::from)
    })
    .await
    {
        Ok(Ok(())) => {
            tracing::warn!(
                "[create-instance] rolled back inserted instance {instance_id} after {failed_step} failed"
            );
        }
        Ok(Err(e)) => {
            tracing::error!(
                "[create-instance] failed to roll back inserted instance {instance_id} after {failed_step} failed: {e}"
            );
        }
        Err(e) => {
            tracing::error!(
                "[create-instance] spawn_blocking failed while rolling back inserted instance {instance_id} after {failed_step} failed: {e}"
            );
        }
    }
}

/// macOS guest-image admission gate, shared by the admin and mobile/household
/// create paths so the `409 GUEST_IMAGE_NOT_READY` shape lives in exactly one
/// place. Returns `Some(conflict response)` when the host's guest image is not
/// yet `done`, else `None`.
///
/// Pure over the supplied state — the caller reads
/// `GuestImageState::read_current()` inside `#[cfg(target_os = "macos")]`, so
/// this is unit-testable on every platform without touching `init-state.json`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn guest_image_not_ready_response(guest: &GuestImageState) -> Option<Response> {
    if guest.status.as_deref() == Some("done") {
        return None;
    }
    Some(
        (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "macOS guest image is not ready",
                "code": "GUEST_IMAGE_NOT_READY",
                "guest_image_phase": guest.phase,
                "guest_image_status": guest.status,
                "guest_image_error": guest.error,
            })),
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_blocks_until_guest_image_done() {
        for status in ["pending", "in_progress", "failed"] {
            let guest = GuestImageState {
                status: Some(status.to_string()),
                ..Default::default()
            };
            let resp = guest_image_not_ready_response(&guest)
                .unwrap_or_else(|| panic!("status {status:?} must be gated"));
            assert_eq!(resp.status(), StatusCode::CONFLICT);
        }
        // No init-state.json yet (fresh / not started) gates too.
        let fresh = guest_image_not_ready_response(&GuestImageState::not_applicable())
            .expect("a fresh (not-started) guest image must be gated");
        assert_eq!(fresh.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn gate_allows_once_guest_image_done() {
        let done = GuestImageState {
            status: Some("done".to_string()),
            ..Default::default()
        };
        assert!(guest_image_not_ready_response(&done).is_none());
    }

    #[tokio::test]
    async fn gate_response_body_carries_the_failure_contract() {
        let guest = GuestImageState {
            phase: Some("install_macos".to_string()),
            status: Some("in_progress".to_string()),
            error: None,
            ..Default::default()
        };
        let resp = guest_image_not_ready_response(&guest).expect("must gate");
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(v["code"], "GUEST_IMAGE_NOT_READY");
        assert_eq!(v["guest_image_status"], "in_progress");
        assert_eq!(v["guest_image_phase"], "install_macos");
        assert!(
            v.as_object()
                .expect("object body")
                .contains_key("guest_image_error"),
            "the gate body must always carry guest_image_error (null when absent)"
        );
    }
}
