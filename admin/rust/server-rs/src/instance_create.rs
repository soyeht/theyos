use crate::state::SharedState;
use core_rs::error::{ApiError, blocking};

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
        if let Err(e) = st.instance_db.release_all_leases("instance", &iid) {
            tracing::warn!(
                "[create-instance] failed to release leases for {iid} during rollback: {e}"
            );
        }

        if restore_warm_pool_lease {
            if let Some(row) = row.as_ref() {
                if let Err(e) = st.instance_db.create_lease(&store_rs::NewLease {
                    owner_type: "warm_pool",
                    owner_id: &format!("{}:slot:0", row.claw_type),
                    lease_kind: "runtime",
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
