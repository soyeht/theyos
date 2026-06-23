//! Background task that reaps expired provisioning leases.
//!
//! When a create flow crashes or hangs, the runtime lease's `expires_at` eventually
//! passes. The reaper detects these expired leases, marks the corresponding instances
//! as Failed, and releases the expired runtime lease. Storage remains reserved
//! until explicit cleanup confirms disk is actually free.
//!
//! Runs every 60 seconds. Complementary to the startup reconcile (which handles
//! crash recovery for active instances).

use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use std::time::Duration;

use crate::state::SharedState;

/// Interval between reaper sweeps.
const REAPER_INTERVAL: Duration = Duration::from_secs(60);

/// Start the lease reaper as a background tokio task.
///
/// Returns immediately. The task runs until the tokio runtime shuts down.
pub fn start_lease_reaper(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("[lease-reaper] started (interval={REAPER_INTERVAL:?})");

        loop {
            tokio::time::sleep(REAPER_INTERVAL).await;

            let st = state.clone();
            let result = tokio::task::spawn_blocking(move || reap_expired_leases_once(&st)).await;

            match result {
                Ok(0) => {} // nothing to reap — common case, no log
                Ok(n) => tracing::warn!("[lease-reaper] reaped {n} expired lease(s)"),
                Err(e) => tracing::error!("[lease-reaper] task panicked: {e}"),
            }
        }
    })
}

/// Scan for expired runtime leases and clean them up.
///
/// Returns the number of leases reaped.
pub fn reap_expired_leases_once(state: &SharedState) -> u32 {
    let expired = match state.instance_db.expired_runtime_leases() {
        Ok(leases) => leases,
        Err(e) => {
            tracing::warn!("[lease-reaper] failed to query expired leases: {e}");
            return 0;
        }
    };

    let mut reaped = 0u32;

    for lease in &expired {
        let instance_id = &lease.owner_id;

        // Only reap instance leases (warm pool leases are handled by warm pool reconcile)
        if lease.owner_type != LeaseOwnerType::Instance.as_str() {
            continue;
        }

        tracing::warn!(
            "[lease-reaper] expired lease for instance {instance_id} \
             (acquired_at={}, expires_at={:?})",
            lease.acquired_at,
            lease.expires_at,
        );

        // Check if the instance still exists and is in a terminal state.
        // If the job already completed/failed, the lease should have been finalized/released
        // by the executor. Finding it here means something went wrong.
        let release_all = match state.instance_db.get(instance_id) {
            Ok(Some(row)) => {
                // Only reap if still provisioning. If already active/stopped/failed,
                // the lease is stale but the instance is fine — just release the lease.
                if row.status == store_rs::InstanceStatus::Provisioning {
                    // Mark instance as failed
                    if let Err(e) = state.instance_db.update_status(&store_rs::StatusUpdate {
                        id: instance_id,
                        status: store_rs::InstanceStatus::Failed,
                        message: "provisioning timed out (lease expired)",
                        error: "provisioning_timeout",
                        job_id: "",
                        phase: "",
                    }) {
                        tracing::warn!(
                            "[lease-reaper] failed to mark {instance_id} as failed: {e}"
                        );
                    }
                    if let Err(e) = state
                        .instance_db
                        .set_observed_state(instance_id, store_rs::ObservedState::Failed)
                    {
                        tracing::warn!(
                            "[lease-reaper] failed to set observed_state for {instance_id}: {e}"
                        );
                    }
                }
                false
            }
            Ok(None) => {
                // Instance row doesn't exist — just clean up the lease
                tracing::warn!("[lease-reaper] orphaned lease for missing instance {instance_id}");
                true
            }
            Err(e) => {
                tracing::warn!("[lease-reaper] failed to get instance {instance_id}: {e}");
                false
            }
        };

        if release_all {
            match state
                .instance_db
                .release_all_leases(LeaseOwnerType::Instance, instance_id)
            {
                Ok(n) => {
                    tracing::info!("[lease-reaper] released {n} lease(s) for {instance_id}");
                }
                Err(e) => {
                    tracing::warn!(
                        "[lease-reaper] failed to release leases for {instance_id}: {e}"
                    );
                }
            }
        } else if let Err(e) = state.instance_db.release_lease(
            LeaseOwnerType::Instance,
            instance_id,
            LeaseKind::Runtime,
        ) {
            tracing::warn!("[lease-reaper] failed to release runtime lease for {instance_id}: {e}");
        }

        let resource_snapshot = crate::capacity::capacity_snapshot_json(&state.instance_db).ok();

        // Record audit event
        if let Err(e) = state
            .instance_db
            .record_instance_event(&store_rs::NewInstanceEvent {
                instance_id: Some(instance_id),
                event_type: "provisioning_timeout",
                actor: "system",
                detail: Some("lease expired, runtime released by reaper"),
                resource_snapshot: resource_snapshot.as_deref(),
            })
        {
            tracing::warn!("[lease-reaper] failed to record event for {instance_id}: {e}");
        }

        reaped += 1;
    }

    reaped
}
