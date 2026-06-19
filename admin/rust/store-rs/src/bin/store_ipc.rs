//! store-ipc — JSON-RPC-over-stdin/stdout bridge for `InstanceDb` operations.
//!
//! Protocol: one JSON object per line on stdin, one JSON response per line on stdout.
//!
//! All commands open a fresh `SQLite` connection per request using the `db_path`
//! parameter. This is stateless by design so the orchestrator can call any
//! subset of commands in any order.

use core_rs::ipc::{harness::run_ipc_loop, wire::Response};
use serde_json::Value;
use store_rs::{InstanceDb, InstanceStatus, NewInstance, NewInstanceEvent, NewLease, StatusUpdate};

fn main() {
    run_ipc_loop("store-ipc", dispatch);
}

fn dispatch(method: &str, params: &Value) -> Response {
    match method {
        "InstanceDbInit" => handle_instancedb_init(params),
        "InstanceDbInsert" => handle_instancedb_insert(params),
        "InstanceDbFindConflict" => handle_instancedb_find_conflict(params),
        "InstanceDbGet" => handle_instancedb_get(params),
        "InstanceDbList" => handle_instancedb_list(params),
        "InstanceDbUpdateStatus" => handle_instancedb_update_status(params),
        "InstanceDbUpdatePort" => handle_instancedb_update_port(params),
        "InstanceDbClearPort" => handle_instancedb_clear_port(params),
        "InstanceDbSetVmNetwork" => handle_instancedb_set_vm_network(params),
        "InstanceDbDelete" => handle_instancedb_delete(params),
        "InstanceDbSetJobId" => handle_instancedb_set_job_id(params),
        "InstanceDbGetCfHostnameId" => handle_instancedb_get_cf_hostname_id(params),
        "ResourceLeaseCreate" => handle_lease_create(params),
        "ResourceLeaseRelease" => handle_lease_release(params),
        "ResourceLeaseReleaseAll" => handle_lease_release_all(params),
        "ResourceLeaseExtend" => handle_lease_extend(params),
        "ResourceLeaseFinalize" => handle_lease_finalize(params),
        "RecordInstanceEvent" => handle_record_instance_event(params),
        "SetDesiredState" => handle_set_desired_state(params),
        "SetObservedState" => handle_set_observed_state(params),
        "SoftDelete" => handle_soft_delete(params),
        other => Response::err(format!("unknown method: {other}")),
    }
}

// ─── InstanceDb helpers ───────────────────────────────────────────────────────

fn open_instance_db(params: &Value) -> Result<InstanceDb, Response> {
    let db_path = match params["db_path"].as_str() {
        Some(s) if !s.is_empty() => s,
        _ => return Err(Response::err("missing 'db_path' param")),
    };
    InstanceDb::open(db_path).map_err(|e| Response::err(e.to_string()))
}

fn instance_row_to_value(row: &store_rs::InstanceRow) -> Value {
    serde_json::json!({
        "id": row.id,
        "name": row.name,
        "container": row.container,
        "clawType": row.claw_type,
        "hostPort": row.host_port,
        "status": row.status.to_string(),
        "provisioningMessage": row.provisioning_message,
        "provisioningError": row.provisioning_error,
        "provisioningPhase": row.provisioning_phase,
        "jobId": row.job_id,
        "customDomain": row.custom_domain,
        "cfHostnameId": row.cf_hostname_id,
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
    })
}

fn handle_instancedb_init(params: &Value) -> Response {
    match open_instance_db(params) {
        Ok(_) => Response::ok(serde_json::json!({"ok": true})),
        Err(resp) => resp,
    }
}

fn handle_instancedb_insert(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(name) = params["name"].as_str() else {
        return Response::err("missing 'name' param");
    };
    let Some(container) = params["container"].as_str() else {
        return Response::err("missing 'container' param");
    };
    let Some(claw_type) = params["claw_type"].as_str() else {
        return Response::err("missing 'claw_type' param");
    };
    let sunset_date = params["sunset_date"].as_str().unwrap_or("");
    let guest_os = params["guest_os"].as_str();
    let aux_storage_path = params["aux_storage_path"].as_str();
    let cpu_cores = params["cpu_cores"].as_i64();
    let ram_config_mb = params["ram_config_mb"].as_i64();
    let disk_gb = params["disk_gb"].as_i64();
    match db.insert(&NewInstance {
        id,
        name,
        container,
        claw_type,
        sunset_date,
        guest_os,
        aux_storage_path,
        cpu_cores,
        ram_config_mb,
        disk_gb,
        household_id: None,
        household_machine_id: None,
    }) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_find_conflict(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(name) = params["name"].as_str() else {
        return Response::err("missing 'name' param");
    };
    match db.find_conflict(id, name) {
        Ok(existing) => Response::ok(serde_json::json!({"existingId": existing})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_get(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    match db.get(id) {
        Ok(Some(row)) => Response::ok(serde_json::json!({"row": instance_row_to_value(&row)})),
        Ok(None) => Response::ok(serde_json::json!({"row": null})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_list(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    match db.list() {
        Ok(rows) => {
            let items: Vec<Value> = rows.iter().map(instance_row_to_value).collect();
            Response::ok(serde_json::json!({"data": items}))
        }
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_update_status(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(status) = params["status"].as_str() else {
        return Response::err("missing 'status' param");
    };
    let message = params["message"].as_str().unwrap_or("");
    let error = params["error"].as_str().unwrap_or("");
    let job_id = params["job_id"].as_str().unwrap_or("");
    let phase = params["phase"].as_str().unwrap_or("");
    let status_val: InstanceStatus = match status.parse() {
        Ok(s) => s,
        Err(e) => return Response::err(format!("invalid status: {e}")),
    };
    match db.update_status(&StatusUpdate {
        id,
        status: status_val,
        message,
        error,
        job_id,
        phase,
    }) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_update_port(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(port) = params["port"].as_i64() else {
        return Response::err("missing 'port' param");
    };
    match db.update_port(id, port) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_clear_port(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    match db.clear_port(id) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_set_vm_network(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(container) = params["container"].as_str() else {
        return Response::err("missing 'container' param");
    };
    let Some(ip) = params["ip"].as_str() else {
        return Response::err("missing 'ip' param");
    };
    let Some(mac) = params["mac"].as_str() else {
        return Response::err("missing 'mac' param");
    };
    match db.set_vm_network(container, ip, mac) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_delete(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    match db.delete(id) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_set_job_id(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(job_id) = params["job_id"].as_str() else {
        return Response::err("missing 'job_id' param");
    };
    match db.set_job_id(id, job_id) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_instancedb_get_cf_hostname_id(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    match db.get_cf_hostname_id(id) {
        Ok(cf_id) => Response::ok(serde_json::json!({"cf_hostname_id": cf_id})),
        Err(e) => Response::err(e.to_string()),
    }
}

// ─── Resource Lease IPC handlers ────────────────────────────────────────────

fn handle_lease_create(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(owner_type) = params["owner_type"].as_str() else {
        return Response::err("missing 'owner_type' param");
    };
    let Some(owner_id) = params["owner_id"].as_str() else {
        return Response::err("missing 'owner_id' param");
    };
    let Some(lease_kind) = params["lease_kind"].as_str() else {
        return Response::err("missing 'lease_kind' param");
    };
    let cpu_cores = params["cpu_cores"].as_i64().unwrap_or(0);
    let ram_mb = params["ram_mb"].as_i64().unwrap_or(0);
    let disk_gb = params["disk_gb"].as_i64().unwrap_or(0);
    let expires_at = params["expires_at"].as_i64();
    match db.create_lease(&NewLease {
        owner_type,
        owner_id,
        lease_kind,
        cpu_cores,
        ram_mb,
        disk_gb,
        expires_at,
    }) {
        Ok(id) => Response::ok(serde_json::json!({"lease_id": id})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_lease_release(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(owner_type) = params["owner_type"].as_str() else {
        return Response::err("missing 'owner_type' param");
    };
    let Some(owner_id) = params["owner_id"].as_str() else {
        return Response::err("missing 'owner_id' param");
    };
    let Some(lease_kind) = params["lease_kind"].as_str() else {
        return Response::err("missing 'lease_kind' param");
    };
    match db.release_lease(owner_type, owner_id, lease_kind) {
        Ok(affected) => Response::ok(serde_json::json!({"released": affected})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_lease_release_all(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(owner_type) = params["owner_type"].as_str() else {
        return Response::err("missing 'owner_type' param");
    };
    let Some(owner_id) = params["owner_id"].as_str() else {
        return Response::err("missing 'owner_id' param");
    };
    match db.release_all_leases(owner_type, owner_id) {
        Ok(count) => Response::ok(serde_json::json!({"released_count": count})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_lease_extend(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(owner_type) = params["owner_type"].as_str() else {
        return Response::err("missing 'owner_type' param");
    };
    let Some(owner_id) = params["owner_id"].as_str() else {
        return Response::err("missing 'owner_id' param");
    };
    let Some(lease_kind) = params["lease_kind"].as_str() else {
        return Response::err("missing 'lease_kind' param");
    };
    let Some(new_expires_at) = params["new_expires_at"].as_i64() else {
        return Response::err("missing 'new_expires_at' param");
    };
    match db.extend_lease(owner_type, owner_id, lease_kind, new_expires_at) {
        Ok(affected) => Response::ok(serde_json::json!({"extended": affected})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_lease_finalize(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(owner_type) = params["owner_type"].as_str() else {
        return Response::err("missing 'owner_type' param");
    };
    let Some(owner_id) = params["owner_id"].as_str() else {
        return Response::err("missing 'owner_id' param");
    };
    let Some(lease_kind) = params["lease_kind"].as_str() else {
        return Response::err("missing 'lease_kind' param");
    };
    match db.finalize_lease(owner_type, owner_id, lease_kind) {
        Ok(affected) => Response::ok(serde_json::json!({"finalized": affected})),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_record_instance_event(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(event_type) = params["event_type"].as_str() else {
        return Response::err("missing 'event_type' param");
    };
    let actor = params["actor"].as_str().unwrap_or("system");
    let instance_id = params["instance_id"].as_str();
    let detail = params["detail"].as_str();
    let resource_snapshot = params["resource_snapshot"].as_str();
    match db.record_instance_event(&NewInstanceEvent {
        instance_id,
        event_type,
        actor,
        detail,
        resource_snapshot,
    }) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_set_desired_state(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(state_str) = params["desired_state"].as_str() else {
        return Response::err("missing 'desired_state' param");
    };
    let state: store_rs::DesiredState = match state_str.parse() {
        Ok(s) => s,
        Err(e) => return Response::err(format!("invalid desired_state: {e}")),
    };
    match db.set_desired_state(id, state) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_set_observed_state(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    let Some(state_str) = params["observed_state"].as_str() else {
        return Response::err("missing 'observed_state' param");
    };
    let state: store_rs::ObservedState = match state_str.parse() {
        Ok(s) => s,
        Err(e) => return Response::err(format!("invalid observed_state: {e}")),
    };
    match db.set_observed_state(id, state) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}

fn handle_soft_delete(params: &Value) -> Response {
    let db = match open_instance_db(params) {
        Ok(db) => db,
        Err(resp) => return resp,
    };
    let Some(id) = params["id"].as_str() else {
        return Response::err("missing 'id' param");
    };
    match db.soft_delete(id) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e.to_string()),
    }
}
