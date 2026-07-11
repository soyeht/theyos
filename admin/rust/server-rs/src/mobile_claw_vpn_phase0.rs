//! Phase 0 Product A status surface.
//!
//! The production server exposes only this count-free, read-only status. The
//! owner/admin mutators, offer/session issuer, rendezvous authorization, mesh
//! store, and relay responder are absent from the production dependency graph.

use crate::{handlers_mobile::extract_mobile_bearer, state::SharedState};
use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use core_rs::error::ApiError;
use serde::Serialize;

pub const STATUS_PATH: &str = "/claw-vpn/status";

#[derive(Serialize)]
struct Phase0Status {
    product: &'static str,
    phase: &'static str,
    production_activation: bool,
    state: &'static str,
}

/// Complete Product A route set shipped in Phase 0.
pub fn routes() -> Router<SharedState> {
    Router::new().route(STATUS_PATH, get(handle_status))
}

/// Machine-readable contract emitted by the production artifact's
/// `--owner-present-phase0-contract` command before daemon initialization.
#[must_use]
pub fn artifact_contract() -> serde_json::Value {
    serde_json::json!({
        "schema": "theyos-owner-present-phase0-artifact-contract-v1",
        "authority": "none",
        "phase": "phase0_compile_out",
        "production_activation": false,
        "mobile_route_prefix": "/api/v1/mobile",
        "declared_product_a_routes": [STATUS_PATH],
        "third_target_injection_seam_compiled":
            cfg!(any(test, feature = "dev_t1_datapath")),
        "generic_ip_tunnel_backend_compiled":
            crate::claw_share_relay_stream_offer_store::IP_TUNNEL_RESOURCE_COMPILED,
        "generic_ip_tunnel_store_accepts_resource":
            crate::claw_share_relay_stream_offer_store::phase0_ip_tunnel_store_accepts_resource(),
        "generic_ip_tunnel_env_accepts_resource":
            crate::claw_share_relay_stream_mount::phase0_ip_tunnel_env_accepts_resource(),
        "state": "unavailable"
    })
}

/// Read-only status for clients that know the Product A endpoint.
pub async fn handle_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    Ok(Json(Phase0Status {
        product: "product_a_mobile_claw_vpn",
        phase: "phase0_compile_out",
        production_activation: false,
        state: "unavailable",
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase0_status_contains_no_authority_or_mesh_counts() {
        let value = serde_json::to_value(Phase0Status {
            product: "product_a_mobile_claw_vpn",
            phase: "phase0_compile_out",
            production_activation: false,
            state: "unavailable",
        })
        .unwrap();
        assert_eq!(value["phase"], "phase0_compile_out");
        assert_eq!(value["production_activation"], false);
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value.as_object().unwrap().len(), 4);
    }

    #[test]
    fn artifact_contract_is_status_only_and_non_authoritative() {
        let value = artifact_contract();
        assert_eq!(value["authority"], "none");
        assert_eq!(value["production_activation"], false);
        assert_eq!(
            value["declared_product_a_routes"],
            serde_json::json!([STATUS_PATH])
        );
        assert_eq!(value["third_target_injection_seam_compiled"], true);
        assert_eq!(
            value["generic_ip_tunnel_backend_compiled"],
            crate::claw_share_relay_stream_offer_store::IP_TUNNEL_RESOURCE_COMPILED
        );
        assert_eq!(
            value["generic_ip_tunnel_store_accepts_resource"],
            crate::claw_share_relay_stream_offer_store::phase0_ip_tunnel_store_accepts_resource()
        );
        assert_eq!(
            value["generic_ip_tunnel_env_accepts_resource"],
            crate::claw_share_relay_stream_mount::phase0_ip_tunnel_env_accepts_resource()
        );
    }
}
