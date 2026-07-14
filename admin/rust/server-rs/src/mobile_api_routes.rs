//! Canonical mobile API route composition shared by the production binary and
//! its contract tests.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::{claw_store_routes, handlers_mobile, mobile_claw_vpn_phase0, state::SharedState};

/// Build the exact `/api/v1/mobile` surface mounted by the production server.
///
/// Product A contributes only [`mobile_claw_vpn_phase0::routes`]. Claw install
/// routes remain direct because their parameterized paths conflict with nested
/// Axum routes; keeping both branches here prevents tests from reconstructing a
/// parallel route graph.
pub fn routes(state: &SharedState) -> Router {
    let nested = Router::new()
        .route("/auth", post(handlers_mobile::handle_mobile_auth))
        .route("/pair", post(handlers_mobile::handle_pair))
        .route("/status", get(handlers_mobile::handle_mobile_status))
        .route(
            "/instances",
            get(handlers_mobile::handle_mobile_instances)
                .post(handlers_mobile::handle_mobile_create_instance),
        )
        .route(
            "/instances/{id}/status",
            get(handlers_mobile::handle_mobile_instance_status),
        )
        .route("/logout", post(handlers_mobile::handle_mobile_logout))
        .route("/users", get(handlers_mobile::handle_mobile_users))
        .route(
            "/server-info",
            get(handlers_mobile::handle_mobile_server_info),
        )
        .route(
            "/resource-options",
            get(handlers_mobile::handle_resource_options),
        )
        .merge(mobile_claw_vpn_phase0::routes())
        .merge(claw_store_routes::mobile_nested_routes())
        .with_state(Arc::clone(state));

    Router::new()
        .merge(claw_store_routes::mobile_direct_routes(Arc::clone(state)))
        .nest("/api/v1/mobile", nested)
}
