//! Canonical production HTTP composition shared by the server binary and
//! Phase 0 boundary tests.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    response::Html,
    routing::{delete, get, patch, post, put},
};
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    auth::{self, require_auth},
    claw_store_routes, cloudflare_admin,
    config::Config,
    handlers_admin, handlers_instances, handlers_invites, handlers_jobs, handlers_misc,
    handlers_mobile, handlers_network, handlers_terminal, handlers_terminal_attachments, health,
    mobile_api_routes, mobile_claw_vpn_phase0, public_sites,
    state::SharedState,
};

async fn set_cache_control(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let is_asset = req.uri().path().starts_with("/assets/");
    let mut response = next.run(req).await;

    if is_asset {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else if response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/html"))
    {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache"),
        );
    }

    response
}

async fn rewrite_spa_404_to_200(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    if response.status() == axum::http::StatusCode::NOT_FOUND {
        let is_html = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html"));
        if is_html {
            *response.status_mut() = axum::http::StatusCode::OK;
        }
    }
    response
}

async fn handle_privacy() -> Html<&'static str> {
    Html(include_str!("privacy.html"))
}

/// Build the exact production app, including every route group, fallback, and
/// middleware layer. The final wrapper is the outermost Phase 0 deny boundary.
///
/// # Panics
///
/// Panics if `cfg.frontend_origin` is not a valid HTTP header value.
pub fn compose(state: &SharedState, cfg: &Config) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            cfg.frontend_origin
                .parse::<axum::http::HeaderValue>()
                .expect("Invalid FRONTEND_ORIGIN"),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_credentials(true);

    let index_path = format!("{}/index.html", cfg.web_dir);
    let spa_service = ServeDir::new(&cfg.web_dir).not_found_service(ServeFile::new(&index_path));

    let api_streaming = Router::new().route(
        "/terminals/{container}/pty",
        get(handlers_terminal::handle_terminal_pty),
    );

    let api_rest = Router::new()
        .route("/auth/logout", post(auth::handle_logout))
        .route("/me", get(auth::handle_me))
        .route("/claw-types", get(handlers_misc::handle_claw_types))
        .merge(claw_store_routes::admin_routes())
        .route("/version", get(handlers_misc::handle_version))
        .route("/logs", get(handlers_misc::handle_logs))
        .route(
            "/network/status",
            get(handlers_network::handle_network_status),
        )
        .route("/network/expose", post(handlers_network::handle_expose))
        .route("/jobs", get(handlers_jobs::handle_list_jobs))
        .route("/jobs/{id}", get(handlers_jobs::handle_get_job))
        .route("/instances", get(handlers_instances::handle_list_instances))
        .route(
            "/instances",
            post(handlers_instances::handle_create_instance_body),
        )
        .route(
            "/instances/{id}",
            get(handlers_instances::handle_get_instance),
        )
        .route(
            "/instances/{id}/status",
            get(handlers_instances::handle_instance_status),
        )
        .route(
            "/instances/{id}/public-sites",
            get(public_sites::handle_list_public_sites)
                .post(public_sites::handle_upsert_public_sites),
        )
        .route(
            "/instances/{id}/public-sites/{domain}",
            delete(public_sites::handle_delete_public_site),
        )
        .route(
            "/instances/{id}/stop",
            post(handlers_instances::handle_stop_instance),
        )
        .route(
            "/instances/{id}/restart",
            post(handlers_instances::handle_restart_instance),
        )
        .route(
            "/instances/{id}/rebuild",
            post(handlers_instances::handle_rebuild_instance),
        )
        .route(
            "/instances/{id}",
            delete(handlers_instances::handle_delete_instance),
        )
        .route(
            "/instances/{id}/autoupdate",
            post(handlers_instances::handle_instance_autoupdate),
        )
        .route(
            "/instances/{id}",
            patch(handlers_instances::handle_assign_owner),
        )
        .route(
            "/admin/warm-pool-status",
            get(handlers_admin::handle_warm_pool_status),
        )
        .route(
            "/admin/warm-pool-refill",
            post(handlers_admin::handle_warm_pool_refill),
        )
        .route(
            "/admin/warm-pool-init",
            post(handlers_admin::handle_warm_pool_init),
        )
        .route(
            "/admin/drain-warm-pool",
            post(handlers_admin::handle_drain_warm_pool),
        )
        .route("/admin/resources", get(handlers_admin::handle_resources))
        .route(
            "/admin/simulator-token",
            post(handlers_mobile::handle_simulator_token),
        )
        .route(
            "/admin/maintenance",
            get(handlers_admin::handle_maintenance_status),
        )
        .route(
            "/admin/cloudflare/status",
            get(cloudflare_admin::handle_status),
        )
        .route(
            "/admin/cloudflare/zones",
            post(cloudflare_admin::handle_list_zones),
        )
        .route(
            "/admin/cloudflare/setup",
            post(cloudflare_admin::handle_setup).delete(cloudflare_admin::handle_disconnect),
        )
        .route("/llm/catalog", get(crate::handlers_llm::handle_catalog))
        .route(
            "/llm/active",
            get(crate::handlers_llm::handle_get_active).put(crate::handlers_llm::handle_put_active),
        )
        .route(
            "/llm/active/{claw_type}",
            put(crate::handlers_llm::handle_put_active_claw)
                .delete(crate::handlers_llm::handle_delete_active_claw),
        )
        .route(
            "/llm/providers",
            get(crate::handlers_llm::handle_list_providers)
                .post(crate::handlers_llm::handle_upsert_provider),
        )
        .route(
            "/llm/providers/{id}",
            delete(crate::handlers_llm::handle_delete_provider),
        )
        .route(
            "/llm/providers/{id}/test",
            post(crate::handlers_llm::handle_test_provider),
        )
        .route("/llm/audit", get(crate::handlers_llm::handle_get_audit))
        .route(
            "/terminals/containers",
            get(handlers_terminal::handle_containers),
        )
        .route(
            "/terminals/{container}/reconnect",
            post(handlers_terminal::handle_terminal_reconnect),
        )
        .route(
            "/terminals/{container}/workspace",
            post(handlers_terminal::handle_terminal_workspace),
        )
        .route(
            "/terminals/{container}/workspaces",
            get(handlers_terminal::handle_list_conversations)
                .post(handlers_terminal::handle_create_conversation),
        )
        .route(
            "/terminals/{container}/workspaces/{id}",
            patch(handlers_terminal::handle_rename_conversation)
                .delete(handlers_terminal::handle_delete_conversation),
        )
        .route(
            "/terminals/{container}/files",
            get(handlers_terminal::handle_files_list),
        )
        .route(
            "/terminals/{container}/files/read",
            get(handlers_terminal::handle_files_read),
        )
        .route(
            "/terminals/{container}/files/download",
            get(handlers_terminal::handle_files_download),
        )
        .route(
            "/invites",
            get(handlers_invites::handle_list_invites).post(handlers_invites::handle_create_invite),
        )
        .route(
            "/invites/{id}",
            delete(handlers_invites::handle_delete_invite),
        )
        .route(
            "/instances/{id}/qr-token",
            post(handlers_mobile::handle_generate_qr_token),
        )
        .route(
            "/mobile/continue-qr",
            post(handlers_mobile::handle_generate_continue_qr),
        )
        .route(
            "/mobile/qr-status/{token}",
            get(handlers_mobile::handle_continue_qr_status),
        )
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ));

    let api_uploads = Router::new()
        .route(
            "/terminals/{container}/attachments",
            post(handlers_terminal_attachments::handle_upload_attachment),
        )
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(600),
        ));

    let api = api_rest
        .merge(api_streaming)
        .merge(api_uploads)
        .layer(middleware::from_fn_with_state(
            Arc::clone(state),
            require_auth,
        ))
        .with_state(Arc::clone(state));

    let app = Router::new()
        .route(
            "/health",
            get(health::handle_health).with_state(Arc::clone(state)),
        )
        .route(
            "/healthz",
            get(health::handle_health).with_state(Arc::clone(state)),
        )
        .route(
            "/readyz",
            get(health::handle_ready).with_state(Arc::clone(state)),
        )
        .route("/debugz", get(health::handle_debug))
        .route("/privacy", get(handle_privacy))
        .route(
            "/qr/{image_id}",
            get(handlers_mobile::handle_pair_qr_image).with_state(Arc::clone(state)),
        )
        .route(
            "/api/v1/auth/login",
            post(auth::handle_login).with_state(Arc::clone(state)),
        )
        .route(
            "/api/v1/invites/redeem",
            post(handlers_invites::handle_redeem_invite).with_state(Arc::clone(state)),
        )
        .route(
            "/api/v1/mobile/pair-token",
            post(handlers_mobile::handle_pair_token).with_state(Arc::clone(state)),
        )
        .merge(mobile_api_routes::routes(state))
        .nest("/api/v1", api)
        .fallback_service(spa_service)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(
            Arc::clone(state),
            public_sites::public_site_gateway,
        ))
        .layer(middleware::from_fn(rewrite_spa_404_to_200))
        .layer(middleware::from_fn(set_cache_control))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    mobile_claw_vpn_phase0::close_production_app(app)
}
