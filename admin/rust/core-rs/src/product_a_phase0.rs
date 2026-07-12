//! Shared Phase 0 HTTP choke-point for every published Axum listener.

use axum::{
    Router,
    extract::Request,
    extract::connect_info::{ConnectInfo, Connected, IntoMakeServiceWithConnectInfo},
    http::{Method, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    serve::{IncomingStream, Listener, Serve},
};
use std::fmt::Debug;

const PRODUCT_A_HTTP_ROOT: &str = "/api/v1/mobile/claw-vpn";
const PRODUCT_A_STATUS_PATH: &str = "/api/v1/mobile/claw-vpn/status";

/// Wrap a complete application after all routes, fallbacks, and middleware
/// have been composed. Product A is default-deny outside GET/HEAD status.
pub fn close_http_app(app: Router) -> Router {
    app.layer(middleware::from_fn(reject_product_a_effect))
}

async fn reject_product_a_effect(req: Request, next: middleware::Next) -> Response {
    let path = req.uri().path();
    let is_product_a_path = path == PRODUCT_A_HTTP_ROOT
        || path
            .strip_prefix(PRODUCT_A_HTTP_ROOT)
            .is_some_and(|suffix| suffix.starts_with('/'));
    let status_read_only =
        path == PRODUCT_A_STATUS_PATH && matches!(req.method(), &Method::GET | &Method::HEAD);
    if is_product_a_path && !status_read_only {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

/// The only permitted production HTTP serve primitive. The implementation is
/// isolated here so callers cannot bypass the outer boundary with an alias.
#[allow(clippy::disallowed_methods)]
pub fn serve<L>(listener: L, app: Router) -> Serve<L, Router, Router>
where
    L: Listener + 'static,
    L::Addr: Debug,
{
    axum::serve(listener, close_http_app(app))
}

#[allow(clippy::disallowed_methods)]
pub fn serve_with_connect_info<L, C>(
    listener: L,
    app: Router,
) -> Serve<
    L,
    IntoMakeServiceWithConnectInfo<Router, C>,
    axum::middleware::AddExtension<Router, ConnectInfo<C>>,
>
where
    L: Listener + 'static,
    L::Addr: Debug,
    C: for<'a> Connected<IncomingStream<'a, L>>,
{
    axum::serve(
        listener,
        close_http_app(app).into_make_service_with_connect_info::<C>(),
    )
}

#[macro_export]
macro_rules! phase0_axum_serve {
    ($listener:expr, $router:expr) => {{ $crate::product_a_phase0::serve($listener, $router) }};
    ($listener:expr, $router:expr, connect_info = $connect_info:ty) => {{ $crate::product_a_phase0::serve_with_connect_info::<_, $connect_info>($listener, $router) }};
}
