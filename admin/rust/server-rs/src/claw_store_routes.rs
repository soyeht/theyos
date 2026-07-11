//! Claw Store route registry and Axum mount helpers.
//!
//! This is the single Rust owner for Claw Store route literals and their
//! current handler bindings. The v1 contract tests compare
//! `admin/contracts/claw-store/v1/contract.json` against this registry.

use std::sync::Arc;

use crate::{
    handlers_claws, handlers_household_claws, handlers_household_claws::HouseholdClawsState,
    handlers_mobile, state::SharedState,
};
use axum::{
    Router,
    routing::{get, post},
};

pub mod admin {
    pub const LIST: &str = "/claws";
    pub const DETAIL: &str = "/claws/{name}";
    pub const AVAILABILITY: &str = "/claws/{name}/availability";
    pub const INSTALL: &str = "/claws/{name}/install";
    pub const UNINSTALL: &str = "/claws/{name}/uninstall";
    pub const RESOURCE_OPTIONS: &str = "/resource-options";
    pub const USERS: &str = "/users";
    pub const CREATE_INSTANCE: &str = "/instances";
    pub const INSTANCE_STATUS: &str = "/instances/{id}/status";
    pub const STOP_INSTANCE: &str = "/instances/{id}/stop";
    pub const RESTART_INSTANCE: &str = "/instances/{id}/restart";
    pub const REBUILD_INSTANCE: &str = "/instances/{id}/rebuild";
    pub const DELETE_INSTANCE: &str = "/instances/{id}";
    pub const WORKSPACES: &str = "/terminals/{container}/workspaces";
    pub const WORKSPACE: &str = "/terminals/{container}/workspaces/{id}";
    pub const PTY: &str = "/terminals/{container}/pty";

    pub const LIST_PATH: &str = "/api/v1/claws";
    pub const DETAIL_PATH: &str = "/api/v1/claws/{name}";
    pub const AVAILABILITY_PATH: &str = "/api/v1/claws/{name}/availability";
    pub const INSTALL_PATH: &str = "/api/v1/claws/{name}/install";
    pub const UNINSTALL_PATH: &str = "/api/v1/claws/{name}/uninstall";
    pub const RESOURCE_OPTIONS_PATH: &str = "/api/v1/resource-options";
    pub const USERS_PATH: &str = "/api/v1/users";
    pub const CREATE_INSTANCE_PATH: &str = "/api/v1/instances";
    pub const INSTANCE_STATUS_PATH: &str = "/api/v1/instances/{id}/status";
    pub const STOP_INSTANCE_PATH: &str = "/api/v1/instances/{id}/stop";
    pub const RESTART_INSTANCE_PATH: &str = "/api/v1/instances/{id}/restart";
    pub const REBUILD_INSTANCE_PATH: &str = "/api/v1/instances/{id}/rebuild";
    pub const DELETE_INSTANCE_PATH: &str = "/api/v1/instances/{id}";
    pub const WORKSPACES_PATH: &str = "/api/v1/terminals/{container}/workspaces";
    pub const WORKSPACE_PATH: &str = "/api/v1/terminals/{container}/workspaces/{id}";
    pub const PTY_PATH: &str = "/api/v1/terminals/{container}/pty";
}

pub mod mobile {
    pub const LIST: &str = "/claws";
    pub const CREATE_INSTANCE: &str = "/instances";
    pub const INSTANCE_STATUS: &str = "/instances/{id}/status";
    pub const AVAILABILITY: &str = "/api/v1/mobile/claws/{name}/availability";
    pub const INSTALL: &str = "/api/v1/mobile/claws/{name}/install";
    pub const UNINSTALL: &str = "/api/v1/mobile/claws/{name}/uninstall";

    pub const LIST_PATH: &str = "/api/v1/mobile/claws";
    pub const CREATE_INSTANCE_PATH: &str = "/api/v1/mobile/instances";
    pub const INSTANCE_STATUS_PATH: &str = "/api/v1/mobile/instances/{id}/status";
    pub const AVAILABILITY_PATH: &str = "/api/v1/mobile/claws/{name}/availability";
    pub const INSTALL_PATH: &str = "/api/v1/mobile/claws/{name}/install";
    pub const UNINSTALL_PATH: &str = "/api/v1/mobile/claws/{name}/uninstall";
}

pub mod household {
    pub const LIST: &str = "/api/v1/household/claws";
    pub const AVAILABILITY: &str = "/api/v1/household/claws/{name}/availability";
    pub const INSTALL: &str = "/api/v1/household/claws/{name}/install";
    pub const UNINSTALL: &str = "/api/v1/household/claws/{name}/uninstall";
    pub const CREATE_INSTANCE: &str = "/api/v1/household/instances";
    pub const INSTANCE_STATUS: &str = "/api/v1/household/instances/{id}/status";
    pub const STOP_INSTANCE: &str = "/api/v1/household/instances/{id}/stop";
    pub const RESTART_INSTANCE: &str = "/api/v1/household/instances/{id}/restart";
    pub const REBUILD_INSTANCE: &str = "/api/v1/household/instances/{id}/rebuild";
    pub const DELETE_INSTANCE: &str = "/api/v1/household/instances/{id}";
    pub const WORKSPACES: &str = "/api/v1/household/terminals/{container}/workspaces";
    pub const WORKSPACE: &str = "/api/v1/household/terminals/{container}/workspaces/{id}";
    pub const ATTACH_TOKEN: &str = "/api/v1/household/terminals/{container}/attach-token";
    pub const PTY: &str = "/api/v1/household/terminals/{container}/pty";
}

pub const METHOD_GET: &str = "GET";
pub const METHOD_POST: &str = "POST";
pub const METHOD_PATCH: &str = "PATCH";
pub const METHOD_DELETE: &str = "DELETE";
pub const KIND_HTTP_JSON: &str = "http_json";
pub const KIND_WEBSOCKET_UPGRADE: &str = "websocket_upgrade";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClawStoreRouteSpec {
    pub id: &'static str,
    pub surface: &'static str,
    pub method: &'static str,
    pub path_template: &'static str,
    pub mount_file: &'static str,
    pub mount_slice: &'static str,
    pub route_literal: &'static str,
    pub route_expr: &'static str,
    pub household_operation: Option<&'static str>,
}

impl ClawStoreRouteSpec {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.id {
            "admin_terminal_pty" | "household_terminal_pty" => KIND_WEBSOCKET_UPGRADE,
            _ => KIND_HTTP_JSON,
        }
    }
}

pub const ROUTES: &[ClawStoreRouteSpec] = &[
    ClawStoreRouteSpec {
        id: "admin_list_claws",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::LIST_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::LIST,
        route_expr: "admin::LIST",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_get_claw",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::DETAIL_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::DETAIL,
        route_expr: "admin::DETAIL",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_claw_availability",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::AVAILABILITY_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::AVAILABILITY,
        route_expr: "admin::AVAILABILITY",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_install_claw",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::INSTALL_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::INSTALL,
        route_expr: "admin::INSTALL",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_uninstall_claw",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::UNINSTALL_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::UNINSTALL,
        route_expr: "admin::UNINSTALL",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_resource_options",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::RESOURCE_OPTIONS_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::RESOURCE_OPTIONS,
        route_expr: "admin::RESOURCE_OPTIONS",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_users",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::USERS_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "admin_routes",
        route_literal: admin::USERS,
        route_expr: "admin::USERS",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_create_instance",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::CREATE_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::CREATE_INSTANCE,
        route_expr: "\"/instances\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_instance_status",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::INSTANCE_STATUS_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::INSTANCE_STATUS,
        route_expr: "\"/instances/{id}/status\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_stop_instance",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::STOP_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::STOP_INSTANCE,
        route_expr: "\"/instances/{id}/stop\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_restart_instance",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::RESTART_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::RESTART_INSTANCE,
        route_expr: "\"/instances/{id}/restart\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_rebuild_instance",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::REBUILD_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::REBUILD_INSTANCE,
        route_expr: "\"/instances/{id}/rebuild\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_delete_instance",
        surface: "admin",
        method: METHOD_DELETE,
        path_template: admin::DELETE_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::DELETE_INSTANCE,
        route_expr: "delete(handlers_instances::handle_delete_instance)",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_list_workspaces",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::WORKSPACES_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::WORKSPACES,
        route_expr: "\"/terminals/{container}/workspaces\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_create_workspace",
        surface: "admin",
        method: METHOD_POST,
        path_template: admin::WORKSPACES_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::WORKSPACES,
        route_expr: "\"/terminals/{container}/workspaces\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_rename_workspace",
        surface: "admin",
        method: METHOD_PATCH,
        path_template: admin::WORKSPACE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::WORKSPACE,
        route_expr: "\"/terminals/{container}/workspaces/{id}\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_delete_workspace",
        surface: "admin",
        method: METHOD_DELETE,
        path_template: admin::WORKSPACE_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_rest",
        route_literal: admin::WORKSPACE,
        route_expr: "\"/terminals/{container}/workspaces/{id}\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "admin_terminal_pty",
        surface: "admin",
        method: METHOD_GET,
        path_template: admin::PTY_PATH,
        mount_file: "admin/rust/server-rs/src/main.rs",
        mount_slice: "main_api_streaming",
        route_literal: admin::PTY,
        route_expr: "\"/terminals/{container}/pty\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_list_claws",
        surface: "mobile",
        method: METHOD_GET,
        path_template: mobile::LIST_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "mobile_nested_routes",
        route_literal: mobile::LIST,
        route_expr: "mobile::LIST",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_create_instance",
        surface: "mobile",
        method: METHOD_POST,
        path_template: mobile::CREATE_INSTANCE_PATH,
        mount_file: "admin/rust/server-rs/src/mobile_api_routes.rs",
        mount_slice: "routes",
        route_literal: mobile::CREATE_INSTANCE,
        route_expr: "\"/instances\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_instance_status",
        surface: "mobile",
        method: METHOD_GET,
        path_template: mobile::INSTANCE_STATUS_PATH,
        mount_file: "admin/rust/server-rs/src/mobile_api_routes.rs",
        mount_slice: "routes",
        route_literal: mobile::INSTANCE_STATUS,
        route_expr: "\"/instances/{id}/status\"",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_claw_availability",
        surface: "mobile",
        method: METHOD_GET,
        path_template: mobile::AVAILABILITY_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "mobile_direct_routes",
        route_literal: mobile::AVAILABILITY,
        route_expr: "mobile::AVAILABILITY",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_install_claw",
        surface: "mobile",
        method: METHOD_POST,
        path_template: mobile::INSTALL_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "mobile_direct_routes",
        route_literal: mobile::INSTALL,
        route_expr: "mobile::INSTALL",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "mobile_uninstall_claw",
        surface: "mobile",
        method: METHOD_POST,
        path_template: mobile::UNINSTALL_PATH,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "mobile_direct_routes",
        route_literal: mobile::UNINSTALL,
        route_expr: "mobile::UNINSTALL",
        household_operation: None,
    },
    ClawStoreRouteSpec {
        id: "household_list_claws",
        surface: "household",
        method: METHOD_GET,
        path_template: household::LIST,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "household_routes",
        route_literal: household::LIST,
        route_expr: "household::LIST",
        household_operation: Some("claws.list"),
    },
    ClawStoreRouteSpec {
        id: "household_claw_availability",
        surface: "household",
        method: METHOD_GET,
        path_template: household::AVAILABILITY,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "household_routes",
        route_literal: household::AVAILABILITY,
        route_expr: "household::AVAILABILITY",
        household_operation: Some("claws.list"),
    },
    ClawStoreRouteSpec {
        id: "household_install_claw",
        surface: "household",
        method: METHOD_POST,
        path_template: household::INSTALL,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "household_routes",
        route_literal: household::INSTALL,
        route_expr: "household::INSTALL",
        household_operation: Some("claws.create"),
    },
    ClawStoreRouteSpec {
        id: "household_uninstall_claw",
        surface: "household",
        method: METHOD_POST,
        path_template: household::UNINSTALL,
        mount_file: "admin/rust/server-rs/src/claw_store_routes.rs",
        mount_slice: "household_routes",
        route_literal: household::UNINSTALL,
        route_expr: "household::UNINSTALL",
        household_operation: Some("claws.delete"),
    },
    ClawStoreRouteSpec {
        id: "household_list_instances",
        surface: "household",
        method: METHOD_GET,
        path_template: household::CREATE_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::CREATE_INSTANCE,
        route_expr: "\"/api/v1/household/instances\"",
        household_operation: Some("claws.list"),
    },
    ClawStoreRouteSpec {
        id: "household_create_instance",
        surface: "household",
        method: METHOD_POST,
        path_template: household::CREATE_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::CREATE_INSTANCE,
        route_expr: "\"/api/v1/household/instances\"",
        household_operation: Some("claws.create"),
    },
    ClawStoreRouteSpec {
        id: "household_instance_status",
        surface: "household",
        method: METHOD_GET,
        path_template: household::INSTANCE_STATUS,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::INSTANCE_STATUS,
        route_expr: "\"/api/v1/household/instances/{id}/status\"",
        household_operation: Some("claws.list"),
    },
    ClawStoreRouteSpec {
        id: "household_stop_instance",
        surface: "household",
        method: METHOD_POST,
        path_template: household::STOP_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::STOP_INSTANCE,
        route_expr: "\"/api/v1/household/instances/{id}/stop\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_restart_instance",
        surface: "household",
        method: METHOD_POST,
        path_template: household::RESTART_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::RESTART_INSTANCE,
        route_expr: "\"/api/v1/household/instances/{id}/restart\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_rebuild_instance",
        surface: "household",
        method: METHOD_POST,
        path_template: household::REBUILD_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::REBUILD_INSTANCE,
        route_expr: "\"/api/v1/household/instances/{id}/rebuild\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_delete_instance",
        surface: "household",
        method: METHOD_DELETE,
        path_template: household::DELETE_INSTANCE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::DELETE_INSTANCE,
        route_expr: "\"/api/v1/household/instances/{id}\"",
        household_operation: Some("claws.delete"),
    },
    ClawStoreRouteSpec {
        id: "household_list_workspaces",
        surface: "household",
        method: METHOD_GET,
        path_template: household::WORKSPACES,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::WORKSPACES,
        route_expr: "\"/api/v1/household/terminals/{container}/workspaces\"",
        household_operation: Some("claws.list"),
    },
    ClawStoreRouteSpec {
        id: "household_create_workspace",
        surface: "household",
        method: METHOD_POST,
        path_template: household::WORKSPACES,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::WORKSPACES,
        route_expr: "\"/api/v1/household/terminals/{container}/workspaces\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_rename_workspace",
        surface: "household",
        method: METHOD_PATCH,
        path_template: household::WORKSPACE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::WORKSPACE,
        route_expr: "\"/api/v1/household/terminals/{container}/workspaces/{id}\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_delete_workspace",
        surface: "household",
        method: METHOD_DELETE,
        path_template: household::WORKSPACE,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::WORKSPACE,
        route_expr: "\"/api/v1/household/terminals/{container}/workspaces/{id}\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_attach_token",
        surface: "household",
        method: METHOD_POST,
        path_template: household::ATTACH_TOKEN,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::ATTACH_TOKEN,
        route_expr: "\"/api/v1/household/terminals/{container}/attach-token\"",
        household_operation: Some("claws.use"),
    },
    ClawStoreRouteSpec {
        id: "household_terminal_pty",
        surface: "household",
        method: METHOD_GET,
        path_template: household::PTY,
        mount_file: "admin/rust/server-rs/src/household_bootstrap.rs",
        mount_slice: "household_claws_router",
        route_literal: household::PTY,
        route_expr: "\"/api/v1/household/terminals/{container}/pty\"",
        household_operation: None,
    },
];

#[must_use]
pub fn route_by_id(id: &str) -> Option<&'static ClawStoreRouteSpec> {
    ROUTES.iter().find(|route| route.id == id)
}

pub fn admin_routes() -> Router<SharedState> {
    Router::new()
        .route(admin::LIST, get(handlers_claws::handle_list_claws))
        .route(admin::DETAIL, get(handlers_claws::handle_get_claw))
        .route(
            admin::AVAILABILITY,
            get(handlers_claws::handle_claw_availability),
        )
        .route(admin::INSTALL, post(handlers_claws::handle_install_claw))
        .route(
            admin::UNINSTALL,
            post(handlers_claws::handle_uninstall_claw),
        )
        .route(
            admin::RESOURCE_OPTIONS,
            get(handlers_mobile::handle_admin_resource_options),
        )
        .route(admin::USERS, get(handlers_mobile::handle_admin_users))
}

pub fn mobile_nested_routes() -> Router<SharedState> {
    Router::new().route(mobile::LIST, get(handlers_mobile::handle_mobile_claws))
}

pub fn mobile_direct_routes(state: SharedState) -> Router {
    Router::new()
        .route(
            mobile::INSTALL,
            post(handlers_mobile::handle_mobile_install_claw).with_state(Arc::clone(&state)),
        )
        .route(
            mobile::UNINSTALL,
            post(handlers_mobile::handle_mobile_uninstall_claw).with_state(Arc::clone(&state)),
        )
        .route(
            mobile::AVAILABILITY,
            get(handlers_mobile::handle_mobile_claw_availability).with_state(state),
        )
}

pub fn household_routes() -> Router<HouseholdClawsState> {
    Router::new()
        .route(
            household::LIST,
            get(handlers_household_claws::handle_household_list_claws),
        )
        .route(
            household::AVAILABILITY,
            get(handlers_household_claws::handle_household_claw_availability),
        )
        .route(
            household::INSTALL,
            post(handlers_household_claws::handle_household_install_claw),
        )
        .route(
            household::UNINSTALL,
            post(handlers_household_claws::handle_household_uninstall_claw),
        )
}
