//! server-rs library target — exposes handler modules for integration tests.

pub mod apns_dispatcher;
pub mod apns_push;
pub mod apns_tickle_transport;
pub mod artifact_installer;
pub mod artifact_resolver;
pub mod auth;
pub mod availability;
pub mod bonjour_browser;
#[cfg(target_os = "macos")]
pub mod bonjour_impl_dns_sd;
#[cfg(not(target_os = "macos"))]
pub mod bonjour_impl_mdns_sd;
pub mod bonjour_publisher;
pub mod bonjour_trust;
pub mod bootstrap_mutation_lock;
pub mod capacity;
pub mod claw_share_app_descriptor;
pub mod claw_share_data_tunnel_listener;
pub mod claw_share_pty_target;
pub mod claw_share_relay_loop;
pub mod claw_share_relay_offer_challenge;
pub mod claw_share_relay_stream_abuse;
pub mod claw_share_relay_stream_admission;
pub mod claw_share_relay_stream_contract;
pub mod claw_share_relay_stream_issuer_trust;
pub mod claw_share_relay_stream_mount;
pub mod claw_share_relay_stream_noise;
pub mod claw_share_relay_stream_noise_keystore;
pub mod claw_share_relay_stream_offer_store;
pub mod claw_share_relay_stream_provision;
pub mod claw_share_relay_stream_public_relay_config;
pub mod claw_share_relay_stream_reopen_limiter;
pub mod claw_share_relay_stream_responder;
pub mod claw_share_relay_stream_responder_config;
pub mod claw_share_relay_stream_responder_params;
pub mod claw_share_relay_stream_responder_reverse_connect;
pub mod claw_share_relay_stream_responder_server;
pub mod claw_share_relay_stream_reverse_connect_binding;
pub mod claw_share_relay_stream_reverse_connect_pool;
pub mod claw_share_relay_stream_runtime;
pub mod claw_share_relay_stream_session;
pub mod claw_share_relay_stream_target_router;
#[cfg(test)]
pub(crate) mod claw_share_relay_stream_test_support;
pub mod claw_share_relay_stream_trust_context_cache;
pub mod claw_share_relay_stream_trust_context_health;
pub mod claw_share_relay_stream_trust_refresh_driver;
pub mod claw_share_rendezvous_stream_relay;
pub mod claw_share_rendezvous_stream_relay_listener;
pub mod claw_share_rendezvous_stream_relay_status;
pub mod claw_share_session_clock;
pub mod claw_store_routes;
pub mod claw_store_service;
pub mod claw_vpn_dev_config;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_interface_route_plan;
#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "linux"))]
pub mod claw_vpn_linux_tun;
#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "macos"))]
pub mod claw_vpn_macos_utun;
// S0: the nonblocking-frame module moved to `tunnel_wire_rs::frame_stream`.
// It is byte-stream framing and partial-transfer bookkeeping — mechanics,
// with no decision about who may do what — so it travels with the wire types
// it is built on, and the duplicate that briefly existed here is gone.
//
// Its `#[cfg]` was deleted WITH it. Leaving the attribute behind is silent: an
// attribute skips comments and binds to the next ITEM, so the orphan landed
// on the packet pump module below, which then carried two. Identical
// conditions made it idempotent and nothing warned — but edit either copy and
// the module becomes their conjunction.
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_packet_pump;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_pollable_pump;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_relay_stream;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_runtime;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_t1_caller;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_t1_relay_stream_router;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_target_session_relay;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_target_session_router;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_target_session_runtime;
#[cfg(any(test, feature = "dev_t1_datapath"))]
pub mod claw_vpn_wiring;
pub mod cloudflare_admin;
pub mod cloudflare_api;
pub mod cloudflared_sync;
pub mod config;
#[cfg(any(test, feature = "failure-injection"))]
pub mod failure_injection;
pub mod folder_access_sentinel;
pub mod guest_image_state;
pub mod handlers_admin;
pub mod handlers_bootstrap;
pub mod handlers_claw_share;
pub mod handlers_claws;
pub mod handlers_device_pairing;
pub mod handlers_household;
pub mod handlers_household_claws;
pub mod handlers_household_guest_image;
pub mod handlers_household_roster;
pub mod handlers_instances;
pub mod handlers_invites;
pub mod handlers_jobs;
pub mod handlers_llm;
pub mod handlers_misc;
pub mod handlers_mobile;
pub mod handlers_network;
pub mod handlers_owner_events;
pub mod handlers_pair_device;
pub mod handlers_pair_machine;
pub mod handlers_sign_machine_cert;
pub mod handlers_terminal;
pub mod handlers_terminal_attachments;
pub mod health;
pub mod household_attach_token;
pub mod household_auth;
pub mod household_bootstrap;
pub mod household_listener;
pub mod household_state;
pub mod install_cli;
pub mod install_worker;
pub mod instance_create;
pub mod jobs_worker;
pub mod lease_reaper;
pub mod macos_local_caller_auth;
pub mod macos_local_registration_listener;
pub mod mobile_api_routes;
pub mod mobile_claw_vpn_phase0;
// Phase 0 compiles the owner-present model only into this crate's unit tests.
// Phase 1 must introduce a separately reviewed production target and wiring.
#[cfg(test)]
#[allow(dead_code)]
mod mobile_claw_vpn_owner_present_foundation;
pub mod mobile_token;
pub mod nonce_cache;
pub mod owner_cert_auth;
pub(crate) mod owner_site_a2_noise;
pub(crate) mod owner_site_a2_responder;
pub(crate) mod owner_site_a2_wire;
pub(crate) mod owner_site_ake;
pub(crate) mod owner_site_authority;
pub(crate) mod owner_site_binding_glue;
pub(crate) mod owner_site_capability;
pub(crate) mod owner_site_challenge;
pub(crate) mod owner_site_m3_verify;
pub(crate) mod owner_site_promotion;
pub(crate) mod owner_site_resolution_store;
pub(crate) mod owner_site_roster_adapter;
pub mod owner_webauthn_recovery_consume_rate_limit;
pub mod pair_machine_local;
pub mod production_app;
pub mod public_sites;
pub mod ratelimit;
pub mod reconcile;
pub mod responses;
pub mod setup_beacon;
pub mod setup_invitation;
pub mod shutdown;
pub mod startup_wiring;
pub mod state;
pub mod tailnet_address;
pub mod test_helpers;
pub mod time_util;
pub mod version;
pub mod warm_pool_reconciler;
