//! Dev-only standalone relay for the Product A `relay_stream` smoke (C7c-2c-d).
//!
//! This binary is NOT wired into the engine, `household_bootstrap`, or `main`:
//! it runs only when invoked explicitly, so it is default-off by construction.
//! It binds a loopback TCP relay — the blind rendezvous splicer — so that a
//! guest (friend-cli) and a claw (the engine's reverse-connect pool) can pair on
//! a shared rendezvous token for a LOCAL dev smoke.
//!
//! It is a thin wrapper over the existing test-only listener: it reads its bind
//! address from `THEYOS_RELAY_STREAM_RELAY_ENDPOINT` (default `127.0.0.1:49152`
//! — the SAME env the engine uses for the offer's `relay_endpoint` and the
//! reverse-connect pool's dial target, so the relay binds exactly where both
//! sides dial; single source, no divergence) and calls the explicit-address
//! helper [`spawn_rendezvous_stream_relay`], which reuses the listener's
//! loopback-only, fail-closed bind validation. No process-env mutation.
//!
//! Default is loopback-only. For a remote/CGNAT smoke (C7d-2) the bind can be
//! opened to a public `IP:port` by setting `THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_BIND=1`,
//! which switches to [`spawn_rendezvous_stream_relay_allow_public`] (loopback
//! check skipped). This is TEST-ONLY with NO production hardening: run it only
//! during a supervised test window and never in production. Without the flag the
//! behavior is unchanged — loopback-only, fail-closed.
//!
//! The relay has no Noise and no confidentiality on its own wire: the
//! guest<->claw payload is Noise-encrypted end to end; the relay only ever sees
//! the plaintext rendezvous hello and then opaque ciphertext, which it splices
//! blind. It logs no payload and no rendezvous token — only the loopback bind
//! address.

use server_rs::claw_share_rendezvous_stream_relay_listener::{
    spawn_rendezvous_stream_relay, spawn_rendezvous_stream_relay_allow_public,
};

/// Mirror of `claw_share_relay_stream_mount`'s engine-side endpoint env (kept in
/// sync; that const is crate-private to the mount module).
const RELAY_STREAM_RELAY_ENDPOINT_ENV: &str = "THEYOS_RELAY_STREAM_RELAY_ENDPOINT";
const DEFAULT_RELAY_STREAM_RELAY_ENDPOINT: &str = "127.0.0.1:49152";

/// Opt-in flag (C7d-2) to allow a NON-loopback public bind for a remote/CGNAT
/// smoke. Default-off: unset/anything-but-`1` keeps the loopback-only path.
const ALLOW_PUBLIC_BIND_ENV: &str = "THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_BIND";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind_addr = std::env::var(RELAY_STREAM_RELAY_ENDPOINT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_RELAY_STREAM_RELAY_ENDPOINT.to_string());

    let allow_public = std::env::var(ALLOW_PUBLIC_BIND_ENV)
        .map(|value| value.trim() == "1")
        .unwrap_or(false);

    let handle = if allow_public {
        // TEST-ONLY public bind: loopback check skipped on explicit opt-in. No
        // production hardening — run only during a supervised test window.
        eprintln!(
            "WARNING: {ALLOW_PUBLIC_BIND_ENV}=1 — binding relay_stream dev relay on PUBLIC \
             address {bind_addr}. This is a TEST-ONLY splicer with NO production hardening \
             (no auth/TLS on the rendezvous hello, only in-memory caps). Run it only for the \
             duration of the smoke and stop it afterward. Never use in production."
        );
        spawn_rendezvous_stream_relay_allow_public(&bind_addr).await?
    } else {
        // Explicit-address helper: reuses the listener's loopback-only fail-closed
        // bind validation; a non-loopback address errors out here.
        let handle = spawn_rendezvous_stream_relay(&bind_addr).await?;
        eprintln!(
            "relay_stream dev relay listening on {bind_addr} (loopback, test-only splicer); Ctrl-C to stop"
        );
        handle
    };

    tokio::signal::ctrl_c().await?;
    eprintln!("relay_stream dev relay shutting down");
    handle.abort();
    Ok(())
}
