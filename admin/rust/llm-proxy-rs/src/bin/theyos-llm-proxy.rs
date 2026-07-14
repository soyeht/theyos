//! Entry point for the `theyos-llm-proxy` host daemon.
//!
//! Loads config from env, resolves the active provider, then serves the
//! axum router on the configured loopback port. Restart-friendly: every
//! launchd `KeepAlive`/systemd `Restart=always` cycle re-reads the
//! profile, so editing `~/.theyos/llm-profiles/default.toml` and bouncing
//! the service is the supported way to change the active provider in
//! Slice 1. Hot-reload via admin API arrives in Slice 5.

use keystore_rs::KeystoreBackend;
use llm_proxy::{
    ProxyConfig, build_credential_store, build_state_from_profile, first_run_profile, router,
};
use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && argv[1] == "--owner-present-phase0-contract" {
        println!(
            "{}",
            serde_json::json!({
                "schema": "theyos-product-a-phase0-http-boundary-v1",
                "component": "theyos-llm-proxy",
                "authority": "none",
                "production_activation": false,
                "allowed_requests": [
                    {"method": "GET", "path": "/api/v1/mobile/claw-vpn/status"},
                    {"method": "HEAD", "path": "/api/v1/mobile/claw-vpn/status"}
                ]
            })
        );
        return ExitCode::SUCCESS;
    }
    init_tracing();

    // CLI subcommands. The proxy binary is the operator's one entry point —
    // it serves traffic, AND it manages credentials so operators don't need
    // a second tool just to write a secret. Anything other than the (no-arg)
    // server-mode case is handled before the server starts.
    if argv.len() >= 2 {
        match argv[1].as_str() {
            "set-credential" => return run_set_credential(&argv[2..]),
            "get-credential" => return run_get_credential(&argv[2..]),
            "delete-credential" => return run_delete_credential(&argv[2..]),
            "--help" | "-h" | "help" => {
                print_help();
                return ExitCode::from(0);
            }
            unknown => {
                eprintln!("theyos-llm-proxy: unknown subcommand: {unknown:?}");
                print_help();
                return ExitCode::from(64);
            }
        }
    }

    let config = ProxyConfig::from_env();
    tracing::info!(?config, "starting theyos-llm-proxy");

    let state = match build_state_from_profile(&config) {
        Ok(state) => state,
        Err(llm_proxy::ProxyError::NoProvider(_)) => {
            // First boot: write a sane default and exit cleanly so the
            // operator can edit it. `save_default_if_absent` is critical
            // here — if the daemon restarts and the profile file is
            // present but the [active] block is missing (operator
            // half-edited it), an unconditional write would clobber
            // their changes. The if-absent guard makes the stub a true
            // first-boot scaffold, never a restart hazard.
            tracing::warn!(
                profile_dir = %config.profile_dir.display(),
                "no profile found; writing first-run profile and exiting — edit it then restart"
            );
            if let Err(e) = first_run_profile().save_default_if_absent(&config.profile_dir) {
                tracing::error!(error = %e, "could not write first-run profile");
                return ExitCode::from(2);
            }
            return ExitCode::from(0);
        }
        Err(e) => {
            tracing::error!(
                error.kind = e.kind(),
                error.message = %e,
                "could not build server state — fix the profile and restart"
            );
            return ExitCode::from(1);
        }
    };

    tracing::info!(
        bind = %config.bind,
        default_provider = state.default_active().provider,
        default_model = state.default_active().model,
        "proxy ready"
    );

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, bind = %config.bind, "bind failed");
            return ExitCode::from(3);
        }
    };

    // SIGHUP handler: re-read the profile + keystore and rebuild the
    // provider registry without restarting. The motivating case is
    // `theyos-llm-proxy set-credential` or any admin-API mutation that
    // changes the profile/keystore on disk — those tools mutate disk
    // but the running daemon's providers already cached their
    // credentials at construction time, so the change has no effect
    // until SIGHUP (or a service restart).
    //
    // Cloning the state into the task is cheap (single Arc bump). The
    // task lives for the process lifetime; tokio cancels it on shutdown.
    let reload_state = state.clone();
    tokio::spawn(async move {
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGHUP handler; credential reload disabled");
                return;
            }
        };
        while hup.recv().await.is_some() {
            match reload_state.reload_from_disk() {
                Ok(n) => tracing::info!(provider_count = n, "SIGHUP: reloaded profile + keystore"),
                Err(e) => tracing::error!(
                    error.kind = e.kind(),
                    error.message = %e,
                    "SIGHUP: reload failed; live state unchanged"
                ),
            }
        }
    });

    let app = router(state);
    if let Err(e) = core_rs::phase0_axum_serve!(listener, app).await {
        tracing::error!(error = %e, "axum::serve exited");
        return ExitCode::from(4);
    }
    ExitCode::from(0)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,llm_proxy=info,tower_http=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn print_help() {
    eprintln!(
        "theyos-llm-proxy — host-side LLM multiplexer\n\
         \n\
         USAGE:\n  \
           theyos-llm-proxy                            run the proxy (default)\n  \
           theyos-llm-proxy set-credential <account>   read secret from stdin, store under <account>\n  \
           theyos-llm-proxy get-credential <account>   print the stored secret to stdout (debug only)\n  \
           theyos-llm-proxy delete-credential <account>  remove the stored secret\n  \
           theyos-llm-proxy help                       show this message\n\
         \n\
         Service namespace: com.soyeht.theyos (see keystore-rs::SERVICE).\n\
         \n\
         CREDENTIAL BACKEND\n  \
           THEYOS_LLM_KEYSTORE=file (default) writes 0600 files under\n  \
             $THEYOS_LLM_KEYSTORE_DIR (default $HOME/.theyos/keystore).\n  \
             Survives reboot; works on headless hosts. Recommended.\n  \
           THEYOS_LLM_KEYSTORE=system uses OS keystore (macOS Keychain or Linux\n  \
             Secret Service). On Linux, set THEYOS_KEYRING=kernel to fall back\n  \
             to keyutils — note: kernel keyring is wiped on service restart."
    );
}

/// CLI subcommands consult the same `ProxyConfig` as the daemon, so set/get/
/// delete always touch the store the running service would read. Otherwise
/// an operator could set a credential into the File backend while the
/// daemon reads from System (or vice-versa) and silently miss it.
fn resolve_keystore() -> Arc<dyn KeystoreBackend> {
    let config = ProxyConfig::from_env();
    build_credential_store(&config)
}

fn run_set_credential(args: &[String]) -> ExitCode {
    let Some(account) = args.first() else {
        eprintln!("set-credential: missing <account> argument");
        return ExitCode::from(64);
    };
    let mut secret = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut secret) {
        eprintln!("set-credential: read stdin: {e}");
        return ExitCode::from(1);
    }
    // Trim a single trailing newline so `echo "key" | …` works as expected
    // but embedded newlines in the secret are preserved.
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }
    if secret.is_empty() {
        eprintln!("set-credential: secret is empty (read from stdin)");
        return ExitCode::from(64);
    }
    let store = resolve_keystore();
    if let Err(e) = store.set(account, secret.as_bytes()) {
        eprintln!("set-credential: {e}");
        return ExitCode::from(1);
    }
    eprintln!("stored {} bytes under account {account:?}", secret.len());
    if signal_running_daemon_to_reload() {
        eprintln!("signalled running daemon to reload (SIGHUP)");
    }
    ExitCode::from(0)
}

fn run_get_credential(args: &[String]) -> ExitCode {
    let Some(account) = args.first() else {
        eprintln!("get-credential: missing <account> argument");
        return ExitCode::from(64);
    };
    let store = resolve_keystore();
    match store.get(account) {
        Ok(bytes) => {
            use std::io::Write;
            if let Err(e) = std::io::stdout().write_all(&bytes) {
                eprintln!("get-credential: write stdout: {e}");
                return ExitCode::from(1);
            }
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("get-credential: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_delete_credential(args: &[String]) -> ExitCode {
    let Some(account) = args.first() else {
        eprintln!("delete-credential: missing <account> argument");
        return ExitCode::from(64);
    };
    let store = resolve_keystore();
    if let Err(e) = store.delete(account) {
        eprintln!("delete-credential: {e}");
        return ExitCode::from(1);
    }
    eprintln!("deleted account {account:?}");
    if signal_running_daemon_to_reload() {
        eprintln!("signalled running daemon to reload (SIGHUP)");
    }
    ExitCode::from(0)
}

/// Best-effort signal a same-host daemon to reload its credentials.
///
/// Looks up `theyos-llm-proxy` PIDs via `/proc/*/comm` and sends SIGHUP
/// to each. Returns `true` when at least one signal was delivered.
///
/// Why /proc instead of `pgrep`: keeps this binary dep-free and the
/// behaviour deterministic — `pgrep` may not be on PATH, and pulling
/// `procfs` in just for this is overkill. On non-Linux this is a no-op.
fn signal_running_daemon_to_reload() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let Ok(entries) = fs::read_dir("/proc") else {
            return false;
        };
        let mut signalled = false;
        let our_pid = std::process::id();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };
            if pid == our_pid {
                continue;
            }
            let comm_path = entry.path().join("comm");
            let Ok(comm) = fs::read_to_string(&comm_path) else {
                continue;
            };
            // /proc/<pid>/comm is the first 15 chars of argv[0] basename;
            // systemd's process name truncates to "theyos-llm-prox".
            if !comm.trim_end().starts_with("theyos-llm-prox") {
                continue;
            }
            // SAFETY: kill() with SIGHUP (=1) and a numeric PID — no
            // user-controlled memory, no concurrent invariants. The
            // worst-case outcome is ESRCH (process exited between
            // scan and signal), which we silently ignore.
            //
            // u32 → i32 cast: PIDs on Linux are in [0, 2^22) by default
            // (`/proc/sys/kernel/pid_max`), well below i32::MAX. We
            // parsed `pid` from a `/proc/<pid>` directory entry so it
            // came from the kernel in the first place.
            #[allow(unsafe_code)]
            #[allow(clippy::cast_possible_wrap)]
            unsafe {
                if libc::kill(pid as libc::pid_t, libc::SIGHUP) == 0 {
                    signalled = true;
                }
            }
        }
        signalled
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS dev path: launchd-managed, just hint at the equivalent.
        eprintln!("(non-Linux: send SIGHUP manually or restart the launchd job to apply)");
        false
    }
}
