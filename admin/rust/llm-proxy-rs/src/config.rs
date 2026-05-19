//! Static proxy configuration parsed from env vars at startup.
//!
//! No per-request reload (yet) — profile reload happens via SIGHUP or the
//! admin endpoint, not via env. These values pin the lifetime of the
//! process.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Listening port the proxy binds to. Claws reach the proxy by reverse SSH
/// tunnel that maps guest-loopback → host-loopback on this port. Default
/// matches `core_rs::claw_llm::DEFAULT_LLM_PROXY_PORT`.
pub const DEFAULT_PROXY_PORT: u16 = 18900;

/// Env var override for the bind port.
pub const ENV_PROXY_PORT: &str = "THEYOS_LLM_PROXY_PORT";

/// Env var override for the bind address (defaults to loopback only).
pub const ENV_PROXY_BIND: &str = "THEYOS_LLM_PROXY_BIND";

/// Env var override for the profile directory
/// (default: `$HOME/.theyos/llm-profiles`).
pub const ENV_PROFILE_DIR: &str = "THEYOS_LLM_PROFILE_DIR";

/// Env var override for the audit log path. Default is
/// `$HOME/.theyos/.run/llm-audit.log`. Set to an empty string to disable
/// audit logging.
pub const ENV_AUDIT_LOG: &str = "THEYOS_LLM_AUDIT_LOG";

/// Env var selecting the credential backend.
///
/// Recognised values:
/// - `auto` (default) — pick the most secure backend available on the
///   host: macOS Keychain on darwin; TPM2-sealed file on Linux when a
///   TPM is present; plain `0600` file fallback otherwise.
/// - `file` — `0600` files under `$HOME/.theyos/keystore`. No
///   encryption-at-rest. Works on any host.
/// - `system` / `keychain` / `secret-service` — OS-native credential
///   store. macOS Keychain or Linux Secret Service / kernel keyring.
/// - `tpm` — Linux-only TPM2-sealed via `systemd-creds`. Returns an
///   error at startup if no TPM is available.
pub const ENV_KEYSTORE: &str = "THEYOS_LLM_KEYSTORE";

/// Env var overriding the file-keystore root directory. Default is
/// `$HOME/.theyos/keystore`. Only consulted when [`KeystoreKind::File`]
/// is active.
pub const ENV_KEYSTORE_DIR: &str = "THEYOS_LLM_KEYSTORE_DIR";

/// Which credential backend the proxy uses. The chosen kind determines
/// where credentials are persisted and how `theyos-llm-proxy set-credential`
/// stores values.
///
/// [`KeystoreKind::Auto`] is the default — it resolves at startup to the
/// best backend the host can support (Keychain on macOS, TPM-sealed file
/// on Linux with TPM2, plain file otherwise). Explicit values let an
/// operator pin the choice for predictability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreKind {
    /// Resolve the best available backend at startup. See
    /// [`build_credential_store`](crate::build_credential_store).
    Auto,
    /// `0600` files under [`ProxyConfig::keystore_dir`]. No
    /// encryption-at-rest beyond filesystem ACLs. Works anywhere.
    File,
    /// OS-native credential store (macOS Keychain on darwin; Linux
    /// Secret Service or kernel keyring depending on `THEYOS_KEYRING`).
    /// Pick this when the OS provides encryption-at-rest via TPM/Secure
    /// Enclave and the daemon is reachable from the service unit.
    System,
    /// Linux-only: TPM2-sealed via `systemd-creds`. Each credential
    /// is sealed to the host's TPM and bound to its account name; moving
    /// the file to another host (clone disk, restore backup) breaks
    /// unseal. Fails fast at startup if no TPM2 is available.
    Tpm,
}

impl KeystoreKind {
    /// Resolve from the `THEYOS_LLM_KEYSTORE` env var. Unknown / unset
    /// values fall back to [`KeystoreKind::Auto`] — the documented
    /// "pick the best" behaviour.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(ENV_KEYSTORE)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("file") => Self::File,
            Some("system" | "keychain" | "secret-service") => Self::System,
            Some("tpm" | "tpm2" | "systemd-creds") => Self::Tpm,
            // Empty/missing/unknown → Auto. Treating "auto" explicitly
            // keeps the env var self-documenting when an operator wants
            // to be explicit about wanting auto-detect.
            Some("auto") | None => Self::Auto,
            Some(other) => {
                tracing::warn!(
                    value = other,
                    "unknown THEYOS_LLM_KEYSTORE value; falling back to Auto"
                );
                Self::Auto
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub bind: SocketAddr,
    pub profile_dir: PathBuf,
    /// Path to the audit log file. `None` disables audit logging.
    pub audit_log: Option<PathBuf>,
    /// Which credential backend to use. Captured at startup; CLI
    /// subcommands consult the same value so set/get/delete touch the
    /// same store the running daemon would read.
    pub keystore_kind: KeystoreKind,
    /// Root directory for the file keystore (when `keystore_kind == File`).
    /// Default `$HOME/.theyos/keystore`. Ignored for system keystore.
    pub keystore_dir: PathBuf,
}

impl ProxyConfig {
    /// Build configuration from environment, falling back to documented
    /// defaults. Never panics — invalid values are reported through
    /// `tracing::warn` and the default is used instead.
    #[must_use]
    pub fn from_env() -> Self {
        let port = std::env::var(ENV_PROXY_PORT)
            .ok()
            .and_then(|raw| match raw.parse::<u16>() {
                Ok(p) if p > 0 => Some(p),
                _ => {
                    tracing::warn!(value = raw, "invalid {ENV_PROXY_PORT}, using default");
                    None
                }
            })
            .unwrap_or(DEFAULT_PROXY_PORT);

        let bind_addr = std::env::var(ENV_PROXY_BIND)
            .ok()
            .and_then(|raw| match raw.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    tracing::warn!(value = raw, error = %e, "invalid {ENV_PROXY_BIND}, using loopback");
                    None
                }
            })
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let bind = SocketAddr::new(bind_addr, port);

        let profile_dir = if let Ok(dir) = std::env::var(ENV_PROFILE_DIR) {
            PathBuf::from(dir)
        } else {
            let home = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".theyos").join("llm-profiles")
        };

        let audit_log = match std::env::var(ENV_AUDIT_LOG) {
            Ok(raw) if raw.trim().is_empty() => None,
            Ok(raw) => Some(PathBuf::from(raw)),
            Err(_) => {
                let home = std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default();
                Some(home.join(".theyos").join(".run").join("llm-audit.log"))
            }
        };

        let keystore_kind = KeystoreKind::from_env();
        let keystore_dir = if let Ok(dir) = std::env::var(ENV_KEYSTORE_DIR) {
            PathBuf::from(dir)
        } else {
            let home = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".theyos").join("keystore")
        };

        Self {
            bind,
            profile_dir,
            audit_log,
            keystore_kind,
            keystore_dir,
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)] // Tests serialise env mutations via ENV_LOCK below.
mod tests {
    use super::*;
    use std::sync::{Mutex, PoisonError};

    // Env mutations have to be serialised — std::env is process-global.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<R>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> R) -> R {
        let _g = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            // SAFETY: serialised via ENV_LOCK; no other thread is reading env.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        let out = f();
        for (k, v) in saved {
            // SAFETY: see above.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
        out
    }

    #[test]
    fn keystore_kind_defaults_to_auto() {
        with_env(&[(ENV_KEYSTORE, None)], || {
            assert_eq!(KeystoreKind::from_env(), KeystoreKind::Auto);
        });
    }

    #[test]
    fn keystore_kind_recognises_system_aliases() {
        for alias in ["system", "System", "KEYCHAIN", "secret-service"] {
            with_env(&[(ENV_KEYSTORE, Some(alias))], || {
                assert_eq!(
                    KeystoreKind::from_env(),
                    KeystoreKind::System,
                    "alias {alias:?} should resolve to System"
                );
            });
        }
    }

    #[test]
    fn keystore_kind_recognises_tpm_aliases() {
        for alias in ["tpm", "TPM", "tpm2", "systemd-creds"] {
            with_env(&[(ENV_KEYSTORE, Some(alias))], || {
                assert_eq!(
                    KeystoreKind::from_env(),
                    KeystoreKind::Tpm,
                    "alias {alias:?} should resolve to Tpm"
                );
            });
        }
    }

    #[test]
    fn keystore_kind_file_is_explicit() {
        with_env(&[(ENV_KEYSTORE, Some("file"))], || {
            assert_eq!(KeystoreKind::from_env(), KeystoreKind::File);
        });
    }

    #[test]
    fn keystore_kind_unknown_value_falls_back_to_auto() {
        with_env(&[(ENV_KEYSTORE, Some("garbage"))], || {
            assert_eq!(KeystoreKind::from_env(), KeystoreKind::Auto);
        });
    }

    #[test]
    fn keystore_dir_defaults_to_home_subdir() {
        with_env(
            &[
                (ENV_KEYSTORE_DIR, None),
                ("HOME", Some("/tmp/aurora-test-home")),
            ],
            || {
                let cfg = ProxyConfig::from_env();
                assert!(cfg.keystore_dir.ends_with(".theyos/keystore"));
            },
        );
    }

    #[test]
    fn keystore_dir_override_wins() {
        with_env(
            &[(ENV_KEYSTORE_DIR, Some("/var/lib/theyos-llm/keystore"))],
            || {
                let cfg = ProxyConfig::from_env();
                assert_eq!(
                    cfg.keystore_dir,
                    PathBuf::from("/var/lib/theyos-llm/keystore")
                );
            },
        );
    }
}
