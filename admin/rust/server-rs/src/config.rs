use std::net::SocketAddr;
use std::str::FromStr;

const DEFAULT_ADDR: &str = "127.0.0.1:8090";

/// Runtime configuration sourced from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on. Default: `127.0.0.1:8090`.
    pub addr: SocketAddr,

    /// Path to the `web/` directory that contains the built frontend assets.
    /// Default: `web` (relative to CWD).
    pub web_dir: String,

    /// Allowed CORS origin for the frontend dev server.
    /// Default: `http://localhost:5173`.
    pub frontend_origin: String,
}

impl Config {
    /// # Panics
    ///
    /// Panics if `ADDR` env var contains an invalid socket address.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Self {
        let addr_str = lookup("ADDR").unwrap_or_else(|| DEFAULT_ADDR.to_string());
        let addr =
            SocketAddr::from_str(&addr_str).unwrap_or_else(|_| panic!("Invalid ADDR: {addr_str}"));

        Config {
            addr,
            web_dir: lookup("WEB_DIR").unwrap_or_else(|| "web".to_string()),
            frontend_origin: lookup("FRONTEND_ORIGIN")
                .unwrap_or_else(|| "http://localhost:5173".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_addr_is_loopback_only() {
        let cfg = Config::from_lookup(|_| None);

        assert_eq!(cfg.addr, "127.0.0.1:8090".parse().unwrap());
        assert!(cfg.addr.ip().is_loopback());
    }

    #[test]
    fn explicit_addr_override_is_honored() {
        let cfg = Config::from_lookup(|key| (key == "ADDR").then(|| "0.0.0.0:8892".to_string()));

        assert_eq!(cfg.addr, "0.0.0.0:8892".parse().unwrap());
        assert!(cfg.addr.ip().is_unspecified());
    }
}
