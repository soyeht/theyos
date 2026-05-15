use std::net::SocketAddr;
use std::str::FromStr;

/// Runtime configuration sourced from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on. Default: `0.0.0.0:8090`.
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
        let addr_str = std::env::var("ADDR").unwrap_or_else(|_| "0.0.0.0:8090".to_string());
        let addr =
            SocketAddr::from_str(&addr_str).unwrap_or_else(|_| panic!("Invalid ADDR: {addr_str}"));

        Config {
            addr,
            web_dir: std::env::var("WEB_DIR").unwrap_or_else(|_| "web".to_string()),
            frontend_origin: std::env::var("FRONTEND_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
        }
    }
}
