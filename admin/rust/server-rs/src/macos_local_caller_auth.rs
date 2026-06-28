//! macOS local-engine caller authentication boundary.
//!
//! M1 intentionally ships fail-closed: production wiring has no permissive
//! verifier. A future M1b verifier must derive the peer identity from the
//! accepted UDS connection and verify a stable designated requirement before
//! any local enrollment route can succeed.

use axum::http::{HeaderMap, Method, Uri};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacosLocalCallerAuthError {
    #[error("macOS local caller verifier unavailable")]
    Unavailable,
    #[error("macOS local caller rejected")]
    Rejected,
}

pub struct MacosLocalCallerAuthRequest<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

pub trait MacosLocalCallerAuth: Send + Sync {
    fn authorize(
        &self,
        request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError>;
}

#[derive(Debug, Default)]
pub struct FailClosedMacosLocalCallerAuth;

impl MacosLocalCallerAuth for FailClosedMacosLocalCallerAuth {
    fn authorize(
        &self,
        _request: &MacosLocalCallerAuthRequest<'_>,
    ) -> Result<(), MacosLocalCallerAuthError> {
        Err(MacosLocalCallerAuthError::Unavailable)
    }
}
