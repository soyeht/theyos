//! Typed errors for the LLM proxy. Mirrors the `error.kind`/`error.hint`
//! contract used elsewhere in theyOS so structured-log consumers can join
//! across crates.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    /// No provider is configured under the requested id (or no profile is
    /// active at all).
    #[error("no provider configured for id {0:?}")]
    NoProvider(String),

    /// Active profile referenced a provider id that is not in the
    /// catalog. This is a server-side configuration outage — the
    /// runtime can't serve any request that would route through this
    /// provider until an operator fixes the profile. 503 is appropriate.
    #[error("profile references unknown provider {provider:?}: {hint}")]
    UnknownProvider { provider: String, hint: String },

    /// Client-supplied provider id is not configured. Distinct from
    /// `UnknownProvider` (which means "the server's own profile is
    /// inconsistent") because this one is the client's fault — they
    /// asked to activate or test a provider id the server doesn't
    /// know about. 422 (Unprocessable Entity) matches the semantics:
    /// the request was well-formed but the value cannot be processed.
    #[error("provider {provider:?} is not configured: {hint}")]
    InvalidProviderSelection { provider: String, hint: String },

    /// Upstream HTTP error talking to the model server / cloud API.
    #[error("upstream {provider}: {message}")]
    Upstream { provider: String, message: String },

    /// Inbound request was malformed (bad JSON, missing required field).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Profile load / save failure.
    #[error("profile {path}: {kind}")]
    Profile { path: String, kind: String },

    /// Credential lookup failed (keystore unavailable, entry missing, etc.).
    #[error("credential for {provider}: {hint}")]
    Credential { provider: String, hint: String },

    /// Streaming I/O failure mid-response.
    #[error("stream: {0}")]
    Stream(String),
}

impl ProxyError {
    /// Stable machine-readable error kind for the `error.kind` log field.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoProvider(_) => "proxy.no_provider",
            Self::UnknownProvider { .. } => "proxy.unknown_provider",
            Self::InvalidProviderSelection { .. } => "proxy.invalid_provider",
            Self::Upstream { .. } => "proxy.upstream",
            Self::BadRequest(_) => "proxy.bad_request",
            Self::Profile { .. } => "proxy.profile",
            Self::Credential { .. } => "proxy.credential",
            Self::Stream(_) => "proxy.stream",
        }
    }

    /// HTTP status code to return to the client when this error escapes the
    /// chat-completions handler.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::InvalidProviderSelection { .. } => 422,
            Self::NoProvider(_) | Self::UnknownProvider { .. } => 503,
            Self::Credential { .. } | Self::Upstream { .. } | Self::Stream(_) => 502,
            Self::Profile { .. } => 500,
        }
    }
}

impl From<keystore_rs::KeystoreError> for ProxyError {
    fn from(e: keystore_rs::KeystoreError) -> Self {
        ProxyError::Credential {
            provider: String::new(),
            hint: e.hint(),
        }
    }
}
