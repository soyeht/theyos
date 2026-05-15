//! Standardized error types for the theyOS backend.

/// Semantic error codes that map to HTTP status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    NotFound,
    InvalidInput,
    Conflict,
    RateLimited,
    Timeout,
    Internal,
    Unauthorized,
    Forbidden,
    Gone,
    ServiceUnavailable,
}

impl ErrorCode {
    /// Stable machine-readable string for API error responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::InvalidInput => "INVALID_INPUT",
            Self::Conflict => "CONFLICT",
            Self::RateLimited => "RATE_LIMITED",
            Self::Timeout => "TIMEOUT",
            Self::Internal => "INTERNAL",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::Gone => "GONE",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
        }
    }
}

/// Trait for domain errors that can report their semantic error code.
pub trait AppError: std::error::Error + Send + Sync {
    fn code(&self) -> ErrorCode;

    /// Optional structured reasons for the error, serialized as JSON in the
    /// response body under the `"reasons"` key. Default returns `None`.
    ///
    /// Override this on error types that carry additional structured
    /// information the client should be able to match on (e.g. claw
    /// availability unavail reasons).
    #[cfg(feature = "http")]
    fn reasons(&self) -> Option<&serde_json::Value> {
        None
    }
}

/// Simple ad-hoc error for inline validation messages and one-off errors.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SimpleError {
    code: ErrorCode,
    message: String,
}

impl AppError for SimpleError {
    fn code(&self) -> ErrorCode {
        self.code
    }
}

/// Error variant that carries structured reasons alongside the human message.
///
/// Used for API responses where the client needs to match on why the request
/// failed beyond the coarse `ErrorCode`. The `reasons` field is opaque JSON
/// defined by the caller — typically a serialized
/// `Vec<core_rs::availability::UnavailReason>` or similar tagged enum.
///
/// Example:
/// ```ignore
/// use serde_json::json;
/// let err = ApiError::bad_request_with_reasons(
///     "claw is not installed",
///     json!([{"type": "not_installed"}]),
/// );
/// ```
#[cfg(feature = "http")]
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ReasonedError {
    code: ErrorCode,
    message: String,
    reasons: serde_json::Value,
}

#[cfg(feature = "http")]
impl AppError for ReasonedError {
    fn code(&self) -> ErrorCode {
        self.code
    }

    fn reasons(&self) -> Option<&serde_json::Value> {
        Some(&self.reasons)
    }
}

// ─── HTTP integration (requires `http` feature) ─────────────────────────────

#[cfg(feature = "http")]
mod http_support {
    use super::{AppError, ErrorCode, ReasonedError, SimpleError};
    use axum::Json;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use serde_json::json;

    impl ErrorCode {
        /// Map to the corresponding HTTP status code.
        #[must_use]
        pub fn http_status(self) -> StatusCode {
            match self {
                ErrorCode::NotFound => StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput => StatusCode::BAD_REQUEST,
                ErrorCode::Conflict => StatusCode::CONFLICT,
                ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
                ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
                ErrorCode::Forbidden => StatusCode::FORBIDDEN,
                ErrorCode::Gone => StatusCode::GONE,
                ErrorCode::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            }
        }
    }

    /// Wrapper that turns any `AppError` into an axum `Response`.
    pub struct ApiError(Box<dyn AppError>);

    impl ApiError {
        pub fn new(err: impl AppError + 'static) -> Self {
            ApiError(Box::new(err))
        }

        pub fn bad_request(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::InvalidInput,
                message: msg.into(),
            })
        }

        pub fn not_found(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::NotFound,
                message: msg.into(),
            })
        }

        pub fn internal(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Internal,
                message: msg.into(),
            })
        }

        pub fn conflict(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Conflict,
                message: msg.into(),
            })
        }

        pub fn rate_limited(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::RateLimited,
                message: msg.into(),
            })
        }

        pub fn unauthorized(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Unauthorized,
                message: msg.into(),
            })
        }

        pub fn timeout(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Timeout,
                message: msg.into(),
            })
        }

        pub fn forbidden(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Forbidden,
                message: msg.into(),
            })
        }

        pub fn gone(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::Gone,
                message: msg.into(),
            })
        }

        pub fn service_unavailable(msg: impl Into<String>) -> Self {
            ApiError::new(SimpleError {
                code: ErrorCode::ServiceUnavailable,
                message: msg.into(),
            })
        }

        /// Construct a 400 Bad Request error carrying structured reasons.
        ///
        /// The `reasons` argument is opaque JSON — typically
        /// `serde_json::to_value(&my_reasons_enum)?` — that gets emitted
        /// verbatim under the `"reasons"` key in the response body.
        ///
        /// Example:
        /// ```ignore
        /// use serde_json::json;
        /// let err = ApiError::bad_request_with_reasons(
        ///     "claw is not installed",
        ///     json!([{"type": "not_installed"}]),
        /// );
        /// ```
        pub fn bad_request_with_reasons(
            msg: impl Into<String>,
            reasons: serde_json::Value,
        ) -> Self {
            ApiError::new(ReasonedError {
                code: ErrorCode::InvalidInput,
                message: msg.into(),
                reasons,
            })
        }
    }

    impl<E: AppError + 'static> From<E> for ApiError {
        fn from(err: E) -> Self {
            ApiError::new(err)
        }
    }

    impl IntoResponse for ApiError {
        fn into_response(self) -> Response {
            let code = self.0.code();
            let status = code.http_status();
            let mut body = json!({
                "error": self.0.to_string(),
                "code": code.as_str(),
            });
            // If this error type carries structured reasons (via the
            // AppError::reasons trait method), include them in the body.
            // Legacy error types return None and their responses are
            // unchanged.
            if let Some(reasons) = self.0.reasons() {
                body["reasons"] = reasons.clone();
            }
            (status, Json(body)).into_response()
        }
    }

    impl std::fmt::Debug for ApiError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ApiError({}: {})", self.0.code().http_status(), self.0)
        }
    }

    impl std::fmt::Display for ApiError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    /// Helper for async handlers: run a blocking closure on the tokio blocking pool.
    ///
    /// Maps `JoinError` → `ApiError::internal` so callers use `?` instead of `.unwrap()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the spawned blocking task panics or is cancelled.
    pub async fn blocking<F, T>(f: F) -> Result<T, ApiError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))
    }

    /// Extension trait that converts `PoisonError` → `ApiError::internal`.
    ///
    /// Usage: `state.instance_db.lock_or_internal("instance_db")?`
    pub trait MutexExt<T> {
        /// Acquire the mutex lock, returning an internal error if poisoned.
        ///
        /// # Errors
        ///
        /// Returns an `ApiError::internal` if the mutex is poisoned.
        fn lock_or_internal(&self, ctx: &str) -> Result<std::sync::MutexGuard<'_, T>, ApiError>;
    }

    impl<T> MutexExt<T> for std::sync::Mutex<T> {
        fn lock_or_internal(&self, ctx: &str) -> Result<std::sync::MutexGuard<'_, T>, ApiError> {
            self.lock()
                .map_err(|_| ApiError::internal(format!("lock poisoned: {ctx}")))
        }
    }

    /// Extension trait for `RwLock` — converts `PoisonError` → `ApiError::internal`.
    pub trait RwLockExt<T> {
        /// Acquire a read lock, returning an internal error if poisoned.
        ///
        /// # Errors
        ///
        /// Returns an `ApiError::internal` if the `RwLock` is poisoned.
        fn read_or_internal(
            &self,
            ctx: &str,
        ) -> Result<std::sync::RwLockReadGuard<'_, T>, ApiError>;
        /// Acquire a write lock, returning an internal error if poisoned.
        ///
        /// # Errors
        ///
        /// Returns an `ApiError::internal` if the `RwLock` is poisoned.
        fn write_or_internal(
            &self,
            ctx: &str,
        ) -> Result<std::sync::RwLockWriteGuard<'_, T>, ApiError>;
    }

    impl<T> RwLockExt<T> for std::sync::RwLock<T> {
        fn read_or_internal(
            &self,
            ctx: &str,
        ) -> Result<std::sync::RwLockReadGuard<'_, T>, ApiError> {
            self.read()
                .map_err(|_| ApiError::internal(format!("rwlock read poisoned: {ctx}")))
        }
        fn write_or_internal(
            &self,
            ctx: &str,
        ) -> Result<std::sync::RwLockWriteGuard<'_, T>, ApiError> {
            self.write()
                .map_err(|_| ApiError::internal(format!("rwlock write poisoned: {ctx}")))
        }
    }
}

#[cfg(feature = "http")]
pub use http_support::{ApiError, MutexExt, RwLockExt, blocking};

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "http")]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use serde_json::{Value, json};

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn legacy_simple_error_has_no_reasons_key() {
        let err = ApiError::bad_request("nothing to see here");
        let response = err.into_response();
        assert_eq!(response.status(), 400);
        let body = body_json(response).await;
        assert_eq!(body["error"], "nothing to see here");
        assert_eq!(body["code"], "INVALID_INPUT");
        // Critical: legacy errors must not grow a reasons field
        assert!(body.get("reasons").is_none());
    }

    #[tokio::test]
    async fn reasoned_error_emits_reasons_in_body() {
        let reasons = json!([
            { "type": "not_installed" },
            { "type": "install_in_progress", "percent": 43 }
        ]);
        let err = ApiError::bad_request_with_reasons("claw is not ready", reasons.clone());
        let response = err.into_response();
        assert_eq!(response.status(), 400);
        let body = body_json(response).await;
        assert_eq!(body["error"], "claw is not ready");
        assert_eq!(body["code"], "INVALID_INPUT");
        assert_eq!(body["reasons"], reasons);
    }

    #[tokio::test]
    async fn reasoned_error_with_empty_reasons_array() {
        let err = ApiError::bad_request_with_reasons("blocked", json!([]));
        let response = err.into_response();
        let body = body_json(response).await;
        assert_eq!(body["reasons"], json!([]));
    }

    #[test]
    fn app_error_default_reasons_is_none() {
        let simple = SimpleError {
            code: ErrorCode::InvalidInput,
            message: "x".into(),
        };
        assert!(simple.reasons().is_none());
    }

    #[test]
    fn reasoned_error_returns_reasons_via_trait() {
        let reasons = json!([{"type": "not_installed"}]);
        let err = ReasonedError {
            code: ErrorCode::InvalidInput,
            message: "x".into(),
            reasons: reasons.clone(),
        };
        assert_eq!(err.reasons(), Some(&reasons));
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }
}
