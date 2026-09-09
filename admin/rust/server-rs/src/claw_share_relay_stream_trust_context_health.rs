//! Health/refresh policy over the `relay_stream` trust-context cache.
//!
//! C4b building block. [`RelayStreamTrustContextCache`] keeps the last good
//! context on refresh error (correct for a cache), but a future C4 pool MUST
//! stop serving when refresh has been failing for too long or the cached
//! context has aged past a staleness bound. This layer makes that policy a
//! small, testable unit; it does NOT spawn timers, watch app state, or wire a
//! pool.
//!
//! The refresh cadence a consumer drives over this runtime must cover BOTH
//! signals that change trust: a household record/members change (via
//! `HouseholdState`) and a mesh-log append/projection change (via
//! `MeshLogStore`). Both are folded through `refresh_now`, which re-reads the
//! current household identity and a fresh mesh-log projection.
//!
//! Out of scope (still): pool/reverse-connect, spawn/timer, bootstrap/app-state
//! wiring, and any `DirectoryDeviceRemoved` production emitter (release gate).

use std::fmt;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use household_rs::household_mesh_log::MeshLogStore;

use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_trust_context_cache::{
    RelayStreamTrustContextCache, RelayStreamTrustContextCacheError,
};
use crate::household_state::HouseholdState;

/// Serving policy for a `relay_stream` trust context: how stale the cached
/// context may get, and how many consecutive refresh failures are tolerated,
/// before the runtime refuses to serve.
#[derive(Clone, Copy, Debug)]
pub struct RelayStreamTrustContextRefreshPolicy {
    max_stale: Duration,
    max_consecutive_failures: u32,
}

impl RelayStreamTrustContextRefreshPolicy {
    /// Validate and build a policy. Both bounds must be meaningful: `max_stale`
    /// at least one second (staleness is compared in whole `now_unix` seconds,
    /// so a sub-second bound would round down to zero and trip immediately) and
    /// `max_consecutive_failures >= 1`, so a degenerate policy can never silently
    /// disable the stop-serving guards.
    pub fn new(
        max_stale: Duration,
        max_consecutive_failures: u32,
    ) -> Result<Self, RelayStreamTrustContextPolicyError> {
        if max_stale.as_secs() == 0 {
            return Err(RelayStreamTrustContextPolicyError::MaxStaleZero);
        }
        if max_consecutive_failures == 0 {
            return Err(RelayStreamTrustContextPolicyError::MaxConsecutiveFailuresZero);
        }
        Ok(Self {
            max_stale,
            max_consecutive_failures,
        })
    }
}

#[derive(Debug)]
struct HealthState {
    last_success_unix: u64,
    consecutive_failures: u32,
    last_error: Option<String>,
    /// Set when the wall clock cannot be read plausibly. Freshness is computed
    /// FROM the clock, so a broken one would otherwise report "fresh" forever.
    clock_unusable: bool,
}

/// A trust-context cache plus its serving-health bookkeeping.
///
/// `refresh_now` is async (it re-reads household + mesh log); the health checks
/// (`ensure_healthy`, `issuer_trust_if_healthy`) are sync and cheap, so the
/// future pool can gate every accept/serve on them without awaiting.
pub struct RelayStreamTrustContextRuntime {
    cache: RelayStreamTrustContextCache,
    policy: RelayStreamTrustContextRefreshPolicy,
    health: Mutex<HealthState>,
}

impl RelayStreamTrustContextRuntime {
    /// Build the runtime by loading the cache once; marks the load time as the
    /// initial success. Fails closed (no runtime) if no household is loaded.
    pub async fn load(
        household: &HouseholdState,
        mesh_log: &MeshLogStore,
        now_unix: u64,
        policy: RelayStreamTrustContextRefreshPolicy,
    ) -> Result<Self, RelayStreamTrustContextCacheError> {
        let cache = RelayStreamTrustContextCache::load(household, mesh_log).await?;
        Ok(Self {
            cache,
            policy,
            health: Mutex::new(HealthState {
                last_success_unix: now_unix,
                consecutive_failures: 0,
                last_error: None,
                clock_unusable: false,
            }),
        })
    }

    /// Re-read household + mesh log into the cache. On success, record the time
    /// and reset the failure counter. On error, increment the failure counter,
    /// record a debug-safe reason, and leave the cache's last good context in
    /// place (the cache itself never serves a permissive context).
    pub async fn refresh_now(
        &self,
        household: &HouseholdState,
        mesh_log: &MeshLogStore,
        now_unix: u64,
    ) -> Result<(), RelayStreamTrustContextCacheError> {
        match self.cache.refresh(household, mesh_log).await {
            Ok(()) => {
                let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
                // Never move last_success backward: a good refresh observed under
                // a backwards clock must not later read as artificially stale.
                health.last_success_unix = health.last_success_unix.max(now_unix);
                health.consecutive_failures = 0;
                health.last_error = None;
                Ok(())
            }
            Err(error) => {
                let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
                health.consecutive_failures = health.consecutive_failures.saturating_add(1);
                health.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    /// Return `Ok` only if the cached context is fresh enough and refresh has
    /// not been failing past the policy limit.
    ///
    /// Clock-backwards safe: `now_unix < last_success_unix` is treated as zero
    /// elapsed (fresh) via saturating subtraction, never a panic.
    pub fn ensure_healthy(&self, now_unix: u64) -> Result<(), RelayStreamTrustContextHealthError> {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        // An unusable wall clock invalidates the freshness judgement itself:
        // `stale_secs` is computed FROM the clock, so a broken one would report
        // "fresh" forever. Refuse before looking at staleness.
        if health.clock_unusable {
            return Err(RelayStreamTrustContextHealthError::ClockUnusable);
        }
        let stale_secs = now_unix.saturating_sub(health.last_success_unix);
        let max_stale_secs = self.policy.max_stale.as_secs();
        if stale_secs > max_stale_secs {
            return Err(RelayStreamTrustContextHealthError::Stale {
                stale_secs,
                max_stale_secs,
            });
        }
        if health.consecutive_failures >= self.policy.max_consecutive_failures {
            return Err(RelayStreamTrustContextHealthError::RefreshFailing {
                consecutive_failures: health.consecutive_failures,
                max_consecutive_failures: self.policy.max_consecutive_failures,
            });
        }
        Ok(())
    }

    /// Mark the wall clock unusable, making [`Self::ensure_healthy`] fail
    /// IMMEDIATELY rather than letting the last-good context keep serving until
    /// `max_stale` — a clock failure must not look handled while still
    /// admitting.
    pub fn mark_clock_unusable(&self) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        if !health.clock_unusable {
            tracing::warn!(
                stage = "claw_share.relay_stream.trust_context.clock_unusable",
                "wall clock unusable; trust context marked unhealthy",
            );
        }
        health.clock_unusable = true;
    }

    /// Clear the unusable-clock state after a plausible reading, so a recovered
    /// clock plus a successful refresh can bring the runtime back.
    pub fn clear_clock_unusable(&self) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health.clock_unusable = false;
    }

    /// The method the future pool must call before accepting/serving: hand out a
    /// [`RelayStreamIssuerTrust`] only while the runtime is healthy. The trust
    /// seam itself still authorizes each offer against the live context; this
    /// gate only refuses to serve at all when stale or persistently failing.
    pub fn issuer_trust_if_healthy(
        &self,
        now_unix: u64,
    ) -> Result<RelayStreamIssuerTrust, RelayStreamTrustContextHealthError> {
        self.ensure_healthy(now_unix)?;
        Ok(self.cache.issuer_trust())
    }

    /// The configured staleness bound. A refresh driver uses this to validate
    /// that its tick is strictly shorter than the window; a tick at or beyond
    /// `max_stale` would let the context age out between refreshes and flap.
    #[must_use]
    pub fn max_stale(&self) -> Duration {
        self.policy.max_stale
    }
}

impl fmt::Debug for RelayStreamTrustContextRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("RelayStreamTrustContextRuntime")
            .field("cache", &"redacted")
            .field("policy", &self.policy)
            .field("last_success_unix", &health.last_success_unix)
            .field("consecutive_failures", &health.consecutive_failures)
            .field("last_error", &health.last_error)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamTrustContextPolicyError {
    #[error("relay stream trust refresh policy max_stale must be at least 1 second")]
    MaxStaleZero,

    #[error("relay stream trust refresh policy max_consecutive_failures must be at least 1")]
    MaxConsecutiveFailuresZero,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamTrustContextHealthError {
    /// The wall clock is unusable, so freshness cannot be judged at all.
    #[error("relay stream trust context unhealthy: system clock unusable")]
    ClockUnusable,

    #[error(
        "relay stream trust context stale: {stale_secs}s since last refresh exceeds max {max_stale_secs}s"
    )]
    Stale {
        stale_secs: u64,
        max_stale_secs: u64,
    },

    #[error(
        "relay stream trust context refresh failing: {consecutive_failures} consecutive failures reached limit {max_consecutive_failures}"
    )]
    RefreshFailing {
        consecutive_failures: u32,
        max_consecutive_failures: u32,
    },
}

#[cfg(test)]
mod tests;
