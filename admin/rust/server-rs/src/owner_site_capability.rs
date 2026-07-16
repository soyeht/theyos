//! Pre-effect owner-site capability types.
//!
//! This module intentionally stops before challenge issuance, proof
//! verification, consume, authority generation, revocation, or any backend
//! connection. PR1 only provides the typed server-owned shape that later
//! slices must extend. In particular, the only admitting capability is a
//! crate-test fixture, not a production authority or a bearer wire format.

use std::net::SocketAddr;

#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Immutable server-owned request shape for one owner-site action.
///
/// `OwnerSiteIntent` is deliberately not a terminal, guest, or relay scope.
/// The HTTP route receives only an opaque claw resource selector; household
/// and actor bindings remain inside this server-owned value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteIntent {
    household_id: String,
    actor_id: String,
    operation: OwnerSiteOperation,
    resource: OwnerSiteResource,
}

impl OwnerSiteIntent {
    /// Builds a server-owned intent for crate-local route tests only.
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        household_id: &str,
        actor_id: &str,
        resource: OwnerSiteResource,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            household_id: validated_component(household_id)?,
            actor_id: validated_component(actor_id)?,
            operation: OwnerSiteOperation::Open,
            resource,
        })
    }
}

/// The operation namespace is intentionally distinct from `household_rs`
/// caveat operations until the owner-site PoP/challenge design is reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteOperation {
    #[cfg(test)]
    Open,
}

/// Exact server-resolved `ClawSite` resource selector.
///
/// This is an opaque component, not a URL, hostname, DNS name, or backend
/// address. The backend remains inside [`OwnerSiteCapabilityScope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteResource {
    claw_name: String,
}

impl OwnerSiteResource {
    /// Converts the route's claw segment into an opaque resource selector.
    pub(crate) fn from_route_claw(claw_name: &str) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            claw_name: validated_component(claw_name)?,
        })
    }
}

/// Rejection for a non-canonical owner-site selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteIntentError {
    InvalidComponent,
}

fn validated_component(value: &str) -> Result<String, OwnerSiteIntentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(OwnerSiteIntentError::InvalidComponent);
    }
    Ok(value.to_owned())
}

/// Server-selected numeric loopback backend.
///
/// The type accepts a `SocketAddr`, never a URL or hostname. It is carried for
/// a later effect slice but PR1 does not connect to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteBackend {
    socket: SocketAddr,
}

impl OwnerSiteBackend {
    #[cfg(test)]
    pub(crate) fn numeric_loopback(socket: SocketAddr) -> Result<Self, OwnerSiteBackendError> {
        if socket.ip().is_loopback() {
            Ok(Self { socket })
        } else {
            Err(OwnerSiteBackendError::NotLoopback)
        }
    }
}

/// Rejection for a backend outside numeric loopback.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteBackendError {
    NotLoopback,
}

/// Opaque remote-principal placeholder for a later reviewed NEX boundary.
///
/// It intentionally carries no network address and no roster or revocation
/// generation. Those authority semantics are parked for later slices.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRemotePrincipal {
    opaque_id: String,
}

#[cfg(test)]
impl OwnerSiteRemotePrincipal {
    pub(crate) fn injected_for_harness(opaque_id: &str) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            opaque_id: validated_component(opaque_id)?,
        })
    }
}

/// Current authority material observed by the pre-effect capability store.
///
/// No production variant can admit in PR1. `InjectedForHarness` is compiled
/// only into crate tests so a production router cannot acquire a valid
/// owner-site capability merely by mounting an extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteAuthoritySnapshot {
    #[cfg(test)]
    Unavailable,
    #[cfg(test)]
    Stale,
    #[cfg(test)]
    Mismatch,
    #[cfg(test)]
    InjectedForHarness(OwnerSiteRemotePrincipal),
}

impl OwnerSiteAuthoritySnapshot {
    #[must_use]
    fn admits_pre_effect(&self) -> bool {
        #[cfg(test)]
        {
            matches!(self, Self::InjectedForHarness(_))
        }
        #[cfg(not(test))]
        {
            let _ = self;
            false
        }
    }
}

/// Server-only bindings for one future owner-site capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteCapabilityScope {
    intent: OwnerSiteIntent,
    authority: OwnerSiteAuthoritySnapshot,
    backend: OwnerSiteBackend,
}

impl OwnerSiteCapabilityScope {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(
        intent: OwnerSiteIntent,
        authority: OwnerSiteAuthoritySnapshot,
        backend: OwnerSiteBackend,
    ) -> Self {
        Self {
            intent,
            authority,
            backend,
        }
    }
}

/// Opaque typed sibling of every existing capability family.
///
/// PR1 deliberately offers no wire handle, random material, TTL, mint, or
/// consume operation. Future slices may introduce those only after the
/// challenge and authority contracts have landed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteCapability {
    scope: OwnerSiteCapabilityScope,
}

impl OwnerSiteCapability {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(scope: OwnerSiteCapabilityScope) -> Self {
        Self { scope }
    }
}

/// Inert server-side holder for an explicitly injected owner-site capability.
///
/// Production cannot construct an admitting store in PR1: all constructors
/// that can install a capability are crate-test-only. The production household
/// router also never mounts this extension, so a missing provider is forbidden.
/// The store has no mutation or network operation.
#[derive(Clone, Debug)]
pub(crate) struct OwnerSiteCapabilityStore {
    capability: Option<OwnerSiteCapability>,
    #[cfg(test)]
    effects: Arc<OwnerSiteEffectCounters>,
}

impl OwnerSiteCapabilityStore {
    /// Builds a test-only inert provider together with its attached probes.
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        capability: OwnerSiteCapability,
    ) -> (Self, Arc<OwnerSiteEffectCounters>) {
        let effects = Arc::new(OwnerSiteEffectCounters::default());
        (
            Self {
                capability: Some(capability),
                effects: Arc::clone(&effects),
            },
            effects,
        )
    }

    /// Builds a test-only provider with no capability at all.
    #[cfg(test)]
    pub(crate) fn unavailable_for_harness() -> (Self, Arc<OwnerSiteEffectCounters>) {
        let effects = Arc::new(OwnerSiteEffectCounters::default());
        (
            Self {
                capability: None,
                effects: Arc::clone(&effects),
            },
            effects,
        )
    }

    /// Number of injected capabilities retained by this inert PR1 store.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending_count(&self) -> usize {
        usize::from(self.capability.is_some())
    }

    /// Checks only the immutable pre-effect shape.
    ///
    /// This method intentionally does not mint, consume, revalidate a live
    /// authority generation, bind a listener, or contact a backend. It is the
    /// narrow seam that makes the future wire route testable while production
    /// stays fail-closed.
    pub(crate) fn pre_effect_admission(
        &self,
        resource: &OwnerSiteResource,
    ) -> Result<(), OwnerSitePreEffectRejection> {
        #[cfg(test)]
        self.effects.record_pre_effect_admission();

        let capability = self
            .capability
            .as_ref()
            .ok_or(OwnerSitePreEffectRejection::MissingCapability)?;

        // Preserve each future server-owned binding in this pre-effect shape
        // without treating any of them as a current authority substitute.
        let _ = (
            &capability.scope.intent.household_id,
            &capability.scope.intent.actor_id,
            capability.scope.intent.operation,
            capability.scope.backend.socket,
        );

        if !capability.scope.authority.admits_pre_effect() {
            return Err(OwnerSitePreEffectRejection::AuthorityUnavailable);
        }
        if capability.scope.intent.resource != *resource {
            return Err(OwnerSitePreEffectRejection::ScopeMismatch);
        }
        Ok(())
    }
}

/// Uniform fail-closed result for the pre-effect route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSitePreEffectRejection {
    MissingCapability,
    AuthorityUnavailable,
    ScopeMismatch,
}

/// Test-only counters attached to the injected provider itself.
///
/// `pre_effect_admissions` proves that a route request reached the exact
/// provider under observation. The five effect counters remain zero because
/// PR1 exposes no API that can bind, mint, consume, dial, or write site bytes.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct OwnerSiteEffectCounters {
    listener_binds: AtomicUsize,
    mints: AtomicUsize,
    consumes: AtomicUsize,
    proxy_dials: AtomicUsize,
    site_bytes: AtomicUsize,
    pre_effect_admissions: AtomicUsize,
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteEffectSnapshot {
    pub(crate) listener_binds: usize,
    pub(crate) mints: usize,
    pub(crate) consumes: usize,
    pub(crate) proxy_dials: usize,
    pub(crate) site_bytes: usize,
    pub(crate) pre_effect_admissions: usize,
}

#[cfg(test)]
impl OwnerSiteEffectCounters {
    fn record_pre_effect_admission(&self) {
        self.pre_effect_admissions.fetch_add(1, Ordering::SeqCst);
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> OwnerSiteEffectSnapshot {
        OwnerSiteEffectSnapshot {
            listener_binds: self.listener_binds.load(Ordering::SeqCst),
            mints: self.mints.load(Ordering::SeqCst),
            consumes: self.consumes.load(Ordering::SeqCst),
            proxy_dials: self.proxy_dials.load(Ordering::SeqCst),
            site_bytes: self.site_bytes.load(Ordering::SeqCst),
            pre_effect_admissions: self.pre_effect_admissions.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(authority: OwnerSiteAuthoritySnapshot) -> OwnerSiteCapabilityScope {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let intent =
            OwnerSiteIntent::injected_for_harness("household-alpha", "owner-alpha", resource)
                .expect("intent");
        let backend =
            OwnerSiteBackend::numeric_loopback("127.0.0.1:7411".parse().expect("loopback"))
                .expect("loopback backend");
        OwnerSiteCapabilityScope::new(intent, authority, backend)
    }

    fn store(
        authority: OwnerSiteAuthoritySnapshot,
    ) -> (OwnerSiteCapabilityStore, Arc<OwnerSiteEffectCounters>) {
        OwnerSiteCapabilityStore::injected_for_harness(OwnerSiteCapability::injected_for_harness(
            scope(authority),
        ))
    }

    #[test]
    fn backend_accepts_only_numeric_loopback() {
        assert!(
            OwnerSiteBackend::numeric_loopback("127.0.0.1:7411".parse().expect("loopback socket"),)
                .is_ok()
        );
        assert_eq!(
            OwnerSiteBackend::numeric_loopback("192.0.2.10:7411".parse().expect("remote socket")),
            Err(OwnerSiteBackendError::NotLoopback)
        );
    }

    #[test]
    fn pre_effect_admission_is_non_consuming_and_scope_exact() {
        let principal =
            OwnerSiteRemotePrincipal::injected_for_harness("peer-alpha").expect("principal");
        let (store, effects) = store(OwnerSiteAuthoritySnapshot::InjectedForHarness(principal));
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");

        assert_eq!(store.pending_count(), 1);
        assert_eq!(store.pre_effect_admission(&resource), Ok(()));
        assert_eq!(store.pending_count(), 1, "PR1 admission must not consume");
        assert_eq!(effects.snapshot().pre_effect_admissions, 1);

        let other = OwnerSiteResource::from_route_claw("otherclaw").expect("resource");
        assert_eq!(
            store.pre_effect_admission(&other),
            Err(OwnerSitePreEffectRejection::ScopeMismatch)
        );
        assert_eq!(store.pending_count(), 1);
        assert_eq!(effects.snapshot().pre_effect_admissions, 2);
    }

    #[test]
    fn unavailable_authority_fails_closed_without_mutation() {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        for authority in [
            OwnerSiteAuthoritySnapshot::Unavailable,
            OwnerSiteAuthoritySnapshot::Stale,
        ] {
            let (store, effects) = store(authority);
            assert_eq!(
                store.pre_effect_admission(&resource),
                Err(OwnerSitePreEffectRejection::AuthorityUnavailable)
            );
            assert_eq!(store.pending_count(), 1);
            assert_eq!(effects.snapshot().pre_effect_admissions, 1);
        }
    }
}
