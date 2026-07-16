//! Pre-effect owner-site capability types.
//!
//! This module intentionally stops before proof verification, capability
//! redemption, authority-provider wiring, or any backend connection. The
//! separate `owner_site_challenge` and `owner_site_authority` modules now hold
//! only pre-effect staging types; neither is reachable from production routing.
//! In particular, the only admitting capability remains a crate-test fixture,
//! not a production authority or a bearer wire format.

use std::net::SocketAddr;

use crate::owner_site_authority::OwnerSiteAuthoritySnapshot;

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
    pre_auth: OwnerSitePreAuthIntent,
    actor_id: String,
}

impl OwnerSiteIntent {
    /// Builds a server-owned intent for crate-local route tests only.
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        household_id: &str,
        actor_id: &str,
        resource: OwnerSiteResource,
    ) -> Result<Self, OwnerSiteIntentError> {
        let request = OwnerSiteCanonicalRequest::injected_for_harness(
            OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x42; 32],
        )?;
        Self::injected_for_harness_with_request(
            household_id,
            "owner-site-mesh",
            actor_id,
            resource,
            request,
        )
    }

    /// Builds the full canonical intent shape for tests that need to exercise
    /// route/body/network transcript separation.
    #[cfg(test)]
    pub(crate) fn injected_for_harness_with_request(
        household_id: &str,
        network_id: &str,
        actor_id: &str,
        resource: OwnerSiteResource,
        request: OwnerSiteCanonicalRequest,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            pre_auth: OwnerSitePreAuthIntent::injected_for_harness(
                household_id,
                network_id,
                resource,
                request,
            )?,
            actor_id: validated_server_identifier(actor_id)?,
        })
    }

    #[must_use]
    pub(crate) fn household_id(&self) -> &str {
        self.pre_auth.household_id()
    }

    #[must_use]
    pub(crate) fn actor_id(&self) -> &str {
        &self.actor_id
    }

    #[must_use]
    pub(crate) fn network_id(&self) -> &str {
        self.pre_auth.network_id()
    }

    #[must_use]
    pub(crate) fn resource(&self) -> &OwnerSiteResource {
        self.pre_auth.resource()
    }

    #[must_use]
    #[allow(dead_code)] // carried for the later A2 transcript builder
    pub(crate) fn request(&self) -> &OwnerSiteCanonicalRequest {
        self.pre_auth.request()
    }

    #[must_use]
    #[allow(dead_code)] // consumed by the future A2 M1/M3 type bridge
    pub(crate) fn pre_auth(&self) -> &OwnerSitePreAuthIntent {
        &self.pre_auth
    }
}

/// The operation namespace is intentionally distinct from `household_rs`
/// caveat operations until the owner-site PoP/challenge design is reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteOperation {
    #[cfg(test)]
    Open,
}

/// Exact intent material that may be known at A2 `M1` before a device actor is
/// authenticated. It intentionally contains no actor or remote principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSitePreAuthIntent {
    household_id: String,
    network_id: String,
    operation: OwnerSiteOperation,
    resource: OwnerSiteResource,
    request: OwnerSiteCanonicalRequest,
}

impl OwnerSitePreAuthIntent {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        household_id: &str,
        network_id: &str,
        resource: OwnerSiteResource,
        request: OwnerSiteCanonicalRequest,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            household_id: validated_server_identifier(household_id)?,
            network_id: validated_component(network_id)?,
            operation: OwnerSiteOperation::Open,
            resource,
            request,
        })
    }

    #[must_use]
    pub(crate) fn household_id(&self) -> &str {
        &self.household_id
    }

    #[must_use]
    pub(crate) fn network_id(&self) -> &str {
        &self.network_id
    }

    #[must_use]
    pub(crate) fn resource(&self) -> &OwnerSiteResource {
        &self.resource
    }

    #[must_use]
    #[allow(dead_code)] // carried for the later A2 transcript builder
    pub(crate) fn request(&self) -> &OwnerSiteCanonicalRequest {
        &self.request
    }
}

/// Canonical HTTP verb committed into the future A2 transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // the A2 wire slice constructs this canonical verb
pub(crate) enum OwnerSiteRequestMethod {
    Post,
}

/// Server-owned canonical request material committed into the future A2
/// transcript. It is not an HTTP parser and has no wire encoding in PR2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteCanonicalRequest {
    method: OwnerSiteRequestMethod,
    route: String,
    body_hash: [u8; 32],
}

impl OwnerSiteCanonicalRequest {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        method: OwnerSiteRequestMethod,
        route: &str,
        body_hash: [u8; 32],
    ) -> Result<Self, OwnerSiteIntentError> {
        if route.is_empty()
            || route.len() > 256
            || !route.starts_with('/')
            || !route.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'{' | b'}' | b'-')
            })
        {
            return Err(OwnerSiteIntentError::InvalidRoute);
        }
        Ok(Self {
            method,
            route: route.to_owned(),
            body_hash,
        })
    }
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
#[allow(dead_code)] // retained for the staged canonical-request constructor
pub(crate) enum OwnerSiteIntentError {
    InvalidComponent,
    InvalidRoute,
}

pub(crate) fn validated_component(value: &str) -> Result<String, OwnerSiteIntentError> {
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

/// Canonical server-owned identity component.
///
/// Household and member identifiers use reserved underscore prefixes such as
/// `hh_` and `g_`; route resource names deliberately continue to use the
/// stricter [`validated_component`] grammar above.
#[allow(dead_code)] // invoked by the staged A2 construction path in the next slice
pub(crate) fn validated_server_identifier(value: &str) -> Result<String, OwnerSiteIntentError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
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
            capability.scope.intent.household_id(),
            &capability.scope.intent.actor_id,
            capability.scope.intent.pre_auth.operation,
            capability.scope.backend.socket,
        );

        if !capability
            .scope
            .authority
            .admits_pre_effect(&capability.scope.intent)
        {
            return Err(OwnerSitePreEffectRejection::AuthorityUnavailable);
        }
        if capability.scope.intent.resource() != resource {
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
/// this pre-effect slice exposes no API that can bind, mint, claim a challenge,
/// dial, or write site bytes.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct OwnerSiteEffectCounters {
    listener_binds: AtomicUsize,
    mints: AtomicUsize,
    consumes: AtomicUsize,
    proxy_dials: AtomicUsize,
    site_bytes: AtomicUsize,
    challenge_issues: AtomicUsize,
    challenge_claims: AtomicUsize,
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
    pub(crate) challenge_issues: usize,
    pub(crate) challenge_claims: usize,
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
            challenge_issues: self.challenge_issues.load(Ordering::SeqCst),
            challenge_claims: self.challenge_claims.load(Ordering::SeqCst),
            pre_effect_admissions: self.pre_effect_admissions.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_site_authority::active_authority_fixture;

    fn scope(actor_id: &str, authority: OwnerSiteAuthoritySnapshot) -> OwnerSiteCapabilityScope {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let intent = OwnerSiteIntent::injected_for_harness("household-alpha", actor_id, resource)
            .expect("intent");
        let backend =
            OwnerSiteBackend::numeric_loopback("127.0.0.1:7411".parse().expect("loopback"))
                .expect("loopback backend");
        OwnerSiteCapabilityScope::new(intent, authority, backend)
    }

    fn store(
        actor_id: &str,
        authority: OwnerSiteAuthoritySnapshot,
    ) -> (OwnerSiteCapabilityStore, Arc<OwnerSiteEffectCounters>) {
        OwnerSiteCapabilityStore::injected_for_harness(OwnerSiteCapability::injected_for_harness(
            scope(actor_id, authority),
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
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let (actor_id, authority) =
            active_authority_fixture("household-alpha", resource).expect("typed authority fixture");
        let (store, effects) = store(&actor_id, authority);
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
    fn resolved_intent_keeps_pre_auth_route_and_body_commitment_exact() {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let request = OwnerSiteCanonicalRequest::injected_for_harness(
            OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x72; 32],
        )
        .expect("canonical request");
        let intent = OwnerSiteIntent::injected_for_harness_with_request(
            "household-alpha",
            "owner-site-mesh",
            "owner-alpha",
            resource,
            request,
        )
        .expect("intent");

        assert_eq!(intent.request(), intent.pre_auth().request());
        assert_eq!(intent.network_id(), "owner-site-mesh");
    }

    #[test]
    fn unavailable_authority_fails_closed_without_mutation() {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        for authority in [
            OwnerSiteAuthoritySnapshot::Unavailable,
            OwnerSiteAuthoritySnapshot::Stale,
            OwnerSiteAuthoritySnapshot::Mismatch,
            OwnerSiteAuthoritySnapshot::Revoked,
        ] {
            let (store, effects) = store("owner-alpha", authority);
            assert_eq!(
                store.pre_effect_admission(&resource),
                Err(OwnerSitePreEffectRejection::AuthorityUnavailable)
            );
            assert_eq!(store.pending_count(), 1);
            assert_eq!(effects.snapshot().pre_effect_admissions, 1);
        }
    }
}
