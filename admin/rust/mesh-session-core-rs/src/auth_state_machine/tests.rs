#![cfg(test)]

use super::*;
use crate::error::RekeyError;
use crate::ingress::{CeremonyBudget, CeremonyDeadlinePolicy};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

struct TestKMesh(SigningKey);
impl MeshSessionFrameSigner for TestKMesh {
    fn sign_mesh_session_frame(
        &self,
        preimage: &crate::auth_frames::MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
}

/// Test-only stand-in that accepts any delegation, unconditionally —
/// proves the *state machine's wiring* (order of calls, what gates
/// what) independent of the still-undecided real preimage/verifier.
/// Never shipped as part of this crate's real API.
struct AlwaysAcceptDelegation;
impl DelegationSignatureVerifier for AlwaysAcceptDelegation {
    fn verify_delegation(
        &self,
        _delegation: &MeshSessionDelegation,
        _deadline: &CeremonyDeadline,
    ) -> Result<(), crate::error::DelegationError> {
        Ok(())
    }
}

/// Always-succeeding D1Admission double: `Pending<'a>`/`Active<'a>` are
/// just `()`. Used by tests where D1 admission's own mechanism isn't
/// under test — the dedicated D1 REDs (and the GAT/Drop-lock-free
/// proofs in `intent.rs`'s own test module) inject their own,
/// genuinely borrowed doubles.
impl crate::intent::D1Pending<()> for () {
    fn commit_after_ack(self) {}
    fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
        crate::intent::D1CancelOutcome::CancelledAndRemoved
    }
}

struct AlwaysAdmitD1;
impl crate::intent::D1Admission for AlwaysAdmitD1 {
    type Pending<'a> = ();
    type Active<'a> = ();
    fn reserve_pending(
        &self,
        _key: &crate::intent::D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<(), crate::error::IntentError> {
        Ok(())
    }
}

/// D4 resolver double pre-configured with a fixed, independently-known
/// authority — NOT derived from whatever a peer's frame claims
/// (2026-08-04, item 5). Every call site builds one from the SAME
/// values it independently used to construct the initiator's own
/// `LocalIdentity`/delegation, so this stays a genuine (if simplified)
/// resolver double rather than routing the peer's claim back through
/// itself — the dedicated resolver REDs additionally inject one
/// configured to return a deliberately MISMATCHED key/generation.
struct FixedResolver {
    delegated_pub: Vec<u8>,
    generation: u64,
    not_after: u64,
}
impl crate::intent::RetainedGenerationResolver for FixedResolver {
    fn resolve(
        &self,
        _hh_id: &str,
        _initiator_m_id: &str,
        _channel: ExpectedChannel,
        _delegated_key_id: &str,
        _deadline: &CeremonyDeadline,
    ) -> Result<crate::intent::ResolvedSignerAuthority, crate::error::IntentError> {
        Ok(crate::intent::ResolvedSignerAuthority::new(
            self.delegated_pub.clone(),
            self.generation,
            self.not_after,
        ))
    }
}

/// In-memory, single-process nonce ledger double — real check-and-set
/// semantics (a `HashSet`), enough to prove replay rejection without
/// any real persistence. `not_after`/`digest`/`deadline` are accepted
/// (matching the real trait shape) but unused by this simple double —
/// no eviction/blocking policy is under test here.
struct InMemoryLedger {
    consumed: std::sync::Mutex<std::collections::HashSet<crate::intent::IntentNonceKey>>,
}
impl InMemoryLedger {
    fn new() -> Self {
        Self {
            consumed: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}
impl crate::intent::IntentNonceLedger for InMemoryLedger {
    fn consume(
        &self,
        key: &crate::intent::IntentNonceKey,
        _not_after: u64,
        _digest: &[u8; 32],
        _channel: ExpectedChannel,
        _deadline: &CeremonyDeadline,
    ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
        let mut set = self.consumed.lock().unwrap();
        if !set.insert(key.clone()) {
            return Ok(crate::intent::NonceConsumeOutcome::AlreadyConsumed);
        }
        Ok(crate::intent::NonceConsumeOutcome::Committed)
    }
}

/// Panics if `consume` is ever called — proves a rejection happened
/// strictly BEFORE the single nonce-consumption call site (D9
/// addendum §5), the same "zero X before Y" discipline `PanicsOnIo`
/// already applies to I/O elsewhere in this test suite.
struct PanicsIfConsumed;
impl crate::intent::IntentNonceLedger for PanicsIfConsumed {
    fn consume(
        &self,
        _key: &crate::intent::IntentNonceKey,
        _not_after: u64,
        _digest: &[u8; 32],
        _channel: ExpectedChannel,
        _deadline: &CeremonyDeadline,
    ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
        panic!("nonce was consumed before the D9 addendum SS4.8 authority-scoping check rejected");
    }
}

/// Fixed-reading clock double. Fine for happy-path tests where the
/// deadline is far in the future; the deadline-specific REDs use a
/// dedicated advancing/expired clock instead.
struct FixedClock(u64);
impl crate::intent::Clock for FixedClock {
    fn now(&self) -> Result<u64, crate::error::IntentError> {
        Ok(self.0)
    }
}

fn far_future_deadline() -> CeremonyDeadline {
    CeremonyDeadline::for_test(std::time::Instant::now(), Duration::from_secs(3600))
}

/// A generous `CeremonyBudget` for happy-path tests where the ceremony
/// deadline itself isn't under test — the deadline-specific REDs build
/// their own tight/expired `CeremonyDeadline` via
/// `CeremonyDeadline::for_test`/`already_expired_for_test` instead.
fn far_future_budget() -> CeremonyBudget {
    let policy = CeremonyDeadlinePolicy::new(Duration::from_secs(3600)).unwrap();
    CeremonyBudget::new(Duration::from_secs(3600), &policy).unwrap()
}

/// Builds a `PendingIntent` whose initiator-side fields (hh_id/m_id/
/// fingerprint/delegated_key_id) are derived from `local` (2026-08-04,
/// @kiana: `IntentDetails` no longer carries them independently — see
/// its own doc), `target_*` fields name the given responder, and
/// `checkpoint_hash` matches `checkpoint` exactly (so
/// `PendingIntent::verify_binds_to`'s checkpoint-binding check passes
/// by construction in fixtures that pass the SAME checkpoint to both
/// this and the later `run_initiator_handshake` call).
#[allow(clippy::too_many_arguments)]
fn pending_intent_for(
    k_mesh: &TestKMesh,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    target_m_id: &str,
    target_cert_fingerprint: Vec<u8>,
    nonce: [u8; 32],
    not_after: u64,
    channel: ExpectedChannel,
) -> crate::intent::PendingIntent {
    crate::intent::PendingIntent::build_and_sign(
        crate::intent::IntentDetails {
            target_m_id: target_m_id.to_string(),
            target_cert_fingerprint,
            nonce: nonce.to_vec(),
            not_after,
        },
        channel,
        local,
        checkpoint,
        k_mesh,
    )
    .unwrap()
}

fn fixed_checkpoint() -> LocalCheckpoint {
    LocalCheckpoint {
        hash: vec![0xAA; 32],
        sequence: 1,
        event_head: vec![0xBB; 32],
        not_after: 1_000_000,
    }
}

/// A delegation whose `delegated_pub` really is the SEC1-compressed
/// form of `verifying` (so `verifier_from_delegated_pub`, which reads
/// `delegated_pub` straight out of the received frame, constructs a
/// verifier that actually matches the key `k_mesh` signs with),
/// whose `hh_id`/`delegator_m_id`/`delegator_cert_fingerprint` match
/// the identity presenting it (so `check_partial_binding`'s
/// non-roster triple-equality checks — which compare the frame's own
/// `hh_id`/`self_m_id`/`self_cert_fingerprint` against these exact
/// fields — actually pass), and whose `roles`/`transcript_kinds`
/// exactly match `EXPECTED_DELEGATION_ROLES`/`EXPECTED_TRANSCRIPT_KINDS`
/// (2026-08-04, @kiana, round 5: `pass_delegation_gate` now enforces
/// this exactly, so every fixture that expects to pass the gate needs
/// to already satisfy it — see the round-5 REDs for what happens when
/// it doesn't).
fn delegation_for_key(
    verifying: &VerifyingKey,
    hh_id: &str,
    delegator_m_id: &str,
    delegator_cert_fingerprint: Vec<u8>,
    not_before: u64,
    not_after: u64,
) -> MeshSessionDelegation {
    let delegated_pub = verifying.to_encoded_point(true).as_bytes().to_vec();
    crate::delegation::DelegationWire {
        version: crate::delegation::DELEGATION_VERSION,
        kind: crate::delegation::DELEGATION_KIND.to_string(),
        domain: crate::delegation::DELEGATION_DOMAIN.to_string(),
        hh_id: hh_id.to_string(),
        delegator_m_id: delegator_m_id.to_string(),
        delegator_cert_fingerprint,
        delegated_pub,
        delegated_key_id: "key-1".to_string(),
        profile: crate::delegation::DELEGATION_PROFILE.to_string(),
        transcript_kinds: EXPECTED_TRANSCRIPT_KINDS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        roles: EXPECTED_DELEGATION_ROLES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        channel: "dev".to_string(),
        serial: 1,
        not_before,
        not_after,
        sig: vec![0u8; 64],
    }
    .try_into()
    .unwrap()
}

/// Like [`delegation_for_key`], but every scoping field is caller
/// controlled — used to build deliberately mis-scoped delegations for
/// the round-5 REDs (missing/extra/duplicate role or transcript kind,
/// wrong channel). `hh_id`/`delegator_m_id`/`delegator_cert_fingerprint`
/// still default to values `pass_delegation_gate`'s scoping checks
/// don't depend on — irrelevant for these tests since the checks
/// under test fire before `check_partial_binding` is ever reached.
fn delegation_wire_with(
    verifying: &VerifyingKey,
    roles: Vec<String>,
    transcript_kinds: Vec<String>,
    channel: &str,
) -> MeshSessionDelegation {
    let delegated_pub = verifying.to_encoded_point(true).as_bytes().to_vec();
    crate::delegation::DelegationWire {
        version: crate::delegation::DELEGATION_VERSION,
        kind: crate::delegation::DELEGATION_KIND.to_string(),
        domain: crate::delegation::DELEGATION_DOMAIN.to_string(),
        hh_id: "hh-1".to_string(),
        delegator_m_id: "someone-1".to_string(),
        delegator_cert_fingerprint: vec![0xCC; 32],
        delegated_pub,
        delegated_key_id: "key-1".to_string(),
        profile: crate::delegation::DELEGATION_PROFILE.to_string(),
        transcript_kinds,
        roles,
        channel: channel.to_string(),
        serial: 1,
        not_before: 0,
        not_after: u64::MAX / 2,
        sig: vec![0u8; 64],
    }
    .try_into()
    .unwrap()
}

fn valid_roles() -> Vec<String> {
    EXPECTED_DELEGATION_ROLES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn valid_transcript_kinds() -> Vec<String> {
    EXPECTED_TRANSCRIPT_KINDS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn identity(
    hh_id: &str,
    m_id: &str,
    cert_fingerprint: Vec<u8>,
    delegation: MeshSessionDelegation,
) -> LocalIdentity {
    LocalIdentity {
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        cert_fingerprint,
        delegation,
    }
}

/// Drives a full, real handshake over a real TCP loopback with both
/// sides using `AlwaysAcceptDelegation` (the delegation-gate wiring is
/// covered separately by `delegation_gate_blocks_with_no_verifier_configured`)
/// and a real per-side P-256 K_mesh keypair, each with a delegation
/// whose `delegated_pub` genuinely matches that key. Returns both
/// sides' Active sessions for further assertions (POS-4, etc.).
fn full_handshake() -> (
    ActiveMeshSession<TcpStream, ()>,
    ActiveMeshSession<TcpStream, ()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
            .unwrap()
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x99; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_session = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    )
    .unwrap();

    let responder_session = responder.join().unwrap();
    (initiator_session, responder_session)
}

/// item 5 RED (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`
/// P0-5): a `RetainedGenerationResolver` that returns a genuinely
/// DIFFERENT key than the one the initiator actually signed with must
/// cause rejection — proving `initiator_verifier` is built from the
/// RESOLVED key, not `proof_i.delegation().delegated_pub()` (the
/// peer's own embedded, self-consistency-only claim). If this crate
/// regressed to building the verifier from the peer's claim again,
/// this test would incorrectly pass (Active) instead of failing.
#[test]
fn red_responder_resolver_returning_a_different_key_than_signed_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);
    // A THIRD, unrelated key — never used to sign anything — is what
    // the resolver (wrongly, deliberately for this test) returns.
    let wrong_key = SigningKey::random(&mut OsRng);
    let wrong_verifying = VerifyingKey::from(&wrong_key);
    assert_ne!(
        initiator_verifying.to_encoded_point(true).as_bytes(),
        wrong_verifying.to_encoded_point(true).as_bytes(),
        "test fixture bug: wrong_key must differ from the real initiator key"
    );

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);
    let resolver_returning_wrong_key = FixedResolver {
        delegated_pub: wrong_verifying.to_encoded_point(true).as_bytes().to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                &resolver_returning_wrong_key,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x81; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    // The initiator genuinely signs with its real key — the responder
    // will reject not because the initiator misbehaved, but because
    // the (misconfigured, for this test) resolver disagrees.
    let _initiator_result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );

    let responder_result = responder.join().unwrap();
    match responder_result {
        Err(AuthFrameError::BadSignature) => {}
        Err(other) => {
            panic!("expected BadSignature (resolver's wrong key rejected), got {other:?}")
        }
        Ok(_) => panic!(
            "expected the responder to reject Proof-I's signature against the \
                 resolver's (wrong) key, but it reached Active"
        ),
    }
}

#[test]
fn full_handshake_reaches_active_on_both_sides_with_matching_h_final() {
    let (initiator, responder) = full_handshake();
    assert_eq!(initiator.h_final(), responder.h_final());
    assert_eq!(initiator.peer_m_id(), "responder-1");
    assert_eq!(responder.peer_m_id(), "initiator-1");
    assert_eq!(initiator.ingress_evidence().observed_at, 2);
    assert_eq!(responder.ingress_evidence().observed_at, 1);
    // WIP audit point A, v6 §10: both sides carry the SAME computed
    // expires_at. `full_handshake`'s fixtures use `u64::MAX / 2` for
    // local/peer delegation, lease, ingress_expiry, and the intent's
    // own not_after — but `fixed_checkpoint().not_after` is
    // `1_000_000`, strictly the smallest of the 6, so the true
    // minimum (and therefore the stored value) must be exactly
    // `1_000_000`, not `u64::MAX / 2` — proving `effective_expires_at`
    // actually picked the checkpoint component, not just echoed
    // whichever component happens to be listed first/last.
    assert_eq!(initiator.expires_at(), 1_000_000);
    assert_eq!(responder.expires_at(), 1_000_000);
}

/// WIP audit point A unit tests: `effective_expires_at` genuinely
/// picks the minimum across all 6 components (not just the first/last
/// one), and `check_effective_expiry`'s half-open boundary is exact —
/// `expires_at - 1` accepted, `== expires_at` rejected.
#[test]
fn effective_expires_at_picks_the_true_minimum_from_any_position() {
    // Each of the 6 positions gets a turn being the unique minimum.
    let base = 1_000_000u64;
    let components = |min_at: usize| -> [u64; 6] {
        let mut c = [base; 6];
        c[min_at] = 500;
        c
    };
    for pos in 0..6 {
        let c = components(pos);
        let got = effective_expires_at(c[0], c[1], c[2], c[3], c[4], c[5]);
        assert_eq!(got, 500, "position {pos} should have been the minimum");
    }
}

#[test]
fn red_check_effective_expiry_boundary_expires_at_minus_one_accepted_equality_rejected() {
    let expires_at = 1_000u64;
    assert!(check_effective_expiry(expires_at - 1, expires_at).is_ok());
    assert!(matches!(
        check_effective_expiry(expires_at, expires_at),
        Err(AuthFrameError::Intent(
            crate::error::IntentError::TtlInvalid
        ))
    ));
}

/// D9 addendum SS4.8 RED (2026-08-04, @kiana, blocker): a real,
/// validly-signed intent whose OWN `not_after` (2_000) exceeds the
/// initiator delegation's `not_after` (1_000) — an authority-scoping
/// violation the `effective_expires_at = min(...)` composite alone
/// does NOT catch, since `now` (0, via `FixedClock(0)`) is still
/// below both values. `PanicsIfConsumed` proves the rejection happens
/// strictly before the single nonce-consume call site. Hand-crafted
/// (bypassing `run_initiator_handshake`, whose own
/// `PendingIntent::verify_binds_to` preflight would otherwise reject
/// this before any byte is sent) to exercise the RESPONDER's
/// independent, defense-in-depth check on what a peer actually sent
/// — same pattern as `red_proof_i_checkpoint_mutant_rejected_by_responder`.
#[test]
fn red_intent_not_after_exceeding_delegation_not_after_rejected_before_nonce_consume() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    // Initiator delegation authorizes only up to not_after = 1_000 —
    // strictly less than the intent's own claimed not_after below.
    // `now` (FixedClock(0)) stays below both, so the min-based
    // composite alone would incorrectly accept this. Generated before
    // the responder thread spawns so the resolver double can be
    // pre-configured with the real key/expiry, same as every other
    // call site.
    const DELEGATION_NOT_AFTER: u64 = 1_000;
    const INTENT_NOT_AFTER: u64 = 2_000;
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: DELEGATION_NOT_AFTER,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &PanicsIfConsumed,
                &AlwaysAdmitD1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let mut sock = TcpStream::connect(addr).unwrap();
    let handshake =
        noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
        AuthFrame::ProofR(_) => {}
        _ => panic!("expected ProofR"),
    }

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        DELEGATION_NOT_AFTER,
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            initiator_delegation.clone(),
        ),
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x85; 32],
        INTENT_NOT_AFTER,
        ExpectedChannel::Dev,
    );
    send_intent_record(
        &mut sock,
        &mut transport,
        pending_intent.intent(),
        &far_future_deadline(),
    )
    .unwrap();
    let connection_intent_digest = ConnectionIntentDigest::from_bytes(
        crate::intent::intent_digest(pending_intent.intent()).unwrap(),
    );
    let checkpoint = fixed_checkpoint();
    let proof_i = ProofI::new(
        h_final.clone(),
        "hh-1".to_string(),
        "initiator-1".to_string(),
        "responder-1".to_string(),
        vec![0xEE; 32],
        vec![0xCC; 32],
        checkpoint.hash.clone(),
        checkpoint.sequence,
        checkpoint.event_head.clone(),
        checkpoint.not_after,
        initiator_delegation,
        connection_intent_digest,
        vec![0u8; 64],
    )
    .unwrap();
    let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
    send_frame(
        &mut sock,
        &mut transport,
        &AuthFrame::ProofI(proof_i),
        &far_future_deadline(),
    )
    .unwrap();

    let responder_result = responder.join().unwrap();
    assert!(matches!(
        responder_result,
        Err(AuthFrameError::Intent(
            crate::error::IntentError::TtlInvalid
        ))
    ));
}

/// Like `full_handshake`, but lets the caller substitute the
/// initiator's own checkpoint (used for the checkpoint-mutant REDs)
/// and returns both sides' raw `Result` instead of unwrapping, so a
/// test can assert on the responder's rejection.
type SessionResult = Result<ActiveMeshSession<TcpStream, ()>, AuthFrameError>;

fn full_handshake_with_initiator_checkpoint(
    initiator_checkpoint: LocalCheckpoint,
) -> (SessionResult, SessionResult) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &initiator_checkpoint,
        "responder-1",
        vec![0xCC; 32],
        [0x98; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &initiator_checkpoint,
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );

    let responder_result = responder.join().unwrap();
    (initiator_result, responder_result)
}

// These three mutate the INITIATOR's own local checkpoint away from
// what the responder's real Proof-R carries. Since the initiator
// checks received Proof-R against its own checkpoint *before* it ever
// builds/sends Proof-I, this is caught on the initiator side — proving
// check_checkpoint's full-4-scalar comparison on the Proof-R path.
// (The responder never receives a Proof-I at all in this shape, so it
// just observes the dropped connection, not CheckpointMismatch
// itself — see red_proof_i_checkpoint_mutant_rejected_by_responder
// below for the symmetric proof on the Proof-I/responder path.)
#[test]
fn red_checkpoint_sequence_mutant_rejected() {
    let mut bad = fixed_checkpoint();
    bad.sequence += 1; // hash still matches; sequence alone differs
    let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
    assert!(matches!(
        initiator_result,
        Err(AuthFrameError::CheckpointMismatch)
    ));
}

#[test]
fn red_checkpoint_event_head_mutant_rejected() {
    let mut bad = fixed_checkpoint();
    bad.event_head = vec![0xFF; 32]; // hash still matches; event_head alone differs
    let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
    assert!(matches!(
        initiator_result,
        Err(AuthFrameError::CheckpointMismatch)
    ));
}

#[test]
fn red_checkpoint_not_after_mutant_rejected() {
    let mut bad = fixed_checkpoint();
    bad.not_after += 1; // hash still matches; not_after alone differs
    let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
    assert!(matches!(
        initiator_result,
        Err(AuthFrameError::CheckpointMismatch)
    ));
}

#[test]
fn red_proof_i_expected_peer_mismatch_rejected_before_final_confirm() {
    // Simulates a validly-signed Proof-I whose signed intent was to
    // reach a DIFFERENT responder (R2) arriving instead at this
    // responder (R1) — constructed directly (bypassing
    // run_initiator_handshake's own field population, which would
    // never build this) to prove R1's own check is real and not
    // merely redundant with the initiator's ExpectedResponder check.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    // Generated before the responder thread spawns (this test never
    // reaches the resolver — it rejects on ExpectedPeerMismatch first
    // — but every call site pre-configures a real one regardless).
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    // Attacker/misdirected initiator: real Noise handshake, real
    // Proof-R receipt, but a hand-built Proof-I whose
    // expected_peer_m_id/fingerprint name a DIFFERENT machine
    // ("responder-2") than the one it is actually talking to.
    let mut sock = TcpStream::connect(addr).unwrap();
    let handshake =
        noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
        AuthFrame::ProofR(_) => {}
        _ => panic!("expected ProofR"),
    }

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let checkpoint = fixed_checkpoint();
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            initiator_delegation.clone(),
        ),
        &checkpoint,
        "responder-1",
        vec![0xCC; 32],
        [0x97; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    send_intent_record(
        &mut sock,
        &mut transport,
        pending_intent.intent(),
        &far_future_deadline(),
    )
    .unwrap();
    let connection_intent_digest = ConnectionIntentDigest::from_bytes(
        crate::intent::intent_digest(pending_intent.intent()).unwrap(),
    );
    let proof_i = ProofI::new(
        h_final.clone(),
        "hh-1".to_string(),
        "initiator-1".to_string(),
        "responder-2".to_string(), // WRONG — real peer is responder-1
        vec![0xEE; 32],
        vec![0xDD; 32], // some other machine's fingerprint
        checkpoint.hash.clone(),
        checkpoint.sequence,
        checkpoint.event_head.clone(),
        checkpoint.not_after,
        initiator_delegation,
        connection_intent_digest,
        vec![0u8; 64],
    )
    .unwrap();
    let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
    send_frame(
        &mut sock,
        &mut transport,
        &AuthFrame::ProofI(proof_i),
        &far_future_deadline(),
    )
    .unwrap();

    let responder_result = responder.join().unwrap();
    assert!(matches!(
        responder_result,
        Err(AuthFrameError::ExpectedPeerMismatch)
    ));
}

#[test]
fn red_proof_i_checkpoint_mutant_rejected_by_responder() {
    // Symmetric to the expected-peer test above: a hand-built Proof-I,
    // correctly addressed this time, but with checkpoint_sequence
    // mutated away from the responder's real checkpoint — proves the
    // RESPONDER's own check_checkpoint call (on the Proof-I path)
    // independently catches all 4 scalars, not just hash, mirroring
    // the initiator-side proof above (which exercises the Proof-R
    // path instead).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let mut sock = TcpStream::connect(addr).unwrap();
    let handshake =
        noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
        AuthFrame::ProofR(_) => {}
        _ => panic!("expected ProofR"),
    }

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            initiator_delegation.clone(),
        ),
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x96; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    send_intent_record(
        &mut sock,
        &mut transport,
        pending_intent.intent(),
        &far_future_deadline(),
    )
    .unwrap();
    let connection_intent_digest = ConnectionIntentDigest::from_bytes(
        crate::intent::intent_digest(pending_intent.intent()).unwrap(),
    );
    let mut bad_checkpoint = fixed_checkpoint();
    bad_checkpoint.sequence += 1; // hash matches; sequence alone differs
    let proof_i = ProofI::new(
        h_final.clone(),
        "hh-1".to_string(),
        "initiator-1".to_string(),
        "responder-1".to_string(), // correctly addressed this time
        vec![0xEE; 32],
        vec![0xCC; 32], // matches the real responder's fingerprint
        bad_checkpoint.hash.clone(),
        bad_checkpoint.sequence,
        bad_checkpoint.event_head.clone(),
        bad_checkpoint.not_after,
        initiator_delegation,
        connection_intent_digest,
        vec![0u8; 64],
    )
    .unwrap();
    let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
    send_frame(
        &mut sock,
        &mut transport,
        &AuthFrame::ProofI(proof_i),
        &far_future_deadline(),
    )
    .unwrap();

    let responder_result = responder.join().unwrap();
    assert!(matches!(
        responder_result,
        Err(AuthFrameError::CheckpointMismatch)
    ));
}

/// A stream double that panics the instant anything touches it — used
/// to prove `check_signer_matches_delegation` rejects a mismatched
/// signer key *before any write* (2026-08-04, @kiana, round 3: "REDs:
/// ... signer public key != delegation rejeitado antes de qualquer
/// write"). A plain `matches!` on the returned error would only prove
/// the function eventually returns the right `Err` — it would not
/// prove the stream (and therefore the Noise handshake, and every
/// frame write) was never touched first. If the check ran even one
/// statement too late, this panics instead of silently passing.
struct PanicsOnIo;
impl Read for PanicsOnIo {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        panic!("stream was read before check_signer_matches_delegation rejected");
    }
}
impl Write for PanicsOnIo {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        panic!("stream was written before check_signer_matches_delegation rejected");
    }
    fn flush(&mut self) -> std::io::Result<()> {
        panic!("stream was flushed before check_signer_matches_delegation rejected");
    }
}
impl wire::DeadlineBoundedIo for PanicsOnIo {
    fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
        panic!("stream deadline was armed before rejection");
    }
}

#[test]
fn red_responder_signer_key_mismatched_delegation_rejected_before_any_write() {
    let delegation_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&delegation_key),
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
    // Deliberately a DIFFERENT key than the one delegation.delegated_pub
    // encodes — the signer does not hold the delegated key.
    let mismatched_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));

    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_responder_handshake(
        ingress,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &mismatched_k_mesh,
        &InMemoryLedger::new(),
        &AlwaysAdmitD1,
        &FixedClock(0),
        // Never reached — rejection happens before the first Noise
        // byte, let alone the resolver seam.
        &FixedResolver {
            delegated_pub: vec![],
            generation: 0,
            not_after: 0,
        },
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::SignerKeyMismatchDelegation)
    ));
}

#[test]
fn red_initiator_signer_key_mismatched_delegation_rejected_before_any_write() {
    let delegation_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&delegation_key),
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
    let mismatched_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));
    let pending_intent = pending_intent_for(
        &mismatched_k_mesh,
        &local,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x95; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );

    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_initiator_handshake(
        ingress,
        pending_intent,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &mismatched_k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::SignerKeyMismatchDelegation)
    ));
}

/// Total-ceremony slow-loris RED (2026-08-04, @kiana, definitive):
/// an admission whose `CeremonyDeadline` is already fully expired
/// (`CeremonyDeadline::already_expired_for_test`, threaded in via
/// `PrevalidatedIngress::new_for_test` — the only way to construct a
/// pre-expired deadline outside production code) must be rejected
/// before the FIRST Noise byte, on both sides — `PanicsOnIo` proves
/// zero I/O of any kind (read, write, or even arming/clearing a
/// deadline) is ever attempted.
#[test]
fn red_initiator_total_ceremony_deadline_already_expired_zero_io_attempted() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&key),
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
    let k_mesh = TestKMesh(key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &local,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x89; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );

    let ingress = PrevalidatedIngress::new_for_test(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        CeremonyDeadline::already_expired_for_test(),
    );
    let result = run_initiator_handshake(
        ingress,
        pending_intent,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::Intent(
            crate::error::IntentError::DeadlineExceeded
        ))
    ));
}

#[test]
fn red_responder_total_ceremony_deadline_already_expired_zero_io_attempted() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&key),
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
    let k_mesh = TestKMesh(key);

    let ingress = PrevalidatedIngress::new_for_test(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        CeremonyDeadline::already_expired_for_test(),
    );
    let result = run_responder_handshake(
        ingress,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &InMemoryLedger::new(),
        &AlwaysAdmitD1,
        &FixedClock(0),
        // Never reached — the deadline is already expired before any
        // I/O, let alone the resolver seam.
        &FixedResolver {
            delegated_pub: vec![],
            generation: 0,
            not_after: 0,
        },
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::Intent(
            crate::error::IntentError::DeadlineExceeded
        ))
    ));
}

/// 2026-08-04, @kiana, round 4: `SessionRekeyState::new`'s RNG-backed
/// mint used to run AFTER the responder durably wrote ActivateAck —
/// a real (if rare) RNG failure there would have let the write reach
/// the peer while this side returned `Err` and produced no
/// `ActiveMeshSession`, breaking the erratum's atomic-linearization
/// guarantee (peer could still reach Active alone). The mint now
/// runs first, before any I/O. Uses the `test_failpoint` (real
/// deterministic failure injection, not a hope that `OsRng` fails)
/// plus `PanicsOnIo` to prove not just that the right `Err` comes
/// back, but that the responder never touches the stream at all —
/// so, a fortiori, ActivateAck (and every earlier frame) is never
/// written.
#[test]
fn red_responder_rekey_mint_failure_writes_zero_bytes_before_returning() {
    let responder_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&responder_key),
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
    let k_mesh = TestKMesh(responder_key);

    crate::rekey::test_failpoint::force_next_fresh_to_fail();
    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_responder_handshake(
        ingress,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &InMemoryLedger::new(),
        &AlwaysAdmitD1,
        &FixedClock(0),
        // Never reached — the rekey mint fails before any I/O, let
        // alone the resolver seam.
        &FixedResolver {
            delegated_pub: vec![],
            generation: 0,
            not_after: 0,
        },
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::Rekey(RekeyError::RngFailure))
    ));
}

/// Same finding, initiator side (2026-08-04, @kiana, round 4): the
/// mint now runs before Proof-I, before Activate — before anything
/// is ever sent. If it fails, this side sends literally nothing, so
/// there is no way this attempt could cause a peer to reach Active.
/// `PanicsOnIo` proves zero I/O, not just the right `Err`.
#[test]
fn red_initiator_rekey_mint_failure_writes_zero_bytes_before_returning() {
    let initiator_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_for_key(
        &VerifyingKey::from(&initiator_key),
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &local,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x94; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );

    crate::rekey::test_failpoint::force_next_fresh_to_fail();
    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_initiator_handshake(
        ingress,
        pending_intent,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::Rekey(RekeyError::RngFailure))
    ));
}

// --- 2026-08-04, @kiana, round 5: pass_delegation_gate scope checks ---
// A validly-signed, correctly-bound delegation used to authorize
// frames regardless of what roles/transcript_kinds/channel it
// actually declared. These call `pass_delegation_gate` directly —
// it's a pure function of (delegation, policy, verifier, ctx,
// expected_channel) — since the new checks run right after signature
// verification and before check_partial_binding, `ctx` never needs
// to actually match for these to reach the check under test.

fn gate_ctx() -> PartialBindingInputs {
    PartialBindingInputs {
        proof_hh_id: "hh-1".to_string(),
        local_hh_id: "hh-1".to_string(),
        proof_self_m_id: "someone-1".to_string(),
        proof_self_cert_fingerprint: vec![0xCC; 32],
    }
}

/// Reads `deadline` itself and fails if already expired — proves the
/// SAME token `pass_delegation_gate` receives genuinely reaches a
/// real verifier's own check, not a fresh/independently-resettable
/// one a real implementation could use to extend its own budget past
/// what the ceremony allows (2026-08-04, @kiana, WIP audit, E3 seam).
struct DeadlineAwareVerifier;
impl DelegationSignatureVerifier for DeadlineAwareVerifier {
    fn verify_delegation(
        &self,
        _delegation: &MeshSessionDelegation,
        deadline: &CeremonyDeadline,
    ) -> Result<(), crate::error::DelegationError> {
        if deadline.is_expired() {
            return Err(crate::error::DelegationError::DeadlineExceeded);
        }
        Ok(())
    }
}

#[test]
fn red_pass_delegation_gate_propagates_the_official_ceremony_deadline_to_the_verifier() {
    let delegation = delegation_for_key(
        &VerifyingKey::from(&SigningKey::random(&mut OsRng)),
        "hh-1",
        "someone-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let expired = CeremonyDeadline::already_expired_for_test();
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &DeadlineAwareVerifier,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &expired,
    );
    assert!(matches!(result, Err(AuthFrameError::DelegationGate)));
}

#[test]
fn red_delegation_gate_rejects_roles_missing_a_required_role() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        vec!["initiator".to_string()], // omits "responder"
        valid_transcript_kinds(),
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationRolesMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_roles_with_an_unexpected_extra_role() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        vec![
            "initiator".to_string(),
            "responder".to_string(),
            "observer".to_string(), // not in EXPECTED_DELEGATION_ROLES
        ],
        valid_transcript_kinds(),
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationRolesMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_roles_with_a_duplicate() {
    // Same length as EXPECTED_DELEGATION_ROLES (2), but a duplicate
    // "initiator" displaces "responder" entirely -- proves the check
    // is a real set comparison, not just a length check.
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        vec!["initiator".to_string(), "initiator".to_string()],
        valid_transcript_kinds(),
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationRolesMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_transcript_kinds_missing_a_required_kind() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        valid_roles(),
        vec!["final-confirm".to_string(), "activate".to_string()], // omits "activate-ack"
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationTranscriptKindsMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_transcript_kinds_with_an_unexpected_extra_kind() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        valid_roles(),
        vec![
            "final-confirm".to_string(),
            "activate".to_string(),
            "activate-ack".to_string(),
            "proof-r".to_string(), // not in EXPECTED_TRANSCRIPT_KINDS
        ],
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationTranscriptKindsMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_transcript_kinds_with_a_duplicate() {
    // Same length as EXPECTED_TRANSCRIPT_KINDS (3), but a duplicated
    // "final-confirm" displaces "activate-ack" entirely.
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        valid_roles(),
        vec![
            "final-confirm".to_string(),
            "final-confirm".to_string(),
            "activate".to_string(),
        ],
        "dev",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev,
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationTranscriptKindsMismatch)
    ));
}

#[test]
fn red_delegation_gate_rejects_channel_not_matching_expected() {
    let key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&key),
        valid_roles(),
        valid_transcript_kinds(),
        "release",
    );
    let result = pass_delegation_gate(
        &delegation,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &gate_ctx(),
        ExpectedChannel::Dev, // caller expects dev; delegation says release
        &far_future_deadline(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationChannelMismatch)
    ));
}

/// Wiring confirmation, responder side: proves the roles/kinds/channel
/// check is actually reached via `run_responder_handshake`'s own call
/// to `pass_delegation_gate` on the RECEIVED (Proof-I) delegation, not
/// just correct in isolation as the direct `pass_delegation_gate`
/// tests above prove. Manual-attacker-harness pattern (real Noise
/// handshake + hand-built, correctly-addressed, validly-signed but
/// mis-scoped Proof-I).
#[test]
fn red_responder_rejects_received_delegation_with_missing_role() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let responder_key = SigningKey::random(&mut OsRng);
    let responder_delegation = delegation_for_key(
        &VerifyingKey::from(&responder_key),
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                // Never reached — the missing-role delegation is
                // rejected by pass_delegation_gate, before the
                // resolver seam.
                &FixedResolver {
                    delegated_pub: vec![],
                    generation: 0,
                    not_after: 0,
                },
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let mut sock = TcpStream::connect(addr).unwrap();
    let handshake =
        noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
        AuthFrame::ProofR(_) => {}
        _ => panic!("expected ProofR"),
    }

    let initiator_key = SigningKey::random(&mut OsRng);
    let bad_delegation = delegation_wire_with(
        &VerifyingKey::from(&initiator_key),
        vec!["initiator".to_string()], // omits "responder"
        valid_transcript_kinds(),
        "dev",
    );
    let checkpoint = fixed_checkpoint();
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            bad_delegation.clone(),
        ),
        &checkpoint,
        "responder-1",
        vec![0xCC; 32],
        [0x93; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    send_intent_record(
        &mut sock,
        &mut transport,
        pending_intent.intent(),
        &far_future_deadline(),
    )
    .unwrap();
    let connection_intent_digest = ConnectionIntentDigest::from_bytes(
        crate::intent::intent_digest(pending_intent.intent()).unwrap(),
    );
    let proof_i = ProofI::new(
        h_final.clone(),
        "hh-1".to_string(),
        "initiator-1".to_string(),
        "responder-1".to_string(),
        vec![0xEE; 32],
        vec![0xCC; 32],
        checkpoint.hash.clone(),
        checkpoint.sequence,
        checkpoint.event_head.clone(),
        checkpoint.not_after,
        bad_delegation,
        connection_intent_digest,
        vec![0u8; 64],
    )
    .unwrap();
    let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
    send_frame(
        &mut sock,
        &mut transport,
        &AuthFrame::ProofI(proof_i),
        &far_future_deadline(),
    )
    .unwrap();

    let responder_result = responder.join().unwrap();
    assert!(matches!(
        responder_result,
        Err(AuthFrameError::DelegationRolesMismatch)
    ));
}

/// Symmetric wiring confirmation, initiator side: a hand-built,
/// correctly-addressed, validly-signed but mis-scoped Proof-R must be
/// rejected via `run_initiator_handshake`'s own call to
/// `pass_delegation_gate`.
#[test]
fn red_initiator_rejects_received_delegation_with_missing_role() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let attacker = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let handshake =
            noise::run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline()).unwrap();
        let mut transport = handshake.transport;
        let h_final = handshake.handshake_hash;

        let responder_key = SigningKey::random(&mut OsRng);
        let bad_delegation = delegation_wire_with(
            &VerifyingKey::from(&responder_key),
            vec!["initiator".to_string()], // omits "responder"
            valid_transcript_kinds(),
            "dev",
        );
        let checkpoint = fixed_checkpoint();
        let proof_r = ProofR::new(
            h_final.clone(),
            "hh-1".to_string(),
            "responder-1".to_string(),
            vec![0xCC; 32],
            checkpoint.hash.clone(),
            checkpoint.sequence,
            checkpoint.event_head.clone(),
            checkpoint.not_after,
            bad_delegation,
            vec![0u8; 64],
        )
        .unwrap();
        let k_mesh = TestKMesh(responder_key);
        let proof_r = auth_frames::sign_frame(proof_r, &k_mesh, &far_future_deadline()).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ProofR(proof_r),
            &far_future_deadline(),
        )
        .unwrap();
    });

    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_delegation = delegation_for_key(
        &VerifyingKey::from(&initiator_key),
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x92; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    attacker.join().unwrap();
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationRolesMismatch)
    ));
}

/// Local pre-I/O channel check, responder side (2026-08-04, @kiana,
/// round 5): the LOCAL delegation's own channel must match what the
/// caller says this ceremony expects, checked before any I/O.
/// `PanicsOnIo` proves zero I/O, not just the right `Err`.
#[test]
fn red_responder_local_delegation_channel_mismatch_rejected_before_any_write() {
    let responder_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&responder_key),
        valid_roles(),
        valid_transcript_kinds(),
        "release", // local delegation says release
    );
    let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
    let k_mesh = TestKMesh(responder_key);

    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_responder_handshake(
        ingress,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev, // caller expects dev
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &InMemoryLedger::new(),
        &AlwaysAdmitD1,
        &FixedClock(0),
        // Never reached — the local channel mismatch is rejected
        // before any I/O, let alone the resolver seam.
        &FixedResolver {
            delegated_pub: vec![],
            generation: 0,
            not_after: 0,
        },
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationChannelMismatch)
    ));
}

/// Symmetric to the above, initiator side.
#[test]
fn red_initiator_local_delegation_channel_mismatch_rejected_before_any_write() {
    let initiator_key = SigningKey::random(&mut OsRng);
    let delegation = delegation_wire_with(
        &VerifyingKey::from(&initiator_key),
        valid_roles(),
        valid_transcript_kinds(),
        "release",
    );
    let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &local,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x91; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );

    let ingress = PrevalidatedIngress::admit_at_accept(
        PanicsOnIo,
        IngressEvidence {
            observed_at: 1,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let result = run_initiator_handshake(
        ingress,
        pending_intent,
        &local,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    assert!(matches!(
        result,
        Err(AuthFrameError::DelegationChannelMismatch)
    ));
}

#[test]
fn red_commit_outgoing_rekey_with_foreign_permit_does_not_touch_transport() {
    let (mut initiator, _responder) = full_handshake();
    let other_threshold = RekeyThreshold::new(1).unwrap();
    let donor = rekey::DirectionalRekeyState::new(other_threshold).unwrap();
    let foreign_permit = donor.before_send_marker().unwrap();

    let err = initiator.commit_outgoing_rekey(foreign_permit).unwrap_err();
    assert!(matches!(err, crate::error::RekeyError::StalePermit));
    // The tx counter must be completely unaffected — validate_marker_permit
    // rejected before transport.rekey_outgoing() or after_send_marker
    // ever ran.
    assert_eq!(initiator.rekey.tx().generation(), 0);
    assert_eq!(initiator.rekey.tx().policy_count(), 0);
}

#[test]
fn delegation_gate_blocks_with_no_verifier_configured() {
    // The initiator side uses AlwaysAcceptDelegation (so it gets far
    // enough to actually send Proof-I) and a delegation whose
    // delegated_pub genuinely matches its K_mesh key (so its own
    // outer-frame signature checks pass); the RESPONDER uses the
    // crate's REAL shipped verifier, NoVerifierConfigured — proving
    // the gate is genuinely closed by default, on the side under test,
    // not just in prose.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_identity = identity(
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        delegation_for_key(
            &responder_verifying,
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        ),
    );
    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &crate::delegation::NoVerifierConfigured,
                &k_mesh,
                &InMemoryLedger::new(),
                &AlwaysAdmitD1,
                &FixedClock(0),
                // Never reached — NoVerifierConfigured always fails
                // pass_delegation_gate, before the resolver seam.
                &FixedResolver {
                    delegated_pub: vec![],
                    generation: 0,
                    not_after: 0,
                },
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_identity = identity(
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        delegation_for_key(
            &VerifyingKey::from(&initiator_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        ),
    );
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x90; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );

    // The responder gates on Proof-I's delegation and rejects with
    // DelegationGate specifically; the initiator, having already sent
    // Proof-I, is left blocked waiting for FinalConfirm that never
    // comes (the responder errors out and drops the socket) — it
    // fails too, but with a connection error, not DelegationGate.
    let responder_result = responder.join().unwrap();
    assert!(matches!(
        responder_result,
        Err(AuthFrameError::DelegationGate)
    ));
    assert!(initiator_result.is_err());
    assert!(!matches!(
        initiator_result,
        Err(AuthFrameError::DelegationGate)
    ));
}

#[test]
fn pos4_rekey_with_a_real_snow_pair_both_directions() {
    let (mut initiator, mut responder) = full_handshake();

    // Drive initiator's TX through exactly one rekey (N=3: 2 non-marker
    // + marker), coupled to a REAL TransportState::rekey_outgoing().
    let p1 = initiator.before_send_non_marker().unwrap();
    initiator.after_send_non_marker(p1).unwrap();
    let p2 = initiator.before_send_non_marker().unwrap();
    initiator.after_send_non_marker(p2).unwrap();
    let marker_permit = initiator.before_outgoing_rekey().unwrap();
    let next_generation = marker_permit.next_generation();
    initiator.commit_outgoing_rekey(marker_permit).unwrap();

    // Responder's RX mirrors it, coupled to a REAL
    // TransportState::rekey_incoming().
    responder.observe_incoming_non_marker().unwrap();
    responder.observe_incoming_non_marker().unwrap();
    responder.commit_incoming_rekey(next_generation).unwrap();

    // Prove the REAL Noise keys actually rotated together: encrypt on
    // the new initiator generation, decrypt on the new responder
    // generation.
    let plaintext = b"post-rekey application data";
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let ct_len = initiator
        .transport
        .write_message(plaintext, &mut ciphertext)
        .unwrap();
    let mut recovered = vec![0u8; plaintext.len()];
    let pt_len = responder
        .transport
        .read_message(&ciphertext[..ct_len], &mut recovered)
        .unwrap();
    assert_eq!(&recovered[..pt_len], plaintext);
}

#[test]
fn red_simultaneous_independent_rekey_real_rx_and_tx_do_not_interfere() {
    let (mut initiator, mut responder) = full_handshake();

    // Drive initiator TX to a rekey...
    let p1 = initiator.before_send_non_marker().unwrap();
    initiator.after_send_non_marker(p1).unwrap();
    let p2 = initiator.before_send_non_marker().unwrap();
    initiator.after_send_non_marker(p2).unwrap();
    let marker_permit = initiator.before_outgoing_rekey().unwrap();
    let tx_next_generation = marker_permit.next_generation();
    initiator.commit_outgoing_rekey(marker_permit).unwrap();

    // ...simultaneously with responder driving ITS OWN tx (opposite
    // direction) to a rekey, real coupling on both.
    let p1 = responder.before_send_non_marker().unwrap();
    responder.after_send_non_marker(p1).unwrap();
    let p2 = responder.before_send_non_marker().unwrap();
    responder.after_send_non_marker(p2).unwrap();
    let responder_marker_permit = responder.before_outgoing_rekey().unwrap();
    let rx_next_generation = responder_marker_permit.next_generation();
    responder
        .commit_outgoing_rekey(responder_marker_permit)
        .unwrap();

    // Now settle both receive sides for the marks each peer sent.
    responder.observe_incoming_non_marker().unwrap();
    responder.observe_incoming_non_marker().unwrap();
    responder.commit_incoming_rekey(tx_next_generation).unwrap();

    initiator.observe_incoming_non_marker().unwrap();
    initiator.observe_incoming_non_marker().unwrap();
    initiator.commit_incoming_rekey(rx_next_generation).unwrap();

    // Real bidirectional traffic on the new generations, both ways.
    let mut ct = vec![0u8; 64];
    let n = initiator.transport.write_message(b"i->r", &mut ct).unwrap();
    let mut pt = vec![0u8; 64];
    let m = responder.transport.read_message(&ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], b"i->r");

    let n = responder.transport.write_message(b"r->i", &mut ct).unwrap();
    let m = initiator.transport.read_message(&ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], b"r->i");
}

#[test]
fn red_wrong_generation_marker_rejected_and_does_not_touch_real_transport() {
    let (mut initiator, _responder) = full_handshake();
    let before = initiator.rekey.rx().generation();
    let err = initiator.commit_incoming_rekey(999).unwrap_err();
    assert!(matches!(err, RekeyError::WrongGeneration { .. }));
    assert_eq!(initiator.rekey.rx().generation(), before);
}

/// A D1 double that records whether `cancel_before_ack` ran and always
/// reports a specific, injected [`crate::intent::D1CancelOutcome`] —
/// used by the two integration REDs below to prove the outcome is
/// actually threaded into the propagated error, not merely that SOME
/// error came back (2026-08-04, @kiana, runtime-facade audit
/// `3cbbfb37…` item 7c).
struct RecordingD1 {
    cancel_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    outcome: crate::intent::D1CancelOutcome,
}
struct RecordingPending {
    cancel_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    outcome: crate::intent::D1CancelOutcome,
}
impl crate::intent::D1Pending<()> for RecordingPending {
    fn commit_after_ack(self) {}
    fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
        self.cancel_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.outcome
    }
}
impl crate::intent::D1Admission for RecordingD1 {
    type Pending<'a> = RecordingPending;
    type Active<'a> = ();
    fn reserve_pending<'a>(
        &'a self,
        _key: &crate::intent::D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
        Ok(RecordingPending {
            cancel_called: std::sync::Arc::clone(&self.cancel_called),
            outcome: self.outcome,
        })
    }
}

/// Wraps a real `TcpStream`, letting the first `fail_from - 1` top-level
/// `.write()` calls through untouched and failing every call from
/// `fail_from` on. Small buffers over a healthy loopback socket
/// complete in exactly one `.write()` syscall per
/// `write_all_with_deadline` frame (the same assumption this crate's
/// own wire-level tests already rely on), so `fail_from` reliably
/// targets one specific top-level frame — here, the responder's third
/// and final write, `ActivateAck`.
struct FailWriteFromCall {
    inner: TcpStream,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_from: usize,
}
impl Read for FailWriteFromCall {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for FailWriteFromCall {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let call_number = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if call_number >= self.fail_from {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test-injected write failure",
            ));
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
impl wire::DeadlineBoundedIo for FailWriteFromCall {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.inner.arm_io_deadline(remaining)
    }
}

/// item 7c RED, responder side: the `ActivateAck` write itself fails
/// (partial/broken-pipe) — `cancel_before_ack` must run and its
/// specific `D1CancelOutcome` must be threaded into the propagated
/// error (`AckExchangeFailedWithCancelOutcome`), never discarded via
/// `let _ =`, and the session must never reach `Active`.
#[test]
fn red_responder_ack_write_failure_cancels_pending_and_surfaces_cancel_outcome() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };

    let cancel_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d1 = RecordingD1 {
        cancel_called: std::sync::Arc::clone(&cancel_called),
        outcome: crate::intent::D1CancelOutcome::BarrierReleasedBookkeepingDeferred,
    };
    let write_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        let write_calls = std::sync::Arc::clone(&write_calls);
        move || {
            let (sock, _) = listener.accept().unwrap();
            let wrapped = FailWriteFromCall {
                inner: sock,
                calls: write_calls,
                // Each logical frame is 2 raw `.write()` calls
                // (length-prefix, then body — `write_length_prefixed_frame`).
                // Noise handshake message 2 (calls 1-2), ProofR (3-4),
                // FinalConfirm (5-6) succeed; ActivateAck's own
                // length-prefix write (7) fails first, so zero
                // ActivateAck bytes ever reach the peer.
                fail_from: 7,
            };
            let ingress = PrevalidatedIngress::admit_at_accept(
                wrapped,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &d1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x83; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    // The initiator side will fail too (the Ack it's waiting for never
    // arrives, and the responder's socket closes when its thread
    // returns) — its own result isn't the point of this test.
    let _initiator_result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &AlwaysAdmitD1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );

    let responder_result = responder.join().unwrap();
    match responder_result {
        Err(AuthFrameError::AckExchangeFailedWithCancelOutcome { cancel_outcome, .. }) => {
            assert_eq!(
                cancel_outcome,
                crate::intent::D1CancelOutcome::BarrierReleasedBookkeepingDeferred
            );
        }
        Err(other) => panic!("expected AckExchangeFailedWithCancelOutcome, got {other:?}"),
        Ok(_) => panic!("expected the responder to fail, but it reached Active"),
    }
    assert!(
        cancel_called.load(std::sync::atomic::Ordering::SeqCst),
        "cancel_before_ack was never called on ActivateAck write failure"
    );
}

/// item 7c RED, initiator side: a COMPLETE but cryptographically
/// INVALID `ActivateAck` (correct shape/digest, wrong signature) —
/// `cancel_before_ack` must run and its outcome must be threaded into
/// the propagated error, and the initiator must never reach `Active`.
/// Hand-crafted-attacker pattern (bypasses `run_responder_handshake`,
/// which would never produce an invalid signature) so this is a
/// genuine defense-in-depth proof, not merely redundant with a
/// well-behaved responder.
#[test]
fn red_initiator_invalid_activate_ack_cancels_pending_and_surfaces_cancel_outcome() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let expected_fp = vec![0xCCu8; 32];

    let cancel_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d1 = RecordingD1 {
        cancel_called: std::sync::Arc::clone(&cancel_called),
        outcome: crate::intent::D1CancelOutcome::RegistryUnavailable,
    };

    // Fake responder thread: real Noise + real ProofR/FinalConfirm, but
    // the final ActivateAck is signed with a DIFFERENT key than the
    // one Proof-R/FinalConfirm used — a complete, well-shaped frame
    // that fails signature verification, not a truncated one.
    let responder_handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let handshake =
            noise::run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline()).unwrap();
        let mut transport = handshake.transport;
        let h_final = handshake.handshake_hash;
        let k_mesh = TestKMesh(responder_key);
        let checkpoint = fixed_checkpoint();

        let proof_r = ProofR::new(
            h_final.clone(),
            "hh-1".to_string(),
            "responder-1".to_string(),
            expected_fp.clone(),
            checkpoint.hash.clone(),
            checkpoint.sequence,
            checkpoint.event_head.clone(),
            checkpoint.not_after,
            responder_delegation.clone(),
            vec![0u8; 64],
        )
        .unwrap();
        let proof_r = auth_frames::sign_frame(proof_r, &k_mesh, &far_future_deadline()).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ProofR(proof_r),
            &far_future_deadline(),
        )
        .unwrap();

        let _intent =
            recv_intent_record(&mut sock, &mut transport, &far_future_deadline()).unwrap();
        let proof_i = match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
            AuthFrame::ProofI(f) => f,
            _ => panic!("expected ProofI"),
        };

        let final_confirm = FinalConfirm::new(
            h_final.clone(),
            proof_i.self_m_id().to_string(),
            proof_i.self_cert_fingerprint().to_vec(),
            "responder-1".to_string(),
            vec![0u8; 64],
        )
        .unwrap();
        let final_confirm =
            auth_frames::sign_frame(final_confirm, &k_mesh, &far_future_deadline()).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::FinalConfirm(final_confirm.clone()),
            &far_future_deadline(),
        )
        .unwrap();

        let activate = match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap()
        {
            AuthFrame::Activate(f) => f,
            _ => panic!("expected Activate"),
        };
        let activate_digest = auth_frames::frame_digest(&activate).unwrap();

        // Complete, well-shaped ActivateAck — but signed with a
        // DIFFERENT key than proof_r/final_confirm, so it fails
        // signature verification despite arriving intact.
        let wrong_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));
        let activate_ack = ActivateAck::new(
            h_final.clone(),
            "responder-1".to_string(),
            activate_digest.to_vec(),
            vec![0u8; 64],
        )
        .unwrap();
        let activate_ack =
            auth_frames::sign_frame(activate_ack, &wrong_k_mesh, &far_future_deadline()).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ActivateAck(activate_ack),
            &far_future_deadline(),
        )
        .unwrap();
    });

    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_delegation = delegation_for_key(
        &VerifyingKey::from(&initiator_key),
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0x87; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_result = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &d1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    );
    responder_handle.join().unwrap();

    match initiator_result {
        Err(AuthFrameError::AckExchangeFailedWithCancelOutcome { cancel_outcome, .. }) => {
            assert_eq!(
                cancel_outcome,
                crate::intent::D1CancelOutcome::RegistryUnavailable
            );
        }
        Err(other) => panic!("expected AckExchangeFailedWithCancelOutcome, got {other:?}"),
        Ok(_) => panic!("expected the initiator to fail, but it reached Active"),
    }
    assert!(
        cancel_called.load(std::sync::atomic::Ordering::SeqCst),
        "cancel_before_ack was never called on an invalid ActivateAck"
    );
}

/// A `IntentNonceLedger` double whose `consume` blocks on a 2-party
/// `Barrier` as its very first action, before touching the shared
/// `HashSet` — forces two genuinely concurrent real ceremonies to
/// both arrive at the check-and-set before either one's `insert` can
/// run, so this is a forced interleaving, not scheduling luck
/// (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`, CFX-1 on
/// `018aed57`).
struct SyncedSharedLedger {
    consumed: std::sync::Mutex<std::collections::HashSet<crate::intent::IntentNonceKey>>,
    barrier: std::sync::Barrier,
}
impl crate::intent::IntentNonceLedger for SyncedSharedLedger {
    fn consume(
        &self,
        key: &crate::intent::IntentNonceKey,
        _not_after: u64,
        _digest: &[u8; 32],
        _channel: ExpectedChannel,
        _deadline: &CeremonyDeadline,
    ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
        self.barrier.wait();
        let mut set = self.consumed.lock().unwrap();
        if !set.insert(key.clone()) {
            return Ok(crate::intent::NonceConsumeOutcome::AlreadyConsumed);
        }
        Ok(crate::intent::NonceConsumeOutcome::Committed)
    }
}

/// A D1 double that counts `reserve_pending` calls via a shared
/// counter and always succeeds — used to prove the LOSING ceremony
/// never reserves at all (nonce consume runs strictly before D1
/// reservation in both handshake functions, so a nonce rejection
/// structurally prevents `reserve_pending` from ever being called for
/// that attempt; this double makes that observable instead of merely
/// inferred from reading the source).
struct CountingD1 {
    reserve_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
struct CountingPending;
impl crate::intent::D1Pending<()> for CountingPending {
    fn commit_after_ack(self) {}
    fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
        crate::intent::D1CancelOutcome::CancelledAndRemoved
    }
}
impl crate::intent::D1Admission for CountingD1 {
    type Pending<'a> = CountingPending;
    type Active<'a> = ();
    fn reserve_pending<'a>(
        &'a self,
        _key: &crate::intent::D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
        self.reserve_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(CountingPending)
    }
}

/// item 7d RED, entrypoint-level closure (2026-08-04, @kiana,
/// runtime-facade audit `3cbbfb37…`, CFX-1 on `018aed57` — the
/// unit-level `intent::tests::two_concurrent_attempts_at_the_same_nonce_yield_exactly_one_winner`
/// alone did not close item 7d; this does). TWO real, independent
/// Noise handshakes/responder ceremonies, driven by hand-crafted
/// initiator threads that both replay the IDENTICAL signed 0x06
/// intent (same nonce — this genuinely IS a nonce-replay attack, the
/// exact scenario the ledger exists to stop), racing the SAME
/// `SyncedSharedLedger` and counted by the SAME `CountingD1`.
///
/// A byte-for-byte `ProofI` cannot be replayed across the two
/// connections — its signature covers `h_final`, which is unique per
/// Noise handshake — so each attacker thread signs its OWN fresh
/// `ProofI` bound to its own connection's real `h_final`, but both
/// reference the SAME `connection_intent_digest` (computed from the
/// SAME replayed intent bytes), exactly as a real replay would need
/// to.
#[test]
fn red_two_real_responder_ceremonies_racing_the_same_nonce_exactly_one_reaches_active() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );

    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);
    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity(
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        initiator_delegation.clone(),
    );
    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };
    let k_mesh = TestKMesh(initiator_key);

    // The SAME nonce, replayed on both connections.
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0xA5; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let shared_intent = pending_intent.intent().clone();
    let connection_intent_digest =
        ConnectionIntentDigest::from_bytes(crate::intent::intent_digest(&shared_intent).unwrap());

    let ledger = std::sync::Arc::new(SyncedSharedLedger {
        consumed: std::sync::Mutex::new(std::collections::HashSet::new()),
        barrier: std::sync::Barrier::new(2),
    });
    let reserve_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Attacker threads spawn FIRST: `TcpStream::connect` completes once
    // the OS-level listen backlog accepts the SYN, independent of when
    // this process calls `listener.accept()` — spawning them before
    // the two `accept()` calls below avoids a connect-before-listener-
    // is-ready deadlock without needing a separate acceptor thread.
    let attacker_threads: Vec<_> = (0..2)
        .map(|_| {
            let shared_intent = shared_intent.clone();
            let connection_intent_digest = connection_intent_digest.clone();
            let initiator_identity_hh_id = initiator_identity.hh_id.clone();
            let initiator_identity_m_id = initiator_identity.m_id.clone();
            let initiator_cert_fingerprint = initiator_identity.cert_fingerprint.clone();
            let initiator_delegation = initiator_delegation.clone();
            let k_mesh = TestKMesh(k_mesh.0.clone());
            thread::spawn(move || {
                let mut sock = TcpStream::connect(addr).unwrap();
                let handshake =
                    noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline())
                        .unwrap();
                let mut transport = handshake.transport;
                let h_final = handshake.handshake_hash;
                match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
                    AuthFrame::ProofR(_) => {}
                    _ => panic!("expected ProofR"),
                }
                send_intent_record(
                    &mut sock,
                    &mut transport,
                    &shared_intent,
                    &far_future_deadline(),
                )
                .unwrap();
                let checkpoint = fixed_checkpoint();
                let proof_i = ProofI::new(
                    h_final.clone(),
                    initiator_identity_hh_id,
                    initiator_identity_m_id,
                    "responder-1".to_string(),
                    initiator_cert_fingerprint,
                    vec![0xCC; 32],
                    checkpoint.hash.clone(),
                    checkpoint.sequence,
                    checkpoint.event_head.clone(),
                    checkpoint.not_after,
                    initiator_delegation,
                    connection_intent_digest,
                    vec![0u8; 64],
                )
                .unwrap();
                let proof_i =
                    auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
                send_frame(
                    &mut sock,
                    &mut transport,
                    &AuthFrame::ProofI(proof_i),
                    &far_future_deadline(),
                )
                .unwrap();
                // Only the nonce winner ever receives a real FinalConfirm
                // — the loser's responder returns Err(NonceAlreadyConsumed)
                // and closes its socket without sending anything more.
                // Both attacker threads are prepared to complete the full
                // flight regardless, since neither knows in advance which
                // one will win.
                let final_confirm =
                    match recv_frame(&mut sock, &mut transport, &far_future_deadline()) {
                        Ok(AuthFrame::FinalConfirm(f)) => f,
                        _ => return, // lost the race — connection closed/errored
                    };
                let final_confirm_digest = auth_frames::frame_digest(&final_confirm).unwrap();
                let activate = Activate::new(
                    h_final.clone(),
                    "responder-1".to_string(),
                    final_confirm_digest.to_vec(),
                    vec![0u8; 64],
                )
                .unwrap();
                let activate =
                    auth_frames::sign_frame(activate, &k_mesh, &far_future_deadline()).unwrap();
                send_frame(
                    &mut sock,
                    &mut transport,
                    &AuthFrame::Activate(activate),
                    &far_future_deadline(),
                )
                .unwrap();
                let _ = recv_frame(&mut sock, &mut transport, &far_future_deadline());
            })
        })
        .collect();

    // Accept both connections and spawn a real responder ceremony for
    // each, sharing the same ledger/D1 counter.
    let responder_threads: Vec<_> = (0..2)
        .map(|_| {
            let (sock, _) = listener.accept().unwrap();
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key.clone());
            let responder_identity = identity(
                "hh-1",
                "responder-1",
                vec![0xCC; 32],
                responder_delegation.clone(),
            );
            let ledger = std::sync::Arc::clone(&ledger);
            let d1 = CountingD1 {
                reserve_count: std::sync::Arc::clone(&reserve_count),
            };
            let initiator_resolver = FixedResolver {
                delegated_pub: initiator_resolver.delegated_pub.clone(),
                generation: initiator_resolver.generation,
                not_after: initiator_resolver.not_after,
            };
            thread::spawn(move || {
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    ledger.as_ref(),
                    &d1,
                    &FixedClock(0),
                    &initiator_resolver,
                    u64::MAX / 2,
                    RekeyThreshold::new(3).unwrap(),
                )
            })
        })
        .collect();

    for h in attacker_threads {
        let _ = h.join();
    }
    let responder_results: Vec<_> = responder_threads
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();

    let active_count = responder_results.iter().filter(|r| r.is_ok()).count();
    let already_consumed_count = responder_results
        .iter()
        .filter(|r| {
            matches!(
                r,
                Err(AuthFrameError::Intent(
                    crate::error::IntentError::NonceAlreadyConsumed
                ))
            )
        })
        .count();

    assert_eq!(
        active_count, 1,
        "expected exactly one responder ceremony to reach Active"
    );
    assert_eq!(
        already_consumed_count, 1,
        "expected exactly one responder ceremony to be rejected with NonceAlreadyConsumed"
    );
    assert_eq!(
        reserve_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "D1::reserve_pending must have been called exactly once — the losing \
             ceremony's nonce rejection must happen strictly before D1 reservation, \
             so it must never reserve at all"
    );
}

// ---- post-Active wire addendum (b14fcf95…/erratum1 4be4cd3d…) tests ----

/// A `D1::Active<'a>` gate double whose authorization can be flipped
/// externally by the test, shared via `Arc` so both the session and
/// the test hold a handle to the SAME underlying flag.
struct TestGate {
    authorized: std::sync::atomic::AtomicBool,
}
impl TestGate {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            authorized: std::sync::atomic::AtomicBool::new(true),
        })
    }
    fn revoke(&self) {
        self.authorized
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
impl ActiveGateAuthorization for std::sync::Arc<TestGate> {
    type Guard<'a> = ();
    fn try_authorize(&self) -> Option<()> {
        if self.authorized.load(std::sync::atomic::Ordering::SeqCst) {
            Some(())
        } else {
            None
        }
    }
}

struct GatedD1 {
    gate: std::sync::Arc<TestGate>,
}
struct GatedPending {
    gate: std::sync::Arc<TestGate>,
}
impl crate::intent::D1Pending<std::sync::Arc<TestGate>> for GatedPending {
    fn commit_after_ack(self) -> std::sync::Arc<TestGate> {
        self.gate
    }
    fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
        crate::intent::D1CancelOutcome::CancelledAndRemoved
    }
}
impl crate::intent::D1Admission for GatedD1 {
    type Pending<'a> = GatedPending;
    type Active<'a> = std::sync::Arc<TestGate>;
    fn reserve_pending<'a>(
        &'a self,
        _key: &crate::intent::D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
        Ok(GatedPending {
            gate: std::sync::Arc::clone(&self.gate),
        })
    }
}

type GatedSession = ActiveMeshSession<TcpStream, std::sync::Arc<TestGate>>;

/// Same shape as `full_handshake()`, but with a `GatedD1` double whose
/// gate the test can flip after the ceremony completes — needed for
/// every post-Active RED that depends on live D1 authorization, which
/// `AlwaysAdmitD1`'s `()` gate cannot express at all.
fn full_handshake_with_gate() -> (
    GatedSession,
    GatedSession,
    std::sync::Arc<TestGate>,
    std::sync::Arc<TestGate>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };
    let responder_gate = TestGate::new();
    let initiator_gate = TestGate::new();

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        let d1 = GatedD1 {
            gate: std::sync::Arc::clone(&responder_gate),
        };
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &d1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
            .unwrap()
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0xB7; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_d1 = GatedD1 {
        gate: std::sync::Arc::clone(&initiator_gate),
    };
    let initiator_session = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &initiator_d1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    )
    .unwrap();

    let responder_session = responder.join().unwrap();
    (
        initiator_session,
        responder_session,
        initiator_gate,
        responder_gate,
    )
}

// ---- @khai audit d7e45e10… BLOCKER fix: clock is re-sampled fresh,
// never a caller scalar (post-Active wire addendum §5, "reamostrar") ----

/// A clock double whose reading the test can flip at runtime
/// (2026-08-04, @khai audit `d7e45e10…` BLOCKER fix). Shared via
/// `Clone` (cheap `Arc` clone) so the session's injected `&C` and the
/// test's own handle observe the SAME underlying value.
#[derive(Clone)]
struct MutableClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl MutableClock {
    fn new(initial: u64) -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            initial,
        )))
    }
    fn set(&self, value: u64) {
        self.0.store(value, std::sync::atomic::Ordering::SeqCst);
    }
}
impl crate::intent::Clock for MutableClock {
    fn now(&self) -> Result<u64, crate::error::IntentError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// Flips a `MutableClock` the instant the wrapped stream's raw
/// read/write call count reaches a runtime-armed target — a
/// deterministic, single-threaded "rendezvous": the flip is a direct
/// causal consequence of one specific syscall completing, not a sleep
/// or a real thread race. `arm(n, flip_to)` is called by the test
/// AFTER the handshake completes (whose own raw call count this
/// struct does not need to know or hard-code — it counts relative to
/// whatever the call count already is) and BEFORE the one post-Active
/// call under test, so `n` only has to describe that single call's own
/// raw-syscall shape: 2 per logical record (length-prefix, then
/// body) — the same model `FailWriteFromCall` already documents for
/// writes, symmetric for reads since both go through
/// `read_exact_with_deadline`/`write_all_with_deadline`, one syscall
/// per frame piece on a healthy loopback with small buffers.
struct ClockFlipTrigger {
    calls: std::sync::atomic::AtomicUsize,
    trigger_at: std::sync::atomic::AtomicUsize,
    flip_to: std::sync::atomic::AtomicU64,
    clock: MutableClock,
}
impl ClockFlipTrigger {
    fn new(clock: MutableClock) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            trigger_at: std::sync::atomic::AtomicUsize::new(usize::MAX),
            flip_to: std::sync::atomic::AtomicU64::new(0),
            clock,
        }
    }
    fn arm(&self, n: usize, flip_to: u64) {
        self.flip_to
            .store(flip_to, std::sync::atomic::Ordering::SeqCst);
        let current = self.calls.load(std::sync::atomic::Ordering::SeqCst);
        self.trigger_at
            .store(current + n, std::sync::atomic::Ordering::SeqCst);
    }
    fn tick(&self) {
        let call_number = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if call_number == self.trigger_at.load(std::sync::atomic::Ordering::SeqCst) {
            self.clock
                .set(self.flip_to.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
}

/// Flips the trigger's clock the instant a raw `.write()` call
/// completes — proves `send_data`'s fresh `clock.now()` reflects time
/// that "passed" during a due marker's own write, not a reading taken
/// before it.
struct ClockFlipOnWriteStream {
    inner: TcpStream,
    trigger: std::sync::Arc<ClockFlipTrigger>,
}
impl Read for ClockFlipOnWriteStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for ClockFlipOnWriteStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.trigger.tick();
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
impl wire::DeadlineBoundedIo for ClockFlipOnWriteStream {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.inner.arm_io_deadline(remaining)
    }
}

/// Flips the trigger's clock the instant a raw `.read()` call
/// completes — proves `receive_data`'s fresh `clock.now()` reflects
/// time that "passed" during the blocking read/decrypt, not a reading
/// taken before it.
struct ClockFlipOnReadStream {
    inner: TcpStream,
    trigger: std::sync::Arc<ClockFlipTrigger>,
}
impl Read for ClockFlipOnReadStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.trigger.tick();
        Ok(n)
    }
}
impl Write for ClockFlipOnReadStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
impl wire::DeadlineBoundedIo for ClockFlipOnReadStream {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.inner.arm_io_deadline(remaining)
    }
}

/// Same shape as `full_handshake_with_gate()`, but the INITIATOR's
/// stream is wrapped by the caller-supplied `wrap` closure (the
/// responder side is untouched: plain `TcpStream`, spawned thread).
/// `clock` drives both the initiator's own handshake-time
/// `effective_expires_at` check and, when reused by the caller for the
/// post-Active calls under test, the same freshness check this whole
/// section exists to prove.
fn full_handshake_with_gate_and_wrapped_initiator<W, F>(
    clock: &MutableClock,
    wrap: F,
) -> (
    ActiveMeshSession<W, std::sync::Arc<TestGate>>,
    GatedSession,
    std::sync::Arc<TestGate>,
    std::sync::Arc<TestGate>,
)
where
    W: Read + Write + wire::DeadlineBoundedIo,
    F: FnOnce(TcpStream) -> W,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };
    let responder_gate = TestGate::new();
    let initiator_gate = TestGate::new();

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        let d1 = GatedD1 {
            gate: std::sync::Arc::clone(&responder_gate),
        };
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &d1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
            .unwrap()
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let wrapped = wrap(sock);
    let ingress = PrevalidatedIngress::admit_at_accept(
        wrapped,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0xB7; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_d1 = GatedD1 {
        gate: std::sync::Arc::clone(&initiator_gate),
    };
    let initiator_session = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &initiator_d1,
        clock,
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    )
    .unwrap();

    let responder_session = responder.join().unwrap();
    (
        initiator_session,
        responder_session,
        initiator_gate,
        responder_gate,
    )
}

/// @khai audit `d7e45e10…` BLOCKER fix, RED 1/2: `send_data`'s
/// `clock.now()` must reflect time that passed DURING a due marker's
/// own write, not a reading taken before it. The clock flips to an
/// already-expired value the instant the marker's own raw write
/// completes (deterministic single-threaded rendezvous, no sleep);
/// `send_data` must still reject with `Expired`, and the DATA record
/// itself must never be written — the raw write-call count must freeze
/// at exactly the marker's own 2 calls.
#[test]
fn red_send_data_clock_advances_during_marker_write_rejects_before_data_is_sent() {
    let clock = MutableClock::new(0);
    let trigger = std::sync::Arc::new(ClockFlipTrigger::new(clock.clone()));
    let (mut initiator, _responder, _ig, _rg) = {
        let trigger = std::sync::Arc::clone(&trigger);
        full_handshake_with_gate_and_wrapped_initiator(&clock, move |sock| ClockFlipOnWriteStream {
            inner: sock,
            trigger,
        })
    };

    let expires_at = initiator.expires_at();

    // Drive N-1 = 2 ordinary DATA sends (threshold=3) so the 3rd send
    // owes a marker. Not yet armed, so these cannot spuriously flip
    // the clock no matter how many raw writes the handshake itself used.
    for i in 0..2u8 {
        initiator.send_data(&[i], OP_BUDGET, &clock).unwrap();
    }

    // Arm relative to the CURRENT call count: the marker's own write
    // is exactly 2 raw calls (prefix, body) — flip the instant the
    // 2nd of those completes, i.e. immediately after the marker is
    // fully on the wire but before `send_data_inner` re-samples the
    // clock for the DATA record that follows it.
    trigger.arm(2, expires_at);
    let calls_before = trigger.calls.load(std::sync::atomic::Ordering::SeqCst);

    let err = initiator.send_data(b"late", OP_BUDGET, &clock).unwrap_err();
    assert!(matches!(err, PostActiveError::Expired));
    assert!(initiator.is_closed());
    assert_eq!(
        trigger.calls.load(std::sync::atomic::Ordering::SeqCst) - calls_before,
        2,
        "only the marker's own 2 raw writes should have happened — \
             the DATA record must never be sent once the fresh clock \
             reading rejects the operation"
    );
}

/// @khai audit `d7e45e10…` BLOCKER fix, RED 2/2: `receive_data`'s
/// `clock.now()` must reflect time that passed DURING the blocking
/// read/decrypt, not a reading taken before it. The clock flips to an
/// already-expired value the instant the DATA record's own raw read
/// completes; `receive_data` must still reject with `Expired`, and the
/// caller's buffer — pre-filled with a sentinel pattern — must be
/// provably untouched (addendum §5: a rejected operation copies zero
/// bytes).
#[test]
fn red_receive_data_clock_advances_during_read_rejects_and_leaves_buffer_untouched() {
    let clock = MutableClock::new(0);
    let trigger = std::sync::Arc::new(ClockFlipTrigger::new(clock.clone()));
    let (mut initiator, mut responder, _ig, _rg) = {
        let trigger = std::sync::Arc::clone(&trigger);
        full_handshake_with_gate_and_wrapped_initiator(&clock, move |sock| ClockFlipOnReadStream {
            inner: sock,
            trigger,
        })
    };

    let expires_at = initiator.expires_at();
    responder
        .send_data(b"0123456789", OP_BUDGET, &FixedClock(0))
        .unwrap();

    // The DATA record is exactly 2 raw reads (length-prefix, body) —
    // flip the instant the body's own read completes, i.e. right
    // after the plaintext is fully decrypted but before
    // `receive_data_inner` re-samples the clock for the delivery
    // decision.
    trigger.arm(2, expires_at);

    let mut buf = [0xAAu8; 16];
    let err = initiator
        .receive_data(&mut buf, OP_BUDGET, &clock)
        .unwrap_err();
    assert!(matches!(err, PostActiveError::Expired));
    assert!(initiator.is_closed());
    assert_eq!(buf, [0xAAu8; 16], "buffer must be untouched on rejection");
}

const FAR_FUTURE_NOW: u64 = 0;
const OP_BUDGET: Duration = Duration::from_secs(5);

/// POS-5-equivalent, addendum §8 item 5: N=3, `DATA, DATA, marker,
/// DATA, DATA` in EACH direction, real Snow transport, real socket —
/// proves `send_data` auto-emits the required marker and
/// `receive_data` transparently consumes it, end to end, in both
/// directions independently.
#[test]
fn post_active_n3_data_data_marker_data_data_each_direction_real_snow() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    let mut buf = [0u8; 64];

    for i in 0..4u8 {
        let payload = [i; 4];
        initiator
            .send_data(&payload, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
        let n = responder
            .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
        assert_eq!(&buf[..n], &payload);
    }
    assert_eq!(initiator.rekey.tx().generation(), 1);
    assert_eq!(responder.rekey.rx().generation(), 1);

    for i in 0..4u8 {
        let payload = [0x80 + i; 4];
        responder
            .send_data(&payload, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
        let n = initiator
            .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
        assert_eq!(&buf[..n], &payload);
    }
    assert_eq!(responder.rekey.tx().generation(), 1);
    assert_eq!(initiator.rekey.rx().generation(), 1);

    assert!(!initiator.is_closed());
    assert!(!responder.is_closed());
}

/// addendum §5/§8 item 7: a D1 gate rejection on `send_data` closes
/// the session — no bytes are ever written for that attempt.
#[test]
fn red_send_data_rejected_when_gate_denies_and_closes_session() {
    let (mut initiator, _responder, initiator_gate, _rg) = full_handshake_with_gate();
    initiator_gate.revoke();
    let err = initiator
        .send_data(b"hello", OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::NotAuthorized));
    assert!(initiator.is_closed());
    // Idempotent: a second call fails closed without touching the gate again.
    let err2 = initiator
        .send_data(b"hello", OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(err2, PostActiveError::Closed));
}

/// addendum §5/§8 item 9: `now >= expires_at` closes `send_data`
/// (equality is already-expired, half-open, same convention as the
/// handshake's own `check_effective_expiry`).
#[test]
fn red_send_data_expired_at_equality_closes_session() {
    let (mut initiator, _responder, _ig, _rg) = full_handshake_with_gate();
    let expires_at = initiator.expires_at();
    let err = initiator
        .send_data(b"hello", OP_BUDGET, &FixedClock(expires_at))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::Expired));
    assert!(initiator.is_closed());
}

/// addendum §8 item 9, positive half: `now == expires_at - 1` still
/// delivers — proves the boundary is exclusive on the expired side
/// only, not off-by-one in the other direction.
#[test]
fn expiry_minus_one_still_delivers() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    let expires_at = initiator.expires_at();
    initiator
        .send_data(b"hi", OP_BUDGET, &FixedClock(expires_at - 1))
        .unwrap();
    let mut buf = [0u8; 8];
    let n = responder
        .receive_data(&mut buf, OP_BUDGET, &FixedClock(expires_at - 1))
        .unwrap();
    assert_eq!(&buf[..n], b"hi");
    assert!(!initiator.is_closed());
    assert!(!responder.is_closed());
}

#[test]
fn close_gracefully_is_idempotent() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    initiator.close_gracefully(OP_BUDGET).unwrap();
    assert!(initiator.is_closed());
    initiator.close_gracefully(OP_BUDGET).unwrap(); // no-op, does not error or reopen
    assert!(initiator.is_closed());

    let mut buf = [0u8; 8];
    let err = responder
        .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::PeerClosed));
    assert!(responder.is_closed());
}

#[test]
fn red_receive_data_after_local_close_fails_without_touching_stream() {
    let (mut initiator, _responder, _ig, _rg) = full_handshake_with_gate();
    initiator.close_gracefully(OP_BUDGET).unwrap();
    let mut buf = [0u8; 8];
    let err = initiator
        .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::Closed));
}

#[test]
fn notify_revoked_and_close_delivers_peer_revoked() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    initiator.notify_revoked_and_close(OP_BUDGET).unwrap();
    assert!(initiator.is_closed());

    let mut buf = [0u8; 8];
    let err = responder
        .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::PeerRevoked));
    assert!(responder.is_closed());
}

/// addendum §5: "Se ... o buffer é pequeno, nenhum byte é copiado;
/// descartar e fechar" — a too-small receive buffer closes the
/// session and leaves the buffer untouched.
#[test]
fn red_receive_data_buffer_too_small_closes_and_copies_nothing() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    initiator
        .send_data(b"0123456789", OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap();
    let mut tiny = [0xAAu8; 4];
    let err = responder
        .receive_data(&mut tiny, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(
        err,
        PostActiveError::ReceiveBufferTooSmall {
            buffer_len: 4,
            payload_len: 10
        }
    ));
    assert!(responder.is_closed());
    assert_eq!(tiny, [0xAAu8; 4], "buffer must be untouched on rejection");
}

/// addendum §6/§8 item 6: a non-marker record arriving when the
/// sender's own policy_count already reached `threshold - 1` (i.e. a
/// marker was required and never sent) is rejected by the receiver's
/// own rekey bookkeeping — hand-crafted attacker path, bypassing
/// `send_data`'s auto-marker-emission, to prove the RECEIVER's own
/// check is real, not merely never exercised because the well-behaved
/// sender never triggers it.
#[test]
fn red_non_marker_at_threshold_minus_one_without_marker_rejected_by_receiver() {
    let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
    // Drive N-1 = 2 ordinary DATA records the normal way first.
    for i in 0..2u8 {
        initiator
            .send_data(&[i], OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
        let mut buf = [0u8; 8];
        responder
            .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
            .unwrap();
    }
    // Now policy_count == threshold-1 == 2 on both sides. Hand-craft
    // a THIRD DATA record directly onto the wire, bypassing
    // send_data's auto-marker-emission entirely.
    let record = post_active::encode_data_record(b"late").unwrap();
    let mut ciphertext = vec![0u8; record.len() + 16];
    let ct_len = initiator
        .transport
        .write_message(&record, &mut ciphertext)
        .unwrap();
    wire::write_transport_record(
        &mut initiator.stream,
        &ciphertext[..ct_len],
        &OperationDeadline::new(OP_BUDGET).unwrap(),
    )
    .unwrap();

    let mut buf = [0u8; 8];
    let err = responder
        .receive_data(&mut buf, OP_BUDGET, &FixedClock(FAR_FUTURE_NOW))
        .unwrap_err();
    assert!(matches!(
        err,
        PostActiveError::Rekey(crate::error::RekeyError::ExpectedRekeyMarker)
    ));
    assert!(responder.is_closed());
}

// ---- addendum §8 item 7: revoke racing an in-flight receive_data ----

/// addendum §8 item 7: a REVOKE announced while `receive_data`'s
/// read/decrypt is genuinely in flight — no bytes even exist on the
/// wire for it to read yet — still correctly fails the operation once
/// the read completes: `try_authorize()` runs fresh, AFTER decrypt,
/// and by then observes the revocation. Buffer intact, session closes.
///
/// **Forced interleaving, not a race.** A `Barrier` makes the receiver
/// thread enter `receive_data` before this thread proceeds; from
/// there, `revoke()` and the DATA write both happen on THIS thread,
/// strictly in that order — and TCP's blocking-read semantics
/// guarantee the receiver thread cannot return from
/// `read_transport_record` until those exact bytes exist. So the
/// revoke is unconditionally complete, in real memory-visible terms
/// (`SeqCst`), before the read can possibly unblock: there is no
/// window in which the outcome depends on scheduler timing.
#[test]
fn red_revoke_while_receive_in_flight_final_authorization_fails_buffer_intact() {
    let (mut initiator, mut responder, _ig, responder_gate) = full_handshake_with_gate();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let receiver = thread::spawn({
        let barrier = std::sync::Arc::clone(&barrier);
        move || {
            let mut buf = [0xAAu8; 16];
            barrier.wait();
            let result = responder.receive_data(&mut buf, OP_BUDGET, &FixedClock(0));
            (result, buf, responder)
        }
    });

    barrier.wait();
    // At this point the receiver thread has entered `receive_data`
    // and is blocked in `read_transport_record` — no bytes exist yet,
    // since the write below has not happened. Revoke first, THEN
    // write: the read cannot return before this write, so it cannot
    // observe anything but the already-revoked gate.
    responder_gate.revoke();
    initiator
        .send_data(b"0123456789", OP_BUDGET, &FixedClock(0))
        .unwrap();

    let (result, buf, responder) = receiver.join().unwrap();
    let err = result.unwrap_err();
    assert!(matches!(err, PostActiveError::NotAuthorized));
    assert_eq!(
        buf, [0xAAu8; 16],
        "buffer must be byte-for-byte intact — the guard failed before any copy"
    );
    assert!(responder.is_closed());
}

// ---- addendum §8 item 8: real blocking guard + no-callback proof ----

/// A real blocking-guard synchronization double, modeled directly on
/// the household `SessionSync`/`ForwardingGuard` (verified earlier
/// this engagement by reading `mesh_session_registry.rs`): a
/// lock-protected `authorized` bit plus an `active_readers` counter
/// and a `Condvar` a revoker waits on until it reaches zero.
/// `TestGate`'s plain `AtomicBool` cannot express this at all —
/// nothing there can block a revoke behind an in-flight guard — which
/// is exactly why item 7 (a `TestGate` is authorized/not at the
/// instant it's checked, no window to hold) did not need this double
/// but item 8 does.
struct BlockingGateState {
    authorized: bool,
    active_readers: usize,
}
struct BlockingGate {
    state: std::sync::Mutex<BlockingGateState>,
    drained: std::sync::Condvar,
}
impl BlockingGate {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            state: std::sync::Mutex::new(BlockingGateState {
                authorized: true,
                active_readers: 0,
            }),
            drained: std::sync::Condvar::new(),
        })
    }
    /// Matches the real `SessionSync::revoke`'s wait-for-drain
    /// contract exactly: withdraws authorization first (so no NEW
    /// guard can be acquired from this point on), then blocks until
    /// every already-issued guard has dropped.
    fn revoke_and_wait_for_drain(&self) {
        self.revoke_and_wait_for_drain_with_hook(|| {});
    }
    /// Test-only extension point: `before_wait` fires exactly once
    /// per loop iteration, synchronously on THIS thread, immediately
    /// before the actual blocking `Condvar::wait` call — i.e. only
    /// once it's confirmed `active_readers != 0` and this call is
    /// genuinely about to block. A test can observe "the revoker has
    /// reached the point of blocking" with no race against it,
    /// because nothing on this thread can proceed past this specific
    /// point except by actually calling (and being woken from)
    /// `.wait()` — there is no path from "before_wait ran" to
    /// "the function returned" that skips the wait.
    fn revoke_and_wait_for_drain_with_hook(&self, mut before_wait: impl FnMut()) {
        let mut guard = self.state.lock().unwrap();
        guard.authorized = false;
        while guard.active_readers != 0 {
            before_wait();
            guard = self.drained.wait(guard).unwrap();
        }
    }
}
struct BlockingGateGuard {
    gate: std::sync::Arc<BlockingGate>,
}
impl Drop for BlockingGateGuard {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        state.active_readers -= 1;
        if state.active_readers == 0 {
            self.gate.drained.notify_all();
        }
    }
}
impl ActiveGateAuthorization for std::sync::Arc<BlockingGate> {
    type Guard<'a> = BlockingGateGuard;
    fn try_authorize(&self) -> Option<BlockingGateGuard> {
        let mut state = self.state.lock().unwrap();
        if state.authorized {
            state.active_readers += 1;
            Some(BlockingGateGuard {
                gate: std::sync::Arc::clone(self),
            })
        } else {
            None
        }
    }
}

struct BlockingGatedD1 {
    gate: std::sync::Arc<BlockingGate>,
}
struct BlockingGatedPending {
    gate: std::sync::Arc<BlockingGate>,
}
impl crate::intent::D1Pending<std::sync::Arc<BlockingGate>> for BlockingGatedPending {
    fn commit_after_ack(self) -> std::sync::Arc<BlockingGate> {
        self.gate
    }
    fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
        crate::intent::D1CancelOutcome::CancelledAndRemoved
    }
}
impl crate::intent::D1Admission for BlockingGatedD1 {
    type Pending<'a> = BlockingGatedPending;
    type Active<'a> = std::sync::Arc<BlockingGate>;
    fn reserve_pending<'a>(
        &'a self,
        _key: &crate::intent::D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
        Ok(BlockingGatedPending {
            gate: std::sync::Arc::clone(&self.gate),
        })
    }
}

type BlockingGatedSession = ActiveMeshSession<TcpStream, std::sync::Arc<BlockingGate>>;

/// Same shape as `full_handshake_with_gate()`, but both sides use
/// `BlockingGate` instead of `TestGate`.
fn full_handshake_with_blocking_gate() -> (
    BlockingGatedSession,
    BlockingGatedSession,
    std::sync::Arc<BlockingGate>,
    std::sync::Arc<BlockingGate>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let responder_key = SigningKey::random(&mut OsRng);
    let responder_verifying = VerifyingKey::from(&responder_key);
    let initiator_key = SigningKey::random(&mut OsRng);
    let initiator_verifying = VerifyingKey::from(&initiator_key);

    let responder_delegation = delegation_for_key(
        &responder_verifying,
        "hh-1",
        "responder-1",
        vec![0xCC; 32],
        0,
        u64::MAX / 2,
    );
    let responder_identity = identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

    let initiator_resolver = FixedResolver {
        delegated_pub: initiator_verifying
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        generation: 1,
        not_after: u64::MAX / 2,
    };
    let responder_gate = BlockingGate::new();
    let initiator_gate = BlockingGate::new();

    let responder = thread::spawn({
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(responder_key);
        let d1 = BlockingGatedD1 {
            gate: std::sync::Arc::clone(&responder_gate),
        };
        move || {
            let (sock, _) = listener.accept().unwrap();
            let ingress = PrevalidatedIngress::admit_at_accept(
                sock,
                IngressEvidence {
                    observed_at: 1,
                    ingress_expiry: u64::MAX / 2,
                },
                far_future_budget(),
            );
            run_responder_handshake(
                ingress,
                &responder_identity,
                &checkpoint,
                ExpectedChannel::Dev,
                &DelegationPolicy::test(u64::MAX / 2),
                &AlwaysAcceptDelegation,
                &k_mesh,
                &InMemoryLedger::new(),
                &d1,
                &FixedClock(0),
                &initiator_resolver,
                u64::MAX / 2,
                RekeyThreshold::new(3).unwrap(),
            )
            .unwrap()
        }
    });

    let initiator_delegation = delegation_for_key(
        &initiator_verifying,
        "hh-1",
        "initiator-1",
        vec![0xEE; 32],
        0,
        u64::MAX / 2,
    );
    let initiator_identity = identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
    let sock = TcpStream::connect(addr).unwrap();
    let ingress = PrevalidatedIngress::admit_at_accept(
        sock,
        IngressEvidence {
            observed_at: 2,
            ingress_expiry: u64::MAX / 2,
        },
        far_future_budget(),
    );
    let k_mesh = TestKMesh(initiator_key);
    let pending_intent = pending_intent_for(
        &k_mesh,
        &initiator_identity,
        &fixed_checkpoint(),
        "responder-1",
        vec![0xCC; 32],
        [0xB7; 32],
        u64::MAX / 2,
        ExpectedChannel::Dev,
    );
    let initiator_d1 = BlockingGatedD1 {
        gate: std::sync::Arc::clone(&initiator_gate),
    };
    let initiator_session = run_initiator_handshake(
        ingress,
        pending_intent,
        &initiator_identity,
        &fixed_checkpoint(),
        ExpectedChannel::Dev,
        &DelegationPolicy::test(u64::MAX / 2),
        &AlwaysAcceptDelegation,
        &k_mesh,
        &initiator_d1,
        &FixedClock(0),
        u64::MAX / 2,
        RekeyThreshold::new(3).unwrap(),
    )
    .unwrap();

    let responder_session = responder.join().unwrap();
    (
        initiator_session,
        responder_session,
        initiator_gate,
        responder_gate,
    )
}

/// addendum §8 item 8: a real blocking guard proves
/// `revoke_and_wait_for_drain` genuinely waits until an in-flight
/// `receive_data` copy's guard drops, and that once it returns, zero
/// new DATA can be delivered.
///
/// **Deterministic, not timing-based — two independent rendezvous, no
/// flag ever raced against.** (1) The copy hook blocks
/// `receive_data_inner` mid-copy (guard held, `active_readers == 1`)
/// until this test explicitly releases it. (2)
/// `revoke_and_wait_for_drain_with_hook`'s `before_wait` fires
/// synchronously, on the REVOKER's own thread, immediately before its
/// one and only `Condvar::wait` call — so once this test observes
/// that signal, `revoker_done` is checked on THIS (main) thread and is
/// guaranteed `false`: the revoker cannot have returned without first
/// completing that specific `.wait()` call, which cannot complete
/// before this test notifies it (by releasing the copy hook). There is
/// no window where two independently-scheduled threads race over a
/// shared flag — every ordering claim here reduces to single-thread
/// program order plus condvar wait/notify happens-before.
#[test]
fn item8_revoke_and_wait_for_drain_blocks_until_guard_drops_then_zero_new_data() {
    let (mut initiator, responder, _initiator_gate, responder_gate) =
        full_handshake_with_blocking_gate();

    let hook_entered =
        std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release_hook = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_signal =
        std::sync::Arc::new((std::sync::Mutex::new(()), std::sync::Condvar::new()));

    let mut responder = responder;
    {
        let hook_entered = std::sync::Arc::clone(&hook_entered);
        let release_hook = std::sync::Arc::clone(&release_hook);
        let release_signal = std::sync::Arc::clone(&release_signal);
        responder.set_receive_before_copy_hook(move || {
            {
                let (lock, cvar) = &*hook_entered;
                let mut entered = lock.lock().unwrap();
                *entered = true;
                cvar.notify_all();
            }
            let (lock, cvar) = &*release_signal;
            let mut g = lock.lock().unwrap();
            while !release_hook.load(std::sync::atomic::Ordering::SeqCst) {
                g = cvar.wait(g).unwrap();
            }
        });
    }

    initiator
        .send_data(b"hello", OP_BUDGET, &FixedClock(0))
        .unwrap();

    let receiver = thread::spawn(move || {
        let mut buf = [0u8; 8];
        let result = responder.receive_data(&mut buf, OP_BUDGET, &FixedClock(0));
        (responder, buf, result)
    });

    // Rendezvous 1: block until the copy hook has actually fired —
    // the guard is held (active_readers == 1) for as long as it stays
    // blocked here.
    {
        let (lock, cvar) = &*hook_entered;
        let mut entered = lock.lock().unwrap();
        while !*entered {
            entered = cvar.wait(entered).unwrap();
        }
    }

    let before_wait_signal =
        std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let revoker_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let revoker = thread::spawn({
        let gate = std::sync::Arc::clone(&responder_gate);
        let before_wait_signal = std::sync::Arc::clone(&before_wait_signal);
        let revoker_done = std::sync::Arc::clone(&revoker_done);
        move || {
            gate.revoke_and_wait_for_drain_with_hook(|| {
                let (lock, cvar) = &*before_wait_signal;
                let mut fired = lock.lock().unwrap();
                *fired = true;
                cvar.notify_all();
            });
            revoker_done.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    // Rendezvous 2: block until the revoker has reached its own
    // Condvar::wait call.
    {
        let (lock, cvar) = &*before_wait_signal;
        let mut fired = lock.lock().unwrap();
        while !*fired {
            fired = cvar.wait(fired).unwrap();
        }
    }
    // At this exact point `revoke_and_wait_for_drain` CANNOT have
    // returned: the only path to returning goes through the
    // `.wait()` call this test just confirmed is about to happen (or
    // is already happening), and that wait cannot complete before
    // the guard drops below — which this test has not yet done.
    assert!(
        !revoker_done.load(std::sync::atomic::Ordering::SeqCst),
        "revoke_and_wait_for_drain returned before the in-flight guard dropped"
    );

    // Only now let the copy hook — and therefore the guard — drop.
    release_hook.store(true, std::sync::atomic::Ordering::SeqCst);
    release_signal.1.notify_all();

    revoker.join().unwrap();
    assert!(
        revoker_done.load(std::sync::atomic::Ordering::SeqCst),
        "revoke_and_wait_for_drain must have returned after the guard dropped"
    );

    let (mut responder, buf, result) = receiver.join().unwrap();
    result.unwrap();
    assert_eq!(&buf[..5], b"hello");

    // "then zero new DATA": the gate is now permanently revoked — a
    // subsequent receive_data must reject with NotAuthorized, never
    // deliver.
    initiator
        .send_data(b"more", OP_BUDGET, &FixedClock(0))
        .unwrap();
    let mut buf2 = [0xAAu8; 8];
    let err = responder
        .receive_data(&mut buf2, OP_BUDGET, &FixedClock(0))
        .unwrap_err();
    assert!(matches!(err, PostActiveError::NotAuthorized));
    assert_eq!(buf2, [0xAAu8; 8], "no new DATA delivered post-revoke");
}

/// addendum §8 item 8, "no callback under the guard" half: a
/// dedicated structural proof, not just true-by-construction-and-
/// trust-me. Reads this crate's OWN source (`include_str!`) and
/// asserts the production `pub fn receive_data`/`pub fn send_data`
/// signature lines contain none of Rust's closure/trait-object
/// spellings. This is deliberately a proof about THIS file's current
/// text, not a runtime guarantee about future edits — same accepted
/// class of self-check as item 14's `static_assertions` — but it is
/// scoped to the two production signature lines specifically (found
/// by their exact, unique `pub fn ... -> Result<...PostActiveError>`
/// text), not the whole file, so it cannot be satisfied by the
/// `#[cfg(test)]`-only hook living elsewhere in this same file.
#[test]
fn red_receive_data_and_send_data_signatures_have_no_callback_parameter() {
    let source = include_str!("../auth_state_machine.rs");
    let forbidden = ["Box<dyn Fn", "impl Fn", "&dyn Fn", "FnMut", "FnOnce"];

    let receive_data_sig = "pub fn receive_data<C: crate::intent::Clock>(\n        &mut self,\n        buffer: &mut [u8],\n        budget: Duration,\n        clock: &C,\n    ) -> Result<usize, PostActiveError> {";
    assert!(
        source.contains(receive_data_sig),
        "receive_data's exact production signature text was not found — \
             this test's anchor is stale and must be updated to match the \
             real signature before it can prove anything"
    );
    for token in forbidden {
        assert!(
            !receive_data_sig.contains(token),
            "receive_data's production signature must never contain {token}"
        );
    }

    let send_data_sig = "pub fn send_data<C: crate::intent::Clock>(\n        &mut self,\n        payload: &[u8],\n        budget: Duration,\n        clock: &C,\n    ) -> Result<(), PostActiveError> {";
    assert!(
        source.contains(send_data_sig),
        "send_data's exact production signature text was not found — \
             this test's anchor is stale and must be updated to match the \
             real signature before it can prove anything"
    );
    for token in forbidden {
        assert!(
            !send_data_sig.contains(token),
            "send_data's production signature must never contain {token}"
        );
    }
}

// ---- addendum §8 item 12: partial write never diverges count/generation ----

/// Runtime-armed raw-write-call counter/failure trigger — same
/// "arm relative to the current call count, after the handshake"
/// design as `ClockFlipTrigger`, so `n` only has to describe the one
/// post-Active write under test, never the handshake's own call
/// count.
struct FailAfterTrigger {
    calls: std::sync::atomic::AtomicUsize,
    fail_at: std::sync::atomic::AtomicUsize,
}
impl FailAfterTrigger {
    fn new() -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail_at: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }
    }
    fn arm(&self, n: usize) {
        let current = self.calls.load(std::sync::atomic::Ordering::SeqCst);
        self.fail_at
            .store(current + n, std::sync::atomic::Ordering::SeqCst);
    }
    fn should_fail(&self) -> bool {
        let call_number = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        call_number == self.fail_at.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Fails the raw `.write()` call the trigger is armed for — the
/// underlying write never runs at all for that one call (unlike
/// `FailWriteFromCall`, which fails every call from a fixed point on;
/// this fails exactly one, then lets any further calls through,
/// matching "one partial write" rather than "the connection is now
/// dead").
struct FailWriteAfterCall {
    inner: TcpStream,
    trigger: std::sync::Arc<FailAfterTrigger>,
}
impl Read for FailWriteAfterCall {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for FailWriteAfterCall {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.trigger.should_fail() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test-injected partial-write failure",
            ));
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
impl wire::DeadlineBoundedIo for FailWriteAfterCall {
    fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.inner.arm_io_deadline(remaining)
    }
}

/// addendum §8 item 12, DATA half: a failed write during `send_data`
/// must never advance `policy_count` or `generation` — the record
/// never landed, so the sender's own bookkeeping must not move either.
/// Fails on the DATA record's 2nd raw write (the body) — the
/// length-prefix goes out, the body never does: a genuinely partial
/// record left dangling mid-write, not merely "nothing sent at all."
#[test]
fn item12_partial_write_during_data_send_never_advances_count_or_generation() {
    let clock = MutableClock::new(0);
    let trigger = std::sync::Arc::new(FailAfterTrigger::new());
    let (mut initiator, _responder, _ig, _rg) = {
        let trigger = std::sync::Arc::clone(&trigger);
        full_handshake_with_gate_and_wrapped_initiator(&clock, move |sock| FailWriteAfterCall {
            inner: sock,
            trigger,
        })
    };

    let gen_before = initiator.rekey.tx().generation();
    let count_before = initiator.rekey.tx().policy_count();

    trigger.arm(2);
    let err = initiator
        .send_data(b"partial", OP_BUDGET, &clock)
        .unwrap_err();
    assert!(matches!(err, PostActiveError::Wire(_)));
    assert!(initiator.is_closed());
    assert_eq!(
        initiator.rekey.tx().generation(),
        gen_before,
        "generation must not advance on a failed write"
    );
    assert_eq!(
        initiator.rekey.tx().policy_count(),
        count_before,
        "policy_count must not advance on a failed write either"
    );
}

/// addendum §8 item 12, CLOSE half: a failed write during
/// `close_gracefully` (no marker due) still leaves the session
/// terminal — `closed` is set true before any write is even
/// attempted (addendum §6/§7), so a failed CLOSE write can never
/// leave the session re-openable, and a second call is a harmless
/// no-op rather than a resend attempt or a panic.
#[test]
fn item12_partial_write_during_close_still_leaves_session_closed() {
    let clock = MutableClock::new(0);
    let trigger = std::sync::Arc::new(FailAfterTrigger::new());
    let (mut initiator, _responder, _ig, _rg) = {
        let trigger = std::sync::Arc::clone(&trigger);
        full_handshake_with_gate_and_wrapped_initiator(&clock, move |sock| FailWriteAfterCall {
            inner: sock,
            trigger,
        })
    };

    // No marker due yet — CLOSE's own record is exactly 2 raw writes;
    // fail on the 2nd (the body).
    trigger.arm(2);
    let err = initiator.close_gracefully(OP_BUDGET).unwrap_err();
    assert!(matches!(err, PostActiveError::Wire(_)));
    assert!(initiator.is_closed());
    assert!(
        initiator.close_gracefully(OP_BUDGET).is_ok(),
        "a second call after a failed write must be a harmless no-op"
    );
}

/// addendum §8 item 12, the "highest-value of the four" case @khai's
/// own audit flagged as worth the fault-injecting double: a marker
/// whose write is fully integral (peer legitimately rekeyed,
/// generation/count committed) followed by a CLOSE whose own write
/// then fails. This must still be a coherent terminal state — never a
/// panic, never a re-attempt, never a rollback of the marker's
/// already-committed rekey (that would desynchronize from a peer who
/// really did receive it) — matching the addendum's own framing: "the
/// peer, having legitimately rekeyed, then observes EOF" rather than
/// an explicit CLOSE.
#[test]
fn item12_marker_integral_close_failed_is_coherent_terminal_state() {
    let clock = MutableClock::new(0);
    let trigger = std::sync::Arc::new(FailAfterTrigger::new());
    let (mut initiator, _responder, _ig, _rg) = {
        let trigger = std::sync::Arc::clone(&trigger);
        full_handshake_with_gate_and_wrapped_initiator(&clock, move |sock| FailWriteAfterCall {
            inner: sock,
            trigger,
        })
    };

    // Drive N-1 = 2 ordinary sends (threshold=3) so a marker becomes
    // due on the next send/close.
    for i in 0..2u8 {
        initiator.send_data(&[i], OP_BUDGET, &clock).unwrap();
    }
    assert_eq!(initiator.rekey.tx().generation(), 0);
    assert_eq!(initiator.rekey.tx().policy_count(), 2);

    // Let the marker's own 2 raw writes (prefix, body) succeed; fail
    // on the 3rd upcoming call — CLOSE's own length-prefix write.
    trigger.arm(3);
    let err = initiator.close_gracefully(OP_BUDGET).unwrap_err();
    assert!(matches!(err, PostActiveError::Wire(_)));

    assert_eq!(
        initiator.rekey.tx().generation(),
        1,
        "the marker's own rekey commit must survive CLOSE's own later write failure"
    );
    assert_eq!(initiator.rekey.tx().policy_count(), 0);
    assert!(initiator.is_closed());

    // Idempotent even in this partially-failed state.
    assert!(
        initiator.close_gracefully(OP_BUDGET).is_ok(),
        "close_gracefully must be idempotent even after a prior write failure"
    );
}
