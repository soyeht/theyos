# Feature Specification: Phase 2 - Owner Pairing and Proof-of-Possession Auth (theyOS)

**Feature Branch**: `002-owner-pairing-auth`
**Created**: 2026-05-06
**Status**: Draft
**Input**: User description: "Phase 2 - Owner device pairing and proof-of-possession auth in theyOS. Complete the backend half of the install-time QR flow started in Phase 1: when theyOS has an active soyeht://household/pair-device window, the Soyeht iPhone app can confirm pairing by presenting the one-shot nonce and the owner's P-256 person public key. theyOS validates the pair window, consumes the token exactly once, issues the first owner PersonCert signed by the household root, returns it to the app, and persists enough local household state for future cert validation. The first owner device receives PersonCert only; do not issue a DeviceCert in this phase because the first device directly holds P_priv. Add Soyeht proof-of-possession validation for household-scoped requests and remove bearer-token authentication from household-scoped operations. Scope this feature to the first owner device only; exclude second-machine joining, inviting other people, revocation/CRL, gossip replication, Claw creation workflows, and second-device delegation."

**Reference contract**: `docs/household-protocol.md` sections 7, 11, 12, and 14; Phase 1 pairing-window behavior in `specs/001-phase-1-crypto-skeleton/spec.md` FR-018.

## User Scenarios & Testing *(mandatory)*

The actors are the household owner using the Soyeht iPhone app, theyOS running on the founding machine, and any client attempting household-scoped requests. This phase turns the Phase 1 QR into the first usable owner credential and replaces bearer-token authentication for household-scoped operations with proof that the requester holds the certified private key.

### User Story 1 - First owner claims the household (Priority: P1)

The owner scans the install-time `soyeht://household/pair-device` QR with the Soyeht iPhone app. While the pair window is active, the app presents the one-shot nonce and the owner's P-256 person public key. theyOS verifies the window, verifies the device controls the matching private key, consumes the nonce exactly once, signs the first owner PersonCert with the household root, returns that PersonCert to the app, and closes the pair window.

**Why this priority**: Without the first owner PersonCert, no person can authenticate to the household or authorize later household actions.

**Independent Test**: Start from a Phase 1 bootstrapped household with an active pair window. Submit one valid pairing confirmation from the Soyeht app test harness. Confirm that the response contains a valid owner PersonCert, the pair token is no longer usable, and the app has no DeviceCert.

**Acceptance Scenarios**:

1. **Given** theyOS has an active unexpired install-time pair window and no first owner PersonCert, **When** the Soyeht app confirms with the exact nonce and a valid owner person public key proof, **Then** theyOS returns one owner PersonCert signed by the household root.
2. **Given** a pairing confirmation succeeds, **When** the same nonce is submitted again, **Then** no second PersonCert is issued and the original owner PersonCert remains the only first-owner certificate.
3. **Given** the Soyeht app receives the owner PersonCert, **When** it stores its local pairing state, **Then** it stores only the PersonCert for this phase and no DeviceCert.

---

### User Story 2 - Owner authenticates with proof of possession (Priority: P2)

After pairing, the owner uses the Soyeht app to make household-scoped requests. Each request proves possession of the private key corresponding to the stored PersonCert. theyOS validates the request signature, the PersonCert chain to the household root, the certificate validity window, and the requested operation's caveats before allowing the request. Bearer tokens no longer authenticate household-scoped operations.

**Why this priority**: Pairing is only useful if the resulting credential becomes the sole authentication mechanism for household-scoped behavior.

**Independent Test**: Use a paired first-owner app harness to send one valid proof-of-possession request and one bearer-token-only request to the same household-scoped operation. Confirm that the signed request is evaluated by certificate and caveats, while the bearer-token-only request is rejected.

**Acceptance Scenarios**:

1. **Given** a valid first owner PersonCert and matching private key, **When** the app signs a household-scoped request for an operation allowed by the owner caveats, **Then** theyOS accepts the request without requiring or checking a bearer token.
2. **Given** a request carries only a bearer token and no valid proof-of-possession, **When** it targets a household-scoped operation, **Then** theyOS rejects it even if the bearer token was accepted by legacy flows before this phase.
3. **Given** a signed request is replayed outside the accepted time window or with changed request contents, **When** theyOS validates it, **Then** the request is rejected.

---

### User Story 3 - Household auth state survives restart (Priority: P3)

The owner pairs once and restarts theyOS later. theyOS reloads the local household auth state, validates the stored first owner PersonCert against the household root, and can continue validating future proof-of-possession requests without asking the owner to pair again.

**Why this priority**: The first owner credential must be durable; otherwise every restart would strand the household.

**Independent Test**: Pair the first owner, restart theyOS repeatedly, and confirm the same owner PersonCert remains valid for proof-of-possession checks. Then tamper with the stored PersonCert and confirm theyOS refuses to trust it.

**Acceptance Scenarios**:

1. **Given** a successfully paired first owner, **When** theyOS restarts, **Then** the same PersonCert is loaded, verified against the household root, and available for request validation.
2. **Given** the persisted PersonCert has been modified, **When** theyOS loads household auth state, **Then** it refuses to treat that PersonCert as valid and does not allow household-scoped requests under it.

---

### Edge Cases

- **No active pair window**: Pairing confirmation produces no certificate and does not create household auth state.
- **Expired pair window**: The nonce is no longer accepted, the window closes, and a new owner PersonCert is not issued unless the operator opens a fresh install-time pairing window before first-owner pairing succeeds.
- **Wrong nonce**: The request is rejected without revealing whether another nonce is active.
- **Malformed or unsupported person public key**: No certificate is issued, no owner state is persisted, and the active token remains available for a valid confirmation until expiry.
- **Invalid private-key proof during pairing**: No certificate is issued because the app has not proven control of the submitted person public key.
- **Concurrent confirmations with the same nonce**: Exactly one confirmation can succeed; all others fail without issuing or persisting additional certificates.
- **First owner already paired**: theyOS never issues a second first-owner PersonCert in this phase, even if a QR is scanned later.
- **Bearer token presented with or without a signed request**: Bearer material grants no household-scoped authority; authorization is decided solely by valid proof-of-possession and the certified caveats.
- **Tampered local auth state**: theyOS refuses to trust modified PersonCert state and does not silently regenerate or replace it.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: theyOS MUST accept first-owner pairing confirmation only while an install-time `soyeht://household/pair-device` window is active and unexpired.
- **FR-002**: Pairing confirmation MUST require the exact one-shot nonce from the active pair window and the owner's P-256 person public key.
- **FR-003**: Pairing confirmation MUST verify that the submitting app controls the private key corresponding to the submitted person public key before issuing a PersonCert.
- **FR-004**: theyOS MUST reject pairing confirmation when the nonce is missing, expired, already consumed, malformed, or not equal to the active pair-window nonce.
- **FR-005**: theyOS MUST consume the pair token atomically as part of successful PersonCert issuance, so concurrent or repeated confirmations cannot produce more than one first owner PersonCert.
- **FR-006**: theyOS MUST derive the owner person identifier from the submitted person public key using the household identifier convention and bind that identifier into the issued PersonCert.
- **FR-007**: theyOS MUST issue exactly one first owner PersonCert signed by the household root, carrying the full owner caveats needed for household administration in the single-machine phase.
- **FR-008**: The issued first owner PersonCert MUST be returned to the Soyeht app in the successful pairing response.
- **FR-009**: theyOS MUST persist the first owner PersonCert and related local household auth metadata needed to validate future PersonCert chains after restart.
- **FR-010**: theyOS MUST validate persisted first owner PersonCert state against the household root before using it for any future request validation.
- **FR-011**: theyOS MUST NOT issue, return, persist, or require a DeviceCert in this phase; the first owner device directly holds the person private key.
- **FR-012**: Household-scoped operations MUST NOT accept bearer-token authentication, except that the public household identity read remains unauthenticated and first-owner pairing remains gated by the one-shot pair token.
- **FR-013**: Household-scoped operations that require an authenticated subject MUST require Soyeht proof-of-possession from a certified PersonCert holder.
- **FR-014**: Proof-of-possession validation MUST bind the signature to the requested operation, request target, request contents, and a recent timestamp so copied signatures cannot authorize different or stale requests.
- **FR-015**: Proof-of-possession validation MUST verify the PersonCert signature chain to the local household root before evaluating authorization caveats.
- **FR-016**: Authorization MUST be based on PersonCert caveats and MUST NOT depend on role labels or bearer-token session state.
- **FR-017**: Pairing and proof-of-possession failures MUST return a generic authentication or unavailability outcome that does not reveal the active nonce, whether a pair window exists, or which validation step failed.
- **FR-018**: theyOS MUST record security-relevant outcomes for successful pairing, failed pairing, token consumption, accepted proof-of-possession, and rejected proof-of-possession without logging private keys, raw signatures, or full one-shot nonces.
- **FR-019**: This feature MUST remain limited to the first owner device on the founding machine. It MUST NOT add second-machine joining, invitations for other people, revocation or CRL behavior, gossip replication, Claw creation workflows, or second-device delegation.

### Key Entities *(include if feature involves data)*

- **Pair Window**: A short-lived install-time state that allows the first owner device to claim the household. Key attributes are household identity, nonce, expiry time, and open/closed state.
- **Pair Token**: The one-shot nonce associated with the active pair window. It can be redeemed at most once and only before expiry.
- **Person Public Key**: The owner's P-256 public key generated by the Soyeht app. Its corresponding private key remains on the first owner device.
- **PersonCert**: The first owner capability certificate signed by the household root. Key attributes are household identifier, person identifier, person public key, caveats, validity information, issuance metadata, and signature.
- **Household Auth State**: Local persisted state theyOS uses to validate future household-scoped requests. It includes the trusted household root public identity and the current first owner PersonCert.
- **Proof-of-Possession Request**: A household-scoped request carrying evidence that the requester controls the private key certified by a valid PersonCert.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A first owner device can complete pairing and receive its PersonCert within 10 seconds of submitting a valid confirmation while the pair window is active.
- **SC-002**: In 100 concurrent confirmation attempts using the same valid nonce, exactly one attempt succeeds, exactly one first owner PersonCert is issued, and all other attempts fail without additional certificates.
- **SC-003**: Across 50 restart cycles after successful pairing, the same first owner PersonCert remains valid for proof-of-possession checks without requiring the owner to scan another QR.
- **SC-004**: 100% of bearer-token-only attempts against household-scoped operations are rejected after this phase, including bearer tokens that were valid before the household auth migration.
- **SC-005**: 100% of valid first-owner proof-of-possession requests for operations allowed by owner caveats are accepted, and 100% of replayed, stale, tampered, or mismatched-signature requests are rejected in the auth test suite.
- **SC-006**: After pairing, local household auth state contains exactly one first owner PersonCert and zero DeviceCerts for the first owner device.

## Assumptions

- Phase 1 has already bootstrapped a household root, machine identity, public household identity response, install-time pair window, and QR emission.
- The Soyeht iPhone app has already generated or can generate the owner P-256 person keypair before confirming pairing.
- The first owner display name can use an app-provided value when present; otherwise a neutral "Owner" display name is acceptable until profile editing exists.
- The public household identity read remains unauthenticated because it exposes only public material and was intentionally designed that way in Phase 1.
- First-owner pairing is the only unauthenticated household state-changing flow in this phase, and it is authorized solely by the active one-shot pair token plus private-key proof.
- Proof-of-possession timestamp tolerance follows the household protocol default of a short replay window around the current time.
- There is no revocation list in this phase, so certificate validity checks cover signature chain, time validity, caveats, and local tamper detection only.
- Any existing non-household legacy behavior not reachable through household-scoped operations is outside this feature unless it directly grants household authority.
