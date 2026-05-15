# Research: Phase 2 - Owner Pairing and Proof-of-Possession Auth

## R1 - First Device Cert Chain Shape

**Decision**: The install-time first owner iPhone receives a `PersonCert` only. It does not receive or require a `DeviceCert`.

**Rationale**: `docs/household-protocol.md` states that a person's first device holds `P_priv` directly, while DeviceCert is required for second and later devices. Keeping this phase to PersonCert avoids inventing an unnecessary cert edge and matches the iSoyehtTerm companion spec.

**Alternatives considered**:
- Issue PersonCert + DeviceCert for the first device: rejected because it contradicts the current protocol text and blurs the later second-device delegation story.
- Issue a temporary bearer token after pairing: rejected by the constitution's capability-auth requirement.

## R2 - Pairing Proof Format

**Decision**: Pairing confirmation carries the submitted `p_pub` plus a raw P-256 signature over deterministic CBOR `PairingProofContext = {v, purpose, hh_id, nonce, p_pub}`. The signature proves control of the matching `P_priv` before theyOS signs a PersonCert.

**Rationale**: The proof is independent of HTTP transport details and binds the person key to the exact household and one-shot nonce. Deterministic CBOR preserves the protocol's signed-payload invariant.

**Alternatives considered**:
- Trust `p_pub` without proof: rejected because an attacker could bind someone else's public key.
- Sign ad hoc strings: rejected because deterministic CBOR is the protocol-wide signed-payload format.

## R3 - PersonCert Storage

**Decision**: Persist `owner_person_cert.cbor` and `household_auth_state.cbor` under the existing household state directory with atomic write semantics and mode 0600.

**Rationale**: Phase 1 already established this storage boundary for household identity. Keeping owner auth state adjacent makes restart loading and tamper refusal straightforward.

**Alternatives considered**:
- Store in SQLite: rejected because the cert is protocol state, not relational app data, and deterministic CBOR is already required for signature verification.
- Store only in memory: rejected because restarts must preserve owner auth state.

## R4 - Request Proof-of-Possession Contract

**Decision**: Use `Authorization: Soyeht-PoP v1:<p_id>:<ts>:<signature_b64url>`, where the signature is over deterministic CBOR `RequestSigningContext = {v, method, path_and_query, timestamp, body_hash}`.

**Rationale**: The header is easy to parse in axum, keeps bodies unchanged, and binds signatures to method, target, timestamp, and body contents. theyOS can look up the first owner PersonCert locally by `p_id`.

**Alternatives considered**:
- Put cert and signature in every request body: rejected because it complicates GET/WS flows and duplicates stable cert material.
- Continue bearer tokens for household routes: rejected by the spec and constitution.

## R5 - Timestamp Tolerance

**Decision**: Accept PoP timestamps within ±60 seconds of server wall clock.

**Rationale**: This matches the household protocol default and is short enough to reduce replay exposure while tolerating ordinary phone/Mac clock skew.

**Alternatives considered**:
- Longer tolerance: rejected because it expands replay risk.
- Nonce challenge per request: deferred because this phase only has one owner and no gossip/revocation infrastructure.

## R6 - Auth Failure Shape

**Decision**: Return generic authentication failure for PoP errors and 404-style closed-window behavior for pair-window errors, preserving Phase 1's no-oracle property.

**Rationale**: The spec requires that failures not reveal active nonce, pair-window existence, or exact validation step.

**Alternatives considered**:
- Detailed error codes for every failure: rejected because it creates pairing and auth probing oracles.

## R7 - Owner Caveat Template

**Decision**: The first owner PersonCert carries the full owner caveat set from the protocol: list/create/delete/use/assign Claws plus household invite/revoke/add_machine capabilities, even if several operations remain unimplemented in this phase.

**Rationale**: The cert expresses household authority, not only currently mounted routes. Future UI can render from the same owner cert without reissuing it immediately.

**Alternatives considered**:
- Issue only capabilities used by Phase 2 routes: rejected because it would force immediate cert rotation before the next household-management feature.
