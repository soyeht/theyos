# Onboarding S2: Owner Approval Envelope Design

Status: S1/S2 inert primitives are merged after Caio GO. No endpoint
enforcement is enabled by this document.

Base: S1 WebAuthn RP core is merged; S2 runtime primitives are separate from
the later endpoint enforcement switch.

Implemented inert pieces:

- WebAuthn RP core with server-side challenge storage and tests.
- `OwnerApprovalContextV2` canonical CBOR encoding and challenge digest.
- Rust<->Swift cross-language fixture for canonical bytes and challenge digest.
- Trusted-state builder for pair-machine approval context.
- `OwnerApprovalV2` body shape and byte-equality guard against trusted context.

Held pieces:

- Handler enforcement and any behavior switch remain gated on design review and
  explicit Caio approval.
- Bootstrap/owner-operation enforcement remains sequenced after S3 enrollment
  UX and CLI/installer migration.

## Goal

S2 turns the existing pair-machine owner approval into a Protocol-v2 envelope
that is authorized by the owner's passkey/WebAuthn credential. The envelope must
bind the human approval to the exact operation and candidate request the engine
will commit.

S2 does not replace `BOOTSTRAP_MUTATION_LOCK`. The lock still serializes the
check -> disk -> memory transaction. S2 decides whether the caller is authorized
to enter that transaction.

## Current Gap

Today `OwnerApprovalContext` signs only:

- `purpose`
- `hh_id`
- `p_id`
- `cursor`
- `challenge_sig`
- `timestamp`

That proves an owner key approved some pending cursor, but it does not directly
bind the approval to the candidate address, transport, nonce, TTL, derived
machine id, or canonical join request hash.

The current handler also relies on the existing owner PoP/auth path before it
parses `OwnerApproval`. S2 should keep generic failure surfaces but move the
authorization root for owner operations to WebAuthn.

## Genesis Exception

There is one deliberate exception to "owner operation requires owner assertion":
the first `BootstrapInitialize` on an empty engine has no owner credential yet.
It cannot require a pre-existing passkey without breaking founder onboarding.

Genesis initialize is therefore an enrollment ceremony:

- allowed only in the empty pre-household state;
- trusted by the existing local/founder bootstrap surface and loopback/operator
  gating;
- creates household identity and enrolls owner credential #1 through WebAuthn
  registration;
- does not accept an IdP-only proof as owner authority.

Every operation after a household and owner credential exist requires owner
assertion: re-initialize over an existing household, teardown, pair-machine
approve, pair-device confirm, credential revoke, and future owner-sensitive
mutations.

Do not flip enforcement on bootstrap endpoints before S3 enrollment UX and the
non-passkey CLI/installer flows are migrated. The S2 context can be built and
tested first; production enforcement is sequenced after enrollment is usable.

## Protocol-v2 Shape

Add a new versioned context instead of mutating the v1 shape in place:

```rust
pub enum OwnerOperation {
    PairMachineApprove,
    BootstrapInitialize,
    BootstrapTeardown,
    PairDeviceConfirm,
    RevokeCredential,
}

pub struct OwnerApprovalContextV2 {
    #[serde(rename = "v")]
    pub version: u8, // 2
    pub purpose: String, // "owner-approval-v2"
    pub op: OwnerOperation, // fixed string enum, serde rename_all="kebab-case"
    pub hh_id: HouseholdId,
    pub owner_p_id: PersonId,
    pub cursor: Option<u64>,
    pub m_id: Option<MachineId>,
    pub addr: Option<String>,
    pub transport: Option<JoinTransport>,
    pub ttl_unix: Option<u64>,
    pub nonce: Option<ByteBuf>,
    pub join_request_hash: Option<ByteBuf>,
    pub capabilities: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub replay_nonce: ByteBuf,
}
```

For pair-machine approval, every `Option` above is required except fields that
do not apply to other operations. The verifier should reject a
`PairMachineApprove` context missing any of:

- `cursor`
- `m_id`
- `addr`
- `transport`
- `ttl_unix`
- `nonce`
- `join_request_hash`

`m_id` is derived from `JoinRequest.m_pub` using the existing
`derive_machine_id` rule. `join_request_hash` is the existing BLAKE3 hash of the
canonical cached join request bytes. `ttl_unix`, `addr`, `transport`, and
`nonce` must be copied from the active `PairMachineWindowSnapshot`/decoded
`JoinRequest`, not from the caller body.

## Deterministic Encoding

Canonicalization is a merge gate, not a best-effort implementation detail. Rust
and Swift must agree byte-for-byte on the context before any handler accepts a
v2 approval.

Rules:

- CBOR uses RFC 8949 section 4.2 deterministic encoding.
- All maps and strings use definite lengths; indefinite encodings are rejected.
- Map keys are sorted by their encoded bytes.
- Integers use the shortest valid encoding.
- Duplicate map keys are rejected.
- `ByteBuf` fields encode as CBOR byte strings, not base64 strings.
- `OwnerOperation` encodes as an explicit kebab-case string with a fixed mapping
  (`pair-machine-approve`, `bootstrap-initialize`, `bootstrap-teardown`,
  `pair-device-confirm`, `revoke-credential`).
- `Option::None` fields are omitted from the map, not encoded as `null`.
- `capabilities` is sorted deterministically before signing/verifying; an
  unsorted list is rejected by the context builder/verifier.

The Rust<->Swift fixture for these bytes must be a permanent CI gate. It is not
just a one-time review artifact.

## WebAuthn Binding

The current `webauthn-rs` / `webauthn-rs-core` API generates authentication
challenges internally. Its challenge constructor and authentication-state
challenge field are crate-private, and `authenticate_credential` verifies only
against the state emitted by the library. Do not fork the crate, hand-roll
COSE/client-data/signature verification, or mutate library-internal state by
serde/field injection just to supply custom challenge bytes.

S2 therefore uses server-side challenge-state binding:

- `webauthn-rs` still issues the opaque random WebAuthn challenge `R`;
- at issue time, the server writes one atomic challenge-state record binding
  `R` / challenge id to the canonical context bytes, challenge digest,
  operation, credential policy, replay nonce, and expiry;
- at finish time, the library verifies the assertion over `R`;
- the server then requires byte-equality between `body.context`, the context
  rebuilt from trusted live state, and the context stored with `R`;
- only after that does the handler reassert the live window under
  `BOOTSTRAP_MUTATION_LOCK` and mutate state.

This means the context binding in S2 is enforced by security-critical server
state, not directly by the WebAuthn signature. The signature proves owner
presence/consent over the fresh challenge `R`; the server-side `R` to context
record makes that consent operation-specific. The record must be single-use,
TTL-bound to no later than the join window, and consumed without a replay window
once verification succeeds.

The deterministic context digest remains the SSOT for cross-language fixtures
and stored challenge metadata:

```text
context_digest = SHA-256("soyeht-owner-approval-v2\0" || canonical_cbor(context))
```

The submitted approval body should carry:

```rust
pub struct OwnerApprovalV2 {
    #[serde(rename = "v")]
    pub version: u8, // 2
    pub context: OwnerApprovalContextV2,
    pub credential_id: ByteBuf,
    pub authenticator_data: ByteBuf,
    pub client_data_json: ByteBuf,
    pub signature: ByteBuf,
    pub user_handle: Option<ByteBuf>,
}
```

Verification order:

1. Decode canonical CBOR and reject non-canonical encodings.
2. Verify the WebAuthn assertion using S1, enforcing RP ID, origin,
   single-use challenge, TTL, active credential, revoked credential rejection,
   and sign-count policy.
3. Look up and consume the server-side challenge-state record for `R`.
4. Rebuild the expected context from trusted server/window state.
5. Require byte-equality between `body.context`, the rebuilt context, and the
   canonical context bytes stored with `R`.
6. Recompute the context digest from canonical context bytes and require it to
   match the digest stored with `R`.
7. Reassert the live window/cursor/join request under
   `BOOTSTRAP_MUTATION_LOCK`.
8. Only then enter the existing prepare/finalize transaction under
   `BOOTSTRAP_MUTATION_LOCK`.

The assertion itself remains opaque to local code outside the S1 verifier. Do
not hand-roll COSE/client-data/signature validation in pair-machine handlers.

## Sign-count Policy

WebAuthn `sign_count` is not a durable clone-detection guarantee for the
default owner passkey path. Synced platform passkeys, including iCloud-synced
passkeys, may report counter `0` forever. Treating repeated zero values as a
regression would reject legitimate synced passkeys, so zero is an unknown
counter baseline.

The current S1/S2 verification path therefore uses `sign_count` as a
best-effort, ceremony-local check only:

- `previous == 0` accepts `next == 0` and any later positive counter.
- Once a positive counter has been established for the credential instance
  being verified, `next <= previous` is rejected as a regression.
- Counter advances are not appended to the owner WebAuthn authority log and are
  not advanced in the rollback anchor in the current design.

This means S2 must not claim durable clone detection for the default
synced-passkey deployment. If hardware or otherwise non-synced authenticators
with meaningful monotonically increasing counters become a security target,
that is a future persist+anchor slice: record the counter advance in the owner
WebAuthn authority log, persist it before trusting it for later requests, and
advance the keystore-backed anchor after the log commit. Until that exists,
`sign_count` is an audit signal and local verifier hardening, not an enforced
durable policy.

## Replay And Expiry

`replay_nonce` is server-issued and stored server-side with the S1 challenge.
`expires_at` must be no later than the join window expiry and no more than the
S1 challenge TTL.

Replay rejection comes from the S1 challenge store consuming the challenge on
first successful verification. A second approval body with the same WebAuthn
assertion must be rejected before any state mutation.

The single-use challenge store is keyed by the server-issued challenge id for
the opaque WebAuthn challenge `R`; it stores the context digest as metadata and
never trusts a caller-supplied cursor or nonce alone. Submitting the same
context/assertion a second time must miss the consumed challenge and fail
closed.

## Endpoint Integration

### Pair-machine approve

Primary integration point:

- `server-rs/src/handlers_owner_events.rs::owner_approve_handler`
- `household-rs/src/pair_machine.rs::OwnerApprovalContext`

Implementation should introduce v2 alongside v1, then switch the handler to
require v2 when the S2 feature is enabled. For branch review, a hard switch is
acceptable if all existing e2e helpers are migrated in the same branch.

The expected context is built after:

- current household identity is loaded
- active window snapshot is checked for `AwaitingOwner`
- cached join request is decoded and canonical hash is computed

Those reads happen before the Shamir split and before finalization work. The
existing bootstrap mutation lock must remain around the actual mutation path.

### Bootstrap initialize / teardown / pair-device confirm

S2 must not route these through the pair-machine context type. Use the same
`OwnerApprovalContextV2` with operation-specific required fields:

- genesis initialize: no owner assertion; runs WebAuthn registration and stores
  owner credential #1 under the existing empty-state local bootstrap gate
- re-initialize over an existing household: bind `op`, `hh_id`, desired
  household label, owner credential id, issued nonce, `issued_at`, `expires_at`
- teardown: bind `op`, `hh_id`, reason/audit nonce, `issued_at`, `expires_at`
- pair-device confirm: bind `op`, `hh_id`, pairing request id, target device id
  if present, `issued_at`, `expires_at`

Each handler verifies authorization before entering or while already inside the
existing `BOOTSTRAP_MUTATION_LOCK`, but the lock must continue to cover the full
check -> disk -> memory transaction.

## Tests Required Before Runtime Enforcement

Backend/unit:

- pair-machine v2 context canonical bytes are stable.
- generated WebAuthn challenge digest changes when any bound field changes:
  `op`, `addr`, `transport`, `ttl_unix`, `nonce`, `m_id`,
  `join_request_hash`, `capabilities`.
- missing required field for `PairMachineApprove` is rejected.
- expired context is rejected.
- replayed assertion is rejected via the S1 challenge store.
- replayed assertion uses the same challenge digest and is rejected even if the
  HTTP body is resent byte-for-byte.
- origin/RP-ID mismatch is rejected by the S1 verifier.
- sign-count regression is rejected when previous count is non-zero.
- genesis initialize performs registration/enrollment and does not require a
  pre-existing owner assertion.
- re-initialize/teardown/pair/revoke on an existing household require owner
  assertion.

E2E/focused handler:

- unsigned v1 approval body is rejected once S2 is enabled.
- v2 approval for one cursor cannot approve another cursor.
- v2 approval for one join request cannot approve a mutated `addr`,
  `transport`, `nonce`, or `join_request_hash`.
- v2 approval cannot be replayed after a successful approval.
- v2 approval failures use one generic HTTP error for context, credential,
  origin/RP, sign-count, and WebAuthn verifier failures; the response must not
  reveal which layer rejected the request.
- pair-machine-only rollout accepts the legacy path only while the owner has no
  active passkey credential. Once an active owner passkey exists, legacy v1
  approval is rejected while S2 is enabled.
- rejection happens before `CeremonyTxn::prepare` or any disk mutation.

Cross-language fixture:

- Rust fixture emits canonical `OwnerApprovalContextV2` bytes and challenge
  digest.
- Swift fixture computes the same bytes/digest for the same input.
- Fixture asserts `Option::None` omission, fixed string enum encoding, byte
  strings, sorted capabilities, shortest integer encoding, duplicate-key
  rejection, and indefinite-length rejection.
- Fixture values must use neutral aliases only (`mac-alpha`, `192.0.2.10`,
  `100.64.0.10`) and no real host/device identifiers.

## Non-Goals For S2

- No Sign in with Apple/GitHub/Google wiring.
- No UI implementation; S3 owns iOS/macOS passkey enrollment and approval UI.
- No m_priv/headless key redesign.
- No removal of `BOOTSTRAP_MUTATION_LOCK`.
- No Product A/nvpn dependency.
