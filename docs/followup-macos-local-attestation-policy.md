# Follow-up: macOS local enrollment active finish needs a platform proof policy

Blocking follow-up from the M1b macOS local enrollment review.

## Symptom / issue

The macOS local enrollment route has two independent gates:

- **Gate 1, caller auth:** peer code-signing from the accepted UDS connection.
  M1b-peer landed this foundation by deriving peer identity from
  `LOCAL_PEERTOKEN`, validating it through SecCode and the designated
  requirement, and keeping the TCP/PoP path separate.
- **Gate 2, credential attestation:** the new owner passkey must be proven
  server-side to come from an acceptable platform authenticator with user
  verification before local finish can commit it.

Gate 1 is implemented. Gate 2 is not. The local finish must therefore remain
`local_attestation_constraints_unavailable`.

The platform option added for local start is only request shaping. In the
current `webauthn-rs` wrapper, `authenticatorAttachment=platform` is a client
hint; the normal `Passkey` finish path enforces user verification but does not
prove platform attachment server-side. Activating local finish with only the
platform hint, UV, and peer-auth would trust the client for a security property
that the server has not verified.

## Current policy

Default state: **B / blocked by safe platform proof**.

Do not activate macOS local finish with the current `Passkey` path. The route
may continue to support peer-authenticated start/status and local platform
request options, but it must not call `finish_registration`, `sign_genesis`,
save owner auth, update memory, or advance the WebAuthn anchor until Gate 2 is
explicitly solved.

## Acceptable active-finish policy

Active local finish requires a separate architecture/security decision. The
minimum acceptable shape is:

- Apple WebAuthn anonymous attestation is verified against the pinned Apple
  WebAuthn root CA, not by hand-rolled parsing.
- The registration ceremony uses attestation conveyance that actually returns
  attestation evidence and is challenge/RP/nonce bound to the local start.
- User verification is required and verified server-side.
- Backup eligibility/state flags are rejected if the library exposes reliable
  predicates for them; if these flags are not available, active finish remains
  sub-blocked.
- Gate 1 peer-auth remains mandatory; attestation is not a replacement for
  peer-auth, and peer-auth is not a replacement for attestation.
- The attested registration state and finish path are separate from the normal
  `PasskeyRegistration`/`finish_passkey_registration` path so existing TCP,
  iOS, recovery, and AddCredential paths cannot silently weaken.
- Attestation evidence or verified metadata is retained or audited in a way
  that makes future review/debugging possible.

Apple Anonymous attestation may not expose a Mac model AAGUID. That gap is a
policy decision, not an implementation detail: accepting Apple Anonymous means
accepting the composition of local signed-app peer-auth, challenge binding,
Apple root-verified platform attestation, device-bound flags, and UV as the
proof. If that policy is not accepted, keep local finish inert until a stronger
server-side proof is available.

## Required tests for any active slice

- No attestation, self attestation, wrong CA, wrong RP, wrong challenge/nonce,
  UV false, and prohibited backup flags all reject opaquely with zero commit.
- A missing or denied local peer still rejects before decode/challenge work.
- The TCP/PoP path continues to use the normal registration flow and cannot
  enter the local attested path.
- Source guards prevent fallback from local active finish to the normal
  `Passkey` finish path.
- Successful local finish appends exactly one initial enrollment genesis event,
  saves owner auth, updates memory, and advances only the WebAuthn anchor.

## Files of interest

- `admin/rust/household-rs/src/owner_webauthn.rs` - registration challenge
  state, platform local start helper, and normal passkey finish path.
- `admin/rust/server-rs/src/handlers_owner_events.rs` - macOS local registration
  wrappers and inert local finish.
- `admin/rust/server-rs/src/macos_local_caller_auth.rs` - Gate 1 caller-auth
  verifier boundary.
