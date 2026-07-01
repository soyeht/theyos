# Follow-up: macOS local enrollment active finish needs a platform proof policy

Historical follow-up from the M1b macOS local enrollment review.

As of 2026-06-29, the previous **A-now** strategy is deferred. Hardware smoke
reached the native Apple `ASAuthorizationPlatformPublicKeyCredentialProvider`
ceremony and the platform reported that passkeys do not support attestation.
The native synced platform-passkey surface cannot produce the Apple Anonymous /
device-bound proof that the A3 policy required.

The current A-now work is foundation-only and remains inert: local start may
request and stage an attested Apple Anonymous ceremony, and the backend may
model/verify the Apple proof in an inert helper, but local finish remains
`local_attestation_constraints_unavailable`. This follow-up is now a record of
why active finish must stay deferred unless a future STOP defines a new proof
surface.

## Symptom / issue

The macOS local enrollment route has two independent gates:

- **Gate 1, caller auth:** peer code-signing from the accepted UDS connection.
  M1b-peer landed this foundation by deriving peer identity from
  `LOCAL_PEERTOKEN`, validating it through SecCode and the designated
  requirement, and keeping the TCP/PoP path separate.
- **Gate 2, credential attestation:** the new owner passkey must be proven
  server-side to come from an acceptable platform authenticator with user
  verification before local finish can commit it.

Gate 1 is implemented. Gate 2 was staged in slices: request/state foundation
first, then proof/model helper, then active commit. The native macOS
platform-passkey hardware smoke reached the Apple ceremony and showed that this
surface does not produce the device-bound Apple attestation required by that
active commit design. The active commit slice is therefore blocked unless a
future STOP selects a new proof surface. Until then, the local HTTP finish must
remain `local_attestation_constraints_unavailable`.

The platform option added for local start is only request shaping. In the
current `webauthn-rs` wrapper, `authenticatorAttachment=platform` is a client
hint; the normal `Passkey` finish path enforces user verification but does not
prove platform attachment server-side. Activating local finish with only the
platform hint, UV, and peer-auth would trust the client for a security property
that the server has not verified.

## Current policy

Current strategy: **defer native macOS-local active finish**. Product direction
is Local Workspace plus Secure/Upgrade with iPhone before multi-device fan-out;
owner-tier/provenance is tracked in the Swift-side
`docs/local-workspace-trust-model.md`.

Do not activate macOS local finish with the current `Passkey` path or with
request-shaped options alone. The route may support peer-authenticated
start/status, may stage a distinct `LocalAttestedRegistration` challenge for the
Apple Anonymous path, and may expose an internal `VerifiedLocalAppleAttestedCredential`
proof object after Apple-root/flag checks. The HTTP local finish still must not
call `finish_registration`, `sign_genesis`, save owner auth, update memory, or
advance the WebAuthn anchor unless a future reviewed proof surface explicitly
solves Gate 2.

The attested challenge state must remain separate from normal
`PasskeyRegistration` state. Normal TCP finish must reject it opaquely. The
internal proof/model helper may consume only `LocalAttestedRegistration` state,
but the HTTP local finish must stay `local_attestation_constraints_unavailable`
before any storage or commit work.

## Acceptable active-finish policy

Active local finish requires a later architecture/security STOP with a proof
surface that actually returns evidence. The old native platform-passkey surface
does not satisfy this requirement. The minimum acceptable shape is:

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
- The active commit path accepts only a typed verified proof object, not an
  unchecked `Credential` or generic `Passkey` conversion.

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
- Source guards keep `LocalAttestedRegistration` non-consumable by the normal
  `PasskeyRegistration` finish path.
- Successful local finish appends exactly one initial enrollment genesis event,
  saves owner auth, updates memory, and advances only the WebAuthn anchor.

## A3 evidence harness

The public `webauthn-rs-core 0.5.5` registration API does not expose a
test-only `verify_at` / clock-injection seam. Its public
`register_credential` path verifies attestation certificates at the current
OpenSSL verification time. The expired Apple Anonymous fixture kept in tests is
therefore only a negative proof that the pinned CA path is active; it is not
positive evidence for active finish.

Positive A3 evidence would need to come from either a future safe upstream/test-only
time seam or from a fresh hardware capture on a surface that actually returns
attestation evidence. The current harness is the ignored
test
`macos_local_attested_registration_manual_hardware_fixture_verifies_current_apple_chain`.
It reads an untracked local fixture from
`SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE`, routes it through the same pinned
Apple root verifier and five local policy checks, and prints only sanitized
verdict data: attestation format, UV, BE, BS, root policy version, and root
fingerprint.

Do not commit fresh hardware attestation objects, credential IDs, certificate
blobs, machine names, account names, device identifiers, local socket paths, or
other live-device material. If a local app is needed to capture the fixture,
use `Soyeht Dev.app` or a dedicated test harness, never the installed shipping
`/Applications/Soyeht.app`.

The operator bridge for this capture lives in `soyeht-ios` as PR #273 and is
documented in `docs/macos-local-attestation-capture-runbook.md` in that repo.
It depends on theyOS PR #206 so the isolated `SoyehtDev` state namespace uses
the Development peer verifier for a normally signed `Soyeht Dev.app`. That
bridge stops at live `/registration/local/start` -> `ASAuthorization` ->
untracked local fixture; it does not call `/registration/local/finish`, produce
a positive proof verdict, commit owner auth, update memory, advance anchors, or
activate local enrollment.

The live native run did not produce a fixture because Apple platform passkeys
refused attestation. Do not treat `attestation=none` plus UV as a substitute for
the A3 proof.

Manual command shape:

```sh
SOYEHT_LOCAL_APPLE_ATTESTATION_FIXTURE=/path/to/untracked/local-apple-attestation.json \
  cargo test -p household-rs --manifest-path admin/rust/Cargo.toml \
    macos_local_attested_registration_manual_hardware_fixture_verifies_current_apple_chain \
    -- --ignored --nocapture
```

Fixture shape:

```json
{
  "rp_id": "example.test",
  "origin": "https://example.test",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "attestationObject": "...",
      "clientDataJSON": "..."
    },
    "type": "public-key"
  }
}
```

This harness is evidence-only. It must not activate `/registration/local/finish`,
commit owner auth, write memory, advance anchors, or weaken the production
certificate-time checks.

## Files of interest

- `admin/rust/household-rs/src/owner_webauthn.rs` - registration challenge
  state, platform local start helper, inert Apple proof model, and normal
  passkey finish path.
- `admin/rust/server-rs/src/handlers_owner_events.rs` - macOS local registration
  wrappers and inert local finish.
- `admin/rust/server-rs/src/macos_local_caller_auth.rs` - Gate 1 caller-auth
  verifier boundary.
