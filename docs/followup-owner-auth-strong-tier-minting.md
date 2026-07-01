# Follow-up: strong owner tier minting needs a server-verifiable proof

Status as of 2026-07-01: US-13 schema, App-Attest-specific provenance,
Secure/Upgrade transcript vectors, backend proof verification, durable replay,
and the default-off runtime minter wrapper are implemented and reviewed. The
runtime path remains disabled unless the dedicated Secure/Upgrade rollout and
runtime App Attest configuration are explicitly enabled. Production remains
default-off until a separate flip decision.

## Issue

The current first-owner `pair-device/confirm` path cannot honestly mint a strong
owner tier. It verifies only the pairing nonce and proof of possession for the
submitted owner public key, then signs the owner certificate through the legacy
tierless path.

Client implementations may create that owner key with Secure Enclave APIs, but
the backend does not receive server-verifiable evidence that the key came from an
iOS/iPadOS strong-owner source. A platform string or client convention is not
provenance.

## Current policy

- `pair-device/confirm` remains tierless/weak.
- `PersonCert::sign_owner_with_verified_provenance` must not be called directly
  from runtime. Runtime minting must go through
  `sign_owner_cert_with_secure_upgrade_verification`, which revalidates the
  verified ceremony scope before calling the minter.
- Missing, legacy, malformed, unknown, or null owner-tier/provenance stays
  non-strong.
- App-Attest-specific provenance names (`ios-app-attest-owner` /
  `ipados-app-attest-owner`) are schema-staged, vector-pinned, and mintable only
  after `verify_secure_upgrade_ceremony_for_challenge` succeeds.
- The STOP is source-guarded:
  `owner_strong_tier_minting_source_guard_requires_stop_resolution` fails on a
  direct runtime minter caller, missing ceremony/runtime wiring, or accidental
  rollout inclusion.
- `reviewed-core-v2` remains a separate base rollout and does not include
  Secure/Upgrade. Secure/Upgrade strong minting is gated by the exact
  `reviewed-core-v2-secure-upgrade` rollout plus required runtime App Attest
  environment configuration.

## Implemented proof design and remaining activation boundary

Define a Secure/Upgrade with iPhone ceremony that proves strong owner provenance
to the backend. The minimum shape:

- server-issued challenge and freshness/replay protection;
- server verification of the iOS/iPadOS provenance proof;
- typed provenance accepted only after verification;
- no trust in request strings, headers, UI state, or client-side Secure Enclave
  claims alone;
- migration semantics for existing tierless owners: local-only or
  upgrade-required, never silently strong;
- cross-language vectors for any new signed/canonical payloads.

The reviewed proof surface is App Attest with a canonical transcript and
owner-key signature over the same challenge digest. The old native macOS
platform-passkey attestation path remains deferred and is not a substitute.

## Candidate A: App Attest-backed Secure/Upgrade with iPhone

Status: implemented and reviewed as the default-off Secure/Upgrade ceremony.
The positive App Attest chain gate was sealed with a real iPhone capture through
the local-only harness; no raw capture fixture is committed.

Apple's App Attest documentation describes the shape that matches the missing
proof boundary: the app creates an App Attest key, asks Apple to certify that
key, sends the attestation object and key identifier to the server, and later
uses that key to produce assertions at critical moments. Apple also requires a
unique, one-time server challenge before attestation or assertion so replayed
objects cannot mint trust. References:

- <https://developer.apple.com/documentation/devicecheck/dcappattestservice>
- <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>
- <https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service>

If accepted, the strong-owner ceremony should be a new Secure/Upgrade with
iPhone flow, not a mutation of the legacy `pair-device/confirm` nonce-prover.
The minimal ceremony is:

1. The backend issues a single-use, short-lived strong-owner challenge bound to
   the household, installation profile, intended owner public key, and operation
   (`secure_with_iphone` / `upgrade_owner_tier`).
2. The iPhone client creates or reuses an App Attest key for the correct app
   profile. First use sends an Apple App Attest attestation object plus key
   identifier. Later use sends an App Attest assertion over the same
   challenge-bound transcript.
3. The iPhone owner key signs the same transcript through the existing owner
   approval UX. This proves possession of the owner key and preserves the
   biometric/user-presence ceremony in the client UX, but the backend must not
   treat a local Secure Enclave claim as provenance by itself.
4. The backend verifies the App Attest object/assertion against Apple's App
   Attest rules, the expected team/app identifier, the challenge transcript, and
   replay/counter state.
5. Only after verification succeeds, and only if governance accepts this
   composite proof semantics, does runtime construct the typed provenance value
   and call `sign_owner_with_verified_provenance`.

Important proof boundary: App Attest attests the app instance / App Attest key
according to Apple's App Attest model. It does not, by itself, remotely attest
that the separate owner signing key was generated in the Secure Enclave. This
candidate therefore treats "App Attest proof + canonical transcript + owner-key
signature over the same transcript + client source guards for the expected
Secure Enclave provider" as the proposed proof for strong owner provenance. If
that composition is not accepted, the runtime provenance enum must be renamed or
extended (for example, an App-Attest-specific owner provenance) instead of
minting the existing `IosSecureEnclaveOwner` / `IpadOsSecureEnclaveOwner`
variants.

The transcript is canonical CBOR with cross-language Rust/Swift vectors and
includes:

- household identifier / authority head being upgraded;
- owner public key / existing tierless owner certificate identity;
- install profile (`dev` vs `prod`) and expected app identity;
- operation label and protocol version;
- server nonce, issued-at, expiry, and single-use challenge id;
- App Attest key identifier and environment (`development` vs `production`);
- owner-key signature over the same transcript.

Implemented server-side acceptance criteria:

- verify the Apple App Attest attestation/assertion before creating a typed
  provenance object;
- reject replayed, expired, cross-profile, cross-household, or cross-operation
  transcripts opaquely with no mutation;
- store enough App Attest key/counter/challenge state to enforce freshness and
  replay protection across restart/rollback;
- make sandbox/development App Attest material valid only for the dev profile
  and production material valid only for production;
- preserve legacy/tierless owners as weak until they complete this ceremony;
- add fixtures/vectors for the signed transcript and for failure-classification
  results, without committing real user/device material.

Client-side acceptance criteria and current boundary:

- App Attest capture support exists only in a Dev/test harness guarded outside
  product sources; shipping Swift product roots remain source-guarded against
  `DCAppAttestService` / `DeviceCheck`;
- add source guards/tests proving the Secure/Upgrade flow uses the expected
  Secure Enclave owner-key provider, not a software or fallback key path;
- check `DCAppAttestService.isSupported` and fail into "upgrade unavailable" /
  "try on a supported iPhone" UX, not into a weak fallback;
- keep Local Workspace copy local-only until the server returns a verified
  strong tier;
- do not label a Mac-local owner as hardware-attested or strong;
- do not use synced passkey `attestation=none` or platform strings as a
  substitute for App Attest.

Operational constraints:

- App Attest development and production environments are distinct; keys or
  receipts from one environment must not be accepted in the other.
- Attestation calls should be rolled out gradually and rate-limit failures must
  fail closed for strong-tier minting.
- Simulators and unsupported devices must not mint strong tier. They may keep
  Local Workspace behavior.

Open decisions for Caio + security/governance:

- Which production app identities are allowed to mint strong, and when should
  production be flipped from the default-off state?
- Does strong-tier upgrade replace the tierless `PersonCert`, append a new
  owner-auth event, or mint a new certificate version under the same owner key?
- What explicit approved/denied or approved/online signal should the Mac receive
  after upgrade, rather than relying only on reactive presence? See
  `followup-approved-online-signal.md`.
- What migration path applies to existing tierless owners?

Recommended governance framing:

| Option | Meaning | Tradeoff |
| --- | --- | --- |
| 1. Accept the existing enum name | Governance explicitly accepts "App Attest proof + canonical transcript + owner-key signature + client source guards" as sufficient semantics for `IosSecureEnclaveOwner` / `IpadOsSecureEnclaveOwner`. | Smallest schema delta, but the name can be over-read as remote attestation of the owner key's Secure Enclave origin unless docs and tests keep the composite-proof boundary clear. |
| 2. Add App-Attest-specific provenance | Add a provenance name whose wire meaning is exactly App-Attest-backed owner minting, then gate fan-out on the accepted strong set. The schema/vector support for this naming is staged, but runtime minting still waits on the proof ceremony. | Slightly more schema/test work, but avoids semantic overclaim and keeps future direct key-origin proof distinguishable. |

Conservative recommendation: keep option 2, the App-Attest-specific provenance
names, and keep production default-off until operational flip readiness is
explicitly accepted. The current runtime wrapper supports the reviewed ceremony
without adding Secure/Upgrade to the base `reviewed-core-v2` rollout.

Decision record checklist, to fill before implementation:

- proof model decision: App Attest composite proof, another proof model, or
  rejected/deferred;
- provenance naming decision: App-Attest-specific
  `ios-app-attest-owner` / `ipados-app-attest-owner`, existing
  `*-secure-enclave-owner` with explicit composite semantics, or another
  reviewed value;
- allowed app identities and environments: production bundle/team/app id,
  development profile, and whether dev receipts are isolated from production;
- proof verification anchor / trust root: which pinned root or anchor verifies
  the selected proof, compiled in with provenance and proof-source-only
  acceptance (Apple App Attest root for Candidate A);
- platform scope: iOS only or iOS + iPadOS at first release;
- transcript scope: operation label, household id, owner key id, challenge id,
  expiry, selected proof key id/environment (App Attest key id/environment for
  Candidate A), and owner-key signature over the same bytes;
- replay/counter storage: challenge state, selected proof counter/freshness
  state (App Attest counter persistence for Candidate A), rollback behavior, and
  opaque failure semantics;
- migration semantics: whether existing tierless owners stay weak until an
  explicit upgrade, whether the upgrade replaces or appends owner-auth state,
  and whether any legacy cert version changes are required;
- client key-provider requirement: the Secure/Upgrade path must use the
  expected Secure Enclave owner-key provider, with no software/fallback key path
  allowed to mint strong;
- approved/online signal choice: Option R reactive-only or Option E explicit
  versioned signal, with the wire names and Swift/server STOP guard updates
  recorded together if Option E is chosen;
- flip boundary: `reviewed-core-v2` remains off for real households until real
  owners can be minted/upgraded and every newly active fan-out gate has
  default-safe activation tests.

Initial decision for the transcript-vector slice:

- proof model: Candidate A, App Attest composite proof;
- provenance naming: App-Attest-specific
  `ios-app-attest-owner` / `ipados-app-attest-owner`;
- platform scope: iOS + iPadOS;
- proof verification anchor / trust root: Apple App Attest root, pinned and
  compiled in with provenance and proof-source-only acceptance in the verifier
  slice;
- approved/online signal: Option R reactive-only for now; do not add
  `presence_approved` in the transcript/vector slice;
- migration semantics: existing tierless owners stay weak until explicit
  Secure/Upgrade; upgrade issues a new HH-root-signed owner auth state carrying
  the App-Attest-specific provenance, with no silent promotion.

The verifier, durable replay, typed provenance, runtime wrapper, and Dev capture
harness have landed. The remaining STOP is activation: production must not set
`reviewed-core-v2-secure-upgrade` until Caio explicitly approves that
environment, and `reviewed-core-v2` remains separate.

### Apple App Attestation Root Provenance

The Secure/Upgrade App Attest verifier pins Apple's App Attestation root
certificate and does not use the system trust store. The embedded DER in
`SECURE_UPGRADE_APP_ATTEST_ROOT_CA_DER_B64` must decode to this exact root
and match `SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256` before it can be used as a
trust anchor.

Public source of truth:

- Apple PKI private CA page:
  <https://www.apple.com/certificateauthority/private/>
- Apple App Attestation Root CA PEM:
  <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>

Verified certificate metadata from the Apple PEM:

- subject: `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`
- issuer: `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`
- validity: `2020-03-18 18:32:53 UTC` to `2045-03-15 00:00:00 UTC`
- SHA-256 fingerprint / DER hash:
  `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`

Repro commands:

```sh
curl -fsSL \
  https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem \
  -o /tmp/Apple_App_Attestation_Root_CA.pem
openssl x509 -in /tmp/Apple_App_Attestation_Root_CA.pem \
  -noout -subject -issuer -dates -fingerprint -sha256
openssl x509 -in /tmp/Apple_App_Attestation_Root_CA.pem -outform der \
  | shasum -a 256
```

This provenance check closes the trust-root identity gate. The 3b
chain-verification path was then sealed by a local-only real iPhone App Attest
capture and ignored Rust verifier run; the raw fixture stays outside the repo.

## Post-decision implementation sequence

Implementation stayed sliced so proof semantics landed before enforcement:

1. **Freeze the decision record.** Record the accepted provenance name, allowed
   app identities, iOS/iPadOS scope, migration semantics, and Option R/E signal
   choice before runtime code changes the STOP guards.
2. **Pin the canonical transcript first.** Add Rust/Swift golden vectors for the
   Secure/Upgrade transcript, including operation label, household/owner
   identity, challenge id, expiry, app profile, selected proof key
   id/environment. The owner key signs these same transcript bytes in the later
   proof slice. A transcript drift must fail before any runtime proof path
   depends on it.
3. **Implement backend verification without broad gates.** Add the challenge
   store, selected proof verification (App Attest for Candidate A),
   replay/counter persistence, typed provenance construction, and
   `sign_owner_with_verified_provenance` call only after the proof verifies.
   Existing tierless owners remain weak until they complete this ceremony.
4. **Implement the iPhone Secure/Upgrade client path.** Add App Attest support,
   if Candidate A is accepted, plus provider source guards for the expected
   Secure Enclave owner-key path and unsupported-device UX. No software/fallback
   key path may mint strong.
5. **Implement the approved/online decision.** If Option E is chosen, add the
   versioned approval signal and a client approval-state model separate from
   presence state, updating the Swift and server STOP guards in the same
   reviewed PR. If Option R is chosen, keep reactive presence copy honest and do
   not add `presence_approved`.
6. **Only then stage remaining fan-out gates.** Device-pairing approve, remote
   attach, mesh/relay/VPN membership, and any Product A transport integration
   need their own default-safe policy tests before depending on real strong
   owners. `reviewed-core-v2` stays off for real households until real owners can
   be minted/upgraded and the gates have activation-safety tests.

## Future fan-out gates

`/api/v1/household/device-pairing/approve` is a fan-out path: it approves a
pending device-pairing request and returns owner/device certificate material.
It should eventually require the same strong-tier classifier as pair-machine,
but not before the rollout boundary is explicit and strong-tier minting exists.

If this gate is staged before minting is implemented, it must be default-safe:

- a separate policy dimension or rollout that is not accidentally enabled by the
  current `reviewed-core-v2` package;
- default/legacy behavior continues to allow tierless owners;
- policy-on behavior rejects tierless owners opaquely before finalizing the
  pending request;
- tests pin both behaviors and source guards prevent accidental inclusion in the
  main flip.

Current guard: `device_pairing_fan_out_gate_source_guard_remains_stop_gated`
keeps `/device-pairing/approve` out of `owner_can_fan_out()` /
`reviewed-core-v2` until that separate rollout and strong-tier minting design
exist.

Current guard: `household_remote_attach_source_guard_remains_stop_gated` keeps
household attach-token / terminal PTY remote attach on its current
`Operation::ClawsUse` + single-use attach-token path, and out of
`owner_can_fan_out()` / `reviewed-core-v2`, until the separate rollout and
strong-tier minting design exist.

Product A / nvpn / mesh, relay membership, and remote attach are post-trust
transports. They do not elevate owner tier and must not become authority. Current
guard: `product_a_transport_source_guard_does_not_become_owner_tier_authority`
fails if the relay-stream/Product A runtime starts depending on the strong-tier
classifier, the strong-tier minter, or the current `reviewed-core-v2` rollout.
