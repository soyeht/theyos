# Research: Phase 3 - Machine Join Ceremony

This document closes every plan-time decision left open after specify. Each entry follows the same shape: Decision → Rationale → Alternatives considered.

## R1 — Bonjour distinguishing of pair-device vs pair-machine

**Decision**: Continue publishing exactly one `_soyeht-household._tcp` service. Distinguish the active window via the existing `pairing` TXT key, with values `none` (idle, key may be absent), `device` (Phase 2 pair-device window open), or `machine` (Phase 3 pair-machine window open). When `pairing=machine`, also publish `pair_nonce=<short>` and `pair_role=joiner` on the candidate, and `pair_role=founder` on the founding machine. The publisher reflects `PairDeviceWindow` and `PairMachineWindow` state changes by re-registering TXT only (not service type), preserving Phase-2 RFC behavior.

**Rationale**: A second mDNS service type would force browsers to open two parallel browses and would not reuse Phase-2 publisher infrastructure. A subtype (`_pair-machine._sub._soyeht-household._tcp`) is a cleaner DNS-SD construct but is not uniformly supported by the iOS/macOS NWBrowser shape the iSoyehtTerm app uses. Keeping a single service with TXT-reflected window state matches Phase 2's approach (`pairing=open`) and only needs a value enum bump.

**Alternatives considered**:
- Subtype `_pair-machine._sub._soyeht-household._tcp`: rejected for cross-platform browser fragility; would have required a parallel iSoyehtTerm browse.
- Second service type `_soyeht-pair-machine._tcp`: rejected; doubles the publisher and listener surface for no protocol gain.

## R2 — `pair_role` distinguishing founder from joiner on LAN

**Decision**: Both M1 and M2 publish on `_soyeht-household._tcp` while a Phase-3 ceremony is open: M1 carries `hh_id=<id>` and `pair_role=founder`; M2 carries the **same** `hh_id` (the founder advertises it; M2 picks it up by browsing) and `pair_role=joiner`. M2 advertises a fresh `m_pub_b32=<bare base32 of BLAKE3-128 over its M_pub_SEC1>` (12-byte truncation, encoded as 20 base32 chars) so M1 can identify the candidate before any HTTP traffic. M2 also includes its short `pair_nonce`.

**Rationale**: M1 needs a deterministic way to associate an mDNS announcement with the join-request that follows, and to display a candidate identifier in the UI before the candidate has authenticated. A truncated BLAKE3 of the candidate's machine public key is collision-resistant enough at 96 bits for this single-ceremony use, and short enough to fit a TXT value comfortably. The full M_pub flows over HTTP; the TXT only carries an identifier hint. The `m_id` form (full BLAKE3-256 + base32 + prefix) is reserved for cert chains and would be too long for TXT.

**Alternatives considered**:
- Full SEC1-encoded M_pub in TXT: rejected because TXT records have a 255-byte-per-key limit and base64 of 33 bytes is 44 chars, viable but uses budget poorly when the same string appears in HTTP later.
- `m_id` (full BLAKE3-256 → base32) in TXT: rejected because the value is 52 chars; the hint use case does not need full collision resistance.

## R3 — `soyeht://household/pair-machine` URI is a self-contained signed credential

**Decision**: The QR URI carries every field of a complete `JoinRequest` that the iPhone forwards directly to M1 in **a single network hop**. Per protocol §11 (updated 2026-05-06): `v=1`, `m_pub=<base64url 33-byte SEC1>`, `nonce=<base64url 32 bytes>`, `hostname=<percent-encoded UTF-8>`, `platform=macos|linux-nix|linux-other`, `transport=tailscale|lan`, `addr=<host:port>` (informational hint only), `challenge_sig=<base64url 64-byte raw r||s P-256>`, and `ttl=<unix seconds>` (5-minute window).

The candidate's installer signs `challenge_sig` at install time, before rendering the QR, over canonical CBOR `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}`. The signature binds the four owner-visible identifying fields together — an attacker cannot tamper any of them without invalidating the signature, so the fingerprint and hostname the owner sees on the iPhone are guaranteed to match what the candidate's installer printed.

The owner-side flow is therefore one hop: iPhone scans → iPhone re-verifies `challenge_sig` locally over the reconstructed `JoinChallenge` → iPhone forwards the deterministic CBOR `JoinRequest` to M1's `POST /api/v1/household/join-request` over Tailscale. The iPhone never connects to M2 directly. The `addr` field is informational so M1 (or a future household member) can confirm reachability when probing back.

**Rationale (Apple-grade)**: A two-hop design (iPhone fetches signed JoinRequest from M2 via `local/seed`, then forwards to M1) introduces a second failure surface (iPhone↔M2 reachability) and a longer ceremony, both of which a non-technical user can perceive as flakiness. The single-hop design is **measurably faster** end-to-end, **more resilient** (only iPhone↔M1 Tailscale connectivity is needed), and the "the QR has a signature in it" property is exactly the kind of cryptographic robustness Apple-grade owner UX expects (the iPhone can show "this QR is genuine" before forwarding anything). The QR is ~340 base64url chars after adding `challenge_sig` + `hostname` + `platform` — well under any QR Version 14 budget at error-correction level H, scannable from a phone camera at arm's length.

**`hostname` and `platform` in the signed challenge** prevent a printer-substitution or QR-overlay attacker from showing the owner a misleading hostname while the cert is issued for an attacker-controlled host. Without that binding the QR's `hostname` would be unauthenticated metadata.

**Alternatives considered**:
- Two-hop fetch (iPhone → M2 `local/seed` → iPhone → M1): rejected; adds latency, adds a failure surface, doesn't improve any security property since the M2-side `local/seed` still answers anyone with the short-nonce.
- Owner iPhone POSTs the join-request directly to M2 instead of M1: rejected; M2 has no PersonCert chain to validate the iPhone, so the request would have to travel unauthenticated. The §5 protocol places M1 as the issuer.
- Keep the §11 URI shape with only the existing fields (no `challenge_sig`, no signed hostname): rejected; this was the original design and is what `/speckit-analyze` flagged as **C1 critical** — the iPhone has no way to produce the `challenge_sig` because it does not hold `M_priv`, leaving the protocol underspecified.

## R4 — `JoinRequest` payload and proof of M_priv possession

**Decision**: `JoinRequest` is the deterministic CBOR map below. Its `challenge_sig` is signed by M2 at install time (before rendering the QR) over `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}` — no `hh_id` in the challenge because M2 has no knowledge of the household at install time, and the binding does not need it (the Tailscale destination plus the single-use nonce plus the TTL provide all the binding the protocol relies on):

```cbor
JoinRequest = {
  "v": 1,
  "m_pub": bytes,        // 33-byte SEC1
  "hostname": text,
  "platform": "macos" | "linux-nix" | "linux-other",
  "nonce": bytes,        // 32 random bytes from QR
  "addr": text,          // candidate's reachable host:port hint (informational)
  "transport": "tailscale" | "lan",
  "challenge_sig": bytes // 64-byte raw r||s P-256 over canonical CBOR(JoinChallenge)
}
```

The owner iPhone reconstructs this CBOR directly from the scanned QR's URL parameters (after verifying `challenge_sig` locally) and forwards it to M1's `POST /api/v1/household/join-request` (Story 1). In Story 2, M1 fetches the same signed `JoinRequest` from M2's pre-household `local/seed` endpoint after detecting M2 on Bonjour (R5). Both stories converge on the same byte-pattern reaching M1.

**Rationale**: Direct EC P-256 signature over deterministic CBOR matches the project-wide signed-payload format (Phase 1 `MachineCert`, Phase 2 `PairingProofContext`, request PoP). Signing at install time (not request time) means the QR is a self-contained credential and Story 1 can complete in one network hop (R3).

**Alternatives considered**:
- Include `hh_id` in the challenge: rejected; M2 doesn't know it at install time, and the binding is provided by other invariants.
- TLS client cert with M_priv: rejected because the candidate has no household-issued cert to use for TLS auth, and protocol-wide signed-payload CBOR is the established style.
- A fresh server-issued challenge before signing: rejected because the QR nonce already serves as the unique challenge token within the join window TTL.

## R5 — `JoinRequest` reaches M1 over LAN (Story 2) without an owner scan

**Decision**: When M1 detects M2 on Bonjour with `pair_role=joiner` and a `pair_nonce` it does not yet have a `JoinRequest` for, M1 issues a single GET to `http://<addr-from-bonjour>:<port>/pair-machine/local/seed?nonce=<short>` against M2's pre-household listener. The route is server-validated to only respond while M2's `PairMachineWindow` is open and the supplied short-nonce matches; the response body is exactly the `JoinRequest` CBOR (signed by M2 at window open time). This is the Story-2 substitute for the owner manually scanning M2's QR.

**Rationale**: It keeps the security envelope identical between Stories 1 and 2 — the same signed `JoinRequest` reaches M1 either via owner-scanned QR (the owner iPhone POSTs M1) or via LAN-detected Bonjour (M1 fetches it from M2). The owner iPhone confirmation flow that follows is identical regardless of how M1 obtained the JoinRequest. This is automatic discovery without bypassing owner approval.

**Alternatives considered**:
- M1 trusts the Bonjour TXT alone to construct a JoinRequest stub: rejected; TXT is unauthenticated and can be spoofed on the LAN.
- Skip Story 2 and require QR always: rejected; that violates Apple-Grade Quality on the LAN happy path.

## R6 — Atomic Shamir transition commit ordering (FR-013)

**Decision**: Two-phase commit with the following ordered steps; M1 holds an in-memory `CeremonyTxn` that owns the resources to be committed or rolled back:

**Phase A (prepare, all on M1, all in-memory only)**:
1. Validate owner approval signature against owner PersonCert.
2. Reconstruct `HH_priv` into a `Zeroizing<[u8;32]>` (from sole-shard custody).
3. Sign the `MachineCert` for M2 over canonical CBOR.
4. Generate fresh Shamir shards `(s1, s2)` with `vsss-rs` for `(k=2, n=2)` over the 32-byte `HH_priv` scalar.
5. Encrypt `s1` for M1 (ECDH(M1_priv, M1_pub) → ChaCha20-Poly1305) producing `EncryptedShard_1`.
6. Encrypt `s2` for M2 using ECDH(M1_priv, M2_pub) → ChaCha20-Poly1305 producing `EncryptedShard_2_for_M2`.
7. Stage two files atomically next to their commit targets but with `.staged` suffix:
   - `household_record.cbor.staged` (membership=2, shamir_k=2, shamir_n=2, members=[m1_id, m2_id]).
   - `shamir/self_shard.cbor.staged` (EncryptedShard_1).
8. fsync staged files.
9. Zeroize `HH_priv` from RAM.

**Phase B (request M2's persistence, ack-required)**:
10. POST `JoinResponse{MachineCert, EncryptedShard_2_for_M2, household_record_post_join, peer_list}` to a designated `http://<m2-addr>:<port>/pair-machine/local/finalize` endpoint exposed by M2's pre-household listener (HTTP not HTTPS — see `docs/household-protocol.md` § Pre-household routes for rationale; M2 verifies the cert against the `hh_pub` it pinned earlier from `LocalAnchor`, NOT the response body).
11. M2 atomically writes `machine_certs/<m1_id>.cbor` (M1's self-cert from `peer_list`), `machine_certs/<m2_id>.cbor` (its own newly-issued household cert), `shamir/self_shard.cbor` (its EncryptedShard_2_for_M2 unwrapped under ECDH(M2_priv, M1_pub) and re-wrapped under M2's own at-rest key), and `household_record.cbor`, fsyncs the directory, and replies `200 OK` with a deterministic CBOR ack carrying `m_id` and `BLAKE3-256(MachineCert for M2)`.

**Phase C (commit on M1, irreversible)**:
12. On `200 OK` from M2 with a matching ack hash, M1 atomically renames its `.staged` files to commit, deletes `household_root_sole.cbor` (sole-shard destruction is the **last** step), and clears the `PairMachineWindow` state.
13. Append a `machine_joined` event to `owner_events/log.cbor` so the owner iPhone next poll surfaces "Casa now has 2 machines: M1, M2".

**Rollback**: If any step in A or B fails, `.staged` files are deleted, `HH_priv` is re-zeroized (defense in depth), the sole-shard custody on disk is left untouched, and the join window is closed with no state change.

**Why this ordering**: M1's commit is the irreversible step. By completing M2's persistence (step 11) **before** sole-shard destruction (step 12), we guarantee that if step 12 fails for any reason, the household has not yet become unrecoverable: the worst outcome is "M2 has a MachineCert and shard but M1 still holds sole-shard custody". M1's `household_record.cbor` and own-shard staging file have not yet committed; we treat that as a rollback. The ack hash from M2 binds step 12 to step 11 byte-equivalently — if M2 received different bytes, M1 will not commit.

**Single residual edge case**: M2's ack reaches M1 but M1 crashes before step 12 commits. On restart M1 finds `.staged` files and the sole-shard still present. Recovery is documented in `contracts/shamir-transition.md`: M1 detects this state on boot, probes M2 over Tailscale to determine M2's view, then either finishes step 12 or rolls back. The probe uses a **two-state path** that survives M2's pre-household → household-listener transition:

- If M2 has not yet committed (still in pre-household mode), M1 calls `GET http://<m2_addr>/pair-machine/local/seed?nonce=<short>` — the same endpoint M1 uses in Story 2 (HTTP not HTTPS — pre-household listener, see `docs/household-protocol.md` § Pre-household routes). A `200 OK` carrying a `JoinRequest` with the same `m_pub` indicates "M2 has not committed".
- If M2 has committed, the pre-household listener is shut down and M2 has started serving its household identity. M1 calls `GET <m2_addr>/api/v1/household/identity` over the household's normal transport (HTTPS over Tailscale once the household-scoped listener is up, since M2 now has a household-issued cert). A `200 OK` carrying the same `hh_id` and `hh_pub` as M1's staged household record indicates "M2 has committed". This re-uses an existing protocol surface; no new endpoint is added for recovery.
- If both probes fail (connection refused, DNS error, timeout), M1 retries within `RECOVERY_TIMEOUT` (default 5 minutes). Past that deadline, M1 rolls back and treats any `MachineCert` M2 may have persisted as orphan per `FR-013a`.

When M2 has committed but M1 has not, M1's recovery completes step 12 (atomic rename of `.staged` files), step 13 (sole-shard delete), and step 14 (machine-joined event append). M1's retry of `local/finalize` is idempotent on M2 because M2 returns the same `FinalizeAck` for the same MachineCert bytes it already persisted.

**Alternatives considered**:
- Destroy sole-shard before M2 ack: rejected; a network failure between steps would leave the household unrecoverable.
- Three-machine protocol with a witness: out of scope (Phase 3 is exactly 2 machines) and would require extra infrastructure.

## R7 — Idempotent replay response shape (FR-015)

**Decision**: A duplicate `JoinRequest` (same `m_pub` + `nonce`) submitted within the original join window's TTL after a successful ceremony returns the **same** `JoinResponse` bytes that were returned the first time. M1 stores the most recently issued `JoinResponse` in memory keyed by `(m_pub, nonce)` for the remainder of the TTL plus a 60-second grace window. After the grace window, the cache entry is dropped and any further request is rejected with the generic unauthenticated outcome.

**Rationale**: Bit-equivalent replay response is the simplest contract a candidate's installer can verify safely (it can compare CBOR bytes), and it lets a candidate's network retry behavior (e.g., the request succeeded but the response was lost on the first hop) recover deterministically without re-issuing a second `MachineCert`.

**Alternatives considered**:
- 200 OK with empty body for replays: rejected; leaks "I have seen this nonce" without giving the candidate the materials it needs to recover.
- New `MachineCert` per replay: rejected by FR-015's "MUST NOT cause issuance of a second MachineCert".

## R8 — `OwnerEvent` schema and append log

**Decision**: `OwnerEvent` is the deterministic CBOR map:

```cbor
OwnerEvent = {
  "v": 1,
  "cursor": uint,           // monotonic per household
  "ts": uint,               // unix seconds
  "type": "join-request" | "machine-joined" | "join-cancelled",
  "payload": map,           // type-specific
  "issuer_m_id": text,      // m_id of the household member that staged this event
  "signature": bytes        // 64-byte raw r||s P-256 over canonical CBOR(everything above)
}
```

For `type="join-request"`, `payload` is `{join_request_cbor, fingerprint, expiry}`. `join_request_cbor` carries the candidate's full signed `JoinRequest` (including `challenge_sig`) verbatim — same bytes whether M1 received them from the iPhone (Story 1) or fetched them from M2's `local/seed` (Story 2). This is the single design choice that makes Stories 1 and 2 converge on a byte-identical iPhone-side verification path: the iPhone always reads `payload.join_request_cbor`, decodes to extract the candidate's signed fields, and verifies `challenge_sig` against `m_pub` locally before treating any field as authoritative. The outer `OwnerEvent.signature` is by `M_priv` of the staging member (in Phase 3 always M1) and proves the event reached the iPhone via a real household member, not a long-poll spoof. Persistent storage is `owner_events/log.cbor` (an array of CBOR events, fsync-on-append) plus `owner_events/cursor_head.cbor` (the highest cursor written, for fast resume).

**Rationale**: Signing each event by the issuing member's machine cert means the owner iPhone cannot be spoofed by a network attacker who reaches the long-poll endpoint without holding a household machine private key. The log on disk lets long-poll restart cleanly across server restarts (cursor is durable). Phase 4's gossip will replicate this log unchanged.

**Alternatives considered**:
- In-memory only event stream: rejected because server restarts during a pending join would silently drop the join-request event.
- SQLite-backed event log: rejected because deterministic CBOR is the project-wide signed-payload format; SQLite would just be wrapping CBOR.

## R9 — Cursor encoding

**Decision**: Cursor is a CBOR-unsigned integer monotonic per household, encoded as a base64url-no-pad string in HTTP query params (`?since=<base64url-of-cbor-uint>`). The owner iPhone treats the cursor opaquely.

**Rationale**: Wrapping it in CBOR keeps every wire-format integer identically encoded across the project. base64url-no-pad is URL-safe, fits in a few bytes for ordinary cursor values, and matches the Phase-1/2 base64url convention used for nonces and pubkeys.

**Alternatives considered**:
- Plain decimal in URL: rejected because the project standardizes on base64url for all binary-shaped tokens.
- ULID: rejected because per-household monotonic counter is sufficient and cheaper to validate.

## R10 — Long-poll holding pattern and timeout

**Decision**: `GET /api/v1/household/owner-events?since=<cursor>` is held server-side via `tokio::select!` over (a) a `tokio::sync::broadcast::Receiver<OwnerEvent>` subscribed at request time, (b) a `tokio::time::sleep(Duration::from_secs(45))` timeout, and (c) the request's cancellation token. On (a) with `event.cursor > since`: respond immediately with the matched event(s). On (b): respond `204 No Content` with the unchanged cursor; the client re-polls. On (c): drop silently. Catch-up: if at request time `cursor_head > since`, respond immediately with all events between `since` and `cursor_head`.

**Rationale**: 45 seconds is well below typical mobile NAT idle timeouts (60–90s on cellular, longer on Wi-Fi) and provides a tight enough loop that an APNS tickle is rarely needed for awake iPhones, while keeping per-connection lifetime bounded so memory does not grow unboundedly under network-stuck clients.

**Alternatives considered**:
- WebSocket: rejected; long-poll is sufficient for the event volume in Phase 3 (single-digit events per household per day) and avoids axum WS upgrade complexity.
- Server-Sent Events: rejected; SSE is one-way and fine, but the cursor-based catch-up plus the `204` timeout shape are simpler with plain HTTP responses.

## R11 — Opaque APNS contract

**Decision**: The APNS payload sent by `apns_dispatcher` is exactly the constant byte sequence `b"{\"aps\":{\"content-available\":1}}"`, defined once in code as `pub const APNS_TICKLE_BODY: &[u8] = b"{\"aps\":{\"content-available\":1}}";` in `apns_dispatcher.rs`. The `aps.content-available: 1` envelope is required by Apple's silent-push spec — the iPhone will not wake a backgrounded app for any other body shape, so an earlier `{"v":1}` body satisfied opacity but never woke the long-poll re-poller. APNS HTTP/2 headers are `apns-push-type: background`, `apns-priority: 5`, and `apns-topic: <bundle id from build-time config>`; the `content-available` signal travels in the body, not as a header. The dispatcher's only public function takes a single `&OwnerDevicePushToken` and has no parameter that could carry household-typed payload. The lint stack is **three layers**:

1. **API shape (compile-time)**: `pub async fn dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError>` is the only public function in the module. A `const _: fn(&OwnerDevicePushToken) -> _ = dispatch_tickle;` assertion makes any signature change a compile error.
2. **Runtime audit (test)**: `tests/apns_dispatcher_payload.rs` captures the serialized HTTP body via a spy `ApnsTransport` impl and asserts byte-equality to `APNS_TICKLE_BODY` over a happy-path ceremony.
3. **Source-level lint (CI)**: a script greps `apns_dispatcher.rs` for any byte/string literal in the file other than the declared `APNS_TICKLE_BODY` constant; any `format!`, `serde_json::json!`, `serde_json::to_vec`, `Vec<u8>::from`, or string-literal expression that could produce body bytes is rejected. A second grep rejects any `pub` item other than the declared dispatcher trait, the dispatcher function, and the `ApnsError` enum, so the module's surface area cannot grow accidentally.

**Rationale**: This is the Constitution III honesty test. Apple sees only "this device has something to fetch from its household" and never which household, which event, or which fingerprint. A single layer (the previous task's grep for `serde_json::json!`) is a paper tiger because the dispatcher does not use that macro; it produces bytes from a const. The three-layer stack makes accidental information leaks structurally impossible: an API-shape change breaks the build, a payload change breaks the test, a new body source breaks the lint.

**Alternatives considered**:
- Empty body `{}`: rejected; APNS will not wake a background app without `aps.content-available: 1`.
- Custom body shape `{"v":1}`: rejected for the same reason — the previous Phase 3 implementation chose this and pr-backend-4 caught it during review. Apple silent-push only fires when the `aps.content-available` envelope is present.
- VoIP push: rejected; VoIP is for live calls and Apple is increasingly restrictive about background-only use.

## R12 — Push-token registration and replication

**Decision**: `POST /api/v1/household/owner-device/push-token` accepts `{v=1, push_token, platform="ios"}` authenticated by Soyeht-PoP from the owner PersonCert. The token is persisted on M1 (the only household member in this phase) in `owner_device_push_token.cbor`. When Phase 3 commits and M2 joins, the file is included in `peer_list`'s replication payload as **opaque membership state** so M2 has it on first run. In Phase 4 gossip handles ongoing replication; Phase 3 ships the static-on-join replication so the (2-machine) household is correct from the start.

**Rationale**: Token rotation handled by the iPhone POSTing again with the new token; old tokens are simply overwritten (a single owner device in this phase). The fact that any future household member can dispatch the tickle is the principle that supports the no-SPOF design — Phase 3 exposes the registry and a single dispatcher; Phase 4+ generalizes the dispatch.

**Alternatives considered**:
- Token-per-machine (each machine knows its own token to use): rejected; the owner has one device, the token is one fact, every member that may need to dispatch sees the same fact.
- Centralized push gateway: rejected by Constitution III.

## R13 — Shard-at-rest scheme

**Decision**: A shard is encrypted at rest with ChaCha20-Poly1305 under a key derived via **BLAKE3's native KDF mode**: `key = blake3::derive_key(context = "soyeht-shard-at-rest-v1 m_id=<m_id>", key_material = ECDH(M_priv_owner, M_pub_owner))`. The `context` string follows BLAKE3 KDF best practice (a unique, application-specific, never-reused string that incorporates the per-machine identifier). The encrypted shard format (`EncryptedShard`) is `{v=1, index: uint, nonce: bytes(12), ciphertext: bytes}` deterministic CBOR. Per-machine encryption isolates a leaked shard file: an attacker who reads `shamir/self_shard.cbor` from a backup but does not control the machine's `M_priv` cannot decrypt it.

**Rationale**: Constitution v2.0.0 enumerates exactly five cryptographic primitives — P-256 ECDSA, P-256 ECDH, BLAKE3-256 (with SHA-256 as a temporary fallback), ChaCha20-Poly1305, and Shamir GF(256). HKDF-SHA256 is not on the list and "new primitives require constitution amendment". BLAKE3 has a native, audited KDF mode (`blake3::derive_key`) that is exactly the right shape for this use case (32-byte ECDH shared secret → 32-byte AEAD key). Using it keeps the entire shard-at-rest scheme inside the constitution's allowed primitive set with zero amendment overhead and one fewer dependency in the lock file. BLAKE3 KDF takes a unique `context` string per call site (not a salt parameter), so we encode the per-machine binding directly in the context string.

**Alternatives considered**:
- HKDF-SHA256: rejected because not in the constitution's enumerated primitives; would require a v2.1.0 amendment, which is unjustified when BLAKE3 KDF fits exactly.
- Plain BLAKE3 keyed hash without KDF mode: rejected; BLAKE3 has a dedicated `derive_key` mode (with a different domain-separation tag) precisely so KDF callers don't have to roll their own context-binding scheme.
- Shard encrypted by a fresh symmetric key stored in the OS keystore: rejected because it adds a second secret-management surface that can rot independently of `M_priv`.
- Shard encrypted by the household root: rejected; circular (unwrapping the shard would require reconstructing `HH_priv` first).

## R14 — Generic-failure shape (FR-017, FR-018, FR-019, FR-019a)

**Decision**: Every failure on every household-scoped endpoint introduced or modified by this phase (the join-request endpoint, the owner-events long-poll, the owner approve/decline endpoints, the push-token registry, and M2's pre-household `local/seed` and `local/finalize`) returns HTTP `401` with `Content-Type: application/cbor` and body = deterministic CBOR `{"v": 1, "error": "unauthenticated"}`. No mixing of CBOR success bodies with JSON error bodies. There is no breakdown of nonce-vs-signature-vs-already-consumed-vs-no-window. The same response is returned by both the candidate-facing path (after owner decline/timeout) and the cross-window path (no active window). Internal logs distinguish reasons via `tracing` events at `info` for state transitions and `warn` for malformed input, none containing private material.

**Rationale**: Any externally visible distinction creates an oracle. Mixing JSON and CBOR on the same wire is its own oracle (an observer can tell error vs. success by content-type alone) and breaks the project-wide deterministic-CBOR invariant; the success and failure bodies should be distinguishable only by HTTP status. The cost of the uniform shape is one round-trip of "is something I tried failing because of A or B" replaced by "I retry until expiry"; that cost is acceptable and is why the join window TTL is explicit.

**Alternatives considered**:
- Distinct error codes per condition: rejected, oracle.
- JSON error bodies for human-readability: rejected; the entire wire is deterministic CBOR for signature-stability and content-type uniformity. Human readability of error bodies is solved by `tracing` logs on the server, not by mixing on-the-wire formats.
- Always 200 with body `{"ok": false}`: rejected; the HTTP status mismatch causes more friction with infra than benefits.

## R15 — Library choices

**Decision**: 
- **Shamir GF(256)**: `vsss-rs` (already in the project's transitive dependency graph; constitution-allowed). Wrap with a thin module that fixes (k=2, n=2) and a 32-byte secret length; reject other shapes.
- **mDNS**: reuse `mdns-sd` already used by Phase-2 publisher; no new dependency.
- **APNS**: `a2` HTTP/2 client. The dispatcher behind a trait so test builds can inject a spy.
- **Key derivation**: `blake3::derive_key` (already in the `blake3` crate; no separate KDF crate). Per R13 — HKDF is **not** used.
- **ChaCha20-Poly1305**: `chacha20poly1305` crate, already pinned.

**Rationale**: Every primitive is a constitution-recognized cryptographic operation. No new categories of dependency are introduced.

**Alternatives considered**:
- Hand-rolled Shamir: rejected; vsss-rs is auditable and tested.
- Avoid APNS at all and require LAN-only operation: rejected; Story 1 (remote owner) is required.

## R16 — `PairWindow` → `PairDeviceWindow` rename

**Decision**: In the same change set, rename Phase-2 `PairWindow` symbol to `PairDeviceWindow`, and `pair_window.cbor` on disk to `pair_device_window.cbor`. The server's startup code performs a one-shot in-place migration: if `pair_window.cbor` exists and `pair_device_window.cbor` does not, rename it; otherwise leave alone. Subsequent boots see the new name and never look at the old.

**Rationale**: Adoption-First demands no parallel naming. The rename is mechanical and the in-place migration is one branch of one boot helper; once a host has booted under Phase 3 once, the old name is gone.

**Alternatives considered**:
- Keep both names valid forever: rejected by Constitution IV.

## Open items deliberately deferred to later phases (not Phase 3)

- Replicating the owner-events log across machines (Phase 4 gossip).
- Re-sharding to (2, 3) when a third machine joins (later phase).
- Push-token rotation across multiple owner devices when DeviceCert ships (Phase 5).
- Owner-events from non-M1 issuers when membership grows (Phase 5+).
