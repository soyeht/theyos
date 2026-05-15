# Data Model: Phase 3 - Machine Join Ceremony

All on-disk and on-the-wire shapes use deterministic CBOR per RFC 8949 §4.2.1 unless explicitly stated. Public keys are 33-byte SEC1 compressed P-256. Signatures are 64-byte raw `r || s` P-256 ECDSA. Hashes are BLAKE3-256 unless stated.

## PairMachineWindow (in-memory + `pair_machine_window.cbor`)

A short-lived state on the founding machine M1 authorizing exactly one machine-join ceremony at a time.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `state` | text | One of `idle`, `staging`, `awaiting_owner`, `committed`, `aborted` |
| `m_pub` | bytes / null | 33-byte SEC1 of the candidate; null in `idle` |
| `nonce` | bytes / null | 32 random bytes from `JoinRequest`; null in `idle` |
| `expiry` | uint / null | Unix seconds; 5 minutes after window open; null in `idle` |
| `transport` | text / null | `tailscale` or `lan`; null in `idle` |
| `addr_hint` | text / null | Candidate's reachable host:port; null in `idle` |
| `fingerprint` | text / null | 6-word BIP-39 fingerprint string; null in `idle` |
| `owner_event_cursor` | uint / null | Cursor of the staged `join-request` event; null until staged |
| `cached_join_request` | bytes / null | Bit-equivalent deterministic-CBOR bytes of the verified `JoinRequest` (including its `challenge_sig`) for the active ceremony; null until staged. Used at owner-approve time to bit-compare against the `challenge_sig` field embedded in `OwnerApprovalContext` for transitive ceremony binding. |
| `cached_response` | bytes / null | Bit-equivalent CBOR of last successful `JoinResponse`, retained for replay window |
| `anchor_secret` | bytes / null | **Candidate-side only.** 32 random bytes minted at install time, embedded in the QR query string, and persisted here. The owner iPhone presents these bytes back via `POST /pair-machine/local/anchor` to authenticate a `(hh_id, hh_pub)` pin (B7 / `contracts/local-anchor.md`). MUST NOT be returned by `local/seed`. Founder-side staging (Story 1 join-request POST or Story 2 Bonjour fetch) leaves this `null`; only the candidate's own install path sets it. |
| `pinned_hh_pub` | bytes / null | **Candidate-side only.** 33-byte SEC1 of the household's `hh_pub` pinned by a successful `local/anchor` POST. `local/finalize` refuses any `JoinResponse` whose `household_record.hh_pub` does not bit-equal this value. |
| `pinned_hh_id` | text / null | **Candidate-side only.** Defense-in-depth cross-check against `pinned_hh_pub`. Set atomically with `pinned_hh_pub`. |

State transitions:
- `idle → staging` on receipt of a verified `JoinRequest`.
- `staging → awaiting_owner` after the `OwnerEvent{type=join-request}` is appended and broadcast.
- `awaiting_owner → committed` on owner approval + successful 2PC (R6 phases A/B/C complete).
- Any state → `aborted` on decline, timeout, candidate disconnect, founding-side failure during prepare.
- `committed`, `aborted`, expired-`awaiting_owner` → `idle` after the replay grace window (TTL + 60 s).

Only one window may be `staging` or `awaiting_owner` at any time.

## JoinRequest (wire CBOR; never persisted on M1 outside `cached_response`)

Sent by the owner iPhone (Story 1, after QR scan) or fetched by M1 from M2's pre-household listener (Story 2).

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `m_pub` | bytes | 33 bytes |
| `hostname` | text | 1..=64 UTF-8 bytes, host label characters |
| `platform` | text | One of `macos`, `linux-nix`, `linux-other` |
| `nonce` | bytes | 32 random bytes (matches QR / Bonjour `pair_nonce` window) |
| `addr` | text | host:port hint |
| `transport` | text | `tailscale` or `lan` |
| `challenge_sig` | bytes | 64-byte raw `r || s` over canonical CBOR(`JoinChallenge`) |

Validation by M1:
- `m_pub` decodes as a valid SEC1 P-256 point.
- `nonce` decodes to exactly 32 bytes.
- `challenge_sig` verifies under `m_pub` over canonical CBOR of `JoinChallenge` reconstructed from the same fields.
- `m_pub` is not already a household member.

## JoinChallenge (signed payload, never serialized over the wire by itself)

Signed by the candidate at install time, before rendering the QR. The signature (`challenge_sig`) travels in the QR and in the eventual `JoinRequest`. No `hh_id` field — the candidate has no household identity at install time, and the binding is provided by the single-use nonce, the TTL, and the Tailscale destination.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `purpose` | text | MUST be `machine-join-request` |
| `m_pub` | bytes | 33 bytes |
| `nonce` | bytes | 32 bytes |
| `hostname` | text | 1..=64 UTF-8 bytes; identical to the `JoinRequest.hostname` and to the QR's `hostname` parameter |
| `platform` | text | One of `macos`, `linux-nix`, `linux-other`; identical to `JoinRequest.platform` |

## OwnerApproval (wire CBOR submitted by owner iPhone)

The iPhone signs over a deterministic CBOR `OwnerApprovalContext` after biometry and POSTs it to the approve endpoint (see `contracts/owner-events.md`). Decline uses the same body shape with the path-disambiguated decline endpoint (no `decision` field — the decision lives in the URL path, not the signed body).

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `cursor` | uint | The cursor of the `OwnerEvent{type=join-request}` being approved |
| `approval_sig` | bytes | 64-byte raw `r || s` over canonical CBOR(`OwnerApprovalContext`) |

`OwnerApprovalContext`:

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `purpose` | text | MUST be `owner-approve-join` |
| `hh_id` | text | MUST equal local household id (chain-validation hint) |
| `p_id` | text | MUST equal owner PersonCert's `p_id` |
| `cursor` | uint | MUST equal the path parameter `<cursor>` and `PairMachineWindow.owner_event_cursor` |
| `challenge_sig` | bytes | The candidate's 64-byte `challenge_sig` from the JoinRequest the owner is approving — provides **transitive cryptographic binding** to the exact ceremony (any tampering of `m_pub`, `nonce`, `hostname`, or `platform` would have invalidated `challenge_sig` upstream and therefore invalidates the approval) |
| `timestamp` | uint | Unix seconds; ±60 s replay window per project standard |

Validation:
- `approval_sig` verifies under owner PersonCert's `p_pub` over canonical CBOR(`OwnerApprovalContext`).
- `cursor` matches the active `PairMachineWindow.owner_event_cursor` and the path parameter.
- `challenge_sig` matches the `challenge_sig` of the JoinRequest cached in `PairMachineWindow` (server cross-checks bit-equality, not just signature validity).
- `p_id` matches local owner PersonCert's `p_id`.
- `hh_id` matches local household id.
- `timestamp` within ±60 s of server clock.

The transitive binding is the elegance: an attacker cannot replay an old `OwnerApproval` against a different candidate because the embedded `challenge_sig` would only match the original ceremony's `PairMachineWindow.cached_join_request.challenge_sig`. There is no need to additionally bind `m_pub_being_joined` because `challenge_sig` already commits to it.

## MachineCert (CBOR file `machine_certs/<m_id>.cbor` on each member)

Per protocol §5; this is the cert M1 issues for M2 (and the cert M2 persists as its own membership credential).

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `type` | text | MUST be `machine` |
| `hh_id` | text | Local household id (`hh_<base32>`) |
| `m_id` | text | Candidate's `m_<base32>` derived from `m_pub` |
| `m_pub` | bytes | 33 bytes |
| `hostname` | text | From `JoinRequest` |
| `platform` | text | From `JoinRequest` |
| `joined_at` | uint | Unix seconds at issuance |
| `issued_by` | text | `hh_id` (signed under household root) |
| `signature` | bytes | 64-byte raw `r || s` over canonical CBOR of fields above (excluding `signature`) |

Validation: signature verifies against household root pubkey from `HouseholdRecord.hh_pub`.

State transitions: `Draft → Signed` only after M1 has reconstructed `HH_priv`. `Signed → Persisted` only as part of 2PC commit on each side.

## ShamirShard (in-memory only; never serialized as plaintext on disk)

| Field | Type | Rules |
|---|---|---|
| `index` | uint | Shard index (1 or 2 in this phase) |
| `bytes` | bytes | 32 bytes — Shamir share over GF(256) of the 32-byte P-256 scalar |

Plaintext shards exist only inside `Zeroizing<>` containers in the prepare phase of the ceremony. They are encrypted into `EncryptedShard` before staging to disk and the plaintext is zeroized within ≤500 ms of leaving the in-memory path, per protocol §6.

## EncryptedShard (CBOR file `shamir/self_shard.cbor` on each member)

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `index` | uint | Shard index this file holds (1 on M1, 2 on M2) |
| `nonce` | bytes | 12 random bytes |
| `ciphertext` | bytes | ChaCha20-Poly1305 ciphertext of the 32-byte plaintext shard, AAD = `m_id` |

Encryption key derivation: `key = blake3::derive_key(context = format!("soyeht-shard-at-rest-v1 m_id={}", m_id), key_material = ECDH(M_priv, M_pub))`. The owning machine recomputes the key from its own `M_priv` at unwrap time. BLAKE3's KDF mode is the project's chosen key-derivation primitive (see research `R13`); HKDF is not used.

## HouseholdRecord (post-join, CBOR file `household_record.cbor` on each member)

The same shape as Phase 1 / Phase 2 with new field values reflecting the 2-machine state.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `hh_id` | text | Unchanged from Phase 1 |
| `hh_pub` | bytes | 33 bytes; unchanged |
| `name` | text | Unchanged |
| `created_at` | uint | Unchanged |
| `shamir_k` | uint | MUST be `2` after this ceremony commits |
| `shamir_n` | uint | MUST be `2` after this ceremony commits |
| `members` | array of text | `[m1_id, m2_id]` after commit |

## OwnerEvent (CBOR entries in `owner_events/log.cbor`, append-only)

Streamed to the owner iPhone via long-poll; persisted so reconnects can resume.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `cursor` | uint | Strictly increasing per household |
| `ts` | uint | Unix seconds at staging |
| `type` | text | `join-request`, `machine-joined`, or `join-cancelled` |
| `payload` | map | Type-specific (below) |
| `issuer_m_id` | text | `m_id` of the staging member (always M1 in this phase) |
| `signature` | bytes | 64-byte raw `r || s` by issuer's `M_priv` over canonical CBOR of all fields above except `signature` |

`payload` for `type=join-request`:

| Field | Type | Rules |
|---|---|---|
| `join_request_cbor` | bytes | The **exact** deterministic CBOR bytes of the candidate's signed `JoinRequest` — same bytes regardless of how M1 obtained them (Story 1: forwarded by iPhone after QR scan; Story 2: fetched by M1 from M2's `local/seed`). The iPhone re-decodes this to extract `m_pub`, `nonce`, `hostname`, `platform`, `addr`, `transport`, `challenge_sig`, and verifies `challenge_sig` locally over the reconstructed `JoinChallenge` before treating any field as authoritative. |
| `fingerprint` | text | 6-word BIP-39 string derived from `m_pub` by the issuer; iPhone re-derives independently and asserts equality (cross-check defense against derivation drift). |
| `expiry` | uint | Unix seconds when the join window closes; conveyed separately because it is not in the candidate-signed `JoinRequest` (the `ttl` lives in the QR query string, not in the signed CBOR). |

The iPhone's verification flow on receiving an `OwnerEvent{type=join-request}`:
1. Verify `OwnerEvent.signature` against `issuer_m_id`'s MachineCert chained to household root (proves the event is from a household member, not a long-poll spoof).
2. Decode `payload.join_request_cbor` to get the inner `JoinRequest` fields.
3. Reconstruct `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}` (deterministic CBOR).
4. Verify `JoinRequest.challenge_sig` against `m_pub` over canonical CBOR of `JoinChallenge`.
5. Re-derive the 6-word fingerprint from `m_pub` and assert equality with `payload.fingerprint`.
6. Surface `hostname`, `platform`, and `fingerprint` to the owner. On approve, embed `JoinRequest.challenge_sig` in the `OwnerApprovalContext` (transitive binding — see `OwnerApproval` schema).

Stories 1 and 2 produce **byte-identical** `payload.join_request_cbor`. The iPhone's verification path is therefore identical regardless of transport.

`payload` for `type=machine-joined`:

| Field | Type | Rules |
|---|---|---|
| `m_pub` | bytes | 33 bytes |
| `m_id` | text | `m_<base32>` |
| `hostname` | text | From JoinRequest |
| `joined_at` | uint | Unix seconds at commit |

`payload` for `type=join-cancelled`:

| Field | Type | Rules |
|---|---|---|
| `m_pub` | bytes | 33 bytes |
| `reason` | text | `declined`, `timeout`, `prepare_failed`, `candidate_unreachable`, `superseded` (the last is reserved for future races) |

The signature on every event chains via `issuer_m_id` → MachineCert → household root, so the iPhone can verify integrity end-to-end without trusting the long-poll transport.

## OwnerEventCursor (file `owner_events/cursor_head.cbor`)

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `head` | uint | Highest cursor written to the log |

Updated atomically (write-rename) after each successful append.

## OwnerDevicePushToken (file `owner_device_push_token.cbor`)

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `p_id` | text | Owner person id (must equal the local owner PersonCert's `p_id`) |
| `platform` | text | MUST be `ios` in this phase |
| `push_token` | bytes | Apple-issued device token (binary, 32 bytes typical) |
| `updated_at` | uint | Unix seconds of last write |

Replicated to M2 as part of the join ceremony's `peer_list` payload (R12). Written by `POST /api/v1/household/owner-device/push-token` (PoP-authenticated by owner PersonCert).

## JoinResponse (wire CBOR, returned to candidate on commit)

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `join_request_hash` | bytes(32) | `BLAKE3-256` of the exact deterministic-CBOR `JoinRequest` bytes M2 cached in `PairMachineWindow.cached_join_request`; M2 rejects finalize if this does not match the active window |
| `machine_cert` | MachineCert | The cert issued for the candidate |
| `encrypted_shard` | EncryptedShard | The shard for the candidate, encrypted under `ECDH(M2_priv, M1_pub)` (so M2 unwraps with its own `M_priv`) |
| `household_record` | HouseholdRecord | Post-join record (membership=2, shamir_k=2, shamir_n=2) |
| `peer_list` | array of `PeerEntry` | Members the candidate should connect to next |
| `push_token_seed` | OwnerDevicePushToken / null | Replicated registry entry; null if owner has not yet registered a token at commit time |
| `response_sig` | bytes(64) | Raw P-256 `r || s` signature by M1 over canonical CBOR(`JoinResponseUnsigned`) |

`PeerEntry`:

| Field | Type | Rules |
|---|---|---|
| `m_id` | text | Member id |
| `m_pub` | bytes | 33 bytes |
| `hostname` | text | Hostname for display |
| `tailscale_addr` | text / null | Last known Tailscale address |
| `machine_cert` | MachineCert / absent | Present for M1 in Phase 3 so M2 can persist `machine_certs/<m1_id>.cbor` during `local/finalize`; may be absent for peers whose cert is already known |

The whole `JoinResponse` is the bit-pattern returned to a duplicate `JoinRequest` within the replay grace window per FR-015 / R7.

`JoinResponseUnsigned` has the same fields except `response_sig`. M2 verifies
`response_sig` under the founder `MachineCert.m_pub` from `peer_list`, after
verifying that cert chains to `household_record.hh_pub`, before persisting any
field from the response.

## CeremonyTxn (in-memory only)

The 2PC transaction handle held by M1 during the ceremony. Not persisted, but its lifecycle is observable via `tracing` events for testability.

| Field | Type |
|---|---|
| `m_pub` | bytes |
| `nonce` | bytes |
| `hh_priv` | `Zeroizing<[u8;32]>` (in-flight only, prepare phase only) |
| `machine_cert_signed` | bytes (CBOR) |
| `shards` | `[Zeroizing<[u8;32]>; 2]` (prepare phase only) |
| `encrypted_self_shard` | `EncryptedShard` |
| `staged_household_record_path` | `PathBuf` |
| `staged_self_shard_path` | `PathBuf` |
| `m2_finalize_url` | `Url` |

Lifecycle: created in `staging`; advanced through prepare/finalize; on commit, encryption-key material and `hh_priv` are zeroized **before** the M1-side rename step (sole-shard destruction); on rollback, all `Zeroizing` containers drop and `.staged` files are unlinked.

## Anti-Phishing Fingerprint Derivation (deterministic, no on-disk artifact)

Given a candidate `m_pub` (33-byte SEC1):

1. `digest = BLAKE3-256(m_pub)`
2. Take `digest[0..9]` (72 bits) as bit-stream MSB-first.
3. Take the **first 66 bits** of the bit-stream (ignore the trailing 6 bits of byte 8).
4. Split into six 11-bit groups (MSB-first).
5. Map each 11-bit group to one BIP-39 English word (the 2048-word standard list).
6. Render as six lower-case ASCII words separated by single spaces.

Example output shape: `mango clutch piano fossil bridge zone`.

Determinism: identical bytes in → identical string out, on Mac and Linux, in Rust and Swift, across architectures.
