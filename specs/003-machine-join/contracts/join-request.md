# Contract: `POST /api/v1/household/join-request` and candidate's pre-household listener

## Endpoint on M1

`POST /api/v1/household/join-request`

### Request

**Story 1 (remote QR)**: the owner iPhone POSTs the signed `JoinRequest` reconstructed from the scanned QR (per `contracts/pair-machine-url.md`). The request is authenticated by Soyeht-PoP from the owner PersonCert — that is, the iPhone's outer Soyeht-PoP signature proves owner authority, and the inner `JoinRequest.challenge_sig` proves the candidate's possession of `M_priv`. M1 verifies both: the outer PoP gates "is this an authorized owner asking us to admit a candidate", the inner challenge gates "did the candidate actually sign this binding".

**Story 2 (LAN)**: M1's own internal Bonjour browser fetches the same signed `JoinRequest` from M2's pre-household `local/seed` endpoint and stages it through the same handler path used by Story 1, sharing the implementation via a private helper `founder_stage_join_request`. The Story 2 entry does not transit a Soyeht-PoP-authenticated request — it is an in-process function call — but the staging only advances to `awaiting_owner` when an `OwnerEvent{type=join-request}` is appended; the owner's biometric approval is still the only condition that issues a MachineCert (FR-018).

- Content-Type: `application/cbor`
- Body: deterministic CBOR `JoinRequest` per `data-model.md`.

### Response

- `201 Created` with `Content-Type: application/cbor` and body deterministic CBOR `JoinRequestAccepted = {v=1, owner_event_cursor: uint, expiry: uint}`. `owner_event_cursor` is the cursor of the staged `OwnerEvent{type=join-request}` so the iPhone's next long-poll `since=` correctly catches it.
- `401 Unauthorized` with `Content-Type: application/cbor` and body deterministic CBOR `{v=1, error="unauthenticated"}` for any failure (no oracle, R14, FR-019a).

### State effects

On success: `PairMachineWindow` transitions `idle → staging → awaiting_owner`; one `OwnerEvent{type=join-request}` is appended; the long-poll broadcaster is notified.

### Idempotency

A second request with the same `m_pub`/`nonce` while the window is `awaiting_owner` returns `201` with the same `owner_event_cursor` (no new event is appended, the previous one is still pending).

A second request after a successful commit, within the replay grace window, returns the cached `JoinResponse` directly with `200 OK` and `Content-Type: application/cbor` (R7). After the replay grace window: `401`.

## Endpoint on M2 (pre-household listener)

The candidate's listener exists before M2 is a household member. It accepts only two routes and refuses everything else with `401`.

### `GET /pair-machine/local/seed?nonce=<base32_short>`

- Used by M1 in Story 2 to fetch the signed `JoinRequest` after detecting the candidate on Bonjour.
- Required guards:
  - Local `PairMachineWindow.state == awaiting_owner_or_staging` (M2 has just opened a window).
  - Supplied short-nonce equals first 8 bytes of `PairMachineWindow.nonce`, base32-encoded.
  - Source IP is on a household-routable network (any interface; the listener does not pre-trust IPs).
- Response: `200 OK`, `Content-Type: application/cbor`, body = signed `JoinRequest` CBOR.
- Failure: `401`, generic body.

### `POST /pair-machine/local/finalize`

- Used by M1 in 2PC step 11 (R6 phase B).
- Body: deterministic CBOR `JoinResponse` per `data-model.md`.
- Required guards:
  - Local `PairMachineWindow.state == awaiting_owner_or_staging` (still active).
  - **Anchor pin established (R5/B7)**: M2's `PairMachineWindow.pinned_hh_pub` and `pinned_hh_id` MUST be present (set by an earlier `POST /pair-machine/local/anchor` from the owner iPhone) AND MUST match `JoinResponse.household_record.{hh_id, hh_pub}`. The household root used for cert-chain verification below is the **pinned** value, not the value read out of `JoinResponse.household_record.hh_pub` — a stolen `JoinResponse` carrying an attacker-issued cert under an attacker-rooted `household_record` would otherwise verify under itself and pass.
  - `JoinResponse.join_request_hash == BLAKE3-256(PairMachineWindow.cached_join_request)`, binding the finalize body to the current nonce/challenge and rejecting stale responses for a reused candidate key.
  - M1's `response_sig` verifies over canonical CBOR(`JoinResponseUnsigned`) under the founder `MachineCert.m_pub` embedded in `peer_list`, after that founder cert verifies against the **pinned** `hh_pub`.
  - `JoinResponse.machine_cert.signature` verifies under the **pinned** `hh_pub`.
  - `JoinResponse.encrypted_shard` decrypts under M2's `ECDH(M2_priv, M1_pub)` and yields a 32-byte shard.
  - Reconstructing the household scalar from the candidate's just-received shard and a cooperatively-supplied second shard from M1 is **not** required at finalize-time — verifying the cert signature is sufficient. Reconstruction tests run later in any case.
- M2 atomically writes `machine_certs/<m1_id>.cbor` (from `peer_list`'s embedded M1 self-cert), `machine_certs/<m2_id>.cbor` (the just-issued cert), `self_m_id` (set to M2's `m_id`), `shamir/self_shard.cbor` (with `EncryptedShard` re-encrypted under M2's own per-machine key derivation per R13 — the wire-format `encrypted_shard` from M1 is unwrapped and re-wrapped, so the at-rest file is keyed to M2's machine identity), `household_record.cbor`, and `pair_machine_window.cbor` set to `committed`. **No `machine_cert.cbor` self-cert file at the state-dir root** — every cert lives in the unified `machine_certs/` directory.
- Response: `200 OK`, `Content-Type: application/cbor`, body = `FinalizeAck = {v=1, m_id: text, machine_cert_hash: bytes(32)}` where `machine_cert_hash = BLAKE3-256(canonical CBOR of MachineCert)`.
- Idempotency: a second `finalize` with the same MachineCert bytes returns the same `FinalizeAck`. A finalize with different bytes after one already committed: `401`.

The pre-household listener is shut down on the same machine after `pair_machine_window.cbor.state == committed` and the owner-events / household-listener stack starts up under the new household identity.
