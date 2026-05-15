# Contract: Atomic sole-shard → Shamir(2, 2) transition

This contract specifies the byte-and-step protocol for the destructive root-key custody change that occurs the first time a household admits a second machine. It refines R6.

## Invariants

- Before the ceremony begins on M1: `household_root_sole.cbor` exists (sole-shard custody) AND `machine_certs/<m1_id>.cbor` exists (renamed in this phase from Phase 1's `machine_cert.cbor`) AND no `shamir/self_shard.cbor` exists.
- After the ceremony commits on M1: `shamir/self_shard.cbor` exists AND `household_root_sole.cbor` is deleted AND `machine_certs/<m1_id>.cbor` and `machine_certs/<m2_id>.cbor` exist AND `household_record.cbor` carries `shamir_k=2, shamir_n=2, members=[m1_id, m2_id]`.
- After the ceremony commits on M2: `shamir/self_shard.cbor` exists AND `machine_certs/<m1_id>.cbor` and `machine_certs/<m2_id>.cbor` exist AND `household_record.cbor` carries the same shape.
- Partial states (one machine has its post-commit shape, the other does not) are tolerated **only** during the in-flight window between Phase B step 11 and Phase C step 12; recovery on M1 boot reconciles to a fully-committed or fully-aborted state.

## Step list (M1 perspective)

1. Verify `OwnerApproval`; transition `PairMachineWindow.state` from `awaiting_owner` to internal `prepare`.
2. Reconstruct `HH_priv` from sole-shard custody into `Zeroizing<[u8;32]>`. (On macOS this is an SE-mediated extraction-by-handover-prep; the SE-resident scalar is read-protected and a fresh in-software scalar is bound to the same `HH_pub`. On Linux this is a kernel keyring read.)
3. Sign `MachineCert` for M2 with `HH_priv` over canonical CBOR.
4. Use `vsss-rs` to split `HH_priv` into Shamir shares with `(k=2, n=2)` over GF(256). Save shares as `[Zeroizing<[u8;32]>; 2]`.
5. Encrypt M1's share into `EncryptedShard_for_M1` using `key = blake3::derive_key(context = format!("soyeht-shard-at-rest-v1 m_id={}", m1_id), key_material = ECDH(M1_priv, M1_pub))` + ChaCha20-Poly1305(nonce=12-byte-random, AAD=m1_id).
6. Encrypt M2's share into `EncryptedShard_for_M2` using `key = blake3::derive_key(context = format!("soyeht-shard-at-rest-v1 m_id={}", m2_id), key_material = ECDH(M1_priv, M2_pub))` + ChaCha20-Poly1305(nonce=12-byte-random, AAD=m2_id). The wire-format encrypted shard is asymmetric: M1 encrypts using its own `M1_priv` and M2's `M2_pub` so that M2 can recompute the same key with `ECDH(M2_priv, M1_pub)` and unwrap. M2 then re-wraps under its own at-rest key (R13) before persisting.
7. Build `JoinResponseUnsigned{join_request_hash=BLAKE3-256(cached JoinRequest CBOR), machine_cert, encrypted_shard=EncryptedShard_for_M2, household_record_post_join, peer_list, push_token_seed}` and sign its canonical CBOR with M1's `M_priv`, yielding `JoinResponse{..., response_sig}`.
8. Atomically write `household_record.cbor.staged` and `shamir/self_shard.cbor.staged` (containing `EncryptedShard_for_M1`) and fsync both.
9. Zeroize `HH_priv`. Zeroize the plaintext shards. Zeroize the wire-format `EncryptedShard_for_M2` plaintext fields.
10. Atomically write `phase3_finalize_ack.marker` as a finalize-intent pin before sending the first finalize POST. With a pre-Shamir record this marker means "do not roll back `.staged` blindly; recovery must probe M2".
11. POST `JoinResponse` (canonical CBOR) to `http://<m2_addr>:<port>/pair-machine/local/finalize` (HTTP not HTTPS — M2's pre-household listener has no household-issued cert; the underlay is Tailscale WireGuard or LAN, the response body is bound by `response_sig`, and the only confidential payload is the AEAD-encrypted shard, so TLS adds no security here).
12. Receive `FinalizeAck{m_id, machine_cert_hash}` with `200 OK`. Verify `m_id` matches the issued cert's `m_id`, and `machine_cert_hash == BLAKE3-256(canonical CBOR of MachineCert)`. If M2 returns a definitive non-2xx response, clear the marker and roll back. If the POST may have reached M2 but M1 cannot validate the ack (transport/read/decode/hash error), preserve the marker and `.staged` files and return the contracted `500 {v=1, error="internal"}` so boot recovery can reconcile.
13. Atomically rename `household_record.cbor.staged` → `household_record.cbor` and `shamir/self_shard.cbor.staged` → `shamir/self_shard.cbor`. Persist `machine_certs/<m2_id>.cbor` (already-signed bytes from step 3). fsync the directory.
14. Delete `household_root_sole.cbor`. fsync.
15. Append `OwnerEvent{type=machine-joined, payload=...}` to the owner-events log.
16. Set `PairMachineWindow.state = committed`. Cache `JoinResponse` for the replay window.
17. Clear `phase3_finalize_ack.marker`; if this clear fails, boot recovery removes the stale marker after observing the post-Shamir record.

## Step list (M2 perspective, inside `local/finalize`)

A. Verify `JoinResponse` per `contracts/machine-cert-cbor.md` validation rules, verify M1's `response_sig` over canonical CBOR(`JoinResponseUnsigned`) under the verified founder cert from `peer_list`, and verify `join_request_hash` matches the active `PairMachineWindow.cached_join_request`.
B. Decrypt `encrypted_shard` using `key = blake3::derive_key(context = format!("soyeht-shard-at-rest-v1 m_id={}", m2_id), key_material = ECDH(M2_priv, M1_pub))` + ChaCha20-Poly1305(AAD=m2_id). Get `Zeroizing<[u8;32]>` plaintext shard.
C. Re-wrap the plaintext shard under M2's at-rest key per R13. Atomically write `shamir/self_shard.cbor`. Atomically write `machine_certs/<m1_id>.cbor` (from `JoinResponse.peer_list`'s embedded MachineCert if provided; in Phase 3 we include M1's existing self-cert in `peer_list`'s `PeerEntry`). Atomically write `machine_certs/<m2_id>.cbor`. Atomically write `self_m_id` with M2's id. Atomically write `household_record.cbor`. fsync.
D. Set `PairMachineWindow.state = committed`. Persist `pair_machine_window.cbor`.
E. Reply `200 OK` with `FinalizeAck{m_id=m2_id, machine_cert_hash=BLAKE3-256(canonical CBOR of MachineCert for M2)}`.

## Rollback

- On any failure during steps 2–10 on M1 before the finalize POST is launched: delete `.staged` files; clear any marker written in step 10; zeroize all `Zeroizing` material; reset `PairMachineWindow.state = aborted`; append `OwnerEvent{type=join-cancelled, reason=...}`.
- On a definitive M2 reject after step 11 (for example, M2 returns the generic non-2xx finalize response before any valid ack): clear the marker, delete `.staged` files, reset `PairMachineWindow.state = aborted`, and append `OwnerEvent{type=join-cancelled, reason=...}`.
- On an ambiguous failure after step 11 (transport error, read error, invalid/missing `FinalizeAck`, or task failure where M1 cannot prove whether M2 committed): leave `phase3_finalize_ack.marker` and M1's `.staged` files on disk, do not append `join-cancelled`, and return `500 {v=1, error="internal"}`. Boot recovery owns the final roll-forward/rollback decision.

## Recovery on M1 boot

If M1 boots and finds `phase3_finalize_ack.marker` with a pre-Shamir `household_record.cbor`, plus `household_record.cbor.staged` and `shamir/self_shard.cbor.staged` while `household_root_sole.cbor` still exists:

1. Read the staged record; identify the candidate `m2_id`, `m_pub`, and the `addr` from the cached `JoinRequest`.
2. **Two-state probe** (because M2's pre-household listener is shut down once M2 commits and is replaced by the household listener):
   - **Pre-commit probe**: `GET http://<m2_addr>/pair-machine/local/seed?nonce=<short>` (HTTP — pre-household listener, see step 10 rationale). A `200 OK` carrying a `JoinRequest` with the same `m_pub` indicates "M2 has not yet committed"; M1 retries `local/finalize` with the staged `JoinResponse` (idempotent on M2's side) and proceeds to step 12 once an ack arrives.
   - **Post-commit probe**: if pre-commit returns `404` / connection-refused, fall back to `GET <m2_addr>/api/v1/household/identity` over the household transport (HTTPS over Tailscale once M2 is committed, since M2 now has a household-issued cert). A `200 OK` carrying the same `hh_id` and `hh_pub` as M1's staged `household_record.cbor.staged` indicates "M2 has committed"; M1 finishes step 12 (rename), step 13 (delete sole-shard), and step 14 (append `machine-joined` event).
   - **Both probes fail**: M2 is unreachable. M1 retries the two-state probe periodically until `RECOVERY_TIMEOUT` (default 5 minutes, see `pair_machine::RECOVERY_TIMEOUT`).
3. Past `RECOVERY_TIMEOUT`: M1 deletes `.staged` files and treats the ceremony as rolled back. Per `FR-013a`, any `MachineCert` M2 may have persisted before becoming permanently unreachable is treated as orphan; if M2 ever returns it MUST re-do the ceremony from scratch and obtain a fresh `MachineCert`.

Recovery is idempotent on every step: re-running it after partial completion converges to the same fully-committed or fully-rolled-back state.

## Failure-injection test plan

- Crash M1 between step 8 and step 10 → boot recovery deletes staged files; sole-shard intact; M2 was never written.
- Crash M1 between step 10 and step 11 (M2 has finalized; M1 has not committed) → boot recovery reaches M2, observes `committed`, finishes step 12+; M2 is unchanged.
- Crash M1 between step 11 and step 12 (ack received but rename not yet done) → boot recovery same as above.
- Crash M2 during step C (mid-write): M2 retries on next boot from its still-valid `pair_machine_window.cbor.staging`; M1's retry ensures progress.
- Network partition between step 10 and step 11: M1 retries; on permanent partition past the recovery window, M1 rolls back; on M2 side, the `local/finalize` was idempotent and either fully wrote or did not write.

These tests live in `e2e-rs/tests/phase3_atomic_rollback.rs`.
