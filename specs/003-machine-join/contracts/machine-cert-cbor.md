# Contract: MachineCert CBOR

Per protocol §5; this Phase 3 cert is signed by the household root and attests that a candidate machine is a member of the household.

## Canonical CBOR shape

Map keys are sorted lex; integers shortest-form per RFC 8949 §4.2.1.

```cbor
MachineCert = {
  "v": 1,
  "type": "machine",
  "hh_id": text,        // hh_<base32>
  "m_id": text,         // m_<base32>
  "m_pub": bytes,       // 33-byte SEC1
  "hostname": text,     // 1..=64 UTF-8 bytes
  "platform": text,     // "macos" | "linux-nix" | "linux-other"
  "joined_at": uint,    // unix seconds
  "issued_by": text,    // hh_id (always — only household root attests machines)
  "signature": bytes    // 64-byte raw r||s P-256 over canonical CBOR of fields above (excluding "signature")
}
```

## Issuance preconditions

- `PairMachineWindow.state == awaiting_owner` and a verified `OwnerApproval` for the matching `cursor` and `m_pub_being_joined` has just been received.
- M1's local `HouseholdRecord` self-validates against household root pubkey.
- `m_pub` is not already a household member.

## Signing

`HH_priv` is reconstructed in-memory from sole-shard custody (Phase 3 first time) or from Shamir threshold (Phase 4+). The signature is computed via `p256` on Linux or via the SE on macOS; in both cases the output is 64-byte raw `r || s`. `HH_priv` is zeroized within ≤500 ms of signing completion.

## Validation by candidate (M2)

Performed inside `POST /pair-machine/local/finalize`:
1. Decode CBOR (deterministic — re-encode and check bytes match).
2. Recompute `m_id = "m_" + base32_lower_no_pad(BLAKE3-256(m_pub))` and assert equals the cert's `m_id`.
3. Verify `signature` against the `hh_pub` already pinned in `PairMachineWindow` by `LocalAnchor`, not against a trust root learned only from `JoinResponse`.
4. Assert the pinned `hh_pub` and `hh_id` equal `JoinResponse.household_record.{hh_pub, hh_id}`.
5. Assert `m_pub` equals M2's own machine public key.

## Storage

Each member persists every MachineCert it knows under `machine_certs/<m_id>.cbor`. **There is exactly one canonical path** — `machine_certs/<m_id>.cbor` — for every cert the household has ever issued, including the founding machine's self-cert. Phase 1's `machine_cert.cbor` (a single-file path that held only the self-cert) is **renamed in this phase** to `machine_certs/<m1_id>.cbor`, in the same Adoption-First sweep as the `pair_window.cbor` → `pair_device_window.cbor` rename. There is no parallel old/new layout; the migration is one-shot and idempotent on subsequent boots.

After Phase 3 commit, M1 has two such files (`machine_certs/<m1_id>.cbor` from the rename + `machine_certs/<m2_id>.cbor` issued in this phase), and M2 has the same two.

## Phase 3 vs later phases

Phase 3 admits exactly one new MachineCert (M2's). Phase 4+ replicates new MachineCerts via gossip; the cert shape is identical.
