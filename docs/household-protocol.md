# Household Protocol Specification

**Status:** Draft v0.2 (2026-05-06; replaces Ed25519/X25519 with EC P-256 ECDSA/ECDH for Secure Enclave compatibility — see Constitution v2.0.0 amendment)
**Scope:** Cross-repo contract for `theyos` (Rust backend) and `iSoyehtTerm` (Swift apps)
**Audience:** Implementers of theyOS or any client speaking the household protocol

---

## 1. Overview

A **Household** is a set of theyOS machines and people that share a single cryptographic identity. The household is the unit of trust, ownership, and access control — not the individual machine.

This document defines the protocol that lets:
- Multiple theyOS machines form one household
- People be invited once and granted granular capabilities valid across the whole household
- State (membership, capabilities, revocations) replicate peer-to-peer with no central server
- All identity material remain local-first (no cloud control plane)

### Design principles

1. **No SPOF** — every member machine is equal; the household identity survives loss of any single machine.
2. **Capability-based, not role-based** — permissions are signed certificates with explicit caveats, not roles in a database.
3. **Local-first** — discovery via Bonjour/mDNS on LAN, Tailscale on WAN; no cloud service required.
4. **Cryptographic over consensual** — every state mutation traces back to a signed event whose signature chains to the household root.
5. **Apple-grade UX** — automatic discovery, automatic failover, no manual operator commands.

### Non-goals (v0.1)

- Public-key directory shared across households (cross-household sharing of Claws is future work).
- Strong eventual consistency under network partitions longer than 24h.
- Claw migration between machines on host outage.

---

## 2. Core concepts

| Concept | Identity | Held where |
|---|---|---|
| **Household** | EC P-256 keypair (root) | Private scalar Shamir-sharded across member machines; on the founding Mac the unsharded scalar is created inside the Secure Enclave (`kSecAttrTokenIDSecureEnclave`). Public key (33-byte SEC1) is the household identifier. |
| **Machine** | EC P-256 keypair (per machine) | Private scalar in Secure Enclave on macOS (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`); on Linux in kernel keyring or Secret Service |
| **Person** | EC P-256 keypair (per human) | Private scalar in the owner Device's Secure Enclave; biometry-gated for signing operations |
| **Device** | EC P-256 keypair (per device of a person) | Private scalar in Device's Secure Enclave (iOS) or Mac SE (macOS) |
| **Capability Cert** | CBOR document | Signed by household or person; held by subject |
| **Event** | CBOR document | Signed by issuer; replicated via gossip |

### Identifiers

All identifiers are URL-safe base32 of BLAKE3-256 of the public key, prefixed:

- `hh_<32 chars>` — household
- `m_<32 chars>` — machine
- `p_<32 chars>` — person
- `d_<32 chars>` — device
- `c_<32 chars>` — claw (existing model, gains household scope)

Identifiers are **stable**: a person's `p_*` never changes even when they add devices or rotate device keys.

---

## 3. Cryptographic primitives

| Use | Primitive | Rust | Swift |
|---|---|---|---|
| Signing | **EC P-256 ECDSA**, raw `r \|\| s` 64 bytes | `p256` (cross-platform), `security-framework` (macOS SE-backed path) | `CryptoKit.P256.Signing` (host-managed) + `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` (SE-backed identity keys) |
| Key agreement | **EC P-256 ECDH** | `p256::ecdh`, `security-framework` for SE | `CryptoKit.P256.KeyAgreement` + SE-backed via `SecKey` |
| Hashing | BLAKE3-256 (SHA-256 fallback for v0.1 only when BLAKE3 unavailable) | `blake3` | `swift-crypto` BLAKE3 port if available; SHA-256 via `CryptoKit.SHA256` as v0.1 fallback |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | `CryptoKit.ChaChaPoly` |
| Secret sharing | Shamir GF(256) k-of-n applied to the 32-byte P-256 private scalar | `vsss-rs` | Custom impl (~200 LoC) |
| Serialization | CBOR (deterministic, RFC 8949 §4.2.1) | `ciborium` | `SwiftCBOR` (or hand-rolled deterministic encoder) |

**Encoding contract:**
- **Public keys**: 33-byte SEC1 compressed form (`02`/`03` prefix + 32-byte X coordinate). Wherever this spec writes `*_pub` as `bytes`, it means 33-byte SEC1.
- **Signatures**: 64-byte raw `r || s` (NOT DER-encoded). This matches Apple's `CryptoKit.P256.Signing.ECDSASignature.rawRepresentation`.
- **Identifiers**: still BLAKE3-256 of the SEC1 public key, base32-lowercase no-pad, prefixed.

**Decision rationale:** EC P-256 is the only signing primitive Apple's Secure Enclave supports natively. Identity-bearing keys (`HH_priv`, `M_priv` on Mac, `P_priv`, `D_priv`) created with `kSecAttrTokenIDSecureEnclave` never expose the private scalar to software memory; signing happens inside the chip. This is the property required by user stories 1, 8, 10, 11 (biometric-gated hardware-enforced signing). On non-Apple targets the `p256` crate provides software-side parity. No FFI bridge between Rust and Swift is needed for the wire format — the same SEC1+raw-`r||s` shape interoperates.

### Hash convention

When the spec says "hash X", it means `BLAKE3-256(X)` truncated to 32 bytes, encoded URL-safe base32 (lowercase, no padding). For v0.1, SHA-256 is acceptable as a temporary substitute when BLAKE3 is unavailable (must be agreed by both sides — protocol version field signals which).

### Canonical encoding

All CBOR encoding MUST be deterministic per RFC 8949 §4.2.1 (sorted map keys, definite-length, shortest integers). Signatures are computed over the canonical CBOR bytes.

---

## 4. Household identity

### Bootstrap

When `theyos` is installed for the first time on a machine and the user creates a new household:

1. Generate EC P-256 keypair `(HH_priv, HH_pub)`. On macOS, MUST be created with `SecKeyCreateRandomKey` and attribute `kSecAttrTokenIDSecureEnclave` so the private scalar lives in the Secure Enclave from birth. Compute `hh_id = hash(HH_pub)` where `HH_pub` is the 33-byte SEC1 form.
2. Generate machine keypair `(M_priv, M_pub)` with the same SE residency rule. Compute `m_id = hash(M_pub)`.
3. Issue a self-signed **MachineCert** for this machine, attesting it as a member. The signature is produced by SE-mediated `SecKeyCreateSignature` (Mac) or by the `p256` crate (Linux).
4. Persist `HH_pub`, `M_pub`, `MachineCert` as CBOR on disk; persist `M_priv` and `HH_priv` references in the OS keystore.
5. Sole-shard mode: the SE itself is the "shard" while only one machine exists. There is no exportable plaintext copy of `HH_priv` on disk; reconstruction means asking the SE to sign or to derive (no unwrap to RAM).

Sole-shard mode is permitted only while the household has 1 machine. Adding the second machine triggers Shamir splitting (see §6).

### Household record

Every machine stores:

```cbor
HouseholdRecord = {
  "v": 1,
  "hh_id": bytes,
  "hh_pub": bytes,      // 33 bytes (SEC1 compressed P-256)
  "name": text,         // human-friendly, e.g. "Sample Home"
  "created_at": int,    // unix seconds
  "shamir_k": uint,     // threshold (e.g. 2)
  "shamir_n": uint,     // total shards (e.g. 3)
  "members": [m_id...], // current machines (cached; canonical source = events log)
}
```

The version key is `"v"` (not `"version"`) for parity with `MachineCert` (§5) and to keep the on-wire CBOR map keys short.

---

## 5. Machine membership

### MachineCert

A MachineCert attests that a machine belongs to a household.

```cbor
MachineCert = {
  "v": 1,
  "type": "machine",
  "hh_id": text,            // hh_<base32>
  "m_id": text,             // m_<base32>
  "m_pub": bytes,
  "hostname": text,
  "platform": "macos" | "linux-nix" | "linux-other",
  "joined_at": int,
  "issued_by": text,         // hh_id as SubjectId::Household (always — only household root can attest machines)
  "signature": bytes,        // 64-byte raw P-256 ECDSA `r || s` over canonical CBOR of fields above (excluding "signature")
}
```

A machine is "in" the household iff it has a valid `MachineCert` whose `issued_by` chains to the household root and which is not present in the CRL (§9).

### Joining ceremony (Phase 3)

For Phase 3 (single-machine → 2-machine join), the wire shapes, URI, REST endpoint, and Bonjour vocabulary live in §11 (`soyeht://household/pair-machine` URI), §12 (`POST /api/v1/household/join-request` + `local/seed` / `local/finalize` candidate-side routes + the owner-events long-poll for biometric confirmation), and §13 (Bonjour TXT records `pairing=machine`, `pair_role=founder|joiner`, `m_pub_b32`, `pair_nonce`). The summary below is a narrative overview only — the canonical wire formats are §11/§12/§13.

```
M2 (joining, pre-household)               M1 (existing member)
  |                                            |
  | install theyOS, gen keypair                |
  | sign JoinChallenge over (v, purpose,       |
  |   m_pub, nonce, hostname, platform)        |
  | start bounded local listener for           |
  |   /pair-machine/local/seed                 |
  |   /pair-machine/local/finalize             |
  | publish Bonjour: pairing=machine,          |
  |   pair_role=joiner, m_pub_b32, pair_nonce  |
  | render fingerprint (six BIP-39 words) on   |
  |   installer console + render QR (Story 1)  |
  |                                            |
  |   --- Story 1: owner iPhone scans QR ---   |
  |                  (skip to "M1 receives JoinRequest")
  |                                            |
  |   --- Story 2: M1 detects Bonjour ---      |
  |                                            |
  |                            <----- M1 sees pairing=machine + pair_role=joiner
  |                                   matching its open PairMachineWindow
  |                            ----- GET http://<addr>:<port>/pair-machine/local/seed?nonce=<short>
  | -- responds: signed JoinRequest CBOR --->  |
  |                                            |
  |   --- both stories converge here ---       |
  |                                            | M1 verifies challenge_sig over JoinChallenge
  |                                            | M1 stages PairMachineWindow=Staging
  |                                            | M1 appends OwnerEvent{type=join-request}
  |                                            |   signed by M1's M_priv
  |                                            | (broadcaster wakes long-poll OR APNS tickle)
  |                                            |
  |                                            | owner iPhone displays fingerprint + hostname,
  |                                            | requires biometric, POSTs approve/decline
  |                                            |
  |                                            | on approve: CeremonyTxn::prepare runs:
  |                                            |   - issue MachineCert for M2
  |                                            |   - split HH_priv into 2-of-2 Shamir shards
  |                                            |   - encrypt M1's shard at-rest (BLAKE3 KDF + ChaCha20-Poly1305)
  |                                            |   - encrypt M2's shard for ECDH peer delivery
  |                                            |   - stage cert + self_shard + new HouseholdRecord(k=n=2,members=[m1,m2])
  |                                            |     (record-rename is the canonical commit marker, promoted LAST)
  |                                            |   - hh_priv + m1_priv_scalar drop here
  |                                            |
  | <----- POST /pair-machine/local/finalize { MachineCert, m2_shamir_shard, peer_list, household_record }
  |                                            |
  | M2 verifies cert against pinned hh_pub     |
  |  (from earlier LocalAnchor — NOT response),|
  | persists cert + shard,                     |
  | ACKs with BLAKE3-256(canonical(MachineCert))
  |                                            |
  |                                            | CeremonyTxn::commit:
  |                                            |   - promote staged files (cert, record, self_shard)
  |                                            |   - delete household_root_sole.cbor (LAST step)
  |                                            | append OwnerEvent{type=machine-joined}
  |                                            | window → Committed
```

The 1-machine state (sole shard `household_root_sole.cbor`) is **destructively** converted: after commit, the only on-disk material is the encrypted Shamir self-shard. If a crash leaves both files alive, `recover_post_join_sole_shard` (boot recovery in `load_state_dir`) deletes the sole file as a security cleanup.

### Joining endpoint contract

The HTTP boundary collapses every owner-side / candidate-side authentication failure to deterministic CBOR `401 {"v":1,"error":"unauthenticated"}` (R14). There is no 202/409 surface — the candidate's view is binary "did the response carry a `MachineCert` or not". Internal `tracing` events distinguish reasons; the wire response does not.

See §12 for the full table.

---

## 6. Household private key custody (Shamir)

The household root private key `HH_priv` is **never stored intact** on any single machine after the second machine joins.

### Splitting

Using Shamir Secret Sharing over GF(256), applied to the 32-byte P-256 private scalar:

- `n` = number of member machines
- `k` = `floor(n/2) + 1` (default), MINIMUM 2 even when n=2
- Each machine stores its shard encrypted under its own machine key (P-256 ECDH to derive an AEAD key, then ChaCha20-Poly1305).

**SE caveat for the founding Mac:** the founding household scalar is created inside the SE (`kSecAttrTokenIDSecureEnclave`), which means the SE — not the host process — holds the only copy. To Shamir-split, the founding theyOS performs an SE-mediated re-issuance: it generates a new P-256 keypair outside the SE (in `p256` crate memory), Shamir-splits that scalar across machines, then has the SE-resident identity sign a record promotion event proving the scalar handover. The original SE-resident scalar is then destroyed. From then on, identity reconstruction follows the standard Shamir threshold flow (`HH_priv` materializes briefly in RAM; zeroized within ≤500ms).

Shamir parameters are recorded in `HouseholdRecord`. When membership changes, shards are re-issued (proactive secret sharing).

### Reconstruction

`HH_priv` is reconstructed in-memory only when:
1. Issuing a new MachineCert (joining ceremony)
2. Issuing a top-level revocation that requires household signature
3. Initial root operations during bootstrap

Reconstruction requires `k` machines online and reachable. After reconstruction, `HH_priv` is zeroed within ≤500ms of operation completion (programmatic guarantee, not best-effort).

### Loss recovery

- Loss of `< n - k` machines: no impact, household survives.
- Loss of `≥ n - k + 1` machines simultaneously: household is unrecoverable. Documented limitation; recommend `n ≥ 3` in product UX.

### Edge case: single-machine household

When only 1 machine exists, `HH_priv` lives inside the founding machine's Secure Enclave (Mac) or the kernel keyring (Linux). There is no exportable plaintext copy on disk. Adding the 2nd machine MUST trigger the SE-handover-to-Shamir-split flow described above before the join ceremony completes.

For Phase 3's concrete 1→2 transition, the byte-level commit, rollback, and
boot-recovery steps are specified by
`specs/003-machine-join/contracts/shamir-transition.md`. That contract is the
authority for the `household_root_sole.cbor` → `shamir/self_shard.cbor`
destructive handoff and for the `JoinResponse` / `FinalizeAck` 2PC boundary.

---

## 7. Subjects (people and their devices)

### Person identity

A person is created when invited to a household. Their identity is generated client-side on their first device:

1. App calls `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` to mint `(P_priv, P_pub)` directly inside the SE (P-256). Computes `p_id`.
2. The P-256 SE key is configured with `kSecAccessControlBiometryCurrentSet` so `SecKeyCreateSignature` (used at PoP time) prompts for Face ID / Touch ID.
3. App accepts the household's invitation, receives signed PersonCert.

### PersonCert (capability cert)

```cbor
PersonCert = {
  "v": 1,
  "type": "person",
  "hh_id": text,             // hh_<base32>
  "p_id": text,              // p_<base32>
  "p_pub": bytes,
  "display_name": text,
  "caveats": [Caveat],
  "not_before": int,
  "not_after": int | null,    // null = no expiry
  "nonce": bytes (16),
  "issued_at": int,
  "issued_by": text,          // hh_id as SubjectId::Household
  "signature": bytes,
}
```

### Caveat grammar

A caveat is a CBOR object expressing one constraint. Caveats are **conjunctive** — all must be satisfied for an action to be allowed.

```cbor
Caveat = {
  "op": text,              // operation namespace (see table)
  "scope": Scope | null,   // null = all
  "constraints": map | null,
}

Scope = {"all": true} | {"owned_by_self": true} | {"specific": [c_id...]}
```

### Operation namespace (v0.1)

| op | scope | meaning |
|---|---|---|
| `claws.list` | scope determines which claws are visible | read-only enumeration |
| `claws.create` | always `all` (per-machine restriction is `constraints.machines`) | create a new Claw |
| `claws.delete` | `owned_by_self` or `specific` | delete a Claw |
| `claws.use` | `owned_by_self` or `specific` | open terminal / interact |
| `claws.assign` | `owned_by_self` | change owner of a Claw |
| `household.invite` | n/a | invite a new person |
| `household.revoke` | n/a | revoke a person or device |
| `household.add_machine` | n/a | attest a new machine |

Constraints (optional):
- `machines: [m_id...]` — restrict the op to specific machines (HONORED in v0.1)
- `expires_at: int` — caveat-level expiry overriding `not_after`

**Per-machine evaluation rule:** when a request is dispatched to machine `m_id` and a caveat carries `constraints.machines`, the operation is permitted only if `m_id ∈ constraints.machines`. Absence of the constraint means "all household machines".

### Persona examples

**Owner (owner)** — full caveats:
```cbor
caveats: [
  { op: "claws.list", scope: { all: true } },
  { op: "claws.create", scope: { all: true } },
  { op: "claws.delete", scope: { all: true } },
  { op: "claws.use", scope: { all: true } },
  { op: "claws.assign", scope: { all: true } },
  { op: "household.invite", scope: null },
  { op: "household.revoke", scope: null },
  { op: "household.add_machine", scope: null },
]
```

**Pai (power user)**:
```cbor
caveats: [
  { op: "claws.list", scope: { owned_by_self: true } },
  { op: "claws.create", scope: { all: true } },
  { op: "claws.delete", scope: { owned_by_self: true } },
  { op: "claws.use", scope: { owned_by_self: true } },
]
```

**Pai restricted to one machine** (per-machine granularity example):
```cbor
caveats: [
  { op: "claws.list", scope: { owned_by_self: true } },
  { op: "claws.create", scope: { all: true }, constraints: { machines: [m_linux_mini] } },
  { op: "claws.delete", scope: { owned_by_self: true } },
  { op: "claws.use", scope: { owned_by_self: true } },
]
```
Pai may create Claws only on the Linux Mini, but may use any Claw he owns regardless of host.

**Esposa (limited use, can't create)**:
```cbor
caveats: [
  { op: "claws.list", scope: { owned_by_self: true } },
  { op: "claws.use", scope: { owned_by_self: true } },
]
```

**Mãe (single Claw)**:
```cbor
caveats: [
  { op: "claws.use", scope: { specific: [c_xxxxx] } },
]
```

The app inspects the local PersonCert to render UI: hide buttons for ops with no caveat. **No 403 round-trips for permission errors.**

---

## 8. Devices (per-person endpoints)

A person may hold their `P_priv` on multiple devices via DeviceCert chain. The first device holds `P_priv` directly; subsequent devices hold a derived `D_priv` certified by the first device.

### DeviceCert (v0.1: REQUIRED)

```cbor
DeviceCert = {
  "v": 1,
  "type": "device",
  "p_id": text,              // p_<base32>
  "d_id": text,              // d_<base32>
  "d_pub": bytes,
  "device_name": text,        // "iPhone 15", "iPad Pro", etc.
  "platform": text,
  "added_at": int,
  "issued_by": text,          // p_id as SubjectId::Person (delegation from person)
  "signature": bytes,         // by P_priv on first device
  "caveats": [Caveat] | null, // attenuation only — never expand
}
```

**Attenuation rule:** caveats on a DeviceCert may only be a subset (or stricter constraints) of the parent PersonCert. Implementation MUST validate this on cert presentation.

**v0.1 behavior:** A person's first device holds `P_priv` directly. Adding a 2nd, 3rd, … device of their own triggers `pair-device` ceremony (§11) — first device signs a DeviceCert binding the new device's `D_pub` to the same `p_id`. Each device performs PoP signing with its own `D_priv`; the server validates the chain `cert_request_signature → DeviceCert → PersonCert → HouseholdRoot`.

---

## 9. Revocation (CRL)

Revocation is an explicit signed event in the replicated log. There is no cert lookup against a directory; instead, every machine maintains a local CRL replica.

```cbor
RevocationEvent = {
  "v": 1,
  "type": "revocation",
  "target_id": text,            // p_id, m_id, d_id, or claw c_id
  "target_type": "person" | "machine" | "device" | "claw",
  "reason": text | null,
  "revoked_at": int,
  "issued_by": text,            // hh_id (for top-level) or p_id (self-revoke own device)
  "signature": bytes,
}
```

### Validation order

When a machine receives an authenticated request:
1. Validate cert signature chain to `hh_id`.
2. Check cert `not_before` ≤ now ≤ `not_after`.
3. Check `target_id` of cert (and any chain ancestor) NOT in CRL.
4. Evaluate caveats against requested operation, including
   `constraints.machines` against the dispatched machine `m_id`.

Any failure → **401 / hide-in-UI**, never best-effort.

### Cascading effects of machine revocation

When a `MachineRevocation` event is replicated, every Claw whose `host` was
the revoked `m_id` MUST be removed from household state on receiving peers
(emit synthetic `claw_deleted` per claw, signed by the receiving machine and
attributed to the revocation event for audit). **Claw data on the lost
machine is considered lost.** No replication of Claw payload data occurs
prior to revocation; this is intentional — privacy preserved by design,
data tied to physical custody.

---

## 10. Event log & replication

### Event types

| Type | Issuer | Meaning |
|---|---|---|
| `machine_joined` | hh_id | New MachineCert issued |
| `machine_left` | hh_id | Machine voluntarily leaves |
| `person_added` | hh_id | New PersonCert issued |
| `person_caveats_updated` | hh_id | New PersonCert supersedes old |
| `device_added` | p_id | New DeviceCert issued |
| `revocation` | hh_id or p_id | See §9 |
| `claw_created` | m_id | Claw created on this machine |
| `claw_assigned` | m_id | Claw owner changed |
| `claw_deleted` | m_id | Claw deleted |
| `peer_seen` | m_id | Heartbeat for liveness |

Each event:
```cbor
Event = {
  "v": 1,
  "type": text,
  "ts": int,
  "vc": map<m_id, uint>,    // vector clock at issue time
  "issuer": bytes,
  "payload": map,
  "signature": bytes,
}
```

### Vector clock

Every machine increments its own counter on every event it issues, and bumps to max(local, received) on every event received. Used for causal ordering.

### Conflict resolution

- **Additive ops** (anything that creates) — no conflict by construction (different nonces, different ids).
- **Mutational ops** (cert update, revocation) — last-writer-wins by `(vc, ts, signature_bytes)` lex order. Rationale: vector clock provides causal order; ties broken deterministically.
- **Adversarial branches** — a machine that issues conflicting mutations is detectable: signed evidence both branches exist, can be revoked by household.

### Gossip protocol

- Transport: WebSocket over Tailscale (TLS via Tailscale's WireGuard).
- Cadence: anti-entropy round every 30s (exchange (head_vc, recent_event_hashes) summaries; pull missing).
- Push: new events issued by a machine are pushed to all live peers immediately (best-effort) AND included in next anti-entropy round (authoritative).
- Topology: full mesh up to 10 machines (acceptable for household scale).

### Snapshot

A machine joining for the first time pulls a CBOR snapshot from one peer:
```cbor
Snapshot = {
  "v": 1,
  "as_of_vc": map<m_id, uint>,
  "household": HouseholdRecord,
  "machines": [MachineCert],
  "people": [PersonCert],         // current, not history
  "devices": [DeviceCert],
  "claws": [ClawRecord],
  "crl": [RevocationEvent],
  "head_event_hash": bytes,
}
```

Subsequent updates come via gossip events.

---

## 11. URI / QR scheme

All household URIs use scheme `soyeht://`. Existing scheme `theyos://` (used today) is replaced.

### `soyeht://household/pair-machine`

```
soyeht://household/pair-machine?
  v=1
  &m_pub=<base64url>          // 33-byte SEC1 compressed P-256 of candidate machine
  &nonce=<base64url>          // 32 random bytes; single-use server-side
  &hostname=<percent-encoded UTF-8 host label>
  &platform=macos|linux-nix|linux-other
  &transport=tailscale|lan
  &addr=<host:port>           // candidate's reachable host:port (informational hint)
  &challenge_sig=<base64url>  // 64-byte raw r||s P-256 ECDSA, see signing rule below
  &ttl=<unix seconds>
```
TTL: 5 minutes. Single-use enforced server-side via `nonce`.

**Signing rule (`challenge_sig`):** the candidate's installer signs at install
time, before rendering the QR, over the canonical CBOR of
`JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}`.
This binds the four user-visible identifying fields (`m_pub`, `nonce`, `hostname`,
`platform`) cryptographically — an attacker cannot tamper any of them without
invalidating the signature, so the fingerprint and hostname the owner sees on
the iPhone are guaranteed to match what the candidate's installer printed.

The owner-side flow:
- The Soyeht iPhone scans the QR, decodes every field, verifies `challenge_sig`
  against `m_pub` over the reconstructed `JoinChallenge`, and only then
  forwards a deterministic CBOR `JoinRequest` (the same fields plus
  `transport`/`addr`) to the founding machine's
  `POST /api/v1/household/join-request`.
- The QR is therefore a self-contained signed credential — the iPhone needs
  one network hop (iPhone → founding machine over Tailscale) to deliver it,
  not two. The `addr` field is informational; the iPhone never connects to
  the candidate directly.

### `soyeht://household/pair-device`

```
soyeht://household/pair-device?
  v=1
  &hh_pub=<base64url>         // household root pubkey, 33-byte SEC1 compressed (install-time)
                              //   OR: d_pub=<base64url> when an existing person is adding a 2nd device
  &nonce=<base64url>
  &p_id=<base64url>           // optional, hint
  &ttl=<unix seconds>
  &m_cert_fp=<base64url>      // 32-byte SHA-256 of the canonical CBOR of this
                              //   machine's admitted MachineCert
  &crit=m_cert_fp             // exactly once, value exactly `m_cert_fp`
  &host=<host:port>           // optional Bonjour-fallback hint
  &house_name=<percent-encoded UTF-8>  // optional display name
```

**`m_cert_fp` (added 0.1.25, critical).** The scanning device pins the engine
it is about to pair with. The value is the *same* fingerprint the roster wire
carries as `machine_cert_fingerprint` / `signer_machine_cert_fingerprint` —
`SHA-256(canonical CBOR(MachineCert))` — and there is deliberately one
definition, not one per surface.

Emission rules, all enforced by `PairDeviceQR` on the scanning device:

- `m_cert_fp` appears **exactly once**; a duplicate is rejected.
- `crit` appears **exactly once** and its value is **exactly** `m_cert_fp`.
  It is not a comma-separated list: the client compares the whole value, so
  `crit=m_cert_fp,other` is refused.
- The value is base64url **without padding**, decoding to exactly 32 bytes.
- The encoding must be **canonical**: the client re-encodes the decoded bytes
  and requires the result to equal the query value byte for byte. A
  non-canonical form that still decodes to the right 32 bytes is rejected.

The fingerprint is derived from the `MachineCert` the engine already loaded
and validated, never from a fresh read of `machine_certs/`, and never from a
candidate identity — a producer that cannot name an admitted cert must refuse
to render rather than emit an unpinned QR. It is resolved **before** the
pairing window is minted, so a failure leaves no window open behind an error.

Announcing it as critical is what makes this safe to roll forward: a scanner
that does not understand `m_cert_fp` refuses the QR instead of pairing
unpinned. The converse is the rollout constraint — a client older than the
field also refuses, so emission must not precede client support.

Two flows share this URI shape:

- **Install-time** (Phase 1, FR-018): the operator's terminal renders the QR
  immediately after `theyos install` mints a single-use pairing token. The
  URI carries `hh_pub` so the scanning device can verify the household
  identity before generating its own keypair and submitting it to
  `/pair-device/confirm`. In Phase 2, confirm carries `p_pub` plus a
  P-256 proof over `{v, purpose="pair-device-confirm", hh_id, nonce, p_pub}`;
  theyOS returns exactly one owner PersonCert and no DeviceCert.
- **2nd device for an existing person** (Phase 5+, US10): the URI carries
  `d_pub` instead — the public key of the new device, generated locally by
  the joining device, scanned by an existing paired device.

`ttl` is the unix-seconds expiry timestamp (5-minute window, server-tracked,
single-use).

### `soyeht://household/invite`

```
soyeht://household/invite?
  v=1
  &cert=<base64url CBOR signed offer>
  &host=<addr>
  &ttl=<unix seconds>
```
The `cert` payload contains a draft PersonCert plus a one-shot acceptance token. Recipient app generates its keypair, presents the keypair + acceptance token, receives signed PersonCert in response.

---

## 12. REST API

Existing `/api/v1/mobile/*` endpoints are deprecated. New surface:

### Authentication

Every household-scoped authenticated request carries:

```http
Authorization: Soyeht-PoP v1:<p_id>:<unix_seconds>:<signature_b64url>
```

`signature_b64url` is a 64-byte raw P-256 ECDSA signature over deterministic
CBOR:

```
{
  "v": 1,
  "method": "GET",
  "path_and_query": "/api/v1/household/snapshot",
  "timestamp": 1714972800,
  "body_hash": h'...'  // BLAKE3-256 over exact request body bytes
}
```
Server validates by:
1. Look up subject by `p_id` (or `m_id` for machine-to-machine).
2. Verify timestamp within ±60s.
3. Verify signature.
4. Validate cert chain + CRL (§9).

Phase 2 validates the first owner PersonCert persisted by install-time
pairing. DeviceCert chains arrive with the later second-device phase.

Bearer tokens are gone. Replay window is the timestamp tolerance.

### Endpoints

| Method | Path | Purpose | Caveat required |
|---|---|---|---|
| GET | `/api/v1/household/identity` | Returns `hh_id`, `name`, version | none (public on member network) |
| GET | `/api/v1/household/members` | List MachineCerts | `claws.list` (any) |
| GET | `/api/v1/household/people` | List PersonCerts | `household.invite` |
| POST | `/api/v1/household/join-request` | Machine joining (owner iPhone forwards QR-derived `JoinRequest` from §11) | n/a (gated by QR/Bonjour + owner biometric confirmation) |
| GET | `/api/v1/household/owner-events?since=<base64url-cbor-cursor>` | Owner iPhone long-polls signed `OwnerEvent`s. Held server-side ~45s. Returns immediately when a new event lands. (Phase 3) | Owner Soyeht-PoP |
| POST | `/api/v1/household/owner-events/{cursor}/approve` | Owner approves a pending join-request after biometric check (Phase 3) | Owner Soyeht-PoP |
| POST | `/api/v1/household/owner-events/{cursor}/decline` | Owner declines a pending join-request (Phase 3) | Owner Soyeht-PoP |
| POST | `/api/v1/household/owner-device/push-token` | Owner iPhone registers/rotates its APNS push token. Body: `{v=1, push_token, platform="ios"}`. Triggers opaque `aps.content-available` tickle when long-poll absent. (Phase 3) | Owner Soyeht-PoP |
| POST | `/api/v1/household/invite` | Issue PersonCert offer | `household.invite` |
| POST | `/api/v1/household/accept-invite` | Redeem invite | n/a (one-shot token) |
| POST | `/api/v1/household/revoke` | Revoke target | `household.revoke` |
| GET | `/api/v1/household/snapshot` | Bootstrap state | machine cert |
| GET (WS) | `/api/v1/household/gossip` | Event stream | machine cert |
| GET | `/api/v1/claws` | List Claws (filtered by caveats) | `claws.list` |
| POST | `/api/v1/claws` | Create Claw | `claws.create` |
| POST | `/api/v1/claws/{c_id}/{action}` | start/stop/restart | `claws.use` |
| DELETE | `/api/v1/claws/{c_id}` | Delete Claw | `claws.delete` |

#### Phase 3 candidate-side (pre-household) endpoints

These are served by a **bounded** local listener that the candidate machine M2 runs **only while its `PairMachineWindow` is open**. M2 has not joined the household yet — it has no `MachineCert` and is not a Soyeht-PoP subject — so these routes use single-use `nonce` + TTL gating instead of capability auth. Both routes shut down the moment the ceremony commits or aborts.

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `http://<m2-addr>:<port>/pair-machine/local/seed?nonce=<short>` | M1 fetches M2's signed `JoinRequest` after Bonjour discovery (Story 2; R5). Body: deterministic CBOR `JoinRequest` (§11 challenge_sig included). HTTP (not HTTPS): the candidate has no household root yet, so it cannot present a household-issued cert; the underlay is Tailscale WireGuard or LAN, the response is bound by `response_sig`, and the only confidential payload (the AEAD-encrypted shard) ships separately on `local/finalize`. | Short-nonce match against the open `PairMachineWindow`. |
| POST | `http://<m2-addr>:<port>/pair-machine/local/finalize` | M1 delivers `JoinResponse = {MachineCert, m2_shamir_shard, peer_list, ...}` after the owner approves; M2 verifies the cert against the `hh_pub` it pinned earlier from `LocalAnchor` (NOT from this response body), persists the shard, ACKs with `BLAKE3-256(canonical CBOR(MachineCert))`. A successful response may also carry `x-soyeht-candidate-tailscale-addr` as an unsigned, non-authoritative post-Ready liveness hint; the deterministic `FinalizeAck` CBOR remains unchanged. HTTP rationale identical to `local/seed`. | M1's signature over the JoinResponse + nonce match + anchor pin (`contracts/local-anchor.md`). |

### Routing in multi-machine households

The app pairs once with the household; the `members` list gives it all machines' Tailscale addresses. App ranks by latency, fails over silently. Mutating endpoints that target a specific Claw must be sent to the machine hosting that Claw (snapshot includes `claw → host m_id`).

---

## 13. Network discovery

### Bonjour services

Two service types are published depending on the engine's bootstrap state:

| Service type | Port | When published | Purpose |
|---|---|---|---|
| `_soyeht-setup._tcp.` | 8091 (householdPort) | state ≠ ready (onboarding) | iPhone discovers engine for first-launch setup |
| `_soyeht-household._tcp.` | 8443 (default HTTPS) | state == ready | Peer discovery, pair-device, pair-machine |

Full `_soyeht-setup._tcp.` TXT schema documented in §16b.

### `_soyeht-household._tcp` — post-onboarding peer discovery

```
Service type: _soyeht-household._tcp
Port:         (theyOS HTTPS port, default 8443)
TXT records:
  hh_id=<hh_id>           // omitted on a candidate that has not yet joined
  hh_name=<name>
  m_id=<m_id>             // omitted on a pre-household candidate
  proto=1
```

A single shared service type carries every pairing intent — no `_sub` subtype, no parallel `_soyeht-pair-machine._tcp`. The active pairing window is reflected via additional TXT keys, so a single browser can pick up either pair-device (Phase 2) or pair-machine (Phase 3) ceremonies.

#### Phase 2 pair-device window

```
  pairing=device
  pair_nonce=<short nonce>
```

Set on a founding machine that has just minted an install-time pair-device token (or, in US10, on a machine where an existing person is adding a 2nd device). Indicates the device-side QR scanner can complete pair against this advertisement.

#### Phase 3 pair-machine window (per `specs/003-machine-join/research.md` R1, R2, R5)

```
  pairing=machine
  pair_role=founder|joiner
  pair_nonce=<short nonce>     // matches the candidate's installer nonce
  m_pub_b32=<bare base32>      // ONLY when pair_role=joiner; 20 chars =
                               //   BLAKE3-128(M_pub_sec1) truncated to 12 bytes
```

When a Phase-3 ceremony is open, **both** machines advertise:

- The founding machine M1: `pairing=machine`, `pair_role=founder`, `hh_id=<existing>`, `pair_nonce=<the short nonce M1 got from M2's JoinRequest>`.
- The candidate M2: `pairing=machine`, `pair_role=joiner`, **no** `hh_id` (M2 has not joined yet), `pair_nonce=<short nonce>`, `m_pub_b32=<short pubkey hash>`.

#### Browse semantics

- A previously-paired machine browses `_soyeht-household._tcp` and:
  - Same `hh_id` it already belongs to → adds the member to its known peer list (steady-state).
  - `pairing=device` → device-side completes pair against this advertisement (Phase 2 / Phase 5 US10).
  - `pairing=machine, pair_role=joiner, m_pub_b32=<X>` AND no `hh_id` set → if M1 has a `PairMachineWindow` open whose `m_pub` BLAKE3-128 truncation equals `<X>`, M1 fetches the candidate's signed `JoinRequest` from `http://<addr>:<port>/pair-machine/local/seed?nonce=<short>` (R5; HTTP not HTTPS — see `§ Pre-household routes` table for rationale). The owner-confirmation flow that follows is identical to Story 1.

### Tailscale fallback

When mDNS doesn't resolve (different LAN / cellular), the app falls back to:
1. Stored Tailscale addresses from snapshot.
2. QR scan of `soyeht://household/pair-machine` URI (§11).

---

## 14. Migration from current model (destructive)

Per product decision 2026-05-06: no real users in production. Migration is destructive — single sweep, no coexistence.

### Old model recap (deprecated)

- Per-machine SQLite `users` table with `Admin | User` roles.
- Bearer tokens stored per-machine.
- `theyos://` URI scheme.
- App's `PairedServer` model — one entry per machine, no household concept.

### Sweep

theyOS:
1. Delete `users`, `mobile_sessions`, `invites` tables.
2. Add `household`, `machine_cert`, `person_cert`, `device_cert`, `events_log`, `crl`, `shamir_shard` tables.
3. Replace bearer auth middleware with PoP middleware.
4. Replace `/api/v1/mobile/*` with `/api/v1/household/*`.
5. Remove `theyos://` scheme handling.

iSoyehtTerm:
1. Delete `PairedServer`, `SessionStore.activeServerId`, bearer-token storage path.
2. Add `Household`, `MachineRecord`, `PersonCert` (decoded), `CertStore`, `KeyAgent` (Secure Enclave wrapper).
3. Replace QR scanner state machine — only `soyeht://household/*` URIs.
4. Replace UI condition logic on `role == "admin"` with caveat checks.
5. Add `HouseholdBrowser` (NWBrowser) for Bonjour discovery.

### Bootstrap of existing dev/test installs

Provide one-shot installer command `theyos household init` that:
1. Generates new household identity.
2. Issues MachineCert for current machine.
3. Re-issues a PersonCert for the operator (manual: app pairs with this machine via QR).
4. **Existing Claws are wiped.** No data preservation in v0.1 (acceptable per "no real users").

---

## 15. Versioning & evolution

- Protocol version field on every CBOR document (`v`).
- v0.1 is the initial release.
- Backward incompatible changes require coordinated upgrade of all members of a household.
- Forward compat: machines reject events with `v` higher than their max supported.

---

## 16. Security model

### Trusted

- Member machines (transitively trusted via MachineCert).
- Devices holding subject private keys (Secure Enclave / Keychain).
- Tailscale WireGuard transport.

### Untrusted

- Network observers between machines (mitigated by Tailscale).
- Anyone holding a leaked QR token (mitigated: TTL + single-use + operator confirmation).
- Compromised machine: limited blast radius — can issue events, but quorum-protected ops (new MachineCert) require Shamir threshold.

### Attack scenarios addressed

- **Stolen device with cached cert** — cert revoked via CRL, propagates within seconds across online machines.
- **Replay** — PoP timestamps enforce ±60s.
- **MITM in same LAN** — TLS termination required even on LAN; Bonjour TXT only carries identifiers, never secrets.
- **Compromised single machine** — cannot mint MachineCerts alone (Shamir quorum), cannot escalate caveats (signature chain).
- **Sole-shard mode breach** (single-machine household) — operator MUST add 2nd machine before storing sensitive Claws; documented in install UX.

### Out of scope (v0.1)

- Post-compromise recovery (rotate household root) — future.
- Anti-tampering of local SQLite — relies on OS file permissions.

---

## 16a. Threat Model: anchor-handoff Tailnet trust boundary (added 2026-05-09 for spec 005)

The `GET /pair-machine/anchor-handoff` endpoint (spec 005-soyeht-onboarding contract `anchor-handoff.md`) delivers a candidate machine's `anchor_secret` to a peer in the same Tailnet, eliminating the need for a QR scan in the common path. This section documents the threat model and why this is acceptable.

### Trust boundaries

- **Discovery (read-only)**: Bonjour advertisements on LAN and Tailnet. Anyone on the network can see "Casa X exists". This is by design (mDNS) and does not leak secret material.
- **Pareamento (write)**: anchor-handoff + `local/anchor` POST + `/bootstrap/initialize` from peer. **Tailnet-required**. Engine returns 403 if caller is not in `100.64.0.0/10` (Tailnet CGNAT) or `fd7a:115c:a1e0::/48` (Tailnet IPv6). LAN bruta has zero write capability.

### Capability proof chain

1. Tailscale installs device-bound certificates on each tailnet member. Only authenticated tailnet members can route to the engine's Tailnet IP.
2. The engine's `pair_machine_window` is minted only when a user explicitly runs install (User Story 2 / Caso B / Story 4) — i.e., the casa owner intentionally set up this candidate AND added it to their tailnet. Both actions are user-mediated.
3. The owner's biometric Face ID gate on the iPhone (mandatory before signing the `local/anchor` POST or `/bootstrap/initialize`) is the additional defense-in-depth.

### Attacker scenarios analyzed

| Scenario | Defense |
|---|---|
| Attacker on the same LAN tries to harvest `anchor_secret` via the LAN-side endpoint | Endpoint refuses non-Tailnet IPs with 403 |
| Attacker compromises a tailnet member device and queries anchor-handoff | Steals `anchor_secret`, but cannot complete pareamento without owner's Face ID on iPhone (which lives in Secure Enclave biometric ACL — uncopyable) |
| Tailscale ACL misconfig (everyone in the tailnet has same trust level) | Same as above: biometric Face ID is the second factor |
| Attacker MITMs the HTTP loopback inside the Mac | Tailscale is not loopback — Tailnet traffic uses tailscale0 device, encrypted by Tailscale's WireGuard |
| Attacker captures the QR scan path instead | Equivalent threat profile to anchor-handoff: stealing the `anchor_secret` from the QR is exactly equivalent to stealing it from anchor-handoff. Both still require biometric to be useful |

### Comparison with QR scan path

- QR scan: user takes a photo with iPhone of the candidate's screen. Security relies on physical proximity ("user must visually confirm the right machine") + 6-emoji-word fingerprint match.
- anchor-handoff: caller is in tailnet (cryptographic proof of casa-membership) + 6-emoji-word fingerprint match.

Both paths require the **same biometric Face ID gate** before pareamento completes. Both have the same attack surface for stealing `anchor_secret`. anchor-handoff trades the "physical-proximity ceremony" for "tailnet-membership ceremony". For 95%+ of users (already on Tailscale at the moment of pair-machine), tailnet-membership is the natural ceremony.

### Edge cases

- Tailnet not configured (user runs install on a fresh Linux without Tailscale): anchor-handoff fails (403); flow falls back to QR scan path. UX: install script detects absence and instructs user to install Tailscale before continuing OR proceed with QR scan path.
- Multiple casas in the same tailnet (rare, but possible — user has personal casa + work casa): each casa has its own `pair_machine_window` lifecycle. The auto-pair offer in iPhone Soyeht surfaces both casas; user picks which one to add the candidate to.

### Future evolution

If Apple introduces a passkey-based "device identity proof" mechanism that doesn't require a separate Tailscale layer, that path may supersede tailnet-membership as the proof. Documented for revisit when `ASAuthorizationProvider` capabilities expand.

### Push delivery (added 2026-05-09 for spec 005)

Engine sends Apple Push Notifications direct to APNs gateway from the engine process, signed with a shared bundled `.p8` provider key in `Soyeht.app/Contents/Resources/apns.p8` (per research.md R11). Per-house provider keys are documented as a future migration path (v0.3.0+) when scale or audit justifies it.

---

## 16b. Bootstrap endpoints (spec 005-soyeht-onboarding, added 2026-05-10)

The household identity listener runs on port **8091** (configurable via `services.theyos.householdPort` in the NixOS module). Control endpoints use CBOR bodies (`Content-Type: application/cbor`); the diagnostic echo is the explicitly documented octet-stream exception.

### Bootstrap endpoints table

| Endpoint | Contract | State gate | Auth |
|---|---|---|---|
| `GET /bootstrap/status` | `contracts/bootstrap-status.md` | any | none |
| `POST /bootstrap/initialize` | `contracts/bootstrap-initialize.md` | uninitialized, ready_for_naming | none (biometric on iPhone side) |
| `POST /bootstrap/teardown` | `contracts/bootstrap-teardown.md` | named_awaiting_pair, ready, recovering | owner cert ECDSA (P-256) |
| `POST /bootstrap/claim-setup-invitation` | `contracts/setup-invitation.md` | uninitialized | Tailnet IP (100.64.0.0/10 or fc00::/7) |
| `GET /pair-machine/anchor-handoff` | `contracts/anchor-handoff.md` | ready | Tailnet IP |
| `POST /api/v1/household/reachability/echo` | fixed 32-byte octet-stream echo; reachability diagnostic only, never identity or `VerifiedMesh` authority | ready | loopback or Tailnet source |
| `GET /health` | — | any | none |

### Bonjour setup service (`_soyeht-setup._tcp.`)

During onboarding (state ≠ ready), the engine additionally publishes:

```
Service type: _soyeht-setup._tcp.
Port:         8091  (householdPort)
TXT records:
  proto=1
  setup_role=founder_candidate   // present only when state == uninitialized AND no casa detected on Tailnet
  m_id=<m_id>                    // only after initialize
  hh_id=<hh_id>                  // only after initialize
```

iPhone Soyeht browses `_soyeht-setup._tcp.` during first-launch onboarding. The browser finds this advertisement and drives the user through POST /bootstrap/initialize (naming the casa) and the pair-device ceremony. After pairing completes and the engine transitions to `ready`, the `_soyeht-setup._tcp.` advertisement is retracted and the standard `_soyeht-household._tcp.` advertisement takes over (§13).

### Teardown (spec 005 FR-004)

`POST /bootstrap/teardown` is the "recomeçar do zero" primitive. The owner signs a `TeardownRequest` CBOR on the iPhone (after Face ID gate) with their device cert private key (`D_priv`, Secure Enclave). The engine validates the cert chain (owner cert → hh_pub), verifies the ECDSA signature, atomically renames `household/` to `household.tearing-down/`, persists `Uninitialized` state, and exits cleanly. Next boot: engine starts in `uninitialized` and republishes `_soyeht-setup._tcp.`.

Special case: when state == `named_awaiting_pair` (casa named but owner cert not yet issued), teardown succeeds without cert+sig check — there is no sensitive material yet and the user may want to rename the casa.

Cross-language contract mirror: `specs/005-soyeht-onboarding/contracts/bootstrap-teardown.md` is mirrored in `soyeht/soyeht-ios/specs/017-onboarding-canonical/contracts/bootstrap-teardown.md`.

### Guest-image preparation status (macOS engines, added 2026-05-28)

A macOS engine builds a base macOS guest image before it can host claws. Its
progress is surfaced **additively** on `GET /bootstrap/status` (and echoed by
`POST /api/v1/household/guest-image/prepare`). All fields are optional; Linux
engines and Mac engines that have not started provisioning omit them entirely.

| Field | Type | Meaning |
|---|---|---|
| `guest_image_phase` | string? | `download_ipsw` \| `create_disk` \| `install_macos` \| `provision` \| `create_snapshot` \| `complete` |
| `guest_image_status` | string? | `pending` \| `in_progress` \| `done` \| `failed` |
| `guest_image_error` | string? | Human-readable error from the most recent failed phase. **Display-only** — clients MUST NOT parse it for logic. Present only when `guest_image_status == "failed"`. |
| `guest_image_failure_code` | string? | **Machine-readable** failure reason (snake_case enum). Present only when `guest_image_status == "failed"`; absent on older engines. |

`guest_image_failure_code` values (fail-soft — an unknown/future value MUST
decode to `unknown`, never break the client):

| Code | Meaning | Suggested client action |
|---|---|---|
| `host_vm_limit_reached` | Apple's per-host concurrent macOS-VM limit was hit (VZ `Code=6`); a prior VM session is still held by the OS. | Offer "Restart Soyeht engine", then "Restart your Mac" if it persists. Reboot clears the leaked session. |
| `helper_missing` | A privileged helper (e.g. `theyos-provision-inject`) is missing or `sudo` is not NOPASSWD-configured. | Guide the operator to reinstall / configure the helper. |
| `insufficient_disk` | Not enough free disk to build the image. | Ask the user to free space (≥ image size). |
| `entitlement_missing` | Virtualization entitlement absent / not honored. | Surface a reinstall / re-sign hint. |
| `ipsw_download_failed` | The macOS restore image failed to download. | Offer retry (transient/network). |
| `ipsw_incompatible` | No restore image is compatible with this host. | Explain the host/OS mismatch; not retryable as-is. |
| `unknown` | Unclassified failure (fail-soft catch-all). | Show the generic "couldn't prepare" copy + `guest_image_error` as secondary detail. |

The code is the contract; clients key localized recovery copy off it and treat
`guest_image_error` as optional secondary detail (never the primary user-facing
line). Mirrors the `unavailable_reason_code` pattern used for claw installability.

---

## 16c. Machine roster currency endpoint (B0a, added 2026-07-30)

`GET /api/v1/household/roster/currency/{m_id}` answers one question — *what is
this household's current, durable position on this machine?* — from the roster
authority in `household-rs::machine_roster_store`. It does not mutate the roster
chain: it admits no checkpoint, changes no membership, and mints no signature.
It **does** durably observe/advance the monotonic clock floor used for temporal
decisions; the first successful no-genesis query may create that floor record.
Consequently each successful query takes the cross-process roster lock and may
perform an atomic disk replacement. This is an authenticated temporal-state
write, not a side-effect-free cache read.

This is **not** the roster evidence endpoint. Evidence and currency partition
the same underlying store states differently and are specified separately;
notably, no-genesis and both fork states are *unavailable* outcomes here, while
the evidence surface reports them as served states. Do not infer one endpoint's
contract from the other.

### Transport

| Property | Value |
|---|---|
| Method / path | `GET /api/v1/household/roster/currency/{m_id}` |
| Response Content-Type | `application/cbor` |
| Encoding | Canonical CBOR. The client decodes, re-encodes and byte-compares; a non-canonical response is rejected before it is read. |
| Auth | Owner `PoP` (`Soyeht-PoP v1`), capability `claws.list` — the same gate as `GET /api/v1/household/machines` — **or** an admitted household device delegated by that owner, selected by the optional `Soyeht-Device-Id` header (see below). |
| Request body | None. The client sends no request Content-Type and the server does not inspect one. A non-empty body is refused even when correctly signed. |
| `{m_id}` | Validated as `m_` + 52 base32 chars (`MachineId::parse`) before any store read. |

The household must additionally hold a **strong-tier owner cert with a verified
provenance** (`owner_auth_tier = "strong"` plus one of the four iOS/iPadOS
Secure Enclave / App Attest provenances). The roster authority derives its owner
binding from that cert; a basic-tier owner is refused with
`invalid_current_owner_authority` before the store is read.

### Delegated device access (D2c)

`Soyeht-Device-Id` is **optional**, and its presence alone selects the caller:

| Header | Authorized as |
|---|---|
| absent | The owner, exactly as before. Nothing about the owner path changes. |
| present | **Device-only, and terminal.** The request is never re-tried as the owner, even if it also carries a valid owner signature, and even if the device id is malformed, unknown, or revoked. |

That asymmetry is the point: a header that could silently fall back to the owner
would turn an explicit delegation into an escalation.

**The `Soyeht-PoP` wire is unchanged.** It stays `v1:<p_id>:<ts>:<sig>`, the
`p_id` slot still names the *parent person*, and the signed context is still
method + path/query + timestamp + body. Only the verifying key differs: the
server checks the signature against the device's admitted `d_pub`, never the
person's `p_pub`. A client that already signs owner requests adds one header and
changes no signing code.

The device is authorized only if the durable admission authority holds it as
`active` under a non-zero generation, its parent person is not revoked, that
parent matches both the proof's `p_id` and the live owner cert (including that
cert's digest), the inherited validity limit has not passed, and the effective
caveat set permits `claws.list` — the device's own set when it declared one,
otherwise the verified person's.

| Condition | Status | Body `error` |
|---|---|---|
| Any device-side refusal — malformed/unknown/revoked device, revoked person, cross-binding, wrong signature, stale proof, caveat denial | `401` | `unauthenticated` |
| Device admission authority absent | `503` | `not_initialized` |

The `401` is deliberately **collapsed and non-enumerating**: one class for every
device-side refusal, so an unauthenticated caller cannot use the status to learn
which device ids exist or what state they are in. The reason class is recorded
server-side in tracing only; no `d_id`, `p_id`, key, or path is ever logged.
`503` is reserved for a genuinely absent authority — a service state, not a
credential judgement — so a client can distinguish "not set up yet" from
"refused" without that distinction leaking anything about a specific device.

### Outcomes (200)

Nine outcomes, one closed key set per family. The literals come from
`PublicCurrencyOutcome::wire_str` in `machine_roster_store.rs` — that mapping is
the single source of this vocabulary, and nothing else may re-spell it.

| `outcome` | Response keys | Meaning |
|---|---|---|
| `active` | `{v, outcome, member}` | Machine is a current member of the accepted roster. |
| `revoked` | `{v, outcome, tombstone}` | Machine was revoked; the tombstone proves it. |
| `not_listed` | `{v, outcome}` | Roster is readable and this machine appears nowhere in it. |
| `unavailable_no_genesis` | `{v, outcome}` | Store provisioned but no genesis checkpoint accepted yet. |
| `unavailable_checkpoint_stale` | `{v, outcome}` | Accepted checkpoint is outside its temporal envelope. |
| `unavailable_checkpoint_fork_conflict` | `{v, outcome}` | Terminal checkpoint fork recorded. |
| `unavailable_event_fork_conflict` | `{v, outcome}` | Terminal event fork recorded. |
| `unavailable_clock_state` | `{v, outcome}` | Monotonic clock floor unusable; no temporal judgement is possible. |
| `unavailable_owner_authority` | `{v, outcome}` | Current owner authority does not bind to the chain's owner. |

`v` is `1` in every response.

`member` is the canonical 4-key `MachineRosterMemberV1`: `m_id`, `m_pub`,
`machine_cert`, `machine_cert_fingerprint`.

`tombstone` is the **complete** canonical 16-key `MachineRosterRevocationV1`:
`v`, `kind`, `hh_id`, `epoch`, `sequence`, `prev_event_hash`, `m_id`, `m_pub`,
`machine_cert_fingerprint`, `revoked_at`, `reason`, `cascade`, `owner_p_id`,
`owner_cert_fingerprint`, `owner_person_cert`, `signature`. It is served whole
so the client can verify the revocation offline against the household root;
a trimmed tombstone would be unverifiable and must be rejected on device.

An `unavailable_*` outcome is a statement about the *roster*, not about the
machine. It must never be collapsed into `not_listed`, which asserts proven
non-membership.

### Errors (non-200)

Errors are a canonical CBOR envelope with exactly two keys:
`{v: 1, error: "<literal>"}`.

| Status | `error` | Cause |
|---|---|---|
| 401 | `unauthenticated` | Missing, malformed, expired, or non-owner `PoP`. |
| 400 | `invalid_machine_id` | `{m_id}` is not a well-formed machine id. |
| 409 | `already_initialized` | A store operation observed an already-initialized state. |
| 413 | `body_not_allowed` | A request body was supplied. |
| 503 | `not_initialized` | Roster store not provisioned (or the household unloaded mid-request). |
| 503 | `lock_timeout` | Roster lock not acquired in time. |
| 503 | `clock_unavailable` | Server wall clock is before the Unix epoch, so the `PoP` time gate cannot be evaluated. |
| 500 | `store_io`, `unsafe_file_type`, `temp_already_exists`, `mode_mismatch`, `invalid_path`, `inconsistent_provisioning_state`, `readback_mismatch`, `latch_poisoned`, `invalid_current_owner_authority`, `storage`, `household`, `owner_auth`, `encode_failed`, `internal_error` | Typed store or encoding failure. |
| 500 | `integrity_*` | Chain integrity failure; one literal per `ChainIntegrityError` variant (`integrity_non_canonical`, `integrity_duplicate_key`, `integrity_unknown_field`, `integrity_null_field`, `integrity_version`, `integrity_household`, `integrity_key_set`, `integrity_checkpoint_decode`, `integrity_checkpoint_signature`, `integrity_owner_certificate`, `integrity_owner_continuity`, `integrity_sequence`, `integrity_hash`, `integrity_projection`, `integrity_fork_reapply`, `integrity_temporal`, `integrity_epoch`). |

Fail-closed: no failure path may fabricate a roster fact. The endpoint either
serves an authority-derived outcome or an error envelope.

Implementation: `admin/rust/server-rs/src/handlers_household_roster.rs`;
contract tests in `admin/rust/server-rs/tests/household_roster_currency.rs`.

---

## 16d. Machine roster evidence endpoint (B0b, added 2026-07-30)

`POST /api/v1/household/roster/evidence` answers a different question from
§16c: *what is this household's whole current roster position, stated by the
machine that serves it, bound to a nonce I chose?* It is not a per-machine
query — the request carries no `m_id`, and `invalid_machine_id` never appears
on this route.

Like currency it performs no roster-chain mutation: it admits no checkpoint,
changes no membership, and mints no roster signature. And exactly like currency,
it **does** durably observe and may advance the monotonic clock floor. Every
served response takes the cross-process roster lock and may perform an atomic
disk replacement of the floor record; on a no-genesis store the first served
response may create that record. **Serving evidence is an authenticated
temporal-state write, not a side-effect-free read.** That is not incidental
bookkeeping: the floor this call lands on is the `floor_secs` the response
attests and signs, so the write and the statement are the same act.

Evidence and currency partition the same underlying store states
**differently**. §16c's nine-outcome table does not apply here and neither
contract may be inferred from the other.

### Transport

| Property | Value |
|---|---|
| Method / path | `POST /api/v1/household/roster/evidence` |
| Request Content-Type | `application/cbor`, exactly. Absent is as fatal as wrong, and neither is leniently parsed. |
| Response Content-Type | `application/cbor`, with `Cache-Control: no-store`. |
| Encoding | Canonical CBOR in both directions. The request is decoded, re-encoded and byte-compared; a decodable but non-canonical request is refused rather than normalized, so the bytes the client signed and the nonce echoed back cannot diverge. |
| Max request size | 1024 bytes. Evaluated **after** authorization. |
| Auth | Owner `PoP` (`Soyeht-PoP v1`), capability `claws.list` — **or** an admitted household device delegated by that owner, selected by the optional `Soyeht-Device-Id` header. |

Gate order is fixed: clock → authorization → size → media type → request shape →
identity → store. Authorization runs before every request-shape complaint, so an
unauthenticated caller learns only `401` and never whether their body was too
large, the wrong media type, or malformed. An oversized body with an invalid
`PoP` is therefore `401`, not `413`.

### Request

Exactly two keys, canonical CBOR:

| Key | Type |
|---|---|
| `client_nonce` | `bstr`, exactly 32 bytes |
| `v` | `1` |

An unrecognised key is a rejection, never something to ignore. A 31- or 33-byte
nonce, a missing key, a wrong `v`, an indefinite-length map, a non-canonical key
order, an empty body and a non-map value all collapse to one `400
invalid_request` — the server never enumerates which shape rule was broken.

The `PoP` signed context is method + path/query + timestamp + body, so a POST
signature covers the request body and therefore the nonce itself.

### Auth: owner or delegated device (D2c)

The gate is the same `authorize_roster_read` §16c uses, so the owner path is
byte-identical and the delegated-device rules there apply here unchanged —
nothing about them is specific to currency. In particular:

| Header | Authorized as |
|---|---|
| `Soyeht-Device-Id` absent | The owner. |
| `Soyeht-Device-Id` present | **Device-only, and terminal.** Never re-tried as the owner, even when the request also carries a valid owner signature, and even if the device id is malformed, unknown, or revoked. |

Every device-side refusal collapses to one non-enumerating `401
unauthenticated`; only a genuinely absent admission authority is
distinguishable, as `503 not_initialized`. No `d_id`, `p_id`, key or path is
ever logged.

### Outcomes (200)

Four literals. They come from `RosterEvidenceOutcome::wire_str` in
`machine_roster_evidence.rs`, which is the single source of this vocabulary. It
is deliberately **not** shared with `PublicCurrencyOutcome`: those nine literals
partition the same store states incompatibly, and a shared enum or helper would
leak one vocabulary into the other.

| `outcome` | Body | Meaning |
|---|---|---|
| `available` | 10 keys, with `snapshot_body` | The chain was read and is attested; `snapshot_body.state_kind` says which state. |
| `unavailable_clock_state` | 7 keys | Monotonic clock floor unusable; no temporal judgement is possible. |
| `unavailable_owner_authority` | 7 keys | Current owner authority does not bind to the chain's owner. |
| `unavailable_checkpoint_stale` | 7 keys | Accepted checkpoint is outside its temporal envelope. |

The repartition against §16c, stated explicitly: **no-genesis and both fork
states are `unavailable_*` for currency but `available` here**, carried as
`state_kind` 0, 2 and 3. Per-machine results have no meaning on this surface, so
currency's `active`, `revoked` and `not_listed` all reduce to `available` with
`state_kind` 1 — the evidence answer does not depend on any machine identity.

**An `unavailable_*` is a `200`, signed and signer-anchored — not an error
envelope.** It is a statement the household's own machine puts its name and
signature to, and a client can verify and retain it. It therefore requires a
usable signer: if no household identity is loaded there is no signer and the
answer is `503 not_initialized`; a signing failure is `500 sign_failed`. Neither
is an `unavailable_*`, because those four literals describe the *roster*, and
"this machine cannot sign" is not a fact about the roster.

### Response key sets

Two closed key sets. Omitted keys are **absent, not null**; a null or an
unexpected key is a protocol violation.

**`available` — exactly ten keys:**

| Key | Type |
|---|---|
| `client_nonce` | `bstr[32]`, echoed from the request |
| `full_snapshot_digest` | `bstr[32]` |
| `outcome` | `"available"` |
| `signature` | `bstr`, P-256 |
| `signer_m_id` | text |
| `signer_machine_cert` | `bstr`, canonical CBOR `MachineCert` |
| `signer_machine_cert_fingerprint` | `bstr[32]` |
| `snapshot_body` | **nested CBOR map** (see below) |
| `state_evidence_digest` | `bstr[32]` |
| `v` | `1` |

**Every `unavailable_*` — exactly seven keys:** `client_nonce`, `outcome`,
`signature`, `signer_m_id`, `signer_machine_cert`,
`signer_machine_cert_fingerprint`, `v`. `snapshot_body`,
`state_evidence_digest` and `full_snapshot_digest` are **absent**.

Key order on the wire is the canonical CBOR order (by encoded key bytes,
shortest first), not the order tabulated here.

### `snapshot_body` by `state_kind`

`state_kind` crosses the boundary as a `u8`; the store's internal chain-state
type is not part of this surface. Four keys are always present — `floor_secs`,
`hh_id`, `state_kind`, `v` — and checkpoint keys are omitted rather than nulled
when the state does not have them.

| `state_kind` | Store state | Additional keys |
|---|---|---|
| 0 | No genesis accepted | none — exactly `{floor_secs, hh_id, state_kind, v}` |
| 1 | Accepted chain | `genesis_checkpoint`, `accepted_checkpoint`, plus `predecessor_checkpoint` when one exists |
| 2 | Checkpoint fork conflict | `genesis_checkpoint`, `accepted_checkpoint`, `conflicting_checkpoint`, plus `predecessor_checkpoint` when one exists |
| 3 | Event fork conflict | same as 2 |

Checkpoint values are the stored canonical checkpoint blobs, passed through
unchanged.

### Domains, the two digests, and the floor asymmetry

Two domain separators. **The trailing NUL byte is part of each domain, not a
typo** — dropping it still hashes and still verifies against itself, and never
matches the client:

```
evidence domain:  "soyeht/roster-evidence/v1\x00"
snapshot domain:  "soyeht/roster-snapshot/v1\x00"
```

Each digest is `SHA-256(domain ‖ canonical_cbor(body))`, and the two are taken
over **different preimages**. The difference is exactly `floor_secs`:

| Digest | Domain | Body |
|---|---|---|
| `state_evidence_digest` | evidence | the snapshot body **without** `floor_secs` |
| `full_snapshot_digest` | snapshot | the snapshot body **with** `floor_secs` |

The asymmetry is load-bearing. `state_evidence_digest` names the roster state
independently of when it was observed, so it is stable across queries that only
advance the floor; `full_snapshot_digest` binds that same state to the observed
moment. Swapping the two produces two internally coherent digests of the wrong
preimages — a server that verifies against itself and that the client rejects
every time. The `snapshot_body` served on the wire is the **with-floor** body.

### Signature

`signature` is a P-256 signature by the responding machine's identity key over

```
"soyeht/roster-evidence/v1\x00" ‖ canonical_cbor(unsigned_map)
```

where `unsigned_map` is the response **minus `signature`**:

- `available` — nine keys: `client_nonce`, `full_snapshot_digest`, `outcome`,
  `signer_m_id`, `signer_machine_cert`, `signer_machine_cert_fingerprint`,
  `snapshot_body`, `state_evidence_digest`, `v`.
- `unavailable_*` — six keys: `client_nonce`, `outcome`, `signer_m_id`,
  `signer_machine_cert`, `signer_machine_cert_fingerprint`, `v`.

Two properties here fail **silently** if got wrong — each yields a server that
is internally consistent and that the client rejects:

1. **`snapshot_body` is signed as a nested CBOR map, not as a byte string
   containing CBOR.** Asserting mere presence cannot tell the two apart. The
   `bstr` form is a different preimage, and a server built that way verifies
   against itself.
2. **When the outcome is `available`, the signature must cover `snapshot_body`
   and both digests.** Omitting them signs a strictly weaker statement that
   still verifies.

The response is signer-anchored: `signer_m_id`, the full canonical
`signer_machine_cert` and its 32-byte fingerprint are all inside the signed map,
so the statement names its author and carries the household-issued cert that
author was issued. `client_nonce` is inside the signed map too, binding the
response to the specific request that asked for it.

### Errors (non-200)

Same canonical two-key envelope as §16c: `{v: 1, error: "<literal>"}`.

| Status | `error` | Cause |
|---|---|---|
| 401 | `unauthenticated` | Missing, malformed, expired, or non-owner `PoP`; or any device-side refusal. |
| 413 | `payload_too_large` | Request body over 1024 bytes. Evaluated after authorization. |
| 415 | `unsupported_media_type` | Request `Content-Type` absent or not exactly `application/cbor`. |
| 400 | `invalid_request` | Any malformed request shape, collapsed to one literal. |
| 409 | `already_initialized` | A store operation observed an already-initialized state. |
| 503 | `not_initialized` | Roster store not provisioned, device admission authority absent, household unloaded mid-request, or no loaded identity to sign with. |
| 503 | `lock_timeout` | Roster lock not acquired in time. |
| 503 | `clock_unavailable` | Server wall clock is before the Unix epoch, so the `PoP` time gate cannot be evaluated. |
| 500 | `sign_failed` | The response was assembled but could not be signed. |
| 500 | `encode_failed` | The response could not be canonically encoded. |
| 500 | `internal_error` | The blocking store task failed to join. |
| 500 | `store_io`, `unsafe_file_type`, `temp_already_exists`, `mode_mismatch`, `invalid_path`, `inconsistent_provisioning_state`, `readback_mismatch`, `latch_poisoned`, `invalid_current_owner_authority`, `storage`, `household`, `owner_auth` | Typed store failure; same mapping as §16c. |
| 500 | `integrity_*` | Chain integrity failure; one literal per `ChainIntegrityError` variant, same set as §16c. |

`invalid_machine_id` and `body_not_allowed` are §16c literals and never appear
here: this route takes no `{m_id}`, and its request body is required rather than
forbidden.

Fail-closed: no failure path may fabricate a roster fact, and no path may serve
a `snapshot_body` outside a signed `available` response.

Implementation: `admin/rust/household-rs/src/machine_roster_evidence.rs`
(domains, digests, signing preimage), `admin/rust/household-rs/src/machine_roster_store.rs`
(`query_roster_evidence`), `admin/rust/server-rs/src/handlers_household_roster.rs`
(route and wire); contract tests in
`admin/rust/server-rs/tests/household_roster_currency.rs`.

---

## 17. Ratified product decisions (2026-05-06)

All four schema-blocking decisions closed:

1. **Claws on lost machine — DIE.** When a machine is revoked, all Claws
   hosted on it are removed from household state on all peers. Data on the
   lost machine is considered lost. No pre-revocation replication of Claw
   payload data. (See §9 cascading effects.)
2. **Multi-device per person in v0.1 — INCLUDED.** `DeviceCert` ships as a
   required schema element in v0.1. Pair-device ceremony is part of Phase 5.
3. **Per-machine permission granularity in v0.1 — INCLUDED.**
   `caveats[].constraints.machines` is honored by the v0.1 caveat evaluator.
   See §7 per-machine evaluation rule.
4. **`theyos://` scheme — DIES.** Replaced entirely by `soyeht://`. No
   parallel handling, no path-namespace reuse. Existing QR/deep-link
   consumers MUST be updated as part of Phase 2.

---

## 18. Implementation phases

Spec covers everything; phases sequence the build:

| Phase | Deliverable | Spec sections |
|---|---|---|
| 0 | This document, reviewed and closed | all |
| 1 | Crypto skeleton: keypair gen, persist, no behavior change yet | §3, §4 |
| 2 | Single-machine household: bootstrap + own owner-device pair; `soyeht://` scheme replaces `theyos://` | §4, §5 (sole-shard mode), §7, §11 (pair-device), §12 (subset), §14 |
| 3 | Add 2nd machine via QR (Tailscale): join ceremony, Shamir split | §5, §6, §11 (pair-machine), §12 (join-request) |
| 4 | Gossip + snapshot + CRL replication; cascading claw deletion on machine revocation | §9, §10 |
| 5 | Capabilities operational: invite, accept, revoke, UI rendering on caveats; multi-device per person; per-machine constraint evaluator | §7 (incl. constraints.machines), §8 (DeviceCert), §11 (invite, pair-device), §12 (full) |
| 6 | Bonjour discovery + push-confirm UX | §13 |

Each phase MUST end with both repos in a working state (no half-migration on `main`).

---

*End of v0.1 spec.*
