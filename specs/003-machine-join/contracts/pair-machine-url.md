# Contract: `soyeht://household/pair-machine` URI

Per protocol §11 (updated 2026-05-06).

## Shape

```
soyeht://household/pair-machine?
  v=1
  &m_pub=<base64url no-pad of 33-byte SEC1>
  &nonce=<base64url no-pad of 32 random bytes>
  &hostname=<percent-encoded UTF-8 host label, 1..=64 bytes>
  &platform=macos|linux-nix|linux-other
  &transport=tailscale|lan
  &addr=<host:port of candidate's reachable address; informational hint>
  &challenge_sig=<base64url no-pad of 64-byte raw r||s P-256 ECDSA>
  &anchor_secret=<base64url no-pad of 32 random bytes>
  &ttl=<unix seconds, MUST be ≤ 300 from issuance>
```

`anchor_secret` is the iPhone-to-candidate trust-anchor authenticator
defined in `contracts/local-anchor.md`. It is minted at install time
alongside `nonce`, persisted in the candidate's window snapshot, and
MUST NOT be exposed by `local/seed` or any other endpoint — only the
QR carries it.

The QR is a **self-contained signed credential**. The owner iPhone forwards a CBOR `JoinRequest` reconstructed from the QR's URL parameters to the founding machine in a single network hop; it never connects to the candidate.

## Producer (theyOS installer on candidate M2)

At install time, before rendering the QR:

1. Mint a fresh EC P-256 keypair `(M_priv, M_pub)` if not already present. Default residency is Secure Enclave on macOS / kernel keyring on Linux. **Phase 3 carve-out (FR-002 + FR-021)**: on macOS, the candidate MUST be launched with `THEYOS_FORCE_SOFTWARE_KEYS=1` so `M_priv` lives under the software-fallback keystore (file-based, mode `0o600`); ECDH-based shard decryption needs the raw scalar, which the Secure Enclave will not release. The flag MUST remain set across subsequent daemon boots on macOS until the SE-resident threshold-signature primitive lands.
2. Generate a 32-byte CSPRNG `nonce`.
3. Determine `hostname` (the machine's reported host label) and `platform`.
4. Determine `transport` — `tailscale` if M2 has a Tailscale interface bound, else `lan` — and `addr` accordingly.
5. Set `ttl = now + 300` (5-minute window).
6. Build the canonical CBOR `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}` (deterministic CBOR per RFC 8949 §4.2.1; map keys sorted lex).
7. Sign with `M_priv` to produce `challenge_sig` (64-byte raw `r || s` P-256 ECDSA).
8. URL-encode each field, render the QR.
9. Print the QR alongside the same fingerprint string the owner iPhone will display, exactly as derived in `contracts/fingerprint-derivation.md`.

The signed challenge cryptographically binds `m_pub`, `nonce`, `hostname`, `platform`. Any tampering of those four fields in the printed QR — by a malicious printer, a QR overlay, or any in-path mutation — invalidates the signature, and the owner iPhone refuses the QR before the owner ever sees a confirmation prompt.

The `transport` and `addr` fields are NOT covered by the signature because they are informational hints used only for reachability probes; their tampering can produce at most a denial-of-service (the iPhone or M1 fails to reach the indicated address) but never a confused-deputy or substitution attack.

## Consumer (Soyeht iPhone app)

1. Parse the URI; verify `v=1`.
2. Decode every field; reject the QR with a generic UX failure if any field is missing, malformed, or fails its individual validation rule below.
3. Reconstruct canonical CBOR `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}`.
4. Verify `challenge_sig` against `m_pub` over the reconstructed `JoinChallenge`. If verification fails, reject the QR with a generic UX failure ("This QR is not valid"). The iPhone never reaches M1 with a tampered QR.
5. Compute the 6-word BIP-39 fingerprint locally over `m_pub` per `contracts/fingerprint-derivation.md`. This is what the owner sees on the iPhone's confirmation prompt.
6. Build the deterministic CBOR `JoinRequest` (per `data-model.md`) reusing the QR's `m_pub`, `nonce`, `hostname`, `platform`, `addr`, `transport`, and `challenge_sig` fields verbatim.
7. POST the CBOR `JoinRequest` to **the household's founding machine M1**'s `POST /api/v1/household/join-request` over Tailscale, authenticated by Soyeht-PoP from the owner PersonCert. Do not connect to `addr`; the iPhone's only network hop is to M1.

## Validation rules (per field)

- `v` must be exactly `1`. Any other value: reject the QR.
- `m_pub` must decode as a valid SEC1 P-256 point (33 bytes, `02`/`03` prefix).
- `nonce` must be exactly 32 bytes after base64url decode.
- `hostname` must be 1..=64 UTF-8 bytes after percent-decode.
- `platform` must be exactly one of `macos`, `linux-nix`, `linux-other`.
- `transport` must be exactly one of `tailscale` or `lan`.
- `challenge_sig` must be exactly 64 bytes after base64url decode.
- `anchor_secret` must be exactly 32 bytes after base64url decode.
- `ttl` must be in the future; an expired QR is rejected.

## Single-use

The `nonce` is single-use server-side at M1: a `JoinRequest` carrying it can be admitted at most once into a `staging` window. Subsequent submissions within the join window TTL hit the replay path (R7); subsequent submissions after TTL hit the generic-CBOR-401 path (R14).

## Story 2 reuse

The same signed `JoinRequest` (assembled by M2 at install time and stored in `pair_machine_window.cbor`) is what M2's `local/seed` endpoint serves to M1 in Story 2 (R5). Stories 1 and 2 therefore deliver byte-equivalent `JoinRequest`s to M1; the only difference is who fetches/forwards the bytes (iPhone in Story 1, M1 itself in Story 2).
