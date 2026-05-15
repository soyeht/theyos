# Contract: `GET /pair-machine/anchor-handoff`

Per spec FR-006 and FR-018.

## Status

**MVP for spec 005-soyeht-onboarding** (promoted from "future enhancement" via cross-team alignment 2026-05-09). This endpoint is the path of 95%+ of pair-machine flows in the wild (per SC-007). QR scan is the fallback for cases where Tailnet trust isn't established (rare).

## Purpose

Eliminate QR scan in the Phase 3 machine-join flow when both candidate and owner-iPhone are on the same Tailnet. The endpoint delivers the candidate's `anchor_secret` (Phase 3 protocol §11/§12) directly to the owner-iPhone, gated by Tailscale ACL trust. With this in hand, the iPhone can POST `local/anchor` to the candidate (Phase 3 contract `local-anchor.md`) without the user ever having to scan the QR.

This also resolves the iSoyehtTerm Phase 3 implementation gap (the `local/anchor` POST was never implemented in the iOS app — see hardware-walkthrough memory). With anchor-handoff, the iOS-side call is internal orchestration, not user-visible.

## Tailnet-required (post-alignment 2026-05-09)

Pair-machine operations (anchor-handoff, `/bootstrap/initialize`, `local/anchor` POST) are **Tailnet-required**. There is NO HTTP plain fallback in LAN bruta. If caller is not in Tailnet IP ranges, endpoint returns **403** with body `{v:1, error:"tailnet_required"}` and human-readable message *"Pra adicionar máquinas, ative Tailscale na sua rede"*. LAN bruta discovery (opt-in via Settings) allows users to **see** other casas in the local network but NOT to join them or be joined by them. Discovery (read-only) and pareamento (write) have different security boundaries.

**Threat model**: see `theyos/docs/household-protocol.md` §"Threat Model: anchor-handoff Tailnet trust boundary" for full attacker analysis (compromised tailnet member, Tailscale ACL misconfig, biometric Face ID as defense-in-depth, comparison with QR scan path security).

## Preconditions

- Candidate engine MUST have an active `pair_machine_window` (state `Staging` or `AwaitingOwner`). Otherwise 404.
- Caller MUST be on the same Tailnet as the candidate. The endpoint validates source IP belongs to `100.64.0.0/10` (Tailnet CGNAT range) or `fd7a:115c:a1e0::/48` (Tailnet IPv6 range). Otherwise 403.

## Wire shape

### Request

```
GET /pair-machine/anchor-handoff HTTP/1.1
Host: <candidate-tailnet-ip>:8091
Accept: application/cbor
```

No body. No auth header beyond the implicit Tailnet ACL (Tailscale's authenticated identity layer is the auth — the request only reaches us if the caller is in our tailnet).

### Success response

```
HTTP/1.1 200 OK
Content-Type: application/cbor
Cache-Control: no-store

AnchorHandoffResponse = {
  "v":             1,
  "m_pub":         bstr(.size 33),       ; SEC1-compressed P-256 — candidate's machine public key
  "nonce":         bstr(.size 32),       ; the JoinRequest nonce
  "anchor_secret": bstr(.size 32),       ; the QR-equivalent secret
  "fingerprint":   tstr,                 ; 6-emoji-word security code (FR-025)
  "expires_at":    uint,                 ; unix seconds — pair_machine_window expiry
}
```

The response is **only** sent if the engine has an active pair-machine window. Otherwise:

### Failure responses

- **403 Forbidden** — source IP not in Tailnet ranges. Body: `{v:1, error:"not_in_tailnet"}`.
- **404 Not Found** — no active pair_machine_window. Body: `{v:1, error:"no_active_pair_machine"}`.
- **410 Gone** — pair_machine_window expired or terminated. Body: `{v:1, error:"window_terminated"}`.

## Engine-side processing order

1. **Source IP check** — request originating IP ∈ Tailnet ranges (`100.64.0.0/10` or `fd7a:115c:a1e0::/48`). Otherwise 403.
2. **Window load** — `pair_machine_window.load_active()`. If none, 404.
3. **Window state check** — state ∈ {`Staging`, `AwaitingOwner`}. Otherwise 410.
4. **Compute fingerprint** — derive 6 emoji-word security code from `(m_pub, nonce, hostname)` via `BIP39 wordlist → emoji mapping` (deterministic; both Rust engine and Swift client use the same lookup table, see `emoji-security-code-wordlist.csv`).
5. **Build response** — populate fields from window state.
6. **Return** — `AnchorHandoffResponse`.

## Caller-side flow (iPhone — anchor-handoff client)

```swift
// In Soyeht iOS app (TerminalApp/Soyeht/Pairing/AnchorHandoffClient.swift)

func attemptAutoPair(candidateTailnetURL: URL, hh: Household) async throws {
    // 1. Fetch handoff response over Tailscale
    let response = try await httpGet(candidateTailnetURL.appending(path: "pair-machine/anchor-handoff"))
    let handoff = try CBORDecoder.decode(AnchorHandoffResponse.self, from: response)

    // 2. Verify fingerprint matches what we'll show to user
    let displayCode = EmojiSecurityCode.from(mPub: handoff.mPub, nonce: handoff.nonce)

    // 3. Show user "Adicionar Linux à Sample Home?" with displayCode
    let approved = try await BiometricGate.confirm(
        prompt: "Adicionar máquina à \(hh.name)?",
        secondaryDisplay: displayCode
    )
    guard approved else { throw PairError.userDeclined }

    // 4. POST local/anchor to candidate (resolves Story 2 gap)
    let anchorBody = LocalAnchor(
        v: 1,
        anchorSecret: handoff.anchorSecret,
        hhId: hh.id,
        hhPub: hh.pubKey
    )
    try await httpPostCBOR(
        candidateTailnetURL.appending(path: "pair-machine/local/anchor"),
        body: CBOREncoder.encode(anchorBody)
    )

    // 5. POST owner-event approve to founder (existing Phase 3 flow)
    try await ownerEventClient.approve(
        machineId: handoff.mPub.toMId(),
        hhId: hh.id
    )

    // 6. Wait for finalize confirmation event (existing Phase 3 flow)
    try await waitForCommit(timeout: 30)
}
```

## Security model

- **Why Tailnet ACL is sufficient**: The fact that the request reached the engine over the Tailnet is itself a capability proof. Tailscale issues device-bound certs; only authenticated tailnet members can route to the engine's Tailnet IP. The candidate's pair-machine window is also only minted in response to user explicitly running install — meaning the casa owner *intentionally* set up this candidate machine and added it to their tailnet. There is no "open to the internet" exposure for this endpoint.
- **Why this is not a downgrade from QR-scan**: The QR-scan path's security is "user verified the BIP-39 fingerprint matches between Mac and iPhone screens, proving the Mac the iPhone is talking to is the one they set up". With Tailnet ACL, the analogous proof is "user explicitly added this Mac to their tailnet". Both are user-mediated trust. The fingerprint is still computed and shown to the user as the secondary check (defense in depth).
- **What an attacker on the Tailnet could do**: Steal `anchor_secret`. Mitigation: the user MUST still confirm with biometric on the iPhone before the `local/anchor` POST goes through. Stealing `anchor_secret` alone is useless without the user's biometric approval. Comparable to "stealing the QR code" in the QR scan flow — same threat profile.

## Backward compatibility

- Phase 3 protocol unchanged on the candidate side except for adding this new endpoint. `local/anchor` POST contract is unchanged (per `local-anchor.md`).
- iOS clients that don't support anchor-handoff still work via the QR scan fallback (Phase 3 contract original path).
- Older candidate engines without this endpoint return 404 to the iPhone's GET; iPhone falls back to QR scan UX.

## Tests

- Contract: response shape, fingerprint determinism.
- Integration: end-to-end anchor-handoff over a real (or simulated) Tailnet between two engines + an iPhone client.
- Integration: 403 when caller is not in Tailnet range.
- Integration: 404 when no pair_machine_window.
- Integration: window state transitions correctly after handoff (handoff doesn't terminate the window; only `local/finalize` does).
- Integration: emoji-security-code byte-for-byte match between Rust and Swift implementations (cross-language test asset).
