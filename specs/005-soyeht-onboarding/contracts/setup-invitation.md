# Contract: Setup Invitation (scenario B handshake)

Per spec FR-005 and FR-013.

## Purpose

Coordinate the iPhone-first install flow (scenario B) where Soyeht iPhone helps install Soyeht on a Mac the user is about to onboard. Solves the chicken-and-egg: when the Mac engine is fresh, it needs to know "this install was started-by-iPhone" so the UX can pull `name your household` to the iPhone instead of the Mac, and so the engine can defer naming until the iPhone signals ready.

## Components

1. **Bonjour service `_soyeht-setup._tcp.`** — published by Soyeht iPhone while waiting for the Mac to join.
2. **`POST /bootstrap/claim-setup-invitation`** — endpoint on Mac engine to claim the invitation token after install.

## Beacon timing (scenario B AirDrop flow) — post-alignment

The iPhone MUST publish `_soyeht-setup._tcp.` Bonjour beacon **BEFORE** dispatching `UIActivityViewController` AirDrop. Sequence:

1. iPhone mints token (32 random bytes), TTL 1h.
2. iPhone publishes beacon with token in TXT.
3. iPhone displays AirDrop sheet (`UIActivityViewController`).
4. Mac receives Soyeht.dmg; user drags to Applications.
5. SoyehtMac on first launch browses `_soyeht-setup._tcp.` (already alive); claims with token; engine validates via callback.
6. Beacon withdrawn on successful claim OR TTL expiry.

**Reasoning (Apple-grade UX):** if beacon is published only AFTER AirDrop succeeds, there is a race where the Mac finishes install fast and the SoyehtMac browse for the beacon fires before iPhone has it published — falls back to QR even on the happy path. Beacon-first eliminates this race; TTL bounds resource usage if AirDrop never succeeds.

## Tailnet-required for `/bootstrap/initialize` after claim — post-alignment

After Mac engine accepts `claim-setup-invitation`, the subsequent `POST /bootstrap/initialize` from the iPhone (carrying the casa name) MUST come over Tailnet. Engine refuses initialize on plain LAN (returns 403 with body `{v:1, error:"tailnet_required"}`). The iPhone's Soyeht client app uses NWConnection over the Mac's Tailnet IP (resolved from Bonjour) for this hop. Discovery via LAN bruta (opt-in) does NOT enable initialize via LAN bruta — user MUST be on Tailnet for the actual write operation.

## Bonjour service: `_soyeht-setup._tcp.`

### Publisher (Soyeht iPhone)

Published when user completes the carrossel and selects "Tenho um Mac aqui". Token TTL 1 hour. Service withdrawn after Mac claims OR TTL expires.

TXT record contents:

| Key | Type | Description |
|-----|------|-------------|
| `v` | uint | Always `1` |
| `token` | base64url no-pad | 32 bytes CSPRNG, identifier of this invitation |
| `hh_id` | tstr or empty | Optional. Set if iPhone already has a casa (advanced flow: iPhone helps Mac join existing casa). Empty for "fresh casa starting from iPhone" |
| `owner_display_name` | tstr | iPhone owner's display name (from iCloud first-name if available, otherwise empty) |
| `created_at` | uint | Unix seconds when token minted |
| `expires_at` | uint | Unix seconds; `created_at + 3600` |
| `port` | uint | Port iPhone is listening on for callback verification |

Service hostname: `iphone-soyeht-setup-<random6>.local.` (random suffix to avoid collisions if multiple iPhones publishing).

### Browser (Mac engine)

The Mac engine, on boot in state `uninitialized`, browses `_soyeht-setup._tcp.` on the local Bonjour domain. If found, it stores discovered tokens in memory (no persistence; expire when iPhone unpublishes or TTL passes).

When SoyehtMac.app on the same Mac POSTs `/bootstrap/claim-setup-invitation` with a token, engine validates the token came from a Bonjour-discovered iPhone before treating the install as iPhone-initiated.

## Endpoint: `POST /bootstrap/claim-setup-invitation`

### Purpose

Mark the engine as "iniciado-pelo-iPhone" and bind the install to a specific iPhone via the token.

### Preconditions

Engine MUST be in state `uninitialized`. Calling in any other state → 409.

### Wire shape

#### Request

```
POST /bootstrap/claim-setup-invitation HTTP/1.1
Host: 127.0.0.1:8091
Content-Type: application/cbor

ClaimSetupInvitationRequest = {
  "v":                  1,
  "token":              bstr(.size 32),       ; the 32 random bytes from the Bonjour TXT
  "iphone_apns_token":  bstr(.size 32),       ; OPTIONAL — APNs device token of the originating iPhone
                                              ; If present, engine persists for house_created push delivery
                                              ; (see contracts/push-events.md). If absent, scenario B falls
                                              ; back to Bonjour-only flow (no push).
}
```

No auth required at this endpoint level — the engine validates the token by calling back to the iPhone via the Bonjour-discovered hostname.

#### Success response

```
HTTP/1.1 200 OK
Content-Type: application/cbor

ClaimSetupInvitationAck = {
  "v":                  1,
  "iphone_endpoint":    tstr,            ; "<host>.local.:<port>" — for follow-up calls
  "owner_display_name": tstr,            ; from TXT record
  "hh_id":              tstr or null,    ; null if iPhone is bringing a new casa; non-null if joining existing casa
}
```

After this response, the engine in `uninitialized` state stays there but is "marked": `/bootstrap/initialize` calls will be expected to come from the iPhone (validated via Tailnet IP source check).

#### Failure responses

- **400 Bad Request** — invalid CBOR or token bytes wrong size. Body: `{v:1, error:"invalid_request"}`.
- **401 Unauthorized** — token not found in Bonjour cache, or callback verification to iPhone failed. Body: `{v:1, error:"invitation_not_recognized"}`.
- **404 Not Found** — token expired (TTL passed) or iPhone unpublished service. Body: `{v:1, error:"invitation_expired"}`.
- **409 Conflict** — engine already initialized. Body: `{v:1, error:"already_initialized"}`.

### Engine-side processing order

1. **State gate** — engine in `uninitialized`. Otherwise 409.
2. **Token shape check** — 32 bytes. Otherwise 400.
3. **Bonjour cache lookup** — token must match a recently-discovered `_soyeht-setup._tcp.` advertisement. Otherwise 401.
4. **TTL check** — `now < expires_at` from the cached TXT. Otherwise 404.
5. **Callback verify** — engine sends a verification ping to the iPhone's published endpoint (`<hostname>.local:<port>/setup/verify`) carrying `{token}` and expects 200 with the same token echoed back (proof iPhone still considers this token valid). Otherwise 401.
6. **Mark engine** — persist `household-state-pending/setup-invitation.cbor` with token + iphone_endpoint. This is read by the next `/bootstrap/initialize` call to enforce caller-IP validation.
7. **Return** — `ClaimSetupInvitationAck`.

### Effect on `/bootstrap/initialize`

When the engine has a pending setup invitation, `/bootstrap/initialize` adds an extra check:
- Source IP of the request MUST be within Tailnet ranges (100.64.0.0/10 or fc00::/7 per RFC 4193 — includes Tailscale's fd7a:115c:a1e0::/48 subset).
- Source IP MUST match the iPhone's address. Resolution order:
  1. If `iphone_endpoint` hostname ends in `.local`, attempt OS-level mDNS resolution
     (`tokio::net::lookup_host`) with a 3-second timeout.
  2. If resolution succeeds, check resolved addresses first.
  3. Fall back to the `iphone_addrs` list captured at claim time if resolution fails or times out.
  4. Non-`.local` hostnames skip live resolution entirely (prevents attacker-controlled DNS targets).
- Otherwise 403 Forbidden (the iPhone reserved this engine; another caller can't hijack).

## Verification callback: `POST <iphone>/setup/verify`

iPhone publishes a tiny HTTP endpoint on the same port advertised in Bonjour TXT, bound to localhost AND to the Tailnet interface. Endpoint accepts:

```
POST /setup/verify HTTP/1.1
Content-Type: application/cbor

VerifyRequest = {
  "v":     1,
  "token": bstr(.size 32),
}
```

Returns `200` with `{v:1, token: <same bytes>, hh_id: tstr or null, owner_display_name: tstr}` if the token is still valid in iPhone's view; `404` otherwise.

iPhone-side, this endpoint is an in-memory map of token → state; cleared on app background after 1h TTL.

## Tests

- Contract: shapes, sanitize.
- Integration: full scenario B flow end-to-end (iPhone publishes, Mac engine browses + claims, iPhone verifies, ack).
- Integration: replay protection — same token claimed twice → second 409 (consumed).
- Integration: TTL expiry — token expires after 1h.
- Integration: hijack attempt — different IP tries `/bootstrap/initialize` after invitation marked → 403.
