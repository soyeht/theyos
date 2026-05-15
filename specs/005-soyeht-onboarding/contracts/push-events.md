# Contract: APNs push events from engine to owner iPhone

Per spec 005-soyeht-onboarding research.md R11 (APNs architecture) and cross-team alignment 2026-05-09.

## Purpose

Engine-emitted Apple Push Notifications to the owner iPhone for household lifecycle events. v1 of this contract covers a single event (`house_created`) used in the scenario B onboarding flow. Forward-extensible to future events (`device_added`, `member_left`, `household_recovering`, etc.) without breaking on-wire format.

## Why this exists

scenario B onboarding flow has the iPhone in foreground at install time, but **the iPhone may be backgrounded or locked** between the moment it AirDrops Soyeht.dmg to the Mac and the moment the Mac engine completes `/bootstrap/initialize`. Without an APNs push, the user has to come back to the app manually and the UX feels disconnected. With an APNs push, the iPhone surfaces a notification *"Maple Home is ready - tap to continue"* and the user is back in the flow with one tap.

scenario A does NOT need this — both devices are foreground + same Tailnet + Bonjour discovery is instant + reliable. Adding an APNs round-trip would add ~500ms-2s latency unnecessarily.

## v1 scope

This contract v1 covers exactly ONE event:

- **`house_created`** — emitted when engine processes `POST /bootstrap/initialize` successfully AND has a pending setup invitation with `iphone_apns_token` populated (i.e., this is a scenario B install).

Future events (NOT in this contract v1, reserved for future expansion):
- `device_added` — new personal device joined the household
- `member_left` — member machine revoked
- `household_recovering` — recovery flow initiated
- `pair_machine_request` — owner needs to approve a candidate-machine join

## Authority

- Engine (theyos): emits the push by signing with the bundled provider key (.p8) and POSTing to APNs gateway. Owns the event taxonomy, payload shape, and emit timing.
- iPhone (iSoyehtTerm): receives push via APNs, parses payload, surfaces notification, navigates to appropriate UI on tap. Owns rendering + dispatch.

## APNs envelope (aps dictionary, standard)

```json
{
  "aps": {
    "alert": {
      "title-loc-key": "house_created_title",
      "loc-key": "house_created_body",
      "loc-args": ["<hh_name>"]
    },
    "sound": "house-created.caf",
    "mutable-content": 1,
    "interruption-level": "active",
    "thread-id": "house-events"
  },
  "soyeht": {
    "v": 1,
    "type": "house_created",
    "hh_id": "<base32 hh_<...>>",
    "hh_name": "<utf8 ≤64>",
    "machine_id": "<base32 m_<...>>",
    "machine_label": "<utf8 ≤32, e.g. 'Developer Mac'>",
    "pair_qr_uri": "<utf8, fallback URI if iPhone Bonjour discovery fails>",
    "ts": <uint unix seconds>
  }
}
```

**Encoding notes:**
- The `aps` dictionary follows Apple's canonical structure (https://developer.apple.com/documentation/usernotifications/setting-up-a-remote-notification-server/generating-a-remote-notification).
- The `soyeht` custom payload is JSON within the same APNs JSON envelope (NOT separate CBOR — APNs payload is JSON-only on the wire, max 4KB total).
- `mutable-content: 1` enables iOS Notification Service Extension to mutate the notification before display (e.g., download avatar emoji + colorize).
- `thread-id: "house-events"` groups all household lifecycle events into one thread in Notification Center.
- Localization keys (`house_created_title`, `house_created_body`) live in iSoyehtTerm Localizable.xcstrings — engine emits keys, iPhone localizes per user locale (15 languages per FR-027a).

**Payload size budget:**
- aps section: ~200 bytes
- soyeht section: hh_id (45) + hh_name (≤64) + machine_id (45) + machine_label (≤32) + pair_qr_uri (≤200) + ts (10) + overhead ≈ 400-500 bytes
- Total well under 4KB APNs limit.

## Trigger conditions (engine-side)

Engine emits `house_created` push **iff ALL of:**

1. State transition `ready_for_naming → named_awaiting_pair` just happened (i.e., `POST /bootstrap/initialize` succeeded).
2. Pending setup invitation exists in `household-state-pending/setup-invitation.cbor` AND its `iphone_apns_token` field is non-empty.
3. APNs delivery infrastructure is available (`.p8` cert loaded, network online).

Otherwise: no push (this is scenario A — Bonjour discovery handles it).

After push is dispatched (regardless of APNs gateway success/failure), engine deletes the setup invitation cache (single-use enforcement). If APNs gateway returns retriable error, engine retries with exponential backoff up to 30s, then gives up silently — Bonjour discovery is the fallback path even in scenario B.

## Setup-invitation contract update (`setup-invitation.md`)

The `ClaimSetupInvitationRequest` shape adds an `iphone_apns_token` field:

```cbor
ClaimSetupInvitationRequest = {
  "v":                  1,
  "token":              bstr(.size 32),       ; setup invitation token
  "iphone_apns_token":  bstr(.size 32),       ; APNs device token (optional in v1; required if scenario B + APNs available)
}
```

Field is optional in CBOR (nullable). When absent, engine treats scenario B as Bonjour-only (no push); when present, engine persists it and uses it for `house_created` push delivery later.

## Engine-side persistence

Setup invitation cache extended:

```cbor
SetupInvitation = {
  "v":                  1,
  "token":              bstr(.size 32),
  "iphone_endpoint":    tstr,
  "iphone_apns_token":  bstr(.size 32),       ; new field
  "claimed_at":         uint,
  "expires_at":         uint,
}
```

Persisted in `household-state-pending/setup-invitation.cbor` (encrypted at rest if state dir is encrypted; otherwise mode `0o600`).

## APNs gateway interaction

Engine uses HTTP/2 to `api.push.apple.com` (production) or `api.development.push.apple.com` (development; selected by entitlement). JWT-based auth with the bundled `.p8` key (per research.md R11).

Header `apns-topic: com.soyeht.app` (matches iOS app bundle ID — verified via `PRODUCT_BUNDLE_IDENTIFIER` in iSoyehtTerm Xcode project).
Header `apns-push-type: alert`.
Header `apns-priority: 10` (immediate delivery for user-visible alerts).

Engine retries on 5xx or network failure with exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap). On 4xx (token invalid, payload too big), abort retry and log `tracing::warn!(stage = "apns.house_created.failed", reason = "<error_class>")` — falls back to Bonjour-only flow gracefully.

## iPhone-side handling (authority: iSoyehtTerm)

Per iSoyehtTerm T066 (APNsTokenRegistrar) + T067 (HouseCreatedPushHandler):
- T066 registers for APNs at app launch (UNUserNotificationCenter.requestAuthorization), persists device token, includes it in `_soyeht-setup._tcp.` Bonjour TXT or in the `claim-setup-invitation` callback verify response.
- T067 receives push, runs Notification Service Extension to fetch+render avatar, surfaces notification with thread-id "house-events", navigates to onboarding-completion screen on tap.

## Security model

- The `house_created` push is informational only — does NOT carry secret material. The `pair_qr_uri` field IS sensitive but its inclusion is intentional: the iPhone will use it as fallback if Bonjour discovery fails after the push. The `pair_qr_uri` includes the `anchor_secret` necessary for `local/anchor` POST. Risk: APNs operator (Apple) can see the push payload in transit.
- Mitigation v1: accepted risk. APNs payload is encrypted in transit (TLS) and Apple commits not to inspect/store custom payloads (https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns).
- Future hardening (v2): encrypt the `soyeht` section using a per-household AEAD key derived from `hh_priv` + iPhone's `D_pub`, decrypt in Notification Service Extension. Documented in `docs/household-protocol.md` §Push Delivery for revisit.

## Tests

- Contract: payload shape (JSON schema), aps envelope correctness, payload size <4KB.
- Integration: end-to-end `bootstrap/initialize` scenario B with mocked APNs gateway, asserts push dispatched with correct payload + retries on 5xx + drops on 4xx.
- Cross-language fixture: a fixed `(hh_id, hh_name, machine_id, machine_label, pair_qr_uri, ts)` tuple → expected JSON payload byte-equal across Rust generator and Swift consumer parser. Future: bind into `tests/fixtures/house_created_push.json`.

## Backward compatibility / forward extension

- Adding new event types (`device_added`, etc.) is additive: new `type` value, new payload fields, no breaking change to existing parsers (which dispatch on `type`).
- Setup-invitation `iphone_apns_token` field is optional — older iPhones (pre-spec-005) without APNs registration capability degrade to Bonjour-only scenario B. No regression.
- v1 → v2 upgrade path (encrypted payload, future): `v: 2` with a new field; clients that see `v >= 2` use new decryption path; clients pinned to `v: 1` skip silently. No flag-day migration needed.
