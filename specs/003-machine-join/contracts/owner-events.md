# Contract: Owner events long-poll, owner approval, and opaque APNS

## `GET /api/v1/household/owner-events?since=<cursor>`

Long-polled stream of `OwnerEvent`s targeting the owner.

### Authentication

Soyeht-PoP under the owner PersonCert. Replay window: ±60 s as elsewhere.

### Request

- Query parameter `since`: base64url-no-pad of CBOR-encoded uint cursor; `0` (zero) on first poll. The iPhone treats this opaquely.
- No request body.

### Response

- `200 OK`, `Content-Type: application/cbor`, body = `OwnerEventsResponse = {v=1, events: [OwnerEvent...], next_cursor: uint}`. The `events` array contains one or more `OwnerEvent`s with `cursor > since`. `next_cursor` is the highest cursor returned (used as the next `since`).
- `204 No Content` after server-side timeout (45 s by default, configurable but ≤ 60 s) with no body and no cursor change.
- `401 Unauthorized` with `Content-Type: application/cbor` and body deterministic CBOR `{v=1, error="unauthenticated"}` for any failure (R14, FR-019a). No oracle differentiation between "bad PoP" and "owner not found".

### Server behaviour

`tokio::select!` over (a) `broadcast::Receiver<OwnerEvent>` filtered by `cursor > since`, (b) `tokio::time::sleep(timeout)`, (c) request cancellation. Catch-up: on entry, if `cursor_head > since`, return immediately with all events `cursor_head ≥ cursor > since`.

### Per-event signature verification (client-side)

The iPhone MUST verify each event's `signature` against the issuer's MachineCert chained to household root before treating its `payload` as authoritative. In Phase 3 the issuer is always M1, but the verification logic generalizes for Phase 4+.

## `POST /api/v1/household/owner-events/<cursor>/approve`

Owner submits the biometric-gated approval for a pending `join-request` event.

### Authentication

Soyeht-PoP under the owner PersonCert.

### Request

- Path parameter `<cursor>`: the cursor of the event being approved (must equal the active `PairMachineWindow.owner_event_cursor`).
- Content-Type: `application/cbor`
- Body: deterministic CBOR `OwnerApproval = {v=1, cursor, approval_sig}` where `approval_sig` covers canonical CBOR of `OwnerApprovalContext = {v=1, purpose="owner-approve-join", hh_id, p_id, cursor, challenge_sig, timestamp}` per `data-model.md`. The `challenge_sig` field carries the **candidate's** install-time signature verbatim from the `JoinRequest` the owner is approving — its bit-equality with `PairMachineWindow.cached_join_request.challenge_sig` provides the transitive ceremony binding, so there is no `m_pub_being_joined` field (it would be redundant).

### Response

- `200 OK`, `Content-Type: application/cbor`, body = `OwnerApprovalAck = {v=1, machine_cert_hash: bytes(32)}` after the 2PC commits. The hash is for the iPhone to record in its own owner-events history.
- `401 Unauthorized` with body `{v=1, error="unauthenticated"}` for any failure before M1 launches `local/finalize`, or for a definitive M2 reject such as a generic non-2xx finalize response. The iPhone's UX shows a generic "approval could not be confirmed" and the operator on M2 sees the ceremony abort on the candidate side.
- `500 Internal Server Error` with body `{v=1, error="internal"}` for any ambiguous post-send finalize outcome or post-FinalizeAck failure on M1 (`local/finalize` transport/read/ack-decode failure after the POST may have reached M2, `txn.commit()` failure on M1 disk after M2 has acked, in-memory window update failure, owner-events log append failure). Rationale: once M1 cannot prove whether M2 committed, rolling back on M1 or returning 401 can create a worse split-brain (M2 committed, M1 rolled back) than surfacing the partial-commit honestly. The 500 surface tells the iPhone client: "the ceremony is in an indeterminate state — surface a 'sync may be incomplete; will reconcile' notice to the owner, do NOT auto-retry the approve, and let the next long-poll observe the post-commit `OwnerEvent{type=machine-joined}`". M1's `.staged` files and the finalize intent marker are preserved for boot-time recovery (T073/T074).

### State effects

On success the ceremony advances per R6 phases A → B → C. A `OwnerEvent{type=machine-joined}` is appended at the end. On definitive internal failure during phases A or B, an `OwnerEvent{type=join-cancelled, reason=...}` is appended. Ambiguous post-send failures and Phase-C (post-FinalizeAck) failures are recorded only via tracing::error and the preserved `.staged` files; they do not append a join-cancelled event because the household may already have joined on M2.

## `POST /api/v1/household/owner-events/<cursor>/decline`

Owner declines the pending event. Body is empty. Authentication identical.

- `200 OK` with body `OwnerDeclineAck = {v=1}`.
- Internally: `PairMachineWindow → aborted`, `OwnerEvent{type=join-cancelled, reason=declined}` appended.

## Opaque APNS dispatch (server-side only; not a client-facing endpoint)

Triggered by the broadcaster when a new `OwnerEvent` is published and no long-poll connection is currently held by the owner device.

- Apple endpoint: `https://api.push.apple.com/3/device/<push_token_hex>` (or sandbox during dev).
- HTTP/2 headers:
  - `apns-push-type: background`
  - `apns-priority: 5`
  - `apns-topic: <Soyeht iPhone bundle id>` (configured at build time)
  - `apns-expiration: <now + 300>`
- Body: **exactly** `{"aps":{"content-available":1}}` UTF-8 JSON. No other fields beyond `aps.content-available: 1`. No `alert`, no `sound`, no `badge`, no `mutable-content`, no `category`, no household-derived bytes. The `aps.content-available` envelope is required by Apple's silent-push spec — the iPhone will not wake a backgrounded app for any other shape, so the earlier `{"v":1}` body satisfied opacity but never woke the long-poll re-poller.

### Audit and lint (three-layer enforcement)

The Constitution III "no household metadata reaches the push provider" property is enforced **structurally**, not by reviewer vigilance:

1. **Compile-time API shape**: `apns_dispatcher` declares `pub const APNS_TICKLE_BODY: &[u8] = b"{\"aps\":{\"content-available\":1}}";` and `pub async fn dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError>` as its only payload-producing surface. A `const _: fn(&OwnerDevicePushToken) -> _ = dispatch_tickle;` assertion in the same file makes any signature change a build error. The dispatcher cannot accept event-typed, fingerprint-typed, or `m_*`-typed parameters because no such parameters exist on its public function.
2. **Runtime test**: `admin/rust/server-rs/tests/apns_dispatcher_payload.rs` injects a spy `ApnsTransport`, drives a happy-path ceremony, captures every body the dispatcher serializes, and asserts byte-equality to `APNS_TICKLE_BODY`. Any drift fails CI.
3. **Source-level lint**: `admin/rust/scripts/lint-apns-payload.sh` greps `admin/rust/server-rs/src/apns_dispatcher.rs` for forbidden body sources — any `format!`, `serde_json::json!`, `serde_json::to_vec`, `Vec::from`, `Vec::extend_from_slice` with non-constant input, or any byte/string literal in the file other than the declared `APNS_TICKLE_BODY` constant. A second pass rejects any `pub` item beyond the declared `dispatch_tickle`, `ApnsError`, the `ApnsTransport` trait, and `APNS_TICKLE_BODY`; the regex covers every `pub`-item kind Rust admits (`use`, `static`, `mod`, `type`, `union`, `extern`, `crate`, `unsafe` in addition to the obvious ones). Any match fails the build. The lint runs as a dedicated step in `.github/workflows/backend-ci.yml` so it gates every PR alongside `cargo build`/`cargo test`/`cargo clippy`.

The three layers are independent: a payload change has to pass an API-shape break OR a test failure OR a lint failure to slip through. All three would have to be subverted in the same PR for a leak to land.

## Push token registration

`POST /api/v1/household/owner-device/push-token` — see `contracts/push-token-register.md`.
