# Soyeht Share — Apple-like Product and Code Quality Plan

Status: **APPROVED** — decisions **D1–D6** closed, the relay architecture study
consolidated in §7.5, and no divergence outstanding. Implementation may proceed
from this document.
**Amended after the first approval:** D6 rewrote the Share's identity authority
(§5.1), replaced two unproducible acceptance criteria (§7.1), and widened Slice B to
a store migration. Earlier revisions are preserved in repository history and are
superseded — build from **this** revision, not an earlier plan revision.
Agreed architecture: **Tokio/epoll, always-relay, S0 as the gate, S1 buffers, S2
splice only if needed, io_uring and direct-first conditional on measured triggers.**
**Cost acceptance remains a measured rollout gate**, not an agreement: §7.4 is
closed only by recorded measurements. S0 establishes the baseline-relay capacity
evidence required by §7.5; it does not by itself turn every modelled §7.4 number
into evidence. Both run before rollout, not before implementation.
Relay infrastructure: the **designated project relay** is the baseline — a blind
public relay already validated by remote Dev E2E. Infrastructure access, local
worktree locations, device identifiers, and evidence-storage locations are not
recorded in this public plan. Keep those materials in access-controlled run records.

## 1. Outcome

Turn the working remote Soyeht Share proof into a coherent first product:

> An owner selects one running app, chooses how long to share it, and sends a
> private invitation. The guest sees who shared which app, opens it remotely,
> recovers from ordinary failures, and loses access immediately when the share
> expires or is revoked. Neither person sees transport, host, VM, relay, or
> credential implementation details.

The existing public blind relay, Noise session, Device + ClawSite authorization,
OpenPersistent session reuse, replay protection, byte budgets, and reopen limiter
remain the transport/security foundation. This cycle improves product correctness,
identity, routing, lifecycle, observability, maintainability, and iOS experience.

## 2. Explicit non-goals

This cycle does **not** include:

- personal LLM credential delegation or LLM billing;
- custom domains, public URLs, browser/WASM guests, or public publishing;
- Product A/nvpn, ClawShareBridge, or any mesh dependency;
- PTY or IpTunnel behavior changes;
- WebSocket, SSE, streaming media, large-file transfer, or multiplexed streams;
- multi-region, anycast, high availability, or a second relay;
- production Soyeht state, the production engine, or any legacy test household.

## 3. Baseline that must remain true

1. The guest can use a Device + ClawSite invite over 5G while the owner is on a
   different network.
2. Payload remains end-to-end protected; the public relay sees rendezvous metadata
   and ciphertext, not application plaintext.
3. One authenticated Noise connection supports multiple sequential HTTP exchanges.
4. Revocation and expiry are enforced at the endpoint by a live gate polled every
   `REVOKE_POLL_INTERVAL` (500 ms, `claw_share_data_tunnel.rs`) **and** on every
   inbound Data frame. A clock that cannot be trusted revokes.
   *Ordering caveat:* "before every new persistent target open" is the intended
   property but is not separately pinned today — the poll makes it true in practice.
   §7.1 must pin the ordering with a test rather than inherit it from the interval.
5. The relay fails closed at consumed-table capacity and never evicts live evidence
   (`mark_consumed` returns `false` instead of evicting; `consumed_has_capacity` +
   `mark_consumed` are one atomic `&mut self` section; `offer_would_park` mirrors
   the rejection before any per-source permit is acquired).
6. Session budgets remain `PERSISTENT_MAX_TARGET_OPENS = 128` and
   `PERSISTENT_MAX_BYTES_PER_DIRECTION = 64 MiB` unless a separately reviewed
   contract changes them.
7. The public relay byte cap remains a backstop **strictly greater** than the
   endpoint budget. Measured today: relay default 72 MiB
   (`DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION`) > endpoint 64 MiB. This
   ordering is currently **correct but unenforced** — it is an env-var
   (`THEYOS_RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION`) away from
   inverting, which is why §6.1 makes it a validated invariant rather than a
   convention.
8. Non-ClawSite Device resources remain in the legacy single-target path.

Any implementation that weakens one of these properties is a regression even when
the happy-path UI still renders.

**Status honesty:** items 1–3, 5, 6, 8 are measured true at the baseline SHAs.
Item 7 is true by value but not by mechanism. Item 4 is true by mechanism with the
ordering caveat noted. Nothing in this section may be cited as proven without the
matching test in §7.

## 4. Product principles

“Apple-like” in this plan means:

- **Intent first:** people choose an app and a duration — not a host, VM, relay,
  resource enum, or URL transport. **There is deliberately no recipient step**: the
  product hands the owner a link and lets them send it through whatever channel they
  already use, and whoever opens it first takes the slot. (This principle originally
  read "an app, a recipient/context, and a duration"; no recipient step exists in
  §5.2 or in the shipped flow, and adding one would change the product from
  "send a link" to "invite a person" — a different feature with a different identity
  model. If that is wanted, it needs its own decision, not a principle bullet.)
- **Stable identity:** display names and icons may change; authorization and routing
  use stable identifiers.
- **Truthful provenance:** the guest can tell which owner shared which app and until
  when.
- **Safe lifecycle:** every active share is visible, expirable, and revocable.
- **Recovery is part of the design:** common failures have human language and a next
  action.
- **Progressive disclosure:** raw links, diagnostics, and transport details live
  behind a secondary Details surface, not in the primary flow.
- **Native behavior:** system share sheet, Dynamic Type, VoiceOver, localization,
  reduced-motion compatibility, and standard navigation/state restoration.

## 5. Required product contract

### 5.1 Stable app identity and routing

Introduce one cross-repository app descriptor. Exact type names may change during
review, but the information and authority must not:

```text
ShareableAppDescriptor {
  app_id          stable opaque identifier, never display name
  claw_id         stable authorized claw identifier
  display_name    mutable presentation string
  resource        ClawSite for this cycle
  readiness       running | starting | stopped | unavailable
}
```

> **DECISION D6 — CLOSED: the Share owns its own
> identity authority, in a dedicated persisted binding.**
>
> **Why this was forced.** `instance_create.rs:543` builds
> `instance_id = format!("inst-{name}")` — the instance id **is the name with a
> prefix**, so it satisfies neither "opaque" nor "independent of display". And
> `instances.name` is `UNIQUE` with **no rename operation anywhere**, so the two
> approved acceptance criteria — two apps sharing a display name, and rename
> preserving routing — were **not producible by the product**. Testing them would
> have required fixtures staging a capability that does not exist: a test that goes
> green over a fiction.
>
> **Measured mitigation, and why it does not save us.** Delete+recreate under the
> same name is **not reachable through the product API today**: the delete path is
> soft (`handlers_instances.rs:665-667`), the only non-test caller of the hard
> `delete()` is the create-rollback at `instance_create.rs:89`, and `name TEXT
> UNIQUE NOT NULL` is a full-column constraint, so a soft-deleted row keeps
> occupying its name. But that protection is **incidental** — it falls out of an
> audit-history decision, not a designed control. Two ordinary future commits
> destroy it: a GC that purges old soft-deleted rows, or relaxing `UNIQUE` to a
> partial index so owners can reuse names of deleted apps (a likely product
> request). An opaque `app_id` converts an accidental property into a designed one.
> This is why it is fixed now and not deferred behind the 24 h invite TTL: TTL
> bounds how long a crossed authority lasts, not whether it is acceptable.
>
> **The shape.** A dedicated `shareable_apps` binding — a **table, not columns on
> `instances`** — because the binding must be able to outlive its instance and be
> *terminal* relative to it, which a column cannot express (it dies with the row or
> is revived with it).
>
> **Minimum schema — pinned, so implementation is not handed the ambiguity back:**
>
> ```sql
> CREATE TABLE shareable_apps (
>   app_id       TEXT PRIMARY KEY,   -- "app_" + 32 hex (128 bits CSPRNG)
>   instance_id  TEXT NOT NULL,      -- binding to instances.id
>   household_id TEXT NOT NULL,      -- scope; never NULL, never backfilled unscoped
>   display_name TEXT NOT NULL,      -- mutable, non-unique, nonempty, length-bounded
>   resource     TEXT NOT NULL,      -- "clawsite" this cycle
>   retired_at   INTEGER,            -- tombstone; NULL = live. Terminal.
>   created_at   INTEGER NOT NULL,
>   updated_at   INTEGER NOT NULL
> );
>
> -- One LIVE binding per instance; retired rows are exempt, so a tombstone
> -- never blocks a fresh binding and a fresh binding never revives a tombstone.
> CREATE UNIQUE INDEX ux_shareable_apps_live_instance
>   ON shareable_apps(instance_id) WHERE retired_at IS NULL;
>
> CREATE INDEX ix_shareable_apps_household ON shareable_apps(household_id);
> ```
>
> - `app_id` format is **pinned**: `app_` + 32 lowercase hex characters = 128 bits
>   from a CSPRNG. Immutable; delete+recreate yields a different one. Not derived
>   from any name. (Entropy is for uniqueness and non-reuse, not secrecy — see
>   below; do not inflate it, and do not treat it as a capability.)
> - `display_name` is **mutable, non-unique**, its own authority, validated
>   **nonempty and length-bounded**.
> - `host_port` is **NOT copied here.** It stays in `instances` and is read by a
>   **live join** — it is runtime readiness, not identity, and duplicating it would
>   create a second source of truth that goes stale (§A2's two failure classes).
> - `instances.name` stays `UNIQUE` as the technical slug. **No existing constraint
>   is weakened.**
>
> **Hard delete is not permitted to run beside a live binding.** The operation
> **fails** when a non-retired binding exists, unless the tombstone is written
> **atomically in the same transaction**. There is no bare delete path: either the
> binding is already retired, or retiring it is part of the same transaction, or the
> delete is refused. This is what keeps `ensure` from ever meeting an orphaned live
> binding whose instance is gone.
>
> **Lifecycle rules — each closes a specific hole:**
>
> 1. **`ensure` must never revive a tombstoned binding.** The chain is
>    `app_id → instance_id → app`, and the middle link is the reusable
>    `inst-{name}`. An opaque `app_id` is defeated if its binding can be
>    resurrected by a new instance taking the old id. A tombstone is terminal;
>    `ensure` mints a **new** `app_id` instead of returning a dead one.
> 2. **`ensure` sets `display_name` only when it creates the binding.** It must
>    **never** re-sync from `instances.name` afterwards — otherwise re-running the
>    picker or a mint silently overwrites a rename.
> 3. **A real `rename_shareable_app(app_id, household_id, new_display_name)`** must
>    exist, household-scoped and fail-closed. This is what makes the acceptance
>    criteria honest: the same-name test creates two instances with different
>    technical slugs and renames both bindings to the same display name; the rename
>    test uses this operation and proves `app_id` and routing intact.
> 4. **Tombstoning is atomic with removal, on the removal paths that actually
>    exist — and there are exactly two.** Enumerated in production code:
>    - `instance_db::soft_delete` — the product delete. It has **two entry
>      points**: the HTTP handler (`handlers_instances.rs:667`, reached by both
>      the admin and household routes) and the store IPC surface
>      (`store_ipc.rs:487` → `db.soft_delete(id)`).
>    - `instance_db::delete` — the hard delete, whose only non-test caller is the
>      create-rollback at `instance_create.rs:89`.
>
>    Transaction shape:
>    `soft_delete` tx = update the instance row **+ retire the binding**;
>    hard-delete tx = **retire the binding** + delete invites + delete the
>    instance.
>
>    **The transaction must live inside the store functions, not in the HTTP
>    handler.** Putting it in `handlers_instances` would leave the `store_ipc`
>    entry point deleting an instance while its binding stays live — the exact
>    orphan rule 1 forbids. Two callers, one chokepoint.
>
>    **There is no `unpair` path.** An earlier revision listed one; that was a
>    word collision — every `unpair` in this codebase means an *unpaired
>    rendezvous stream* in the relay, and none of those modules touch
>    `instance_db`. No household leave/reset/remove-machine operation removes
>    instances either. A lifecycle promise naming an operation that does not
>    exist cannot be violated, so it cannot be tested: it reads as coverage
>    while asserting nothing.
> 5. **Re-pair is a scope change, and scope is the invariant.** Since no unpair
>    operation exists, the real hazard is a machine re-paired into a *different*
>    household while its instance rows survive. Three rules, all testable today:
>    - **resolve requires a household match.** A binding whose `household_id`
>      differs from the authenticated caller's fails as **foreign** — terminal,
>      not "unknown", and never a readiness state.
>    - **`ensure` detects a live binding belonging to a different household**,
>      retires it, and mints a **new** `app_id`. It must never re-scope a binding
>      in place: that would silently carry an outstanding invite across a
>      household boundary, which is the crossed authority D6 exists to prevent.
>    - outstanding invites for the retired `app_id` therefore fail closed after a
>      re-pair, by construction rather than by cleanup.
> 6. **Backfill runs AFTER household bootstrap**, or skips `household_id IS NULL`
>    rows. `seed_mac_host_instance` runs at `main.rs:226` and
>    `bootstrap_household` at `main.rs:317`, so rows are born unscoped; a startup
>    backfill would mint `app_id`s bound to rows the resolver then rejects —
>    reproducing an already-fixed empty-picker class.
>
> **Resolver: two failure classes that must never merge.** Strict lookup for a
> household-scoped, non-tombstoned, ClawSite binding, joined live to `host_port`.
> - **Identity** failures — unknown, foreign, deleted `app_id` — are **terminal,
>   fail-closed**.
> - **Readiness** failures — no `host_port`, stopped — are **recoverable
>   unavailable**, per D1. Folding them together would make a starting app
>   indistinguishable from a deleted one and hand the guest a terminal message for
>   a transient condition.
>
> **`app_id` is not a secret.** It is random for uniqueness and non-reuse, not for
> secrecy: the offer is owner-signed and slot-bound, so guessing an `app_id` buys
> nothing. Stated so nobody treats it as a capability and skips a check, and so
> nobody over-engineers its entropy.
>
> **Presentation is a signed snapshot.** Outstanding invites keep the
> `display_name` from mint time; new shares carry the updated name. Consequence to
> honour in the UI: Active Shares shows the **current** name while the guest sees
> the **snapshot**, and they will differ after a rename — by design. A rename
> cannot retract a name already sent.
>
> **Scope fence.** `offer.claw_id = app_id` applies to **Device + ClawSite only**.
> Group and Public stay **entirely** in the legacy name namespace this cycle,
> because `claw_id` is a live foreign key there — `group.granted_claws.get(claw_id)`
> and `is_claw_published(claw_id)`, polled every 500 ms by the live gate. **No half
> migration, and never two namespaces inside one gate**: that is what would turn a
> fail-closed availability break into a revoke bypass.
>
> **The split is closed by internal types, not by convention.** Mint and resolver
> APIs take `DeviceShareAppId` or `LegacyClawId` — never a bare `String`. The wire
> field stays `claw_id: String` for compatibility, and conversion to `String`
> happens **only at the signed edge**. No call site accepts an ambiguous raw string,
> so crossing the namespaces is a compile error rather than a runtime mismatch.
> Fail-closed by type beats fail-closed by decision.

> **DECISION D3 — CLOSED: no icon this cycle.**
> `icon` is **removed** from the descriptor — it is neither a requirement nor an
> authority here. The engine's instance records carry name and status, not
> iconography, so a descriptor field would have been stubbed silently during
> implementation. The UI renders a **generic local symbol** and must not present it
> as the app's authoritative iconography. An icon catalogue/manifest authority is a
> **separate follow-up**, deliberately deferred. Zero silent stubs.

**What is already true, and what is actually being added.** The signed
`RelayStreamOfferPayload` already binds `claw_id`, `slot_id`, `guest_device_pub`,
`resource`, `not_after` and `claw_static_pub`. So "binds the `ClawSite` resource"
is **already satisfied** — the addition in this cycle is a *stable app identity*
distinct from the display name, plus per-app backend resolution.

**Wire-compatibility technique is mandatory, not optional.** Any new field in the
signed payload MUST follow the `authz` precedent in
`claw_share_relay_stream_contract.rs`: `#[serde(default, skip_serializing_if =
"Option::is_none")]`, so an offer that omits it produces canonical CBOR
byte-identical to today's. The offer payload CBOR is embedded in the Noise
prologue and covered by the owner signature — a naive additive field silently
invalidates every existing signature and every cross-language fixture. This is the
single highest-risk edit in the cycle.

**Sibling problem, same change:** `resource` is bound in the offer but *chosen* at
mint time from a process-global environment value, not per app (open task: "thread
resource kind through invite minting"). Per-app backend resolution and per-app
resource selection are the same defect seen twice; solving one without the other
leaves the product path still globally configured.

Requirements:

- The iOS picker identifies rows by `app_id`, not `instance.name`.
- The signed offer binds the stable app identity additively, per the technique above.
- The engine resolves the signed identity to the correct private backend.
- The product path must not route every app to one global, process-wide ClawSite
  backend setting.
- A display-name change must not invalidate a share or route it to another app.
- Duplicate display names must be harmless.
- Unknown, deleted, foreign-household, or non-ClawSite targets fail closed before
  application bytes are opened.

The development environment may retain an explicit single-backend fixture for
focused tests, but it must be named and gated as a fixture, not silently used as the
product router.

### 5.2 Owner flow

Primary flow:

1. Select one shareable app — **running or not**, per decision D1 below.
2. Choose duration using human language.
3. Create the invitation once.
4. Present the system share sheet immediately.

> **DECISION D1 — CLOSED: warn-and-allow.**
> A stopped or unavailable app **may** be shared. Minting is permitted with an
> explicit owner-facing warning; the guest receives the designed *recoverable*
> unavailable state until the app comes up.
> Rationale: the link represents **future authorization until expiry**, so gating
> it on a readiness snapshot is the wrong semantics — a 24-hour link is a bet on
> the future and the owner is better placed to make it than the picker is. This
> preserves the shipped reasoning already documented in `ShareAppViewModel.swift`
> ("Blocking the share here would be guessing about the future on the owner's
> behalf") and is made honest by the guest-side unavailable state in §5.4.
> An earlier line in this plan required "running and shareable"; that requirement
> is **withdrawn**.
> Tests must pin: mint permitted for a stopped app, owner warning shown, and guest
> recovery once the app starts. A hard-gate test would now be a regression.

Presentation requirements:

- Use the app display name and a generic local symbol (D3 — no authoritative icon
  this cycle).
- Expiry must include the day when needed, or use an unambiguous relative form such
  as “Tomorrow at 5:00 PM”. A 24-hour invitation must never show only the same clock
  time with no date.
- Do not show the bearer link as the primary content. Provide Copy Link and Details
  as secondary actions.
- A stopped/unavailable app is shareable (D1) but must never be presented **as if
  ready**: state the condition plainly at mint time and say what the guest will see
  until the app starts.
- Prevent duplicate minting while a request is in flight.

### 5.3 Active shares and revocation

The owner surface uses `GET /api/v1/claw-share/shares` and
`POST /api/v1/claw-share/revoke`, alongside the existing mint and claim routes.
The listing reads durable slot projection state; it is not a presence gauge.

> **DECISION D2 — CLOSED: no live presence this
> cycle.** The list shows exactly these states, each from one named authority:
>
> | UI status | authority | kind |
> |---|---|---|
> | **Waiting** | `SlotState::Open` | persisted |
> | **Accepted** + `accepted_at` | `SlotState::Consumed { consumed_at }` | persisted |
> | **Expired** | `not_after` vs clock | derived, not stored |
> | **Revoked** | `SlotState::Revoked { revoked_at }` | persisted |
> | **App unavailable** | instance readiness | separate condition, not a share status |
>
> **`Consumed` must NEVER be rendered as a live connection.** It means the slot was
> claimed once, not that a guest is connected now — showing it as "active" would
> present a guest who closed the app days ago as present, the exact lie §4's
> truthful-provenance principle forbids. **No new presence gauge is introduced.**
> Live session state exists only in the responder, does not survive an engine
> restart, and is out of scope this cycle.
>
> "App unavailable" is a *separate condition* rendered alongside the share status,
> not a fifth mutually-exclusive value: a Waiting share for a stopped app is both
> Waiting and unavailable (D1).

`SlotState` has exactly three variants — `Open`,
`Consumed { guest_device_pub, consumed_at }`, `Revoked { revoked_at }` — which is
why Expired is derived and why no status above requires new persisted state.

**Guest identity: show the event, never the key.** The only guest identity the
protocol holds is a raw P256 public key (`Consumed { guest_device_pub }`), and this
section also forbids presenting raw keys. Both hold once the presentation is
specified: render *that* a device accepted and *when* — "Accepted · today 14:32" —
and never the key itself. A human-readable guest name would be a new protocol field
and is not in this cycle.

The owner needs one native Active Shares surface containing:

- app display name (generic local symbol only — see D3);
- creation and expiry;
- status, per the D2 authority table;
- whether the invitation has been accepted, and when — never the guest's key;
- Copy Link only while meaningful;
- Stop Sharing as a destructive, confirmed action.

Revocation requirements:

- Revocation is idempotent.
- A revoked share cannot reconnect or open another target.
- An open persistent session stops within the existing live-gate bound. The
  mechanism is `REVOKE_POLL_INTERVAL = 500 ms` plus a check on every inbound Data
  frame, so the 1 second acceptance target has ~500 ms of headroom and is a real
  bound rather than a wish. If the poll interval ever changes, this number must
  change with it — state the interval, not just the target.
- UI converges to the authoritative state after relaunch or another device acts.
- No raw slot, credential, key, or relay token is presented to the owner.

### 5.4 Guest flow

> **DEPENDENCY — owner provenance is not local polish.** The signed
> `RelayStreamOfferPayload` carries **no owner display identity**: its fields are
> `v, kind, rendezvous_token, claw_id, slot_id, guest_device_pub, resource,
> expected_path, relay_endpoint, claw_static_pub, not_after, authz`. The guest can
> today prove *which key* signed (`claw_static_pub`, and the credential's
> `ownerPublicKey`), but a human-readable "Shared by <owner>" does not exist on the
> wire. Showing it therefore requires an additive signed field under §5.1's
> compatibility technique — it is **Slice B work, not Slice A**. Slice A must not
> claim it. (Icon is settled separately by D3: none this cycle, generic symbol.)

Before opening, show:

- app name, with a generic local symbol (D3);
- owner provenance at whatever fidelity the wire actually carries — until Slice B
  adds a display name, that is verified-key provenance;
- expiry in unambiguous language;
- a short privacy statement;
- one primary Open action.

Inside the shared app:

- Show the real app identity and “Shared by <owner>”.
- Do not show `Mac Host`, `[shared app]`, relay endpoints, VM names, or transport
  vocabulary in the normal chrome.
- Preserve in-page navigation and state across SwiftUI updates. Do not reload the
  root merely because `webView.url` changed during valid app navigation.
- Keep the non-persistent web data store unless a separately reviewed requirement
  needs persistence.

Failure states must map technical causes to stable product errors:

- owner/app offline;
- invitation expired;
- invitation already consumed when applicable;
- access revoked;
- temporary connection failure;
- incompatible/outdated client;
- app unavailable.

Every recoverable state offers an appropriate next action: Retry, Ask for a New
Link, or Close. Raw `localizedDescription` is diagnostics-only.

## 6. Code-quality work

### 6.1 Relay invariants

- Add a test/config validation that guarantees
  `public_relay_byte_cap > endpoint_session_byte_budget` for the deployed ClawSite
  configuration. A lower relay cap must fail configuration rather than turn a typed
  endpoint error into an opaque hard close.
- Make the uncapped `splice_opaque_streams` private to its tests or remove it if it
  remains unused. The production API should make the safe path the natural path.
- Remove `live_evictions` if no implementation can write it. Tests should prove
  no-live-eviction through behavior and structure, not a permanently-zero decorative
  counter.
- Preserve separate direction counters and hard-close behavior at the byte cap.

### 6.2 Telemetry

- Count forwarded bytes when a splice ends through `IdleTimedOut` or
  `LifetimeElapsed`, not only through normal close or byte-cap exhaustion.
- Keep enforcement independent from telemetry.
- Add focused tests with non-zero bytes for normal close, idle timeout, lifetime
  expiry, and both byte-cap directions.
- Status fields must distinguish cumulative counters from live gauges in naming or
  documentation (`paired_sessions` is cumulative; `active_connections` is live).

### 6.3 Persistent client lifecycle

Resolve the four known persistent-client debts:

1. Correct the stale comment that asks a caller to drain an acknowledgement already
   drained internally.
2. Make `send_close` check-and-write atomic in the Rust API, rather than relying only
   on Swift actor serialization.
3. Close the cancellation handoff race that can open an orphan target for a caller
   cancelled at slot transfer.
4. Restore and test the intended legacy writer lifetime after Close; persistent
   behavior must not silently change legacy behavior.

### 6.4 Protocol and module boundaries

- Establish one authoritative definition for `OpenPersistent` and its wire value,
  consumed by Rust and Swift through generation or a pinned shared contract test.
> **DECISION D4 — CLOSED: the cheap 80%, and
> that is the final commitment.** Cross-repository compatibility is covered by
> exactly three things, all of which fit inside this cycle:
> 1. a **pinned fixture of the offer payload's canonical CBOR** — this is what
>    directly catches the §5.1 signature-breaking risk;
> 2. **additive preservation** via `serde` `default` + `skip_serializing_if =
>    "Option::is_none"`, so an omitted field encodes byte-identically;
> 3. **fail-closed on an unknown frame** byte.
>
> **No sizing spike and no legacy-binary matrix this cycle.** Building and running
> old binaries on both sides has no precedent in this repo and was the plan's
> largest hidden cost; it is deliberately out of scope, not merely unscheduled.
- Propose, but **do not perform**, a module layout that separates rendezvous
  admission, public listener/splice, endpoint authorization, persistent session,
  routing, and status. The deliverable this cycle is the written proposal.
  Performing the extraction requires its own authorization and its own
  behavior-unchanged evidence; it is explicitly **not** in Slice D.
- Correct stale ClawSite comments that still describe the endpoint as a placeholder.

### 6.5 Cost and scale discipline

> **DECISION D5 — CLOSED: Share must stay cheap at
> thousands of users.** Stated as invariants, not as a promise about a number:

1. **The relay VPS stays blind and stateless.** No database, no durable storage, no
   per-user state. Its whole memory is the in-process pending/consumed tables, which
   are bounded and expire.
2. **No managed dependency and no per-user cost** is introduced this cycle. Adding a
   priced-per-seat or priced-per-request service would make user count a cost driver
   by construction.
3. **Cost is governed by bytes and concurrency, never by registered users.** A
   registered user who is not connected costs nothing: there is no row, no session,
   no poll. Users enter the cost model only through the sessions they open and the
   bytes those sessions move.
4. **Active-share state lives in the owner/engine authority, never on the VPS.**
   This is already implied by §5.3's authority table — `SlotState` is the engine's.
   Putting share state on the relay would create exactly the per-user durable state
   invariant 1 forbids.
5. **Caps and content-free logs are preserved.** The per-direction byte cap, the
   session budgets, the reopen limiter and the abuse buckets are the cost controls;
   removing one to "simplify" is a cost regression. Logs stay free of payload
   content — the relay cannot read it and must not start.
6. **Upgrades happen on a measured trigger, never on a forecast** — see §7.4.
7. **No HA and no multi-region** (already in §2 non-goals). The existing Linode is
   the real baseline and the only relay.

**Why this is credible rather than hopeful:** the measured shared page is 5,887 B,
so a session costs roughly 8 KiB with Noise and framing. Bandwidth is therefore not
the binding constraint at any plausible near-term scale — **concurrency is**. The
live ceilings are `max_active_connections = 2048` and `max_pending = 1024`, with
`idle_timeout = 300 s` and `splice_lifetime = 3600 s` bounding how long a slot is
held. Note that 2048 counts **connections**, and a paired session takes two, so the
pair ceiling is ~1,024 (§7.4). That is the number to watch, and §7.4 measures it
instead of assuming it.

**Sources for the cost and architecture positions** (primary where available):
[Akamai/Linode São Paulo pricing](https://www.akamai.com/cloud/pricing/sao-paulo) ·
[splice(2)](https://man7.org/linux/man-pages/man2/splice.2.html) ·
[pipe(7)](https://man7.org/linux/man-pages/man7/pipe.7.html) ·
[LWN — pipe page allocation](https://lwn.net/Articles/1079784/) ·
[tokio `copy_bidirectional`](https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html) ·
[tokio-uring](https://docs.rs/tokio-uring/latest/tokio_uring/) ·
[arXiv:2512.04859 — io_uring for DBMSs](https://arxiv.org/abs/2512.04859) ·
[Apache Iggy — thread-per-core + io_uring](https://iggy.apache.org/blogs/2026/02/27/thread-per-core_io_uring/) ·
[oss-security — 42 Linux kernel exploits](https://www.openwall.com/lists/oss-security/2023/06/17/2) ·
arXiv:2604.12484 (hole punching, ACM IMC 2026) ·
DOI 10.1109/CISCE69494.2026.11504706 (splice in ATS, IEEE CISCE 2026; the cited
result is treated as contextual research, with corroborating older TCP-splice proxy
literature noted in §7.5).

## 7. Verification contract

### 7.1 Server-focused tests

- **Same display name** (D6): create two instances with **different technical
  slugs**, rename both bindings to the **same** `display_name` via
  `rename_shareable_app`, and prove each `app_id` routes to its own backend. This
  replaces an earlier criterion that was **not producible** — `instances.name` is
  `UNIQUE`, so "two same-named apps" could only ever have been staged by a fixture.
- **Rename preserves authorization and routing** (D6): exercise the real
  `rename_shareable_app` operation and prove `app_id`, outstanding authorization,
  and routing are all intact afterwards. Previously untestable: no rename operation
  existed anywhere in the product.
- **`ensure` never re-syncs a renamed binding**: after a rename, re-running the
  picker/mint path must leave `display_name` unchanged.
- **Delete+recreate fails closed** (D6): tombstone the binding, recreate an instance
  that reuses the same technical slug, and prove the old `app_id` no longer
  resolves and that `ensure` mints a **new** one rather than reviving the tombstone.
- **Identity vs readiness stay distinct**: unknown / foreign / deleted / retired
  `app_id` fails **terminal** before backend allocation; a valid binding with no
  `host_port` or a stopped instance resolves as **recoverable unavailable** (D1).
  A test that collapses these into one outcome is a regression.
- **Tombstoning is atomic on both real removal paths**: `instance_db::soft_delete`
  (exercised through **both** entry points — the HTTP handler and the `store_ipc`
  surface) and the create-rollback hard delete each leave no live binding. Assert
  the transaction is in the store function, not the handler: a test that only
  drives the HTTP route would pass while the IPC path orphans bindings.
- **Re-pair scope invariant (replaces the fictitious unpair criterion)**: with a
  binding live under household A, re-scope the machine to household B and prove
  (a) resolve fails **foreign/terminal** for the old `app_id`, (b) `ensure` retires
  the old binding and mints a **new** `app_id` rather than re-scoping in place, and
  (c) an invite outstanding against the old `app_id` fails closed.
- Revocation between persistent target opens rejects the next open. This test is
  what turns §3.4's ordering from "true because the 500 ms poll usually wins the
  race" into a pinned property — write it so it fails if the check moves after the
  open, not merely if revocation stops working.
- Relay cap ordering is validated: a configured relay cap **≤** the endpoint session
  budget fails configuration startup rather than degrading a typed
  `session-byte-budget-exhausted` into an opaque hard close.
- Idle/lifetime byte totals are preserved (non-zero in all four terminal paths).
- No uncapped production splice entry point remains.
- Active-share listing and status agree with authorization state, and every listed
  status is derived from the authority named in §5.3's table.
- A v1 offer with the new identity field omitted encodes byte-identically to the
  pinned baseline CBOR fixture.

### 7.2 iOS-focused tests

- Expiry: same day, next day, 24 hours, locale/time-zone boundary.
- Owner flow: one app, multiple apps, mint failure, duplicate tap, Copy Link,
  system share sheet.
- Stopped app (D1): mint **succeeds**, the owner warning is present, and the guest
  reaches the recoverable unavailable state — then recovers once the app starts.
  A test asserting mint is blocked is a regression, not coverage.
- Active shares (D2 vocabulary): Waiting, Accepted + `accepted_at`, Expired,
  Revoked, plus App-unavailable as a separate co-rendered condition; idempotent
  revoke. A test that renders `Consumed` as a live connection is a regression.
- Guest confirmation: owner/app identity, expiry, accessibility labels.
- Guest errors: every product error renders human copy and the correct action.
- Web view does not reload the root during valid in-page navigation or an unrelated
  SwiftUI render.
- Cancellation tests cover before registration, while queued, at handoff, and after
  target open.
- Dynamic Type, VoiceOver, and localization smoke coverage **scoped to the surfaces
  this cycle creates or changes** — the owner picker, share result, Active Shares,
  guest confirmation, and guest error states. An app-wide accessibility pass is
  unbounded work and is not what this cycle is buying; say so explicitly so it does
  not silently expand during implementation.

### 7.3 Integrated Dev E2E

Use only the designated Dev app, Dev profile, Dev engine, and iOS Dev build. Never
use or reset production state.

Run at least these scenarios on real devices/networks:

1. Owner on Wi-Fi, guest on 5G: create, accept, render, and perform at least two
   sequential app interactions in one persistent session.
2. Revoke while the guest app is open: current access closes within the bound and
   retry is denied with a human message.
3. Owner app offline/stopped: mint is prevented, or an already-issued share renders
   the designed unavailable state and later recovers.
4. Expired invitation: guest receives the designed terminal state.
5. Two different apps with the same display name route to their own backends.

Repeat the happy-path scenario three times with fresh invitations.

> **Instrument warning — the reopen limiter will eventually bite the tester.** The
> per-principal gate allows 8 authenticated connections per 60 s per
> `(claw_id, guest_device_pub)`. Three repeats on one guest device against one claw
> consume 3 of 8 and are safe. A future "repeat 10 times" run, or rapid retries
> during debugging, will hit `relay-stream-reopen-rate-exceeded` — which looks
> exactly like a product failure and is not one. Either space the runs past the 60 s
> window or record the limiter counter alongside the result, so a rate rejection is
> never misdiagnosed as a regression.

Preserve a dated evidence directory containing SHAs, environment identity,
screenshots, status JSON, and the event timeline. `active_connections` must return
to baseline; cumulative `paired_sessions` is not used as a leak gauge.

### 7.4 Cost acceptance before rollout (D5)

A rollout gate, measured on the **existing Linode**, not modelled from vendor
marketing. Every number below is currently **unknown and must be filled by
measurement** — this section is a protocol, not a claim.

**Measure (real sessions, not synthetic echo):**

- bytes per session, **p50 and p95**, per direction, from the splice counters —
  which requires §6.2's idle/lifetime telemetry to land first, or the tail is
  invisible;
- resident memory per `pending` entry and per `paired` session, from a run that
  fills the tables to a known depth;
- **sustainable concurrency** in **paired sessions** on the current instance — this
  is spike S0 in §7.5; do not duplicate the run, and record the number that held.

**Populations are four different numbers. Conflating them is marketing.**

- **Registered** — accounts that exist. Costs nothing: no row on the relay, no
  session, no poll (§6.5.3).
- **MAU** — a fraction of registered.
- **DAU** — a fraction of MAU. This is the first number that touches the relay.
- **Peak concurrent** — the only number the relay's ceilings actually constrain:

  `peak_concurrent = DAU × sessions_per_user_day × duration_s ÷ 86400 × peak_to_mean`

**Modelled scenarios.** Premises are stated so they can be attacked; the outputs are
arithmetic from them, **not measurements**. Replace P4/P5 with §7.4's measured values
before this table is used for any decision.

| premise | value | status |
|---|---|---|
| P1 MAU / registered | 40% | assumption |
| P2 DAU / MAU | 20% | assumption |
| P3 sessions / user / day | 2 | assumption |
| P4 mean session duration | 120 s | assumption — bounded above by `idle_timeout = 300 s` |
| P5 bytes p95 / session | 64 KiB | assumption, 8× the **measured** 5,887 B single-exchange page. **This is the TOTAL billable relay egress for one session, summing both directions** — guest→claw plus claw→guest — not 64 KiB per direction. If the intended premise were 64 KiB *per direction*, every egress figure below doubles. |
| P6 peak-to-mean | 5× | assumption |

**`max_active_connections = 2048` counts CONNECTIONS, not sessions.** Verified in
`claw_share_rendezvous_stream_relay_listener.rs`: the semaphore permit is acquired
immediately after **every** `listener.accept()` (`:182` → `:193`), and a pairing is
built from **two** accepted streams — Guest and Claw. So one paired session consumes
**~2 permits**:

- theoretical ceiling ≈ **1,024 paired sessions** per node, not 2,048;
- with the 2× headroom rule, the planable figure is **512 paired sessions** per node
  before any sustainable-capacity measurement.

Any text saying "2048 sessions" is wrong; it is 2048 connections ≈ 1024 pairs.

**Real regional cost — use São Paulo, not the global list price.** Nanode 1 GB in
São Paulo is **US$7.00/month** (1 vCPU, 1 GB RAM, 25 GB storage, 1 TB transfer,
40/1 Gbps), with transfer overage at **US$0.007/GB**.

**Cost formulas, so a scenario is costable rather than asserted:**

```
nodes  = ceil( peak_paired_sessions / (0.5 × sustainable_measured_pairs_per_node) )
egress = max(0, total_GB − pooled_allowance_GB) × US$0.007
```

`sustainable_measured_pairs_per_node` is **unknown until S0**. Until it is measured,
the placeholder fed into the formula is the **theoretical ceiling of 1,024 pairs**,
which the formula's own `0.5` factor turns into the **512-pair planable capacity**.
Do not feed 512 into the formula — applying the headroom twice would yield 256 and
silently triple the node count.

| registered | DAU | peak paired sessions | % of 1,024 pair ceiling | egress / month | nodes @512 | cost / month |
|---|---|---|---|---|---|---|
| 1 k | 80 | ~1 | 0.1% | ~0.3 GB | 1 | US$7 |
| 10 k | 800 | ~11 | 1.1% | ~3.1 GB | 1 | US$7 |
| 100 k | 8 k | ~111 | 10.8% | ~31 GB | 1 | US$7 |
| 1 M | 80 k | ~1,111 | **108.5%** | ~315 GB | **3** | **US$21** |

**Two load-bearing corrections of record.**
(1) An earlier revision called the 1 M row "inside 2× headroom, but only just" —
arithmetic error: 54.2% is above 50%, so it failed even on the wrong denominator.
(2) That denominator was itself wrong: counting connections rather than pairs
doubles the load. Corrected, **1 M under P1–P6 exceeds even the theoretical
single-node pair ceiling** (1,111 > 1,024) before headroom is considered. Under
P1–P6 roughly **460 k registered** is what one node carries within headroom.

**Every capacity number above is configured, not measured.** Sustainable capacity may
be lower, which moves every percentage up and every node count with it. No row may be
quoted as a capacity claim until S0 replaces the placeholder.

**The honest headline:** registered users are not the cost driver — concurrency and
bytes are (§6.5.3). 1 k–100 k sit comfortably on one US$7 instance. **1 M is not a
single-instance claim**; under these premises it is about three instances, ~US$21/mo,
and that remains conditional on measurement. Egress is not the binding constraint at
P5 = 64 KiB in any scenario — concurrency is.

**What falsifies it — name the premise, the movement, and the break:**

- **P4 duration.** At 30 min instead of 120 s, 1 M gives ~16,700 peak concurrent —
  **16.3× the 1,024-pair theoretical ceiling and 32.6× the 512-pair planable
  capacity** — that is ~33 nodes, not a tuning problem. (Stated in pairs on purpose:
  quoting it against 2048 mixes pairs with connections.) Session duration is the
  single most load-bearing
  premise, which means `idle_timeout` is a **cost control**, not hygiene. Raising it
  is a cost decision requiring this model to be re-run.
- **P5 bytes.** At 5 MiB/session (a media-ish app) 1 M gives ~23 TiB/month — tens of
  instances' worth of transfer. The 72 MiB relay cap and the 64 MiB session budget
  are what keep this bounded; they are cost controls too.
- **P1/P2 engagement.** These move the result linearly and are the least certain;
  they are also the least dangerous, because they scale the whole column together.

Require **2× headroom** against both included transfer and measured sustainable
capacity. A scenario needing more than half of either fails the gate. Under P1–P6
that gate is already decisive: 1 k–100 k pass on one node, and **1 M does not fit one
node at all** — it needs three by the table above. None of these rows has been
validated against *measured* sustainable capacity; that is what S0 exists for, and
the model must not be treated as evidence until it has run.

**Horizontal path — stateless sharding, if and only if a trigger fires.** "Possible
at 1 M" must mean a costable path, not a claim that one Nanode serves 1 M concurrent.
The path already exists in the protocol: the signed offer carries `relay_endpoint`,
so **the shard is chosen at mint time and baked into the signed offer**. Guest and
claw therefore always meet on the same relay with no runtime coordination, no shared
table, no consistent hashing, and no cross-shard state — each relay stays exactly as
blind and stateless as today (§6.5.1). Capacity scales by adding independent
instances and letting the mint distribute across them; cost scales linearly and is
estimable from the measured per-instance ceiling.
Accepted consequence, stated rather than hidden: losing one shard invalidates the
offers minted for it until they expire. The mitigation is short invite TTLs, **not**
HA or a second region (§2). This is a documented path, not scheduled work.

**Upgrade triggers — measured, never forecast:**

| signal | act on the measurement, not the projection |
|---|---|
| CPU | sustained utilisation past the level found above |
| RAM | working set approaching the measured per-entry budget × table caps |
| egress | monthly transfer past 50% of included |
| active connections | sustained `active_connections` past 50% of the measured sustainable ceiling **expressed in connections** — the same unit the gauge reports. Do not compare a connection gauge against a pair figure, and do not use `paired_sessions`: it is a cumulative counter, not a live gauge, so no paired-session gauge exists to trigger on. |

No upgrade is authorised by a growth forecast, a launch, or a projection. If a
trigger fires, the response is a bigger single instance — **not** HA, not a second
region, not anycast (§2).

### 7.5 Relay I/O architecture — decision and spikes

**Decision: keep Tokio/epoll and the current bounded copy loop as the baseline.**
No runtime change and no I/O-mechanism change is authorised from this document.
The justification is architectural, not a microbenchmark.

**What the cost actually is, per idle paired session** — likely dominated by
**2 sockets/FDs + kernel TCP buffers + the 300 s idle window**, not by copying a
small payload. One measured userspace component is already known:
`splice_opaque_streams_capped` allocates `2 × SPLICE_CHUNK = 32 KiB` **per splice,
i.e. per paired session**, eagerly, held for the whole session. Tokio's
`copy_bidirectional` uses `DEFAULT_BUF_SIZE = 8 KiB` in two buffers = 16 KiB per
pair. **The capped rewrite doubled per-pair userspace buffer memory**: +16 KiB per
paired session. At the ~1,024-pair ceiling that is 32 MiB today versus 16 MiB —
a **16 MiB** theoretical saving, ~1.6% of a 1 GB Nanode. Small, real, and cheap to
test; it is a cost regression introduced alongside a cost control, and the only I/O
change worth considering this cycle.

**io_uring — excluded this cycle as added risk with no measured benefit.** Stated
carefully, not as an axiom that io_uring is unsafe for any listener: our relay
process is trusted and a remote client never invokes io_uring directly. The reasons
are (a) **no measured benefit is in evidence** — "High-Performance DBMSs with
io_uring" (arXiv:2512.04859) finds naive replacement of epoll/libaio yields only
**1.06×–1.10×**, with real gains (2.05×) requiring a design built around batching
and registered buffers; Apache Iggy reports the same, that swapping Tokio is not
enough without thread-per-core plus batching and redesign; (b) our instance has
**1 vCPU**, so thread-per-core offers no structural advantage; (c) it carries
**additional kernel attack surface** — Google limited io_uring across ChromeOS,
Android and production servers after it accounted for ~60% of their VRP kernel
submissions, and CVEs continued into 2025–2026. Adopting Monoio, Glommio or
tokio-uring would be a concurrency-model rewrite, not a dependency swap.
*Revisit only if the Tokio baseline reaches >60% CPU before FD, RAM or egress
triggers fire.*

**splice(2) — a valid spike, NOT disqualified.** An earlier revision of this plan
claimed splice was ruled out because 4,096 pipes × 64 KiB would pin 256 MiB. That
was **too strong and is withdrawn**: pipe(7) describes *capacity and quota
accounting*, and pages are allocated as data is written, so idle pipes do not
necessarily hold their full capacity resident. The accurate concerns are narrower
and sufficient to require measurement rather than adoption:
- splice needs one end to be a pipe (`EINVAL` otherwise), so socket→socket needs a
  pipe pair: **4 extra FDs per paired session**;
- a pipe's default **64 KiB is logical capacity and quota accounting, not RSS already
  resident**; pages are allocated as data is written;
- `pipe-user-pages-soft` by default permits roughly **1,024 pipes at default
  capacity**, well below the ~4,096 a full node would want — though `F_SETPIPE_SZ`
  can shrink pipes (e.g. 2 pages) and change that arithmetic entirely;
- byte-cap accounting and telemetry become harder to keep exact across a pipe hop;
- and, decisively for now, **there is no measured bottleneck for it to relieve.**

There is real evidence splice helps *when throughput or CPU is the bottleneck*
(`Zero-Copy Proxy Tunneling via Linux Splice`, IEEE CISCE 2026,
DOI 10.1109/CISCE69494.2026.11504706 — ATS ~275→550 MB/s, −40–55% latency,
−20–30% CPU on AWS C6in, 5 KB–10 MB payloads). Corroborating older work reports
10–43% CPU reduction from TCP splice in web proxies. **None of that establishes a
gain for 1 vCPU with small, mostly-idle sessions**, which is our profile. Hence a
spike with kill criteria, not adoption.

**Spike shortlist — S0 can end the rest.** All variants must preserve the
per-direction cap, revoke teardown, rate limiting, fail-closed admission, and
zero payload logging.

| # | spike | metrics | kill criteria |
|---|---|---|---|
| **S0** | Realistic Nanode baseline: sustainable **paired** capacity | RSS, `ss -m` kernel socket memory, FD count, CPU, p95 added latency, at 1/100/500/1000 pairs | If 512 pairs hold with RSS < 50% and CPU < 30%, **no runtime or I/O work is justified** — S2/S3 close. Also replaces the placeholder in §7.4. |
| **S1** | Idle × buffer matrix: idle 30/60/120/300 s × buffer 4/8/16 KiB | **userspace bytes per paired session**, p95, CPU | Accept a buffer reduction if it saves ~16 KiB per pair with no material p95/CPU regression (>10%). **Do not** use "%RSS of the VPS" as the criterion — the whole theoretical saving is ~16 MiB at the 1,024-pair ceiling (~1.6% of RAM), so a ">5% RSS" gate is unsatisfiable by construction. |
| **S2** | splice(2) prototype, benchmarked on **our** workload (small + idle), with `F_SETPIPE_SZ` sizing | throughput, CPU, RSS/connection, FD count, cap+telemetry fidelity | Kill if CPU improves <15%, or RSS per connection worsens, or the byte cap/telemetry becomes harder to enforce, or p95 worsens. |
| **S3** | io_uring | — | **Only** if the Tokio baseline hits the CPU trigger (>60%) before FD/RAM/egress triggers. Otherwise not run. |
| **S4** | direct-first + invisible relay fallback | — | **Only** if measured egress exceeds 50% of the 1 TB allowance, or workloads grow materially. Otherwise not run. |

**Always-relay stands for this cycle**, and the reason is privacy rather than cost.
A direct path would reveal the owner's **residential IP to the guest**, contradicting
the product promise that a friend uses the app without entering the owner's home;
the blind relay keeps both ends mutually anonymous. The cost argument is weak in both
directions: hole punching succeeds **70% ± 7.1% and conditionally** (arXiv:2604.12484,
ACM IMC 2026 — 4.4 M attempts, 85 k networks, 167 countries; TCP and QUIC
statistically indistinguishable; 97.6% of successes on the first attempt), so the
relay must stay provisioned for the worst case regardless, and under the current model
the whole prize is roughly **US$21 → US$7/month at 1 M registered**. Stated as the
trade it is: we decline a real concurrency saving to avoid leaking the owner's IP.
Reopen only on the S4 trigger.

## 8. Proposed implementation ownership

Final ownership is assigned only after this draft reaches `APPROVED`.

- **Server product owner — routing and lifecycle:** stable app identity, per-app
  backend resolution **and per-app resource selection at mint**, active-share/revoke
  API (new routes — none exist today), focused server integration tests.
- **iOS product owner — product experience:** owner flow, active shares, guest confirmation,
  error/retry states, web-view state preservation, accessibility/UI tests.
- **Invariant owner — adversarial controls:** cap ordering, uncapped splice removal,
  `live_evictions` removal, revocation boundary **including the §3.4 ordering test**,
  authorization/routing review, negative and mutation controls.
- **Integration owner:** prevent file overlap, freeze candidate generations,
  cross-repository compatibility, Dev deployment, hardware E2E, evidence custody,
  and final acceptance.

**Gaps found in this division — assign before implementation:**

| unowned work | proposed owner | why |
|---|---|---|
| §6.2 telemetry (idle/lifetime bytes) | server product owner | server-side, not an invariant |
| §6.3 debts 1 & 4 (stale comment, legacy writer lifetime) | server product owner | Rust tunnel |
| §6.3 debts 2 & 3 (`send_close` atomicity, cancellation handoff) | invariant owner | concurrency correctness, needs adversarial interleaving review |
| §6.4 shared protocol contract / wire fixture | integration owner | spans both repos by definition |
| §6.4 module layout **proposal** | integration owner | needs the whole-system view |

**Real overlap that needs sequencing, not just declaration.** Sec's uncapped-splice
removal and the server telemetry work both edit the splice outcome types and
`claw_share_rendezvous_stream_relay{,_listener}.rs`. These are the same two files.
Sequence: **the invariant work lands first**, then the server owner adds telemetry
on the settled shape. Concurrent edits here will conflict on `SpliceCappedOutcome` /
`RendezvousSpliceOutcome`.

Before implementation, each owner must declare the exact files they intend to touch.
Overlapping files require explicit sequencing, not concurrent edits.

## 9. Delivery sequence

### Slice A — high-value polish, no protocol change

- unambiguous expiry;
- human guest errors + Retry;
- Copy Link + system share behavior;
- remove transport vocabulary from guest chrome (`Mac Host`, `[shared app]`,
  endpoints, VM names) and show the app name the wire already carries;
- owner warning for a stopped app (D1);
- stale comment corrections.

**Not in Slice A:** owner display name and icon in guest chrome — neither exists on
the wire (§5.4 dependency). Attempting them here forces either a protocol change
inside a "no protocol change" slice, or a fabricated value.

Exit, measured mechanically: the slice diff touches **zero** files under
`claw_share_relay_stream_*`, `claw_share_rendezvous_stream_*`,
`claw_share_data_tunnel.rs`, or the offer contract; iOS UI tests green.

### Slice B — stable app contract and correct backend

- **store migration: the `shareable_apps` binding table** (D6) — CSPRNG `app_id`,
  mutable non-unique `display_name`, household scope, terminal tombstone, partial
  index; plus lazy `ensure` (post-bootstrap, scoped rows only, sets `display_name`
  once), a real `rename_shareable_app`, and atomic tombstoning wired into
  `instance_db::soft_delete` and the create-rollback hard delete — inside the store
  functions, so the `store_ipc` entry point is covered too — plus the re-pair scope
  invariant (foreign resolve, retire-and-remint, never re-scope in place);
- **API surface** for listing and renaming, and the iOS picker bound to `app_id`;
- internal `DeviceShareAppId` / `LegacyClawId` types at the mint and resolver
  boundaries, with `String` only at the signed edge;
- stable app descriptor;
- additive signed app identity (§5.1 technique — `skip_serializing_if`, canonical
  CBOR byte-identical when omitted);
- per-app backend resolver **and** per-app resource selection at mint (the same
  defect twice — do not ship one without the other);
- owner display name on the wire (icon explicitly excluded — D3);
- guest-side recoverable unavailable state (D1);
- same-name and rename tests.

Exit: two bindings sharing one `display_name` route independently **through the real
rename operation, not a fixture**; delete+recreate of the same technical slug fails
closed with a fresh `app_id`; the global backend value is reachable only from an
explicitly named dev fixture; and a v1 offer with the new field omitted serialises
byte-identically to the baseline fixture.

### Slice C — lifecycle control

- active-share listing;
- revoke UI/API;
- authoritative state convergence;
- revoke-while-open E2E.

Exit: an owner can see and terminate every live share without terminal access.

### Slice D — hardening and maintainability

- cap-order invariant;
- remove/private uncapped splice;
- remove the write-less `live_evictions` counter;
- `SPLICE_CHUNK` 16 KiB → 8 KiB **behind S1's measurement** (§7.5) — this slice, not
  Slice A, because it touches transport;
- idle/lifetime telemetry;
- four persistent-client lifecycle debts;
- shared protocol contract per D4: pinned canonical-CBOR fixture, additive
  `default` + `skip_serializing_if` preservation, fail-closed unknown frame;
- module layout **proposal only** — no extraction in this slice (§6.4).

Exit: focused mutations prove the new tests detect removal of each invariant.

### Slice E — integrated acceptance

- compose one frozen server+iOS candidate;
- focused checks before expensive integrated gates;
- real-device five-scenario matrix;
- evidence and rollback notes;
- no production, custom-domain, or nvpn changes.

## 10. Approval checklist

Approved for implementation:

- [x] every user-visible state has a defined message and next action;
- [x] app identity and backend authority are unambiguous;
- [x] active-share listing and revocation semantics are complete (D2);
- [x] relay and endpoint budgets preserve typed errors (§3.7 + §6.1 invariant);
- [x] server/iOS protocol compatibility is testable (D4);
- [x] work ownership has no unsequenced file overlap (§8 gap table + sequencing);
- [x] all non-goals remain outside the implementation;
- [x] Dev-only test and evidence requirements are executable;
- [x] rollback/cleanup does not touch production state.

**Mechanical gates — these are checked, not judged:**

- [x] every §5.3 status maps to a named authority in the authority table — **D2**;
- [x] `icon` either has a named source of truth or is removed from §5.1 — **D3,
      removed**;
- [x] the legacy-compatibility scope has a final answer — **D4, cheap 80%, no
      spike, no legacy-binary matrix**;
- [x] the stopped-app behaviour has a rejection criterion — **D1, warn-and-allow**;
- [x] the §8 gap table is fully assigned, with splice sequencing agreed;
- [x] no §7 criterion lacks a rejection condition — for each test, what makes it
      **fail** is written down;
- [x] every claim in §3 either cites a constant/mechanism or is marked as a
      requirement rather than a measured fact;
- [x] cost invariants are stated as invariants, not as a promised number — **D5**;
- [ ] **§7.4 cost acceptance is executed on the existing Linode and its numbers
      recorded.** This is the one gate that cannot be closed by agreement — it
      requires measurement, and it runs before rollout, not before implementation.

## 11. Review history

Detailed attribution, local environment references, transient artifact identifiers, and
operational run notes are intentionally excluded from this public plan. Repository
history and access-controlled test records preserve that custody. The durable design
record is:

- Decisions D1–D6 closed the owner flow, lifecycle vocabulary, presentation scope,
  compatibility approach, cost discipline, and Share identity authority.
- The owner-facing share list and idempotent revoke endpoint use durable slot
  projection; readiness remains a separate runtime axis.
- The Share identity is a household-scoped, terminal binding rather than a display
  name or reusable instance identifier. Deletion and re-pairing retire the binding
  atomically and fail outstanding invitations closed.
- Public-relay admission remains enforcement-only; status remains observational.
  Relay limits, byte accounting, and revoke ordering require non-vacuous tests and
  mutation controls.
- The selected relay architecture is the bounded Tokio/epoll baseline. Further I/O
  work remains conditional on recorded capacity and cost triggers, never forecasts.
- Dev-only integration evidence must use the designated Dev profile and must not
  modify production state. Evidence records must exclude invitation links,
  credentials, device identifiers, and local paths.

The implementation and test suites, rather than this historical summary, are the
authoritative source for current operational behavior.
