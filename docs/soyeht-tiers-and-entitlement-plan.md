# Soyeht — tiers and entitlement plan (the seam, not the price)

**Status: design plan. Pricing and packaging are the owner's and are UNDECIDED.**
This document designs the *seam* at which a paid/unpaid distinction could be
enforced, not the price, the plan names, the trial length, or the thresholds.
**Every specific number in this document is an example and is marked
`ILLUSTRATIVE`.** No constant in this plan may be committed to code as a
threshold; the build order in §12 exists precisely so the seam can land with
today's behaviour byte-identical and no number in it. This is not an activation
record, does not authorize a deploy, and does not authorize adding a payment
provider.

All measurements in this document were taken against
`origin/main = e60bad85313eb39c9a000a29852bde1a944e425e`, with
`git show origin/main:<path>` and `git grep <pat> origin/main`. Line numbers are
valid **in that tree only** and must be re-measured before being cited elsewhere.
Where the working tree or another branch was used, it is said so explicitly —
nowhere in this document, as far as it goes.

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/server-rs/src/claw_share_relay_stream_issuer_trust.rs
  - admin/rust/server-rs/src/claw_share_relay_stream_abuse.rs
  - admin/rust/household-rs/src/claw_share.rs
  - admin/rust/household-rs/src/claw_share_data_tunnel.rs
  - admin/rust/household-rs/src/claw_share_relay_stream_contract.rs
  - admin/rust/household-rs/src/household_mesh_log.rs
  - admin/rust/Cargo.toml
-->

The repository is public. Aliases only; no real hostnames, addresses, device
names, account names, relay endpoints, paths, or secrets appear below.

**Corrections carried in this revision.** Three claims in an earlier draft were
wrong and are corrected in place rather than deleted, because a silently patched
"nothing is there" stops the next reader looking:

- **§4.1** — row 4 of the chokepoint table claimed `ClawVpnSessionRegistry::open`
  has *no caller*. The cited `git grep` was re-run and returns 16 lines; two are
  in production-compiled code. The row's conclusion survives for a different and
  sharper reason.
- **§7.5.1** — the grace window was anchored on *monotonic elapsed*. A monotonic
  clock in Rust is `std::time::Instant`, which resets on process restart and on
  reboot, so the mechanism did not deliver this document's own PASS condition.
  Replaced by a persisted, monotonically non-decreasing counter (§7.5.3).
- **§8.3** — the meter was a classifier over `relay_endpoint`, which is
  structurally unable to see device↔device sessions, i.e. half the stated paid
  core. Resolved in §8.4 by one predicate over two carriers.

**§5.0 is the cross-plan resolution** of the entitlement chokepoint. The per-claw
and device-mesh plans cite it and do not restate it.

## Which document is normative for what

Settled 2026-08-06 across the five Product A / cost plans, so that a shared
concept is resolved **once**. A document that is not normative for a row cites
that row's owner and does not restate it; where two documents disagree, the
defect is in the non-normative one.

| shared concept | normative document |
|---|---|
| transport modes — the Soyeht datapath vs **user-operated overlay transport** (`Overlay-U`) | `docs/product-a-per-claw-vpn-plan.md` **§12** (per-mode security table: §12.3) |
| entitlement chokepoint | **this document, §5.0** |
| relay cost, capacity, and the limits a session runs under | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` |
| device⇄device track | `docs/product-a-device-mesh-vpn-plan.md` |
| iOS client state | `docs/product-a-mobile-claw-control-vpn-plan.md` |

Aliases used here:

- `Relay-R`: the Soyeht-operated public rendezvous/splice relay (the thing that
  costs money per user) — the **single** relay alias across all five plans, per
  `docs/agent-operations-index.md` §2. This document previously called it
  `Relay-S`; that second alias is retired.
- `Overlay-U`: the network a user brings and operates themselves — their own
  tailnet, their own reachable address, their own LAN. Costs Soyeht nothing.
  The mode is **user-operated overlay transport**, defined in per-claw §12,
  which also holds the single registry of the spellings this mode retired —
  including the ones this document used. That list is not restated here.
- `Issuer-E`: the future Soyeht-side signer of entitlement assertions. Does not
  exist today.
- `Claw-X`: any Claw target (Mac or Linux).
- `Device-D`: a member device.

---

## 1. What exists today (measured, not assumed)

The entitlement seam has to be created from nothing. There is no tier type at
any layer.

| Claim | Evidence (`origin/main = e60bad85`) |
| --- | --- |
| No payment/billing/store infrastructure anywhere | `git grep -niE 'stripe\|revenuecat\|storekit\|in_app_purchase\|invoice\|\bpaywall\b' origin/main` → 0 lines; `git grep -lni 'billing' origin/main -- '*.rs'` → empty |
| Every `subscription` hit in Rust is pub/sub plumbing or an LLM tagline; every `entitlement` hit is macOS codesign or VM guest-image failure codes | `git grep -ni 'subscription' origin/main -- '*.rs'` → 38 lines (`core-rs/claw_llm.rs` tagline, `household-rs/owner_events.rs` `SubscriptionGuard`, `llm-proxy-rs` catalog taglines, `nostr-relay-rs` REQ subs, `server-rs` relay loops); `git grep -ni 'entitlement' origin/main` → 105 lines, all `.github/workflows/release-macos.yml`, `core-rs/guest_image_failure.rs`, `server-rs/guest_image_state.rs`, `soyeht-rs/deploy.rs` |
| The per-Claw VPN ACL has no tier dimension | `household-rs/src/claw_vpn.rs:150` — `ClawVpnAclKey { member_id, device_pub, claw_id }`, three fields, three accessors |
| Nothing counts shared apps, shares, or slots against any limit | `household-rs/src/claw_share.rs:787` `ClawShareSlotStore::insert` refuses duplicates only; `server-rs/src/handlers_claw_share.rs:764` `mint_invite_inner` has no count check; `:2244` `list_shareable_apps_core` and `:2338` `list_active_shares_core` build lists and compare them to nothing; `git grep -nE '\.len\(\) *(>=\|>) *[A-Z_]+' origin/main -- handlers_claw_share.rs claw_share.rs instance_db.rs` → empty |
| The only counting caps in the Share/VPN path are DoS backstops, not quotas | `server-rs/src/claw_share_relay_stream_offer_store.rs:36-37` — `MAX_RELAY_STREAM_OFFERS = 4096`, `MAX_RELAY_STREAM_OFFERS_PER_CLAW = 64`; `household-rs/src/claw_vpn.rs:20` — `CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW = 1` |
| `RelayStreamResource::IpTunnel` is compiled OUT of the production artifact | `offer_store.rs:38` — `pub const IP_TUNNEL_RESOURCE_COMPILED: bool = cfg!(any(test, feature = "dev_t1_datapath"))`, enforced at `:362 require_resource_enabled` and `:352 resource_enabled_for_build` |
| The public relay is structurally blind | `household-rs/src/claw_share_rendezvous_hello.rs:45` — `RendezvousHello { version: u8, role, token }`; its only per-caller dimension is `RelaySourceBucket::from_ip` (`server-rs/src/claw_share_relay_stream_abuse.rs:27`) |
| There is no Soyeht-side per-user identity | household trust root, machine key, mesh log (`household-rs/src/household_mesh_log.rs:990` `MeshLogStore`), `HouseholdAuthState`, and `instance_db` SQLite are all generated and held on the user's own machine |
| Tailscale already ships as a *detected access channel*, not dev-admin-only | `core-rs/src/network_detect.rs:71` pushes `detect_tailscale(admin_port)` alongside local/lan/cloudflare; `fn detect_tailscale` at `:302`; `apply_effective_tailscale_https` at `:80` rewrites its URLs when Caddy runs |
| A "shared app" already has a durable identity | `store-rs/src/instance_db.rs:1198` `CREATE TABLE shareable_apps (app_id PRIMARY KEY, instance_id, household_id, …, retired_at, …)`, `:1208` `CREATE UNIQUE INDEX ux_shareable_apps_live_instance ON shareable_apps(instance_id) WHERE retired_at IS NULL`, `:1231` `ensure_shareable_app` mints lazily and never revives a tombstone |

Two consequences follow immediately and constrain everything below:

1. **Nothing to attach to on the relay.** The relay cannot be the meter without
   destroying the property that makes it cheap and safe.
2. **Nothing to attach to on the client, either.** `instance_db` is local
   SQLite, the mesh log is local NDJSON signed by the *local* machine key, and
   `HouseholdAuthState` is a local CBOR file. Any count kept there is a count
   the machine owner can edit.

---

## 2. Tier model as a shape

Owner intent, recorded 2026-08-06: the paid core is the VPN (device↔device and
device↔Claw); Share is the free-tier carrot; a user who brings their own
transport pays nothing and is still a supported user; there may be an initial
free period. Specifics are deferred.

The shape has three positions, not two. The third is the one that makes the
design tractable.

| Position | What it is | What it includes | Cost to Soyeht |
| --- | --- | --- | --- |
| **Free** | Default on install | Full household, pairing, owner auth, Claws, ClawSite, PTY. Share limited — an example bound is *3 concurrent shared apps* (`ILLUSTRATIVE`) — and possibly a free period of the order of *3 months* (`ILLUSTRATIVE`) before the bound applies | Relay bandwidth for the bounded Share traffic |
| **Paid** | Entitled | Everything Free has, without the Share bound, plus VPN sessions over `Relay-R` (device↔device and device↔Claw) | Relay bandwidth, at the volume that motivates charging |
| **User-operated overlay transport** (`Overlay-U`) | User operates their own network | Everything, unbounded, forever, free — because none of it traverses Soyeht infrastructure | Zero |

The `Overlay-U` position is not a concession, it is the load-bearing simplification:
**the thing being sold is Soyeht-operated relay capacity, not a feature.** That
single reframing makes the meter a *transport* question (§8) instead of a
*capability* question, which is what allows the check to sit at a single place
and to be unable to widen anyone's access (§6).

**One half of the Paid row is not yet observable.** device↔Claw sessions carry a
signed `relay_endpoint` and can be attributed; device↔device sessions do not go
through the relay-stream offer at all, so nothing in this tree can tell a paid
device↔device session from a free one. §8.3 states the gap and §8.4 resolves it
without retreating from the owner's decision — but the resolution is a
requirement on unbuilt code, not a mechanism that exists. Do not read this table
as describing something enforceable today.

### 2.1 The `Overlay-U` position — the transport contradiction is resolved elsewhere

**The contradiction between "Tailscale is not part of the shipped datapath" and
the owner's 2026-08-06 decision is resolved once, in
`docs/product-a-per-claw-vpn-plan.md` §12.1**, whose table gives a verdict per
contradicting sentence. This document previously carried its own resolution of
the same contradiction; **that duplicate is deleted**, because three resolutions
of one decision is how a mode acquires three meanings. The per-mode security
table (which of S1–S12 survive) is per-claw §12.3 and is not reproduced here.

**One stale quotation, corrected rather than dropped.** An earlier revision of
this section quoted `product-a-mobile-claw-control-vpn-plan.md` as *stating, as
a live product invariant*, "Tailscale may be used for developer administration
only; it is not part of the shipped VPN datapath." That plan has since been
rewritten and has **split** that sentence, under "Transport choice — two claims
that were conflated": clause (a) *our datapath depends on no third-party
overlay* is kept and still true; clause (b) *the user may not choose one* is
superseded. The sentence no longer stands in the form this document quoted it
in, and citing it as live would be citing a document that no longer says it.

What this document keeps, because it is the tiers-side consequence and belongs
nowhere else: the security argument for the original invariant survives intact,
and this is why supporting `Overlay-U` weakens nothing. A user-operated overlay
is **outside the Noise/offer trust boundary**, so the product may not *rely* on
it for authorization. It is now also **outside the paid boundary**, so the
product need
not *meter* it. Both statements are about the same fact — Soyeht neither trusts
nor bills what it does not operate. Authorization for an `Overlay-U` session is
byte-identical to authorization for a relayed one; only the entitlement term
(§6) differs, and it differs in the permissive direction, where a bug costs
revenue rather than security.

---

## 3. What must work, free and forever, for an `Overlay-U` user

This list is a PASS condition on any entitlement implementation. None of these
paths touches `Relay-R`, so none of them may consult entitlement at all.

- Household bootstrap, machine pairing, owner auth / PoP / WebAuthn ceremonies.
- Machine roster and mesh-log replication.
- Claw create / list / use.
- ClawSite and PTY over an address the user can already reach.
- Group and member management; share minting and revocation as *records*.
- The Tailscale channel detection that already ships
  (`core-rs/src/network_detect.rs:302`).

**PASS:** with entitlement hard-coded absent, every item above still works in
the existing test suite with no test modified.

---

## 4. Chokepoint ranking

Ten candidate sites, hardest-to-bypass first, with why each is or is not usable
as the entitlement point.

| # | Site | File:line (`origin/main`) | Bypass cost | Usable as a tier gate? |
| --- | --- | --- | --- | --- |
| 1 | `require_resource_enabled` / `resource_enabled_for_build` | `server-rs/src/claw_share_relay_stream_offer_store.rs:362` / `:352` | Needs a **different binary** | **No.** A per-build boolean with no principal. It can never express "this user, right now". |
| 2 | `RelayStreamOfferTargetGate::validate_ip_tunnel_target` / `::validate_target_for_resource` | `server-rs/src/claw_share_relay_stream_target_router.rs:165` / `:213` | Server-side; re-runs on every target open against a fresh projection | **Yes — admission.** |
| 3 | `relay_stream_offer_session_revoked` | `server-rs/src/claw_share_relay_stream_session.rs:193` | Server-side; polled on a 500 ms interval and before every forwarded `Data` frame | **Yes — liveness.** |
| 4 | `ClawVpnSessionRegistry::open` | `household-rs/src/claw_vpn.rs:579` | Fail-closed enum: `Unauthorized` / `MemberClawSessionLimitReached` / `ClawSessionLimitReached` | **No — and for a different reason than an earlier draft of this row claimed. See §4.1.** |
| 5 | `RelayStreamOfferStore::put_signed` / `::put_minted` | `offer_store.rs:159` / `:138` | Mint time only | **No, alone.** See §6.3 — a signed `not_after` can reach 90 days out. |
| 6 | `RelayStreamAdmission::admit` | `server-rs/src/claw_share_relay_stream_admission.rs:35` | Right ordering | **No.** Takes only `now_unix`; carries no member, claw, app, or household, so it cannot express a per-user term. |
| 7 | `household_auth::authorize_request(.., Operation::HouseholdInvite, ..)` | `server-rs/src/handlers_claw_share.rs:980` `handle_mint_invite`, `:1967` `handle_invite_to_claw` | Authenticates the owner | **No.** It authenticates exactly the party being limited. |
| 8 | `assemble_claw_vpn_t1_caller` | `server-rs/src/claw_vpn_t1_caller.rs:146` | Process-global, once at startup | **No.** One operator-supplied boolean triple for the whole process. |
| 9 | `RelayAbuseState` / `RelaySourceBucket::from_ip` | `server-rs/src/claw_share_relay_stream_abuse.rs:27` | Change network | **No.** IP-keyed, and the relay is deliberately blind. |
| 10 | The client / UI (`claw-share-bridge-rs` FFI, plus the out-of-repo apps) | — | Editing the attacker's own process | **No.** Not a check. `git ls-tree -r --name-only origin/main \| grep -icE '\.swift$\|\.xcodeproj'` → 0: the clients are in another repository and are the untrusted side of every decision here. |

### 4.1 Correction to row 4 — the caller exists; the row's evidence was wrong

An earlier draft of row 4 said `ClawVpnSessionRegistry::open` has **no caller**
and cited `git grep -n 'ClawVpnSessionRegistry' origin/main -- admin/rust/server-rs/src/`.
That command was re-run for this revision and **returns 16 lines across 7 files**,
not zero. The conclusion (not a tier gate) stands; the reason it stands is
different and sharper. Recorded rather than silently patched, because a wrong
"nothing is there" is exactly the shape of claim that stops the next reader
looking.

What the re-run actually shows:

- **13 of the 16 lines are inside `#[cfg(test)]` modules.** The `#[cfg(test)]`
  attribute in each file precedes them: `claw_vpn_packet_pump.rs:641`,
  `claw_vpn_pollable_pump.rs:88`, `claw_vpn_runtime.rs:329`,
  `claw_vpn_target_session_router.rs:164`,
  `claw_vpn_target_session_runtime.rs:224`, `claw_vpn_wiring.rs:461`.
- **The remaining hits are not.** `claw_vpn_t1_relay_stream_router.rs` declares
  `ClawVpnSessionRegistry` in a top-level `use` at `:37`, and that file's
  `#[cfg(test)]` does not start until `:1491`. The registry is **constructed in
  production-compiled code** at `:1102` and `:1380`, inside the two
  `async fn open_ip_tunnel` implementations (`:1072` for the blocking router,
  `:1350` for the pollable one) of the
  `RelayStreamIpTunnelRouter` trait (`claw_share_relay_stream_target_router.rs:105`).
- **`::open` is genuinely reached** from there:
  `ClawVpnAgentCore::open_with_audit` (`household-rs/src/claw_vpn.rs:1017`) →
  `ClawVpnDatapath::open_with_audit` (`:918`) →
  `ClawVpnSessionRegistry::open_with_audit` (`:630`) → `::open` (`:579`).
- The module is mounted unconditionally: `server-rs/src/lib.rs:84` —
  `pub mod claw_vpn_t1_relay_stream_router;` — and it is assembled from
  `claw_share_relay_stream_mount.rs:801`
  (`assemble_claw_vpn_t1_relay_stream_router`).

**The reason row 4 is still "No" is better than "no caller":**

Both `open_ip_tunnel` bodies do the same three statements before opening:

```text
let mut acl = ClawVpnAcl::new();
acl.grant(key.clone());
let registry = ClawVpnSessionRegistry::with_limits(acl, …)?;
…
let (session, open_event) = core.open_with_audit(&key);   // same `key`
```

The ACL is **minted one statement earlier from the very key that is then
presented**. `open`'s first line is `if !self.acl.is_authorized(key)`
(`claw_vpn.rs:583`), which at this call site can never be false. Its
`Unauthorized` arm is structurally unreachable here; only the two session-count
limits can fire. Attaching entitlement to a predicate whose authorization arm is
a rubber stamp would look like a control and be none — the same failure the
per-claw plan records for `ClawVpnAclKey` in its §11.2.

**Two things this does not say.** It does not say the T1 path is live in
production: `validate_ip_tunnel_target` — the only route to an `IpTunnel`
backend — is `#[cfg(any(test, feature = "dev_t1_datapath"))]`
(`claw_share_relay_stream_target_router.rs:164`), and
`IP_TUNNEL_RESOURCE_COMPILED` (`offer_store.rs:38`) is false in a production
build. **The caller compiles unconditionally; the path that reaches it is
compiled out.** And it does not say the earlier draft's *conclusion* was wrong —
only its evidence.

---

## 5. The chosen chokepoint: one producer, evaluated at every decision

**The entitlement term is a single value, ANDed into existing predicates.**
It is not several policies; it is one policy, produced once, consulted at
admission and at liveness.

### 5.0 The chokepoint, stated once, for all three plans

Three plan documents named an entitlement seam and they did not agree. **This
section is the resolution. Both other plans now cite it** — per-claw §11.1 and
device-mesh §7 were rewritten on 2026-08-06 to point here rather than restate,
and the wordings in the "what it named" column below are what they said before
that, kept so the change is legible.

| Plan | What it named (superseded) | Verdict |
| --- | --- | --- |
| `docs/product-a-per-claw-vpn-plan.md` §11.1 | `validate_ip_tunnel_target` + `relay_stream_offer_session_revoked`; the entitlement fact "**projected from the same household mesh log**" | Sites too narrow **and** the carrier wrong — see below and R-9. Now cites this section |
| `docs/product-a-device-mesh-vpn-plan.md` §7 | `MeshSessionRegistry::try_preauthorize_before` (`household-rs/src/mesh_session_registry.rs:1177`) | A genuinely different admission path, correctly identified — a second *enforcement* site, not a second producer. Now cites this section and adopts the one-value rule |
| this document, §5.1 / §5.2 | `validate_target_for_resource` + `relay_stream_offer_session_revoked` | Sites agree; the producer above them is the chokepoint |

**The measurement that resolves it.** Every relay-stream authorization decision
in the tree passes through exactly one function.
`git grep -n 'verify_offer_with_context' origin/main -- admin/rust/server-rs/src/`
returns **eight** lines: one is the definition itself and four are doc-comment
or module-doc text, leaving **three call sites**. (An earlier revision of this
paragraph said "seven lines; four are its own defining module or comment text";
the command was re-run for this revision and returns eight — the arithmetic, not
the conclusion, was wrong.)

- `claw_share_relay_stream_target_router.rs:177` — inside `validate_ip_tunnel_target`
- `claw_share_relay_stream_target_router.rs:232` — inside `validate_target_for_resource`
- `claw_share_relay_stream_session.rs:200` — inside `relay_stream_offer_session_revoked`

All three call `RelayStreamIssuerTrust::verify_offer_with_context`
(`server-rs/src/claw_share_relay_stream_issuer_trust.rs:77`), which builds its
result from **one** `(self.source)()` call and returns a
`RelayStreamTrustContext` (`issuer_trust.rs:34`) with exactly three public
fields: `record`, `cert`, `projection`. That single source call is what makes
the "no second snapshot" property true, and it is the property the per-claw
plan correctly calls its hard constraint.

> **THE CHOKEPOINT, by file and function.**
>
> **Producer (the chokepoint):** `RelayStreamIssuerTrust::verify_offer_with_context`
> — `admin/rust/server-rs/src/claw_share_relay_stream_issuer_trust.rs:77`.
> The entitlement fact becomes a **fourth field on `RelayStreamTrustContext`**
> (`issuer_trust.rs:34`), produced by that one call.
>
> **Consumers (the `AND` conjuncts):** `validate_target_for_resource`
> (`target_router.rs:213`) and `relay_stream_offer_session_revoked`
> (`session.rs:193`) for the shipping resources; `validate_ip_tunnel_target`
> (`target_router.rs:165`) as well, but only where it exists — it is
> `#[cfg(any(test, feature = "dev_t1_datapath"))]` at `:164`.

**The producer exists in a product build, and that is the reason it — and not
the `IpTunnel` gate — is the chokepoint.** This is the fact the per-claw plan
supplied and it decides the choice:

- `pub mod claw_share_relay_stream_issuer_trust;` (`server-rs/src/lib.rs:27`)
  carries no `cfg`, and neither does the `impl RelayStreamIssuerTrust` block
  holding `verify_offer_with_context`.
- `validate_target_for_resource` (`target_router.rs:213`) and
  `relay_stream_offer_session_revoked` (`session.rs:193`) carry no `cfg` either.
- `validate_ip_tunnel_target` **is** `#[cfg(any(test, feature =
  "dev_t1_datapath"))]` (`target_router.rs:164`), and `dev_t1_datapath` is not in
  `default` — so **a seam placed only there is absent from every product
  artifact**, which is exactly what per-claw §11.1's original site list would
  have produced. The `IpTunnel` consumer joins the other two on the day the
  feature does, and needs no redesign to do so, because it already receives the
  same `ctx`.

#### The correction the per-claw plan must take: `RelayStreamTrustContext`, not `ProjectedState`

This is not a wording preference. `check_relay_stream_group_membership`
(`household-rs/src/claw_share_relay_stream_contract.rs:411`) has this signature:

```text
pub fn check_relay_stream_group_membership(
    projection: &ProjectedState,
    group_id: &str, member_id: &str, claw_id: &str,
    guest_device_pub: &P256PublicKey,
) -> Result<(), &'static str>
```

Its first parameter is the **whole** `ProjectedState`. The per-claw plan's
*former* phrasing — an entitlement fact "projected from the same household mesh
log" — read most naturally as a new field on `ProjectedState`, and that is
exactly the placement that breaks §6.1. (That plan withdrew the phrase on
2026-08-06 and its §11.1 now cites this section; the argument is kept because
the substitution stays available to the next author.) Put the commercial value inside `ProjectedState` and
the authorization predicate now *receives* it; the non-weakening proof degrades
from "structurally impossible" to "nobody has read that field yet", which is a
review discipline, not a guarantee. Put it **beside** `projection` on
`RelayStreamTrustContext` and the value is absent from the authorization
function's type signature, where no future edit to that function's body can
reach it.

Both requirements hold at once under this placement: the per-claw plan's
no-second-snapshot rule (one `(self.source)()` call produces the whole context)
and this document's non-weakening proof (`ProjectedState` is unchanged).

#### The device↔device path is a second site, and saying otherwise would be false

`MeshSessionRegistry::try_preauthorize_before`
(`household-rs/src/mesh_session_registry.rs:1177`) takes
`(&SealedBinding, Weak<H>, Instant)`. It neither constructs nor receives a
`RelayStreamOfferContract`, so no arrangement of the relay-stream gate covers
it, and no honest document can claim one chokepoint serves both products. What
is unified is the *policy object*, not the call site:

> **One `Entitlement` value type. One evaluation. N enforcement sites, each of
> which RECEIVES the value and never re-derives it.**

That is R-6 restated as a rule instead of a warning. A second derivation is a
second policy; three of them are three policies that will diverge, and the
divergence will surface as a decision input sitting at a caller nobody tested.

**A note on which tree the mesh seam lives in, because the name misleads.**
`household-rs/src/mesh_session_registry.rs` is **not** part of the detached
mesh-session track. `household-rs` is a full workspace member
(`admin/rust/Cargo.toml`, `members`), and `pub mod mesh_session_registry;`
(`household-rs/src/lib.rs:79`) carries no `cfg`, so that file compiles and its
tests run in an ordinary build. Only `mesh-session-control-model-rs` and
`mesh-session-core-rs` are in the workspace `exclude` list. For those two the
accurate statement — corrected here so it is not repeated in the old wrong form —
is: **their libraries ARE compile-checked in CI** — the backend workflow
enumerates every non-default feature of every workspace package and runs
`cargo check --locked -p <pkg> --all-targets --features <feat>`, and `keystore-rs`
declares a `mesh-session` feature (`keystore-rs/Cargo.toml:12`) carrying an
optional path dependency on `mesh-session-core-rs` (`:25`) *and* inlining
`mesh-session-control-model-rs/src/lib.rs` through
`#[cfg(feature = "mesh-session")] #[path = …]`
(`keystore-rs/src/lib.rs:56-57`), so both excluded libraries are reached.
**Their tests never execute**, because no `cargo test` invocation can reach a
non-member package. And
`mesh-session-control-model-rs/tests/model_invariants.rs`, inlined at
`keystore-rs/src/lib.rs:116` behind `#[cfg(all(test, feature = "mesh-session",
feature = "test-support", feature = "roster-sync-unratified"))]` (`:110-115`) —
**three features at once, while that CI loop passes one feature at a time** — is
therefore neither compiled nor run. That is a structural trap, not an oversight:
no single-feature invocation can ever reach it. Nothing this document
depends on sits in that gap — the seam it names is in `household-rs` — but the
distinction matters when someone reads "mesh-session" and assumes dead code.

### 5.1 Admission — `RelayStreamOfferTargetGate` (`target_router.rs:165` / `:213`)

This is the last server decision before an address exists. The ordering in
`household-rs/src/claw_share_data_tunnel.rs` is explicit:

- `:997` — `if is_revoked(&cred)` (pre-open revocation check)
- `:1011` — `} = match router.open(&target_id).await {` destructures a
  `TargetSession` carrying `vpn_mesh_ipv4`
- `:1019` — `send_frame(&mut tunnel_w, &TunnelFrame::Open)` (stream-ready ack)
- `:1031` — `if let Some(mesh_ipv4) = vpn_mesh_ipv4 {`
- `:1045` — `send_frame(&mut tunnel_w, &TunnelFrame::NetworkSettings(body))`

The client cannot configure an interface until the server sends
`TunnelFrame::NetworkSettings` at `:1045`. A denial inside the target gate
returns *before* `router.open` at `:1011`, so on denial **the route never
exists** — there is nothing to tear down and nothing to leak.

The gate is also already the right *shape*. `validate_target_for_resource`
(`:213`) carries this comment verbatim in `origin/main`:

> `_with_context` returns the SAME live context so the Group path checks
> membership on the EXACT projection that gated the signer (no second snapshot).

**The entitlement term must be evaluated on that same `ctx` snapshot.** Opening
a second projection for entitlement would reintroduce exactly the split the
existing code went out of its way to avoid.

### 5.2 Liveness — `relay_stream_offer_session_revoked` (`session.rs:193`)

Entitlement lapses while sessions are up. This is the only predicate the serve
loop already polls, and its ordering is marked load-bearing in
`claw_share_data_tunnel.rs`:

> SECURITY INVARIANT (audit D4 — load-bearing ordering; do not reorder). … (1)
> the revoke_poll first tick fires IMMEDIATELY … (2) the per-`Data`
> `is_revoked` check PRECEDES the forward/write below …

`REVOKE_POLL_INTERVAL` is 500 ms (`claw_share_data_tunnel.rs:741`); `is_revoked`
is consulted at `:997`, `:1106`, and `:1162`.

**Constraint on reuse:** an entitlement lapse must *not* reuse this predicate's
tear-down semantics. See §7.4 — the correct behaviour for a lapse is "deny new,
do not cut in-flight", which means the entitlement term enters this predicate
only for the *revoked* case, never the *expired-and-in-grace* case. This is the
single most delicate point in the design and is called out again as a risk in
§11.

### 5.3 Why the others are wrong, restated as failure modes

- **UI/client only** → the check runs in the attacker's process, in a repository
  this tree cannot even verify.
- **Offer store only** → the store's own module header says it is not a trust
  anchor; every read path (`load` / `get_active` / `list_active`) re-verifies and
  prunes, so anything written there is advisory.
- **Mint time only** → §6.3: up to 90 days of paid relay after a downgrade.
- **`RelayStreamAdmission::admit`** → no principal to charge.
- **`assemble_claw_vpn_t1_caller`** → one boolean for the whole process.
- **Relay abuse limiter** → keyed on an IP, on a component that must stay blind.
- **`ClawVpnSessionRegistry::open`** → it *is* called from production-compiled
  code (§4.1), but with an ACL minted from the presented key one statement
  earlier. A gate whose authorization arm cannot fire is not a gate.

---

## 6. Non-weakening: entitlement is a SECOND gate, never a replacement

This section is the one an implementer must not deviate from.

### 6.1 The ordering rule

```text
allow  ==  authorized(ctx)  AND  entitled(ctx)
```

- `authorized(ctx)` is the existing predicate, unchanged, byte-identical:
  `verify_offer_with_context` (signature, signer-is-active-machine-issuer,
  `not_after`, directory-device revocation kill switch) followed by the audience
  branch — `check_relay_stream_group_membership` or `check_relay_stream_public`
  — on that same projection.
- `entitled(ctx)` is the new term, evaluated on the same `ctx`.
- The operator is `AND`. There is no code path in which `entitled` is consulted
  when `authorized` is false, and no code path in which `entitled == true`
  substitutes for any part of `authorized`.

**Paying must never widen access.** Two independent reasons. The second is the
one that survives a careless edit, and it is conditional on §5.0 being followed.

1. **`entitled` is a conjunct.** Conjoining a term can only shrink the accepted
   set. True of the code as written.
2. **The entitlement value is not in the authorization predicate's type
   signature.** `check_relay_stream_group_membership`
   (`household-rs/src/claw_share_relay_stream_contract.rs:411`) takes
   `(&ProjectedState, &str, &str, &str, &P256PublicKey)`. §5.0 places the
   entitlement fact on `RelayStreamTrustContext` — a sibling of `projection`,
   not a field inside it — so there is no value of the entitlement token that
   `check_relay_stream_group_membership` can observe **at all**: not because
   nobody reads it, but because it is not reachable from its arguments.

**Reason 2 evaporates if the fact is put inside `ProjectedState` instead**, and
then only reason 1 remains — a claim about the code as written, not about the
code as it will be. That substitution is a one-line diff, it looks like a
simplification, and the per-claw plan's current wording invites it. It is
recorded as R-9 so a reviewer has something to grep for: **any change to
`ProjectedState`'s field list inside an entitlement PR is this failure.**

**Not paying must never bypass authorization.** Structurally guaranteed the same
way, in the other direction: `authorized` is evaluated regardless of the
entitlement value, and its failure returns before `entitled` matters.

### 6.2 Where the ordering is enforced, concretely

| Site | Enforcement |
| --- | --- |
| `target_router.rs:165` / `:213` | `verify_offer_with_context` already runs first (`:177`, `:232`) and `?`-returns `target_unavailable("relay-stream-offer-invalid")` on failure. The entitlement term is added *after* the existing audience check, as the last conjunct, reading the new field on the `ctx` already in scope. |
| `session.rs:193` | `let Ok(ctx) = trust.verify_offer_with_context(offer, now_unix) else { return true; }` (`:200`) already fails closed before the audience match. The entitlement term is added inside the same function, after the audience branch. |
| `claw_vpn.rs:579` — **already reached** from non-test code, behind a compiled-out path (§4.1) | **Not an entitlement site, and must not become one.** The ACL it consults is minted from the same key one statement earlier (§4.1), so a check there would be a rubber stamp. Entitlement for the T1 path is enforced upstream at `validate_ip_tunnel_target` (`target_router.rs:165`), which is where §5.0's value is in scope. |

**PASS (mutation-style, unit level):** an implementation in which `entitled`
returns `true` unconditionally must produce a test suite that is *entirely
green* — that is the "today's behaviour is byte-identical" proof. An
implementation in which `entitled` returns `true` unconditionally **and**
`authorized` is stubbed to `true` must produce a *red* in the existing
authorization tests. If both are green, the `AND` was not wired; the second is
the non-vacuity control and must exist.

### 6.3 The mint-time hole, named

`household-rs/src/claw_share.rs:71` — `pub const MAX_CREDENTIAL_TTL_SECS: u64 =
90 * 24 * 60 * 60;`. `provision_relay_stream_offer`
(`server-rs/src/claw_share_relay_stream_provision.rs:47`) is called from
`provision_relay_stream_offer_for_claim`
(`server-rs/src/claw_share_relay_stream_mount.rs:1107`) with
`credential.expires_at` as `not_after`.

Therefore **a plan that puts the entitlement check only at the HTTP mint
handlers leaks up to 90 days of paid relay to a user who stopped paying an hour
later.** This is not a tuning question; it is why §5 requires the check at open
and at liveness rather than at mint.

### 6.4 Gates that must not be relaxed to make a paid feature reachable

- Do **not** weaken `IP_TUNNEL_RESOURCE_COMPILED` / `require_resource_enabled`
  (`offer_store.rs:38` / `:362`). A tier must never be the reason to lift a
  Phase 0 compiled-out boundary. Enabling `IpTunnel` in production is a separate,
  owner-authorized event with its own evidence, and it is upstream of every word
  in this document.
- Do **not** relax the `put_signed` caps or add eviction. Their comment states
  the intent verbatim: "at a cap a NEW offer is rejected (`StoreFull`) rather
  than evicting a valid one."
- Do **not** add a tier field to `ClawVpnAclKey` (`claw_vpn.rs:150`). The ACL is
  an authorization relation; mixing a commercial dimension into it is precisely
  the "paying widens access" failure this section forbids.

---

## 7. Offline and degraded entitlement policy

### 7.1 The split

**Authorization stays fail-closed and byte-identical. Entitlement is fail-soft
and separately named.** These are different questions with different worst
cases:

| | Worst case if it fails open | Worst case if it fails closed |
| --- | --- | --- |
| Authorization | A stranger reaches a user's machine | A legitimate user is denied |
| Entitlement | Soyeht is owed money | A **paying** user loses their VPN because Soyeht's issuer was unreachable |

Every other gate in this codebase fails closed, by explicit design:
`wall_now_secs` (`server-rs/src/claw_share_session_clock.rs:65`) returns `None`
below `MIN_PLAUSIBLE_UNIX_SECS = 1_767_225_600` (`:50`); the target gate maps a
missing clock to `target_unavailable("relay-stream-offer-invalid")` with the
comment "An unusable wall clock cannot enforce `not_after`, so it can only
DENY"; `SessionClock` keeps both wall and monotonic and revokes on the more
restrictive. (That last discipline is correct for a *session* and does **not**
transfer to the grace budget — §7.5.1 says why, and it is the reason a whole
subsection exists.)

**Entitlement is the one legitimate exception, and the reason is the table
above:** a fail-closed entitlement check converts a Soyeht-side outage into a
product-wide VPN outage for the users who are paying. That is a worse outcome
than the revenue loss it prevents, and unlike an authorization bypass it costs
no user any security. This asymmetry is the entire justification, and it holds
*only* because entitlement is a conjunct that can never widen access (§6.1) — if
that property is ever lost, this exception must be withdrawn with it.

**This will be the only fail-soft gate in the system.** Per the standing
discipline that a justification must live where the decision is made and not in
a comment above it, the reason belongs **in the allow/deny message emitted at
the gate**, not only in this document.

### 7.2 The entitlement assertion

Modelled on the discipline of `OwnerApprovalContextV2`
(`household-rs/src/owner_approval_v2.rs:253`), which already demonstrates the
right shape in this codebase: an explicit `version`, a `purpose` string, its own
domain-separation constant, canonical CBOR with `#[serde(deny_unknown_fields)]`,
`issued_at` / `expires_at`, a `replay_nonce`, and `capabilities: Vec<String>`.

It **cannot be reused directly**: `OwnerApprovalContextV2` is an interactive
WebAuthn assertion bound to a server-chosen challenge, so it cannot be validated
offline against a stored issuer. The entitlement assertion borrows the
discipline and changes exactly one thing — it is verifiable **offline against a
pinned `Issuer-E` public key**, refreshed opportunistically whenever the device
is online.

### 7.3 The policy table

| State | New sessions over `Relay-R` | In-flight sessions | Rationale |
| --- | --- | --- | --- |
| Valid assertion | ALLOW | continue | Normal |
| **No assertion ever seen** | **DENY** | n/a | A fresh install has never been entitled. Grace is for *lapse*, not for *absence*. |
| Expired, within grace | ALLOW | continue | Issuer unreachable is the expected cause |
| Expired, grace exhausted | DENY | **continue** (see §7.4) | Do not cut a live session on entitlement grounds |
| **Revoked** (explicit, not merely expired) | **DENY, no grace** | **tear down** | Otherwise grace becomes a revocation bypass with a documented duration |
| Assertion signature invalid / issuer unknown | DENY | tear down | This is a forgery signal, not a connectivity signal |
| **Entitlement evaluation ITSELF fails** — store unreadable, record corrupt, canonical decode rejects, durable clock floor unavailable | **DENY** | **continue** | Not a connectivity signal, and not distinguishable from the cheapest attack on §7.5. See §7.3.1 |
| Session rides `Overlay-U`, not `Relay-R` | ALLOW | continue | Never metered (§8) |

Assertion lifetime: **weeks, not hours** — an example is *21 days*
(`ILLUSTRATIVE`). Grace after expiry: **bounded and NON-RENEWABLE** — an example
is *7 days* (`ILLUSTRATIVE`). Non-renewable means the grace budget is consumed
once per assertion-expiry event and is not reset by going offline again; a
renewable grace is an unbounded grace with extra steps.

### 7.3.1 Why an unreadable or corrupt entitlement store DENIES

The fail-soft exception in §7.1 is justified by exactly one worst case:
*Soyeht's issuer was unreachable*. An unreadable or corrupt **local** record is
not that case, and it falls the other way for three reasons.

- **It is indistinguishable from the cheapest attack on §7.5.** "Delete the file
  to reset the consumed-grace counter" is the same move as "reboot to reset the
  monotonic clock". If it grants grace, the §7.5 fix is defeated by `rm` and
  this document has moved the hole rather than closed it.
- **The non-attack case is repairable by the user without Soyeht.** Go online
  once and refetch. A genuine issuer outage is *not* repairable by the user —
  that asymmetry is the whole content of §7.1, and it does not hold here.
- **This codebase already answers the identical question this way.**
  `MissingFloorPolicy::RejectUnavailable`
  (`household-rs/src/machine_roster_store.rs:923`, applied at `:1140`): on an
  initialized store a *missing* clock-floor record yields `FloorUnavailable`,
  not a fresh start. Deleting state is not a reset there and must not be here.

So: **DENY new relayed sessions, continue in-flight** — §7.4's rule is unchanged,
because this is a failed evaluation, not a revocation. And the denial must be
**repairable, not latched**: a subsequent successful read of a valid assertion
restores ALLOW with no operator action, the way `FloorLatch::record_success`
(`machine_roster_store.rs:914`) clears `failure_latched`.

**The cost, stated rather than smoothed.** A paying user who is *both* offline
*and* holding a corrupt record loses relayed VPN with no self-service repair.
That is a real product regression and it is accepted deliberately, because the
alternative makes the record's *absence* more valuable to a user than its
presence. If the owner judges that cost too high, the correct lever is a longer
assertion lifetime (§7.3) — never a softer failure mode here.

**Uncertainty, unresolved:** the relative frequency of "corrupt record while
offline" (a real user losing service) versus "record deleted deliberately" (the
attack) is unknown, and nothing in this tree measures it. *Settled by:* counting
decode failures of the household state records that already exist, over a real
fleet, once one exists. Until then the policy is chosen on the security
argument, not on the frequency.

### 7.4 What grace can and cannot unlock

**Can:** continue relayed VPN sessions for an already-entitled household; mint
new relayed VPN offers for principals the ACL already authorizes; exceed the
free-tier Share bound if the assertion said so.

**Cannot, ever:** authorize a principal the ACL does not authorize; revive an
expired offer's `not_after`; survive an explicit revocation; grant to a
household that has never presented a valid assertion; lift
`IP_TUNNEL_RESOURCE_COMPILED`.

### 7.5 The clock problem: the grace budget is persisted state, not a clock reading

The user owns the clock. `MIN_PLAUSIBLE_UNIX_SECS`
(`server-rs/src/claw_share_session_clock.rs:50`) exists in this codebase
precisely because a clock reading is an untrusted input. A grace window
implemented as a plain wall-clock comparison **is not a limit** — the user sets
the clock back.

#### 7.5.1 The defect in the previous version of this section, corrected

An earlier draft of this section anchored the grace window on *"monotonic elapsed
since the last successful issuer proof"*, borrowing the `SessionClock` two-clock
discipline. **That is wrong, and it fails a PASS condition this same document
states.** Rust's monotonic clock is `std::time::Instant` — which is what
`SessionClock` holds (`claw_share_session_clock.rs:39`, `use std::time::{Duration,
Instant};`). An `Instant` has no meaning across processes: it resets on process
restart and on reboot. The attack is one step long — **reboot the device and the
grace budget is new** — and it costs the attacker nothing. PASS condition 3 in
§7.6 ("an exhausted grace stays exhausted") was therefore *not delivered* by the
mechanism the section specified.

The category error is worth naming, because it is available again at every future
site that wants "elapsed since". `SessionClock` is correct for what it does: it
bounds **one live session**, whose lifetime is contained in one process lifetime,
so `Instant` is a valid instrument there. A grace budget of days is deliberately
**device-scoped** and outlives the process. Using a process-scoped instrument for
a device-scoped quantity is not a tuning error — the instrument cannot express
the quantity at all.

The `SessionClock` module comment already states the half that carries over
verbatim: *"Wall alone is defeated by rollback"*. What it does not say — because
in its own scope it never needed to — is that **monotonic alone is defeated by
restart**. Both halves are needed here; neither is sufficient.

#### 7.5.2 The mechanism, taken from what this codebase already persists

Do not invent a counter. `MachineRosterStore` already ships a durable,
rollback-detecting, monotonically non-decreasing wall-clock floor, and it is the
correct anchor. Every property a grace budget needs is already implemented and
tested there:

| Property the grace budget needs | Where it already exists (`origin/main = e60bad85`) |
| --- | --- |
| Survives reboot | `ClockFloorRecordV1 { v, hh_id, floor_secs }` (`household-rs/src/machine_roster_store.rs:226`) — canonical CBOR, `#[serde(deny_unknown_fields)]`, written to `clock_floor_path(state_dir)` (`:171`) |
| Monotonically non-decreasing | `observe_wall_floor` (`:1118`) stores `new_floor = max(durable_floor, raw, latch.last_verified, latch.failed_target)` |
| Rollback is **detected**, not merely ignored | `:1150` — `if durable_floor > 0 && raw < durable_floor { latch.record_failure(high); return Err(FloorUnavailable) }`. A clock below the floor does not read as "less time passed"; it fails closed |
| A rollback attempt is remembered across calls | `FloorLatch::record_failure` (`:906`) sets `failure_latched` and raises `failed_target` to the max of every value seen, so the next call cannot start from the lowered value |
| Deleting the record is not a reset | `MissingFloorPolicy::RejectUnavailable` (`:923`, applied at `:1140`) |
| The write cannot be half-applied | `strict_atomic_replace` (`:544`) writes a temp file and **verifies the readback decodes to the exact expected record** before committing |
| A future-dated clock is bounded too | `DURABLE_CLOCK_FUTURE_SKEW_SECS = 60` (`:866`), checked at `:1132` |

**Reachable without new API.** `MachineRosterStore::query_roster_evidence`
(`:1571`) is `pub`; it returns a `RosterEvidenceSnapshot`
(`household-rs/src/machine_roster_evidence.rs:104`) whose `pub floor_secs: u64`
is that floor; and its own doc comment states that serving it *"may durably
persist or advance the monotonic clock floor by atomic replacement"*.

Read that claim narrowly. **The entitlement module needs no new mechanism, file
format, or privileged accessor for a rollback-resistant notion of "now"** — it
does still need its own small record to hold `grace_consumed_secs`, which §12
defers along with everything else that waits for a price. What is being reused
is the *hard* part, and the part that would have been reinvented wrong.

Two preconditions, named rather than assumed. The floor lives inside
`MachineRosterStore`, so it is available only where the roster store is
**initialized** — `observe_wall_floor`'s callers `?`-return `NotInitialized`
otherwise. On a device with no initialized roster there is no floor to read, and
the entitlement answer there is DENY for an independent reason (§7.3, "no
assertion ever seen"), so the two agree; that agreement should be asserted, not
assumed. And the floor is *household*-scoped (`ClockFloorRecordV1.hh_id`), which
is a subject question — see O-5 and O-4.

#### 7.5.3 The rule

> **The grace budget is `grace_consumed_secs`: a persisted counter that is
> monotonically non-decreasing in storage. It is never derived from a clock
> reading, in either direction.**

Per evaluation, in this order:

1. Read the durable floor `F_now` (§7.5.2). If unavailable → §7.3's
   evaluation-failure row: **DENY, do not consume, do not reset.**
2. `delta = F_now.saturating_sub(last_floor_secs)` — `saturating_sub`, so a floor
   that somehow appears lower contributes **zero**, never a negative.
3. `grace_consumed_secs = grace_consumed_secs.saturating_add(delta)`. The stored
   value can only rise.
4. **Persist `(grace_consumed_secs, last_floor_secs = F_now)` BEFORE returning
   ALLOW**, with the write-then-verify-readback shape of `strict_atomic_replace`.
   Debit first, allow second: a crash between the two must cost the user grace,
   never grant it.
5. ALLOW only while `grace_consumed_secs < grace_budget_secs`.

The wall clock still appears, but **only as an upper bound** — via the
assertion's own signed `issued_at` / `expires_at`, exactly as `SessionClock`
keeps the signed wall expiry alongside its deadline. It may add restriction; it
may never remove any. **Never take a `min` of the two accumulators, and never
re-read anything in a way that can lower `grace_consumed_secs`.**

#### 7.5.4 What this does NOT close, stated plainly

This closes reboot, process restart, and wall-clock rollback. It does **not**
close a machine owner who edits `grace_consumed_secs` in their own state
directory: the floor record is canonical CBOR with a readback check, not a
signature under a key Soyeht holds. That is the same boundary §9.2 draws —
**tamper-evident, not tamper-proof** — and it is closed only by option (i)
there, a blinded `Issuer-E` assertion that carries the budget. **Do not describe
the grace budget to users as unresettable.**

A reviewer reading only a future entitlement module will know neither
`MIN_PLAUSIBLE_UNIX_SECS` nor the clock floor exists, which is why this
requirement is written here, **must be restated in that module's own doc
comment**, and must appear in the assert messages of the §7.6 tests rather than
in a comment above them.

### 7.6 PASS conditions for the offline policy

1. **Negative, unit level:** a *revoked* assertion denies immediately, with zero
   grace. A positive "entitled user connects" test cannot catch a grace that
   stopped discriminating between expired and revoked.
2. **Negative:** a fresh install with no assertion is denied `Relay-R` VPN, and
   the denial reason is distinguishable in tests from an authorization denial
   while remaining *opaque on the wire* (the target gate's existing discipline is
   one static reason; entitlement must not become an oracle that tells a caller
   which of the two conjuncts failed).
3. **Clock rollback:** with the wall clock rolled back arbitrarily far, an
   exhausted grace stays exhausted. **Assert on the persisted
   `grace_consumed_secs`, never on an elapsed-time term** — a test that asserts
   on elapsed time is asserting on the instrument §7.5.1 just removed.
4. **Restart and reboot mid-grace — the condition that catches §7.5.1.** Consume
   part of the grace budget, then **destroy and rebuild the process** (and, in
   the integration variant, reboot the host) with the state directory intact.
   The budget must resume at its consumed value, not at zero. PASS requires both
   halves:
   - *positive:* remaining budget after restart equals remaining budget before,
     within one evaluation tick;
   - *negative (non-vacuity):* the same test run against a build whose grace term
     is derived from `Instant` **must FAIL**. A restart test that passes against
     the defective implementation is measuring something else, and a positive
     test alone cannot catch a guard that stopped guarding.
5. **Deletion is not a reset:** delete the entitlement record mid-grace; the next
   evaluation DENIES (§7.3.1) and does not restart the budget. Negative test.
6. **Debit-before-allow:** kill the process between the budget write and the
   ALLOW return; the budget must show the interval as consumed. Assert on the
   persisted bytes, not on the returned verdict — the verdict is the thing that
   never happened.
7. **Non-vacuity:** with the entitlement term forced to `true`, the whole suite is
   green (proves no behaviour change); with `authorized` forced to `true`, the
   authorization suite is red (proves the `AND` is real).

**Where these live.** Conditions 3–6 are about a persisted counter, so they
belong at unit level against a temp state directory, not behind an end-to-end
VPN session. Condition 4's reboot variant is the only one that needs a host, and
it is the only one that cannot be faked by a test that re-uses one process.

---

## 8. What is metered: transport, not intent

Key on what Soyeht **operates**, never on what the user *says* they are doing.

### 8.1 Two questions, not one — and they belong to two different plans

"Metering" was used loosely in an earlier draft and it hid a real gap. There are
two separable questions, and conflating them is what let this document specify a
meter that could not see the product it claims to price.

| Question | Answer type | Owned by |
| --- | --- | --- |
| **Attribution** — *is this session chargeable?* i.e. did it traverse Soyeht-operated infrastructure | boolean, per session | **this document** (§8.2, §8.4) |
| **Volume ceiling** — *is any one principal consuming an abusive amount?* | a fixed byte ceiling, identical for every user | **`docs/soyeht-relay-vps-capacity-and-cost-plan.md` §6 lever L1 — normative** |

They compose; they do not compete. Attribution is the *applicability predicate*.
The volume ceiling is **not** a counter feeding a bill.

> **One mechanism, named once — and the capacity plan's §6 L1 is normative for
> its description. The block below is byte-identical to the copy there.**
>
> A **resource-keyed endpoint byte budget**: extend
> `PERSISTENT_MAX_BYTES_PER_DIRECTION` from `ClawSite`-only to a resource-keyed
> budget covering `IpTunnel`, and extend the reopen limiter — already keyed on
> `(claw_id, guest_device_pub)` — to cover `IpTunnel` too. It is **a constant
> compiled into the responder, identical for every user, enforced locally,
> reported to nobody, never signed, and never seen by Relay-R or by
> `Issuer-E`.** It lives at the endpoint — **never on the relay**, which must
> stay blind. It is a **fair-use and abuse ceiling, not a pricing meter.**
>
> Tiers-side framing, outside the shared block: "the endpoint" is the Claw/engine
> side, and relay blindness is §10 here. At the capacity plan's measured rate the
> egress a typical user moves costs cents, so there is nothing there to price,
> while a single principal at three orders of magnitude more is invisible today.
> Building it is the capacity plan's work item, not this one's. Neither document
> may grow the other's half.

**A correction this revision makes, because the mismatch was load-bearing.** An
earlier draft of this box said the budget is "keyed on the principal the reopen
limiter already uses, **applied exactly when the attribution predicate says
`Relay-R`**" (quoted with the retired alias `Relay-S` normalised to `Relay-R`).
That is a *different mechanism* from the one the capacity plan
specifies, and the difference is not cosmetic: a ceiling applied conditionally on
an entitlement-derived predicate is a per-user, entitlement-varying quantity —
which is precisely what §10's prohibition ("no usage telemetry as a billing
input") forbids, and it would break the capacity plan's own compliance argument,
which rests on there being **no per-user observation anywhere in the
mechanism**. The ceiling is therefore **unconditional**: it applies to every
`IpTunnel` session regardless of entitlement, exactly as the `ClawSite` budget
does today. Attribution (§8.2, §8.4) decides *chargeability*; it does not switch
the ceiling on and off.

**What would break this alignment, named in both documents:** packaging that is
*volume-differentiated* ("500 GB free, 5 TB paid"). A differentiated ceiling is a
per-user **number** delivered to the endpoint, which this plan's entitlement
value — a verdict, not a quantity — cannot carry. The only mechanism here that
could is §9.2 option (i), where `Issuer-E` signs an assertion quoting quota `N`
against a blinded pseudonym, and it is deliberately **not** in §12's build order.
The capacity plan tracks the same fork as **T-METER**; neither document may close
it alone, because it is an owner decision on packaging shape (O-9, §13).

The capacity plan's measurement of the endpoint side is adopted here rather than
re-derived, and the two agree:
`PERSISTENT_MAX_BYTES_PER_DIRECTION = 64 MiB`
(`household-rs/src/claw_share_data_tunnel.rs:276`) is gated on
`allows_persistent_targets`, which is
`offer.payload.resource == RelayStreamResource::ClawSite`
(`server-rs/src/claw_share_relay_stream_session.rs:72`, and `:110` for the
Device arm). The reopen limiter is keyed on `(claw_id, guest_device_pub)` and
its module doc says verbatim that *"`IpTunnel` … and `Pty` never reach it"*
(`server-rs/src/claw_share_relay_stream_reopen_limiter.rs:13-14`).
**So for `IpTunnel` there is no endpoint byte budget and no per-principal rate
limit today.** The tier seam has nothing to attach a counter to on the exact
resource it means to sell. That is a dependency on the capacity plan's L1, and
it is stated here so this document does not read as though the counter exists.

### 8.2 Attribution for the relay-stream family: a classifier over `relay_endpoint`

`RelayStreamOfferPayload.relay_endpoint`
(`household-rs/src/claw_share_relay_stream_contract.rs:107`, field at `:116`) is
already a signed `String`, and `provision_relay_stream_offer`
(`claw_share_relay_stream_provision.rs:47`) takes `relay_endpoint` as a
parameter. That string is the natural discriminator.

**Build a classifier over `relay_endpoint` that answers one question — "is this a
Soyeht-operated relay?" — with no policy attached.** Per §8.1 this is the
*attribution* half only: it decides applicability, it counts nothing. Gate and
charge only offers that classify as `Relay-R`.

| Session | Chargeable? |
| --- | --- |
| Offer whose `relay_endpoint` classifies as `Relay-R` | Yes |
| Offer whose `relay_endpoint` is a direct or user-operated address | No |
| Anything not traversing Soyeht infrastructure | No |

Downgrade and upgrade fall out for free, with **no new kill switch and no
out-of-band revocation sweep**: because the check sits at open *and* at liveness
(§5), a downgrade simply stops minting `Relay-R` offers and re-checks existing
ones at every open; an upgrade takes effect at the next mint.

**Open question (O-3):** nothing in `origin/main` classifies `relay_endpoint`
today — the string is carried and compared for binding
(`claw_share_relay_stream_contract.rs` has a test named
`rendezvous_stream_relay_contract_relay_endpoint_and_path_change_fail_binding`)
but never interpreted. The classifier's *rule* (exact-match against an operator
allowlist? suffix match? a signed operator attestation?) is undecided; see §13.

### 8.3 The gap this document previously hid

§2 names **device↔device VPN** as half the paid core. §8.2's classifier is
defined over `RelayStreamOfferPayload`, and the device↔device admission path
never constructs one: `MeshSessionRegistry::try_preauthorize_before`
(`household-rs/src/mesh_session_registry.rs:1177`) takes
`(&SealedBinding, Weak<H>, Instant)`. **A classifier over `relay_endpoint` is
structurally incapable of seeing a device↔device session.** As written, the tier
model claimed to price something its meter could not observe.

### 8.4 The resolution: one predicate name, two carriers

The owner's decision is that device↔device VPN *is* part of the paid core, so
the tier model does not retreat — the attribution point does.

> **The predicate is the same question in both products: "did this session
> traverse Soyeht-operated infrastructure?" It is asked of two different
> carriers, and in both cases it must be an ADMITTED fact, never an observed
> one.**

| Product | Carrier of the fact | Where it is read |
| --- | --- | --- |
| Claw VPN, ClawSite, PTY (relay-stream family) | `RelayStreamOfferPayload.relay_endpoint` — signed at mint (`contract.rs:116`) | §5.0's chokepoint, `verify_offer_with_context` (`issuer_trust.rs:77`) |
| Device↔device mesh | the transport mode the session was **admitted under** — the device-mesh plan's mode 1 (Soyeht datapath over `Relay-R`) vs mode 2 (**user-operated overlay transport**, `Overlay-U`; per-claw §12) | `MeshSessionRegistry::try_preauthorize_before` (`mesh_session_registry.rs:1177`), as an input |

**"Admitted, never observed" is the load-bearing half.** If the meter has to
*infer* the mode from a socket, a peer address, or an interface name, then the
attacker chooses the input to the inference, and the free/paid boundary is
decided by an untrusted observation. The mode must be a value the admission
decision already had, carried forward — which is R-6's rule again, applied to
the attribution fact rather than to the entitlement fact.

**Honest scope, stated rather than smoothed.** The device-mesh plan's own §2
records that rendezvous has **no implementation**; the mode-1/mode-2 distinction
is designed and unbuilt. So the device↔device attribution point **cannot be
built from this tree today**, and no PASS condition in §12 depends on it. What
*can* be fixed now, and costs nothing, is the requirement above: when the
device-mesh admission path is built, the transport mode must be an admitted
input to `try_preauthorize_before` and not something a later meter reconstructs.
Recorded as R-10 and O-7 so it is not rediscovered as a redesign.

**What must NOT be done to close this gap:** do not make `Relay-R` the meter.
The capacity plan's L1 measures why — the relay counts bytes per *splice* and
holds no principal, so metering there means ending its blindness, which is
requirement #4 (§10). A meter that can see the user is a worse outcome than a
product that charges a flat price.

---

## 9. The counted unit, if a count is used at all

The owner's stated shape is "roughly 3 shared apps free, more when paid".

### 9.1 The right counted object

**A live row in `shareable_apps`** — `retired_at IS NULL`, scoped by
`household_id` (`store-rs/src/instance_db.rs:1198`, index at `:1208`). Not
slots, not offers.

Why: it is the only object 1:1 with "an app the user shares"; it already has a
stable `app_id` primary key; `ensure_shareable_app` (`:1231`) mints it lazily and
never revives a tombstone.

**This makes the bound CONCURRENT ("N live shares at a time"), not lifetime.**
The two differ by exactly the retire-and-recreate move. If the owner means
lifetime, the count must run over rows *including* tombstones, and the plan must
say so before any code counts.

**Do not reuse the offer-store caps as the meter.** `put_minted`
(`offer_store.rs:138`) does not enforce `MAX_RELAY_STREAM_OFFERS` or
`MAX_RELAY_STREAM_OFFERS_PER_CLAW`; only `put_signed` (`:159`) does. `put_minted`
is the production path from a guest claim. Metering on those caps means the
meter has a hole on the exact path a paying user's guest takes. See §11 (R-1).

### 9.2 The honest limit: tamper-evident, not tamper-proof

**There is nowhere today to keep a count the machine owner cannot reset.**
`instance_db` is local SQLite; the mesh log is local NDJSON signed by the *local*
machine key; `HouseholdAuthState` is local CBOR; the relay sees
`{version, role, token}`. A client-unresettable count **requires** a Soyeht-side
per-household identity, which directly contradicts the owner's requirement that
the relay "must see NOTHING of the user".

That tension is real and must be chosen, not papered over. Three options:

| Option | Mechanism | Relay blindness | Cheating requires | Cost |
| --- | --- | --- | --- | --- |
| **(i) Blind quota** *(preferred)* | `Issuer-E` signs a short-lived assertion quoting quota `N` and a **blinded** household pseudonym; the client enforces `N` locally; the relay learns nothing | Preserved | Forging an `Issuer-E` signature | New signer + key distribution |
| **(ii) Tamper-evident local count** | A `ShareableAppBound` event in the mesh log, leaning on its append-only signed structure and `state_digest()` (`household_mesh_log.rs:1149`) | Preserved | Rewriting one's own signed log — **detectable, not prevented** | Low |
| **(iii) Do not count apps at all** | Make the free tier **time-bounded** (the "~3 months free" shape) instead of count-bounded | Preserved | Clock manipulation, bounded by §7.5 | Lowest — needs no identity and no counter |

Option (iii) deserves emphasis: it needs no per-user identity, no counter, and no
new store, and it matches an intent the owner already stated. If the packaging
can be time-shaped rather than count-shaped, the entire §9 problem disappears.

**Whichever is chosen, the document that ships to users must not imply
tamper-proof enforcement while shipping tamper-evident enforcement.** Stating a
hard "3 apps" limit obliges stating, in the same breath, that it is
tamper-evident (option ii) or that a blinded issuer exists (option i).

---

## 10. Privacy: what the billing layer may learn

Requirement #4 is that the relay must see nothing of the user. The billing layer
is a second observer and needs its own budget, stated as an allowlist.

| Actor | MAY learn | MUST NOT learn |
| --- | --- | --- |
| `Relay-R` | `{version, role, token}` (`claw_share_rendezvous_hello.rs:45`) and a source-IP bucket (`abuse.rs:27`) — i.e. **exactly what it learns today** | Anything else. No `household_id`, no `account_id`, no `app_id`, no member, no claw, no app name |
| `Issuer-E` | That *some* pseudonym is entitled, and until when | Which apps are shared, which Claws exist, which members exist, device keys, session times, byte counts, endpoints contacted |
| Payment provider (future) | Whatever the payment rail intrinsically requires of the payer | Any household, device, claw, app, or member identifier. The linkage between a payment identity and a household pseudonym is the thing to avoid creating |

Rules that follow:

- **Do not add identity to `RendezvousHello`** (`claw_share_rendezvous_hello.rs:45`).
  Adding `household_id`, `account_id`, or `app_id` there destroys the blindness
  property and is **unrecoverable once clients ship it**. This is the single most
  consequential prohibition in this document.
- **Do not put the tier in the signed offer contract.** A tier field on
  `RelayStreamOfferPayload` (`contract.rs:107`) becomes a wire-compatibility
  commitment shipped to guests (including `friend-cli`) and forces a re-mint of
  every offer on every packaging change. The tier belongs in the separately
  signed entitlement assertion, where packaging can change without touching the
  offer wire.
- **The entitlement assertion carries a pseudonym, not an identity.** The
  household is the natural subject; the pseudonym must be blinded so that
  `Issuer-E` cannot correlate it with a payment identity without additional
  deliberate linkage.
- **No usage telemetry as a billing input.** Per-session, per-byte, or
  per-endpoint metering would require the relay to observe what it is
  structurally built not to observe. Quotas must be enforced client-side against
  a signed number, not server-side against an observed one.

---

## 11. Named risks

- **R-1 — `put_minted` skips the caps `put_signed` enforces.**
  `offer_store.rs:138` vs `:159`. Reachable in production from a guest claim
  — `server-rs/src/claw_share_relay_loop.rs:539` →
  `try_provision_relay_stream_offer_for_claim`
  (`server-rs/src/claw_share_relay_stream_mount.rs:976`) →
  `provision_relay_stream_offer_for_claim` (`mount.rs:1107`) →
  `provision_relay_stream_offer`
  (`server-rs/src/claw_share_relay_stream_provision.rs:47`) →
  `store.put_minted`. Today the blast radius is bounded
  because slots are owner-minted and consume-once, so this is a latent asymmetry
  rather than a live DoS. **Fix it as a correctness bug, before anything counts on
  it, and not as a tier feature.**
- **R-2 — a client-unresettable count is unachievable without contradicting "the
  relay must see NOTHING".** Any plan promising both is promising something the
  architecture cannot deliver. §9.2 chooses; do not silently re-merge the two.
- **R-3 — the grace window is the first fail-soft gate in a fail-closed system,
  and its budget is state the user's machine holds.** Mitigated only by §7.5. A
  reviewer reading the entitlement module in isolation will not know that
  discipline exists, and §7.5.4 bounds what it buys: reboot, restart and
  rollback are closed; editing the state directory is not.
- **R-4 — grace must distinguish EXPIRED from REVOKED.** If it does not, the
  grace *is* a revocation bypass with a documented duration. Needs the negative
  unit test in §7.6(1).
- **R-5 — mint-time-only enforcement leaks up to 90 days** (§6.3).
- **R-6 — `ClawVpnSessionRegistry::open` (`claw_vpn.rs:579`) is ALREADY reached
  from non-test server code** (§4.1), behind a path that is compiled out of the
  production artifact. It must not become an entitlement site: the ACL it
  consults is minted from the same key one statement earlier, so a check there
  would be a rubber stamp. Design the entitlement as a **value carried into**
  each gate from §5.0's single producer, never a boolean re-derived at each site;
  re-derivation is how a policy becomes three divergent copies, and how the
  decision input ends up at an untested caller.
- **R-7 — hygiene, adjacent:** `core-rs/src/network_detect.rs:248` contains a
  literal CGNAT address in a doc comment as sample command output, in a **public**
  repository. Non-routable and low severity, but the standing constraint says no
  real IPs. A lane touching that file should neutralise it. It is deliberately not
  reproduced here.
- **R-8 — denial must not become an oracle.** The target gate today returns one
  static reason for every authorization failure. If entitlement denial returns a
  distinguishable wire reason, an unauthenticated caller can probe which conjunct
  failed. Keep the wire reason opaque; put the distinction in local logs only.
- **R-9 — the entitlement fact could land on `ProjectedState` instead of on
  `RelayStreamTrustContext`.** §5.0. The per-claw plan's §11.1 **used to** say
  the fact is "projected from the same household mesh log", which reads as
  exactly that placement; it withdrew the phrase on 2026-08-06, and the risk is
  kept because the substitution is a one-line diff that looks like a
  simplification to anyone who has not read this section. Both choices satisfy the no-second-snapshot rule; only one
  keeps the entitlement value out of `check_relay_stream_group_membership`'s type
  signature (`contract.rs:411`, first parameter `&ProjectedState`). **Reviewable
  as a one-line diff:** any change to `ProjectedState`'s field list inside an
  entitlement PR is this risk realised.
- **R-10 — the paid core includes device↔device VPN, and nothing in this tree can
  attribute a device↔device session to a transport.** §8.3 / §8.4. The classifier
  is defined over `RelayStreamOfferPayload.relay_endpoint`; the mesh-session
  admission path (`mesh_session_registry.rs:1177`) never constructs one. This is a
  **scope** risk, not a live bug — the mesh datapath is unbuilt — but it becomes a
  redesign if the mode is not carried as an admitted input from the start.
- **R-11 — a grace budget anchored on a clock is a grace budget on nothing.**
  §7.5.1. Recorded as a standing risk rather than a closed defect, because the
  same substitution is available at every future site that wants "elapsed since":
  `Instant` is the ergonomic choice in Rust and it is wrong for any quantity that
  outlives a process. The tell is a duration compared against a budget measured
  in days.
- **R-12 — this document's §8 counter does not exist and belongs to another
  plan.** §8.1. If the capacity plan's L1 (resource-keyed endpoint byte budget
  covering `IpTunnel`) does not land, the tier model has an attribution predicate
  and nothing to count with. Do not close that gap by adding a counter here; two
  counters is worse than none.

---

## 12. Build order

Only these three items are authorized by this plan. Everything else waits for a
price.

1. **An `Entitlement` value type with an explicit, named `unmetered()`
   constructor**, carried as a **fourth field on `RelayStreamTrustContext`**
   (`issuer_trust.rs:34`), produced at §5.0's chokepoint
   `verify_offer_with_context` (`issuer_trust.rs:77`), and threaded as an
   additional `AND` term into `RelayStreamOfferTargetGate`
   (`target_router.rs:165` / `:213`) and `relay_stream_offer_session_revoked`
   (`session.rs:193`). Today's behaviour must be byte-identical; the seam becomes
   visible **in the type signatures**, not in a document.
   **PASS:** whole suite green; §6.2 non-vacuity control red; no threshold
   constant anywhere in the diff; and — the §5.0 / R-9 check —
   **`ProjectedState`'s field list is untouched by the diff**, verifiable by
   `git diff` on `household_mesh_log.rs` alone.
2. **A transport classifier over `relay_endpoint`** answering "is this a
   Soyeht-operated relay?", with no policy attached and no caller yet.
   **PASS:** pure function, unit-tested both ways, zero product callers.
   **Blocked on O-3** (§13) for its rule.
3. **A written decision on the counted unit** — live `shareable_apps` rows,
   concurrent vs lifetime — recorded here, **with no threshold constant in code**.

Explicitly **not** built now: any price, currency, plan name, SKU, trial-length
constant, or threshold constant; any StoreKit / Play Billing / payment-provider
SDK; any receipt validator or webhook route; a tier field on `ClawVpnAclKey`
(`claw_vpn.rs:150`) or on `RelayStreamOfferPayload` (`contract.rs:107`); any
identity field on `RendezvousHello` (`rendezvous_hello.rs:45`); **any new field
on `ProjectedState`** (R-9); any new persistent store — including the grace
record of §7.5, which is designed but deferred because there is nothing to lapse
until a price exists.

### 12.1 What unblocks each deferred item

| Deferred | Unblocked by |
| --- | --- |
| Payment provider choice | The owner naming a rail, plus a jurisdiction/tax decision. Nothing in code depends on it — the entitlement assertion is provider-agnostic by construction |
| Price and currency | Owner decision |
| Store mechanics (App Store / Play in-app purchase vs direct) | Owner decision, then a distribution-policy read. Note the clients are in another repository, so this cannot be prototyped from this tree |
| Refunds and receipts | Follows the provider. In this design a refund is a **revocation** of the entitlement assertion, which §7.3 already specifies as immediate and grace-free |
| Free-tier thresholds (`3` apps, `3` months) | Owner decision; §9.1 fixes only the *unit*, not the number |
| Whether the bound is concurrent or lifetime | Owner decision; changes the count from live rows to all rows |
| `Issuer-E` key management, rotation, pinning | Follows the choice in §9.2. Option (iii) removes the need entirely |
| The persisted grace record of §7.5.3 | A price, because grace only exists once something can lapse. The *design* is fixed now (§7.5.2–§7.5.4) so it is not redesigned under time pressure; the record is not written until then |
| A byte counter for the paid resource | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` §6 L1 — a resource-keyed endpoint byte budget covering `IpTunnel`. Not this document's to build (§8.1, R-12) |
| Device↔device attribution | The device-mesh datapath existing at all. Until then, only the requirement in §8.4 binds: the transport mode is an admitted input, never an observation |

---

## 13. Open questions, each with the measurement that settles it

- **O-1 — Concurrent or lifetime share bound?**
  *Settled by:* an owner sentence. *Measurable consequence:* the count runs over
  `shareable_apps WHERE retired_at IS NULL` (concurrent) or over all rows
  (lifetime). The two differ by exactly one user action: retire and recreate.
- **O-2 — Count-bounded or time-bounded free tier?**
  *Settled by:* an owner sentence. *Consequence:* option (iii) in §9.2 deletes the
  entire counting problem, including the identity tension in R-2.
- **O-3 — What rule classifies `relay_endpoint` as Soyeht-operated?**
  *Settled by:* deciding between an operator allowlist compiled into the engine, a
  signed operator attestation, and a naming convention. *Measurement that
  discriminates:* whether a hostile *user* controls the string. The offer is
  owner-signed, so today the string is chosen by the household's own owner key —
  which means a household could self-declare its relay as non-Soyeht and evade
  metering. **This is unresolved and is the weakest point in §8.** A signed
  operator attestation is the only option that survives it; the allowlist is
  adequate only if the engine, not the offer, decides.
- **O-4 — Does the entitlement subject pseudonym survive a household re-pair?**
  *Settled by:* reading how `household_id` behaves across a re-pair.
  `ensure_shareable_app` (`instance_db.rs:1231`) already tombstones a binding whose
  household changed, which suggests re-scoping happens in practice. If the
  pseudonym is derived from something that rotates, a paying user loses their
  entitlement on re-pair.
- **O-5 — Is the free tier per household or per person?**
  *Settled by:* an owner sentence. *Consequence:* the ACL is keyed by
  `member_id` (`claw_vpn.rs:150`) while `shareable_apps` is keyed by
  `household_id` (`instance_db.rs:1198`). These are different subjects; the
  entitlement subject must match whichever the bound is written against, or the
  count and the gate will disagree.
- **O-6 — Does an entitlement lapse mid-session tear down or drain?**
  §7.3 specifies "continue in-flight". *Settled by:* an owner sentence on whether
  that is acceptable revenue leakage. *Bound:* it is bounded by session lifetime,
  not by the grace window, so a long-lived session is the exposure. Measuring the
  observed session-duration distribution would quantify it; no such measurement
  exists today.
- **O-7 — Will the device-mesh admission path carry its transport mode as an
  admitted input?** §8.4. *Settled by:* reading the signature of
  `MeshSessionRegistry::try_preauthorize_before` when the mesh datapath is built.
  Today it is `(&SealedBinding, Weak<H>, Instant)`
  (`household-rs/src/mesh_session_registry.rs:1177`) — **no transport-mode term**,
  which is correct for what it does today and insufficient for attribution. *The
  measurement that discriminates:* whether the mode reaching the meter is a value
  the admission decision already held, or one reconstructed afterwards from a
  socket, address, or interface name. The second is decided by an input the
  attacker chooses.
- **O-8 — Can an entitlement module reach the durable clock floor without new
  API?** §7.5.2 says yes via `MachineRosterStore::query_roster_evidence`
  (`machine_roster_store.rs:1571`, `pub`) →
  `RosterEvidenceSnapshot.floor_secs` (`machine_roster_evidence.rs:104`, `pub`).
  *Not yet verified:* whether that call is affordable at entitlement-evaluation
  frequency. It takes the cross-process `RosterLock` and performs a durable
  atomic write — its own doc comment calls serving evidence *"an authenticated
  temporal-state write, not a cache read"*. *Settled by:* measuring the call's
  cost and the lock contention it adds when invoked on the open path. If it is
  too expensive there, the answer is a cheaper **read-only** floor accessor with
  the same monotonic guarantee — **not** a cached copy, which would reintroduce
  a rewindable value.
- **O-9 — Is the packaging shape volume-differentiated?** §8.1. This is the one
  open question that puts this plan and
  `docs/soyeht-relay-vps-capacity-and-cost-plan.md` back into conflict, and that
  plan tracks it as **T-METER** (its §6 L1) and as its own Q9. The mechanism
  chosen here is a **verdict**; a volume-differentiated tier needs a **number**
  delivered per user, which exists here only as §9.2 option (i) and is not in
  §12's build order. *Settled by:* an owner sentence on shape —
  transport-shaped (§8), count-shaped (§9.1), time-shaped (§9.2 option iii), or
  volume-shaped. Three of the four require nothing from the capacity plan.
  *Recorded, not decided:* the capacity plan's measured egress rate gives no
  economic reason to pick the fourth. Until it is answered, the byte ceiling
  stays a single fixed constant (§8.1) and neither document specifies a meter.
