# Product A — mobile Claw control over per-Claw VPN

Status: planning document for the Product A slice that puts a Soyeht iPhone in
control of Mac and Linux Claws over the Soyeht-owned per-Claw VPN datapath.

Status header rewritten 2026-08-06. This plan was the only one of the Product A
set left out of the previous rewrite round: three sibling plans each declared one
of its invariants superseded and each assigned the edit elsewhere, so nobody made
it. Four of that round's blocking findings were against this file. They are
answered in §0.

**This plan is not an activation record and does not authorize production by
itself.** Every public example uses neutral aliases only. Real hostnames, device
names, account names, LAN/tailnet addresses, relay endpoints, any real IP outside
documentation ranges, paths, secrets, and raw run logs must remain in ignored
private files or operator-only stores.

## Measurement trees

This document reads **two repositories**, and every claim below is tagged with
the one it was measured in. Line numbers are valid only in the tree named beside
them and are never carried across trees; symbol names and repo-relative paths are
the stable handles.

| Tag | Repository | Commit read | Date |
|---|---|---|---|
| `theyos@e60bad85` | `github.com/soyeht/theyos` (public) | `e60bad85313eb39c9a000a29852bde1a944e425e` | 2026-08-06 |
| `ios@e2fcab64` | `github.com/soyeht/soyeht-ios` | `e2fcab64ca2d91a691225ab74929ab9ee0cd49ff` | 2026-08-05 |

**No build and no test was run for this rewrite.** Everything in §0 is a read of
source, workflow YAML and git history at those two commits. Where that is not
enough to settle a question, the question is written down with the measurement
that would settle it, rather than smoothed over.

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/server-rs/src/mobile_claw_vpn_*.rs
  - admin/rust/server-rs/src/claw_vpn_t1_relay_stream_router.rs
  - admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs
  - admin/rust/server-rs/src/main.rs
  - admin/rust/t1-iptunnel-dev-runner-rs/src/main.rs
  - admin/rust/tunnel-wire-rs/
  - admin/rust/claw-share-bridge-rs/
  - admin/rust/Cargo.toml
-->

The `ios@e2fcab64` half of this table is **not** covered by the doc-freshness
gate: that gate can only measure history in the repository it runs in. The
cross-repo pin is a separate mechanism, and its absence is why nothing reports
the drift measured in §0.2 — the iOS build's `household-rs` vendor pin sits
**174 commits** behind `theyos@e60bad85` (153 excluding merges), a **6-day**
gap (`c81144ba` 2026-07-31 → `e60bad85` 2026-08-06), by
`git rev-list --count c81144ba..e60bad85`. An earlier revision of this paragraph
said "858 commits behind for six weeks"; that figure is not reproducible at
either commit and is withdrawn — it also contradicted this document's own §0.2.

Aliases used here:

- `Device-D`: a Soyeht iPhone dev device.
- `App-M`: the Soyeht macOS app/engine coordinating user-visible state.
- `Claw-M`: a Mac Claw target.
- `Claw-L`: a Linux Claw target or VM.
- `Relay-R`: the community rendezvous relay.
- `Mesh-C`: the mesh/control-plane state used for discovery, authorization,
  offers, and revocation.
- `Overlay-U`: the overlay network a user brings and operates themselves — a
  personal WireGuard, Tailscale, or equivalent. The mode is **user-operated
  overlay transport**, defined in `docs/product-a-per-claw-vpn-plan.md` §12,
  which also holds the single registry of the spellings this mode retired —
  including the ones this plan used. That list is not restated here.

## Which document is normative for what

Settled 2026-08-06 across the five Product A / cost plans, so that a shared
concept is resolved **once**. A document that is not normative for a row cites
that row's owner and does not restate it; where two documents disagree, the
defect is in the non-normative one.

| shared concept | normative document |
|---|---|
| transport modes — the Soyeht datapath vs **user-operated overlay transport** (`Overlay-U`) | `docs/product-a-per-claw-vpn-plan.md` **§12** (per-mode security table: §12.3) |
| entitlement chokepoint | `docs/soyeht-tiers-and-entitlement-plan.md` **§5.0** |
| relay cost, capacity, and the limits a session runs under | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` |
| device⇄device track | `docs/product-a-device-mesh-vpn-plan.md` |
| iOS client state | **this document** |

---

## 0. Measured state (2026-08-06)

### 0.1 What the dev-host T1 arc did and did not establish

Both halves belong in one paragraph, and neither may be quoted without the
other.

**The datapath was observed working, once.** On 2026-07-09 an owner-present run
on a dev host (`docs/product-a-per-claw-vpn-t1-t2-hardware-observation-log.md`,
code under test `main` @ `368a88f9`) injected ICMP toward the claw `/32` through
the tunnel interface and got 40/40 then 20/20 back — **60/60, 0% loss**, RTT
≈ 12.4 ms and ≈ 11.7 ms — alongside route-installation and teardown sweeps. ICMP
echo requires both directions to carry, so that is end-to-end bidirectional
delivery, not a self-report. **And that record is not an activation
authorization.** Its own opening block states, verbatim, that it is an
observation log and *not* a preflight/activation record; it carries **no owner
signature**; `production_activation=false`; and the production mount remains
`PerClawVpnT1PreflightEvidence::missing`. The log further records that only
claw-`/32` reachability was verified and that *"a complete route-scope negative
(e.g. default route provably unchanged) was not separately captured"*.

**And the datapath is not in a product build at all.** At `theyos@e60bad85` the
`IpTunnel` resource path is **compiled out**, not merely default-off:
`IP_TUNNEL_RESOURCE_COMPILED` in
`admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs` is
`cfg!(any(test, feature = "dev_t1_datapath"))`; the `cfg(not(...))` arm of
`ClawTargetRouter` answers `IpTunnel` with
`target_unavailable("relay-stream-iptunnel-compiled-out")`; and
`admin/rust/server-rs/src/main.rs` carries a `compile_error!` refusing to build a
release binary with `dev_t1_datapath`, `dev_claw_share_mint` or
`failure-injection` enabled. `dev_t1_datapath` is not in `default`.

**Therefore there is no "SHA-bound private gate validates the activation
artifact" achievement to cite.** The SHA-binding machinery exists and is
executable — `startup_wiring.rs` parses `per_claw_vpn_t1_preflight_evidence_v1`
with an exact 40-hex artifact SHA match, scope `dev-host T1-T4 only`,
`production_activation=false`, three non-empty private refs and an
absolute-normal `audit_root` — but it has never been fed an authorized record,
and the engine bootstrap path hardcodes `PerClawVpnT1PreflightEvidence::missing`
and never reads the record env var. Only the mount reads it. The correct sentence
is *"the gate is built and unexercised"*, never *"the gate validated the
artifact"*.

Consequences for the phases below: **T1–T4 are not a proven baseline this plan
may reuse.** They are a single dated observation on superseded code. The
2026-07-09 log predates `#392` (the post-`Open` `NetworkSettings` frame),
`157c3d6b` (the compile-out), `#410` and `#413`, so under the checklist's own
SHA-binding rule it is **not** reusable as `hardware_evidence_ref` at any new
artifact SHA. A fresh T1–T4 pack at the activation SHA is required. Sequencing,
producers and PASS conditions for that run live in
`docs/product-a-per-claw-vpn-plan.md` §13 and are not duplicated here.

### 0.2 There are two client FFI stacks, and the iPhone links the *other* one

This is the correction that most changes this plan, and it invalidates a
reviewer finding as stated as well as the sentence the finding was aimed at.

| | `claw-share-bridge-rs` | `relay-stream-guest-ffi` |
|---|---|---|
| Repo / path | `theyos@e60bad85`, `admin/rust/claw-share-bridge-rs` | `ios@e2fcab64`, `Native/RelayStreamGuestFFI` |
| Shipped to the iPhone? | **No.** No xcframework, no Swift package, no `import` anywhere in `ios@e2fcab64` | **Yes.** `RelayStreamGuestFFI.xcframework`, built by `Scripts/build-relay-stream-guest-ffi-xcframework.sh` — a path in the **iOS** repo (`ios@e2fcab64`), not in this one — imported by the packet-tunnel extension |
| Workspace status | unconditional member of `admin/rust/Cargo.toml`; `default = []`; `uniffi` optional | standalone crate in the iOS repo; depends on a **vendored copy of theyos `household-rs`** |
| CI | `cargo fmt/check/clippy/test -p claw-share-bridge-rs`, plus `--features uniffi` check+clippy (`backend-ci.yml`) | built and its Swift consumers tested by `xcodebuild test -scheme Soyeht` on an iOS **Simulator** destination (`ios@e2fcab64`, `.github/workflows/xcode.yml`) |

**The absence claim, re-run and corrected — it enumerates names now, not just
paths.** An earlier revision said "the only occurrences of the string
`ClawShareBridge` in `ios@e2fcab64` are **two** test files". That enumeration was
**wrong**: there is a third occurrence. Re-measured with
`git grep -n <pat> e2fcab64` in the current `soyeht-ios` clone, over every
spelling the crate is named by:

| pattern | hits at `ios@e2fcab64` | where |
|---|---|---|
| `claw-share-bridge` (the cargo/crate spelling) | **0** | — |
| `claw_share_bridge` (the Rust module spelling) | **0** | — |
| `ClawShareBridge` (the Swift-cased spelling) | **3**, in 3 files | `Packages/SoyehtCore/Tests/SoyehtCoreTests/MeshDataPlaneInertBoundaryTests.swift` and `…/OwnerSiteA2TransportScaffoldTests.swift` — both listing it as a **forbidden** surface an inert scaffold must not introduce — and `docs/claw-store-execution-plan.md`, a scope note telling that repo to **keep it out** |

**What the corrected enumeration supports, and no more:** the crate is absent
under every spelling; there is no dependency edge, and all three mentions are
prohibitions rather than uses. The conclusion the earlier sentence drew survives;
its count did not. It is stated this way because an absence claim that
enumerates only the paths it happened to look at is how a third occurrence
survives review.

**The vendored copy is pinned, and it is behind.** Both
`Native/RelayStreamGuestFFI/Cargo.toml`
(`household-rs = { path = ".vendor/theyos/admin/rust/household-rs" }`) and
`Scripts/prepare-household-rs-source.sh` pin
`SOURCE_REV = c81144ba9ac98c0b19912c51765886b227ba30f5` — theyos `c81144ba`,
2026-07-31, `#403`. That is **174 commits behind `theyos@e60bad85`**. Everything
the iPhone links from theyos is therefore measured at `c81144ba`, not at
`e60bad85`; the `tunnel-wire-rs` extraction (`#413`) and everything after it is
not in the iOS build. **Uncertainty, stated:** this rewrite read the *iOS FFI's
own* source at `ios@e2fcab64` and did not diff `household-rs` between `c81144ba`
and `e60bad85`. The measurement that would settle whether that drift changes any
wire or validation behaviour is
`git diff c81144ba..e60bad85 -- admin/rust/household-rs` in theyos, read for
`claw_share_data_tunnel` and `claw_share_relay_stream_contract` in particular.
Until that is run, no statement here about the *engine* side may be assumed true
of the *bytes the phone actually links*.

### 0.3 Route-scope enforcement, per stack

The document previously asserted, as shipped fact, that *"the iPhone FFI
independently validates and installs only that CIDR, fail-closing on a
default/out-of-scope route, an invalid frame, or a `session_id` mismatch."*
Measured, that sentence is **true of the stack the iPhone links and false of the
crate the reviewers measured**. Both halves are recorded.

| Check | `claw-share-bridge-rs::accept_network_settings` (`theyos@e60bad85`) | `relay-stream-guest-ffi::validate_ip_tunnel_network_settings` (`ios@e2fcab64`) | Swift `RelayStreamIPTunnelNetworkSettings.make` (`ios@e2fcab64`) |
|---|---|---|---|
| frame **missing** | **not enforceable** — its own doc says the bridge cannot know whether the path is `IpTunnel`; delegated to the consumer | **enforced** — `requires_network_metadata` is *derived* from the verified offer (`offer.payload.resource == RelayStreamResource::IpTunnel`), and the read is under a timeout that fails closed | n/a (a `nil` `meshIpv4`, or a non-`nil` `meshIpv6`, is rejected in the provider) |
| frame **duplicated** | **enforced** — a second frame is refused rather than allowed to re-point a configured interface | one frame is consumed on the open path | n/a |
| `session_id` == auth ack | **enforced** | **enforced** | **not here** — only non-empty is checked |
| `mtu` == auth ack | not checked | **enforced**, plus `1280..=9000` | `1_280...9_000` only |
| `prefix_len` bound | **NOT CHECKED — copied verbatim, `u8` unbounded. `prefix_len = 0` is `0.0.0.0/0`, a default route by another name** | `1..=31` | `1...31` |
| `addr`/`peer` parse as IPv4 | not checked | enforced | enforced |
| `peer != addr`, unicast, peer inside prefix | not checked | enforced | enforced |
| network / broadcast address excluded | not checked | enforced when `prefix_len <= 30` | enforced when `prefix_len <= 30` |
| route actually installed | n/a — hands a `VpnNetworkSettings` to a consumer | n/a — returns metadata | `NEIPv4Settings.includedRoutes = [network/mask]`, `tunnelRemoteAddress = peer`. **One prefix, explicitly set; never `NEIPv4Route.default()`** |

Reading of that table:

1. **The reviewer finding against `claw-share-bridge-rs` is CONFIRMED as a
   defect of that crate.** `accept_network_settings` has exactly **three**
   rejection arms — settings-before-handshake, `session_id` mismatch, and
   duplicate-frame — and **none of them looks at the address**: it then copies
   `prefix_len` verbatim, unbounded.  (Counted at `theyos@e60bad85`; the same
   three are counted in `product-a-per-claw-vpn-plan.md` §3.2, which is why the
   route-scope check would be the *fourth*.) `MeshIpv4::route_scope_violation()` exists in
   `admin/rust/tunnel-wire-rs/src/tunnel_wire.rs` as a callable and is invoked by
   `admin/rust/t1-iptunnel-dev-runner-rs/src/main.rs` and by nothing else in
   `theyos@e60bad85`. The strict decoder `decode_network_settings_body` enforces
   only canonical CBOR shape (`deny_unknown_fields`, canonical key order, no
   trailing bytes) — not route scope.
2. **The finding's conclusion — "the iPhone FFI does not validate" — does not
   follow**, because that crate is not what the iPhone links. The stack the phone
   links validates route scope **twice**, in Rust and again in Swift, and the
   Rust half additionally closes the *missing-frame* hole that
   `claw-share-bridge-rs` documents as unclosable, because it knows the resource
   from the offer it verified.
3. **The gap is real anyway and stays a REQUIREMENT, not an achievement.**
   `claw-share-bridge-rs` is an unconditional workspace member with no T1,
   preflight or feature gate, exposing the full `VpnNetworkSettings` surface, and
   it is the crate a *second* client would most plausibly reach for. The moment
   any client links it — including a shared client for **user-operated overlay
   transport** (`Overlay-U`; § product invariants, and
   `product-a-per-claw-vpn-plan.md` §12.3 row S12) — the missing bound becomes
   live. **Required change, owned in `product-a-per-claw-vpn-plan.md` §13.1 as
   B2:** add `route_scope_violation()` as a **fourth** rejection arm in
   `accept_network_settings` — *fourth*, not third: an earlier revision of this
   line said third and disagreed with the plan that owns the fix — with the
   `prefix_len = 0` negative asserted as a unit test **on the FFI itself**, not
   only against a server that would never send it (that plan's T20). This plan
   does not invent a second remedy.
4. **Single-implementation point, named.** On the iOS path the cross-phase
   `session_id`/`mtu` equality against the auth ack lives in exactly one place —
   the vendored Rust. The Swift layer re-derives the *route* rules but checks
   only that the session id is non-empty. That is defensible layering, but it
   means a regression in the vendored crate is not caught by the Swift tests. The
   measurement that would settle whether it is covered: whether any test in
   `Native/RelayStreamGuestFFI` asserts a mismatched-`session_id` frame is
   rejected. Not read for this rewrite.

### 0.4 Evidence-hygiene correction carried into this plan

Repeated twice to the owner in a form that is half wrong, and therefore
corrected here so it is not re-imported:

> ~~"26,694 lines in the excluded crates never compile or run in CI."~~

Measured at `theyos@e60bad85`: `admin/rust/Cargo.toml` line 7 excludes
`mesh-session-control-model-rs` and `mesh-session-core-rs`, together **26,692
lines**. **The predicate, so the number is reproducible rather than quotable:**
the sum of `wc -l` over every **tracked `.rs` file** under those two crate
directories at `origin/main` — **28 files**, splitting 14,732
(`mesh-session-core-rs`) + 11,960 (`mesh-session-control-model-rs`). The two
crates hold 34 tracked files in all; the six manifests and lockfiles are outside
the predicate. `docs/product-a-device-mesh-vpn-plan.md` §1.3 carries the same
figure and the same predicate; **`26,694` matches no path set tried at this SHA**
and survives only as the quoted claim being corrected. What is true is narrower
and stranger:

- **Their libraries DO compile in CI.** `backend-ci.yml` derives its
  `(package, feature)` list from `cargo metadata` — never hand-written — and runs
  `cargo check --locked -p <pkg> --all-targets --features <feat>` for every
  non-default feature of every workspace package. `keystore-rs` declares
  `mesh-session = [..., "dep:mesh-session-core-rs"]`, and its `src/lib.rs` carries
  `#[cfg(feature = "mesh-session")]` with
  `#[path = "../../mesh-session-control-model-rs/src/lib.rs"]`. So both excluded
  crates' libraries are compile-checked through that member.
- **Their tests never execute.** No `cargo test` invocation can reach a
  non-member package.
- **`mesh-session-control-model-rs/tests/model_invariants.rs` (6,137 lines) does
  not even compile.** `keystore-rs/src/lib.rs` inlines it behind
  `#[cfg(all(test, feature = "mesh-session", feature = "test-support",
  feature = "roster-sync-unratified"))]` — **three features at once** — while the
  CI loop passes **one feature at a time**. No single-feature invocation can ever
  reach it. This is structural, not an oversight of one run.

Correct phrasing, wherever this comes up: *libraries compile; tests never
execute; `model_invariants.rs` does not even compile, for the three-feature
reason above.*

### 0.5 What is not measured

Stated so a later reader does not mistake absence for confirmation.

- The `household-rs` drift between the iOS vendor pin `c81144ba` and
  `theyos@e60bad85` (§0.2).
- Whether the vendored FFI has a negative test for a mismatched `session_id`
  (§0.3).
- Claw-side teardown ordering on abnormal exit at `theyos@e60bad85`. A **T4**
  claim must not lean on this document for it.
- Whether the iOS simulator test run exercises the extension's `startTunnel`
  path at all, or only the pure types around it. A simulator has no
  NetworkExtension activation (see Phase 6).

---

## Goal

Ship a Soyeht-owned, per-Claw VPN path where `Device-D` can select and control
`Claw-M` or `Claw-L` through Soyeht, with:

- a datapath that depends on no third-party overlay;
- a blind, untrusted community relay used only for rendezvous/splice;
- mesh/control-plane authorization before any tunnel becomes usable;
- per-Claw route scope, not a default/full-tunnel VPN;
- Mac and Linux Claw support;
- real E2E validation from iPhone dev hardware.

## Target architecture

```text
Device-D (Soyeht iPhone)
  -> Mesh-C discovery/authorization
  -> Relay-R blind rendezvous/splice (Device-D and Claw-* both dial outbound)
  -> Claw-M or Claw-L per-Claw VPN responder (no inbound listener required)
  -> Soyeht control channel for the selected Claw
```

Responsibilities:

- `Device-D`: mobile controller, NetworkExtension packet tunnel client, and
  user-facing connect/disconnect state.
- `App-M`: coordinates Claw inventory, offers, user-visible session state, and
  audit/status surfaces. It must not become a datapath proxy, Linux admin
  workaround, or secret-printing proxy.
- `Claw-M` / `Claw-L`: VPN responder plus Soyeht control target. Each Claw owns
  its tunnel interface, route scope, packet policy, teardown, and audit events.
- `Relay-R`: blind pairing/splice only. It is not trusted for security or
  authorization and must not need plaintext.
- `Mesh-C`: discovery, owner/member/device authorization, offer lifecycle,
  revocation, and stale-session prevention.

## Product invariants

### Transport choice — two claims that were conflated

The previous invariant read: *"Tailscale may be used for developer
administration only; it is not part of the shipped VPN datapath."* That sentence
carried two distinct claims and the owner decision of 2026-08-06 supersedes
exactly one of them. It is split rather than deleted:

- **(a) Our datapath depends on no third-party overlay. STILL TRUE, kept.** The
  Soyeht per-Claw VPN does not require Tailscale or any other user-operated
  overlay to function, and no third-party overlay code is in our datapath. E2E
  evidence must still prove the *product* route/tunnel was used rather than LAN,
  tailnet, or another fallback path — otherwise the run measures someone else's
  network.
- **(b) The user may not choose one. NOW FALSE, superseded.** A user may elect
  to reach their Claws over an overlay they operate themselves — personal
  WireGuard, Tailscale, or equivalent (`Overlay-U`). That is a **supported
  product mode** — **user-operated overlay transport**, the one name all five
  plans use for it — not dev tooling and not a workaround. An `Overlay-U` user
  pays nothing for carriage and is fully supported on the control plane.

**This split is what the other plans must quote.** Three sibling documents cite
this sentence; until 2026-08-06 two of them quoted it in its *unsplit* form, as
though it were still a live single invariant. It is not, and has not been since
this rewrite: clause (a) stands, clause (b) is superseded.

The authoritative per-mode analysis — which security properties survive, which
change hands, and what the product UI is obliged to say — is
`docs/product-a-per-claw-vpn-plan.md` §12, and this plan **aligns with it rather
than inventing a second resolution**. The three consequences that bind *this*
document:

1. **S3 (E2E encryption) and S9 (anti-spoof + no forwarding) are not ours on
   that path**, and byte-level audit is unavailable because there is no pump of
   ours to count. Revocation is **authorization-complete but not necessarily
   reachability-complete**: we can stop a session being opened; whether the
   member can still reach the Claw at the IP layer is the user's overlay ACL,
   which we neither read nor control.
2. **The CGNAT exclusion becomes more load-bearing, not less.**
   `ClawVpnIpv4Pool::try_new` rejecting overlap with `100.64.0.0/10` and the RFC
   1918 ranges stops being hypothetical once a user deliberately runs a
   CGNAT-using overlay on the same phone.
3. **The route-scope gap in §0.3 becomes a prerequisite, not a nicety.** A
   user-operated overlay transport is a second plausible producer of a
   `NetworkSettings`-shaped frame; a client that accepted `prefix_len = 0` from
   it would install a default route.

Nothing here is a licence to weaken a gate. Where this mode removes one of our
properties, the mode loses the property — the gate does not.

### Datapath invariants

- v1 is one selected Claw per active iPhone tunnel. Authorization may be N:N,
  but each active route scope is per selected Claw.
- The iPhone installs only the selected Claw route, preferably `/32` for the
  Claw tunnel address. It must not install a default route by default.
- The Claw responder is not a LAN router. It accepts only the session peer to
  the selected Claw address and drops everything else fail-closed.
- **T1 IpTunnel address delivery — RATCHET (placeholder → real):** the Claw
  responder emits the guest's REAL, pool-allocated IPv4 address to the iPhone in
  a dedicated post-`Open` `NetworkSettings` frame (kind `0x17`); the auth
  `TunnelAck` still carries only a placeholder `mesh_ipv6` and stays address-free
  as an allocation on every path (PTY/ClawSite/Device unchanged). Server-side
  `build_vpn_mesh_ipv4`
  (`admin/rust/server-rs/src/claw_vpn_t1_relay_stream_router.rs`,
  `theyos@e60bad85`) enforces the route-scope invariant **fail-closed before the
  session opens**: it rejects `prefix_len == 0 || > 32`, `device == peer`,
  non-unicast, and either address outside `network(addr, prefix_len)`, returning
  `claw-vpn-t1-route-scope-{prefix,peer,cidr}` and closing the session. The
  frame's `session_id` equals the auth ack's, giving a cross-phase binding.
- **Client-side route scope is a REQUIREMENT with a named gap — see §0.3.** On
  the stack the iPhone links today it is held twice over (Rust
  `validate_ip_tunnel_network_settings` and Swift
  `RelayStreamIPTunnelNetworkSettings.make`, `ios@e2fcab64`). On
  `claw-share-bridge-rs` (`theyos@e60bad85`) it is **absent**: `prefix_len` is
  unbounded and `MeshIpv4::route_scope_violation()` is never called. Until that
  arm lands (`product-a-per-claw-vpn-plan.md` §13.1 B2, T20), enforcement in
  `theyos` is server-side only, which is a single-implementation assumption. **No
  document in this repo may state client-side route scope as a shipped property
  of `claw-share-bridge-rs`.**
- A real default route / full-tunnel remains a separate authenticated policy
  decision, never inferred from a settings frame.
- All offers and records are SHA/session bound where applicable. Stale offers,
  stale records, stale refs, and revoked ACL entries fail closed.

### Privacy invariants

- Public logs, docs, PRs, screenshots, and agent messages must contain only
  aliases and documentation-safe addresses. Real `Relay-R` endpoints must be
  treated as private operator values and shown publicly only as aliases.
- Raw E2E captures must live as mode `0600` files inside private ignored
  directories with mode `0700`.

## Work phases

### Phase 1 — product model and state machine

Define the concrete user/product model:

- Claw identity model for Mac and Linux Claws.
- iPhone device identity and enrollment state.
- Per-Claw authorization state.
- Offer lifecycle: create, publish, consume, expire, revoke.
- Session lifecycle: unavailable, available, connecting, connected, degraded,
  disconnecting, disconnected, failed, revoked.
- Transport mode as an explicit, user-visible product state: Soyeht datapath vs
  user-operated overlay (§ Product invariants). The two modes must not be
  representable as the same state with a different address.
- User-visible macOS/iOS status fields.

Deliverables:

- Product state-machine document.
- Threat model update for `Device-D -> Relay-R -> Claw-*`.
- Explicit list of states that must fail closed.
- The user-facing statement of which properties are ours and which are the
  user's transport's, for the overlay mode. Required; the string itself is owned
  by product, not by this plan.

### Phase 2 — Mesh-C discovery and authorization

Implement/control:

- Claw registration and availability.
- Device-to-Claw ACL entries.
- Owner/member authorization for iPhone access to each Claw.
- Explicit per-Claw VPN capability, separate from existing PTY/share
  capabilities.
- Offer minting for `IpTunnel` sessions.
- Offer TTL, single-use/replay protection, and revocation.
- Status surface for active sessions and denied attempts.

Exit criteria:

- `Device-D` can request access to `Claw-M` or `Claw-L`.
- Unauthorized or revoked device cannot obtain a usable offer.
- Expired/stale offer cannot connect.
- All denial output is generic and no-value-echo.
- Agents may implement validators, dry-runs, fixtures, and mocked tests
  autonomously, but must not grant real owner/member ACL access, mark a real
  enrollment authorized, or call an owner authorization complete without owner
  input.

### Phase 3 — Relay-R community rendezvous

Prepare the community relay path for product E2E:

- Stable dev endpoint for `Relay-R`.
- Blind splice only; no plaintext, no authorization authority.
- Explicit rendezvous sequence: `Mesh-C` authorizes/mints an offer; `Device-D`
  and the selected `Claw-*` both dial outbound to `Relay-R`; `Relay-R` pairs the
  slot and splices bytes without authenticating the product session, initiating
  any inbound connection, or seeing plaintext.
- Abuse limits: pending slots, source caps, TTL, splice caps, idle timeout.
- Health check and operator status.
- Redacted logs only.

Relay capacity, cost and scaling posture are owned by
`docs/soyeht-relay-vps-capacity-and-cost-plan.md`. This plan takes only the
security posture from it: the relay holds **no authorization role**.

Exit criteria:

- `Device-D` outside the Claw LAN can rendezvous with `Claw-M` and `Claw-L`.
- No inbound listener on `Claw-*` is required for rendezvous.
- Relay failure produces a clear user error and cleans up local tunnel state.
- Relay compromise does not grant access without valid session auth.

### Phase 4 — Claw responder for Mac and Linux

Productize the responder side for both target classes:

- Mac Claw responder using `utun`.
- Linux Claw responder using `tun`.
- Pollable pump for both sides.
- Route apply/cleanup with bounded rollback.
- Interface/route/process cleanup on all exits.
- Drop non-IPv4 and out-of-policy packets without killing valid sessions.
- Audit events for open, denied, revoked, closed, and teardown result.

Exit criteria:

- `Claw-M` responder can run and tear down cleanly.
- `Claw-L` responder can run and tear down cleanly.
- Policy rejects traffic not bound to the selected session pair.
- Teardown leaves no tunnel route, interface, or responder process.

### Phase 5 — Soyeht macOS coordinator

Implement the macOS app/engine product layer:

- List Claws and their VPN availability.
- Mint or fetch per-Claw offers.
- Show iPhone connection state per Claw.
- Start/stop responder where appropriate.
- Treat `Claw-L` as its own responder agent/daemon: it registers availability
  through `Mesh-C` and serves offers itself. `App-M` coordinates user-visible
  state and owner actions; it must not become an implicit SSH or overlay control
  path or an ad hoc Linux administration proxy.
- Show audit/status without leaking real identifiers.
- Handle sleep/wake and reconnect-visible state.
- Keep production and dev profiles separate.

Exit criteria:

- macOS can prepare a session for `Device-D -> Claw-M`.
- macOS can prepare a session for `Device-D -> Claw-L`.
- UI/status reflects connect, disconnect, error, and revoked states.
- Starting a responder is gated by profile checks plus an explicit user action
  or an approved background policy. Missing, denied, or stale gates must fail
  before opening TUN/utun, installing routes, spawning responder processes, or
  marking the Claw connectable.

### Phase 6 — iPhone Packet Tunnel client

**This phase is not at 0–10%. A substantial implementation exists, in a
different repository, and this plan previously did not know that.** Measured at
`ios@e2fcab64` in `github.com/soyeht/soyeht-ios`.

#### 6.1 What exists

**2,438 lines of Swift across 12 files are dedicated to the IP tunnel** — 1,068
lines of source and 1,370 of tests:

| File (repo-relative, `ios@e2fcab64`) | Lines | Role |
|---|---|---|
| `TerminalApp/SoyehtClawShareTunnelProvider/SoyehtClawShareTunnelProvider.swift` | 270 | the `NEPacketTunnelProvider` itself |
| `Packages/SoyehtCore/Sources/SoyehtCore/Mesh/RelayStreamIPTunnelSessionMachine.swift` | 245 | start/stop lifecycle, epoch-checked |
| `TerminalApp/Soyeht/RelayStream/RelayStreamIPTunnelController.swift` | 200 | host-app side: prepares and passes start options |
| `Packages/SoyehtCore/Sources/SoyehtCore/Mesh/RelayStreamIPPacketPump.swift` | 141 | `RelayStreamIPPacket`, `RelayStreamIPFamily`, the pump |
| `TerminalApp/SoyehtClawShareTunnelProvider/RelayStreamIPTunnelNetworkSettings.swift` | 117 | route-scope validation → `NEPacketTunnelNetworkSettings` |
| `TerminalApp/SoyehtClawShareTunnelProvider/NEPacketTunnelFlowAdapter.swift` | 54 | `NEPacketTunnelFlow` ⇄ pump binding |
| `TerminalApp/SoyehtClawShareTunnelProvider/RelayStreamGuestIPTunnelSessionAdapter.swift` | 41 | narrows the frame protocol to packets; PTY control frames fail closed |
| `…SoyehtCoreTests/RelayStreamIPTunnelSessionMachineTests.swift` | 391 | tests |
| `…SoyehtTests/RelayStreamIPTunnelControllerTests.swift` | 382 | tests |
| `…SoyehtTests/RelayStreamIPTunnelNetworkSettingsTests.swift` | 328 | tests |
| `…SoyehtTests/RelayStreamGuestIPTunnelSessionAdapterTests.swift` | 131 | tests |
| `…SoyehtCoreTests/RelayStreamIPPacketPumpTests.swift` | 138 | tests |

Behind them, `Native/RelayStreamGuestFFI/src/lib.rs` (3,434 lines total for the
whole guest FFI, of which the `IpTunnel` path is one part) drives offer
verification, rendezvous, Noise NK, auth, health, open, and the post-`Open`
`NetworkSettings` frame.

The provider target is a real `PBXNativeTarget`, a dependency of the app target,
and embedded in the app's *Embed App Extensions* phase — it is not an orphaned
directory.

**The `NEPacketTunnelFlow` adapter question this plan flagged as needing
explicit design is answered in code.** The decision taken was *Rust core through
FFI, Swift-native pump*: `NEPacketTunnelFlowAdapter` wraps
`readPackets`/`writePackets`, rejects a `packets.count != protocols.count`
mismatch, maps each protocol number through `RelayStreamIPFamily` and rejects an
unsupported family, and treats a `false` from `writePackets` as an error rather
than a silent drop. `RelayStreamGuestIPTunnelSessionAdapter` re-validates every
frame as an IP packet in both directions and fails closed on any non-packet
frame kind (`window`, `exitCode`, `exitSignal`, `exitLost`, `health`, `open`).
Packet boundaries are preserved because the transport is frame-per-packet, not a
byte stream.

**Lifecycle ordering is designed, not incidental.** `startTunnel`/`stopTunnel`
arrive as synchronous callbacks on NetworkExtension's queue;
`RelayStreamIPTunnelSessionMachine` commits each intent synchronously at the
callback and hands out an epoch, so a stop that arrives during a start supersedes
it instead of racing it, and the losing session is closed by its own caller. A
pump failure claims ownership before emitting `cancelTunnelWithError`, so a
stale generation cannot cancel a newer tunnel.

**Fail-closed ordering before route install is implemented.** In `beginSession`:
start options must be present and decode against a live clock; the offer must be
canonical (`offer.canonicalBytes() == startOptions.offerCbor`); it must verify
via `verifyRelayStreamIPTunnelGuest` against the expected signer and guest device
keys; and the start options must bind to it — `authMode`, `endpoint`, `targetId`
vs `clawId`, `authMaterialCbor`, and `expiresAt <= payload.notAfter` — or
`authBindingMismatch`. Only then is a session dialled. Network settings are
applied **before** the session is returned, and any failure closes the session.

**Entitlements are declared, in both flavours** (verbatim keys, `ios@e2fcab64`):

| Key | `SoyehtClawShareTunnelProvider.entitlements` | `…ProviderDev.entitlements` |
|---|---|---|
| `com.apple.developer.networking.networkextension` | `packet-tunnel-provider` | `packet-tunnel-provider` |
| `com.apple.security.application-groups` | `group.com.soyeht.mobile.clawshare` | `group.com.soyeht.mobile.clawshare.dev` |
| `keychain-access-groups` | `$(AppIdentifierPrefix)$(CFBundleIdentifier)`, `$(AppIdentifierPrefix)com.soyeht.mobile.clawshare.mesh` | same, `.mesh.dev` |

#### 6.2 A DECLARED entitlement is not a PROVISIONED one

**Say this out loud wherever the entitlements are cited.** A `.entitlements`
plist is a *request*. Whether the App ID carries the Network Extensions
capability and whether the provisioning profile actually grants
`packet-tunnel-provider` is settled by a **signed build that installs and runs on
real hardware** — never by reading a plist, and never by a green simulator test.

Two measured facts that make this concrete rather than pedantic:

- `TerminalApp/Soyeht.xcodeproj/project.pbxproj` at `ios@e2fcab64` sets
  `DEVELOPMENT_TEAM = "<IOS_TEAM_ID>"` — a **placeholder**, not a team. Automatic
  signing cannot resolve a profile carrying the capability from that.
- `TerminalApp/Base.xcconfig` is explicitly *"CI-safe defaults (ad-hoc signing,
  no team)"*: `CODE_SIGN_IDENTITY = -`, `DEVELOPMENT_TEAM =` empty, with a
  gitignored `Local.xcconfig` override for local developers.
- CI runs `xcodebuild test -scheme Soyeht` against an **iOS Simulator**
  destination. A simulator does not exercise NetworkExtension activation, does
  not evaluate the entitlement against a profile, and cannot create a `utun`.

So the honest status is: **implemented and unit-tested; never provisioned, never
activated, never run on device.** The go/no-go the owner is asked for is not
"does the code exist" but "does a signed device build install and start the
tunnel".

#### 6.3 What remains

- **Entitlement provisioning** — App ID capability, profile, team. PASS
  condition: a signed dev build installs on `Device-D` and
  `NETunnelProviderManager` saves a configuration without an entitlement error.
  This is an owner/infra unlock, not agent work.
- **The engine side is compiled out** (§0.1). There is nothing on the product
  server for this client to dial until a `dev_t1_datapath` build plus an
  authorized preflight record exists. The client being ready does not move that
  gate.
- **The vendor pin is 174 commits behind** (§0.2). Repinning is a decision with
  a wire-compatibility question attached; see the diff named there.
- **Claw selection UI** and per-Claw offer selection.
- **Reconnect across network change / background** at the product level, beyond
  what the lifecycle machine handles.
- **User-visible status and redacted errors** — the provider's log lines are
  static labels today (`relay_stream_ip_tunnel_started`, `…_start_failed`,
  `…_packet_pump_failed`), which is the right shape; the product surface still
  needs building.
- **MTU coherence.** `product-a-per-claw-vpn-plan.md` §3.5 records **four** live
  and disagreeing MTU values — 1280 advertised on both frames, 1250 enforced by
  the claw pump, 1400 as the dev config generator's default, and **none** set on
  the interface at all (its defect D2; the capacity plan's R9 measures the same
  four). The iOS side accepts `1280..=9000` and configures from
  the advertised value, so it will faithfully configure a number the claw pump
  may then drop packets against. Do not run mobile E2E before that is unified;
  otherwise the run measures the wrong thing.

Exit criteria:

- `Device-D` connects to a selected Claw through `Relay-R` on a signed device
  build.
- The mobile datapath adapter preserves packet boundaries, handles backpressure
  without over-counting delivery, cancels cleanly, and cannot corrupt a partial
  stream frame on suspend/reconnect.
- Default route is not captured; only the selected Claw route is installed.
- Disconnect removes the route and packet tunnel.
- Ordering is fail-closed: verify offer, session binding, ACL, revocation
  status, and selected-Claw identity before route install and before reporting
  `connected`. Invalid, stale, revoked, or mismatched input must prevent route
  installation, tear down any partial tunnel state, and report only a redacted
  error.
- A `prefix_len = 0` settings frame is refused **by the client** — asserted as a
  unit test on the client, not inferred from a server that would never send one.

### Phase 7 — Soyeht control over the VPN

Wire the actual control plane over the tunnel:

- Soyeht command/control channel reaches the selected Claw over an in-tunnel
  endpoint bound to the selected Claw route. The concrete protocol/port/service
  must be documented before E2E and must be scoped by the active session ACL.
- Terminal/control APIs work for `Claw-M`.
- Terminal/control APIs work for `Claw-L`.
- Control failure is distinct from tunnel failure in user-facing state.
- There is no fallback to a user overlay, LAN, or relay data channel when the
  product tunnel is down. Switching transport mode is a deliberate user choice,
  never an automatic degradation.
- No command payload or secret material enters public logs.

Exit criteria:

- `Device-D` can control a Mac Claw over the Soyeht datapath alone.
- `Device-D` can control a Linux Claw over the Soyeht datapath alone.
- Control survives normal packet loss/retry within documented bounds.
- Tunnel up plus control service down reports a degraded/control-failed state,
  not a tunnel success. Tunnel down plus control request must fail without
  falling back to any non-product datapath.

### Phase 8 — E2E matrix

Run real E2E with private raw capture and public redacted summaries:

- `Device-D -> Claw-M` on the same LAN.
- `Device-D -> Claw-L` on the same LAN.
- `Device-D -> Claw-L` in a remote network.
- `Device-D -> Claw-*` over `Relay-R` from outside the LAN.
- Cellular or otherwise non-shared-network run with **no pre-existing user
  overlay active on `Device-D`** — the property this row was always about is *no
  shared L2 and no other VPN in the path*, so that our datapath is measured in
  isolation.
- `Overlay-U` mode: Claw reachable over the user's own overlay with
  the product datapath disabled. Must record which properties we provide and
  which we do not (`product-a-per-claw-vpn-plan.md` §12.3, T22).
- Relay offline.
- Claw offline.
- Offer expired.
- Revocation during active session.
- Reconnect after network change.
- iOS background/foreground.
- iOS screen lock/unlock.
- Soyeht app kill/reopen while the Packet Tunnel remains active.
- Wi-Fi -> cellular and cellular -> Wi-Fi.
- Claw responder restart while iOS tunnel is active.
- Relay idle timeout while iOS app is suspended.
- Selected `Claw-M` cannot reach `Claw-L`, a LAN peer, or engine/admin
  endpoint through the tunnel.
- Selected `Claw-L` cannot reach `Claw-M`, a LAN peer, or engine/admin endpoint
  through the tunnel.
- Device authorized for one Claw is denied for an unselected/unauthorized Claw.
- Tunnel up with control service down.
- Control authorization revoked while the tunnel is up.
- Teardown after normal disconnect and after forced failure.

Each passing E2E must prove:

- T1: tunnel interface up.
- T2: sustained forwarding with a numeric threshold: at minimum 60 seconds of
  traffic with `>=98%` ICMP delivery or an equivalent `N/N` packet count,
  plus TCP echo or real Soyeht control payload success. Pump counters may
  corroborate delivery, but they do not replace end-to-end delivery evidence.
- T3: selected-Claw route scope only; default route unchanged. **The negative
  half must be captured explicitly** — the 2026-07-09 log records that it was
  not, and a repeat of that omission makes the route-scope claim unfalsifiable.
- T4: teardown/rollback clean.
- Soyeht control channel works over the tunnel.
- The route table has exactly the selected Claw route for the tunnel scope; no
  default route, LAN route, overlay route, unselected Claw route, or engine/admin
  route is installed through the tunnel.
- Attempts to reach unselected Claws, LAN peers, and engine/admin endpoints are
  denied or dropped without session reuse.
- The product tunnel, not a user overlay or LAN, carried the bytes: public
  summaries should show only aliases and product tunnel/relay evidence, never
  overlay addresses or routes.
- Relay failure and control-service failure produce distinct public summaries.
- Command denial and control auth errors do not log command payloads.
- iOS lifecycle cases leave no stale route, stale interface, stale session, or
  misleading connected state.
- Public summary has no real hostnames, paths, secrets, LAN/overlay IPs, relay
  endpoints, real non-documentation IPs, or device identifiers.
- **Every E2E result names the two trees it was measured in** (theyos SHA and
  soyeht-ios SHA) and the vendor pin in force. A mobile result without both is
  not attributable.

### Phase 9 — reviews and release gates

Required lenses before product release:

- Code/build correctness.
- Fail-closed gates and ordering.
- Test/evidence fidelity.
- Architecture/datapath/boundary.
- Privacy/no-value-echo.

Blocking findings include:

- Full-tunnel/default-route capture without explicit product decision.
- A client that accepts an unbounded `prefix_len` from a settings frame.
- Relay treated as trusted authorization.
- Stale offer/session/record accepted.
- Secret, path, hostname, LAN/overlay IP, relay endpoint, real
  non-documentation IP, or device identifier in public output.
- Teardown leaves interface/route/process behind.
- iPhone can reach anything beyond the selected Claw scope.
- Claw responder forwards to LAN or another Claw.
- A shipped-fact claim about a security property that is measured only in the
  crate that is *not* linked (the §0.3 failure mode).

### Phase 10 — rollout

Rollout sequence:

1. Local dev profile.
2. Internal iPhone dev devices.
3. Mac dev app.
4. Remote Linux Claw dev target.
5. TestFlight/internal dogfood.
6. Controlled production rollout.

Production release requires:

- signed/reviewed release record for the effective build SHA;
- green CI and release validation;
- rollback plan;
- private evidence pack;
- owner approval for production activation;
- no open blocking findings;
- production evidence and owner approval newly bound to the effective
  production build SHA and production policy. Dev-host T1 records, dev private
  evidence, and `production_activation=false` records cannot authorize
  production.

## Owner and infrastructure unlocks

These are the only expected human/infra unlocks. Everything else should proceed
as implementation/review work without ceremony.

Can proceed automatically:

- Documentation, architecture drafts, local code, and test implementation.
- Unit tests, mocked/no-host integration tests, dry-run scripts, and private
  validators.
- Redacted evidence formatting, local static scans, and PR preparation.
- Review-response edits that do not grant real access, mutate a host, publish
  private evidence, or activate production.
- **T1 dev-host activation decisions**, delegated to the agents by owner
  decision of 2026-08-06 and sequenced in `product-a-per-claw-vpn-plan.md` §13.
  Production activation, production deploy and flag flips affecting real
  households are **not** covered by that delegation.

Requires Caio or owner/infra action:

- Provide or confirm the disposable dev relay endpoint for `Relay-R` as a
  private operator value. Public docs and evidence should use only the `Relay-R`
  alias.
- Ensure a dev-accessible Linux Claw target is online when remote E2E starts.
- Ensure Mac Claw and iPhone dev devices are available when mobile E2E starts.
- **Provision the packet-tunnel entitlement**: App ID capability, development
  team, and a profile that grants `packet-tunnel-provider`. The entitlement is
  already *declared* in both prod and dev plists (§6.1); provisioning is the part
  no agent can do and no plist can prove (§6.2).
- Approve real `Device-D` / `Claw-*` enrollment and real ACL grants.
- Confirm any owner/member authorization record for real device-to-Claw access.
- Grant temporary owner-present sudo or scoped NOPASSWD only when a run needs
  TUN/utun/route mutation on a dev host.
- Produce the T1 owner authorization record — the single irreducible
  owner-produced artifact of the activation PR.
- Approve publication of evidence outside the private store.
- Confirm production rollout only after all dev/TestFlight gates are complete.

Agents must not request passwords in chat and must not print secrets. If an
unlock is needed, ask for the exact minimal owner action, then continue
automatically after it is done.

## Current blocker inventory

Rewritten 2026-08-06 against measurement. The previous line — *"No code blocker
is known"* — was wrong in both directions: it missed a real client-side gap and
it missed a substantial existing implementation.

| # | Blocker | Kind | Where it is owned |
|---|---|---|---|
| 1 | `claw-share-bridge-rs::accept_network_settings` accepts an unbounded `prefix_len` and never calls `route_scope_violation()` | **code** | `product-a-per-claw-vpn-plan.md` §13.1 B2 + T20 |
| 2 | Engine-side `IpTunnel` path is compiled out of any product build; no authorized preflight record exists | **gate** | `product-a-per-claw-vpn-plan.md` §13 (dev-host, delegated); production remains owner-authorized |
| 3 | Packet-tunnel entitlement is declared but never provisioned; no signed device build has ever run | **owner/infra** | this plan, §6.2 |
| 4 | iOS vendor pin of theyos `household-rs` is 174 commits behind `e60bad85`; drift unmeasured | **code/measurement** | this plan, §0.2 |
| 5 | **Four** disagreeing MTU values (1280 advertised / 1250 enforced / 1400 generated / none on the interface); a compliant client will emit packets the claw pump drops | **code** | `product-a-per-claw-vpn-plan.md` §3.5 / §13.1 B1 + T21 |
| 6 | Mesh/offer/session product wiring for mobile Claw selection | **product** | Phases 1–2 here |
| 7 | Mac and Linux responder productization | **product** | Phase 4 here |
| 8 | Community relay dev/prod readiness | **infra** | `soyeht-relay-vps-capacity-and-cost-plan.md` |
| 9 | Real iPhone-to-Claw E2E across the matrix | **evidence** | Phase 8 here |
| 10 | `dev_t1_datapath` implies `dev_claw_share_mint`, an owner-authorization **bypass** fixture — so no dev-host T1 run is a faithful rehearsal of the production authorization path | **named risk** | `product-a-per-claw-vpn-plan.md` §8 |

Blockers 1–5 are prerequisites of Phase 6 exit. Nothing in this list may be
discharged by relaxing a gate; if a fix appears to need one relaxed, it is
recorded as a risk instead.

## Definition of done

Product A mobile Claw control is complete when:

- `Device-D` can select and connect to `Claw-M` over the Soyeht-owned datapath,
  with no third-party overlay required.
- `Device-D` can select and connect to `Claw-L` on the same terms.
- `Overlay-U` mode (user-operated overlay transport) works as a supported
  alternative, with the
  properties it does and does not carry stated to the user (T22).
- Soyeht control commands work over the tunnel for both Claw classes.
- Relay-R is blind and untrusted.
- Mesh-C authorizes and revokes sessions correctly.
- Route scope is per selected Claw, not a default route — enforced on the
  **server and the client**, with the client half asserted by a client-side
  negative test.
- T1/T2/T3/T4 pass in the real E2E matrix at the activation SHA, with the
  route-scope negative captured, not assumed.
- Public evidence is redacted and private raw capture is stored as `0600` files
  under `0700` private directories.
- All five review lenses are clean.
- Rollback is documented and tested.

Nothing in this plan is authorized to run anywhere by virtue of the plan
existing.
