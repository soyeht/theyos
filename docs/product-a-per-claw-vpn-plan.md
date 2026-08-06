# Product A — per-Claw VPN plan (relay_stream → real IP tunnel)

Authored 2026-07-02 by the security-review agent at the owner's request.
Status header rewritten 2026-08-06.

> **Why the header changed.** The previous status block was 203 lines of
> append-only prose: every slice added a sentence and no sentence was ever
> retracted, so by 2026-08-06 nine of its claims were false and the structure
> made that invisible. It is replaced by §0 — a dated state table plus a dated
> ledger — so that "what is true now" and "what changed when" are separately
> readable. The slice-by-slice narrative is not reproduced; `git log` over
> `admin/rust/server-rs/src/claw_vpn_*`,
> `admin/rust/household-rs/src/claw_vpn.rs` and
> `admin/rust/t1-iptunnel-dev-runner-rs/` is the authoritative history.

**Measurement tree.** Every file, symbol, constant and line number in this
document was read from `origin/main` at commit
`e60bad85313eb39c9a000a29852bde1a944e425e` (2026-08-06). Line numbers are
valid in that tree only; symbol names are the stable handle. Any reader
re-measuring in a different tree must re-derive them.

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/server-rs/src/claw_vpn_*
  - admin/rust/server-rs/src/claw_share_relay_stream_mount.rs
  - admin/rust/server-rs/src/claw_share_relay_stream_offer_store.rs
  - admin/rust/server-rs/src/claw_share_relay_stream_target_router.rs
  - admin/rust/server-rs/src/main.rs
  - admin/rust/server-rs/Cargo.toml
  - admin/rust/household-rs/src/claw_vpn*.rs
  - admin/rust/t1-iptunnel-dev-runner-rs/
  - admin/rust/claw-share-bridge-rs/
-->

**Aliases.** This document uses neutral aliases only — no real hostnames, IPs,
device IDs, or account identifiers: `Claw-A` (a specific target claw/VM),
`Member-M` (a household member), `Device-D` (Member-M's iPhone), `Relay-R`
(the Soyeht-operated public rendezvous/splice relay — the **single** relay alias
across all five plans, per `docs/agent-operations-index.md` §2; the earlier
second alias `Relay-S` is retired), `Overlay-U` (an overlay network the *user*
brings and operates — a personal
WireGuard, Tailscale, or equivalent), `Engine-dev` / `Engine-prod` (engine
instances). Multi-party scenarios use `Member-M1`/`Member-M2`/`Member-M3` and
a second claw `Claw-B`. The only concrete IP ranges named are
standards-reserved documentation/reserved ranges (`198.18.0.0/15` RFC 2544,
`100.64.0.0/10` RFC 6598, RFC 1918) — never a deployed address.

## Which document is normative for what

Settled 2026-08-06 across the five Product A / cost plans, so that a shared
concept is resolved **once**. A document that is not normative for a row cites
that row's owner and does not restate it; where two documents disagree, the
defect is in the non-normative one.

| shared concept | normative document |
|---|---|
| transport modes — the Soyeht datapath vs **user-operated overlay transport** (`Overlay-U`) | **this document, §12** (per-mode security table: §12.3) |
| entitlement chokepoint | `docs/soyeht-tiers-and-entitlement-plan.md` **§5.0** |
| relay cost, capacity, and the limits a session runs under | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` |
| device⇄device track | `docs/product-a-device-mesh-vpn-plan.md` |
| iOS client state | `docs/product-a-mobile-claw-control-vpn-plan.md` |

**One name for the mode.** The user-supplied-transport mode is called
**user-operated overlay transport**, and the network the user operates is
**`Overlay-U`**. "Overlay-U mode" is the short form. The spellings this mode
retired are enumerated **once**, in **§12** of this document; the other four
plans cite that registry and do not keep their own.

---

## 0. Where the code actually is (measured 2026-08-06 @ `e60bad85`)

### 0.1 The headline: the datapath is *absent*, not merely off

The single most load-bearing security property of the per-Claw VPN today is
**not** "default-off". It is **compiled out**. In any build that is not
`cfg(test)` and does not pass `--features dev_t1_datapath`, the `IpTunnel`
resource path, the `claw_vpn_*` modules, the mount wiring and the bootstrap
gate are *not present in the artifact at all*.

| Mechanism | Where | Effect |
|---|---|---|
| `IP_TUNNEL_RESOURCE_COMPILED` | `server-rs/src/claw_share_relay_stream_offer_store.rs` — `pub const … = cfg!(any(test, feature = "dev_t1_datapath"))` | `false` in a product build; `require_resource_enabled` returns `ResourceCompiledOut` |
| Router arm | `server-rs/src/claw_share_relay_stream_target_router.rs`, the `#[cfg(not(any(test, feature = "dev_t1_datapath")))]` impl of `ClawTargetRouter` | `RelayStreamResource::IpTunnel => Err(target_unavailable("relay-stream-iptunnel-compiled-out"))` — no gate call, no backend reference |
| Mount branch | `server-rs/src/claw_share_relay_stream_mount.rs` | `#[cfg(any(test, feature = "dev_t1_datapath"))]` returns `assemble_relay_stream_live_with_ip_tunnel_router(...)`; the `not(...)` branch returns plain `assemble_relay_stream_live(...)` |
| Bootstrap gate | `server-rs/src/main.rs` | the `per_claw_vpn_startup_gate_from_env()` call itself is `#[cfg(feature = "dev_t1_datapath")]`, and its result is bound to `_claw_vpn_status` (discarded) |
| Release refusal | `server-rs/src/main.rs:26` | `compile_error!("the production server binary cannot be built with DEV/test features")` when `dev_t1_datapath`, `dev_claw_share_mint` or `failure-injection` is enabled |
| CI enforcement | `.github/workflows/owner-present-phase0-compileout.yml`, plus `check-mobile-claw-vpn-owner-present-phase0-compileout.sh` invoked from `release-linux.yml` and `release-macos.yml` | the compile-out is re-proved on every release build, not only on PR |

`dev_t1_datapath = ["dev_claw_share_mint"]` is declared in
`server-rs/Cargo.toml` and is **not** in `default`. `dev_claw_share_mint` is
labelled in that same file as an owner-authorization **bypass** fixture.
Enabling `dev_t1_datapath` therefore also enables an auth-bypass mint path;
the two cannot be taken separately today. That coupling is a named risk (§8.2).

**PASS condition for this claim** (re-runnable): a `cargo build -p server-rs`
with no extra features produces a binary in which
`grep -c relay-stream-iptunnel-compiled-out` is ≥ 1 and
`grep -c relay-stream-iptunnel-not-configured` is 0 — i.e. the *absent* arm
is the one linked, not the *unavailable-router* arm. Not yet executed; see
§0.5.

### 0.2 Component state table

| Component | File / crate | State @ `e60bad85` |
|---|---|---|
| Signed resource `IpTunnel` | `household-rs/src/claw_share_relay_stream_contract.rs` | reserved and mintable. `validate_resource_for_audience` there forbids only `Pty` for `Group`/`Public`; it carries **no** `IpTunnel` fail-close (see §0.4 correction) |
| Offer→backend gate | `server-rs/src/claw_share_relay_stream_target_router.rs` | `validate_ip_tunnel_target` requires audience `Group` and passes `check_relay_stream_group_membership` on the exact projection that gated the signer |
| T1 caller gate | `server-rs/src/claw_vpn_t1_caller.rs` | ordered, lazy: `Disabled`/`InvalidConfig` return **before** `load_preflight()` runs and before any caller is built; pinned by two tests asserting the closures were never invoked |
| Preflight evidence loader | `server-rs/src/startup_wiring.rs` | parses `per_claw_vpn_t1_preflight_evidence_v1`: exact 40-hex artifact SHA match, scope `dev-host T1-T4 only`, `production_activation=false`, three non-empty private refs, absolute-normal `audit_root` |
| Engine bootstrap path | `server-rs/src/startup_wiring.rs` | `per_claw_vpn_startup_gate_with` hardcodes `PerClawVpnT1PreflightEvidence::missing`. It never reads `THEYOS_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD`. **Only the mount does.** The bootstrap path can therefore never report anything but `Disabled` / `InvalidConfig` / owner-authorization-required |
| Address pool | `household-rs/src/claw_vpn.rs` — `ClawVpnIpv4Pool::try_new` | **decided and enforced**, not open. Rejects `prefix_len > 30`, host bits set, and any overlap with CGNAT `100.64.0.0/10` or all three RFC 1918 ranges |
| Route-scope invariant (server) | `server-rs/src/claw_vpn_t1_relay_stream_router.rs` — `build_vpn_mesh_ipv4` | rejects `prefix_len == 0 \|\| > 32`, `device == peer`, non-unicast, and either address outside `network(addr, prefix_len)`. Called from **both** `open_ip_tunnel` impls before the runtime is assembled; on violation the session is closed via `core.close_with_audit` and the dial fails |
| Route-scope invariant (neutral rule) | `tunnel-wire-rs/src/tunnel_wire.rs` — `MeshIpv4::route_scope_violation()` | exists as a callable, deliberately **not** wired into `TunnelFrame::decode` (its doc comment states the reason: decode must stay byte-identical). Consumers are expected to call it |
| Dev client | `t1-iptunnel-dev-runner-rs` | under `--features dev_t1_datapath`, `run-device-datapath` opens a real TUN/utun, installs routes through the reviewed route plan, drives the pollable pump to a bounded budget, and calls `route_scope_violation()` on the received frame |
| iOS FFI | `claw-share-bridge-rs` (`src/lib.rs`, **1,594** lines; the crate's two tracked `.rs` files total **1,609** — `src/bin/uniffi-bindgen.rs` is the other 15) | unconditional workspace member, `default = []`, only `uniffi` optional. Exposes `VpnNetworkSettings { addr, prefix_len, peer, mtu, session_id }` behind **no** T1/preflight/feature gate, and does **not** call `route_scope_violation()` (§0.4) |
| Guest CLI | `friend-cli-rs` | permanently refuses: `bail!("relay_stream IpTunnel payload is not implemented in this client")` before any TCP connect. This is intended to stay a refusal |
| Per-claw VPN ACL store | — | **does not exist.** `ClawVpnAcl` is constructed fresh inside `open_ip_tunnel` and immediately granted the key derived from the already-authenticated target — a rubber stamp. Real authorization is 100% signed offer + live household projection |

### 0.3 Gate chain: bootstrap → live `IpTunnel` session

In order. Each row fails closed on its own.

| # | Gate | Where | Failure |
|---|---|---|---|
| G0 | build feature | `IP_TUNNEL_RESOURCE_COMPILED`, router `cfg(not(...))` arm, mount branch | `relay-stream-iptunnel-compiled-out` |
| G0b | release build | `server-rs/src/main.rs:26` | `compile_error!` — refuses to build |
| G1 | offer store | `require_resource_enabled` | `ResourceCompiledOut` |
| G2 | mount env parse | `parse_resource_for_policy` rejects `ip_tunnel` | resource not policy-selectable |
| G3 | dev config | `ClawVpnDevConfig::from_env` — needs `THEYOS_CLAW_VPN_LIVE=1` XOR `THEYOS_CLAW_VPN_DIAL=1`, plus endpoint and IPv4-pool vars | `None`→`Disabled`, `Err`→`InvalidConfig` |
| G4 | SHA-bound evidence | `t1_preflight_evidence_bundle_from_env` + `load_..._for_current_build` vs `THEYOS_SERVER_BUILD_GIT_SHA` | preflight `missing` → router `Unavailable` |
| G5–G7 | ordered preflight | `assemble_claw_vpn_t1_caller`: owner authorization → rollback → hardware T1–T4 | first missing gate returns; no caller constructed |
| G8 | mode | exhaustive match; `Dial` → `UnsupportedMode` | client-side mode never activates the claw side |
| G9 | audit sink | `t1_open_audit_sink_from_preflight` | no bundle / bad root → a sink that always `Err`s |
| G10 | per-open offer | `validate_ip_tunnel_target`: live clock, `verify_offer_with_context`, `expected_path == RelayStream`, `resource == IpTunnel`, `target_id == claw_id`, audience **must be `Group`**, `check_relay_stream_group_membership` | `relay-stream-iptunnel-member-required` or the membership reason |
| G11 | admission reserve | `ClawVpnSessionRegistry` limits | session refused |
| G12 | audit accept | sink must accept `SessionOpen` before runtime inputs are built | fails closed; rollback `SessionClose` routed through the same sink |
| G13 | route scope | `build_vpn_mesh_ipv4` | `claw-vpn-t1-route-scope-{prefix,peer,cidr}`, session closed |

**Where it stops today.** In a product build: G0/G1. In a
`dev_t1_datapath` build without a private record: G4. The terminal object on
the blocked path is `RelayStreamMountedIpTunnelRouter::Unavailable(
RelayStreamIpTunnelUnavailableRouter)`, which answers every open with
`target_unavailable("relay-stream-iptunnel-not-configured")`; the status is
logged with a `Debug` impl that prints `caller = "<redacted>"`.

### 0.4 Corrections this rewrite makes to the previous header

The old header asserted these; they were false at `e60bad85`.

| Old claim | Measured truth | Superseded by |
|---|---|---|
| "The mount now injects that backend through the same T1 caller gate" (stated unconditionally) | true only under `cfg(test)` or `--features dev_t1_datapath`; the product build takes a different branch | `157c3d6b` 2026-07-11 |
| "the engine bootstrap observes the default-off per-Claw VPN dev config" | the call site is feature-gated **and** its result discarded | `157c3d6b` |
| the startup gate is the classifier for the runbook gates | it hardcodes `PerClawVpnT1PreflightEvidence::missing` and never reads the record env var; only the mount reads it | pre-existing, never recorded |
| `IpTunnel` "remains fail-closed … (`claw_share_relay_stream_contract.rs`)" | that file holds no `IpTunnel` fail-close; the three real fail-closes are the offer store const, the router `cfg(not(...))` arm, and the mount's `parse_resource_for_policy` | `157c3d6b` |
| address range is an undecided "Phase-1 decision" | decided and enforced in `ClawVpnIpv4Pool::try_new` | pre-existing |
| default bootstrap "cannot … run an iOS Packet Tunnel" | half true: the engine side is blocked, but `claw-share-bridge-rs` (added 2026-07-31, `c81144ba`) is an unconditional workspace member exposing the full `VpnNetworkSettings` surface with no gate | `c81144ba` |
| "Status: plan + early scaffolding" | a real client (`t1-iptunnel-dev-runner-rs`) opens interfaces, installs routes and pumps packets; a real owner-present run carried 60/60 ICMP (§0.6) | `#392`, the observation log |

**How stale the old header was — stated as a reproducible count, not a number.**
An earlier draft of this section asserted "fourteen commits touched per-claw VPN
code … none updated it". That number is withdrawn: it was not reproducible
because the counting predicate was never stated, and no path set tried at
`e60bad85` yields it. What is reproducible, with the command spelled out:

```
# the claim that carries the argument, and the only one that needs no path set
git log --oneline e4bd798f..e60bad85 -- docs/product-a-per-claw-vpn-plan.md
# → empty. ZERO commits touched this document in that range.

# the code-side count, with the exact path set (Appendix A's three paths)
git log --oneline --no-merges e4bd798f..e60bad85 -- \
  'admin/rust/server-rs/src/claw_vpn_*' \
  admin/rust/household-rs/src/claw_vpn.rs \
  admin/rust/t1-iptunnel-dev-runner-rs/
# → 8   (9 if merge commits are counted)

# widened to the two crates the area later grew into
git log --oneline --no-merges e4bd798f..e60bad85 -- \
  'admin/rust/server-rs/src/claw_vpn_*' \
  admin/rust/household-rs/src/claw_vpn.rs \
  admin/rust/t1-iptunnel-dev-runner-rs/ \
  admin/rust/claw-share-bridge-rs/ \
  admin/rust/tunnel-wire-rs/
# → 10  (12 if merge commits are counted)
```

The count is a function of the path set, which is exactly why quoting a bare
number was wrong. `e4bd798f` is the last commit that touched this file before
the 2026-08-06 rewrite; its dates differ by field — author 2026-07-05,
committer 2026-07-09 — and the ledger below uses the committer date.

### 0.5 What is *not* measured

Stated so a later reader does not mistake absence for confirmation.

- **No build or test was run for this rewrite.** Every claim above is a read
  of source and git history at `e60bad85`.
- **13 tests compile but never execute in CI.** Say this precisely, because
  the loose version ("this code never runs in CI") is wrong in its first half
  and the distinction is the whole point. `dev_t1_datapath` reaches CI through
  **three** steps in `backend-ci.yml`, all compile-only:
  1. `cargo clippy -p t1-iptunnel-dev-runner-rs --all-targets --features
     dev_t1_datapath --locked -- -D warnings`;
  2. the **feature-surface** step, which derives every `(package, non-default
     feature)` pair from `cargo metadata` and runs `cargo check --locked -p
     <pkg> --all-targets --features <feat>` over the list — so
     `server-rs --features dev_t1_datapath` and
     `claw-share-bridge-rs --features uniffi` are compiled here, including
     their test targets, without anyone naming them;
  3. the compile-out script invoked from the release workflows.

  What no step does is **run** them: `dev_t1_datapath` is never passed to
  `cargo test`. Every `cargo test` invocation in the workflows uses default
  features, with one exception that is a different feature
  (`-p household-rs --features mesh-session-runtime --test
  compile_fail_peer_expectation`). So the tests that compile-but-never-execute
  are exactly the live-datapath ones: **10** in
  `t1-iptunnel-dev-runner-rs/src/main.rs` behind
  `#[cfg(feature = "dev_t1_datapath")]` — nine individually gated plus the
  whole `dev_datapath_two_end_integration` module — and **3** in
  `server-rs/src/bin/t1_iptunnel_claw_dev.rs`, whose target declares
  `required-features = ["dev_t1_datapath"]`. Counted at `e60bad85` by
  brace-matching the gated regions. Compiling is not exercising: these steps
  catch a caller that stopped type-checking, never a guard that stopped
  guarding.
- **The FFI's tests, by contrast, do execute.** `claw-share-bridge-rs` is a
  workspace member with its own CI job running `cargo test -p
  claw-share-bridge-rs` on default features. This is load-bearing for §13.1 B2:
  a negative test added there *runs*, whereas one added behind
  `dev_t1_datapath` would only compile. Prefer the FFI as the home for any
  route-scope negative.
- **A structural trap worth naming even though it is not in this area.** In the
  excluded `mesh-session-*` crates, `keystore-rs` inlines a large test file
  behind `#[cfg(all(test, feature = "mesh-session", feature = "test-support",
  feature = "roster-sync-unratified"))]` — *three* features at once, while the
  feature-surface loop passes exactly **one** feature per invocation. No
  single-feature invocation can ever reach it, so that file is neither compiled
  nor run. Recorded here only as the shape to check for: a `cfg(all(...))` with
  more features than the enumerating loop passes is invisible to a coverage
  argument built on that loop. Nothing in the per-claw VPN area currently has
  that shape, checked at `e60bad85` with

  ```
  git grep -nE 'cfg\(all\(' origin/main -- \
    'admin/rust/server-rs/**' 'admin/rust/t1-iptunnel-dev-runner-rs/**' \
    'admin/rust/claw-share-bridge-rs/**' 'admin/rust/tunnel-wire-rs/**' \
    | grep -E 'feature.*feature'
  ```

  which returns nothing. Re-run it whenever a feature is added to these crates;
  a single hit means the feature-surface step has stopped covering that region
  and its silence has become uninformative.
- The claw-side teardown ordering on abnormal exit (route cleanup, interface
  destroy) has not been read at this SHA. A **T4** claim must not lean on
  this document for it.
- Whether an `IpTunnel` offer with a `Device` or `Public` audience can be
  **minted and stored** today is unverified. `validate_resource_for_audience`
  forbids only `Pty` for shared audiences, so such an offer appears signable;
  it simply cannot reach a backend (G10 rejects with
  `relay-stream-iptunnel-member-required`). See §9 Q3.

### 0.6 Hardware observation, 2026-07-09 — both halves

On 2026-07-09 an owner-present run on a dev host
(`docs/product-a-per-claw-vpn-t1-t2-hardware-observation-log.md`, code under
test `main` @ `368a88f9`) **observed the datapath working**: ICMP injected
toward the claw `/32` through the tunnel interface returned 40/40 then 20/20,
**60/60 total, 0% loss**, RTT ≈ 12.4 ms and ≈ 11.7 ms; ICMP echo requires both
directions to carry, so this is measured end-to-end bidirectional delivery,
alongside route-installation and teardown sweeps. **And that record is not an
activation authorization**: its own opening block states it is an observation
log and *not* a preflight/activation record, it carries no owner signature,
`production_activation=false`, and the production mount remains
`PerClawVpnT1PreflightEvidence::missing`. Neither half may be quoted without
the other. Two further limits belong in the same breath: the log itself
records that only claw-`/32` reachability was verified and *"a complete
route-scope negative (e.g. default route provably unchanged) was not
separately captured"*; and the run predates `#392` (post-`Open`
`NetworkSettings`), `157c3d6b` (compile-out), `#410` (admission-instant caller
repair) and `#413` (`tunnel-wire-rs` extraction), so it is **not** re-usable
as `hardware_evidence_ref` at a new artifact SHA — the checklist's SHA-binding
rule forbids it.

### 0.7 Dated ledger

Newest first. This table is append-only; §0.1–§0.4 are rewritten in place.

| Date | Commit / PR | What changed | What it superseded |
|---|---|---|---|
| 2026-07-31 | `c81144ba` (#403) | added `claw-share-bridge-rs`, the iOS FFI: `VpnNetworkSettings`, split reader/writer halves so the two `NEPacketTunnel` loops do not contend | the assumption that no client surface existed outside the dev runner |
| 2026-07-29 | `c48386d1` (#392) | real pool-allocated IPv4 to the client: `TunnelFrame::NetworkSettings` (kind `0x17`), CBOR `{mesh_ipv4{addr,prefix_len,peer}, mtu, session_id}`, sent immediately after the `Open`-ack on the `IpTunnel` path only. The auth `TunnelAck` is unchanged and stays address-free on every path. Server-side `build_vpn_mesh_ipv4` enforces route scope before the runtime is assembled. Strict `deny_unknown_fields` decode mirrors: non-canonical key order, unmodelled key or trailing bytes fail closed | placeholder/locally-derived addressing on the wire. Touched the mobile plan; **did not** touch this plan |
| 2026-07-11 | `157c3d6b` | owner-present phase-0 **compile-out**: introduced `IP_TUNNEL_RESOURCE_COMPILED`, cfg-gated the mount/router/startup call, deleted ~2,500 lines of `mobile_claw_vpn_relay_*` modules (42 files, +1,403/−5,562) | "default-off" as the primary property. This is the largest superseder in the plan's history and the old header never mentioned it |
| 2026-07-09 | observation log | owner-present dev-host T1/T2 run: 60/60 ICMP, 0% loss, route + teardown sweeps — **not** an activation record (§0.6) | nothing; it is the only hardware evidence that exists |
| 2026-07-09 | `e4bd798f` | last edit to this plan before the 2026-08-06 rewrite | — |

---

## 1. Where we are today (the relay_stream base)

The merged relay_stream path (default-off, dev-proven end to end on real
hardware over a public relay) is an **application-layer** authenticated byte
stream:

- **Claw side** — with `THEYOS_RELAY_STREAM_LIVE=1`, the claw mounts an
  outbound-only connection toward `THEYOS_RELAY_STREAM_RELAY_ENDPOINT` and
  serves streams (`server-rs/src/claw_share_relay_stream_mount.rs`,
  `claw_share_relay_loop.rs`). Nothing on the claw listens for inbound.
- **Guest side** — with `THEYOS_RELAY_STREAM_DIAL=1`, a guest verifies a
  signed offer, dials Relay-R, authenticates (SessionAuthToken proof-of-
  possession bound to `target_id = claw_id`), opens a stream and runs a typed
  payload. Shipped payloads: `Pty` and `ClawSite`. `IpTunnel` is reserved in
  the signed contract and is fail-closed **in three places that are not the
  contract file** — see §0.1 and §0.4.
- **Relay-R** — a blind splicer (`relay_stream_relay_dev` bin +
  `claw_share_rendezvous_stream_relay_listener.rs`): it pairs two rendezvous
  hellos and splices bytes. It never holds keys or plaintext (Noise is
  end-to-end guest ⇄ claw). The public variant already carries abuse limits
  (per-source hello/pending/splice caps, TTLs, reaper — the
  `THEYOS_RELAY_STREAM_PUBLIC_*` family).
- **Membership (groups/public)** provides member identity and per-claw dial
  authorization off-LAN.

What this is **not**: an IP network. Each new use case needs a new
application-layer payload variant. Device-D cannot point `ssh`, a browser, or
any stock app at Claw-A.

## 2. What changes: app-layer channel → real VPN

|  | today (relay_stream) | target (per-Claw VPN) |
|---|---|---|
| unit of traffic | one purpose-typed byte stream | IP packets |
| iOS surface | in-app bridge, our app only | NetworkExtension Packet Tunnel: a system tunnel interface |
| what reaches Claw-A | only implemented payload types | any app on Device-D → any TCP/UDP service on Claw-A |
| routing on Device-D | none | exactly the session prefix carrying Claw-A's address, nothing else |
| claw surface | PTY handler | TUN/utun interface owned by a claw VPN agent |
| relay | blind splicer, untrusted | **unchanged**: blind splicer, untrusted |
| identity/auth/replay | household certs + member PoP + signed TTL'd offers | **unchanged**, reused |

The load-bearing reuse: the VPN is the **same verified dial pipeline**
(offer verify → relay dial → authenticate → open stream) with one new
resource variant (`IpTunnel`) whose stream carries length-prefixed IP packets
instead of PTY bytes, plus one post-`Open` control frame (`NetworkSettings`,
`#392`). Transport, trust, replay, and authorization machinery is not
reinvented.

Deliberate consequence: "VPN" here means **point-to-point, one claw at a
time per device** — not a network. The *authorization* model is still fully
N:N across members and claws (§3.6). See non-goals (§7).

## 3. Architecture

### 3.1 Claw VPN agent (macOS/Linux)
- A userspace agent adjacent to the claw workload owns a tunnel interface:
  Linux `TUN` for claw guests, macOS `utun` for dev bins/host-side runs.
  - Dependency: Linux claw guests need a kernel with `CONFIG_TUN=y`. The
    `firecracker-kernel` package is source-built and force-enables built-in
    TUN support. macOS `utun` has no such gate.
- The agent bridges TUN ⇄ the authenticated Noise stream, mounted exactly
  like today's claw mount: outbound-only toward Relay-R.
- Packet policy is **fail-closed DROP by default**:
  - inbound (from Device-D): accept only `src == session peer address` AND
    `dst == Claw-A's own tunnel address`;
  - outbound: only `src == Claw-A's tunnel address` to the session peer;
  - **no forwarding, ever** — the agent is not a router; the claw host's LAN
    and other claws are unreachable by construction.
- Oversize drop: `CLAW_VPN_V1_INNER_MTU = 1250` in
  `household-rs/src/claw_vpn.rs`; a packet longer than that is rejected
  (`PacketTooLarge`). See the MTU defect in §3.5.

### 3.2 iOS Packet Tunnel (Device-D)
- `NEPacketTunnelProvider` in the app group. Started **manually** by Member-M
  for a chosen Claw-A (explicit selection; no on-demand/auto-connect in v1).
- Tunnel settings install ONLY the route derived from the session's
  `NetworkSettings` frame. Never a default route; no DNS override in v1.
- The provider runs the same dial pipeline (offer verify → relay → auth →
  open `IpTunnel`), consumes the post-`Open` `NetworkSettings` frame, then
  pumps `packetFlow` ⇄ stream.
- Any auth/verify/parse failure → `cancelTunnelWithError` (system removes the
  interface and routes) — fail-closed.
- **Entry gate for Phase 2**: the packet-tunnel NetworkExtension entitlement
  must be confirmed for the team/app IDs (go/no-go checkpoint before any iOS
  work starts).
- **Open defect D1 — client-side route-scope check is missing on this path**
  (§8.1). `ClawSession::accept_network_settings` in
  `admin/rust/claw-share-bridge-rs/src/lib.rs` has exactly **three** rejection
  arms: settings-before-handshake, `session_id` mismatch against the auth ack,
  and duplicate-frame. None of them looks at the address. It then copies
  `prefix_len` verbatim into `VpnNetworkSettings` with **no bound**. A
  `prefix_len` of `0` — a default route, i.e. full exit-node capture — would
  be accepted and handed to the consumer, as would `> 32`, `peer == addr`, and
  a peer outside the prefix. The rule already exists as a callable,
  `MeshIpv4::route_scope_violation()` in `tunnel-wire-rs`, and at `e60bad85`
  its only non-test caller in the whole tree is the dev runner. Enforcement is
  therefore **server-side only** (`build_vpn_mesh_ipv4`), which is a
  single-implementation assumption. **Required change** (§13.1 B2): add
  `route_scope_violation()` as a **fourth** rejection arm, plus a negative test
  asserting `prefix_len = 0` is refused. That test would actually execute —
  `claw-share-bridge-rs` has its own `cargo test` job in CI (§0.5) — which is
  why the FFI, not the dev runner, is the right home for it. This is a
  prerequisite of Phase 2, not a nice-to-have; see §12, where `Overlay-U`
  makes a second frame producer concrete.

### 3.3 Relay-R — unchanged
Remains a blind stream splicer, treated as fully untrusted. v1 carries
IP-in-stream over the existing TCP splice, accepting TCP-over-TCP behavior
under loss for dev purposes (measured in Phase 5). A datagram/QUIC relay mode
is a possible later slice, explicitly out of scope here. The relay is
**reused, not rebuilt**: it is the same infrastructure the Share path already
runs on, and it holds **no authorization role** — see §11.

### 3.4 Control plane (engine)
- A VPN-capable offer/capability is a **new, distinct capability** minted by
  an explicit owner action. It is *not* implied by an existing PTY/share
  capability (explicit-selection principle). Authorization is keyed by
  `(member, device, claw)` — a per-relationship record, never a single-owner
  or claw-wide switch. In code: `ClawVpnAclKey { member_id, device_pub,
  claw_id }` in `household-rs/src/claw_vpn.rs`.
- Session admission reuses SessionAuthToken PoP bound to
  (member, device, claw). Admission assigns the session's tunnel address pair
  and registers the active session — listable and revocable by the owner.
- Deny-list reconcile (remove-wins) applies: revocation tears down live VPN
  sessions within a bounded interval (≤60s target). The live mechanism is a
  500 ms poll (`REVOKE_POLL_INTERVAL` in
  `household-rs/src/claw_share_data_tunnel.rs`) plus a per-inbound-`Data`-frame
  check.
- **There is no persistent per-claw VPN ACL store.** `ClawVpnAcl` is built
  fresh per open and granted the key derived from the already-authenticated
  target. Every authorization decision is re-derived from the signed offer
  plus the live household projection on every open and every 500 ms. This is
  deliberate and it constrains §11.

### 3.5 Addressing, routes and MTU

**Addressing is decided and enforced in code — this is no longer an open
question.** `ClawVpnIpv4Pool::try_new` rejects:

| Rejection | Reason |
|---|---|
| `prefix_len > 30` | `PrefixTooSmall` — a pool must hold a usable pair |
| host bits set in the network address | `HostBitsSet` |
| overlap with CGNAT `100.64.0.0/10` | `OverlapsReservedRange` — coexistence with a CGNAT-using VPN on the same phone |
| overlap with `10/8`, `172.16/12`, `192.168/16` | `OverlapsReservedRange` — home-LAN collision |

The dev pool is `198.18.0.0/24` (RFC 2544 benchmarking range), declared in
`t1-iptunnel-dev-runner-rs/src/main.rs` as `DEV_DEVICE_POOL_NETWORK` /
`DEV_DEVICE_POOL_PREFIX_LEN`. IPv6 ULA remains the likely v2 direction.

The CGNAT exclusion **becomes more load-bearing, not less**, under §12: once a
user may deliberately run a CGNAT-using mesh on the same device, an
overlapping pool is a live collision rather than a hypothetical one.

**Open defect D2 — four MTU values are live and they disagree** (§8.1).

| Value | Where (all at `e60bad85`) | Role |
|---|---|---|
| **1280** | `household-rs/src/claw_share_data_tunnel.rs` — hard-coded twice: `TunnelAck::Ok { … mtu: 1280 … }` on the auth ack, and `NetworkSettings { … mtu: 1280 … }` on the post-`Open` frame | what the wire advertises on **both** frames; the client is expected to configure its interface from it |
| **1250** | `CLAW_VPN_V1_INNER_MTU` in `household-rs/src/claw_vpn.rs` | the claw pump **drops** anything larger (`PacketTooLarge`); also the read length in `claw_vpn_packet_pump.rs` (`… + 1`) and the pump width in `claw_vpn_pollable_pump.rs` |
| **1400** | `t1-iptunnel-dev-runner-rs/src/main.rs` — `gen-device-config`'s `--mtu` `default_value_t` | what a generated dev config writes if the operator does not override it |
| **none** | `server-rs/src/claw_vpn_interface_route_plan.rs` contains no `mtu` at all (grep for `mtu` in that file returns zero hits) | the route plan never sets an interface MTU, so the OS default (typically 1500) applies to the interface it configures |

Two consequences, and the second is worse than the first:

1. A client that honours the advertised **1280** emits 1251..1280-byte packets
   that the claw drops silently.
2. The dev runner's own validator accepts `1280..=9000` — applied in three
   places (`gen-device-config`, session-config validation, and the ack check).
   **Every value in that accepted range is strictly greater than the pump's
   1250 drop threshold.** There is no MTU the config validator accepts at
   which a full-size packet survives. The validator's range and the pump's
   threshold do not merely differ; they are disjoint in the wrong direction.

The 60/60 ICMP result in §0.6 used small packets and could not observe any of
this — which is precisely why "the datapath worked" and "the MTU is coherent"
are separate claims. **This must be resolved before T1–T4 is re-run**, or the
next hardware log measures the wrong thing at a number nobody chose.
**PASS condition:** one number is chosen; the advertised value on both frames,
`CLAW_VPN_V1_INNER_MTU`, the config generator's default, and the accepted
validator range are all consistent with it; and a test sends a packet at
exactly the threshold and at threshold+1 and asserts delivered/dropped
respectively (T21). Owner of the fix: §13.1 B1.

### 3.6 Multiuser — the ACL is an N:N relation
Access between members/devices and claws is explicitly many-to-many:

- each claw carries an ACL: the set of `(member, device)` pairs authorized to
  tunnel to it;
- a member may be authorized for several claws, and a claw may have several
  authorized members — e.g. Member-M1, Member-M2 and Member-M3 all tunnel to
  Claw-A, while Member-M1 is *also* authorized for Claw-B and Member-M2 for a
  third claw; any N:N shape is representable;
- the VPN capability is keyed by `(member, device, claw)` (§3.4) — admission
  carries no single-owner assumption;
- revocation operates on exactly one ACL entry: removing Member-M2's device
  from Claw-A tears down only that session (S5). Member-M1's and Member-M3's
  sessions to Claw-A, and Member-M2's sessions to other claws, are untouched;
- concurrent sessions to the same claw are isolated: own stream, own address
  pair, own per-session policy check;
- iOS runs one active packet tunnel per provider: **v1 = one claw at a time
  per device**. This limits simultaneity on a device, not authorization — the
  N:N ACL is unaffected. Default caps: 1 active session per (member, claw)
  (`CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW`); small fixed cap per claw.

## 4. Security load-bearing points

> **⚠ Every item below is stated for the Soyeht datapath, and four of them do
> not survive Overlay-U mode. Read this list only together with §12.3,
> which holds the per-mode table and is the authoritative version.** In
> overlay mode **S3** and **S9** stop being
> ours, **S5** becomes authorization-complete but not reachability-complete, and
> **S12** does not apply. **S9 does not hold at all** — that is a real loss, not
> a re-phrasing. The four are marked inline below with `[→ §12.3]`; the table is
> deliberately **not** duplicated here, because two copies of a per-mode matrix
> is how the second one goes stale. Quoting any item below without §12.3 quotes
> the datapath-mode version only.

S1–S10 are unchanged in meaning and numbering. S11–S12 are added by this
rewrite because the code acquired properties the original list did not name.

- **S1 Device/user authentication** — every tunnel session requires member
  PoP (existing household-cert machinery) bound to the target
  (`target_id = claw_id`). Failures are rejected generically (anti-oracle).
- **S2 Per-claw authorization (N:N)** — VPN capability is explicit and keyed
  by `(member, device, claw)`, one ACL entry per relationship (§3.6); no
  single-owner assumption; holding a PTY/share capability does NOT grant VPN.
- **S3 E2E encryption** `[→ §12.3: NOT OURS in Overlay-U mode]` — Noise
  end-to-end Device-D ⇄ claw agent. Relay-R never holds keys or plaintext
  (unchanged trust model: relay untrusted). In Overlay-U mode the overlay's
  own encryption applies and we neither perform, verify, nor attest it.
- **S4 Replay/TTL/single-use** — offers stay TTL'd + replay-guarded
  (existing guards); handshake nonces get **explicit window-boundary replay
  negatives** in the test plan (an adjacent-code review previously caught a
  nonce-window boundary replay bug that unit tests had missed — this class
  is tested deliberately, not incidentally).
- **S5 Rotation/revocation** `[→ §12.3: PARTIAL in Overlay-U mode —
  authorization-complete, not reachability-complete]` — per-session keys;
  bounded session lifetime
  with rekey/reconnect; deny-list reconcile kills live sessions ≤60s; owner
  can list and terminate sessions. Revocation is **per ACL entry**: removing
  one (member, device) from one claw kills only that member's session(s) to
  that claw — other members of the same claw, and that member's access to
  other claws, are unaffected.
- **S6 Fail-closed everywhere** — no route exists until authentication
  completes; any failure tears the tunnel down and removes routes; claw
  agent default-DROP; missing envs at bootstrap → warn + feature absent
  (the proven `runtime_unavailable` discipline); flags default-off on both
  sides.
- **S7 Dev/prod isolation** — `THEYOS_CLAW_VPN_LIVE` / `THEYOS_CLAW_VPN_DIAL`
  plus endpoint and pool vars default-off; dev-only standalone bins first
  (the existing `relay_stream_*_dev` pattern); Engine-prod is untouched by
  every phase in this plan; each deploy/flip is a separate owner-authorized
  STOP gate (a relayed GO is not a GO).
- **S8 Auditability without sensitive logs** — structured session lifecycle
  events recorded per `(member, device, claw)` (open/deny/close + reason
  codes, byte counters) using internal neutral ids, so N:N access is
  attributable per relationship. Never packet payloads, external IPs, UDIDs,
  or key material in logs. Neutral ids are pseudonymous local identifiers, not
  anonymization; the T1 router module has a reviewed HMAC-SHA-256 export
  redactor for future off-host/shared audit export, but choosing the export key
  source, rotation, and exposure policy remains part of the SHA-bound
  activation review.
- **S9 Anti-spoof + no forwarding** `[→ §12.3: DOES NOT HOLD in Overlay-U mode]`
  — both directions filtered to the single
  (session peer ⇄ claw) address pair; the agent never routes beyond itself;
  LAN and other claws unreachable by construction. **This is the mechanism
  that makes §7's "not a mesh" a security property rather than a scope
  statement.** A plan that lifts the non-goal must name what replaces S9.
- **S10 Explicit selection** — connecting is a manual member action naming a
  specific claw; no auto-connect, no wildcard offers, no implicit device
  enrollment.
- **S11 Build-time absence (added 2026-08-06)** — in any artifact without
  `dev_t1_datapath`, the `IpTunnel` resource, its target type, its router
  trait, the `claw_vpn_*` modules, the mount wiring and the bootstrap gate
  are **absent**, and `server-rs/src/main.rs:26` refuses to build a release
  binary with the feature at all. Re-proved on every release build by
  `check-mobile-claw-vpn-owner-present-phase0-compileout.sh`. This is a
  strictly stronger claim than "default-off" and it is the one reviewers
  actually rely on. Weakening it requires an explicit, named gate change.
- **S12 Route scope travels with the address (added 2026-08-06)**
  `[→ §12.3: NOT APPLICABLE in Overlay-U mode — and the converse is a hazard]`
  — the client installs a route for exactly `network(addr, prefix_len)` and never a
  default route. Enforced server-side by `build_vpn_mesh_ipv4` before the
  runtime is assembled, and client-side by `MeshIpv4::route_scope_violation()`.
  **Today S12 holds on the server and in the dev runner, and does NOT hold in
  `claw-share-bridge-rs`** (§3.2). S12 is not satisfied until the FFI enforces
  it too.

## 5. Implementation phases (conservative; no product activation)

Phase 0 and most of Phase 1 are complete in the sense of *code merged and
compiled out*. What remains for T1 is an authorized run, not more scaffolding.
The slice-by-slice construction record lives in `git log`, not here.

| Phase | Entry | Content | Exit |
|---|---|---|---|
| **0** — plan + inert scaffolding | — | signed resource reserved; pure packet/admission/audit helpers; default-off dev config; source guard; **compile-out (S11)** | done. `157c3d6b` made this stronger than the phase originally required |
| **1** — Rust↔Rust dev proof (no Apple gates) | Phase 0 | claw agent with TUN/utun; `t1-iptunnel-dev-runner-rs` as the dev client; route plan + executor; bounded pump + runtime coordinator; T1 caller gate; SHA-bound preflight loader; spooled redacted JSONL audit sink; `#392` `NetworkSettings` frame; **defects D2 and D3 fixed** (§8.1) | **T1–T4 green on dev hosts, under an authorized run** (§13), **plus T21 and T23**. D2 and D3 are exit prerequisites, not follow-ups: without them the run measures the wrong MTU and attests addressing it never exercised. Code is merged; the run is not authorized |
| **2** — iOS Packet Tunnel dev build | entitlement go/no-go **and** defect **D1** fixed (§8.1, §3.2) | `NEPacketTunnelProvider`; `claw-share-bridge-rs` consumed for real | T5–T7 green (iPhone reaches Claw-A — and only Claw-A), **plus T20** |
| **3** — adversarial hardening | Phase 2 | full negative matrix T8–T13, revocation latency, reconnect/background; independent security re-review of S1–S12 against the code as built | T8–T13 green |
| **4** — multiuser + limits + audit events | Phase 3 | T14–T16 and T19 (the N:N positive/negative pair) | those rows green |
| **5** — hardware E2E + performance baseline | Phase 4 | cellular, public relay, both transport modes (§12); T17–T18, T22 | those rows green. Shipping/activation remains a separate explicit owner decision |

**Correction to the phase/row mapping.** An earlier draft placed T20–T22 all in
Phase 5. That was inconsistent with §13.1: T20, T21 and T23 are the PASS
conditions of blocking fixes B2, B1 and B4, and a blocking fix whose test is
deferred four phases is not blocking anything. They are moved to the phase
whose gate they actually are — T21 and T23 to the Phase-1 exit, T20 to the
Phase-2 exit. Only **T22** (Overlay-U mode) genuinely belongs in
Phase 5, because it needs the hardware and public-relay setting.

Standing governance inside every phase: any deploy touching a shared host and
any flag flip is individually owner-authorized; peer-relayed authorization is
not authorization. **T1 dev-host decisions are delegated to the agents (§13);
production activation, deploy and flag flips are not.**

## 6. Test matrix — the 100% bar

T1–T19 are unchanged in ID and meaning. T17's parenthetical is corrected for
§12: the point of that row was always *"a path with no shared L2 and no
pre-existing user VPN"*, not *"Tailscale is forbidden"*.

| ID | proves | PASS condition |
|----|--------|----------------|
| T1 | interface up | agent creates TUN/utun with assigned addresses; clean exit removes the interface |
| T2 | tunnel plumbing | ICMP + TCP echo client ⇄ Claw-A over Relay-R (Rust dev client) |
| T3 | route scope | client route table contains ONLY the session prefix via the tunnel; LAN and other-claw addresses take the normal path |
| T4 | fail-closed plumbing | kill Relay-R mid-session → tunnel down, routes gone, no half-open interface |
| T5 | iOS interface/routes | NE tunnel up on a dev iPhone; system routes show only the session prefix via utun |
| T6 | authorized reachability | ssh/http from stock apps on Device-D to Claw-A succeed |
| T7 | unauthorized unreachability | another claw's address, the claw host's LAN address, and the engine address are all unreachable via the tunnel |
| T8 | ACL negative | Member-M3, with no VPN capability for Claw-A: admission rejected (generic error), no session created, audit deny event recorded per (member, device, claw) |
| T9 | revocation granularity | with Member-M1 and Member-M2 both live on Claw-A: revoking Member-M2's entry for Claw-A tears down only M2's session ≤60s and rejects M2's reconnect; M1's session to Claw-A and M2's sessions to other authorized claws stay up |
| T10 | replay negatives | replayed offer, replayed handshake, and nonce-window **boundary** replay all rejected; zero route side effects |
| T11 | tamper negative | bit-flipped frames dropped; session fails closed or survives cleanly (no plaintext leak, no crash) |
| T12 | spoof negative | crafted src/dst outside the session pair dropped in both directions (counted, never forwarded) |
| T13 | cross-purpose negative | a PTY-only capability cannot open the `IpTunnel` resource |
| T14 | N:N positive + isolation | Member-M1 and Member-M2 both reach Claw-A concurrently: isolated sessions, per-session address enforcement; Member-M1 additionally authorized for (and able to reach) Claw-B — the N:N shape proven live |
| T15 | session caps | second session for the same (member, claw) rejected per policy |
| T16 | audit hygiene | audit output for all rows contains reason codes + neutral ids only (reviewed against S8) |
| T17 | real-world path | iPhone on cellular, no shared L2 with the claw and no pre-existing user VPN active → public Relay-R → Claw-A: T5–T7 repeated |
| T18 | lifecycle | app background/foreground, Wi-Fi⇄cellular flap, claw restart, engine restart: reconnect or fail-closed — never a stale route |
| T19 | cross-claw negative | Member-M1 authorized for Claw-A but NOT Claw-B: Claw-A session succeeds while Claw-B admission is rejected (generic error), no session, no route |

**Rows added 2026-08-06.** New IDs, so T1–T19 keep their meaning.

| ID | proves | PASS condition |
|----|--------|----------------|
| T20 | client-side route scope (S12) — closes defect **D1** | a `NetworkSettings` frame with `prefix_len = 0` is **rejected by the client** — asserted against `ClawSession::accept_network_settings` in `claw-share-bridge-rs` as a unit test, not only against a server that would never send it. Also `prefix_len > 32`, `peer == addr`, and peer outside the prefix. Must be a **negative** test on the FFI's own default-feature test target, which CI actually runs (§0.5) — a positive test cannot catch a guard that stopped guarding |
| T21 | MTU coherence (§3.5) — closes defect **D2** | a packet at exactly the agreed inner MTU is delivered; MTU+1 is dropped and counted. Run after all four values (advertised on both frames, `CLAW_VPN_V1_INNER_MTU`, generator default, accepted validator range) are made consistent |
| T22 | Overlay-U mode (§12) | with the product datapath disabled and the claw reachable over `Overlay-U`: Claw-A reachable; S1/S2/S5/S8/S10 still demonstrably enforced (admission still requires PoP; revocation still tears the session down ≤60s); S3/S9/S12 explicitly recorded as **not** provided by us on that path |
| T23 | client honours the server's allocation — closes defect **D3** | the client's interface address and prefix equal the `NetworkSettings` frame's `addr`/`prefix_len`. Negative half, which is the load-bearing one: with the client's local pool deliberately set to disagree with the server's allocation, the session **fails closed** instead of coming up on the local address. Without this row a green T1/T2 attests only that two independently configured allocators agreed (§8.1) |

100% = every row green in its owning phase, negatives included, before the
next phase begins. Claw variants: the matrix runs against both a macOS-hosted
claw and a Linux claw.

## 7. Non-goals — scope of *this* plan (v1)

- NOT a whole-network VPN: no default route, no exit node, no LAN exposure.
  This survives unchanged and is enforced by S12.
- **Not claw⇄claw or device⇄device routing *in this plan*.** The original
  wording was "NOT a mesh: no claw⇄claw or device⇄device routing". That
  sentence was never only a scope statement — it named a security property.
  The point-to-point shape is what makes **S9** (anti-spoof + no forwarding)
  enforceable as a two-address policy check per session; there is no
  forwarding table to get wrong because there is no forwarding.
  A device⇄device track has since been commissioned and is specified in
  **`docs/product-a-device-mesh-vpn-plan.md`**. The correct reading of this
  bullet today:
  - **this document** commits only to the point-to-point per-claw tunnel;
    the per-claw agent remains a non-router, and nothing here may be cited
    as authorizing claw⇄claw or device⇄device forwarding;
  - **the mesh plan** must state, explicitly, which mechanism replaces S9
    once the two-address invariant no longer applies — it does not inherit
    S9 by being adjacent to this document;
  - the earlier clause **"no nvpn/mesh promises until daemon + interface +
    routes are proven"** is retained verbatim in force: §0.6 is one
    owner-present observation, not a proof, and it is not transferable to the
    mesh track.
- No DNS/split-DNS; no auto/on-demand connect; no UDP/datagram relay mode;
  no public/anonymous VPN offers.
- **Not billing.** §11 cites the *seam* an entitlement check will occupy —
  defined in `docs/soyeht-tiers-and-entitlement-plan.md` §5.0, not here.
  It defines no price, tier, packaging, trial length or grace behaviour, and
  no code in this plan reads a plan/tier value.

## 8. Dependencies & risks

### 8.1 Named code defects — three, each owned, each blocking a phase

These are **defects in the tree**, not observations about it. Each was read at
`origin/main` @ `e60bad85`. Each has a file, a symbol, an owner in §13.1, and a
phase it gates. They are numbered so a later document can cite one without
re-describing it, and so "we know about that" cannot be offered in place of
"it is fixed".

| # | Defect | File — symbol | Blocks | Owner |
|---|---|---|---|---|
| **D1** | The iOS FFI accepts `prefix_len` **unbounded** — including `0` (default route / full exit-node capture), `> 32`, `peer == addr`, and a peer outside the prefix | `admin/rust/claw-share-bridge-rs/src/lib.rs` — `ClawSession::accept_network_settings` | **Phase 2 entry**; and §12 shared-client support | §13.1 **B2** |
| **D2** | The inner MTU disagrees across the tree: **1280** advertised / **1250** dropped / **1400** generated / **none** on the route plan — and the accepted validator range `1280..=9000` is disjoint from, and entirely above, the drop threshold | `household-rs/src/claw_share_data_tunnel.rs`, `household-rs/src/claw_vpn.rs` — `CLAW_VPN_V1_INNER_MTU`, `t1-iptunnel-dev-runner-rs/src/main.rs` — `gen-device-config`, `server-rs/src/claw_vpn_interface_route_plan.rs` | **Phase 1 exit** (T1–T4 re-run) | §13.1 **B1** |
| **D3** | The dev runner **observes** the server's allocated address instead of being configured by it — a path we believed was server-configured is, at that point, merely watched | `t1-iptunnel-dev-runner-rs/src/main.rs` — `pipe_target_session_to_tunnel` (the `TunnelFrame::NetworkSettings` arm), `device_session_core`, `run_device_datapath_with_inputs` | **Phase 1 exit** | §13.1 **B4** |

D1 and D2 are described in full at §3.2 and §3.5. **D3 is the one that matters
most, and it is worse than "the runner prints instead of configures."** The
sequence, read at `e60bad85` inside `run_device_datapath_with_inputs`:

1. `device_session_core(offer, device_key, config)` runs **first**, before any
   connection. It constructs its **own** `ClawVpnIpv4Pool::try_new(
   DEV_DEVICE_POOL_NETWORK, DEV_DEVICE_POOL_PREFIX_LEN)`, opens a session
   against it, and then merely *cross-checks* `session.addrs() != config.addrs`
   against the local JSON. The address is thus produced by a **second,
   client-local allocator**.
2. The runtime — TUN/utun open, route install — is assembled from that core.
   Note `build_inputs` takes its config parameter as `_config`: the interface
   name comes from the opened device, and the addressing has already been
   settled in step 1.
3. Only **then** does `pipe_target_session_to_tunnel` receive the server's
   `NetworkSettings` frame. It decodes the sealed body, calls
   `route_scope_violation()` (correctly, fail-closed), and then does exactly
   one thing with the result: `eprintln!("dev datapath: VPN NetworkSettings
   received (prefix_len={})", …)`.

So the interface is **already configured, from a different source**, by the
time the authoritative frame arrives. `#392`'s guarantee ("a real,
pool-allocated IPv4 address reaches the client") is true **on the wire** and
**not true at the interface**.

The two addresses agree today only by configuration, and the two sides do not
even get their pool the same way — which is what makes the agreement fragile:

- **server side**: the pool is parsed from an env var CIDR string at runtime
  (`server-rs/src/claw_vpn_dev_config.rs` — `parse_ipv4_pool`);
- **runner side**: the pool is a **compile-time constant** —
  `const DEV_DEVICE_POOL_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0)` and
  `const DEV_DEVICE_POOL_PREFIX_LEN: u8 = 24` in
  `t1-iptunnel-dev-runner-rs/src/main.rs`.

An operator who sets the server's pool env var to anything other than
`198.18.0.0/24` produces a client that configures a **different** address than
the one the server allocated, and nothing on either side reports it. Nothing on
the wire checks the two for equality.

**Uncertainty, stated rather than smoothed.** Address agreement also requires
the two sides to land on the same **session index** within the pool. The runner
side is measured: `ClawVpnAgentCore::new(...)` followed by a single
`open_with_audit`, i.e. a fresh registry's first allocation. The server side is
**not** measured at this SHA — its index depends on `ClawVpnSessionRegistry`
state at open time, which this rewrite did not read. **Measurement that would
settle it:** read `ClawVpnSessionRegistry`'s allocation order in
`household-rs/src/claw_vpn.rs` and determine whether a second concurrent or
prior session on the serving claw shifts the allocation. If it does, the two
sides disagree the moment a second session exists — which would make D3 not
merely a meaning gap but a live functional bug the moment T14 (concurrent N:N
sessions) is attempted.

Why this is the important one: it changes what a T1/T2 green means. A passing
run does **not** demonstrate that the client honours the server's allocation,
because the client never reads it. It demonstrates that two independently
configured allocators happened to agree. Any future divergence — a different
pool, a non-zero session index, a server-side reallocation — produces a
silently mis-addressed interface that the current runner would not notice, and
the current T1/T2 rows would not catch. Until B4 lands, no result from this
runner may be cited as evidence that server-driven addressing works
end-to-end.

**Non-defect, recorded so it is not "fixed" by mistake:** the dev runner *does*
call `route_scope_violation()` on the received frame and bails on violation.
That half is correct and is the only non-test caller of that rule in the tree.
B4 must add interface configuration **without** removing that check.

### 8.2 Standing dependencies and risks

- Apple packet-tunnel entitlement (Phase-2 entry gate; approval delay is the
  risk — mitigated by the all-Rust Phase 1).
- Linux guest kernel `CONFIG_TUN=y` for VM claws; the `firecracker-kernel`
  package is source-built and force-enables TUN.
- TCP-over-TCP performance under loss (accepted for v1; measured in Phase 5).
- **`dev_t1_datapath` implies `dev_claw_share_mint`.** The feature that
  compiles in the datapath also compiles in an owner-authorization **bypass**
  mint fixture (so labelled in `server-rs/Cargo.toml`). Any dev-host T1 run
  therefore runs with that bypass present. It is contained by G0b (release
  builds refuse the feature) and by the run being dev-host-only, but it means
  a T1 run is **not** a faithful rehearsal of the production authorization
  path. Splitting the two features is a candidate follow-up; until then this
  is a named limitation of every T1 result.
- **13 of the datapath tests never execute in CI** (§0.5). The evidence for
  the live path is a manual owner-present run plus compile-only checks. This
  class of gap has already bitten once: `#410`'s own message records that a
  caller left broken by the `#406` admission-API change reached `main`
  invisibly.
- **The only hardware evidence is ~4 weeks old and SHA-stale** (§0.6). It
  cannot be reused as `hardware_evidence_ref` at a new artifact SHA.
- **Audit-sink failure is indistinguishable from unavailability.** A missing
  or unwritable evidence bundle yields a sink that `Err`s on every event,
  which aborts the session with one opaque reason string. A full disk, a
  rotated-out fd or an fsync failure on the host therefore presents as "VPN
  unavailable". Correct as fail-closed behaviour; but once §11's entitlement
  check sits on the same path, an infrastructure fault becomes a
  billing-visible outage with no distinguishing signal. Name a distinct
  reason code for sink-failure before that lands.
- **Client-side route scope is unenforced in the iOS FFI** — defect **D1**
  (§8.1, §3.2, S12). Harmless only while exactly one server implementation can
  produce the frame. §12 makes a second producer plausible.
- **The inner MTU is incoherent** — defect **D2** (§8.1, §3.5).
- **The dev runner does not consume the server's address** — defect **D3**
  (§8.1). This one degrades the meaning of every T1/T2 result taken before it
  is fixed; it is not merely unfinished work.
- Address-range collision with user networks — constrained by
  `ClawVpnIpv4Pool::try_new` (§3.5), not eliminated.
- iOS NE lifecycle quirks (background termination/restart) — covered by T18.
- **Stale-in the-dangerous-direction doc**:
  `docs/followup-t1-iptunnel-dev-client-runner.md` (last changed 2026-07-07)
  still lists "open interface / install `/32` / pump packets / emit evidence"
  as *Fails*. `run-device-datapath` does all four. A doc that over-states
  readiness gets caught; one that under-states capability does not, because
  nobody audits good news. Correcting it is an owned item (§13.1 B3). Note it
  is *right* about the frame: `run-device-datapath` installs the interface and
  routes from its **own** pool, not from the frame — that is D3, and B3's
  correction must not overwrite one under-statement with an over-statement.

## 9. Open questions

Settled questions have been removed. Each remaining question carries the
measurement that would settle it.

1. **What is the single inner MTU?** (defect D2, §8.1, §3.5) — settled by
   choosing a number and making the advertised value on both frames, the pump
   threshold, the config-generator default and the accepted validator range
   consistent, then running T21. Delegated: §13.1 B1 owns the choice.
2. **Should VPN-capability granting be owner-only, or delegable to group
   admins?** — settled by an owner statement. Not agent-delegable: it changes
   who can create an authorization relation.
3. **Can an `IpTunnel` offer with a `Device` or `Public` audience be minted
   and stored?** (§0.5) — settled by reading the mint path's audience guard,
   or by a test that attempts to mint one and asserts rejection. If it can be
   minted, an unusable-but-signable capability exists, which is an
   audit-surface question even though G10 blocks it at open.
4. **Retention target for session audit events**, and the export key
   source/rotation/destination policy for the HMAC redactor (S8) — settled by
   an owner statement plus the activation review's audit-export-policy
   artifact.
5. **Do the five private references named by the activation record actually
   point at the artifacts they name?** The Rust loader and the offline
   validator are shape checks; the checklist itself concedes they "do not
   prove that a reference points to the artifact it names." Settled only by a
   human reading the referenced artifacts at review time. **This is the single
   named residual risk of the activation PR** (§13), not one bullet among
   twenty.
6. **Does the server's session-index allocation stay aligned with the dev
   runner's?** (defect D3, §8.1) — the runner allocates from a fresh registry's
   first open against a compile-time-constant pool; the server allocates from
   `ClawVpnSessionRegistry` against an env-configured pool. Settled by reading
   `ClawVpnSessionRegistry`'s allocation order in
   `household-rs/src/claw_vpn.rs` and determining whether a prior or concurrent
   session on the serving claw shifts the index. **If it does, D3 stops being a
   meaning gap and becomes a live functional bug the first time T14 runs two
   concurrent sessions.** Not settled by this rewrite; B4 makes the question
   moot by having the client read the frame instead of guessing.

## 10. Relation to existing plans

- **This plan** — the point-to-point per-claw tunnel over the proven relay
  path. It is the evolution of "plan 1".
- **`docs/product-a-mobile-claw-control-vpn-plan.md`** — the mobile control
  surface. `#392` (`NetworkSettings`) was recorded there and not here; §0.7
  now carries it in both.
- **`docs/product-a-device-mesh-vpn-plan.md`** — the commissioned
  device⇄device track (§7). Separate document, separate security argument;
  it does not inherit S9.
- **nvpn L3 mesh ("plan 3")** — not resurrected by this document. This plan
  reuses only the kernel-TUN recipe.
- **User-operated overlay transport ("plan 2")** — **no longer excluded.**
  See §12. The former wording, "no Tailscale dependency", remains true in one
  precise sense and false in another, and §12 states which is which rather
  than deleting the sentence.

The plans stay separate; this document commits only to the point-to-point
per-claw tunnel described above.

## 11. Entitlement seam (deferred hook — chokepoint only, no pricing)

The product will be charged for. **`docs/soyeht-tiers-and-entitlement-plan.md`
is normative for the entitlement seam**; this section cites its chokepoint
(§11.1), records the two seams that look right and are wrong from *this*
product's side (§11.2), and states what is deferred. It fixes **nothing** about
price, tier, packaging, trial length or grace behaviour, and no code named here
reads a plan value today.

### 11.1 The chokepoint — defined in the tiers plan, cited here

**`docs/soyeht-tiers-and-entitlement-plan.md` §5.0 is normative for the
entitlement chokepoint.** This section does not restate it. What follows is the
pointer, the one rule every plan carries, and the per-claw-specific fact that
plan needed from here.

> **The chokepoint** is the *producer*:
> `RelayStreamIssuerTrust::verify_offer_with_context`
> (`server-rs/src/claw_share_relay_stream_issuer_trust.rs`). The entitlement
> fact is a **field on `RelayStreamTrustContext`**, beside `projection` and not
> inside it, produced by that one call. Enforcement sites **receive** it.

The rule, in the tiers plan's words, and it binds this document too:

> **One `Entitlement` value type. One evaluation. N enforcement sites, each of
> which RECEIVES the value and never re-derives it.**

**Why the producer, and not the two sites this section used to name.** Every
relay-stream authorization decision in the tree reaches exactly one function.
At `origin/main = e60bad85`,
`git grep -n 'verify_offer_with_context' origin/main -- admin/rust/server-rs/src/`
returns **eight** lines: the definition, four doc/comment mentions, and
**three call sites** —
`claw_share_relay_stream_target_router.rs:177` (inside `validate_ip_tunnel_target`),
`:232` (inside `validate_target_for_resource`), and
`claw_share_relay_stream_session.rs:200` (inside
`relay_stream_offer_session_revoked`). All three take their whole context from
**one** `(self.source)()` call, which is what makes the no-second-snapshot
property true.

**The per-claw fact the tiers plan takes from this document, and it is the
reason the site list changed.** `validate_ip_tunnel_target` is
`#[cfg(any(test, feature = "dev_t1_datapath"))]`
(`claw_share_relay_stream_target_router.rs:164`), exactly like the rest of the
`IpTunnel` path (§0.1, S11). **A seam placed only there does not exist in a
product build.** `validate_target_for_resource` (`:213`) and
`relay_stream_offer_session_revoked` (`session.rs:193`) carry no `cfg`, and
`pub mod claw_share_relay_stream_issuer_trust;` (`server-rs/src/lib.rs:27`) is
unconditional — so the producer and its two shipping consumers are present in a
default build, and the `IpTunnel` consumer joins them on the day the feature
does. That is the whole reason the chokepoint is the producer rather than the
`IpTunnel` gate.

Properties this buys, in this plan's own terms:

- **unbypassable** — admission and liveness are both covered, and there is no
  third way to reach a backend;
- **cannot weaken the ACL** — it is an `AND` evaluated on the same context that
  already gated the signer, so it can only ever deny more;
- **one producer** — whereas the router has **two** `open_ip_tunnel` impls (sync
  and pollable) that would each need a re-derived check and could drift apart.

**Hard constraint, and the correction this section carries.** An earlier
revision of §11.1 said the entitlement fact should be "projected from the same
household mesh log". That wording is **withdrawn**: it reads as a new field on
`ProjectedState`, and `check_relay_stream_group_membership`
(`household-rs/src/claw_share_relay_stream_contract.rs:411`) takes
`&ProjectedState` as its **first parameter** — so placing the entitlement fact
there puts a commercial value inside the authorization predicate's own type
signature, which is the failure the tiers plan records as R-9. The constraint
that was right stays: the fact must come from the **same single snapshot** that
gated the signer, never a second one. Both hold at once only if the fact sits
**beside** `projection` on `RelayStreamTrustContext`, which is what tiers §5.0
specifies. **Any change to `ProjectedState`'s field list inside an entitlement
PR is that defect.**

### 11.2 Two seams that look right and are wrong

Recorded so a later slice does not rediscover them.

- **Offer mint time** (`require_resource_enabled` in the offer store) —
  **wrong.** Offers are TTL'd and cached. An entitlement that lapses mid-TTL
  would grant free VPN until `not_after`.
- **`ClawVpnAclKey`** — **wrong twice.** It has no tier dimension
  (`member_id`, `device_pub`, `claw_id` only), and its ACL is a fresh rubber
  stamp constructed *after* authorization has already happened (§3.4).
  Adding a tier field there would look like a control and be none.

### 11.3 What is explicitly deferred

Price, tiers, trial length, grace period, dunning, what happens to a live
session when entitlement lapses (tear down at the next 500 ms tick, or run to
end of session), and whether Share's free allowance and the VPN entitlement
share one projected fact or two. None of these are decided here. The seam is
designed; the policy is not.

### 11.4 Relay cost posture

The relay is reused, not rebuilt (§3.3). Its cost properties follow from the
existing trust model rather than from new work: it is a blind splicer, so it
holds no keys, no plaintext and no user identity; it performs no authorization;
and its per-source hello/pending/splice caps, TTLs and reaper are already
merged.

**`docs/soyeht-relay-vps-capacity-and-cost-plan.md` is normative for relay
cost, capacity and the limits a session actually runs under**, and two of its
findings bind this plan rather than merely informing it: the shipped public
profile's `splice_max_bytes_per_direction` and `splice_max_lifetime` terminate a
continuous session long before a VPN run would finish (its §4.3), and
`splice_idle_timeout` is a no-op for continuous traffic. A T1/T2 result taken
under the Share profile is short enough to say nothing about either. No
capacity or efficiency target for a paid tier is set here.

**One correction that belongs in both documents:** the phrase "the relay sees
nothing of the user" is not accurate and must not ship. The capacity plan's
§2.5 states the accurate form — *Relay-R cannot read what is carried; it can see
who is talking to whom, when, for how long, and how much* — and that is the
sentence to use wherever this plan's "blind splicer" shorthand would otherwise
be read as "sees nothing".

## 12. User-operated overlay transport (a supported mode)

**Decision, 2026-08-06 (owner).** A user may choose to reach their claws over
an overlay network they operate themselves — a personal WireGuard, Tailscale,
or equivalent — instead of the Soyeht-owned datapath. This is a **supported
product mode**, not a workaround.

**Retired names — the registry, held here and nowhere else.** Earlier drafts
across these five plans reached this one mode under **four** other spellings,
and each plan then kept its own partial list of them, disagreeing on the count.
The surviving name is **user-operated overlay transport**, alias **`Overlay-U`**.
The retired spellings, in full, are:

1. "Tailscale mode"
2. "bring-your-own-transport (BYO)" — also written "BYO-transport"
3. "user-chosen third-party transport" — also written "user-chosen transport"
4. "`Transport-U`"

The other four plans cite this list and **do not restate it**. A fifth spelling
in a sixth document is the failure this registry exists to prevent.

### 12.1 The contradiction, stated rather than deleted

Four sentences in the repository asserted the opposite. Resolving them
honestly matters more than making them disappear. **This table is the single
resolution; the other four plans cite it and do not re-resolve it** (see the
normative-document index at the top of this file).

| Sentence | Verdict |
|---|---|
| `product-a-mobile-claw-control-vpn-plan.md`, **former** wording: *"Tailscale may be used for developer administration only; it is not part of the shipped VPN datapath."* | **superseded as a product-scope statement, and the sentence no longer stands in that form.** That plan's rewrite has since **split** it under "Transport choice — two claims that were conflated": clause (a) *our datapath depends on no third-party overlay* is **kept**, clause (b) *the user may not choose one* is **superseded**. Quote the split, not the original |
| this plan, Phase 5: *"Cellular, no Tailscale, public relay"* | **corrected** (§5, T17): the property that mattered was *no shared L2 and no pre-existing user VPN*, so the row measures our datapath in isolation. That is now stated directly |
| this plan, T17: *"iPhone on cellular (no Tailscale, no shared Wi-Fi)"* | **corrected** as above |
| this plan, §10: *"no Tailscale dependency (plan 2)"* | **narrowed, still true in one sense**: the Soyeht datapath has no dependency on any third-party overlay — it does not require one to function, and no third-party code is in our datapath. What is now false is the implication that a user *may not* choose one |
| this plan, §3.5: *"must avoid CGNAT `100.64.0.0/10` (Tailscale coexistence on the same phone)"* | **kept, and more load-bearing than before.** It is enforced by `ClawVpnIpv4Pool::try_new`, and once a user may deliberately run a CGNAT-using overlay on the same device the collision it prevents is real rather than hypothetical |

The precise resolution: **our datapath depends on no third-party overlay; the
user may choose one as their transport.** Those are compatible statements and
the old wording conflated them.

### 12.2 What the mode means for *this* plan

Concretely: Claw-A is reachable at an address on the user's own overlay, and
Device-D reaches it over that overlay. There is **no** `IpTunnel` session, no
`NetworkSettings` frame, no claw VPN agent, no pool allocation, and no
Relay-R hop. Our code is not in the path at all.

What we still own on that path is the **control plane**: which member may
address which claw, session admission, revocation, and audit. What we do not
own is packet carriage.

### 12.3 Which of S1–S12 still hold

This is the part that must not be hand-waved.

| | Holds in Overlay-U mode? | Why |
|---|---|---|
| **S1** authentication | **Yes** | member PoP is a control-plane check; it does not depend on who carries the packets |
| **S2** per-claw authorization (N:N) | **Yes** | same |
| **S3** E2E encryption | **Not ours.** | the overlay's own encryption applies. We do not perform, verify, or attest it. Must be stated to the user as *their* transport's property, never as ours |
| **S4** replay/TTL | **Yes** for offers and admission | the overlay's own replay properties are outside our claim |
| **S5** rotation/revocation | **Yes, with a caveat** | revoking the household authorization removes the member's ability to open a session. Whether it removes their *network reachability* to the claw depends on the user's overlay ACL, which we do not control. Revocation is therefore **authorization-complete but not necessarily reachability-complete** — this must be said in the product UI, not buried here |
| **S6** fail-closed | **Yes for our components** | our gates still fail closed; we cannot make a third-party overlay fail closed |
| **S7** dev/prod isolation | **Yes** | unaffected |
| **S8** auditability | **Yes** | session lifecycle events are still ours to record; byte counters that depended on our pump are **not** available on this path |
| **S9** anti-spoof + no forwarding | **NO.** | this is the significant loss. S9 is enforced by the claw agent's two-address policy check. With no agent in the path there is no such check, and the claw is reachable at whatever scope the user's overlay grants — which may well include other hosts on that overlay. A user who chooses this mode is choosing their overlay's isolation model over ours |
| **S10** explicit selection | **Yes** | selecting a claw remains a manual member action |
| **S11** build-time absence | **Yes, trivially** | no `IpTunnel` code runs |
| **S12** route scope | **Not applicable, and that is the hazard** | we issue no `NetworkSettings` frame, so there is no route for us to scope. The hazard is the converse: if a user-operated overlay transport ever *does* produce a `NetworkSettings`-shaped frame, `claw-share-bridge-rs` would accept `prefix_len = 0` today — defect **D1** (§8.1, §3.2). The FFI fix (§13.1 B2) is a prerequisite of supporting this mode with a shared client |

**PASS condition for the mode:** T22 (§6). **Required product statement:** the
UI must say which of these properties are provided by Soyeht and which by the
user's own network — S3, S9 and byte-level audit are the three that change
hands. Writing that string is out of scope here; the fact that it is required
is not.

### 12.4 Non-goals of this mode

We do not install, configure, operate, recommend a specific vendor, hold
credentials for, or troubleshoot the user's overlay. We do not proxy through
it. We do not read its ACL. A user on this mode is a fully supported user of
the control plane and an unsupported user of packet carriage.

## 13. T1 activation — owned checklist

Owner decision, 2026-08-06: **T1 dev-host activation decisions are delegated
to the agents.** This section therefore states what will be done and by whom.
It does not ask the owner to choose. Production activation, deploy and flag
flips remain separate owner-authorized events and are **not** covered here.

### 13.1 Blocking fixes that land *before* the T1 run

| # | Item | Owner | PASS condition |
|---|---|---|---|
| B1 | Unify the inner MTU — defect **D2** (§8.1, §3.5) | datapath agent | the value advertised on **both** the auth `TunnelAck` and the `NetworkSettings` frame, `CLAW_VPN_V1_INNER_MTU`, the `gen-device-config` default, and the accepted validator range are all consistent with one chosen number; T21 green |
| B2 | Wire `route_scope_violation()` into `ClawSession::accept_network_settings` as a **fourth** rejection arm — defect **D1** (§8.1, §3.2) | FFI agent | T20 green, including the `prefix_len = 0` negative as a unit test on the FFI itself. It must be a test that **executes**: `cargo test -p claw-share-bridge-rs` is a real CI job on default features (§0.5), whereas a test placed behind `dev_t1_datapath` would only compile |
| B3 | Correct `docs/followup-t1-iptunnel-dev-client-runner.md` (§8.2) | docs agent | items 4/5/6/7 marked done; the one genuinely remaining item stated (B4) |
| B4 | Make `run-device-datapath` configure its interface **from** the server's `NetworkSettings` frame instead of from its own client-local allocator — defect **D3** (§8.1) | datapath agent | T23 green: the runner's interface address and prefix equal the frame's `addr`/`prefix_len`, and the negative half holds — with the runner's local pool deliberately set to disagree with the server's allocation, the run fails closed rather than coming up on the local address. `route_scope_violation()` must still be called on the frame |

B4 is the single remaining functional gap between "the wire delivers a real
pool-allocated address" and "the client uses it" — and per §8.1 it is also a
**meaning** gap, not only a functional one: until it lands, a green T1/T2 does
not attest server-driven addressing, because the runner never reads the
server's address. B4's negative test is what converts the two allocators'
present agreement from a coincidence into a checked property.

**Sequencing note.** B1 and B4 are both prerequisites of the same event (the
T1–T4 re-run, Phase 1 exit) and both touch the dev runner; B2 gates Phase 2 and
touches a different crate. B2 can therefore land in parallel and should not be
held behind the T1 run.

### 13.2 Activation-PR artifacts, by producer

**Agent-produced, in the PR (public):**

1. the mount-to-gate diff (already drafted in
   `claw_share_relay_stream_mount.rs`);
2. the narrow source-guard relaxation naming exactly the mount symbols,
   re-tripping `product_a_per_claw_vpn_dev_config_remains_default_off_and_unwired`
   (`server-rs/tests/owner_events.rs:4033`);
3. a clean `scripts/check-t1-preflight-default-off.py` run on the **base**,
   with the three named carry filters `t1_spooled_audit_sink`,
   `t1_audit_log_path`, `t1_audit_export_jsonl`;
4. the artifact SHA and build hash.

**Operator-produced, private, never in the PR:**

5. `.env.t1-preflight-evidence.json` from
   `scripts/prepare-t1-preflight-evidence-record.py <sha>`, validated with
   `scripts/validate-t1-preflight-evidence-record.py <sha> <record>
   --check-root-dir --check-private-refs --expected-pr <n>`;
6. the prebuilt rollback artifact + `scripts/validate-t1-rollback-evidence.py`;
7. a **fresh** T1–T4 hardware evidence pack at the activation SHA +
   `scripts/validate-t1-hardware-evidence-pack.py`. The 2026-07-09 log is
   **not** reusable (§0.6);
8. the audit export policy + `scripts/validate-t1-audit-export-policy.py`;
9. the Device-side session config +
   `scripts/validate-t1-device-session-config.py`.

**Owner-produced — the only irreducible item:**

10. the authorization record carrying the verbatim sentence and
    `production_activation=false`, validated by
    `scripts/validate-t1-owner-authorization.py`.

**Reviewer-produced:** the five named ACKs — architecture/boundary,
tests/CI, claims/privacy, security/adversarial, checklist/product-risk
(`docs/product-a-per-claw-vpn-t1-review-agent-profiles.md`).

**Script inventory — corrected count.** An earlier draft closed this section
with "all eleven validator scripts named above exist". That was wrong twice:
the list above names **eight** distinct scripts, not eleven, and two of the
eight are not validators. Counted and verified at `origin/main` @ `e60bad85`,
each with the co-located `test_*` file named beside it:

| # | Script | Kind | Co-located test |
|---|---|---|---|
| 1 | `scripts/check-t1-preflight-default-off.py` | check | `scripts/test_check_t1_preflight_default_off.py` |
| 2 | `scripts/prepare-t1-preflight-evidence-record.py` | prepare | `scripts/test_prepare_t1_preflight_evidence_record.py` |
| 3 | `scripts/validate-t1-preflight-evidence-record.py` | validate | `scripts/test_validate_t1_preflight_evidence_record.py` |
| 4 | `scripts/validate-t1-rollback-evidence.py` | validate | `scripts/test_validate_t1_rollback_evidence.py` |
| 5 | `scripts/validate-t1-hardware-evidence-pack.py` | validate | `scripts/test_validate_t1_hardware_evidence_pack.py` |
| 6 | `scripts/validate-t1-audit-export-policy.py` | validate | `scripts/test_validate_t1_audit_export_policy.py` |
| 7 | `scripts/validate-t1-device-session-config.py` | validate | `scripts/test_validate_t1_device_session_config.py` |
| 8 | `scripts/validate-t1-owner-authorization.py` | validate | `scripts/test_validate_t1_owner_authorization.py` |

So: **eight scripts named — six `validate-*`, one `check-*`, one `prepare-*` —
all eight present, all eight with a co-located test.**

Where "eleven" most likely came from: the tree carries **three further** T1
scripts that this checklist does **not** name —
`scripts/assemble-t1-preflight-record.py`,
`scripts/check-t1-private-gate-status.py` and
`scripts/run-t1-dev-datapath.sh` (each also with a co-located test). 8 + 3 = 11.
Counting the tree and then attributing the count to the list is exactly the
error; the two sets are different and only the list is what an activation PR
runs. Whether any of those three *should* be named here is open — settled by
reading each one's entry point and deciding if it produces an artifact the
activation PR depends on. Until that is done, treat the checklist as eight.

Existence and a passing self-test are not the same claim: this table asserts
that the files are present with tests beside them, read from `git ls-tree -r
origin/main -- scripts/`. **No script was executed for this rewrite** (§0.5).
The checklist is executable today in the sense that nothing is missing, not in
the sense that a green run has been observed at this SHA.

### 13.3 The single named residual risk

**Reference content verification.** The activation record names five private
references. The Rust loader and the offline validator check *shape* — that the
strings are non-empty, that the SHA matches, that the root is absolute and
normal. They do not prove that a reference points to the artifact it names;
`docs/product-a-per-claw-vpn-t1-activation-pr-gate-checklist.md` concedes this
in its own text. There is no executable check for it and none is proposed.
This is the residual risk of the activation PR and it is a human reading, not
a script. It is stated here as *one named risk* rather than as a bullet among
twenty precisely so that it cannot be discharged by pattern-matching a green
validator run.

### 13.4 What this section does not authorize

Nothing in §13 authorizes a production activation, a deploy to a shared host,
a flag flip on any engine serving a real household, or an E2E against
production state. Those remain separate, explicitly owner-authorized events.
The delegation covers dev-host T1 decisions only.

---

## Appendix A — history

The slice-by-slice construction narrative that occupied lines 3–205 of this
document until 2026-08-06 is not reproduced. It is recoverable in full from
git:

```
git log --follow -p docs/product-a-per-claw-vpn-plan.md
git log admin/rust/server-rs/src/claw_vpn_*
git log admin/rust/household-rs/src/claw_vpn.rs
git log admin/rust/t1-iptunnel-dev-runner-rs/
```

Two commits are worth reading directly before touching this area:
`157c3d6b` (2026-07-11, the compile-out) and `c48386d1` (`#392`, 2026-07-29,
the `NetworkSettings` frame).

Nothing in this plan is authorized to run anywhere by virtue of the plan
existing.
