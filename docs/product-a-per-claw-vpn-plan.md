# Product A — per-Claw VPN plan (relay_stream → real IP tunnel)

**Status: plan + early inert scaffolding.** The first code slices define signed
contracts, fail-closed placeholders, pure packet/admission/audit helpers, a pure
interface-to-relay datapath core, and a guarded default-off dev config parser,
but there is still no TUN/utun interface, route installation, packet relay
runtime, storage-backed session registry, iOS Packet Tunnel, or product
activation. Everything described here is default-off by construction, and every
activation step (deploy, flag flip, shipping) is a separate, explicitly
owner-authorized decision. Nothing in this plan is authorized to run anywhere by
virtue of the plan existing.

Authored 2026-07-02 by the security-review agent at the owner's request.

**Aliases.** This document uses neutral aliases only — no real hostnames, IPs,
device IDs, or account identifiers: `Claw-A` (a specific target claw/VM),
`Member-M` (a household member), `Device-D` (Member-M's iPhone), `Relay-R`
(a public rendezvous relay node), `Engine-dev` / `Engine-prod` (engine
instances). Multi-party scenarios use `Member-M1`/`Member-M2`/`Member-M3` and
a second claw `Claw-B`. IP ranges shown are placeholders pending the Phase-1
decision.

---

## 1. Where we are today

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
  payload (`friend-cli-rs`). The currently implemented payloads are `Pty` and
  `ClawSite`; `IpTunnel` is reserved in the signed contract and remains
  fail-closed until the Phase-1 tunnel agent exists
  (`household-rs/src/claw_share_relay_stream_contract.rs`).
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
| routing on Device-D | none | exactly Claw-A's tunnel address (a /32), nothing else |
| claw surface | PTY handler | TUN/utun interface owned by a claw VPN agent |
| relay | blind splicer, untrusted | **unchanged**: blind splicer, untrusted |
| identity/auth/replay | household certs + member PoP + signed TTL'd offers | **unchanged**, reused |

The load-bearing reuse: the VPN is the **same verified dial pipeline**
(offer verify → relay dial → authenticate → open stream) with one new
resource variant (working name `IpTunnel`) whose stream carries
length-prefixed IP packets instead of PTY bytes. Transport, trust, replay,
and authorization machinery is not reinvented.

Deliberate consequence: "VPN" here means **point-to-point, one claw at a
time per device** — not a network. The *authorization* model is still fully
N:N across members and claws (§3.6). See non-goals (§7).

## 3. Proposed architecture

### 3.1 Claw VPN agent (macOS/Linux)
- A userspace agent adjacent to the claw workload owns a tunnel interface:
  Linux `TUN` for claw guests, macOS `utun` for dev bins/host-side runs.
  - Dependency: Linux claw guests need a kernel with `CONFIG_TUN=y`. The
    from-source kernel recipe exists on the `spike/nvpn-slirp` branch and
    must land as a Phase-1 prerequisite for VM claws. macOS `utun` has no
    such gate.
- The agent bridges TUN ⇄ the authenticated Noise stream, mounted exactly
  like today's claw mount: outbound-only toward Relay-R.
- Packet policy is **fail-closed DROP by default**:
  - inbound (from Device-D): accept only `src == session peer address` AND
    `dst == Claw-A's own tunnel address`;
  - outbound: only `src == Claw-A's tunnel address` to the session peer;
  - **no forwarding, ever** — the agent is not a router; the claw host's LAN
    and other claws are unreachable by construction.

### 3.2 iOS Packet Tunnel (Device-D)
- `NEPacketTunnelProvider` in the app group. Started **manually** by Member-M
  for a chosen Claw-A (explicit selection; no on-demand/auto-connect in v1).
- Tunnel settings install ONLY `includedRoutes = [Claw-A/32]`. Never a
  default route; no DNS override in v1.
- The provider runs the same dial pipeline (offer verify → relay → auth →
  open `IpTunnel`), then pumps `packetFlow` ⇄ stream.
- Any auth/verify/parse failure → `cancelTunnelWithError` (system removes the
  interface and routes) — fail-closed.
- **Entry gate for Phase 2**: the packet-tunnel NetworkExtension entitlement
  must be confirmed for the team/app IDs (go/no-go checkpoint before any iOS
  work starts).

### 3.3 Relay-R — unchanged
Remains a blind stream splicer, treated as fully untrusted. v1 carries
IP-in-stream over the existing TCP splice, accepting TCP-over-TCP behavior
under loss for dev purposes (measured in Phase 5). A datagram/QUIC relay mode
is a possible later slice, explicitly out of scope here.

### 3.4 Control plane (engine)
- A VPN-capable offer/capability is a **new, distinct capability** minted by
  an explicit owner action. It is *not* implied by an existing PTY/share
  capability (explicit-selection principle). Each grant is one entry in the
  target claw's ACL, keyed by `(member, device, claw)` — authorization is a
  per-relationship record, never a single-owner or claw-wide switch.
- Session admission reuses SessionAuthToken PoP bound to
  (member, device, claw). Admission assigns the session's tunnel address pair
  and registers the active session — listable and revocable by the owner.
- Deny-list reconcile (remove-wins) applies: revocation tears down live VPN
  sessions within a bounded interval (≤60s target).

### 3.5 Addressing and routes
- One dedicated, configurable per-household prefix allocated by the engine;
  each (claw, session) gets a /32 pair from it. Constraints for the Phase-1
  decision: must avoid CGNAT `100.64.0.0/10` (Tailscale coexistence on the
  same phone), common home-LAN ranges, and any range already reserved by the
  nvpn L3 effort. IPv6 ULA is the likely v2 direction.
- Conservative inner MTU (~1250) pending path measurements.

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
  N:N ACL is unaffected. Default caps: 1 active session per (member, claw);
  small fixed cap per claw.

## 4. Security load-bearing points

- **S1 Device/user authentication** — every tunnel session requires member
  PoP (existing household-cert machinery) bound to the target
  (`target_id = claw_id`). Failures are rejected generically (anti-oracle).
- **S2 Per-claw authorization (N:N)** — VPN capability is explicit and keyed
  by `(member, device, claw)`, one ACL entry per relationship (§3.6); no
  single-owner assumption; holding a PTY/share capability does NOT grant VPN.
- **S3 E2E encryption** — Noise end-to-end Device-D ⇄ claw agent. Relay-R
  never holds keys or plaintext (unchanged trust model: relay untrusted).
- **S4 Replay/TTL/single-use** — offers stay TTL'd + replay-guarded
  (existing guards); handshake nonces get **explicit window-boundary replay
  negatives** in the test plan (an adjacent-code review previously caught a
  nonce-window boundary replay bug that unit tests had missed — this class
  is tested deliberately, not incidentally).
- **S5 Rotation/revocation** — per-session keys; bounded session lifetime
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
- **S7 Dev/prod isolation** — new flags (working names `THEYOS_CLAW_VPN_LIVE`,
  `THEYOS_CLAW_VPN_DIAL`, plus an endpoint var) default-off; dev-only
  standalone bins first (the existing `relay_stream_*_dev` pattern);
  Engine-prod is untouched by every phase in this plan; each deploy/flip is
  a separate owner-authorized STOP gate (a relayed GO is not a GO).
- **S8 Auditability without sensitive logs** — structured session lifecycle
  events recorded per `(member, device, claw)` (open/deny/close + reason
  codes, byte counters) using internal neutral ids, so N:N access is
  attributable per relationship. Never packet payloads, external IPs, UDIDs,
  or key material in logs. Neutral ids are pseudonymous local identifiers, not
  anonymization; any future exported/shared audit backend must use keyed
  derivation (for example HMAC) or an explicit equivalent exposure policy.
- **S9 Anti-spoof + no forwarding** — both directions filtered to the single
  (session peer ⇄ claw) address pair; the agent never routes beyond itself;
  LAN and other claws unreachable by construction.
- **S10 Explicit selection** — connecting is a manual member action naming a
  specific claw; no auto-connect, no wildcard offers, no implicit device
  enrollment.

## 5. Implementation phases (conservative; nothing ships)

- **Phase 0 — plan + inert scaffolding.** Security co-review of the document
  plus reserved signed resource, pure packet/admission/audit helpers, and a
  default-off dev config parser guarded from runtime wiring. STOP: no
  TUN/utun, route installation, storage-backed registry, runtime agent, or
  product activation before a separate implementation sign-off.
- **Phase 1 — Rust↔Rust dev proof (no Apple gates).** Claw agent with
  TUN/utun + a macOS `utun` dev *client* bin (all Rust), over the existing
  dev relay, behind new default-off flags. The first Phase-1 core slice adds
  only the pure local-interface ⇄ relay datapath helper that maps device/claw
  sides to the correct packet direction and rejects spoof/control frames before
  forwarding; the next inert bridge slice makes the relay-stream target gate
  check the signed resource exactly, so a `Pty`/`ClawSite` offer cannot
  authorize a future `IpTunnel` packet path and an `IpTunnel` offer cannot
  authorize a stream target. Neither slice is T1 because they create no
  interface or route. Includes landing the guest-kernel TUN prerequisite for
  Linux claws. Exit: T1–T4 green on dev hosts.
- **Phase 2 — iOS Packet Tunnel dev build.** Entry: entitlement go/no-go.
  Dev device only. Exit: T5–T7 green (iPhone reaches Claw-A — and only
  Claw-A).
- **Phase 3 — adversarial hardening.** Full negative matrix (T8–T13),
  revocation latency, reconnect/background. Independent security re-review
  of S1–S10 against the code as built.
- **Phase 4 — multiuser + limits + audit events.** T14–T16 and T19 (the
  N:N positive/negative pair).
- **Phase 5 — hardware E2E + performance baseline.** Cellular, no Tailscale,
  public relay (T17–T18). Still default-off everywhere. Shipping/activation
  is a separate explicit owner decision; until then any flip is confined to
  isolated test/dev engines with no real households.

Standing governance inside every phase: any deploy touching a shared host and
any flag flip is individually owner-authorized; peer-relayed authorization is
not authorization.

## 6. Test matrix — the 100% bar

| ID | proves | PASS condition |
|----|--------|----------------|
| T1 | interface up | agent creates TUN/utun with assigned addresses; clean exit removes the interface |
| T2 | tunnel plumbing | ICMP + TCP echo client ⇄ Claw-A over Relay-R (Rust dev client) |
| T3 | route scope | client route table contains ONLY Claw-A/32 via the tunnel; LAN and other-claw addresses take the normal path |
| T4 | fail-closed plumbing | kill Relay-R mid-session → tunnel down, routes gone, no half-open interface |
| T5 | iOS interface/routes | NE tunnel up on a dev iPhone; system routes show only Claw-A/32 via utun |
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
| T17 | real-world path | iPhone on cellular (no Tailscale, no shared Wi-Fi) → public Relay-R → Claw-A: T5–T7 repeated |
| T18 | lifecycle | app background/foreground, Wi-Fi⇄cellular flap, claw restart, engine restart: reconnect or fail-closed — never a stale route |
| T19 | cross-claw negative | Member-M1 authorized for Claw-A but NOT Claw-B: Claw-A session succeeds while Claw-B admission is rejected (generic error), no session, no route |

100% = every row green in its owning phase, negatives included, before the
next phase begins. Claw variants: the matrix runs against both a macOS-hosted
claw and a Linux claw.

## 7. Non-goals (v1)

- NOT a whole-network VPN: no default route, no exit node, no LAN exposure.
- NOT a mesh: no claw⇄claw or device⇄device routing; **no nvpn/mesh promises
  until daemon + interface + routes are proven** per this plan.
- No DNS/split-DNS; no auto/on-demand connect; no UDP/datagram relay mode;
  no public/anonymous VPN offers.

## 8. Dependencies & risks

- Apple packet-tunnel entitlement (Phase-2 entry gate; approval delay is the
  risk — mitigated by the all-Rust Phase 1).
- Linux guest kernel `CONFIG_TUN=y` (land the `spike/nvpn-slirp` kernel
  recipe) for VM claws.
- TCP-over-TCP performance under loss (accepted for v1; measured in Phase 5).
- Address-range collision with user networks (constraint-driven choice, §3.5).
- iOS NE lifecycle quirks (background termination/restart) — covered by T18.

## 9. Open questions for the owner

1. Final address-range choice (§3.5): IPv4 sub-range vs ULA-first.
2. Confirm v1 policy of one claw at a time per device.
3. Should granting VPN capability be owner-only, or delegable to group
   admins?
4. Retention target for session audit events.

## 10. Relation to existing plans

This is the evolution of the proven relay path ("plan 1" in the standing
three-plan framing): it reuses the nvpn effort's learnings (kernel TUN
recipe) but is **not** a resurrection of the nvpn L3 mesh ("plan 3") and has
no Tailscale dependency ("plan 2"). The plans stay separate; this document
only commits to the point-to-point per-claw tunnel described above.
