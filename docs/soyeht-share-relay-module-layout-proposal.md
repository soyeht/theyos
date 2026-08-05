# Soyeht Share relay module layout proposal

Status: proposal only. This document satisfies the module-boundary deliverable in
§6.4 of `soyeht-share-apple-like-plan.md`. It does **not** authorize moving files,
changing visibility, changing the wire, or altering runtime behavior.

## Why change the layout later

The server crate currently exposes the relay implementation as a flat set of
`claw_share_relay_stream_*` and `claw_share_rendezvous_stream_relay_*` modules.
The names are accurate, but the package graph does not show which code admits a
connection, which code authorizes an endpoint, which code merely selects a router,
or which code only observes status. That makes an import look like authority even
when it is not.

The future layout should make those boundaries visible without changing them.

## Proposed ownership tree

```text
household-rs/src/claw_share/
  wire/
    data_tunnel.rs          # TunnelFrame, including OpenPersistent = 0x18
    relay_offer.rs          # signed offer/presentation contract
    relay_endpoint.rs       # relay-stream endpoint syntax
    rendezvous.rs           # hello, role, and token wire values
  noise.rs                  # shared Noise protocol primitives

server-rs/src/claw_share_relay/
  mod.rs                    # narrow facade; re-exports only supported entry points
  public_relay/
    admission.rs            # bounded pending/consumed token authority and abuse gates
    listener.rs             # accept loop, hello intake, pair handoff
    splice.rs               # capped bidirectional byte movement and timeout outcomes
    status.rs               # observation-only counters and snapshots
    config.rs               # public relay policy/config validation
  endpoint/
    authorization.rs        # credential/offer checks and target/resource gate
    persistent_session.rs   # OpenPersistent sequencing, budgets, Close lifecycle
    responder.rs            # authenticated endpoint serve loop
    reverse_connect.rs      # binding and pool lifecycle
  routing/
    target.rs               # target router traits and concrete routers
    app.rs                  # DeviceShareAppId descriptor/resolution
    mount.rs                # household-scoped construction and provisioning entry
    runtime.rs              # binding factories and worker lifecycle
  control_plane/
    provision.rs            # signed offer mint inputs
    offer_store.rs          # minted offer storage
    issuer_trust.rs         # issuer trust/cache/refresh health
    noise_keystore.rs       # responder identity persistence
  test_support.rs           # cfg(test) fixtures only
```

The tree groups existing responsibilities; it does not introduce a new layer or a
new protocol. Some current files already correspond one-to-one with a proposed
leaf. Larger files may remain intact behind a facade until a separately reviewed
move has behavior-unchanged evidence.

## Authority boundaries

These constraints are load-bearing and must survive any later extraction.

1. **Wire authority stays in `household-rs`.** `TunnelFrame`, the
   `OpenPersistent` byte, signed offer payloads, endpoint syntax, rendezvous roles,
   and tokens have one definition. `server-rs` consumes those types; it does not
   copy constants or codecs.
2. **The public relay stays blind.** `public_relay` may admit, pair, cap, splice,
   expire, and count opaque streams. It must not import app resolution, household
   state, credentials, presentation data, or endpoint target authorization.
3. **Admission is enforcement; status is observation.** Pending/consumed capacity,
   abuse limits, and the byte cap are decided from their enforcement state. Status
   counters never feed a budget or an allow/deny decision.
4. **Endpoint authorization remains the only access gate.** The existing target,
   resource, expected-path, credential, and signed-audience checks remain in the
   endpoint authorization path. Constructing or selecting a router does not open a
   backend and does not grant access.
5. **Routing selects implementation, not permission.** `routing` may choose the
   Device resolver or the explicitly gated legacy fixture from the signed
   audience. It never dispatches from the textual shape of `claw_id`, and the
   selected router remains inert until the authorization gate calls it.
6. **Persistent session owns sequencing.** Open/Close acknowledgement handling,
   the per-connection open/byte budget, and sequential `OpenPersistent` targets
   live together. They do not move into a router, status object, or public relay.
7. **Product A / IpTunnel remains independent.** A future layout change must not
   import Product A/nvpn assumptions or make the ClawSite resolver a dependency of
   the IpTunnel path. Generic type separation and existing resource fences remain.

## Visibility target

The final facade should expose only the constructors and traits used by bootstrap,
the standalone public-relay binary, and the HTTP handlers. Leaf modules should be
`pub(crate)` by default. Test-only uncapped helpers and fixtures remain private to
`#[cfg(test)]` code. A move must not expand visibility merely to make a new path
compile.

## Safe migration sequence

Any implementation requires a new authorization and should be split into reviewable
behavior-neutral checkpoints:

1. Add facade modules that re-export the existing types; move no implementation.
2. Move the observation-only status module and prove the `/status` serialized shape
   is byte-for-byte unchanged.
3. Move public admission/listener/splice together, preserving cap-order, timeout
   byte telemetry, no-live-eviction, and source-abuse tests.
4. Move endpoint authorization and persistent-session code, preserving canonical
   frame fixtures, unknown-frame rejection, revoke ordering, and legacy Close tests.
5. Move routing/runtime construction, preserving signed-audience dispatch,
   loopback-only Device resolution, and Group/Public legacy behavior.
6. Move control-plane storage/trust modules last, then remove transitional re-exports.

Each checkpoint should keep old public paths through temporary re-exports until all
callers compile. Removing the compatibility paths is a separate final checkpoint,
not mixed with a move.

## Evidence required before accepting an extraction

- canonical CBOR fixtures and the omitted-presentation byte identity are unchanged;
- `OpenPersistent` is still `0x18` and an unknown frame byte fails closed;
- no `serde` field, HTTP route, status field, error reason, or UniFFI export changes;
- the public-relay cap, telemetry, admission, and revoke-order mutation controls stay
  red under their known mutations and green after restoration;
- server workspace check/clippy and focused relay/endpoint suites pass;
- whole-tree searches (not extension-filtered greps) prove no public-relay dependency
  on app/household authority and no Product A/nvpn dependency entered the ClawSite
  path.

## Explicit non-goals

This proposal does not authorize a runtime change, io_uring or `splice(2)`, a new
relay protocol, a new status wire, a new database, HA, a second region, Product A
integration, or any movement in this feature candidate. The current flat modules
remain the shipping implementation until a separate extraction task is approved.
