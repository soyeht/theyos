//! Lane R (@ilia, 2026-08-05): the 4 pieces this round was told explicitly
//! **not** to build, and to declare instead — "estes precisam de decisões
//! de desenho e de material que não existe... Trata-os como trataste o
//! `IntentNonceLedger`: seam documentado, não implementado, com o motivo e
//! com o que falta para o fechar." Unlike [`crate::ledger_seam`], this
//! module adds no type-level enforcement machinery of its own (no
//! `TrustedFloorProof`-shaped mandatory-input pattern) — that mechanism was
//! authorized separately, for a measured capacity cliff this round has no
//! equivalent measurement for. This is prose plus the exact call sites,
//! nothing more, because building enforcement around material that does
//! not exist yet would itself be a fabrication of the seam, the same
//! mistake this round's rule exists to prevent: "nada de doubles de teste
//! num caminho que se diga de produção, e nada de valores inventados para
//! TTL ou generation."
//!
//! All 4 are constructor parameters of
//! `keystore_rs::mesh_session_bridge::{MeshSessionBridgeSigner, BridgeGenerationResolver}::new_internal`
//! (`keystore-rs/src/mesh_session_bridge.rs`), alongside the `roster` and
//! `clock` parameters this same round DID build real adapters for (see
//! [`crate::HouseholdRosterSource`], [`crate::SystemD4Clock`]).
//!
//! # 1. `SignatureVerifier`
//!
//! `crate::validator::SignatureVerifier` (D4, `mesh-session-control-model-rs/src/validator.rs`):
//! `fn verify(&self, public_key: &[u8], delegation: &Delegation, sig: &[u8]) -> bool`.
//! Zero non-test implementations anywhere in this workspace at the base
//! this facade started from (`cf3969fd`) — confirmed by direct search, not
//! assumed. The trait's own doc states it deliberately receives the typed
//! `Delegation`, not preimage bytes: "a real integration is expected to
//! derive whatever bytes mesh-core's eventual frozen preimage function
//! specifies from `delegation`, entirely inside its own implementation of
//! this trait; this crate does not get a vote on that byte layout." That
//! frozen preimage function is exactly the missing material — this facade
//! cannot invent a byte layout mesh-core has not itself frozen without
//! fabricating the wire contract this whole engagement exists to get
//! right. **What would close this:** mesh-core (or whichever crate owns
//! the frozen preimage decision) publishes the delegation-signing byte
//! layout; a real verifier then wraps whatever P-256/opaque-key
//! verification primitive this workspace already has (`opaque_p256`, in
//! this same `keystore-rs` crate) around that fixed layout.
//!
//! # 2. Real `cell::open`
//!
//! `crate::cell::open` (D4, `mesh-session-control-model-rs/src/cell.rs`):
//! `fn open(path: PathBuf, identity: ControlIdentity, purpose: PurposeId,
//! spy: Arc<OrderSpy>) -> Result<Arc<ControlRecordCell>, OpenConflict>`.
//! Two blockers, not one: (a) the same `pub(crate)`-through-`d4_inline`
//! visibility wall this round's `RosterLookup`/`Clock` bridges exist to
//! cross — closeable the same way, a seam trait in `keystore-rs` this
//! crate implements; (b) `open`'s own signature takes `spy:
//! Arc<OrderSpy>`, and `OrderSpy`'s own doc ties it to test inspection
//! ("callers retain their own handle for `OrderSpy` inspection in
//! tests") — there is no evidence in this workspace of what a
//! *production* caller is meant to pass here instead, or whether `open`'s
//! signature itself is expected to grow a production-shaped entry point
//! before a real caller can exist. Building a bridge around (a) alone
//! would silently paper over (b): a "real" `cell::open` wrapper that still
//! has to invent an `OrderSpy` handle to satisfy the type checker is
//! exactly a fabricated seam wearing a real one's name. **What would close
//! this:** either a documented answer for what production passes as
//! `spy`, or a `cell::open`-adjacent constructor that does not take one.
//!
//! # 3. TTL source
//!
//! `crate::validator::DelegationPolicy { max_ttl: u64 }` already has a
//! real, safe, LANDED default — `DelegationPolicy::production()` returns
//! `max_ttl: 0`, rejecting every delegation until a real TTL is
//! configured. That default is not itself the gap; it is the correct
//! fail-closed behaviour in the absence of the gap being closed. The gap
//! is that no measurement exists anywhere in this workspace for what a
//! real `max_ttl` should be — how long a mesh-session delegation should
//! remain valid is an operational security decision (too long widens the
//! window a compromised delegated key stays useful; too short adds
//! reauthorisation overhead this workspace has not measured the cost of),
//! not something this facade gets to pick as a constant. Inventing a
//! number here is precisely the "nada de valores inventados para TTL"
//! this round was told not to do. **What would close this:** an
//! operational measurement (or an explicit policy decision from whoever
//! owns delegation lifetime tradeoffs) producing a real `max_ttl`, which
//! this facade would then pass to `DelegationPolicy::test`-shaped
//! constructor renamed/promoted to a real one — or a new
//! `DelegationPolicy::configured(max_ttl)` constructor if `test` should
//! stay test-only.
//!
//! # 4. `generation: NonZeroU64` source
//!
//! Both `new_internal` functions take a bare `generation: NonZeroU64` —
//! no fetch, no derivation, just a caller-supplied scalar. D4's own
//! `RetainedGenerationResolver::resolve` doc (`mesh_session_bridge.rs`)
//! says the resolved generation is "independently verified against D4's
//! own live record on every call," which describes what happens to a
//! generation once inside D4's validation path — it does not say where
//! the CONSTRUCTOR's `generation` parameter itself should come from before
//! that. No workspace code answers that question at the base this facade
//! started from. **What would close this:** whichever real caller
//! eventually constructs a `MeshSessionBridgeSigner`/`BridgeGenerationResolver`
//! needs a real source for "which generation is this instance retained
//! for" — plausibly household-rs's own generation/epoch tracking (if one
//! exists at the granularity D4 needs; unconfirmed, not investigated this
//! round since the SignatureVerifier/cell::open blockers above already
//! make constructing either type unreachable regardless of this answer).
