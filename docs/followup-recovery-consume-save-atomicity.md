# Follow-up: Recovery consume depends on atomic single-blob auth save

Non-blocking follow-up from the R1-B recovery-consume finish review.

## Symptom / issue

The recovery-consume finish no-brick invariant depends on
`HouseholdAuthState::save()` continuing to persist the full owner auth state as
a single atomic blob. The finish runtime appends both authority events in memory:

- WebAuthn Add with actor `RecoveryProof(X)`.
- Recovery `Consume(X)` for the same recovery head.

It then saves `HouseholdAuthState` once before advancing anchors. Because the
save is currently one atomic `household_auth_state.cbor` write, the two log
events are durable together: either both events exist after a crash, or neither
does. That makes a partial durable log state, such as Add without Consume or
Consume without Add, unreachable in normal operation.

## Why this matters

The finish repair path can safely treat `(Add(X), Consume(X))` as a committed
pair and complete anchors in WebAuthn-then-recovery order. If a future refactor
split WebAuthn and recovery authority logs into separate files, or made save
non-atomic across the two logs, the current defensive partial-commit guard could
turn into a real recovery brick instead of a corruption fail-closed case.

## Follow-up work

- Add a comment near `HouseholdAuthState::save()` documenting that recovery
  consume relies on save remaining a single atomic blob for both owner authority
  logs.
- Add a regression test or source guard proving that recovery consume cannot
  durably persist only one of the two log events through the normal save path.
- If auth persistence is ever split by log, redesign recovery-consume commit and
  repair semantics before merging that persistence change.

## Files of interest

- `admin/rust/household-rs/src/owner_auth.rs` - `HouseholdAuthState::save()`
- `admin/rust/server-rs/src/handlers_owner_events.rs` - recovery-consume finish
  save, memory update, anchor order, and repair path
