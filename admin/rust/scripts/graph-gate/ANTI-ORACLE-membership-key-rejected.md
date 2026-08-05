# Pre-registered anti-oracle criteria — `MembershipKeyRejected`

**Written at base `cf3969fd`, before the implementation exists.** That claim is
checkable rather than asserted: at this commit `git grep -n
"mesh-session-runtime\|mesh_session_runtime"` over the whole tree returns
nothing, and `admin/rust/mesh-session-runtime-rs/` is absent. Nothing here was
fitted to code I had seen, because there was no code to see.

Every question below carries a **rejection criterion**. A checklist entry
without one cannot fail, and a gate that cannot fail is not a gate.

---

## 1. The property being defended

The facade takes caller-supplied material and may answer
`Err(MembershipKeyRejected)`. It is an **oracle** if a caller can learn, from
anything it can observe, *why* the rejection happened — because that turns a
single rejected attempt into a probe, and repeated probes into enumeration of
the roster or of key material.

The property is therefore **indistinguishability**, not secrecy: the caller is
allowed to learn "rejected", and nothing else.

### Input equivalence classes

These are the classes a caller can construct on purpose. All of them that map
to `MembershipKeyRejected` must be mutually indistinguishable:

| Class | Input |
|---|---|
| **A** | member id absent from the roster |
| **B** | member id present, key material does not match |
| **C** | member id present, key matches, membership not active (revoked/expired) |
| **D** | key material malformed (wrong length, not a valid curve point) |
| **E** | key correct but wrong generation/epoch |

The design is **not** required to put all five in one variant. It is required
to declare the partition explicitly — e.g. "D is a decode error, A/B/C/E are
`MembershipKeyRejected`" — and then hold indistinguishability **within each
cell**. An undeclared partition is a failure by default: if the mapping is not
written down, no test can be shown to cover it.

**Rejection criterion (0).** If the code maps classes to public errors without
a declared, exhaustive mapping — in particular if the internal reason enum is
converted with a catch-all arm — REJECT. The mapping must be an exhaustive
`match` over the internal reason type so that adding a reason is a **compile
error**, not a silent new oracle. Fail-closed by TYPE, not by diligence.

---

## 2. Channels, and what refutes each

### C1 — Variant identity
*Leak:* distinct public variants (or distinct discriminants) per class.
*Rejection observation:* for every pair of classes in the same declared cell,
construct both inputs and assert the two error **values** compare equal.
Requires `PartialEq` on the error, or comparison of
`std::mem::discriminant` **plus** full payload.
*REJECT if:* any pair within a cell is unequal, or if equality cannot be
expressed because the error is not comparable — an unobservable property is not
a satisfied one.

### C2 — `Display`
*Leak:* one variant, different rendered text ("unknown member" vs "bad key").
*Rejection observation:* `assert_eq!(format!("{a}"), format!("{b}"))` for every
pair in a cell, **and** assert the rendered string contains none of the
caller-supplied bytes (member id, key bytes, hex or base64 of either).
*REJECT if:* the strings differ, or any caller-supplied identifier appears in
the output.

### C3 — `Debug`
*Leak:* `Display` is uniform but `{:?}` prints the payload. This is the one
that gets missed, and it is precisely what lands in logs.
*Rejection observation:* `assert_eq!(format!("{a:?}"), format!("{b:?}"))`, plus
the same substring check as C2.
*REJECT if:* they differ. A uniform `Display` with a discriminating `Debug` is
a full oracle for anyone reading logs.

### C4 — `source()` / error chain
*Leak:* `thiserror`'s `#[from]` attaches the inner reason as a **source**. The
outer variant can be perfectly uniform while
`std::error::Error::source()` hands back the internal cause verbatim.
*Rejection observation:* walk the whole chain
(`let mut s = e.source(); while let Some(x) = s { … }`) and assert both the
chain **length** and every link's `Display`/`Debug` are equal across a cell.
*REJECT if:* the chains differ in length or content — including the case where
one class has `Some(source)` and another has `None`.

### C5 — Payload shape and contents
*Leak:* a variant carrying `Option<T>`, `Vec<u8>` or `String` whose
presence/length varies by class. Note `size_of::<Error>()` is per-type and
constant, so it is **not** the observable — the contents are.
*Rejection observation:* prefer a **fieldless** variant, verified by exhaustive
destructuring (no `..`) so a later added field is a compile error. Where fields
exist, assert equality of the whole value (C1 already covers this if `PartialEq`
is derived, since a derived impl compares every field including ones added
later).
*REJECT if:* any field's value is a function of which class was supplied.

### C6 — Validation order and observable side effects
*Leak:* the return value is uniform but the *work done* is not — class A
returns before a roster read, class B performs one; a counter is bumped in one
path only; a file is touched in one path only.
*Rejection observation:* a recording double (the `OrderSpy` shape already used
in this repo) placed at the real dependency seams, asserting the **identical
ordered sequence** of observable operations for every class in a cell. The spy
must record the operation itself, not a field read after it.
*REJECT if:* the sequences differ in content or order, including differences
that look benign such as "one extra read".

### C7 — Logs and tracing events
*Leak:* the same `Err` value accompanied by different `tracing` events, targets,
levels or fields. A pure return-value test cannot see this at all, and the log
is the most widely readable surface in the system.
*Rejection observation:* install a capturing subscriber, run each class, and
assert the captured event sequence — target, level, message and **field set with
values** — is equal across the cell.
*REJECT if:* any event differs, or any event carries a caller-supplied
identifier. Prior art in this repo: the identifier slot is also what the error
log prints.

### C8 — Metrics and counters
*Leak:* distinct counters per reason, readable by anyone with metrics access.
*Rejection observation:* snapshot every counter the path can touch before and
after, and assert identical deltas across the cell.
*REJECT if:* any delta differs.

### C9 — Serialised form
*Leak:* if the error crosses a wire, the encoded bytes are a further rendering
that C2/C3 do not cover.
*Rejection observation:* if the error is `Serialize`, assert byte equality of
the encoded value across the cell.
*REJECT if:* bytes differ. **N/A is an acceptable outcome** only if the error is
provably not serialisable at the boundary — state which.

### C10 — Timing / short-circuit
*Leak:* class A returns before any key comparison; class B runs the full
verification. The difference is measurable remotely if it is large.

This one gets an **honest criterion instead of a fake measurement**. A
wall-clock timing test on a developer machine, under a scheduler we do not
control, is not a rejection criterion — it fails and passes for reasons
unrelated to the code, which makes it a broken instrument that will mostly
confirm whatever we already believe. So timing is addressed **structurally**:

*Rejection observation:*
(i) the C6 sequence equality already forbids the early return, since a
short-circuit shows up as a missing operation; **and**
(ii) any comparison of secret-equal material must use a constant-time primitive
(`subtle::ConstantTimeEq` or equivalent), not `==` on the bytes.
*REJECT if:* either (i) fails or (ii) is absent.
*Declared limit:* this gate does **not** claim the implementation is
constant-time end to end. It claims there is no *structural* short-circuit and
no variable-time comparison of secret material. A statistical timing study is
out of scope and would not be trustworthy at this granularity.

---

## 3. Non-vacuity controls (mandatory)

Every criterion above is satisfied trivially by a function that always returns
the same error and does nothing. Each therefore requires its paired control:

- **N1 — the accept path works.** A legitimate, active, correctly-keyed member
  returns `Ok`. Without this, "all classes are indistinguishable" is met by a
  stub.
- **N2 — the spy can see.** Deliberately perturb one class (a mutant that adds
  one roster read on class A only) and show the C6 assertion **fails**. An
  assertion never observed failing has not been shown to be able to fail.
- **N3 — the capture can see.** Same for C7: add one distinguishing log field
  and show the test goes red.
- **N4 — the classes are real.** Assert each constructed input actually lands in
  its intended class (e.g. class B's member genuinely exists in the roster),
  otherwise B silently degenerates into A and the equality passes because both
  sides are the same class.

**N4 is the one most likely to rot**: a fixture that quietly stops populating
the roster turns every class into A, and the whole suite goes green while
measuring nothing.

---

## 4. What this pre-registration does not cover

Stated so a PASS is not read wider than it is:

- Package-granularity only for reachability questions; it says nothing about
  which module inside a crate is reachable.
- No claim about end-to-end constant time (see C10).
- No claim about side channels below the language: cache, branch prediction,
  memory-pressure effects.
- No claim about oracles reachable through *other* facade entry points; this
  covers the rejection path of the membership-key entry point only.
