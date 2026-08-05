#!/usr/bin/env bash
# Lane C mechanical gate. Run from admin/rust:
#   bash scripts/graph-gate/run_gate.sh [structural|full]
#
# Rules this script exists to enforce on itself:
#  * Every command's exit code is captured DIRECTLY into $? and printed. Nothing
#    is piped into tail/head, because a pipeline reports the exit code of the
#    LAST stage and would mask a failing cargo.
#  * A configuration that cannot run (package or feature absent) is reported
#    SKIP with its own marker. SKIP is never counted as PASS — a gate that
#    reports green for a configuration it never executed is the exact failure
#    this lane was created to prevent.
#  * Lint/check commands use --all-targets. Without it a broken caller in a test
#    or bench target is invisible. `--example` alone does NOT lint cfg(test).
#  * No count from `--all-targets` is compared across differently-shaped runs;
#    where a count appears it is anchored to one exact command string.

MODE="${1:-structural}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${GATE_OUT:-$(mktemp -d)}"
GATE_PY="$HERE/graph_gate.py"
mkdir -p "$OUT"

pass=0; fail=0; skip=0
echo "gate_out=$OUT"
echo "mode=$MODE"
echo "rustc=$(rustc --version)"
echo "cargo=$(cargo --version)"
echo "head=$(git rev-parse HEAD)"
echo

# run <label> <command...>  — prints the exact command and its real RC.
run() {
  local label="$1"; shift
  echo "--- $label"
  echo "\$ $*"
  "$@" > "$OUT/$label.out" 2> "$OUT/$label.err"
  local rc=$?
  echo "RC=$rc"
  if [ "$rc" -eq 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
  return $rc
}

skip_cfg() {
  echo "--- $1"
  echo "SKIP reason=$2"
  echo "RC=n/a"
  skip=$((skip+1))
}

have_pkg() {
  cargo metadata --format-version 1 --no-deps --offline 2>/dev/null \
    | python3 -c "import json,sys;print(any(p['name']=='$1' for p in json.load(sys.stdin)['packages']))" \
    | grep -q True
}

# ---------------------------------------------------------------- structural
echo "=== PHASE 1: graph structure (cargo metadata, not manifest reading) ==="

run md-default cargo metadata --format-version 1 --offline
cp "$OUT/md-default.out" "$OUT/md-default.json" 2>/dev/null

run cycles-default python3 "$GATE_PY" cycles --metadata "$OUT/md-default.json"
cat "$OUT/cycles-default.out"

if have_pkg mesh-session-runtime-rs; then
  run md-runtime-on cargo metadata --format-version 1 --offline \
      --features mesh-session-runtime-rs/mesh-session-runtime
  cp "$OUT/md-runtime-on.out" "$OUT/md-runtime-on.json" 2>/dev/null
  run cycles-runtime-on python3 "$GATE_PY" cycles --metadata "$OUT/md-runtime-on.json"
  cat "$OUT/cycles-runtime-on.out"
  # `--local-only` is REQUIRED, not optional: the allowlist file's own header
  # says "Scope is workspace-local only (see --local-only); registry crates are
  # out of scope for this boundary and churn independently" -- and until
  # 2026-08-05 this invocation did not pass it. The allowlist therefore had to
  # account for every transitive registry crate, so PHASE 1a reported
  # `outside_allowlist` permanently, naming hundreds of packages nobody had ever
  # intended it to govern. That red was read as a finding about the delivery and
  # was about a missing flag. Fourth comment-vs-mechanism divergence found in
  # this gate today: the scope was declared in the allowlist and not applied at
  # the call.
  run contain-runtime python3 "$GATE_PY" contain \
      --metadata "$OUT/md-runtime-on.json" --root mesh-session-runtime-rs \
      --allow "$HERE/allowlist-mesh-session-runtime.txt" --local-only \
      --deny server-rs claw-share-bridge-rs t1-iptunnel-dev-runner-rs m1-household-mesh-smoke-rs nostr-relay-rs
  cat "$OUT/contain-runtime.out"
else
  skip_cfg md-runtime-on "package mesh-session-runtime-rs absent at this commit"
  skip_cfg cycles-runtime-on "package mesh-session-runtime-rs absent at this commit"
  skip_cfg contain-runtime "package mesh-session-runtime-rs absent at this commit"
fi

echo
echo "=== PHASE 1b: no NEW edge to a watched package (reformulated (c)) ==="
# The absolute form "default has no mesh/snow" is FALSE at the base: household-rs
# and server-rs both depend on `snow` unconditionally. A criterion that can never
# pass gets waived, and a waived gate is decoration. What a change CAN be held to
# is introducing no NEW parent for a watched package.
#
# Two exemptions, each for ONE named edge. Neither is a re-pin of the baseline:
# the baseline still records the pre-change parent sets, so a THIRD new edge
# still fails here. `--allow-new-parent mesh-session-runtime-rs` was dropped --
# it was measured inert (regress prints the identical two violations with and
# without it) and its bare form is no longer accepted.
#
#   mesh-session-core-rs=household-rs
#     The dev-dependency edge in household-rs/Cargo.toml. Held here rather than
#     removed because the alternative was measured and costs more: the optional
#     [dependencies] entry and the [dev-dependencies] entry unify by NAME, so
#     gating the dev entry behind the feature would activate `test-support`
#     from a normal build -- the one thing Lane R says must never happen. The
#     narrower property (dev-only, household-rs as sole parent) is what PHASE 2
#     now asserts directly, so this exemption is covered by a live check and not
#     merely tolerated.
#
#   snow=mesh-session-core-rs
#     Consequence of the edge above, not an independent decision. `snow` already
#     had two normal workspace parents at the baseline (household-rs, server-rs),
#     so this adds no reachability: it is a new parent of an already-reached
#     package. Recorded rather than waived because "no new parent" is the
#     property this phase measures, and the exemption names the edge that made
#     it true instead of relaxing the predicate for everyone.
#
run regress-default python3 "$GATE_PY" regress \
    --metadata "$OUT/md-default.json" \
    --baseline "$HERE/baseline-cf3969fd.json" \
    --allow-new-parent mesh-session-core-rs=household-rs snow=mesh-session-core-rs
cat "$OUT/regress-default.out"

echo
echo "=== PHASE 2: feature-OFF surface absence (structural half) ==="
# The dependency-level half of "the surface does not exist": with the feature
# off, the crate that provides it must not be in the resolve graph at all.
# Not being CALLED is a weaker property than not being PRESENT.
run offsurface-default python3 - "$OUT/md-default.json"  <<'PY'
import json, sys
md = json.load(open(sys.argv[1]))
nm = {p["id"]: p["name"] for p in md["packages"]}
present = {nm[n["id"]] for n in md["resolve"]["nodes"]}
ks = [n for n in md["resolve"]["nodes"] if nm[n["id"]] == "keystore-rs"]
feats = ks[0]["features"] if ks else None
print("keystore-rs features under workspace default =", feats)
print("mesh-session-core-rs present =", "mesh-session-core-rs" in present)

# DECOMPOSITION -- and it is the PREDICATE, not commentary (@khai, a95b4802).
# Edge kinds mirror graph_gate.py:build_graph exactly: dep_kinds[].kind is null
# for a normal dependency, "dev"/"build" otherwise; an edge counts as non-dev if
# ANY of its kinds is null or "build".
SOLE_ALLOWED_PARENT = "household-rs"
parents = []
for n in md["resolve"]["nodes"]:
    for d in n.get("deps", []):
        if nm.get(d["pkg"]) == "mesh-session-core-rs":
            kinds = [k.get("kind") for k in d.get("dep_kinds", [])] or [None]
            parents.append((nm[n["id"]], kinds))
normal = sorted({p for p, k in parents if any(x is None or x == "build" for x in k)})
others = sorted({p for p, _ in parents if p != SOLE_ALLOWED_PARENT})
print("  decomposition:")
for p, k in sorted(parents):
    print("    parent %s kinds=%s" % (p, k))
print("    reached by a NORMAL/build edge =", bool(normal))

# No `optional = true` clause here on purpose. It would make the gate read
# Cargo.toml, which the header says it does not do -- manifests describe INTENT.
# And it is subsumed: if that entry stops being optional the dependency becomes
# an unconditional normal edge under default, which `normal` already fails on.
# Verified by @khai's probe N, not by argument.
bad = []
if feats:
    bad.append("keystore-rs carries features by default: %s" % feats)
if "mesh-session-core-rs" in present:
    # REVISED PREDICATE (declared revision of line 98's absolute "must not be in
    # the resolve graph at all"). That absolute cannot be satisfied: cargo cannot
    # gate a [dev-dependencies] entry without unifying the feature onto the
    # [dependencies] entry of the same name, and that unification would publish
    # `D1MembershipKey::new_for_test` into the library artifact. The constraint
    # is cargo's, not ours, which is what makes this an exception rather than an
    # excuse. What is still forbidden -- and what the absolute could no longer
    # distinguish once it went permanently red -- is any NORMAL edge and any
    # SECOND parent. Both proved to fire independently (@khai, probes N and P).
    if normal:
        bad.append("mesh-session-core-rs reached by a NORMAL edge: %s" % normal)
    if others:
        bad.append("mesh-session-core-rs has a parent other than %s: %s"
                   % (SOLE_ALLOWED_PARENT, others))
    if not bad:
        print("NOTE: mesh-session-core-rs is PRESENT under workspace default, via a")
        print("      dev-only edge from %s alone. Justified exception," % SOLE_ALLOWED_PARENT)
        print("      not absence -- see the header revision for why absence is")
        print("      unreachable without publishing new_for_test.")
for b in bad:
    print("VIOLATION:", b)
sys.exit(2 if bad else 0)
PY
cat "$OUT/offsurface-default.out"

# A SKIP exits non-zero too. Line 10 already said "SKIP is never counted as
# PASS", and until 2026-08-05 the exit code said otherwise: `pass=0 fail=0
# skip=7` exited 0, so any caller -- CI included -- would have read "green"
# from a run that measured nothing. That is the exact failure this lane exists
# to prevent, and it lived in the one line nobody reads because the summary
# above it looks like the verdict. Fixed at the source rather than asserted by
# each caller: a caller-side `skip=0` check guards one invocation, this guards
# every one.
[ "$MODE" = "structural" ] && { echo; echo "pass=$pass fail=$fail skip=$skip"; exit $([ "$fail" -eq 0 ] && [ "$skip" -eq 0 ] && echo 0 || echo 1); }

# ---------------------------------------------------------------------- full
echo
echo "=== PHASE 3: feature matrix (compiled, --all-targets) ==="

# The AUTHORITATIVE clippy row: this is byte-for-byte what
# .github/workflows/backend-ci.yml runs (`cargo clippy --workspace -- -D
# warnings`, no `--all-targets`). Cite THIS one when reporting "the gate".
run c0-clippy-ci-equivalent cargo clippy --offline --workspace -- -D warnings

# The `--all-targets` row is a DIFFERENT question and is declared debt, not the
# gate: CI's own comment records that `--all-targets` exits 101 across
# core-rs/server-rs/vmrunner-rs/e2e-rs on default features because it has never
# linted test code. Reporting it as "the gate" makes a permanently-red signal
# that masks real regressions -- which is exactly how a lifecycle clippy
# regression stayed hidden. Kept because it answers "is a test-target caller
# broken", but never conflated with the row above.
run c0-check-default    cargo check   --offline --workspace --all-targets
run c0-clippy-alltargets-debt cargo clippy --offline --workspace --all-targets -- -D warnings
run c1-check-mesh       cargo check   --offline -p keystore-rs --all-targets --features mesh-session
run c1-clippy-mesh      cargo clippy  --offline -p keystore-rs --all-targets --features mesh-session -- -D warnings
run c2-clippy-meshtests cargo clippy  --offline -p keystore-rs --all-targets \
      --features mesh-session,test-support,roster-sync-unratified -- -D warnings

if have_pkg mesh-session-runtime-rs; then
  run c3-check-runtime  cargo check  --offline -p mesh-session-runtime-rs --all-targets \
        --features mesh-session-runtime
  run c3-clippy-runtime cargo clippy --offline -p mesh-session-runtime-rs --all-targets \
        --features mesh-session-runtime -- -D warnings
  run c4-check-both     cargo check  --offline -p keystore-rs -p mesh-session-runtime-rs \
        --all-targets --features mesh-session-runtime-rs/mesh-session-runtime
else
  skip_cfg c3-check-runtime  "package mesh-session-runtime-rs absent at this commit"
  skip_cfg c3-clippy-runtime "package mesh-session-runtime-rs absent at this commit"
  skip_cfg c4-check-both     "package mesh-session-runtime-rs absent at this commit"
fi

echo
echo "=== PHASE 4: the two EXCLUDED crates, as separate roots ==="
# They are not workspace members: `cargo check -p mesh-session-core-rs` from
# admin/rust exits 101 "did not match any packages". Measuring them requires
# entering their own workspace, or the matrix silently omits them.
for crate in mesh-session-core-rs mesh-session-control-model-rs; do
  if [ -d "$crate" ]; then
    ( cd "$crate" && cargo check --offline --all-targets ) \
      > "$OUT/standalone-$crate.out" 2> "$OUT/standalone-$crate.err"
    rc=$?
    echo "--- standalone-$crate"
    echo "\$ (cd $crate && cargo check --offline --all-targets)"
    echo "RC=$rc"
    if [ "$rc" -eq 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
  else
    skip_cfg "standalone-$crate" "directory absent"
  fi
done

echo
echo "pass=$pass fail=$fail skip=$skip"
[ "$fail" -eq 0 ] || exit 1
# Same fix as the structural exit above: a skipped configuration is not a pass,
# and the exit code has to agree with the summary line and with line 10.
[ "$skip" -eq 0 ] || exit 1
exit 0
