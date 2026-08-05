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
  run contain-runtime python3 "$GATE_PY" contain \
      --metadata "$OUT/md-runtime-on.json" --root mesh-session-runtime-rs \
      --allow "$HERE/allowlist-mesh-session-runtime.txt" \
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
run regress-default python3 "$GATE_PY" regress \
    --metadata "$OUT/md-default.json" \
    --baseline "$HERE/baseline-cf3969fd.json" \
    --allow-new-parent mesh-session-runtime-rs
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
bad = []
if feats:
    bad.append("keystore-rs carries features by default: %s" % feats)
if "mesh-session-core-rs" in present:
    bad.append("mesh-session-core-rs reachable under workspace default")
for b in bad:
    print("VIOLATION:", b)
sys.exit(2 if bad else 0)
PY
cat "$OUT/offsurface-default.out"

[ "$MODE" = "structural" ] && { echo; echo "pass=$pass fail=$fail skip=$skip"; exit $([ "$fail" -eq 0 ] && echo 0 || echo 1); }

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
exit 0
