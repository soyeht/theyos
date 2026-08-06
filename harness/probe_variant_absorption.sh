#!/usr/bin/env bash
# Compiler-driven proof: which BootstrapState matches are FORCED to change by a
# new variant, and which absorb it SILENTLY (wildcard arm => no error).
#
# The in-crate `as_str` match is satisfied deliberately so household-rs still
# compiles; otherwise cargo stops there and every downstream crate goes
# UNCHECKED, which reads as "nothing else is affected" when nothing else was
# even looked at.
set -u
ROOT="$(git rev-parse --show-toplevel)"
F="$ROOT/admin/rust/household-rs/src/bootstrap_state.rs"
PROBE="ZzProbeVariantDoNotShip"

restore() {
  cd "$ROOT" && git checkout -- admin/rust/household-rs/src/bootstrap_state.rs
}
trap restore EXIT

grep -q "$PROBE" "$F" && { echo "probe already present, aborting"; exit 2; }
perl -0pi -e "s/^pub enum BootstrapState \{\n/pub enum BootstrapState {\n    $PROBE,\n/m" "$F"
perl -0pi -e "s/(            Self::Recovering => \"recovering\",\n)/\$1            Self::$PROBE => \"zz_probe\",\n/m" "$F"
echo "--- probe inserted at: ---"; grep -n "$PROBE" "$F"

cd "$ROOT/admin/rust" || exit 2
# --keep-going so ONE failing crate does not hide every crate behind it
cargo check --workspace --all-targets --keep-going --message-format=short > /tmp/probe_check.out 2>&1
echo "cargo exit: $?"
echo
echo "=== (A) FORCED TO CHANGE — non-exhaustive match, compiler caught it ==="
grep -oE "^[^ :]+\.rs:[0-9]+:[0-9]+: error\[E0004\]" /tmp/probe_check.out | cut -d: -f1 | sort -u
echo
echo "=== error codes seen ==="
grep -oE "error\[E[0-9]+\]" /tmp/probe_check.out | sort | uniq -c
