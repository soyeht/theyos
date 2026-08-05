#!/usr/bin/env bash
# Analysis half of the probe: classify every BootstrapState reference site.
# Reads the cargo output produced by probe_variant_absorption.sh.
set -u
REF="${1:?usage: $0 <git-ref>}"
OUT="${2:-/tmp/probe_check.out}"
cd "$(git rev-parse --show-toplevel)" || exit 2

forced=$(grep -oE "^[^ :]+\.rs:[0-9]+:[0-9]+: error\[E0004\]" "$OUT" | cut -d: -f1 | sed 's|^|admin/rust/|' | sort -u)
all=$(git grep -l "BootstrapState::" "$REF" -- 'admin/rust/**/*.rs' | sed "s|^$REF:||" | sort -u)

echo "### (A) COMPILER-FORCED (E0004) — a new variant cannot slip past these:"
echo "$forced" | sed 's/^/  /'
echo
echo "### (B) SILENT — reference BootstrapState but did NOT error."
echo "###     A new variant takes the else/false branch here with no signal."
echo "###     matches!(), if-let and == are NOT exhaustiveness-checked."
comm -13 <(echo "$forced") <(echo "$all") | grep -v "bootstrap_state.rs" | sed 's/^/  /'
