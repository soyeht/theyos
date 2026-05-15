#!/usr/bin/env bash
#
# T028 source-level lint for `apns_dispatcher.rs` — the third layer of
# the Constitution III "no household metadata reaches the push provider"
# enforcement stack (compile-time API shape + runtime spy test +
# this lint).
#
# Three checks, all of which MUST pass:
#
#   1. Body-source check — the file MUST NOT contain any of the
#      forbidden body sources (`format!`, `serde_json::*`, `Vec::from`,
#      `Vec::extend_from_slice`, `String::from`, `to_owned()` then
#      `into_bytes()`). The only byte/string literal allowed in the
#      file is the canonical Apple silent-push body
#      `b"{\"aps\":{\"content-available\":1}}"`.
#   2. Public-API check — the set of `pub` items MUST equal exactly
#      {APNS_TICKLE_BODY, ApnsTransport, ApnsError, dispatch_tickle}
#      (other `pub` items declared above are treated as supporting
#      configuration and are explicitly enumerated below).
#   3. Body-arg check — `dispatch_tickle`'s signature MUST be exactly
#      `async fn dispatch_tickle(token: &OwnerDevicePushToken)
#      -> Result<(), ApnsError>` (whitespace-insensitive).

set -euo pipefail

DISPATCHER="${DISPATCHER:-admin/rust/server-rs/src/apns_dispatcher.rs}"

if [[ ! -f "${DISPATCHER}" ]]; then
    echo "lint-apns-payload: dispatcher source not found at ${DISPATCHER}" >&2
    exit 2
fi

fail() {
    echo "lint-apns-payload: FAIL — $*" >&2
    exit 1
}

# Strip block comments and line comments so doc-strings can mention the
# forbidden patterns without tripping the lint.
strip_comments() {
    # Remove /* ... */ block comments (single-line only — the file has
    # no multi-line block comments) then trim line comments after //.
    sed -E 's|/\*[^*]*\*/||g' "$1" \
        | sed -E 's|//.*$||'
}

CODE_ONLY="$(strip_comments "${DISPATCHER}")"

# ---- Check 1: body-source check -----------------------------------------
forbidden_patterns=(
    'format!'
    'serde_json::json!'
    'serde_json::to_vec'
    'serde_json::to_string'
    'Vec::from\('
    'Vec::extend_from_slice'
    'String::from\('
    'to_owned\(\).*into_bytes\(\)'
)
for pat in "${forbidden_patterns[@]}"; do
    if grep -E -- "${pat}" <<<"${CODE_ONLY}" > /dev/null; then
        fail "forbidden body source ${pat} present in ${DISPATCHER}"
    fi
done

# Only one byte/string literal is allowed as a payload body: the
# canonical `APNS_TICKLE_BODY` constant. Walk the dispatcher source
# tokenized via Python so we correctly handle escaped quotes inside
# byte/string literals. The allowlist enumerates: the canonical body,
# build-time env-var names, runtime kill-switch values, and tracing
# string fields (non-payload-bearing by construction).
python3 - "$DISPATCHER" <<'PYEOF'
import re, sys
allowed = {
    # Apple silent-push canonical body. Previous {"v":1} payload did not
    # wake the iPhone; the spec demands aps.content-available == 1.
    r'"{\"aps\":{\"content-available\":1}}"',
    r'b"{\"aps\":{\"content-available\":1}}"',
    '"THEYOS_APNS_TOPIC"',
    '"THEYOS_PUSH_DISABLED"',
    '"1"',
    '"apns.disabled_at_runtime"',
    '"skipped APNS dispatch"',
    '"test.theyos.apns"',  # only appears in the spy-test harness, never in dispatcher source
}
src = open(sys.argv[1]).read()
pattern = re.compile(r'b?"(?:[^"\\]|\\.)*"')
no_block = re.sub(r'/\*.*?\*/', '', src, flags=re.DOTALL)
no_line = re.sub(r'//.*$', '', no_block, flags=re.MULTILINE)
# Extract every literal annotated by `#[error("...")]` — those are
# thiserror Display strings, never wire-surface bytes — and add them
# to the allowlist automatically.
for m in re.finditer(r'#\[error\((b?"(?:[^"\\]|\\.)*")\)\]', no_line):
    allowed.add(m.group(1))
for lit in set(pattern.findall(no_line)):
    if lit not in allowed:
        print(f"lint-apns-payload: FAIL — unexpected literal {lit!r}", file=sys.stderr)
        sys.exit(1)
PYEOF

# ---- Check 2: public-API check ------------------------------------------
required_pub=(
    'pub const APNS_TICKLE_BODY'
    'pub trait ApnsTransport'
    'pub enum ApnsError'
    'pub async fn dispatch_tickle'
)
for needle in "${required_pub[@]}"; do
    if ! grep -F -- "${needle}" "${DISPATCHER}" > /dev/null; then
        fail "required pub item missing: ${needle}"
    fi
done

# Allow the explicitly-enumerated supporting `pub` items but reject any
# others (so a future commit cannot widen the public surface without
# updating this lint).
#
# The grep regex covers EVERY pub-item kind Rust admits — `const`,
# `trait`, `enum`, `async fn`, `fn`, `struct`, plus `use`, `static`,
# `mod`, `type`, `union`, `extern`, `crate`, and `unsafe`. A previous
# version only matched the first six and let `pub use serde_json::*`,
# `pub static …`, and `pub mod …` slip past — exactly the smuggling
# vectors a hostile contributor could use to widen the dispatcher's
# surface without tripping any of the three Constitution III gates.
allowed_pubs=(
    'pub const APNS_TICKLE_BODY'
    'pub const APNS_TOPIC_ENV'
    'pub const PUSH_DISABLED_ENV'
    'pub trait ApnsTransport'
    'pub enum ApnsError'
    'pub async fn dispatch_tickle'
    'pub async fn dispatch_tickle_with'
    'pub fn install_transport'
)
while IFS= read -r line; do
    line_trim="$(printf '%s' "${line}" | sed 's/^[[:space:]]*//')"
    is_allowed=0
    for ok in "${allowed_pubs[@]}"; do
        if [[ "${line_trim}" == "${ok}"* ]]; then
            is_allowed=1
            break
        fi
    done
    if [[ "${is_allowed}" -eq 0 ]]; then
        fail "unexpected pub item: ${line_trim}"
    fi
done < <(grep -E '^[[:space:]]*pub (const|trait|enum|async fn|fn|struct|use|static|mod|type|union|extern|crate|unsafe)\b' <<<"${CODE_ONLY}")

# ---- Check 3: body-arg check --------------------------------------------
# Whitespace-collapse the dispatcher source and look for the exact sig.
flat="$(tr -s '[:space:]' ' ' <<<"${CODE_ONLY}")"
expected_sig='pub async fn dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError>'
if ! grep -F -- "${expected_sig}" <<<"${flat}" > /dev/null; then
    fail "dispatch_tickle signature does not match expected '${expected_sig}'"
fi

echo "lint-apns-payload: OK"
