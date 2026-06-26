#!/usr/bin/env bash
# verify-artifact-manifest-signature-urls.sh - verify live registry manifest signatures.
#
# Downloads latest.json and latest.json.sig.json from the artifact registry URL
# and verifies the exact served bytes against the production public pin. This is
# the post-push gate before enabling Required signature enforcement.
#
# Usage:
#   ./scripts/verify-artifact-manifest-signature-urls.sh [--registry-url URL] [--arch x86_64-linux] [claw ...]
#
# Environment:
#   THEYOS_DIR                    Repo root (auto-detected)
#   THEYOS_ARTIFACT_REGISTRY_URL  Registry base URL override
#
set -euo pipefail

usage() {
    awk '
        NR < 2 { next }
        $0 !~ /^#/ { exit }
        {
            sub(/^# ?/, "")
            print
        }
    ' "$0"
}

THEYOS_DIR="${THEYOS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
ARCH="x86_64-linux"
REGISTRY_URL="${THEYOS_ARTIFACT_REGISTRY_URL:-https://raw.githubusercontent.com/soyeht/theyos/main/artifacts}"
CLAWS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --registry-url)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "[error] --registry-url requires a value" >&2
                exit 2
            fi
            REGISTRY_URL="$2"
            shift 2
            ;;
        --arch)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "[error] --arch requires a value" >&2
                exit 2
            fi
            ARCH="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --*)
            echo "[error] unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            CLAWS+=("$1")
            shift
            ;;
    esac
done

REGISTRY_URL="${REGISTRY_URL%/}"

IMAGEBUILDER=""
for candidate in \
    "$THEYOS_DIR/admin/rust/target/release/imagebuilder" \
    "$THEYOS_DIR/admin/rust/target/debug/imagebuilder" \
    "$(command -v imagebuilder 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        IMAGEBUILDER="$candidate"
        break
    fi
done

run_imagebuilder() {
    if [ -n "$IMAGEBUILDER" ]; then
        "$IMAGEBUILDER" "$@"
    else
        cargo run -q -p imagebuilder-rs --manifest-path "$THEYOS_DIR/admin/rust/Cargo.toml" -- "$@"
    fi
}

discover_claws() {
    if [ "${#CLAWS[@]}" -gt 0 ]; then
        printf '%s\n' "${CLAWS[@]}"
        return
    fi
    find "$THEYOS_DIR/artifacts" -mindepth 3 -maxdepth 3 -type f -name latest.json \
        -path "*/$ARCH/latest.json" \
        -print | sed -E "s#^$THEYOS_DIR/artifacts/([^/]+)/$ARCH/latest\\.json\$#\\1#" | sort
}

fetch_url() {
    url="$1"
    output="$2"
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 "$url" -o "$output"
}

TARGETS_FILE="$(mktemp)"
WORK_DIR="$(mktemp -d)"
cleanup() {
    rm -f "$TARGETS_FILE"
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

discover_claws > "$TARGETS_FILE"
if [ ! -s "$TARGETS_FILE" ]; then
    echo "[error] no artifacts/*/$ARCH/latest.json manifests found" >&2
    exit 1
fi

echo "[raw-verify] registry: configured URL"
echo "[raw-verify] arch: $ARCH"
echo "[raw-verify] claws: $(tr '\n' ' ' < "$TARGETS_FILE" | sed 's/[[:space:]]*$//')"

failed=0

while IFS= read -r claw; do
    manifest_url="$REGISTRY_URL/$claw/$ARCH/latest.json"
    signature_url="$manifest_url.sig.json"
    manifest_file="$WORK_DIR/$claw-latest.json"
    signature_file="$WORK_DIR/$claw-latest.json.sig.json"

    echo "[raw-verify] fetching $claw"
    if ! fetch_url "$manifest_url" "$manifest_file"; then
        echo "[error] failed to fetch manifest for $claw" >&2
        failed=1
        continue
    fi
    if ! fetch_url "$signature_url" "$signature_file"; then
        echo "[error] failed to fetch signature for $claw" >&2
        failed=1
        continue
    fi
    if ! run_imagebuilder verify-manifest-signature "$manifest_file" --signature "$signature_file"; then
        echo "[error] signature verification failed for $claw" >&2
        failed=1
        continue
    fi
done < "$TARGETS_FILE"

if [ "$failed" -ne 0 ]; then
    echo "[error] raw registry signature verification failed" >&2
    exit 1
fi

echo "[raw-verify] OK: all selected live registry manifests verify"
