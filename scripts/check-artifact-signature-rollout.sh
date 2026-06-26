#!/usr/bin/env bash
# check-artifact-signature-rollout.sh - run the post-backfill signature gates.
#
# This helper does not sign manifests and does not need the private key. It is
# the final operator check after the signed .sig.json files have been committed,
# pushed, and pulled into a clean checkout.
#
# Usage:
#   ./scripts/check-artifact-signature-rollout.sh [--registry-url URL] [--arch x86_64-linux] [claw ...]
#
# Environment:
#   THEYOS_DIR                    Repo root (auto-detected)
#   THEYOS_ARTIFACT_REGISTRY_URL  Registry base URL override for the live check
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
REGISTRY_URL="${THEYOS_ARTIFACT_REGISTRY_URL:-}"
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

run_step() {
    echo "[rollout-check] $1"
}

BACKFILL_ARGS=(--check-only --arch "$ARCH")
RAW_VERIFY_ARGS=(--arch "$ARCH")

if [ -n "$REGISTRY_URL" ]; then
    RAW_VERIFY_ARGS+=(--registry-url "$REGISTRY_URL")
fi

if [ "${#CLAWS[@]}" -gt 0 ]; then
    BACKFILL_ARGS+=("${CLAWS[@]}")
    RAW_VERIFY_ARGS+=("${CLAWS[@]}")
fi

run_step "checking committed local signatures"
"$THEYOS_DIR/scripts/backfill-artifact-manifest-signatures.sh" "${BACKFILL_ARGS[@]}"

run_step "checking live registry bytes"
"$THEYOS_DIR/scripts/verify-artifact-manifest-signature-urls.sh" "${RAW_VERIFY_ARGS[@]}"

echo "[rollout-check] OK: local signatures and live registry bytes verify"
