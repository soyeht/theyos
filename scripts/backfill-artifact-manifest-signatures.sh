#!/usr/bin/env bash
# backfill-artifact-manifest-signatures.sh - sign existing latest.json manifests.
#
# This is the P0.1 publish-first helper for the current artifact registry:
# it signs already-committed artifacts/<claw>/<arch>/latest.json files and
# verifies each generated latest.json.sig.json against the production public pin.
# It does not rebuild rootfs images, upload release assets, commit, or push.
#
# Usage:
#   ./scripts/backfill-artifact-manifest-signatures.sh [--dry-run] [--check-only] [--stage] [--arch x86_64-linux] [claw ...]
#
# Environment:
#   THEYOS_DIR                  Repo root (auto-detected)
#   THEYOS_ARTIFACT_KEY_ID      Signing key id (default: artifact-prod-p256-2026q2)
#   THEYOS_ARTIFACT_SIGNER_CMD  External signer command
#   THEYOS_ARTIFACT_SIGNING_KEY Private key path consumed by the default signer
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
DRY_RUN=false
CHECK_ONLY=false
STAGE=false
CLAWS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        --stage)
            STAGE=true
            shift
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

ARTIFACT_KEY_ID="${THEYOS_ARTIFACT_KEY_ID:-artifact-prod-p256-2026q2}"
DEFAULT_ARTIFACT_SIGNER="$THEYOS_DIR/scripts/sign_artifact_manifest_p256.py"
DEFAULT_ARTIFACT_SIGNER_CMD="python3 \"$DEFAULT_ARTIFACT_SIGNER\""
ARTIFACT_SIGNER_CMD="${THEYOS_ARTIFACT_SIGNER_CMD:-$DEFAULT_ARTIFACT_SIGNER_CMD}"

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

signer_is_default() {
    [ "$ARTIFACT_SIGNER_CMD" = "$DEFAULT_ARTIFACT_SIGNER_CMD" ]
}

require_signer_ready() {
    if [ "$CHECK_ONLY" = true ] || [ "$DRY_RUN" = true ]; then
        return
    fi
    if signer_is_default; then
        if [ -z "${THEYOS_ARTIFACT_SIGNING_KEY:-}" ]; then
            echo "[error] THEYOS_ARTIFACT_SIGNING_KEY is required for the default signer" >&2
            exit 2
        fi
        if [ ! -r "$THEYOS_ARTIFACT_SIGNING_KEY" ]; then
            echo "[error] signing key file is not readable" >&2
            exit 2
        fi
    fi
}

manifest_for_claw() {
    printf '%s/artifacts/%s/%s/latest.json\n' "$THEYOS_DIR" "$1" "$ARCH"
}

signature_for_manifest() {
    printf '%s.sig.json\n' "$1"
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

require_signer_ready

TARGETS_FILE="$(mktemp)"
WRITTEN_FILE="$(mktemp)"
cleanup() {
    rm -f "$TARGETS_FILE" "$WRITTEN_FILE"
}
trap cleanup EXIT

discover_claws > "$TARGETS_FILE"
if [ ! -s "$TARGETS_FILE" ]; then
    echo "[error] no artifacts/*/$ARCH/latest.json manifests found" >&2
    exit 1
fi

echo "[backfill] repo: current checkout"
echo "[backfill] arch: $ARCH"
echo "[backfill] claws: $(tr '\n' ' ' < "$TARGETS_FILE" | sed 's/[[:space:]]*$//')"
if [ "$DRY_RUN" = true ]; then
    echo "[backfill] dry-run: no files will be written"
fi
if [ "$CHECK_ONLY" = true ]; then
    echo "[backfill] check-only: verifying existing signatures"
fi

written_count=0
missing=0
failed=0

while IFS= read -r claw; do
    manifest="$(manifest_for_claw "$claw")"
    signature="$(signature_for_manifest "$manifest")"
    rel_manifest="artifacts/$claw/$ARCH/latest.json"
    rel_signature="$rel_manifest.sig.json"

    if [ ! -f "$manifest" ]; then
        echo "[error] missing manifest: $rel_manifest" >&2
        failed=1
        continue
    fi

    if [ "$DRY_RUN" = true ]; then
        if [ -f "$signature" ]; then
            echo "  would verify: $rel_signature"
        else
            echo "  would sign:   $rel_manifest -> $rel_signature"
            missing=$((missing + 1))
        fi
        continue
    fi

    if [ "$CHECK_ONLY" = true ]; then
        if [ ! -f "$signature" ]; then
            echo "[error] missing signature: $rel_signature" >&2
            missing=$((missing + 1))
            failed=1
            continue
        fi
        (cd "$THEYOS_DIR" && run_imagebuilder verify-manifest-signature "$rel_manifest" --signature "$rel_signature") || failed=1
        continue
    fi

    echo "[backfill] signing $rel_manifest"
    tmp_signature="$signature.tmp.$$"
    rel_tmp_signature="$rel_signature.tmp.$$"
    rm -f "$tmp_signature"
    if (cd "$THEYOS_DIR" && \
        run_imagebuilder sign-manifest "$rel_manifest" \
            --key-id "$ARTIFACT_KEY_ID" \
            --signer-cmd "$ARTIFACT_SIGNER_CMD" \
            --output "$rel_tmp_signature" && \
        run_imagebuilder verify-manifest-signature "$rel_manifest" --signature "$rel_tmp_signature"); then
        mv "$tmp_signature" "$signature"
    else
        rm -f "$tmp_signature"
        failed=1
        continue
    fi
    printf '%s\n' "$rel_signature" >> "$WRITTEN_FILE"
    written_count=$((written_count + 1))
done < "$TARGETS_FILE"

if [ "$DRY_RUN" = true ]; then
    echo "[backfill] dry-run complete; missing signatures: $missing"
    exit 0
fi

if [ "$failed" -ne 0 ]; then
    echo "[error] backfill did not complete cleanly" >&2
    exit 1
fi

if [ "$CHECK_ONLY" = true ]; then
    echo "[backfill] OK: all selected signatures verify"
    exit 0
fi

if [ "$written_count" -gt 0 ]; then
    if [ "$STAGE" = true ]; then
        while IFS= read -r rel_path; do
            git -C "$THEYOS_DIR" add "$rel_path"
        done < "$WRITTEN_FILE"
        echo "[backfill] staged $written_count signature files"
        echo "[backfill] next: commit, push, pull a clean checkout, then run:"
        echo "[backfill]   ./scripts/check-artifact-signature-rollout.sh"
    else
        echo "[backfill] wrote $written_count signature files"
        echo "[backfill] next: git add $(tr '\n' ' ' < "$WRITTEN_FILE" | sed 's/[[:space:]]*$//')"
        echo "[backfill] after commit/push: run ./scripts/check-artifact-signature-rollout.sh"
    fi
fi

echo "[backfill] OK"
