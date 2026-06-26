#!/usr/bin/env bash
# publish-claw-artifact.sh — Compress and publish a claw golden rootfs artifact.
#
# Runs on the builder machine (canary/builder host). Publishes to GitHub Releases and
# commits latest.json to the repo so the runtime can discover it via
# raw.githubusercontent.com.
#
# Prerequisites:
#   - Golden image already built: sudo imagebuilder rebuild --force <claw>
#   - gh CLI authenticated (gh auth login)
#   - zstd installed
#   - imagebuilder binary available (compiled from this repo)
#
# Usage:
#   ./scripts/publish-claw-artifact.sh <claw> [--dry-run]
#
# Environment variables:
#   THEYOS_DIR            Repo root (auto-detected)
#   HOME                  Builder home directory
#   THEYOS_ARTIFACT_KEY_ID
#                         Signing key id (default: artifact-prod-p256-2026q2)
#   THEYOS_ARTIFACT_SIGNER_CMD
#                         External signer command for imagebuilder sign-manifest
#                         (default: python3 scripts/sign_artifact_manifest_p256.py)
#   THEYOS_ARTIFACT_SIGNING_KEY
#                         Private key path consumed by the default signer
#
set -euo pipefail

REPO="soyeht/theyos"

json_string_field() {
    local field="$1"
    local file="$2"
    sed -n -E \
        "s/^[[:space:]]*\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"[[:space:]]*,?[[:space:]]*$/\\1/p" \
        "$file" | head -1
}

manifest_version_for_claw() {
    local claw="$1"
    local manifest_file="$2"
    awk -v claw="$claw" '
        $0 == "  " claw ":" { in_block=1; next }
        in_block && /^  [^[:space:]][^:]*:/ { exit }
        in_block && /^[[:space:]]+version:/ {
            value=$2
            gsub(/"/, "", value)
            print value
            exit
        }
    ' "$manifest_file"
}

# ── Args ─────────────────────────────────────────────────────────────────────

CLAW="${1:-}"
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --help|-h)
            sed -n '2,/^$/{ s/^# //; s/^#//; p }' "$0"
            exit 0
            ;;
    esac
done

if [ -z "$CLAW" ] || [ "$CLAW" = "--dry-run" ]; then
    echo "Usage: $0 <claw> [--dry-run]"
    echo "  Example: $0 hermes-agent"
    exit 1
fi

# ── Config ───────────────────────────────────────────────────────────────────

THEYOS_DIR="${THEYOS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
HOME="${HOME:-/root}"
ASSETS_DIR="$HOME/firecracker/assets"
ARCH="x86_64-linux"
ARTIFACT_KEY_ID="${THEYOS_ARTIFACT_KEY_ID:-artifact-prod-p256-2026q2}"
DEFAULT_ARTIFACT_SIGNER="$THEYOS_DIR/scripts/sign_artifact_manifest_p256.py"
DEFAULT_ARTIFACT_SIGNER_CMD="python3 \"$DEFAULT_ARTIFACT_SIGNER\""
ARTIFACT_SIGNER_CMD="${THEYOS_ARTIFACT_SIGNER_CMD:-$DEFAULT_ARTIFACT_SIGNER_CMD}"

# Resolve imagebuilder binary
IMAGEBUILDER=""
for candidate in \
    "$THEYOS_DIR/admin/rust/target/release/imagebuilder" \
    "$(command -v imagebuilder 2>/dev/null || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        IMAGEBUILDER="$candidate"
        break
    fi
done

if [ -z "$IMAGEBUILDER" ]; then
    echo "[error] imagebuilder binary not found"
    echo "  hint: cd $THEYOS_DIR/admin/rust && cargo build -p imagebuilder-rs --release"
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "[error] gh CLI not found"
    echo "  hint: nix-env -iA nixpkgs.gh && gh auth login"
    exit 1
fi

if ! command -v zstd >/dev/null 2>&1; then
    echo "[error] zstd not found"
    echo "  hint: nix-env -iA nixpkgs.zstd"
    exit 1
fi

if ! command -v e2fsck >/dev/null 2>&1 || ! command -v resize2fs >/dev/null 2>&1 || ! command -v dumpe2fs >/dev/null 2>&1; then
    echo "[error] e2fsck/resize2fs not found (needed for rootfs shrink)"
    echo "  hint: nix-env -iA nixpkgs.e2fsprogs"
    exit 1
fi

if ! command -v truncate >/dev/null 2>&1; then
    echo "[error] truncate not found (needed to trim the shrunk image file)"
    echo "  hint: coreutils should provide truncate on the builder"
    exit 1
fi

if [ -z "$ARTIFACT_SIGNER_CMD" ]; then
    echo "[error] artifact signer command is empty"
    exit 1
fi

if [ "$ARTIFACT_SIGNER_CMD" = "$DEFAULT_ARTIFACT_SIGNER_CMD" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[error] python3 not found (needed by the default artifact signer)"
        exit 1
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        echo "[error] openssl not found (needed by the default artifact signer)"
        exit 1
    fi

    if [ ! -f "$DEFAULT_ARTIFACT_SIGNER" ]; then
        echo "[error] default artifact signer is missing"
        echo "  path: $DEFAULT_ARTIFACT_SIGNER"
        exit 1
    fi

    if [ -z "${THEYOS_ARTIFACT_SIGNING_KEY:-}" ]; then
        echo "[error] THEYOS_ARTIFACT_SIGNING_KEY is required for the default signer"
        exit 1
    fi
fi

# ── Validate golden exists ───────────────────────────────────────────────────

GOLDEN_DIR="$ASSETS_DIR/goldens/$CLAW/current"
if [ ! -f "$GOLDEN_DIR/rootfs.ext4" ]; then
    echo "[error] No golden rootfs found at $GOLDEN_DIR/rootfs.ext4"
    echo "  hint: sudo $IMAGEBUILDER rebuild --force $CLAW"
    exit 1
fi

if [ ! -f "$GOLDEN_DIR/golden.meta.json" ]; then
    echo "[error] No golden.meta.json found at $GOLDEN_DIR/"
    echo "  hint: sudo $IMAGEBUILDER rebuild --force $CLAW"
    exit 1
fi

# Extract fields from golden.meta.json without jq/python3
FINGERPRINT="$(json_string_field fingerprint "$GOLDEN_DIR/golden.meta.json" || true)"
if [ -z "$FINGERPRINT" ]; then
    echo "[error] Failed to extract fingerprint from $GOLDEN_DIR/golden.meta.json"
    exit 1
fi

# Get version from claws/manifest.yml
VERSION="$(manifest_version_for_claw "$CLAW" "$THEYOS_DIR/claws/manifest.yml" || true)"
if [ -z "$VERSION" ]; then
    echo "[error] Failed to resolve version for $CLAW from claws/manifest.yml"
    exit 1
fi

RELEASE_TAG="artifact-${CLAW}-${VERSION}"
ASSET_NAME="${CLAW}-${ARCH}-rootfs.ext4.zst"
RELEASE_ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${ASSET_NAME}"

echo "============================================"
echo " Publish claw artifact: $CLAW"
echo "============================================"
echo ""
echo "  Golden:      $GOLDEN_DIR"
echo "  Fingerprint: $FINGERPRINT"
echo "  Version:     $VERSION"
echo "  Arch:        $ARCH"
echo "  Release tag: $RELEASE_TAG"
echo "  Asset name:  $ASSET_NAME"
echo "  Dry run:     $DRY_RUN"
echo "  Sign key id: $ARTIFACT_KEY_ID"
echo ""

# ── Step 1: Shrink rootfs copy ──────────────────────────────────────────────

WORK_DIR="$(mktemp -d /tmp/publish-artifact.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

ROOTFS_ORIG_SIZE=$(stat -c%s "$GOLDEN_DIR/rootfs.ext4" 2>/dev/null || stat -f%z "$GOLDEN_DIR/rootfs.ext4")
SHRUNK_ROOTFS="$WORK_DIR/rootfs-shrink.ext4"

echo "[1/7] Shrinking rootfs copy ($((ROOTFS_ORIG_SIZE / 1024 / 1024)) MB original)..."
cp "$GOLDEN_DIR/rootfs.ext4" "$SHRUNK_ROOTFS"

e2fsck -fy "$SHRUNK_ROOTFS" >/dev/null 2>&1 || true
resize2fs -M "$SHRUNK_ROOTFS" 2>/dev/null

# Truncate the image file to the ext4 filesystem's real size so we do not
# upload trailing zero blocks left behind by the original 10GiB geometry.
FS_SIZE_BYTES="$(
    dumpe2fs -h "$SHRUNK_ROOTFS" 2>/dev/null | awk '
        /^Block count:/ { count=$3 }
        /^Block size:/  { size=$3 }
        END {
            if (count == "" || size == "") exit 1
            printf "%.0f", count * size
        }
    '
)"
if [ -z "$FS_SIZE_BYTES" ]; then
    echo "[error] Failed to determine shrunk filesystem size with dumpe2fs"
    exit 1
fi
truncate -s "$FS_SIZE_BYTES" "$SHRUNK_ROOTFS"

SHRUNK_SIZE=$(stat -c%s "$SHRUNK_ROOTFS" 2>/dev/null || stat -f%z "$SHRUNK_ROOTFS")
echo "  Shrunk: $((SHRUNK_SIZE / 1024 / 1024)) MB (from $((ROOTFS_ORIG_SIZE / 1024 / 1024)) MB)"

# ── Step 2: Compress ────────────────────────────────────────────────────────

ZST_FILE="$WORK_DIR/$ASSET_NAME"

echo "[2/7] Compressing shrunk rootfs..."
zstd -19 -T0 --no-progress "$SHRUNK_ROOTFS" -o "$ZST_FILE"
rm -f "$SHRUNK_ROOTFS"

ZST_SIZE=$(stat -c%s "$ZST_FILE" 2>/dev/null || stat -f%z "$ZST_FILE")
RATIO=$((ROOTFS_ORIG_SIZE / ZST_SIZE))
echo "  Compressed: $((ZST_SIZE / 1024 / 1024)) MB (${RATIO}x from original)"

# ── Guard: 2GB GitHub Releases limit ────────────────────────────────────────

MAX_ASSET_SIZE=2147483648  # 2 GiB
if [ "$ZST_SIZE" -ge "$MAX_ASSET_SIZE" ]; then
    echo ""
    echo "[error] Compressed artifact ($((ZST_SIZE / 1024 / 1024)) MB) exceeds GitHub Releases 2GB limit"
    echo ""
    echo "  Plan B options:"
    echo "    - Upload to R2 instead (ArtifactManifest.url accepts any HTTPS URL)"
    echo "    - Strip devDependencies/cache before golden build"
    echo "    - Use --artifact-url with imagebuilder publish-manifest to point to R2"
    echo ""
    exit 1
fi

# ── Step 3: Generate manifest ────────────────────────────────────────────────

MANIFEST_FILE="$WORK_DIR/latest.json"
SIGNATURE_FILE="$WORK_DIR/latest.json.sig.json"

echo "[3/7] Generating manifest..."
"$IMAGEBUILDER" publish-manifest "$CLAW" \
    --zst-file "$ZST_FILE" \
    --artifact-url "$RELEASE_ASSET_URL" \
    --channel stable \
    -o "$MANIFEST_FILE"

# ── Step 4: Validate ─────────────────────────────────────────────────────────

echo "[4/7] Validating manifest..."
# Validate required fields exist
VALID=true
for field in claw version arch fingerprint sha256 url base_rootfs_sha256 installer_plan_sha256 kernel_sha256; do
    if [ -z "$(json_string_field "$field" "$MANIFEST_FILE" || true)" ]; then
        echo "  FAIL: missing field $field" >&2
        VALID=false
    fi
done
# Validate sha256 is 64 hex chars
MANIFEST_SHA="$(json_string_field sha256 "$MANIFEST_FILE" || true)"
if [ "${#MANIFEST_SHA}" -ne 64 ]; then
    echo "  FAIL: sha256 wrong length: ${#MANIFEST_SHA}" >&2
    VALID=false
fi
if [ "$VALID" = false ]; then
    echo "[error] Manifest validation failed"
    exit 1
fi
echo "  OK: manifest valid"
echo "  URL in manifest: $RELEASE_ASSET_URL"

# -- Step 5: Sign and verify manifest -----------------------------------------

echo "[5/7] Signing and verifying manifest..."
"$IMAGEBUILDER" sign-manifest "$MANIFEST_FILE" \
    --key-id "$ARTIFACT_KEY_ID" \
    --signer-cmd "$ARTIFACT_SIGNER_CMD" \
    --output "$SIGNATURE_FILE"
"$IMAGEBUILDER" verify-manifest-signature "$MANIFEST_FILE" \
    --signature "$SIGNATURE_FILE"
echo "  OK: manifest signature verified"

# -- Step 6: Upload to GitHub Release -----------------------------------------

echo "[6/7] Publishing to GitHub Release ($RELEASE_TAG)..."

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "  [dry-run] Would create release: $RELEASE_TAG"
    echo "  [dry-run] Would upload asset:   $ASSET_NAME ($((ZST_SIZE / 1024 / 1024)) MB)"
    echo "  [dry-run] Would commit:         artifacts/$CLAW/$ARCH/latest.json"
    echo "  [dry-run] Would commit:         artifacts/$CLAW/$ARCH/latest.json.sig.json"
    echo ""
    echo "  [dry-run] Manifest content:"
    cat "$MANIFEST_FILE"
    echo ""
    echo "  [dry-run] Signature content:"
    cat "$SIGNATURE_FILE"
    echo ""
    echo "  [dry-run] Done. Re-run without --dry-run to publish."
    exit 0
fi

# Create release (or reuse existing)
if gh release view "$RELEASE_TAG" --repo "$REPO" >/dev/null 2>&1; then
    echo "  Release $RELEASE_TAG already exists, uploading asset..."
    gh release upload "$RELEASE_TAG" "$ZST_FILE" --repo "$REPO" --clobber
else
    echo "  Creating release $RELEASE_TAG..."
        gh release create "$RELEASE_TAG" "$ZST_FILE" \
        --repo "$REPO" \
        --title "$CLAW $VERSION ($ARCH)" \
        --notes "Pre-built golden rootfs for $CLAW $VERSION ($ARCH).

Fingerprint: \`$FINGERPRINT\`
SHA-256 (zst): \`$MANIFEST_SHA\`
Size: $((ZST_SIZE / 1024 / 1024)) MB"
fi

# -- Step 7: Commit latest.json to repo ---------------------------------------

echo "[7/7] Committing latest.json to repo..."

ARTIFACTS_DIR="$THEYOS_DIR/artifacts/$CLAW/$ARCH"
mkdir -p "$ARTIFACTS_DIR"
cp "$MANIFEST_FILE" "$ARTIFACTS_DIR/latest.json"
cp "$SIGNATURE_FILE" "$ARTIFACTS_DIR/latest.json.sig.json"

cd "$THEYOS_DIR"
git add "artifacts/$CLAW/$ARCH/latest.json" "artifacts/$CLAW/$ARCH/latest.json.sig.json"

if git diff --cached --quiet; then
    echo "  latest.json and latest.json.sig.json unchanged, skipping commit"
else
    git commit -m "Update $CLAW $ARCH artifact manifest to $VERSION

Fingerprint: $FINGERPRINT
Release: $RELEASE_TAG"
    echo "  Committed. Push with: git push"
fi

echo ""
echo "============================================"
echo " Published: $CLAW $VERSION ($ARCH)"
echo "============================================"
echo ""
echo "  Release:     https://github.com/${REPO}/releases/tag/${RELEASE_TAG}"
echo "  Asset URL:   $RELEASE_ASSET_URL"
echo "  Fingerprint: $FINGERPRINT"
echo "  Size:        $((ZST_SIZE / 1024 / 1024)) MB"
echo ""
echo "  Registry URL for your prod server .env:"
echo "    THEYOS_ARTIFACT_REGISTRY_URL=https://raw.githubusercontent.com/${REPO}/main/artifacts"
echo ""
echo "  Verify manifest:"
echo "    curl -sL https://raw.githubusercontent.com/${REPO}/main/artifacts/$CLAW/$ARCH/latest.json | python3 -m json.tool"
echo "    curl -fsSL https://raw.githubusercontent.com/${REPO}/main/artifacts/$CLAW/$ARCH/latest.json.sig.json >/dev/null"
echo ""
echo "  Next steps:"
echo "    1. git push (to make latest.json available via raw.githubusercontent.com)"
echo "    2. Set THEYOS_ARTIFACT_REGISTRY_URL on <prod-host>"
echo "    3. Test: curl the manifest URL from your prod server"
echo ""
