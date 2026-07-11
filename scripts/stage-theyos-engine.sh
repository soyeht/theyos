#!/usr/bin/env bash
# Canonical packaging boundary: the server-rs server binary is distributed
# under the product name theyos-engine.
set -euo pipefail

SOURCE_DIR="${1:?usage: $0 SOURCE_RELEASE_DIR DESTINATION}"
DESTINATION="${2:?usage: $0 SOURCE_RELEASE_DIR DESTINATION}"
SOURCE="${SOURCE_DIR}/server"

if [[ ! -f "${SOURCE}" || -L "${SOURCE}" || ! -x "${SOURCE}" ]]; then
  echo "error: server-rs production binary is missing or not executable: ${SOURCE}" >&2
  exit 1
fi

mkdir -p "$(dirname "${DESTINATION}")"
install -m 0755 "${SOURCE}" "${DESTINATION}"
if ! cmp -s "${SOURCE}" "${DESTINATION}"; then
  echo "error: staged theyos-engine differs from the server-rs production binary" >&2
  exit 1
fi

echo "Staged server-rs production binary as theyos-engine: ${DESTINATION}"
