#!/usr/bin/env bash
set -euo pipefail

# Called by the webhook handler when a new release is published.
# Downloads the binary from the GitHub release and restarts the service.

REPO="jacksonwelsh/authere"
INSTALL_DIR="/opt/authere"
BINARY_NAME="authere_server"
LOG_TAG="authere-deploy"

log() { logger -t "$LOG_TAG" "$@"; echo "[$(date -Iseconds)] $*"; }

log "Starting deploy"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/latest/${BINARY_NAME}"

log "Downloading binary from ${DOWNLOAD_URL}"
TMP_BIN=$(mktemp "${INSTALL_DIR}/${BINARY_NAME}.XXXXXX")
trap 'rm -f "$TMP_BIN"' EXIT

if ! curl -fSL --retry 3 --retry-delay 5 -o "$TMP_BIN" "$DOWNLOAD_URL"; then
  log "ERROR: Failed to download binary"
  exit 1
fi

chmod +x "$TMP_BIN"

# Verify it's a real binary
if ! file "$TMP_BIN" | grep -q "ELF"; then
  log "ERROR: Downloaded file is not a valid ELF binary"
  exit 1
fi

# Atomic swap
mv "$TMP_BIN" "${INSTALL_DIR}/${BINARY_NAME}"
trap - EXIT

log "Binary updated, restarting service"
sudo /usr/bin/systemctl restart authere

log "Deploy complete"
