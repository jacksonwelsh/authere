#!/usr/bin/env bash
set -euo pipefail

# Called by the webhook handler when a new release is published.
# Downloads the binary from the GitHub release and restarts the service.

REPO="jacksonwelsh/authere"
INSTALL_DIR="/opt/authere"
BINARY_NAME="authere_server"
LOG_TAG="authere-deploy"

log() { logger -t "$LOG_TAG" "$@"; }

# Read a GitHub release JSON payload from stdin and print the per-asset API
# URL for the asset with the given name. The API URL contains a unique
# numeric asset ID, so unlike /releases/download/<tag>/<name> it changes
# every time a release is recreated — bypassing GitHub's CDN cache for
# reused tag names like "latest".
extract_asset_url() {
  local asset_name="$1"
  python3 -c '
import json, sys
data = json.load(sys.stdin)
name = sys.argv[1]
for asset in data.get("assets", []):
    if asset.get("name") == name:
        print(asset["url"])
        sys.exit(0)
sys.exit(f"asset not found: {name}")
' "$asset_name"
}

# Check that a file begins with the ELF magic bytes. Avoids depending on
# the `file` command, which isn't in the minimal Debian LXC.
is_elf() {
  python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    sys.exit(0 if f.read(4) == b"\x7fELF" else 1)
' "$1"
}

deploy() {
  log "Starting deploy"

  local release_json asset_url
  if ! release_json=$(curl -fsSL \
      --connect-timeout 30 --max-time 60 \
      --retry 3 --retry-delay 5 \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/${REPO}/releases/tags/latest"); then
    log "ERROR: Failed to fetch release metadata"
    return 1
  fi

  if ! asset_url=$(printf '%s' "$release_json" | extract_asset_url "$BINARY_NAME"); then
    log "ERROR: Could not find asset ${BINARY_NAME} in latest release"
    return 1
  fi

  local tmp_bin
  tmp_bin=$(mktemp "${INSTALL_DIR}/${BINARY_NAME}.XXXXXX")
  trap 'rm -f "$tmp_bin"' EXIT

  if ! curl -fsSL \
      --connect-timeout 30 --max-time 300 \
      --retry 3 --retry-delay 5 \
      -H "Accept: application/octet-stream" \
      -o "$tmp_bin" "$asset_url"; then
    log "ERROR: Failed to download binary"
    return 1
  fi

  chmod +x "$tmp_bin"

  if ! is_elf "$tmp_bin"; then
    log "ERROR: Downloaded file is not a valid ELF binary"
    return 1
  fi

  mv "$tmp_bin" "${INSTALL_DIR}/${BINARY_NAME}"
  trap - EXIT

  sudo /usr/bin/systemctl restart authere

  log "Deploy complete ($(stat -c %s "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || echo "?") bytes)"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  # Route stdout/stderr to syslog so bash errors and curl stderr surface in
  # journalctl — webhook.py points both at /dev/null.
  exec > >(logger -t "$LOG_TAG" -p user.info) 2> >(logger -t "$LOG_TAG" -p user.err)
  deploy
fi
