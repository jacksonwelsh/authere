#!/usr/bin/env bash
set -euo pipefail

# Called by the webhook handler when a new release is published.
# Downloads the binary from the GitHub release and restarts the service.

REPO="jacksonwelsh/authere"
INSTALL_DIR="/opt/authere"
BINARY_NAME="authere_server"
LOG_TAG="authere-deploy"

log() { logger -t "$LOG_TAG" "$@"; echo "[$(date -Iseconds)] $*"; }

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

deploy() {
  log "Starting deploy"

  log "Resolving asset URL via GitHub API"
  local release_json asset_url
  if ! release_json=$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      --retry 3 --retry-delay 5 \
      "https://api.github.com/repos/${REPO}/releases/tags/latest"); then
    log "ERROR: Failed to fetch release metadata"
    return 1
  fi

  if ! asset_url=$(printf '%s' "$release_json" | extract_asset_url "$BINARY_NAME"); then
    log "ERROR: Could not find asset ${BINARY_NAME} in latest release"
    return 1
  fi

  log "Downloading binary from ${asset_url}"
  local tmp_bin
  tmp_bin=$(mktemp "${INSTALL_DIR}/${BINARY_NAME}.XXXXXX")
  trap 'rm -f "$tmp_bin"' EXIT

  if ! curl -fSL --retry 3 --retry-delay 5 \
      -H "Accept: application/octet-stream" \
      -o "$tmp_bin" "$asset_url"; then
    log "ERROR: Failed to download binary"
    return 1
  fi

  chmod +x "$tmp_bin"

  if ! file "$tmp_bin" | grep -q "ELF"; then
    log "ERROR: Downloaded file is not a valid ELF binary"
    return 1
  fi

  mv "$tmp_bin" "${INSTALL_DIR}/${BINARY_NAME}"
  trap - EXIT

  log "Binary updated, restarting service"
  sudo /usr/bin/systemctl restart authere

  log "Deploy complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  deploy
fi
