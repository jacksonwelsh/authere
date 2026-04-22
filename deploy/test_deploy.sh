#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/deploy.sh"

fail=0
pass=0

assert_eq() {
  if [[ "$1" == "$2" ]]; then
    echo "ok: $3"
    pass=$((pass + 1))
  else
    echo "FAIL: $3"
    echo "  expected: $2"
    echo "  got:      $1"
    fail=$((fail + 1))
  fi
}

FIXTURE='{
  "tag_name": "latest",
  "assets": [
    {"name": "authere_server", "url": "https://api.github.com/repos/jacksonwelsh/authere/releases/assets/12345"},
    {"name": "notes.txt",      "url": "https://api.github.com/repos/jacksonwelsh/authere/releases/assets/67890"}
  ]
}'

got=$(printf '%s' "$FIXTURE" | extract_asset_url "authere_server")
assert_eq "$got" \
  "https://api.github.com/repos/jacksonwelsh/authere/releases/assets/12345" \
  "extract_asset_url returns per-asset API URL for matching name"

got=$(printf '%s' "$FIXTURE" | extract_asset_url "notes.txt")
assert_eq "$got" \
  "https://api.github.com/repos/jacksonwelsh/authere/releases/assets/67890" \
  "extract_asset_url selects by asset name (not position)"

if printf '%s' "$FIXTURE" | extract_asset_url "nonexistent" >/dev/null 2>&1; then
  echo "FAIL: extract_asset_url should exit non-zero for missing asset"
  fail=$((fail + 1))
else
  echo "ok: extract_asset_url exits non-zero when asset name not present"
  pass=$((pass + 1))
fi

EMPTY='{"tag_name": "latest", "assets": []}'
if printf '%s' "$EMPTY" | extract_asset_url "authere_server" >/dev/null 2>&1; then
  echo "FAIL: extract_asset_url should exit non-zero when assets array is empty"
  fail=$((fail + 1))
else
  echo "ok: extract_asset_url exits non-zero on empty assets array"
  pass=$((pass + 1))
fi

echo ""
echo "${pass} passed, ${fail} failed"
exit "$fail"
