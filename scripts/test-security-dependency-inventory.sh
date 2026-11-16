#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "security inventory focused tests failed" >&2; exit 1; }

# Exercise the real gate while replacing unrelated Cargo work and the search
# outcome. No dependency download, source mutation or temporary files are needed.
for search_status in 0 1 2 127; do
  result=0
  output="$(
    CARGO_BIN=true SEARCH_TEST_STATUS="$search_status" bash -c '
      rg() { return "$SEARCH_TEST_STATUS"; }
      export -f rg
      exec "$1"
    ' _ "$repo_root/scripts/security-dependency-inventory.sh" 2>&1
  )" || result=$?
  case "$search_status" in
    1)
      [[ "$result" -eq 0 && "$output" == *"security dependency inventory OK" ]] || fail
      ;;
    0)
      [[ "$result" -ne 0 && "$output" == *"first-party unsafe Rust construct found"* ]] || fail
      [[ "$output" != *"security dependency inventory OK"* ]] || fail
      ;;
    *)
      [[ "$result" -ne 0 && "$output" == *"unable to complete first-party unsafe-code inventory"* ]] || fail
      [[ "$output" != *"security dependency inventory OK"* ]] || fail
      ;;
  esac
done

echo "security inventory focused tests OK (clean, match, search error, missing command)"
