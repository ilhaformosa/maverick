#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${CARGO_BIN:-cargo}"

tool_matches() {
  local actual
  actual="$("$cargo_bin" "$1" --version 2>/dev/null)" || return 1
  [[ "$actual" == "$2" ]]
}

install_pinned_tool() {
  local command="$1"
  local version="$2"
  local expected="$3 $version"
  if tool_matches "$command" "$expected"; then
    printf 'cargo-%s %s is already available\n' "$command" "$version"
    return
  fi

  # The binary-only cache need not contain Cargo's installation metadata.
  # Force replacement only after a missing/mismatched tool was observed.
  "$cargo_bin" install "cargo-$command" --version "$version" --locked --force
  if ! tool_matches "$command" "$expected"; then
    printf 'cargo-%s did not report its pinned version after installation\n' "$command" >&2
    return 1
  fi
}

# The workflow hashes this script, binding the cache to these exact pins.
install_pinned_tool audit 0.22.2 cargo-audit
install_pinned_tool deny 0.20.2 cargo-deny
install_pinned_tool cyclonedx 0.5.9 cargo-cyclonedx-cyclonedx
