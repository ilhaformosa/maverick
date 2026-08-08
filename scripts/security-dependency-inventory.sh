#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

case "$#" in
  0) offline=0 ;;
  1)
    if [[ "$1" == "--offline" ]]; then
      offline=1
    else
      echo "usage: security-dependency-inventory.sh [--offline]" >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: security-dependency-inventory.sh [--offline]" >&2
    exit 1
    ;;
esac

cargo_bin="${CARGO_BIN:-}"
if [[ -z "$cargo_bin" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    cargo_bin="$(command -v cargo)"
  elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    cargo_bin="${HOME}/.cargo/bin/cargo"
  else
    echo "cargo was not found" >&2
    exit 1
  fi
fi

require_cargo_subcommand() {
  local name="$1"
  if ! "$cargo_bin" "$name" --help >/dev/null 2>&1; then
    echo "missing cargo-$name; install it before release security inventory" >&2
    exit 1
  fi
}

require_cargo_subcommand audit
require_cargo_subcommand deny

if [[ "$offline" -eq 1 ]]; then
  echo "==> cached dependency advisories: cargo audit (offline)"
  CARGO_NET_OFFLINE=true "$cargo_bin" audit --no-fetch --no-yanked

  echo "==> cached dependency policy: cargo deny (locked and offline)"
  CARGO_NET_OFFLINE=true "$cargo_bin" deny --offline --locked \
    check -D warnings advisories bans licenses sources
else
  echo "==> dependency advisories: cargo audit"
  "$cargo_bin" audit

  echo "==> dependency policy: cargo deny check advisories bans licenses sources"
  "$cargo_bin" deny check -D warnings advisories bans licenses sources
fi

echo "==> first-party unsafe-code inventory"
unsafe_pattern='(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn|impl|trait|extern)'
unsafe_pattern+='|#\[[[:space:]]*(allow|warn|deny)[[:space:]]*\([[:space:]]*unsafe_code[[:space:]]*\)'
unsafe_inventory_status=0
rg -n "$unsafe_pattern" crates fuzz conformance scripts -g '*.rs' \
  -g '!crates/maverick-tests/src/bin/maverick-tun-phase2/linux_tun.rs' \
  2>/dev/null || unsafe_inventory_status=$?
case "$unsafe_inventory_status" in
  0)
    echo "first-party unsafe Rust construct found; triage before release" >&2
    exit 1
    ;;
  1) ;;
  *)
    echo "unable to complete first-party unsafe-code inventory" >&2
    exit 1
    ;;
esac

if [[ "$offline" -eq 1 ]]; then
  echo "cached security dependency inventory OK; online freshness was not checked"
else
  echo "security dependency inventory OK"
fi
