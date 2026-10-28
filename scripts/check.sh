#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ -n "${CARGO_BIN:-}" ]]; then
  cargo_directory="$(dirname "$CARGO_BIN")"
  export PATH="$cargo_directory:$PATH"
elif ! command -v cargo >/dev/null 2>&1 && [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

case "${1:-all}" in
  product) exec ./scripts/local-harness.sh ;;
  rustls) exec ./scripts/check-rustls.sh ;;
  h3) exec ./scripts/check-h3.sh ;;
  quiche-candidate) exec ./scripts/check-quiche-candidate.sh ;;
  all)
    for check in product rustls h3 quiche-candidate; do
      echo "==> $check"
      ./scripts/check.sh "$check"
    done
    ;;
  *)
    echo "usage: $0 [all|product|rustls|h3|quiche-candidate]" >&2
    exit 2
    ;;
esac
