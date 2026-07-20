#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

out="${1:-runtime-evidence/fingerprint-lab}"
profile="${2:-rustls}"
shift $(( $# >= 1 ? 1 : 0 ))
shift $(( $# >= 1 ? 1 : 0 ))

case "$profile" in
  rustls|browser|all) ;;
  *)
    echo "profile must be rustls, browser, or all" >&2
    exit 2
    ;;
esac

features=()
if [[ "$profile" != "rustls" && "${MAVERICK_FINGERPRINT_BROWSER_TLS:-0}" == "1" ]]; then
  features=(--features browser-tls)
fi

"$cargo_bin" run -q -p maverick-tests "${features[@]}" --bin fingerprint-lab -- \
  --output-dir "$out" \
  --profile "$profile" \
  "$@"
