#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

"$cargo_bin" clippy -p maverick-client --features browser-tls --all-targets -- -D warnings
"$cargo_bin" test -p maverick-core --features browser-tls
"$cargo_bin" test -p maverick-client --features browser-tls
"$cargo_bin" test -p maverick-tests --features browser-tls --test tcp_relay \
  browser_tls_h2_pool_uses_channel_binding
"$cargo_bin" build -p maverick-cli --features browser-tls
"$cargo_bin" build -p maverick-sdk --features browser-tls

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
MAVERICK_FINGERPRINT_BROWSER_TLS=1 \
  ./scripts/fingerprint-lab.sh "$tmpdir/fingerprint" browser --samples 3 >/dev/null
grep -Fq '"name": "browser_mimic"' "$tmpdir/fingerprint/fingerprint-summary.json"
grep -Fq '"tls_channel_binding_available": true' \
  "$tmpdir/fingerprint/fingerprint-summary.json"
python3 scripts/check-browser-tls-baseline.py \
  --current-summary "$tmpdir/fingerprint/fingerprint-summary.json"

echo "browser TLS harness OK"
