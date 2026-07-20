#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi
python_bin="${PYTHON_BIN:-python3}"

echo "==> GUI runtime smoke: loopback lifecycle"
"$cargo_bin" test -p maverick-sdk gui_client_runtime -- --nocapture

echo "==> GUI runtime smoke: profile metadata and secret-store contract"
"$cargo_bin" test -p maverick-sdk profile -- --nocapture

echo "==> GUI runtime smoke: redacted diagnostics and read-only TUN state"
"$cargo_bin" test -p maverick-core diagnostics::tests::gui -- --nocapture

echo "==> GUI runtime smoke: blocker manifest"
"$python_bin" scripts/test-gui-runtime-blockers.py
"$python_bin" scripts/check-gui-runtime-blockers.py docs/history/manifests/gui-runtime-blockers.json

echo "GUI runtime smoke OK"
