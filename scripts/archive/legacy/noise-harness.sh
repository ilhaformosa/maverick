#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${PYTHON:-python3}"

cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

"$cargo_bin" test -p maverick-core --features noise-experimental noise
"$python_bin" scripts/test-noise-runtime-approval.py
"$python_bin" scripts/check-noise-runtime-approval.py docs/history/manifests/noise-runtime-approval.json

echo "noise harness OK"
