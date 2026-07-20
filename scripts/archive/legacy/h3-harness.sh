#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

"$cargo_bin" test --workspace --features h3
