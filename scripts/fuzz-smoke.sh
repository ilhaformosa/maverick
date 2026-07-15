#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

python_bin="${PYTHON_BIN:-python3}"
"$python_bin" fuzz/sync-corpus.py

"$cargo_bin" check --manifest-path fuzz/Cargo.toml --bins

if [[ "${MAVERICK_RUN_CARGO_FUZZ:-0}" == "1" ]]; then
  if [[ -n "${CARGO_FUZZ_BIN:-}" ]]; then
    cargo_fuzz_cmd=("$CARGO_FUZZ_BIN")
  elif "$cargo_bin" fuzz --version >/dev/null 2>&1; then
    cargo_fuzz_cmd=("$cargo_bin" "fuzz")
  elif command -v cargo-fuzz >/dev/null 2>&1; then
    cargo_fuzz_cmd=("cargo-fuzz")
  else
    echo "cargo-fuzz not found; install cargo-fuzz or unset MAVERICK_RUN_CARGO_FUZZ" >&2
    exit 1
  fi

  fuzz_runs="${MAVERICK_FUZZ_RUNS:-128}"
  (
    cd fuzz
    "${cargo_fuzz_cmd[@]}" run frame_decode -- -runs="$fuzz_runs"
    "${cargo_fuzz_cmd[@]}" run auth_decode -- -runs="$fuzz_runs"
  )
fi

echo "fuzz smoke OK"
