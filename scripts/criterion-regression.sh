#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

mode="${1:-smoke}"
baseline="${MAVERICK_CRITERION_BASELINE:-maverick-local}"
sample_size="${MAVERICK_CRITERION_SAMPLE_SIZE:-10}"
measurement_time="${MAVERICK_CRITERION_MEASUREMENT_TIME:-1}"
warm_up_time="${MAVERICK_CRITERION_WARM_UP_TIME:-1}"

bench_args=(
  -p maverick-core
  --bench parser_regression
)

case "$mode" in
  smoke)
    "$cargo_bin" bench "${bench_args[@]}" --no-run
    ;;
  baseline)
    "$cargo_bin" bench "${bench_args[@]}" -- \
      --sample-size "$sample_size" \
      --measurement-time "$measurement_time" \
      --warm-up-time "$warm_up_time" \
      --save-baseline "$baseline"
    ;;
  compare)
    "$cargo_bin" bench "${bench_args[@]}" -- \
      --sample-size "$sample_size" \
      --measurement-time "$measurement_time" \
      --warm-up-time "$warm_up_time" \
      --baseline "$baseline"
    ;;
  *)
    echo "usage: $0 [smoke|baseline|compare]" >&2
    exit 2
    ;;
esac
