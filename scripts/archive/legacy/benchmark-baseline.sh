#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

profile="${MAVERICK_BENCH_PROFILE:-release}"
cargo_cmd=("$cargo_bin" run -q)
case "$profile" in
  release)
    cargo_cmd+=(--release)
    ;;
  dev|debug)
    profile="dev"
    ;;
  *)
    echo "MAVERICK_BENCH_PROFILE must be release or dev" >&2
    exit 2
    ;;
esac

if [[ "$#" -eq 0 ]]; then
  sizes=(65536 1048576 10485760)
else
  sizes=("$@")
fi
read -r -a concurrencies <<<"${MAVERICK_BENCH_CONCURRENCY:-1 4}"

echo "Maverick loopback benchmark baseline"
echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "cargo_profile: $profile"
echo "concurrency_set: ${concurrencies[*]}"
echo

for bytes in "${sizes[@]}"; do
  for concurrency in "${concurrencies[@]}"; do
    echo "==> payload_bytes=$bytes concurrency=$concurrency"
    "${cargo_cmd[@]}" -p maverick-cli -- bench-local --bytes "$bytes" --concurrency "$concurrency"
    echo
  done
done
