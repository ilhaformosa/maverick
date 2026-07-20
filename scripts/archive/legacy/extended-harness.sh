#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "==> default local harness"
./scripts/local-harness.sh

echo "==> h3 feature harness"
./scripts/h3-harness.sh

echo "==> ech feature harness"
./scripts/ech-harness.sh

echo "==> criterion parser smoke"
./scripts/criterion-regression.sh smoke

echo "==> shape lab smoke"
./scripts/shape-lab.sh "$tmpdir/shape-lab-smoke.md" 256 >/dev/null
rg -q "loopback-only engineering diagnostics" "$tmpdir/shape-lab-smoke.md"
rg -q "does not prove traffic-analysis resistance" "$tmpdir/shape-lab-smoke.md"

echo "==> benchmark smoke"
bench_profile="${MAVERICK_EXTENDED_BENCH_PROFILE:-dev}"
bench_concurrency="${MAVERICK_EXTENDED_BENCH_CONCURRENCY:-1}"
bench_bytes="${MAVERICK_EXTENDED_BENCH_BYTES:-1024}"
MAVERICK_BENCH_PROFILE="$bench_profile" \
  MAVERICK_BENCH_CONCURRENCY="$bench_concurrency" \
  ./scripts/benchmark-baseline.sh "$bench_bytes" >"$tmpdir/benchmark-smoke.txt"
rg -q "Maverick loopback benchmark baseline" "$tmpdir/benchmark-smoke.txt"
rg -q "payload_bytes=$bench_bytes" "$tmpdir/benchmark-smoke.txt"

echo "extended harness OK"
