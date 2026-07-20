#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out="${1:-docs/BENCHMARK_DASHBOARD.md}"
shift || true

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

./scripts/benchmark-baseline.sh "$@" >"$tmp"

{
  echo "# Maverick Benchmark Dashboard"
  echo
  echo "Status: loopback-only engineering dashboard."
  echo
  echo "- Commit: \`$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\`"
  echo "- Generated UTC: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
  echo "- Scope: direct TCP echo vs Maverick SOCKS relay on localhost."
  echo
  echo "## Latest Run"
  echo
  echo '```text'
  cat "$tmp"
  echo '```'
  echo
  echo "## Notes"
  echo
  echo "- Results are local diagnostics, not production throughput claims."
  echo "- Keep historical generated files or release attachments for trend review."
} >"$out"

echo "wrote $out"
