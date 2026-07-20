#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

out="${1:-docs/SHAPE_LAB_BASELINE.md}"
shift || true

if [[ "$#" -eq 0 ]]; then
  sizes=(256 1024 16384 65536)
else
  sizes=("$@")
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

scenarios=(
  "auto-unshaped|auto|false|false"
  "stable-shaped-gated|stable|true|true"
  "auto-shaped|auto|true|true"
)

{
  echo "# Maverick Shape Lab Baseline"
  echo
  echo "Status: loopback-only engineering diagnostics, not an anonymity claim."
  echo
  echo "- Commit: \`$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\`"
  echo "- Generated UTC: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
  echo "- Scope: direct TCP echo vs Maverick SOCKS relay on localhost across shaping scenarios."
  echo "- Network safety: loopback listeners and OS-assigned ephemeral ports only."
  echo "- Private mode is excluded from the default shape lab because it rejects"
  echo "  \`rustls_default\`, while \`browser_mimic\` requires the non-default"
  echo "  \`browser-tls\` feature."
  echo
  echo "## Summary"
  echo
  echo "| scenario | payload_bytes | mode | client_shaping | server_shaping | direct_tcp_roundtrip_ms | maverick_socks_roundtrip_ms | overhead_ratio |"
  echo "| --- | ---: | --- | --- | --- | ---: | ---: | ---: |"
} >"$out"

for bytes in "${sizes[@]}"; do
  for scenario in "${scenarios[@]}"; do
    IFS='|' read -r label mode client_shaping server_shaping <<<"$scenario"
    args=(run -q -p maverick-cli -- bench-local --bytes "$bytes" --mode "$mode")
    if [[ "$client_shaping" == "true" ]]; then
      args+=(--client-shaping)
    fi
    if [[ "$server_shaping" == "true" ]]; then
      args+=(--server-shaping)
    fi
    run="$("$cargo_bin" "${args[@]}")"
    printf '%s\n' "==> scenario=$label payload_bytes=$bytes" >>"$tmp"
    printf '%s\n\n' "$run" >>"$tmp"

    direct="$(printf '%s\n' "$run" | awk -F': ' '/direct_tcp_roundtrip_ms/ {print $2}')"
    proxied="$(printf '%s\n' "$run" | awk -F': ' '/maverick_socks_roundtrip_ms/ {print $2}')"
    overhead="$(printf '%s\n' "$run" | awk -F': ' '/overhead_ratio/ {print $2}')"
    echo "| $label | $bytes | $mode | $client_shaping | $server_shaping | $direct | $proxied | $overhead |" >>"$out"
  done
done

{
  echo
  echo "## Raw Trace"
  echo
  echo '```text'
  cat "$tmp"
  echo '```'
  echo
  echo "## Interpretation Rules"
  echo
  echo "- Compare reports by payload size and commit, not by a single run."
  echo "- Compare unshaped and shaped scenarios as coarse runtime diagnostics only."
  echo "- Treat private-mode shape as a separate browser-tls evidence task, not a"
  echo "  default CI smoke scenario."
  echo "- Treat large CI or laptop variance as a signal to rerun before drawing conclusions."
  echo "- This lab does not capture packets and does not prove traffic-analysis resistance."
} >>"$out"

echo "wrote $out"
