#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-longhaul-smoke.sh <server-ssh-host>

This script repeatedly runs scripts/public-tcp-smoke.sh and writes a local
runtime-evidence summary. It does not change local proxy, DNS, route, firewall,
VPN, or other network-service settings.

Required environment is inherited from scripts/public-tcp-smoke.sh.

Additional environment:
  MAVERICK_LONGHAUL_DURATION_SECS      Default 86400.
  MAVERICK_LONGHAUL_INTERVAL_SECS      Default 300.
  MAVERICK_LONGHAUL_EVIDENCE_DIR       Default runtime-evidence.
  MAVERICK_PUBLIC_SMOKE_CLIENT_HOST    Strongly recommended. Required unless
                                       MAVERICK_LONGHAUL_ALLOW_LOCAL_CLIENT=1.
EOF
}

server_host="${1:-${MAVERICK_PUBLIC_SMOKE_REMOTE_HOST:-}}"
duration_secs="${MAVERICK_LONGHAUL_DURATION_SECS:-86400}"
interval_secs="${MAVERICK_LONGHAUL_INTERVAL_SECS:-300}"
evidence_root="${MAVERICK_LONGHAUL_EVIDENCE_DIR:-runtime-evidence}"
allow_local_client="${MAVERICK_LONGHAUL_ALLOW_LOCAL_CLIENT:-0}"
client_host="${MAVERICK_PUBLIC_SMOKE_CLIENT_HOST:-}"

if [[ -z "$server_host" ]]; then
  usage
  exit 2
fi

case "$duration_secs:$interval_secs" in
  *[!0-9:]*)
    echo "duration and interval must be numeric seconds" >&2
    exit 2
    ;;
esac

if [[ -z "$client_host" && "$allow_local_client" != "1" ]]; then
  echo "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST is required for long-haul evidence" >&2
  echo "Set MAVERICK_LONGHAUL_ALLOW_LOCAL_CLIENT=1 only for an explicitly approved local-client run." >&2
  exit 2
fi

started="$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="$repo_root/$evidence_root/longhaul-$started"
mkdir -p "$evidence_dir/logs"

start_epoch="$(date +%s)"
end_epoch=$((start_epoch + duration_secs))
iteration=0
passed=0
failed=0

echo "==> long-haul smoke evidence: $evidence_dir"
echo "==> duration=${duration_secs}s interval=${interval_secs}s server=$server_host client=${client_host:-local-approved}"

while [[ "$(date +%s)" -lt "$end_epoch" ]]; do
  iteration=$((iteration + 1))
  log="$evidence_dir/logs/iteration-${iteration}.log"
  iter_started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "==> iteration $iteration started at $iter_started"
  if ./scripts/public-tcp-smoke.sh "$server_host" >"$log" 2>&1; then
    passed=$((passed + 1))
    echo "PASS $iteration $iter_started" | tee -a "$evidence_dir/events.log"
  else
    failed=$((failed + 1))
    echo "FAIL $iteration $iter_started see logs/iteration-${iteration}.log" | tee -a "$evidence_dir/events.log"
  fi

  now="$(date +%s)"
  if [[ "$now" -ge "$end_epoch" ]]; then
    break
  fi
  sleep_for="$interval_secs"
  remaining=$((end_epoch - now))
  if [[ "$remaining" -lt "$sleep_for" ]]; then
    sleep_for="$remaining"
  fi
  sleep "$sleep_for"
done

finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cat >"$evidence_dir/SUMMARY.md" <<EOF
# Maverick Approved-Host Long-Haul Smoke

- started: $started
- finished: $finished
- duration_secs: $duration_secs
- interval_secs: $interval_secs
- server_ssh_host: $server_host
- client_ssh_host: ${client_host:-local-approved}
- iterations: $iteration
- passed: $passed
- failed: $failed
- git_revision: $(git rev-parse HEAD)

This evidence records repeated public TCP smoke tests. It does not change local
proxy, DNS, route, firewall, VPN, or other network-service settings.
EOF

if [[ "$failed" -ne 0 ]]; then
  echo "long-haul smoke completed with failures: $failed" >&2
  exit 1
fi

echo "long-haul smoke OK: $passed/$iteration passed"
