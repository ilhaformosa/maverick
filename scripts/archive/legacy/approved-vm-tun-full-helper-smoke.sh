#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_TUN_FULL_HELPER_APPROVED=1 scripts/approved-vm-tun-full-helper-smoke.sh <ssh-host>

Runs the approved-host full privileged TUN helper integration smoke for the
current prototype scope. It chains the namespace runtime, namespace policy,
service-manager lifecycle, and leak/coexistence smokes, then performs an
independent residue check.

It does not run on localhost, does not modify the developer workstation, does
not install permanent services, and does not make a production full-device
TCP/IP relay claim.
EOF
}

host="${1:-${MAVERICK_TUN_FULL_HELPER_HOST:-}}"
approved="${MAVERICK_TUN_FULL_HELPER_APPROVED:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$host" ]]; then
  usage
  exit 2
fi

if [[ "$approved" != "1" ]]; then
  echo "MAVERICK_TUN_FULL_HELPER_APPROVED=1 is required" >&2
  usage
  exit 2
fi

case "$host" in
  localhost|127.0.0.1|::1)
    echo "refusing to run approved VM TUN full helper smoke against local host: $host" >&2
    exit 2
    ;;
esac

python3 "$script_dir/approved-host-guard.py" "$host" >/dev/null

residue_check() {
  ssh -o BatchMode=yes "$host" 'set -euo pipefail
found=0
if ip netns list | awk '\''{print $1}'\'' | grep -E "^mav"; then found=1; fi
if ip -o link show | awk -F: '\''{print $2}'\'' | tr -d " " | grep -E "^mav"; then found=1; fi
if find /etc/netns -maxdepth 2 -type f -name resolv.conf 2>/dev/null | grep -E "/mav"; then found=1; fi
if systemctl --failed --no-legend 2>/dev/null | awk '\''{print $1}'\'' | grep -E "^maverick-tun-svc-"; then found=1; fi
if [ "$found" -ne 0 ]; then echo residue=present; exit 1; fi
echo remote_residue=absent'
}

echo "==> preflight residue check on $host"
residue_check

echo "==> Phase B namespace runtime smoke"
MAVERICK_TUN_RUNTIME_APPROVED=1 \
  "$script_dir/approved-vm-tun-runtime-smoke.sh" "$host"

echo "==> Phase C namespace policy smoke"
MAVERICK_TUN_POLICY_APPROVED=1 \
  "$script_dir/approved-vm-tun-policy-smoke.sh" "$host"

echo "==> service-manager lifecycle smoke"
MAVERICK_TUN_SERVICE_APPROVED=1 \
  "$script_dir/approved-vm-tun-service-smoke.sh" "$host"

echo "==> leak/coexistence smoke"
MAVERICK_TUN_LEAK_APPROVED=1 \
  "$script_dir/approved-vm-tun-leak-coexistence-smoke.sh" "$host"

echo "==> final residue check on $host"
residue_check

echo "approved_vm_tun_full_helper_smoke=ok"
