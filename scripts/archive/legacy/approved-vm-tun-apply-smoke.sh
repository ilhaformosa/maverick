#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_TUN_APPLY_APPROVED=1 scripts/approved-vm-tun-apply-smoke.sh <ssh-host>

Runs a real TUN/route/namespaced-DNS apply and rollback smoke on an explicitly
approved Linux VM over SSH. It must never be pointed at the developer's local
machine.

What it mutates on the remote host:
  - creates a temporary TUN device;
  - assigns 10.255.0.1/30 to that device;
  - adds a route for the documentation prefix 192.0.2.0/24 to that device;
  - creates a temporary network namespace and namespace-scoped resolv.conf;
  - rolls all of the above back and verifies no residue remains.

It does not add a default route, modify global DNS, alter firewall rules, or
touch proxy/VPN or other network-service settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

host="${1:-${MAVERICK_TUN_APPLY_HOST:-}}"
approved="${MAVERICK_TUN_APPLY_APPROVED:-}"
device="${MAVERICK_TUN_APPLY_DEVICE:-mavtun$$}"
namespace="${MAVERICK_TUN_APPLY_NETNS:-mavdns$$}"

if [[ -z "$host" ]]; then
  usage
  exit 2
fi

if [[ "$approved" != "1" ]]; then
  echo "MAVERICK_TUN_APPLY_APPROVED=1 is required" >&2
  usage
  exit 2
fi

case "$host" in
  localhost|127.0.0.1|::1)
    echo "refusing to run approved VM TUN apply smoke against local host: $host" >&2
    exit 2
    ;;
esac

python3 "$script_dir/approved-host-guard.py" "$host" >/dev/null

if [[ ! "$device" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
  echo "invalid TUN device name: $device" >&2
  exit 2
fi

if [[ ! "$namespace" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
  echo "invalid network namespace name: $namespace" >&2
  exit 2
fi

echo "==> run approved VM TUN apply smoke on $host"
ssh -o BatchMode=yes "$host" \
  "DEVICE=$(shell_quote "$device") NETNS=$(shell_quote "$namespace") bash -s" <<'REMOTE'
set -euo pipefail

ROUTE_CIDR="192.0.2.0/24"
ROUTE_PROBE="192.0.2.1"
TUN_ADDR="10.255.0.1/30"
DNS_SERVER="9.9.9.9"

cleanup() {
  set +e
  sudo -n ip route del "$ROUTE_CIDR" dev "$DEVICE" 2>/dev/null
  sudo -n ip link del "$DEVICE" 2>/dev/null
  sudo -n ip netns del "$NETNS" 2>/dev/null
  sudo -n rm -f "/etc/netns/$NETNS/resolv.conf" 2>/dev/null
  sudo -n rmdir "/etc/netns/$NETNS" 2>/dev/null
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "approved VM TUN apply smoke requires Linux" >&2
  exit 1
fi

command -v ip >/dev/null
sudo -n true

if ip link show "$DEVICE" >/dev/null 2>&1; then
  echo "device already exists, refusing to touch it: $DEVICE" >&2
  exit 1
fi

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "network namespace already exists, refusing to touch it: $NETNS" >&2
  exit 1
fi

trap cleanup EXIT

echo "apply: create TUN $DEVICE"
sudo -n ip tuntap add dev "$DEVICE" mode tun user "$(id -un)"
sudo -n ip addr add "$TUN_ADDR" dev "$DEVICE"
sudo -n ip link set "$DEVICE" up
ip link show dev "$DEVICE" >/dev/null

echo "apply: add documentation-prefix route"
sudo -n ip route add "$ROUTE_CIDR" dev "$DEVICE" metric 4271
ip route get "$ROUTE_PROBE" | grep -q "dev $DEVICE"

echo "apply: namespace-scoped DNS file"
sudo -n ip netns add "$NETNS"
sudo -n mkdir -p "/etc/netns/$NETNS"
printf 'nameserver %s\n' "$DNS_SERVER" | sudo -n tee "/etc/netns/$NETNS/resolv.conf" >/dev/null
sudo -n ip netns exec "$NETNS" sh -c "grep -qx 'nameserver $DNS_SERVER' /etc/resolv.conf"

echo "rollback: remove route, TUN, and namespace DNS"
sudo -n ip route del "$ROUTE_CIDR" dev "$DEVICE"
sudo -n ip link del "$DEVICE"
sudo -n ip netns del "$NETNS"
sudo -n rm -f "/etc/netns/$NETNS/resolv.conf"
sudo -n rmdir "/etc/netns/$NETNS" 2>/dev/null || true
trap - EXIT

echo "verify rollback"
if ip link show "$DEVICE" >/dev/null 2>&1; then
  echo "TUN device residue remains: $DEVICE" >&2
  exit 1
fi

if ip route show "$ROUTE_CIDR" | grep -q "$DEVICE"; then
  echo "route residue remains for $ROUTE_CIDR" >&2
  exit 1
fi

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "network namespace residue remains: $NETNS" >&2
  exit 1
fi

if sudo -n test -e "/etc/netns/$NETNS/resolv.conf"; then
  echo "namespace DNS residue remains: /etc/netns/$NETNS/resolv.conf" >&2
  exit 1
fi

echo "approved_vm_tun_apply_smoke=ok"
REMOTE
