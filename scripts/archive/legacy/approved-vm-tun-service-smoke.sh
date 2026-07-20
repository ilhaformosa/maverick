#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_TUN_SERVICE_APPROVED=1 scripts/approved-vm-tun-service-smoke.sh <ssh-host>

Runs a transient systemd lifecycle smoke for the privileged TUN helper scope on
an explicitly approved Linux VM over SSH. It must never be pointed at the
developer's local machine.

What it mutates on the remote host:
  - creates temporary systemd-run units only;
  - runs temporary helper scripts under those transient units;
  - creates temporary network namespaces and TUN devices inside the transient
    units;
  - exercises success and failure cleanup paths;
  - removes temporary scripts and reset-failed unit state.

It does not install permanent units, add a host default route, modify host
global DNS, alter firewall rules, or touch proxy/VPN or other network-service settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

host="${1:-${MAVERICK_TUN_SERVICE_HOST:-}}"
approved="${MAVERICK_TUN_SERVICE_APPROVED:-}"
namespace="${MAVERICK_TUN_SERVICE_NETNS:-mavsvc$$}"
tun_device="${MAVERICK_TUN_SERVICE_TUN:-mavts$$}"
unit_prefix="${MAVERICK_TUN_SERVICE_UNIT_PREFIX:-maverick-tun-svc-$$}"

if [[ -z "$host" ]]; then
  usage
  exit 2
fi

if [[ "$approved" != "1" ]]; then
  echo "MAVERICK_TUN_SERVICE_APPROVED=1 is required" >&2
  usage
  exit 2
fi

case "$host" in
  localhost|127.0.0.1|::1)
    echo "refusing to run approved VM TUN service smoke against local host: $host" >&2
    exit 2
    ;;
esac

python3 "$script_dir/approved-host-guard.py" "$host" >/dev/null

for name in "$namespace" "$tun_device" "$unit_prefix"; do
  if [[ ! "$name" =~ ^[A-Za-z0-9_.-]{1,30}$ ]]; then
    echo "invalid Linux object name: $name" >&2
    exit 2
  fi
done

echo "==> run approved VM TUN service smoke on $host"
ssh -o BatchMode=yes "$host" \
  "NETNS=$(shell_quote "$namespace") TUN_DEVICE=$(shell_quote "$tun_device") UNIT_PREFIX=$(shell_quote "$unit_prefix") bash -s" <<'REMOTE'
set -euo pipefail

SUCCESS_UNIT="${UNIT_PREFIX}-success"
FAIL_UNIT="${UNIT_PREFIX}-fail"
STATE_DIR="$(mktemp -d /tmp/maverick-tun-service.XXXXXX)"
chmod 700 "$STATE_DIR"
SUCCESS_SCRIPT="$STATE_DIR/success.sh"
FAIL_SCRIPT="$STATE_DIR/fail.sh"
ROUTE_CIDR="192.0.2.0/24"
ROUTE_PROBE="192.0.2.1"
TUN_ADDR="10.255.4.1/30"

snapshot_default_route() {
  ip route show default 2>/dev/null || true
}

snapshot_global_dns() {
  if [[ -e /etc/resolv.conf ]]; then
    sha256sum /etc/resolv.conf
  else
    echo "absent"
  fi
}

cleanup() {
  set +e
  sudo -n systemctl reset-failed "$SUCCESS_UNIT.service" "$FAIL_UNIT.service" 2>/dev/null || true
  sudo -n rm -rf "$STATE_DIR" 2>/dev/null || true
  if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
    sudo -n ip netns exec "$NETNS" ip link del "$TUN_DEVICE" 2>/dev/null || true
    sudo -n ip netns del "$NETNS" 2>/dev/null || true
  fi
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "approved VM TUN service smoke requires Linux" >&2
  exit 1
fi

command -v ip >/dev/null
command -v sha256sum >/dev/null
command -v systemd-run >/dev/null
command -v systemctl >/dev/null
sudo -n true
sudo -n test -e /dev/net/tun

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "network namespace already exists, refusing to touch it: $NETNS" >&2
  exit 1
fi
if ip link show "$TUN_DEVICE" >/dev/null 2>&1; then
  echo "link already exists, refusing to touch it: $TUN_DEVICE" >&2
  exit 1
fi

default_route_before="$(snapshot_default_route)"
global_dns_before="$(snapshot_global_dns)"

trap cleanup EXIT

cat >"$SUCCESS_SCRIPT" <<EOS
#!/usr/bin/env bash
set -euo pipefail
cleanup_unit() {
  set +e
  if ip netns list | awk '{print \$1}' | grep -qx "$NETNS"; then
    ip netns exec "$NETNS" ip route del "$ROUTE_CIDR" dev "$TUN_DEVICE" 2>/dev/null || true
    ip netns exec "$NETNS" ip link del "$TUN_DEVICE" 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
  fi
}
trap cleanup_unit EXIT
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip tuntap add dev "$TUN_DEVICE" mode tun
ip netns exec "$NETNS" ip addr add "$TUN_ADDR" dev "$TUN_DEVICE"
ip netns exec "$NETNS" ip link set "$TUN_DEVICE" up
ip netns exec "$NETNS" ip route add "$ROUTE_CIDR" dev "$TUN_DEVICE"
ip netns exec "$NETNS" ip route get "$ROUTE_PROBE" | grep -q "dev $TUN_DEVICE"
echo helper-service-success
EOS

cat >"$FAIL_SCRIPT" <<EOS
#!/usr/bin/env bash
set -euo pipefail
cleanup_unit() {
  set +e
  if ip netns list | awk '{print \$1}' | grep -qx "$NETNS"; then
    ip netns exec "$NETNS" ip link del "$TUN_DEVICE" 2>/dev/null || true
    ip netns del "$NETNS" 2>/dev/null || true
  fi
}
trap cleanup_unit EXIT
ip netns add "$NETNS"
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip tuntap add dev "$TUN_DEVICE" mode tun
ip netns exec "$NETNS" ip addr add "$TUN_ADDR" dev "$TUN_DEVICE"
ip netns exec "$NETNS" ip link set "$TUN_DEVICE" up
echo helper-service-intentional-failure
exit 42
EOS

chmod 700 "$SUCCESS_SCRIPT" "$FAIL_SCRIPT"

echo "apply: systemd-run transient success unit"
sudo -n systemd-run --wait --collect --unit "$SUCCESS_UNIT" --property=Type=oneshot /bin/bash "$SUCCESS_SCRIPT" >/dev/null
echo "systemd_lifecycle_success=ok"

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "success unit left namespace residue: $NETNS" >&2
  exit 1
fi

echo "apply: systemd-run transient failure cleanup unit"
if sudo -n systemd-run --wait --collect --unit "$FAIL_UNIT" --property=Type=oneshot /bin/bash "$FAIL_SCRIPT" >/dev/null 2>&1; then
  echo "failure unit unexpectedly succeeded" >&2
  exit 1
fi
echo "systemd_failure_cleanup=ok"

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "failure unit left namespace residue: $NETNS" >&2
  exit 1
fi
if ip link show "$TUN_DEVICE" >/dev/null 2>&1; then
  echo "failure unit left link residue: $TUN_DEVICE" >&2
  exit 1
fi

sudo -n systemctl reset-failed "$SUCCESS_UNIT.service" "$FAIL_UNIT.service" 2>/dev/null || true
sudo -n rm -rf "$STATE_DIR"
trap - EXIT

default_route_after="$(snapshot_default_route)"
global_dns_after="$(snapshot_global_dns)"
if [[ "$default_route_before" != "$default_route_after" ]]; then
  echo "host default route changed unexpectedly" >&2
  exit 1
fi
if [[ "$global_dns_before" != "$global_dns_after" ]]; then
  echo "host global DNS resolver changed unexpectedly" >&2
  exit 1
fi

echo "default_route_unchanged: true"
echo "global_dns_unchanged: true"
echo "approved_vm_tun_service_smoke=ok"
REMOTE
