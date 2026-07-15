#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_TUN_POLICY_APPROVED=1 scripts/approved-vm-tun-policy-smoke.sh <ssh-host>

Runs a real namespace-scoped TUN/default-route/DNS policy smoke on an
explicitly approved Linux VM over SSH. It must never be pointed at the
developer's local machine.

What it mutates on the remote host:
  - creates a temporary network namespace;
  - creates a temporary veth pair for control-plane bypass checks;
  - creates a temporary TUN device inside the namespace;
  - adds a namespace-local preserved route for the veth control-plane peer;
  - adds a namespace-local default route to the TUN device;
  - writes a namespace-scoped resolv.conf;
  - verifies DNS and default-route probes select the TUN path;
  - verifies the preserved control-plane route still reaches the host veth peer;
  - rolls all of the above back and verifies no residue remains.

It does not add a host default route, modify host global DNS, alter firewall
rules, or touch proxy/VPN or other network-service settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

host="${1:-${MAVERICK_TUN_POLICY_HOST:-}}"
approved="${MAVERICK_TUN_POLICY_APPROVED:-}"
namespace="${MAVERICK_TUN_POLICY_NETNS:-mavpol$$}"
tun_device="${MAVERICK_TUN_POLICY_TUN:-mavtp$$}"
veth_host="${MAVERICK_TUN_POLICY_VETH_HOST:-mavph$$}"
veth_ns="${MAVERICK_TUN_POLICY_VETH_NS:-mavpn$$}"
echo_port="${MAVERICK_TUN_POLICY_ECHO_PORT:-24552}"

if [[ -z "$host" ]]; then
  usage
  exit 2
fi

if [[ "$approved" != "1" ]]; then
  echo "MAVERICK_TUN_POLICY_APPROVED=1 is required" >&2
  usage
  exit 2
fi

case "$host" in
  localhost|127.0.0.1|::1)
    echo "refusing to run approved VM TUN policy smoke against local host: $host" >&2
    exit 2
    ;;
esac

python3 "$script_dir/approved-host-guard.py" "$host" >/dev/null

for name in "$namespace" "$tun_device" "$veth_host" "$veth_ns"; do
  if [[ ! "$name" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "invalid Linux object name: $name" >&2
    exit 2
  fi
done

case "$echo_port" in
  *[!0-9]*|"")
    echo "echo port must be numeric" >&2
    exit 2
    ;;
esac

echo "==> run approved VM TUN policy smoke on $host"
ssh -o BatchMode=yes "$host" \
  "NETNS=$(shell_quote "$namespace") TUN_DEVICE=$(shell_quote "$tun_device") VETH_HOST=$(shell_quote "$veth_host") VETH_NS=$(shell_quote "$veth_ns") ECHO_PORT=$(shell_quote "$echo_port") bash -s" <<'REMOTE'
set -euo pipefail

TUN_ADDR="10.255.2.1/30"
VETH_HOST_ADDR="198.18.1.1/30"
VETH_NS_ADDR="198.18.1.2/30"
VETH_HOST_IP="198.18.1.1"
CONTROL_PLANE_CIDR="${VETH_HOST_IP}/32"
DEFAULT_PROBE="1.1.1.1"
DNS_SERVER="9.9.9.9"
ECHO_LOG="/tmp/maverick-tun-policy-${NETNS}-echo.log"
ECHO_PID=""

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
  if [[ -n "${ECHO_PID:-}" ]]; then
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
  fi
  rm -f "$ECHO_LOG" 2>/dev/null || true
  if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
    sudo -n ip netns exec "$NETNS" ip route del default dev "$TUN_DEVICE" 2>/dev/null || true
    sudo -n ip netns exec "$NETNS" ip route del "$CONTROL_PLANE_CIDR" dev "$VETH_NS" 2>/dev/null || true
    sudo -n ip netns exec "$NETNS" ip link del "$TUN_DEVICE" 2>/dev/null || true
  fi
  sudo -n ip link del "$VETH_HOST" 2>/dev/null || true
  sudo -n ip netns del "$NETNS" 2>/dev/null || true
  sudo -n rm -f "/etc/netns/$NETNS/resolv.conf" 2>/dev/null || true
  sudo -n rmdir "/etc/netns/$NETNS" 2>/dev/null || true
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "approved VM TUN policy smoke requires Linux" >&2
  exit 1
fi

command -v ip >/dev/null
command -v python3 >/dev/null
command -v sha256sum >/dev/null
sudo -n true
sudo -n test -e /dev/net/tun

if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "network namespace already exists, refusing to touch it: $NETNS" >&2
  exit 1
fi

for link_name in "$TUN_DEVICE" "$VETH_HOST" "$VETH_NS"; do
  if ip link show "$link_name" >/dev/null 2>&1; then
    echo "link already exists, refusing to touch it: $link_name" >&2
    exit 1
  fi
done

default_route_before="$(snapshot_default_route)"
global_dns_before="$(snapshot_global_dns)"

trap cleanup EXIT

echo "apply: create namespace $NETNS"
sudo -n ip netns add "$NETNS"
sudo -n ip netns exec "$NETNS" ip link set lo up

echo "apply: namespace-scoped DNS file"
sudo -n mkdir -p "/etc/netns/$NETNS"
printf 'nameserver %s\n' "$DNS_SERVER" | sudo -n tee "/etc/netns/$NETNS/resolv.conf" >/dev/null
sudo -n ip netns exec "$NETNS" sh -c "grep -qx 'nameserver $DNS_SERVER' /etc/resolv.conf"

echo "apply: veth control-plane path"
sudo -n ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
sudo -n ip link set "$VETH_NS" netns "$NETNS"
sudo -n ip addr add "$VETH_HOST_ADDR" dev "$VETH_HOST"
sudo -n ip link set "$VETH_HOST" up
sudo -n ip netns exec "$NETNS" ip addr add "$VETH_NS_ADDR" dev "$VETH_NS"
sudo -n ip netns exec "$NETNS" ip link set "$VETH_NS" up
sudo -n ip netns exec "$NETNS" ip route replace "$CONTROL_PLANE_CIDR" dev "$VETH_NS"
sudo -n ip netns exec "$NETNS" ip route get "$VETH_HOST_IP" | grep -q "dev $VETH_NS"

echo "apply: create TUN inside namespace"
sudo -n ip netns exec "$NETNS" ip tuntap add dev "$TUN_DEVICE" mode tun user "$(id -un)"
sudo -n ip netns exec "$NETNS" ip addr add "$TUN_ADDR" dev "$TUN_DEVICE"
sudo -n ip netns exec "$NETNS" ip link set "$TUN_DEVICE" up

echo "apply: namespace default route to TUN"
sudo -n ip netns exec "$NETNS" ip route add default dev "$TUN_DEVICE" metric 4272
sudo -n ip netns exec "$NETNS" ip route get "$DEFAULT_PROBE" | grep -q "dev $TUN_DEVICE"
echo "namespace_policy_default_route=ok"

echo "verify: namespace DNS route selects TUN path"
sudo -n ip netns exec "$NETNS" ip route get "$DNS_SERVER" | grep -q "dev $TUN_DEVICE"
echo "namespace_policy_dns_route=ok"

echo "verify: preserved control-plane route still reaches host veth peer"
rm -f "$ECHO_LOG"
python3 -u - "$VETH_HOST_IP" "$ECHO_PORT" >"$ECHO_LOG" 2>&1 <<'PY' &
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))
sock.listen(1)
print("echo-listening", flush=True)
conn, _addr = sock.accept()
data = conn.recv(4096)
conn.sendall(b"maverick-phase-c-ok:" + data)
conn.close()
sock.close()
PY
ECHO_PID="$!"

for _ in $(seq 1 20); do
  if grep -q "echo-listening" "$ECHO_LOG" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
grep -q "echo-listening" "$ECHO_LOG"

sudo -n ip netns exec "$NETNS" python3 - "$VETH_HOST_IP" "$ECHO_PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
with socket.create_connection((host, port), timeout=5) as sock:
    sock.sendall(b"probe")
    data = sock.recv(4096)
if data != b"maverick-phase-c-ok:probe":
    raise SystemExit(f"unexpected echo response: {data!r}")
print("namespace_policy_control_plane=ok")
PY
kill "$ECHO_PID" 2>/dev/null || true
wait "$ECHO_PID" 2>/dev/null || true
ECHO_PID=""
rm -f "$ECHO_LOG"

echo "rollback: remove namespace default route, preserved route, TUN, veth, and namespace DNS"
sudo -n ip netns exec "$NETNS" ip route del default dev "$TUN_DEVICE"
sudo -n ip netns exec "$NETNS" ip route del "$CONTROL_PLANE_CIDR" dev "$VETH_NS"
sudo -n ip netns exec "$NETNS" ip link del "$TUN_DEVICE"
sudo -n ip link del "$VETH_HOST"
sudo -n ip netns del "$NETNS"
sudo -n rm -f "/etc/netns/$NETNS/resolv.conf"
sudo -n rmdir "/etc/netns/$NETNS" 2>/dev/null || true
trap - EXIT

echo "verify rollback and host baselines"
if ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
  echo "network namespace residue remains: $NETNS" >&2
  exit 1
fi

for link_name in "$TUN_DEVICE" "$VETH_HOST" "$VETH_NS"; do
  if ip link show "$link_name" >/dev/null 2>&1; then
    echo "link residue remains: $link_name" >&2
    exit 1
  fi
done

if sudo -n test -e "/etc/netns/$NETNS/resolv.conf"; then
  echo "namespace DNS residue remains: /etc/netns/$NETNS/resolv.conf" >&2
  exit 1
fi

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
echo "approved_vm_tun_policy_smoke=ok"
REMOTE
