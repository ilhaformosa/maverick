#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/public-udp-probe.sh <server-ssh-host> <client-ssh-host>

Required environment:
  MAVERICK_PUBLIC_UDP_REMOTE_ADDR  Public address the client host sends to.

Optional environment:
  MAVERICK_PUBLIC_UDP_PORT         Remote UDP port, default 24443.
  MAVERICK_PUBLIC_UDP_TIMEOUT_SECS Temporary listener lifetime, default 45.

The script starts a temporary UDP echo listener on the server SSH host, sends
one UDP datagram from the client SSH host, prints the observed peer, and removes
the temporary listener on exit. It does not change host network settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

server_host="${1:-${MAVERICK_PUBLIC_UDP_SERVER_HOST:-}}"
client_host="${2:-${MAVERICK_PUBLIC_UDP_CLIENT_HOST:-}}"
remote_addr="${MAVERICK_PUBLIC_UDP_REMOTE_ADDR:-}"
port="${MAVERICK_PUBLIC_UDP_PORT:-24443}"
timeout_secs="${MAVERICK_PUBLIC_UDP_TIMEOUT_SECS:-45}"

if [[ -z "$server_host" || -z "$client_host" || -z "$remote_addr" ]]; then
  usage
  exit 2
fi

case "$port:$timeout_secs" in
  *[!0-9:]*)
    echo "port and timeout must be numeric" >&2
    exit 2
    ;;
esac

remote_log="/tmp/maverick-public-udp-probe-$port.log"
listener_pid=""

cleanup() {
  ssh "$server_host" \
    "LISTENER_PID=$(shell_quote "${listener_pid:-0}") REMOTE_LOG=$(shell_quote "$remote_log") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
kill "$LISTENER_PID" 2>/dev/null || true
rm -f "$REMOTE_LOG"
REMOTE
}

trap cleanup EXIT

echo "==> start UDP listener on $server_host:$port"
listener_pid="$(ssh "$server_host" \
  "PORT=$(shell_quote "$port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") REMOTE_LOG=$(shell_quote "$remote_log") bash -s" <<'REMOTE'
set -euo pipefail
rm -f "$REMOTE_LOG"
nohup timeout "${TIMEOUT_SECS}s" python3 -u - "$PORT" >"$REMOTE_LOG" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
print("udp-listening", flush=True)
data, addr = sock.recvfrom(2048)
print("peer=%s:%s bytes=%d data=%r" % (addr[0], addr[1], len(data), data), flush=True)
sock.sendto(b"maverick-public-udp-probe-ok", addr)
sock.close()
PY
echo $!
REMOTE
)"

for _ in $(seq 1 15); do
  if ssh "$server_host" "REMOTE_LOG=$(shell_quote "$remote_log") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'udp-listening' "$REMOTE_LOG"
REMOTE
  then
    break
  fi
  sleep 1
done

ssh "$server_host" "REMOTE_LOG=$(shell_quote "$remote_log") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'udp-listening' "$REMOTE_LOG"
REMOTE

echo "==> send UDP probe from $client_host to $remote_addr:$port"
ssh "$client_host" \
  "REMOTE_ADDR=$(shell_quote "$remote_addr") PORT=$(shell_quote "$port") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$REMOTE_ADDR" "$PORT" <<'PY'
import socket
import sys

remote_addr = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)
sock.sendto(b"maverick-public-udp-probe", (remote_addr, port))
data, addr = sock.recvfrom(2048)
print(data.decode())
print("reply_from=%s:%s" % (addr[0], addr[1]))
PY
REMOTE

echo "==> server observation"
ssh "$server_host" "REMOTE_LOG=$(shell_quote "$remote_log") bash -s" <<'REMOTE'
set -euo pipefail
cat "$REMOTE_LOG"
REMOTE

echo "public UDP probe OK"
