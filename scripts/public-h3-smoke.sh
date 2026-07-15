#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/public-h3-smoke.sh <server-ssh-host> <client-ssh-host>

Required environment:
  MAVERICK_PUBLIC_H3_REMOTE_ADDR   Public address the remote client dials.
  MAVERICK_PUBLIC_H3_SERVER_NAME   TLS server_name / SNI value.
  MAVERICK_PUBLIC_H3_REMOTE_CERT   Server host PEM certificate chain path.
  MAVERICK_PUBLIC_H3_REMOTE_KEY    Server host PEM private key path.

Optional environment:
  MAVERICK_PUBLIC_H3_PORT          Remote Maverick TCP+UDP port, default 24443.
  MAVERICK_PUBLIC_H3_TARGET_PORT   Server loopback echo port, default 24444.
  MAVERICK_PUBLIC_H3_REMOTE_REPO   Server host repo dir, default maverick-remote-lab.
  MAVERICK_PUBLIC_H3_CLIENT_REPO   Client host repo dir, default remote repo.
  MAVERICK_PUBLIC_H3_TIMEOUT_SECS  Temporary service lifetime, default 180.
  MAVERICK_PUBLIC_H3_CONNECT_TIMEOUT_MS
                                  Client QUIC/H2 connect timeout, default 15000.
  MAVERICK_PUBLIC_H3_BUILD_JOBS    Cargo build jobs on each VM, default 1.
  MAVERICK_PUBLIC_H3_LOCAL_CA_CERT Local CA bundle path for private test certs.

The script builds the feature-gated H3 binary in a separate target directory on
both SSH hosts, starts temporary server/client/echo processes, runs one SOCKS5
TCP echo flow over H3/QUIC, verifies that the server authenticated an H3
session, and removes temporary files on exit.

This script intentionally requires a remote client host so the local machine
only orchestrates over SSH. It does not change local or remote system proxy,
DNS, route, firewall, VPN, or interface settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

require_non_empty() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "$name is required" >&2
    usage
    exit 2
  fi
}

server_host="${1:-${MAVERICK_PUBLIC_H3_REMOTE_HOST:-}}"
client_host="${2:-${MAVERICK_PUBLIC_H3_CLIENT_HOST:-}}"
remote_addr="${MAVERICK_PUBLIC_H3_REMOTE_ADDR:-}"
server_name="${MAVERICK_PUBLIC_H3_SERVER_NAME:-}"
remote_cert="${MAVERICK_PUBLIC_H3_REMOTE_CERT:-}"
remote_key="${MAVERICK_PUBLIC_H3_REMOTE_KEY:-}"
port="${MAVERICK_PUBLIC_H3_PORT:-24443}"
target_port="${MAVERICK_PUBLIC_H3_TARGET_PORT:-24444}"
remote_repo="${MAVERICK_PUBLIC_H3_REMOTE_REPO:-maverick-remote-lab}"
client_repo="${MAVERICK_PUBLIC_H3_CLIENT_REPO:-$remote_repo}"
timeout_secs="${MAVERICK_PUBLIC_H3_TIMEOUT_SECS:-180}"
connect_timeout_ms="${MAVERICK_PUBLIC_H3_CONNECT_TIMEOUT_MS:-15000}"
build_jobs="${MAVERICK_PUBLIC_H3_BUILD_JOBS:-1}"
local_ca_cert="${MAVERICK_PUBLIC_H3_LOCAL_CA_CERT:-}"

require_non_empty "server ssh host" "$server_host"
require_non_empty "client ssh host" "$client_host"
require_non_empty "MAVERICK_PUBLIC_H3_REMOTE_ADDR" "$remote_addr"
require_non_empty "MAVERICK_PUBLIC_H3_SERVER_NAME" "$server_name"
require_non_empty "MAVERICK_PUBLIC_H3_REMOTE_CERT" "$remote_cert"
require_non_empty "MAVERICK_PUBLIC_H3_REMOTE_KEY" "$remote_key"

case "$port:$target_port:$timeout_secs:$connect_timeout_ms:$build_jobs" in
  *[!0-9:]*)
    echo "ports, timeouts, and build jobs must be numeric" >&2
    exit 2
    ;;
esac

if [[ -n "$local_ca_cert" && ! -r "$local_ca_cert" ]]; then
  echo "local CA cert is not readable: $local_ca_cert" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
remote_dir="/tmp/maverick-public-h3-smoke-$(date +%s)-$$"
client_dir="/tmp/maverick-public-h3-client-smoke-$(date +%s)-$$"
server_pid=""
echo_pid=""
client_remote_pid=""

print_logs() {
  echo "--- remote client log ---"
  ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sed -n '1,160p' "$CLIENT_DIR/client.log" 2>/dev/null || true
REMOTE
  echo "--- remote server log ---"
  ssh "$server_host" "REMOTE_DIR=$(shell_quote "$remote_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sed -n '1,200p' "$REMOTE_DIR/server.log" 2>/dev/null || true
REMOTE
  echo "--- remote echo log ---"
  ssh "$server_host" "REMOTE_DIR=$(shell_quote "$remote_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sed -n '1,100p' "$REMOTE_DIR/echo.log" 2>/dev/null || true
REMOTE
}

cleanup() {
  ssh "$client_host" \
    "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_PID=$(shell_quote "${client_remote_pid:-}") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
if [[ "$CLIENT_PID" =~ ^[0-9]+$ && "$CLIENT_PID" != "0" ]]; then
  kill "$CLIENT_PID" 2>/dev/null || true
fi
rm -rf "$CLIENT_DIR"
REMOTE
  ssh "$server_host" \
    "REMOTE_DIR=$(shell_quote "$remote_dir") SERVER_PID=$(shell_quote "${server_pid:-}") ECHO_PID=$(shell_quote "${echo_pid:-}") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
for pid in "$SERVER_PID" "$ECHO_PID"; do
  if [[ "$pid" =~ ^[0-9]+$ && "$pid" != "0" ]]; then
    kill "$pid" 2>/dev/null || true
  fi
done
rm -rf "$REMOTE_DIR"
REMOTE
  rm -rf "$tmpdir"
}

trap 'rc=$?; if [[ $rc -ne 0 ]]; then print_logs; fi; cleanup; exit $rc' EXIT

secret="$(python3 - <<'PY'
import base64
import os

print("mv1_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
)"

echo "==> prepare H3 server host $server_host:$port"
ssh "$server_host" \
  "REMOTE_DIR=$(shell_quote "$remote_dir") REMOTE_CERT=$(shell_quote "$remote_cert") REMOTE_KEY=$(shell_quote "$remote_key") REMOTE_REPO=$(shell_quote "$remote_repo") BUILD_JOBS=$(shell_quote "$build_jobs") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$REMOTE_DIR/public"
printf '%s\n' '<html><body>Maverick public H3 smoke fallback</body></html>' \
  >"$REMOTE_DIR/public/index.html"

if [[ ! -d "$REMOTE_REPO" ]]; then
  echo "remote repo directory does not exist: $REMOTE_REPO" >&2
  exit 1
fi
repo_dir="$(cd "$REMOTE_REPO" && pwd)"
bin="$repo_dir/target-public-h3/debug/maverick"
if [[ ! -x "$bin" ]]; then
  PATH="$HOME/.cargo/bin:$PATH" \
    CARGO_BUILD_JOBS="$BUILD_JOBS" \
    CARGO_TARGET_DIR="$repo_dir/target-public-h3" \
    cargo build --manifest-path "$repo_dir/Cargo.toml" --features h3 -p maverick-cli
fi

if [[ -r "$REMOTE_CERT" && -r "$REMOTE_KEY" ]]; then
  install -m 600 "$REMOTE_CERT" "$REMOTE_DIR/fullchain.pem"
  install -m 600 "$REMOTE_KEY" "$REMOTE_DIR/privkey.pem"
else
  sudo -n install -m 600 -o "$(id -un)" -g "$(id -gn)" "$REMOTE_CERT" "$REMOTE_DIR/fullchain.pem"
  sudo -n install -m 600 -o "$(id -un)" -g "$(id -gn)" "$REMOTE_KEY" "$REMOTE_DIR/privkey.pem"
fi

cat >"$REMOTE_DIR/echo.py" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(5)
print("echo-listening", flush=True)
for _ in range(5):
    conn, addr = sock.accept()
    data = conn.recv(4096)
    print("echo-peer=%s:%s bytes=%d" % (addr[0], addr[1], len(data)), flush=True)
    conn.sendall(data)
    conn.close()
sock.close()
PY
chmod 600 "$REMOTE_DIR/echo.py"
REMOTE

cat >"$tmpdir/server.yaml" <<YAML
version: 1
listen: "0.0.0.0:$port"
tls:
  cert_path: "$remote_dir/fullchain.pem"
  key_path: "$remote_dir/privkey.pem"
maverick:
  tunnel_path: "/assets/upload"
  mode_default: "auto"
  replay_window_secs: 120
  max_concurrent_flows_per_user: 16
users:
  - id: "u_public_h3_smoke"
    name: "public-h3-smoke"
    secret: "$secret"
    enabled: true
    rate_limit: null
    max_concurrent_flows: null
fallback:
  type: "static"
  static_dir: "$remote_dir/public"
  index: "index.html"
dns: null
metrics:
  enabled: false
  listen: "127.0.0.1:0"
log:
  level: "debug"
  redact: true
advanced:
  idle_timeout_secs: 60
  tcp_connect_timeout_ms: 5000
  max_frame_size: 65536
  udp_idle_timeout_ms: 30000
  experimental_h3: true
YAML
chmod 600 "$tmpdir/server.yaml"
scp -q "$tmpdir/server.yaml" "$server_host:$remote_dir/server.yaml"

echo_pid="$(ssh "$server_host" \
  "REMOTE_DIR=$(shell_quote "$remote_dir") REMOTE_REPO=$(shell_quote "$remote_repo") TARGET_PORT=$(shell_quote "$target_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") bash -s" <<'REMOTE'
set -euo pipefail
repo_dir="$(cd "$REMOTE_REPO" && pwd)"
nohup timeout "${TIMEOUT_SECS}s" python3 -u "$REMOTE_DIR/echo.py" "$TARGET_PORT" \
  >"$REMOTE_DIR/echo.log" 2>&1 &
echo $!
REMOTE
)"

server_pid="$(ssh "$server_host" \
  "REMOTE_DIR=$(shell_quote "$remote_dir") REMOTE_REPO=$(shell_quote "$remote_repo") TIMEOUT_SECS=$(shell_quote "$timeout_secs") bash -s" <<'REMOTE'
set -euo pipefail
repo_dir="$(cd "$REMOTE_REPO" && pwd)"
nohup timeout "${TIMEOUT_SECS}s" "$repo_dir/target-public-h3/debug/maverick" server -c "$REMOTE_DIR/server.yaml" \
  >"$REMOTE_DIR/server.log" 2>&1 &
echo $!
REMOTE
)"

echo "==> wait for H3 server TCP listener and echo preflight"
for _ in $(seq 1 30); do
  if ssh "$server_host" "REMOTE_DIR=$(shell_quote "$remote_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick server listening' "$REMOTE_DIR/server.log"
grep -q 'echo-listening' "$REMOTE_DIR/echo.log"
REMOTE
  then
    break
  fi
  sleep 1
done

ssh "$server_host" "REMOTE_DIR=$(shell_quote "$remote_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick server listening' "$REMOTE_DIR/server.log"
grep -q 'echo-listening' "$REMOTE_DIR/echo.log"
REMOTE

ssh "$server_host" "TARGET_PORT=$(shell_quote "$target_port") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$TARGET_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=5)
sock.sendall(b"preflight")
assert sock.recv(1024) == b"preflight"
print("remote_echo_preflight=ok")
PY
REMOTE

echo "==> prepare H3 client host $client_host"
ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_REPO=$(shell_quote "$client_repo") BUILD_JOBS=$(shell_quote "$build_jobs") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$CLIENT_DIR"
if [[ ! -d "$CLIENT_REPO" ]]; then
  echo "client repo directory does not exist: $CLIENT_REPO" >&2
  exit 1
fi
repo_dir="$(cd "$CLIENT_REPO" && pwd)"
bin="$repo_dir/target-public-h3/debug/maverick"
if [[ ! -x "$bin" ]]; then
  PATH="$HOME/.cargo/bin:$PATH" \
    CARGO_BUILD_JOBS="$BUILD_JOBS" \
    CARGO_TARGET_DIR="$repo_dir/target-public-h3" \
    cargo build --manifest-path "$repo_dir/Cargo.toml" --features h3 -p maverick-cli
fi
REMOTE

ca_value="null"
if [[ -n "$local_ca_cert" ]]; then
  scp -q "$local_ca_cert" "$client_host:$client_dir/ca.pem"
  ca_value="\"$client_dir/ca.pem\""
fi

cat >"$tmpdir/client.yaml" <<YAML
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:0"
  dns:
    enabled: false
    listen: null
  http_connect:
    enabled: false
    listen: null
server:
  address: "$remote_addr:$port"
  server_name: "$server_name"
  tunnel_path: "/assets/upload"
  credential_id: "u_public_h3_smoke"
  secret: "$secret"
  ca_cert: $ca_value
  cert_pin: null
log:
  level: "debug"
  redact: true
advanced:
  connect_timeout_ms: $connect_timeout_ms
  idle_timeout_secs: 60
  max_concurrent_flows: 16
  padding: "off"
  udp_idle_timeout_ms: 30000
  allow_non_loopback_listeners: false
  experimental_h3: true
YAML
chmod 600 "$tmpdir/client.yaml"
scp -q "$tmpdir/client.yaml" "$client_host:$client_dir/client.yaml"

client_remote_pid="$(ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_REPO=$(shell_quote "$client_repo") TIMEOUT_SECS=$(shell_quote "$timeout_secs") bash -s" <<'REMOTE'
set -euo pipefail
repo_dir="$(cd "$CLIENT_REPO" && pwd)"
nohup timeout "${TIMEOUT_SECS}s" "$repo_dir/target-public-h3/debug/maverick" client -c "$CLIENT_DIR/client.yaml" \
  >"$CLIENT_DIR/client.log" 2>&1 &
echo $!
REMOTE
)"

client_port=""
for _ in $(seq 1 30); do
  if ! ssh "$client_host" "CLIENT_PID=$(shell_quote "$client_remote_pid") bash -s" <<'REMOTE'
set -euo pipefail
kill -0 "$CLIENT_PID"
REMOTE
  then
    echo "remote client exited early" >&2
    exit 1
  fi
  client_port="$(ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$CLIENT_DIR/client.log" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(errors="ignore") if path.exists() else ""
matches = re.findall(r"127\.0\.0\.1:(\d+)", text)
print(matches[-1] if matches else "")
PY
REMOTE
)"
  if [[ -n "$client_port" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "$client_port" ]]; then
  echo "remote client listener did not become ready" >&2
  exit 1
fi

echo "==> SOCKS5 TCP echo over public Maverick H3/QUIC"
ssh "$client_host" \
  "CLIENT_PORT=$(shell_quote "$client_port") TARGET_PORT=$(shell_quote "$target_port") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$CLIENT_PORT" "$TARGET_PORT" <<'PY'
import socket
import struct
import sys

client_port = int(sys.argv[1])
target_port = int(sys.argv[2])
payload = b"maverick-public-h3-smoke"

sock = socket.create_connection(("127.0.0.1", client_port), timeout=10)
sock.sendall(b"\x05\x01\x00")
method = sock.recv(2)
if method != b"\x05\x00":
    raise SystemExit(f"SOCKS method failed: {method!r}")

request = b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + struct.pack("!H", target_port)
sock.sendall(request)
reply = sock.recv(10)
if len(reply) != 10 or reply[1] != 0:
    raise SystemExit(f"SOCKS connect failed: {reply!r}")

sock.sendall(payload)
received = b""
while len(received) < len(payload):
    chunk = sock.recv(4096)
    if not chunk:
        break
    received += chunk
if received != payload:
    raise SystemExit(f"echo mismatch: {received!r}")

print("public_h3_smoke=ok")
PY
REMOTE

echo "==> verify H3 was used, not H2 fallback"
ssh "$server_host" "REMOTE_DIR=$(shell_quote "$remote_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick H3 session authenticated' "$REMOTE_DIR/server.log"
REMOTE

ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
if grep -q 'H3 transport failed; falling back to H2' "$CLIENT_DIR/client.log"; then
  echo "client fell back from H3 to H2" >&2
  exit 1
fi
REMOTE

echo "public H3 smoke OK"
