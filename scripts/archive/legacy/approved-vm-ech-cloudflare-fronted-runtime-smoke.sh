#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh [origin-ssh-host]

Required environment:
  MAVERICK_ECH_CF_RUNTIME_APPROVED=1

Optional environment:
  MAVERICK_ECH_CF_DOMAIN        Cloudflare proxied domain, default maverick-ech.example.com.
  MAVERICK_ECH_CF_CLIENT_HOST   SSH host that runs the client data plane, default approved-server-vm.
  MAVERICK_ECH_CF_ORIGIN_REPO   Origin repo dir, default maverick-remote-lab.
  MAVERICK_ECH_CF_CLIENT_REPO   Client repo dir, default maverick-remote-lab.
  MAVERICK_ECH_CF_ORIGIN_PORT   Origin HTTPS port, default 443.
  MAVERICK_ECH_CF_TARGET_PORT   Origin loopback echo port, default 24444.
  MAVERICK_ECH_CF_TIMEOUT_SECS  Temporary service lifetime, default 120.
  MAVERICK_ECH_CF_TUNNEL_PATH   Maverick origin tunnel path, default /maverick.Tunnel/Open.

This script runs one Cloudflare-fronted Maverick runtime smoke from approved
VMs. It starts a temporary Maverick H2/TLS plus WebSocket origin server on the
approved origin VM, starts a temporary Maverick client on a separate approved
remote client VM, sends one SOCKS5 TCP echo flow through the Cloudflare proxied
domain, and removes temporary files.

This is not native Maverick server-side ECH. It validates the edge-fronted
runtime path that can be combined with the separate Cloudflare edge ECH
preflight, where Cloudflare terminates the client TLS/ECH handshake and proxies
to the Maverick origin.

Cloudflare must allow WebSocket upgrade requests for this to pass. H2/gRPC
front-door preflights remain in the script to confirm ordinary Cloudflare-to-
origin reachability, but the authenticated Maverick runtime flow uses WebSocket
binary messages.

It does not mutate DNS records, cloud firewall rules, or local workstation
network-service settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

origin_host="${1:-${MAVERICK_ECH_CF_ORIGIN_HOST:-approved-linux-vm}}"
domain="${MAVERICK_ECH_CF_DOMAIN:-maverick-ech.example.com}"
client_host="${MAVERICK_ECH_CF_CLIENT_HOST:-approved-server-vm}"
origin_repo="${MAVERICK_ECH_CF_ORIGIN_REPO:-maverick-remote-lab}"
client_repo="${MAVERICK_ECH_CF_CLIENT_REPO:-maverick-remote-lab}"
origin_port="${MAVERICK_ECH_CF_ORIGIN_PORT:-443}"
target_port="${MAVERICK_ECH_CF_TARGET_PORT:-24444}"
timeout_secs="${MAVERICK_ECH_CF_TIMEOUT_SECS:-120}"
tunnel_path="${MAVERICK_ECH_CF_TUNNEL_PATH:-/maverick.Tunnel/Open}"

if [[ "${MAVERICK_ECH_CF_RUNTIME_APPROVED:-}" != "1" ]]; then
  echo "MAVERICK_ECH_CF_RUNTIME_APPROVED=1 is required" >&2
  usage
  exit 2
fi

for host in "$origin_host" "$client_host"; do
  case "$host" in
    ""|localhost|127.*|::1)
      echo "refusing to run Cloudflare-fronted runtime smoke against local host: $host" >&2
      exit 2
      ;;
  esac
done

case "$domain:$origin_port:$target_port:$timeout_secs" in
  *[!A-Za-z0-9.:-]*|*..*|.*|*.)
    echo "invalid domain, port, or timeout" >&2
    exit 2
    ;;
esac

case "$origin_port:$target_port:$timeout_secs" in
  *[!0-9:]*)
    echo "ports and timeout must be numeric" >&2
    exit 2
    ;;
esac
case "$tunnel_path" in
  /*[!A-Za-z0-9._/-]*|""|*..*|*/)
    echo "invalid tunnel path" >&2
    exit 2
    ;;
esac

tmpdir="$(mktemp -d)"
origin_dir="/tmp/maverick-ech-cf-origin-$(date +%s)-$$"
client_dir="/tmp/maverick-ech-cf-client-$(date +%s)-$$"
origin_server_pid=""
origin_echo_pid=""
client_pid=""

print_logs() {
  echo "--- origin server log ---"
  ssh "$origin_host" "ORIGIN_DIR=$(shell_quote "$origin_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sudo -n sed -n '1,200p' "$ORIGIN_DIR/server.log" 2>/dev/null || true
REMOTE
  echo "--- origin echo log ---"
  ssh "$origin_host" "ORIGIN_DIR=$(shell_quote "$origin_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sed -n '1,120p' "$ORIGIN_DIR/echo.log" 2>/dev/null || true
REMOTE
  echo "--- client log ---"
  ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE' 2>/dev/null || true
set -euo pipefail
sed -n '1,200p' "$CLIENT_DIR/client.log" 2>/dev/null || true
REMOTE
}

cleanup() {
  ssh "$client_host" \
    "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_PID=$(shell_quote "${client_pid:-0}") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
kill "$CLIENT_PID" 2>/dev/null || true
rm -rf "$CLIENT_DIR"
REMOTE
  ssh "$origin_host" \
    "ORIGIN_DIR=$(shell_quote "$origin_dir") SERVER_PID=$(shell_quote "${origin_server_pid:-0}") ECHO_PID=$(shell_quote "${origin_echo_pid:-0}") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
sudo -n kill "$SERVER_PID" 2>/dev/null || true
kill "$ECHO_PID" 2>/dev/null || true
sudo -n rm -rf "$ORIGIN_DIR"
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

echo "==> prepare Cloudflare-fronted origin on $origin_host:$origin_port for $domain"
ssh "$origin_host" \
  "ORIGIN_DIR=$(shell_quote "$origin_dir") ORIGIN_REPO=$(shell_quote "$origin_repo") DOMAIN=$(shell_quote "$domain") TARGET_PORT=$(shell_quote "$target_port") ORIGIN_PORT=$(shell_quote "$origin_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") SECRET=$(shell_quote "$secret") TUNNEL_PATH=$(shell_quote "$tunnel_path") bash -s" <<'REMOTE'
set -euo pipefail

for tool in openssl python3 sudo timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool on origin host: $tool" >&2
    exit 1
  fi
done

if [[ ! -d "$ORIGIN_REPO" ]]; then
  echo "origin repo directory does not exist: $ORIGIN_REPO" >&2
  exit 1
fi

if [[ ! -x "$ORIGIN_REPO/target/debug/maverick" ]]; then
  PATH="$HOME/.cargo/bin:$PATH" cargo build --manifest-path "$ORIGIN_REPO/Cargo.toml" -p maverick-cli
fi

sudo -n rm -rf "$ORIGIN_DIR"
mkdir -p "$ORIGIN_DIR/public"
printf '%s\n' '<html><body>Maverick Cloudflare-fronted runtime smoke fallback</body></html>' \
  >"$ORIGIN_DIR/public/index.html"

openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=${DOMAIN}" \
  -keyout "$ORIGIN_DIR/privkey.pem" -out "$ORIGIN_DIR/fullchain.pem" -days 1 >/dev/null 2>&1
chmod 600 "$ORIGIN_DIR/privkey.pem" "$ORIGIN_DIR/fullchain.pem"

cat >"$ORIGIN_DIR/echo.py" <<'PY'
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
chmod 600 "$ORIGIN_DIR/echo.py"

cat >"$ORIGIN_DIR/server.yaml" <<YAML
version: 1
listen: "0.0.0.0:${ORIGIN_PORT}"
tls:
  cert_path: "${ORIGIN_DIR}/fullchain.pem"
  key_path: "${ORIGIN_DIR}/privkey.pem"
maverick:
  tunnel_path: "${TUNNEL_PATH}"
  mode_default: "auto"
  replay_window_secs: 120
  max_concurrent_flows_per_user: 16
users:
  - id: "u_ech_cf_runtime"
    name: "ech-cf-runtime"
    secret: "${SECRET}"
    enabled: true
    rate_limit: null
    max_concurrent_flows: null
fallback:
  type: "static"
  static_dir: "${ORIGIN_DIR}/public"
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
  experimental_cloudflare_ws: true
YAML
chmod 600 "$ORIGIN_DIR/server.yaml"

cd "$ORIGIN_REPO"
nohup timeout "${TIMEOUT_SECS}s" python3 -u "$ORIGIN_DIR/echo.py" "$TARGET_PORT" \
  >"$ORIGIN_DIR/echo.log" 2>&1 &
echo $! >"$ORIGIN_DIR/echo.pid"

sudo -n nohup timeout "${TIMEOUT_SECS}s" ./target/debug/maverick server -c "$ORIGIN_DIR/server.yaml" \
  >"$ORIGIN_DIR/server.log" 2>&1 &
echo $! >"$ORIGIN_DIR/server.pid"
REMOTE

origin_echo_pid="$(ssh "$origin_host" "cat $(shell_quote "$origin_dir")/echo.pid")"
origin_server_pid="$(ssh "$origin_host" "cat $(shell_quote "$origin_dir")/server.pid")"

echo "==> wait for origin listeners"
for _ in $(seq 1 30); do
  if ssh "$origin_host" "ORIGIN_DIR=$(shell_quote "$origin_dir") bash -s" <<'REMOTE'
set -euo pipefail
sudo -n grep -q 'Maverick server listening' "$ORIGIN_DIR/server.log"
grep -q 'echo-listening' "$ORIGIN_DIR/echo.log"
REMOTE
  then
    break
  fi
  sleep 1
done

ssh "$origin_host" "ORIGIN_DIR=$(shell_quote "$origin_dir") bash -s" <<'REMOTE'
set -euo pipefail
sudo -n grep -q 'Maverick server listening' "$ORIGIN_DIR/server.log"
grep -q 'echo-listening' "$ORIGIN_DIR/echo.log"
REMOTE

echo "==> Cloudflare front-door fallback preflight"
ssh "$client_host" "DOMAIN=$(shell_quote "$domain") ORIGIN_PORT=$(shell_quote "$origin_port") bash -s" <<'REMOTE'
set -euo pipefail
curl -sS -o /dev/null -w "cloudflare_frontdoor_status=%{http_code}\n" --http2 --max-time 20 \
  "https://${DOMAIN}:${ORIGIN_PORT}/"
REMOTE

echo "==> Cloudflare front-door POST preflight"
ssh "$client_host" "DOMAIN=$(shell_quote "$domain") ORIGIN_PORT=$(shell_quote "$origin_port") TUNNEL_PATH=$(shell_quote "$tunnel_path") bash -s" <<'REMOTE'
set -euo pipefail
printf 'maverick-cloudflare-post-preflight' \
  | curl -sS -o /dev/null -w "cloudflare_frontdoor_post_status=%{http_code}\n" \
      --http2 --max-time 20 -X POST -H 'content-type: application/octet-stream' \
      --data-binary @- "https://${DOMAIN}:${ORIGIN_PORT}${TUNNEL_PATH}"
REMOTE

echo "==> prepare approved remote client on $client_host"
ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_REPO=$(shell_quote "$client_repo") DOMAIN=$(shell_quote "$domain") ORIGIN_PORT=$(shell_quote "$origin_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") SECRET=$(shell_quote "$secret") TUNNEL_PATH=$(shell_quote "$tunnel_path") bash -s" <<'REMOTE'
set -euo pipefail

mkdir -p "$CLIENT_DIR"
if [[ ! -d "$CLIENT_REPO" ]]; then
  echo "client repo directory does not exist: $CLIENT_REPO" >&2
  exit 1
fi
if [[ ! -x "$CLIENT_REPO/target/debug/maverick" ]]; then
  echo "client maverick binary does not exist: $CLIENT_REPO/target/debug/maverick" >&2
  exit 1
fi

cat >"$CLIENT_DIR/client.yaml" <<YAML
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
  address: "${DOMAIN}:${ORIGIN_PORT}"
  server_name: "${DOMAIN}"
  tunnel_path: "${TUNNEL_PATH}"
  credential_id: "u_ech_cf_runtime"
  secret: "${SECRET}"
  ca_cert: null
  cert_pin: null
log:
  level: "debug"
  redact: true
advanced:
  connect_timeout_ms: 10000
  idle_timeout_secs: 60
  max_concurrent_flows: 16
  experimental_cloudflare_ws: true
  padding: "off"
  allow_non_loopback_listeners: false
YAML
chmod 600 "$CLIENT_DIR/client.yaml"

cd "$CLIENT_REPO"
nohup timeout "${TIMEOUT_SECS}s" ./target/debug/maverick client -c "$CLIENT_DIR/client.yaml" \
  >"$CLIENT_DIR/client.log" 2>&1 &
echo $! >"$CLIENT_DIR/client.pid"
REMOTE

client_pid="$(ssh "$client_host" "cat $(shell_quote "$client_dir")/client.pid")"

client_port=""
for _ in $(seq 1 30); do
  if ! ssh "$client_host" "CLIENT_PID=$(shell_quote "$client_pid") bash -s" <<'REMOTE'
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

echo "==> SOCKS5 TCP echo through Cloudflare-fronted Maverick origin"
ssh "$client_host" \
  "CLIENT_PORT=$(shell_quote "$client_port") TARGET_PORT=$(shell_quote "$target_port") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$CLIENT_PORT" "$TARGET_PORT" <<'PY'
import socket
import struct
import sys

client_port = int(sys.argv[1])
target_port = int(sys.argv[2])
payload = b"maverick-ech-cloudflare-fronted-runtime-smoke"

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

print("ech_cloudflare_fronted_runtime_smoke=ok")
PY
REMOTE

echo "ECH Cloudflare-fronted runtime smoke OK"
