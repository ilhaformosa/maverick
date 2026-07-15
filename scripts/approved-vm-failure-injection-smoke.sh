#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-failure-injection-smoke.sh <server-ssh-host>

Runs process-level approved-host failure injection for the TCP/H2 runtime path:
- server restart while the client process stays running;
- client restart and reconnect;
- upstream echo target stop/restart;
- upstream stall/timeout and recovery.
- fallback reverse-proxy origin stop/restart without leaking tunnel details.

The script does not mutate host proxy, DNS, routes, VPN, interfaces, or
traffic-control settings. Optional firewall handling creates only one
auto-expiring runtime rule for an initially closed high test port. The script
starts only temporary test processes on the approved hosts and removes
temporary credential material during cleanup.

Required environment:
  MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR   Public address the approved client dials.
  MAVERICK_PUBLIC_SMOKE_SERVER_NAME   TLS server_name / SNI value.
  MAVERICK_PUBLIC_SMOKE_CLIENT_HOST   SSH host that runs the client data plane.

Optional environment:
  MAVERICK_PUBLIC_SMOKE_PORT          Remote Maverick TCP port, default 24443.
  MAVERICK_PUBLIC_SMOKE_TARGET_PORT   Remote loopback echo port, default 24444.
  MAVERICK_PUBLIC_SMOKE_FALLBACK_PORT Remote loopback fallback origin port,
                                      default TARGET_PORT + 1.
  MAVERICK_S2_BUILD_HOST              Default approved client host.
  MAVERICK_S2_PREBUILT_LINUX_BIN      Optional local x86_64 Linux binary.
  MAVERICK_S2_PREBUILT_COMMIT         Required with a prebuilt binary and must
                                      match the current git HEAD short id.
  MAVERICK_FAILURE_TEMP_FIREWALL      Set to 1 to open the server port with an
                                      auto-expiring firewalld runtime rule.
  MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED
                                      Required as 1 for server ports below 1024.
  MAVERICK_FAILURE_RUN_ID             Default timestamp-based id.
  MAVERICK_FAILURE_TIMEOUT_SECS       Temporary service lifetime, default 900.
The tested binary is built from local git HEAD on the build host, or supplied
as a commit-bound local prebuilt binary, and copied to the approved
server/client VMs as a temporary file. The server and client VMs do not need
Rust/Cargo installed unless they are also the build host.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

copy_remote_file() {
  local src_host="$1"
  local src_path="$2"
  local dst_host="$3"
  local dst_path="$4"

  if [[ "$src_host" == "$dst_host" ]]; then
    ssh "$dst_host" "SRC_PATH=$(shell_quote "$src_path") DST_PATH=$(shell_quote "$dst_path") bash -s" <<'REMOTE'
set -euo pipefail
cp "$SRC_PATH" "$DST_PATH"
REMOTE
    return 0
  fi

  scp -3 -q \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=2 \
    "$src_host:$src_path" \
    "$dst_host:$dst_path"
}

copy_build_artifact() {
  local dst_host="$1"
  local dst_path="$2"

  if [[ -n "$prebuilt_linux_bin" ]]; then
    scp -q "$prebuilt_artifact_gz" "$dst_host:$dst_path"
  else
    copy_remote_file "$build_host" "$build_artifact_gz" "$dst_host" "$dst_path"
  fi
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

record() {
  printf '%s\n' "$*" | tee -a "$tmpdir/events.log"
}

server_host="${1:-${MAVERICK_PUBLIC_SMOKE_REMOTE_HOST:-}}"
remote_addr="${MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR:-}"
server_name="${MAVERICK_PUBLIC_SMOKE_SERVER_NAME:-}"
client_host="${MAVERICK_PUBLIC_SMOKE_CLIENT_HOST:-}"
build_host="${MAVERICK_S2_BUILD_HOST:-$client_host}"
prebuilt_linux_bin="${MAVERICK_S2_PREBUILT_LINUX_BIN:-}"
prebuilt_commit="${MAVERICK_S2_PREBUILT_COMMIT:-}"
port="${MAVERICK_PUBLIC_SMOKE_PORT:-24443}"
target_port="${MAVERICK_PUBLIC_SMOKE_TARGET_PORT:-24444}"
fallback_port="${MAVERICK_PUBLIC_SMOKE_FALLBACK_PORT:-}"
privileged_port_approved="${MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED:-0}"
temp_firewall="${MAVERICK_FAILURE_TEMP_FIREWALL:-0}"
run_id="${MAVERICK_FAILURE_RUN_ID:-failure-$(date -u '+%Y%m%dT%H%M%SZ')}"
timeout_secs="${MAVERICK_FAILURE_TIMEOUT_SECS:-900}"
tested_commit="$(git rev-parse --short HEAD)"

require_non_empty "server ssh host" "$server_host"
require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR" "$remote_addr"
require_non_empty "MAVERICK_PUBLIC_SMOKE_SERVER_NAME" "$server_name"
require_non_empty "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST" "$client_host"
if [[ -z "$prebuilt_linux_bin" ]]; then
  require_non_empty "MAVERICK_S2_BUILD_HOST" "$build_host"
fi

if [[ -n "$prebuilt_linux_bin" ]]; then
  require_non_empty "MAVERICK_S2_PREBUILT_COMMIT" "$prebuilt_commit"
  if [[ "$prebuilt_commit" != "$tested_commit" ]]; then
    echo "MAVERICK_S2_PREBUILT_COMMIT must match current git HEAD $tested_commit" >&2
    exit 2
  fi
  if [[ ! -f "$prebuilt_linux_bin" || ! -r "$prebuilt_linux_bin" ]]; then
    echo "MAVERICK_S2_PREBUILT_LINUX_BIN must be a readable file" >&2
    exit 2
  fi
fi

if [[ ! "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "MAVERICK_FAILURE_RUN_ID must be a safe single path component" >&2
  exit 2
fi

python3 "$repo_root/scripts/approved-host-guard.py" "$server_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" "$client_host" >/dev/null
if [[ -z "$prebuilt_linux_bin" ]]; then
  python3 "$repo_root/scripts/approved-host-guard.py" "$build_host" >/dev/null
fi

case "$temp_firewall" in
  0 | 1) ;;
  *)
    echo "MAVERICK_FAILURE_TEMP_FIREWALL must be 0 or 1" >&2
    exit 2
    ;;
esac

case "$port:$target_port:$timeout_secs" in
  *[!0-9:]*)
    echo "ports and timeout must be numeric" >&2
    exit 2
    ;;
esac
if [[ -z "$fallback_port" ]]; then
  if (( target_port < 65535 )); then
    fallback_port=$((target_port + 1))
  else
    fallback_port=$((target_port - 1))
  fi
fi
case "$fallback_port" in
  *[!0-9]*)
    echo "fallback port must be numeric" >&2
    exit 2
    ;;
esac

if (( port < 1024 )) && [[ "$privileged_port_approved" != "1" ]]; then
  echo "MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED=1 is required for server ports below 1024" >&2
  exit 2
fi

secret="$(python3 - <<'PY'
import base64
import os

print("mv1_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
)"

tmpdir="$(mktemp -d)"
server_dir="/tmp/maverick-failure-injection-server-$run_id"
client_dir="/tmp/maverick-failure-injection-client-$run_id"
build_dir="/tmp/maverick-build-$run_id"
build_repo="$build_dir/repo"
build_bin="$build_repo/target/release/maverick"
build_artifact_gz="$build_dir/maverick-linux.gz"
prebuilt_artifact_gz="$tmpdir/maverick-linux-prebuilt.gz"
client_bin="$client_dir/maverick"
client_bin_gz="$client_bin.gz"
server_bin="$server_dir/maverick"
server_bin_gz="$server_bin.gz"
client_port=""
firewall_added=0

stop_server_pidfile() {
  local pidfile="$1"
  ssh "$server_host" \
    "SERVER_DIR=$(shell_quote "$server_dir") PIDFILE=$(shell_quote "$pidfile") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
path="$SERVER_DIR/$PIDFILE"
if [[ ! -f "$path" ]]; then
  exit 0
fi
pid="$(cat "$path" 2>/dev/null || true)"
if [[ -z "$pid" ]]; then
  exit 0
fi
command="$(ps -o args= -p "$pid" 2>/dev/null || true)"
case "$command" in
  *"$SERVER_DIR"*) ;;
  *) echo "refusing to stop server pid with unexpected command" >&2; exit 1 ;;
esac
pids="$pid $(pgrep -P "$pid" 2>/dev/null || true)"
kill $pids 2>/dev/null || true
sleep 1
alive=""
for p in $pids; do
  if kill -0 "$p" 2>/dev/null; then
    alive="$alive $p"
  fi
done
if [[ -n "$alive" ]]; then
  kill -KILL $alive 2>/dev/null || true
fi
REMOTE
}

stop_client() {
  ssh "$client_host" \
    "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
path="$CLIENT_DIR/client.pid"
if [[ ! -f "$path" ]]; then
  exit 0
fi
pid="$(cat "$path" 2>/dev/null || true)"
if [[ -z "$pid" ]]; then
  exit 0
fi
command="$(ps -o args= -p "$pid" 2>/dev/null || true)"
case "$command" in
  *"$CLIENT_DIR"*) ;;
  *) echo "refusing to stop client pid with unexpected command" >&2; exit 1 ;;
esac
pids="$pid $(pgrep -P "$pid" 2>/dev/null || true)"
kill $pids 2>/dev/null || true
sleep 1
alive=""
for p in $pids; do
  if kill -0 "$p" 2>/dev/null; then
    alive="$alive $p"
  fi
done
if [[ -n "$alive" ]]; then
  kill -KILL $alive 2>/dev/null || true
fi
REMOTE
}

close_test_firewall() {
  if [[ "$firewall_added" != "1" ]]; then
    return
  fi
  ssh "$server_host" "SERVER_PORT=$(shell_quote "$port") bash -s" <<'REMOTE' >/dev/null
set -euo pipefail
if sudo -n firewall-cmd --query-port="$SERVER_PORT/tcp" >/dev/null 2>&1; then
  sudo -n firewall-cmd --remove-port="$SERVER_PORT/tcp"
fi
REMOTE
  firewall_added=0
}

cleanup() {
  rc=$?
  stop_client
  stop_server_pidfile server.pid
  stop_server_pidfile echo.pid
  stop_server_pidfile stall.pid
  stop_server_pidfile fallback.pid
  close_test_firewall >/dev/null 2>&1 || true
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
rm -f "$SERVER_DIR/server.yaml" \
  "$SERVER_DIR/privkey.pem" \
  "$SERVER_DIR/fullchain.pem" \
  "$SERVER_DIR/ca.pem" \
  "$SERVER_DIR/ca-key.pem" \
  "$SERVER_DIR/ca.srl" \
  "$SERVER_DIR/leaf.csr" \
  "$SERVER_DIR/leaf.ext"
REMOTE
  ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
rm -f "$CLIENT_DIR/client.yaml" "$CLIENT_DIR/ca.pem"
REMOTE
  rm -rf "$tmpdir"
  exit "$rc"
}

trap cleanup EXIT

cat >"$tmpdir/server.yaml" <<YAML
version: 1
listen: "0.0.0.0:$port"
tls:
  cert_path: "$server_dir/fullchain.pem"
  key_path: "$server_dir/privkey.pem"
maverick:
  tunnel_path: "/assets/upload"
  mode_default: "auto"
  replay_window_secs: 120
  max_concurrent_flows_per_user: 16
users:
  - id: "u_failure_injection"
    name: "failure-injection"
    secret: "$secret"
    enabled: true
    rate_limit: null
    max_concurrent_flows: null
fallback:
  type: "reverse_proxy"
  upstream: "http://127.0.0.1:$fallback_port"
dns: null
metrics:
  enabled: false
  listen: "127.0.0.1:0"
log:
  level: "info"
  redact: true
advanced:
  idle_timeout_secs: 5
  tcp_connect_timeout_ms: 2000
  handshake_timeout_ms: 5000
  pre_auth_max_concurrent: 512
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
  max_frame_size: 65536
  egress:
    allow_loopback: true
YAML
chmod 600 "$tmpdir/server.yaml"

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
  credential_id: "u_failure_injection"
  secret: "$secret"
  ca_cert: "$client_dir/ca.pem"
  cert_pin: null
log:
  level: "info"
  redact: true
advanced:
  connect_timeout_ms: 5000
  idle_timeout_secs: 8
  max_concurrent_flows: 16
  padding: "off"
  allow_non_loopback_listeners: false
YAML
chmod 600 "$tmpdir/client.yaml"

record "run_id=$run_id"
record "started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
record "server_role=approved-server"
record "client_role=approved-client"
record "port=$port"
record "target_port=$target_port"
record "fallback_port=$fallback_port"
record "tested_commit=$tested_commit"

echo "==> preflight approved server ports"
if ssh "$server_host" "PORT=$(shell_quote "$port") TARGET_PORT=$(shell_quote "$target_port") FALLBACK_PORT=$(shell_quote "$fallback_port") bash -s" <<'REMOTE'
set -euo pipefail
if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || true) | grep -E ":(${PORT}|${TARGET_PORT}|${FALLBACK_PORT})\\b" >/dev/null; then
  exit 1
fi
REMOTE
then
  record "preflight_ports=free"
else
  echo "test ports are already listening on approved server" >&2
  exit 1
fi

echo "==> preflight approved host tools"
if [[ -z "$prebuilt_linux_bin" ]]; then
  ssh "$build_host" 'PATH="$HOME/.cargo/bin:$PATH"; command -v cargo >/dev/null && command -v tar >/dev/null && command -v gzip >/dev/null && command -v python3 >/dev/null'
else
  command -v gzip >/dev/null
fi
ssh "$client_host" 'command -v curl >/dev/null && curl --version | grep -q HTTP2 && command -v gzip >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null && command -v sha256sum >/dev/null'
ssh "$server_host" 'command -v python3 >/dev/null && command -v openssl >/dev/null && command -v timeout >/dev/null && command -v gzip >/dev/null && command -v sha256sum >/dev/null'
if [[ "$temp_firewall" == "1" ]]; then
  ssh "$server_host" 'command -v firewall-cmd >/dev/null && command -v sudo >/dev/null && sudo -n true && sudo -n firewall-cmd --state >/dev/null'
fi
if (( port < 1024 )); then
  ssh "$server_host" 'command -v sudo >/dev/null && command -v setcap >/dev/null && sudo -n true'
fi

if [[ -n "$prebuilt_linux_bin" ]]; then
  echo "==> package prebuilt Linux binary for current commit"
  gzip -c "$prebuilt_linux_bin" >"$prebuilt_artifact_gz"
  chmod 600 "$prebuilt_artifact_gz"
else
  echo "==> package source from current commit"
  git archive --format=tar.gz -o "$tmpdir/source.tar.gz" HEAD

  echo "==> build approved release binary"
  ssh "$build_host" "BUILD_DIR=$(shell_quote "$build_dir") bash -s" <<'REMOTE'
set -euo pipefail
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
REMOTE
  scp -q "$tmpdir/source.tar.gz" "$build_host:$build_dir/source.tar.gz"
  ssh "$build_host" "BUILD_DIR=$(shell_quote "$build_dir") BUILD_REPO=$(shell_quote "$build_repo") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$BUILD_REPO"
tar -xzf "$BUILD_DIR/source.tar.gz" -C "$BUILD_REPO"
PATH="$HOME/.cargo/bin:$PATH" cargo build --release --manifest-path "$BUILD_REPO/Cargo.toml" -p maverick-cli
REMOTE
  ssh "$build_host" "BUILD_BIN=$(shell_quote "$build_bin") BUILD_ARTIFACT_GZ=$(shell_quote "$build_artifact_gz") bash -s" <<'REMOTE'
set -euo pipefail
gzip -c "$BUILD_BIN" >"$BUILD_ARTIFACT_GZ"
chmod 600 "$BUILD_ARTIFACT_GZ"
REMOTE
fi

echo "==> prepare approved server"
ssh "$server_host" \
  "SERVER_DIR=$(shell_quote "$server_dir") SERVER_NAME=$(shell_quote "$server_name") TARGET_PORT=$(shell_quote "$target_port") bash -s" <<'REMOTE'
set -euo pipefail
umask 077
mkdir -p "$SERVER_DIR/public"
printf '%s\n' '<html><body>Maverick failure injection fallback</body></html>' \
  >"$SERVER_DIR/public/index.html"

san="DNS:$SERVER_NAME"
if [[ "$SERVER_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  san="IP:$SERVER_NAME"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=Maverick failure injection test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$SERVER_DIR/ca-key.pem" \
  -out "$SERVER_DIR/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=$SERVER_NAME" \
  -keyout "$SERVER_DIR/privkey.pem" \
  -out "$SERVER_DIR/leaf.csr" >/dev/null 2>&1
cat >"$SERVER_DIR/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
openssl x509 -req -in "$SERVER_DIR/leaf.csr" \
  -CA "$SERVER_DIR/ca.pem" \
  -CAkey "$SERVER_DIR/ca-key.pem" \
  -CAcreateserial \
  -days 2 \
  -out "$SERVER_DIR/fullchain.pem" \
  -extfile "$SERVER_DIR/leaf.ext" >/dev/null 2>&1
chmod 600 "$SERVER_DIR/fullchain.pem" "$SERVER_DIR/privkey.pem" "$SERVER_DIR/ca.pem"

cat >"$SERVER_DIR/echo.py" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(32)
print("echo-listening", flush=True)
while True:
    conn, addr = sock.accept()
    data = conn.recv(4096)
    print("echo-peer=%s:%s bytes=%d" % (addr[0], addr[1], len(data)), flush=True)
    conn.sendall(data)
    conn.close()
PY

cat >"$SERVER_DIR/stall.py" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(32)
print("stall-listening", flush=True)
while True:
    conn, addr = sock.accept()
    data = conn.recv(4096)
    print("stall-peer=%s:%s bytes=%d" % (addr[0], addr[1], len(data)), flush=True)
    time.sleep(30)
    conn.close()
PY

cat >"$SERVER_DIR/fallback.py" <<'PY'
import socket
import sys

port = int(sys.argv[1])
body = b"fallback-origin-ok\n"
response = (
    b"HTTP/1.1 200 OK\r\n"
    b"content-type: text/plain; charset=utf-8\r\n"
    + b"content-length: " + str(len(body)).encode() + b"\r\n"
    + b"connection: close\r\n"
    + b"\r\n"
    + body
)
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(32)
print("fallback-listening", flush=True)
while True:
    conn, addr = sock.accept()
    request = conn.recv(4096)
    print("fallback-peer=%s:%s bytes=%d" % (addr[0], addr[1], len(request)), flush=True)
    conn.sendall(response)
    conn.close()
PY
chmod 700 "$SERVER_DIR/echo.py" "$SERVER_DIR/stall.py" "$SERVER_DIR/fallback.py"
REMOTE

scp -q "$tmpdir/server.yaml" "$server_host:$server_dir/server.yaml"
copy_build_artifact "$server_host" "$server_bin_gz"
ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") SERVER_BIN=$(shell_quote "$server_bin") SERVER_BIN_GZ=$(shell_quote "$server_bin_gz") SERVER_PORT=$(shell_quote "$port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") TEMP_FIREWALL=$(shell_quote "$temp_firewall") bash -s" <<'REMOTE'
set -euo pipefail
gzip -dc "$SERVER_BIN_GZ" >"$SERVER_BIN"
rm -f "$SERVER_BIN_GZ"
chmod 700 "$SERVER_BIN"
"$SERVER_BIN" --version >"$SERVER_DIR/binary-version.log"
if (( SERVER_PORT < 1024 )); then
  sudo -n setcap cap_net_bind_service=+ep "$SERVER_BIN"
fi
{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "requested=$TEMP_FIREWALL"
  echo "port=$SERVER_PORT/tcp"
  echo "expiry_secs=$TIMEOUT_SECS"
  if [[ "$TEMP_FIREWALL" == "1" ]]; then
    if sudo -n firewall-cmd --query-port="$SERVER_PORT/tcp" >/dev/null 2>&1; then
      echo "state_before=open"
      echo "action=refused_existing_rule"
      echo "temporary firewall mode requires a port that is initially closed" >&2
      exit 1
    fi
    echo "state_before=closed"
    sudo -n firewall-cmd --add-port="$SERVER_PORT/tcp" --timeout="${TIMEOUT_SECS}s"
    echo "action=temporarily_opened"
    if sudo -n firewall-cmd --query-port="$SERVER_PORT/tcp" >/dev/null 2>&1; then
      echo "state_after=open"
    else
      echo "state_after=closed"
      exit 1
    fi
  else
    echo "action=disabled"
  fi
} >"$SERVER_DIR/firewall.log"
{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "binary_sha256=$(sha256sum "$SERVER_BIN" | awk '{print $1}')"
  echo "logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  uname -a
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  df -P -B1 "$SERVER_DIR" 2>/dev/null || df -P "$SERVER_DIR"
} >"$SERVER_DIR/system-inventory.log"
REMOTE
if [[ "$temp_firewall" == "1" ]]; then
  firewall_added=1
fi
scp -q "$server_host:$server_dir/ca.pem" "$tmpdir/ca.pem"

echo "==> prepare approved client"
ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
umask 077
mkdir -p "$CLIENT_DIR"
rm -f "$CLIENT_DIR/completed.marker" "$CLIENT_DIR/failed.marker"
: >"$CLIENT_DIR/failed.marker"
REMOTE
copy_build_artifact "$client_host" "$client_bin_gz"
ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_BIN=$(shell_quote "$client_bin") CLIENT_BIN_GZ=$(shell_quote "$client_bin_gz") bash -s" <<'REMOTE'
set -euo pipefail
gzip -dc "$CLIENT_BIN_GZ" >"$CLIENT_BIN"
rm -f "$CLIENT_BIN_GZ"
chmod 700 "$CLIENT_BIN"
"$CLIENT_BIN" --version >"$CLIENT_DIR/binary-version.log"
{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "binary_sha256=$(sha256sum "$CLIENT_BIN" | awk '{print $1}')"
  echo "logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  uname -a
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  df -P -B1 "$CLIENT_DIR" 2>/dev/null || df -P "$CLIENT_DIR"
} >"$CLIENT_DIR/system-inventory.log"
REMOTE
scp -q "$tmpdir/client.yaml" "$client_host:$client_dir/client.yaml"
scp -q "$tmpdir/ca.pem" "$client_host:$client_dir/ca.pem"

server_version="$(ssh "$server_host" "SERVER_BIN=$(shell_quote "$server_bin") bash -s" <<'REMOTE'
set -euo pipefail
"$SERVER_BIN" --version
REMOTE
)"
client_version="$(ssh "$client_host" "CLIENT_BIN=$(shell_quote "$client_bin") bash -s" <<'REMOTE'
set -euo pipefail
"$CLIENT_BIN" --version
REMOTE
)"
server_sha256="$(ssh "$server_host" "sha256sum $(shell_quote "$server_bin") | awk '{print \$1}'")"
client_sha256="$(ssh "$client_host" "sha256sum $(shell_quote "$client_bin") | awk '{print \$1}'")"
record "server_binary_version=$server_version"
record "client_binary_version=$client_version"
record "server_binary_sha256=$server_sha256"
record "client_binary_sha256=$client_sha256"
record "server_commit=$tested_commit"
record "client_commit=$tested_commit"

capture_resources() {
  local label="$1"
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
{
  echo "sample_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "label=$LABEL"
  cat /proc/loadavg 2>/dev/null || true
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  for pidfile in server.pid echo.pid stall.pid fallback.pid; do
    test -f "$SERVER_DIR/$pidfile" || continue
    pid="$(cat "$SERVER_DIR/$pidfile" 2>/dev/null || true)"
    ps -o pid=,ppid=,etime=,%cpu=,%mem=,rss=,vsz=,stat=,comm= \
      -p "$pid" --ppid "$pid" 2>/dev/null || true
  done
  cat /proc/net/dev 2>/dev/null || true
  echo "sample_end"
} >>"$SERVER_DIR/resource-metrics.log"
REMOTE
  ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
{
  echo "sample_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "label=$LABEL"
  cat /proc/loadavg 2>/dev/null || true
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  if test -f "$CLIENT_DIR/client.pid"; then
    pid="$(cat "$CLIENT_DIR/client.pid" 2>/dev/null || true)"
    ps -o pid=,ppid=,etime=,%cpu=,%mem=,rss=,vsz=,stat=,comm= \
      -p "$pid" --ppid "$pid" 2>/dev/null || true
  fi
  cat /proc/net/dev 2>/dev/null || true
  echo "sample_end"
} >>"$CLIENT_DIR/resource-metrics.log"
REMOTE
}

start_server() {
  ssh "$server_host" \
    "SERVER_DIR=$(shell_quote "$server_dir") SERVER_BIN=$(shell_quote "$server_bin") SERVER_BIN_GZ=$(shell_quote "$server_bin_gz") TIMEOUT_SECS=$(shell_quote "$timeout_secs") SERVER_PORT=$(shell_quote "$port") bash -s" <<'REMOTE'
set -euo pipefail
if [[ -f "$SERVER_BIN_GZ" ]]; then
  gzip -dc "$SERVER_BIN_GZ" >"$SERVER_BIN"
  rm -f "$SERVER_BIN_GZ"
fi
chmod 700 "$SERVER_BIN"
if (( SERVER_PORT < 1024 )); then
  sudo -n setcap cap_net_bind_service=+ep "$SERVER_BIN"
fi
echo "server_start_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >>"$SERVER_DIR/server.log"
nohup timeout "${TIMEOUT_SECS}s" "$SERVER_BIN" server -c "$SERVER_DIR/server.yaml" \
  </dev/null \
  >>"$SERVER_DIR/server.log" 2>&1 &
echo $! >"$SERVER_DIR/server.pid"
REMOTE
}

wait_server_ready() {
  for _ in $(seq 1 30); do
    if ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE' >/dev/null 2>&1
set -euo pipefail
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
REMOTE
    then
      return 0
    fi
    sleep 1
  done
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
REMOTE
}

start_echo() {
  local label="$1"
  ssh "$server_host" \
    "SERVER_DIR=$(shell_quote "$server_dir") TARGET_PORT=$(shell_quote "$target_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
nohup timeout "${TIMEOUT_SECS}s" python3 -u "$SERVER_DIR/echo.py" "$TARGET_PORT" \
  </dev/null \
  >"$SERVER_DIR/echo-${LABEL}.log" 2>&1 &
echo $! >"$SERVER_DIR/echo.pid"
REMOTE
  for _ in $(seq 1 20); do
    if ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE' >/dev/null 2>&1
set -euo pipefail
grep -q 'echo-listening' "$SERVER_DIR/echo-${LABEL}.log"
REMOTE
    then
      return 0
    fi
    sleep 1
  done
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'echo-listening' "$SERVER_DIR/echo-${LABEL}.log"
REMOTE
}

start_stall() {
  local label="$1"
  ssh "$server_host" \
    "SERVER_DIR=$(shell_quote "$server_dir") TARGET_PORT=$(shell_quote "$target_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
nohup timeout "${TIMEOUT_SECS}s" python3 -u "$SERVER_DIR/stall.py" "$TARGET_PORT" \
  </dev/null \
  >"$SERVER_DIR/stall-${LABEL}.log" 2>&1 &
echo $! >"$SERVER_DIR/stall.pid"
REMOTE
  for _ in $(seq 1 20); do
    if ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE' >/dev/null 2>&1
set -euo pipefail
grep -q 'stall-listening' "$SERVER_DIR/stall-${LABEL}.log"
REMOTE
    then
      return 0
    fi
    sleep 1
  done
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'stall-listening' "$SERVER_DIR/stall-${LABEL}.log"
REMOTE
}

start_fallback() {
  local label="$1"
  ssh "$server_host" \
    "SERVER_DIR=$(shell_quote "$server_dir") FALLBACK_PORT=$(shell_quote "$fallback_port") TIMEOUT_SECS=$(shell_quote "$timeout_secs") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
nohup timeout "${TIMEOUT_SECS}s" python3 -u "$SERVER_DIR/fallback.py" "$FALLBACK_PORT" \
  </dev/null \
  >"$SERVER_DIR/fallback-${LABEL}.log" 2>&1 &
echo $! >"$SERVER_DIR/fallback.pid"
REMOTE
  for _ in $(seq 1 20); do
    if ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE' >/dev/null 2>&1
set -euo pipefail
grep -q 'fallback-listening' "$SERVER_DIR/fallback-${LABEL}.log"
REMOTE
    then
      return 0
    fi
    sleep 1
  done
  ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'fallback-listening' "$SERVER_DIR/fallback-${LABEL}.log"
REMOTE
}

start_client() {
  local label="$1"
  ssh "$client_host" \
    "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_BIN=$(shell_quote "$client_bin") TIMEOUT_SECS=$(shell_quote "$timeout_secs") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
nohup timeout "${TIMEOUT_SECS}s" "$CLIENT_BIN" client -c "$CLIENT_DIR/client.yaml" \
  </dev/null \
  >"$CLIENT_DIR/client-${LABEL}.log" 2>&1 &
echo $! >"$CLIENT_DIR/client.pid"
REMOTE
  client_port=""
  for _ in $(seq 1 30); do
    client_port="$(ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") LABEL=$(shell_quote "$label") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$CLIENT_DIR/client-${LABEL}.log" <<'PY'
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
      return 0
    fi
    sleep 1
  done
  echo "client listener did not become ready" >&2
  exit 1
}

run_fallback_probe() {
  local scenario="$1"
  local phase="$2"
  local expected="$3"
  local out
  if out="$(ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") REMOTE_ADDR=$(shell_quote "$remote_addr") SERVER_NAME=$(shell_quote "$server_name") PORT=$(shell_quote "$port") EXPECTED=$(shell_quote "$expected") bash -s" <<'REMOTE'
set -euo pipefail
body="$(mktemp)"
err="$(mktemp)"
trap 'rm -f "$body" "$err"' EXIT
set +e
http_code="$(curl --silent --show-error --http2 \
  --cacert "$CLIENT_DIR/ca.pem" \
  --connect-to "$SERVER_NAME:$PORT:$REMOTE_ADDR:$PORT" \
  --output "$body" \
  --write-out '%{http_code}' \
  "https://$SERVER_NAME:$PORT/" 2>"$err")"
curl_rc=$?
set -e
combined="$(head -c 400 "$body" 2>/dev/null || true; printf '\n'; head -c 400 "$err" 2>/dev/null || true)"
if printf '%s' "$combined" | grep -Eiq 'socks|tunnel|credential|secret|auth|maverick'; then
  echo "result=protocol_detail_leak http_code=$http_code curl_rc=$curl_rc"
  exit 1
fi
if [[ "$EXPECTED" == "pass" ]]; then
  if [[ "$curl_rc" == "0" && "$http_code" == "200" ]] && grep -q 'fallback-origin-ok' "$body"; then
    echo "result=pass http_code=$http_code"
    exit 0
  fi
  echo "result=unexpected_fallback_response http_code=$http_code curl_rc=$curl_rc"
  exit 1
fi
if [[ "$curl_rc" != "0" || "$http_code" == "000" || "$http_code" == 5* ]]; then
  echo "result=fallback_unavailable http_code=$http_code curl_rc=$curl_rc"
  exit 0
fi
echo "result=unexpected_fallback_success http_code=$http_code curl_rc=$curl_rc"
exit 1
REMOTE
)"; then
    record "CHECK utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ') scenario=$scenario phase=$phase expected=$expected $out"
  else
    rc=$?
    record "CHECK utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ') scenario=$scenario phase=$phase expected=$expected result=unexpected rc=$rc output=${out:-none}"
    exit "$rc"
  fi
}

run_flow() {
  local scenario="$1"
  local phase="$2"
  local expected="$3"
  local out
  if out="$(ssh "$client_host" "CLIENT_PORT=$(shell_quote "$client_port") TARGET_PORT=$(shell_quote "$target_port") EXPECTED=$(shell_quote "$expected") LABEL=$(shell_quote "$scenario-$phase") bash -s" <<'REMOTE'
set -euo pipefail
python3 - "$CLIENT_PORT" "$TARGET_PORT" "$EXPECTED" "$LABEL" <<'PY'
import socket
import struct
import sys

client_port = int(sys.argv[1])
target_port = int(sys.argv[2])
expected = sys.argv[3]
label = sys.argv[4]
payload = ("maverick-failure-injection:" + label).encode()

sock = socket.create_connection(("127.0.0.1", client_port), timeout=10)
sock.settimeout(15)
sock.sendall(b"\x05\x01\x00")
method = sock.recv(2)
if method != b"\x05\x00":
    print(f"result=unexpected_socks_method method={method!r}")
    raise SystemExit(1)

request = b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + struct.pack("!H", target_port)
sock.sendall(request)
reply = sock.recv(10)
if len(reply) != 10:
    print(f"result=unexpected_short_reply len={len(reply)}")
    raise SystemExit(1)
if reply[1] != 0:
    print(f"result=connect_fail socks_code={reply[1]}")
    raise SystemExit(0 if expected == "connect_fail" else 1)
if expected == "connect_fail":
    print("result=unexpected_connect_success")
    raise SystemExit(1)

sock.sendall(payload)
received = b""
try:
    while len(received) < len(payload):
        chunk = sock.recv(4096)
        if not chunk:
            break
        received += chunk
except socket.timeout:
    print("result=stall_timeout")
    raise SystemExit(0 if expected == "stall" else 1)

if received == payload:
    print("result=pass")
    raise SystemExit(0 if expected == "pass" else 1)

if expected == "stall":
    print(f"result=stall_closed bytes={len(received)}")
    raise SystemExit(0)

print(f"result=unexpected_echo_mismatch bytes={len(received)}")
raise SystemExit(1)
PY
REMOTE
)"; then
    record "CHECK utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ') scenario=$scenario phase=$phase expected=$expected $out"
  else
    rc=$?
    record "CHECK utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ') scenario=$scenario phase=$phase expected=$expected result=unexpected rc=$rc output=${out:-none}"
    exit "$rc"
  fi
}

echo "==> start baseline services"
start_echo initial
start_fallback initial
start_server
wait_server_ready
start_client initial
capture_resources baseline_ready

run_flow server_restart baseline pass
stop_server_pidfile server.pid
run_flow server_restart server_down connect_fail
start_server
wait_server_ready
run_flow server_restart recovered pass
capture_resources server_restart_recovered

run_flow client_restart before_restart pass
stop_client
start_client restart_one
run_flow client_restart after_restart_one pass
stop_client
start_client restart_two
run_flow client_restart after_restart_two pass
capture_resources client_restart_recovered

run_flow upstream_echo_failure baseline pass
stop_server_pidfile echo.pid
run_flow upstream_echo_failure echo_down connect_fail
start_echo recovered
run_flow upstream_echo_failure recovered pass
capture_resources echo_failure_recovered

run_fallback_probe fallback_target_failure baseline pass
stop_server_pidfile fallback.pid
run_fallback_probe fallback_target_failure origin_down fallback_fail
run_flow fallback_target_failure tunnel_while_origin_down pass
start_fallback recovered
run_fallback_probe fallback_target_failure recovered pass
capture_resources fallback_failure_recovered

stop_server_pidfile echo.pid
start_stall stall
run_flow upstream_stall_timeout stalled stall
stop_server_pidfile stall.pid
start_echo after_stall
run_flow upstream_stall_timeout recovered pass
capture_resources stall_recovered

finished_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
record "finished_utc=$finished_utc"
check_count="$(grep -c '^CHECK ' "$tmpdir/events.log" || true)"
pass_count="$(grep -c 'result=pass' "$tmpdir/events.log" || true)"
connect_fail_count="$(grep -c 'result=connect_fail' "$tmpdir/events.log" || true)"
stall_count="$(grep -Ec 'result=stall_(timeout|closed)' "$tmpdir/events.log" || true)"
fallback_fail_count="$(grep -c 'result=fallback_unavailable' "$tmpdir/events.log" || true)"
server_resource_samples="$(ssh "$server_host" "grep -c '^sample_utc=' $(shell_quote "$server_dir/resource-metrics.log") 2>/dev/null || true")"
client_resource_samples="$(ssh "$client_host" "grep -c '^sample_utc=' $(shell_quote "$client_dir/resource-metrics.log") 2>/dev/null || true")"
record "checks=$check_count"
record "pass_results=$pass_count"
record "controlled_connect_failures=$connect_fail_count"
record "controlled_stall_results=$stall_count"
record "controlled_fallback_failures=$fallback_fail_count"
record "server_resource_samples=${server_resource_samples:-0}"
record "client_resource_samples=${client_resource_samples:-0}"

ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE' >/dev/null
set -euo pipefail
mkdir -p "$CLIENT_DIR"
REMOTE
scp -q "$tmpdir/events.log" "$client_host:$client_dir/events.log"
cat >"$tmpdir/SUMMARY.md" <<EOF
# Maverick Approved-Host Failure Injection Smoke

- run_id: $run_id
- finished_utc: $finished_utc
- server_role: approved-server
- client_role: approved-client
- server_binary_version: $server_version
- client_binary_version: $client_version
- server_binary_sha256: $server_sha256
- client_binary_sha256: $client_sha256
- server_commit: $tested_commit
- client_commit: $tested_commit
- public_server_port: $port
- loopback_target_port: $target_port
- loopback_fallback_port: $fallback_port
- checks: $check_count
- pass_results: $pass_count
- controlled_connect_failures: $connect_fail_count
- controlled_stall_results: $stall_count
- controlled_fallback_failures: $fallback_fail_count
- server_resource_samples: ${server_resource_samples:-0}
- client_resource_samples: ${client_resource_samples:-0}
- resource_process_children: enabled
EOF
scp -q "$tmpdir/SUMMARY.md" "$client_host:$client_dir/SUMMARY.md"

stop_client
stop_server_pidfile server.pid
stop_server_pidfile echo.pid
stop_server_pidfile stall.pid
stop_server_pidfile fallback.pid
close_test_firewall
record "post_cleanup_firewall=closed_or_disabled"

listener_output="$(ssh "$server_host" "PORT=$(shell_quote "$port") TARGET_PORT=$(shell_quote "$target_port") FALLBACK_PORT=$(shell_quote "$fallback_port") bash -s" <<'REMOTE'
set -euo pipefail
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) | grep -E ":(${PORT}|${TARGET_PORT}|${FALLBACK_PORT})\\b" || true
REMOTE
)"
if [[ -n "$listener_output" ]]; then
  echo "temporary test ports still listening after cleanup:" >&2
  echo "$listener_output" >&2
  exit 1
fi
record "post_cleanup_ports=free"
ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
rm -f "$SERVER_DIR/server.yaml" \
  "$SERVER_DIR/privkey.pem" \
  "$SERVER_DIR/fullchain.pem" \
  "$SERVER_DIR/ca.pem" \
  "$SERVER_DIR/ca-key.pem" \
  "$SERVER_DIR/ca.srl" \
  "$SERVER_DIR/leaf.csr" \
  "$SERVER_DIR/leaf.ext"
for path in server.yaml privkey.pem fullchain.pem ca.pem ca-key.pem ca.srl leaf.csr leaf.ext; do
  test ! -e "$SERVER_DIR/$path"
done
REMOTE
ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
if test -f "$CLIENT_DIR/client.pid"; then
  pid="$(cat "$CLIENT_DIR/client.pid" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "temporary client process still running" >&2
    exit 1
  fi
fi
rm -f "$CLIENT_DIR/client.yaml" "$CLIENT_DIR/ca.pem"
test ! -e "$CLIENT_DIR/client.yaml"
test ! -e "$CLIENT_DIR/ca.pem"
REMOTE
record "post_cleanup_credentials=absent"
cat >>"$tmpdir/SUMMARY.md" <<EOF
- post_cleanup_ports: free
- post_cleanup_firewall: closed_or_disabled
- post_cleanup_credentials: absent
EOF
scp -q "$tmpdir/SUMMARY.md" "$client_host:$client_dir/SUMMARY.md"
scp -q "$tmpdir/events.log" "$client_host:$client_dir/events.log"
ssh "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
rm -f "$CLIENT_DIR/failed.marker"
touch "$CLIENT_DIR/completed.marker"
REMOTE

echo "approved-host failure injection smoke OK"
echo "run_id=$run_id"
echo "summary: ssh <approved-client-host> 'cat $client_dir/SUMMARY.md'"
