#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-detached-tcp-longhaul.sh <server-ssh-host>

Starts a detached approved-host TCP long-haul smoke:
- server and echo run on the server SSH host with timeout;
- the client loop runs on MAVERICK_PUBLIC_SMOKE_CLIENT_HOST;
- the local machine only starts the run and can disconnect afterward.

Required environment:
  MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR
  MAVERICK_PUBLIC_SMOKE_SERVER_NAME
  MAVERICK_PUBLIC_SMOKE_CLIENT_HOST

Certificate environment:
  MAVERICK_PUBLIC_SMOKE_REMOTE_CERT   Required unless generating a test cert.
  MAVERICK_PUBLIC_SMOKE_REMOTE_KEY    Required unless generating a test cert.

Optional environment:
  MAVERICK_PUBLIC_SMOKE_PORT          Default 24443.
  MAVERICK_PUBLIC_SMOKE_TARGET_PORT   Default 24444.
  MAVERICK_S2_BUILD_HOST              Default approved client host.
  MAVERICK_S2_PREBUILT_LINUX_BIN      Optional local x86_64 Linux binary.
  MAVERICK_S2_PREBUILT_COMMIT         Required with a prebuilt binary and must
                                      match the current git HEAD short id.
  MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED
                                      Required as 1 for server ports below 1024.
  MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL
                                      Set to 1 to open the server port with an
                                      auto-expiring firewalld runtime rule.
  MAVERICK_LONGHAUL_DURATION_SECS     Default 3600.
  MAVERICK_LONGHAUL_INTERVAL_SECS     Default 300.
  MAVERICK_LONGHAUL_RESOURCE_INTERVAL_SECS
                                      Default 60.
  MAVERICK_DETACHED_RUN_ID            Default timestamp-based id.
  MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT
                                      Set to 1 to generate a per-run self-signed
                                      test certificate on the approved server
                                      and trust only that certificate on the
                                      approved client.

The tested binary is built from the local git HEAD on the build host and copied
to the approved server/client VMs as a temporary file. The server and client
VMs do not need Rust/Cargo installed unless they are also the build host.
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

server_host="${1:-${MAVERICK_PUBLIC_SMOKE_REMOTE_HOST:-}}"
remote_addr="${MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR:-}"
server_name="${MAVERICK_PUBLIC_SMOKE_SERVER_NAME:-}"
remote_cert="${MAVERICK_PUBLIC_SMOKE_REMOTE_CERT:-}"
remote_key="${MAVERICK_PUBLIC_SMOKE_REMOTE_KEY:-}"
client_host="${MAVERICK_PUBLIC_SMOKE_CLIENT_HOST:-}"
build_host="${MAVERICK_S2_BUILD_HOST:-$client_host}"
prebuilt_linux_bin="${MAVERICK_S2_PREBUILT_LINUX_BIN:-}"
prebuilt_commit="${MAVERICK_S2_PREBUILT_COMMIT:-}"
generate_test_cert="${MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT:-0}"
port="${MAVERICK_PUBLIC_SMOKE_PORT:-24443}"
target_port="${MAVERICK_PUBLIC_SMOKE_TARGET_PORT:-24444}"
privileged_port_approved="${MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED:-0}"
temp_firewall="${MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL:-0}"
duration_secs="${MAVERICK_LONGHAUL_DURATION_SECS:-3600}"
interval_secs="${MAVERICK_LONGHAUL_INTERVAL_SECS:-300}"
resource_interval_secs="${MAVERICK_LONGHAUL_RESOURCE_INTERVAL_SECS:-60}"
run_id="${MAVERICK_DETACHED_RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')}"
tested_commit="$(git rev-parse --short HEAD)"

require_non_empty "server ssh host" "$server_host"
require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR" "$remote_addr"
require_non_empty "MAVERICK_PUBLIC_SMOKE_SERVER_NAME" "$server_name"
require_non_empty "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST" "$client_host"

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
else
  require_non_empty "MAVERICK_S2_BUILD_HOST" "$build_host"
fi

if [[ ! "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "MAVERICK_DETACHED_RUN_ID must be a safe single path component" >&2
  exit 2
fi

python3 "$repo_root/scripts/approved-host-guard.py" "$server_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" "$client_host" >/dev/null
if [[ -z "$prebuilt_linux_bin" ]]; then
  python3 "$repo_root/scripts/approved-host-guard.py" "$build_host" >/dev/null
fi

case "$generate_test_cert" in
  0 | 1) ;;
  *)
    echo "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT must be 0 or 1" >&2
    exit 2
    ;;
esac

case "$temp_firewall" in
  0 | 1) ;;
  *)
    echo "MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL must be 0 or 1" >&2
    exit 2
    ;;
esac

if [[ "$generate_test_cert" != "1" ]]; then
  require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_CERT" "$remote_cert"
  require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_KEY" "$remote_key"
fi

case "$port:$target_port:$duration_secs:$interval_secs:$resource_interval_secs" in
  *[!0-9:]*)
    echo "ports, duration, and interval must be numeric" >&2
    exit 2
    ;;
esac

if (( duration_secs < 60 || duration_secs > 86400 || interval_secs < 1 || resource_interval_secs < 1 )); then
  echo "duration must be between 60 and 86400 seconds and intervals must be positive" >&2
  exit 2
fi

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
trap 'rm -rf "$tmpdir"' EXIT

server_dir="/tmp/maverick-detached-longhaul-server-$run_id"
client_dir="/tmp/maverick-detached-longhaul-client-$run_id"
build_dir="/tmp/maverick-build-$run_id"
build_repo="$build_dir/repo"
build_bin="$build_repo/target/release/maverick"
build_artifact_gz="$build_dir/maverick-linux.gz"
prebuilt_artifact_gz="$tmpdir/maverick-linux-prebuilt.gz"
client_bin="$client_dir/maverick"
client_bin_gz="$client_bin.gz"
server_bin="$server_dir/maverick"
server_bin_gz="$server_bin.gz"
server_timeout=$((duration_secs + interval_secs + 300))
if [[ "$generate_test_cert" == "1" ]]; then
  client_ca_cert="\"$client_dir/ca.pem\""
else
  client_ca_cert="null"
fi

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
  - id: "u_detached_longhaul"
    name: "detached-longhaul"
    secret: "$secret"
    enabled: true
    rate_limit: null
    max_concurrent_flows: null
fallback:
  type: "static"
  static_dir: "$server_dir/public"
  index: "index.html"
dns: null
metrics:
  enabled: false
  listen: "127.0.0.1:0"
log:
  level: "info"
  redact: true
advanced:
  idle_timeout_secs: 60
  tcp_connect_timeout_ms: 5000
  handshake_timeout_ms: 10000
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
  credential_id: "u_detached_longhaul"
  secret: "$secret"
  ca_cert: $client_ca_cert
  cert_pin: null
log:
  level: "info"
  redact: true
advanced:
  connect_timeout_ms: 5000
  idle_timeout_secs: 60
  max_concurrent_flows: 16
  padding: "off"
  allow_non_loopback_listeners: false
YAML
chmod 600 "$tmpdir/client.yaml"

echo "==> preflight approved host tools"
if [[ -z "$prebuilt_linux_bin" ]]; then
  ssh "$build_host" 'PATH="$HOME/.cargo/bin:$PATH"; command -v cargo >/dev/null && command -v tar >/dev/null && command -v gzip >/dev/null && command -v python3 >/dev/null'
fi
ssh "$client_host" 'command -v gzip >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null && command -v nohup >/dev/null && command -v sha256sum >/dev/null && command -v ps >/dev/null'
ssh "$server_host" 'command -v python3 >/dev/null && command -v openssl >/dev/null && command -v timeout >/dev/null && command -v gzip >/dev/null && command -v sha256sum >/dev/null && command -v ps >/dev/null'
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

echo "==> prepare detached server on $server_host:$port"
ssh "$server_host" \
  "SERVER_DIR=$(shell_quote "$server_dir") REMOTE_CERT=$(shell_quote "$remote_cert") REMOTE_KEY=$(shell_quote "$remote_key") SERVER_PORT=$(shell_quote "$port") TARGET_PORT=$(shell_quote "$target_port") SERVER_TIMEOUT=$(shell_quote "$server_timeout") GENERATE_TEST_CERT=$(shell_quote "$generate_test_cert") SERVER_NAME=$(shell_quote "$server_name") bash -s" <<'REMOTE'
set -euo pipefail
umask 077
mkdir -p "$SERVER_DIR/public"
python3 - "$SERVER_PORT" "$TARGET_PORT" >"$SERVER_DIR/port-preflight.log" 2>&1 <<'PY'
import socket
import sys

checks = (("0.0.0.0", int(sys.argv[1])), ("127.0.0.1", int(sys.argv[2])))
sockets = []
try:
    for host, port in checks:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sockets.append(sock)
        print(f"available={host}:{port}")
finally:
    for sock in sockets:
        sock.close()
PY
printf '%s\n' '<html><body>Maverick detached long-haul fallback</body></html>' \
  >"$SERVER_DIR/public/index.html"

if [[ "$GENERATE_TEST_CERT" == "1" ]]; then
  san="DNS:$SERVER_NAME"
  if [[ "$SERVER_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san="IP:$SERVER_NAME"
  fi
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=Maverick detached long-haul test CA" \
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
elif [[ -r "$REMOTE_CERT" && -r "$REMOTE_KEY" ]]; then
  install -m 600 "$REMOTE_CERT" "$SERVER_DIR/fullchain.pem"
  install -m 600 "$REMOTE_KEY" "$SERVER_DIR/privkey.pem"
else
  sudo -n install -m 600 -o "$(id -un)" -g "$(id -gn)" "$REMOTE_CERT" "$SERVER_DIR/fullchain.pem"
  sudo -n install -m 600 -o "$(id -un)" -g "$(id -gn)" "$REMOTE_KEY" "$SERVER_DIR/privkey.pem"
fi
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
nohup timeout "${SERVER_TIMEOUT}s" python3 -u "$SERVER_DIR/echo.py" "$TARGET_PORT" \
  </dev/null \
  >"$SERVER_DIR/echo.log" 2>&1 &
echo $! >"$SERVER_DIR/echo.pid"
REMOTE

if [[ "$generate_test_cert" == "1" ]]; then
  scp -q "$server_host:$server_dir/ca.pem" "$tmpdir/ca.pem"
fi

scp -q "$tmpdir/server.yaml" "$server_host:$server_dir/server.yaml"
copy_build_artifact "$server_host" "$server_bin_gz"

ssh "$server_host" \
  "SERVER_DIR=$(shell_quote "$server_dir") SERVER_BIN=$(shell_quote "$server_bin") SERVER_BIN_GZ=$(shell_quote "$server_bin_gz") SERVER_TIMEOUT=$(shell_quote "$server_timeout") SERVER_PORT=$(shell_quote "$port") RESOURCE_INTERVAL_SECS=$(shell_quote "$resource_interval_secs") TEMP_FIREWALL=$(shell_quote "$temp_firewall") bash -s" <<'REMOTE'
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
  echo "expiry_secs=$SERVER_TIMEOUT"
  if [[ "$TEMP_FIREWALL" == "1" ]]; then
    if sudo -n firewall-cmd --query-port="$SERVER_PORT/tcp" >/dev/null 2>&1; then
      echo "state_before=open"
      echo "action=refused_existing_rule"
      echo "temporary firewall mode requires a port that is initially closed" >&2
      exit 1
    else
      echo "state_before=closed"
      sudo -n firewall-cmd --add-port="$SERVER_PORT/tcp" \
        --timeout="${SERVER_TIMEOUT}s"
      echo "action=temporarily_opened"
    fi
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
nohup timeout "${SERVER_TIMEOUT}s" "$SERVER_BIN" server -c "$SERVER_DIR/server.yaml" \
  </dev/null \
  >"$SERVER_DIR/server.log" 2>&1 &
echo $! >"$SERVER_DIR/server.pid"

{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "binary_sha256=$(sha256sum "$SERVER_BIN" | awk '{print $1}')"
  echo "logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  uname -a
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  df -P -B1 "$SERVER_DIR" 2>/dev/null || df -P "$SERVER_DIR"
} >"$SERVER_DIR/system-inventory.log"

cat >"$SERVER_DIR/resource-monitor.sh" <<'MONITOR'
#!/usr/bin/env bash
set -u
server_dir="$1"
interval_secs="$2"

while true; do
  server_pid="$(cat "$server_dir/server.pid" 2>/dev/null || true)"
  echo_pid="$(cat "$server_dir/echo.pid" 2>/dev/null || true)"
  if ! kill -0 "$server_pid" 2>/dev/null && ! kill -0 "$echo_pid" 2>/dev/null; then
    break
  fi
  {
    echo "sample_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    cat /proc/loadavg 2>/dev/null || true
    grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
    ps -o pid=,ppid=,etime=,%cpu=,%mem=,rss=,vsz=,stat=,comm= \
      -p "$server_pid,$echo_pid" --ppid "$server_pid,$echo_pid" 2>/dev/null || true
    df -P -B1 "$server_dir" 2>/dev/null || df -P "$server_dir" 2>/dev/null || true
    cat /proc/net/dev 2>/dev/null || true
    echo "sample_end"
  } >>"$server_dir/resource-metrics.log"
  sleep "$interval_secs"
done
MONITOR
chmod 700 "$SERVER_DIR/resource-monitor.sh"
nohup timeout "${SERVER_TIMEOUT}s" "$SERVER_DIR/resource-monitor.sh" \
  "$SERVER_DIR" "$RESOURCE_INTERVAL_SECS" </dev/null \
  >"$SERVER_DIR/resource-monitor.log" 2>&1 &
echo $! >"$SERVER_DIR/resource-monitor.pid"
REMOTE

echo "==> wait for detached server readiness"
for _ in $(seq 1 30); do
  if ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
grep -q 'echo-listening' "$SERVER_DIR/echo.log"
REMOTE
  then
    break
  fi
  sleep 1
done

ssh "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
grep -q 'echo-listening' "$SERVER_DIR/echo.log"
REMOTE

echo "==> prepare detached client loop on $client_host"
ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
umask 077
rm -rf "$CLIENT_DIR"
mkdir -p "$CLIENT_DIR/logs"
REMOTE

if [[ "$generate_test_cert" == "1" ]]; then
  scp -q "$tmpdir/ca.pem" "$client_host:$client_dir/ca.pem"
fi

scp -q "$tmpdir/client.yaml" "$client_host:$client_dir/client.yaml"
copy_build_artifact "$client_host" "$client_bin_gz"

ssh "$client_host" \
  "CLIENT_DIR=$(shell_quote "$client_dir") CLIENT_BIN=$(shell_quote "$client_bin") TARGET_PORT=$(shell_quote "$target_port") DURATION_SECS=$(shell_quote "$duration_secs") INTERVAL_SECS=$(shell_quote "$interval_secs") RESOURCE_INTERVAL_SECS=$(shell_quote "$resource_interval_secs") SERVER_HOST=$(shell_quote "$server_host") SERVER_DIR=$(shell_quote "$server_dir") RUN_ID=$(shell_quote "$run_id") TESTED_COMMIT=$(shell_quote "$tested_commit") bash -s" <<'REMOTE'
set -euo pipefail
gzip -dc "$CLIENT_BIN.gz" >"$CLIENT_BIN"
rm -f "$CLIENT_BIN.gz"
chmod 700 "$CLIENT_BIN"
"$CLIENT_BIN" --version >"$CLIENT_DIR/binary-version.log"
rm -f "$CLIENT_DIR/completed.marker" "$CLIENT_DIR/failed.marker"
: >"$CLIENT_DIR/failed.marker"
{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "binary_sha256=$(sha256sum "$CLIENT_BIN" | awk '{print $1}')"
  echo "logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  uname -a
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  df -P -B1 "$CLIENT_DIR" 2>/dev/null || df -P "$CLIENT_DIR"
} >"$CLIENT_DIR/system-inventory.log"
cat >"$CLIENT_DIR/client-loop.sh" <<'LOOP'
#!/usr/bin/env bash
set -euo pipefail

start_epoch="$(date +%s)"
start_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
end_epoch=$((start_epoch + DURATION_SECS))
iteration=0
passed=0
failed=0
resource_samples=0

record_resource_sample() {
  local label="$1"
  local pid="${2:-}"
  {
    echo "sample_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "label=$label"
    echo "iteration=$iteration"
    cat /proc/loadavg 2>/dev/null || true
    grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
    if [[ -n "$pid" ]]; then
      ps -o pid=,ppid=,etime=,%cpu=,%mem=,rss=,vsz=,stat=,comm= \
        -p "$pid" --ppid "$pid" 2>/dev/null || true
    fi
    cat /proc/net/dev 2>/dev/null || true
    echo "sample_end"
  } >>"CLIENT_DIR/resource-metrics.log"
  resource_samples=$((resource_samples + 1))
}

echo "run_id: RUN_ID"
echo "tested_commit: TESTED_COMMIT"
echo "server_host: SERVER_HOST"
echo "server_dir: SERVER_DIR"
echo "client_bin: CLIENT_BIN"
echo "target_port: TARGET_PORT"
echo "duration_secs: DURATION_SECS"
echo "interval_secs: INTERVAL_SECS"
echo "resource_interval_secs: RESOURCE_INTERVAL_SECS"

while [[ "$(date +%s)" -lt "$end_epoch" ]]; do
  iteration=$((iteration + 1))
  iter_started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  client_log="CLIENT_DIR/logs/client-${iteration}.log"
  probe_log="CLIENT_DIR/logs/probe-${iteration}.log"
  echo "==> iteration $iteration started at $iter_started"

  nohup timeout 180s "CLIENT_BIN" client -c "CLIENT_DIR/client.yaml" \
    </dev/null \
    >"$client_log" 2>&1 &
  echo $! >"CLIENT_DIR/logs/client-${iteration}.pid"
  client_pid="$(cat "CLIENT_DIR/logs/client-${iteration}.pid")"
  record_resource_sample "client_started" "$client_pid"
  client_port=""
  for _ in $(seq 1 30); do
    if ! kill -0 "$client_pid" 2>/dev/null; then
      echo "client exited early" >>"$client_log"
      break
    fi
    client_port="$(python3 - "$client_log" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(errors="ignore") if path.exists() else ""
matches = re.findall(r"127\.0\.0\.1:(\d+)", text)
print(matches[-1] if matches else "")
PY
)"
    if [[ -n "$client_port" ]]; then
      break
    fi
    sleep 1
  done

  if [[ -n "$client_port" ]] && python3 - "$client_port" "TARGET_PORT" "$iteration" >"$probe_log" 2>&1 <<'PY'
import socket
import struct
import sys
import time

client_port = int(sys.argv[1])
target_port = int(sys.argv[2])
iteration = sys.argv[3]
payload = ("maverick-detached-longhaul:" + iteration).encode()
stage = "connect_socks"
sock = None
started = time.monotonic()

try:
    sock = socket.create_connection(("127.0.0.1", client_port), timeout=10)
    sock.settimeout(20)
    print("stage=connect_socks ok", flush=True)

    stage = "socks_method"
    sock.sendall(b"\x05\x01\x00")
    method = sock.recv(2)
    if method != b"\x05\x00":
        raise RuntimeError(f"SOCKS method failed: {method!r}")
    print("stage=socks_method ok", flush=True)

    stage = "socks_connect"
    request = b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + struct.pack("!H", target_port)
    sock.sendall(request)
    reply = sock.recv(10)
    if len(reply) != 10 or reply[1] != 0:
        raise RuntimeError(f"SOCKS connect failed: {reply!r}")
    print("stage=socks_connect ok", flush=True)

    stage = "echo_payload"
    sock.sendall(payload)
    received = b""
    while len(received) < len(payload):
        chunk = sock.recv(4096)
        if not chunk:
            break
        received += chunk
    if received != payload:
        raise RuntimeError(f"echo mismatch: {received!r}")
    print("stage=echo_payload ok", flush=True)
    print("detached_tcp_smoke=ok", flush=True)
except Exception as exc:
    print(f"failure_stage={stage}", flush=True)
    print(f"error_type={type(exc).__name__}", flush=True)
    print(f"error={exc!r}", flush=True)
    raise SystemExit(1)
finally:
    if sock is not None:
        sock.close()
    print("elapsed_ms=%d" % round((time.monotonic() - started) * 1000), flush=True)
PY
  then
    passed=$((passed + 1))
    probe_elapsed_ms="$(awk -F= '/^elapsed_ms=/{print $2; exit}' "$probe_log")"
    echo "PASS iteration=$iteration started=$iter_started finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') elapsed_ms=${probe_elapsed_ms:-unknown} client_port=$client_port" | tee -a "CLIENT_DIR/events.log"
  else
    failed=$((failed + 1))
    probe_elapsed_ms="$(awk -F= '/^elapsed_ms=/{print $2; exit}' "$probe_log" 2>/dev/null || true)"
    {
      echo "diagnostic_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      echo "iteration=$iteration"
      echo "client_pid=$client_pid"
      echo "client_port=${client_port:-none}"
      echo "--- probe log ---"
      cat "$probe_log" 2>/dev/null || true
      echo "--- client log tail ---"
      tail -120 "$client_log" 2>/dev/null || true
      echo "--- client process ---"
      ps -o pid=,ppid=,etime=,%cpu=,%mem=,rss=,vsz=,stat=,comm= \
        -p "$client_pid" --ppid "$client_pid" 2>/dev/null || true
      echo "--- memory ---"
      grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
      echo "--- network counters ---"
      cat /proc/net/dev 2>/dev/null || true
    } >>"CLIENT_DIR/logs/failure-${iteration}.log"
    echo "FAIL iteration=$iteration started=$iter_started finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') elapsed_ms=${probe_elapsed_ms:-unknown} client_port=${client_port:-none}" | tee -a "CLIENT_DIR/events.log"
  fi

  record_resource_sample "probe_finished" "$client_pid"

  kill "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true

  now="$(date +%s)"
  if [[ "$now" -ge "$end_epoch" ]]; then
    break
  fi
  sleep_for="INTERVAL_SECS"
  remaining=$((end_epoch - now))
  if [[ "$remaining" -lt "$sleep_for" ]]; then
    sleep_for="$remaining"
  fi
  sleep "$sleep_for"
done

finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
client_log_count="$(find "CLIENT_DIR/logs" -maxdepth 1 -type f -name 'client-*.log' | wc -l | tr -d ' ')"
probe_log_count="$(find "CLIENT_DIR/logs" -maxdepth 1 -type f -name 'probe-*.log' | wc -l | tr -d ' ')"
failure_log_count="$(find "CLIENT_DIR/logs" -maxdepth 1 -type f -name 'failure-*.log' | wc -l | tr -d ' ')"
cat >"CLIENT_DIR/SUMMARY.md" <<EOF
# Maverick Detached Approved-Host TCP Long-Haul

- run_id: RUN_ID
- started_utc: $start_utc
- finished_utc: $finished
- tested_commit: TESTED_COMMIT
- duration_secs: DURATION_SECS
- interval_secs: INTERVAL_SECS
- resource_interval_secs: RESOURCE_INTERVAL_SECS
- server_role: approved-server
- client_role: approved-client
- server_runtime_dir: redacted
- client_runtime_dir: redacted
- iterations: $iteration
- passed: $passed
- failed: $failed
- client_log_count: $client_log_count
- probe_log_count: $probe_log_count
- failure_log_count: $failure_log_count
- resource_samples: $resource_samples
- resource_process_children: enabled
- client_inventory: collected
- server_inventory: collected
- server_resource_monitor: enabled
EOF

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
rm -f "CLIENT_DIR/failed.marker"
touch "CLIENT_DIR/completed.marker"
LOOP

python3 - "$CLIENT_DIR/client-loop.sh" "$CLIENT_DIR" "$CLIENT_BIN" "$TARGET_PORT" \
  "$DURATION_SECS" "$INTERVAL_SECS" "$SERVER_HOST" "$SERVER_DIR" "$RUN_ID" "$TESTED_COMMIT" "$RESOURCE_INTERVAL_SECS" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
replacements = {
    "CLIENT_DIR": sys.argv[2],
    "CLIENT_BIN": sys.argv[3],
    "TARGET_PORT": sys.argv[4],
    "DURATION_SECS": sys.argv[5],
    "RESOURCE_INTERVAL_SECS": sys.argv[11],
    "INTERVAL_SECS": sys.argv[6],
    "SERVER_HOST": sys.argv[7],
    "SERVER_DIR": sys.argv[8],
    "RUN_ID": sys.argv[9],
    "TESTED_COMMIT": sys.argv[10],
}
for old, new in replacements.items():
    text = text.replace(old, new)
path.write_text(text)
PY

chmod 700 "$CLIENT_DIR/client-loop.sh"
nohup "$CLIENT_DIR/client-loop.sh" </dev/null >"$CLIENT_DIR/orchestrator.log" 2>&1 &
echo $! >"$CLIENT_DIR/orchestrator.pid"
REMOTE

echo "detached long-haul started"
echo "run_id=$run_id"
echo "server_host=$server_host"
echo "server_dir=$server_dir"
echo "client_host=$client_host"
echo "client_dir=$client_dir"
echo "poll:"
echo "  ssh $client_host 'sed -n \"1,120p\" $client_dir/events.log; cat $client_dir/SUMMARY.md 2>/dev/null || true'"
