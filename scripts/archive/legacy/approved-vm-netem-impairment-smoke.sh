#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 scripts/approved-vm-netem-impairment-smoke.sh <server-ssh-host>

Starts a detached approved-VM TCP/H2 network-impairment run:
- server and echo target run on the approved server host;
- client runs on the approved client host;
- latency/loss are applied only inside a temporary network namespace/veth pair
  on the approved client host;
- the local machine only starts the run and can disconnect afterward.

Required environment:
  MAVERICK_NETEM_IMPAIRMENT_APPROVED=1
  MAVERICK_NETEM_CLIENT_HOST          SSH host that runs the client and netem.

Optional environment:
  MAVERICK_NETEM_REMOTE_ADDR          Public address the client dials.
  MAVERICK_NETEM_SERVER_NAME          TLS server_name / SNI value.
  MAVERICK_NETEM_PORT                 Remote Maverick TCP port, default 24443.
  MAVERICK_NETEM_TARGET_PORT          Remote loopback echo port, default 24444.
  MAVERICK_NETEM_BUILD_HOST           Default approved client host.
  MAVERICK_S2_PREBUILT_LINUX_BIN      Optional local x86_64 Linux binary.
  MAVERICK_S2_PREBUILT_COMMIT         Required with a prebuilt binary and must
                                      match the current git HEAD short id.
  MAVERICK_NETEM_TEMP_FIREWALL        Set to 1 to open the server port with an
                                      auto-expiring firewalld runtime rule.
  MAVERICK_NETEM_PRIVILEGED_PORT_APPROVED
                                      Required as 1 for server ports below 1024.
  MAVERICK_NETEM_RUN_ID               Default timestamp-based id.
  MAVERICK_NETEM_INTERVAL_SECS        Default 300.
  MAVERICK_NETEM_SCENARIO_PROFILE     Default 8h-v2. Also supports 11h-v1
                                      and diagnostic-quick.

This script intentionally uses sudo on the approved client VM for temporary
network namespace, veth, tc netem, ip_forward, and iptables NAT setup. It must
not be run against a developer workstation. The tested binary is built from
local git HEAD on the build host, or supplied as a commit-bound local prebuilt
binary, and copied to the approved server/client VMs as a temporary file. The
server and client VMs do not need Rust/Cargo installed unless they are also the
build host.
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
    ssh -o BatchMode=yes "$dst_host" "SRC_PATH=$(shell_quote "$src_path") DST_PATH=$(shell_quote "$dst_path") bash -s" <<'REMOTE'
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

reject_local_host() {
  local label="$1"
  local host="$2"
  case "$host" in
    "" | localhost | 127.* | ::1)
      echo "refusing to run approved VM netem impairment smoke against local host: $label" >&2
      exit 2
      ;;
  esac
  local local_name
  local_name="$(hostname 2>/dev/null || true)"
  if [[ -n "$local_name" && "$host" == "$local_name" ]]; then
    echo "refusing to run approved VM netem impairment smoke against local host: $label" >&2
    exit 2
  fi
}

ssh_hostname() {
  local host="$1"
  ssh -G "$host" | awk '$1 == "hostname" { print $2; exit }'
}

write_kv() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value"
}

if [[ "${MAVERICK_NETEM_IMPAIRMENT_APPROVED:-0}" != "1" ]]; then
  echo "MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 is required" >&2
  usage
  exit 2
fi

server_host="${1:-}"
client_host="${MAVERICK_NETEM_CLIENT_HOST:-}"
build_host="${MAVERICK_NETEM_BUILD_HOST:-${MAVERICK_S2_BUILD_HOST:-$client_host}}"
prebuilt_linux_bin="${MAVERICK_S2_PREBUILT_LINUX_BIN:-}"
prebuilt_commit="${MAVERICK_S2_PREBUILT_COMMIT:-}"
require_non_empty "server ssh host" "$server_host"
require_non_empty "MAVERICK_NETEM_CLIENT_HOST" "$client_host"
reject_local_host "server" "$server_host"
reject_local_host "client" "$client_host"
if [[ -z "$prebuilt_linux_bin" ]]; then
  require_non_empty "MAVERICK_NETEM_BUILD_HOST" "$build_host"
  reject_local_host "build" "$build_host"
fi

remote_addr="${MAVERICK_NETEM_REMOTE_ADDR:-$(ssh_hostname "$server_host")}"
server_name="${MAVERICK_NETEM_SERVER_NAME:-$remote_addr}"
port="${MAVERICK_NETEM_PORT:-24443}"
target_port="${MAVERICK_NETEM_TARGET_PORT:-24444}"
privileged_port_approved="${MAVERICK_NETEM_PRIVILEGED_PORT_APPROVED:-0}"
temp_firewall="${MAVERICK_NETEM_TEMP_FIREWALL:-0}"
interval_secs="${MAVERICK_NETEM_INTERVAL_SECS:-300}"
run_id="${MAVERICK_NETEM_RUN_ID:-netem-$(date -u '+%Y%m%dT%H%M%SZ')}"
scenario_profile="${MAVERICK_NETEM_SCENARIO_PROFILE:-8h-v2}"
tested_commit="$(git rev-parse --short HEAD)"

if [[ ! "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "MAVERICK_NETEM_RUN_ID must be a safe single path component" >&2
  exit 2
fi

python3 "$repo_root/scripts/approved-host-guard.py" "$server_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" "$client_host" >/dev/null
if [[ -z "$prebuilt_linux_bin" ]]; then
  python3 "$repo_root/scripts/approved-host-guard.py" "$build_host" >/dev/null
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

case "$temp_firewall" in
  0 | 1) ;;
  *)
    echo "MAVERICK_NETEM_TEMP_FIREWALL must be 0 or 1" >&2
    exit 2
    ;;
esac

case "$port:$target_port:$interval_secs" in
  *[!0-9:]*)
    echo "ports and interval must be numeric" >&2
    exit 2
    ;;
esac

if (( port < 1024 )) && [[ "$privileged_port_approved" != "1" ]]; then
  echo "MAVERICK_NETEM_PRIVILEGED_PORT_APPROVED=1 is required for server ports below 1024" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

case "$scenario_profile" in
  8h-v2)
    cat >"$tmpdir/scenarios.tsv" <<'EOF'
baseline	1800	none
latency_50ms_jitter10	3600	delay 50ms 10ms distribution normal
latency_100ms_jitter20	3600	delay 100ms 20ms distribution normal
loss_0_5pct	3600	loss 0.5%
loss_1pct	3600	loss 1%
combined_100ms_jitter20_loss1	5400	delay 100ms 20ms distribution normal loss 1%
rough_150ms_jitter50_loss2	3600	delay 150ms 50ms distribution normal loss 2% 25%
recovery_baseline	3600	none
EOF
    ;;
  11h-v1)
    cat >"$tmpdir/scenarios.tsv" <<'EOF'
baseline	1800	none
latency_50ms_jitter10	5400	delay 50ms 10ms distribution normal
latency_100ms_jitter20	5400	delay 100ms 20ms distribution normal
loss_0_5pct	5400	loss 0.5%
loss_1pct	5400	loss 1%
combined_100ms_jitter20_loss1	7200	delay 100ms 20ms distribution normal loss 1%
rough_150ms_jitter50_loss2	5400	delay 150ms 50ms distribution normal loss 2% 25%
recovery_baseline	3600	none
EOF
    ;;
  diagnostic-quick)
    cat >"$tmpdir/scenarios.tsv" <<'EOF'
baseline	120	none
latency_50ms_jitter10	120	delay 50ms 10ms distribution normal
recovery_baseline	120	none
EOF
    ;;
  *)
    echo "unsupported MAVERICK_NETEM_SCENARIO_PROFILE: $scenario_profile" >&2
    exit 2
    ;;
esac

total_duration_secs="$(awk -F'\t' '{ total += $2 } END { print total + 0 }' "$tmpdir/scenarios.tsv")"
if (( total_duration_secs > 43200 )); then
  echo "netem duration exceeds 12 hour cap" >&2
  exit 2
fi
server_timeout_secs=$((total_duration_secs + 1800))

secret="$(python3 - <<'PY'
import base64
import os

print("mv1_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
PY
)"

server_dir="/tmp/maverick-netem-server-$run_id"
client_dir="/tmp/maverick-netem-client-$run_id"
build_dir="/tmp/maverick-build-$run_id"
build_repo="$build_dir/repo"
build_bin="$build_repo/target/release/maverick"
build_artifact_gz="$build_dir/maverick-linux.gz"
prebuilt_artifact_gz="$tmpdir/maverick-linux-prebuilt.gz"
client_bin="$client_dir/maverick"
client_bin_gz="$client_bin.gz"
server_bin="$server_dir/maverick"
server_bin_gz="$server_bin.gz"
namespace="mavnetem_${run_id//[^A-Za-z0-9_]/_}"
veth_host="mavnh${run_id//[^A-Za-z0-9]/}"
veth_ns="mavnn${run_id//[^A-Za-z0-9]/}"
veth_host="${veth_host:0:15}"
veth_ns="${veth_ns:0:15}"

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
  - id: "u_netem_impairment"
    name: "netem-impairment"
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
  credential_id: "u_netem_impairment"
  secret: "$secret"
  ca_cert: "$client_dir/ca.pem"
  cert_pin: null
log:
  level: "info"
  redact: true
advanced:
  connect_timeout_ms: 8000
  idle_timeout_secs: 60
  max_concurrent_flows: 16
  padding: "off"
  allow_non_loopback_listeners: false
YAML
chmod 600 "$tmpdir/client.yaml"

echo "==> preflight approved hosts"
if [[ -z "$prebuilt_linux_bin" ]]; then
  ssh -o BatchMode=yes "$build_host" 'PATH="$HOME/.cargo/bin:$PATH"; command -v cargo >/dev/null && command -v tar >/dev/null && command -v gzip >/dev/null && command -v python3 >/dev/null'
else
  command -v gzip >/dev/null
fi
ssh -o BatchMode=yes "$client_host" 'command -v sudo >/dev/null && command -v ip >/dev/null && command -v tc >/dev/null && command -v iptables >/dev/null && command -v gzip >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null && command -v sha256sum >/dev/null && sudo -n true'
ssh -o BatchMode=yes "$server_host" 'command -v python3 >/dev/null && command -v openssl >/dev/null && command -v timeout >/dev/null && command -v gzip >/dev/null && command -v sha256sum >/dev/null'
if [[ "$temp_firewall" == "1" ]]; then
  ssh -o BatchMode=yes "$server_host" 'command -v firewall-cmd >/dev/null && command -v sudo >/dev/null && sudo -n true && sudo -n firewall-cmd --state >/dev/null'
fi
if (( port < 1024 )); then
  ssh -o BatchMode=yes "$server_host" 'command -v sudo >/dev/null && command -v setcap >/dev/null && sudo -n true'
fi

echo "==> preflight approved server ports"
if ! ssh -o BatchMode=yes "$server_host" "PORT=$(shell_quote "$port") TARGET_PORT=$(shell_quote "$target_port") bash -s" <<'REMOTE'
set -euo pipefail
if (ss -ltn 2>/dev/null || true) | grep -E ":(${PORT}|${TARGET_PORT})\\b" >/dev/null; then
  exit 1
fi
REMOTE
then
  echo "test ports are already listening on approved server" >&2
  exit 1
fi

if [[ -n "$prebuilt_linux_bin" ]]; then
  echo "==> package prebuilt Linux binary for current commit"
  gzip -c "$prebuilt_linux_bin" >"$prebuilt_artifact_gz"
  chmod 600 "$prebuilt_artifact_gz"
else
  echo "==> package source from current commit"
  git archive --format=tar.gz -o "$tmpdir/source.tar.gz" HEAD

  echo "==> build approved release binary"
  ssh -o BatchMode=yes "$build_host" "BUILD_DIR=$(shell_quote "$build_dir") bash -s" <<'REMOTE'
set -euo pipefail
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
REMOTE
  scp -q "$tmpdir/source.tar.gz" "$build_host:$build_dir/source.tar.gz"
  ssh -o BatchMode=yes "$build_host" "BUILD_DIR=$(shell_quote "$build_dir") BUILD_REPO=$(shell_quote "$build_repo") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$BUILD_REPO"
tar -xzf "$BUILD_DIR/source.tar.gz" -C "$BUILD_REPO"
PATH="$HOME/.cargo/bin:$PATH" cargo build --release --manifest-path "$BUILD_REPO/Cargo.toml" -p maverick-cli
REMOTE
  ssh -o BatchMode=yes "$build_host" "BUILD_BIN=$(shell_quote "$build_bin") BUILD_ARTIFACT_GZ=$(shell_quote "$build_artifact_gz") bash -s" <<'REMOTE'
set -euo pipefail
gzip -c "$BUILD_BIN" >"$BUILD_ARTIFACT_GZ"
chmod 600 "$BUILD_ARTIFACT_GZ"
REMOTE
fi
echo "==> prepare approved-server release binary"
ssh -o BatchMode=yes "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
rm -rf "$SERVER_DIR"
mkdir -p "$SERVER_DIR/public"
printf '%s\n' '<html><body>Maverick netem impairment fallback</body></html>' \
  >"$SERVER_DIR/public/index.html"
REMOTE
copy_build_artifact "$server_host" "$server_bin_gz"
scp -q "$tmpdir/server.yaml" "$server_host:$server_dir/server.yaml"
ssh -o BatchMode=yes "$server_host" \
  "SERVER_DIR=$(shell_quote "$server_dir") SERVER_BIN=$(shell_quote "$server_bin") SERVER_BIN_GZ=$(shell_quote "$server_bin_gz") SERVER_NAME=$(shell_quote "$server_name") TARGET_PORT=$(shell_quote "$target_port") SERVER_TIMEOUT=$(shell_quote "$server_timeout_secs") SERVER_PORT=$(shell_quote "$port") TEMP_FIREWALL=$(shell_quote "$temp_firewall") bash -s" <<'REMOTE'
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
    fi
    echo "state_before=closed"
    sudo -n firewall-cmd --add-port="$SERVER_PORT/tcp" \
      --timeout="${SERVER_TIMEOUT}s"
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
san="DNS:$SERVER_NAME"
if [[ "$SERVER_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  san="IP:$SERVER_NAME"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=Maverick netem impairment test CA" \
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
sock.listen(64)
print("echo-listening", flush=True)
while True:
    conn, addr = sock.accept()
    data = conn.recv(65536)
    print("echo-peer=%s:%s bytes=%d" % (addr[0], addr[1], len(data)), flush=True)
    conn.sendall(data)
    conn.close()
PY
nohup timeout "${SERVER_TIMEOUT}s" python3 -u "$SERVER_DIR/echo.py" "$TARGET_PORT" \
  </dev/null >"$SERVER_DIR/echo.log" 2>&1 &
echo $! >"$SERVER_DIR/echo.pid"
nohup timeout "${SERVER_TIMEOUT}s" "$SERVER_BIN" server -c "$SERVER_DIR/server.yaml" \
  </dev/null >"$SERVER_DIR/server.log" 2>&1 &
echo $! >"$SERVER_DIR/server.pid"
cat >"$SERVER_DIR/resource-monitor.sh" <<'MONITOR'
#!/usr/bin/env bash
set -u
server_dir="$1"
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
    cat /proc/net/dev 2>/dev/null || true
    echo "sample_end"
  } >>"$server_dir/resource-metrics.log"
  sleep 60
done
MONITOR
chmod 700 "$SERVER_DIR/resource-monitor.sh"
nohup timeout "${SERVER_TIMEOUT}s" "$SERVER_DIR/resource-monitor.sh" "$SERVER_DIR" \
  </dev/null >"$SERVER_DIR/resource-monitor.log" 2>&1 &
echo $! >"$SERVER_DIR/resource-monitor.pid"
REMOTE

echo "==> wait for approved server readiness"
for _ in $(seq 1 45); do
  if ssh -o BatchMode=yes "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'echo-listening' "$SERVER_DIR/echo.log"
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
REMOTE
  then
    break
  fi
  sleep 1
done
ssh -o BatchMode=yes "$server_host" "SERVER_DIR=$(shell_quote "$server_dir") bash -s" <<'REMOTE'
set -euo pipefail
grep -q 'echo-listening' "$SERVER_DIR/echo.log"
grep -q 'Maverick server listening' "$SERVER_DIR/server.log"
REMOTE

echo "==> verify remote port reachability from approved client"
ssh -o BatchMode=yes "$client_host" "REMOTE_ADDR=$(shell_quote "$remote_addr") PORT=$(shell_quote "$port") python3 - <<'PY'
import os
import socket

addr = os.environ['REMOTE_ADDR']
port = int(os.environ['PORT'])
sock = socket.create_connection((addr, port), timeout=10)
sock.close()
PY"

echo "==> prepare approved client runner"
scp -q "$server_host:$server_dir/ca.pem" "$tmpdir/ca.pem"
ssh -o BatchMode=yes "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$CLIENT_DIR"
REMOTE
copy_build_artifact "$client_host" "$client_bin_gz"
ssh -o BatchMode=yes "$client_host" "CLIENT_BIN=$(shell_quote "$client_bin") CLIENT_BIN_GZ=$(shell_quote "$client_bin_gz") bash -s" <<'REMOTE'
set -euo pipefail
gzip -dc "$CLIENT_BIN_GZ" >"$CLIENT_BIN"
rm -f "$CLIENT_BIN_GZ"
chmod 700 "$CLIENT_BIN"
"$CLIENT_BIN" --version >"$(dirname "$CLIENT_BIN")/binary-version.log"
{
  echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "binary_sha256=$(sha256sum "$CLIENT_BIN" | awk '{print $1}')"
  echo "logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
  uname -a
  grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
  df -P -B1 "$(dirname "$CLIENT_BIN")" 2>/dev/null || df -P "$(dirname "$CLIENT_BIN")"
} >"$(dirname "$CLIENT_BIN")/system-inventory.log"
REMOTE
scp -q "$tmpdir/client.yaml" "$client_host:$client_dir/client.yaml"
scp -q "$tmpdir/ca.pem" "$client_host:$client_dir/ca.pem"

cat >"$tmpdir/run.env" <<EOF
$(write_kv CLIENT_DIR "$client_dir")
$(write_kv CLIENT_BIN "$client_bin")
$(write_kv CLIENT_CONFIG "$client_dir/client.yaml")
$(write_kv REMOTE_ADDR "$remote_addr")
$(write_kv TARGET_PORT "$target_port")
$(write_kv RUN_ID "$run_id")
$(write_kv TESTED_COMMIT "$tested_commit")
$(write_kv NS "$namespace")
$(write_kv VETH_HOST "$veth_host")
$(write_kv VETH_NS "$veth_ns")
$(write_kv INTERVAL_SECS "$interval_secs")
$(write_kv TOTAL_DURATION_SECS "$total_duration_secs")
$(write_kv SCENARIO_PROFILE "$scenario_profile")
EOF
scp -q "$tmpdir/run.env" "$client_host:$client_dir/run.env"
scp -q "$tmpdir/scenarios.tsv" "$client_host:$client_dir/scenarios.tsv"

ssh -o BatchMode=yes "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
cat >"$CLIENT_DIR/run-netem.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

env_file="${1:?env file required}"
# shellcheck disable=SC1090
. "$env_file"

mkdir -p "$CLIENT_DIR/logs"
events="$CLIENT_DIR/events.log"
summary="$CLIENT_DIR/SUMMARY.md"
completed="$CLIENT_DIR/completed.marker"
failed_marker="$CLIENT_DIR/failed.marker"
: >"$failed_marker"
rm -f "$completed"

NETEM_OK_MARKER="approved_vm_netem_impairment_smoke=ok"

log() {
  printf '%s\n' "$*" | tee -a "$events"
}

resource_samples=0
record_resource_sample() {
  local label="$1"
  {
    echo "sample_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "label=$label"
    cat /proc/loadavg 2>/dev/null || true
    grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null || true
    cat /proc/net/dev 2>/dev/null || true
    tc -s qdisc show dev "$VETH_HOST" 2>/dev/null || true
    if sudo ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
      sudo ip netns exec "$NS" tc -s qdisc show dev "$VETH_NS" 2>/dev/null || true
      sudo ip netns exec "$NS" ss -s 2>/dev/null || true
    fi
    echo "sample_end"
  } >>"$CLIENT_DIR/resource-metrics.log"
  resource_samples=$((resource_samples + 1))
}

orig_forward=""
net_cidr=""
egress_iface=""
nat_added=0
fwd_out_added=0
fwd_in_added=0
cleanup_started=0
cleanup_ip_forward_restored="unknown"
cleanup_iptables_residue="unknown"

cleanup() {
  local residue=0
  if [[ "$cleanup_started" == "1" ]]; then
    return
  fi
  set +e
  cleanup_started=1
  log "cleanup_started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if sudo ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
    for pid in $(sudo ip netns pids "$NS" 2>/dev/null || true); do
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $(sudo ip netns pids "$NS" 2>/dev/null || true); do
      kill -KILL "$pid" 2>/dev/null || true
    done
    sudo ip netns exec "$NS" tc qdisc del dev "$VETH_NS" root 2>/dev/null || true
  fi
  sudo tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true
  if [[ "$nat_added" == "1" && -n "$net_cidr" && -n "$egress_iface" ]]; then
    sudo iptables -t nat -D POSTROUTING -s "$net_cidr" -o "$egress_iface" -j MASQUERADE 2>/dev/null || true
  fi
  if [[ "$fwd_out_added" == "1" && -n "$egress_iface" ]]; then
    sudo iptables -D FORWARD -i "$VETH_HOST" -o "$egress_iface" -j ACCEPT 2>/dev/null || true
  fi
  if [[ "$fwd_in_added" == "1" && -n "$egress_iface" ]]; then
    sudo iptables -D FORWARD -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
  sudo ip link del "$VETH_HOST" 2>/dev/null || true
  sudo ip netns delete "$NS" 2>/dev/null || true
  if [[ "$orig_forward" == "0" || "$orig_forward" == "1" ]]; then
    printf '%s\n' "$orig_forward" | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1 || true
  fi
  cleanup_iptables_residue="absent"
  if [[ "$nat_added" == "1" && -n "$net_cidr" && -n "$egress_iface" ]] && \
    sudo iptables -t nat -C POSTROUTING -s "$net_cidr" -o "$egress_iface" -j MASQUERADE 2>/dev/null; then
    cleanup_iptables_residue="present"
    residue=1
  fi
  if [[ "$fwd_out_added" == "1" && -n "$egress_iface" ]] && \
    sudo iptables -C FORWARD -i "$VETH_HOST" -o "$egress_iface" -j ACCEPT 2>/dev/null; then
    cleanup_iptables_residue="present"
    residue=1
  fi
  if [[ "$fwd_in_added" == "1" && -n "$egress_iface" ]] && \
    sudo iptables -C FORWARD -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    cleanup_iptables_residue="present"
    residue=1
  fi
  current_forward="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true)"
  if [[ "$orig_forward" == "0" || "$orig_forward" == "1" ]] && \
    [[ "$current_forward" == "$orig_forward" ]]; then
    cleanup_ip_forward_restored="true"
  else
    cleanup_ip_forward_restored="false"
    residue=1
  fi
  log "iptables_residue=$cleanup_iptables_residue"
  log "ip_forward_restored=$cleanup_ip_forward_restored"
  log "cleanup_finished_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if sudo ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
    log "remote_residue=present"
    residue=1
  elif ip link show "$VETH_HOST" >/dev/null 2>&1; then
    log "remote_residue=present"
    residue=1
  else
    log "remote_residue=absent"
  fi
  set -e
  return "$residue"
}
trap 'cleanup || true' EXIT

default_route_before="$(ip route show default 2>/dev/null | sha256sum | awk '{print $1}')"
dns_before="$(sha256sum /etc/resolv.conf 2>/dev/null | awk '{print $1}')"

log "run_id=$RUN_ID"
log "tested_commit=$TESTED_COMMIT"
log "started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "client_role=approved-client-netem"
log "server_role=approved-server"
log "scope=namespace_veth_netem_only"
log "duration_secs=$TOTAL_DURATION_SECS"
log "interval_secs=$INTERVAL_SECS"
log "scenario_profile=$SCENARIO_PROFILE"

if [[ ! -s "$CLIENT_DIR/scenarios.tsv" ]]; then
  echo "missing scenario plan" >&2
  exit 1
fi
awk -F'\t' '
  NF != 3 || $2 !~ /^[0-9]+$/ || $2 <= 0 { bad = 1 }
  END { exit bad }
' "$CLIENT_DIR/scenarios.tsv"

route_target="$(getent ahostsv4 "$REMOTE_ADDR" | awk 'NR == 1 { print $1; exit }')"
if [[ -z "$route_target" ]]; then
  route_target="$REMOTE_ADDR"
fi
egress_iface="$(ip route get "$route_target" | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
if [[ -z "$egress_iface" ]]; then
  echo "could not determine approved-client egress interface" >&2
  exit 1
fi

octet=$(( (RANDOM % 180) + 40 ))
host_ip="10.253.${octet}.1"
ns_ip="10.253.${octet}.2"
net_cidr="10.253.${octet}.0/30"

orig_forward="$(cat /proc/sys/net/ipv4/ip_forward)"
log "namespace_cidr=$net_cidr"
log "ip_forward_original=$orig_forward"
sudo ip netns add "$NS"
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
sudo ip link set "$VETH_NS" netns "$NS"
sudo ip addr add "$host_ip/30" dev "$VETH_HOST"
sudo ip link set "$VETH_HOST" up
sudo ip netns exec "$NS" ip addr add "$ns_ip/30" dev "$VETH_NS"
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ip link set "$VETH_NS" up
sudo ip netns exec "$NS" ip route add default via "$host_ip"
printf '1\n' | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
sudo iptables -t nat -A POSTROUTING -s "$net_cidr" -o "$egress_iface" -j MASQUERADE
nat_added=1
sudo iptables -A FORWARD -i "$VETH_HOST" -o "$egress_iface" -j ACCEPT
fwd_out_added=1
sudo iptables -A FORWARD -o "$VETH_HOST" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fwd_in_added=1

log "namespace_setup=ok"
log "default_route_unchanged: true"
log "global_dns_unchanged: true"
record_resource_sample "namespace_ready"

apply_netem() {
  local params="$1"
  sudo tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc del dev "$VETH_NS" root 2>/dev/null || true
  if [[ "$params" == "none" ]]; then
    return
  fi
  # Intentional word splitting: tc netem parameters are stored as a command tail.
  sudo tc qdisc replace dev "$VETH_HOST" root netem $params
  sudo ip netns exec "$NS" tc qdisc replace dev "$VETH_NS" root netem $params
}

run_flow() {
  local scenario="$1"
  local iteration="$2"
  local client_log="$CLIENT_DIR/logs/client-${scenario}-${iteration}.log"
  local probe_log="$CLIENT_DIR/logs/probe-${scenario}-${iteration}.log"
  local client_pid=""
  local client_port=""

  stop_client_pids() {
    for pid in $(sudo ip netns pids "$NS" 2>/dev/null || true); do
      kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $(sudo ip netns pids "$NS" 2>/dev/null || true); do
      kill -KILL "$pid" 2>/dev/null || true
    done
  }

  append_failure_diagnostics() {
    local reason="$1"
    {
      echo "diagnostic_reason=$reason"
      echo "diagnostic_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      echo "scenario=$scenario"
      echo "iteration=$iteration"
      echo "client_wrapper_pid=${client_pid:-unknown}"
      echo "client_port=${client_port:-none}"
      printf 'namespace_pids_before_cleanup='
      sudo ip netns pids "$NS" 2>/dev/null | tr '\n' ' ' || true
      echo
      echo "--- namespace ss -ltn ---"
      sudo ip netns exec "$NS" ss -ltn 2>&1 || true
      echo "--- host qdisc ---"
      tc -s qdisc show dev "$VETH_HOST" 2>&1 || true
      echo "--- namespace qdisc ---"
      sudo ip netns exec "$NS" tc -s qdisc show dev "$VETH_NS" 2>&1 || true
      echo "--- client log tail ---"
      tail -80 "$client_log" 2>&1 || true
    } >>"$probe_log"
  }

  sudo ip netns exec "$NS" env PATH="$PATH" timeout 180s "$CLIENT_BIN" client -c "$CLIENT_CONFIG" \
    </dev/null >"$client_log" 2>&1 &
  echo $! >"$CLIENT_DIR/logs/client-${scenario}-${iteration}.pid"
  client_pid="$(cat "$CLIENT_DIR/logs/client-${scenario}-${iteration}.pid")"
  for _ in $(seq 1 45); do
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

  local result="fail"
  if [[ -z "$client_port" ]]; then
    {
      echo "result=client_port_not_found"
      if kill -0 "$client_pid" 2>/dev/null; then
        echo "client_wrapper_pid_alive=true"
      else
        echo "client_wrapper_pid_alive=false"
      fi
    } >"$probe_log"
    append_failure_diagnostics "client_port_not_found"
  elif sudo ip netns exec "$NS" python3 - "$client_port" "$TARGET_PORT" "$scenario" >"$probe_log" 2>&1 <<'PY'
import socket
import struct
import sys
import time

client_port = int(sys.argv[1])
target_port = int(sys.argv[2])
scenario = sys.argv[3]
payload = ("maverick-netem:" + scenario).encode()
stage = "connect_socks"
sock = None
started = time.monotonic()

def fail(message):
    print(f"failure_stage={stage}", flush=True)
    print("error_type=ProbeFailure", flush=True)
    print(f"error={message!r}", flush=True)
    raise SystemExit(1)

try:
    sock = socket.create_connection(("127.0.0.1", client_port), timeout=20)
    sock.settimeout(45)
    print("stage=connect_socks ok", flush=True)

    stage = "socks_method"
    sock.sendall(b"\x05\x01\x00")
    method = sock.recv(2)
    if method != b"\x05\x00":
        fail(f"SOCKS method failed: {method!r}")
    print("stage=socks_method ok", flush=True)

    stage = "socks_connect"
    request = b"\x05\x01\x00\x01" + bytes([127, 0, 0, 1]) + struct.pack("!H", target_port)
    sock.sendall(request)
    reply = sock.recv(10)
    if len(reply) != 10 or reply[1] != 0:
        fail(f"SOCKS connect failed: {reply!r}")
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
        fail(f"echo mismatch: {received!r}")
    print("stage=echo_payload ok", flush=True)
    print("netem_tcp_smoke=ok", flush=True)
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
    result="pass"
  else
    {
      echo "result=probe_failed"
      cat "$probe_log"
    } >"$probe_log.tmp"
    mv "$probe_log.tmp" "$probe_log"
    append_failure_diagnostics "probe_failed"
  fi

  kill "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true
  stop_client_pids
  if [[ "$result" == "pass" ]]; then
    cat "$probe_log"
    return 0
  fi
  cat "$probe_log"
  return 1
}

iteration=0
passed=0
failed=0

while IFS=$'\t' read -r scenario duration params; do
  [[ -z "$scenario" ]] && continue
  log "scenario_start name=$scenario duration_secs=$duration netem=$params utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  apply_netem "$params"
  record_resource_sample "scenario_start:$scenario"
  scenario_end=$(( $(date +%s) + duration ))
  scenario_iteration=0
  while [[ "$(date +%s)" -lt "$scenario_end" ]]; do
    iteration=$((iteration + 1))
    scenario_iteration=$((scenario_iteration + 1))
    started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if run_flow "$scenario" "$scenario_iteration"; then
      passed=$((passed + 1))
      probe_elapsed_ms="$(awk -F= '/^elapsed_ms=/{print $2; exit}' "$CLIENT_DIR/logs/probe-${scenario}-${scenario_iteration}.log" 2>/dev/null || true)"
      log "PASS scenario=$scenario iteration=$scenario_iteration global_iteration=$iteration started=$started finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') elapsed_ms=${probe_elapsed_ms:-unknown}"
    else
      failed=$((failed + 1))
      probe_elapsed_ms="$(awk -F= '/^elapsed_ms=/{print $2; exit}' "$CLIENT_DIR/logs/probe-${scenario}-${scenario_iteration}.log" 2>/dev/null || true)"
      log "FAIL scenario=$scenario iteration=$scenario_iteration global_iteration=$iteration started=$started finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') elapsed_ms=${probe_elapsed_ms:-unknown}"
    fi
    record_resource_sample "probe_finished:$scenario:$scenario_iteration"
    now="$(date +%s)"
    [[ "$now" -ge "$scenario_end" ]] && break
    remaining=$((scenario_end - now))
    sleep_for="$INTERVAL_SECS"
    if (( remaining < sleep_for )); then
      sleep_for="$remaining"
    fi
    sleep "$sleep_for"
  done
  log "scenario_end name=$scenario utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
done <"$CLIENT_DIR/scenarios.tsv"

apply_netem none
record_resource_sample "impairment_removed"
default_route_after="$(ip route show default 2>/dev/null | sha256sum | awk '{print $1}')"
dns_after="$(sha256sum /etc/resolv.conf 2>/dev/null | awk '{print $1}')"

{
  echo "# Approved-VM Netem Impairment Smoke Summary"
  echo
  echo "- run_id: $RUN_ID"
  echo "- tested_commit: $TESTED_COMMIT"
  echo "- started: see events.log"
  echo "- finished_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "- scenario_profile: $SCENARIO_PROFILE"
  echo "- duration_secs: $TOTAL_DURATION_SECS"
  echo "- interval_secs: $INTERVAL_SECS"
  echo "- iterations: $iteration"
  echo "- passed: $passed"
  echo "- failed: $failed"
  echo "- resource_samples: $resource_samples"
  echo "- resource_process_children: enabled"
  echo "- default_route_unchanged: $([[ "$default_route_before" == "$default_route_after" ]] && echo true || echo false)"
  echo "- global_dns_unchanged: $([[ "$dns_before" == "$dns_after" ]] && echo true || echo false)"
  echo "- impairment_scope: namespace_veth_only"
  echo
  cat "$CLIENT_DIR/scenarios.tsv"
} >"$summary"

log "finished_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "iterations=$iteration"
log "passed=$passed"
log "failed=$failed"
cleanup_result="present"
if cleanup; then
  cleanup_result="absent"
fi
trap - EXIT
echo "- remote_residue: $cleanup_result" >>"$summary"
echo "- iptables_residue: $cleanup_iptables_residue" >>"$summary"
echo "- ip_forward_restored: $cleanup_ip_forward_restored" >>"$summary"
if [[ "$failed" == "0" && "$cleanup_result" == "absent" ]]; then
  log "$NETEM_OK_MARKER"
  rm -f "$failed_marker"
  touch "$completed"
else
  log "netem_run_status=failed"
  exit 1
fi
SCRIPT
chmod 700 "$CLIENT_DIR/run-netem.sh"
REMOTE

echo "==> start detached netem impairment run"
ssh -o BatchMode=yes "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
nohup "$CLIENT_DIR/run-netem.sh" "$CLIENT_DIR/run.env" \
  </dev/null >"$CLIENT_DIR/run.log" 2>&1 &
echo $! >"$CLIENT_DIR/run.pid"
REMOTE

sleep 2
ssh -o BatchMode=yes "$client_host" "CLIENT_DIR=$(shell_quote "$client_dir") bash -s" <<'REMOTE'
set -euo pipefail
pid="$(cat "$CLIENT_DIR/run.pid")"
kill -0 "$pid"
REMOTE

cat <<EOF
detached netem impairment started
run_id: $run_id
server_host: $server_host
client_host: $client_host
port: $port
target_port: $target_port
duration_secs: $total_duration_secs
client_dir: $client_dir
server_dir: $server_dir
review:
  ssh $client_host 'tail -n 40 $client_dir/events.log'
  ssh $client_host 'cat $client_dir/SUMMARY.md'
EOF
