#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/s2-evidence-preflight.sh <approved-server-ssh-host>

Read-only preflight for the S2 independent-evidence gate. This script checks
that the approved server/client hosts, SSH access, remote repos, remote tools,
certificate mode, and optional netem prerequisites are ready before starting
the long-haul, impairment, or failure-injection runs.

It does not run Maverick, does not open public ports, and does not mutate local
or remote proxy, DNS, routes, firewall, VPN, interfaces, or traffic-control
settings. If netem checking is enabled, it only verifies passwordless sudo with
`sudo -n true` on the approved client host.

Required environment:
  MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR
  MAVERICK_PUBLIC_SMOKE_SERVER_NAME
  MAVERICK_PUBLIC_SMOKE_CLIENT_HOST

Certificate environment:
  MAVERICK_PUBLIC_SMOKE_REMOTE_CERT   Required unless generating a test cert.
  MAVERICK_PUBLIC_SMOKE_REMOTE_KEY    Required unless generating a test cert.

Optional environment:
  MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT  Set to 1 to skip remote cert/key.
  MAVERICK_PUBLIC_SMOKE_PORT                Default 24443.
  MAVERICK_PUBLIC_SMOKE_TARGET_PORT         Default 24444.
  MAVERICK_S2_BUILD_HOST                    Default approved client host.
  MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED
                                                Required as 1 for server ports <1024.
  MAVERICK_S2_PREFLIGHT_CHECK_NETEM         Default 1. Set 0 to skip netem.
  MAVERICK_NETEM_IMPAIRMENT_APPROVED        Required as 1 when netem check is on.
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

reject_local_host() {
  local label="$1"
  local host="$2"
  case "$host" in
    "" | localhost | 127.* | ::1)
      echo "refusing S2 preflight against local host: $label" >&2
      exit 2
      ;;
  esac

  local resolved=""
  resolved="$(ssh_config_hostname "$host" || true)"
  case "$resolved" in
    localhost | 127.* | ::1)
      echo "refusing S2 preflight against local host: $label" >&2
      exit 2
      ;;
  esac

  local local_name=""
  local local_short=""
  local_name="$(hostname 2>/dev/null || true)"
  local_short="$(hostname -s 2>/dev/null || true)"
  if [[ -n "$local_name" && ( "$host" == "$local_name" || "$resolved" == "$local_name" ) ]]; then
    echo "refusing S2 preflight against local host: $label" >&2
    exit 2
  fi
  if [[ -n "$local_short" && ( "$host" == "$local_short" || "$resolved" == "$local_short" ) ]]; then
    echo "refusing S2 preflight against local host: $label" >&2
    exit 2
  fi
}

ssh_config_hostname() {
  local host="$1"
  "$ssh_bin" -G "$host" 2>/dev/null | awk 'tolower($1) == "hostname" { print $2; exit }'
}

remote_check() {
  local host="$1"
  local script="$2"
  printf '%s\n' "$script" | "$ssh_bin" -o BatchMode=yes -o ConnectTimeout=10 "$host" bash -s
}

remote_hostname() {
  local host="$1"
  remote_check "$host" 'hostname -f 2>/dev/null || hostname'
}

check_local_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing local command: $command_name" >&2
    exit 2
  fi
}

check_server_port_free() {
  local quoted_port
  local quoted_target_port
  quoted_port="$(shell_quote "$port")"
  quoted_target_port="$(shell_quote "$target_port")"
  remote_check "$server_host" "
PORT=$quoted_port
TARGET_PORT=$quoted_target_port
if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || true) | grep -E \":(\${PORT}|\${TARGET_PORT})\\\\b\"; then
  echo \"requested S2 test port is already listening\" >&2
  exit 1
fi
"
}

check_privileged_port() {
  if (( port >= 1024 )); then
    return
  fi
  if [[ "$privileged_port_approved" != "1" ]]; then
    echo "MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED=1 is required for server ports below 1024" >&2
    exit 2
  fi
  remote_check "$server_host" '
command -v sudo >/dev/null
command -v setcap >/dev/null
sudo -n true
'
}

check_cert_mode() {
  if [[ "$generate_test_cert" == "1" ]]; then
    remote_check "$server_host" 'command -v openssl >/dev/null'
    return
  fi

  require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_CERT" "$remote_cert"
  require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_KEY" "$remote_key"
  local quoted_cert
  local quoted_key
  quoted_cert="$(shell_quote "$remote_cert")"
  quoted_key="$(shell_quote "$remote_key")"
  remote_check "$server_host" "
command -v sudo >/dev/null
sudo -n test -r $quoted_cert
sudo -n test -r $quoted_key
"
}

check_netem_prereqs() {
  if [[ "$check_netem" == "0" ]]; then
    echo "netem_check=skipped"
    return
  fi
  if [[ "${MAVERICK_NETEM_IMPAIRMENT_APPROVED:-0}" != "1" ]]; then
    echo "MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 is required for netem preflight" >&2
    exit 2
  fi

  remote_check "$client_host" '
command -v sudo >/dev/null
command -v ip >/dev/null
command -v tc >/dev/null
command -v iptables >/dev/null
command -v getent >/dev/null
command -v sha256sum >/dev/null
sudo -n true
'
  echo "netem_check=ok"
}

ssh_bin="${MAVERICK_S2_PREFLIGHT_SSH_BIN:-ssh}"
server_host="${1:-${MAVERICK_PUBLIC_SMOKE_REMOTE_HOST:-}}"
remote_addr="${MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR:-}"
server_name="${MAVERICK_PUBLIC_SMOKE_SERVER_NAME:-}"
client_host="${MAVERICK_PUBLIC_SMOKE_CLIENT_HOST:-}"
build_host="${MAVERICK_S2_BUILD_HOST:-$client_host}"
remote_cert="${MAVERICK_PUBLIC_SMOKE_REMOTE_CERT:-}"
remote_key="${MAVERICK_PUBLIC_SMOKE_REMOTE_KEY:-}"
generate_test_cert="${MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT:-0}"
port="${MAVERICK_PUBLIC_SMOKE_PORT:-24443}"
target_port="${MAVERICK_PUBLIC_SMOKE_TARGET_PORT:-24444}"
privileged_port_approved="${MAVERICK_PUBLIC_SMOKE_PRIVILEGED_PORT_APPROVED:-0}"
check_netem="${MAVERICK_S2_PREFLIGHT_CHECK_NETEM:-1}"

require_non_empty "server ssh host" "$server_host"
require_non_empty "MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR" "$remote_addr"
require_non_empty "MAVERICK_PUBLIC_SMOKE_SERVER_NAME" "$server_name"
require_non_empty "MAVERICK_PUBLIC_SMOKE_CLIENT_HOST" "$client_host"
require_non_empty "MAVERICK_S2_BUILD_HOST" "$build_host"

case "$generate_test_cert:$check_netem" in
  0:0 | 0:1 | 1:0 | 1:1) ;;
  *)
    echo "MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT and MAVERICK_S2_PREFLIGHT_CHECK_NETEM must be 0 or 1" >&2
    exit 2
    ;;
esac

case "$port:$target_port" in
  *[!0-9:]*)
    echo "ports must be numeric" >&2
    exit 2
    ;;
esac

if [[ "$server_host" == "$client_host" ]]; then
  echo "server and client SSH hosts must be distinct for S2" >&2
  exit 2
fi

reject_local_host "server" "$server_host"
reject_local_host "client" "$client_host"
reject_local_host "build" "$build_host"
python3 "$repo_root/scripts/approved-host-guard.py" --ssh-bin "$ssh_bin" "$server_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" --ssh-bin "$ssh_bin" "$client_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" --ssh-bin "$ssh_bin" "$build_host" >/dev/null

server_resolved="$(ssh_config_hostname "$server_host" || true)"
client_resolved="$(ssh_config_hostname "$client_host" || true)"
build_resolved="$(ssh_config_hostname "$build_host" || true)"
if [[ -n "$server_resolved" && "$server_resolved" == "$client_resolved" ]]; then
  echo "server and client SSH hosts resolve to the same target" >&2
  exit 2
fi

for command_name in git scp tar python3; do
  check_local_command "$command_name"
done

server_remote_name="$(remote_hostname "$server_host")"
client_remote_name="$(remote_hostname "$client_host")"
build_remote_name="$(remote_hostname "$build_host")"
if [[ -n "$server_remote_name" && "$server_remote_name" == "$client_remote_name" ]]; then
  echo "server and client remote hostnames are the same" >&2
  exit 2
fi

remote_check "$server_host" 'command -v bash >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null && command -v nohup >/dev/null && command -v openssl >/dev/null && command -v gzip >/dev/null'
remote_check "$client_host" 'command -v bash >/dev/null && command -v python3 >/dev/null && command -v timeout >/dev/null && command -v nohup >/dev/null && command -v gzip >/dev/null'
remote_check "$build_host" 'PATH="$HOME/.cargo/bin:$PATH"; command -v bash >/dev/null && command -v python3 >/dev/null && command -v cargo >/dev/null && command -v tar >/dev/null && command -v gzip >/dev/null'
check_cert_mode
check_server_port_free
check_privileged_port
check_netem_prereqs

cat <<EOF
s2_evidence_preflight=ok
server_host=$server_host
client_host=$client_host
build_host=$build_host
remote_addr=$remote_addr
server_name=$server_name
port=$port
target_port=$target_port
binary_source=local_git_archive_built_on_build_host
EOF
