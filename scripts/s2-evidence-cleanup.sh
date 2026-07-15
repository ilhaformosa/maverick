#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: MAVERICK_S2_CLEANUP_APPROVED=1 scripts/s2-evidence-cleanup.sh \
  <approved-client-host> <remote-client-dir> \
  <approved-server-host> <remote-server-dir>

Removes one already-collected approved-host S2 runtime. It refuses local hosts,
unknown directory prefixes, reused PIDs, active non-test listeners, and netem
namespace/veth residue. It may remove only the exact auto-expiring firewalld
runtime rule recorded by that server runtime.

This script must run only after evidence collection is complete.
EOF
}

shell_quote() {
  printf '%q' "$1"
}

reject_local_host() {
  local host="$1"
  case "$host" in
    "" | localhost | 127.* | ::1)
      echo "refusing S2 cleanup against local host" >&2
      exit 2
      ;;
  esac
  local resolved
  resolved="$(ssh -G "$host" 2>/dev/null | awk 'tolower($1) == "hostname" { print $2; exit }')"
  case "$resolved" in
    localhost | 127.* | ::1)
      echo "refusing S2 cleanup against local host" >&2
      exit 2
      ;;
  esac
  local local_name local_short
  local_name="$(hostname 2>/dev/null || true)"
  local_short="$(hostname -s 2>/dev/null || true)"
  if [[ -n "$local_name" && ( "$host" == "$local_name" || "$resolved" == "$local_name" ) ]]; then
    echo "refusing S2 cleanup against local host" >&2
    exit 2
  fi
  if [[ -n "$local_short" && ( "$host" == "$local_short" || "$resolved" == "$local_short" ) ]]; then
    echo "refusing S2 cleanup against local host" >&2
    exit 2
  fi
}

validate_dir() {
  local role="$1"
  local dir="$2"
  local pattern
  case "$role" in
    client) pattern='^/tmp/maverick-(detached-longhaul|netem|failure-injection)-client-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    server) pattern='^/tmp/maverick-(detached-longhaul|netem|failure-injection)-server-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    *) pattern='a^' ;;
  esac
  if [[ ! "$dir" =~ $pattern ]]; then
    echo "refusing unexpected S2 $role runtime directory" >&2
    exit 2
  fi
}

cleanup_remote_dir() {
  local host="$1"
  local dir="$2"
  local role="$3"

  ssh -o BatchMode=yes "$host" \
    "DIR=$(shell_quote "$dir") ROLE=$(shell_quote "$role") bash -s" <<'REMOTE'
set -euo pipefail

validate_runtime_dir() {
  local pattern
  case "$ROLE" in
    client) pattern='^/tmp/maverick-(detached-longhaul|netem|failure-injection)-client-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    server) pattern='^/tmp/maverick-(detached-longhaul|netem|failure-injection)-server-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    *) pattern='a^' ;;
  esac
  [[ "$DIR" =~ $pattern ]] || {
    echo "remote directory validation failed" >&2
    exit 1
  }
}

require_owned_safe_mode() {
  local path="$1"
  local kind="$2"
  local mode owner
  if [[ "$kind" == "directory" ]]; then
    [[ -d "$path" && ! -L "$path" ]] || {
      echo "refusing non-directory or symlink runtime path" >&2
      exit 1
    }
  else
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "refusing non-regular or symlink runtime file" >&2
      exit 1
    }
  fi
  owner="$(stat -c %u -- "$path")"
  mode="$(stat -c %a -- "$path")"
  [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]{3,4}$ ]] || {
    echo "refusing runtime path with unexpected ownership or mode" >&2
    exit 1
  }
  if (( (8#$mode & 0022) != 0 )); then
    echo "refusing group/other-writable runtime path" >&2
    exit 1
  fi
}

single_log_value() {
  local key="$1"
  local file="$2"
  [[ "$(grep -c "^${key}=" "$file" || true)" == "1" ]] || {
    echo "refusing firewall journal with ambiguous fields" >&2
    exit 1
  }
  sed -n "s/^${key}=//p" "$file"
}

validate_runtime_dir

if [[ ! -e "$DIR" && ! -L "$DIR" ]]; then
  echo "$ROLE.directory=already_absent"
  exit 0
fi
require_owned_safe_mode "$DIR" directory

collect_tree() {
  local pid="$1"
  local child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    collect_tree "$child"
  done
  echo "$pid"
}

shopt -s nullglob
pidfiles=("$DIR"/*.pid "$DIR"/logs/*.pid)
top_pids=()
for path in "${pidfiles[@]}"; do
  require_owned_safe_mode "$path" file
  pid="$(cat "$path" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || continue
  kill -0 "$pid" 2>/dev/null || continue
  command="$(ps -o args= -p "$pid" 2>/dev/null || true)"
  case "$command" in
    *"$DIR"*) top_pids+=("$pid") ;;
    *)
      echo "refusing reused or unrelated pid $pid" >&2
      exit 1
      ;;
  esac
done

tree_pids=()
for pid in "${top_pids[@]}"; do
  while IFS= read -r tree_pid; do
    [[ "$tree_pid" =~ ^[0-9]+$ ]] && tree_pids+=("$tree_pid")
  done < <(collect_tree "$pid")
done
if (( ${#tree_pids[@]} > 0 )); then
  kill "${tree_pids[@]}" 2>/dev/null || true
  sleep 2
  alive=()
  for pid in "${tree_pids[@]}"; do
    kill -0 "$pid" 2>/dev/null && alive+=("$pid")
  done
  if (( ${#alive[@]} > 0 )); then
    kill -KILL "${alive[@]}" 2>/dev/null || true
  fi
fi

if [[ "$ROLE" == "client" && -f "$DIR/run.env" ]]; then
  require_owned_safe_mode "$DIR/run.env" file
  namespace="$(sed -n 's/^NS=//p' "$DIR/run.env")"
  veth_host="$(sed -n 's/^VETH_HOST=//p' "$DIR/run.env")"
  if [[ -n "$namespace" ]] && sudo ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$namespace"; then
    echo "refusing cleanup while netem namespace residue is present" >&2
    exit 1
  fi
  if [[ -n "$veth_host" ]] && ip link show "$veth_host" >/dev/null 2>&1; then
    echo "refusing cleanup while netem veth residue is present" >&2
    exit 1
  fi
fi

firewall_result="not_applicable"
if [[ "$ROLE" == "server" && -f "$DIR/firewall.log" ]]; then
  require_owned_safe_mode "$DIR/firewall.log" file
  requested="$(single_log_value requested "$DIR/firewall.log")"
  action="$(single_log_value action "$DIR/firewall.log")"
  firewall_port_value="$(single_log_value port "$DIR/firewall.log")"
  expiry_secs="$(single_log_value expiry_secs "$DIR/firewall.log")"
  [[ "$firewall_port_value" =~ ^([0-9]+)\/tcp$ && "$expiry_secs" =~ ^[0-9]+$ ]] || {
    echo "refusing firewall journal with invalid scope" >&2
    exit 1
  }
  firewall_port="${firewall_port_value%/tcp}"
  (( firewall_port >= 1 && firewall_port <= 65535 && expiry_secs >= 1 && expiry_secs <= 172800 )) || {
    echo "refusing firewall journal outside allowed scope" >&2
    exit 1
  }
  if [[ "$requested" == "1" && "$action" == "temporarily_opened" ]]; then
    [[ "$(single_log_value state_before "$DIR/firewall.log")" == "closed" ]]
    [[ "$(single_log_value state_after "$DIR/firewall.log")" == "open" ]]
    require_owned_safe_mode "$DIR/server.yaml" file
    grep -Fqx "listen: \"0.0.0.0:${firewall_port}\"" "$DIR/server.yaml" || {
      echo "refusing firewall cleanup without matching server configuration" >&2
      exit 1
    }
    if ss -H -lnt | awk '{print $4}' | grep -Eq "(^|:)$firewall_port$"; then
      echo "refusing firewall cleanup while test port is listening" >&2
      exit 1
    fi
    if command -v firewall-cmd >/dev/null && \
      sudo -n firewall-cmd --query-port="$firewall_port/tcp" >/dev/null 2>&1; then
      sudo -n firewall-cmd --remove-port="$firewall_port/tcp" >/dev/null
      firewall_result="removed"
    else
      firewall_result="already_absent"
    fi
  elif [[ "$requested" == "0" && "$action" == "disabled" ]]; then
    firewall_result="disabled"
  else
    echo "refusing firewall journal without exact ownership provenance" >&2
    exit 1
  fi
fi

rm -rf "$DIR"
test ! -e "$DIR"
echo "$ROLE.directory=absent"
echo "$ROLE.firewall=$firewall_result"
REMOTE
}

if [[ "${MAVERICK_S2_CLEANUP_APPROVED:-0}" != "1" ]]; then
  echo "MAVERICK_S2_CLEANUP_APPROVED=1 is required" >&2
  usage
  exit 2
fi

client_host="${1:-}"
client_dir="${2:-}"
server_host="${3:-}"
server_dir="${4:-}"
if [[ -z "$client_host" || -z "$client_dir" || -z "$server_host" || -z "$server_dir" ]]; then
  usage
  exit 2
fi

validate_dir client "$client_dir"
validate_dir server "$server_dir"
reject_local_host "$client_host"
reject_local_host "$server_host"
python3 "$repo_root/scripts/approved-host-guard.py" "$client_host" >/dev/null
python3 "$repo_root/scripts/approved-host-guard.py" "$server_host" >/dev/null

cleanup_remote_dir "$client_host" "$client_dir" client
cleanup_remote_dir "$server_host" "$server_dir" server
echo "cleanup_status=ok"
