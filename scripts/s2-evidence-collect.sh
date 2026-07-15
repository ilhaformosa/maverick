#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat >&2 <<'EOF'
usage: scripts/s2-evidence-collect.sh <approved-client-ssh-host> <remote-client-dir> <label>

Read-only collector for S2 detached evidence runs. It copies the remote
`SUMMARY.md`, `events.log`, and available detailed logs from an approved client
host into a local ignored runtime-evidence directory. If a server host/dir is
provided, it also collects server-side `*.log` files.

Examples:
  scripts/s2-evidence-collect.sh <approved-client-host> /tmp/maverick-detached-longhaul-client-20260706T000000Z longhaul
  scripts/s2-evidence-collect.sh <approved-client-host> /tmp/maverick-netem-client-netem-20260706T000000Z netem
  scripts/s2-evidence-collect.sh <approved-client-host> /tmp/maverick-failure-injection-client-failure-20260706T000000Z failure-injection

Optional environment:
  MAVERICK_S2_COLLECT_SSH_BIN      Default ssh.
  MAVERICK_S2_COLLECT_SCP_BIN      Default scp.
  MAVERICK_S2_COLLECT_PYTHON       Default python3.
  MAVERICK_S2_COLLECTION_ROOT      Default runtime-evidence.
  MAVERICK_S2_COLLECTION_SERVER_HOST
  MAVERICK_S2_COLLECTION_SERVER_DIR

This script does not mutate local or remote proxy, DNS, routes, firewall, VPN,
interfaces, traffic-control settings, or remote processes.
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

ssh_config_hostname() {
  local host="$1"
  "$ssh_bin" -G "$host" 2>/dev/null | awk 'tolower($1) == "hostname" { print $2; exit }'
}

reject_local_host() {
  local host="$1"
  case "$host" in
    "" | localhost | 127.* | ::1)
      echo "refusing S2 evidence collection from local host" >&2
      exit 2
      ;;
  esac

  local resolved=""
  resolved="$(ssh_config_hostname "$host" || true)"
  case "$resolved" in
    localhost | 127.* | ::1)
      echo "refusing S2 evidence collection from local host" >&2
      exit 2
      ;;
  esac

  local local_name=""
  local local_short=""
  local_name="$(hostname 2>/dev/null || true)"
  local_short="$(hostname -s 2>/dev/null || true)"
  if [[ -n "$local_name" && ( "$host" == "$local_name" || "$resolved" == "$local_name" ) ]]; then
    echo "refusing S2 evidence collection from local host" >&2
    exit 2
  fi
  if [[ -n "$local_short" && ( "$host" == "$local_short" || "$resolved" == "$local_short" ) ]]; then
    echo "refusing S2 evidence collection from local host" >&2
    exit 2
  fi
}

remote_check() {
  local host="$1"
  local script="$2"
  remote_run "$host" "$script"
}

remote_run() {
  local host="$1"
  local script="$2"
  printf '%s\n' "$script" | "$ssh_bin" -o BatchMode=yes -o ConnectTimeout=10 "$host" bash -s
}

copy_remote_file() {
  local remote_name="$1"
  local local_name="$2"
  "$scp_bin" -q "$client_host:$remote_dir/$remote_name" "$output_dir/$local_name"
}

copy_client_logs() {
  local host="$1"
  local remote_base="$2"
  local local_subdir="$3"
  mkdir -p "$output_dir/$local_subdir"
  if ! remote_check "$host" "test -d $(shell_quote "$remote_base")"; then
    return
  fi
  local quoted_remote_base
  quoted_remote_base="$(shell_quote "$remote_base")"
  if remote_check "$host" "cd $quoted_remote_base && { test -d logs || find . -maxdepth 1 -type f -name '*.log' ! -name 'events.log' -print -quit | grep -q .; }" >/dev/null; then
    remote_run "$host" "
set -euo pipefail
cd $quoted_remote_base
entries=\"\$(mktemp)\"
trap 'rm -f \"\$entries\"' EXIT
if test -d logs; then
  printf '%s\0' logs >>\"\$entries\"
fi
find . -maxdepth 1 -type f -name '*.log' ! -name 'events.log' -printf '%P\0' >>\"\$entries\"
tar --null -czf - --files-from \"\$entries\"
" | tar -xzf - -C "$output_dir/$local_subdir"
  fi
}

copy_server_logs() {
  local host="$1"
  local remote_base="$2"
  local local_subdir="$3"
  mkdir -p "$output_dir/$local_subdir"
  if ! remote_check "$host" "test -d $(shell_quote "$remote_base")"; then
    return
  fi
  local quoted_remote_base
  quoted_remote_base="$(shell_quote "$remote_base")"
  if remote_check "$host" "cd $quoted_remote_base && find . -maxdepth 1 -type f -name '*.log' -print -quit | grep -q ." >/dev/null; then
    remote_run "$host" "
set -euo pipefail
cd $quoted_remote_base
find . -maxdepth 1 -type f -name '*.log' -printf '%P\0' | tar --null -czf - --files-from -
" | tar -xzf - -C "$output_dir/$local_subdir"
  fi
}

ssh_bin="${MAVERICK_S2_COLLECT_SSH_BIN:-ssh}"
scp_bin="${MAVERICK_S2_COLLECT_SCP_BIN:-scp}"
python_bin="${MAVERICK_S2_COLLECT_PYTHON:-python3}"
client_host="${1:-}"
remote_dir="${2:-}"
label="${3:-}"
collection_root="${MAVERICK_S2_COLLECTION_ROOT:-runtime-evidence}"
server_host="${MAVERICK_S2_COLLECTION_SERVER_HOST:-}"
server_dir="${MAVERICK_S2_COLLECTION_SERVER_DIR:-}"

require_non_empty "approved client ssh host" "$client_host"
require_non_empty "remote client dir" "$remote_dir"
require_non_empty "label" "$label"

case "$label" in
  *[!A-Za-z0-9._-]*)
    echo "label may contain only letters, digits, dot, underscore, and dash" >&2
    exit 2
    ;;
esac

case "$remote_dir" in
  /*) ;;
  *)
    echo "remote client dir must be an absolute path" >&2
    exit 2
    ;;
esac

reject_local_host "$client_host"
python3 "$repo_root/scripts/approved-host-guard.py" --ssh-bin "$ssh_bin" "$client_host" >/dev/null

quoted_remote_dir="$(shell_quote "$remote_dir")"
remote_check "$client_host" "
test -d $quoted_remote_dir
test -f $quoted_remote_dir/SUMMARY.md
test -f $quoted_remote_dir/events.log
"

case "$collection_root" in
  /*) collection_base="$collection_root" ;;
  *) collection_base="$repo_root/$collection_root" ;;
esac

started="$(date -u '+%Y%m%dT%H%M%SZ')"
output_dir="$collection_base/s2-$label-$started"
mkdir -p "$output_dir"

copy_remote_file SUMMARY.md SUMMARY.md
copy_remote_file events.log events.log
copy_client_logs "$client_host" "$remote_dir" client-logs
if [[ -n "$server_host" && -n "$server_dir" ]]; then
  reject_local_host "$server_host"
  python3 "$repo_root/scripts/approved-host-guard.py" --ssh-bin "$ssh_bin" "$server_host" >/dev/null
  copy_server_logs "$server_host" "$server_dir" server-logs
fi

remote_marker="$(
  remote_check "$client_host" "
if test -f $quoted_remote_dir/completed.marker; then
  echo completed
elif test -f $quoted_remote_dir/failed.marker; then
  echo failed
else
  echo unmarked
fi
"
)"

cat >"$output_dir/COLLECTION.md" <<EOF
# S2 Evidence Collection

- label: $label
- collected_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- approved_client: redacted-approved-client
- remote_client_dir: redacted
- server_logs_collected: $([[ -n "$server_host" && -n "$server_dir" ]] && echo true || echo false)
- remote_marker: $remote_marker
- files:
  - SUMMARY.md
  - events.log
  - client-logs/
  - server-logs/
  - EVIDENCE_AUDIT.json
  - EVIDENCE_AUDIT.md
  - EVIDENCE_MANIFEST.sha256

This is a local collection record. Redact host labels and environment details
before moving any evidence into docs/history/evidence/.
EOF

cat >"$output_dir/PRIVATE_COLLECTION.md" <<EOF
# Private S2 Evidence Collection

- label: $label
- collected_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- approved_client_host: $client_host
- remote_client_dir: $remote_dir
- approved_server_host: ${server_host:-not-collected}
- remote_server_dir: ${server_dir:-not-collected}
- remote_marker: $remote_marker

This file is intentionally private local evidence. Do not move it into
docs/history/evidence/ or any public release artifact.
EOF

audit_output="$("$python_bin" "$repo_root/scripts/s2-evidence-audit.py" "$output_dir")"
audit_status="$(printf '%s\n' "$audit_output" | awk -F= '$1 == "s2_evidence_audit" { print $2; exit }')"

cat <<EOF
s2_evidence_collection=ok
label=$label
remote_marker=$remote_marker
audit_status=$audit_status
output_dir=$output_dir
client_logs=$output_dir/client-logs
server_logs=$output_dir/server-logs
EOF
