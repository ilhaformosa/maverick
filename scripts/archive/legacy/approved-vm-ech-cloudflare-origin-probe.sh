#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-ech-cloudflare-origin-probe.sh [origin-ssh-host]

Required environment:
  MAVERICK_ECH_ORIGIN_PROBE_APPROVED=1
  MAVERICK_ECH_ORIGIN_IP           Direct origin IP to probe.

Optional environment:
  MAVERICK_ECH_ORIGIN_DOMAIN       Domain to test, default maverick-ech.example.com.
  MAVERICK_ECH_ORIGIN_PROBE_HOST   External SSH probe host, default approved-server-vm.
  MAVERICK_ECH_ORIGIN_LIFETIME     Temporary listener lifetime seconds, default 120.
  MAVERICK_ECH_ORIGIN_ALLOW_BLOCKED=1
                                   Return success while printing blocked status.

This script runs a Cloudflare-fronted origin reachability probe from approved
VMs. It temporarily listens on the origin VM's TCP/80 and TCP/443, uses a
separate external VM to probe direct origin reachability and Cloudflare
front-door reachability, then removes temporary listeners and files.

It does not enable Maverick runtime ECH, mutate DNS records, or change local or
remote proxy, DNS, route, firewall, VPN, or interface settings. It also does
not change cloud firewall rules; if TCP/443 is blocked by the cloud provider,
the script reports that condition.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

origin_host="${1:-${MAVERICK_ECH_ORIGIN_HOST:-approved-linux-vm}}"
domain="${MAVERICK_ECH_ORIGIN_DOMAIN:-maverick-ech.example.com}"
origin_ip="${MAVERICK_ECH_ORIGIN_IP:-}"
probe_host="${MAVERICK_ECH_ORIGIN_PROBE_HOST:-approved-server-vm}"
lifetime="${MAVERICK_ECH_ORIGIN_LIFETIME:-120}"

if [[ "${MAVERICK_ECH_ORIGIN_PROBE_APPROVED:-}" != "1" ]]; then
  echo "MAVERICK_ECH_ORIGIN_PROBE_APPROVED=1 is required" >&2
  usage
  exit 2
fi

if [[ -z "$origin_ip" ]]; then
  echo "MAVERICK_ECH_ORIGIN_IP is required" >&2
  usage
  exit 2
fi

for host in "$origin_host" "$probe_host"; do
  case "$host" in
    ""|localhost|127.*|::1)
      echo "refusing to run approved VM ECH origin probe against local host: $host" >&2
      exit 2
      ;;
  esac
done

case "$domain:$origin_ip:$lifetime" in
  *[!A-Za-z0-9.:-]*|*..*|.*|*.)
    echo "invalid domain, origin IP, or lifetime" >&2
    exit 2
    ;;
esac

case "$lifetime" in
  *[!0-9]*|"")
    echo "listener lifetime must be numeric" >&2
    exit 2
    ;;
esac

python3 "$script_dir/approved-host-guard.py" "$origin_host" >/dev/null
python3 "$script_dir/approved-host-guard.py" "$probe_host" >/dev/null
run_token="$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
state_dir="/tmp/maverick-ech-origin-$run_token"

cleanup_mode() {
  local mode="$1"
  local port="$2"
  ssh -o BatchMode=yes "$origin_host" \
    "MODE=$(shell_quote "$mode") PORT=$(shell_quote "$port") STATE_DIR=$(shell_quote "$state_dir") bash -s" <<'REMOTE' >/dev/null 2>&1 || true
set -euo pipefail
[[ "$STATE_DIR" =~ ^/tmp/maverick-ech-origin-[a-f0-9]{24}$ ]] || exit 1
pid_file="$STATE_DIR/${MODE}.pid"
work="$STATE_DIR/$MODE"
if [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]]; then
  [[ "$(stat -c %u "$STATE_DIR")" == "$(id -u)" && "$(stat -c %a "$STATE_DIR")" == "700" ]] || exit 1
  if [[ -f "$pid_file" && ! -L "$pid_file" ]]; then
    [[ "$(stat -c %u "$pid_file")" == "$(id -u)" ]] || exit 1
    pid="$(cat "$pid_file")"
    [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
    if kill -0 "$pid" 2>/dev/null; then
      command="$(ps -o args= -p "$pid" 2>/dev/null || true)"
      cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
      [[ "$command" == *"$work"* || "$cwd" == "$work" ]] || exit 1
      sudo -n kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  fi
  [[ ! -e "$work" || ( -d "$work" && ! -L "$work" && "$(stat -c %u "$work")" == "$(id -u)" ) ]] || exit 1
  rm -rf "$work" "$pid_file"
  rmdir "$STATE_DIR" 2>/dev/null || true
fi
if ss -ltnp 2>/dev/null | awk -v port="${PORT}" '$4 ~ (":" port "$") {found=1} END {exit found?0:1}'; then
  exit 1
fi
REMOTE
}

cleanup_all() {
  cleanup_mode http80 80
  cleanup_mode https443 443
}
trap cleanup_all EXIT

start_mode() {
  local mode="$1"
  local port="$2"
  ssh -o BatchMode=yes "$origin_host" \
    "MODE=$(shell_quote "$mode") PORT=$(shell_quote "$port") LIFETIME=$(shell_quote "$lifetime") DOMAIN=$(shell_quote "$domain") STATE_DIR=$(shell_quote "$state_dir") bash -s" <<'REMOTE'
set -euo pipefail

for tool in nohup sudo timeout ss; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool on approved origin host: $tool" >&2
    exit 1
  fi
done

case "$MODE" in
  http80)
    for tool in python3; do
      if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool on approved origin host: $tool" >&2
        exit 1
      fi
    done
    ;;
  https443)
    for tool in openssl; do
      if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool on approved origin host: $tool" >&2
        exit 1
      fi
    done
    ;;
  *)
    echo "invalid mode: $MODE" >&2
    exit 2
    ;;
esac

[[ "$STATE_DIR" =~ ^/tmp/maverick-ech-origin-[a-f0-9]{24}$ ]] || exit 1
umask 077
if [[ ! -e "$STATE_DIR" ]]; then
  mkdir -m 700 "$STATE_DIR"
fi
[[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || exit 1
[[ "$(stat -c %u "$STATE_DIR")" == "$(id -u)" && "$(stat -c %a "$STATE_DIR")" == "700" ]] || exit 1
pid_file="$STATE_DIR/${MODE}.pid"
work="$STATE_DIR/$MODE"
[[ ! -e "$pid_file" && ! -e "$work" ]] || exit 1
mkdir -m 700 "$work"

case "$MODE" in
  http80)
    printf '%s\n' "maverick-cloudflare-http-origin-probe" >"$work/index.html"
    (
      cd "$work"
      exec nohup sudo -n timeout "${LIFETIME}s" python3 -m http.server "$PORT" --bind 0.0.0.0
    ) >"$work/server.log" 2>&1 </dev/null &
    ;;
  https443)
    openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=${DOMAIN}" \
      -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 >/dev/null 2>&1
    (
      exec nohup sudo -n timeout "${LIFETIME}s" openssl s_server -quiet -accept "$PORT" \
        -cert "$work/cert.pem" -key "$work/key.pem" -www
    ) >"$work/server.log" 2>&1 </dev/null &
    ;;
esac

pid="$!"
echo "$pid" >"$pid_file"
chmod 600 "$pid_file"
sleep 2

if ! kill -0 "$pid" 2>/dev/null; then
  echo "temporary ${MODE} listener failed to start" >&2
  sed -n '1,80p' "$work/server.log" >&2 || true
  exit 1
fi

if ! ss -ltnp 2>/dev/null | awk -v port="${PORT}" '$4 ~ (":" port "$") {found=1} END {exit found?0:1}'; then
  echo "temporary ${MODE} listener is not visible on TCP/${PORT}" >&2
  sed -n '1,80p' "$work/server.log" >&2 || true
  exit 1
fi
echo "origin_${MODE}_listener=ok"
REMOTE
}

stop_mode() {
  local mode="$1"
  local port="$2"
  ssh -o BatchMode=yes "$origin_host" \
    "MODE=$(shell_quote "$mode") PORT=$(shell_quote "$port") STATE_DIR=$(shell_quote "$state_dir") bash -s" <<'REMOTE'
set -euo pipefail
[[ "$STATE_DIR" =~ ^/tmp/maverick-ech-origin-[a-f0-9]{24}$ ]] || exit 1
[[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || exit 1
[[ "$(stat -c %u "$STATE_DIR")" == "$(id -u)" && "$(stat -c %a "$STATE_DIR")" == "700" ]] || exit 1
pid_file="$STATE_DIR/${MODE}.pid"
work="$STATE_DIR/$MODE"
if [[ -f "$pid_file" && ! -L "$pid_file" ]]; then
  [[ "$(stat -c %u "$pid_file")" == "$(id -u)" ]] || exit 1
  pid="$(cat "$pid_file")"
  [[ "$pid" =~ ^[0-9]+$ ]] || exit 1
  if kill -0 "$pid" 2>/dev/null; then
    command="$(ps -o args= -p "$pid" 2>/dev/null || true)"
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    [[ "$command" == *"$work"* || "$cwd" == "$work" ]] || exit 1
    sudo -n kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
fi
[[ -d "$work" && ! -L "$work" && "$(stat -c %u "$work")" == "$(id -u)" ]] || exit 1
rm -rf "$work" "$pid_file"
rmdir "$STATE_DIR" 2>/dev/null || true
sleep 1
if ss -ltnp 2>/dev/null | awk -v port="${PORT}" '$4 ~ (":" port "$") {found=1; print} END {exit found?0:1}'; then
  echo "origin_${MODE}_residue=present"
  exit 1
fi
echo "origin_${MODE}_residue=none"
REMOTE
}

remote_curl_code() {
  local url="$1"
  local insecure="$2"
  local curl_flags="-sS -o /dev/null -w %{http_code} --max-time 20"
  if [[ "$insecure" == "1" ]]; then
    curl_flags="-k $curl_flags"
  fi

  set +e
  local output
  output="$(ssh -o BatchMode=yes "$probe_host" \
    "curl $curl_flags $(shell_quote "$url") 2>&1")"
  local rc=$?
  set -e
  printf '%s:%s' "$rc" "$output"
}

echo "==> approved VM ECH Cloudflare origin probe"
echo "origin_host=$origin_host"
echo "probe_host=$probe_host"
echo "domain=$domain"
echo "origin_ip=$origin_ip"

blocked=0

start_mode http80 80
direct_http="$(remote_curl_code "http://${origin_ip}/" 0)"
cf_http_origin="$(remote_curl_code "https://${domain}/" 0)"
stop_mode http80 80

direct_http_rc="${direct_http%%:*}"
direct_http_code="${direct_http#*:}"
cf_http_rc="${cf_http_origin%%:*}"
cf_http_code="${cf_http_origin#*:}"

if [[ "$direct_http_rc" == "0" && "$direct_http_code" == "200" ]]; then
  echo "direct_http_origin=ok"
else
  echo "direct_http_origin=blocked rc=${direct_http_rc} code=${direct_http_code}"
  blocked=1
fi

case "$cf_http_code" in
  200|204|301|302|307|308)
    echo "cloudflare_fronted_origin_with_http_listener=reachable code=${cf_http_code}"
    ;;
  521|522|523)
    echo "cloudflare_fronted_origin_with_http_listener=not_required_for_full_mode code=${cf_http_code}"
    ;;
  *)
    echo "cloudflare_fronted_origin_with_http_listener=unexpected rc=${cf_http_rc} code=${cf_http_code}"
    blocked=1
    ;;
esac

start_mode https443 443
direct_https="$(remote_curl_code "https://${origin_ip}/" 1)"
cf_https_origin="$(remote_curl_code "https://${domain}/" 0)"
stop_mode https443 443

direct_https_rc="${direct_https%%:*}"
direct_https_code="${direct_https#*:}"
cf_https_rc="${cf_https_origin%%:*}"
cf_https_code="${cf_https_origin#*:}"

if [[ "$direct_https_rc" == "0" && "$direct_https_code" != "000" ]]; then
  echo "direct_https_origin=reachable code=${direct_https_code}"
else
  echo "direct_https_origin=blocked rc=${direct_https_rc} code=${direct_https_code}"
  blocked=1
fi

if [[ "$cf_https_rc" == "0" && "$cf_https_code" != "000" && "$cf_https_code" != "522" && "$cf_https_code" != "523" ]]; then
  echo "cloudflare_fronted_origin_with_https_listener=reachable code=${cf_https_code}"
else
  echo "cloudflare_fronted_origin_with_https_listener=blocked rc=${cf_https_rc} code=${cf_https_code}"
  blocked=1
fi

if [[ "$blocked" == "0" ]]; then
  echo "approved_vm_ech_cloudflare_origin_probe=ok"
  exit 0
fi

echo "approved_vm_ech_cloudflare_origin_probe=blocked"
if [[ "${MAVERICK_ECH_ORIGIN_ALLOW_BLOCKED:-}" == "1" ]]; then
  exit 0
fi
exit 1
