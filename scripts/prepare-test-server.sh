#!/usr/bin/env bash
set -euo pipefail

# This tool prepares an explicitly authorized, disposable Ubuntu test origin.
# It may install Ubuntu-provided default-kernel updates during the full package
# upgrade. It never installs a custom kernel, reboots the host, starts Maverick,
# or changes a live qdisc with `tc`.

export LC_ALL=C
unset \
  APT_CONFIG BASH_ENV CDPATH DPKG_ADMINDIR DPKG_ROOT ENV MODPROBE_OPTIONS
IFS=$' \t\n'

readonly EXIT_REBOOT_REQUIRED=20
readonly EXIT_SAFETY_GATE=21
readonly EXIT_BBR_UNAVAILABLE=22
readonly EXIT_OS_POLICY=23
readonly EXIT_VERIFY_FAILED=24
readonly EXIT_ROOT_REQUIRED=25

action="${1:-}"
if [[ -n "$action" ]]; then
  shift
fi

allow_2404_fallback=false
fallback_reason=""

usage() {
  cat <<'EOF'
Usage:
  prepare-test-server.sh preflight
  prepare-test-server.sh prepare
  prepare-test-server.sh verify

Ubuntu 26.04 is the default test-server OS. Ubuntu 24.04 is accepted only with:
  --allow-24.04-fallback --fallback-reason "non-secret reason"

Exit codes:
  20  a manual reboot is required before continuing
  21  a package or configuration safety gate blocked the operation
  22  the stock Ubuntu BBRv1 path is unavailable or ambiguous
  23  the OS does not satisfy the test-server policy
  24  persistent or runtime verification failed
  25  prepare must run as root
EOF
}

fail() {
  local code="$1"
  local message="$2"
  printf 'BLOCKED: %s\n' "$message" >&2
  exit "$code"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-24.04-fallback)
      allow_2404_fallback=true
      shift
      ;;
    --fallback-reason)
      [[ $# -ge 2 ]] || fail 2 "--fallback-reason needs a value"
      fallback_reason="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail 2 "unknown option"
      ;;
  esac
done

case "$action" in
  preflight|prepare|verify) ;;
  -h|--help|"")
    usage
    [[ -n "$action" ]] && exit 0
    exit 2
    ;;
  *)
    fail 2 "unknown action"
    ;;
esac

for critical_command in \
  apt-get apt-mark apt-cache awk cat chmod dpkg-query grep md5sum mktemp \
  modinfo modprobe mkdir mv networkctl rm rmdir stat sysctl ip tc uname; do
  unset -f "$critical_command" 2>/dev/null || true
done

# Tests use an isolated filesystem tree and fake commands. Real runs use a
# fixed system PATH and cannot inherit the test bypass.
test_mode="${MAVERICK_TEST_MODE:-0}"
host_root=""
test_bin=""
temporary_apt_log=""
case "$test_mode" in
  0)
    PATH="/usr/sbin:/usr/bin:/sbin:/bin"
    export PATH
    ;;
  isolated-fixture-v1)
    [[ "$EUID" -ne 0 ]] ||
      fail "$EXIT_SAFETY_GATE" "isolated test mode is forbidden for root"
    host_root="${MAVERICK_TEST_ROOT:-}"
    test_bin="${MAVERICK_TEST_BIN:-}"
    [[ -d "$host_root" && -d "$test_bin" ]] ||
      fail "$EXIT_SAFETY_GATE" "test mode requires isolated root and command directories"
    host_root="$(cd "$host_root" && pwd -P)"
    test_bin="$(cd "$test_bin" && pwd -P)"
    temporary_base="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
    case "$host_root/" in
      "$temporary_base/"*) ;;
      *) fail "$EXIT_SAFETY_GATE" "test root must be below the canonical temporary directory" ;;
    esac
    case "$test_bin/" in
      "$temporary_base/"*) ;;
      *) fail "$EXIT_SAFETY_GATE" "test command directory must be below the canonical temporary directory" ;;
    esac
    [[ -f "$host_root/.maverick-isolated-fixture-v1" ]] ||
      fail "$EXIT_SAFETY_GATE" "test root marker is missing"
    [[ "$(<"$host_root/.maverick-isolated-fixture-v1")" == "maverick-isolated-fixture-v1" ]] ||
      fail "$EXIT_SAFETY_GATE" "test root marker is invalid"
    PATH="$test_bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export PATH
    ;;
  *)
    fail "$EXIT_SAFETY_GATE" "unknown test mode is forbidden"
    ;;
esac

cleanup() {
  if [[ -n "${temporary_apt_log:-}" ]]; then
    rm -f -- "$temporary_apt_log"
  fi
}
trap cleanup EXIT

host_path() {
  printf '%s%s' "$host_root" "$1"
}

check_test_command_isolation() {
  local command_name
  local resolved
  [[ "$test_mode" == "isolated-fixture-v1" ]] || return 0
  for command_name in \
    apt-get apt-mark apt-cache dpkg-query md5sum modinfo modprobe \
    networkctl sysctl ip tc uname; do
    resolved="$(command -v "$command_name" 2>/dev/null || true)"
    case "$resolved" in
      "$test_bin/"*)
        [[ -f "$resolved" && ! -L "$resolved" ]] ||
          fail "$EXIT_SAFETY_GATE" "an isolated test command is missing or symbolic"
        ;;
      *) fail "$EXIT_SAFETY_GATE" "a test command escaped the isolated command directory" ;;
    esac
  done
}
check_test_command_isolation

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

read_os_field() {
  local wanted="$1"
  local os_release
  local line
  local value
  os_release="$(host_path /etc/os-release)"
  [[ -f "$os_release" ]] || fail "$EXIT_OS_POLICY" "Ubuntu release metadata is missing"

  while IFS= read -r line; do
    case "$line" in
      "$wanted="*)
        value="${line#*=}"
        value="${value#\"}"
        value="${value%\"}"
        printf '%s' "$value"
        return 0
        ;;
    esac
  done <"$os_release"
  fail "$EXIT_OS_POLICY" "Ubuntu release metadata is incomplete"
}

check_os_policy() {
  local os_id
  local version_id
  os_id="$(read_os_field ID)"
  version_id="$(read_os_field VERSION_ID)"

  [[ "$os_id" == "ubuntu" ]] ||
    fail "$EXIT_OS_POLICY" "only Ubuntu test servers are accepted"

  case "$version_id" in
    26.04)
      printf 'OK: Ubuntu 26.04 test-server policy\n'
      ;;
    24.04)
      if [[ "$allow_2404_fallback" != "true" || -z "$(trim "$fallback_reason")" ]]; then
        fail "$EXIT_OS_POLICY" "Ubuntu 24.04 needs an explicit fallback flag and reason"
      fi
      printf 'OK: explicitly justified Ubuntu 24.04 fallback\n'
      ;;
    *)
      fail "$EXIT_OS_POLICY" "Ubuntu release is outside the test-server policy"
      ;;
  esac
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 ||
      fail "$EXIT_SAFETY_GATE" "a required host command is unavailable"
  done
}

check_root_owned_safe_path() {
  local path="$1"
  local metadata
  local owner
  local mode
  local permission_bits

  [[ "$test_mode" == "0" ]] || return 0
  [[ -e "$path" && ! -L "$path" ]] ||
    fail "$EXIT_SAFETY_GATE" "a managed path or parent is missing or symbolic"
  metadata="$(stat -c '%u %a' "$path" 2>/dev/null || true)"
  owner="${metadata%% *}"
  mode="${metadata#* }"
  [[ "$owner" == "0" && "$mode" =~ ^[0-7]{3,4}$ ]] ||
    fail "$EXIT_SAFETY_GATE" "a managed path or parent has unsafe ownership metadata"
  permission_bits=$((8#$mode))
  (( (permission_bits & 0022) == 0 )) ||
    fail "$EXIT_SAFETY_GATE" "a managed path or parent is group- or world-writable"
}

check_managed_path_safety() {
  check_root_owned_safe_path /
  check_root_owned_safe_path /etc
  check_root_owned_safe_path /etc/modules-load.d
  check_root_owned_safe_path /etc/sysctl.d
  check_root_owned_safe_path /etc/systemd
  check_root_owned_safe_path /etc/systemd/network
  [[ ! -e /etc/modules-load.d/99-maverick-test-network.conf ]] ||
    check_root_owned_safe_path /etc/modules-load.d/99-maverick-test-network.conf
  [[ ! -e /etc/sysctl.d/99-maverick-test-network.conf ]] ||
    check_root_owned_safe_path /etc/sysctl.d/99-maverick-test-network.conf
}

check_reboot_gate() {
  if [[ -e "$(host_path /var/run/reboot-required)" ]]; then
    fail "$EXIT_REBOOT_REQUIRED" "manual reboot required; do not start Maverick"
  fi
}

check_stock_bbrv1_evidence() {
  local require_loaded="${1:-false}"
  local sys_version=""
  local module_version=""
  local sys_version_file

  sys_version_file="$(host_path /sys/module/tcp_bbr/version)"
  if [[ -f "$sys_version_file" ]]; then
    sys_version="$(trim "$(<"$sys_version_file")")"
  fi
  module_version="$(modinfo -F version tcp_bbr 2>/dev/null || true)"
  module_version="$(trim "${module_version%%$'\n'*}")"

  # Mainline Linux BBRv1 normally publishes no module version field. Accept an
  # absent field or an explicit "1" only after the separate Ubuntu stock-kernel
  # package and checksum gate has passed. Reject declared v3 or unknown
  # implementations rather than silently changing the requested baseline.
  if [[ -n "$module_version" && "$module_version" != "1" ]]; then
    fail "$EXIT_BBR_UNAVAILABLE" "installed tcp_bbr metadata conflicts with the stock BBRv1 policy"
  fi
  if [[ -n "$sys_version" && "$sys_version" != "1" ]]; then
    fail "$EXIT_BBR_UNAVAILABLE" "loaded tcp_bbr metadata conflicts with the stock BBRv1 policy"
  fi
  if [[ "$require_loaded" == "true" ]]; then
    local available
    available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
    case " $available " in
      *" bbr "*) ;;
      *) fail "$EXIT_BBR_UNAVAILABLE" "the stock BBR implementation is not available after loading" ;;
    esac
  fi

  printf 'OK: stock Ubuntu tcp_bbr is compatible with the BBRv1 policy\n'
}

package_is_current_ubuntu() {
  local package_name="$1"
  local status
  local installed
  local policy
  local policy_installed
  local candidate
  local candidate_metadata
  local candidate_origin

  status="$(dpkg-query -W -f='${db:Status-Abbrev}' "$package_name" 2>/dev/null || true)"
  case "$status" in
    ii*) ;;
    *) return 1 ;;
  esac

  installed="$(dpkg-query -W -f='${Version}' "$package_name" 2>/dev/null || true)"
  policy="$(apt-cache policy "$package_name" 2>/dev/null || true)"
  policy_installed="$(
    printf '%s\n' "$policy" |
      awk '$1 == "Installed:" { print $2; exit }'
  )"
  candidate="$(
    printf '%s\n' "$policy" |
      awk '$1 == "Candidate:" { print $2; exit }'
  )"

  [[ -n "$installed" && "$installed" != "(none)" ]] || return 1
  [[ "$policy_installed" == "$installed" && "$candidate" == "$installed" ]] || return 1

  candidate_metadata="$(apt-cache show "$package_name=$candidate" 2>/dev/null || true)"
  candidate_origin="$(
    printf '%s\n' "$candidate_metadata" |
      awk '$1 == "Origin:" { print $2; exit }'
  )"
  [[ "$candidate_origin" == "Ubuntu" ]]
}

check_package_current() {
  package_is_current_ubuntu "$1" ||
    fail "$EXIT_SAFETY_GATE" "a kernel package is not current or lacks declared Ubuntu origin"
}

check_stock_kernel_provenance() {
  local running_kernel
  local meta_package
  local candidate_meta
  local module_path
  local module_lookup_path
  local alternate_lookup_path
  local owner_line
  local owner_package
  local expected_modules
  local expected_extra
  local image_package
  local image_path
  local image_owner_line
  local image_owner_package
  local dependency_closure
  local image_md5_manifest
  local image_relative
  local image_recorded_md5
  local image_actual_md5
  local md5_manifest
  local module_relative
  local alternate_relative
  local recorded_md5
  local actual_md5

  running_kernel="$(uname -r 2>/dev/null || true)"
  case "$running_kernel" in
    *-generic|*-virtual) ;;
    *)
      fail "$EXIT_SAFETY_GATE" "the running kernel is not an Ubuntu generic or virtual default flavour"
      ;;
  esac

  module_path="$(modinfo -n tcp_bbr 2>/dev/null || true)"
  case "$module_path" in
    "$(host_path "/lib/modules/$running_kernel/")"*|"$(host_path "/usr/lib/modules/$running_kernel/")"*)
      ;;
    *)
      fail "$EXIT_SAFETY_GATE" "tcp_bbr is not a packaged module for the running Ubuntu kernel"
      ;;
  esac
  [[ -f "$module_path" ]] ||
    fail "$EXIT_SAFETY_GATE" "the packaged tcp_bbr module file is missing"

  module_lookup_path="$module_path"
  alternate_lookup_path="$module_path"
  case "$module_path" in
    "$(host_path /lib/)"*)
      alternate_lookup_path="$(host_path /usr/lib/)${module_path#"$(host_path /lib/)"}"
      ;;
    "$(host_path /usr/lib/)"*)
      alternate_lookup_path="$(host_path /lib/)${module_path#"$(host_path /usr/lib/)"}"
      ;;
  esac
  owner_line="$(dpkg-query -S "$module_lookup_path" 2>/dev/null || true)"
  if [[ -z "$owner_line" && "$alternate_lookup_path" != "$module_lookup_path" ]]; then
    owner_line="$(dpkg-query -S "$alternate_lookup_path" 2>/dev/null || true)"
  fi
  owner_line="${owner_line%%$'\n'*}"
  owner_package="${owner_line%%:*}"
  expected_modules="linux-modules-$running_kernel"
  expected_extra="linux-modules-extra-$running_kernel"
  image_package="linux-image-$running_kernel"
  case "$owner_package" in
    "$expected_modules"|"$expected_extra") ;;
    *)
      fail "$EXIT_SAFETY_GATE" "tcp_bbr is not owned by the running Ubuntu kernel package"
      ;;
  esac

  check_package_current "$image_package"
  check_package_current "$owner_package"

  meta_package=""
  for candidate_meta in linux-generic linux-virtual; do
    package_is_current_ubuntu "$candidate_meta" || continue
    dependency_closure="$(
      apt-cache depends --recurse --important "$candidate_meta" 2>/dev/null || true
    )"
    if printf '%s\n' "$dependency_closure" |
      awk -v image="$image_package" '
        ($1 == "Depends:" || $1 == "PreDepends:" ||
         $1 == "|Depends:" || $1 == "|PreDepends:") && $2 == image {
          found = 1
        }
        END { exit(found ? 0 : 1) }
      '; then
      meta_package="$candidate_meta"
      break
    fi
  done
  if [[ -z "$meta_package" ]]; then
    fail "$EXIT_SAFETY_GATE" "the current default-kernel meta candidate does not select the running image"
  fi

  image_path="$(host_path "/boot/vmlinuz-$running_kernel")"
  [[ -f "$image_path" ]] ||
    fail "$EXIT_SAFETY_GATE" "the running Ubuntu kernel image file is missing"
  image_owner_line="$(dpkg-query -S "$image_path" 2>/dev/null || true)"
  image_owner_line="${image_owner_line%%$'\n'*}"
  image_owner_package="${image_owner_line%%:*}"
  [[ "$image_owner_package" == "$image_package" ]] ||
    fail "$EXIT_SAFETY_GATE" "the running kernel image is not owned by its Ubuntu image package"

  image_md5_manifest="$(host_path "/var/lib/dpkg/info/$image_package.md5sums")"
  [[ -f "$image_md5_manifest" ]] ||
    fail "$EXIT_SAFETY_GATE" "the Ubuntu kernel image checksum manifest is missing"
  image_relative="${image_path#"$host_root"/}"
  image_recorded_md5="$(
    awk -v path="$image_relative" '$2 == path { print $1; exit }' "$image_md5_manifest"
  )"
  image_actual_md5="$(md5sum "$image_path" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  [[ -n "$image_recorded_md5" && "$image_actual_md5" == "$image_recorded_md5" ]] ||
    fail "$EXIT_SAFETY_GATE" "the running kernel image does not match its Ubuntu package checksum"

  md5_manifest="$(host_path "/var/lib/dpkg/info/$owner_package.md5sums")"
  [[ -f "$md5_manifest" ]] ||
    fail "$EXIT_SAFETY_GATE" "the Ubuntu kernel module checksum manifest is missing"
  module_relative="${module_path#"$host_root"/}"
  alternate_relative="$module_relative"
  case "$module_relative" in
    lib/*) alternate_relative="usr/$module_relative" ;;
    usr/lib/*) alternate_relative="${module_relative#usr/}" ;;
  esac
  recorded_md5="$(
    awk -v first="$module_relative" -v second="$alternate_relative" \
      '$2 == first || $2 == second { print $1; exit }' "$md5_manifest"
  )"
  actual_md5="$(md5sum "$module_path" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  [[ -n "$recorded_md5" && "$actual_md5" == "$recorded_md5" ]] ||
    fail "$EXIT_SAFETY_GATE" "the tcp_bbr module does not match its Ubuntu package checksum"

  printf 'OK: Ubuntu default-kernel package provenance verified\n'
}

selected_qdisc=""
selected_scheduler_module=""
managed_modules_content=""
managed_sysctl_content=""
modules_file="$(host_path /etc/modules-load.d/99-maverick-test-network.conf)"
sysctl_file="$(host_path /etc/sysctl.d/99-maverick-test-network.conf)"
managed_sysctl_basename="${sysctl_file##*/}"
network_file_basename=""
network_dropin_dir=""
network_dropin_file=""
managed_networkd_content=""
created_modules_file=false
created_sysctl_file=false
created_network_dropin_file=false
created_network_dropin_dir=false

is_supported_qdisc() {
  case "$(trim "$1")" in
    fq|fq_codel) return 0 ;;
    *) return 1 ;;
  esac
}

configure_network_policy() {
  local active_qdisc
  local active_qdisc_status

  selected_qdisc="$(
    sysctl -n net.core.default_qdisc 2>/dev/null || true
  )"
  selected_qdisc="$(trim "$selected_qdisc")"
  is_supported_qdisc "$selected_qdisc" ||
    fail "$EXIT_SAFETY_GATE" "the configured default qdisc must be fq or fq_codel"

  active_qdisc=""
  active_qdisc_status=0
  active_qdisc="$(default_route_qdisc_kind)" || active_qdisc_status=$?
  case "$active_qdisc_status" in
    0) selected_qdisc="$active_qdisc" ;;
    1) ;;
    *)
      fail "$EXIT_VERIFY_FAILED" "the active qdisc could not be inspected safely"
      ;;
  esac

  case "$selected_qdisc" in
    fq) selected_scheduler_module="sch_fq" ;;
    fq_codel) selected_scheduler_module="sch_fq_codel" ;;
  esac
  managed_modules_content=$'tcp_bbr\n'"$selected_scheduler_module"
  managed_sysctl_content="$(
    printf 'net.core.default_qdisc = %s\n' "$selected_qdisc"
    printf 'net.ipv4.tcp_congestion_control = bbr'
  )"
}

configure_networkd_policy() {
  local interface_name
  local network_file

  interface_name="$(default_route_interface)"
  case "$interface_name" in
    ""|*[!A-Za-z0-9_.:@-]*)
      fail "$EXIT_VERIFY_FAILED" "the first IPv4 default-route interface is invalid"
      ;;
  esac
  network_file="$(
    SYSTEMD_COLORS=0 networkctl --no-pager --full status "$interface_name" 2>/dev/null |
      awk '$1 == "Network" && $2 == "File:" { print $3 }'
  )" ||
    fail "$EXIT_SAFETY_GATE" "systemd-networkd could not identify the effective network file"
  [[ -n "$network_file" && "$network_file" != *$'\n'* ]] ||
    fail "$EXIT_SAFETY_GATE" "systemd-networkd did not report one effective network file"
  network_file_basename="${network_file##*/}"
  [[ "$network_file_basename" =~ ^[A-Za-z0-9_.@-]+\.network$ ]] ||
    fail "$EXIT_SAFETY_GATE" "the effective network filename is unsafe"
  case "$network_file" in
    "/etc/systemd/network/$network_file_basename"|\
    "/run/systemd/network/$network_file_basename"|\
    "/usr/local/lib/systemd/network/$network_file_basename"|\
    "/usr/lib/systemd/network/$network_file_basename")
      ;;
    *)
      fail "$EXIT_SAFETY_GATE" "the effective network file is outside the managed path policy"
      ;;
  esac
  network_file="$(host_path "$network_file")"
  [[ -f "$network_file" && ! -L "$network_file" ]] ||
    fail "$EXIT_SAFETY_GATE" "the effective network file is missing, symbolic, or not regular"
  check_root_owned_safe_path "${network_file%/*}"
  check_root_owned_safe_path "$network_file"

  network_dropin_dir="$(host_path "/etc/systemd/network/$network_file_basename.d")"
  network_dropin_file="$network_dropin_dir/99-maverick-test-qdisc.conf"
  if [[ "$selected_qdisc" == "fq" ]]; then
    managed_networkd_content=$'[FairQueueing]\nParent=root'
  else
    managed_networkd_content=$'[FairQueueingControlledDelay]\nParent=root'
  fi

  if [[ -e "$network_dropin_dir" || -L "$network_dropin_dir" ]]; then
    [[ -d "$network_dropin_dir" && ! -L "$network_dropin_dir" ]] ||
      fail "$EXIT_SAFETY_GATE" "the native qdisc drop-in path is unsafe"
    check_root_owned_safe_path "$network_dropin_dir"
  fi
}

check_managed_target() {
  local file="$1"
  local expected="$2"
  local actual

  [[ ! -L "$file" ]] ||
    fail "$EXIT_SAFETY_GATE" "a managed configuration target is a symbolic link"
  if [[ -e "$file" ]]; then
    [[ -f "$file" ]] ||
      fail "$EXIT_SAFETY_GATE" "a managed configuration target is not a regular file"
    actual="$(<"$file")"
    [[ "$actual" == "$expected" ]] ||
      fail "$EXIT_SAFETY_GATE" "an existing managed configuration has unexpected content"
  fi
}

normalize_sysctl_key() {
  local key
  key="$(trim "$1")"
  key="${key#-}"
  key="${key//\//.}"
  printf '%s' "$key"
}

check_sysctl_conflicts() {
  local directory
  local file
  local raw
  local line
  local key
  local value

  file="$(host_path /etc/sysctl.conf)"
  if [[ -f "$file" ]]; then
    while IFS= read -r raw || [[ -n "$raw" ]]; do
      line="${raw%%#*}"
      [[ "$line" == *"="* ]] || continue
      key="$(normalize_sysctl_key "${line%%=*}")"
      value="$(trim "${line#*=}")"
      case "$key" in
        net.core.default_qdisc)
          is_supported_qdisc "$value" ||
            fail "$EXIT_SAFETY_GATE" "an unsupported default qdisc setting already exists"
          [[ "$value" == "$selected_qdisc" ]] ||
            fail "$EXIT_SAFETY_GATE" "sysctl.conf would replace the selected qdisc after reboot"
          ;;
        net.ipv4.tcp_congestion_control)
          [[ "$value" == "bbr" ]] ||
            fail "$EXIT_SAFETY_GATE" "a conflicting congestion-control setting already exists"
          ;;
      esac
    done <"$file"
  fi

  for directory in \
    /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d \
    /usr/lib/sysctl.d /lib/sysctl.d; do
    for file in "$(host_path "$directory/")"*.conf; do
      [[ -f "$file" ]] || continue
      while IFS= read -r raw || [[ -n "$raw" ]]; do
        line="${raw%%#*}"
        [[ "$line" == *"="* ]] || continue
        key="$(normalize_sysctl_key "${line%%=*}")"
        value="$(trim "${line#*=}")"
        case "$key" in
          net.core.default_qdisc)
            is_supported_qdisc "$value" ||
              fail "$EXIT_SAFETY_GATE" "an effective sysctl directory contains an unsupported qdisc"
            if [[ "$value" != "$selected_qdisc" &&
              "${file##*/}" > "$managed_sysctl_basename" ]]; then
              fail "$EXIT_SAFETY_GATE" "a later sysctl file would replace the selected qdisc after reboot"
            fi
            ;;
          net.ipv4.tcp_congestion_control)
            [[ "$value" == "bbr" ]] ||
              fail "$EXIT_SAFETY_GATE" "an effective sysctl directory contains conflicting congestion control"
            ;;
        esac
      done <"$file"
    done
  done
}

check_module_conflicts() {
  local directory
  local file
  local line
  local directive
  local module_name
  for directory in \
    /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
    /usr/lib/modprobe.d /lib/modprobe.d; do
    for file in "$(host_path "$directory/")"*.conf; do
      [[ -f "$file" ]] || continue
      while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "${line%%#*}")"
        directive=""
        module_name=""
        read -r directive module_name _ <<<"$line"
        module_name="${module_name//-/_}"
        if [[ "$directive" == "blacklist" || "$directive" == "install" ]]; then
          if [[ "$module_name" == "tcp_bbr" ||
            "$module_name" == "$selected_scheduler_module" ]]; then
            fail "$EXIT_SAFETY_GATE" "an effective modprobe directory conflicts with BBR or the selected qdisc"
          fi
        fi
      done <"$file"
    done
  done
}

check_configuration_conflicts() {
  check_managed_target "$modules_file" "$managed_modules_content"
  check_managed_target "$sysctl_file" "$managed_sysctl_content"
  check_managed_target "$network_dropin_file" "$managed_networkd_content"
  check_sysctl_conflicts
  check_module_conflicts
}

stage_managed_file() {
  local file="$1"
  local content="$2"
  local result_variable="$3"
  local temporary

  printf -v "$result_variable" '%s' ""
  if [[ -f "$file" && "$(<"$file")" == "$content" ]]; then
    return 0
  fi

  temporary="$(mktemp "${file%/*}/.maverick-network.XXXXXX")" || return 1
  if ! chmod 0644 "$temporary" || ! printf '%s\n' "$content" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  printf -v "$result_variable" '%s' "$temporary"
}

rollback_created_policy() {
  if [[ "$created_network_dropin_file" == "true" ]]; then
    rm -f -- "$network_dropin_file"
    created_network_dropin_file=false
  fi
  if [[ "$created_sysctl_file" == "true" ]]; then
    rm -f -- "$sysctl_file"
    created_sysctl_file=false
  fi
  if [[ "$created_modules_file" == "true" ]]; then
    rm -f -- "$modules_file"
    created_modules_file=false
  fi
  if [[ "$created_network_dropin_dir" == "true" ]]; then
    rmdir -- "$network_dropin_dir" >/dev/null 2>&1 || true
    created_network_dropin_dir=false
  fi
}

persist_networkd_policy() {
  local stage=""

  if [[ ! -d "$network_dropin_dir" ]]; then
    mkdir -m 0755 -- "$network_dropin_dir" ||
      fail "$EXIT_SAFETY_GATE" "could not create the native qdisc drop-in directory"
    created_network_dropin_dir=true
  fi
  if [[ -L "$network_dropin_dir" ]] ||
    ! stage_managed_file "$network_dropin_file" "$managed_networkd_content" stage; then
    rollback_created_policy
    fail "$EXIT_SAFETY_GATE" "could not stage the native qdisc policy"
  fi
  if [[ -n "$stage" ]] && ! mv -f -- "$stage" "$network_dropin_file"; then
    rm -f -- "$stage"
    rollback_created_policy
    fail "$EXIT_SAFETY_GATE" "could not atomically install the native qdisc policy"
  elif [[ -n "$stage" ]]; then
    created_network_dropin_file=true
  fi
}

persist_network_policy() {
  local modules_stage=""
  local sysctl_stage=""

  persist_networkd_policy
  if ! stage_managed_file "$modules_file" "$managed_modules_content" modules_stage; then
    rollback_created_policy
    fail "$EXIT_SAFETY_GATE" "could not stage the module policy"
  fi
  if ! stage_managed_file "$sysctl_file" "$managed_sysctl_content" sysctl_stage; then
    [[ -z "$modules_stage" ]] || rm -f -- "$modules_stage"
    rollback_created_policy
    fail "$EXIT_SAFETY_GATE" "could not stage the sysctl policy"
  fi

  if [[ -n "$modules_stage" ]]; then
    if ! mv -f -- "$modules_stage" "$modules_file"; then
      rm -f -- "$modules_stage"
      [[ -z "$sysctl_stage" ]] || rm -f -- "$sysctl_stage"
      rollback_created_policy
      fail "$EXIT_SAFETY_GATE" "could not atomically install the module policy"
    fi
    created_modules_file=true
  fi

  if [[ -n "$sysctl_stage" ]]; then
    if [[ "$test_mode" == "isolated-fixture-v1" &&
      "${MAVERICK_TEST_FAIL_SECOND_POLICY_MOVE:-0}" == "1" ]] ||
      ! mv -f -- "$sysctl_stage" "$sysctl_file"; then
      rm -f -- "$sysctl_stage"
      rollback_created_policy
      fail "$EXIT_SAFETY_GATE" "could not atomically install the sysctl policy; rollback completed"
    fi
    created_sysctl_file=true
  fi
}

restore_runtime_policy() {
  local previous_qdisc="$1"
  local previous_cc="$2"
  sysctl -w "net.core.default_qdisc=$previous_qdisc" >/dev/null 2>&1 || true
  sysctl -w "net.ipv4.tcp_congestion_control=$previous_cc" >/dev/null 2>&1 || true
}

check_runtime_congestion_control() {
  local selected
  local available
  local default_qdisc
  selected="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  available="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  default_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  [[ "$(trim "$selected")" == "bbr" ]] || return 1
  is_supported_qdisc "$default_qdisc" || return 1
  [[ "$(trim "$default_qdisc")" == "$selected_qdisc" ]] || return 1
  case " $available " in
    *" bbr "*) return 0 ;;
    *) return 1 ;;
  esac
}

default_route_interface() {
  ip route show default 2>/dev/null |
    awk 'NR == 1 {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev" && i < NF) {
          print $(i + 1)
          exit
        }
      }
    }'
}

default_route_qdisc_kind() {
  local interface_name
  local qdisc_state

  interface_name="$(default_route_interface)"
  [[ -n "$interface_name" ]] || return 2
  case "$interface_name" in
    *[!A-Za-z0-9_.:@-]*) return 2 ;;
  esac

  qdisc_state=""
  qdisc_state="$(tc qdisc show dev "$interface_name" 2>/dev/null)" || return 2
  [[ -n "$qdisc_state" ]] || return 2

  printf '%s\n' "$qdisc_state" |
    awk '
      $1 == "qdisc" {
        is_root = 0
        parent = ""
        for (i = 3; i <= NF; i++) {
          if ($i == "root") {
            is_root = 1
          } else if ($i == "parent" && i < NF) {
            parent = $(i + 1)
          }
        }

        if (is_root) {
          root_count += 1
          root_kind = $2
          next
        }

        if ($2 == "ingress" || $2 == "clsact") {
          next
        }

        egress_child_count += 1
        if (parent !~ /^:[[:xdigit:]]+$/) {
          structure_bad = 1
          next
        }

        leaf_count += 1
        if ($2 != "fq" && $2 != "fq_codel") {
          policy_bad = 1
        } else if (leaf_kind == "") {
          leaf_kind = $2
        } else if ($2 != leaf_kind) {
          policy_bad = 1
        }
      }
      END {
        if (root_count != 1 || structure_bad) {
          exit 2
        }
        if (root_kind == "fq" || root_kind == "fq_codel") {
          if (egress_child_count != 0) {
            exit 2
          }
          print root_kind
          exit 0
        }
        if (root_kind == "mq") {
          if (leaf_count == 0 || egress_child_count != leaf_count) {
            exit 2
          }
          if (policy_bad) {
            exit 1
          }
          print leaf_kind
          exit 0
        }
        exit 1
      }
    '
}

check_default_route_qdisc() {
  default_route_qdisc_kind >/dev/null
}

verify_persistence() {
  [[ -f "$modules_file" && "$(<"$modules_file")" == "$managed_modules_content" ]] ||
    fail "$EXIT_VERIFY_FAILED" "module persistence does not match the managed policy"
  [[ -f "$sysctl_file" && "$(<"$sysctl_file")" == "$managed_sysctl_content" ]] ||
    fail "$EXIT_VERIFY_FAILED" "sysctl persistence does not match the managed policy"
  [[ -f "$network_dropin_file" &&
    "$(<"$network_dropin_file")" == "$managed_networkd_content" ]] ||
    fail "$EXIT_VERIFY_FAILED" "native qdisc persistence does not match the managed policy"
  check_configuration_conflicts
}

run_preflight() {
  check_os_policy
  require_commands \
    apt-get apt-mark apt-cache dpkg-query md5sum modinfo modprobe \
    networkctl sysctl ip tc awk uname stat
  check_managed_path_safety
  check_reboot_gate
  check_stock_kernel_provenance
  check_stock_bbrv1_evidence false
  configure_network_policy
  configure_networkd_policy
  check_configuration_conflicts
  printf 'OK: test-server preflight passed\n'
}

run_prepare() {
  local held_packages
  local previous_default_qdisc
  local previous_congestion_control
  local qdisc_status

  if [[ "$test_mode" == "0" && "$EUID" -ne 0 ]]; then
    fail "$EXIT_ROOT_REQUIRED" "prepare must run as root"
  fi

  check_os_policy
  require_commands \
    apt-get apt-mark apt-cache dpkg-query md5sum modinfo modprobe \
    networkctl sysctl ip tc awk uname mktemp grep mkdir rmdir stat
  check_managed_path_safety

  temporary_apt_log="$(mktemp "${TMPDIR:-/tmp}/maverick-apt.XXXXXX")"
  chmod 0600 "$temporary_apt_log"

  printf 'Preparing: refreshing Ubuntu package metadata\n'
  apt-get -o APT::Update::Error-Mode=any update >"$temporary_apt_log" 2>&1 ||
    fail "$EXIT_SAFETY_GATE" "package metadata refresh failed"

  held_packages="$(apt-mark showhold 2>/dev/null || true)"
  [[ -z "$(trim "$held_packages")" ]] ||
    fail "$EXIT_SAFETY_GATE" "held packages block a fully updated test server"

  apt-get -o APT::Get::Always-Include-Phased-Updates=true \
    -s full-upgrade >"$temporary_apt_log" 2>&1 ||
    fail "$EXIT_SAFETY_GATE" "package upgrade simulation failed"
  if grep -Eq '^Remv[[:space:]]|(^|, )[1-9][0-9]* to remove' "$temporary_apt_log"; then
    fail "$EXIT_SAFETY_GATE" "the package upgrade would remove packages"
  fi

  printf 'Preparing: applying full package upgrade without removals\n'
  DEBIAN_FRONTEND=noninteractive \
    apt-get -o APT::Get::Always-Include-Phased-Updates=true \
      --no-remove -y full-upgrade >"$temporary_apt_log" 2>&1 ||
    fail "$EXIT_SAFETY_GATE" "package upgrade failed or requested a removal"

  apt-get -o APT::Get::Always-Include-Phased-Updates=true \
    -s full-upgrade >"$temporary_apt_log" 2>&1 ||
    fail "$EXIT_SAFETY_GATE" "post-upgrade package verification failed"
  if grep -Eq \
    '^Inst[[:space:]]|^Remv[[:space:]]|kept back|(^|[ ,])[1-9][0-9]* not upgraded' \
    "$temporary_apt_log"; then
    fail "$EXIT_SAFETY_GATE" "package or kernel updates remain pending"
  fi

  check_reboot_gate
  check_managed_path_safety
  check_stock_kernel_provenance
  check_stock_bbrv1_evidence false
  configure_network_policy
  configure_networkd_policy
  check_configuration_conflicts

  modprobe tcp_bbr >/dev/null 2>&1 ||
    fail "$EXIT_BBR_UNAVAILABLE" "the stock Ubuntu BBR module could not be loaded"
  modprobe "$selected_scheduler_module" >/dev/null 2>&1 ||
    fail "$EXIT_VERIFY_FAILED" "the selected qdisc module could not be loaded"
  check_stock_bbrv1_evidence true

  previous_default_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  previous_congestion_control="$(
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
  )"
  if [[ ! "$previous_default_qdisc" =~ ^[A-Za-z0-9_.-]+$ ||
    ! "$previous_congestion_control" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    fail "$EXIT_VERIFY_FAILED" "existing runtime network policy could not be captured safely"
  fi

  persist_network_policy
  if ! sysctl -w "net.core.default_qdisc=$selected_qdisc" >/dev/null 2>&1 ||
    ! sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1; then
    restore_runtime_policy "$previous_default_qdisc" "$previous_congestion_control"
    rollback_created_policy
    fail "$EXIT_VERIFY_FAILED" "runtime policy apply failed; persistent changes were rolled back"
  fi

  if ! check_runtime_congestion_control; then
    restore_runtime_policy "$previous_default_qdisc" "$previous_congestion_control"
    rollback_created_policy
    fail "$EXIT_VERIFY_FAILED" "runtime BBR and default-qdisc verification failed; rollback completed"
  fi
  qdisc_status=0
  check_default_route_qdisc || qdisc_status=$?
  case "$qdisc_status" in
    0) ;;
    1)
      fail "$EXIT_REBOOT_REQUIRED" "the persistent qdisc is ready, but a manual reboot is required before Maverick starts"
      ;;
    *)
      restore_runtime_policy "$previous_default_qdisc" "$previous_congestion_control"
      rollback_created_policy
      fail "$EXIT_VERIFY_FAILED" "the active qdisc could not be inspected safely; persistent changes were rolled back"
      ;;
  esac

  printf 'OK: packages, stock BBRv1, approved qdisc, persistence, and runtime checks passed\n'
}

run_verify() {
  check_os_policy
  require_commands \
    apt-cache dpkg-query md5sum modinfo networkctl sysctl ip tc awk \
    uname stat
  check_managed_path_safety
  check_reboot_gate
  check_stock_kernel_provenance
  check_stock_bbrv1_evidence true
  configure_network_policy
  configure_networkd_policy
  verify_persistence
  check_runtime_congestion_control ||
    fail "$EXIT_VERIFY_FAILED" "runtime BBR or default-qdisc state is invalid"
  check_default_route_qdisc ||
    fail "$EXIT_VERIFY_FAILED" "the first IPv4 default-route qdisc is not fq or fq_codel"
  printf 'OK: test server is ready for a separately authorized Maverick deployment\n'
}

case "$action" in
  preflight) run_preflight ;;
  prepare) run_prepare ;;
  verify) run_verify ;;
esac
