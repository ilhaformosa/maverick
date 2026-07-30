#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
subject="$repo_root/scripts/prepare-test-server.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/maverick-host-test.XXXXXX")"
fixture_root="$(cd "$fixture_root" && pwd -P)"
trap 'rm -rf -- "$fixture_root"' EXIT

pass_count=0

fail_test() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

make_fixture() {
  local name="$1"
  local version="$2"
  local flavour="${3:-generic}"
  local root="$fixture_root/$name/root"
  local bin="$fixture_root/$name/bin"
  local running_kernel="6.8.0-test-$flavour"
  local owner_package="linux-modules-$running_kernel"
  local module_relative="lib/modules/$running_kernel/kernel/net/ipv4/tcp_bbr.ko"
  local expected_md5="0123456789abcdef0123456789abcdef"

  mkdir -p \
    "$root/etc/modules-load.d" \
    "$root/etc/sysctl.d" \
    "$root/etc/modprobe.d" \
    "$root/etc/systemd/network" \
    "$root/run/sysctl.d" \
    "$root/run/modprobe.d" \
    "$root/run/systemd/network" \
    "$root/usr/local/lib/sysctl.d" \
    "$root/usr/local/lib/modprobe.d" \
    "$root/usr/local/lib/systemd/network" \
    "$root/usr/lib/sysctl.d" \
    "$root/usr/lib/modprobe.d" \
    "$root/usr/lib/systemd/network" \
    "$root/lib/sysctl.d" \
    "$root/lib/modprobe.d" \
    "$root/var/run" \
    "$root/sys/module/tcp_bbr" \
    "$root/lib/modules/$running_kernel/kernel/net/ipv4" \
    "$root/boot" \
    "$root/var/lib/dpkg/info" \
    "$root/runtime" \
    "$bin"

  printf 'maverick-isolated-fixture-v1\n' >"$root/.maverick-isolated-fixture-v1"
  printf 'ID=ubuntu\nVERSION_ID="%s"\n' "$version" >"$root/etc/os-release"
  printf '%s\n' "$running_kernel" >"$root/runtime/kernel"
  printf 'bbr\n' >"$root/runtime/cc"
  printf 'fq_codel\n' >"$root/runtime/default-qdisc"
  printf 'reno cubic bbr\n' >"$root/runtime/available"
  printf '%s\n' \
    '[Match]' \
    'Name=test0' \
    '' \
    '[Network]' \
    'DHCP=yes' \
    >"$root/run/systemd/network/10-netplan-test0.network"
  printf 'packaged module fixture\n' >"$root/$module_relative"
  printf 'packaged image fixture\n' >"$root/boot/vmlinuz-$running_kernel"
  printf '%s  %s\n' "$expected_md5" "$module_relative" \
    >"$root/var/lib/dpkg/info/$owner_package.md5sums"
  printf '%s  boot/vmlinuz-%s\n' "$expected_md5" "$running_kernel" \
    >"$root/var/lib/dpkg/info/linux-image-$running_kernel.md5sums"

cat >"$bin/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${APT_CONFIG:-}${DPKG_ROOT:-}${DPKG_ADMINDIR:-}${MODPROBE_OPTIONS:-}" ]]; then
  printf 'unsafe inherited tool environment\n' >&2
  exit 97
fi
printf 'apt-get %s\n' "$*" >>"$MAVERICK_TEST_ROOT/runtime/commands"
if [[ "$*" == "-o APT::Update::Error-Mode=any update" &&
  "${FAKE_APT_UPDATE_FAIL:-0}" == "1" ]]; then
  printf 'partial fetch rejected\n' >&2
  exit 1
elif [[ "$*" == "-o APT::Get::Always-Include-Phased-Updates=true -s full-upgrade" ]]; then
  count_file="$MAVERICK_TEST_ROOT/runtime/simulation-count"
  count=0
  [[ ! -f "$count_file" ]] || count="$(cat "$count_file")"
  count=$((count + 1))
  printf '%s\n' "$count" >"$count_file"
  if [[ "${FAKE_APT_REMOVAL:-0}" == "1" && "$count" -eq 1 ]]; then
    printf 'Remv example-package [1.0]\n'
  elif [[ "${FAKE_APT_PENDING_AFTER:-0}" == "1" && "$count" -ge 2 ]]; then
    printf 'Inst pending-package [1.0] (2.0 Ubuntu:26.04/stable)\n'
    printf '1 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n'
  else
    printf '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n'
  fi
elif [[ "$*" == "-o APT::Get::Always-Include-Phased-Updates=true --no-remove -y full-upgrade" &&
  "${FAKE_REBOOT_REQUIRED:-0}" == "1" ]]; then
  : >"$MAVERICK_TEST_ROOT/var/run/reboot-required"
fi
EOF

  cat >"$bin/apt-mark" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAKE_APT_HELD:-0}" == "1" ]]; then
  printf 'example-held-package\n'
fi
EOF

  cat >"$bin/uname" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-r" ]] || exit 1
cat "$MAVERICK_TEST_ROOT/runtime/kernel"
EOF

  cat >"$bin/modinfo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "-F version tcp_bbr" ]]; then
  printf '%s\n' "${FAKE_BBR_VERSION:-}"
  exit 0
fi
if [[ "$*" == "-n tcp_bbr" ]]; then
  if [[ "${FAKE_MODULE_OUTSIDE_KERNEL:-0}" == "1" ]]; then
    printf '%s\n' "$MAVERICK_TEST_ROOT/opt/tcp_bbr.ko"
  else
    printf '%s/lib/modules/%s/kernel/net/ipv4/tcp_bbr.ko\n' \
      "$MAVERICK_TEST_ROOT" "$(cat "$MAVERICK_TEST_ROOT/runtime/kernel")"
  fi
  exit 0
fi
exit 1
EOF

  cat >"$bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
running_kernel="$(cat "$MAVERICK_TEST_ROOT/runtime/kernel")"
if [[ "${1:-}" == "-S" ]]; then
  [[ "${FAKE_MODULE_UNOWNED:-0}" != "1" ]] || exit 1
  case "$2" in
    *"/boot/vmlinuz-"*)
      printf 'linux-image-%s: %s\n' "$running_kernel" "$2"
      ;;
    *)
      printf 'linux-modules-%s: %s\n' "$running_kernel" "$2"
      ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "-W" ]]; then
  package_name="${3:-}"
  if [[ "${FAKE_INSTALLED_META:-both}" == "virtual-only" &&
    "$package_name" == "linux-generic" ]]; then
    exit 1
  fi
  if [[ "${FAKE_INSTALLED_META:-both}" == "generic-only" &&
    "$package_name" == "linux-virtual" ]]; then
    exit 1
  fi
  case "${2:-}" in
    *Status-Abbrev*) printf 'ii ' ;;
    *Version*) printf '1.0-test' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
exit 1
EOF

  cat >"$bin/apt-cache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  policy)
    printf '%s\n' \
      '  Installed: 1.0-test' \
      '  Candidate: 1.0-test'
    ;;
  show)
    printf 'Origin: %s\n' "${FAKE_APT_ORIGIN:-Ubuntu}"
    ;;
  depends)
    running_kernel="$(cat "$MAVERICK_TEST_ROOT/runtime/kernel")"
    if [[ "${FAKE_META_SELECTS_RUNNING:-1}" == "1" ]]; then
      printf '  Depends: linux-image-%s\n' "$running_kernel"
    else
      printf '  Depends: linux-image-other-generic\n'
    fi
    ;;
  *)
    exit 1
    ;;
esac
EOF

  cat >"$bin/md5sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAKE_MODULE_MD5_BAD:-0}" == "1" ]]; then
  printf 'ffffffffffffffffffffffffffffffff  %s\n' "$1"
elif [[ "${FAKE_IMAGE_MD5_BAD:-0}" == "1" && "$1" == *"/boot/vmlinuz-"* ]]; then
  printf 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  %s\n' "$1"
else
  printf '0123456789abcdef0123456789abcdef  %s\n' "$1"
fi
EOF

  cat >"$bin/modprobe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'modprobe %s\n' "$*" >>"$MAVERICK_TEST_ROOT/runtime/commands"
if [[ "$*" == "tcp_bbr" ]]; then
  [[ "${FAKE_MODPROBE_BBR_FAIL:-0}" != "1" ]] || exit 1
  if [[ -n "${FAKE_LOADED_BBR_VERSION:-}" ]]; then
    printf '%s\n' "$FAKE_LOADED_BBR_VERSION" \
      >"$MAVERICK_TEST_ROOT/sys/module/tcp_bbr/version"
  else
    rm -f "$MAVERICK_TEST_ROOT/sys/module/tcp_bbr/version"
  fi
elif [[ "$*" == "sch_fq" || "$*" == "sch_fq_codel" ]]; then
  [[ "${FAKE_MODPROBE_QDISC_FAIL:-0}" != "1" ]] || exit 1
fi
EOF

  cat >"$bin/sysctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-p" ]]; then
  while IFS= read -r line; do
    case "$line" in
      "net.ipv4.tcp_congestion_control = bbr")
        printf 'bbr\n' >"$MAVERICK_TEST_ROOT/runtime/cc"
        ;;
    esac
  done <"$2"
  exit 0
fi
if [[ "${1:-}" == "-w" ]]; then
  key="${2%%=*}"
  value="${2#*=}"
  if [[ "$key" == "net.ipv4.tcp_congestion_control" &&
    "${FAKE_SYSCTL_APPLY_FAIL:-}" == "cc" && "$value" == "bbr" ]]; then
    exit 1
  elif [[ "$key" == "net.core.default_qdisc" &&
    "${FAKE_SYSCTL_APPLY_FAIL:-}" == "qdisc" ]]; then
    exit 1
  fi
  case "$key" in
    net.ipv4.tcp_congestion_control)
      printf '%s\n' "$value" >"$MAVERICK_TEST_ROOT/runtime/cc"
      ;;
    net.core.default_qdisc)
      printf '%s\n' "$value" >"$MAVERICK_TEST_ROOT/runtime/default-qdisc"
      ;;
    *)
      exit 1
      ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "-n" ]]; then
  case "${2:-}" in
    net.ipv4.tcp_congestion_control)
      cat "$MAVERICK_TEST_ROOT/runtime/cc"
      ;;
    net.ipv4.tcp_available_congestion_control)
      cat "$MAVERICK_TEST_ROOT/runtime/available"
      ;;
    net.core.default_qdisc)
      cat "$MAVERICK_TEST_ROOT/runtime/default-qdisc"
      ;;
    *)
      exit 1
      ;;
  esac
  exit 0
fi
exit 1
EOF

  cat >"$bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'default dev test0\n'
EOF

  cat >"$bin/networkctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'networkctl %s\n' "$*" >>"$MAVERICK_TEST_ROOT/runtime/commands"
if [[ "$*" == "--no-pager --full status test0" ]]; then
  [[ "${FAKE_NETWORK_STATUS_FAIL:-0}" != "1" ]] || exit 1
  network_file="${FAKE_NETWORK_FILE:-/run/systemd/network/10-netplan-test0.network}"
  if [[ "${FAKE_NETWORK_FILE_COUNT:-1}" == "0" ]]; then
    printf 'State: routable\n'
  elif [[ "${FAKE_NETWORK_FILE_COUNT:-1}" == "2" ]]; then
    printf 'Network File: %s\nNetwork File: %s\n' "$network_file" "$network_file"
  else
    printf 'Network File: %s\n' "$network_file"
  fi
  exit 0
fi
exit 1
EOF

  cat >"$bin/tc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'tc %s\n' "$*" >>"$MAVERICK_TEST_ROOT/runtime/commands"
case "${FAKE_QDISC:-fq-codel}" in
  fq)
    printf 'qdisc fq 8001: root refcnt 2\n'
    ;;
  mq-fq)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq 0: parent :1\n'
    printf 'qdisc fq 0: parent :2\n'
    ;;
  fq-codel)
    printf 'qdisc fq_codel 0: root\n'
    ;;
  mq-fq-codel)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq_codel 0: parent :1\n'
    printf 'qdisc fq_codel 0: parent :2\n'
    ;;
  mq-mixed)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq 0: parent :1\n'
    printf 'qdisc fq_codel 0: parent :2\n'
    ;;
  mq-no-leaf)
    printf 'qdisc mq 0: root\n'
    ;;
  mq-unsupported)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq_codel 0: parent :1\n'
    printf 'qdisc cake 0: parent :2\n'
    ;;
  mq-hex)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq_codel 0: parent :1\n'
    printf 'qdisc fq_codel 0: parent :a\n'
    ;;
  mq-hex-unsupported)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq_codel 0: parent :1\n'
    printf 'qdisc cake 0: parent :a\n'
    ;;
  mq-with-ingress)
    printf 'qdisc mq 0: root\n'
    printf 'qdisc fq_codel 0: parent :1\n'
    printf 'qdisc fq_codel 0: parent :2\n'
    printf 'qdisc ingress ffff: parent ffff:fff1\n'
    ;;
  direct-multiple-roots)
    printf 'qdisc fq_codel 0: root\n'
    printf 'qdisc cake 0: root\n'
    ;;
  direct-two-supported-roots)
    printf 'qdisc fq 0: root\n'
    printf 'qdisc fq_codel 0: root\n'
    ;;
  direct-with-child)
    printf 'qdisc fq_codel 0: root\n'
    printf 'qdisc fq_codel 0: parent 1:1\n'
    ;;
  fq-with-dev-token)
    printf 'qdisc fq 8001: dev test0 root refcnt 2\n'
    ;;
  failure-with-output)
    printf 'qdisc fq_codel 0: root\n'
    exit 1
    ;;
  pfifo-fast)
    printf 'qdisc pfifo_fast 0: root\n'
    ;;
  cake)
    printf 'qdisc cake 0: root\n'
    ;;
esac
EOF

  chmod 0755 "$bin"/*
  printf '%s\n%s\n' "$root" "$bin"
}

invoke() {
  local root="$1"
  local bin="$2"
  shift 2
  PATH="$bin:/usr/bin:/bin" \
    MAVERICK_TEST_MODE=isolated-fixture-v1 \
    MAVERICK_TEST_ROOT="$root" \
    MAVERICK_TEST_BIN="$bin" \
    FAKE_BBR_VERSION="${FAKE_BBR_VERSION-}" \
    FAKE_APT_HELD="${FAKE_APT_HELD:-0}" \
    FAKE_APT_REMOVAL="${FAKE_APT_REMOVAL:-0}" \
    FAKE_APT_PENDING_AFTER="${FAKE_APT_PENDING_AFTER:-0}" \
    FAKE_APT_UPDATE_FAIL="${FAKE_APT_UPDATE_FAIL:-0}" \
    FAKE_APT_ORIGIN="${FAKE_APT_ORIGIN:-Ubuntu}" \
    FAKE_META_SELECTS_RUNNING="${FAKE_META_SELECTS_RUNNING:-1}" \
    FAKE_INSTALLED_META="${FAKE_INSTALLED_META:-both}" \
    FAKE_REBOOT_REQUIRED="${FAKE_REBOOT_REQUIRED:-0}" \
    FAKE_MODULE_OUTSIDE_KERNEL="${FAKE_MODULE_OUTSIDE_KERNEL:-0}" \
    FAKE_MODULE_UNOWNED="${FAKE_MODULE_UNOWNED:-0}" \
    FAKE_MODULE_MD5_BAD="${FAKE_MODULE_MD5_BAD:-0}" \
    FAKE_IMAGE_MD5_BAD="${FAKE_IMAGE_MD5_BAD:-0}" \
    FAKE_LOADED_BBR_VERSION="${FAKE_LOADED_BBR_VERSION:-}" \
    FAKE_MODPROBE_BBR_FAIL="${FAKE_MODPROBE_BBR_FAIL:-0}" \
    FAKE_MODPROBE_QDISC_FAIL="${FAKE_MODPROBE_QDISC_FAIL:-0}" \
    FAKE_SYSCTL_APPLY_FAIL="${FAKE_SYSCTL_APPLY_FAIL:-}" \
    FAKE_NETWORK_STATUS_FAIL="${FAKE_NETWORK_STATUS_FAIL:-0}" \
    FAKE_NETWORK_FILE="${FAKE_NETWORK_FILE:-/run/systemd/network/10-netplan-test0.network}" \
    FAKE_NETWORK_FILE_COUNT="${FAKE_NETWORK_FILE_COUNT:-1}" \
    MAVERICK_TEST_FAIL_SECOND_POLICY_MOVE="${MAVERICK_TEST_FAIL_SECOND_POLICY_MOVE:-0}" \
    FAKE_QDISC="${FAKE_QDISC:-fq-codel}" \
    APT_CONFIG="${TEST_APT_CONFIG:-}" \
    DPKG_ROOT="${TEST_DPKG_ROOT:-}" \
    DPKG_ADMINDIR="${TEST_DPKG_ADMINDIR:-}" \
    MODPROBE_OPTIONS="${TEST_MODPROBE_OPTIONS:-}" \
    "$subject" "$@"
}

expect_exit() {
  local expected="$1"
  shift
  local actual=0
  "$@" >/dev/null 2>&1 || actual=$?
  [[ "$actual" -eq "$expected" ]] ||
    fail_test "expected exit $expected, got $actual"
  pass_count=$((pass_count + 1))
}

fixture="$(make_fixture preflight-26 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" preflight >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture unsupported-default-qdisc 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'cake\n' >"$root/runtime/default-qdisc"
expect_exit 21 invoke "$root" "$bin" preflight
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "unsupported default qdisc wrote persistent settings"

fixture="$(make_fixture fallback-24 24.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
expect_exit 23 invoke "$root" "$bin" preflight
invoke "$root" "$bin" preflight \
  --allow-24.04-fallback --fallback-reason "default image unavailable" >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture bbr-version 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_BBR_VERSION=1 invoke "$root" "$bin" preflight >/dev/null
pass_count=$((pass_count + 1))
FAKE_BBR_VERSION=2 expect_exit 22 invoke "$root" "$bin" preflight
FAKE_BBR_VERSION=3 expect_exit 22 invoke "$root" "$bin" preflight

fixture="$(make_fixture loaded-bbrv1 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_LOADED_BBR_VERSION=1 invoke "$root" "$bin" prepare >/dev/null
FAKE_LOADED_BBR_VERSION=1 invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture loaded-bbr-missing 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" prepare >/dev/null
invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture declared-bbrv3 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_BBR_VERSION=3 expect_exit 22 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "declared BBRv3 gate wrote persistent settings"
if grep -Fq 'modprobe ' "$root/runtime/commands"; then
  fail_test "declared BBRv3 gate loaded modules"
fi

fixture="$(make_fixture loaded-bbrv3 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_LOADED_BBR_VERSION=3 expect_exit 22 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "loaded BBRv3 gate wrote persistent settings"

fixture="$(make_fixture unavailable-bbr 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_MODPROBE_BBR_FAIL=1 expect_exit 22 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "unavailable BBR gate wrote persistent settings"

fixture="$(make_fixture unregistered-bbr 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'reno cubic\n' >"$root/runtime/available"
expect_exit 22 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "unregistered BBR gate wrote persistent settings"

fixture="$(make_fixture custom-kernel 26.04 custom)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture unowned-module 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_MODULE_UNOWNED=1 expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture altered-module 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_MODULE_MD5_BAD=1 expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture bad-image 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_IMAGE_MD5_BAD=1 expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture non-ubuntu-origin 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_APT_ORIGIN=Other expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture wrong-meta-closure 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_META_SELECTS_RUNNING=0 expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture partial-update 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_APT_UPDATE_FAIL=1 expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "partial-update gate wrote persistent settings"

fixture="$(make_fixture inherited-tool-environment 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
TEST_APT_CONFIG=/untrusted/apt.conf \
  TEST_DPKG_ROOT=/untrusted/root \
  TEST_DPKG_ADMINDIR=/untrusted/dpkg \
  TEST_MODPROBE_OPTIONS='--config=/untrusted/modprobe.conf' \
  invoke "$root" "$bin" prepare >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture held 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_APT_HELD=1 expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "held-package gate wrote persistent settings"

fixture="$(make_fixture removal 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_APT_REMOVAL=1 expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "removal gate wrote persistent settings"

fixture="$(make_fixture pending-after-upgrade 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_APT_PENDING_AFTER=1 expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "pending-update gate wrote persistent settings"

fixture="$(make_fixture reboot 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_REBOOT_REQUIRED=1 expect_exit 20 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "reboot gate wrote persistent settings"

fixture="$(make_fixture prepare 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" prepare >/dev/null
invoke "$root" "$bin" prepare >/dev/null
invoke "$root" "$bin" verify >/dev/null
grep -Fxq 'tcp_bbr' "$root/etc/modules-load.d/99-maverick-test-network.conf"
grep -Fxq 'sch_fq_codel' "$root/etc/modules-load.d/99-maverick-test-network.conf"
grep -Fxq 'net.core.default_qdisc = fq_codel' \
  "$root/etc/sysctl.d/99-maverick-test-network.conf"
grep -Fxq 'net.ipv4.tcp_congestion_control = bbr' \
  "$root/etc/sysctl.d/99-maverick-test-network.conf"
grep -Fxq '[FairQueueingControlledDelay]' \
  "$root/etc/systemd/network/10-netplan-test0.network.d/99-maverick-test-qdisc.conf"
if grep -Fq 'autoremove' "$root/runtime/commands"; then
  fail_test "prepare invoked autoremove"
fi
grep -Fxq 'apt-get -o APT::Update::Error-Mode=any update' \
  "$root/runtime/commands" ||
  fail_test "prepare did not use strict apt update error mode"
grep -Fxq \
  'apt-get -o APT::Get::Always-Include-Phased-Updates=true --no-remove -y full-upgrade' \
  "$root/runtime/commands" ||
  fail_test "prepare did not include Ubuntu phased updates"
if grep -Eq '^tc qdisc (replace|add|change)' "$root/runtime/commands"; then
  fail_test "prepare attempted an online tc mutation"
fi
if grep -Eq '^networkctl .* (reload|reconfigure)' "$root/runtime/commands"; then
  fail_test "prepare attempted a live networkd qdisc mutation"
fi
pass_count=$((pass_count + 1))

fixture="$(make_fixture prepare-fq 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'fq\n' >"$root/runtime/default-qdisc"
FAKE_QDISC=fq invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=fq invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=fq invoke "$root" "$bin" verify >/dev/null
grep -Fxq 'tcp_bbr' "$root/etc/modules-load.d/99-maverick-test-network.conf"
grep -Fxq 'sch_fq' "$root/etc/modules-load.d/99-maverick-test-network.conf"
grep -Fxq 'net.core.default_qdisc = fq' \
  "$root/etc/sysctl.d/99-maverick-test-network.conf"
grep -Fxq '[FairQueueing]' \
  "$root/etc/systemd/network/10-netplan-test0.network.d/99-maverick-test-qdisc.conf"
pass_count=$((pass_count + 1))

rm -f "$root/sys/module/tcp_bbr/version"
FAKE_QDISC=fq invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))
printf '1\n' >"$root/sys/module/tcp_bbr/version"
FAKE_QDISC=fq invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))
printf '3\n' >"$root/sys/module/tcp_bbr/version"
FAKE_QDISC=fq expect_exit 22 invoke "$root" "$bin" verify

fixture="$(make_fixture virtual 26.04 virtual)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_INSTALLED_META=virtual-only invoke "$root" "$bin" prepare >/dev/null
FAKE_INSTALLED_META=virtual-only invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture existing-supported-qdisc 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.core.default_qdisc = fq_codel\n' >"$root/etc/sysctl.d/existing.conf"
invoke "$root" "$bin" prepare >/dev/null
invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture earlier-supported-qdisc-config 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.core.default_qdisc = fq\n' \
  >"$root/etc/sysctl.d/50-existing.conf"
invoke "$root" "$bin" prepare >/dev/null
invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture later-supported-qdisc-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.core.default_qdisc = fq\n' \
  >"$root/etc/sysctl.d/zz-after-maverick.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "later supported qdisc conflict wrote managed settings"

fixture="$(make_fixture sysctl-conf-supported-qdisc-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.core.default_qdisc = fq\n' >"$root/etc/sysctl.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "sysctl.conf qdisc conflict wrote managed settings"

fixture="$(make_fixture unsupported-qdisc-config 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.core.default_qdisc = cake\n' >"$root/etc/sysctl.d/existing.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "conflict gate overwrote settings"

fixture="$(make_fixture lower-precedence-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'net.ipv4.tcp_congestion_control = cubic\n' \
  >"$root/usr/lib/sysctl.d/vendor.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "effective-directory conflict wrote managed settings"

fixture="$(make_fixture normalized-sysctl-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf '%s\n' '-net/core/default_qdisc = cake' \
  >"$root/run/sysctl.d/normalized.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "normalized sysctl conflict wrote managed settings"

fixture="$(make_fixture normalized-module-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'install tcp-bbr /bin/false\n' \
  >"$root/usr/local/lib/modprobe.d/normalized.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "normalized module conflict wrote managed settings"

fixture="$(make_fixture fq-codel-module-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'install sch-fq-codel /bin/false\n' \
  >"$root/usr/local/lib/modprobe.d/qdisc.conf"
expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "fq_codel module conflict wrote managed settings"

fixture="$(make_fixture fq-module-conflict 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'fq\n' >"$root/runtime/default-qdisc"
printf 'blacklist sch_fq\n' >"$root/etc/modprobe.d/qdisc.conf"
FAKE_QDISC=fq expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "fq module conflict wrote managed settings"

fixture="$(make_fixture rollback-move 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
MAVERICK_TEST_FAIL_SECOND_POLICY_MOVE=1 \
  expect_exit 21 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/modules-load.d/99-maverick-test-network.conf" ]] ||
  fail_test "partial persistence rollback left the modules file"
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "partial persistence rollback left the sysctl file"

fixture="$(make_fixture rollback-runtime 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_SYSCTL_APPLY_FAIL=cc expect_exit 24 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/modules-load.d/99-maverick-test-network.conf" ]] ||
  fail_test "runtime rollback left the modules file"
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "runtime rollback left the sysctl file"
grep -Fxq 'fq_codel' "$root/runtime/default-qdisc" ||
  fail_test "runtime rollback did not restore default_qdisc"

fixture="$(make_fixture qdisc-module-failure 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_MODPROBE_QDISC_FAIL=1 expect_exit 24 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/modules-load.d/99-maverick-test-network.conf" ]] ||
  fail_test "qdisc module failure left the modules file"
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "qdisc module failure left the sysctl file"

fixture="$(make_fixture qdisc-sysctl-failure 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_SYSCTL_APPLY_FAIL=qdisc expect_exit 24 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/modules-load.d/99-maverick-test-network.conf" ]] ||
  fail_test "qdisc sysctl failure left the modules file"
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "qdisc sysctl failure left the sysctl file"
grep -Fxq 'fq_codel' "$root/runtime/default-qdisc" ||
  fail_test "qdisc sysctl failure changed runtime default_qdisc"

fixture="$(make_fixture apply-bbr-from-cubic 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'cubic\n' >"$root/runtime/cc"
invoke "$root" "$bin" prepare >/dev/null
grep -Fxq 'bbr' "$root/runtime/cc" ||
  fail_test "prepare did not select BBR"
invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture mq 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-fq invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=mq-fq invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture supported-qdisc-no-forced-alignment 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=fq invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=fq invoke "$root" "$bin" verify >/dev/null
grep -Fxq 'sch_fq' "$root/etc/modules-load.d/99-maverick-test-network.conf"
grep -Fxq 'net.core.default_qdisc = fq' \
  "$root/etc/sysctl.d/99-maverick-test-network.conf"
grep -Fxq '[FairQueueing]' \
  "$root/etc/systemd/network/10-netplan-test0.network.d/99-maverick-test-qdisc.conf"
if grep -Eq '^tc qdisc (replace|add|change)' "$root/runtime/commands"; then
  fail_test "prepare forced one supported qdisc to replace another"
fi
pass_count=$((pass_count + 1))

fixture="$(make_fixture mq-fq-codel 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-fq-codel invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=mq-fq-codel invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture mq-mixed 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-mixed expect_exit 20 invoke "$root" "$bin" prepare
FAKE_QDISC=mq-mixed expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture mq-no-leaf 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-no-leaf expect_exit 24 invoke "$root" "$bin" prepare
FAKE_QDISC=mq-no-leaf expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture mq-unsupported 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-unsupported expect_exit 20 invoke "$root" "$bin" prepare
FAKE_QDISC=mq-unsupported expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture mq-hex 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-hex invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=mq-hex invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture mq-hex-unsupported 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-hex-unsupported expect_exit 20 invoke "$root" "$bin" prepare
FAKE_QDISC=mq-hex-unsupported expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture mq-with-ingress 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=mq-with-ingress invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=mq-with-ingress invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture direct-multiple-roots 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=direct-multiple-roots expect_exit 24 invoke "$root" "$bin" prepare
FAKE_QDISC=direct-multiple-roots expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture direct-two-supported-roots 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=direct-two-supported-roots expect_exit 24 invoke "$root" "$bin" prepare
FAKE_QDISC=direct-two-supported-roots expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture direct-with-child 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=direct-with-child expect_exit 24 invoke "$root" "$bin" prepare
FAKE_QDISC=direct-with-child expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture fq-with-dev-token 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
printf 'fq\n' >"$root/runtime/default-qdisc"
FAKE_QDISC=fq-with-dev-token invoke "$root" "$bin" prepare >/dev/null
FAKE_QDISC=fq-with-dev-token invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture tc-failure-with-output 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=failure-with-output expect_exit 24 invoke "$root" "$bin" prepare
[[ ! -e "$root/etc/modules-load.d/99-maverick-test-network.conf" ]] ||
  fail_test "failed qdisc inspection left the modules file"
[[ ! -e "$root/etc/sysctl.d/99-maverick-test-network.conf" ]] ||
  fail_test "failed qdisc inspection left the sysctl file"
FAKE_QDISC=failure-with-output expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture wrong-qdisc 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
FAKE_QDISC=pfifo-fast expect_exit 20 invoke "$root" "$bin" prepare
grep -Fxq '[FairQueueingControlledDelay]' \
  "$root/etc/systemd/network/10-netplan-test0.network.d/99-maverick-test-qdisc.conf"
FAKE_QDISC=pfifo-fast expect_exit 24 invoke "$root" "$bin" verify
FAKE_QDISC=fq-codel invoke "$root" "$bin" verify >/dev/null
pass_count=$((pass_count + 1))

fixture="$(make_fixture networkd-dropin-symlink 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
mkdir -p "$root/etc/systemd/network/10-netplan-test0.network.d"
ln -s "$root/etc/os-release" \
  "$root/etc/systemd/network/10-netplan-test0.network.d/99-maverick-test-qdisc.conf"
expect_exit 21 invoke "$root" "$bin" preflight

fixture="$(make_fixture runtime-default 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" prepare >/dev/null
printf 'cake\n' >"$root/runtime/default-qdisc"
expect_exit 21 invoke "$root" "$bin" verify

fixture="$(make_fixture runtime-supported-drift 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" prepare >/dev/null
printf 'fq\n' >"$root/runtime/default-qdisc"
expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture runtime-cc 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
invoke "$root" "$bin" prepare >/dev/null
printf 'cubic\n' >"$root/runtime/cc"
expect_exit 24 invoke "$root" "$bin" verify

fixture="$(make_fixture output 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
output="$(invoke "$root" "$bin" preflight 2>&1)"
if printf '%s\n' "$output" |
  grep -Eiq '([0-9]{1,3}\.){3}[0-9]{1,3}|hostname|provider|test0'; then
  fail_test "output exposed host or network identity"
fi
pass_count=$((pass_count + 1))

fixture="$(make_fixture inherited-awk-function 26.04)"
root="${fixture%%$'\n'*}"
bin="${fixture#*$'\n'}"
# shellcheck disable=SC2317,SC2329 # Exported to the child shell as the test payload.
awk() {
  return 0
}
export -f awk
FAKE_QDISC=direct-multiple-roots expect_exit 24 invoke "$root" "$bin" prepare
unset -f awk

actual=0
MAVERICK_TEST_MODE=1 "$subject" preflight >/dev/null 2>&1 || actual=$?
[[ "$actual" -eq 21 ]] ||
  fail_test "legacy or inherited test mode was not rejected"
pass_count=$((pass_count + 1))

printf 'prepare-test-server tests: PASS (%s checks)\n' "$pass_count"
