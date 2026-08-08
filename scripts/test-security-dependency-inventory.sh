#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inventory="$repo_root/scripts/security-dependency-inventory.sh"
test_root=""

fail() {
  echo "security dependency inventory focused tests failed" >&2
  exit 1
}

cleanup() {
  case "$test_root" in
    /tmp/maverick-security-inventory.*)
      [[ ! -d "$test_root" ]] ||
        find "$test_root" -depth -delete >/dev/null 2>&1 || true
      ;;
  esac
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

test_root="$(mktemp -d /tmp/maverick-security-inventory.XXXXXX)" || fail
fake_bin="$test_root/bin"
mkdir -m 0700 "$fake_bin"

cat >"$fake_bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "audit --help" | "deny --help") exit 0 ;;
  "audit --no-fetch --no-yanked")
    [[ "${CARGO_NET_OFFLINE:-}" == "true" ]] || exit 2
    [[ "${MAVERICK_TEST_DENY_STAGE:-}" != "audit" ]] || exit 3
    ;;
  "deny --offline --locked check -D warnings advisories bans licenses sources")
    [[ "${CARGO_NET_OFFLINE:-}" == "true" ]] || exit 2
    [[ "${MAVERICK_TEST_DENY_STAGE:-}" != "deny" ]] || exit 3
    ;;
  "audit") ;;
  "deny check -D warnings advisories bans licenses sources") ;;
  *) exit 4 ;;
esac

printf '%s\n' "$*" >>"$MAVERICK_TEST_CARGO_LOG"
FAKE_CARGO

cat >"$fake_bin/rg" <<'FAKE_RG'
#!/usr/bin/env bash
set -euo pipefail

case "${MAVERICK_TEST_RG_STATUS:-1}" in
  0)
    printf '%s\n' 'synthetic.rs:1:unsafe {'
    exit 0
    ;;
  1) exit 1 ;;
  2)
    printf '%s\n' "${MAVERICK_TEST_TOOL_MARKER:-synthetic-tool-error}" >&2
    exit 2
    ;;
  *) exit 3 ;;
esac
FAKE_RG

chmod 0700 "$fake_bin/cargo" "$fake_bin/rg"

run_inventory() {
  local name="$1"
  shift
  MAVERICK_TEST_CARGO_LOG="$test_root/$name-cargo" \
    CARGO_BIN="$fake_bin/cargo" PATH="$fake_bin:$PATH" \
    "$inventory" "$@" >"$test_root/$name-output" 2>&1
}

if run_inventory invalid-option synthetic-invalid; then
  fail
fi
grep -Fx 'usage: security-dependency-inventory.sh [--offline]' \
  "$test_root/invalid-option-output" >/dev/null || fail

MAVERICK_TEST_RG_STATUS=1 run_inventory offline-clean --offline || fail
grep -Fx 'audit --no-fetch --no-yanked' "$test_root/offline-clean-cargo" \
  >/dev/null || fail
grep -Fx 'deny --offline --locked check -D warnings advisories bans licenses sources' \
  "$test_root/offline-clean-cargo" >/dev/null || fail
grep -Fx 'cached security dependency inventory OK; online freshness was not checked' \
  "$test_root/offline-clean-output" >/dev/null || fail

MAVERICK_TEST_RG_STATUS=1 run_inventory online-clean || fail
grep -Fx 'audit' "$test_root/online-clean-cargo" >/dev/null || fail
grep -Fx 'deny check -D warnings advisories bans licenses sources' \
  "$test_root/online-clean-cargo" >/dev/null || fail
grep -Fx 'security dependency inventory OK' "$test_root/online-clean-output" \
  >/dev/null || fail

if MAVERICK_TEST_RG_STATUS=0 run_inventory unsafe-match --offline; then
  fail
fi
grep -F 'first-party unsafe Rust construct found' \
  "$test_root/unsafe-match-output" >/dev/null || fail
! grep -F 'inventory OK' "$test_root/unsafe-match-output" >/dev/null || fail

tool_marker='SYNTHETIC_TOOL_ERROR_MARKER'
if MAVERICK_TEST_RG_STATUS=2 MAVERICK_TEST_TOOL_MARKER="$tool_marker" \
  run_inventory rg-error --offline; then
  fail
fi
grep -Fx 'unable to complete first-party unsafe-code inventory' \
  "$test_root/rg-error-output" >/dev/null || fail
! grep -F "$tool_marker" "$test_root/rg-error-output" >/dev/null || fail
! grep -F 'inventory OK' "$test_root/rg-error-output" >/dev/null || fail

if MAVERICK_TEST_RG_STATUS=1 MAVERICK_TEST_DENY_STAGE=deny \
  run_inventory deny-error --offline; then
  fail
fi
! grep -F 'inventory OK' "$test_root/deny-error-output" >/dev/null || fail

echo "security dependency inventory focused tests OK"
