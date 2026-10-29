#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
subject="$repo_root/scripts/install-security-tools.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/maverick-security-tools.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT

fail() {
  printf 'security-tool installer test failed: %s\n' "$1" >&2
  exit 1
}

cat >"$fixture_root/cargo" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
state="${MAVERICK_TEST_TOOL_STATE:?}"
case "${1:-}" in
  audit | deny | cyclonedx)
    [[ $# -eq 2 && "$2" == --version ]] || exit 97
    [[ -f "$state/$1" ]] || exit 1
    case "$1" in
      cyclonedx) label=cargo-cyclonedx-cyclonedx ;;
      *) label="cargo-$1" ;;
    esac
    printf '%s %s\n' "$label" "$(cat "$state/$1")"
    [[ "${MAVERICK_TEST_VERSION_FAILURE:-}" != "$1" ]] || exit 7
    ;;
  install)
    [[ $# -eq 6 && "$3" == --version && "$5" == --locked && "$6" == --force ]] || exit 97
    tool="${2#cargo-}"
    case "$tool" in audit | deny | cyclonedx) ;; *) exit 97 ;; esac
    printf '%s\n' "$*" >>"$state/installs"
    [[ "${MAVERICK_TEST_INSTALL_FAILURE:-}" != "$tool" ]] || exit 8
    version="$4"
    [[ "${MAVERICK_TEST_WRONG_INSTALL:-}" != "$tool" ]] || version=0.0.0
    printf '%s\n' "$version" >"$state/$tool"
    ;;
  *) exit 97 ;;
esac
FAKE
chmod 0755 "$fixture_root/cargo"

new_state() {
  state="$fixture_root/$1"
  mkdir "$state"
  : >"$state/installs"
}

run_installer() {
  env CARGO_BIN="$fixture_root/cargo" MAVERICK_TEST_TOOL_STATE="$state" \
    "$@" "$subject" >"$state/output" 2>&1
}

new_state missing
run_installer
expected="$(printf '%s\n' \
  'install cargo-audit --version 0.22.2 --locked --force' \
  'install cargo-deny --version 0.20.2 --locked --force' \
  'install cargo-cyclonedx --version 0.5.9 --locked --force')"
[[ "$(cat "$state/installs")" == "$expected" ]] || fail missing-tools

# Simulate a binary cache hit: no installation metadata is provided.
: >"$state/installs"
run_installer
[[ ! -s "$state/installs" ]] || fail cache-hit-reinstalled-tools

printf '0.22.1\n' >"$state/audit"
run_installer
[[ "$(cat "$state/installs")" == 'install cargo-audit --version 0.22.2 --locked --force' ]] ||
  fail wrong-version

new_state install-failure
if run_installer MAVERICK_TEST_INSTALL_FAILURE=audit; then
  fail accepted-install-failure
fi
[[ "$(wc -l <"$state/installs" | tr -d ' ')" -eq 1 ]] || fail continued-after-install-failure

new_state wrong-install
if run_installer MAVERICK_TEST_WRONG_INSTALL=audit; then
  fail accepted-wrong-installed-version
fi
[[ "$(wc -l <"$state/installs" | tr -d ' ')" -eq 1 ]] || fail continued-after-wrong-install

new_state version-failure
printf '0.22.2\n' >"$state/audit"
if run_installer MAVERICK_TEST_VERSION_FAILURE=audit; then
  fail accepted-failed-version-command
fi

echo "security-tool installer focused tests OK"
