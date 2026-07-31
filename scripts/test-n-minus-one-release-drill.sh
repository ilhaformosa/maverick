#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

readonly MAC_TARGET="aarch64-apple-darwin"
readonly LINUX_TARGET="x86_64-unknown-linux-gnu"
readonly BETA1_TAG="v1.2.0-beta.1"
readonly BETA1_VERSION="${BETA1_TAG#v}"
readonly BETA1_REVISION="75b2a666f236043c3f3c611a9f2c3de8526c3171"
readonly BETA2_TAG="v1.2.0-beta.2"
readonly BETA2_VERSION="${BETA2_TAG#v}"
readonly BETA2_REVISION="6862a3004ec9c3b1e52fd03f71dc47b771564cc4"
readonly MAX_ARCHIVE_BYTES="67108864"
readonly MAX_TEXT_BYTES="1048576"
readonly MAX_SMALL_TEXT_BYTES="4096"
readonly NATIVE_TIMEOUT_SECONDS="12"
readonly FEATURES_LINE="features: tls13,h2,browser-tls-default,cdn-fronted-h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,user-smoke"
readonly CLEANUP_MARKER_CONTENT="maverick-n-minus-one-private-root"

private_tmp=""
selected_target=""
source_beta1_archive=""
source_beta1_checksum=""
source_beta2_archive=""
source_beta2_checksum=""
beta1_archive_copy=""
beta1_checksum_copy=""
beta2_archive_copy=""
beta2_checksum_copy=""
snapshot_archive=""
snapshot_checksum=""
run_status=0
bounded_supervisor_pid=""
tar_tool=""
tar_flavor=""

cleanup() {
  case "$private_tmp" in
    /tmp/maverick-n-minus-one.*)
      if [[ -d "$private_tmp" && ! -L "$private_tmp" &&
        -f "$private_tmp/.cleanup-marker" &&
        ! -L "$private_tmp/.cleanup-marker" ]] &&
        [[ "$(wc -l <"$private_tmp/.cleanup-marker" 2>/dev/null |
          tr -d '[:space:]')" == "1" ]] &&
        grep -Fqx "$CLEANUP_MARKER_CONTENT" "$private_tmp/.cleanup-marker" \
          2>/dev/null; then
        chmod -R u+rwX "$private_tmp" >/dev/null 2>&1 || true
        find "$private_tmp" -depth -delete >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

fail() {
  echo "N-1 release drill failed" >&2
  exit 1
}

terminate() {
  local status="$1"
  trap - HUP INT TERM
  if [[ "$bounded_supervisor_pid" =~ ^[0-9]+$ ]]; then
    kill -TERM "$bounded_supervisor_pid" >/dev/null 2>&1 || true
    wait "$bounded_supervisor_pid" >/dev/null 2>&1 || true
    bounded_supervisor_pid=""
  fi
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'terminate 129' HUP
trap 'terminate 130' INT
trap 'terminate 143' TERM

file_size() {
  local measured
  measured="$(wc -c <"$1" 2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$measured" =~ ^[0-9]+$ ]] || fail
  printf '%s\n' "$measured"
}

sha256_file() {
  local digest
  if command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')" || fail
  elif command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$1" 2>/dev/null | awk '{print $1}')" || fail
  else
    fail
  fi
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s\n' "$digest"
}

field_hex() {
  dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null |
    od -An -tx1 -v |
    tr -d ' \n'
}

snapshot_release() {
  local source_archive="$1"
  local source_checksum="$2"
  local expected_basename="$3"
  local expected_bytes="$4"
  local expected_archive_sha="$5"
  local expected_checksum_sha="$6"
  local destination="$7"
  local checksum_basename
  local expected_checksum

  [[ -f "$source_archive" && ! -L "$source_archive" ]] || fail
  [[ -f "$source_checksum" && ! -L "$source_checksum" ]] || fail
  [[ "${source_archive##*/}" == "$expected_basename" ]] || fail
  checksum_basename="${expected_basename}.sha256"
  [[ "${source_checksum##*/}" == "$checksum_basename" ]] || fail
  [[ "$(file_size "$source_archive")" == "$expected_bytes" ]] || fail
  [[ "$expected_bytes" -le "$MAX_ARCHIVE_BYTES" ]] || fail
  [[ "$(file_size "$source_checksum")" == "$CHECKSUM_BYTES" ]] || fail
  [[ "$(sha256_file "$source_archive")" == "$expected_archive_sha" ]] || fail
  [[ "$(sha256_file "$source_checksum")" == "$expected_checksum_sha" ]] || fail

  mkdir "$destination" >/dev/null 2>&1 || fail
  chmod 0700 "$destination" >/dev/null 2>&1 || fail
  snapshot_archive="$destination/$expected_basename"
  snapshot_checksum="$destination/$checksum_basename"
  cp "$source_archive" "$snapshot_archive" >/dev/null 2>&1 || fail
  cp "$source_checksum" "$snapshot_checksum" >/dev/null 2>&1 || fail
  chmod 0600 "$snapshot_archive" "$snapshot_checksum" >/dev/null 2>&1 || fail

  [[ -f "$snapshot_archive" && ! -L "$snapshot_archive" ]] || fail
  [[ -f "$snapshot_checksum" && ! -L "$snapshot_checksum" ]] || fail
  [[ "$(file_size "$snapshot_archive")" == "$expected_bytes" ]] || fail
  [[ "$(file_size "$snapshot_archive")" -le "$MAX_ARCHIVE_BYTES" ]] || fail
  [[ "$(file_size "$snapshot_checksum")" == "$CHECKSUM_BYTES" ]] || fail
  [[ "$(sha256_file "$snapshot_archive")" == "$expected_archive_sha" ]] || fail
  [[ "$(sha256_file "$snapshot_checksum")" == "$expected_checksum_sha" ]] || fail
  cmp -s "$source_archive" "$snapshot_archive" || fail
  cmp -s "$source_checksum" "$snapshot_checksum" || fail

  expected_checksum="$destination/expected-checksum"
  printf '%s  %s\n' "$expected_archive_sha" "$expected_basename" >"$expected_checksum"
  chmod 0600 "$expected_checksum" >/dev/null 2>&1 || fail
  [[ "$(wc -l <"$snapshot_checksum" 2>/dev/null | tr -d '[:space:]')" == "1" ]] ||
    fail
  cmp -s "$snapshot_checksum" "$expected_checksum" || fail
}

extract_archive_safely() {
  local archive="$1"
  local extract_dir="$2"

  case "$tar_flavor" in
    bsdtar)
      COPYFILE_DISABLE=1 "$tar_tool" \
        --no-same-owner --no-same-permissions --no-acls --no-fflags --no-xattrs \
        -xzf "$archive" -C "$extract_dir" >/dev/null 2>&1 || fail
      ;;
    gnu-tar)
      "$tar_tool" --extract --gzip --file="$archive" --directory="$extract_dir" \
        --no-same-owner --no-same-permissions --no-acls --no-xattrs \
        --no-selinux --delay-directory-restore >/dev/null 2>&1 || fail
      ;;
    *) fail ;;
  esac
}

verify_beta1_archive_shape() {
  local archive="$1"
  local expected_names="$private_tmp/beta1-expected-names"
  local observed_names="$private_tmp/beta1-observed-names"
  local expected_types="$private_tmp/beta1-expected-types"
  local observed_types="$private_tmp/beta1-observed-types"

  case "$TARGET" in
    "$MAC_TARGET")
      printf '%s\n' \
        "maverick-pilot/" \
        "maverick-pilot/LICENSE" \
        "maverick-pilot/START_HERE.txt" \
        "maverick-pilot/SOURCE.txt" \
        "maverick-pilot/maverick" \
        "maverick-pilot/VERSION.txt" \
        "maverick-pilot/SHA256SUMS" >"$expected_names"
      ;;
    "$LINUX_TARGET")
      printf '%s\n' \
        "maverick-pilot/" \
        "maverick-pilot/SOURCE.txt" \
        "maverick-pilot/START_HERE.txt" \
        "maverick-pilot/maverick" \
        "maverick-pilot/VERSION.txt" \
        "maverick-pilot/SHA256SUMS" \
        "maverick-pilot/LICENSE" >"$expected_names"
      ;;
    *) fail ;;
  esac
  "$tar_tool" -tzf "$archive" >"$observed_names" 2>/dev/null || fail
  cmp -s "$observed_names" "$expected_names" || fail

  awk '{ type = ($0 ~ /\/$/ ? "d" : "-"); print type " " $0 }' \
    "$expected_names" >"$expected_types"
  "$tar_tool" -tvzf "$archive" 2>/dev/null |
    awk 'NF > 1 { print substr($1, 1, 1) " " $NF }' >"$observed_types" || fail
  cmp -s "$observed_types" "$expected_types" || fail
}

verify_payload_shape() {
  local extract_dir="$1"
  local payload_root="$extract_dir/maverick-pilot"
  local payload_file

  [[ -d "$payload_root" && ! -L "$payload_root" ]] || fail
  for payload_file in LICENSE SHA256SUMS SOURCE.txt START_HERE.txt VERSION.txt maverick; do
    [[ -f "$payload_root/$payload_file" && ! -L "$payload_root/$payload_file" ]] ||
      fail
  done
  [[ "$(find "$extract_dir" -mindepth 1 -print 2>/dev/null | wc -l |
    tr -d '[:space:]')" == "7" ]] || fail
}

verify_inner_checksums() {
  local payload_root="$1"
  local inner_file="$payload_root/SHA256SUMS"
  local inner_name
  local expected_inner="$private_tmp/expected-inner-checksums"

  for inner_name in LICENSE SOURCE.txt START_HERE.txt VERSION.txt maverick; do
    printf '%s  %s\n' "$(sha256_file "$payload_root/$inner_name")" "$inner_name"
  done >"$expected_inner"
  cmp -s "$inner_file" "$expected_inner" || fail
}

verify_beta1_metadata() {
  local payload_root="$1"
  local expected_source="$private_tmp/expected-beta1-source"
  local expected_version="$private_tmp/expected-beta1-version"
  local binary="$payload_root/maverick"
  local elf_type
  local file_description
  local readelf_header
  local readelf_tool

  printf '%s\n' \
    "repository: https://github.com/ilhaformosa/maverick" \
    "git_revision: $BETA1_REVISION" \
    "source_state: clean" \
    "version: $BETA1_VERSION" \
    "target: $TARGET" >"$expected_source"
  cmp -s "$expected_source" "$payload_root/SOURCE.txt" || fail

  printf '%s\n' \
    "maverick $BETA1_VERSION" \
    "protocol_version: 1" \
    "$FEATURES_LINE" >"$expected_version"
  cmp -s "$expected_version" "$payload_root/VERSION.txt" || fail

  file_description="$(file -b "$binary" 2>/dev/null)" || fail
  case "$TARGET" in
    "$MAC_TARGET")
      [[ "$(field_hex "$binary" 0 4)" == "cffaedfe" ]] || fail
      [[ "$(field_hex "$binary" 4 4)" == "0c000001" ]] || fail
      [[ "$(field_hex "$binary" 12 4)" == "02000000" ]] || fail
      [[ "$file_description" == *"Mach-O"* &&
        "$file_description" == *"arm64"* ]] || fail
      [[ "$file_description" != *"universal"* &&
        "$file_description" != *"fat"* ]] || fail
      ;;
    "$LINUX_TARGET")
      [[ "$(field_hex "$binary" 0 7)" == "7f454c46020101" ]] || fail
      elf_type="$(field_hex "$binary" 16 2)"
      [[ "$elf_type" == "0200" || "$elf_type" == "0300" ]] || fail
      [[ "$(field_hex "$binary" 18 2)" == "3e00" ]] || fail
      [[ "$file_description" == *"ELF"* &&
        "$file_description" == *"x86-64"* ]] || fail
      if command -v readelf >/dev/null 2>&1; then
        readelf_tool="$(command -v readelf 2>/dev/null)" || fail
      elif command -v greadelf >/dev/null 2>&1; then
        readelf_tool="$(command -v greadelf 2>/dev/null)" || fail
      else
        fail
      fi
      readelf_header="$("$readelf_tool" -h "$binary" 2>/dev/null)" || fail
      printf '%s\n' "$readelf_header" |
        grep -Eq 'Class:[[:space:]]+ELF64' || fail
      printf '%s\n' "$readelf_header" |
        grep -Eq 'Data:[[:space:]]+2.s complement, little endian' || fail
      printf '%s\n' "$readelf_header" |
        grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || fail
      case "$elf_type" in
        0200)
          [[ "$file_description" == *"executable"* ]] || fail
          printf '%s\n' "$readelf_header" |
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]' || fail
          ;;
        0300)
          [[ "$file_description" == *"pie executable"* ]] || fail
          printf '%s\n' "$readelf_header" |
            grep -Eq 'Type:[[:space:]]+DYN.*Position-Independent Executable' ||
            fail
          ;;
      esac
      ;;
    *) fail ;;
  esac
  [[ -x "$binary" ]] || fail
}

run_bounded() {
  local output_file="$1"
  local working_dir="$2"
  local private_home="$3"
  local private_runtime="$4"
  local timeout_driver
  shift 4

  timeout_driver="$(command -v perl 2>/dev/null)" || fail
  (
    cd "$working_dir" || exit 1
    ulimit -f 2048 || exit 1
    # The following single-quoted program is interpreted by Perl.
    # shellcheck disable=SC2016
    exec env -i \
      PATH="/usr/bin:/bin" \
      HOME="$private_home" \
      TMPDIR="$private_runtime" \
      LC_ALL=C \
      "$timeout_driver" -e \
        'my $limit = shift;
         my $pid;
         my $terminate = sub {
           my $code = shift;
           if (defined $pid && $pid > 0) {
             kill "TERM", -$pid;
             select undef, undef, undef, 0.2;
             kill "KILL", -$pid;
             waitpid($pid, 0);
           }
           exit $code;
         };
         $SIG{ALRM} = sub { $terminate->(124); };
         $SIG{HUP} = sub { $terminate->(129); };
         $SIG{INT} = sub { $terminate->(130); };
         $SIG{TERM} = sub { $terminate->(143); };
         $pid = fork();
         exit 127 unless defined $pid;
         if ($pid == 0) {
           setpgrp(0, 0);
           exec @ARGV;
           exit 127;
         }
         alarm $limit;
         waitpid($pid, 0);
         alarm 0;
         exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);' \
        "$NATIVE_TIMEOUT_SECONDS" "$@"
  ) >"$output_file" 2>&1 &
  bounded_supervisor_pid=$!
  set +e
  wait "$bounded_supervisor_pid"
  run_status=$?
  bounded_supervisor_pid=""
  set -e
}

expect_success() {
  local output_file="$1"
  shift
  run_bounded "$output_file" "$@"
  [[ "$run_status" -eq 0 ]] || fail
  [[ "$(file_size "$output_file")" -le "$MAX_TEXT_BYTES" ]] || fail
}

expect_rejection() {
  local expected_text="$1"
  local output_file="$2"
  shift 2
  run_bounded "$output_file" "$@"
  [[ "$run_status" -eq 1 ]] || fail
  [[ "$(file_size "$output_file")" -le "$MAX_TEXT_BYTES" ]] || fail
  [[ "$(wc -l <"$output_file" 2>/dev/null | tr -d '[:space:]')" == "1" ]] || fail
  [[ "$(sed -n '1p' "$output_file" 2>/dev/null)" == \
    "Error: configuration error: $expected_text" ]] || fail
}

assert_health() {
  local binary="$1"
  local version_file="$2"
  local private_home="$3"
  local private_runtime="$4"
  local output_prefix="$5"
  local version_output="$private_tmp/${output_prefix}-version"
  local smoke_output="$private_tmp/${output_prefix}-smoke"
  local failure_status=0

  expect_success "$version_output" "$private_runtime" "$private_home" \
    "$private_runtime" "$binary" version
  [[ "$(file_size "$version_output")" -le "$MAX_SMALL_TEXT_BYTES" ]] || fail
  cmp -s "$version_output" "$version_file" || fail

  expect_success "$smoke_output" "$private_runtime" "$private_home" \
    "$private_runtime" "$binary" user-smoke
  [[ "$(grep -Fxc 'wrong_credential_rejected: PASS' "$smoke_output" 2>/dev/null)" == \
    "1" ]] || fail
  [[ "$(grep -Fxc 'correct_credential_roundtrip: PASS' "$smoke_output" \
    2>/dev/null)" == "1" ]] || fail
  grep -Eq ': FAIL$' "$smoke_output" 2>/dev/null || failure_status=$?
  case "$failure_status" in
    0) fail ;;
    1) ;;
    *) fail ;;
  esac
}

make_neutral_generated_profile() {
  local beta1_binary="$1"
  local profile_dir="$2"
  local private_home="$3"
  local private_runtime="$4"
  local generated_output="$private_tmp/generated-config-output"
  local fixture_secret="mv1_""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  local input_file
  local neutral_file

  mkdir "$profile_dir" >/dev/null 2>&1 || fail
  chmod 0700 "$profile_dir" >/dev/null 2>&1 || fail
  expect_success "$generated_output" "$profile_dir" "$private_home" \
    "$private_runtime" "$beta1_binary" gen-config
  for input_file in client.generated.yaml server.generated.yaml; do
    [[ -f "$profile_dir/$input_file" && ! -L "$profile_dir/$input_file" ]] || fail
    neutral_file="$private_tmp/neutral-$input_file"
    awk -v secret="$fixture_secret" '
      /^[[:space:]]+secret: "/ {
        sub(/secret: "[^"]+"/, "secret: \"" secret "\"")
      }
      /^[[:space:]]+name: "alice"$/ {
        sub(/"alice"/, "\"test-user\"")
      }
      { print }
    ' "$profile_dir/$input_file" >"$neutral_file" || fail
    mv "$neutral_file" "$profile_dir/$input_file" >/dev/null 2>&1 || fail
    chmod 0600 "$profile_dir/$input_file" >/dev/null 2>&1 || fail
    [[ "$(grep -Ec '^[[:space:]]+secret: "' "$profile_dir/$input_file" \
      2>/dev/null)" == "1" ]] || fail
    [[ "$(grep -Fc "secret: \"$fixture_secret\"" "$profile_dir/$input_file" \
      2>/dev/null)" == "1" ]] || fail
  done
}

copy_profile() {
  local source_dir="$1"
  local destination_dir="$2"
  mkdir "$destination_dir" >/dev/null 2>&1 || fail
  chmod 0700 "$destination_dir" >/dev/null 2>&1 || fail
  cp "$source_dir/client.generated.yaml" "$destination_dir/client.generated.yaml" \
    >/dev/null 2>&1 || fail
  cp "$source_dir/server.generated.yaml" "$destination_dir/server.generated.yaml" \
    >/dev/null 2>&1 || fail
  chmod 0600 "$destination_dir/client.generated.yaml" \
    "$destination_dir/server.generated.yaml" >/dev/null 2>&1 || fail
}

write_profile_manifest() {
  local profile_dir="$1"
  local output="$2"
  printf '%s  %s\n' \
    "$(sha256_file "$profile_dir/client.generated.yaml")" "client.generated.yaml" \
    "$(sha256_file "$profile_dir/server.generated.yaml")" "server.generated.yaml" \
    >"$output"
}

check_config_pair_success() {
  local label="$1"
  local binary="$2"
  local profile_dir="$3"
  local private_home="$4"
  local private_runtime="$5"
  local kind
  local output

  for kind in client server; do
    output="$private_tmp/${label}-${kind}-accepted"
    expect_success "$output" "$profile_dir" "$private_home" "$private_runtime" \
      "$binary" check-config --kind "$kind" -c "$kind.generated.yaml"
    [[ "$(wc -l <"$output" 2>/dev/null | tr -d '[:space:]')" == "1" ]] || fail
    [[ "$(sed -n '1p' "$output" 2>/dev/null)" == "$kind config OK" ]] || fail
  done
}

check_config_pair_rejection() {
  local expected_text="$1"
  local label="$2"
  local binary="$3"
  local profile_dir="$4"
  local private_home="$5"
  local private_runtime="$6"
  local kind
  local output

  for kind in client server; do
    output="$private_tmp/${label}-${kind}-rejected"
    expect_rejection "$expected_text" "$output" "$profile_dir" "$private_home" \
      "$private_runtime" "$binary" check-config --kind "$kind" \
      -c "$kind.generated.yaml"
  done
}

attempt_beta2_switch() {
  local profile_dir="$1"
  local label="$2"
  local kind
  local output
  local preflight_failed=0

  for kind in client server; do
    output="$private_tmp/${label}-${kind}-switch-preflight"
    run_bounded "$output" "$profile_dir" "$beta2_home" "$beta2_runtime" \
      "$beta2_binary" check-config --kind "$kind" -c "$kind.generated.yaml"
    [[ "$(file_size "$output")" -le "$MAX_TEXT_BYTES" ]] || fail
    case "$run_status" in
      0)
        [[ "$(wc -l <"$output" 2>/dev/null | tr -d '[:space:]')" == "1" ]] ||
          fail
        [[ "$(sed -n '1p' "$output" 2>/dev/null)" == "$kind config OK" ]] ||
          fail
        ;;
      1)
        preflight_failed=1
        ;;
      *)
        fail
        ;;
    esac
  done
  [[ "$preflight_failed" -eq 0 ]] || return 1
  write_selector "beta2"
}

write_selector() {
  local selected="$1"
  case "$selected" in
    beta1 | beta2) ;;
    *) fail ;;
  esac
  printf '%s\n' "$selected" >"$selector_file" || fail
  chmod 0600 "$selector_file" >/dev/null 2>&1 || fail
}

assert_selected_health() {
  local expected="$1"
  local output_prefix="$2"
  local selected=""
  local selected_binary
  local selected_version_file
  local selected_home
  local selected_runtime

  [[ -f "$selector_file" && ! -L "$selector_file" ]] || fail
  IFS= read -r selected <"$selector_file" || fail
  [[ "$selected" == "$expected" ]] || fail
  [[ "$(wc -l <"$selector_file" 2>/dev/null | tr -d '[:space:]')" == "1" ]] ||
    fail
  case "$selected" in
    beta1)
      selected_binary="$beta1_binary"
      selected_version_file="$beta1_parent/maverick-pilot/VERSION.txt"
      selected_home="$beta1_home"
      selected_runtime="$beta1_runtime"
      ;;
    beta2)
      selected_binary="$beta2_binary"
      selected_version_file="$beta2_parent/maverick-pilot/VERSION.txt"
      selected_home="$beta2_home"
      selected_runtime="$beta2_runtime"
      ;;
    *) fail ;;
  esac
  assert_health "$selected_binary" "$selected_version_file" "$selected_home" \
    "$selected_runtime" "$output_prefix"
}

verify_inputs_unchanged() {
  [[ -f "$source_beta1_archive" && ! -L "$source_beta1_archive" ]] || fail
  [[ -f "$source_beta1_checksum" && ! -L "$source_beta1_checksum" ]] || fail
  [[ -f "$source_beta2_archive" && ! -L "$source_beta2_archive" ]] || fail
  [[ -f "$source_beta2_checksum" && ! -L "$source_beta2_checksum" ]] || fail
  cmp -s "$source_beta1_archive" "$beta1_archive_copy" || fail
  cmp -s "$source_beta1_checksum" "$beta1_checksum_copy" || fail
  cmp -s "$source_beta2_archive" "$beta2_archive_copy" || fail
  cmp -s "$source_beta2_checksum" "$beta2_checksum_copy" || fail
  [[ "$(sha256_file "$source_beta1_archive")" == "$BETA1_SHA256" ]] || fail
  [[ "$(sha256_file "$source_beta1_checksum")" == "$BETA1_CHECKSUM_SHA256" ]] ||
    fail
  [[ "$(sha256_file "$source_beta2_archive")" == "$BETA2_SHA256" ]] || fail
  [[ "$(sha256_file "$source_beta2_checksum")" == "$BETA2_CHECKSUM_SHA256" ]] ||
    fail
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 && -z "$selected_target" ]] || fail
      selected_target="$2"
      shift 2
      ;;
    --beta1-archive)
      [[ $# -ge 2 && -z "$source_beta1_archive" ]] || fail
      source_beta1_archive="$2"
      shift 2
      ;;
    --beta1-checksum)
      [[ $# -ge 2 && -z "$source_beta1_checksum" ]] || fail
      source_beta1_checksum="$2"
      shift 2
      ;;
    --beta2-archive)
      [[ $# -ge 2 && -z "$source_beta2_archive" ]] || fail
      source_beta2_archive="$2"
      shift 2
      ;;
    --beta2-checksum)
      [[ $# -ge 2 && -z "$source_beta2_checksum" ]] || fail
      source_beta2_checksum="$2"
      shift 2
      ;;
    *)
      fail
      ;;
  esac
done

[[ -n "$source_beta1_archive" && -n "$source_beta1_checksum" ]] || fail
[[ -n "$source_beta2_archive" && -n "$source_beta2_checksum" ]] || fail
if [[ -z "$selected_target" ]]; then
  selected_target="$MAC_TARGET"
fi

case "$selected_target" in
  "$MAC_TARGET")
    TARGET="$MAC_TARGET"
    BETA1_BASENAME="maverick-1.2.0-beta.1-pilot-aarch64-apple-darwin.tar.gz"
    BETA1_BYTES="5565864"
    BETA1_SHA256="d44c553c22de52abdb2dfbe4bb7e7bf8d982ce5bdf9cb90f5ae4b8c01d29fc3e"
    BETA1_CHECKSUM_SHA256="202e4b29c6f46b97b87a52784384a11f6be329412aba934af5ecaf9b9c3db272"
    BETA2_BASENAME="maverick-1.2.0-beta.2-pilot-aarch64-apple-darwin.tar.gz"
    BETA2_BYTES="5607172"
    BETA2_SHA256="e48c87795e534d141c5b563a1da4e36ca485c75542046fdd925c2c8495d9a7f1"
    BETA2_CHECKSUM_SHA256="71bd02e2b6d31318356f5197ab61eff1db258b7bb2b95fe553a0bedaa0c935e9"
    CHECKSUM_BYTES="122"
    ;;
  "$LINUX_TARGET")
    TARGET="$LINUX_TARGET"
    BETA1_BASENAME="maverick-1.2.0-beta.1-pilot-x86_64-unknown-linux-gnu.tar.gz"
    BETA1_BYTES="6139821"
    BETA1_SHA256="7867332bcf8cb440b24a7b0569d4e58b554e207a43499ac1cc7e0650dba6b7d5"
    BETA1_CHECKSUM_SHA256="56aa22b84a8e5272a8bfe21aa0e9d2fb503f1d0f892957018224f87bc291e7ac"
    BETA2_BASENAME="maverick-1.2.0-beta.2-pilot-x86_64-unknown-linux-gnu.tar.gz"
    BETA2_BYTES="6185627"
    BETA2_SHA256="6a9afc7c5b1d024f5d279a683a6bf02a4d99fa3437f477fc018283f05688c24b"
    BETA2_CHECKSUM_SHA256="291336c4ff54062bcae5dbfc624850a0ea3b8e1b65667c121ea9e3d13000cf47"
    CHECKSUM_BYTES="126"
    ;;
  *) fail ;;
esac
readonly TARGET BETA1_BASENAME BETA1_BYTES BETA1_SHA256
readonly BETA1_CHECKSUM_SHA256 BETA2_BASENAME BETA2_BYTES BETA2_SHA256
readonly BETA2_CHECKSUM_SHA256 CHECKSUM_BYTES

host_os="$(uname -s 2>/dev/null)" || fail
host_cpu="$(uname -m 2>/dev/null)" || fail
case "$TARGET" in
  "$MAC_TARGET")
    [[ "$host_os" == "Darwin" && "$host_cpu" == "arm64" ]] || fail
    [[ -x /usr/bin/tar ]] || fail
    tar_tool="/usr/bin/tar"
    [[ "$("$tar_tool" --version 2>/dev/null)" == *"bsdtar"* ]] || fail
    tar_flavor="bsdtar"
    ;;
  "$LINUX_TARGET")
    [[ "$host_os" == "Linux" && "$host_cpu" == "x86_64" ]] || fail
    tar_tool="$(command -v tar 2>/dev/null)" || fail
    [[ "$("$tar_tool" --version 2>/dev/null)" == *"GNU tar"* ]] || fail
    tar_flavor="gnu-tar"
    ;;
  *) fail ;;
esac
readonly tar_tool tar_flavor
echo "platform_gate: $host_os/$host_cpu/$tar_flavor: PASS"

private_tmp="$(mktemp -d /tmp/maverick-n-minus-one.XXXXXX 2>/dev/null)" || fail
[[ -d "$private_tmp" && ! -L "$private_tmp" ]] || fail
chmod 0700 "$private_tmp" >/dev/null 2>&1 || fail
case "$TARGET" in
  "$MAC_TARGET")
    [[ "$(stat -f '%Lp' "$private_tmp" 2>/dev/null)" == "700" ]] || fail
    ;;
  "$LINUX_TARGET")
    [[ "$(stat -c '%a' "$private_tmp" 2>/dev/null)" == "700" ]] || fail
    ;;
  *) fail ;;
esac
printf '%s\n' "$CLEANUP_MARKER_CONTENT" >"$private_tmp/.cleanup-marker" || fail
chmod 0600 "$private_tmp/.cleanup-marker" >/dev/null 2>&1 || fail

snapshot_release "$source_beta1_archive" "$source_beta1_checksum" \
  "$BETA1_BASENAME" "$BETA1_BYTES" "$BETA1_SHA256" "$BETA1_CHECKSUM_SHA256" \
  "$private_tmp/input-beta1"
beta1_archive_copy="$snapshot_archive"
beta1_checksum_copy="$snapshot_checksum"
snapshot_release "$source_beta2_archive" "$source_beta2_checksum" \
  "$BETA2_BASENAME" "$BETA2_BYTES" "$BETA2_SHA256" "$BETA2_CHECKSUM_SHA256" \
  "$private_tmp/input-beta2"
beta2_archive_copy="$snapshot_archive"
beta2_checksum_copy="$snapshot_checksum"
echo "artifact_identity: PASS"

beta1_parent="$private_tmp/releases/beta1"
beta2_parent="$private_tmp/releases/beta2"
mkdir -p "$beta1_parent" "$beta2_parent" >/dev/null 2>&1 || fail
chmod 0700 "$private_tmp/releases" "$beta1_parent" "$beta2_parent" \
  >/dev/null 2>&1 || fail

verify_beta1_archive_shape "$beta1_archive_copy"
extract_archive_safely "$beta1_archive_copy" "$beta1_parent"
verify_payload_shape "$beta1_parent"
verify_inner_checksums "$beta1_parent/maverick-pilot"
verify_beta1_metadata "$beta1_parent/maverick-pilot"
chmod 0700 "$beta1_parent/maverick-pilot" \
  "$beta1_parent/maverick-pilot/maverick" >/dev/null 2>&1 || fail
chmod 0600 "$beta1_parent/maverick-pilot/LICENSE" \
  "$beta1_parent/maverick-pilot/SHA256SUMS" \
  "$beta1_parent/maverick-pilot/SOURCE.txt" \
  "$beta1_parent/maverick-pilot/START_HERE.txt" \
  "$beta1_parent/maverick-pilot/VERSION.txt" >/dev/null 2>&1 || fail

mkdir -p "$private_tmp/runtime/beta1/home" "$private_tmp/runtime/beta1/tmp" \
  "$private_tmp/runtime/beta2/home" "$private_tmp/runtime/beta2/tmp" \
  >/dev/null 2>&1 || fail
chmod 0700 "$private_tmp/runtime" "$private_tmp/runtime/beta1" \
  "$private_tmp/runtime/beta1/home" "$private_tmp/runtime/beta1/tmp" \
  "$private_tmp/runtime/beta2" "$private_tmp/runtime/beta2/home" \
  "$private_tmp/runtime/beta2/tmp" >/dev/null 2>&1 || fail

beta1_binary="$beta1_parent/maverick-pilot/maverick"
beta1_home="$private_tmp/runtime/beta1/home"
beta1_runtime="$private_tmp/runtime/beta1/tmp"
beta2_home="$private_tmp/runtime/beta2/home"
beta2_runtime="$private_tmp/runtime/beta2/tmp"
assert_health "$beta1_binary" \
  "$beta1_parent/maverick-pilot/VERSION.txt" "$beta1_home" "$beta1_runtime" \
  "beta1-artifact"
echo "beta1_historical_adapter: PASS"

"$repo_root/scripts/verify-pilot-artifact.sh" \
  --archive "$beta2_archive_copy" \
  --expected-version "$BETA2_VERSION" \
  --expected-revision "$BETA2_REVISION" \
  --expected-target "$TARGET" \
  --verification-level native || fail

extract_archive_safely "$beta2_archive_copy" "$beta2_parent"
verify_payload_shape "$beta2_parent"
chmod 0700 "$beta2_parent/maverick-pilot" \
  "$beta2_parent/maverick-pilot/maverick" >/dev/null 2>&1 || fail
chmod 0600 "$beta2_parent/maverick-pilot/LICENSE" \
  "$beta2_parent/maverick-pilot/SHA256SUMS" \
  "$beta2_parent/maverick-pilot/SOURCE.txt" \
  "$beta2_parent/maverick-pilot/START_HERE.txt" \
  "$beta2_parent/maverick-pilot/VERSION.txt" >/dev/null 2>&1 || fail
beta2_binary="$beta2_parent/maverick-pilot/maverick"
beta1_binary_hash="$(sha256_file "$beta1_binary")"
beta2_binary_hash="$(sha256_file "$beta2_binary")"
readonly beta1_binary_hash
readonly beta2_binary_hash
echo "beta2_current_verifier: PASS"

fixture_root="$private_tmp/fixture"
profile_dir="$fixture_root/profile"
backup_dir="$fixture_root/backup"
mkdir "$fixture_root" >/dev/null 2>&1 || fail
chmod 0700 "$fixture_root" >/dev/null 2>&1 || fail
make_neutral_generated_profile "$beta1_binary" "$profile_dir" \
  "$beta1_home" "$beta1_runtime"
copy_profile "$profile_dir" "$backup_dir"

profile_manifest="$profile_dir/profile.sha256"
backup_manifest="$backup_dir/profile.sha256"
write_profile_manifest "$profile_dir" "$profile_manifest"
write_profile_manifest "$backup_dir" "$backup_manifest"
original_profile_hash="$(sha256_file "$profile_manifest")"
original_backup_hash="$(sha256_file "$backup_manifest")"
readonly original_profile_hash
readonly original_backup_hash
chmod 0400 "$profile_dir/client.generated.yaml" \
  "$profile_dir/server.generated.yaml" "$profile_manifest" \
  "$backup_dir/client.generated.yaml" "$backup_dir/server.generated.yaml" \
  "$backup_manifest" >/dev/null 2>&1 || fail
chmod 0500 "$profile_dir" "$backup_dir" >/dev/null 2>&1 || fail

check_config_pair_success "beta1-known" "$beta1_binary" "$profile_dir" \
  "$beta1_home" "$beta1_runtime"
check_config_pair_success "beta2-known" "$beta2_binary" "$profile_dir" \
  "$beta2_home" "$beta2_runtime"
echo "known_v1_compatibility: PASS"

unknown_dir="$fixture_root/unknown-root"
copy_profile "$profile_dir" "$unknown_dir"
printf '%s\n' "t019c_unknown_root: true" \
  >>"$unknown_dir/client.generated.yaml" || fail
printf '%s\n' "t019c_unknown_root: true" \
  >>"$unknown_dir/server.generated.yaml" || fail
check_config_pair_success "beta1-unknown" "$beta1_binary" "$unknown_dir" \
  "$beta1_home" "$beta1_runtime"
check_config_pair_rejection "unknown configuration key under <root>" \
  "beta2-unknown" "$beta2_binary" "$unknown_dir" "$beta2_home" "$beta2_runtime"
echo "unknown_key_upgrade_preflight: PASS"

version2_dir="$fixture_root/version-2"
copy_profile "$profile_dir" "$version2_dir"
for kind in client server; do
  sed 's/^version: 1$/version: 2/' "$profile_dir/$kind.generated.yaml" \
    >"$version2_dir/$kind.generated.yaml" || fail
  chmod 0600 "$version2_dir/$kind.generated.yaml" >/dev/null 2>&1 || fail
  [[ "$(grep -c '^version: 2$' "$version2_dir/$kind.generated.yaml" \
    2>/dev/null)" == "1" ]] || fail
  sed 's/^version: 2$/version: 1/' "$version2_dir/$kind.generated.yaml" \
    >"$private_tmp/$kind-version-reverted" || fail
  cmp -s "$private_tmp/$kind-version-reverted" \
    "$profile_dir/$kind.generated.yaml" || fail
done
check_config_pair_rejection "only config version 1 is supported" \
  "beta1-version2" "$beta1_binary" "$version2_dir" \
  "$beta1_home" "$beta1_runtime"
check_config_pair_rejection "only config version 1 is supported" \
  "beta2-version2" "$beta2_binary" "$version2_dir" \
  "$beta2_home" "$beta2_runtime"
echo "unsupported_version_rejection: PASS"

selector_file="$private_tmp/release-selector"
write_selector "beta1"

if attempt_beta2_switch "$unknown_dir" "beta2-injected"; then
  fail
else
  [[ "$?" -eq 1 ]] || fail
fi
assert_selected_health "beta1" "beta1-after-fault"
echo "injected_preflight_failure: PASS"

assert_health "$beta2_binary" \
  "$beta2_parent/maverick-pilot/VERSION.txt" "$beta2_home" "$beta2_runtime" \
  "beta2-preflight"
attempt_beta2_switch "$profile_dir" "beta2-known" || fail
assert_selected_health "beta2" "beta2-selected"
echo "upgrade_to_beta2: PASS"

write_selector "beta1"
assert_selected_health "beta1" "beta1-rollback"
echo "rollback_to_beta1: PASS"

[[ "$(sha256_file "$profile_manifest")" == "$original_profile_hash" ]] || fail
[[ "$(sha256_file "$backup_manifest")" == "$original_backup_hash" ]] || fail
write_profile_manifest "$profile_dir" "$private_tmp/final-profile-manifest"
write_profile_manifest "$backup_dir" "$private_tmp/final-backup-manifest"
cmp -s "$profile_manifest" "$private_tmp/final-profile-manifest" || fail
cmp -s "$backup_manifest" "$private_tmp/final-backup-manifest" || fail
cmp -s "$profile_dir/client.generated.yaml" \
  "$backup_dir/client.generated.yaml" || fail
cmp -s "$profile_dir/server.generated.yaml" \
  "$backup_dir/server.generated.yaml" || fail
[[ "$(sha256_file "$beta1_binary")" == "$beta1_binary_hash" ]] || fail
[[ "$(sha256_file "$beta2_binary")" == "$beta2_binary_hash" ]] || fail
verify_inputs_unchanged
echo "fixture_integrity: PASS"

completed_tmp="$private_tmp"
cleanup
private_tmp=""
[[ ! -e "$completed_tmp" ]] || fail
echo "cleanup: PASS"
echo "N-1 release drill OK"
