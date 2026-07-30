#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_verifier="$repo_root/scripts/verify-pilot-artifact.sh"
tag_verifier="$repo_root/scripts/verify-release-tag.sh"
test_root=""

readonly TEST_VERSION="1.2.0-beta.2"
readonly TEST_REVISION="1111111111111111111111111111111111111111"
readonly TEST_MARKER="SYNTH_PRIVATE_MARKER_DO_NOT_ECHO"
readonly FEATURES_LINE="features: tls13,h2,browser-tls-default,cdn-fronted-h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,user-smoke"

cleanup() {
  case "$test_root" in
    /tmp/maverick-release-gates.*)
      if [[ -d "$test_root" ]]; then
        find "$test_root" -depth -delete >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

fail_test() {
  echo "release gate tests failed" >&2
  exit 1
}

trace_test() {
  if [[ "${MAVERICK_RELEASE_GATE_TEST_TRACE:-0}" == "1" ]]; then
    printf 'test: %s\n' "$1" >&2
  fi
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    fail_test
  fi
}

write_outer_checksum() {
  local archive="$1"
  printf '%s  %s\n' "$(sha256_file "$archive")" "${archive##*/}" >"$archive.sha256"
  chmod 0600 "$archive.sha256"
}

refresh_inner_checksums() {
  local root="$1"
  (
    cd "$root"
    for name in LICENSE SOURCE.txt START_HERE.txt VERSION.txt maverick; do
      printf '%s  %s\n' "$(sha256_file "$name")" "$name"
    done >SHA256SUMS
  )
  chmod 0644 "$root/SHA256SUMS"
}

pack_payload() {
  local payload_parent="$1"
  local archive="$2"
  local duplicate_name="${3:-}"
  local tar_version
  local members=(
    maverick-pilot
    maverick-pilot/LICENSE
    maverick-pilot/SHA256SUMS
    maverick-pilot/SOURCE.txt
    maverick-pilot/START_HERE.txt
    maverick-pilot/VERSION.txt
    maverick-pilot/maverick
  )
  if [[ -n "$duplicate_name" ]]; then
    members+=("$duplicate_name")
  fi
  tar_version="$(tar --version 2>/dev/null)" || fail_test
  case "$tar_version" in
    *bsdtar*)
      COPYFILE_DISABLE=1 tar \
        --format ustar \
        --uid 0 \
        --gid 0 \
        --numeric-owner \
        --no-acls \
        --no-fflags \
        --no-xattrs \
        --no-recursion \
        -czf "$archive" \
        -C "$payload_parent" \
        "${members[@]}" >/dev/null 2>&1 || fail_test
      ;;
    *"GNU tar"*)
      tar \
        --format=ustar \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        --no-recursion \
        -czf "$archive" \
        -C "$payload_parent" \
        "${members[@]}" >/dev/null 2>&1 || fail_test
      ;;
    *)
      fail_test
      ;;
  esac
  write_outer_checksum "$archive"
}

compile_fixture_binary() {
  local output="$1"
  local mode="$2"
  local marker_path="$3"
  local source="$test_root/fixture-$mode.c"
  command -v cc >/dev/null 2>&1 || fail_test
  {
    echo '#include <stdio.h>'
    echo '#include <string.h>'
    echo '#include <unistd.h>'
    printf '%s\n' "#define FIXTURE_MODE $mode"
    printf '%s\n' "#define MARKER_PATH \"$marker_path\""
    cat <<'C_SOURCE'
static void record_execution(void) {
  if (MARKER_PATH[0] != '\0') {
    FILE *marker = fopen(MARKER_PATH, FIXTURE_MODE == 6 ? "ab" : "w");
    if (marker != NULL) {
      fputs(FIXTURE_MODE == 6 ? "X" : "executed\n", marker);
      fclose(marker);
    }
  }
}

int main(int argc, char **argv) {
  record_execution();
  if (argc != 2) {
    return 2;
  }
  if (strcmp(argv[1], "version") == 0) {
    if (FIXTURE_MODE == 1) {
      puts("maverick wrong-version");
      return 0;
    }
    puts("maverick 1.2.0-beta.2");
    puts("protocol_version: 1");
    puts("features: tls13,h2,browser-tls-default,cdn-fronted-h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,user-smoke");
    return 0;
  }
  if (strcmp(argv[1], "user-smoke") == 0) {
    if (FIXTURE_MODE == 2) {
      return 3;
    }
    if (FIXTURE_MODE == 3) {
      sleep(30);
    }
    puts("wrong_credential_rejected: PASS");
    if (FIXTURE_MODE == 5) {
      puts("wrong_credential_rejected: PASS");
    }
    puts("correct_credential_roundtrip: PASS");
    if (FIXTURE_MODE == 4) {
      puts("synthetic_additional_check: FAIL");
    }
    return 0;
  }
  return 2;
}
C_SOURCE
  } >"$source"
  cc -O2 "-ffile-prefix-map=$test_root=<fixture>" "$source" -o "$output" \
    >/dev/null 2>&1 || fail_test
  chmod 0755 "$output"
}

make_payload() {
  local payload_parent="$1"
  local binary="$2"
  local target="$3"
  local root="$payload_parent/maverick-pilot"
  mkdir -p "$root"
  chmod 0755 "$root"
  cp "$repo_root/LICENSE" "$root/LICENSE"
  printf '%s\n' \
    "repository: https://github.com/ilhaformosa/maverick" \
    "git_revision: $TEST_REVISION" \
    "source_state: clean" \
    "version: $TEST_VERSION" \
    "target: $target" >"$root/SOURCE.txt"
  sed -n "/^cat >.*START_HERE\\.txt.*<<'GUIDE'$/,/^GUIDE$/p" \
    "$repo_root/scripts/build-pilot.sh" |
    sed '1d;$d' >"$root/START_HERE.txt"
  printf '%s\n' \
    "maverick $TEST_VERSION" \
    "protocol_version: 1" \
    "$FEATURES_LINE" >"$root/VERSION.txt"
  cp "$binary" "$root/maverick"
  chmod 0755 "$root/maverick"
  chmod 0644 "$root/LICENSE" "$root/SOURCE.txt" "$root/START_HERE.txt" \
    "$root/VERSION.txt"
  refresh_inner_checksums "$root"
}

new_artifact_case() {
  local name="$1"
  local binary="${2:-$native_binary}"
  local target="${3:-$native_target}"
  current_case="$test_root/artifacts/$name"
  current_archive="$current_case/maverick-${TEST_VERSION}-pilot-${target}.tar.gz"
  current_target="$target"
  mkdir -p "$current_case/payload"
  make_payload "$current_case/payload" "$binary" "$target"
  pack_payload "$current_case/payload" "$current_archive"
}

run_artifact() {
  local archive="$1"
  local target="$2"
  local level="$3"
  "$artifact_verifier" \
    --archive "$archive" \
    --expected-version "$TEST_VERSION" \
    --expected-revision "$TEST_REVISION" \
    --expected-target "$target" \
    --verification-level "$level"
}

expect_artifact_pass() {
  local label="$1"
  local archive="$2"
  local target="$3"
  local level="$4"
  local log="$test_root/logs/$label"
  trace_test "$label"
  run_artifact "$archive" "$target" "$level" >"$log" 2>&1 || fail_test
  grep -Fx "pilot artifact $level verification OK" "$log" >/dev/null || fail_test
}

expect_artifact_fail() {
  local label="$1"
  local archive="$2"
  local target="$3"
  local level="$4"
  local hidden="${5:-}"
  local log="$test_root/logs/$label"
  trace_test "$label"
  if run_artifact "$archive" "$target" "$level" >"$log" 2>&1; then
    fail_test
  fi
  log_lines="$(wc -l <"$log" | tr -d '[:space:]')"
  if [[ "$log_lines" != "1" ]]; then
    trace_test "$label-log-lines-$log_lines"
    fail_test
  fi
  grep -Fx "pilot artifact verification failed" "$log" >/dev/null || fail_test
  if [[ -n "$hidden" ]]; then
    ! grep -F "$hidden" "$log" >/dev/null 2>&1 || fail_test
  fi
}

unpack_raw_tar() {
  local archive="$1"
  local raw_tar="$2"
  gzip -dc "$archive" >"$raw_tar" 2>/dev/null || fail_test
}

repack_raw_tar() {
  local raw_tar="$1"
  local archive="$2"
  gzip -n -c "$raw_tar" >"$archive" 2>/dev/null || fail_test
  write_outer_checksum "$archive"
}

zero_region() {
  local file="$1"
  local offset="$2"
  local length="$3"
  dd if=/dev/zero of="$file" bs=1 seek="$offset" count="$length" conv=notrunc \
    >/dev/null 2>&1 || fail_test
}

write_region() {
  local file="$1"
  local offset="$2"
  local value="$3"
  printf '%s' "$value" |
    dd of="$file" bs=1 seek="$offset" conv=notrunc >/dev/null 2>&1 || fail_test
}

rewrite_header_checksum() {
  local raw_tar="$1"
  local block="${2:-0}"
  local base=$((block * 512))
  local checksum
  printf '        ' |
    dd of="$raw_tar" bs=1 seek=$((base + 148)) conv=notrunc \
      >/dev/null 2>&1 || fail_test
  checksum="$(
    dd if="$raw_tar" bs=512 skip="$block" count=1 2>/dev/null |
      od -An -tu1 -v |
      awk '{ for (i = 1; i <= NF; i++) sum += $i } END { print sum }'
  )" || fail_test
  printf '%06o\0 ' "$checksum" |
    dd of="$raw_tar" bs=1 seek=$((base + 148)) conv=notrunc \
      >/dev/null 2>&1 || fail_test
}

patch_root_name() {
  local raw_tar="$1"
  local value="$2"
  zero_region "$raw_tar" 0 100
  write_region "$raw_tar" 0 "$value"
  rewrite_header_checksum "$raw_tar" 0
}

patch_root_octal() {
  local raw_tar="$1"
  local offset="$2"
  local value="$3"
  zero_region "$raw_tar" "$offset" 8
  printf '%07o\0' "$value" |
    dd of="$raw_tar" bs=1 seek="$offset" conv=notrunc \
      >/dev/null 2>&1 || fail_test
  rewrite_header_checksum "$raw_tar" 0
}

raw_octal_value() {
  local raw_tar="$1"
  local offset="$2"
  local width="$3"
  local digits
  digits="$(
    dd if="$raw_tar" bs=1 skip="$offset" count="$width" 2>/dev/null |
      tr -d '\000 '
  )" || fail_test
  [[ "$digits" =~ ^[0-7]+$ ]] || fail_test
  printf '%s\n' "$((8#$digits))"
}

first_padding_offset() {
  local raw_tar="$1"
  local tar_bytes
  local total_blocks
  local block=0
  local name
  local size
  local data_blocks
  tar_bytes="$(wc -c <"$raw_tar" | tr -d '[:space:]')"
  total_blocks=$((tar_bytes / 512))
  while [[ "$block" -lt "$total_blocks" ]]; do
    name="$(
      dd if="$raw_tar" bs=512 skip="$block" count=1 2>/dev/null |
        dd bs=1 count=100 2>/dev/null |
        tr -d '\000'
    )" || fail_test
    [[ -n "$name" ]] || break
    size="$(raw_octal_value "$raw_tar" $((block * 512 + 124)) 12)"
    data_blocks=$(((size + 511) / 512))
    if [[ "$size" -gt 0 && $((size % 512)) -ne 0 ]]; then
      printf '%s\n' $(((block + 1) * 512 + size))
      return
    fi
    block=$((block + 1 + data_blocks))
  done
  fail_test
}

first_zero_block() {
  local raw_tar="$1"
  local tar_bytes
  local blocks
  local block=0
  local header
  local name
  local size
  local data_blocks
  tar_bytes="$(wc -c <"$raw_tar" | tr -d '[:space:]')"
  blocks=$((tar_bytes / 512))
  header="$test_root/zero-block-header"
  while [[ "$block" -lt "$blocks" ]]; do
    dd if="$raw_tar" of="$header" bs=512 skip="$block" count=1 \
      2>/dev/null || fail_test
    if od -An -tu1 -v "$header" |
      awk '{ for (i = 1; i <= NF; i++) if ($i != 0) bad = 1 }
           END { exit bad }'; then
      printf '%s\n' "$block"
      return
    fi
    name="$(dd if="$header" bs=1 count=100 2>/dev/null | tr -d '\000')" ||
      fail_test
    [[ -n "$name" ]] || fail_test
    size="$(raw_octal_value "$raw_tar" $((block * 512 + 124)) 12)"
    data_blocks=$(((size + 511) / 512))
    block=$((block + 1 + data_blocks))
  done
  fail_test
}

zero_device_fields() {
  local raw_tar="$1"
  local tar_bytes
  local blocks
  local block=0
  local header="$test_root/device-field-header"
  local name
  local size
  local data_blocks
  tar_bytes="$(wc -c <"$raw_tar" | tr -d '[:space:]')"
  blocks=$((tar_bytes / 512))
  while [[ "$block" -lt "$blocks" ]]; do
    dd if="$raw_tar" of="$header" bs=512 skip="$block" count=1 \
      2>/dev/null || fail_test
    if od -An -tu1 -v "$header" |
      awk '{ for (i = 1; i <= NF; i++) if ($i != 0) bad = 1 }
           END { exit bad }'; then
      return
    fi
    name="$(dd if="$header" bs=1 count=100 2>/dev/null | tr -d '\000')" ||
      fail_test
    [[ -n "$name" ]] || fail_test
    size="$(raw_octal_value "$raw_tar" $((block * 512 + 124)) 12)"
    zero_region "$raw_tar" $((block * 512 + 329)) 16
    rewrite_header_checksum "$raw_tar" "$block"
    data_blocks=$(((size + 511) / 512))
    block=$((block + 1 + data_blocks))
  done
  fail_test
}

git_commit_fixture() {
  local repo="$1"
  local text="$2"
  printf '%s\n' "$text" >>"$repo/state.txt"
  git -C "$repo" add state.txt
  git -C "$repo" commit -m "$text" >/dev/null
}

run_tag() {
  local repo="$1"
  local tag="$2"
  local sha="$3"
  local version="$4"
  local main_ref="$5"
  (
    cd "$repo"
    "$tag_verifier" --tag "$tag" --sha "$sha" --version "$version" \
      --main-ref "$main_ref"
  )
}

expect_tag_pass() {
  local label="$1"
  local repo="$2"
  local tag="$3"
  local sha="$4"
  local version="$5"
  local main_ref="$6"
  local log="$test_root/logs/$label"
  trace_test "$label"
  run_tag "$repo" "$tag" "$sha" "$version" "$main_ref" >"$log" 2>&1 || fail_test
  grep -Fx "release tag verification OK" "$log" >/dev/null || fail_test
}

expect_tag_fail() {
  local label="$1"
  local repo="$2"
  local tag="$3"
  local sha="$4"
  local version="$5"
  local main_ref="$6"
  local log="$test_root/logs/$label"
  trace_test "$label"
  if run_tag "$repo" "$tag" "$sha" "$version" "$main_ref" >"$log" 2>&1; then
    fail_test
  fi
  [[ "$(wc -l <"$log" | tr -d '[:space:]')" == "1" ]] || fail_test
  grep -Fx "release tag verification failed" "$log" >/dev/null || fail_test
}

test_root="$(mktemp -d /tmp/maverick-release-gates.XXXXXX 2>/dev/null)" || fail_test
[[ -d "$test_root" && ! -L "$test_root" ]] || fail_test
chmod 0700 "$test_root"
mkdir "$test_root/artifacts" "$test_root/logs" "$test_root/repos"

host_os="$(uname -s)"
host_cpu="$(uname -m)"
case "$host_os:$host_cpu" in
  Darwin:arm64) native_target="aarch64-apple-darwin" ;;
  Linux:x86_64) native_target="x86_64-unknown-linux-gnu" ;;
  *) fail_test ;;
esac

native_binary="$test_root/native-maverick"
compile_fixture_binary "$native_binary" 0 ""

new_artifact_case positive
expect_artifact_pass positive-static "$current_archive" "$current_target" static
expect_artifact_pass positive-native "$current_archive" "$current_target" native

new_artifact_case gnu-zero-device-fields
raw_tar="$current_case/archive.tar"
unpack_raw_tar "$current_archive" "$raw_tar"
zero_device_fields "$raw_tar"
repack_raw_tar "$raw_tar" "$current_archive"
expect_artifact_pass gnu-zero-device-fields "$current_archive" "$current_target" \
  static

new_artifact_case outer-hash
printf '%064d  %s\n' 0 "${current_archive##*/}" >"$current_archive.sha256"
expect_artifact_fail outer-hash "$current_archive" "$current_target" static

new_artifact_case outer-format
printf '%s *%s\n' "$(sha256_file "$current_archive")" "${current_archive##*/}" \
  >"$current_archive.sha256"
expect_artifact_fail outer-format "$current_archive" "$current_target" static

new_artifact_case outer-trailing
printf '%s' "TRAILING_NO_LF" >>"$current_archive.sha256"
expect_artifact_fail outer-trailing "$current_archive" "$current_target" static

new_artifact_case basename
bad_basename="$current_case/not-the-approved-name.tar.gz"
cp "$current_archive" "$bad_basename"
write_outer_checksum "$bad_basename"
expect_artifact_fail basename "$bad_basename" "$current_target" static

archive_symlink_case="$test_root/artifacts/archive-symlink"
mkdir "$archive_symlink_case"
archive_symlink="$archive_symlink_case/maverick-${TEST_VERSION}-pilot-${native_target}.tar.gz"
ln -s "$current_archive" "$archive_symlink"
write_outer_checksum "$archive_symlink"
expect_artifact_fail archive-symlink "$archive_symlink" "$native_target" static

checksum_symlink_case="$test_root/artifacts/checksum-symlink"
mkdir "$checksum_symlink_case"
checksum_symlink="$checksum_symlink_case/maverick-${TEST_VERSION}-pilot-${native_target}.tar.gz"
cp "$current_archive" "$checksum_symlink"
ln -s "$current_archive.sha256" "$checksum_symlink.sha256"
expect_artifact_fail checksum-symlink "$checksum_symlink" "$native_target" static

for source_case in revision version target repository dirty extra-line; do
  new_artifact_case "source-$source_case"
  source_file="$current_case/payload/maverick-pilot/SOURCE.txt"
  case "$source_case" in
    revision) sed 's/^git_revision:.*/git_revision: 2222222222222222222222222222222222222222/' "$source_file" >"$source_file.new" ;;
    version) sed 's/^version:.*/version: 1.2.0-beta.3/' "$source_file" >"$source_file.new" ;;
    target) sed 's/^target:.*/target: x86_64-unknown-linux-gnu-extra/' "$source_file" >"$source_file.new" ;;
    repository) sed 's#^repository:.*#repository: https://example.invalid/repository#' "$source_file" >"$source_file.new" ;;
    dirty) sed 's/^source_state:.*/source_state: dirty/' "$source_file" >"$source_file.new" ;;
    extra-line)
      cp "$source_file" "$source_file.new"
      printf '%s\n' "extra: rejected" >>"$source_file.new"
      ;;
  esac
  mv "$source_file.new" "$source_file"
  refresh_inner_checksums "$current_case/payload/maverick-pilot"
  pack_payload "$current_case/payload" "$current_archive"
  expect_artifact_fail "source-$source_case" "$current_archive" "$current_target" static
done

for inner_case in missing duplicate wrong trailing; do
  new_artifact_case "inner-$inner_case"
  inner_file="$current_case/payload/maverick-pilot/SHA256SUMS"
  case "$inner_case" in
    missing) sed '$d' "$inner_file" >"$inner_file.new" ;;
    duplicate)
      cp "$inner_file" "$inner_file.new"
      sed -n '1p' "$inner_file" >>"$inner_file.new"
      ;;
    wrong) sed '1s/^[0-9a-f][0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/' "$inner_file" >"$inner_file.new" ;;
    trailing)
      cp "$inner_file" "$inner_file.new"
      printf '%s' "TRAILING_NO_LF" >>"$inner_file.new"
      ;;
  esac
  mv "$inner_file.new" "$inner_file"
  pack_payload "$current_case/payload" "$current_archive"
  expect_artifact_fail "inner-$inner_case" "$current_archive" "$current_target" static
done

new_artifact_case extra-member
printf '%s\n' extra >"$current_case/payload/maverick-pilot/EXTRA"
pack_payload "$current_case/payload" "$current_archive" "maverick-pilot/EXTRA"
expect_artifact_fail extra-member "$current_archive" "$current_target" static

new_artifact_case duplicate-member
pack_payload "$current_case/payload" "$current_archive" "maverick-pilot/VERSION.txt"
expect_artifact_fail duplicate-member "$current_archive" "$current_target" static

new_artifact_case symlink-member
find "$current_case/payload/maverick-pilot" -maxdepth 1 -type f -name VERSION.txt \
  -delete
ln -s SOURCE.txt "$current_case/payload/maverick-pilot/VERSION.txt"
pack_payload "$current_case/payload" "$current_archive"
expect_artifact_fail symlink-member "$current_archive" "$current_target" static

for mode_case in wrong-mode setuid; do
  new_artifact_case "$mode_case"
  if [[ "$mode_case" == "wrong-mode" ]]; then
    chmod 0700 "$current_case/payload/maverick-pilot/maverick"
  else
    chmod 4755 "$current_case/payload/maverick-pilot/maverick"
  fi
  pack_payload "$current_case/payload" "$current_archive"
  expect_artifact_fail "$mode_case" "$current_archive" "$current_target" static
done

for raw_case in traversal absolute uid gid uname gname magic ustar-version checksum devmajor devminor mtime header-pad padding second-end tail-after-end; do
  new_artifact_case "raw-$raw_case"
  raw_tar="$current_case/archive.tar"
  unpack_raw_tar "$current_archive" "$raw_tar"
  case "$raw_case" in
    traversal) patch_root_name "$raw_tar" "../escape/" ;;
    absolute) patch_root_name "$raw_tar" "/absolute/" ;;
    uid) patch_root_octal "$raw_tar" 108 1 ;;
    gid) patch_root_octal "$raw_tar" 116 1 ;;
    uname)
      zero_region "$raw_tar" 265 32
      write_region "$raw_tar" 265 "$TEST_MARKER"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    gname)
      zero_region "$raw_tar" 297 32
      write_region "$raw_tar" 297 "$TEST_MARKER"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    magic)
      zero_region "$raw_tar" 257 6
      write_region "$raw_tar" 257 "broken"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    ustar-version)
      write_region "$raw_tar" 263 "99"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    checksum)
      checksum_digit="$(
        dd if="$raw_tar" bs=1 skip=153 count=1 2>/dev/null
      )" || fail_test
      if [[ "$checksum_digit" == "0" ]]; then
        write_region "$raw_tar" 153 "1"
      else
        write_region "$raw_tar" 153 "0"
      fi
      raw_octal_value "$raw_tar" 148 8 >/dev/null
      ;;
    devmajor)
      write_region "$raw_tar" 329 "1"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    devminor)
      write_region "$raw_tar" 337 "1"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    mtime)
      write_region "$raw_tar" 136 "9"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    header-pad)
      write_region "$raw_tar" 500 "X"
      rewrite_header_checksum "$raw_tar" 0
      ;;
    padding)
      padding_offset="$(first_padding_offset "$raw_tar")"
      write_region "$raw_tar" "$padding_offset" "X"
      ;;
    second-end)
      end_block="$(first_zero_block "$raw_tar")"
      write_region "$raw_tar" $(((end_block + 1) * 512)) "X"
      ;;
    tail-after-end)
      end_block="$(first_zero_block "$raw_tar")"
      tail_offset=$(((end_block + 2) * 512))
      raw_tar_bytes="$(wc -c <"$raw_tar" | tr -d '[:space:]')"
      if [[ "$tail_offset" -ge "$raw_tar_bytes" ]]; then
        dd if=/dev/zero bs=512 count=1 >>"$raw_tar" 2>/dev/null || fail_test
      fi
      write_region "$raw_tar" "$tail_offset" "X"
      ;;
  esac
  repack_raw_tar "$raw_tar" "$current_archive"
  if [[ "$raw_case" == "uname" || "$raw_case" == "gname" ]]; then
    expect_artifact_fail "raw-$raw_case" "$current_archive" "$current_target" \
      static "$TEST_MARKER"
  else
    expect_artifact_fail "raw-$raw_case" "$current_archive" "$current_target" static
  fi
done

oversize_case="$test_root/artifacts/oversize"
mkdir "$oversize_case"
oversize_archive="$oversize_case/maverick-${TEST_VERSION}-pilot-${native_target}.tar.gz"
dd if=/dev/zero of="$oversize_archive" bs=1 count=0 seek=67108865 \
  >/dev/null 2>&1 || fail_test
printf '%064d  %s\n' 0 "${oversize_archive##*/}" >"$oversize_archive.sha256"
expect_artifact_fail oversize-input "$oversize_archive" "$native_target" static

for content_case in license guide version; do
  new_artifact_case "content-$content_case"
  if [[ "$content_case" == "license" ]]; then
    printf '%s\n' "Synthetic replacement license." \
      >"$current_case/payload/maverick-pilot/LICENSE"
  elif [[ "$content_case" == "guide" ]]; then
    printf '%s\n' "Synthetic replacement guide." \
      >"$current_case/payload/maverick-pilot/START_HERE.txt"
  else
    printf '%s\n' "maverick 1.2.0-beta.9" \
      >"$current_case/payload/maverick-pilot/VERSION.txt"
  fi
  refresh_inner_checksums "$current_case/payload/maverick-pilot"
  pack_payload "$current_case/payload" "$current_archive"
  expect_artifact_fail "content-$content_case" "$current_archive" \
    "$current_target" static
done

new_artifact_case privacy-tool-error
fake_grep_path="$test_root/fake-grep-path"
mkdir "$fake_grep_path"
cat >"$fake_grep_path/grep" <<'FAKE_GREP'
#!/usr/bin/env bash
printf '%s\n' "$MAVERICK_TEST_PRIVATE_MARKER" >&2
exit 2
FAKE_GREP
chmod 0755 "$fake_grep_path/grep"
trace_test privacy-tool-error
if MAVERICK_TEST_PRIVATE_MARKER="$TEST_MARKER" \
  PATH="$fake_grep_path:$PATH" \
  run_artifact "$current_archive" "$current_target" static \
  >"$test_root/logs/privacy-tool-error" 2>&1; then
  fail_test
fi
[[ "$(wc -l <"$test_root/logs/privacy-tool-error" | tr -d '[:space:]')" == "1" ]] ||
  fail_test
grep -Fx "pilot artifact verification failed" "$test_root/logs/privacy-tool-error" \
  >/dev/null || fail_test
! grep -F "$TEST_MARKER" "$test_root/logs/privacy-tool-error" \
  >/dev/null 2>&1 || fail_test

new_artifact_case input-mutated-during-verification
fake_strings_path="$test_root/fake-strings-path"
mkdir "$fake_strings_path"
cat >"$fake_strings_path/strings" <<'FAKE_STRINGS'
#!/usr/bin/env bash
if [[ ! -e "$MAVERICK_TEST_MUTATION_MARKER" ]]; then
  printf 'X' >>"$MAVERICK_TEST_ARCHIVE"
  : >"$MAVERICK_TEST_MUTATION_MARKER"
fi
exec "$MAVERICK_TEST_REAL_STRINGS" "$@"
FAKE_STRINGS
chmod 0755 "$fake_strings_path/strings"
trace_test input-mutated-during-verification
if MAVERICK_TEST_ARCHIVE="$current_archive" \
  MAVERICK_TEST_MUTATION_MARKER="$test_root/input-was-mutated" \
  MAVERICK_TEST_REAL_STRINGS="$(command -v strings)" \
  PATH="$fake_strings_path:$PATH" \
  run_artifact "$current_archive" "$current_target" static \
  >"$test_root/logs/input-mutated-during-verification" 2>&1; then
  fail_test
fi
grep -Fx "pilot artifact verification failed" \
  "$test_root/logs/input-mutated-during-verification" >/dev/null || fail_test

new_artifact_case wrong-architecture
printf '%s\n' "not a native binary" >"$current_case/payload/maverick-pilot/maverick"
chmod 0755 "$current_case/payload/maverick-pilot/maverick"
refresh_inner_checksums "$current_case/payload/maverick-pilot"
pack_payload "$current_case/payload" "$current_archive"
expect_artifact_fail wrong-architecture "$current_archive" "$current_target" static

synthetic_macho="$test_root/synthetic-macho"
printf '\317\372\355\376\014\000\000\001\000\000\000\000\002\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' \
  >"$synthetic_macho"
chmod 0755 "$synthetic_macho"
new_artifact_case synthetic-macho "$synthetic_macho" aarch64-apple-darwin
expect_artifact_pass synthetic-macho-static "$current_archive" "$current_target" static

synthetic_shared="$test_root/synthetic-shared.so"
printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\003\000\076\000\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\100\000\070\000\000\000\100\000\000\000\000\000' \
  >"$synthetic_shared"
chmod 0755 "$synthetic_shared"
new_artifact_case synthetic-shared-object "$synthetic_shared" x86_64-unknown-linux-gnu
fake_readelf_path="$test_root/fake-readelf-path"
mkdir "$fake_readelf_path"
cat >"$fake_readelf_path/readelf" <<'FAKE_READELF'
#!/usr/bin/env bash
cat <<'HEADER'
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
HEADER
FAKE_READELF
chmod 0755 "$fake_readelf_path/readelf"
trace_test synthetic-shared-object-rejected
if PATH="$fake_readelf_path:$PATH" run_artifact "$current_archive" \
  "$current_target" static >"$test_root/logs/synthetic-shared-object" 2>&1; then
  fail_test
fi
grep -Fx "pilot artifact verification failed" \
  "$test_root/logs/synthetic-shared-object" \
  >/dev/null || fail_test

private_binary="$test_root/private-binary"
compile_fixture_binary "$private_binary" 0 ""
printf '%s' "OPENAI_""API_KEY=$TEST_MARKER" >>"$private_binary"
chmod 0755 "$private_binary"
new_artifact_case private-binary "$private_binary"
expect_artifact_fail private-binary "$current_archive" "$current_target" static \
  "$TEST_MARKER"

execution_marker="$test_root/static-executed"
probe_binary="$test_root/probe-binary"
compile_fixture_binary "$probe_binary" 0 "$execution_marker"
new_artifact_case static-does-not-execute "$probe_binary"
expect_artifact_pass static-does-not-execute "$current_archive" "$current_target" static
[[ ! -e "$execution_marker" ]] || fail_test

fake_path="$test_root/fake-path"
mkdir "$fake_path"
cat >"$fake_path/uname" <<'FAKE_UNAME'
#!/usr/bin/env bash
case "${1:-}" in
  -s) echo "UnsupportedOS" ;;
  -m) echo "unsupported-cpu" ;;
  *) echo "UnsupportedOS" ;;
esac
FAKE_UNAME
chmod 0755 "$fake_path/uname"
if PATH="$fake_path:$PATH" run_artifact "$current_archive" "$current_target" native \
  >"$test_root/logs/host-mismatch" 2>&1; then
  fail_test
fi
grep -Fx "pilot artifact verification failed" "$test_root/logs/host-mismatch" \
  >/dev/null || fail_test
[[ ! -e "$execution_marker" ]] || fail_test

for native_case in version-mismatch smoke-failure mixed-smoke duplicate-pass timeout; do
  case "$native_case" in
    version-mismatch) fixture_mode=1 ;;
    smoke-failure) fixture_mode=2 ;;
    mixed-smoke) fixture_mode=4 ;;
    duplicate-pass) fixture_mode=5 ;;
    timeout) fixture_mode=3 ;;
  esac
  bad_binary="$test_root/$native_case-binary"
  compile_fixture_binary "$bad_binary" "$fixture_mode" ""
  new_artifact_case "native-$native_case" "$bad_binary"
  if [[ "$native_case" == "timeout" ]]; then
    expect_artifact_pass native-timeout-static "$current_archive" \
      "$current_target" static
    timeout_started="$(date +%s)"
  fi
  expect_artifact_fail "native-$native_case" "$current_archive" "$current_target" native
  if [[ "$native_case" == "timeout" ]]; then
    timeout_elapsed=$(($(date +%s) - timeout_started))
    [[ "$timeout_elapsed" -lt 20 ]] || fail_test
  fi
done

native_mutation_case="$test_root/artifacts/native-input-mutated"
native_mutation_archive="$native_mutation_case/maverick-${TEST_VERSION}-pilot-${native_target}.tar.gz"
native_mutation_binary="$test_root/native-input-mutated-binary"
compile_fixture_binary "$native_mutation_binary" 6 "$native_mutation_archive"
new_artifact_case native-input-mutated "$native_mutation_binary"
[[ "$current_archive" == "$native_mutation_archive" ]] || fail_test
expect_artifact_pass native-input-mutated-static "$current_archive" \
  "$current_target" static
expect_artifact_fail native-input-mutated "$current_archive" "$current_target" native

tag_repo="$test_root/repos/tag"
git init -q -b main "$tag_repo"
git -C "$tag_repo" config user.name "Release Gate Fixture"
git -C "$tag_repo" config user.email "fixture"
git_commit_fixture "$tag_repo" one
first_commit="$(git -C "$tag_repo" rev-parse HEAD)"
git_commit_fixture "$tag_repo" two
second_commit="$(git -C "$tag_repo" rev-parse HEAD)"

git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "annotated fixture" "$second_commit"
expect_tag_pass annotated-main "$tag_repo" "v$TEST_VERSION" "$second_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" checkout -q --detach "$first_commit"
git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "earlier fixture" "$first_commit"
expect_tag_pass earlier-main "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag "v$TEST_VERSION" "$first_commit"
expect_tag_fail lightweight "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a base-annotated -m "base tag" "$first_commit"
base_tag_object="$(git -C "$tag_repo" rev-parse refs/tags/base-annotated)"
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "tag of tag" "$base_tag_object" \
  >/dev/null 2>&1
expect_tag_fail tag-of-tag "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "annotated fixture" "$first_commit"
expect_tag_fail version-mismatch "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "1.2.0-beta.3" main
expect_tag_fail head-sha-mismatch "$tag_repo" "v$TEST_VERSION" "$second_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "other target" "$second_commit"
expect_tag_fail tag-target-mismatch "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "$TEST_VERSION" main

git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "annotated fixture" "$first_commit"
expect_tag_fail missing-main "$tag_repo" "v$TEST_VERSION" "$first_commit" \
  "$TEST_VERSION" missing-main
expect_tag_fail missing-tag "$tag_repo" "v1.2.0-beta.9" "$first_commit" \
  "1.2.0-beta.9" main

git -C "$tag_repo" checkout -q main
git -C "$tag_repo" checkout -q -b side "$first_commit"
git_commit_fixture "$tag_repo" side
side_commit="$(git -C "$tag_repo" rev-parse HEAD)"
git -C "$tag_repo" tag -d "v$TEST_VERSION" >/dev/null
git -C "$tag_repo" tag -a "v$TEST_VERSION" -m "side fixture" "$side_commit"
expect_tag_fail unmerged-side "$tag_repo" "v$TEST_VERSION" "$side_commit" \
  "$TEST_VERSION" main

shallow_repo="$test_root/repos/shallow"
git init -q -b main "$shallow_repo"
git -C "$shallow_repo" config user.name "Release Gate Fixture"
git -C "$shallow_repo" config user.email "fixture"
git_commit_fixture "$shallow_repo" tagged
shallow_tagged_commit="$(git -C "$shallow_repo" rev-parse HEAD)"
git_commit_fixture "$shallow_repo" main-tip
shallow_main_commit="$(git -C "$shallow_repo" rev-parse HEAD)"
git -C "$shallow_repo" tag -a "v$TEST_VERSION" -m "shallow fixture" \
  "$shallow_tagged_commit"
git -C "$shallow_repo" checkout -q --detach "$shallow_tagged_commit"
printf '%s\n' "$shallow_main_commit" >"$shallow_repo/.git/shallow"
[[ "$(git -C "$shallow_repo" rev-parse HEAD)" == "$shallow_tagged_commit" ]] ||
  fail_test
[[ "$(git -C "$shallow_repo" cat-file -t "refs/tags/v$TEST_VERSION")" == "tag" ]] ||
  fail_test
[[ "$(git -C "$shallow_repo" rev-parse "refs/tags/v$TEST_VERSION^{}")" == \
  "$shallow_tagged_commit" ]] || fail_test
[[ "$(git -C "$shallow_repo" rev-parse main)" == "$shallow_main_commit" ]] ||
  fail_test
if git -C "$shallow_repo" merge-base --is-ancestor \
  "$shallow_tagged_commit" "$shallow_main_commit" >/dev/null 2>&1; then
  fail_test
fi
expect_tag_fail missing-history "$shallow_repo" "v$TEST_VERSION" \
  "$shallow_tagged_commit" \
  "$TEST_VERSION" main

echo "release gate tests OK"
