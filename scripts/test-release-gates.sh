#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_verifier="$repo_root/scripts/verify-pilot-artifact.sh"
tag_verifier="$repo_root/scripts/verify-release-tag.sh"
test_root=""

readonly TEST_VERSION="1.2.0-beta.2"
readonly TEST_BETA_ONE_VERSION="1.2.0-beta.1"
readonly TEST_RC_VERSION="1.2.0-rc.1"
readonly TEST_BETA_MULTIDIGIT_VERSION="1.2.0-beta.10"
readonly TEST_RC_MULTIDIGIT_VERSION="1.2.0-rc.10"
readonly TEST_RELEASE_NOTE_VERSION="1.2.0-beta.3"
readonly TEST_REVISION="1111111111111111111111111111111111111111"
readonly TEST_MARKER="SYNTH_PRIVATE_MARKER_DO_NOT_ECHO"
readonly FEATURES_LINE="features: tls13,h2,browser-tls-default,cdn-fronted-h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,user-smoke"
readonly PILOT_RELEASE_WORKFLOW_SHA256="cf60b57afe553b6a23404853def0a0824f4a985808bc52139113cbdec6f122b7"
readonly PILOT_RELEASE_PUBLISH_STEP_SHA256="e5578640dc3066f3e18fc33f9a628cedd8fd1440a1805bef679f76e61c03280c"

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

make_isolated_elf_tool_path() {
  local destination="$1"
  local tool
  local tool_path
  mkdir "$destination"
  for tool in awk bash chmod cmp cp dd dirname find gzip grep head mkdir mktemp \
    od strings tar tr wc; do
    tool_path="$(command -v "$tool")" || fail_test
    ln -s "$tool_path" "$destination/$tool" || fail_test
  done
  if command -v shasum >/dev/null 2>&1; then
    tool_path="$(command -v shasum)" || fail_test
    ln -s "$tool_path" "$destination/shasum" || fail_test
  elif command -v sha256sum >/dev/null 2>&1; then
    tool_path="$(command -v sha256sum)" || fail_test
    ln -s "$tool_path" "$destination/sha256sum" || fail_test
  else
    fail_test
  fi
}

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
  local version="${4:-$TEST_VERSION}"
  local source="$test_root/fixture-$mode.c"
  command -v cc >/dev/null 2>&1 || fail_test
  {
    echo '#include <stdio.h>'
    echo '#include <string.h>'
    echo '#include <unistd.h>'
    printf '%s\n' "#define FIXTURE_MODE $mode"
    printf '%s\n' "#define MARKER_PATH \"$marker_path\""
    printf '%s\n' "#define FIXTURE_VERSION \"$version\""
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
    printf("maverick %s\n", FIXTURE_VERSION);
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
  local version="${4:-$TEST_VERSION}"
  local root="$payload_parent/maverick-pilot"
  mkdir -p "$root"
  chmod 0755 "$root"
  cp "$repo_root/LICENSE" "$root/LICENSE"
  printf '%s\n' \
    "repository: https://github.com/ilhaformosa/maverick" \
    "git_revision: $TEST_REVISION" \
    "source_state: clean" \
    "version: $version" \
    "target: $target" >"$root/SOURCE.txt"
  sed -n "/^cat >.*START_HERE\\.txt.*<<'GUIDE'$/,/^GUIDE$/p" \
    "$repo_root/scripts/build-pilot.sh" |
    sed '1d;$d' >"$root/START_HERE.txt"
  printf '%s\n' \
    "maverick $version" \
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
  local version="${4:-$TEST_VERSION}"
  current_case="$test_root/artifacts/$name"
  current_archive="$current_case/maverick-${version}-pilot-${target}.tar.gz"
  current_target="$target"
  mkdir -p "$current_case/payload"
  make_payload "$current_case/payload" "$binary" "$target" "$version"
  pack_payload "$current_case/payload" "$current_archive"
}

run_artifact() {
  local archive="$1"
  local target="$2"
  local level="$3"
  local version="${4:-$TEST_VERSION}"
  "$artifact_verifier" \
    --archive "$archive" \
    --expected-version "$version" \
    --expected-revision "$TEST_REVISION" \
    --expected-target "$target" \
    --verification-level "$level"
}

expect_artifact_pass() {
  local label="$1"
  local archive="$2"
  local target="$3"
  local level="$4"
  local version="${5:-$TEST_VERSION}"
  local log="$test_root/logs/$label"
  trace_test "$label"
  run_artifact "$archive" "$target" "$level" "$version" >"$log" 2>&1 ||
    fail_test
  grep -Fx "pilot artifact $level verification OK" "$log" >/dev/null || fail_test
}

expect_artifact_fail() {
  local label="$1"
  local archive="$2"
  local target="$3"
  local level="$4"
  local hidden="${5:-}"
  local version="${6:-$TEST_VERSION}"
  local log="$test_root/logs/$label"
  trace_test "$label"
  if run_artifact "$archive" "$target" "$level" "$version" >"$log" 2>&1; then
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

run_release_note() {
  local fixture_root="$1"
  local snapshot_dir="$fixture_root/private-snapshot"
  local snapshot_path="$snapshot_dir/release-notes.md"
  local snapshot_sha
  (
    cd "$fixture_root"
    mkdir "$snapshot_dir"
    chmod 0700 "$snapshot_dir"
    if snapshot_release_note \
      "docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md" \
      "$TEST_RELEASE_NOTE_VERSION" \
      "$snapshot_path" &&
      chmod 0444 "$snapshot_path" &&
      verify_release_note "$snapshot_path" "$TEST_RELEASE_NOTE_VERSION" &&
      snapshot_sha="$(release_note_sha256 "$snapshot_path")" &&
      release_note_digest_matches "$snapshot_path" "$snapshot_sha"; then
      echo "release note verification OK"
    else
      echo "release note verification failed" >&2
      return 1
    fi
  )
}

expect_release_note_pass() {
  local label="$1"
  local fixture_root="$2"
  local log="$test_root/logs/$label"
  trace_test "$label"
  run_release_note "$fixture_root" >"$log" 2>&1 || fail_test
  grep -Fx "release note verification OK" "$log" >/dev/null || fail_test
}

expect_release_note_fail() {
  local label="$1"
  local fixture_root="$2"
  local hidden="${3:-}"
  local log="$test_root/logs/$label"
  trace_test "$label"
  if run_release_note "$fixture_root" >"$log" 2>&1; then
    fail_test
  fi
  [[ "$(wc -l <"$log" | tr -d '[:space:]')" == "1" ]] || fail_test
  grep -Fx "release note verification failed" "$log" >/dev/null || fail_test
  if [[ -n "$hidden" ]]; then
    ! grep -F "$hidden" "$log" >/dev/null 2>&1 || fail_test
  fi
}

extract_release_note_function() {
  local function_name="$1"
  local destination="$2"
  local function_block
  function_block="$(
    sed -n "/^          ${function_name}() {$/,/^          }$/p" \
      "$release_workflow"
  )"
  [[ -n "$function_block" ]] || fail_test
  printf '%s\n' "$function_block" | sed 's/^          //' >>"$destination"
}

exact_line_in() {
  local file="$1"
  local pattern="$2"
  local matches
  local line
  matches="$(grep -Fnx -- "$pattern" "$file")" || fail_test
  [[ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d '[:space:]')" -eq 1 ]] ||
    fail_test
  line="${matches%%:*}"
  [[ "$line" =~ ^[0-9]+$ ]] || fail_test
  printf '%s\n' "$line"
}

insert_line_after() {
  local source="$1"
  local destination="$2"
  local anchor="$3"
  local inserted="$4"
  awk -v anchor="$anchor" -v inserted="$inserted" '
    { print }
    $0 == anchor { print inserted; matches++ }
    END { if (matches != 1) exit 1 }
  ' "$source" >"$destination" || fail_test
}

insert_line_before() {
  local source="$1"
  local destination="$2"
  local anchor="$3"
  local inserted="$4"
  awk -v anchor="$anchor" -v inserted="$inserted" '
    $0 == anchor { print inserted; matches++ }
    { print }
    END { if (matches != 1) exit 1 }
  ' "$source" >"$destination" || fail_test
}

workflow_contract_matches() {
  [[ "$(sha256_file "$1")" == "$PILOT_RELEASE_WORKFLOW_SHA256" ]]
}

publish_step_contract_matches() {
  [[ "$(sha256_file "$1")" == "$PILOT_RELEASE_PUBLISH_STEP_SHA256" ]]
}

test_root="$(mktemp -d /tmp/maverick-release-gates.XXXXXX 2>/dev/null)" || fail_test
[[ -d "$test_root" && ! -L "$test_root" ]] || fail_test
chmod 0700 "$test_root"
mkdir "$test_root/artifacts" "$test_root/logs" "$test_root/repos"

release_workflow="$repo_root/.github/workflows/pilot-release.yml"
release_note_verifier="$test_root/verify-release-note.sh"
: >"$release_note_verifier"
for function_name in \
  snapshot_release_note verify_release_note release_note_sha256 \
  release_note_digest_matches; do
  extract_release_note_function "$function_name" "$release_note_verifier"
done
[[ -s "$release_note_verifier" ]] || fail_test
# shellcheck source=/dev/null
source "$release_note_verifier"
for function_name in \
  snapshot_release_note verify_release_note release_note_sha256 \
  release_note_digest_matches; do
  type "$function_name" >/dev/null 2>&1 || fail_test
done
grep -F "notes_source=\"docs/releases/v\${version}.md\"" "$release_workflow" \
  >/dev/null || fail_test
snapshot_call_pattern="snapshot_release_note \"\$notes_source\" \"\$version\" \"\$notes_file\""
verification_call_pattern="verify_release_note \"\$notes_file\" \"\$version\""
digest_call_pattern="notes_sha=\"\$(release_note_sha256 \"\$notes_file\")\""
publish_step_pattern='      - name: Recheck remote gates and publish the reverified prerelease'
release_create_pattern="          exec gh release create \"\$GITHUB_REF_NAME\" \\"
notes_file_pattern="            --notes-file \"\$NOTES_FILE\""
snapshot_call_line="$(
  grep -Fn "$snapshot_call_pattern" "$release_workflow" | cut -d: -f1
)"
verification_call_line="$(
  grep -Fn "$verification_call_pattern" "$release_workflow" | cut -d: -f1
)"
digest_call_line="$(
  grep -Fn "$digest_call_pattern" "$release_workflow" | cut -d: -f1
)"
publish_step_line="$(exact_line_in "$release_workflow" "$publish_step_pattern")"
release_create_line="$(exact_line_in "$release_workflow" "$release_create_pattern")"
notes_file_line="$(exact_line_in "$release_workflow" "$notes_file_pattern")"
[[ "$snapshot_call_line" =~ ^[0-9]+$ ]] || fail_test
[[ "$verification_call_line" =~ ^[0-9]+$ ]] || fail_test
[[ "$digest_call_line" =~ ^[0-9]+$ ]] || fail_test
[[ "$snapshot_call_line" -lt "$verification_call_line" ]] || fail_test
[[ "$verification_call_line" -lt "$digest_call_line" ]] || fail_test
[[ "$publish_step_line" -lt "$release_create_line" ]] || fail_test
[[ "$release_create_line" -lt "$notes_file_line" ]] || fail_test
workflow_contract_matches "$release_workflow" || fail_test
publish_block="$test_root/publish-workflow-block"
sed -n "${publish_step_line},\$p" "$release_workflow" >"$publish_block"
[[ -s "$publish_block" ]] || fail_test
publish_step_contract_matches "$publish_block" || fail_test
publish_file_set_line="$(
  exact_line_in "$publish_block" \
    "          test \"\$actual_files\" = \"\$expected_files\""
)"
publish_file_count_line="$(
  exact_line_in "$publish_block" \
    "          test \"\$(find \"\$STAGING\" -mindepth 1 -maxdepth 1 -print | wc -l)\" -eq 6"
)"
publish_fetch_line="$(
  exact_line_in "$publish_block" \
    "          git fetch --no-tags --force --atomic origin \\"
)"
publish_tag_line="$(
  exact_line_in "$publish_block" \
    "          ./scripts/verify-release-tag.sh \\"
)"
notes_guard_pattern="          if ! release_note_digest_matches \"\$NOTES_FILE\" \"\$NOTES_SHA\"; then"
notes_guard_line="$(exact_line_in "$release_workflow" "$notes_guard_pattern")"
publish_notes_guard_line="$(exact_line_in "$publish_block" "$notes_guard_pattern")"
publish_create_line="$(exact_line_in "$publish_block" "$release_create_pattern")"
[[ "$publish_file_set_line" -lt "$publish_file_count_line" ]] || fail_test
[[ "$publish_file_count_line" -lt "$publish_fetch_line" ]] || fail_test
[[ "$publish_fetch_line" -lt "$publish_tag_line" ]] || fail_test
[[ "$publish_tag_line" -lt "$publish_notes_guard_line" ]] || fail_test
[[ "$publish_notes_guard_line" -lt "$publish_create_line" ]] || fail_test
[[ "$notes_guard_line" -lt "$release_create_line" ]] || fail_test
actual_release_command="$(
  sed -n "${notes_guard_line},${notes_file_line}p" "$release_workflow"
)"
# The following single-quoted block is the literal workflow command contract.
# shellcheck disable=SC2016
expected_release_command='          if ! release_note_digest_matches "$NOTES_FILE" "$NOTES_SHA"; then
            echo "release note verification failed" >&2
            exit 1
          fi
          exec gh release create "$GITHUB_REF_NAME" \
            "$STAGING/$LINUX_NAME" \
            "$STAGING/$LINUX_NAME.sha256" \
            "$STAGING/$LINUX_SBOM_NAME" \
            "$STAGING/$MAC_NAME" \
            "$STAGING/$MAC_NAME.sha256" \
            "$STAGING/$MAC_SBOM_NAME" \
            --repo "$GITHUB_REPOSITORY" \
            --verify-tag \
            --prerelease \
            --latest=false \
            --title "Maverick $GITHUB_REF_NAME" \
            --notes-file "$NOTES_FILE"'
[[ "$actual_release_command" == "$expected_release_command" ]] || fail_test
[[ "$(grep -Fc "gh release create" "$release_workflow")" -eq 1 ]] ||
  fail_test
[[ "$(grep -Fc -- "--prerelease" "$release_workflow")" -eq 1 ]] ||
  fail_test
[[ "$(grep -Fc -- "--latest" "$release_workflow")" -eq 1 ]] ||
  fail_test
[[ "$(grep -Ec -- '(^|[[:space:]])gh([[:space:]]|$)' "$release_workflow")" -eq 1 ]] ||
  fail_test
release_command_block="$test_root/release-command-block"
printf '%s\n' "$actual_release_command" >"$release_command_block"
[[ "$(grep -Ec -- '(^|[[:space:]])--verify-tag(=|[[:space:]]|$)' "$release_command_block")" -eq 1 ]] ||
  fail_test
[[ "$(grep -Ec -- '(^|[[:space:]])--prerelease(=|[[:space:]]|$)' "$release_command_block")" -eq 1 ]] ||
  fail_test
[[ "$(grep -Ec -- '(^|[[:space:]])--latest(=|[[:space:]]|$)' "$release_command_block")" -eq 1 ]] ||
  fail_test

trace_test workflow-hash-rejects-errexit-disable
errexit_mutation="$test_root/pilot-release-errexit-disabled.yml"
insert_line_before "$publish_block" "$errexit_mutation" \
  "          expected_files=\"\$(" "          set +e"
if publish_step_contract_matches "$errexit_mutation"; then
  fail_test
fi

trace_test workflow-hash-rejects-asset-rebinding
asset_mutation="$test_root/pilot-release-asset-rebound.yml"
insert_line_after "$publish_block" "$asset_mutation" \
  "            --main-ref origin/main" "          MAC_NAME=\"\$LINUX_NAME\""
if publish_step_contract_matches "$asset_mutation"; then
  fail_test
fi

release_notes_root="$test_root/release-notes"
mkdir "$release_notes_root"
valid_root="$release_notes_root/valid"
mkdir -p "$valid_root/docs/releases"
valid_note="$valid_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
printf '%s\n' \
  "# Maverick v$TEST_RELEASE_NOTE_VERSION" \
  "" \
  "A public, version-specific Beta release note." >"$valid_note"
expect_release_note_pass release-note-valid "$valid_root"

missing_root="$release_notes_root/missing"
mkdir -p "$missing_root/docs/releases"
expect_release_note_fail release-note-missing "$missing_root"

symlink_root="$release_notes_root/symlink"
mkdir -p "$symlink_root/docs/releases"
symlink_note="$symlink_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
ln -s "$valid_note" "$symlink_note"
expect_release_note_fail release-note-symlink "$symlink_root"

oversized_root="$release_notes_root/oversized"
mkdir -p "$oversized_root/docs/releases"
oversized_note="$oversized_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
printf '# Maverick v%s\n\n' "$TEST_RELEASE_NOTE_VERSION" >"$oversized_note"
dd if=/dev/zero bs=1 count=65537 2>/dev/null | tr '\000' a >>"$oversized_note"
expect_release_note_fail release-note-oversized "$oversized_root"

wrong_version_root="$release_notes_root/wrong-version"
mkdir -p "$wrong_version_root/docs/releases"
wrong_version_note="$wrong_version_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
printf '%s\n' "# Maverick v1.2.0-beta.9" >"$wrong_version_note"
expect_release_note_fail release-note-version-mismatch "$wrong_version_root"

control_root="$release_notes_root/control"
mkdir -p "$control_root/docs/releases"
control_note="$control_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
cp "$valid_note" "$control_note"
printf '\033' >>"$control_note"
expect_release_note_fail release-note-control-character "$control_root"

private_root="$release_notes_root/private"
mkdir -p "$private_root/docs/releases"
private_note="$private_root/docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
cp "$valid_note" "$private_note"
printf '%s\n' "/U""sers/$TEST_MARKER/build" >>"$private_note"
expect_release_note_fail release-note-private-text "$private_root" "$TEST_MARKER"

trace_test release-note-source-mutation-after-snapshot
source_mutation_root="$release_notes_root/source-mutation"
source_mutation_snapshot_dir="$source_mutation_root/private-snapshot"
source_mutation_source="docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
source_mutation_snapshot="$source_mutation_snapshot_dir/release-notes.md"
mkdir -p "$source_mutation_root/docs/releases" "$source_mutation_snapshot_dir"
chmod 0700 "$source_mutation_snapshot_dir"
cp "$valid_note" "$source_mutation_root/$source_mutation_source"
(
  cd "$source_mutation_root"
  snapshot_release_note \
    "$source_mutation_source" \
    "$TEST_RELEASE_NOTE_VERSION" \
    "$source_mutation_snapshot"
)
chmod 0444 "$source_mutation_snapshot"
verify_release_note "$source_mutation_snapshot" "$TEST_RELEASE_NOTE_VERSION"
source_mutation_sha="$(release_note_sha256 "$source_mutation_snapshot")"
cp "$source_mutation_snapshot" "$source_mutation_root/verified-bytes.md"
printf '%s\n' "changed after snapshot $TEST_MARKER" \
  >"$source_mutation_root/$source_mutation_source"
cmp -s "$source_mutation_snapshot" "$source_mutation_root/verified-bytes.md" ||
  fail_test
release_note_digest_matches "$source_mutation_snapshot" "$source_mutation_sha" ||
  fail_test

trace_test release-note-snapshot-mutation-before-publish
snapshot_mutation_root="$release_notes_root/snapshot-mutation"
snapshot_mutation_snapshot_dir="$snapshot_mutation_root/private-snapshot"
snapshot_mutation_source="docs/releases/v${TEST_RELEASE_NOTE_VERSION}.md"
snapshot_mutation_snapshot="$snapshot_mutation_snapshot_dir/release-notes.md"
mkdir -p "$snapshot_mutation_root/docs/releases" "$snapshot_mutation_snapshot_dir"
chmod 0700 "$snapshot_mutation_snapshot_dir"
cp "$valid_note" "$snapshot_mutation_root/$snapshot_mutation_source"
(
  cd "$snapshot_mutation_root"
  snapshot_release_note \
    "$snapshot_mutation_source" \
    "$TEST_RELEASE_NOTE_VERSION" \
    "$snapshot_mutation_snapshot"
)
chmod 0444 "$snapshot_mutation_snapshot"
verify_release_note "$snapshot_mutation_snapshot" "$TEST_RELEASE_NOTE_VERSION"
snapshot_mutation_sha="$(release_note_sha256 "$snapshot_mutation_snapshot")"
chmod 0644 "$snapshot_mutation_snapshot"
printf '%s\n' "changed after verification $TEST_MARKER" \
  >>"$snapshot_mutation_snapshot"
if release_note_digest_matches \
  "$snapshot_mutation_snapshot" "$snapshot_mutation_sha"; then
  fail_test
fi

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

for supported_version in \
  "$TEST_BETA_ONE_VERSION" "$TEST_BETA_MULTIDIGIT_VERSION" \
  "$TEST_RC_VERSION" "$TEST_RC_MULTIDIGIT_VERSION"; do
  supported_binary="$test_root/native-maverick-$supported_version"
  compile_fixture_binary "$supported_binary" 0 "" "$supported_version"
  new_artifact_case "supported-$supported_version" "$supported_binary" \
    "$native_target" "$supported_version"
  expect_artifact_pass "supported-$supported_version-static" \
    "$current_archive" "$current_target" static "$supported_version"
  if [[ "$supported_version" == "$TEST_RC_VERSION" ]]; then
    expect_artifact_pass "supported-$supported_version-native" \
      "$current_archive" "$current_target" native "$supported_version"
  fi
done

while IFS='|' read -r unsupported_label unsupported_version; do
  unsupported_binary="$test_root/unsupported-$unsupported_label-binary"
  compile_fixture_binary "$unsupported_binary" 0 "" "$unsupported_version"
  new_artifact_case "unsupported-$unsupported_label" "$unsupported_binary" \
    "$native_target" "$unsupported_version"
  expect_artifact_fail "unsupported-$unsupported_label" "$current_archive" \
    "$current_target" static "" "$unsupported_version"
done <<'UNSUPPORTED_ARTIFACT_VERSIONS'
stable|1.2.0
alpha|1.2.0-alpha.1
major|2.2.0-beta.1
minor|1.3.0-beta.1
patch|1.2.1-beta.1
beta-zero|1.2.0-beta.0
beta-leading-zero|1.2.0-beta.01
rc-zero|1.2.0-rc.0
rc-leading-zero|1.2.0-rc.01
UNSUPPORTED_ARTIFACT_VERSIONS

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
real_grep="$(command -v grep)" || fail_test
mkdir "$fake_grep_path"
cat >"$fake_grep_path/grep" <<'FAKE_GREP'
#!/usr/bin/env bash
for argument in "$@"; do
  if [[ "$argument" == "-i" ]]; then
    printf '%s\n' "$MAVERICK_TEST_PRIVATE_MARKER" >&2
    exit 2
  fi
done
exec "$MAVERICK_TEST_REAL_GREP" "$@"
FAKE_GREP
chmod 0755 "$fake_grep_path/grep"
printf '%s\n' "ELF64" |
  MAVERICK_TEST_REAL_GREP="$real_grep" \
    PATH="$fake_grep_path:$PATH" grep -Eq 'ELF64' || fail_test
trace_test privacy-tool-error
if MAVERICK_TEST_PRIVATE_MARKER="$TEST_MARKER" \
  MAVERICK_TEST_REAL_GREP="$real_grep" \
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

greadelf_tool_path="$test_root/greadelf-tool-path"
make_isolated_elf_tool_path "$greadelf_tool_path"
cat >"$greadelf_tool_path/file" <<'FAKE_FILE'
#!/usr/bin/env bash
: >"$MAVERICK_TEST_FILE_MARKER"
printf '%s\n' \
  "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked"
FAKE_FILE
cat >"$greadelf_tool_path/greadelf" <<'FAKE_GREADELF'
#!/usr/bin/env bash
: >"$MAVERICK_TEST_READELF_MARKER"
printf '%s\n' \
  "  Class:                             ELF64" \
  "  Data:                              2's complement, little endian" \
  "  Type:                              DYN (Position-Independent Executable file)" \
  "  Machine:                           Advanced Micro Devices X86-64"
FAKE_GREADELF
chmod 0755 "$greadelf_tool_path/file" "$greadelf_tool_path/greadelf"
new_artifact_case elf-tool-greadelf-fallback "$synthetic_shared" \
  x86_64-unknown-linux-gnu
greadelf_file_marker="$test_root/greadelf-file-called"
greadelf_marker="$test_root/greadelf-called"
trace_test elf-tool-greadelf-fallback
MAVERICK_TEST_FILE_MARKER="$greadelf_file_marker" \
  MAVERICK_TEST_READELF_MARKER="$greadelf_marker" \
  PATH="$greadelf_tool_path" \
  run_artifact "$current_archive" "$current_target" static \
  >"$test_root/logs/elf-tool-greadelf-fallback" 2>&1 || fail_test
grep -Fx "pilot artifact static verification OK" \
  "$test_root/logs/elf-tool-greadelf-fallback" >/dev/null || fail_test
[[ -f "$greadelf_file_marker" && -f "$greadelf_marker" ]] || fail_test

missing_elf_tool_path="$test_root/missing-elf-tool-path"
make_isolated_elf_tool_path "$missing_elf_tool_path"
cat >"$missing_elf_tool_path/file" <<'FAKE_FILE'
#!/usr/bin/env bash
: >"$MAVERICK_TEST_FILE_MARKER"
printf '%s\n' \
  "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked"
FAKE_FILE
chmod 0755 "$missing_elf_tool_path/file"
new_artifact_case elf-tool-missing "$synthetic_shared" x86_64-unknown-linux-gnu
missing_elf_file_marker="$test_root/missing-elf-file-called"
trace_test elf-tool-missing
if MAVERICK_TEST_FILE_MARKER="$missing_elf_file_marker" \
  PATH="$missing_elf_tool_path" \
  run_artifact "$current_archive" "$current_target" static \
  >"$test_root/logs/elf-tool-missing" 2>&1; then
  fail_test
fi
[[ -f "$missing_elf_file_marker" ]] || fail_test
[[ "$(wc -l <"$test_root/logs/elf-tool-missing" | tr -d '[:space:]')" == "1" ]] ||
  fail_test
grep -Fx \
  "pilot artifact verification failed: required tool not found (readelf or greadelf)" \
  "$test_root/logs/elf-tool-missing" >/dev/null || fail_test

private_binary="$test_root/private-binary"
compile_fixture_binary "$private_binary" 0 ""
printf '%s' "OPENAI_""API_KEY=$TEST_MARKER" >>"$private_binary"
chmod 0755 "$private_binary"
new_artifact_case private-binary "$private_binary"
expect_artifact_fail private-binary "$current_archive" "$current_target" static \
  "$TEST_MARKER"

file_uri_noise_binary="$test_root/file-uri-noise-binary"
compile_fixture_binary "$file_uri_noise_binary" 0 ""
printf '%s' "fi""le:///H" >>"$file_uri_noise_binary"
chmod 0755 "$file_uri_noise_binary"
new_artifact_case file-uri-noise "$file_uri_noise_binary"
expect_artifact_pass file-uri-noise "$current_archive" "$current_target" static

linker_file_uri_noise_binary="$test_root/linker-file-uri-noise-binary"
compile_fixture_binary "$linker_file_uri_noise_binary" 0 ""
printf '\0%s\0' "regular fi""le://Failed building..." \
  >>"$linker_file_uri_noise_binary"
chmod 0755 "$linker_file_uri_noise_binary"
new_artifact_case linker-file-uri-noise "$linker_file_uri_noise_binary"
expect_artifact_pass linker-file-uri-noise "$current_archive" "$current_target" \
  static

private_user_path_binary="$test_root/private-user-path-binary"
compile_fixture_binary "$private_user_path_binary" 0 ""
printf '%s' "/U""sers/$TEST_MARKER" >>"$private_user_path_binary"
chmod 0755 "$private_user_path_binary"
new_artifact_case private-user-path-binary "$private_user_path_binary"
expect_artifact_fail private-user-path-binary "$current_archive" "$current_target" static \
  "$TEST_MARKER"

private_home_path_binary="$test_root/private-home-path-binary"
compile_fixture_binary "$private_home_path_binary" 0 ""
printf '%s' "/ho""me/$TEST_MARKER" >>"$private_home_path_binary"
chmod 0755 "$private_home_path_binary"
new_artifact_case private-home-path-binary "$private_home_path_binary"
expect_artifact_fail private-home-path-binary "$current_archive" "$current_target" static \
  "$TEST_MARKER"

private_file_uri_binary="$test_root/private-file-uri-binary"
compile_fixture_binary "$private_file_uri_binary" 0 ""
printf '%s' "fi""le:///private/build/$TEST_MARKER" >>"$private_file_uri_binary"
chmod 0755 "$private_file_uri_binary"
new_artifact_case private-file-uri-binary "$private_file_uri_binary"
expect_artifact_fail private-file-uri-binary "$current_archive" "$current_target" static \
  "$TEST_MARKER"

private_authority_uri_binary="$test_root/private-authority-uri-binary"
compile_fixture_binary "$private_authority_uri_binary" 0 ""
printf '%s' "fi""le://private-host.invalid/share/$TEST_MARKER" \
  >>"$private_authority_uri_binary"
chmod 0755 "$private_authority_uri_binary"
new_artifact_case private-authority-uri-binary "$private_authority_uri_binary"
expect_artifact_fail private-authority-uri-binary "$current_archive" \
  "$current_target" static "$TEST_MARKER"

private_authority_root_uri_binary="$test_root/private-authority-root-uri-binary"
compile_fixture_binary "$private_authority_root_uri_binary" 0 ""
printf '%s' "fi""le://private-build-host/" \
  >>"$private_authority_root_uri_binary"
chmod 0755 "$private_authority_root_uri_binary"
new_artifact_case private-authority-root-uri-binary \
  "$private_authority_root_uri_binary"
expect_artifact_fail private-authority-root-uri-binary "$current_archive" \
  "$current_target" static "private-build-host"

private_bare_authority_uri_binary="$test_root/private-bare-authority-uri-binary"
compile_fixture_binary "$private_bare_authority_uri_binary" 0 ""
printf '\0%s\0' "fi""le://private-build-host" \
  >>"$private_bare_authority_uri_binary"
chmod 0755 "$private_bare_authority_uri_binary"
new_artifact_case private-bare-authority-uri-binary \
  "$private_bare_authority_uri_binary"
expect_artifact_fail private-bare-authority-uri-binary "$current_archive" \
  "$current_target" static "private-build-host"

maverick_secret_binary="$test_root/maverick-secret-binary"
compile_fixture_binary "$maverick_secret_binary" 0 ""
printf '%s' "mv""1_${TEST_MARKER}AAAAAAAAAAAAAAAAAAAA" >>"$maverick_secret_binary"
chmod 0755 "$maverick_secret_binary"
new_artifact_case maverick-secret-binary "$maverick_secret_binary"
expect_artifact_fail maverick-secret-binary "$current_archive" "$current_target" static \
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

git -C "$tag_repo" tag -a "v$TEST_RC_VERSION" -m "annotated RC fixture" \
  "$second_commit"
expect_tag_pass annotated-rc-main "$tag_repo" "v$TEST_RC_VERSION" \
  "$second_commit" "$TEST_RC_VERSION" main

for release_version in \
  "$TEST_BETA_MULTIDIGIT_VERSION" "$TEST_RC_MULTIDIGIT_VERSION"; do
  git -C "$tag_repo" tag -a "v$release_version" \
    -m "annotated multi-digit fixture" "$second_commit"
  expect_tag_pass "annotated-$release_version" "$tag_repo" \
    "v$release_version" "$second_commit" "$release_version" main
done

while IFS='|' read -r unsupported_label unsupported_version; do
  git -C "$tag_repo" tag -a "v$unsupported_version" \
    -m "unsupported release fixture" "$second_commit"
  expect_tag_fail "unsupported-$unsupported_label" "$tag_repo" \
    "v$unsupported_version" "$second_commit" "$unsupported_version" main
done <<'UNSUPPORTED_RELEASE_VERSIONS'
stable|1.2.0
alpha|1.2.0-alpha.1
major|2.2.0-beta.1
minor|1.3.0-beta.1
patch|1.2.1-beta.1
beta-zero|1.2.0-beta.0
beta-leading-zero|1.2.0-beta.01
rc-zero|1.2.0-rc.0
rc-leading-zero|1.2.0-rc.01
UNSUPPORTED_RELEASE_VERSIONS

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
