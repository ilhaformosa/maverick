#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

private_tmp=""
negative_checks=0

fail() {
  echo "CycloneDX SBOM focused tests failed" >&2
  exit 1
}

script_dir="$(dirname "${BASH_SOURCE[0]}" 2>/dev/null)" || fail
repo_root="$(
  cd "$script_dir/.." 2>/dev/null || exit 1
  pwd 2>/dev/null
)" || fail
generator="$repo_root/scripts/generate-cyclonedx-sbom.sh"
verifier="$repo_root/scripts/verify-cyclonedx-sbom.sh"
version="$(
  awk -F'"' '/^version =/ {print $2; exit}' "$repo_root/Cargo.toml" 2>/dev/null
)" || fail
revision="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)" || fail
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || fail
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail
linux_target="x86_64-unknown-linux-gnu"
mac_target="aarch64-apple-darwin"
max_sbom_bytes=8388608

cleanup() {
  case "$private_tmp" in
    /tmp/maverick-sbom-test.*)
      [[ ! -d "$private_tmp" ]] ||
        find "$private_tmp" -depth -delete >/dev/null 2>&1 || true
      ;;
  esac
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

measure_test_file() {
  {
    wc -c <"$1" |
      tr -d '[:space:]'
  } 2>/dev/null
}

write_revision_list() {
  local destination="$1"
  git -C "$repo_root" rev-list "$revision" >"$destination" 2>/dev/null
}

assert_literal_absent() {
  local literal="$1"
  local input_file="$2"
  local grep_status=0
  grep -Fq -- "$literal" "$input_file" 2>/dev/null || grep_status=$?
  case "$grep_status" in
    0) fail ;;
    1) ;;
    *) fail ;;
  esac
}

[[ -x "$generator" && -x "$verifier" ]] || fail
command -v jq >/dev/null 2>&1 || fail
bash -n "$generator" "$verifier" "$0" >/dev/null 2>&1 || fail

private_tmp="$(mktemp -d /tmp/maverick-sbom-test.XXXXXX 2>/dev/null)" || fail
chmod 0700 "$private_tmp" >/dev/null 2>&1 || fail

generate_one() {
  local target="$1"
  local output="$2"
  "$generator" \
    --expected-version "$version" \
    --expected-revision "$revision" \
    --target "$target" \
    --output "$output" >/dev/null
}

verify_one() {
  local sbom="$1"
  local target="$2"
  local level="$3"
  "$verifier" \
    --sbom "$sbom" \
    --expected-version "$version" \
    --expected-revision "$revision" \
    --expected-target "$target" \
    --verification-level "$level" \
    --source-root "$repo_root" >/dev/null
}

linux_name="maverick-${version}-pilot-${linux_target}.cdx.json"
mac_name="maverick-${version}-pilot-${mac_target}.cdx.json"
linux_first="$private_tmp/linux-first/$linux_name"
linux_second="$private_tmp/linux-second/$linux_name"
mac_first="$private_tmp/mac-first/$mac_name"
mac_second="$private_tmp/mac-second/$mac_name"
mkdir -m 0700 \
  "$private_tmp/linux-first" "$private_tmp/linux-second" \
  "$private_tmp/mac-first" "$private_tmp/mac-second"

expect_generator_failure() {
  local name="$1"
  local expected_stage="$2"
  shift 2
  local output_dir="$private_tmp/generator-$name"
  local output_path="$output_dir/$linux_name"
  local output_log="$private_tmp/generator-$name-output"
  local expected_log="$private_tmp/generator-$name-expected"
  mkdir -m 0700 "$output_dir"
  if env "$@" "$generator" \
    --expected-version "$version" \
    --expected-revision "$revision" \
    --target "$linux_target" \
    --output "$output_path" >"$output_log" 2>&1; then
    fail
  fi
  printf 'CycloneDX SBOM generation failed: %s\n' "$expected_stage" \
    >"$expected_log"
  cmp -s "$expected_log" "$output_log" || fail
  [[ ! -e "$output_path" && ! -L "$output_path" ]] || fail
  negative_checks=$((negative_checks + 1))
}

real_cyclonedx_bin="${CARGO_CYCLONEDX_BIN:-}"
if [[ -z "$real_cyclonedx_bin" ]]; then
  real_cyclonedx_bin="$(command -v cargo-cyclonedx 2>/dev/null || true)"
fi
[[ -x "$real_cyclonedx_bin" ]] || fail

mock_cargo_grep_dir="$private_tmp/mock-cargo-grep"
mkdir -m 0700 "$mock_cargo_grep_dir"
cargo_grep_sentinel="$private_tmp/cargo-grep-fired"
cargo_grep_segment="maverick-sbom-cargo-version-marker"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  ': >"${MOCK_GREP_SENTINEL:?}" || exit 43' \
  'private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  'printf "%s\n" "$private_marker" >&2' \
  'exit 42' >"$mock_cargo_grep_dir/grep"
chmod 0700 "$mock_cargo_grep_dir/grep"
expect_generator_failure cargo-version-grep-error environment \
  "PATH=$mock_cargo_grep_dir:$PATH" \
  "MOCK_GREP_SENTINEL=$cargo_grep_sentinel" \
  "MOCK_PRIVATE_SEGMENT=$cargo_grep_segment"
[[ -f "$cargo_grep_sentinel" ]] || fail
cargo_grep_public_log="$private_tmp/generator-cargo-version-grep-error-output"
assert_literal_absent \
  "/U""sers/$cargo_grep_segment/private" "$cargo_grep_public_log"

mock_dirname_dir="$private_tmp/mock-dirname"
mkdir -m 0700 "$mock_dirname_dir"
real_dirname="$(command -v dirname 2>/dev/null)" || fail
dirname_counter="$private_tmp/dirname-counter"
dirname_segment="maverick-sbom-dirname-marker"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'count=0' \
  'if [[ -f "${MOCK_DIRNAME_COUNTER:?}" ]]; then' \
  '  IFS= read -r count <"$MOCK_DIRNAME_COUNTER" || exit 43' \
  'fi' \
  'count=$((count + 1))' \
  'printf "%s\n" "$count" >"$MOCK_DIRNAME_COUNTER" || exit 43' \
  '"${REAL_DIRNAME:?}" "$@" || exit 43' \
  'private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  'printf "%s\n" "$private_marker" >&2' \
  'exit 42' >"$mock_dirname_dir/dirname"
chmod 0700 "$mock_dirname_dir/dirname"
expect_generator_failure dirname-tool-error environment \
  "PATH=$mock_dirname_dir:$PATH" \
  "REAL_DIRNAME=$real_dirname" \
  "MOCK_DIRNAME_COUNTER=$dirname_counter" \
  "MOCK_PRIVATE_SEGMENT=$dirname_segment"
[[ "$(cat "$dirname_counter")" == 1 ]] || fail
dirname_public_log="$private_tmp/generator-dirname-tool-error-output"
assert_literal_absent \
  "/U""sers/$dirname_segment/private" "$dirname_public_log"

mock_hash_awk_dir="$private_tmp/mock-hash-awk"
mkdir -m 0700 "$mock_hash_awk_dir"
real_awk="$(command -v awk 2>/dev/null)" || fail
hash_awk_sentinel="$private_tmp/hash-awk-fired"
hash_awk_segment="maverick-sbom-hash-awk-marker"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'expected_filter="{print $"' \
  'expected_filter+="1}"' \
  'for argument in "$@"; do' \
  '  if [[ "$argument" == "$expected_filter" ]]; then' \
  '    : >"${MOCK_AWK_SENTINEL:?}" || exit 43' \
  '    private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  '    printf "%s\n" "$private_marker" >&2' \
  '    exit 42' \
  '  fi' \
  'done' \
  'exec "${REAL_AWK:?}" "$@"' >"$mock_hash_awk_dir/awk"
chmod 0700 "$mock_hash_awk_dir/awk"
expect_generator_failure hash-awk-error snapshot \
  "PATH=$mock_hash_awk_dir:$PATH" \
  "CARGO_CYCLONEDX_BIN=$real_cyclonedx_bin" \
  "REAL_AWK=$real_awk" \
  "MOCK_AWK_SENTINEL=$hash_awk_sentinel" \
  "MOCK_PRIVATE_SEGMENT=$hash_awk_segment"
[[ -f "$hash_awk_sentinel" ]] || fail
hash_awk_public_log="$private_tmp/generator-hash-awk-error-output"
assert_literal_absent \
  "/U""sers/$hash_awk_segment/private" "$hash_awk_public_log"

mock_generation_dir="$private_tmp/mock-generation"
mkdir -m 0700 "$mock_generation_dir"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "$*" == "cyclonedx --version" ]]; then' \
  '  printf "%s\n" "cargo-cyclonedx-cyclonedx 0.5.9"' \
  '  exit 0' \
  'fi' \
  'private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  'printf "\033[31m%s\n%s\033[0m\n" "$private_marker" "synthetic detail" >&2' \
  'exit 42' >"$mock_generation_dir/cargo-cyclonedx"
chmod 0700 "$mock_generation_dir/cargo-cyclonedx"
generation_private_segment="maverick-sbom-sensitive-marker"
expect_generator_failure generation-tool-error generation \
  "CARGO_CYCLONEDX_BIN=$mock_generation_dir/cargo-cyclonedx" \
  "MOCK_PRIVATE_SEGMENT=$generation_private_segment"
generation_public_log="$private_tmp/generator-generation-tool-error-output"
assert_literal_absent \
  "/U""sers/$generation_private_segment/private" "$generation_public_log"
assert_literal_absent $'\033' "$generation_public_log"

generate_one "$linux_target" "$linux_first"
generate_one "$linux_target" "$linux_second"
generate_one "$mac_target" "$mac_first"
generate_one "$mac_target" "$mac_second"
cmp -s "$linux_first" "$linux_second" || fail
cmp -s "$mac_first" "$mac_second" || fail
verify_one "$linux_first" "$linux_target" structural
verify_one "$linux_first" "$linux_target" full
verify_one "$mac_first" "$mac_target" structural
verify_one "$mac_first" "$mac_target" full

linux_components="$(jq '.components | length' "$linux_first")"
mac_components="$(jq '.components | length' "$mac_first")"
[[ "$linux_components" == 177 && "$mac_components" == 176 ]] || fail
jq -r '.components[] | "\(.name)@\(.version)"' "$linux_first" | sort -u \
  >"$private_tmp/linux-components"
jq -r '.components[] | "\(.name)@\(.version)"' "$mac_first" | sort -u \
  >"$private_tmp/mac-components"
target_delta="$(
  comm -3 "$private_tmp/linux-components" "$private_tmp/mac-components"
)"
[[ "$target_delta" == "linux-raw-sys@0.12.1" ]] || fail

fixture_path=""
make_fixture() {
  local name="$1"
  local filter="$2"
  local dir="$private_tmp/fixture-$name"
  mkdir -m 0700 "$dir"
  fixture_path="$dir/$linux_name"
  jq -S "$filter" "$linux_first" >"$fixture_path"
  chmod 0600 "$fixture_path"
}

make_raw_component_fixture() {
  local name="$1"
  local injection="$2"
  local dir="$private_tmp/fixture-$name"
  local inserted=0
  local line
  mkdir -m 0700 "$dir"
  fixture_path="$dir/$linux_name"
  while IFS= read -r line; do
    printf '%s\n' "$line"
    if [[ "$inserted" -eq 0 && "$line" == *'"component": {'* ]]; then
      printf '%s\n' "$injection"
      inserted=1
    fi
  done <"$linux_first" >"$fixture_path"
  [[ "$inserted" -eq 1 ]] || fail
  chmod 0600 "$fixture_path"
  jq -e . "$fixture_path" >/dev/null 2>&1 || fail
}

make_raw_root_fixture() {
  local name="$1"
  local injection="$2"
  local dir="$private_tmp/fixture-$name"
  local inserted=0
  local line
  mkdir -m 0700 "$dir"
  fixture_path="$dir/$linux_name"
  while IFS= read -r line; do
    printf '%s\n' "$line"
    if [[ "$inserted" -eq 0 && "$line" == "{" ]]; then
      printf '%s\n' "$injection"
      inserted=1
    fi
  done <"$linux_first" >"$fixture_path"
  [[ "$inserted" -eq 1 ]] || fail
  chmod 0600 "$fixture_path"
  jq -e . "$fixture_path" >/dev/null 2>&1 || fail
}

expect_failure() {
  local code="$1"
  local sbom="$2"
  local level="${3:-structural}"
  local expected_revision="${4:-$revision}"
  local output="$private_tmp/failure-output"
  if "$verifier" \
    --sbom "$sbom" \
    --expected-version "$version" \
    --expected-revision "$expected_revision" \
    --expected-target "$linux_target" \
    --verification-level "$level" \
    --source-root "$repo_root" >"$output" 2>&1; then
    fail
  fi
  [[ "$(cat "$output")" == "sbom verification failed: $code" ]] || fail
  negative_checks=$((negative_checks + 1))
}

wrong_dir="$private_tmp/fixture-wrong-basename"
mkdir -m 0700 "$wrong_dir"
cp "$linux_first" "$wrong_dir/wrong.cdx.json"
expect_failure basename "$wrong_dir/wrong.cdx.json"

malformed_dir="$private_tmp/fixture-malformed"
mkdir -m 0700 "$malformed_dir"
printf '{not-json}\n' >"$malformed_dir/$linux_name"
expect_failure json "$malformed_dir/$linux_name"

multi_dir="$private_tmp/fixture-multiple-documents"
mkdir -m 0700 "$multi_dir"
multi_file="$multi_dir/$linux_name"
{
  printf '{"safe_extra":true}\n'
  cat "$linux_first"
} >"$multi_file"
jq -e . "$multi_file" >/dev/null 2>&1 || fail
expect_failure document-count "$multi_file"

make_fixture identity '.bomFormat = "NotCycloneDX"'
expect_failure identity "$fixture_path"

make_fixture target \
  '(.metadata.properties[] | select(.name == "cdx:rustc:sbom:target:triple").value) = "aarch64-apple-darwin"'
expect_failure target "$fixture_path"

make_fixture version '.metadata.component.version = "0.0.0"'
expect_failure root "$fixture_path"

make_fixture revision \
  '(.metadata.component.externalReferences[] | select(.type == "vcs").url) = "https://github.com/ilhaformosa/maverick/tree/0000000000000000000000000000000000000000"'
expect_failure vcs "$fixture_path"

historical_revision=""
historical_version=""
mock_git_dir="$private_tmp/mock-git"
mkdir -m 0700 "$mock_git_dir"
real_git="$(command -v git)"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'for argument in "$@"; do' \
  '  if [[ "$argument" == "rev-list" ]]; then' \
  '    printf "%s\n" "${MOCK_REVISION:?}"' \
  '    printf "%s\n" "/U""sers/example/private" >&2' \
  '    exit 42' \
  '  fi' \
  'done' \
  'exec "${REAL_GIT:?}" "$@"' >"$mock_git_dir/git"
chmod 0700 "$mock_git_dir/git"
mock_revision_list="$private_tmp/mock-revision-list"
if PATH="$mock_git_dir:$PATH" \
  REAL_GIT="$real_git" \
  MOCK_REVISION="$revision" \
  write_revision_list "$mock_revision_list"; then
  fail
fi
[[ -s "$mock_revision_list" ]] || fail
negative_checks=$((negative_checks + 1))

revision_list="$private_tmp/revision-list"
write_revision_list "$revision_list" || fail
chmod 0600 "$revision_list"
candidate_manifest="$private_tmp/candidate-Cargo.toml"
while IFS= read -r candidate_revision; do
  [[ "$candidate_revision" =~ ^[0-9a-f]{40}$ ]] || fail
  git -C "$repo_root" show "$candidate_revision:Cargo.toml" \
    >"$candidate_manifest" 2>/dev/null || fail
  chmod 0600 "$candidate_manifest"
  candidate_version="$(
    awk -F'"' '/^version =/ {print $2; exit}' "$candidate_manifest" 2>/dev/null
  )" || fail
  [[ -z "$candidate_version" ||
    "$candidate_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || fail
  if [[ -n "$candidate_version" && "$candidate_version" != "$version" ]]; then
    historical_revision="$candidate_revision"
    historical_version="$candidate_version"
    break
  fi
done <"$revision_list"
[[ "$historical_revision" =~ ^[0-9a-f]{40}$ ]] || fail
[[ -n "$historical_version" && "$historical_version" != "$version" ]] || fail
historical_epoch="$(
  git -C "$repo_root" show -s --format=%ct "$historical_revision" 2>/dev/null
)" || fail
[[ "$historical_epoch" =~ ^[0-9]+$ ]] || fail
if historical_timestamp="$(
  date -u -r "$historical_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
)"; then
  :
elif historical_timestamp="$(
  date -u -d "@$historical_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
)"; then
  :
else
  fail
fi
historical_vcs="https://github.com/ilhaformosa/maverick/tree/$historical_revision"
historical_dir="$private_tmp/fixture-historical-revision"
mkdir -m 0700 "$historical_dir"
historical_file="$historical_dir/$linux_name"
jq -S \
  --arg timestamp "$historical_timestamp" \
  --arg vcs "$historical_vcs" \
  '.metadata.timestamp = $timestamp |
   (.metadata.component.externalReferences[] |
     select(.type == "vcs").url) = $vcs' \
  "$linux_first" >"$historical_file"
expect_failure source-version "$historical_file" full "$historical_revision"

make_fixture duplicate-ref \
  '.components[1]."bom-ref" = .components[0]."bom-ref" | .components[1].purl = .components[0].purl'
expect_failure duplicate-ref "$fixture_path"

make_fixture dangling-ref '.dependencies[0].ref = "pkg:cargo/dangling@0"'
expect_failure graph-ref "$fixture_path"

make_fixture dangling-dep \
  '.dependencies[0].dependsOn = ((.dependencies[0].dependsOn // []) + ["pkg:cargo/dangling@0"])'
expect_failure graph-dependency "$fixture_path"

make_fixture private-path \
  '.metadata.component.description = ("/" + "Users/example/private")'
expect_failure privacy "$fixture_path"

private_user_word="U""sers"
decoded_private="/${private_user_word}/example/private"
mock_grep_dir="$private_tmp/mock-grep"
mkdir -m 0700 "$mock_grep_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_grep_dir/grep"
chmod 0700 "$mock_grep_dir/grep"
mock_grep_status=0
mock_grep_result="$(
  PATH="$mock_grep_dir:$PATH" \
    assert_literal_absent safe "$linux_first" 2>&1
)" || mock_grep_status=$?
[[ "$mock_grep_status" -ne 0 ]] || fail
[[ "$mock_grep_result" == "CycloneDX SBOM focused tests failed" ]] || fail
negative_checks=$((negative_checks + 1))

unicode_injection="      \"description\": \"\\u002f${private_user_word}\\u002fexample\\u002fprivate\","
make_raw_component_fixture unicode-escaped-private-path "$unicode_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
decoded_value="$(jq -r '.metadata.component.description' "$fixture_path")"
[[ "$decoded_value" == "$decoded_private" ]] || fail
expect_failure privacy "$fixture_path"

slash_injection="      \"description\": \"\\/${private_user_word}\\/example\\/private\","
make_raw_component_fixture slash-escaped-private-path "$slash_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
decoded_value="$(jq -r '.metadata.component.description' "$fixture_path")"
[[ "$decoded_value" == "$decoded_private" ]] || fail
expect_failure privacy "$fixture_path"

escaped_key_injection="  \"\\u002f${private_user_word}\\u002fexample\\u002fprivate\": true,"
make_raw_root_fixture escaped-private-object-key "$escaped_key_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
jq -e --arg key "$decoded_private" 'has($key)' \
  "$fixture_path" >/dev/null 2>&1 || fail
expect_failure privacy "$fixture_path"

duplicate_injection="$(
  printf '      "description": "%s",\n      "description": "safe",' \
    "$decoded_private"
)"
make_raw_component_fixture duplicate-private-value "$duplicate_injection"
grep -Fq "/${private_user_word}/" "$fixture_path" || fail
[[ "$(jq -r '.metadata.component.description' "$fixture_path")" == "safe" ]] ||
  fail
expect_failure privacy "$fixture_path"

duplicate_unicode_injection="$(
  printf '      "description": "\\u002f%s\\u002fexample\\u002fprivate",\n      "description": "safe",' \
    "$private_user_word"
)"
make_raw_component_fixture duplicate-unicode-private-value \
  "$duplicate_unicode_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
[[ "$(jq -r '.metadata.component.description' "$fixture_path")" == "safe" ]] ||
  fail
expect_failure privacy "$fixture_path"

duplicate_slash_injection="$(
  printf '      "description": "\\/%s\\/example\\/private",\n      "description": "safe",' \
    "$private_user_word"
)"
make_raw_component_fixture duplicate-slash-private-value \
  "$duplicate_slash_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
[[ "$(jq -r '.metadata.component.description' "$fixture_path")" == "safe" ]] ||
  fail
expect_failure privacy "$fixture_path"

duplicate_escaped_key_injection="$(
  printf '      "descr\\u0069ption": "\\u002f%s\\u002fexample\\u002fprivate",\n      "description": "safe",' \
    "$private_user_word"
)"
make_raw_component_fixture duplicate-escaped-key-private-value \
  "$duplicate_escaped_key_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
[[ "$(jq -r '.metadata.component.description' "$fixture_path")" == "safe" ]] ||
  fail
expect_failure privacy "$fixture_path"

duplicate_metadata_injection="$(
  printf '  "metadata": {"\\u002f%s\\u002fexample\\u002fprivate": true},' \
    "$private_user_word"
)"
make_raw_root_fixture duplicate-metadata-with-escaped-private-key \
  "$duplicate_metadata_injection"
assert_literal_absent "/${private_user_word}/" "$fixture_path"
jq -e '.metadata.component.name == "maverick"' \
  "$fixture_path" >/dev/null 2>&1 || fail
expect_failure privacy "$fixture_path"

make_fixture file-url \
  '.metadata.component.description = ("fi" + "le:///private/tmp/source")'
expect_failure privacy "$fixture_path"

make_fixture credential \
  '.metadata.component.description = ("gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")'
expect_failure privacy "$fixture_path"

make_fixture private-host \
  '.metadata.component.description = ("10" + ".0.0.1")'
expect_failure privacy "$fixture_path"

make_fixture serial '.serialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"'
expect_failure serial "$fixture_path"

add_component_filter() {
  local name="$1"
  local component_version="$2"
  printf '.components += [{"type":"library","name":"%s","version":"%s","scope":"required","purl":"pkg:cargo/%s@%s","bom-ref":"pkg:cargo/%s@%s"}] | .dependencies += [{"ref":"pkg:cargo/%s@%s","dependsOn":[]}]' \
    "$name" "$component_version" "$name" "$component_version" \
    "$name" "$component_version" "$name" "$component_version"
}

make_fixture dev-component "$(add_component_filter criterion 0.8.2)"
expect_failure closure "$fixture_path" full

make_fixture build-component "$(add_component_filter clang-sys 1.8.1)"
expect_failure closure "$fixture_path" full

make_fixture test-component "$(add_component_filter maverick-tests "$version")"
expect_failure closure "$fixture_path" full

make_fixture unrelated-component "$(add_component_filter maverick-sdk "$version")"
expect_failure closure "$fixture_path" full

mock_uniq_dir="$private_tmp/mock-uniq"
mkdir -m 0700 "$mock_uniq_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_uniq_dir/uniq"
chmod 0700 "$mock_uniq_dir/uniq"
mock_uniq_output="$private_tmp/mock-uniq-output"
if PATH="$mock_uniq_dir:$PATH" "$verifier" \
  --sbom "$linux_first" \
  --expected-version "$version" \
  --expected-revision "$revision" \
  --expected-target "$linux_target" \
  --verification-level full \
  --source-root "$repo_root" >"$mock_uniq_output" 2>&1; then
  fail
fi
mock_uniq_result="$(cat "$mock_uniq_output")" || fail
[[ "$mock_uniq_result" == "sbom verification failed: ambiguous-identity" ]] ||
  fail
negative_checks=$((negative_checks + 1))

mock_hash_dir="$private_tmp/mock-hash"
mkdir -m 0700 "$mock_hash_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_hash_dir/shasum"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "$*" != "cyclonedx --version" ]]; then' \
  '  : >"${MOCK_SENTINEL:?}"' \
  'fi' \
  'exec "${REAL_CYCLONEDX_BIN:?}" "$@"' \
  >"$mock_hash_dir/cargo-cyclonedx"
chmod 0700 "$mock_hash_dir/shasum" "$mock_hash_dir/cargo-cyclonedx"
hash_sentinel="$private_tmp/hash-generator-started"
expect_generator_failure hash-tool snapshot \
  "PATH=$mock_hash_dir:$PATH" \
  "CARGO_CYCLONEDX_BIN=$mock_hash_dir/cargo-cyclonedx" \
  "REAL_CYCLONEDX_BIN=$real_cyclonedx_bin" \
  "MOCK_SENTINEL=$hash_sentinel"
[[ ! -e "$hash_sentinel" ]] || fail

mock_find_dir="$private_tmp/mock-find"
mkdir -m 0700 "$mock_find_dir"
real_find="$(command -v find)"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case " $* " in' \
  '  *" -print0 "*)' \
  '    "${REAL_FIND:?}" "$@"' \
  '    find_status=$?' \
  '    [[ "$find_status" -eq 0 ]] || exit "$find_status"' \
  '    printf "%s\n" "/U""sers/example/private" >&2' \
  '    exit 42' \
  '    ;;' \
  'esac' \
  'exec "${REAL_FIND:?}" "$@"' >"$mock_find_dir/find"
chmod 0700 "$mock_find_dir/find"
expect_generator_failure find-partial-error candidate \
  "PATH=$mock_find_dir:$PATH" \
  "REAL_FIND=$real_find"

mock_jq_dir="$private_tmp/mock-jq"
mkdir -m 0700 "$mock_jq_dir"
real_jq="$(command -v jq)"
jq_error_sentinel="$private_tmp/jq-error-fired"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'candidate_check=false' \
  'previous=""' \
  'last=""' \
  'for argument in "$@"; do' \
  '  if [[ "$previous" == "--arg" && "$argument" == "target" ]]; then' \
  '    candidate_check=true' \
  '  fi' \
  '  previous="$argument"' \
  '  last="$argument"' \
  'done' \
  'if [[ "$candidate_check" == true ]] &&' \
  '  "${REAL_JQ:?}" -e '\''.metadata.component.name != "maverick"'\'' "$last" >/dev/null 2>&1; then' \
  '  : >"${MOCK_JQ_SENTINEL:?}"' \
  '  printf "%s\n" "/U""sers/example/private" >&2' \
  '  exit 42' \
  'fi' \
  'exec "${REAL_JQ:?}" "$@"' >"$mock_jq_dir/jq"
chmod 0700 "$mock_jq_dir/jq"
expect_generator_failure jq-tool-error candidate \
  "PATH=$mock_jq_dir:$PATH" \
  "REAL_JQ=$real_jq" \
  "MOCK_JQ_SENTINEL=$jq_error_sentinel"
[[ -f "$jq_error_sentinel" ]] || fail

mock_normalization_dir="$private_tmp/mock-normalization"
mkdir -m 0700 "$mock_normalization_dir"
normalization_sentinel="$private_tmp/normalization-error-fired"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'for argument in "$@"; do' \
  '  if [[ "$argument" == "-S" ]]; then' \
  '    : >"${MOCK_NORMALIZATION_SENTINEL:?}"' \
  '    printf "%s\n" "/U""sers/example/private" >&2' \
  '    exit 42' \
  '  fi' \
  'done' \
  'exec "${REAL_JQ:?}" "$@"' >"$mock_normalization_dir/jq"
chmod 0700 "$mock_normalization_dir/jq"
expect_generator_failure normalization-tool-error normalization \
  "PATH=$mock_normalization_dir:$PATH" \
  "REAL_JQ=$real_jq" \
  "MOCK_NORMALIZATION_SENTINEL=$normalization_sentinel"
[[ -f "$normalization_sentinel" ]] || fail

mock_verification_dir="$private_tmp/mock-verification"
mkdir -m 0700 "$mock_verification_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_verification_dir/wc"
chmod 0700 "$mock_verification_dir/wc"
expect_generator_failure verification-tool-error verification-input \
  "PATH=$mock_verification_dir:$PATH"

real_cmp="$(command -v cmp)" || fail
mock_verification_closure_dir="$private_tmp/mock-verification-closure"
mkdir -m 0700 "$mock_verification_closure_dir"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case "${2:-} ${3:-}" in' \
  '  *"/expected-components /"*"/actual-components") exit 1 ;;' \
  'esac' \
  'exec "${REAL_CMP:?}" "$@"' >"$mock_verification_closure_dir/cmp"
chmod 0700 "$mock_verification_closure_dir/cmp"
expect_generator_failure verification-closure verification-closure \
  "PATH=$mock_verification_closure_dir:$PATH" \
  "REAL_CMP=$real_cmp"

mock_verification_malformed_dir="$private_tmp/mock-verification-malformed"
mkdir -m 0700 "$mock_verification_malformed_dir"
verification_private_segment="maverick-sbom-verification-marker"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case "${2:-} ${3:-}" in' \
  '  *"/expected-components /"*"/actual-components")' \
  '    private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  '    printf "sbom verification failed: closure\n\033[31m%s\n%s\033[0m\n" \
      "$private_marker" "synthetic detail" >&2' \
  '    exit 1' \
  '    ;;' \
  'esac' \
  'exec "${REAL_CMP:?}" "$@"' >"$mock_verification_malformed_dir/cmp"
chmod 0700 "$mock_verification_malformed_dir/cmp"
expect_generator_failure verification-malformed-output verification \
  "PATH=$mock_verification_malformed_dir:$PATH" \
  "REAL_CMP=$real_cmp" \
  "MOCK_PRIVATE_SEGMENT=$verification_private_segment"
verification_public_log="$private_tmp/generator-verification-malformed-output-output"
assert_literal_absent \
  "/U""sers/$verification_private_segment/private" "$verification_public_log"
assert_literal_absent $'\033' "$verification_public_log"

mock_verification_capture_dir="$private_tmp/mock-verification-capture"
mkdir -m 0700 "$mock_verification_capture_dir"
real_cat="$(command -v cat)" || fail
verification_capture_segment="maverick-sbom-capture-marker"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '"${REAL_CAT:?}" >/dev/null || exit 43' \
  'private_marker="/U""sers/${MOCK_PRIVATE_SEGMENT:?}/private"' \
  'printf "%s\n" "$private_marker" >&2' \
  'exit 42' >"$mock_verification_capture_dir/tail"
chmod 0700 "$mock_verification_capture_dir/tail"
expect_generator_failure verification-capture-error verification \
  "PATH=$mock_verification_capture_dir:$PATH" \
  "REAL_CAT=$real_cat" \
  "MOCK_PRIVATE_SEGMENT=$verification_capture_segment"
verification_capture_log="$private_tmp/generator-verification-capture-error-output"
assert_literal_absent \
  "/U""sers/$verification_capture_segment/private" "$verification_capture_log"

mock_graph_ref_dir="$private_tmp/mock-graph-ref-missing"
mkdir -m 0700 "$mock_graph_ref_dir"
real_jq="$(command -v jq)" || fail
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'normalization=false' \
  'for argument in "$@"; do' \
  '  case "$argument" in' \
  '    *"def canonical_purl:"*) normalization=true ;;' \
  '  esac' \
  'done' \
  'if [[ "$normalization" == true ]]; then' \
  '  normalized="${MOCK_GRAPH_REF_TMP:?}/normalized.json"' \
  '  "${REAL_JQ:?}" "$@" >"$normalized" || exit 43' \
  '  case "${MOCK_GRAPH_REF_MODE:?}" in' \
  '    missing)' \
  '      filter=".dependencies = .dependencies[:-1]"' \
  '      ;;' \
  '    structure-type)' \
  '      filter=".dependencies = {}"' \
  '      ;;' \
  '    ref-type)' \
  '      filter=".dependencies[0].ref = null"' \
  '      ;;' \
  '    *) exit 43 ;;' \
  '  esac' \
  '  "${REAL_JQ:?}" "$filter" "$normalized"' \
  '  exit $?' \
  'fi' \
  'exec "${REAL_JQ:?}" "$@"' >"$mock_graph_ref_dir/jq"
chmod 0700 "$mock_graph_ref_dir/jq"
expect_generator_failure graph-ref-missing verification-graph-ref-missing \
  "PATH=$mock_graph_ref_dir:$PATH" \
  "REAL_JQ=$real_jq" \
  "MOCK_GRAPH_REF_TMP=$private_tmp" \
  "MOCK_GRAPH_REF_MODE=missing"
expect_generator_failure graph-ref-structure-type verification-graph-ref \
  "PATH=$mock_graph_ref_dir:$PATH" \
  "REAL_JQ=$real_jq" \
  "MOCK_GRAPH_REF_TMP=$private_tmp" \
  "MOCK_GRAPH_REF_MODE=structure-type"
expect_generator_failure graph-ref-ref-type verification-graph-ref \
  "PATH=$mock_graph_ref_dir:$PATH" \
  "REAL_JQ=$real_jq" \
  "MOCK_GRAPH_REF_TMP=$private_tmp" \
  "MOCK_GRAPH_REF_MODE=ref-type"

mock_integrity_dir="$private_tmp/mock-integrity"
mkdir -m 0700 "$mock_integrity_dir"
real_shasum="$(command -v shasum)"
integrity_counter="$private_tmp/integrity-hash-counter"
# These single quotes deliberately preserve variables for the generated mock.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'hash_input=""' \
  'for hash_input in "$@"; do :; done' \
  'case "$hash_input" in' \
  '  */Cargo.lock) ;;' \
  '  *) exec "${REAL_SHASUM:?}" "$@" ;;' \
  'esac' \
  'count=0' \
  'if [[ -f "${MOCK_HASH_COUNTER:?}" ]]; then' \
  '  IFS= read -r count <"$MOCK_HASH_COUNTER" || exit 43' \
  'fi' \
  'count=$((count + 1))' \
  'printf "%s\n" "$count" >"$MOCK_HASH_COUNTER" || exit 43' \
  'if [[ "$count" -gt 3 ]]; then' \
  '  printf "%s\n" "/U""sers/example/private" >&2' \
  '  exit 42' \
  'fi' \
  'exec "${REAL_SHASUM:?}" "$@"' >"$mock_integrity_dir/shasum"
chmod 0700 "$mock_integrity_dir/shasum"
expect_generator_failure integrity-hash-error integrity \
  "PATH=$mock_integrity_dir:$PATH" \
  "REAL_SHASUM=$real_shasum" \
  "MOCK_HASH_COUNTER=$integrity_counter"
[[ "$(cat "$integrity_counter")" == 4 ]] || fail

mock_install_dir="$private_tmp/mock-install"
mkdir -m 0700 "$mock_install_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_install_dir/install"
chmod 0700 "$mock_install_dir/install"
expect_generator_failure install-tool-error output \
  "PATH=$mock_install_dir:$PATH"

mock_wc_dir="$private_tmp/mock-wc"
mkdir -m 0700 "$mock_wc_dir"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "0\n"' \
  'printf "%s\n" "/U""sers/example/private" >&2' \
  'exit 42' >"$mock_wc_dir/wc"
chmod 0700 "$mock_wc_dir/wc"
mock_wc_output="$private_tmp/mock-wc-output"
if PATH="$mock_wc_dir:$PATH" "$verifier" \
  --sbom "$linux_first" \
  --expected-version "$version" \
  --expected-revision "$revision" \
  --expected-target "$linux_target" \
  --verification-level structural \
  --source-root "$repo_root" >"$mock_wc_output" 2>&1; then
  fail
fi
mock_wc_result="$(cat "$mock_wc_output")" || fail
[[ "$mock_wc_result" == "sbom verification failed: input" ]] || fail
negative_checks=$((negative_checks + 1))
mock_wc_status=0
mock_size="$(
  PATH="$mock_wc_dir:$PATH" measure_test_file "$linux_first"
)" || mock_wc_status=$?
[[ "$mock_wc_status" -ne 0 && "$mock_size" == 0 ]] || fail
negative_checks=$((negative_checks + 1))

symlink_dir="$private_tmp/fixture-symlink"
mkdir -m 0700 "$symlink_dir"
ln -s "$linux_first" "$symlink_dir/$linux_name"
expect_failure input "$symlink_dir/$linux_name"

oversized_dir="$private_tmp/fixture-oversized"
mkdir -m 0700 "$oversized_dir"
dd if=/dev/zero of="$oversized_dir/$linux_name" bs=1 count=0 \
  seek=$((max_sbom_bytes + 1)) 2>/dev/null
expect_failure oversized "$oversized_dir/$linux_name"

mutation_dir="$private_tmp/fixture-mutation"
mkdir -m 0700 "$mutation_dir"
mutation_file="$mutation_dir/$linux_name"
cp "$linux_first" "$mutation_file"
dd if=/dev/zero bs=1024 count=1024 2>/dev/null | tr '\000' ' ' \
  >>"$mutation_file"
mutation_output="$private_tmp/mutation-output"
"$verifier" \
  --sbom "$mutation_file" \
  --expected-version "$version" \
  --expected-revision "$revision" \
  --expected-target "$linux_target" \
  --verification-level full \
  --source-root "$repo_root" >"$mutation_output" 2>&1 &
verify_pid=$!
while kill -0 "$verify_pid" 2>/dev/null; do
  printf ' ' >>"$mutation_file"
  sleep 0.02
done
mutation_status=0
wait "$verify_pid" || mutation_status=$?
[[ "$mutation_status" -ne 0 ]] || fail
[[ "$(cat "$mutation_output")" == "sbom verification failed: mutation" ]] || fail
negative_checks=$((negative_checks + 1))

[[ "$negative_checks" -eq 53 ]] || fail
linux_bytes="$(measure_test_file "$linux_first")" || fail
mac_bytes="$(measure_test_file "$mac_first")" || fail
[[ "$linux_bytes" =~ ^[0-9]+$ && "$mac_bytes" =~ ^[0-9]+$ ]] || fail
[[ "$linux_bytes" -le "$max_sbom_bytes" ]] || fail
[[ "$mac_bytes" -le "$max_sbom_bytes" ]] || fail

echo "CycloneDX SBOM focused tests OK (2 targets, 53 negative checks)"
