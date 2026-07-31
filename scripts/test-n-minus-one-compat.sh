#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C
export LANG=C
export CARGO_NET_OFFLINE=true

readonly N_TAG="v1.2.0-beta.2"
readonly N_TAG_OBJECT="3a2f7409c3193d03349219b1f8c144d76db74d67"
readonly N_COMMIT="6862a3004ec9c3b1e52fd03f71dc47b771564cc4"
readonly N_VERSION="1.2.0-beta.2"
readonly N1_TAG="v1.2.0-beta.1"
readonly N1_TAG_OBJECT="71c1a5fdf0cf74aa1c9ee7dc3a578647fba8a720"
readonly N1_COMMIT="75b2a666f236043c3f3c611a9f2c3de8526c3171"
readonly N1_VERSION="1.2.0-beta.1"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

case "${1:-}" in
  "") run_mode=full ;;
  --source-binding-tests-only) run_mode=source_binding_tests ;;
  *) fail "unsupported compatibility test option" ;;
esac

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P 2>/dev/null) ||
  fail "repository location is unavailable"
cd "$repo_root" 2>/dev/null || fail "repository location is unavailable"

temp_parent=${TMPDIR:-/tmp}
case "$temp_parent" in
  /*) ;;
  *) temp_parent=/tmp ;;
esac
temp_root=$(mktemp -d "${temp_parent%/}/maverick-n-minus-one.XXXXXX" 2>/dev/null) ||
  fail "unable to create private compatibility workspace"
marker="$temp_root/.maverick-n-minus-one"
: 2>/dev/null >"$marker" || fail "unable to initialize private compatibility workspace"

cleanup() {
  if [ -n "${temp_root:-}" ] && [ -d "$temp_root" ] && [ -f "$marker" ]; then
    rm -rf -- "$temp_root" 2>/dev/null || true
  fi
}

on_signal() {
  trap - EXIT
  cleanup
  exit 1
}

trap cleanup EXIT
trap on_signal HUP INT TERM

safe_git() {
  command git --no-replace-objects "$@"
}

validate_tag_binding() {
  binding_repo=$1
  binding_tag=$2
  binding_tag_object=$3
  binding_commit=$4

  actual_tag_object=$(
    safe_git -C "$binding_repo" rev-parse --verify "refs/tags/$binding_tag" 2>/dev/null
  ) || return 1
  [ "$actual_tag_object" = "$binding_tag_object" ] || return 1
  [ "$(safe_git -C "$binding_repo" cat-file -t "$binding_tag_object" 2>/dev/null)" = "tag" ] ||
    return 1

  tag_headers=$(
    safe_git -C "$binding_repo" cat-file -p "$binding_tag_object" 2>/dev/null
  ) || return 1
  direct_object=$(printf '%s\n' "$tag_headers" | awk '$1 == "object" { print $2; exit }')
  direct_type=$(printf '%s\n' "$tag_headers" | awk '$1 == "type" { print $2; exit }')
  direct_name=$(printf '%s\n' "$tag_headers" | awk '$1 == "tag" { print $2; exit }')

  [ "$direct_type" = "commit" ] || return 1
  [ "$direct_name" = "$binding_tag" ] || return 1
  [ "$direct_object" = "$binding_commit" ] || return 1
  [ "$(safe_git -C "$binding_repo" cat-file -t "$binding_commit" 2>/dev/null)" = "commit" ] ||
    return 1
  [ "$(
    safe_git -C "$binding_repo" rev-parse --verify "$binding_tag_object^{}" 2>/dev/null
  )" = "$binding_commit" ] || return 1
}

archive_pinned_commit() {
  archive_repo=$1
  archive_commit=$2
  archive_file=$3
  archive_log=$4

  safe_git -C "$archive_repo" archive "$archive_commit" 2>"$archive_log" >"$archive_file"
}

run_source_binding_negative_tests() {
  fixture_repo="$temp_root/source-binding-fixture"
  fixture_archive="$temp_root/source-binding.tar"
  fixture_log="$temp_root/source-binding.log"

  safe_git init -q "$fixture_repo" >"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" config user.name Fixture >>"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" config user.email fixture.invalid >>"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  printf 'expected\n' 2>>"$fixture_log" >"$fixture_repo/source.txt" ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" add source.txt >>"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" commit -q -m expected >>"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  fixture_good=$(safe_git -C "$fixture_repo" rev-parse HEAD 2>>"$fixture_log") ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" tag -a release "$fixture_good" -m release \
    >>"$fixture_log" 2>&1 || fail "source binding fixture setup failed"
  fixture_tag_object=$(
    safe_git -C "$fixture_repo" rev-parse refs/tags/release 2>>"$fixture_log"
  ) || fail "source binding fixture setup failed"

  printf 'substituted\n' 2>>"$fixture_log" >"$fixture_repo/source.txt" ||
    fail "source binding fixture setup failed"
  safe_git -C "$fixture_repo" commit -q -am substituted >>"$fixture_log" 2>&1 ||
    fail "source binding fixture setup failed"
  fixture_bad=$(safe_git -C "$fixture_repo" rev-parse HEAD 2>>"$fixture_log") ||
    fail "source binding fixture setup failed"

  safe_git -C "$fixture_repo" replace "$fixture_good" "$fixture_bad" \
    >>"$fixture_log" 2>&1 || fail "replace-object fixture setup failed"
  validate_tag_binding "$fixture_repo" release "$fixture_tag_object" "$fixture_good" ||
    fail "replace-object source binding test failed"
  archive_pinned_commit "$fixture_repo" "$fixture_good" "$fixture_archive" "$fixture_log" ||
    fail "replace-object archive test failed"
  [ "$(tar -xOf "$fixture_archive" source.txt 2>>"$fixture_log")" = "expected" ] ||
    fail "replace-object archive source changed"
  safe_git -C "$fixture_repo" replace -d "$fixture_good" >>"$fixture_log" 2>&1 ||
    fail "replace-object fixture cleanup failed"

  validate_tag_binding "$fixture_repo" release "$fixture_tag_object" "$fixture_good" ||
    fail "tag rebuild fixture validation failed"
  safe_git -C "$fixture_repo" tag -f -a release "$fixture_bad" -m rebuilt \
    >>"$fixture_log" 2>&1 || fail "rebuilt-tag fixture setup failed"
  if validate_tag_binding "$fixture_repo" release "$fixture_tag_object" "$fixture_good"; then
    fail "rebuilt tag was not rejected"
  fi
  archive_pinned_commit "$fixture_repo" "$fixture_good" "$fixture_archive" "$fixture_log" ||
    fail "rebuilt-tag archive test failed"
  [ "$(tar -xOf "$fixture_archive" source.txt 2>>"$fixture_log")" = "expected" ] ||
    fail "rebuilt tag changed pinned archive source"

  safe_git -C "$fixture_repo" update-ref refs/tags/release "$fixture_tag_object" \
    >>"$fixture_log" 2>&1 || fail "nested-tag fixture setup failed"
  validate_tag_binding "$fixture_repo" release "$fixture_tag_object" "$fixture_good" ||
    fail "nested tag fixture validation failed"
  safe_git -C "$fixture_repo" tag -a inner "$fixture_bad" -m inner \
    >>"$fixture_log" 2>&1 || fail "nested-tag fixture setup failed"
  safe_git -C "$fixture_repo" tag -f -a release refs/tags/inner -m nested \
    >>"$fixture_log" 2>&1 || fail "nested-tag fixture setup failed"
  nested_tag_object=$(
    safe_git -C "$fixture_repo" rev-parse refs/tags/release 2>>"$fixture_log"
  ) || fail "nested-tag fixture setup failed"
  if validate_tag_binding "$fixture_repo" release "$fixture_tag_object" "$fixture_good"; then
    fail "nested tag rebuild was not rejected"
  fi
  if validate_tag_binding "$fixture_repo" release "$nested_tag_object" "$fixture_bad"; then
    fail "nested tag target was not rejected"
  fi
  archive_pinned_commit "$fixture_repo" "$fixture_good" "$fixture_archive" "$fixture_log" ||
    fail "nested-tag archive test failed"
  [ "$(tar -xOf "$fixture_archive" source.txt 2>>"$fixture_log")" = "expected" ] ||
    fail "nested tag changed pinned archive source"

  printf 'PASS source_binding_negative_tests replace=1 rebuilt=1 nested=1 pinned_archives=3\n'
}

workspace_version() {
  awk '
    $0 == "[workspace.package]" { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && $1 == "version" {
      value = $3
      gsub(/"/, "", value)
      print value
      exit
    }
  ' "$1" 2>/dev/null
}

lock_has_workspace_versions() {
  awk -v expected="$2" '
    function check_package() {
      if (name ~ /^maverick-/) {
        count++
        if (version != expected) bad = 1
      }
    }
    $0 == "[[package]]" {
      check_package()
      name = ""
      version = ""
      next
    }
    $1 == "name" {
      name = $3
      gsub(/"/, "", name)
    }
    $1 == "version" {
      version = $3
      gsub(/"/, "", version)
    }
    END {
      check_package()
      if (bad || count != 7) exit 1
    }
  ' "$1" 2>/dev/null
}

export_tag() {
  label=$1
  tag=$2
  tag_object=$3
  commit=$4
  version=$5
  source_dir="$temp_root/source-$label"
  archive_file="$temp_root/source-$label.tar"

  validate_tag_binding "$repo_root" "$tag" "$tag_object" "$commit" ||
    fail "published tag binding check failed"
  mkdir -m 700 "$source_dir" 2>"$temp_root/mkdir-$label.log" ||
    fail "local source workspace setup failed"
  archive_pinned_commit \
    "$repo_root" "$commit" "$archive_file" "$temp_root/archive-$label.log" ||
    fail "local tag export failed"
  tar -xf "$archive_file" -C "$source_dir" 2>"$temp_root/extract-$label.log" ||
    fail "local tag extraction failed"
  [ "$(workspace_version "$source_dir/Cargo.toml")" = "$version" ] ||
    fail "published package version check failed"
  lock_has_workspace_versions "$source_dir/Cargo.lock" "$version" ||
    fail "published lock version check failed"
  cargo metadata --quiet --offline --locked --no-deps \
    --manifest-path "$source_dir/Cargo.toml" \
    >"$temp_root/metadata-$label.json" 2>"$temp_root/metadata-$label.log" ||
    fail "published lock consistency check failed"
  printf '%s\n' "$source_dir"
}

build_pair() {
  label=$1
  source_dir=$2
  target_dir="$temp_root/target-$label"
  binary_dir="$temp_root/bin"
  if [ ! -d "$binary_dir" ]; then
    mkdir -m 700 "$binary_dir" 2>"$temp_root/build-$label-default.log" ||
      fail "historical binary workspace setup failed"
  fi

  cargo build --quiet --offline --locked -p maverick-cli \
    --manifest-path "$source_dir/Cargo.toml" --target-dir "$target_dir" \
    >"$temp_root/build-$label-default.log" 2>&1 ||
    fail "historical default build failed; compatibility not evaluated"
  cp "$target_dir/debug/maverick" "$binary_dir/$label-default" \
    >>"$temp_root/build-$label-default.log" 2>&1 ||
    fail "historical default binary capture failed; compatibility not evaluated"

  cargo build --quiet --offline --locked -p maverick-cli --no-default-features \
    --manifest-path "$source_dir/Cargo.toml" --target-dir "$target_dir" \
    >"$temp_root/build-$label-rustls.log" 2>&1 ||
    fail "historical rustls build failed; compatibility not evaluated"
  cp "$target_dir/debug/maverick" "$binary_dir/$label-rustls" \
    >>"$temp_root/build-$label-rustls.log" 2>&1 ||
    fail "historical rustls binary capture failed; compatibility not evaluated"
}

check_version() {
  binary=$1
  expected=$2
  output=$("$binary" version 2>/dev/null) ||
    fail "historical binary version command failed; compatibility not evaluated"
  first_line=$(printf '%s\n' "$output" | sed -n '1p')
  protocol_line=$(printf '%s\n' "$output" | sed -n '2p')
  [ "$first_line" = "maverick $expected" ] ||
    fail "historical binary version mismatch; compatibility not evaluated"
  [ "$protocol_line" = "protocol_version: 1" ] ||
    fail "historical protocol version mismatch; compatibility not evaluated"
}

run_test_stage() {
  test_name=$1
  failure=$2
  expected_passes=$3
  expected_summary=$4
  log_file="$temp_root/test-$test_name.log"

  if ! cargo test --quiet --offline --locked -p maverick-tests \
    --target-dir "$temp_root/current-test-target" \
    --test n_minus_one_process "$test_name" -- --ignored --exact --nocapture \
    >"$log_file" 2>&1; then
    sed -n '/^Error: /p;/test result: FAILED/p' "$log_file" >&2
    fail "$failure"
  fi
  pass_count=$(grep -c "PASS " "$log_file" 2>/dev/null || true)
  [ "$pass_count" -eq "$expected_passes" ] ||
    fail "compatibility matrix result count changed"
  summary_count=$(grep -Fxc "$expected_summary" "$log_file" 2>/dev/null || true)
  [ "$summary_count" -eq 1 ] ||
    fail "matrix summary verification failed; compatibility not established"
  sed -n '/PASS /p;/MATRIX_RESULT /p' "$log_file"
}

run_source_binding_negative_tests
if [ "$run_mode" = source_binding_tests ]; then
  exit 0
fi

n_source=$(export_tag beta2 "$N_TAG" "$N_TAG_OBJECT" "$N_COMMIT" "$N_VERSION")
n1_source=$(export_tag beta1 "$N1_TAG" "$N1_TAG_OBJECT" "$N1_COMMIT" "$N1_VERSION")
printf 'PASS identity N=%s N-1=%s annotated_tags=2 tag_objects=2 locks=2\n' \
  "$N_VERSION" "$N1_VERSION"

build_pair beta2 "$n_source"
build_pair beta1 "$n1_source"

export MAVERICK_BETA2_DEFAULT_BIN="$temp_root/bin/beta2-default"
export MAVERICK_BETA1_DEFAULT_BIN="$temp_root/bin/beta1-default"
export MAVERICK_BETA2_RUSTLS_BIN="$temp_root/bin/beta2-rustls"
export MAVERICK_BETA1_RUSTLS_BIN="$temp_root/bin/beta1-rustls"

check_version "$MAVERICK_BETA2_DEFAULT_BIN" "$N_VERSION"
check_version "$MAVERICK_BETA1_DEFAULT_BIN" "$N1_VERSION"
check_version "$MAVERICK_BETA2_RUSTLS_BIN" "$N_VERSION"
check_version "$MAVERICK_BETA1_RUSTLS_BIN" "$N1_VERSION"
printf 'PASS build_version binaries=4 default=2 rustls=2\n'

cargo test --quiet --offline --locked -p maverick-tests \
  --target-dir "$temp_root/current-test-target" \
  --test n_minus_one_process --no-run \
  >"$temp_root/test-harness-build.log" 2>&1 ||
  fail "local test harness build failed; compatibility not evaluated"

run_test_stage historical_configs_are_accepted \
  "historical config preflight failed; compatibility not evaluated" 8 \
  "MATRIX_RESULT stage=config completed=true cells=8 checks=16 binaries=4 auth_modes=2"
run_test_stage same_version_h2_process_controls \
  "same-version process control failed; compatibility not evaluated" 8 \
  "MATRIX_RESULT stage=same_version completed=true cells=8 default=4 rustls=4 auth_v1=4 auth_v2=4"
run_test_stage cross_version_h2_process_matrix \
  "matrix did not complete; compatibility not established" 8 \
  "MATRIX_RESULT stage=cross_version completed=true cells=8 default=4 rustls=4 auth_v1=4 auth_v2=4"

printf 'SUMMARY matrix_total=16 same_version=8 cross_version=8 default=8 rustls=8 auth_v1=8 auth_v2=8\n'
