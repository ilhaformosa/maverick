#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

readonly EXPECTED_TOOL_VERSION=0.5.9
readonly PUBLIC_REPOSITORY="https://github.com/ilhaformosa/maverick"

expected_version=""
expected_revision=""
target=""
output_path=""
private_tmp=""
current_stage=environment

fail() {
  trap - HUP INT TERM
  local public_stage="$current_stage"
  case "$public_stage" in
    arguments | environment | source | snapshot | generation | candidate | \
      normalization | verification | integrity | output) ;;
    *) public_stage=internal ;;
  esac
  printf 'CycloneDX SBOM generation failed: %s\n' "$public_stage" >&2 || :
  exit 1
}

script_dir="$(dirname "${BASH_SOURCE[0]}" 2>/dev/null)" || fail
repo_root="$(
  cd "$script_dir/.." 2>/dev/null || exit 1
  pwd 2>/dev/null
)" || fail
verifier="$repo_root/scripts/verify-cyclonedx-sbom.sh"

current_stage=arguments

cleanup() {
  case "$private_tmp" in
    /tmp/maverick-sbom-generate.*)
      [[ ! -d "$private_tmp" ]] ||
        find "$private_tmp" -depth -delete >/dev/null 2>&1 || true
      ;;
  esac
}

trap cleanup EXIT
trap 'current_stage=internal; fail' HUP INT TERM

sha256_file() {
  local digest=""
  if command -v shasum >/dev/null 2>&1; then
    digest="$(
      {
        shasum -a 256 "$1" | awk '{print $1}'
      } 2>/dev/null
    )" || return 1
  elif command -v sha256sum >/dev/null 2>&1; then
    digest="$(
      {
        sha256sum "$1" | awk '{print $1}'
      } 2>/dev/null
    )" || return 1
  else
    return 1
  fi
  printf '%s\n' "$digest" 2>/dev/null || return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-version)
      [[ $# -ge 2 && -z "$expected_version" ]] || fail
      expected_version="$2"
      shift 2
      ;;
    --expected-revision)
      [[ $# -ge 2 && -z "$expected_revision" ]] || fail
      expected_revision="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 && -z "$target" ]] || fail
      target="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 && -z "$output_path" ]] || fail
      output_path="$2"
      shift 2
      ;;
    *)
      fail
      ;;
  esac
done

[[ "$expected_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || fail
[[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || fail
case "$target" in
  x86_64-unknown-linux-gnu | aarch64-apple-darwin) ;;
  *) fail ;;
esac
[[ -n "$output_path" && ! -e "$output_path" && ! -L "$output_path" ]] || fail
output_dir="$(dirname "$output_path" 2>/dev/null)" || fail
[[ -d "$output_dir" && ! -L "$output_dir" ]] || fail
expected_name="maverick-${expected_version}-pilot-${target}.cdx.json"
output_name="$(basename "$output_path" 2>/dev/null)" || fail
[[ "$output_name" == "$expected_name" ]] || fail

current_stage=environment
[[ -x "$verifier" ]] || fail
command -v jq >/dev/null 2>&1 || fail

current_stage=source
manifest_version="$(
  awk -F'"' '/^version =/ {print $2; exit}' "$repo_root/Cargo.toml" 2>/dev/null
)" || fail
[[ "$manifest_version" == "$expected_version" ]] || fail
current_revision="$(
  git -C "$repo_root" rev-parse HEAD 2>/dev/null
)" || fail
[[ "$current_revision" == "$expected_revision" ]] || fail
git -C "$repo_root" cat-file -e "$expected_revision^{commit}" \
  >/dev/null 2>&1 || fail

current_stage=environment
cargo_bin="${CARGO_BIN:-}"
if [[ -z "$cargo_bin" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    cargo_bin="$(command -v cargo 2>/dev/null)" || fail
  elif [[ -n "${HOME:-}" && -x "${HOME}/.cargo/bin/cargo" ]]; then
    cargo_bin="${HOME}/.cargo/bin/cargo"
  else
    fail
  fi
fi
{
  "$cargo_bin" --version | grep -Eq '^cargo 1\.97\.1 '
} >/dev/null 2>&1 || fail

cyclonedx_bin="${CARGO_CYCLONEDX_BIN:-}"
if [[ -z "$cyclonedx_bin" ]]; then
  cyclonedx_bin="$(command -v cargo-cyclonedx 2>/dev/null || true)"
fi
[[ -x "$cyclonedx_bin" ]] || fail
tool_version="$(
  "$cyclonedx_bin" cyclonedx --version 2>/dev/null
)" || fail
[[ "$tool_version" == "cargo-cyclonedx-cyclonedx $EXPECTED_TOOL_VERSION" ]] ||
  fail

current_stage=snapshot
private_tmp="$(mktemp -d /tmp/maverick-sbom-generate.XXXXXX 2>/dev/null)" ||
  fail
chmod 0700 "$private_tmp" >/dev/null 2>&1 || fail
snapshot_root="$private_tmp/source"
mkdir -m 0700 "$snapshot_root" >/dev/null 2>&1 || fail

status_before="$private_tmp/status-before"
status_after="$private_tmp/status-after"
git -C "$repo_root" status --porcelain=v1 --untracked-files=all \
  2>/dev/null >"$status_before" || fail

locks=(
  Cargo.lock
  fuzz/Cargo.lock
  spikes/tun-engine-comparison/smoltcp-harness/Cargo.lock
)
lock_hashes_before="$private_tmp/lock-hashes-before"
lock_hashes_after="$private_tmp/lock-hashes-after"
: 2>/dev/null >"$lock_hashes_before" || fail
for lock_path in "${locks[@]}"; do
  [[ -f "$repo_root/$lock_path" && ! -L "$repo_root/$lock_path" ]] || fail
  lock_digest="$(sha256_file "$repo_root/$lock_path")" || fail
  [[ "$lock_digest" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s  %s\n' "$lock_digest" "$lock_path" \
    2>/dev/null >>"$lock_hashes_before" || fail
done

{
  git -C "$repo_root" archive --format=tar "$expected_revision" |
    tar -xf - -C "$snapshot_root"
} >/dev/null 2>&1 || fail
[[ -f "$snapshot_root/Cargo.lock" ]] || fail
[[ -f "$snapshot_root/crates/maverick-cli/Cargo.toml" ]] || fail
[[ ! -e "$snapshot_root/.git" ]] || fail

metadata_wrapper="$private_tmp/cargo-metadata-only"
# These single quotes deliberately preserve variables for the generated wrapper.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  '[[ $# -ge 1 && "$1" == "metadata" ]] || exit 64' \
  'exec "${MAVERICK_REAL_CARGO:?}" "$@" --locked --offline' \
  2>/dev/null >"$metadata_wrapper" || fail
chmod 0700 "$metadata_wrapper" >/dev/null 2>&1 || fail

current_stage=source
source_epoch="$(
  git -C "$repo_root" show -s --format=%ct "$expected_revision" 2>/dev/null
)" || fail
[[ "$source_epoch" =~ ^[0-9]+$ ]] || fail
if source_timestamp="$(
  date -u -r "$source_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
)"; then
  :
elif source_timestamp="$(
  date -u -d "@$source_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
)"; then
  :
else
  fail
fi

current_stage=generation
generation_log="$private_tmp/generation.log"
generation_status=0
{
  (
    cd "$snapshot_root" || exit 1
    exec env \
      CARGO="$metadata_wrapper" \
      CARGO_NET_OFFLINE=true \
      MAVERICK_REAL_CARGO="$cargo_bin" \
      SOURCE_DATE_EPOCH="$source_epoch" \
      "$cyclonedx_bin" cyclonedx \
      --manifest-path crates/maverick-cli/Cargo.toml \
      --format json \
      --spec-version 1.5 \
      --describe binaries \
      --target "$target" \
      --target-in-filename \
      --all \
      --no-build-deps \
      --no-default-features \
      --features maverick-cli/browser-tls \
      -qq
  ) >"$generation_log" 2>&1
} 2>/dev/null || generation_status=$?
[[ "$generation_status" -eq 0 ]] || fail

current_stage=candidate
candidate=""
candidate_count=0
candidate_files="$private_tmp/candidate-files"
find "$snapshot_root" -type f ! -type l -name '*.cdx.json' -print0 \
  2>/dev/null >"$candidate_files" || fail
chmod 0600 "$candidate_files" >/dev/null 2>&1 || fail
candidate_open_status=0
{
  exec 3<"$candidate_files"
} 2>/dev/null || candidate_open_status=$?
[[ "$candidate_open_status" -eq 0 ]] || fail
while IFS= read -r -d '' generated; do
  candidate_status=0
  jq -e \
    --arg version "$expected_version" \
    --arg target "$target" \
    '
      .metadata.component.type == "application" and
      .metadata.component.name == "maverick" and
      .metadata.component.version == $version and
      (.metadata.component.purl |
        startswith("pkg:cargo/maverick-cli@" + $version)) and
      ([.metadata.properties[]? |
        select(.name == "cdx:rustc:sbom:target:triple" and .value == $target)] |
        length == 1)
    ' "$generated" >/dev/null 2>&1 || candidate_status=$?
  case "$candidate_status" in
    0)
      candidate="$generated"
      candidate_count=$((candidate_count + 1))
      ;;
    1) ;;
    *) fail ;;
  esac
done <&3
{
  exec 3<&-
} 2>/dev/null || fail
[[ "$candidate_count" -eq 1 && -n "$candidate" ]] || fail

jq -e \
  'has("serialNumber") | not' \
  "$candidate" >/dev/null 2>&1 || fail

current_stage=normalization
normalized="$private_tmp/normalized.cdx.json"
exact_vcs="${PUBLIC_REPOSITORY}/tree/${expected_revision}"
jq -S \
  --arg schema "http://cyclonedx.org/schema/bom-1.5.schema.json" \
  --arg timestamp "$source_timestamp" \
  --arg vcs "$exact_vcs" '
  def canonical_purl:
    sub("\\?download_url=[^#]*"; "");
  ([.metadata.component] + .components) as $items |
  ($items | map(
    if (.purl | type) != "string" or (."bom-ref" | type) != "string"
    then error("missing identity")
    else (.purl | canonical_purl)
    end)) as $canonical |
  if ($canonical | length) != ($canonical | unique | length)
  then error("duplicate canonical identity")
  else .
  end |
  (reduce $items[] as $component ({};
    . + {($component."bom-ref"): ($component.purl | canonical_purl)})) as $refs |
  ."$schema" = $schema |
  .metadata.timestamp = $timestamp |
  .metadata.component as $root |
  .metadata.component.purl = ($root.purl | canonical_purl) |
  .metadata.component."bom-ref" = $refs[$root."bom-ref"] |
  .metadata.component.externalReferences = (
    ([.metadata.component.externalReferences[]? | select(.type != "vcs")] +
     [{"type":"vcs","url":$vcs}]) |
    sort_by(.type, .url)
  ) |
  .components = (
    [.components[] as $component |
      $component |
      .purl = ($component.purl | canonical_purl) |
      ."bom-ref" = $refs[$component."bom-ref"] |
      if .externalReferences
      then .externalReferences |= sort_by(.type, .url)
      else .
      end] |
    sort_by(."bom-ref")
  ) |
  .dependencies = (
    [.dependencies[] |
      .ref = ($refs[.ref] // error("unknown dependency ref")) |
      .dependsOn = (
        [(.dependsOn // [])[] |
          $refs[.] // error("unknown dependsOn ref")] |
        sort
      )] |
    sort_by(.ref)
  )
' "$candidate" 2>/dev/null >"$normalized" || fail
chmod 0600 "$normalized" >/dev/null 2>&1 || fail

mv "$normalized" "$private_tmp/$expected_name" >/dev/null 2>&1 || fail
current_stage=verification
"$verifier" \
  --sbom "$private_tmp/$expected_name" \
  --expected-version "$expected_version" \
  --expected-revision "$expected_revision" \
  --expected-target "$target" \
  --verification-level full \
  --source-root "$repo_root" >/dev/null 2>&1 || fail

current_stage=integrity
: 2>/dev/null >"$lock_hashes_after" || fail
for lock_path in "${locks[@]}"; do
  lock_digest="$(sha256_file "$repo_root/$lock_path")" || fail
  [[ "$lock_digest" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s  %s\n' "$lock_digest" "$lock_path" \
    2>/dev/null >>"$lock_hashes_after" || fail
done
cmp -s "$lock_hashes_before" "$lock_hashes_after" \
  >/dev/null 2>&1 || fail
git -C "$repo_root" status --porcelain=v1 --untracked-files=all \
  2>/dev/null >"$status_after" || fail
cmp -s "$status_before" "$status_after" >/dev/null 2>&1 || fail

current_stage=output
install -m 0600 "$private_tmp/$expected_name" "$output_path" \
  >/dev/null 2>&1 || fail
printf 'target-aware CycloneDX SBOM generated: %s\n' "$expected_name" \
  2>/dev/null || fail
