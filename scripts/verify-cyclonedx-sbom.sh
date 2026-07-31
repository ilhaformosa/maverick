#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

readonly MAX_SBOM_BYTES=8388608
readonly EXPECTED_TOOL_VERSION=0.5.9
readonly EXPECTED_SCHEMA="http://cyclonedx.org/schema/bom-1.5.schema.json"
readonly PUBLIC_REPOSITORY="https://github.com/ilhaformosa/maverick"

private_tmp=""
sbom_path=""
expected_version=""
expected_revision=""
expected_target=""
verification_level=""
source_root=""

fail() {
  echo "sbom verification failed: $1" >&2
  exit 1
}

cleanup() {
  case "$private_tmp" in
    /tmp/maverick-sbom-verify.*)
      [[ ! -d "$private_tmp" ]] ||
        find "$private_tmp" -depth -delete >/dev/null 2>&1 || true
      ;;
  esac
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

file_size() {
  local measured
  measured="$(
    {
      wc -c <"$1" |
        tr -d '[:space:]'
    } 2>/dev/null
  )" || fail input
  [[ "$measured" =~ ^[0-9]+$ ]] || fail input
  printf '%s\n' "$measured"
}

sha256_file() {
  local digest
  if command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')" ||
      fail input
  elif command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$1" 2>/dev/null | awk '{print $1}')" ||
      fail input
  else
    fail tool
  fi
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail input
  printf '%s\n' "$digest"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sbom)
      [[ $# -ge 2 && -z "$sbom_path" ]] || fail arguments
      sbom_path="$2"
      shift 2
      ;;
    --expected-version)
      [[ $# -ge 2 && -z "$expected_version" ]] || fail arguments
      expected_version="$2"
      shift 2
      ;;
    --expected-revision)
      [[ $# -ge 2 && -z "$expected_revision" ]] || fail arguments
      expected_revision="$2"
      shift 2
      ;;
    --expected-target)
      [[ $# -ge 2 && -z "$expected_target" ]] || fail arguments
      expected_target="$2"
      shift 2
      ;;
    --verification-level)
      [[ $# -ge 2 && -z "$verification_level" ]] || fail arguments
      verification_level="$2"
      shift 2
      ;;
    --source-root)
      [[ $# -ge 2 && -z "$source_root" ]] || fail arguments
      source_root="$2"
      shift 2
      ;;
    *)
      fail arguments
      ;;
  esac
done

[[ -n "$sbom_path" && -n "$expected_version" ]] || fail arguments
[[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || fail arguments
case "$expected_target" in
  x86_64-unknown-linux-gnu | aarch64-apple-darwin) ;;
  *) fail arguments ;;
esac
case "$verification_level" in
  structural | full) ;;
  *) fail arguments ;;
esac
[[ -d "$source_root" && ! -L "$source_root" ]] || fail source
command -v jq >/dev/null 2>&1 || fail tool

expected_name="maverick-${expected_version}-pilot-${expected_target}.cdx.json"
[[ "$(basename "$sbom_path")" == "$expected_name" ]] || fail basename
[[ -f "$sbom_path" && ! -L "$sbom_path" ]] || fail input
input_bytes="$(file_size "$sbom_path")"
[[ "$input_bytes" -le "$MAX_SBOM_BYTES" ]] || fail oversized
input_sha="$(sha256_file "$sbom_path")"

private_tmp="$(mktemp -d /tmp/maverick-sbom-verify.XXXXXX 2>/dev/null)" ||
  fail input
chmod 0700 "$private_tmp" >/dev/null 2>&1 || fail input
sbom_copy="$private_tmp/input.cdx.json"
cp "$sbom_path" "$sbom_copy" >/dev/null 2>&1 || fail input
chmod 0600 "$sbom_copy" >/dev/null 2>&1 || fail input
[[ "$(file_size "$sbom_copy")" == "$input_bytes" ]] || fail mutation
[[ "$(sha256_file "$sbom_copy")" == "$input_sha" ]] || fail mutation
cmp -s "$sbom_path" "$sbom_copy" || fail mutation

documents_file="$private_tmp/documents.json"
jq -s . "$sbom_copy" >"$documents_file" 2>/dev/null || fail json
chmod 0600 "$documents_file" >/dev/null 2>&1 || fail json
jq -e 'length == 1 and (.[0] | type == "object")' \
  "$documents_file" >/dev/null 2>&1 || fail document-count
sbom_document="$private_tmp/document.json"
jq -S '.[0]' "$documents_file" >"$sbom_document" 2>/dev/null ||
  fail document-count
chmod 0600 "$sbom_document" >/dev/null 2>&1 || fail document-count

git -C "$source_root" cat-file -e "$expected_revision^{commit}" \
  >/dev/null 2>&1 || fail source
revision_manifest="$private_tmp/revision-Cargo.toml"
git -C "$source_root" show "$expected_revision:Cargo.toml" \
  >"$revision_manifest" 2>/dev/null || fail source
chmod 0600 "$revision_manifest" >/dev/null 2>&1 || fail source
revision_version="$(
  awk -F'"' '/^version =/ {print $2; exit}' "$revision_manifest"
)" || fail source-version
[[ "$revision_version" == "$expected_version" ]] || fail source-version
source_epoch="$(git -C "$source_root" show -s --format=%ct "$expected_revision" 2>/dev/null)" ||
  fail source
[[ "$source_epoch" =~ ^[0-9]+$ ]] || fail source
if source_timestamp="$(date -u -r "$source_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
  :
elif source_timestamp="$(date -u -d "@$source_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
  :
else
  fail source
fi

jq -e \
  --arg schema "$EXPECTED_SCHEMA" \
  '.bomFormat == "CycloneDX" and
   .specVersion == "1.5" and
   .version == 1 and
   ."$schema" == $schema' \
  "$sbom_document" >/dev/null 2>&1 || fail identity

jq -e 'has("serialNumber") | not' "$sbom_document" >/dev/null 2>&1 ||
  fail serial
jq -e --arg timestamp "$source_timestamp" \
  '.metadata.timestamp == $timestamp' \
  "$sbom_document" >/dev/null 2>&1 || fail timestamp

jq -e --arg tool_version "$EXPECTED_TOOL_VERSION" \
  '.metadata.tools | type == "array" and length == 1 and
   .[0].vendor == "CycloneDX" and
   .[0].name == "cargo-cyclonedx" and
   .[0].version == $tool_version' \
  "$sbom_document" >/dev/null 2>&1 || fail tool-identity

root_purl="pkg:cargo/maverick-cli@${expected_version}#src/main.rs"
jq -e --arg version "$expected_version" --arg purl "$root_purl" \
  '.metadata.component.type == "application" and
   .metadata.component.name == "maverick" and
   .metadata.component.version == $version and
   .metadata.component.purl == $purl and
   .metadata.component."bom-ref" == $purl' \
  "$sbom_document" >/dev/null 2>&1 || fail root

jq -e --arg target "$expected_target" \
  '.metadata.properties | type == "array" and length == 1 and
   .[0].name == "cdx:rustc:sbom:target:triple" and
   .[0].value == $target' \
  "$sbom_document" >/dev/null 2>&1 || fail target

expected_vcs="${PUBLIC_REPOSITORY}/tree/${expected_revision}"
jq -e --arg vcs "$expected_vcs" \
  '[.metadata.component.externalReferences[]? | select(.type == "vcs")] |
   length == 1 and .[0].url == $vcs' \
  "$sbom_document" >/dev/null 2>&1 || fail vcs

privacy_pattern='/U''sers/|/ho''me/[^/[:space:]"]+|fi''le://'
privacy_pattern+='|/tm''p/maverick-sbom|/pri''vate/tm''p/maverick-sbom'
privacy_pattern+='|/runner/_wo''rk/|local''host'
privacy_pattern+='|(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
privacy_pattern+='|192\.168\.[0-9]{1,3}\.[0-9]{1,3}'
privacy_pattern+='|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})'
privacy_pattern+='([^0-9]|$)|BEGIN (RSA |EC |OPENSSH )?PRI''VATE KEY'
privacy_pattern+='|ssh''-rsa|gh[pousr]_[A-Za-z0-9_]{20,}'
privacy_pattern+='|sk-(proj-|svcacct-)?[A-Za-z0-9_-]{40,}'
privacy_pattern+='|dop_v1_[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}'
privacy_pattern+='|Bearer[[:space:]]+[A-Za-z0-9._-]{20,}'
privacy_pattern+='|OPENAI_''API_KEY|DIGITALOCEAN_''API_TOKEN'
privacy_pattern+='|AWS_SECRET_''ACCESS_KEY'
canonical_json="$private_tmp/canonical.json"
jq -cS . "$sbom_document" >"$canonical_json" 2>/dev/null ||
  fail privacy
chmod 0600 "$canonical_json" >/dev/null 2>&1 || fail privacy
decoded_occurrences="$private_tmp/decoded-occurrences"
jq --stream -r '
  . as $item |
  ($item[0][]? | select(type == "string")),
  ($item[1]? | select(type == "string"))
' "$sbom_copy" >"$decoded_occurrences" 2>/dev/null ||
  fail privacy
chmod 0600 "$decoded_occurrences" >/dev/null 2>&1 || fail privacy

privacy_scan() {
  local input_file="$1"
  local scan_status=0
  grep -E -i -q "$privacy_pattern" "$input_file" 2>/dev/null ||
    scan_status=$?
  case "$scan_status" in
    0) fail privacy ;;
    1) ;;
    *) fail privacy ;;
  esac
}

privacy_scan "$sbom_copy"
privacy_scan "$canonical_json"
privacy_scan "$decoded_occurrences"

jq -e '
  (.components | type == "array" and length > 0) and
  (all(.components[];
    .type == "library" and
    .scope == "required" and
    (."bom-ref" | type == "string" and startswith("pkg:cargo/")) and
    .purl == ."bom-ref" and
    (.purl | contains("download_url=") | not))) and
  (([.metadata.component."bom-ref"] + [.components[]."bom-ref"]) as $refs |
    ($refs | length) == ($refs | unique | length))
' "$sbom_document" >/dev/null 2>&1 || fail duplicate-ref

jq -e '
  ([.metadata.component."bom-ref"] + [.components[]."bom-ref"] | sort) as $refs |
  (.dependencies | type == "array" and length == ($refs | length)) and
  ([.dependencies[].ref] | sort) as $graph_refs |
  ($graph_refs == $refs) and
  (($graph_refs | length) == ($graph_refs | unique | length))
' "$sbom_document" >/dev/null 2>&1 || fail graph-ref

jq -e '
  ([.metadata.component."bom-ref"] + [.components[]."bom-ref"] | unique) as $refs |
  all(.dependencies[];
    (.dependsOn | type == "array") and
    ((.dependsOn | length) == (.dependsOn | unique | length)) and
    all(.dependsOn[]; . as $dep | $refs | index($dep)))
' "$sbom_document" >/dev/null 2>&1 || fail graph-dependency

if [[ "$verification_level" == "full" ]]; then
  cargo_bin="${CARGO_BIN:-}"
  if [[ -z "$cargo_bin" ]]; then
    if command -v cargo >/dev/null 2>&1; then
      cargo_bin="$(command -v cargo)"
    elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
      cargo_bin="${HOME}/.cargo/bin/cargo"
    else
      fail tool
    fi
  fi
  "$cargo_bin" --version 2>/dev/null |
    grep -Eq '^cargo 1\.97\.1 ' || fail cargo-version

  snapshot_root="$private_tmp/source"
  mkdir -m 0700 "$snapshot_root" >/dev/null 2>&1 || fail source
  git -C "$source_root" archive --format=tar "$expected_revision" 2>/dev/null |
    tar -xf - -C "$snapshot_root" >/dev/null 2>&1 || fail source
  [[ -f "$snapshot_root/Cargo.lock" && ! -L "$snapshot_root/Cargo.lock" ]] ||
    fail source
  [[ -f "$snapshot_root/crates/maverick-cli/Cargo.toml" &&
    ! -L "$snapshot_root/crates/maverick-cli/Cargo.toml" ]] || fail source
  [[ ! -e "$snapshot_root/.git" ]] || fail source

  metadata_file="$private_tmp/metadata.json"
  CARGO_NET_OFFLINE=true "$cargo_bin" metadata \
    --format-version 1 \
    --manifest-path "$snapshot_root/crates/maverick-cli/Cargo.toml" \
    --locked \
    --offline \
    --filter-platform "$expected_target" \
    --no-default-features \
    --features maverick-cli/browser-tls \
    >"$metadata_file" 2>/dev/null || fail metadata
  chmod 0600 "$metadata_file" >/dev/null 2>&1 || fail metadata

  jq -e --arg version "$expected_version" '
    . as $m |
    ($m.resolve.root // "") as $root |
    ([.packages[] | select(.id == $root)] | length == 1) and
    ([.packages[] | select(.id == $root)][0].name == "maverick-cli") and
    ([.packages[] | select(.id == $root)][0].version == $version) and
    ([.resolve.nodes[] | select(.id == $root)][0].features == ["browser-tls"])
  ' "$metadata_file" >/dev/null 2>&1 || fail metadata-root

  expected_components="$private_tmp/expected-components"
  jq -r '
    def normal_closure($nodes; $seen; $frontier):
      if ($frontier | length) == 0 then $seen
      else
        ([ $frontier[] as $id
           | $nodes[$id].deps[]?
           | select(any(.dep_kinds[]?; .kind == null))
           | .pkg ] |
         unique |
         map(select(. as $id | ($seen | index($id) | not)))) as $next |
        normal_closure($nodes; (($seen + $next) | unique); $next)
      end;
    . as $m |
    (reduce $m.resolve.nodes[] as $node ({}; .[$node.id] = $node)) as $nodes |
    normal_closure($nodes; [$m.resolve.root]; [$m.resolve.root]) as $ids |
    $m.packages[] |
    select(.id != $m.resolve.root) |
    select(.id as $id | $ids | index($id)) |
    "\(.name)@\(.version)"
  ' "$metadata_file" | sort >"$expected_components" || fail metadata

  actual_components="$private_tmp/actual-components"
  jq -r '.components[] | "\(.name)@\(.version)"' "$sbom_document" |
    sort >"$actual_components" || fail closure
  expected_duplicates="$private_tmp/expected-duplicates"
  actual_duplicates="$private_tmp/actual-duplicates"
  uniq -d "$expected_components" >"$expected_duplicates" 2>/dev/null ||
    fail ambiguous-identity
  chmod 0600 "$expected_duplicates" >/dev/null 2>&1 ||
    fail ambiguous-identity
  uniq -d "$actual_components" >"$actual_duplicates" 2>/dev/null ||
    fail ambiguous-identity
  chmod 0600 "$actual_duplicates" >/dev/null 2>&1 ||
    fail ambiguous-identity
  [[ ! -s "$expected_duplicates" ]] || fail ambiguous-identity
  [[ ! -s "$actual_duplicates" ]] || fail ambiguous-identity
  cmp -s "$expected_components" "$actual_components" || fail closure
fi

[[ -f "$sbom_path" && ! -L "$sbom_path" ]] || fail mutation
[[ "$(file_size "$sbom_path")" == "$input_bytes" ]] || fail mutation
[[ "$(sha256_file "$sbom_path")" == "$input_sha" ]] || fail mutation
cmp -s "$sbom_path" "$sbom_copy" || fail mutation

if [[ "$verification_level" == "full" ]]; then
  echo "minimal CycloneDX 1.5 contract and locked runtime closure verified"
else
  echo "minimal CycloneDX 1.5 structural contract verified"
fi
