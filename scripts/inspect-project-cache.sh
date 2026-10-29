#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO_BIN:-cargo}"
stat_os="$(uname -s)"

capture() (
  local output="$1" temp metadata target_dir workspace label name source kind profile file hash
  local root_id root_count=0 i relative_source absolute_source dependencies matched
  local roots=() manifest expected symbol
  temp="$(mktemp -d "${TMPDIR:-/tmp}/maverick-cache-inspect.XXXXXX")"
  trap 'rm -rf -- "$temp"' EXIT
  : >"$temp/files"
  for manifest in "$repo_root/Cargo.toml" "$repo_root/crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml"; do
    if ! metadata="$("$cargo_bin" metadata --locked --offline --no-deps --format-version 1 --manifest-path "$manifest" 2>"$temp/metadata-error")"; then
      echo 'project-cache inspection: Cargo metadata failed' >&2
      return 1
    fi
    target_dir="$(jq -r .target_directory <<<"$metadata")"
    workspace="$(jq -r .workspace_root <<<"$metadata")"
    root_id=""
    for ((i = 0; i < root_count; i++)); do
      if [[ "${roots[$i]}" == "$target_dir" ]]; then root_id="target-$i"; fi
    done
    if [[ -z "$root_id" ]]; then
      root_id="target-$root_count"
      roots[root_count]="$target_dir"
      root_count=$((root_count + 1))
    fi
    [[ -d "$target_dir" ]] || continue
    jq -r '. as $m | .packages[] | select(.id as $id | $m.workspace_members | index($id)) |
      . as $p | .targets[] | select(any(.kind[]; . == "bin" or . == "test" or . == "bench")) |
      [($p.name + ":" + .kind[0] + ":" + .name), .name, .src_path, .kind[0]] | @tsv' \
      <<<"$metadata" >"$temp/targets"
    while IFS=$'\t' read -r label name source kind; do
      # rustc depfiles name the crate root first. Match it, not an arbitrary dependency.
      absolute_source="${source// /\\ }"
      relative_source="${source#"$workspace"/}"
      relative_source="${relative_source// /\\ }"
      for profile in "$target_dir"/* "$target_dir"/*/*; do
        [[ -d "$profile/deps" ]] || continue
        for file in "$profile/$name" "$profile/deps/${name//-/_}"-*; do
          [[ -f "$file" && -x "$file" && ! -L "$file" ]] || continue
          if [[ "$file" == "$profile/$name" ]]; then
            [[ "$kind" == bin ]] || continue
          else
            hash="${file##*/}"
            hash="${hash#"${name//-/_}"-}"
            [[ "$hash" =~ ^[0-9a-f]+$ ]] || continue
          fi
          [[ -f "$file.d" ]] || continue
          IFS= read -r dependencies <"$file.d" || true
          dependencies="${dependencies#*: }"
          matched=false
          for expected in "$absolute_source" "$relative_source"; do
            if [[ "$dependencies" == "$expected" || "$dependencies" == "$expected "* ]]; then matched=true; fi
          done
          [[ "$matched" == true ]] || continue
          record_file "$file" binary "$root_id" "$target_dir" "$label" "$temp/files"
          if [[ -d "$file.dSYM" && ! -L "$file.dSYM" ]]; then
            while IFS= read -r -d '' symbol; do
              record_file "$symbol" dsym "$root_id" "$target_dir" "$label" "$temp/files"
            done < <(find "$file.dSYM" -type f -print0)
          fi
        done
      done
    done <"$temp/targets"
  done
  jq -s '{schema: 1, files: (unique_by([.root, .path]) | sort_by(.root, .path))}' "$temp/files" >"$output"
)

record_file() {
  local file="$1" artifact_kind="$2" root_id="$3" target_dir="$4" label="$5" output="$6"
  local fields size modified inode
  if [[ "$stat_os" == Darwin ]]; then
    fields="$(stat -f $'%z\t%Fm\t%i' "$file")"
  else
    fields="$(TZ=UTC stat -c $'%s\t%y\t%i' "$file")"
  fi
  IFS=$'\t' read -r size modified inode <<<"$fields"
  jq -cn --arg root "$root_id" --arg path "${file#"$target_dir"/}" --arg target "$label" \
    --arg kind "$artifact_kind" --argjson size "$size" --arg mtime "$modified" --arg inode "$inode" \
    '{root: $root, path: $path, target: $target, kind: $kind, size: $size, mtime: $mtime, inode: $inode}' >>"$output"
}

compare() {
  jq -nr --slurpfile before "$1" --slurpfile after "$2" '
    def key: [.root, .path] | join("/");
    def inventory($x): $x[0].files | map({key: key, value: .}) | from_entries;
    def stats($files): {files: ($files | length), bytes: ($files | map(.size) | add // 0)};
    def before_bytes($state): [.changes[] | select(.state == $state) | .before.size] | add // 0;
    inventory($before) as $b | inventory($after) as $a |
    [($b | keys[]), ($a | keys[])] | unique | map(. as $k |
      {target: ($a[$k].target // $b[$k].target), before: $b[$k], after: $a[$k],
       state: (if $b[$k] == null then "new" elif $a[$k] == null then "removed"
       elif ([$b[$k].size, $b[$k].mtime, $b[$k].inode] == [$a[$k].size, $a[$k].mtime, $a[$k].inode])
       then "retained" else "rewritten" end)}) as $changes |
    "project-cache: retained means unchanged size/mtime/inode, not proof of Cargo reuse.",
    "project-cache: bytes count logical sizes per path (hardlinks can count twice), not compressed size or disk savings.",
    "project-cache: attribution uses current metadata and the first depfile source.",
    "target\tbefore_files\tbefore_bytes\tafter_files\tafter_bytes\trewritten\tretained\tremoved\tnew\trewritten_before_bytes\tretained_before_bytes\tremoved_before_bytes",
    ((($changes | group_by(.target) | map({target: .[0].target, changes: .})) + [{target: "TOTAL", changes: $changes}])[] |
    stats([.changes[].before | select(. != null)]) as $old |
    stats([.changes[].after | select(. != null)]) as $new |
    [.target, $old.files, $old.bytes, $new.files, $new.bytes,
     ([.changes[] | select(.state == "rewritten")] | length),
     ([.changes[] | select(.state == "retained")] | length),
     ([.changes[] | select(.state == "removed")] | length),
     ([.changes[] | select(.state == "new")] | length),
     before_bytes("rewritten"), before_bytes("retained"), before_bytes("removed")] | @tsv)'
}

case "${1:-}" in
  capture) [[ $# -eq 2 ]] && capture "$2" ;;
  compare) [[ $# -eq 3 ]] && compare "$2" "$3" ;;
  *) echo 'usage: inspect-project-cache.sh capture OUTPUT | compare BEFORE AFTER' >&2; exit 2 ;;
esac
