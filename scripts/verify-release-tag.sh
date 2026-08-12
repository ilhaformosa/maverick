#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

fail() {
  echo "release tag verification failed" >&2
  exit 1
}

tag=""
sha=""
version=""
main_ref=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 && -z "$tag" ]] || fail
      tag="$2"
      shift 2
      ;;
    --sha)
      [[ $# -ge 2 && -z "$sha" ]] || fail
      sha="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 && -z "$version" ]] || fail
      version="$2"
      shift 2
      ;;
    --main-ref)
      [[ $# -ge 2 && -z "$main_ref" ]] || fail
      main_ref="$2"
      shift 2
      ;;
    *)
      fail
      ;;
  esac
done

[[ -n "$tag" && -n "$sha" && -n "$version" && -n "$main_ref" ]] || fail
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "$version" =~ ^1\.2\.0-(beta|rc)\.[1-9][0-9]*$ ]] || fail
[[ "$tag" == "v$version" ]] || fail
[[ "$main_ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || fail
[[ "$main_ref" != *..* && "$main_ref" != /* && "$main_ref" != */ ]] || fail

head_commit="$(git rev-parse HEAD 2>/dev/null)" || fail
[[ "$head_commit" == "$sha" ]] || fail

tag_ref="refs/tags/$tag"
tag_object="$(git rev-parse "$tag_ref" 2>/dev/null)" || fail
[[ "$(git cat-file -t "$tag_object" 2>/dev/null)" == "tag" ]] || fail

tag_payload="$(git cat-file -p "$tag_object" 2>/dev/null)" || fail
tag_target="$(printf '%s\n' "$tag_payload" | awk '$1 == "object" {print $2; exit}')"
tag_target_type="$(printf '%s\n' "$tag_payload" | awk '$1 == "type" {print $2; exit}')"
tag_name="$(printf '%s\n' "$tag_payload" | awk '$1 == "tag" {print $2; exit}')"
[[ "$tag_target" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "$tag_target_type" == "commit" && "$tag_name" == "$tag" ]] || fail
[[ "$(git cat-file -t "$tag_target" 2>/dev/null)" == "commit" ]] || fail
[[ "$tag_target" == "$sha" ]] || fail
[[ "$(git rev-parse "$tag_object^{}" 2>/dev/null)" == "$sha" ]] || fail

main_commit="$(git rev-parse "$main_ref^{commit}" 2>/dev/null)" || fail
[[ "$main_commit" =~ ^[0-9a-f]{40}$ ]] || fail
git merge-base --is-ancestor "$sha" "$main_commit" >/dev/null 2>&1 || fail

echo "release tag verification OK"
