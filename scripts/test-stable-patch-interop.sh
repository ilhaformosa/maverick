#!/usr/bin/env bash
# Compare the installed files from two native archives on loopback.
set -euo pipefail
umask 077
export LC_ALL=C
[[ $# -eq 2 ]] || { echo "usage: $0 BASELINE_ARCHIVE CANDIDATE_ARCHIVE" >&2; exit 1; }
base_archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
candidate_archive="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
cd "$(dirname "$0")/.."
target="$(rustc -vV | awk '/^host:/ {print $2}')"
case "$(uname -sm)/$target" in
  "Darwin arm64/aarch64-apple-darwin") baseline_sha=e6e109978168dd9b89f9d5a5db9eb75cc31da0e9fcc700f1638c3b0735ca6a71 ;;
  "Linux x86_64/x86_64-unknown-linux-gnu") baseline_sha=9fbe1664cc4b4f7ff321ff66149a525e4a2f142b36e1617b53948d28786c5bf2 ;;
  *) echo "unsupported native host" >&2; exit 1 ;;
esac
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}
[[ "$(hash_file "$base_archive")" == "$baseline_sha" ]]
revision="$(git rev-parse HEAD)"
version="$(awk -F'"' '/^version =/ {print $2; exit}' Cargo.toml)"
candidate_sha="$(hash_file "$candidate_archive")"
./scripts/verify-pilot-artifact.sh --archive "$base_archive" --expected-version 1.2.0 \
  --expected-revision 4ff413039a39aaa1a157080ca233e64dfe87bcb1 --expected-target "$target" --verification-level static
./scripts/verify-pilot-artifact.sh --archive "$candidate_archive" --expected-version "$version" \
  --expected-revision "$revision" --expected-target "$target" --verification-level static
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
for role in baseline candidate; do
  mkdir "$scratch/$role"
  archive="$candidate_archive"
  if [[ "$role" == baseline ]]; then archive="$base_archive"; fi
  tar -xzf "$archive" -C "$scratch/$role" maverick-pilot/maverick
done
export MAVERICK_BASELINE_CLI="$scratch/baseline/maverick-pilot/maverick"
export MAVERICK_CANDIDATE_CLI="$scratch/candidate/maverick-pilot/maverick"
cargo test --locked -p maverick-tests --test end_to_end \
  package_interop::stable_patch_package_interop -- --exact --ignored --nocapture | tee "$scratch/result"
grep -Fxq 'Stable patch package matrix: 30/30 passed' "$scratch/result"
[[ "$(hash_file "$candidate_archive")" == "$candidate_sha" ]]
printf 'Verified %s: 1.2.0 %s, %s %s, source %s\n' "$target" "$baseline_sha" "$version" "$candidate_sha" "$revision"
