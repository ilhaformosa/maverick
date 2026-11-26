#!/usr/bin/env bash
# Compare the installed files from two native archives on loopback.
set -euo pipefail
umask 077
export LC_ALL=C
[[ $# -eq 2 ]] || { echo "usage: $0 BASELINE_ARCHIVE|--all-published CANDIDATE_ARCHIVE" >&2; exit 1; }
candidate_archive="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
script_dir="$(cd "$(dirname "$0")" && pwd)"
target="$(rustc -vV | awk '/^host:/ {print $2}')"
case "$(uname -sm)/$target" in
  "Darwin arm64/aarch64-apple-darwin" | "Linux x86_64/x86_64-unknown-linux-gnu") ;;
  *) echo "unsupported native host" >&2; exit 1 ;;
esac

# Published versions in order: version, tagged commit, macOS SHA-256, Linux SHA-256.
baselines=(
  "1.2.0 4ff413039a39aaa1a157080ca233e64dfe87bcb1 e6e109978168dd9b89f9d5a5db9eb75cc31da0e9fcc700f1638c3b0735ca6a71 9fbe1664cc4b4f7ff321ff66149a525e4a2f142b36e1617b53948d28786c5bf2"
  "1.2.1 e9c3673879a4e42870c76095521ff2f382c73ea2 fa4b06f000402a6b2707de05bb9bb68e828a230e31c4bfb2176c9829fba60238 683383108b2281989222ca7265c1f3d5446cef243e64c76d72aa1f0625ca1b84"
  "1.2.2 04049de772722bb6dce1d5b92e5e163b1d56a78d 403c64540ba289423470c6a0250c63ce73c02381f5c0ac405ad8cdc40cceac8b ff53efb0b9cfd3a3ad82e495d49a204d05fd743e13455babda3a635fd7d36cd5"
  "1.2.3 69a3cc8441becd5b22cc6d763d33f54213d049f7 f27077c3d0209b0b3c5418ac83f1621ba8cded16f89eaca87c700cefd18365ee 24e22d78bcf26936e16134c6ff47e720577b77005b4c10c75cfadd660fda5c7e"
)
latest="${baselines[${#baselines[@]}-1]%% *}"
if [[ "$1" == --all-published ]]; then
  downloads="$(mktemp -d)"
  trap 'rm -rf "$downloads"' EXIT
  for record in "${baselines[@]}"; do
    baseline_version="${record%% *}"
    archive="maverick-${baseline_version}-pilot-${target}.tar.gz"
    for file in "$archive" "$archive.sha256"; do
      curl --fail --silent --show-error --location --retry 2 \
        "https://github.com/ilhaformosa/maverick/releases/download/v${baseline_version}/$file" -o "$downloads/$file"
    done
    "$script_dir/test-stable-patch-interop.sh" "$downloads/$archive" "$candidate_archive"
  done
  exit 0
fi

base_archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
baseline_sha=""
for record in "${baselines[@]}"; do
  read -r baseline_version baseline_revision mac_sha linux_sha <<<"$record"
  if [[ "${base_archive##*/}" == "maverick-${baseline_version}-pilot-${target}.tar.gz" ]]; then
    baseline_sha="$linux_sha"
    if [[ "$target" == aarch64-apple-darwin ]]; then baseline_sha="$mac_sha"; fi
    break
  fi
done
[[ -n "$baseline_sha" ]] || { echo "unsupported baseline archive" >&2; exit 1; }
cd "$script_dir/.."
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}
[[ "$(hash_file "$base_archive")" == "$baseline_sha" ]]
revision="$(git rev-parse HEAD)"
version="$(awk -F'"' '/^version =/ {print $2; exit}' Cargo.toml)"
candidate_sha="$(hash_file "$candidate_archive")"
./scripts/verify-pilot-artifact.sh --archive "$base_archive" --expected-version "$baseline_version" \
  --expected-revision "$baseline_revision" --expected-target "$target" --verification-level static
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
export MAVERICK_BASELINE_VERSION="$baseline_version"
export MAVERICK_BASELINE_CLI="$scratch/baseline/maverick-pilot/maverick"
export MAVERICK_CANDIDATE_CLI="$scratch/candidate/maverick-pilot/maverick"
# Run the handoff suite once per native candidate, using the same installed
# executable as the current-stable upgrade drill.
if [[ "$baseline_version" == "$latest" ]]; then
  cargo test --locked -p maverick-cli --no-default-features --features experimental-h3 --test config_handoff
  rollover=credential_rollover::packaged_credential_rollover_and_restore
  for role in baseline candidate; do
    MAVERICK_CANDIDATE_CLI="$scratch/$role/maverick-pilot/maverick" \
      cargo test --locked -p maverick-cli --no-default-features --features experimental-h3 \
        --test h3_product "$rollover" -- --exact --ignored | tee "$scratch/rollover"
    grep -Fxq "test $rollover ... ok" "$scratch/rollover"
    echo "Credential rollover: $role passed all four phases"
  done
fi
cargo test --locked -p maverick-tests --test end_to_end \
  package_interop::stable_patch_package_interop -- --exact --ignored --nocapture | tee "$scratch/result"
grep -Fxq 'Stable patch package matrix: 30/30 passed' "$scratch/result"
[[ "$(hash_file "$candidate_archive")" == "$candidate_sha" ]]
printf 'Verified %s: baseline %s (%s) %s, candidate %s (%s) %s\n' \
  "$target" "$baseline_version" "$baseline_revision" "$baseline_sha" "$version" "$revision" "$candidate_sha"
