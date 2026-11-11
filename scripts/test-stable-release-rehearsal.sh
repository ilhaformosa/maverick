#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

# A private, tagless packaging fixture, never a releasable source revision.
# No remote, gh invocation, deployment or publication occurs here.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
previous_dir=""
output=""
fail() { echo "Stable release rehearsal failed" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --previous-dir) [[ $# -ge 2 && -z "$previous_dir" ]] || fail; previous_dir="$2"; shift 2 ;;
    --output) [[ $# -ge 2 && -z "$output" ]] || fail; output="$2"; shift 2 ;;
    *) fail ;;
  esac
done
[[ -d "$previous_dir" && -n "$output" && ! -e "$output" && ! -L "$output" ]] || fail
previous_dir="$(cd "$previous_dir" && pwd)"
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)" ]] || fail
source_revision="$(git -C "$repo_root" rev-parse HEAD)"
source_version="$(awk -F'"' '/^version =/ {print $2; exit}' "$repo_root/Cargo.toml")"
"$repo_root/scripts/release-channel.sh" "$source_version" >/dev/null
target="$(rustc -vV | awk '/^host:/ {print $2}')"
case "$target" in aarch64-apple-darwin | x86_64-unknown-linux-gnu) ;; *) fail ;; esac

mkdir -m 0700 "$output"
output="$(cd "$output" && pwd)"
fixture="$output/source"
mkdir -m 0700 "$fixture"
git init -q "$fixture"
# Local object transfer retains historical versions required by the existing
# SBOM regression suite. No remote is configured and no tags are fetched.
git -C "$fixture" fetch --quiet --no-tags "$repo_root" "$source_revision"
git -C "$fixture" checkout --quiet --detach FETCH_HEAD
# Preserve source attribution in this local-only synthetic snapshot; do not
# change the user's configuration or invent a product author.
git -C "$fixture" config user.name "$(git -C "$repo_root" show -s --format=%an "$source_revision")"
git -C "$fixture" config user.email "$(git -C "$repo_root" show -s --format=%ae "$source_revision")"
# Change only package version fields in the isolated source fixture. Registry
# versions/checksums stay locked; the actual project and Git refs are untouched.
awk '
  /^\[workspace.package\]$/ { package = 1 }
  package && /^version =/ { print "version = \"1.2.0\""; package = 0; next }
  { print }
' "$fixture/Cargo.toml" >"$fixture/Cargo.toml.new"
mv "$fixture/Cargo.toml.new" "$fixture/Cargo.toml"
for lock in Cargo.lock crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.lock; do
  awk -v source_version="$source_version" '
    /^\[\[package\]\]$/ { package = 0 }
    /^name = "maverick-/ { package = 1 }
    package && $0 == "version = \"" source_version "\"" { print "version = \"1.2.0\""; package = 0; next }
    { print }
  ' "$fixture/$lock" >"$fixture/$lock.new"
  mv "$fixture/$lock.new" "$fixture/$lock"
done
# The standalone H3 fixture has its own version/workspace. Verify its lock
# still matches, instead of treating the main package's build as proof of it.
cargo metadata --locked --offline --format-version 1 --features proxy \
  --manifest-path "$fixture/crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml" >/dev/null
git -C "$fixture" add .
git -C "$fixture" -c commit.gpgsign=false commit --allow-empty -qm 'Synthetic Stable packaging rehearsal; not a release'
fixture_revision="$(git -C "$fixture" rev-parse HEAD)"
[[ -z "$(git -C "$fixture" remote)" && -z "$(git -C "$fixture" tag)" ]] || fail
{
  echo 'NOT A RELEASE: isolated Stable-format packaging rehearsal'
  echo "source_revision: $source_revision"
  echo "fixture_revision: $fixture_revision"
  echo "target: $target"
  echo 'The fixture is not a public source revision or independent release qualification.'
} >"$output/REHEARSAL.txt"

export MAVERICK_PILOT_BUILD_DIR="${MAVERICK_PILOT_BUILD_DIR:-$repo_root/target/pilot-artifact}"
(
  cd "$fixture"
  ./scripts/build-pilot.sh
)
archive="$fixture/dist/maverick-1.2.0-pilot-${target}.tar.gz"
sbom="$fixture/dist/maverick-1.2.0-pilot-${target}.cdx.json"
"$repo_root/scripts/verify-pilot-artifact.sh" --archive "$archive" \
  --expected-version 1.2.0 --expected-revision "$fixture_revision" \
  --expected-target "$target" --verification-level native
"$fixture/scripts/generate-cyclonedx-sbom.sh" --expected-version 1.2.0 \
  --expected-revision "$fixture_revision" --target "$target" --output "$sbom"
"$repo_root/scripts/verify-cyclonedx-sbom.sh" --sbom "$sbom" \
  --expected-version 1.2.0 --expected-revision "$fixture_revision" \
  --expected-target "$target" --verification-level full --source-root "$fixture"
"$fixture/scripts/test-cyclonedx-sbom.sh"
"$repo_root/scripts/test-n-minus-one-release-drill.sh" --target "$target" \
  --previous-archive "$previous_dir/maverick-1.2.0-beta.4-pilot-${target}.tar.gz" \
  --previous-checksum "$previous_dir/maverick-1.2.0-beta.4-pilot-${target}.tar.gz.sha256" \
  --candidate-archive "$archive" --candidate-checksum "$archive.sha256" \
  --candidate-version 1.2.0 --candidate-revision "$fixture_revision"
[[ "$(git -C "$repo_root" rev-parse HEAD)" == "$source_revision" ]] || fail
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)" ]] || fail
echo "Stable format native/SBOM/Beta.4 rollback rehearsal OK: $target; source $source_revision; fixture $fixture_revision"
