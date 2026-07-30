#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/dist/maverick-pilot"
cargo_bin="${CARGO_BIN:-}"
rustc_bin="${RUSTC_BIN:-}"

if [[ -z "$cargo_bin" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    cargo_bin="$(command -v cargo)"
  elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    cargo_bin="${HOME}/.cargo/bin/cargo"
  else
    echo "cargo was not found" >&2
    exit 1
  fi
fi

if [[ -z "$rustc_bin" ]]; then
  if command -v rustc >/dev/null 2>&1; then
    rustc_bin="$(command -v rustc)"
  elif [[ -x "${HOME}/.cargo/bin/rustc" ]]; then
    rustc_bin="${HOME}/.cargo/bin/rustc"
  else
    echo "rustc was not found" >&2
    exit 1
  fi
fi

require_clean_checkout() {
  local source_status
  if ! source_status="$(git status --porcelain=v1 --untracked-files=normal 2>/dev/null)"; then
    echo "unable to verify clean source checkout" >&2
    exit 1
  fi
  if [[ -n "$source_status" ]]; then
    echo "refusing to build a pilot artifact from a dirty checkout" >&2
    exit 1
  fi
}

require_unchanged_source() {
  local current_revision
  if ! current_revision="$(git rev-parse HEAD 2>/dev/null)"; then
    echo "unable to verify source revision" >&2
    exit 1
  fi
  if [[ "$current_revision" != "$source_revision" ]]; then
    echo "refusing to package a changed source revision" >&2
    exit 1
  fi
  require_clean_checkout
}

version="$(awk -F'"' '/^version =/ {print $2; exit}' "$repo_root/Cargo.toml")"
target="${MAVERICK_PILOT_TARGET:-$("$rustc_bin" -vV | awk '/^host:/ {print $2}')}"
if [[ ! "$target" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$target" == *..* ]]; then
  echo "invalid pilot target name" >&2
  exit 1
fi
archive_name="maverick-${version}-pilot-${target}.tar.gz"
archive_path="$repo_root/dist/$archive_name"
build_dir="${MAVERICK_PILOT_BUILD_DIR:-$repo_root/target/pilot-artifact}"

if [[ -e "$output_dir" || -e "$archive_path" || -e "$archive_path.sha256" ]]; then
  echo "refusing to overwrite an existing pilot artifact under dist/" >&2
  exit 1
fi

cd "$repo_root"

if ! source_revision="$(git rev-parse HEAD 2>/dev/null)"; then
  echo "unable to determine source revision" >&2
  exit 1
fi
require_clean_checkout

encoded_rustflags="${CARGO_ENCODED_RUSTFLAGS:-}"
for flag in \
  "--remap-path-prefix=$repo_root=<workspace>" \
  "--remap-path-prefix=${HOME}=<home>"; do
  if [[ -n "$encoded_rustflags" ]]; then
    encoded_rustflags+=$'\x1f'
  fi
  encoded_rustflags+="$flag"
done

build_args=(build --locked --release -p maverick-cli)
if [[ -n "${MAVERICK_PILOT_TARGET:-}" ]]; then
  build_args+=(--target "$target")
fi
build_args+=(--target-dir "$build_dir")

c_prefix_map="-ffile-prefix-map=$repo_root=maverick-src -ffile-prefix-map=${HOME}=build-home"
cflags="${CFLAGS:-}"
cxxflags="${CXXFLAGS:-}"
[[ -z "$cflags" ]] || cflags+=" "
[[ -z "$cxxflags" ]] || cxxflags+=" "
cflags+="$c_prefix_map"
cxxflags+="$c_prefix_map"

CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
  CFLAGS="$cflags" \
  CXXFLAGS="$cxxflags" \
  "$cargo_bin" "${build_args[@]}"

binary_dir="$build_dir/release"
if [[ -n "${MAVERICK_PILOT_TARGET:-}" ]]; then
  binary_dir="$build_dir/$target/release"
fi

mkdir -p "$output_dir"
install -m 0755 "$binary_dir/maverick" "$output_dir/maverick"
install -m 0644 LICENSE "$output_dir/LICENSE"
(
  cd "$output_dir"
  ./maverick version >VERSION.txt
)

strings "$output_dir/maverick" >"$output_dir/.binary-strings"
if grep -E '/U[s]ers/|/home/[^/]+/' "$output_dir/.binary-strings" >/dev/null; then
  find "$output_dir" -maxdepth 1 -type f -name '.binary-strings' -delete
  find "$output_dir" -depth -delete
  echo "pilot binary contains a local build path; do not share it" >&2
  exit 1
fi
find "$output_dir" -maxdepth 1 -type f -name '.binary-strings' -delete

cat >"$output_dir/START_HERE.txt" <<'GUIDE'
Maverick owner pilot

Fast client start

Use this path only when a separately authorized pilot has already provided a
private client.generated.yaml beside the maverick binary. The public archive
never contains that file.

Open a terminal in this folder. Paste the whole block once; each step runs only
if the preceding step succeeded:

chmod 700 . &&
chmod 600 client.generated.yaml &&
(
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS
  else
    sha256sum -c SHA256SUMS
  fi
) &&
./maverick version &&
./maverick user-smoke &&
./maverick client -c ./client.generated.yaml

The final command keeps running. Stop it with Control-C.

Generate new local example configs

If no private client config was provided, generate fresh client and server
examples locally:

./maverick gen-config

The generated files are owner-only. Replace every example hostname and
certificate path before use, then validate both:

./maverick check-config --kind server -c server.generated.yaml
./maverick check-config --kind client -c client.generated.yaml

Generated configs select the H2 carrier but leave provider fronting disabled.
Real-network use still requires a separate owner decision about the environment
and any provider TLS termination.

Point only the chosen application at Maverick's loopback SOCKS5 listener. Do
not change system proxy, DNS, routes, firewall, or VPN settings.

This artifact is experimental prerelease software, provided without warranty. It is
not production-ready, anonymous, censorship-resistant, or browser-identical.
GUIDE

require_unchanged_source

{
  echo "repository: https://github.com/ilhaformosa/maverick"
  echo "git_revision: $source_revision"
  echo "source_state: clean"
  echo "version: $version"
  echo "target: $target"
} >"$output_dir/SOURCE.txt"

(
  cd "$output_dir"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 LICENSE SOURCE.txt START_HERE.txt VERSION.txt maverick >SHA256SUMS
  else
    sha256sum LICENSE SOURCE.txt START_HERE.txt VERSION.txt maverick >SHA256SUMS
  fi
)

chmod 0755 "$output_dir" "$output_dir/maverick"
chmod 0644 \
  "$output_dir/LICENSE" \
  "$output_dir/SHA256SUMS" \
  "$output_dir/SOURCE.txt" \
  "$output_dir/START_HERE.txt" \
  "$output_dir/VERSION.txt"

if tar --version 2>/dev/null | grep -qi 'bsdtar'; then
  COPYFILE_DISABLE=1 tar \
    --format ustar \
    --uid 0 \
    --gid 0 \
    --numeric-owner \
    --no-acls \
    --no-fflags \
    --no-xattrs \
    -czf "$archive_path" \
    -C "$repo_root/dist" \
    "$(basename "$output_dir")"
elif tar --version 2>/dev/null | grep -qi 'GNU tar'; then
  tar \
    --format=ustar \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -czf "$archive_path" \
    -C "$repo_root/dist" \
    "$(basename "$output_dir")"
else
  echo "unsupported tar implementation; expected bsdtar or GNU tar" >&2
  exit 1
fi

(
  cd "$repo_root/dist"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_name" >"$archive_name.sha256"
  else
    sha256sum "$archive_name" >"$archive_name.sha256"
  fi
)
chmod 0644 "$archive_path.sha256"

echo "pilot folder: dist/maverick-pilot"
echo "shareable pilot archive: dist/$archive_name"
