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

version="$(awk -F'"' '/^version =/ {print $2; exit}' "$repo_root/Cargo.toml")"
target="${MAVERICK_PILOT_TARGET:-$("$rustc_bin" -vV | awk '/^host:/ {print $2}')}"
archive_name="maverick-${version}-pilot-${target}.tar.gz"
archive_path="$repo_root/dist/$archive_name"
build_dir="${MAVERICK_PILOT_BUILD_DIR:-$repo_root/target/pilot-artifact}"

if [[ -e "$output_dir" || -e "$archive_path" || -e "$archive_path.sha256" ]]; then
  echo "refusing to overwrite an existing pilot artifact under dist/" >&2
  exit 1
fi

cd "$repo_root"

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

1. Confirm the binary and run the local product check:
   ./maverick version
   ./maverick user-smoke

2. Generate fresh credentials and two local configs on this machine:
   ./maverick gen-config
   chmod 600 client.generated.yaml server.generated.yaml

3. Before any real-network use, replace every example hostname and certificate
   path in both generated YAML files. Never reuse configs from a public archive.

4. Validate:
   ./maverick check-config --kind server -c server.generated.yaml
   ./maverick check-config --kind client -c client.generated.yaml

5. Stop here for local rehearsal. Generated configs select the H2 carrier but
   leave CDN fronting disabled. A real-network pilot still requires an explicit
   owner decision accepting or rejecting TLS termination at the CDN edge.

6. Point only the chosen application at Maverick's loopback SOCKS5 listener.
   Do not change system proxy, DNS, routes, firewall, or VPN settings.

This artifact is experimental alpha software, provided without warranty. It is
not production-ready, anonymous, censorship-resistant, or browser-identical.
GUIDE

{
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    source_state="dirty"
  else
    source_state="clean"
  fi
  echo "repository: https://github.com/ilhaformosa/maverick"
  echo "git_revision: $(git rev-parse HEAD)"
  echo "source_state: $source_state"
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

tar -czf "$archive_path" -C "$repo_root/dist" "$(basename "$output_dir")"
(
  cd "$repo_root/dist"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_name" >"$archive_name.sha256"
  else
    sha256sum "$archive_name" >"$archive_name.sha256"
  fi
)

echo "pilot folder: dist/maverick-pilot"
echo "shareable pilot archive: dist/$archive_name"
