#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cleanup_paths=()
cleanup() {
  local path
  for path in "${cleanup_paths[@]}"; do
    rm -rf "$path"
  done
}
trap cleanup EXIT

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

rustc_bin="${RUSTC_BIN:-rustc}"
if [[ -x "$HOME/.cargo/bin/rustc" ]]; then
  rustc_bin="$HOME/.cargo/bin/rustc"
fi

version="${MAVERICK_RELEASE_VERSION:-$(awk -F\" '/^version =/ {print $2; exit}' Cargo.toml)}"
target="${MAVERICK_RELEASE_TARGET:-$("$rustc_bin" -vV | awk '/^host:/ {print $2}')}"
features="${MAVERICK_RELEASE_FEATURES:-}"
name="${MAVERICK_RELEASE_NAME:-maverick-${version}-${target}}"
out_dir="$repo_root/dist/$name"

rustflags=(
  "--remap-path-prefix=$repo_root=<workspace>"
)

if [[ -n "${HOME:-}" ]]; then
  rustflags+=("--remap-path-prefix=$HOME=<home>")
fi

cargo_home="${CARGO_HOME:-${HOME:-}/.cargo}"
if [[ -n "$cargo_home" ]]; then
  rustflags+=("--remap-path-prefix=$cargo_home=<cargo-home>")
fi

rustup_home="${RUSTUP_HOME:-${HOME:-}/.rustup}"
if [[ -n "$rustup_home" ]]; then
  rustflags+=("--remap-path-prefix=$rustup_home=<rustup-home>")
fi

encoded_rustflags="${CARGO_ENCODED_RUSTFLAGS:-}"
for flag in "${rustflags[@]}"; do
  if [[ -n "$encoded_rustflags" ]]; then
    encoded_rustflags+=$'\x1f'
  fi
  encoded_rustflags+="$flag"
done

build_args=(build --release --locked -p maverick-cli)
if [[ -n "${MAVERICK_RELEASE_TARGET:-}" ]]; then
  build_args+=(--target "$MAVERICK_RELEASE_TARGET")
fi
if [[ -n "$features" ]]; then
  build_args+=(--features "$features")
fi

echo "==> building ${name}"
CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" "$cargo_bin" "${build_args[@]}"

binary_dir="$repo_root/target/release"
if [[ -n "${MAVERICK_RELEASE_TARGET:-}" ]]; then
  binary_dir="$repo_root/target/$MAVERICK_RELEASE_TARGET/release"
fi

binary="$binary_dir/maverick"
if [[ ! -x "$binary" ]]; then
  echo "missing release binary: $binary" >&2
  exit 1
fi

mkdir -p "$out_dir"
cp "$binary" "$out_dir/maverick"
chmod 0755 "$out_dir/maverick"
cp README.md SECURITY.md CHANGELOG.md LICENSE "$out_dir/"

if command -v strings >/dev/null 2>&1; then
  if strings "$out_dir/maverick" | grep -F "$repo_root" >/dev/null; then
    echo "release artifact privacy check failed: binary contains repo path" >&2
    exit 1
  fi

  if [[ -n "${HOME:-}" ]] && strings "$out_dir/maverick" | grep -F "$HOME" >/dev/null; then
    echo "release artifact privacy check failed: binary contains home path" >&2
    exit 1
  fi
fi

if command -v grep >/dev/null 2>&1; then
  if grep -R -F "$repo_root" "$out_dir" >/dev/null; then
    echo "release artifact privacy check failed: artifact contains repo path" >&2
    exit 1
  fi

  if [[ -n "${HOME:-}" ]] && grep -R -F "$HOME" "$out_dir" >/dev/null; then
    echo "release artifact privacy check failed: artifact contains home path" >&2
    exit 1
  fi
fi

{
  echo "name: $name"
  echo "version: $version"
  echo "target: $target"
  echo "features: ${features:-default}"
  echo "git_revision: $(git rev-parse HEAD)"
  echo "built_at_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "rustc: $("$rustc_bin" --version)"
} >"$out_dir/BUILDINFO"

(
  cd "$out_dir"
  rm -f SHA256SUMS SHA256SUMS.sig
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * >SHA256SUMS
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum * >SHA256SUMS
  else
    echo "missing shasum or sha256sum" >&2
    exit 1
  fi
)

signing_key="${MAVERICK_RELEASE_SIGNING_KEY:-}"
if [[ -n "$signing_key" ]]; then
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "missing ssh-keygen for release checksum signing" >&2
    exit 1
  fi
  if [[ ! -f "$signing_key" ]]; then
    echo "missing release signing key: $signing_key" >&2
    exit 1
  fi

  signing_namespace="${MAVERICK_RELEASE_SIGNING_NAMESPACE:-maverick-release}"
  allowed_signers="${MAVERICK_RELEASE_ALLOWED_SIGNERS:-}"
  signer_identity="${MAVERICK_RELEASE_SIGNER_IDENTITY:-maverick-release}"
  keychain_service="${MAVERICK_RELEASE_SIGNING_KEYCHAIN_SERVICE:-}"
  keychain_account="${MAVERICK_RELEASE_SIGNING_KEYCHAIN_ACCOUNT:-maverick-release-signing-ed25519-2026}"
  signing_passphrase=""
  signing_askpass=""

  if [[ -n "$allowed_signers" && "$allowed_signers" != /* ]]; then
    allowed_signers="$repo_root/$allowed_signers"
  fi

  if [[ -n "$keychain_service" ]]; then
    if ! command -v security >/dev/null 2>&1; then
      echo "missing macOS security command for release signing keychain lookup" >&2
      exit 1
    fi

    signing_passphrase="$(security find-generic-password -w -a "$keychain_account" -s "$keychain_service")"
    signing_askpass_dir="$(mktemp -d)"
    cleanup_paths+=("$signing_askpass_dir")
    signing_askpass="$signing_askpass_dir/askpass"
    printf '%s\n' \
      '#!/bin/sh' \
      'printf %s "$MAVERICK_RELEASE_SIGNING_KEY_PASSPHRASE"' \
      >"$signing_askpass"
    chmod 700 "$signing_askpass"
  fi

  (
    cd "$out_dir"
    if [[ -n "$keychain_service" ]]; then
      export MAVERICK_RELEASE_SIGNING_KEY_PASSPHRASE="$signing_passphrase"
      export SSH_ASKPASS="$signing_askpass"
      export SSH_ASKPASS_REQUIRE=force
      export DISPLAY="${DISPLAY:-:0}"
    fi

    rm -f SHA256SUMS.sig
    ssh-keygen -Y sign -f "$signing_key" -n "$signing_namespace" SHA256SUMS >/dev/null
    if [[ -n "$allowed_signers" ]]; then
      ssh-keygen -Y verify \
        -f "$allowed_signers" \
        -I "$signer_identity" \
        -n "$signing_namespace" \
        -s SHA256SUMS.sig <SHA256SUMS >/dev/null
    fi
  )
  unset signing_passphrase
fi

echo "release artifacts written to $out_dir"
