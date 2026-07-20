#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-}"
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

echo "==> formatting"
"$cargo_bin" fmt --all -- --check

echo "==> clippy"
"$cargo_bin" clippy --workspace --all-targets -- -D warnings

echo "==> Rust tests"
"$cargo_bin" test --workspace

echo "==> explicit rustls compatibility build"
"$cargo_bin" check -p maverick-cli --no-default-features

echo "==> generated config defaults"
config_tmp="$(mktemp -d)"
trap 'rm -rf "$config_tmp"' EXIT
(
  cd "$config_tmp"
  "$cargo_bin" run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p maverick-cli -- gen-config >/dev/null
  chmod 600 client.generated.yaml server.generated.yaml
  rg -q 'tls_fingerprint: "browser_mimic"' client.generated.yaml
  rg -q 'carrier: "h2"' client.generated.yaml
  rg -q 'carrier: "h2"' server.generated.yaml
  "$cargo_bin" run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p maverick-cli -- check-config --kind client \
    -c client.generated.yaml >/dev/null
  "$cargo_bin" run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p maverick-cli -- check-config --kind server \
    -c server.generated.yaml >/dev/null
)

echo "==> local product smoke"
CARGO_BIN="$cargo_bin" ./scripts/user-smoke.sh

echo "==> active-surface checks"
active_python="$(
  find . \
    \( -path './.git' -o -path './target' -o -path './fuzz/target' \
       -o -path './scripts/archive/python' \) -prune \
    -o -type f -name '*.py' -print
)"
if [[ -n "$active_python" ]]; then
  echo "Python tooling must live under scripts/archive/python" >&2
  printf '%s\n' "$active_python" >&2
  exit 1
fi

active_docs=(
  AGENTS.md
  README.md
  STATUS.md
  ROADMAP.md
  CONFIG.md
  THREAT_MODEL.md
  SECURITY.md
  docs/TRANSPORT_ARCHITECTURE.md
  docs/archive/README.md
)
for doc_path in "${active_docs[@]}"; do
  [[ -f "$doc_path" ]] || {
    echo "missing active document: $doc_path" >&2
    exit 1
  }
done

if rg -l '/Users/|file://|ssh-rsa|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' \
  AGENTS.md README.md STATUS.md ROADMAP.md CONFIG.md THREAT_MODEL.md SECURITY.md \
  docs/TRANSPORT_ARCHITECTURE.md scripts/user-smoke.sh scripts/build-pilot.sh \
  crates config .github/workflows
then
  echo "active source contains a private path or key marker" >&2
  exit 1
fi

git diff --check
bash -n scripts/local-harness.sh scripts/user-smoke.sh scripts/build-pilot.sh \
  scripts/security-dependency-inventory.sh

echo "local harness OK"
