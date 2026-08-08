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
  if [[ "$(uname -s)" == "Darwin" ]]; then
    [[ "$(stat -f '%Lp' client.generated.yaml)" == "600" ]]
    [[ "$(stat -f '%Lp' server.generated.yaml)" == "600" ]]
  else
    [[ "$(stat -c '%a' client.generated.yaml)" == "600" ]]
    [[ "$(stat -c '%a' server.generated.yaml)" == "600" ]]
  fi
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

echo "==> isolated test-server preparation checks"
./scripts/test-prepare-test-server.sh

echo "==> release publication gate checks"
./scripts/test-release-gates.sh

echo "==> security dependency inventory focused checks"
./scripts/test-security-dependency-inventory.sh

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
  docs/TEST_SERVER_PREPARATION.md
  docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md
  docs/archive/README.md
)
for doc_path in "${active_docs[@]}"; do
  [[ -f "$doc_path" ]] || {
    echo "missing active document: $doc_path" >&2
    exit 1
  }
done

active_privacy_pattern='/U''sers/|fi''le://|ssh''-rsa|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'
active_privacy_status=0
rg -q "$active_privacy_pattern" \
  AGENTS.md README.md STATUS.md ROADMAP.md CONFIG.md THREAT_MODEL.md SECURITY.md \
  docs/TRANSPORT_ARCHITECTURE.md docs/TEST_SERVER_PREPARATION.md \
  docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md scripts/user-smoke.sh \
  scripts/build-pilot.sh scripts/generate-cyclonedx-sbom.sh \
  scripts/prepare-test-server.sh scripts/security-dependency-inventory.sh \
  scripts/test-cyclonedx-sbom.sh scripts/test-security-dependency-inventory.sh \
  scripts/test-prepare-test-server.sh scripts/verify-pilot-artifact.sh \
  scripts/verify-cyclonedx-sbom.sh scripts/verify-release-tag.sh \
  scripts/test-release-gates.sh \
  crates config .github/workflows 2>/dev/null || active_privacy_status=$?
case "$active_privacy_status" in
  0)
    echo "active source contains a private path or key marker" >&2
    exit 1
    ;;
  1) ;;
  *)
    echo "unable to complete the active-source privacy scan" >&2
    exit 1
    ;;
esac

pilot_guide="$(
  sed -n "/^cat >.*START_HERE\\.txt.*<<'GUIDE'$/,/^GUIDE$/p" \
    scripts/build-pilot.sh
)"
for required_line in \
  "chmod 600 client.generated.yaml &&" \
  "shasum -a 256 -c SHA256SUMS" \
  "./maverick version &&" \
  "./maverick user-smoke &&" \
  "./maverick client -c ./client.generated.yaml"; do
  grep -Fq "$required_line" <<<"$pilot_guide" || {
    echo "pilot fast-start guide is missing: $required_line" >&2
    exit 1
  }
done

git diff --check
bash -n scripts/local-harness.sh scripts/user-smoke.sh scripts/build-pilot.sh \
  scripts/generate-cyclonedx-sbom.sh scripts/security-dependency-inventory.sh \
  scripts/prepare-test-server.sh scripts/test-cyclonedx-sbom.sh \
  scripts/test-prepare-test-server.sh scripts/test-security-dependency-inventory.sh \
  scripts/verify-cyclonedx-sbom.sh \
  scripts/verify-pilot-artifact.sh scripts/verify-release-tag.sh \
  scripts/test-release-gates.sh
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s bash scripts/*.sh
fi

echo "local harness OK"
