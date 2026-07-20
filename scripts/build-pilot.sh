#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/dist/maverick-pilot"
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

if [[ -e "$output_dir" ]]; then
  echo "refusing to overwrite existing pilot directory: dist/maverick-pilot" >&2
  exit 1
fi

cd "$repo_root"
"$cargo_bin" build --release -p maverick-cli

mkdir -p "$output_dir"
install -m 0755 target/release/maverick "$output_dir/maverick"
(
  cd "$output_dir"
  ./maverick gen-config >/dev/null
  ./maverick version >VERSION.txt
  shasum -a 256 maverick >SHA256SUMS
)

if strings "$output_dir/maverick" | rg -q '/U[s]ers/|/home/[^/]+/'; then
  echo "pilot binary contains a local build path; do not share it" >&2
  exit 1
fi

cat >"$output_dir/START_HERE.txt" <<'GUIDE'
Maverick owner pilot

1. Run the local product check:
   ./maverick user-smoke

2. Before any real-network use, replace every example hostname, certificate
   path, and credential setting in both generated YAML files. Keep both files
   owner-readable only.

3. Validate:
   ./maverick check-config --kind server -c server.generated.yaml
   ./maverick check-config --kind client -c client.generated.yaml

4. Stop here for local rehearsal. The generated files already select the H2
   carrier but leave CDN fronting disabled. Before a real restricted-network
   pilot, name the provider and accept that it can observe tunnel content, then
   set both configs' cdn_fronting.enabled and
   trusted_tls_terminating_provider fields to true. If that trust is rejected,
   use owner-controlled handshake forwarding instead.

5. Put the exact server/client start commands into the separately authorized,
   plain-language pilot envelope. Point only the chosen application at the
   loopback SOCKS5 listener; do not change system proxy, DNS, routes, firewall,
   or VPN settings as part of this guide.

This artifact is alpha software. It is not audited, production-ready,
anonymous, censorship-resistant, or browser-identical.
GUIDE

chmod 600 "$output_dir/client.generated.yaml" "$output_dir/server.generated.yaml"
echo "pilot artifact: dist/maverick-pilot"
