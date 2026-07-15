#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/approved-vm-ech-edge-preflight.sh [ssh-host]

Required environment:
  MAVERICK_ECH_EDGE_PREFLIGHT_APPROVED=1

Optional environment:
  MAVERICK_ECH_EDGE_HOST          SSH host, default approved-linux-vm.
  MAVERICK_ECH_EDGE_DOMAIN        Domain to test, default maverick-ech.example.com.
  MAVERICK_ECH_EDGE_RESOLVER      DNS resolver for HTTPS/TYPE65 query, default 1.1.1.1.
  MAVERICK_ECH_EDGE_TIMEOUT_SECS  Remote build/run timeout, default 240.

This script runs a Cloudflare edge-only ECH preflight from an approved VM. It
queries the domain's HTTPS/SVCB record, extracts the ech parameter, builds a
temporary rustls ECH client in /tmp, performs one TLS 1.3 client handshake, and
requires rustls to report EchStatus::Accepted.

It does not enable Maverick runtime ECH, mutate DNS records, or change local or
remote proxy, DNS, route, firewall, VPN, or interface settings.
EOF
}

shell_quote() {
  printf "%q" "$1"
}

host="${1:-${MAVERICK_ECH_EDGE_HOST:-approved-linux-vm}}"
domain="${MAVERICK_ECH_EDGE_DOMAIN:-maverick-ech.example.com}"
resolver="${MAVERICK_ECH_EDGE_RESOLVER:-1.1.1.1}"
timeout_secs="${MAVERICK_ECH_EDGE_TIMEOUT_SECS:-240}"

if [[ "${MAVERICK_ECH_EDGE_PREFLIGHT_APPROVED:-}" != "1" ]]; then
  echo "MAVERICK_ECH_EDGE_PREFLIGHT_APPROVED=1 is required" >&2
  usage
  exit 2
fi

case "$host" in
  ""|localhost|127.*|::1)
    echo "refusing to run approved VM ECH edge preflight against local host: $host" >&2
    exit 2
    ;;
esac

case "$domain" in
  maverick-ech.example.com)
    ;;
  *)
    if [[ "${MAVERICK_ECH_EDGE_ALLOW_CUSTOM_DOMAIN:-}" != "1" ]]; then
      echo "custom ECH edge domain requires MAVERICK_ECH_EDGE_ALLOW_CUSTOM_DOMAIN=1" >&2
      exit 2
    fi
    ;;
esac

case "$domain:$resolver" in
  *[!A-Za-z0-9.:-]*|*..*|.*|*.)
    echo "invalid domain or resolver" >&2
    exit 2
    ;;
esac

case "$timeout_secs" in
  *[!0-9]*|"")
    echo "timeout must be numeric" >&2
    exit 2
    ;;
esac

echo "==> approved VM ECH edge preflight on $host for $domain"
ssh -o BatchMode=yes "$host" \
  "DOMAIN=$(shell_quote "$domain") RESOLVER=$(shell_quote "$resolver") TIMEOUT_SECS=$(shell_quote "$timeout_secs") bash -s" <<'REMOTE'
set -euo pipefail

for tool in dig cargo rustc timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool on approved host: $tool" >&2
    exit 1
  fi
done

work="$(mktemp -d /tmp/maverick-ech-edge.XXXXXX)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

echo "dns_https_query=begin"
https_record="$(dig +short HTTPS "$DOMAIN" @"$RESOLVER" | head -n1)"
if [[ -z "$https_record" ]]; then
  echo "missing HTTPS/SVCB record for $DOMAIN" >&2
  exit 1
fi
echo "dns_https_record_present=ok"

ech_config="$(printf '%s\n' "$https_record" | sed -n 's/.*ech=\([^ ]*\).*/\1/p' | head -n1)"
if [[ -z "$ech_config" ]]; then
  echo "missing ech parameter for $DOMAIN" >&2
  exit 1
fi
echo "dns_ech_parameter_present=ok"

a_records="$(dig +short A "$DOMAIN" @"$RESOLVER" | tr '\n' ' ')"
if [[ -z "$a_records" ]]; then
  echo "missing A records for $DOMAIN" >&2
  exit 1
fi
echo "dns_a_records_present=ok"

cd "$work"
export CARGO_HOME="$work/cargo-home"
cat > Cargo.toml <<'EOF'
[package]
name = "maverick-ech-edge-smoke"
version = "0.0.0"
edition = "2021"

[dependencies]
base64 = "0.22"
rustls = "=0.23.41"
rustls-pki-types = "=1.13.1"
webpki-roots = "=0.26.11"
zeroize = "=1.8.2"
EOF

mkdir -p src
cat > src/main.rs <<'EOF'
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use base64::Engine;
use rustls::client::{EchConfig, EchMode, EchStatus};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = env::args().nth(1).ok_or("missing domain")?;
    let ech_b64 = env::args().nth(2).ok_or("missing ECH base64 argument")?;
    let ech_bytes = base64::engine::general_purpose::STANDARD.decode(ech_b64.as_bytes())?;
    let ech_list = EchConfigListBytes::from(ech_bytes);
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let ech_config = EchConfig::new(ech_list, ALL_SUPPORTED_SUITES)?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_ech(EchMode::Enable(ech_config))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let server_name = ServerName::try_from(domain.clone())?.to_owned();
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    let tcp = TcpStream::connect((domain.as_str(), 443))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(format!("HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n").as_bytes())?;
    let mut buf = [0_u8; 512];
    let _ = tls.read(&mut buf);

    let status = tls.conn.ech_status();
    println!("ech_status={status:?}");
    println!("protocol={:?}", tls.conn.protocol_version());
    println!("alpn={:?}", tls.conn.alpn_protocol());
    if status != EchStatus::Accepted {
        return Err(format!("ECH was not accepted: {status:?}").into());
    }
    println!("approved_vm_ech_edge_preflight=ok");
    Ok(())
}
EOF

cargo generate-lockfile >/dev/null
timeout "${TIMEOUT_SECS}s" cargo run --locked --quiet -- "$DOMAIN" "$ech_config"

cleanup
trap - EXIT
if [[ -e "$work" ]]; then
  echo "temporary work directory residue remains: $work" >&2
  exit 1
fi
echo "remote_temp_cleanup=ok"
REMOTE
