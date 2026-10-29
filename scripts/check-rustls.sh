#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo check --locked \
  -p maverick-cli -p maverick-sdk -p maverick-tests \
  --all-targets --no-default-features
retirement_tests="$(cargo test --locked -p maverick-tests --no-default-features \
  --test tcp_relay -- --list)"
grep -Fqx 'server_rejects_retired_v1_h3_config_with_fixed_error: test' \
  <<<"${retirement_tests}"
grep -Fqx 'bad_auth_reverse_proxy_fallback_preserves_path_query_and_available_body: test' \
  <<<"${retirement_tests}"
grep -Fqx 'auth_v2_private_client_rejects_rustls_fingerprint: test' \
  <<<"${retirement_tests}"
cargo test --locked -p maverick-tests --no-default-features \
  --test tcp_relay
cargo test --locked -p maverick-cli --no-default-features --test config_handoff
cargo test --locked -p maverick-cli -p maverick-sdk \
  --no-default-features --test server_startup
cargo test --locked -p maverick-client --no-default-features tunnel::relay_tests
