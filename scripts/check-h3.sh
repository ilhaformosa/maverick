#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

manifest=crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml
cargo test --locked -p maverick-client --features experimental-h3 h3::tests
cargo test --locked -p maverick-client --features experimental-h3 tunnel::relay_tests
cargo test --locked -p maverick-server --features experimental-h3 h3::tests
cargo test --locked -p maverick-server --features experimental-h3 relay::tests::h2_
cargo test --locked -p maverick-core --no-default-features quiche_h3
cargo test --locked -p maverick-cli --features experimental-h3 quiche_h3
cargo test --locked -p maverick-cli --features experimental-h3 --test h3_product
cargo test --locked -p maverick-cli --features experimental-h3 --test user_smoke
cargo test --locked -p maverick-cli --features experimental-h3 --test config_handoff
cargo test --locked -p maverick-cli -p maverick-sdk \
  --features maverick-cli/experimental-h3 --test server_startup
cargo clippy --locked -p maverick-cli -p maverick-client -p maverick-server \
  --features experimental-h3 --all-targets -- -D warnings
product_graph="$(cargo tree --locked -p maverick-cli --features experimental-h3 --edges normal,build --prefix none)"
[[ "$(grep -Ecx 'boring-sys v5\.3\.0' <<<"$product_graph")" -eq 1 ]]
[[ "$(grep -Ecx 'quiche v0\.30\.0' <<<"$product_graph")" -eq 1 ]]
cargo fmt --manifest-path "$manifest" -- --check
cargo clippy --locked --manifest-path "$manifest" --features proxy --all-targets -- -D warnings
cargo test --locked --manifest-path "$manifest" --features proxy
cargo test --locked --release --manifest-path "$manifest" --features proxy \
  --test upstream_behavior --test proxy_logging logging
cargo run --locked --manifest-path "$manifest" --features proxy --bin h3-proxy-smoke
cargo tree --locked --manifest-path "$manifest" --features proxy --edges normal,build -i boring-sys
cargo metadata --locked --manifest-path "$manifest" --features proxy \
  --format-version 1 | jq -e '
    [.resolve.nodes[] as $node | .packages[] | select(.id == $node.id) |
      {name, version, features: $node.features}] as $graph |
    ([$graph[] | select(.name == "log")] | length == 1) and
    ($graph[] | select(.name == "log") |
      .version == "0.4.33" and
      (.features | index("max_level_debug")) != null and
      ([.features[] | select(startswith("release_max_level_"))] | length == 0)) and
    ([$graph[] | select(.name == "quiche")] | length == 1) and
    ($graph[] | select(.name == "quiche") |
      .version == "0.30.0" and (.features | index("qlog")) == null)
  ' >/dev/null
