# Maverick

Maverick is an experimental Rust privacy proxy. It is Beta software, is
not production-ready, and does not claim anonymity, censorship resistance, or
exact browser fingerprint equivalence.

[STATUS.md](STATUS.md) records current capabilities, release state and
authorization. [ROADMAP.md](ROADMAP.md) gives the next deliverables;
[CONFIG.md](CONFIG.md) describes runnable configuration.

## Build and Configure

The default source build uses Direct H2. Choose one generation recipe below
from the checkout; neither generated file may already exist.

```sh
cargo build --locked -p maverick-cli
./target/debug/maverick version
./target/debug/maverick gen-config
./target/debug/maverick check-config --kind server -c server.generated.yaml
./target/debug/maverick check-config --kind client -c client.generated.yaml
```

For an explicitly selected H3 build and configuration pair, use this alternative:

```sh
cargo build --locked -p maverick-cli --features experimental-h3
./target/debug/maverick version
./target/debug/maverick gen-config --quiche-h3
./target/debug/maverick check-config --kind server -c server.generated.yaml
./target/debug/maverick check-config --kind client -c client.generated.yaml
```

Generation creates fresh matching credentials in owner-only files and checks
both output names before writing. Bare `gen-config` keeps H2 even when the
binary supports H3. The explicit H3 option requires the build feature;
`version` reports compiled support, not a successful connection.

The generated files are examples: replace `example.com`, the server address
and certificate paths before any separately authorized deployment. Keep the
matching credential private. `check-config` validates configuration syntax and
policy; it does not prove certificate files or a remote server work. Ordinary
startup uses `server -c server.generated.yaml` and
`client -c client.generated.yaml`. Field validation remains deferred.

H3 supports direct TCP through SOCKS5 and HTTP CONNECT, using existing
certificate/hostname/pin verification and authentication v1/v2. Both ends must
select `advanced.quiche_h3: true`; omission keeps H2. Fronting, local DNS/TUN,
rustls selection and SOCKS UDP associations are unsupported. There is no
automatic selection or fallback. Profile URI v1 cannot carry H3 or every
connection/authentication/trust setting; unsupported exports are rejected
instead of silently changing policy. See [CONFIG.md](CONFIG.md#transport).

These are source-build capabilities. Published RC.2 files remain immutable and
do not include H3 or subsequent source changes.

## Embedded SDK State

`GuiClientRuntime::connect()` starts local listeners. Its diagnostics report
`listening` / `unverified`, not a verified remote connection. Use
`is_listening()` for local lifecycle checks; the old `is_connected()` name is
deprecated. See [SDK diagnostics and compatibility](CONFIG.md#sdk-diagnostics-and-local-lifecycle)
for state meanings and consumer updates.

## Local Product Checks

Run the small loopback product check:

```sh
./scripts/user-smoke.sh
```

To explicitly check H3 in a build that includes it:

```sh
cargo run --locked -p maverick-cli --features experimental-h3 -- user-smoke --quiche-h3
```

Both modes use temporary local certificates, credentials, `127.0.0.1` and
OS-assigned ports. They verify the real client/server path, correct-credential
payload exchange and wrong-credential rejection. The result identifies
`carrier: h2` or `carrier: h3`. Bare `user-smoke` and the default-build shell
wrapper keep H2; a build without H3 rejects an explicit H3 request. Neither
check uses a deployment configuration or establishes real-network usability.
Printed timings are diagnostic, not performance pass criteria.

For normal development:

```sh
./scripts/check.sh
```

For default-product-only changes, `./scripts/local-harness.sh` is the smaller
entry. The complete shared check also covers the rustls compatibility matrix,
configured H3 path and retained quiche candidate checks; it already includes
the product harness. Use `./scripts/check.sh h3` (or `product`, `rustls`,
`quiche-candidate`) while iterating, then the complete entry for changes
spanning those paths. It requires existing Rust, C/C++ build and shell tools,
including `jq`, `rg` and `shellcheck`; it does not install tools.

The same entry runs in CI, which also retains native release archive, SBOM,
upgrade/rollback and CodeQL checks. Linux and macOS run in parallel. Long
performance runs are opt-in and are repeated for relevant runtime changes or
unresolved failures, not every PR.

The ordinary CLI integration suite starts separate local client/server processes:

```sh
cargo test --locked -p maverick-cli --features experimental-h3 --test h3_product
```

It covers authentication/TLS, payload integrity, half-close, concurrency,
cleanup and process recovery. Filter with `resilience::` for selected datagram
loss/delay, slow-reader isolation and same-client server-restart recovery;
filter with `shaping::` for configured Auto/Stable padding behavior. Separate
authenticated client tests verify frame ordering and batching with a paused
clock. These checks have no performance thresholds and change no host networking.

## Manual Performance and Resource Measurements

For a release-mode H2/H3 loopback comparison:

```sh
cargo test --locked --release -p maverick-cli --features experimental-h3 \
  --test h3_product compare_h2_h3_loopback -- --ignored --nocapture
```

This measures connection setup and verified bulk transfers, then checks
30 seconds of bounded concurrency and recovery. Each carrier records
`comparison_host` context before and after the work. Use the same workload and
comparable conditions for quantitative comparisons; report an unreliable
comparison instead of claiming a speedup.

For longer sustained/churn traffic and process-resource sampling:

```sh
MAVERICK_SOAK_SECONDS=300 cargo test --locked --release -p maverick-cli \
  --features experimental-h3 --test h3_product \
  soak::long_running_carrier_resources -- --ignored --nocapture
```

This uses three 100-second H2 reference phases and three 300-second H3 phases,
eight sustained bidirectional flows and four short flows/s. Each long flow
sends 64 KiB per direction every 100 ms. Idle, cancellation and client-exit/
restart checks bring the total to about 22 minutes. Set
`MAVERICK_SOAK_SECONDS=10` for a preflight. For the established higher-load recipe:

```sh
MAVERICK_SOAK_SECONDS=600 MAVERICK_SOAK_CONCURRENCY=32 \
  cargo test --locked --release -p maverick-cli --features experimental-h3 \
  --test h3_product soak::long_running_carrier_resources -- --ignored --nocapture
```

This takes about 42 minutes: three 200-second H2 and three 600-second H3 phases,
plus cleanup/recovery. All peers are paired before the common traffic window.
The report records concurrency, block size, setup time, verified bytes and
transfer time. The byte/transfer-time ratio excludes setup and later recovery;
it is an achieved paced rate, not maximum throughput. The normal CI lifecycle
case instead uses 32 flows for 12 seconds per carrier and 16 KiB blocks, keeping
debug offered load at 10 MiB/s versus 40 MiB/s for the manual 32-flow recipe.

The sampler requires `ps` and `lsof` and records numeric CPU time, RSS,
descriptor counts and server metrics. Whole-host context includes available
CPU parallelism and 1/5/15-minute load averages. macOS adds its raw pressure
code and cumulative swap-in/out pages; Linux adds total/available memory and
used swap in KiB. These platform-specific memory values are not interchangeable.
Load averages include Maverick and other work, are not CPU percentages, and do
not identify idle cores. No other project names or process command lines are
collected. Unavailable context fails the manual measurement explicitly.

Keep this task's builds/profiling separate from timing runs; other projects may
remain active. Context never skips an assertion or changes a deadline. CPU uses
counter differences over elapsed time, restarted after a process restart;
100% represents one core. RSS/descriptor observations are samples, not peaks or
proof of leak freedom. H2 may retain pooled connections during idle observation.
Both carriers must release connections/admission after client termination,
within the existing 15-second allowance, before restart. Manual phases retain
15-second idle observations. There are no CPU/RSS thresholds in CI.
[STATUS.md](STATUS.md#local-evidence-and-limits) links measured results and limits.

## Retained Developer References

The shared H3 checks also use the isolated TLS/auth fixture. For focused work:

```sh
cargo test --locked \
  --manifest-path crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml
cargo run --locked \
  --manifest-path crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml \
  --features proxy --bin h3-proxy-smoke
```

The fixture uses the same H3 driver as the product with its separate lockfile.
Proxy mode verifies authentication and 512 KiB transfers in both directions;
adding `--features proxy` to its test command includes rejection, limits,
timeouts and cleanup. Control/push and debug/release logging checks retain their
bounded scope, rather than claiming full HTTP/3 conformance.

The earlier single-request loopback lab remains available:

```sh
cargo run --locked -p maverick-tests --no-default-features \
  --features quiche-candidate --bin backend-capture-lab -- quiche-loopback
```

It accepts no external address, uses temporary credentials and a five-second
network deadline, and does not complete the separate Chrome qualification.

## Pilot Artifacts and Further Documentation

`./scripts/build-pilot.sh` builds the default H2 CLI, start guide, checksums and
target archive under ignored `dist/`. Public archives contain no credentials;
operators generate them locally. The builder does not contact a server or
change network settings. Publication and Stable follow the
[release contract](docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md).

- [CONFIG.md](CONFIG.md): runnable configuration and compatibility.
- [docs/TRANSPORT_ARCHITECTURE.md](docs/TRANSPORT_ARCHITECTURE.md): product data path.
- [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md): protections,
  reporting and limits.
- [docs/TEST_SERVER_PREPARATION.md](docs/TEST_SERVER_PREPARATION.md): preparation
  for a separately authorized Ubuntu origin; it can change that server's packages
  and TCP settings and is not a local quick-start step.
- [docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md](docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md):
  field diagnosis within a separately authorized trial.
- [docs/archive/README.md](docs/archive/README.md): historical-material boundary.

Local tests use loopback and ephemeral ports. Never change this Mac's system
proxy, DNS, routes, firewall, VPN or Surge settings. Real-network trials require
a separately named owner-controlled environment and explicit authorization.
Keep credentials and private infrastructure details out of git and shared logs.

Apache License 2.0. See [LICENSE](LICENSE).
