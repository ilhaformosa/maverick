# Maverick

Maverick is an experimental Rust privacy proxy. It is Beta software, is
not production-ready, and does not claim anonymity, censorship resistance, or
exact browser fingerprint equivalence.

[STATUS.md](STATUS.md) records current capabilities, release state and
authorization. [ROADMAP.md](ROADMAP.md) gives the next deliverables;
[CONFIG.md](CONFIG.md) describes runnable configuration.

## Build and Configure

Complete candidate packages include H2 and H3. Build that same capability set
from source and generate a new direct pair in an empty directory:

```sh
cargo build --locked -p maverick-cli --features experimental-h3
./target/debug/maverick version
./target/debug/maverick gen-config
./target/debug/maverick check-config --kind server -c server.generated.yaml
./target/debug/maverick check-config --kind client -c client.generated.yaml
```

New direct generation uses a dual H2/H3 server, an automatic client and explicit
`udp_policy: allow_reliable`. Use `gen-config --h2` or `gen-config --quiche-h3`
for a fixed carrier. Add `--udp-policy native_required` to auto/H3 generation
to forbid reliable UDP compatibility. Existing files are not overwritten and
omitted settings retain their prior meaning. Minimal H2 source builds remain
available without the H3 feature and require `gen-config --h2`.

Generation creates matching credentials in owner-only files. `version` reports
compiled support, not remote connectivity. The `experimental-h3` feature name
is retained for source compatibility; these candidate builds are not Stable.

The generated files are examples: replace `example.com`, the server address
and certificate paths before any separately authorized deployment. Keep the
matching credential private. `check-config` validates configuration syntax and
policy; it does not prove certificate files or a remote server work. Ordinary
startup uses `server -c server.generated.yaml` and
`client -c client.generated.yaml`. Field validation remains deferred.

H2 and H3 both carry TCP and persistent UDP sessions. H3 provides native
unreliable datagrams up to 1200 bytes; H2 provides reliable compatibility up to
65507 bytes, with lower limits possible from SOCKS encapsulation or the path.
The core selects only for new connections/sessions, with a shared temporary
avoidance cache after pre-response H3 network failure. UDP may select H2 only
under `allow_reliable`, including authenticated capability absence before data.
TLS, identity, authentication, malformed protocol and target/admission failures
never permit fallback. Existing sessions retain their carrier and packets are
not replayed. Target silence is not a tunnel reachability failure.

Protected intermediaries use H2 only. H3 fronting, local DNS/TUN and rustls
selection remain unsupported. Profile URI v1 rejects new transport/UDP policies
it cannot preserve; use full YAML or stored SDK profiles.
See [CONFIG.md](CONFIG.md#transport).

These capabilities are included in the [RC.5 checkpoint](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.0-rc.5)
at `e4a21e2`, published as a prerelease/non-Latest for macOS arm64 and Linux
x86_64. See [STATUS.md](STATUS.md) for its exact qualification and remaining gates.
Older RC.2 files remain immutable and do not include H3 or subsequent changes.

For an H2 intermediary that terminates outer TLS, RC.5 and source builds provide explicit
origin-pinned inner TLS through `advanced.end_to_end`. Generate the protected
pair using `gen-config --relay --origin-name origin.example.invalid --origin-cert origin.pem`, optionally with `--origin-ca ca.pem`.
The owner-supplied public certificate determines the mandatory pin. The client verifies a
separate origin CA/hostname/pin before sending authentication, proxy targets or
payloads; protection failures never retry in the historical unprotected mode.
See [configuration](CONFIG.md#origin-pinned-end-to-end-h2) and the
[protocol boundary](docs/END_TO_END_PROTECTION.md). This is locally tested
streaming H2, not real-provider qualification or native UDP. The intermediary
can still observe the origin TLS name, timing and volume.

## Integration and Deployment

Proxy cores can use the public SDK's `ProxyConnector` directly with caller-owned
I/O, without opening a local SOCKS listener. H2 pooling, origin protection,
H3/automatic TCP and UDP selection, and both UDP policies reuse the product paths. See
[SDK and wire integration](docs/INTEGRATION.md), including checked frame examples.

Start with the [runnable SDK consumer](crates/maverick-sdk/examples/connector_loopback.rs):

```sh
cargo run --locked -p maverick-sdk --features experimental-h3 --example connector_loopback -- auto allow_reliable
```

It runs entirely on loopback with temporary test credentials, demonstrates TCP
and independent UDP replies, and closes the embedded server. The integration
guide explains fixed carriers, native-required UDP, dependency setup and
caller-owned sessions. This is local integration preparation, not field use.

A [Linux service template and runbook](docs/DEPLOYMENT.md) describe later
owner-authorized deployment. CLI servers stop normally on SIGTERM/SIGINT.
RC.5 is an experimental checkpoint, not Stable. Field use, real deployment and
Stable publication remain separate decisions; see the proposed acceptance plan
in [ROADMAP.md](ROADMAP.md#proposed-field-acceptance--discussion-only).

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

`./scripts/build-pilot.sh` builds the full H2/H3 CLI, start guide, checksums and
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
