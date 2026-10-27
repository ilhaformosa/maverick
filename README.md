# Maverick

Maverick is an experimental Rust privacy proxy. It is Beta software, is
not production-ready, and does not claim anonymity, censorship resistance, or
exact browser fingerprint equivalence.

## Current Direction

Current product truth, pilot strategy, audit status, and authorization all live
in [STATUS.md](STATUS.md). [ROADMAP.md](ROADMAP.md) contains execution order,
not a second status record. Historical plans and orchestration remain under the
archive directories as provenance only.

## Product Surface

The active product is the Rust core, client, server, CLI, SDK, and loopback
integration suite. `STATUS.md` is the only record of what is currently
implemented or validated. [CONFIG.md](CONFIG.md) documents configuration, and
[docs/TRANSPORT_ARCHITECTURE.md](docs/TRANSPORT_ARCHITECTURE.md) explains the
data path without creating a second status ledger.

## Local Product Check

Run the small, human-readable loopback check:

```sh
./scripts/user-smoke.sh
```

It uses only `127.0.0.1` and OS-assigned ephemeral ports. It starts the real
server/client path, proves a correct credential can relay data, and proves a
wrong credential cannot establish a proxy flow. This is a local product check,
not evidence of real-network usability or censorship resistance.

For the complete local code gate:

```sh
./scripts/local-harness.sh
```

To build the ordinary CLI with H3 support and check separate local client/server
processes:

```sh
cargo build --locked -p maverick-cli --features experimental-h3
cargo test --locked -p maverick-cli --features experimental-h3 --test h3_product
```

Set `advanced.quiche_h3: true` in both existing v1 configs, then use the ordinary
`server -c` and `client -c` commands. Omission keeps H2. The new path reuses
certificate/hostname/pin verification and authentication v1/v2. It rejects
fronting, DNS/TUN and UDP associations; the retired `experimental_h3` flag stays
rejected. See [configuration](CONFIG.md) for the exact scope. This is a Beta
source capability, not a change to the immutable published RC.2 files.

For a manual local H2/H3 comparison using optimized binaries:

```sh
cargo test --locked --release -p maverick-cli --features experimental-h3 \
  --test h3_product compare_h2_h3_loopback -- --ignored --nocapture
```

This measures connection setup and verified bulk transfers, then checks
30 seconds of bounded concurrent traffic and recovery after interrupted flows.
Run it without other builds or tests competing for CPU. Timing is diagnostic;
CI runs the bounded correctness/stability cases without speed thresholds.
See `STATUS.md` for observations and their limits.

For longer local stability and process-resource measurements:

```sh
MAVERICK_SOAK_SECONDS=300 cargo test --locked --release -p maverick-cli \
  --features experimental-h3 --test h3_product \
  soak::long_running_carrier_resources -- --ignored --nocapture
```

The default runs three 100-second H2 reference phases and three 300-second H3
phases, each with eight sustained bidirectional flows and four short flows per
second. Idle intervals, cancellation, active-client exit and restart bring the
total to about 22 minutes. Use `MAVERICK_SOAK_SECONDS=10` for a short preflight.
The manual sampler requires `ps` and `lsof` and records only numeric CPU time,
resident memory, descriptor counts and existing server metrics. Compare CPU
time differences over elapsed time, and restart the counter after a process
restart. Memory samples are not peaks, and retained allocator capacity or H2
pool connections alone do not establish a leak. CI checks the same lifecycle
with a short active run and no platform-dependent resource thresholds.

The following developer laboratories retain focused reference checks.

Run the opt-in local quiche/H3 experiment:

```sh
cargo run --locked -p maverick-tests --no-default-features \
  --features quiche-candidate --bin backend-capture-lab -- quiche-loopback
```

This developer command generates temporary local credentials, validates the
server certificate and hostname, exchanges one H3 request/response over real
loopback UDP, and closes both connections. It uses OS-assigned ports, fixed
packet/body limits, and a five-second network deadline; it accepts no external
address. Temporary credentials and sockets are released on return. It does
not enable H3 in the product or complete backend qualification. The existing
`backend-capture-lab preflight` reports the separate qualification state.

To check the existing TLS settings and authentication v1/v2 through quiche's
upstream Boring integration, run the isolated test package:

```sh
cargo test --locked \
  --manifest-path crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml
```

It reuses the client TLS settings, core authentication, and the shared H3
driver. Its separate lockfile retains the isolated test setup; the current
source uses one aligned Boring TLS version across H2 and H3. Current product
and release state are recorded in `STATUS.md`.

Run the local SOCKS-to-H3-to-TCP proxy smoke with actual server authentication:

```sh
cargo run --locked \
  --manifest-path crates/maverick-tests/fixtures/quiche-tls-auth/Cargo.toml \
  --features proxy --bin h3-proxy-smoke
```

This opt-in executable creates local SOCKS, QUIC, and TCP-origin sockets on
`127.0.0.1` with OS-assigned ports. Authentication v1 and v2 each transfer
512 KiB in both directions with client-first and server-first half-close,
and simultaneous upload/download. Add `--features proxy` to the test command
above to also check credentials, replay, flow limits, egress, active-download
timeouts, GOAWAY, and disconnect cleanup. H3 remains default-off and TCP-only.
The ordinary CLI can now opt into this same driver; field validation is deferred.

The isolated tests also exercise the selected upstream library's push/control
behavior and logging cap. Request-priority hints preserve valid flows; ignored
push metadata never becomes proxy data, and actual pushed streams are rejected.
This does not claim full upstream push-ID conformance. Debug and release tests
check H3/QPACK logging with verbose host loggers; see `STATUS.md` for the exact
P1/P2/P3 decisions and remaining integration work.

Build the first owner-pilot folder and shareable archive:

```sh
./scripts/build-pilot.sh
```

It creates ignored output under `dist/`: one CLI binary, a start guide, checksums,
and a target-specific `.tar.gz`. Public archives contain no credentials; the
user runs `maverick gen-config` after download to create fresh local configs.
Version tags publish the same target archives as GitHub prereleases. The builder
does not contact a server or change network settings. See `STATUS.md` for the
current validation state.

## Build and Configure

```sh
cargo build -p maverick-cli
cargo run -p maverick-cli -- gen-config
cargo run -p maverick-cli -- check-config --kind server -c server.generated.yaml
cargo run -p maverick-cli -- check-config --kind client -c client.generated.yaml
```

Generated configs contain fresh credentials and are ignored by git. Protect
real config files with owner-only permissions and never commit real endpoints,
credentials, account details, or infrastructure identifiers.

Separately authorized Ubuntu test origins use the fail-closed host gate in
[docs/TEST_SERVER_PREPARATION.md](docs/TEST_SERVER_PREPARATION.md). Ubuntu
26.04 LTS is the default; Ubuntu 24.04 LTS requires an explicit fallback reason.
The gate updates packages, stops for a required manual reboot, and persistently
configures stock Ubuntu BBR (commonly called BBRv1) while preserving an existing
`fq` or `fq_codel` choice after its package and configuration safety gates pass.
Those two qdiscs are equally supported; every other value is rejected. The gate
then verifies runtime state, rolling back an apply failure or requesting a
reboot when the active qdisc is still unsupported. It does not install a custom
kernel, reboot, start Maverick, or change a live qdisc. The package upgrade may
install an Ubuntu-provided default-kernel update.

## Active Documents

- [STATUS.md](STATUS.md): the single current-truth and pilot decision record.
- [ROADMAP.md](ROADMAP.md): the user-first execution order.
- [CONFIG.md](CONFIG.md): configuration reference.
- [THREAT_MODEL.md](THREAT_MODEL.md): the current Beta threat model.
- [SECURITY.md](SECURITY.md): reporting, secret handling, and security limits.
- [docs/TRANSPORT_ARCHITECTURE.md](docs/TRANSPORT_ARCHITECTURE.md): compact
  product architecture.
- [docs/TEST_SERVER_PREPARATION.md](docs/TEST_SERVER_PREPARATION.md):
  fail-closed Ubuntu test-origin package, reboot, BBRv1, and qdisc gate.
- [docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md](docs/YOUTUBE_PLAYBACK_DIAGNOSIS.md):
  privacy-safe, one-change-at-a-time field diagnosis.
- [docs/archive/README.md](docs/archive/README.md): historical-material boundary.

## Safety

Local tests and demos must not change this machine's system proxy, DNS, route
table, firewall, VPN, or other network-service settings. They use loopback and
ephemeral ports only. A real-network pilot requires a separately named,
owner-controlled environment and explicit authorization.

Apache License 2.0. See [LICENSE](LICENSE).
