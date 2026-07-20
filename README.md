# Maverick

Maverick is an experimental Rust privacy proxy. It remains alpha software, is
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

## Active Documents

- [STATUS.md](STATUS.md): the single current-truth and pilot decision record.
- [ROADMAP.md](ROADMAP.md): the user-first execution order.
- [CONFIG.md](CONFIG.md): configuration reference.
- [THREAT_MODEL.md](THREAT_MODEL.md): the current pilot threat model.
- [SECURITY.md](SECURITY.md): reporting, secret handling, and security limits.
- [docs/TRANSPORT_ARCHITECTURE.md](docs/TRANSPORT_ARCHITECTURE.md): compact
  product architecture.
- [docs/archive/README.md](docs/archive/README.md): historical-material boundary.

## Safety

Local tests and demos must not change this machine's system proxy, DNS, route
table, firewall, VPN, or other network-service settings. They use loopback and
ephemeral ports only. A real-network pilot requires a separately named,
owner-controlled environment and explicit authorization.

Apache License 2.0. See [LICENSE](LICENSE).
