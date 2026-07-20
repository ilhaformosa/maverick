# Maverick

Maverick is an experimental Rust privacy proxy. Its protocol core, local
client/server path, authentication, replay protection, fallback handling, and
bounded relay code are real and tested. It is still alpha software: it has not
been formally audited, is not production-ready, and does not claim anonymity,
censorship resistance, or exact browser fingerprint equivalence.

The project now has one measure of progress:

> A real person installs a simple Maverick artifact, uses it from a real
> network for a normal day, and records whether it was usable and whether the
> network exposed a Maverick-specific block or probe response.

Test counts, receipts, hashes, and fail-closed tooling remain useful checks.
They are not product progress by themselves.

## Current Direction

The former Phase 3 production-certification program is terminally retired and
will not be restarted under another name. Historical plans, evidence indexes,
release records, and orchestration tools remain under `docs/archive/`,
`scripts/archive/`, and `.github/archive/`; they are provenance only.

The first pilot is deliberately narrow:

- first user: the project owner, not an unconsenting or at-risk third party;
- client: the Maverick CLI on an owner-controlled desktop;
- server: a separately authorized owner-controlled endpoint;
- path: browser-like TLS over the CDN-fronted H2 pilot carrier after one
  explicit provider-trust decision;
- task: ordinary browsing for one workday;
- result: a short usability and network-observation record, including failures.

No remote endpoint, spending, or host/network mutation is authorized merely by
this repository direction.

## What Works

- TLS 1.3 and HTTP/2 client/server transport.
- Local SOCKS5, DNS, and HTTP CONNECT inputs.
- Authenticated TCP, DNS, and UDP relay.
- HMAC authentication, replay protection, certificate validation and pinning.
- Static and reverse-proxy fallback for unauthenticated requests.
- Resource bounds, redacted logs, and loopback-only metrics.
- Browser-like client TLS as the default build and generated-client profile on
  supported macOS arm64 and Linux x86_64 targets. It is browser-like, not
  browser-identical.
- A first-class CDN-fronted H2 carrier that preserves the browser-like client
  path and disables impossible cross-termination TLS exporter binding. It is
  loopback-tested, not yet validated through a real provider.
- Rust unit and loopback integration tests.

`protocol_version` remains `1`, config `version` remains `1`, and the workspace
software version remains `1.2.0-alpha.1`.

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

Build the first owner-pilot folder:

```sh
./scripts/build-pilot.sh
```

It creates ignored output under `dist/maverick-pilot/`: one CLI binary, two
generated configs, a checksum, version output, and one short start guide. The
builder does not contact a server or change network settings. A fresh user's
five-minute install has not yet been demonstrated.

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
