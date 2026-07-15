# Maverick

Maverick is a Rust privacy-preserving proxy protocol prototype. The public
source mainline is development toward `v1.2.0`. The completed
pre-publication `v1.1.0` release is the latest narrow stable engineering
boundary for `maverick-tls-h2-cli-v1`: CLI-managed Rust client/server, TLS 1.3
+ HTTP/2 as the mandatory default transport, local SOCKS5/HTTP CONNECT
inbound, TCP/DNS/UDP relay over authenticated tunnel frames, replay
protection, resource bounds, loopback metrics, and static or reverse-proxy
fallback.

The pre-publication `v1.1.0` release has approved-host runtime evidence,
bounded impairment and failure-injection evidence, community/anonymous
review-input closure, and frozen conformance metadata for that narrow scope.
Its private Git history, tags, and releases were intentionally not imported
into the sanitized public repository. See `docs/PUBLIC_HISTORY_BOUNDARY.md`.
Maverick has not had a formal independent security audit and is not
production-ready. It does not claim browser-grade TLS fingerprint mimicry,
strong traffic shaping, anonymity, or censorship resistance.

The only pre-freeze production claim candidate is Ubuntu 24.04 LTS `amd64`,
IPv4, the `maverick` server/CLI, the `maverick-reference-client` Debian service
package, and TLS 1.3 plus HTTP/2. `production-readiness.json` currently records
No-Go; `docs/PRODUCTION_SCOPE.md` defines the exact boundary.

## Status

This sanitized source snapshot is the public development starting point. It
is not itself a new software release or tag. It is also not a production
deployment recommendation, formal security-audit sign-off, anonymity claim,
censorship-resistance guarantee, browser-fingerprint-equivalence claim, or
standardization proposal.

Recommended public repository description:

```text
Experimental Rust privacy proxy protocol; public main targets v1.2.0 and is not audited or production-ready.
```

## What Works

- Rust workspace with separate core, client, server, CLI, and integration-test crates.
- Local SOCKS5 CONNECT inbound on the client.
- TLS 1.3 + HTTP/2 tunnel transport using rustls and h2.
- In-channel ClientHello / ServerHello authentication using HMAC-SHA256.
- TLS channel-binding HMAC support for direct rustls H2/WebSocket transports.
- Multi-user server config with redacted secrets.
- Optional leaf certificate SHA-256 pin verification after normal TLS validation.
- Timestamp and nonce replay protection.
- Enforced per-user TCP flow limits and optional aggregate byte pacing.
- Client connection timeout covering TCP, TLS, and H2 setup.
- Runtime-scoped H2 connection reuse across local SOCKS5, HTTP CONNECT, DNS,
  and UDP flows, with bounded stream admission, idle retirement, and reconnect.
- Client-side local TCP flow limit for SOCKS5 and HTTP CONNECT.
- Server global/per-source connection caps, pre-auth admission limit, fallback
  concurrency cap, and source-IP failed-auth rate limiting.
- Static website fallback for unauthenticated or non-tunnel requests.
- Reverse-proxy fallback for ordinary web requests.
- TCP relay through the Maverick tunnel.
- DNS relay over authenticated tunnel frames.
- SOCKS5 UDP ASSOCIATE relay over authenticated `OpenUdp` / `UdpPacket` flows.
- Optional feature-gated HTTP/3 / QUIC tunnel carrier with H2 fallback.
- Runtime H3 fallback/cooldown when experimental H3 setup fails.
- Experimental Cloudflare-fronted WebSocket carrier as the current workaround
  for Cloudflare edge ECH experiments. This is not native Maverick
  server-side ECH.
- Stealth configuration guards for active-probing behavior, unsupported
  browser-fingerprint mimicry, and explicit CDN-fronting acknowledgement.
- Explicit opt-in client next-credential switching for staged credential
  rotation.
- Bounded runtime shaping baselines for client/server padding, client-side
  batching, bounded delay, and operator-approved cover padding.
- Optional local HTTP CONNECT inbound.
- Optional loopback-only metrics endpoint.
- Client local listeners are loopback-only by default, with explicit opt-in for LAN exposure.
- Loopback-only `bench-local` micro-benchmark.
- Config migration dry-run, secret-free profile QR export, redacted key inventory, rotation lint dry-run, and benchmark dashboard scripts.
- Explicit config URI import from the OS clipboard.
- Read-only experimental track listing for gate and status review.
- Optional default-off `tun-runtime` SDK/client feature with caller-supplied
  packet I/O, pinned `smoltcp 0.13.1`, bounded TCP/DNS/UDP flow mapping, and
  synthetic plus loopback evidence. It does not create a TUN device or change
  host networking.
- Unit and integration tests for core parser/auth/replay and local relay behavior.

## Not Ready Yet

- Strong traffic-analysis resistance or anonymity guarantees.
- Anonymous credential lookup, native server-side ECH, post-quantum hybrid
  handshakes.
- Production package publication, sustained daily-use validation, production
  credential-root protection, abrupt power-loss recovery, GUI clients, and
  mobile clients.
- Real TUN device, route, and DNS ownership are deliberately not built into the
  Maverick CLI. A separate experimental Linux reference-client project now
  implements that platform boundary and has bounded safety, recovery, and
  signed package-lifecycle evidence. One exact candidate also passes a bounded
  eight-hour sustained-resource and route-isolation gate. Broader
  transition/leak, power-loss, package-publication, daily-use, and
  cross-platform gates remain open.

## Core Tracking Items

- Native server-side ECH remains a core long-term tracking item. The current
  workaround is Cloudflare-fronted WebSocket, where Cloudflare handles
  client-facing ECH and Maverick runs as the origin. Native Maverick ECH stays
  disabled until server-side TLS backend support and approved-host runtime
  evidence exist. See [docs/NATIVE_ECH_TRACKING.md](docs/NATIVE_ECH_TRACKING.md).

See [docs/PLAN_POST_V1.md](docs/PLAN_POST_V1.md) for the active execution plan
and [ROADMAP.md](ROADMAP.md) for the concise public direction.
See [docs/TRANSPORT_ARCHITECTURE.md](docs/TRANSPORT_ARCHITECTURE.md) for the
internal transport abstraction plan.
See [docs/H3_QUIC_PLAN.md](docs/H3_QUIC_PLAN.md) for the optional H3/QUIC
status and guardrails.

## Documentation Map

- [docs/DOCS_INDEX.md](docs/DOCS_INDEX.md): short contributor reading path and
  active/history inventory.
- [STATUS.md](STATUS.md): current claim boundary, ready/not-ready summary, and
  process notes.
- [docs/PLAN_POST_V1.md](docs/PLAN_POST_V1.md): active post-v1 execution order,
  evidence gates, and release mapping.
- [ROADMAP.md](ROADMAP.md): concise current direction and long-term sequencing.
- [docs/PLAN_SHORT_TERM_TO_V1.md](docs/PLAN_SHORT_TERM_TO_V1.md):
  completed plan from alpha to `v1.0.0`.
- [docs/RELEASE_TRAIN.md](docs/RELEASE_TRAIN.md): alpha -> beta -> rc ->
  stable gate history.
- [docs/STABLE_SCOPE_CANDIDATE.md](docs/STABLE_SCOPE_CANDIDATE.md): first
  narrow stable-scope candidate definition.
- [SPEC.md](SPEC.md): protocol and session behavior.
- [WIRE_FORMAT.md](WIRE_FORMAT.md): frame encoding details.
- [CONFIG.md](CONFIG.md): client and server configuration.
- [SECURITY.md](SECURITY.md): security policy, limitations, and release checks.
- [THREAT_MODEL.md](THREAT_MODEL.md): explicit defended and non-defended cases.
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md): release verification checklist.
- [SUPPORT.md](SUPPORT.md): support, security-report, and compatibility policy.
- [docs/OPERATIONS.md](docs/OPERATIONS.md): self-hosted operations guide.
- [docs/PRODUCTION_SCOPE.md](docs/PRODUCTION_SCOPE.md): narrow v1.2.0 production
  target and permanent scope exclusions.
- [docs/INDEPENDENT_AUDIT_PACKAGE.md](docs/INDEPENDENT_AUDIT_PACKAGE.md):
  pre-freeze external-auditor scope and instructions; not an audit result.
- [docs/RELEASE_GATES_V1_2.md](docs/RELEASE_GATES_V1_2.md): exact public alpha,
  beta, RC, and stable gates.
- [docs/PUBLIC_FEEDBACK_PROCESS.md](docs/PUBLIC_FEEDBACK_PROCESS.md): public
  issue triage, privacy boundaries, and active-milestone selection rules.
- [docs/FAILURE_INJECTION_PLAN.md](docs/FAILURE_INJECTION_PLAN.md): restart,
  timeout, target-failure, and network-impairment evidence plan.
- [docs/RELEASE_ARTIFACTS.md](docs/RELEASE_ARTIFACTS.md): local artifact and
  checksum workflow.
- [docs/RELEASE_TAGGING.md](docs/RELEASE_TAGGING.md): tag and release policy.
- [docs/history/](docs/history): dated alpha, release, readiness, evidence, and
  review archives.

## Quick Start

Build:

```sh
cargo build --workspace
```

Generate a user credential:

```sh
cargo run -p maverick-cli -- gen-user --name alice
```

Compute a certificate pin from a PEM certificate:

```sh
cargo run -p maverick-cli -- pin-cert --cert certs/fullchain.pem
```

Generate example config files:

```sh
cargo run -p maverick-cli -- gen-config
```

This writes `client.generated.yaml` and `server.generated.yaml`. They contain
fresh credential material and are ignored by git.

Validate configs:

```sh
cargo run -p maverick-cli -- check-config --kind server -c server.generated.yaml
cargo run -p maverick-cli -- check-config --kind client -c client.generated.yaml
```

Review credential rotation state without printing secrets:

```sh
cargo run -p maverick-cli -- rotate-credential --server server.generated.yaml --dry-run
```

List disabled-by-default experimental tracks:

```sh
cargo run -p maverick-cli -- experimental list
```

Import a profile URI from the OS clipboard without printing secret material:

```sh
cargo run -p maverick-cli -- config-uri import --clipboard --dry-run
```

For secret-bearing URIs, prefer stdin instead of shell argv:

```sh
pbpaste | cargo run -p maverick-cli -- config-uri import --uri - --dry-run
```

Run a loopback-only benchmark:

```sh
cargo run -p maverick-cli -- bench-local --bytes 65536 --concurrency 1
```

The benchmark can also run bounded shaping scenarios without changing any
system network settings:

```sh
cargo run -p maverick-cli -- bench-local --bytes 65536 --mode private --client-shaping --server-shaping
```

Run the server:

```sh
cargo run -p maverick-cli -- server -c server.generated.yaml
```

Run the client:

```sh
cargo run -p maverick-cli -- client -c client.generated.yaml
```

Point local applications at the SOCKS5 listener, normally
`127.0.0.1:1080`.

If enabled, local DNS relay listens on the configured UDP address, normally
`127.0.0.1:5353`. HTTP CONNECT inbound is available as an optional local-only
listener for tools that support HTTP proxy settings.

Client listeners reject non-loopback addresses by default. Use
`advanced.allow_non_loopback_listeners: true` only when you intentionally want
to bind a non-loopback address. Runtime peer filtering still rejects
non-loopback clients; the current v1.x line does not provide an authenticated
open proxy mode.

## Modes

The user-visible modes are product policy labels:

- `auto`: default behavior; TLS/H2, authentication, replay protection, static fallback.
- `stable`: conservative behavior for networks where UDP is unreliable; TCP relay stays the primary path.
- `private`: stricter logging posture and reserved future privacy fields.

The implementation does not expose H2, QUIC, Noise, padding, or cipher-suite
selection as ordinary user choices. H3 is available only through build and
runtime experimental gates.

## Testing

All current integration tests bind only to `127.0.0.1` with OS-assigned
ephemeral ports. They do not change system proxy, DNS, route, firewall, or
VPN/proxy application settings.

Default local harness:

```sh
./scripts/local-harness.sh
```

Core Rust checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See [docs/HARNESS_ENGINEERING.md](docs/HARNESS_ENGINEERING.md) for the repo
workflow used to keep agent-driven changes bounded and verifiable.

Loopback benchmark baseline:

```sh
./scripts/benchmark-baseline.sh
```

Optional H3 feature-gate build:

```sh
./scripts/h3-harness.sh
```

Optional ECH feature-gate build:

```sh
./scripts/ech-harness.sh
```

Pre-release dependency advisory and first-party unsafe-code inventory:

```sh
./scripts/security-dependency-inventory.sh
```

## Security Notes

- Use `maverick gen-user` for high-entropy secrets.
- Do not use short passwords as secrets.
- Protect server and client config file permissions.
- Use real TLS certificates for deployed servers.
- Optional `cert_pin` uses `sha256/<base64url-no-pad>` over the leaf certificate DER.
- Maverick defaults to rustls and does not claim to look exactly like Chromium
  or any browser.
- Client `private` mode rejects the default rustls TLS fingerprint. Use a
  build with the optional `browser-tls` feature before treating that mode as
  configurable.
- `advanced.stealth.tls_fingerprint: browser_mimic` is available only in
  builds compiled with the optional `browser-tls` feature. It uses a BoringSSL
  client path with TLS exporter channel binding, GREASE, extension permutation,
  Chrome-reference ALPN, and Chrome-reference H2 settings. Measured ALPS and
  signature-algorithm differences remain, so it is browser-like, not
  browser-identical.
- Unauthenticated tunnel-like requests are served fallback content rather than
  Maverick-specific protocol errors.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Contributing

Maverick is intentionally conservative about local network safety. Tests and
examples should stay loopback-only unless a separate approved test host is
explicitly documented. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening
larger changes.

## License

Apache License 2.0. See [LICENSE](LICENSE).
