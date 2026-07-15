# ECH Feature Gate Design

Status: design complete for v3 planning. Build features, config gates, local
feature harness, and operator-safe diagnostics are declared;
`experimental_ech: true` is rejected until native TLS stack support is wired
and tested. `docs/history/manifests/ech-runtime-approval.json` records the native runtime gate,
completed local/Cloudflare-fronted evidence, and keeps native ECH handshakes
disallowed. `docs/history/manifests/ech-runtime-blockers.json` tracks blocker-first preparation
slices such as client API tracking, approved-host readiness, Cloudflare DNS
planning, Cloudflare-fronted runtime smoke, upstream server TLS support, and
native runtime handshake acceptance. Native Maverick server-side ECH handshakes
are not implemented.

Encrypted ClientHello can reduce exposure of the public TLS ClientHello server
name in deployments that have correct DNS and TLS ecosystem support. Maverick
must treat ECH as an optional deployment feature, not a default privacy claim.

Relevant standards:

- RFC 9849: TLS Encrypted ClientHello, https://www.rfc-editor.org/rfc/rfc9849
- RFC 9848: Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings,
  https://www.rfc-editor.org/rfc/rfc9848
- RFC 9934: ECH configuration for public names,
  https://www.rfc-editor.org/rfc/rfc9934

## Goals

- Keep ECH off by default.
- Add only when the Rust TLS and QUIC stacks expose stable, reviewed APIs.
- Avoid weakening ordinary certificate validation.
- Avoid silent fallback that exposes SNI in `private` mode.
- Keep H2/TLS as the reliable fallback transport when ECH is not enabled.

## Non-Goals

- Hard-coding a provider-specific ECH configuration.
- Shipping a custom ECH implementation.
- Claiming browser parity.
- Treating ECH as a substitute for fallback, auth, or replay protections.

## Feature Gate

Build-time gate:

```toml
[features]
ech = []
```

Runtime gate:

```yaml
advanced:
  experimental_ech: false
  ech_fallback_policy: "fail_closed"
```

The runtime flag is ignored unless the binary is compiled with the ECH feature
and the selected TLS backend supports ECH.

Implemented baseline:

- workspace crates declare an `ech` feature with no TLS behavior attached;
- `scripts/ech-harness.sh` compiles and tests the workspace with
  `--features ech`;
- the feature harness includes a compile-time smoke for rustls client ECH API
  names used by a future runtime implementation;
- client/server config default `advanced.experimental_ech` to false;
- client config defaults `advanced.ech_fallback_policy` to `fail_closed`;
- `experimental_ech: true` is rejected until implementation support exists;
- `private` mode rejects `allow_plain_sni`.
- `EchDiagnosticsSnapshot` reports requested/disabled status, current
  implementation support, fallback policy, and private-mode plain-SNI blocking
  without suggesting downgrade behavior.
- `EchReadinessSnapshot` records build feature, client TLS API,
  Cloudflare-fronted runtime smoke evidence, server TLS backend, ECH config
  source, controlled integration, and runtime config acceptance gates.
- `docs/history/manifests/ech-runtime-approval.json` records that client TLS API tracking,
  fallback-policy tests, controlled Cloudflare DNS evidence, approved-host
  preparation, and Cloudflare-fronted WebSocket runtime smoke are distinct from
  native server-side ECH. Server TLS backend and native ECHConfig distribution
  remain blocked, and runtime config acceptance remains deferred.
- `docs/history/manifests/ech-runtime-blockers.json` records the execution plan boundary: client API
  and fallback-policy tests are complete locally, `approved-linux-vm` is the
  approved integration host, the Cloudflare subdomain plan plus edge-only
  preflight and origin reachability are complete, the Cloudflare-fronted
  WebSocket runtime smoke has passed on approved hosts, earlier H2/gRPC runtime
  attempts remain documented as provider-behavior incompatibility, and native
  server-side runtime support remains blocked on TLS-stack readiness.

## Fallback Policy

ECH failure has different privacy consequences than an ordinary H3 failure.

```text
stable  -> ECH disabled unless explicitly configured
auto    -> fallback allowed only if ech_fallback_policy = allow_plain_sni
private -> fail closed on ECH setup failure
```

`allow_plain_sni` must be explicit in config. It should never be inferred.

## Configuration Inputs

The implementation should consume ECH configuration from standard DNS
SVCB/HTTPS records or from an explicit operator-supplied config file once
supported by the TLS stack.

It should validate:

- ECH config freshness;
- public name and origin name consistency;
- certificate chain validation after handshake;
- ALPN compatibility for H2 and H3;
- no 0-RTT for authenticated tunnel setup.

## Required Tests

Initial tests can be compile-time and config-level until TLS stack support is
available:

- `ech` feature compiles without enabling ECH by default.
- `ech` feature compile checks fail if the tracked rustls client ECH API names
  disappear or move.
- Config rejects `experimental_ech: true` when the binary lacks support.
- `private` mode fails closed on simulated ECH setup failure.
- `auto` mode allows fallback only with explicit `allow_plain_sni`.
- Explicit diagnostics report unsupported ECH and private-mode plain-SNI
  blockers without emitting downgrade advice.
- Readiness diagnostics expose concrete blockers without marking runtime ECH
  ready.
- No test changes host DNS, proxy, firewall, route, VPN, or other network-service settings.

Later integration tests should run on a dedicated VM or explicit test host with
controlled DNS records. They should not run against the user's everyday network
configuration.

`scripts/check-ech-runtime-approval.py` keeps that boundary machine-checkable:
approval metadata must not allow native runtime ECH or network activity,
completed gates must stay completed, and native server-side gates must remain
blocked or deferred until upstream TLS support and config-source coverage exist.

See `docs/ECH_UPSTREAM_STATUS.md` for the current rustls client/server support
boundary and source links. See `docs/ECH_NATIVE_TLS_LIMITATION.md` for the
plain-language native ECH limitation explanation. See
`docs/ECH_RUNTIME_PLAN.md` for the frozen blocker-reduction reference and
Cloudflare subdomain preparation boundary. `docs/ECH_WORKAROUND.md` documents
the Cloudflare-fronted WebSocket workaround that keeps native ECH rejected
while removing ECH as a broader roadmap blocker.

## Current Decisions

- No Rust TLS API is treated as stable enough for Maverick ECH runtime support
  until client and server behavior, controlled ECH config distribution, and VM
  integration tests are all available.
- A client-only ECH API is not enough to enable runtime ECH. Server backend,
  config distribution, fallback behavior, and controlled integration evidence
  must all pass the readiness gate first.
- H2 and H3 should share config parsing and fallback-policy validation, but
  handshake validation should remain transport-specific when runtime support is
  implemented.
