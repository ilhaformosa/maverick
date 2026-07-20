# Security Policy

Maverick is experimental alpha software. Do not treat it as audited,
production-ready, anonymous, censorship-resistant, or browser-identical.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting when available. If it is
unavailable, open a public issue containing only a non-sensitive coordination
request. Never place exploit details, credentials, real endpoints, private
hostnames, account data, infrastructure identifiers, payloads, or private logs
in a public issue.

The maintainer should acknowledge a report within seven calendar days when
possible and coordinate disclosure only after triage and a reasonable update
path.

## Credentials and Configs

Generate credentials with:

```sh
maverick gen-user
```

Keep client/server configs owner-readable only. Do not paste generated secrets,
private keys, bearer tokens, HMAC material, or real endpoint details into logs,
screenshots, issues, commits, or chat.

`SecretString` redacts ordinary formatting and serialization, but it cannot
protect against a compromised process, crash dump, swap, or copied plaintext.

## TLS

The supported default client build uses the BoringSSL-backed browser-like H2
path. It includes exporter channel binding, GREASE, extension permutation, and
pinned browser-reference settings, but measured differences remain. It is not
an exact browser-equivalence claim.

The CDN-fronted H2 carrier keeps the browser-like client TLS profile but
terminates TLS at the provider edge. Maverick therefore disables exporter
channel binding for fronted H2 and WebSocket; client-edge and edge-origin TLS
exporters cannot match. The provider can observe authentication and tunnel
payload. Set `trusted_tls_terminating_provider: true` only after accepting that
tradeoff. Loopback tests do not prove real-provider behavior.

`--no-default-features` builds retain the explicit rustls fallback for
development and compatibility checks. A client config may also explicitly set
`advanced.stealth.tls_fingerprint: rustls_default`; that path is distinguishable
and is rejected in `private` mode.

Use valid server certificates. Optional `cert_pin` verifies the leaf
certificate SHA-256 after normal CA and hostname validation; it is not a
replacement for them.

## Network and Logging Limits

Client listeners bind to loopback by default. Keep server egress blocks for
loopback, private, link-local, multicast, shared, and unspecified ranges unless
a separate deployment has its own isolation and review.

Ordinary logs must not include credentials, HMAC tags, payload bytes, TLS
keying material, or full target domains in private mode.

## Local Safety

Local tests and demos use `127.0.0.1` and OS-assigned ephemeral ports. They must
not change system proxy, DNS, routes, firewall, VPN, interfaces, or network
services. A real-network pilot requires separately named owner-controlled
systems and explicit authorization.

## Dependency Gate

Before publishing a binary or accepting a security-sensitive change, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
```

Review the actual Rust diff and dependency output. A passing tool is supporting
evidence, not a security sign-off.

## Archived Material

Former audit packages, release gates, incident playbooks, evidence ledgers, and
their checkers are retained under `docs/archive/` and `scripts/archive/`.
They are historical references only and must not be presented as current audit
or production approval.
