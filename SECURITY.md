# Security Policy

Maverick is a narrow stable engineering release of an experimental prototype
and should not be treated as production security software.

## Reporting Security Issues

Use private reporting for vulnerabilities. Prefer GitHub private vulnerability
reporting when it is available for this repository. If that GitHub entry point
is unavailable, open a public issue with only a short, non-sensitive title such
as "Security report coordination request" and ask the maintainer to coordinate
privately. Do not include exploit details, real server addresses, private
hostnames, generated credentials, access tokens, keys, HMAC tags, payload data,
or private logs in public issues.

The maintainer should acknowledge security coordination requests within
7 calendar days when possible. Public disclosure should wait until the report is
triaged and users have a reasonable update path.

The complete private-report lifecycle is in
`docs/SECURITY_DISCLOSURE_WORKFLOW.md`; finding severity and release effect are
in `docs/AUDIT_REMEDIATION_POLICY.md`; incident playbooks are in
`docs/INCIDENT_RESPONSE.md`.

## Secrets

Use:

```sh
maverick gen-user
```

Generated secrets are high-entropy base64url values prefixed with `mv1_`.
Short passwords are rejected by config validation.

Do not paste secrets into issue trackers, logs, screenshots, or chat messages.
Maverick zeroizes `SecretString` storage on drop, but this is not a complete
defense against process memory disclosure, copies, swap, crash dumps, or
compromised hosts.

## Config File Permissions

Server and client configs may contain user credentials. Store them with
restricted filesystem permissions and avoid syncing them to untrusted locations.
The CLI creates generated and imported secret-bearing config files with
owner-only permissions on Unix. Starting the client or server refuses
group/other-readable configs by default; `--allow-loose-permissions` is an
explicit operator override for test environments.

## Local Listener Scope

Client SOCKS5, DNS, and HTTP CONNECT listeners are loopback-only by default.
Only set `advanced.allow_non_loopback_listeners: true` when you intentionally
need to bind a non-loopback address. In the current v1.x line, runtime peer
filtering still rejects non-loopback clients; Maverick does not provide an
authenticated open-proxy mode.

## TLS

Use valid TLS certificates for deployed servers. The v1 client supports a custom
CA certificate for tests or private deployments, but production deployments
should use normal certificate hygiene.

Optional `cert_pin` verifies the SHA-256 digest of the leaf certificate DER
after normal CA and hostname validation. It is not a replacement for certificate
validity checks.

Direct rustls H2/WebSocket auth can bind ClientHello and ServerHello HMACs to
the current TLS connection using TLS exporter material. This is enabled
opportunistically by default and can be required with
`auth.channel_binding.require: true` on both client and server for supported
direct TLS transports. It is not available for the experimental H3 carrier or
TLS-terminating fronted deployments.

## Logging

Default logging is redacted. Logs must not include:

- user secrets;
- HMAC tags;
- raw tokens;
- payload bytes;
- TLS keying material;
- full target domains in `private` mode.

`SecretString` redacts `Debug`, `Display`, and ordinary serde serialization by
default. CLI config writers are the explicit paths that materialize secret
values into owner-only config files.

## v1 Limitations

- Prior review input does not equal stable or production security sign-off.
- No browser-grade TLS fingerprint claim. Client `private` mode rejects the
  default rustls TLS fingerprint, but the `browser-tls` feature is still not
  proof of exact browser equivalence.
- No guarantee that active probes are perfectly indistinguishable from a normal
  fallback origin. Failed-auth requests are routed through fallback behavior
  while preserving method/path/header shape where possible, but timing, TLS
  stack, and traffic shape can still differ.
- No strong traffic-analysis resistance claim. Runtime shaping and cover
  padding are experimental, bounded, and off by default.
- No production-grade HTTP/3/QUIC transport claim.
- No claim that a Cloudflare-fronted or other TLS-terminating fronting provider
  cannot observe Maverick auth frames or tunnel payload. Fronted modes must
  treat the fronting provider as fully trusted.
- UDP relay is implemented as an experimental tunnel feature and is not
  suitable for latency-sensitive production claims.
- Per-user `rate_limit` is a simple shared byte pacer, not a precise quota,
  accounting, or abuse-prevention system.
- Server egress is policy-filtered by default, but authenticated proxy egress is
  inherent to the product. Operators should keep loopback/private/link-local
  blocks enabled unless there is a deliberate deployment reason and separate
  network isolation.
- Server-side connection counts, pre-auth work, fallback work, and repeated
  failed tunnel authentication attempts are bounded by advanced overload
  controls. This is basic overload control, not a complete WAF, account-abuse
  system, or DDoS mitigation layer.
- No protection if the client or server host is compromised.

Security review planning is documented in `docs/SECURITY_REVIEW_PLAN.md`.
The 2026-06-28 external-AI review has been triaged in
`docs/history/review/SECURITY_REVIEW_TRIAGE_2026_06_28.md`, but it is not an audit or
production sign-off.
The 2026-07-03 scoped independent alpha review findings have been remediated,
but this is still not a stable or production security certification.
The 2026-07-08 anonymous review bundle has been triaged and remediated for the
narrow `maverick-tls-h2-cli-v1` scope; see
`docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`. This closes the S3
review-input gate for an RC candidate, but it is still not a formal audit,
production sign-off, anonymity claim, censorship-resistance claim, or browser
fingerprint-equivalence claim.

The pre-freeze production audit instructions are in
`docs/INDEPENDENT_AUDIT_PACKAGE.md`. That package has not started or completed a
formal audit. Codex, AI, maintainer, and earlier scoped reviews cannot be used as
the independent production sign-off.

## Pre-Release Dependency And Unsafe-Code Inventory

Before a public source release, run:

```sh
./scripts/security-dependency-inventory.sh
./scripts/local-harness.sh
```

The public repository must also have a working private vulnerability-reporting
entry point before its visibility is changed.

This checks dependency advisories with `cargo audit`, applies the repository
`cargo-deny` policy for advisories, bans, licenses, and sources, then scans
Maverick first-party Rust sources for unsafe constructs. As of the 2026-06-30
pass, Maverick has no first-party unsafe Rust constructs. YAML config parsing
uses `serde_yaml_ng` rather than the unmaintained `serde_yaml` crate.
`cargo-geiger` was attempted as a dependency-wide
unsafe inventory tool, but the current local version does not complete
reliably on this workspace because it fails to parse
`signal-hook-registry 1.4.8`; use the script above as the active gate and
re-evaluate `cargo-geiger` after the toolchain or dependency graph changes.

## Public CI Boundary

Public pull-request and release-candidate workflows use read-only permissions,
full action revision pins, and checkout with persisted credentials disabled.
They require no deployment, package-publication, private-host, or private
reference-client secret. The release-candidate workflow builds and checks an
exact public commit but cannot push, tag, upload a package, or create a release.

Treat public runner logs as public. Never add private aliases, addresses,
provider/account data, credentials, raw runtime evidence, or exploit details to
workflow inputs or output. See `docs/CI_AND_RELEASE_GATES.md`.
