# Comprehensive Security Audit Remediation 2026-07-08

Source: consolidated external audit report `COMPREHENSIVE_SECURITY_AUDIT.md`.

This file records engineering remediation work. It is not an audit,
certification, production-readiness sign-off, anonymity claim, or browser
fingerprint-equivalence claim.

## Finding Status

| ID | Status | Resolution |
|---|---|---|
| M-1 | Fixed | H2 rejection fallback preserves method, path/query, request headers, and bounded request bodies. Reverse-proxy fallback preserves non-GET requests and decodes chunked upstream responses. Active-probe regression tests compare rejected tunnel requests with same-path fallback behavior. |
| M-2 | Mitigated with residual release blocker | Client `private` mode now rejects `rustls_default`; docs state the default rustls fingerprint is identifiable and `browser-tls` remains the only browser-mimic path. This does not claim browser-identical TLS or make browser-mimic the global default. A real fingerprint evidence gate is still required before stronger stealth claims. |
| M-3 | Fixed for native TLS carriers | ClientHello and ServerHello HMAC transcripts can include TLS exporter channel-binding material. H2 and WebSocket carriers export channel binding from rustls TLS sessions, and `auth.channel_binding.require` rejects unsupported transports. |
| L-1 | Fixed | Server H2 now sets explicit concurrent-stream and reset-stream caps. H3 uses the same configured concurrent-stream cap where supported. |
| L-2 | Fixed | H2 and H3 accept loops drain finished stream tasks during long-lived connections, avoiding completed task handle buildup. |
| L-3 | Fixed and documented | Replay cache now separates per-credential nonce capacity from per-shard credential-key capacity. Docs clarify that replay cache state is process-local memory and is not shared across restarts or nodes. |
| L-4 | Fixed | `serde_yaml` was replaced with `serde_yaml_ng`; a weekly/manual supply-chain workflow runs `cargo audit`, cargo-deny advisories/bans/licenses/sources, and first-party unsafe-code inventory. `deny.toml` covers all features and bans reintroducing `serde_yaml`. |
| L-5 | Mitigated | Server credential matching now borrows user and secret material instead of cloning them for each authentication attempt. First-party crates now forbid unsafe Rust code. |

## Information-Level Hardening

| Item | Status | Resolution |
|---|---|---|
| Certificate pin comparison | Fixed | H2 certificate pin comparison uses constant-time equality. |
| 6to4 anycast range | Fixed | Default egress policy rejects the full `192.88.99.0/24` reserved range. |
| Reverse-proxy parser robustness | Improved | Tests cover non-GET preservation and chunked upstream response decoding. |
| Protocol-version timing differences | Deferred | No security claim depends on equal timing here; broader timing statistics remain future hardening work. |
| gRPC trailer/status mimicry | Deferred | Current tests cover fallback shape and protocol-error hiding; exact gRPC trailer mimicry remains future active-probe hardening. |

## Verification

- `./scripts/local-harness.sh`
- `./scripts/security-dependency-inventory.sh`
- `cargo deny check advisories bans licenses sources`
- `cargo test -p maverick-tests --test tcp_relay --quiet`
- `cargo test -p maverick-core -p maverick-server -p maverick-client --quiet`
