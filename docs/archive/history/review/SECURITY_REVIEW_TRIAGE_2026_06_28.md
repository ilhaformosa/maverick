# Security Review Triage 2026-06-28

Sources:

- local external-AI review at
  `<repo-root>-security-review-2026-06-28.md`;
- follow-up AI-assisted security review at
  `<repo-root>-ai-security-review-2026-06-28.md`.

This triage records engineering follow-up. It is not an audit, certification,
production-readiness sign-off, or security guarantee.

## Finding Status

| ID | Status | Resolution |
|---|---|---|
| MAV-01 | Fixed | Auth tag verification now uses `subtle::ConstantTimeEq` for v1 and v2 client/server hello tags. |
| MAV-02 | Fixed | Rejected tunnel-like H2/H3 requests now pass the original method and path/query to fallback routing instead of forcing `GET /`. Reverse-proxy fallback still normalizes unsupported methods to `GET` by design. |
| MAV-03 | Fixed | Server TCP, UDP, and DNS relay paths enforce `advanced.egress`; default policy blocks loopback, private, shared, link-local, multicast, unspecified, IPv4-mapped IPv6, deprecated IPv4-compatible IPv6, and well-known NAT64-embedded private/internal forms. Loopback tests opt in explicitly. |
| MAV-04 | Fixed | `gen-config` and `config-uri import` now create secret-bearing output files with `0600` permissions on Unix and refuse overwrite through `create_new`. |
| MAV-05 | Fixed | Replay cache now rejects new entries when full after cleanup instead of evicting in-window entries. SPEC and conformance vectors now match this behavior. |
| MAV-06 | Mitigated | Unknown credential paths now perform equivalent HMAC verification work using a per-server dummy secret before fallback. This reduces credential-id timing differences but does not claim full active-probing indistinguishability. |
| MAV-07 | Fixed | `auth.v2.require` lets operators reject v1 ClientHello after v2 migration. Default remains compatible. |
| MAV-08 | Fixed | Server stable mode now rejects experimental H3 and Cloudflare WebSocket carriers. `experimental_h3=true` also fails at server startup when the `h3` feature is not compiled. |
| MAV-09 | Documented | Private-mode log redaction remains a guardrail for future target/size logging; current runtime does not log destinations or payload sizes by default. |
| MAV-10 | Fixed with residual risk | Server pre-auth work is bounded by `advanced.pre_auth_max_concurrent`, and repeated failed tunnel auth is rate-limited by source IP with `auth_rate_limit_rejections` metrics. This is still not a DDoS mitigation layer and needs long-haul/load evidence before production claims. |
| MAV-11 | Documented | `gen-user` printing to stdout remains intentional. Operators must avoid leaking terminal scrollback; a future `--out` mode can write `0600` secret files. |
| MAV-12 | Fixed | DNS UDP response buffer increased to 65,535 bytes. |

## Follow-Up AI Review Findings

| ID | Status | Resolution |
|---|---|---|
| MAV-AI-001 | Fixed | `ServerEgressPolicyConfig::allows_ip` canonicalizes IPv4-mapped, deprecated IPv4-compatible, and well-known NAT64-embedded IPv4 addresses before policy classification. Tests cover loopback, private, shared, link-local, multicast, and public embedded forms. |
| MAV-AI-002 | Fixed | TCP carrier handshakes now enforce `advanced.handshake_timeout_ms` around TLS accept, H2 handshake, WebSocket handshake, and first ClientHello reads. H2 connection accept and Cloudflare WebSocket relay loops now enforce `advanced.idle_timeout_secs`. |
| MAV-AI-003 | Fixed | `ReplayCache` is partitioned by credential and keeps reject-when-full semantics within each credential partition. `maverick.replay_cache_entries_per_credential` makes the per-credential cap operator-configurable. |
| MAV-AI-004 | Fixed | H2 client and server Rustls configs now pin TLS 1.3, matching the documented carrier claim. A loopback integration test verifies a TLS 1.2-only client is rejected. |
| MAV-AI-005 | Fixed | `Frame::decode_from` validates the frame type before mutating the input buffer. A unit test asserts unknown frame types leave the buffer unchanged. |
| MAV-AI-006 | Documented | Active-probing non-claims remain explicit. Cloudflare-fronted WebSocket/ECH documentation now treats Cloudflare as a fully trusted TLS-terminating front that can observe auth frames and tunnel payload. |

## Remaining Non-Claims

- Maverick is still experimental and unaudited.
- These fixes do not prove indistinguishability from fallback origins.
- Authenticated server egress remains inherent to proxy operation; operators
  should keep the default egress policy or deploy additional network isolation.
- HPKE, ML-KEM, and native server-side ECH runtime paths remain blocked until
  their dedicated upstream/review gates are satisfied. Noise has a
  feature-gated core session harness, but product transport exposure remains
  disabled by ordinary config.
- Cloudflare-fronted WebSocket/ECH is not native server-side ECH. The fronting
  provider terminates TLS and must be treated as fully trusted for that mode.
- The external-AI reviews are useful engineering triage input and have been
  used to address concrete findings. They defer, but do not replace, community
  or independent review evidence before stable, public security, or production
  claims.

## Verification

Relevant tests and harnesses:

- `cargo test -p maverick-core`
- `cargo test -p maverick-server`
- `cargo test -p maverick-tests`
- `cargo test -p maverick-tests server_rejects_tls12_only_client`
- `cargo test -p maverick-cli import_config_uri_writes_output_and_refuses_overwrite`
- `python3 conformance/runner/python_verify.py conformance/vectors`
- `./scripts/local-harness.sh`
