# Maverick end-to-end protection

Date: 2026-11-09
Status: implementation contract; validation state is recorded in STATUS.md.

## Goal and trust boundary

The owner requires a TLS-terminating intermediary to be unable to read
Maverick credentials, authentication messages, proxy destination addresses or
payloads, impersonate the origin, or modify accepted tunnel data. The client
and owner-operated origin remain trusted. External client development, endpoint/IP-block recovery,
new provider resources and field trials are outside this work.

An intermediary can still observe the outer endpoint, HTTP path, inner TLS
ClientHello (including the origin TLS name), connection timing and byte counts.
It can block or delay traffic. This is content confidentiality and integrity,
not anonymity, ECH, browser equivalence or a censorship-resistance claim.

## Decision: TLS 1.3 inside a streaming H2 request

```text
Maverick frames + existing auth v1/v2 + target policy
  inside H2
  inside origin-authenticated TLS 1.3
  inside one outer HTTPS/H2 POST body
  through an untrusted TLS-terminating intermediary
  to the owner-operated origin
```

The outer connection retains the existing TLS identity checks and H2 profile.
The inner connection uses existing rustls TLS 1.3 and H2 session code. The
client checks its CA chain, hostname and a mandatory owner-supplied leaf
SHA-256 pin before sending Maverick authentication. Deliver the pin independently
of the intermediary; no trust-on-first-use or fallback to outer trust is allowed.
The origin reuses its configured certificate and private key, which must not
be supplied to the intermediary. Certificate replacement requires an explicit
pin update. Inner 0-RTT is disabled.

The outer request is POST to the configured tunnel path with content type
`application/octet-stream`. A successful response has status 200 and the same
content type. Bodies carry an unmodified bidirectional TLS byte stream; HTTP
DATA boundaries have no TLS meaning. Inner ALPN is `h2`. Existing Maverick
gRPC framing, auth versions, flow limits, egress checks and half-close semantics
run inside inner H2 unchanged. Authentication binds to the **inner** TLS
exporter, never the intermediary-facing exporter.

The media type is deliberately generic. A TLS-over-HTTP endpoint is still
observable to an active requester that knows its path; this is not a new claim
of probe indistinguishability.

A protected listener accepts only this outer envelope at its tunnel path.
Protection is not negotiated from an unauthenticated header. Neither endpoint
retries a failed inner handshake as plaintext or recursively accepts nested
envelopes. Unrelated outer requests retain ordinary HTTP fallback handling.

## Configuration and compatibility

- Client: `advanced.end_to_end` supplies `server_name`, optional `ca_cert`,
  and required `cert_pin` for the inner origin. Existing `server` fields
  describe the outer TLS endpoint and the Maverick credential/path.
- Server: `advanced.end_to_end: true` requires the protected envelope using
  existing `tls` files. Both ends require enabled channel binding.
- This envelope is H2-only; WebSocket and explicit H3 reject this option.
  Direct H2/H3 already authenticate the origin through carrier TLS; H3 remains
  default-off. TLS-terminating H3 fronting remains unsupported.
- Omitted settings retain existing wire behavior. Historical explicitly
  trusted-provider H2/WS configurations are compatibility paths that do NOT
  satisfy intermediary confidentiality. They are never fallback destinations
  for a protected connection. Published RC.2 stays immutable.
- Profile URI v1 and policy-only Config v2 projection reject the new setting
  rather than discard inner identity. No new auth or runnable config version.

## Cost and implementation boundary

Direct carrier TLS protects content only if an intermediary does not terminate
it. Custom frame cryptography or promoting the old Noise experiment would add
another key lifecycle, record format and frame-size boundary. Nested TLS reuses
certificate, exporter, auth and relay code at the cost of an extra TLS/H2
handshake and encrypted framing. Inner H2 reuses the existing bounded client
pool. Existing connection, handshake, idle and admission limits apply; no
per-packet task or new supervisor is required.

The intermediary must stream request and response bodies simultaneously.
Local success does not qualify a CDN's buffering policy or timeouts. Validation
uses a local TLS-terminating relay with a separately trusted outer certificate.

## Acceptance

Verify real client/server sessions through that relay:

- auth v1/v2, payload integrity, both TCP half-close orders, concurrent flows,
  cancellation, release and restart;
- no credential identifier, proxy target or known application payload in the
  relay's decrypted outer body (a bounded observation, not a crypto proof);
- valid outer TLS cannot substitute the origin; wrong inner CA, hostname or
  pin fails before target access;
- tampered records and captured-session replay fail without plaintext retry;
- protection mismatch fails, existing H2/H3 stays covered, and export cannot
  silently discard protection;
- all applicable local/CI product, rustls, H3, candidate, dependency, native
  artifact/rollback and code-scanning checks remain enabled.

TLS security relies on RFC 8446 and its maintained implementation. Future
native UDP must meet the same trust boundary; a TLS byte stream is not native
Datagram delivery. Select that carrier before changing UDP wire semantics.

Reference: https://www.rfc-editor.org/rfc/rfc8446.html
