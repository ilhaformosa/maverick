# Auth v2 Design

Status: v3 runtime baseline implemented behind explicit client and server
configuration. Core `ClientHelloV2` / `ServerHelloV2` data structures,
HKDF-SHA256 epoch-key derivation, unit tests, and loopback runtime tests are
implemented. Auth v1 remains the default path.

Auth v2 is a compatibility-layer design for rotating credentials, reducing
long-lived credential metadata exposure, and keeping replay state bounded. It
does not replace TLS and does not introduce custom unaudited cryptography.

## Goals

- Keep the user-facing product identity as Maverick.
- Preserve v1 auth while v2 rolls out.
- Support epoch-based credential rotation.
- Bind auth to the tunnel path, policy mode, transport feature flags, and replay
  nonce.
- Keep all lookup, replay, and flow state bounded.
- Avoid logging credential ids, auth tags, secrets, or pre-auth failure causes.

## Non-Goals

- Replacing TLS authentication or confidentiality.
- Shipping HPKE, Noise, or post-quantum handshakes as a default path.
- Claiming anonymous credentials before blinded lookup is implemented and
  reviewed.
- Requiring users to select a transport or auth version manually.

## Compatibility Model

Auth v1 remains the default path until Auth v2 has migration tooling,
operational hardening, and an external review path.

Servers accept v2 only when explicitly configured:

```text
auth:
  v2:
    enabled: true
    require: true
    accepted_epochs: [202607, 202608]
```

Servers reject configs that enable Auth v2 without `auth.v2.require: true`.
This avoids a quiet mixed mode where v1 remains accepted after v2 is enabled.

Clients opt into v2 explicitly:

```text
auth:
  v2:
    enabled: true
  rotation:
    active_epoch: "202607"
```

If `auth.rotation.auto_switch=true`, the client uses the same validated
next-credential selector for Auth v2 credential hints and ServerHelloV2
verification. Otherwise Auth v2 uses `server.credential_id` and `server.secret`
like the v1 path.

Before operators configure both sides, clients continue using v1.

## ClientHelloV2 Sketch

```text
protocol_version:  u16 = 2
auth_epoch:        u64
client_nonce:      32 bytes
timestamp_unix:    i64
credential_hint:   variable opaque bytes
mode:              u8
feature_flags:     u64
rotation_flags:    u32
auth_tag:          32 bytes HMAC-SHA256
```

`credential_hint` is not a secret. The v3 implementation may initially use a
rotated explicit id, but the field is shaped so a later blinded lookup scheme
can fit without changing the rest of the transcript.

The auth tag transcript must include:

- protocol version;
- epoch;
- nonce;
- timestamp;
- credential hint;
- tunnel path;
- policy mode;
- selected transport feature flags;
- rotation flags.

## ServerHelloV2 Sketch

```text
protocol_version_selected: u16 = 2
selected_epoch:            u64
server_nonce:              32 bytes
session_id_len:            u8
session_id:                session_id_len bytes
max_frame_size:            u32
max_concurrent_flows:      u32
feature_flags_selected:    u64
rotation_window_secs:      u32
server_auth_tag:           32 bytes HMAC-SHA256
```

The server tag must bind the client nonce, server nonce, selected epoch,
session id, limits, and selected feature flags.

## Epoch Derivation

Auth v2 should derive per-epoch MAC keys from the configured credential secret
instead of using the long-lived secret directly for every epoch.

Candidate derivation:

```text
epoch_mac_key = HKDF-SHA256(
  input_key_material = credential_secret,
  salt = "Maverick auth v2 epoch" || auth_epoch,
  info = "client" or "server"
)
```

This derivation must use reviewed Rust crypto APIs. It must not be hand-rolled
from raw hash concatenation.

## Replay Policy

Replay cache keys become:

```text
auth_version || selected_epoch || credential_lookup_key || client_nonce
```

The server accepts only configured epochs. A normal rotation window should
accept the current and immediately previous epoch. Larger overlap windows are
operator-risk decisions and must remain explicit.

Replay failure remains pre-auth behavior: serve fallback content or close as an
ordinary web failure without a Maverick protocol error.

## Implemented Baseline

- `ClientHelloV2` encode/decode and verification.
- `ServerHelloV2` encode/decode and verification.
- HKDF-SHA256 per-epoch MAC-key derivation.
- Credential-hint length bounds.
- Unit tests for roundtrip, tag binding, epoch binding, and session length
  bounds.
- Client-side opt-in when `auth.v2.enabled=true` and
  `auth.rotation.active_epoch` is a numeric epoch.
- Server-side accept path when `auth.v2.enabled=true`,
  `auth.v2.require=true`, and the client epoch is listed in
  `auth.v2.accepted_epochs`.
- Server-side v2-only enforcement for every v2-enabled server.
- Loopback integration tests for v2 TCP relay, unaccepted epoch rejection, and
  expired epoch rejection outside the configured rotation window.
- Blinded credential lookup is tracked as a research-only experimental track;
  the runtime still uses explicit credential hints.
- v1 remains the default when Auth v2 is disabled. Enabling Auth v2 makes the
  server v2-only.

## Migration Plan

1. Keep v1 as the default path while v2 is opt-in.
2. Add migration dry-run checks that detect missing client/server epoch
   settings.
3. Add epoch-specific replay cache tests.
4. Design blinded or less-identifying credential lookup experiments behind the
   `blinded-lookup-experimental` research track.
5. Add operational docs for rolling epoch windows.

## Required Tests

Implemented:

- Auth v2 encode/decode roundtrips.
- Valid and invalid client tag verification.
- Valid and invalid server tag verification.
- Config rejects enabled client v2 without a numeric active epoch.
- Config rejects enabled server v2 without accepted epochs.
- v1-only server still accepts v1 clients.
- v2-enabled server can still accept v1 during migration.
- v2-enabled client/server can complete a loopback TCP relay.
- Unaccepted v2 epochs are rejected before tunnel setup.
- Expired v2 epochs outside the configured rotation window are rejected before
  tunnel setup.
- Replay rejection across epoch and nonce combinations.
- Current plus previous epoch acceptance.
- Disabled user and wrong secret return fallback-like behavior.
- Log hygiene scan rejects logging macros that include secrets, raw auth tags,
  credential hints, or credential ids.

## Current Decisions

- The first v2 runtime baseline uses explicit credential hints. Blinded lookup
  remains a research-only experimental track and is not required before the
  first opt-in v2 release.
- Client config currently requires numeric `auth.rotation.active_epoch` values
  for Auth v2. Operators can map those numbers to calendar buckets or internal
  counters outside the wire protocol.
- No new pre-auth server capability discovery endpoint is added. Clients use
  explicit local config and existing fallback-like failure behavior so v1/v2
  negotiation does not become a new fingerprintable unauthenticated signal.
