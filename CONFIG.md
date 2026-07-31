# Maverick Configuration

All currently runnable client and server config files use YAML and `version: 1`.

## Config v2 policy semantic contract

> **Policy parser only:** `maverick_core::config::v2::Policy::from_yaml_str`
> now validates the strict five-axis policy schema below. It does not define a
> complete client or server config, perform migration, read secrets, start a
> runtime, or make config v2 runnable. The canonical `ClientConfig` and
> `ServerConfig` readers still accept only config v1 and reject `version: 2`.
> T009 changes no protocol, stored-profile, authentication, frame, or wire fact.

Config v2 separates five concerns that v1 `mode` currently mixes. A persisted
config expresses requested policy or a minimum requirement. It does not prove
what a connection selected or observed at runtime.

The five canonical axes are:

| Axis | Persisted request | First accepted ID or IDs | Recommended generated value |
|---|---|---|---|
| `SecurityPosture` | `security.posture` | `standard` | `standard` |
| `TransportStrategy` | `transport.strategy` | `auto`, `h2` | `auto` |
| `TrustRoute` | `trust.route` | `direct_to_maverick`, `tls_terminating_front` | `direct_to_maverick` |
| `NamePrivacyCapability` | `name_privacy.minimum` | `plain_sni` | `plain_sni` |
| `TrafficShapingPolicy` | `traffic_shaping.policy` | `disabled` | `disabled` |

A canonical v2 config must explicitly carry all five requests. The parser must
not infer a missing axis from legacy `mode`, fill in a missing security intent,
or silently correct a conflict. Generator recommendations are not parser
defaults.

### Implemented policy-only schema

The smallest accepted direct policy is:

```yaml
version: 2
security:
  posture: standard
transport:
  strategy: auto
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
```

The smallest accepted TLS-terminating-front policy is:

```yaml
version: 2
security:
  posture: standard
transport:
  strategy: h2
trust:
  route: tls_terminating_front
  front:
    provider: cloudflare
    trusted_tls_terminating_provider: true
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
```

Both `transport.strategy: auto` and `transport.strategy: h2` are valid with
either accepted TrustRoute. The front shape carries only the provider selection
and the explicit acknowledgment that the provider terminates client-facing TLS.
It does not carry an endpoint, hostname, credential, path, or runtime proof.

The policy parser reads the original YAML directly into private strict wire
types. Every mapping node rejects unknown keys, and duplicate keys, multiple
documents, invalid version metadata, missing policy axes, conflicts, unavailable
reserved capabilities, and malformed values fail closed through fixed,
privacy-safe configuration errors. The public policy types do not implement
Serde, Default, a builder, a generator, or v1 conversion.

### Requested policy and observed results

Persisted configuration is an input:

- `security.posture` requests a local product security floor;
- `transport.strategy` requests carrier-selection behavior;
- `trust.route` requests where client-facing TLS terminates;
- `name_privacy.minimum` requests the lowest acceptable name-privacy result;
- `traffic_shaping.policy` requests whether traffic shaping is used.

Runtime facts are read-only outputs. The actual carrier, negotiated TLS version
and group, ECH acceptance, channel-binding status, selected authentication or
PQ policy, and other observed results must not be written back into config as
proof. A config cannot manufacture those facts. Later diagnostics must report
the request and the resolved or observed result separately.

### SecurityPosture

The first v2 contract accepts only `security.posture: standard`. It has no
`auto` value and no weaker user-selectable mode. `standard` represents the
locally enforceable product safety floor, including strict identity and
certificate checks, privacy-safe logging, authentication and replay gates
before target work, and bounded resource use.

`standard` does not claim that auth v3 is in use, that a PQ or hybrid KEX was
selected, that native ECH succeeded, or that an actual TLS version or group was
observed. Those facts require their separately owned protocol, policy, and
diagnostic work.

SecurityPosture does not select a carrier, change a TrustRoute, enable name
privacy, or enable traffic shaping.

### TransportStrategy

The first v2 contract recognizes `transport.strategy: auto` and
`transport.strategy: h2`. The stable ID `h3` is reserved, but it must be
rejected until the H3 capability is explicitly opened. Generated ordinary-user
configs use `auto`. Explicit `h2`, and future explicit `h3`, are developer-mode
choices and fail closed if unavailable.

Initially, H2 is the only eligible Auto candidate, so `auto` resolves to H2.
Auto may select a carrier only:

- within one DeploymentProfile;
- without changing server identity, credential namespace, TrustRoute, or any
  of the other four axes; and
- for a new session or flow that has not sent user data.

Auto must not fall back because of a certificate, server-name, pin,
authentication, replay, policy, KEX, TrustRoute, or name-privacy failure. It
must not replay or duplicate user data already sent on another carrier.

TransportStrategy selects an outer carrier. It does not select whether the
inner application carries TCP or UDP, choose a provider, change where TLS
terminates, or claim ECH.

### TrustRoute

TrustRoute has no `auto` value. The first v2 contract accepts two explicit
routes and reserves a third:

| ID | TLS termination and visibility | Current v2 status |
|---|---|---|
| `direct_to_maverick` | Client-facing TLS terminates at the Maverick server. A supported direct route can use exporter material shared by those endpoints. | accepted request |
| `tls_terminating_front` | Client-facing TLS terminates at a trusted front, followed by a separate front-to-origin connection. The front can observe Maverick authentication information and tunnel bytes. | accepted request with explicit route details and trust acknowledgment |
| `front_with_inner_e2e` | A front terminates outer TLS, while a separately designed inner Maverick session would provide origin end-to-end protection. | reserved and rejected |

A front must have explicit route details and an explicit trust acknowledgment.
Provider or fronting selection is route detail, not a transport strategy and
not proof of name privacy. DNS-resolution privacy is also outside TrustRoute.

A TLS-terminating front cannot claim direct exporter binding across the two TLS
connections. Future inner end-to-end protection requires its own protocol and
review; it must not be inferred from fronting.

### NamePrivacyCapability

NamePrivacyCapability is an independent conceptual axis, but persisted config
expresses only a minimum requirement. The first v2 contract accepts only:

```yaml
name_privacy:
  minimum: plain_sni
```

The stable ID `native_ech` is reserved and rejected until Maverick has a real
ECHConfig path, proof that ECH was accepted, and a diagnostic loop that reports
the observed result. ECH GREASE, using a provider hostname, hiding an origin IP,
and protecting DNS resolution are different properties; none proves
`native_ech`.

Observed name privacy belongs in read-only diagnostics and must not be written
back as configuration proof. If the requested minimum cannot be met, startup
or connection establishment must fail closed before DNS queries or user
traffic are sent on the nonconforming path.

NamePrivacyCapability does not choose a provider, carrier, TrustRoute, or DNS
policy.

### TrafficShapingPolicy

TrafficShapingPolicy is independent and initially accepts only
`traffic_shaping.policy: disabled`. It defaults to no behavior through an
explicit generated value, not through omission. Transport Auto must never
enable or change it.

Any future enabled policy would require separately frozen, explicit, bounded
padding, timing, batching, and cover-traffic budgets. It must not claim to hide
traffic analysis. The current schema names no enabled-policy ID, budget field,
or future sentinel: any extra mapping entry under `traffic_shaping` is an
invalid policy. Names shown in design discussion are non-normative placeholders
until T010a proves whether the complete v1 Auto and Private behavior can be
mapped without loss.

The v1 evaluator must account for every padding, timing, batching,
cover-traffic, and budget field before an enabled v2 policy is accepted.

### Deferred capability boundaries

This semantic contract does not imply that deferred capabilities exist:

- T013a freezes only the legacy-auth and policy-only projection boundary below.
- Later T013 work remains the boundary for authenticated policy confirmation,
  direct exporter and fronted application-session designs, per-flow MAC,
  downgrade protection, expiry, and revocation.
- T014 is the boundary for read-only observed diagnostics for the actual TLS
  version and group, actual carrier, binding status, and observed name privacy.
- T015 is the boundary for PQ and KEX policy plus downgrade tests.
- T011 is the boundary for Profile URI v2.
- Future H3 and UDP work is the boundary for making `h3` an executable carrier
  choice and defining its data-plane behavior.

### Pure v2 validation boundary

At minimum, the following configurations are invalid or unavailable:

| Input | Privacy-safe semantic category |
|---|---|
| legacy `mode` appears with the five v2 axes | policy conflict |
| any required axis is missing | missing required policy |
| `direct_to_maverick` carries front route details | policy conflict |
| `tls_terminating_front` lacks explicit trust acknowledgment | policy conflict |
| `tls_terminating_front` requires direct exporter binding | unavailable capability |
| reserved `h3` is requested before its capability opens | unavailable capability |
| reserved `native_ech` is requested before observed proof exists | unavailable capability |
| reserved `front_with_inner_e2e` is requested before its protocol exists | unavailable capability |
| any extra field appears under `traffic_shaping.policy: disabled` | invalid policy |

These are semantic categories, not frozen public Rust enums, API signatures, or
Display strings. Errors may identify a bounded canonical schema location, but
must not echo an endpoint, credential, secret, private path, user-provided
value, or raw input fragment.

### Config v1 compatibility boundary

Config v2 never mixes with legacy `mode`. T012a does not design a config,
stored-profile, protocol, frame, or authentication schema bump.

Existing v1 behavior remains unchanged:

- `Mode` keeps its Serde meanings and wire IDs: `auto` is `0`, `stable` is `1`,
  and `private` is `2`;
- auth v1 and v2 keep their existing transcript labels, fields, and bytes;
- Profile URI v1 remains Profile URI v1;
- stored-profile schema 1 remains schema 1 and preserves its current explicit
  channel-binding migration contract; and
- config, protocol, frame, and authentication wire versions remain independent
  compatibility boundaries.

### Legacy auth and policy-only projection contract

Auth v1 and auth v2 both carry the client's legacy Mode wire byte inside the
MAC-protected ClientHello transcript. The server authenticates the byte supplied
by the client, but it does not compare or retain that Mode as the session policy,
and ServerHello does not echo or select it. A client/server Mode mismatch can
therefore authenticate and relay successfully. After authentication, the client
continues to use its local `mode`, while the server continues to use its local
`maverick.mode_default`. This is legacy compatibility behavior, not proof that
the peers agreed on one policy.

The five config-v2 axes remain requested, local policy. A parsed or projected
policy does not prove a peer-confirmed selection or a runtime-observed result.
A config-v2 policy-only projection does not require auth v3. Any capability that
claims both peers authenticated the same policy, that the server echoed or
selected it, or that policy and auth-version downgrade was prevented must wait
for auth v3 or an equivalent separately reviewed wire contract. N/N-1
negotiation is also outside this policy-only boundary.

Legacy Mode is compatibility metadata, not a sixth v2 policy axis:

- a v2 policy must not contain legacy `mode`;
- migration must not infer Mode from the five axes or reinterpret its wire byte;
- the first positive T010b projection preserves the source `Mode::Auto` and wire
  byte `0` only as separate internal legacy compatibility metadata; and
- that metadata does not claim that the server confirmed the Mode.

The first positive T010b result is limited to one strictly valid config-v1
client input whose effective behavior is all of the following:

- legacy `Mode::Auto`;
- H2 only, with no H3 attempt or fallback;
- `direct_to_maverick`;
- plain SNI;
- traffic shaping disabled; and
- no WebSocket, mixed TrustRoute, cross-boundary fallback, or other mapping
  blocker.

Its policy-only output is exactly:

```yaml
version: 2
security:
  posture: standard
transport:
  strategy: h2
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
```

The projection must write `transport.strategy: h2`, not `auto`, so a future
expansion of Auto to H3 cannot change the preserved v1 behavior. It must not
write the legacy Mode into this policy document. Existing auth v1 or v2
selection remains a separate compatibility fact and is not changed by the
projection.

Stable and Private Mode, complete server migration, H3, WebSocket, mixed
TrustRoute, enabled shaping, and peer policy confirmation remain distinct typed
migration blockers. T010b must not collapse them into one generic readiness
result; this docs-only contract does not freeze their public Rust names.

The only positive readiness label allowed by this contract is **client policy
projection ready**. It does not mean that a complete or runnable config-v2
client exists, that secrets or runtime settings migrated, that a server agreed
with the policy, that auth v3 exists, or that downgrade protection exists.

Existing auth v1/v2 wire bytes, MAC labels and field order, and configured auth
version selection remain unchanged. This contract authorizes no automatic auth
v2-to-v1 fallback and no automatic strict-to-legacy fallback.

The current direct-route exporter binding is an existing authentication input;
it is not a claim of complete RFC 9266 policy confirmation. A TLS-terminating
front cannot share one exporter across its two TLS connections. Inner
application-session authentication and per-flow MAC for that route remain later
work.

### T010b Auto/H2 client policy projection foundation

`maverick_core::config::v2::project_v1_client_policy(&ClientConfig)` is the
only public T010b entry point. It returns a typed policy-only projection or a
typed, value-free blocker. It first applies canonical config-v1 client
validation, then checks blockers in this fixed order: legacy Mode, configured
H3, configured WebSocket, any TLS-terminating front, and enabled traffic
shaping.

The successful result exposes only the five-axis `Policy`, the retained legacy
Mode, and whether a peer confirmed that Mode. For this first subset the retained
Mode is Auto, its existing `wire_id()` remains `0`, and peer confirmation is
always false. The wire byte has no separate stored or serialized copy, and
legacy Mode never enters Policy.

Valid direct-H2 channel-binding choices and valid configuration fields outside
the five policy axes do not block projection. Those fields are not migrated.
This API has no raw-YAML adapter or serializer and does not produce a complete
or runnable config-v2 client, server agreement, or runtime result.

### T012b-1 first transport-axis runtime consumer

The client default-transport selector consumes only the successful T010b
projection's explicit H2 transport axis. A projection blocker, invalid v1
source, or unsupported future transport axis uses the unchanged legacy v1
selector, preserving existing non-projected paths. This is not a complete
config-v2, trust, name-privacy, shaping, authentication, or runtime migration,
and it does not claim peer confirmation or connection success.

### T010a effective-behavior handoff

T010a must evaluate strictly valid v1 configuration before T009 freezes a
strict v2 DTO or parser. The evaluator is a pure function whose inputs are:

- a valid v1 `ClientConfig` or `ServerConfig`;
- the client or server role; and
- only the necessary compile-time capability facts.

It performs no network access, secret access, cooldown lookup, clock read, or
environment mutation. Because its configuration inputs are already parsed,
T010a freezes only effective behavior that can be derived objectively from the
current in-memory values and Mode. It does not recover field-presence
information or original syntax that v1 parsing and defaults have already
erased. Its output must report effective v1 behavior field by field, including:

- legacy Mode and its wire byte;
- carrier candidates and exact fallback conditions;
- TrustRoute and the current name-privacy fact;
- route-effective channel binding and auth selection;
- all shaping, padding, timing, batching, cover-traffic, and budget behavior;
  and
- a blocker for every behavior that cannot be proven to map without loss.

When the current v1 in-memory model still distinguishes two inputs, T010a must
preserve that distinction. When omission and an explicit default have already
collapsed to the same value, T010a reports the same effective behavior and
marks source provenance unavailable; it must not guess which syntax the user
wrote. A future v2 output may normalize that behavior into explicit five-axis
values, but it promises effective-behavior preservation rather than
byte-for-byte text or original source-intent preservation. If equivalence
cannot be proven field by field, T010a returns a review or migration blocker.

Source-level deterministic migration belongs to later T010b. YAML migration can
distinguish field presence only when it receives the original, strictly
validated representation or an equivalent duplicate-safe field-presence map.
SDK stored profiles, Profile URI, and values constructed through the public API
must each migrate only the information that boundary can actually express. An
API-created value without source provenance can guarantee effective-behavior
equivalence, but it must not invent an original intent. This contract does not
choose a data structure, parser, or migration algorithm for T010b.

A later v1-to-v2 round trip must preserve the information expressible at each
core YAML, SDK stored-profile, CLI/Profile URI, and public-API boundary, plus
effective behavior. If a boundary lacks information required for a lossless
migration, it returns a migration or review blocker. It does not promise to
recover unsaved data or original text. T012a and T009 implement no migration.
T009 freezes only the strict five-axis policy DTO and parser. T010b remains
later deterministic migration work.

## Canonical v1 YAML readers

`ClientConfig::from_yaml_str` and `ServerConfig::from_yaml_str` are the
canonical core readers. The CLI and SDK YAML entry points use these readers.
Each canonical reader first inspects the root `version` with one private,
duplicate-safe discriminator, then dispatches version `1` to the existing
strict v1 reader. Any other integer version returns a fixed
unsupported-version error before v1 deserialization. Missing, duplicate, or
non-integer version metadata and a non-mapping root fail closed without echoing
the untrusted version value. These canonical v1 readers do not accept config v2;
the independent `config::v2::Policy` parser validates policy only.

After version dispatch, the v1 reader still parses the original YAML. It
recursively rejects unknown mapping keys before validation or startup;
unknown keys are not an extension mechanism and are never corrected or allowed
to select a default silently.

Every documented v1 field and its existing default keeps the same meaning.
Adding a future field requires an explicit, versioned compatibility decision.
Stored-profile serialization is a separate boundary; this contract makes no
claim about stored-profile JSON.

## Stored client-profile JSON

The SDK fully understands and supports two usable stored-profile
representations: published Beta.1 flat JSON containing exactly its known fields
for explicit migration, and the current schema-1 envelope. This is an
intentional, observable compatibility tightening from the published Beta.1
reader. Exact known-field Beta.1 flat profiles remain readable and explicitly
migratable. A profile carrying extra mapping keys that the old reader accepted
and ignored is now intentionally rejected. Those extras were never preserved
by migration or rewriting and were never a supported extension mechanism.

At the `StoredClientProfile` deserialization boundary, every mapping node in
both supported representations recursively rejects unknown keys. Rejection uses
the fixed error `invalid stored client profile metadata`; an unknown key or
value is never treated as an extension, corrected, or echoed. When returned by
`serde_json::from_str`, this fixed text may be followed only by numeric line and
column coordinates added by `serde_json`.

Only a `StoredClientProfile` whose `compatibility_status()` is `Current` can be
serialized by that top-level type into a schema-1 envelope. A schema-1 profile
is rejected with `invalid stored client profile metadata` when channel binding
is disabled but required, or when required channel binding is combined with
H3, the legacy CDN-fronting flag, or first-class TLS-terminating CDN fronting.
Legacy and unsupported schemas retain the existing current-schema-only
serialization error, and schema-1 metadata missing channel binding retains its
existing missing-data error. Legal `Current` envelope content and ordering are
unchanged.

`Current` describes stored-metadata compatibility only. It does not prove that
the complete client configuration or referenced secrets are valid, or that a
runtime connection will succeed. This top-level guard also cannot prevent a
caller from hand-writing equivalent JSON outside `StoredClientProfile`, and it
is not an atomic file-persistence guarantee. Direct top-level serialization of
contradictory metadata rejects before calling its writer, but an enclosing
serializer, a caller that truncates a file first, or a downstream writer failure
while serializing a legal profile can still leave partial or empty output.
Maverick does not currently provide an atomic stored-profile file API.

The direct generic Serde behavior of the public nested SDK and core types is a
separate compatibility surface and is not the stored-profile reader. A future
stored-profile field requires an explicit stored-schema and reader
compatibility decision. An envelope declaring a newer schema can report typed
`UnsupportedSchema` only when its payload otherwise has the shape understood
by the current reader; a payload containing future-only fields can be rejected
during deserialization before that status is available.

## Profile URI v1 parser boundary

The CLI Profile URI v1 reader accepts exactly these ten decoded query keys:
`server`, `name`, `path`, `mode`, `credential_id`, `secret`, `cert_pin`,
`experimental_h3`, `experimental_ech`, and `experimental_tun`. Their order is
arbitrary, but each key may appear at most once. Before reading any individual
field, the reader checks all decoded query pairs once. An unknown or duplicate
key fails with the fixed error `invalid profile URI query`; the error does not
echo the key, value, URI, endpoint, credential, secret, control characters, or
other untrusted content.

This is an intentional compatibility tightening. The older reader silently
ignored unknown query keys and used the first value of a repeated recognized
key. It now rejects both shapes. Unknown and duplicate keys were never a
supported extension mechanism, and the old reader did not preserve ignored
data. Legal v1 fields and field order, canonical serialization order,
materialization defaults, the secret-omission default, QR and clipboard safety
rules, the file-permission rule, and the overwrite rule remain unchanged.

The outer envelope is exactly the existing `maverick://profile/v1?...` shape.
A v1 URI carrying a username, password, authority port, or fragment is rejected;
this includes an empty fragment and any user-information or port delimiter whose
value is empty. Before URL parsing or field reads, every `%` in each raw query
key or value must have exactly two hexadecimal digits, and the decoded bytes in
that component must be valid UTF-8. Lowercase and uppercase hex digits are both
legal. URL form `+` behavior, encoded `&` and `=` characters, valid Unicode,
and the existing absence of Unicode normalization remain unchanged.

The normalized single URI accepted by the parser is limited to 16 KiB. The
exact limit is legal; one additional byte is rejected. This is a parser input
contract, not a claim that every upstream allocation is bounded: the stdin and
clipboard commands may already have read their payload into memory before this
check. This slice does not add field-specific or credential-specific limits and
does not rewrite clipboard process handling or stdin as a streaming reader.

These envelope, lossless-decoding, and length failures use the fixed error
`invalid profile URI`; they do not echo the URI, user information, password,
fragment, endpoint, query key or value, raw decoded bytes, or a lower-level
untrusted error. A parseable URL password also triggers the existing fixed argv
secret warning. Raw and decoded query-secret detection remains in place,
including the malformed-input raw fallback.

This is also an intentional compatibility tightening. The older reader
accepted and ignored user information, authority ports, and fragments, and its
query decoder could accept malformed percent text or replace invalid UTF-8
lossily. Those ambiguous shapes are now rejected. Legal v1 URIs retain their
existing meaning and form semantics.

Profile URI v2 is still unimplemented and `/v2` remains rejected. A future v2
codec should be unified in core while remaining a separate compatibility
boundary from the stored-profile schema; this v1 tightening does not implement
migration, a complete config v2, or a runtime consumer.

## Client

```yaml
version: 1
mode: auto

local:
  socks5:
    listen: "127.0.0.1:1080"
  dns: null
  http_connect:
    enabled: false
    listen: "127.0.0.1:18080"

server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_example"
  secret: "mv1_base64url_high_entropy_secret"
  ca_cert: null
  cert_pin: null

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
  rotation:
    active_epoch: null
    next_credential_id: null
    auto_switch: false
    next: null

log:
  level: "info"
  redact: true

advanced:
  connect_timeout_ms: 10000
  idle_timeout_secs: 300
  max_concurrent_flows: 256
  padding: "auto"
  experimental_h3: false
  experimental_cloudflare_ws: false
  udp_idle_timeout_ms: 30000
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  stealth:
    tls_fingerprint: "browser_mimic"
    active_probe_resistance: true
    cdn_fronting:
      enabled: false
      provider: "cloudflare"
      carrier: "h2"
      trusted_tls_terminating_provider: false
  allow_non_loopback_listeners: false
  experimental_ech: false
  experimental_tun: false
  ech_fallback_policy: "fail_closed"
```

Client local listeners must stay on loopback addresses by default. Setting a
SOCKS5, DNS, or HTTP CONNECT listener to `0.0.0.0` or a LAN address is rejected
unless `advanced.allow_non_loopback_listeners: true` is set explicitly.

`local.dns` is an optional UDP DNS relay. Firefox using a SOCKS5 proxy with
**Proxy DNS when using SOCKS v5** enabled sends hostname lookups through SOCKS
and does not need this separate UDP listener. Generated and example configs
therefore use `local.dns: null`.

Software that specifically needs a local UDP DNS port can opt in with an unused
loopback port:

```yaml
local:
  dns:
    enabled: true
    listen: "127.0.0.1:15353"
```

`log.redact` is a safety gate in this prototype. It must remain `true`;
`log.redact: false` is rejected instead of acting like a supported unsafe mode.

## Server

```yaml
version: 1
listen: "0.0.0.0:443"

tls:
  cert_path: "./certs/fullchain.pem"
  key_path: "./certs/privkey.pem"

maverick:
  tunnel_path: "/assets/upload"
  mode_default: "auto"
  replay_window_secs: 120
  replay_cache_entries_per_credential: 16384
  replay_cache_max_credentials_per_shard: 1024
  max_concurrent_flows_per_user: 128

users:
  - id: "u_example"
    name: "alice"
    secret: "mv1_base64url_high_entropy_secret"
    enabled: true
    rate_limit:
      bytes_per_second: 1048576
    max_concurrent_flows: 128
    rotation: null

fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"

# Alternative:
# fallback:
#   type: "reverse_proxy"
#   upstream: "http://127.0.0.1:8080"

log:
  level: "info"
  redact: true

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false

advanced:
  idle_timeout_secs: 300
  tcp_connect_timeout_ms: 10000
  handshake_timeout_ms: 10000
  max_concurrent_connections: 2048
  max_concurrent_connections_per_source: 256
  pre_auth_max_concurrent: 512
  fallback_max_concurrent: 512
  h2_max_concurrent_streams: 256
  h2_max_concurrent_reset_streams: 50
  h2_max_pending_accept_reset_streams: 20
  h2_max_local_error_reset_streams: 1024
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
  max_frame_size: 65536
  experimental_h3: false
  experimental_cloudflare_ws: false
  udp_idle_timeout_ms: 30000
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  experimental_ech: false
```

Server `log.redact` follows the same rule as the client: it must remain `true`.
The prototype does not support a non-redacted operational logging mode.

## Modes

- `auto`: default v1 behavior.
- `stable`: stable policy label whose outer carrier is H2/TCP.
- `private`: stricter privacy posture and future reserved fields.

On a separately prepared Linux server, the server-sent half of all three
modes' normal H2/TCP carrier uses the host's configured `fq` or `fq_codel` plus
stock BBR (commonly called BBRv1). Both qdiscs are equally supported, and an
existing approved selection is preserved. This is an operating-system policy,
not a YAML mode setting. `stable` always keeps its outer carrier on H2/TCP. If
experimental H3/QUIC is explicitly enabled in `auto` or `private`, that UDP
carrier uses its userspace congestion controller rather than Linux TCP BBR; H2
fallback and the server-sent half of server-to-target TCP connections still use
the host TCP policy.

Maverick does not expose transport internals as ordinary user choices. Supported
default builds and generated client configs use
`advanced.stealth.tls_fingerprint: browser_mimic`. The BoringSSL-backed path is
browser-like, not browser-identical. The currently evidence-backed targets are
macOS arm64 and Linux x86_64; other targets use or require the explicit
`rustls_default` compatibility path until matching build and fingerprint
evidence exists. `private` mode rejects `rustls_default`.

## Transport

H2/TLS is mandatory and remains the default. H3/QUIC is experimental and runs
only when the binary is built with the `h3` feature and both client and server
set:

```yaml
advanced:
  experimental_h3: true
```

If runtime H3 setup fails, the client falls back to H2 and records a short
cooldown for that server. 0-RTT remains disabled.

The owner-pilot fronting path is browser-like TLS/H2 to a Cloudflare edge, with
H2 forwarded to the origin. It is off by default, rejected in `stable` mode,
and does not enable native Maverick server-side ECH. Enable it on both client
and server only after accepting that the provider terminates TLS and can observe
Maverick authentication and tunnel payload:

```yaml
advanced:
  stealth:
    cdn_fronting:
      enabled: true
      provider: cloudflare
      carrier: h2
      trusted_tls_terminating_provider: true
```

The older `carrier: web_socket` path remains available with
`tls_fingerprint: rustls_default`; `experimental_cloudflare_ws: true` is its
legacy selector. Browser mimicry is supported only by the H2 carrier. The
normal direct transport remains H2/TLS while fronting is disabled. Loopback
coverage alone does not prove that a real provider configuration accepts
sustained bidirectional H2. The first owner pilot exercised the path through a
real provider and network; `STATUS.md` records the bounded success and open
usability failures.

The H2 carrier uses gRPC message envelopes for Maverick frames. A complete
response ends with a `grpc-status: 0` trailer; a reset, incomplete message, or
transport failure must not be presented as a successful gRPC response. The
client drains and validates that trailer while remaining compatible with
Alpha.3 servers that ended terminal DATA without trailers.

## Fallback

Maverick supports static fallback and bounded HTTP reverse-proxy fallback.
Reverse-proxy fallback currently supports `http://` upstreams through Hyper's
HTTP/1 client. Ordinary fallback requests preserve the method, path/query, safe
request headers, and body. Rejected tunnel-like requests preserve the exact
authentication-stage body bytes already read by the server without waiting for
the client to close its stream. Fixed and `Connection`-nominated hop-by-hop
headers are stripped, chunked responses are decoded, upstream response bodies
are capped at 1 MiB, and upstream failures become a generic `502 Bad Gateway`.

Fallback bodies remain bounded and buffered rather than streamed end to end.
Upstream HTTPS and request/response trailer forwarding are not supported yet.
These are explicit active-probe residuals, not origin-equivalence claims.

## DNS

DNS relay is implemented over authenticated tunnel frames. Client DNS listens
on UDP locally when enabled; server DNS sends UDP queries to the configured
upstream.

## UDP

UDP relay is implemented through SOCKS5 UDP ASSOCIATE using authenticated
`OpenUdp` / `UdpPacket` flows. One UDP ASSOCIATE control connection owns one
lazy Maverick UDP association and reuses it for later datagrams. The timeout is
bounded by:

```yaml
advanced:
  udp_idle_timeout_ms: 30000
```

UDP remains experimental and does not claim high performance for games,
realtime voice, or loss-sensitive workloads.

## Experimental Packet Runtime

`advanced.experimental_tun` defaults to `false`. It is a second runtime gate in
addition to the optional client/SDK build feature `tun-runtime`:

```yaml
advanced:
  experimental_tun: true
```

The flag alone does not create a TUN interface or change routes, DNS, firewall,
proxy, or VPN state. An embedding application must supply already-open packet
I/O through the SDK. `stable` mode rejects the flag, and a client build without
`tun-runtime` rejects startup when it is enabled. The experimental runtime has
synthetic/loopback evidence and an accepted approved-host Phase 2 IPv4 matrix
through a separate namespace-local TUN runner. That runner is not a product
network helper. IPv6 is not scheduled, and platform integration remains open.

## Auth v2 and Rotation

Auth v2 is disabled by default. Runtime authentication uses the v1
ClientHello/ServerHello path unless `auth.v2.enabled` is explicitly enabled.
Credential rotation fields are parsed and validated so migrations can be staged
without printing secret material. Server-side Auth v2 requires
`auth.v2.require=true` when `auth.v2.enabled=true`, so a v2-enabled server does
not silently keep accepting v1 ClientHello messages.

TLS channel binding is enabled by default for direct TLS transports. When both
sides have end-to-end TLS exporter material, the client requests the
`FEATURE_TLS_CHANNEL_BINDING` auth flag and both ClientHello and ServerHello
HMACs bind to that TLS connection. Set `auth.channel_binding.require: true` on
both client and server only for transports that support this direct TLS
binding; required channel binding is rejected for experimental H3 and
TLS-terminating CDN fronting. Fronted H2/WebSocket disables exporter binding
because the client-edge and edge-origin TLS connections have different
exporters.

Client rotation metadata:

```yaml
auth:
  v2:
    enabled: false
  rotation:
    active_epoch: "2026-07"
    next_credential_id: null
    auto_switch: false
    next: null
```

Clients can opt in to local next-credential switching by carrying the next
credential material and an RFC3339 activation time:

```yaml
auth:
  rotation:
    next_credential_id: "u_example_2026_08"
    auto_switch: true
    next:
      id: "u_example_2026_08"
      secret: "mv1_next_redacted_example"
      not_before: "2026-07-15T00:00:00Z"
```

When `auto_switch` is false, the client always uses `server.credential_id` and
`server.secret`. When it is true, the client switches only after
`auth.rotation.next.not_before`. The next secret is sensitive and diagnostic
commands must redact it.

Server previous credentials are bounded and time-windowed:

```yaml
users:
  - id: "u_example"
    secret: "mv1_current_redacted_example"
    rotation:
      previous:
        - id: "u_example_2026_06"
          secret: "mv1_previous_redacted_example"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
      next:
        id: "u_example_2026_08"
        not_before: "2026-07-15T00:00:00Z"
```

Validation rejects short rotated secrets, duplicate active/previous/next ids,
more than four previous credentials per user, invalid RFC3339 timestamps,
client `auto_switch` without next credential material, mismatched client next
ids, and previous windows whose `not_after` is not after `not_before`.

## Shaping Budgets

Shaping is disabled by default. When enabled, the current runtime applies
bounded client-side padding, server-side padding, client-side batching, and
bounded delay according to these budgets:

```yaml
advanced:
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
```

Validation rejects zero padding caps, non-finite or out-of-range overhead
ratios, delay caps above 1000 ms, batch caps above 1 MiB, cover traffic without
`enabled: true`, cover traffic without
`cover_traffic_operator_approved: true`, and cover traffic windows outside
1-60000 ms. Runtime cover traffic is disabled by default and emits only bounded
`Padding` frames tied to observed payload budget; it does not generate idle
background traffic.

## ECH Gate

Native Maverick server-side ECH is not implemented. The config surface and
readiness diagnostics are present only to enforce future defaults and
fail-closed policy:

```yaml
advanced:
  experimental_ech: false
  ech_fallback_policy: "fail_closed"
```

`experimental_ech: true` is rejected until native server-side TLS stack support,
ECH config distribution, and controlled integration coverage are ready. In
`private` mode, `ech_fallback_policy: "allow_plain_sni"` is rejected even when
ECH itself is disabled. The Cloudflare-fronted H2 carrier and older WebSocket
carrier are provider-fronted experiments and do not enable this native ECH
flag. The browser-like client currently sends ECH GREASE only; it does not load
a real ECHConfig or establish that ECH was accepted. Treat the H2 path as a
`provider-fronted workaround`, not ECH. The current plan tracks upstream rustls
server-side ECH work and does not fork rustls or vendor an unmerged ECH patch.

## Metrics

Server metrics can be enabled with a loopback-only listener:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:19090"
```

The endpoint is `GET /metrics` and returns process-lifetime aggregate JSON
counters only. Target-opening diagnostics include:

- `target_resolution_timeouts`: hostname resolution exceeded
  `advanced.tcp_connect_timeout_ms`;
- `target_resolution_failures`: hostname resolution returned an error, excluding
  timeouts and egress-policy rejection;
- `target_connect_timeouts`: resolution succeeded, but the target TCP connection
  exceeded `advanced.tcp_connect_timeout_ms`; and
- `target_connect_failures`: resolution succeeded, but the target TCP connection
  returned an error before the timeout.

These resolution counters cover hostnames carried by ordinary SOCKS5 TCP flows.
They are separate from the optional UDP DNS relay's existing `dns_queries`
counter. An address rejected by the server egress policy is intentionally not
counted as either a DNS or target-connect failure.

Metrics have a fixed, unlabeled numeric schema. They do not contain domains, IP
addresses, ports, URLs, flow identifiers, user identifiers, credentials,
browsing content, error strings, or per-event timestamps. The metrics listener
is disabled unless configured and must remain loopback-only; Maverick does not
upload or persist these counters.

On an owner- or operator-controlled client shutdown, Maverick also emits one
info-level, fixed aggregate H2 pool summary containing only fixed,
destination-free numeric and boolean fields. If the active filter excludes
`info`, or an SDK embedding has no tracing subscriber, this event may not be
visible. In addition to the existing public connection-pool snapshot fields,
its crate-private shutdown-only data has exactly these observed outer-TLS
counters:

- `pooled_h2_client_observed_outer_tls12_connections`;
- `pooled_h2_client_observed_outer_tls13_connections`; and
- `pooled_h2_client_observed_outer_tls_unknown_connections`.

These counters classify only physical H2 connection generations managed by
`ClientTunnelPool` after actual TLS and H2 setup both succeeded and the
generation was installed in the pool. Each installed generation is classified
once; cached checkout and stream reuse do not increment the counters. The
counters saturate without breaking the stored invariant that TLS 1.2 plus TLS
1.3 plus unknown equals `connections_created`. `unknown` means the TLS backend
returned no negotiated version or a version other than TLS 1.2 or TLS 1.3; it
is never inferred from configured or offered versions.

The observation is the client-facing outer TLS leg. For direct H2 that leg is
client to Maverick server. With a TLS-terminating provider front it is client to
provider edge, not provider to origin. It is not an authenticated-tunnel count:
a physical connection remains counted if later Maverick credential or
authentication work fails. It does not describe end-to-end Maverick TLS,
origin TLS, destination HTTPS, ECH, post-quantum properties, channel binding, or
any other security proof.

H3, H3-to-H2 non-pooled fallback, WebSocket, direct non-pooled
`tunnel::open` H2, and any H2 connection not installed by this pool are outside
these counters. Three zero values mean only that this process installed no
pool-managed H2 physical connection; they do not prove that the process used no
TLS or H2. The summary never includes the server address or name, a provider,
port, destination, credential, secret, certificate path, connection ID,
error string, browsing content, or any user-provided string. Its counter payload
contains no per-connection or per-version timestamp, although the surrounding
logger may attach one event time to the controlled-shutdown info event. The
process-lifetime connection and stream counts are still activity-volume metadata
and should be handled accordingly.

## Certificate Pinning

`server.cert_pin` is optional. When set, Maverick first performs normal TLS CA
and hostname validation, then verifies the leaf certificate DER SHA-256 digest.
The format is:

```yaml
cert_pin: "sha256/<base64url-no-pad>"
```

Generate the value from a PEM certificate:

```sh
maverick pin-cert --cert certs/fullchain.pem
```

## User Limits

`users[].max_concurrent_flows` overrides the server default for that user.
When the limit is reached, authenticated sessions receive a coarse
`FLOW_LIMIT_EXCEEDED` error frame and local clients surface a connection
failure.

`users[].rate_limit.bytes_per_second` enables a simple per-user shared byte
pacer across TCP, DNS, and UDP relay paths. It is intended as an operator safety
control, not a precise billing-grade traffic shaper.

## Validation

```sh
maverick check-config --kind client -c client.yaml
maverick check-config --kind server -c server.yaml
maverick migrate-config --kind client -c client.yaml
maverick migrate-config --kind server -c server.yaml
```

`advanced.connect_timeout_ms` on the client bounds the full server connection
setup path: TCP connect, TLS handshake, and H2 handshake. Timeout values must be
greater than zero.

`advanced.max_concurrent_flows` on the client limits simultaneous local TCP
proxy flows opened through SOCKS5 CONNECT and HTTP CONNECT. When the limit is
reached, new local TCP proxy attempts fail before opening a Maverick tunnel.

Server `advanced.max_concurrent_connections` and
`advanced.max_concurrent_connections_per_source` limit accepted TCP/TLS
connections globally and per source IP. Server `advanced.pre_auth_max_concurrent`
limits concurrent unauthenticated handshake and tunnel-sniffing work across
H2/H3/WebSocket carriers. Server `advanced.fallback_max_concurrent` bounds
ordinary static or reverse-proxy fallback work. Server
`advanced.h2_max_concurrent_streams` advertises the HTTP/2 concurrent stream
limit per connection and is also used as the experimental H3 bidirectional
stream cap. `advanced.h2_max_concurrent_reset_streams`,
`advanced.h2_max_pending_accept_reset_streams`, and
`advanced.h2_max_local_error_reset_streams` make HTTP/2 reset-stream defense
limits explicit instead of relying on library defaults. Server
`advanced.max_auth_failures_per_window`,
`advanced.auth_failure_window_secs`, and
`advanced.auth_failure_cache_max_entries` bound repeated failed tunnel
authentication attempts by source IP. Ordinary failed authentication attempts
still receive fallback behavior; repeated failures beyond the configured window
keep receiving fallback-shaped behavior when active-probing resistance is on and
increment `auth_rate_limit_rejections`.

`migrate-config` is currently a dry-run report. It validates config and reports
missing defaults such as `advanced.experimental_h3=false` and
`advanced.experimental_cloudflare_ws=false`,
`advanced.experimental_tun=false`,
`advanced.udp_idle_timeout_ms=30000`,
`advanced.max_concurrent_connections=2048`,
`advanced.max_concurrent_connections_per_source=256`,
`advanced.pre_auth_max_concurrent=512`,
`advanced.fallback_max_concurrent=512`,
`advanced.auth_failure_window_secs=60`,
`advanced.max_auth_failures_per_window=24`,
`advanced.auth_failure_cache_max_entries=4096`,
`advanced.shaping.enabled=false`,
`advanced.experimental_ech=false`, `advanced.ech_fallback_policy=fail_closed`,
and `auth.v2.enabled=false` without rewriting files or printing secrets.
