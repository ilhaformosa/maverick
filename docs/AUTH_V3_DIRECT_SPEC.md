# Maverick Direct Auth-v3 Canonical Contract

> **Pre-runtime contract:** this document and its canonical vectors freeze a
> docs/test-only protocol contract. Maverick does not currently enable auth-v3
> in its client or server. Nothing here is a peer-confirmed product result, a
> runtime state-transfer proof, a post-quantum guarantee, a release decision, or
> authorization to deploy or use a real network.

## 1. Scope and compatibility boundary

This contract defines exactly one authentication mechanism instance for one
direct physical H2/TLS or H3/QUIC connection. After both peers authenticate the
connection, later logical flows on that same connection may inherit the result.
A replacement physical connection or generation MUST run auth-v3 again and
MUST NOT receive authenticated state copied from the old generation.

This contract does not change Maverick's current product protocol version,
config version, stored-profile schema version, authentication wire format, or
frame wire format. Existing auth-v1/v2 messages retain their exact bytes and
their legacy TLS exporter label:

```text
maverick tls channel binding v1
```

The legacy label above is exact ASCII without a trailing NUL. It MUST NOT be
reinterpreted as the auth-v3 exporter label.

Direct auth-v3 is deliberately separate from a TLS-terminating front. Fronted
application-session authentication and per-flow MACs remain deferred. T015 and
all PQ/hybrid enforcement claims remain `DEFER`.

## 2. Canonical encoding rules

- Every multi-byte integer is unsigned big-endian.
- Every message has one exact fixed length. Truncation and trailing bytes are
  invalid.
- Every flags or reserved field MUST be zero.
- Registry value zero, every unknown registry ID, and every unknown capability
  bit are invalid.
- A parser MUST validate shape and registry values before using any parsed
  value for authentication or state changes.
- Every validation failure is fail closed. Runtime diagnostics, when later
  implemented, MUST use fixed privacy-safe categories and MUST NOT contain a
  secret, exporter, identity input or commitment, nonce, session ID, endpoint,
  target, raw peer bytes, or raw backend error.

## 3. Registry

| Registry | Value | Meaning |
| --- | ---: | --- |
| Magic | `4d564133` | ASCII `MVA3` |
| Message type | `0x01` | `ClientControl` |
| Message type | `0x02` | `ServerConfirmation` |
| Auth version | `0x0003` | direct auth-v3 |
| Carrier | `0x01` | direct H2 over TLS |
| Carrier | `0x02` | direct H3 over QUIC/TLS |
| TrustRoute | `0x01` | `direct_to_maverick` |
| Binding type | `0x01` | RFC 9266 `tls-exporter` |
| Capability bit | `0x00000001` | `DIRECT_CARRIER_SESSION_V1` |
| KEX policy | `0x0001` | `TLS13_CLASSICAL_FLOOR` |
| Resource class | `0x0001` | `EXPLICIT_BOUNDED_LIMITS_V1` |
| Policy encoding | `0x01` | canonical policy encoding v1 |
| Security posture | `0x01` | `standard` |
| Name privacy | `0x01` | `plain_sni` |
| Traffic shaping | `0x01` | `disabled` |

Only the direct TrustRoute and TLS-exporter binding values above are assigned.
Every other TrustRoute or binding value is unassigned and invalid. This direct
contract does not pre-allocate numbers for a future fronted protocol.

The first version MUST set exactly the capability bit
`DIRECT_CARRIER_SESSION_V1`; no other bit may be set. `TLS13_CLASSICAL_FLOOR`
means only that the actual physical connection uses TLS 1.3 and provides the
classical TLS 1.3 security floor. It does not identify the selected group and
does not claim a PQ, hybrid-preferred, or hybrid-required guarantee. The
underlying library may have selected a classical or hybrid group without
changing this value.

Wire values do not prove physical-connection facts. A verifier MUST receive an
independent trusted connection context containing the actual H2/H3 dispatch,
actual TLS version, actual direct route, exporter from this exact generation,
selected deployment-profile ID, authenticated/expected server identity or
origin, and actual control/tunnel path. Before MAC acceptance it MUST establish:

- the policy carrier equals the actual physical dispatch;
- the actual TLS version is exactly TLS 1.3;
- the route is direct;
- early data/0-RTT was not used;
- the exporter came from this same generation with a present empty context;
  and
- deployment profile, server identity/origin, and control path equal the
  trusted local DeploymentProfile mapping.

`TLS13_CLASSICAL_FLOOR`, the policy carrier, and the direct route are claims to
check against that context, never evidence about the connection by themselves.

## 4. Canonical policy block

The policy block is exactly 8 bytes:

| Policy offset | Length | Field | First-version value |
| ---: | ---: | --- | --- |
| 0 | 1 | encoding version | `0x01` |
| 1 | 1 | security posture | `0x01` (`standard`) |
| 2 | 1 | resolved physical carrier | H2 `0x01`; H3 `0x02` |
| 3 | 1 | TrustRoute | `0x01` (`direct_to_maverick`) |
| 4 | 1 | name privacy | `0x01` (`plain_sni`) |
| 5 | 1 | traffic shaping | `0x01` (`disabled`) |
| 6 | 2 | reserved | `0x0000` |

Canonical values are:

```text
H2 direct: 0101010101010000
H3 direct: 0101020101010000
```

`Auto` is a local selection input and never appears on the wire. The client
first resolves a physical carrier under trusted local policy, establishes that
carrier, and then authenticates it.

For this first contract, the server can accept or reject only. It MUST NOT make
an approximate, weaker, reordered, or lattice-style selection:

```text
policy_selected == policy_minimum
kex_selected == kex_minimum == 0x0001
capabilities_selected == capabilities_required == 0x00000001
resource_class_selected == resource_class_required == 0x0001
```

All equalities above are exact byte/value equalities.

## 5. ClientControl

`ClientControl` is exactly 256 bytes.

| Offset | Length | Field | First-version rule |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | `MVA3` |
| 4 | 2 | auth version | `0x0003` |
| 6 | 1 | message type | `0x01` |
| 7 | 1 | flags | zero |
| 8 | 2 | total length | `0x0100` (256) |
| 10 | 2 | reserved | zero |
| 12 | 8 | policy minimum | canonical H2 or H3 policy block |
| 20 | 1 | binding type | `0x01` |
| 21 | 1 | reserved | zero |
| 22 | 2 | KEX minimum | `0x0001` |
| 24 | 4 | capabilities required | `0x00000001` |
| 28 | 2 | resource class required | `0x0001` |
| 30 | 2 | reserved | zero |
| 32 | 8 | credential epoch | nonzero monotonic `u64` |
| 40 | 8 | client time | Unix seconds `u64` |
| 48 | 32 | principal commitment | Section 7 |
| 80 | 32 | deployment-profile commitment | Section 7 |
| 112 | 32 | credential-namespace commitment | Section 7 |
| 144 | 32 | client nonce | random; all-zero invalid |
| 176 | 16 | downgrade sentinel | exact ASCII `MVRK-AUTH-V3-REQ` |
| 192 | 32 | policy minimum hash | Section 9 |
| 224 | 32 | client auth tag | Section 9 |

The exact size is also the maximum accepted size. A direct auth-v3 parser MUST
reject every other length.

## 6. ServerConfirmation

`ServerConfirmation` is exactly 320 bytes.

| Offset | Length | Field | First-version rule |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | `MVA3` |
| 4 | 2 | auth version | `0x0003` |
| 6 | 1 | message type | `0x02` |
| 7 | 1 | flags | zero |
| 8 | 2 | total length | `0x0140` (320) |
| 10 | 2 | reserved | zero |
| 12 | 8 | policy selected | exact ClientControl policy minimum |
| 20 | 1 | binding type selected | `0x01` |
| 21 | 1 | reserved | zero |
| 22 | 2 | KEX selected | `0x0001` |
| 24 | 4 | capabilities selected | `0x00000001` |
| 28 | 2 | resource class selected | `0x0001` |
| 30 | 2 | reserved | zero |
| 32 | 8 | credential epoch selected | exact ClientControl epoch |
| 40 | 8 | admission expiry | absolute Unix seconds |
| 48 | 8 | hard expiry | absolute Unix seconds |
| 56 | 32 | principal commitment | exact echo |
| 88 | 32 | deployment-profile commitment | exact echo |
| 120 | 32 | credential-namespace commitment | exact echo |
| 152 | 32 | server nonce | random; all-zero invalid |
| 184 | 16 | session ID | random; all-zero invalid |
| 200 | 16 | downgrade sentinel | exact echo |
| 216 | 32 | policy selected hash | independently recomputed |
| 248 | 32 | ClientControl commitment | Section 9; covers all 256 bytes including client tag |
| 280 | 4 | max frame size | server-selected and nonzero; client applies its local cap |
| 284 | 4 | max concurrent flows | server-selected and nonzero; client applies its local cap |
| 288 | 32 | server auth tag | Section 9 |

The exact size is also the maximum accepted size. A direct auth-v3 parser MUST
reject every other length.

## 7. Opaque identity inputs and commitments

Provisioning generates three independent opaque random 16-byte IDs:

- principal ID;
- deployment-profile ID; and
- credential-namespace ID.

An ID MUST NOT be all zero and MUST NOT be derived from or replaced with a
username, email address, domain, path, readable profile name, account name,
location, endpoint, or other operational label. One deployment-profile ID maps
to one expected server identity/origin, the direct TrustRoute, and one exact
control/tunnel path. Credential authorization and PSK lookup use exactly this
four-part tuple:

```text
(principal_commitment,
 deployment_profile_commitment,
 credential_namespace_commitment,
 credential_epoch)
```

All three commitments and the epoch MUST match the trusted local provisioning
registry entry before a MAC can be accepted. The registry relation is
one-to-one: one exact four-part tuple maps to exactly one PSK, and one PSK
belongs to exactly one tuple. The registry MUST reject a tuple mapped to two
different PSKs, a PSK reused by two different tuples, and duplicate entries
even when both tuple and PSK are identical. PSK lookup starts from the trusted
local exact tuple; wire values only prove equality with that tuple and MUST NOT
select or substitute another identity, deployment, namespace, epoch, or PSK.
The client performs the same exact-tuple check against its trusted local
profile; it does not accept a wire commitment as authority to select another
identity, deployment, namespace, epoch, server, route, or path.

Commitments use these exact ASCII domain labels without a trailing NUL:

```text
COMMIT(label, opaque_id_16) =
    SHA256(label || BE16(16) || opaque_id_16)

principal_commitment =
    COMMIT("Maverick auth v3 principal commitment", principal_id)

deployment_profile_commitment =
    COMMIT("Maverick auth v3 deployment profile commitment", deployment_profile_id)

credential_namespace_commitment =
    COMMIT("Maverick auth v3 credential namespace commitment", credential_namespace_id)
```

The credential epoch is a nonzero monotonic `u64`. Both sides validate it
against the provisioned current epoch and credential-validity window before
accepting a message. Failure MUST NOT cause a retry with an older epoch.

## 8. RFC 9266 exporter binding

Direct H2 and direct H3 use an exporter from the exact physical TLS/QUIC
connection being authenticated:

```text
label   = ASCII("EXPORTER-Channel-Binding")
context = empty byte string
length  = 32
```

The label has no trailing NUL. The context is **present and empty**, not missing
and not application-defined. A future backend call therefore uses the
equivalent of `Some(&[])`; `None` is invalid. Actual H2/H3 backend enforcement is
left to the runtime slice. The 32-byte result is an input to both authenticated
transcripts and is never sent on the wire, logged, or recorded in metrics.

One physical connection carries one auth-v3 authentication-mechanism instance.
The first ClientControl atomically occupies that generation's unique auth slot
before shape parsing or MAC verification. A concurrent or duplicate control,
or any failure of the first control, closes the generation; no second attempt is
allowed. This is normative state-model behavior only. This docs/test slice does
not prove production atomicity, state transfer, or no-fallback enforcement. The
authenticated session lifetime is the physical connection lifetime; when that
session ends, the corresponding connection closes.

## 9. KDF, hashes, commitments, and MACs

Only SHA-256, HMAC-SHA256, and HKDF-SHA256 are used. `PSK` is the complete UTF-8
byte sequence returned by the existing `SecretString`, including its `mv1_`
prefix. It is not base64-decoded or otherwise transformed.

All quoted values below are exact ASCII without a trailing NUL. Every displayed
length prefix is unsigned big-endian.

```text
PSK = UTF8(SecretString.expose_secret())

salt =
    ASCII("Maverick auth v3 hkdf salt")
    || BE64(credential_epoch)

PRK = HKDF-Extract-SHA256(salt, PSK)

identity_context =
    principal_commitment
    || deployment_profile_commitment
    || credential_namespace_commitment

client_mac_key = HKDF-Expand-SHA256(
    PRK,
    ASCII("Maverick auth v3 client control mac key")
      || identity_context,
    32
)

server_mac_key = HKDF-Expand-SHA256(
    PRK,
    ASCII("Maverick auth v3 server confirmation mac key")
      || identity_context,
    32
)

policy_hash(policy_8) = SHA256(
    ASCII("Maverick auth v3 policy hash")
    || BE16(8)
    || policy_8
)

client_auth_tag = HMAC-SHA256(
    client_mac_key,
    ASCII("Maverick auth v3 client control transcript")
    || BE16(32)
    || tls_exporter_32
    || BE16(224)
    || ClientControl[0..224]
)

client_control_commitment = SHA256(
    ASCII("Maverick auth v3 client control commitment")
    || BE16(256)
    || ClientControl[0..256]
)

server_auth_tag = HMAC-SHA256(
    server_mac_key,
    ASCII("Maverick auth v3 server confirmation transcript")
    || BE16(32)
    || tls_exporter_32
    || BE16(288)
    || ServerConfirmation[0..288]
)
```

The client and server derive their MAC keys independently. The server MUST
verify the client tag before accepting the control. The client MUST verify both
the complete ClientControl commitment and the server tag before treating the
connection as authenticated.

## 10. Time, expiry, and bounded resources

All times are absolute Unix seconds represented as `u64`.

- Maximum client/server clock skew is a hard 300-second cap. The server compares
  `client_time` with its own trusted `server_now` using ordered, checked
  subtraction: subtract the smaller from the larger and reject if the checked
  difference exceeds 300. It MUST NOT use signed conversion, unchecked
  addition/subtraction, or a `u64` absolute-value shortcut. `0`, `u64::MAX`, and
  a time 301 seconds in either direction are rejected. `client_time` values `0`
  and `u64::MAX` are unconditionally invalid even if a trusted local clock has
  the same extreme value.
- The provisioned credential epoch MUST be current, nonzero, and unexpired.
- On generation, the server uses its own trusted now and MUST enforce
  `server_now < admission_expiry < hard_expiry`, admission lifetime at most
  1,800 seconds, and hard lifetime at most 86,400 seconds. Checked subtraction
  from each expiry to `server_now` establishes both caps. Overflow or wrap is
  invalid. It also MUST enforce
  `admission_expiry <= credential_not_after` and
  `hard_expiry <= credential_not_after` using ordered comparisons. Equality is
  allowed because the corresponding session lifetime ends when the credential
  does. The server may shorten either lifetime and a shorter credential
  validity MUST shorten them; it may never extend either cap or the credential
  validity.
- On receipt, the client independently requires
  `client_now < admission_expiry < hard_expiry`. Using checked subtraction, it
  limits `admission_expiry - client_now` to 2,100 seconds and
  `hard_expiry - client_now` to 86,700 seconds. The extra 300 seconds only
  compensates for the already permitted case where the server clock leads the
  client clock by up to 300 seconds; it never extends the server's own strict
  1,800/86,400-second caps. The client also checks that the `client_time`
  retained from its original ClientControl is within 300 seconds of
  `client_now`, again using ordered checked subtraction. Values beyond the
  client bounds, far-future values, and overflow/wrap fail closed. The client
  independently requires both expiries to be less than or equal to the trusted
  local `credential_not_after`; equality is allowed, while either expiry above
  credential validity fails closed.
- After admission expiry, the server rejects every new flow without queueing it
  or starting target work.
- At hard expiry, the server closes the physical connection and all remaining
  flows.
- Revocation, epoch change, or a security-significant policy or identity change
  skips grace and closes the physical connection.

The server selects its own nonzero `max frame size` and `max concurrent flows`;
it does not know or assert the client's local caps. On receipt, the client
rejects zero or any selected value above its own trusted local cap. The session
ID identifies only this connection session. It is not a bearer token, is not
sent with later flows, and must not be logged.

## 11. Validation and state transition order

The required lifecycle is:

1. Complete a direct TLS 1.3 or QUIC/TLS 1.3 handshake.
2. Obtain the RFC 9266 exporter from that same physical connection.
3. Send exactly one ClientControl in a dedicated control request. 0-RTT/early
   data is forbidden.
4. Atomically occupy the physical generation's only auth slot before parsing or
   verifying the first byte sequence. Concurrent/duplicate controls reject and
   close; failure keeps the slot consumed and closes the generation.
5. Strictly validate message shape and registry values, then compare every wire
   connection claim with the independent trusted connection context. Validate
   the exact four-part credential tuple, provisioning validity, client clock,
   nonce/replay, sentinel, policy hash, exporter binding, and client MAC. All
   three commitments MUST match before PSK lookup/MAC acceptance.
6. Generate a ServerConfirmation only after all validation succeeds.
7. For the frozen direct-H2 reference, keep the local server gate in
   `Authenticating` until the response headers have been accepted by the local
   h2 API, all response DATA totaling exactly 320 bytes has been successfully
   accepted into this generation's response `SendStream` after obtaining the
   necessary send capacity, and the final `send_data` carrying the remaining
   bytes with `END_STREAM` returns success. One or more `send_data` operations
   may carry the body. Only that exact cumulative event transitions the gate to
   `Authenticated`; Section 11.1 freezes the boundary and failure behavior.
8. Independently validate on the client: shape, registry values, trusted
   connection/profile context, every exact
   selected/minimum equality and echo, expiry relation, limits, nonces/session
   ID, policy hash, complete ClientControl commitment, exporter binding, and
   server MAC.
9. Mark the client generation authenticated only after all validation succeeds.

Before ServerConfirmation completes, the client MUST NOT open or queue a user
flow. Before the server generation is authenticated, the server MUST reject a
flow immediately; it MUST NOT queue it, resolve a target or DNS name, run egress
resolution, or connect to a target.

### 11.1 Frozen direct-H2 control carrier mapping

This subsection freezes a future direct-H2 control seam. It does not enable a
runtime or claim that the client or server currently enforces the mapping.

The control request has exactly this HTTP/2 mapping:

- The method is the exact, case-sensitive value `POST`.
- The raw HTTP/2 `:path` path-and-query value MUST equal the pre-I/O validated
  config-schema-3 tunnel path byte for byte. The query component MUST be
  completely absent; a trailing empty query delimiter `?` is invalid. An
  implementation MUST NOT normalize, percent-decode, parse and rebuild, or
  otherwise transform either value to obtain an equivalent form.
- There is exactly one request `content-type` field. Its value is the exact,
  case-sensitive ASCII string `application/maverick-auth-v3`. Parameters,
  duplicates, and every other value are invalid.
- The request body is semantically exactly 256 bytes containing one
  `ClientControl`. Those bytes may span multiple HTTP/2 DATA frames, but the
  accumulated body length MUST be exactly 256 bytes and the request MUST then
  end with `END_STREAM`. Request trailers are forbidden.
- The raw 256 bytes MUST NOT enter the legacy frame decoder.

The only successful control response has exactly this HTTP/2 mapping:

- The status is exactly `200`.
- There is exactly one response `content-type` field. Its value is the exact,
  case-sensitive ASCII string `application/maverick-auth-v3`. Parameters,
  duplicates, and every other value are invalid.
- The response body is semantically exactly 320 bytes containing one
  `ServerConfirmation`. Those bytes may span multiple HTTP/2 DATA frames, but
  the accumulated body length MUST be exactly 320 bytes and the response MUST
  then end with `END_STREAM`. Response trailers are forbidden.
- The client MUST completely validate all 320 bytes before it creates or
  exposes an authenticated capability for the generation.

The first pre-auth request is the generation's only control candidate and
atomically consumes the physical generation's unique auth slot before the
server reads or parses any request-body byte. It remains the only candidate
even when its metadata, body, or authentication is invalid. A concurrent or
duplicate control, any pre-auth non-control request, a wrong method, path,
query, or content type, a truncated or trailing body, trailers, or any invalid
shape, registry value, MAC, trusted context, expiry, policy, commitment, echo,
nonce, sentinel, or limit consumes the slot and closes the entire physical
TLS/H2 generation. A malformed or failed success response and every client-side
confirmation failure have the same generation-wide result.

Failure MUST NOT produce the canonical success response or any HTTP response
that a peer could mistake for it. A v3 failure MUST NOT enter legacy fallback,
be offered to a v2 or v1 decoder, retry another carrier, profile, or PSK, or
start relay or target work. Local diagnostics may record only fixed,
privacy-safe categories. The particular HTTP/2 or TLS close frame, error code,
or ordering is not a stable application-protocol signal. The only result a peer
may rely on is that the physical generation closed without an authenticated
capability or target work.

Connection ordering is strict:

- The client MUST finish the control request and validate the complete
  confirmation before the generation enters any pool or exposes a user-flow
  sender.
- The server gate starts in `Authenticating`. It may transition to
  `Authenticated` only after the local h2 API has accepted the response
  headers and the response `SendStream` belonging to this generation has
  successfully accepted all response DATA totaling exactly 320 bytes after the
  necessary send capacity was obtained. The final `send_data` MUST carry the
  remaining bytes, set `END_STREAM`, and return `Ok`. One or more `send_data`
  operations may carry the 320-byte body. With h2 0.4, the final boundary is
  `send_data(remaining_confirmation_bytes, true) == Ok(())` when the bytes
  accepted by that final call plus all preceding successful calls, if any,
  total exactly 320.
- Constructing `ServerConfirmation`, a successful `send_response` or headers
  operation, reserving or polling send capacity, or successfully queueing only
  part of the DATA is insufficient. A cumulative accepted length below or above
  320 bytes is invalid and MUST NOT authenticate the generation. The final
  success above means only that the local h2 API accepted or queued the complete
  response; it does not prove that the peer received or validated it.
- Any error or cancellation while reserving or polling capacity, any
  `send_response` or `send_data` error, or any reset before that transition
  keeps the auth slot consumed, closes the generation, and creates no
  authenticated capability. A reset or connection error after the local
  transition still closes the generation, and authenticated state does not
  transfer. No particular transport error or reset code is frozen here.
- Before confirmation, the client MUST NOT create or queue a flow. The server
  MUST NOT read a flow body, query the legacy `UserStore`, resolve DNS, apply
  target egress resolution, connect to a target, relay bytes, or invoke
  fallback.
- One physical generation has exactly one authentication-mechanism instance.
  Every replacement generation MUST authenticate from the beginning, and
  authenticated state MUST NOT transfer between generations.

### 11.2 First rustls direct-H2 reference trust contract

The first future runtime reference slice defines one new rustls-only direct-H2
entry point. Before DNS resolution, a TCP connection, a TLS handshake, or any
other I/O, that entry point MUST:

- reject a BrowserMimic/BoringSSL backend selection, an H3 carrier selection,
  or any other selection that is not rustls direct H2 through one fixed,
  privacy-safe local category, without routing it into this reference path; and
- reject the configured tunnel path through one fixed, privacy-safe local
  category unless it can be represented byte for byte as a legal HTTP/2 path
  component. At minimum, a raw query delimiter `?` and a raw fragment delimiter
  `#` are invalid.

This path-representability check is a future runtime-reference pre-I/O gate.
This docs-only slice does not tighten the current config-schema-3 parser and
does not claim that its `valid_tunnel_path` validation already rejects these
values. These entry-point requirements do not change any existing legacy
BrowserMimic/BoringSSL, H3, or other backend/carrier path; their current
behavior remains unchanged.

After the TLS handshake completes and before starting HTTP/2, the client and
server MUST obtain the following actual observations from the same rustls
`ClientConnection` or `ServerConnection` that owns the generation:

- `protocol_version() == Some(ProtocolVersion::TLSv1_3)`;
- `alpn_protocol() == Some(b"h2")`; and
- exactly 32 RFC 9266 exporter bytes from
  `export_keying_material` with label
  `b"EXPORTER-Channel-Binding"` and context `Some(&[])`.

The exporter MUST come from that same generation. The client configuration
MUST set `enable_early_data = false`, and after the handshake the
`ClientConnection` MUST report `is_early_data_accepted() == false`. The server
configuration MUST set `max_early_data_size = 0` and
`send_half_rtt_data = false`, and the `ServerConnection` MUST report no
accepted or delivered early application data through `early_data()`. A client
that cannot prove every required fact MUST fail closed before sending any
`ClientControl`; a server that cannot prove them MUST fail closed before
accepting its body. Configured versions, offered ALPN values, or other policy
inputs MUST NOT be substituted for these actual connection observations.

This slice deliberately does not freeze user-flow HTTP or data-plane mapping.
A later runtime reference built from it owns only the control seam and MUST NOT
be described as multi-flow support, completed runtime generation state, or a
working direct-v3 runtime.

This carrier freeze changes none of the 256-byte or 320-byte wire bytes,
canonical vectors, auth/config/frame/stored schemas, legacy exporter label,
legacy `None` exporter context, or legacy behavior. Legacy `application/grpc`
plus framed ClientHello/ServerHello retains its current meaning.

## 12. Downgrade resistance and failure handling

The exact 16-byte sentinel is:

```text
MVRK-AUTH-V3-REQ
```

It is covered by the client MAC, echoed in ServerConfirmation, and covered by
the server MAC. The marker alone is not downgrade protection. The protection
requires all of the following:

- a trusted local profile with auth minimum 3;
- the authenticated sentinel on both messages; and
- a strict no-legacy-fallback rule.

After auth minimum 3 is selected, the client sends only v3. A missing or wrong
sentinel, timeout, malformed message, unknown ID/bit, policy, KEX, binding,
commitment, MAC, exporter, or confirmation failure closes the physical
generation. The client MUST NOT retry auth-v2 or auth-v1 on the same connection
or a new connection because v3 failed.

Before any ClientControl byte is sent, ordinary H3 transport unavailability
may select a new H2 generation only if separately allowed by trusted local
carrier policy. That new H2 generation still runs auth-v3. Once any v3 control
byte has been sent, an authentication failure cannot trigger carrier-rescue
fallback. A legacy profile is an explicit independent local choice and is never
selected by v3 failure.

The unique-slot, close-on-first-failure, no state transfer, and no-fallback
rules above still require later production runtime enforcement. Passing this
test-only state model is not runtime proof.

## 13. Direct/front separation

Both direct message types accept only this tuple:

```text
TrustRoute   = 0x01 direct_to_maverick
binding      = 0x01 tls_exporter
capabilities = 0x00000001 DIRECT_CARRIER_SESSION_V1
```

Every other TrustRoute and binding number is currently unassigned and invalid.
A future fronted protocol assigns its vocabulary only in its own
dispatch/message specification. It needs an independent application-session
lifetime, independent flow nonces, canonical metadata and KDF/MAC domains,
independent vectors, and no assumption of front-to-origin connection affinity.
It cannot claim RFC 9266 end-to-end binding across a TLS-terminating front.

## 14. Canonical vectors and negative contract

The repository freezes four positive vectors:

- H2 ClientControl;
- H2 ServerConfirmation;
- H3 ClientControl; and
- H3 ServerConfirmation.

Each uses a fixed, neutral test-only PSK, opaque IDs, nonces, exporter, times,
expiry, and limits. Each JSON contains complete encoded hex and intermediate
commitments, hashes, and MAC keys/tags so an independent implementation can
reproduce it. Exporter bytes exist only as public test input in these vectors;
they are not a wire field.

The executable test-only parser/verifier rejects at least:

- wrong magic, version, type, length, truncation, or trailing bytes;
- nonzero flags, wrong policy encoding version at offset 12, or either policy
  reserved byte;
- unknown carrier, TrustRoute, binding, KEX, resource ID, policy value, or
  capability bit;
- a correctly MACed H2 message claiming H3, the reverse carrier mismatch,
  actual TLS 1.2, non-direct context, early data, missing/nonempty exporter
  context, wrong deployment profile, wrong server identity, or wrong path;
- wrong policy hash or minimum/selected mismatch;
- zero, wrong, or expired credential epoch; same-tuple/different-PSK,
  different-tuple/same-PSK, or duplicate registry entries; and conflicting
  DeploymentProfile mappings;
- client time 301 seconds in either direction, zero, `u64::MAX`, or an
  overflow/wrap case;
- any changed identity commitment;
- all-zero client/server nonce or session ID;
- wrong downgrade sentinel;
- invalid admission/hard-expiry relationships, admission or hard expiry beyond
  credential validity, lifetimes beyond 1,800/86,400 seconds, far-future
  values, client-now rejection, or overflow/wrap;
- zero or excessive resource limits;
- changed client MAC, server MAC, or complete ClientControl commitment;
- H2/H3 exporter mismatch or a replacement generation's exporter;
- auth-v1/v2 bytes under an auth-v3 parser; and
- duplicate ClientControl on one physical generation.

The new-generation vector check proves only that a transcript bound to one
exporter fails with another exporter. It does **not** prove that current runtime
code prevents authenticated state transfer; runtime auth-v3 does not exist in
this slice.

## 15. Evolution rules

The following incompatible changes require auth-v4 rather than reinterpretation
of auth-v3:

- any field order, width, fixed length, magic, message type, or version change;
- assigning current reserved bytes or changing unknown-value rejection;
- changing exact policy equality into negotiation, downgrade, or a lattice;
- changing policy bytes, policy-hash domain, commitment inputs/length/hash, PSK
  decoding, HKDF salt/info, MAC labels, transcript scopes, exporter
  label/context/length, nonce/session length, or expiry units/semantics;
- permitting more than one auth mechanism instance on the same direct physical
  connection;
- moving authenticated state to another physical generation; or
- adding an actual negotiated-group field to the fixed layout.

A genuinely independent additive capability may use a new capability bit or
resource-class ID and independent vectors without changing existing semantics.
A hybrid/PQ minimum additionally requires a new KEX ID, a new required
capability, fail-closed enforcement on every production H2/H3 client and server
path, selected-group or equivalent evidence, and downgrade tests. Until then,
`TLS13_CLASSICAL_FLOOR` is the only valid KEX value and T015 remains `DEFER`.
