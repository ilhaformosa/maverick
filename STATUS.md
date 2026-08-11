# Maverick Status

Date: 2026-08-11

This is the only active current-truth document. Archived plans, manifests,
evidence records, and release notes do not override it.

## Direction Decision

Phase 3 and every recovery alias are terminally retired. Its incomplete result
remains `No-Go`; it produced no product result, and no Phase 3 server, lease, or
run is active. The separately authorized owner pilot is a new product-learning
track, not an amendment, completion, or relabeling of Phase 3.

Progress now means:

> A real person uses the real product to complete a real task.

Passing tests, safe rejection, hashes, manifests, and evidence tooling are
quality controls. They do not count as product progress on their own.

## One-Page Pilot Strategy

### 1. Who is the first user?

The first user is the project owner on an owner-controlled spare macOS laptop.
No friend, journalist, activist, or otherwise at-risk third party is recruited
for the first pilot. The task is ordinary, non-sensitive web use through
Maverick during one 24-hour observation window; continuous browsing is not
required.

### 2. What is the first adversary?

The first adversary model is the access-network observer on the selected pilot
path. It may block endpoints using TLS metadata or traffic fingerprints and may
actively probe the public server. The primary client path for this pilot is one
privately identified, owner-controlled lawful restricted access network; its
type, provider, address, endpoint, and location are not public project data. A
second access-network run would be a separate later test. No claim is made about
a named country, firewall, or censorship system unless the test actually
produces evidence that supports it.

### 3. How does the user get the software?

The first distribution channel is a GitHub prerelease containing a standalone
`maverick` CLI binary and one short start/check guide for each supported pilot
target. The user generates fresh credentials and two minimal configs locally;
public archives never carry shared credentials. `./scripts/build-pilot.sh`
produces the same shareable archive from a source checkout. A package repository,
updater, GUI, and broad platform matrix are not prerequisites. The five-minute
install path was first attempted with `v1.2.0-alpha.2`. The first successful
proxied page load occurred after 5 minutes 18 seconds, so that path worked but
missed the strict target by 18 seconds. A later `v1.2.0-alpha.3` retest exposed
a default local-DNS port conflict on its first attempt. With only the optional
local DNS listener disabled, a corrected second attempt completed in 3 minutes
44 seconds.

### 4. What are the field threats?

The first field threats are:

- install or configuration friction that prevents use;
- a distinguishable client TLS/H2 profile;
- active probes receiving a Maverick-specific response;
- connection instability during normal daily use;
- DNS, timing, volume, endpoint-IP, and destination metadata that Maverick does
  not currently hide.

Compromised endpoints, a malicious server operator, global traffic correlation,
and destination-site browser fingerprinting remain outside this pilot.

## North-Star Result

The first milestone passes only when all of the following are true:

1. the owner installs the pilot artifact in five minutes without developer
   intervention;
2. the owner performs ordinary browsing during one 24-hour observation window
   on the privately named, lawful real-network path;
3. the default client uses the browser-like TLS/H2 path;
4. ordinary browsing works well enough to finish the day;
5. the record contains no Maverick-specific active-probe response and no
   observed block attributable to the tested Maverick fingerprint;
6. failures and unknowns are recorded plainly.

This result would still be one pilot, not proof of anonymity, broad
censorship resistance, production readiness, or browser identity.

## Current Product Truth

- Development stage: **Beta**. The owner entered Beta after the fresh-origin
  Alpha.6 installation, ordinary-browsing, browser-diagnosis, and sleep/resume
  gates described below passed. This is a development-stage decision, not a
  retroactive rename of an already published artifact.
- Declared workspace package version, current published Beta prerelease, and
  last independently reverified public artifact: `v1.2.0-beta.4`. PR #27
  merged the reviewed candidate as main commit
  `5109d89bdddc23a2830eda2c0c56a954d3b214a9`. Annotated tag object
  `18f18eee87f8a89c662356334ae3f85d80bc577e` directly targets that commit.
  Pilot-release run `30718828654` completed successfully: its exact-tag/current-
  main gate, local product gates, Linux and macOS archive builds, native
  verification, target-aware CycloneDX generation and verification, exact-file
  re-verification, and publication jobs all passed. GitHub marks the resulting
  non-draft prerelease immutable, and it contains exactly two archives, two
  checksum files, and two target-aware SBOMs.
  Independent public checks reconfirmed the tag, current-main ancestry, release
  metadata, byte-for-byte release note, exact six asset names, uploaded states,
  sizes, and GitHub API SHA-256 digests. The downloaded Apple Silicon archive
  passed static and native verification, and both downloaded SBOMs passed the
  full locked runtime-closure verifier. The Linux archive was natively verified
  on the matching Ubuntu release runner before publication; the publish job
  statically reverified the exact uploaded bytes, and the independently
  downloaded bytes matched the public API digest. A separate macOS check also
  reconfirmed the Linux checksum and archive contents before stopping
  fail-closed at the architecture-tool gate because GNU `readelf` is not
  installed there. These are publication quality controls, not a new human
  user, real-network, production, anonymity, or broad censorship-resistance
  result. Beta.4 changes no Maverick protocol version, config version,
  stored-profile schema version, or existing authentication/frame wire format.
- The failed Beta.3 publication attempt remains immutable. Annotated
  `v1.2.0-beta.3` tag object
  `3f3f1e20000cdd5857d14c665181eb88902c838f` directly targets `main`
  commit `fa201b6844ace93a95411ec9162c3317d4868043`. Pilot-release run
  `30690464199` stopped fail-closed: verification succeeded; the Linux build,
  target-aware CycloneDX SBOM, re-verification, and Actions artifact upload
  succeeded; and the macOS binary, archive, and native verification succeeded
  before CycloneDX SBOM generation failed. The macOS artifact upload did not
  occur, and publication was skipped. No GitHub Release or public release asset
  exists. This was not a Rust product failure. The later portable verifier
  repair and Beta.4 publication do not retroactively turn Beta.3 into a release,
  and its tag was not moved, deleted, force-updated, reused, or given assets.
- The previous `v1.2.0-beta.2` prerelease remains immutable. Its annotated tag
  directly targets main commit
  `6862a3004ec9c3b1e52fd03f71dc47b771564cc4`, and GitHub marks the prerelease
  immutable. The release contains exactly the two supported pilot archives and
  their checksum files. Post-publication checks reconfirmed the release and
  asset attestations, exact asset names and digests, both checksum files, and
  native execution of the Apple Silicon artifact. The Linux artifact passed
  static and native verification on the matching Ubuntu release runner; a
  separate macOS recheck confirmed its archive, source, version, checksum, and
  raw ELF identity before stopping fail-closed because GNU `readelf` is not
  installed on that workstation. It remains the independently verified
  rollback option documented for Beta.4; it was not moved, replaced, or
  retroactively renamed.
- The historical `v1.2.0-beta.1` and `v1.2.0-alpha.6` releases were not moved,
  replaced, or retroactively renamed.
- Protocol version: `1` (unchanged).
- Config version: `1` (unchanged).
- Stored-client-profile schema version: `1` (unchanged).
- Existing authentication and frame wire formats: unchanged.
- Unpublished workspace source now includes the opt-in, library-only
  `run_direct_v3_h3_client_once(ClientRoleConfig)` entry under
  `quiche-foundation`. It binds one configured nonzero loopback SOCKS5
  address, accepts exactly the first external peer attempt, starts the sole
  direct-v3 H3 owner only after one loopback IP-literal CONNECT parses and
  passes policy, carries that one flow, and then explicitly finishes or cancels
  the flow and closes the owner. Local cross-crate tests cover the real
  SOCKS/H3/server/TCP path, exact clean EOF, fixed rejection, zero server
  ingress/actor/target activity for pre-owner rejection, and address/resource
  reclamation. This is local quality evidence, not a new human user or
  real-network result. It does not alter published Beta.4, the default H2 path,
  normal `start_client`, CLI or SDK wiring, non-loopback use, concurrent or
  long-running service, retry or replacement, release state, or deployment
  authorization.
- Unpublished workspace source now also gives each authenticated legacy H2 or
  opt-in legacy-H3 `OpenUdp` flow one crate-private connected UDP target slot.
  Sequential packets naming the same logical `TargetAddr` and port reuse one
  operating-system socket and source address. A target change drops the old
  owner before opening the replacement, and an open, send, receive, or bounded
  target-receive failure leaves the slot empty. Normal handler scope releases
  it on explicit close, request EOF, idle timeout, handler error, cancellation,
  or return. A bare initial `UdpPacket` remains the unchanged one-shot path.
  Local loopback tests cover H2 and legacy-H3 same-target source reuse, target
  switching, a receive timeout clearing its slot and releasing its exact source,
  and exact-source reclamation after close. The existing exchange remains
  serial: send one packet, then receive at most one packet. It has no
  request-response correlation, so a delayed, duplicate, or unsolicited target
  datagram may be observed by a later exchange; that traffic is neither
  supported nor verified here. This changes no published Beta.4 artifact, wire
  or frame format, config or schema version, limit, CLI, SDK, direct-v3/quiche
  H3 path, or deployment authorization. It is sequential foundation behavior,
  not pipelining, CONNECT-UDP, QUIC Datagram, a general-purpose SOCKS UDP
  contract, evidence of suitability for games or voice, a new human user,
  real-network evidence, or product-readiness evidence.
- Unpublished workspace source now also binds every later non-padding,
  actionable frame in one authenticated legacy H2 or opt-in legacy-H3
  `OpenUdp` request to the flow identifier that opened it. A mismatched
  `UdpPacket` or `CloseFlow` returns exactly the opened flow's `ProtocolError`
  and terminates that request stream before application-payload decoding,
  rate-policy work, target-slot access, socket creation, or target I/O. H2
  completes that application error with `grpc-status: 0`; legacy H3 ends with
  FIN. Public-tunnel loopback tests assert the actual H2 or H3 variant, prove
  that a real UDP target receives no mismatched packet, and cover mismatched
  close plus terminal response shape. The handler does not explicitly close
  the authenticated physical connection, but these tests do not prove its
  reuse. Existing same-flow behavior remains covered by the full local suites.
  This changes no published Beta.4 artifact, frame or wire format, protocol,
  config or schema version, public API, client behavior, direct-v3/quiche H3
  path, deployment authorization, human-user result, real-network result, or
  product-readiness claim.
- Unpublished workspace source now also gives each `send_data` operation that
  carries one encoded Maverick response frame on the opt-in legacy-H3 server
  path a whole-operation completion deadline. Runtime padding, each emitted
  cover frame, and the business frame each start a full independent budget; a
  requested stream finish starts another full budget only after its final DATA
  completes. `ServerHello` uses the configured handshake timeout, other
  state-machine responses use the configured server idle timeout, and TCP relay
  DATA or FIN uses that relay's idle timeout. Expiry propagates one fixed private
  error through the existing handler, without trying to send another Maverick
  `Error` on the blocked stream, and ordinary scope drop releases request and
  target owners. A raw Quinn/H3 loopback test sends valid authentication,
  `OpenUdp`, and six same-flow requests without ever consuming the response
  direction; the real target receives six ordered requests from one reused
  server source and returns 48 KiB across six replies to that source. With QUIC
  keepalive preserving the physical connection, the exact UDP source becomes
  reusable after the state deadline. This is bounded
  whole-operation behavior, not H2-style progress-reset parity, proof that the
  connection can serve another request, or coverage of raw fallback responses,
  client sends, direct-v3/quiche H3, non-loopback traffic, general-purpose UDP,
  a real-network result, a published-artifact change, or product readiness.
- Unpublished workspace source now also makes a client `UdpAssociation` fail
  closed after an in-flight relay has taken its tunnel owner but does not
  complete with one matching, decoded `UdpPacket`. The association temporarily
  removes that private owner before its first transport await and restores it
  only after complete success. Cancellation, send or read failure, response
  timeout, decode failure, a terminal frame, or response EOF therefore drops
  the ambiguous tunnel and leaves the association permanently unusable. Every
  later relay attempt and `close` returns exactly `UDP association is no longer
  usable` before transport I/O; a healthy local encode failure still occurs
  before ownership is taken and does not poison the association. Real loopback
  H2 and opt-in legacy-H3 tests cancel only after target A receives the exact
  request and reveals the server UDP source, then send a delayed reply A. The
  next relay is rejected before a different target B receives anything, the
  exact target-A source becomes reusable, and closing the unusable association
  returns the same fixed error. H3 selection with no cooldown before and after
  the exchange rejects H3-connect fallback evidence. Existing healthy
  same-association roundtrips and explicit close remain covered. Public
  signatures are unchanged, but this intentionally tightens one public failure
  behavior. It changes no published Beta.4 artifact, server behavior, frame or
  wire format, protocol, config or schema version, feature, dependency, CLI,
  SDK, direct-v3/quiche H3 path, or deployment authorization. It does not add
  per-packet correlation, pipelining, full-duplex UDP, TUN or SOCKS end-to-end
  evidence, physical-connection reuse evidence, a real-network result, or
  product readiness.
- Unpublished workspace source now also adds three public constants that name
  the authenticated legacy-H2/legacy-H3 `OpenUdp` mode-negotiation gate, the
  existing flags-zero serial mode, and the duplex request bit.
  At that negotiation-gate slice, production clients did not send that duplex
  mode, H2 and WebSocket did not accept it, and the following source-only
  selected legacy-H3 server foundation was its sole acceptance path. The later
  library, selected-H3 SOCKS, and bounded selected-H3 TUN items below add the
  current client consumers; ordinary `UdpAssociation`, H2, WebSocket,
  flags-zero TUN, and flags-zero SOCKS paths remain serial or reject duplex as
  described below.
  The handshake gate bit means only that both peers understand the gate. New
  clients request that gate bit on H2 and opt-in legacy-H3, and new servers
  select it there only as an authenticated supported subset. WebSocket continues
  to request and select zero for that bit, the existing TLS channel-binding
  selection is preserved, and clients retain only the complete selected mask
  that passed the `ServerHello` MAC, protocol, and subset checks.
  At that gate-only slice, production clients sent only flags-zero `OpenUdp`
  and required an exact same-flow, flags-zero, empty `WindowUpdate` before the
  first UDP packet. That strict check remains the rule for ordinary
  `UdpAssociation` and every flags-zero production UDP tunnel attempt,
  including a WebSocket-backed attempt; the later selected-H3 consumers
  instead require the exact flags-one acknowledgement described below. Normal
  WebSocket TCP behavior and mode-bit request/selection remain unchanged. The
  legacy H2 server rejects
  every nonzero `OpenUdp` flag, while legacy H3 rejects feature-zero nonzero
  flags and every reserved or mixed mode, with the opened flow's exact
  `ProtocolError` before a flow permit, `OpenUdp` payload decode, rate policy,
  target slot, socket, or target I/O. Raw real-loopback H2 and Quinn/H3 tests
  cover feature-zero and selected-bit serial success, H2 duplex rejection,
  selected legacy-H3 exact-duplex acceptance, legacy-H3 feature-zero duplex
  rejection, and reserved-mode rejection; unit tests cover auth v1/v2
  selection, old-server subsets, TLS channel binding, WebSocket mode-bit
  isolation, and strict client acknowledgement shape. The focused matrices,
  all-features integration,
  formatting, strict Clippy, Rustdoc, `user-smoke.sh`, and `local-harness.sh`
  pass. The broader `--no-default-features` and
  `--no-default-features --features h3` integration runs each retain the same
  pre-existing unrelated private-mode/rustls-default configuration-test
  mismatch; all their other tests pass. This adds source-level public constants
  but changes no existing public signature, published Beta.4 artifact,
  protocol/config/schema version, existing frame encoding, dependency,
  manifest, CLI, SDK, SOCKS, TUN, relay owner, normal WebSocket TCP or mode-bit
  request/selection behavior, or direct-v3/quiche H3 path. That negotiation-gate
  slice alone added no duplex, pipelining, correlation, CONNECT-UDP, QUIC
  Datagram, real-network result, product-readiness result, or release
  authorization; the next item records the later exact legacy-H3 server
  acceptance. Per-flow flags have no separate MAC, so the existing provider-
  fronted H2 terminating-intermediary trust residual remains.
- Unpublished workspace source now also accepts the already named duplex
  `OpenUdp` flag only on an authenticated legacy-H3 request whose selected,
  MAC-authenticated `ServerHello` mask contains the existing mode-negotiation
  bit. The server first returns the same-flow, flags-one, empty
  `WindowUpdate`. The first decodable same-flow `UdpPacket` then fixes its
  exact logical target and port before rate policy, resolution, socket
  creation, or target I/O. One handler owns one connected UDP socket, splits
  the H3 request stream, and selects among peer frames, fixed-target datagrams,
  and the idle deadline. The target can therefore send more datagrams than the
  peer has sent requests, and the peer can continue sending afterward, without
  adding a task, channel, queue, second owner, retry, packet correlation, or
  automatic fallback.
  A later target or port change, malformed input, or actionable wrong-flow
  frame returns the opened flow's exact `ProtocolError` and bounded FIN. The
  wrong-flow gate runs before payload decode, target locking, rate policy, or
  target I/O; after any such bad frame is decoded, no further target operation
  begins. This is not an absolute cross-direction ordering guarantee: a valid
  target datagram that already won selection may be forwarded before a
  concurrently arriving bad peer frame is decoded. Target open, send, or
  receive failure instead returns the opened flow's `TargetConnectFailed` and
  bounded FIN, drops the owner, and never reopens it. Explicit close, active-
  owner idle expiry, request unwind, and blocked-response expiry release the
  exact source; response DATA and FIN retain the existing whole-operation
  completion deadlines.
  Both directions borrow the same `UserPolicy` and its same optional shared
  `RateLimiter`, throttling the corresponding payload byte count before target
  or H3 send I/O. The existing limiter unit gate remains green, but this slice
  adds no nonzero-rate real-H3 duplex timing evidence and does not establish
  end-to-end rate-policy timing. Raw Quinn/H3 loopback coverage verifies the
  authenticated selection, exact acknowledgement, fixed source, two peer
  packets followed without another peer frame by three target datagrams,
  including one excess unsolicited push, continued peer send, exact terminal
  errors, active-owner idle cleanup, blocked-response cleanup, FIN, and source
  rebinding. The 93-test H3 integration target, all-feature
  workspace suite, no-default server and focused H3 gates, formatting, strict
  Clippy, warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh` pass
  locally.
  This began as a legacy-H3 server/wire foundation. At that slice,
  `UdpAssociation`, SOCKS, TUN, and client paths remained flags-zero serial;
  the next two items record the later library and selected-H3 SOCKS consumers.
  H2 nonzero flags, feature-zero nonzero flags, and reserved or mixed modes
  remain rejected. WebSocket and direct-v3/quiche H3 are unchanged. The slice
  reuses one existing feature bit, flag, frame set, payload set, and encoding;
  it adds no number, wire field, protocol/config/profile version, public API
  signature, feature, dependency, manifest, or `Cargo.lock` change. Biased
  selection may starve target receive under continuously ready peer input, so
  there is no fairness or no-loss claim. By itself it did not establish a
  client consumer, general-purpose SOCKS/TUN UDP, games or voice suitability,
  real-network evidence, a published-artifact change, product readiness, or
  release authorization.
- Unpublished workspace source now also exposes an additive, public,
  `feature = "h3"` library API for one opt-in legacy-H3 duplex UDP
  association. `LegacyH3DuplexUdpAssociation::open` fixes one target and port,
  and `split(&mut self)` lends distinct send and receive halves without
  creating owned or `'static` direction handles. A successful
  `send_packet(Bytes)` means only complete tunnel submission;
  `receive_packet()` returns the next fixed-target datagram without request
  correlation and returns `None` only after the server's clean idle close and
  response FIN. `close(self)` performs the bounded terminal exchange. At this
  library-only slice, normal `UdpAssociation`, H2, WebSocket, SOCKS, TUN, CLI,
  SDK, and direct-v3/quiche H3 paths remained unchanged and flags-zero serial;
  the selected legacy-H3 SOCKS integration in the next item later reuses the
  same implementation without changing those public signatures.
  Opening first validates the complete client config, requires explicit
  legacy H3, rejects TLS-terminating fronting and required channel binding,
  and validates the fixed target and nonzero port before network I/O. It then
  makes one direct Quinn/H3 connection without consulting the scheduler,
  fallback, or cooldown state; uses the production authenticated handshake;
  requires the selected mode gate; and accepts only the exact same-flow,
  flags-one, empty acknowledgement. The association owns the sole request
  stream and transport. Its borrowed halves share only one atomic unusable
  state and a crate-private synchronous abort handle, with no added lock, task,
  channel, queue, retry, second owner, or multi-target map.
  Pending receive is cancellation-safe. Send and close arm one scope guard
  before their first await inside the split transport operation; cancellation,
  timeout, outer-frame encode or transport failure, or incomplete terminal
  handling after that point makes the association permanently unusable and
  aborts the dedicated connection.
  Every H3 DATA and request FIN has an independent whole-operation completion
  deadline. Receive requires the fixed flow, flags, target, and port. Close
  concurrently sends exact `CloseFlow` plus request FIN while draining racing
  valid packets through response FIN and no trailers; the first direction
  failure cancels the other immediately. Drop also aborts the owner. Public
  failures use fixed, source-free categories and do not copy target, backend,
  credential, certificate-path, or raw transport values.
  Real public-API Quinn/H3 loopback coverage sends A and B before any target
  reply from one exact server UDP source, receives three target pushes without
  another client frame, sends C through the same source, closes, and rebinds
  that source. Separate tests cover a canceled pending receive that continues,
  deterministic send cancellation while the guard is armed in a pre-I/O
  shaping wait, close cancellation, active-owner idle cleanup, and an
  oversized post-A send that reaches the guarded outer-frame encode failure,
  returns the fixed send-failed category, aborts, and releases the source.
  Preflight tests point invalid, disabled-H3, valid WebSocket/fronting, and
  required-binding configs at a real UDP server sentinel and observe zero
  datagrams; unavailable H3 with H2 available performs no H2 authentication or
  target I/O. Unit and source checks cover exact acknowledgement and receive
  classifiers, sticky single abort, first-error close cancellation, and the
  guard around real DATA and FIN awaits.
  This slice does not add a scripted malicious H3 peer, so it does not provide
  public-carrier dynamic evidence for missing feature selection, a wrong
  acknowledgement, malformed/wrong-flow/wrong-target response, or the fixed
  receive-failed and close-failed categories. It also does not deterministically
  cancel during a transport write or prove a partial write or blocked response;
  the send-cancel test is specifically pre-I/O. There is no fairness, ordering,
  no-loss, physical-connection reuse, general SOCKS/TUN UDP, games or voice,
  real-network, product-readiness, or release claim.
  The eight-test focused public matrix, 83-test H3 client library suite,
  101-test H3 relay target, all-features workspace suite, formatting, strict
  all-target/all-feature and relevant no-default Clippy, warning-denied
  Rustdoc, `user-smoke.sh`, and `local-harness.sh` pass locally. Client library
  tests also pass 74/74 with no default features and 80/80 with no default
  features plus H3. The broader no-default relay runs retain exactly the
  already recorded unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo`
  private-mode/rustls-default mismatch: 67 other tests pass without default
  features, and 98 other tests pass with H3. This public source API is
  SemVer-observable under the opt-in feature, but it changes no published
  Beta.4 artifact, package version, manifest, dependency, `Cargo.lock`, wire
  number or encoding, protocol/config/profile version, deployment
  authorization, human-user result, or release state. Any publication requires
  a new prerelease.
- Unpublished workspace source now also lets the normal `start_client` SOCKS5
  UDP ASSOCIATE path consume the already authenticated legacy-H3 duplex mode.
  The first accepted local UDP packet makes exactly one
  `ClientTunnelPool::open` call. If the returned tunnel is actually legacy H3
  and its MAC-verified selected mask contains the existing mode-negotiation
  bit, that same tunnel requests flags one and the one SOCKS handler selects
  among control EOF, local UDP input, and target pushes through the borrowed
  send and receive halves. Actual H2, WebSocket, H3 without the selected bit,
  and H2 returned by the existing scheduler after an H3 setup failure use the
  same already-open tunnel in the existing flags-zero serial association. The
  handler makes no second connection or fallback decision for that initial
  packet.
  At that earlier selected-H3 consumer slice, the flags-one path fixed the first
  legal target and port. A later different-target packet was dropped locally
  before tunnel send, touched neither the fixed target nor the rejected target,
  and did not prevent a following packet for the fixed target. At that slice,
  duplex open, send, receive, terminal, or close failure ended the current
  SOCKS control association; it did not clear the state to reopen, replay, or
  fall back after authenticated H3 duplex setup. Flags-zero associations retain
  their prior per-packet target and abnormal control-byte behavior. The existing
  one-local-peer rule and SOCKS UDP encoding remain unchanged. No task, channel,
  queue, lock, target map, second association owner, retry, or packet correlation
  was added.
  Real loopback tests through normal `MaverickHarness`/`start_client` verify an
  actual selected H3 carrier with no cooldown or H2 pool activity, one complete
  packet-A roundtrip, then two target pushes delivered without a new local UDP
  packet, control-EOF cleanup, and exact server-source rebinding. Separate
  normal-client test at that earlier slice verified a different-target packet
  contacted neither A nor B before A continued on the same source. A separate
  authenticated H3 flow-limit rejection ends the control association with zero
  target I/O and no fallback; an unavailable H3 setup falls back to one H2
  serial association inside the existing scheduler and successfully switches
  from target A to B; and the ordinary H2 serial path retains one tunnel flow
  and per-packet target switching. The observed target-push order is bounded
  loopback regression
  evidence only, not an ordering, fairness, no-loss, or request-response
  correlation promise. H3-without-the-bit and WebSocket mode selection are
  source/unit or existing handshake evidence, not claimed as new successful
  SOCKS UDP runtime tests. Clean idle and transport-failure cleanup remain
  lower-layer public-association evidence rather than new SOCKS end-to-end
  evidence.
  The focused SOCKS matrix passes 8/8; client libraries pass 74/74 without
  default features and 81/81 with H3. The all-features workspace suite,
  formatting, strict all-target/all-feature and relevant no-default Clippy,
  warning-denied Rustdoc, `user-smoke.sh`, and `local-harness.sh` pass locally.
  The broader no-default relay runs retain only the already recorded unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo`
  private-mode/rustls-default mismatch: 68 other tests pass without H3 and 103
  other tests pass with H3. This changes the runtime behavior of the existing
  public `start_client` and `serve_udp_associate` entry points and is therefore
  SemVer-observable even though it adds no public signature. CLI command syntax
  and SDK signatures are unchanged, but opt-in callers inherit the selected-H3
  SOCKS behavior. No package version, published Beta.4 artifact, manifest,
  dependency, `Cargo.lock`, wire number or encoding, protocol/config/profile
  version, deployment authorization, real-network result, product-readiness
  result, or release state changes. Any future publication requires a new
  prerelease and must not rewrite Beta.4. That earlier result was one
  fixed-target legacy-H3 SOCKS slice, not general multi-target duplex SOCKS,
  TUN integration, games or voice suitability, or a fairness/no-loss guarantee.
- Unpublished workspace source now also bounds and cancels pending normal-SOCKS
  legacy-H3 setup. After legacy-H3 transport connection succeeds, the common
  tunnel-open path gives the request through complete, MAC-verified
  `ServerHello` one fresh `connect_timeout_ms` budget. Expiry returns a fixed,
  source-free, crate-private application-handshake category and dropping the
  pending owner synchronously aborts its dedicated H3 request and connection.
  This failure bound is common to callers of the normal legacy-H3 tunnel-open
  path; successful opens are unchanged, and the public direct-H3 duplex API
  retains its existing single outer connection-plus-handshake budget.
  Dynamic stalled-peer evidence in this slice covers only normal
  `start_client` SOCKS5 UDP, not TCP, DNS, HTTP CONNECT, TUN, or the direct-v3/
  quiche H3 path.
  A statically configured H3-candidate SOCKS association—H3 compiled, `auto`
  mode, `experimental_h3` enabled, and WebSocket absent—now uses a biased,
  EOF-first select between control EOF and the pending pool open. That select
  remains active through H3 cooldown and the same open attempt's permitted
  pre-request H3-connect-to-H2 fallback wait, avoiding a second dynamic
  transport decision. Default-H2 `auto`, `stable`, `private`, and WebSocket
  configurations retain their direct await. Non-EOF control bytes are still
  ignored and do not cancel setup, but while a configured-H3-candidate open is
  pending the new select may consume them earlier than before; this slice makes
  no unchanged consumption- or scheduling-time claim. A pre-request H3
  connection failure may still mark cooldown and fall back to H2. Once an H3
  request has begun, its application-handshake timeout is terminal for that
  SOCKS association: there is no cooldown, H2 fallback, replay, resend, or
  reopen.
  If the actual H3 carrier returns a valid `ServerHello` selecting flags-zero
  compatibility, the SOCKS-only flags-zero `OpenUdp` acknowledgement wait gets
  a separate fresh `connect_timeout_ms` budget. Only expiry maps to a fixed,
  source-free terminal category. H2 and WebSocket serial setup and the
  selected-bit duplex path with its existing deadlines remain unchanged. The
  generic/public/TUN post-tunnel flags-zero `OpenUdp` acknowledgement wait is
  unchanged; a caller that reaches the normal common legacy-H3 tunnel-open path
  still inherits the application-handshake bound described above. Control EOF
  can cancel the SOCKS pending setup through the same outer configured-H3-
  candidate select, but this slice's independent flags-zero scripted-peer test
  dynamically proves its deadline, not a second flags-zero-specific EOF case.
  Real Quinn/H3 scripted-peer coverage through normal `start_client` first
  verifies the production `ClientHello`, then either withholds the final byte
  of a MAC-valid `ServerHello` or sends a complete selected-zero hello, observes
  the exact flags-zero `OpenUdp`, and withholds its acknowledgement. The
  partial-hello cases dynamically prove both the configured deadline and
  prompt control-EOF cancellation; the flags-zero case proves the separate
  deadline. Together they observe zero UDP-target contact, zero same-port TCP/
  H2 fallback and pool activity, exactly one H3 connection and request, no
  replay or cooldown, and bounded H3 abort cleanup. They do not prove other
  callers' stall cancellation, a malicious peer's wrong acknowledgement or
  malformed/wrong-flow/wrong-target response, partial client transport writes,
  or blocked client-response transport pressure.
  Formatting, the all-features workspace suite, the 108/108 all-features relay
  target, client libraries at 74/74 without default features and 82/82 with H3,
  strict workspace and client Clippy matrices, warning-denied Rustdoc,
  `user-smoke.sh`, and `local-harness.sh` pass locally. The broader no-default
  relay runs retain only the already recorded unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo`
  private-mode/rustls-default mismatch: 68 other tests pass without H3 and 105
  other tests pass with H3. The common application-handshake failure bound is
  SemVer-observable through every public entry point that reaches the common
  legacy-H3 tunnel-open path, including `start_client` and
  `serve_udp_associate`, but adds no public signature and changes no package
  version, published Beta.4 artifact, manifest, dependency, `Cargo.lock`, wire
  number or encoding, protocol/config/profile version, deployment
  authorization, real-network result, product-readiness result, or release
  state.
- Unpublished workspace source now lets one normal `start_client` SOCKS5 UDP
  ASSOCIATE accepted over an IPv6-loopback control connection advertise and
  bind one `[::1]` loopback UDP relay. The local relay family follows the
  accepted control peer when it is available and, only when it is absent,
  falls back to the control connection's local-address family. IPv4 controls
  still advertise and bind one `127.0.0.1` relay. The existing exact control-IP
  check and first accepted UDP peer's full-`SocketAddr` pin are unchanged.
  The real-loopback test uses an IPv6 local listener, control connection, and
  UDP peer while carrying an independent IPv4 tunnel target to an IPv4 UDP
  target. It proves that local IPv6 relay roundtrip, exact SOCKS target metadata,
  H2 pool use, and source cleanup; it does not prove IPv6 target reachability,
  dual-stack listener compatibility, IPv4-mapped IPv6 support, non-loopback
  access, real-network behavior, product readiness, or release authorization.
  The exact IPv6-control test passes 1/1. The relay matrices pass 72/72 with
  defaults and 109/109 with all features. The no-default relay matrix passes
  69 tests and the no-default-plus-H3 matrix passes 106 tests; each retains only
  the same pre-existing unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo` failure
  because private mode rejects
  `advanced.stealth.tls_fingerprint=rustls_default`. Client library tests pass
  74/74 without default features and 82/82 without defaults plus H3. The
  all-features workspace suite, strict workspace and no-default client Clippy
  matrices, warning-denied all-features workspace Rustdoc, formatting,
  `user-smoke.sh`, and `local-harness.sh` pass locally.
  The SOCKS BND address-family change is a SemVer-observable runtime and SOCKS-
  wire result through public `start_client` and `serve_udp_associate`;
  `serve_udp_associate_with_pool` remains crate-private. It adds no wire number
  or encoding and changes no Maverick tunnel wire behavior, public signature,
  protocol/config/profile version, package version, or published Beta.4
  artifact. Any future publication requires a new prerelease and must not
  rewrite Beta.4.
- Unpublished workspace source now also lets one normal `start_client` SOCKS5
  UDP ASSOCIATE using actually selected legacy-H3 duplex mode move
  sequentially from target A to B and back to A. When one accepted local packet
  names a different target or port, the handler carries exactly that one packet
  out of the borrowed split operation, takes sole ownership of the old client
  association, and selects control EOF before its bounded close. Source review
  confirms that only a successful old `close` return permits exactly one fresh
  `SocksUdpAssociation::open_with_pool` call and at most one send of the
  retained packet. Control EOF or a close failure ends the handler before the
  new target is opened or contacted.
  A fresh retryable pool or serial-open failure drops the retained packet,
  leaves association state empty, and keeps the control association available;
  a later new local packet may make its own independent open attempt. A fresh
  pre-request H3 transport-setup failure may still return one H2 serial
  association before the retained packet has been sent, so that is neither
  fallback nor replay of a sent packet. An opened duplex association sends the
  retained packet once under the same EOF-first selection and becomes current
  only after complete send success. An opened serial association performs the
  existing one-packet relay behavior and becomes current only on the existing
  successful or non-EOF-control result. Authenticated H3 duplex setup, first-
  send, or terminal failure remains terminal with no H2 fallback, replay,
  resend, or automatic reopen. Same-target sends, target pushes, flags-zero H3,
  H2, WebSocket, and ordinary serial behavior remain on their existing paths.
  A real-loopback normal-client test proves A1, B1, and A2 roundtrips through
  three actually selected H3 associations with zero H2 pool activity and no H3
  cooldown. The B association also delivers one fixed unsolicited push, with
  B's exact SOCKS target metadata, after B's roundtrip and without another local
  UDP packet. The test observes exactly three successful authenticated
  sessions and rebinds every unique server UDP source after control EOF. That
  metric corroborates three successful authentications; it does not
  independently count or bound all outer connection attempts. Source review,
  not that metric, establishes successful client close before the one fresh
  pool open and authentication.
  A client close response FIN is not a server flow-permit-drop barrier. The
  remote handler may retain its permit briefly until its scope drops, so this
  card neither proves nor guarantees a remote permit barrier or zero remote
  permit-lifetime overlap. During handoff, valid old-target pushes may be
  drained and discarded, and the handler does not read another local UDP
  packet; additional packets may remain in the operating-system socket buffer
  or be dropped. This is sequential client-side single-active-target behavior,
  not concurrent multi-target UDP, fairness, ordering, no loss, physical H3
  connection reuse, TUN integration, games or voice suitability, real-network
  evidence, a human-user result, product readiness, or release authorization.
  The exact handoff test passes 1/1. Ten focused relay regressions covering the
  existing H3 push, authenticated duplex-open failure, initial H3-to-H2 serial
  fallback, H2 serial target switching, H3/H2 SOCKS roundtrips, public receive/
  send/close cancellation, and flags-zero setup deadline each pass; focused
  client UDP unit coverage passes 13/13. The all-features workspace suite and
  the 108/108 all-features relay target pass. Client library tests pass 74/74
  without default features and 82/82 without defaults plus H3. The no-default
  relay run retains one pre-existing unrelated failure with 68 other tests
  passing, and the no-default-plus-H3 run retains the same failure with 105
  other tests passing:
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo` rejects
  `advanced.stealth.tls_fingerprint=rustls_default` in private mode. Default,
  H3, and no-default-plus-H3 client checks; strict workspace all-target/all-
  feature Clippy; strict no-default client Clippy with and without H3; warning-
  denied all-feature workspace Rustdoc; formatting; `user-smoke.sh`; and
  `local-harness.sh` all pass.
  This changes existing public `start_client` and `serve_udp_associate` runtime
  behavior and is therefore SemVer-observable without adding or changing a
  Rust signature. It changes no package version, public fixed-target duplex
  API, manifest, dependency, `Cargo.lock`, wire number or encoding,
  protocol/config/profile version, CLI syntax, SDK signature, server/core/frame
  path, published Beta.4 artifact, deployment authorization, or release state.
  Any future publication requires a new prerelease and must not rewrite Beta.4.
- Unpublished workspace source now gives the public TUN `DatagramFlow` contract
  an optional independent receive operation and gives `FlowConnector` an
  optional target-aware UDP open operation. Both additions are object-safe
  default methods: an unchanged serial flow waits until cancellation and then
  returns `Cancelled`, while an unchanged connector delegates target-aware
  open to its existing `open_udp`. Existing required `open_udp`, `exchange`,
  and `close` signatures and behavior are unchanged. `Ok(None)` from an
  independent receive is reserved for clean remote close; a received datagram
  carries no request-correlation guarantee, and support is fixed for the flow
  lifetime.
  The TUN UDP worker now opens with its existing `{app, target}` key and selects
  one cancellation-safe independent receive alongside the existing local
  command, idle, and shutdown paths. A local command first drops the pending
  receive future and then uses the unchanged bounded `exchange`. A remote
  datagram reuses the existing single `EngineEvent::UdpResponse`, exact-target
  gate, single pending response, accepted backpressure, payload limit, and
  packet writer. The existing successful local-exchange idle refresh is
  unchanged. On independent receive, only an accepted same-target datagram
  refreshes idle; a wrong-target independent datagram is dropped by the
  existing gate and cannot keep the flow alive by itself. The worker still owns
  exactly one flow and adds no production task, channel, queue, lock, map,
  buffer, counter, or config.
  A fake-connector packet-runtime test proves A and B exchanges, cancellation
  and reuse of a known-pending receive, rejection of one wrong-target push,
  delivery of one exact-target push without a new local packet, a subsequent C
  exchange, one exact target-aware open, and non-forced quiescent cleanup. The
  exact test passes 1/1 and also passed 50 consecutive focused reruns; the TUN
  runtime and library suites pass 20/20 and 4/4. The all-features workspace
  suite passes after one unchanged server timing test failed transiently in
  the first run, then passed both its exact rerun and the complete rerun. The
  relay target passes 72/72 with defaults and 109/109 with all features. Its
  canonical serial no-default run passes 69 tests and its serial
  no-default-plus-H3 run passes 106; each retains only the same pre-existing
  unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo` failure
  because private mode rejects
  `advanced.stealth.tls_fingerprint=rustls_default`. Client library tests pass
  74/74 without defaults and 82/82 without defaults plus H3. Strict workspace
  and no-default client Clippy, warning-denied all-features Rustdoc,
  formatting, `user-smoke.sh`, and `local-harness.sh` pass locally.
  This is a public fake-connector TUN runtime foundation, not a real Maverick
  client or legacy-H3 consumer, a general duplex UDP result, blocked-send
  concurrency evidence, ordering, fairness, no loss, correlation, games or
  voice suitability, real-network evidence, product readiness, or release
  authorization. The bounded selected-H3 TUN consumer recorded next preserves
  the existing flags-zero TUN setup behavior and does not inherit the
  SOCKS-only setup deadline.
  The two additive public trait methods are SemVer-observable and may conflict
  with downstream same-name methods. They change no existing required
  signature, package version, manifest, dependency, `Cargo.lock`, wire number
  or encoding, protocol/config/profile version, or published Beta.4 artifact.
  Any future publication requires a new prerelease and must not rewrite Beta.4.
- Unpublished workspace source now connects the T025b target-aware TUN runtime
  contract to a bounded normal `start_client` legacy-H3 UDP consumer when both
  H3 and TUN are explicitly enabled. Source review shows one existing TUN flow
  permit, one connector flow, and one association owner. The TUN-specific open
  calls `ClientTunnelPool::open` once. Only an actual legacy-H3 tunnel whose
  MAC-, protocol-, and subset-verified `ServerHello` selected mask includes the
  mode-negotiation bit is consumed by the existing flags-one duplex opener,
  which requires the exact same-flow, flags-one, empty acknowledgement.
  Actual H2, WebSocket, and actual H3 with that selected bit clear consume the
  same already-open tunnel through the existing flags-zero serial
  `UdpAssociation`. The TUN path keeps its existing packet-runtime outer
  connect timeout and does not inherit the SOCKS-only fresh post-tunnel
  flags-zero acknowledgement deadline.
  Before any UDP request begins, the one pool open retains the existing
  scheduler behavior: an H3 connection failure may update the existing
  scheduler cooldown state, emit its existing diagnostic, and fall back to H2
  within that same pool-open call. Once an authenticated flags-one H3
  `OpenUdp` begins, an open, send, receive, terminal, or close failure is
  terminal for that association, with no second pool open, fallback, retry,
  replay, resend, or automatic reopen.
  The duplex TUN flow is fixed to the target used at open. `exchange` rejects a
  different endpoint before any send, then sends once and returns the next
  same-target datagram without promising request correlation.
  `receive_unsolicited` receives without sending. Both operations borrow the
  same association halves, while close takes and consumes the sole owner.
  Pending receive cancellation remains reusable. Once the existing send poison
  guard is armed, failure or cancellation of that in-progress send invalidates
  and aborts the association; cancellation before the guard is armed performs
  no transport send, while cancellation waiting for receive after a completed
  send retains the reusable receive semantics. Incomplete close drops the owner
  through the existing idempotent abort path. The adapter exposes only fixed
  TUN `FlowErrorKind` categories and adds no logging or raw target, backend,
  certificate-path, or transport value. The existing pre-request scheduler
  diagnostic remains outside that new adapter boundary.
  No production task, channel, queue, lock, map, buffer, counter, config, or
  second association owner is added.
  A normal local-loopback `start_client` integration test proves an A
  roundtrip to one real UDP target, continued ownership of the exact observed
  target-facing source, delivery of a target push without a new local TUN
  packet, and a later C roundtrip from the same source. The same run observes
  H3 selected before and after the push, no H3 cooldown, zero H2 pool activity,
  one opened and zero failed TUN UDP associations, a clean stopped and
  quiescent packet runtime, exact source rebind, and clean fixture shutdown.
  The exact test passes 1/1; `tun_packet_runtime` passes 2/2 without H3 and 3/3
  with H3. Client library suites pass 71/71 without defaults plus TUN and 79/79
  without defaults plus H3 and TUN; the ordinary no-default and no-default-H3
  suites remain 74/74 and 82/82. Focused H2/H3 flags-zero regressions pass 2/2,
  and the existing selected-H3 SOCKS push regression passes 1/1.
  The all-features workspace passes, including client 154/154, server 304/304,
  relay 109/109, TUN packet integration 3/3, and TUN runtime/library 20/20 and
  4/4. The relay no-default matrix passes 69 tests and its no-default-plus-H3
  matrix passes 106; each retains only the same pre-existing unrelated
  `auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo` failure
  because private mode rejects
  `advanced.stealth.tls_fingerprint=rustls_default`. Strict workspace and
  no-default client Clippy across the relevant H3/TUN combinations,
  warning-denied all-features Rustdoc, formatting, `user-smoke.sh`, and
  `local-harness.sh` all pass locally.
  This changes the opt-in normal public `start_client` TUN runtime result and is
  SemVer-observable, but this slice adds no public Rust signature, type, method,
  field, or error. It changes no server, core, SOCKS, DNS, TCP,
  connection-manager, transport, direct-v3, manifest, dependency, `Cargo.lock`,
  wire number or encoding, protocol/config/profile version, CLI or SDK
  signature, published Beta.4 artifact, deployment authorization, or release
  state. Any future publication requires a new prerelease and must not rewrite
  Beta.4.
  This is bounded local evidence for one fixed IPv4 target through one normal
  selected legacy-H3 TUN consumer. It is not general or multi-target duplex
  UDP, blocked-send concurrent receive, malicious-peer or transport-pressure
  evidence, request correlation, ordering, fairness, no loss, physical-H3
  connection reuse, IPv6-target, real-TUN-device, games or voice, real-network,
  human-user, product-readiness, deployment, or release evidence.
- Rust product core and loopback relay path: implemented.
- Browser-like TLS backend: default build path on supported targets.
- Generated client profile: browser-like TLS/H2 by default on supported targets.
- Provider-fronted origin-address-hiding implementation: browser-like TLS over
  CDN-fronted H2 is implemented, loopback-verified, and exercised by the first
  owner pilot. The first live-provider deployment check exposed and fixed
  missing HTTP/2 scheme and authority metadata. The corrected path then carried
  the timed spare-laptop setup and real-network observation described below.
  This validates one provider-terminated reverse-proxy path, not native ECH or
  provider-independent handshake privacy. The browser-like client sent ECH
  GREASE but did not load a real ECHConfig or confirm ECH acceptance, so the
  pilot did not demonstrate that ECH hid the outer SNI. Native Maverick
  server-side ECH remains unimplemented and its runtime flag remains
  fail-closed. TLS exporter channel binding remains disabled across provider
  termination because the two TLS connections cannot share an exporter. The
  owner accepted Cloudflare TLS termination for the authorized owner-only
  24-hour observation window and understands that Cloudflare can observe
  Maverick authentication information and tunnel traffic. The older WebSocket
  carrier remains a rustls compatibility path.
- Transport naming and dependency decision: the CDN-fronted H2 path is a
  `provider-fronted workaround`, not ECH. The project will track upstream rustls
  server-side ECH work and will not fork rustls or vendor an unmerged ECH patch
  in the current execution plan. A native implementation remains a separately
  gated future option, not authorized current work.
- Local correct-credential relay and wrong-credential rejection: covered by
  `./scripts/user-smoke.sh`.
- Single-binary owner-pilot folder and shareable archive: generated locally by
  `./scripts/build-pilot.sh`; version tags publish equivalent GitHub prerelease
  assets for the supported pilot targets. The first timed owner setup completed
  all artifact, product-smoke, and configuration checks and reached a proxied
  page in 5 minutes 18 seconds. The corrected `alpha.3` retest completed the
  same user-visible checks and first proxied page in 3 minutes 44 seconds. The
  `alpha.5` retest completed all five artifact checks, both product smoke
  checks, listener startup, and the first proxied page in 1 minute 45 seconds.
  The fresh-origin `alpha.6` run completed those gates and reached its first
  proxied page in 1 minute 44 seconds.
- First timed-install artifact: `v1.2.0-alpha.2`. The earlier
  `v1.2.0-alpha.1` artifact is superseded because it lacks the live-provider H2
  request fix. The published `alpha.3` fast-start path has now been timed by the
  owner. Its first attempt failed because the generated optional DNS listener
  tried to bind the commonly occupied UDP port `5353`; a corrected second
  attempt passed in 3 minutes 44 seconds. Both results remain part of the
  product record.
- Python coordination/validation tooling: frozen under `scripts/archive/python/`.
- Former remote/evidence shell orchestration: frozen under
  `scripts/archive/legacy/`.
- Non-current documents and machine-readable production ledgers: archived under
  `docs/archive/`.
- Real install by the owner on the spare laptop: demonstrated. The original
  `alpha.2` attempt missed five minutes by 18 seconds. The corrected second
  `alpha.3` attempt beat five minutes, but the first `alpha.3` attempt failed
  because of the generated DNS default. The clean `alpha.5` path also beat five
  minutes without using the optional DNS listener. The fresh-origin `alpha.6`
  path completed from-scratch deployment and the client start gate, then beat
  five minutes in the owner-operated field run.
- Owner-only real-network pilot: completed. The planned 24-hour observation
  window was followed by an unplanned 48-hour 18-minute overrun, for a total
  client run of 72 hours 18 minutes.
- Owner-confirmed audit checkpoint (2026-07-21): the latest formal independent
  security audit of the then-current repository code completed with no open
  findings reported. This is a point-in-time result, not a warranty,
  certification, or claim that later changes inherit the same review.
- Future formal audits are optional and are not a pilot, release, or progress
  requirement. Open-source users remain responsible for deciding whether the
  software and its threat model fit their use.
- Stable, mature, production-ready, anonymity, broad censorship-resistance, and
  exact browser-equivalence claims: not made. Entering Beta does not imply any
  of those claims.

## First Pilot Result

General web browsing was smooth during the owner-only real-network pilot.
At that time, three usability exceptions remained open:

- one major video service loaded its interface and supported most non-playback
  actions, but video playback did not work;
- some images on one news site loaded extremely slowly or appeared not to
  finish; and
- during weaker connectivity, some pages continued to show an active loading
  indicator after their visible content appeared complete.

These were observed symptoms, not established causes. Evidence from that run
did not show whether they came from provider TLS termination, Maverick's H2
carrier, the destination services, browser behavior, or the underlying network.
Reconciled server-side service logs show authenticated activity across the run
without a service restart or error-like line in the retained journal, but those
logs are not detailed enough to diagnose the three symptoms. All three
observations came from the Firefox instance configured to use Maverick; Chrome
was not used during the pilot.

The planned 24-hour observation remains valid product evidence. At the end of
that run, the North-Star milestone had not passed because the timed setup
exceeded five minutes by 18 seconds and the usability findings above were
unresolved. Later sections record the corrected installation and diagnostic
results; the first-pilot result itself still does not support production,
anonymity, broad censorship-resistance, or exact browser-equivalence claims.

## Alpha.3 Reliability Hardening

The published `1.2.0-alpha.3` prerelease is locally verified hardening, not a
Beta, Stable, or mature release.

Local diagnosis reproduced one definite server-side defect: the H2 response
path could accept more target data without waiting for the receiver's flow
control window, allowing the H2 library to buffer an unbounded amount. The
server now waits for real H2 capacity and keeps only one prepared target frame
pending, while still allowing upload traffic to move when the download window
is full. The same bounded send behavior now covers the other Maverick
protocol-frame sends on the server H2 path and client H2 uploads.

Regression coverage now proves that:

- a large server send waits when the receiver stops granting capacity and
  completes byte-for-byte after capacity returns;
- client H2 sends and server protocol-frame sends outside the TCP downlink relay
  stop after no capacity progress; a slow client H2 send that keeps making
  progress may continue beyond one idle interval;
- a blocked download direction does not stop upload traffic on the same flow;
- a slow large stream does not indefinitely starve a small stream on the same
  H2 connection;
- both a Maverick TCP reset and an actual H2 request-stream reset release the
  server relay promptly instead of waiting for the ordinary idle timeout;
- a local application or target that stops reading cannot leave a relay write
  blocked beyond the configured idle bound, while slow writes that keep making
  progress are not stopped merely because their total duration is longer; and
- a normal client half-close still receives a delayed target response.

The pilot start guide now puts the already-authorized private-client path first
and reduces its terminal work to one fail-closed pasted block. Generated
example configs are also checked to retain owner-only file permissions. The
complete loopback harness, workspace tests, browser-like default build, rustls
compatibility build, generated-config checks, and local product smoke pass.

This proves the reproduced code defects are fixed locally. The later owner
retest proved that the corrected shorter install path can beat five minutes,
but it also reproduced the video, slow-image, and lingering-loading symptoms.
The retest therefore does not justify Beta, Stable, mature, production-ready,
or provider-independent claims.

## Alpha.3 Owner Retest Result

The published Apple Silicon `v1.2.0-alpha.3` artifact was retested by the owner
on the same owner-controlled spare laptop and lawful real-network path.

The first timed attempt failed after the binary, version check, and product
smoke passed because the generated client configuration enabled an optional UDP
DNS listener on `127.0.0.1:5353`, which was already in use. Double-clicking the
bare executable before running the guide did not start a listener and was not
the cause. The client reported a generic address-in-use error only after the
SOCKS listener had briefly started, making the failing component unclear.

For the second attempt, the optional local DNS listener alone was disabled.
The artifact checks, both product smoke checks, client configuration check, and
SOCKS listener all passed. Firefox first loaded a page through Maverick after 3
minutes 44 seconds. This is a successful corrected install, but it does not
erase the first-attempt default-configuration failure.

The corrected client then ran for about two hours. Ordinary browsing and text
interaction worked, but the reliability retest did not pass:

- the previously affected major video service still displayed its interface
  while refusing to play main videos, although some advertisements played;
- the previously affected news site remained slow, left some small page
  portions unloaded, and could still play its own embedded video;
- ordinary pages could retain Firefox's active loading indicator for 5 to 10
  seconds after their visible content appeared complete; and
- a complex interactive site worked but generally felt 2 to 3 seconds slower
  than the owner's normal path.

The origin did not restart, panic, exhaust memory, or show CPU, disk-I/O, or
network-interface saturation during the retained test window. A controlled
30-flow check through the same provider path also completed without an error,
so the evidence does not support simple VPS resource exhaustion or a universally
broken carrier. The field run did have weaker underlying connectivity, and the
origin egress address received an adverse third-party reputation label plus
inconsistent destination-side geolocation. Those are material confounders, not
proof of a destination-service policy decision.

Cloudflare terminates Maverick's outer provider-facing TLS connection; it does
not terminate the inner HTTPS connection between Firefox and each destination.
The evidence therefore does not support the broad claim that provider TLS
termination decrypted the video service's own HTTPS media and made video
generally impossible. Exit reputation or routing, destination-specific media
hosts, target resolution/connection delay, single-outer-TCP loss amplification,
and provider-carrier stream handling remain distinct hypotheses.

The live server metrics endpoint was not enabled, and the retained redacted
logs do not separate target DNS failure, target connection failure, H2 stream
wait, reset, or graceful close. The field evidence therefore cannot choose
among those hypotheses.

## Alpha.4 Reliability Prerelease

The published GitHub prerelease is `v1.2.0-alpha.4`. It remains Alpha and is
not Beta, Stable, mature, production-ready, or provider-independent.

The release fixes the confirmed default-install defect: newly generated and
example client configurations no longer enable the optional UDP DNS listener,
and SOCKS5, DNS, and HTTP CONNECT bind failures name the responsible setting.
Existing version-1 configurations that explicitly enable the DNS relay remain
accepted; the configuration and wire-protocol versions remain `1`.

The release adds four fixed, aggregate server counters for target-resolution
timeout, target-resolution failure, target-connect timeout, and target-connect
failure. Egress-policy rejection is not mislabeled as one of those failures.
The counters contain no domain, address, URL, credential, browsing content,
free-form error string, user label, or per-event timestamp. A controlled client
shutdown also reports the existing aggregate H2 connection-pool numbers and
booleans; those counts are activity-volume metadata even though they contain no
destination or user-provided string.

Release review also confirmed that the H2 carrier declared `application/grpc`
without completing successful responses with the required `grpc-status`
trailer. Alpha.4 sends `grpc-status: 0` only after a complete
Maverick response, while reset, incomplete-message, I/O, stall, and other
incomplete transport paths remain failures. The production client drains and
validates successful trailers, accepts the older Alpha.3 terminal-DATA behavior
without trailers, and preserves a narrow compatibility exception for Alpha.3
persistent-UDP explicit close. It never copies a provider `grpc-message` or
other free-form trailer text into its error.

The repository-local user smoke and complete local harness pass, including
formatting, strict linting, workspace tests, H2 completion/reset integration
tests, generated-config checks, rustls compatibility, and product smoke. The
required pull-request gate, CodeQL checks, main-branch CodeQL, and the single
release workflow also passed. Both public archives were downloaded again and
passed outer and inner SHA-256 checks, source/version, content, executable-mode,
and privacy checks. The downloaded Apple Silicon binary passed `version` and
`user-smoke` locally.

These results prove only the release integrity, local fixes, and diagnostic
behavior. Alpha.4 has not been tested through a new real provider path and does
not prove that the major-video, slow-image, or lingering-loading symptoms are
fixed. A new live run remains a separately authorized future action.

## Alpha.5 Reliability Prerelease

The published GitHub prerelease is `v1.2.0-alpha.5`. It remains Alpha and is
not Beta, Stable, mature, production-ready, or provider-independent.

Source inspection confirmed that the server previously passed every resolved
target address to Tokio's slice-form TCP connect operation. Tokio 1.52.3 tries
that slice strictly in order, so a slow first address can consume the entire
target-connect deadline before an address from the other IP family is tried.
This is a confirmed limitation in Maverick's former connection path, but the
existing field evidence does not prove that it caused the observed video,
slow-image, or lingering-loading symptoms.

For targets that resolve to both IPv4 and IPv6, Alpha.5 now starts the
first resolver-selected address immediately and may start the other address
family after a fixed 250-millisecond delay. A fast failure starts the next
candidate immediately. At most two attempts are active, all attempts share the
existing request-level connection deadline, the first success cancels unfinished
attempts, and the server's egress policy still filters every address before any
connection is attempted. Single-address and same-family results keep their
previous sequential order. Request-level target failure metrics remain counted
once rather than once per address attempt.

Regression tests cover delayed alternate-family startup, immediate replacement
after a quick failure, the two-attempt ceiling, winner and deadline
cancellation, resolver-order error behavior, same-family sequencing,
egress-before-connect ordering, and request-level metric classification. The
repository user smoke, complete local harness, formatting, strict linting, and
workspace tests pass. An independent read-only review reported no P0, P1, P2,
or P3 finding. The required pull-request gate, pull-request CodeQL, retained
main-branch CodeQL, and the single release workflow passed without a retry. The
automatically duplicated main-branch product CI was cancelled only after the
merge tree was proven identical to the already verified pull-request tree.

The two public archives and their checksum files were downloaded again. Both
outer archive checksums, both inner `SHA256SUMS` files, exact contents,
source/version/target metadata, executable modes, and privacy scans passed.
The remote tag resolves to the reviewed merge commit, and the downloaded Apple
Silicon binary passed `version` and `user-smoke` locally.

This proves only release integrity, the reviewed implementation, and regression
behavior. It does not show that any field symptom is fixed, does not justify
Beta or Stable, and does not authorize a provider deployment or another owner
retest.

## Alpha.5 Owner Retest Result

The published Apple Silicon `v1.2.0-alpha.5` artifact was retested by the owner
on the same owner-controlled spare laptop and lawful real-network path. All five
artifact checks and both product smoke checks passed, the SOCKS5 listener
started, and the first proxied page opened 1 minute 45 seconds after the timed
start. The complete session lasted 1 hour 37 minutes 12 seconds.

The owner reported materially faster page loading and shorter lingering-loading
indicators than in the previous retest. The previously slow news site worked
normally, search and a complex interactive site felt faster, and short-form
video played with only occasional waits. These percentages and impressions are
subjective comparisons, not controlled benchmarks.

Two reliability findings remain:

- the same major video service still showed `Video unavailable` for main
  videos, even though some advertisements and video on other services played;
  and
- after the laptop slept and resumed, short-form video became slow and reported
  a playback problem until the page was refreshed.

The server's final aggregate counters recorded 1,364 TCP flows and four target
connection failures. Target-resolution timeout, target-resolution failure,
target-connect timeout, admission rejection, overload rejection, and
authentication rejection counters remained zero. The retained service journal
contained no Maverick H2/gRPC reset, stall, or timeout line during the client
window. These destination-free counters cannot show whether the four failures
belonged to the major video service.

This evidence makes a universally broken video carrier, simple origin resource
exhaustion, or provider decryption of inner destination HTTPS unlikely. It does
not distinguish a destination decision about the exit network, a Firefox
profile or player state, a destination-specific media-host failure, or a
Maverick carrier defect. The sleep/resume finding is separately consistent with
a stale pooled H2 connection being reused until refresh.

At the end of the Alpha.5 retest, Beta was not justified. The default install
beat five minutes, but the important major-video failure was still reproducible
and was neither fixed nor understood with an acceptable documented boundary.
That was the Alpha.5 conclusion; the later fresh-origin Alpha.6 result below
supersedes it as current stage evidence.

## Alpha.6 Reliability Prerelease

The published GitHub prerelease is `v1.2.0-alpha.6`. That artifact remains an
Alpha prerelease and is not retroactively renamed by the later stage decision.
Its first field attempt was diagnostically invalid because the origin's
ordinary browsing performance failed the baseline gate. The valid fresh-origin
replacement run described below is now complete and moved current development
into Beta; it did not make Maverick Stable, mature, production-ready, or
provider-independent.

The H2 connection pool now handles one confirmed stale-cache shape
conservatively. If a tunnel handshake or ClientHello send stalls, the client
retires only the exact cached connection generation involved, only after its
failed lease has been released and no other flow is using that generation. It
then creates one fresh connection and retries once. It does not terminate an
unrelated live flow, bypass a healthy peer concurrency limit, build a hidden
multi-H2 pool, or add a periodic heartbeat. A sleep/resume case that leaves
apparently active flows on a half-dead connection remains an explicit boundary
for later evidence rather than a claimed complete fix.

`TCP_NODELAY` is now fail-closed on the client-to-server outer H2/TCP
connection, the server's accepted outer TCP connection, and each
server-to-target TCP connection. Fixed destination-free metrics now distinguish
exact timeout
retirement and recovery, H2 stream reset, H2 capacity-send stall, closed and
idle retirement, and successful connection-latency classes. Client connection
setup and tunnel open plus server target resolution and connect use the fixed
10, 25, 50, 100, 250, 500, 1,000, 2,500, 5,000, 10,000, and infinity
millisecond cumulative buckets. They retain no destination, address, URL, SNI,
credential, stream identifier, free-form error text, or per-event timestamp.

At Alpha.6 publication time, the remaining major-video symptom was unexplained.
The active diagnosis guide ordered the owner's preferred hypotheses: current
Firefox state, an isolated clean-Chrome comparison, player or media request
rejection/failure, and Maverick/provider-fronted path compatibility, including
a careful comparison inspired by the similar Mozilla proxy-service report. The
later fresh-origin comparison separated a signed-out service-authentication
challenge from the shared path's ability to carry high-definition video. It did
not prove that an exit address alone caused the challenge or that Firefox
itself is defective. The Mozilla case remains an analogy, not a Maverick
diagnosis, and provider termination of Maverick's outer TLS does not by itself
decrypt the inner browser-to-destination HTTPS connection.

The standing test-host policy is now Ubuntu 26.04 LTS first. Ubuntu 24.04 LTS
is accepted only as an explicitly justified fallback when 26.04 cannot perform
the test. Before Maverick starts, the host must apply every offered package and
default-kernel update, stop for a manual reboot whenever Ubuntu requires one,
and pass a post-reboot verifier. The owner superseded the earlier BBRv3 request:
the deployment default is now the stock Ubuntu kernel's native BBR
implementation (commonly called BBRv1), with no congestion-control A/B and no
custom BBRv3 kernel. The host's qdisc must be either `fq` or `fq_codel`.
Neither is preferred; an existing approved selection is preserved and every
other value is rejected.

The host gate validates the selected Ubuntu default-kernel package track,
declared `Origin: Ubuntu`, current package candidates, running image and module
ownership, and local package-checksum agreement before loading BBR. It then
persists `bbr` plus the host's existing approved qdisc and checks the available
and selected congestion control, default qdisc, and the first IPv4
default-route qdisc. Mainline
`tcp_bbr` normally publishes no numeric module-version field, so missing
version metadata is not mislabeled as an error or used as fake proof. An
explicitly declared version other than `1` is rejected to avoid silently
changing the requested baseline. These checks establish package provenance and
runtime state, not a formal proof of every algorithm detail.

BBR and the approved qdisc are server operating-system deployment settings, not
Maverick wire or YAML settings. They govern packets sent by that server; they
cannot make the owner's Mac, a provider edge, or a remote website use Linux
BBR. The `stable` mode is always H2/TCP; `auto` and `private` default to H2/TCP,
so all three normal carriers' server-sent halves can use the host's BBRv1 plus
`fq` or `fq_codel`. Explicit experimental H3/QUIC uses UDP and its userspace
congestion controller instead of TCP BBR, although its outgoing packets still
pass through the server queue. The server-sent half of all three modes'
server-to-target TCP connections continues to use the server TCP policy.

The repository-local gate passes formatting, strict workspace linting, all 492
Rust tests, the rustls compatibility build, both required loopback product
checks, and 78 isolated fake-host preparation checks. Those fake-host checks
exercise the stock BBRv1 path without numeric version metadata, rejection of
declared non-v1 or unavailable BBR, partial package-index updates, stale or
substituted kernel packages, unsafe configuration conflicts, incomplete
persistence, rollback, and reboot-required states. No real server, route,
qdisc, system proxy, DNS, VPN, or other host-network setting was changed by
this verification.

The final independent read-only review reported no P0, P1, or P2 finding; its
one P3 documentation precision finding was corrected before commit. The
required pull-request product gate and CodeQL checks, retained main-branch
product gate and CodeQL checks, and the single release workflow all passed
without a retry.

Both public archives and their checksum files were downloaded again. Their
outer checksums, inner `SHA256SUMS`, exact contents, source/version/target
metadata, executable modes, and privacy path scans passed. The remote tag
resolves to the reviewed merge commit, and the downloaded Apple Silicon binary
passed `version` and `user-smoke` locally.

At publication time, these results proved only release integrity, the reviewed
implementation, and local regression behavior. They did not then resolve the
major-video result, show stale-connection recovery after a real sleep/resume
event, prove that BBR improves field experience, justify a custom kernel, or
justify Beta. The later field result below supplies the missing Beta-entry
evidence without changing those narrower publication-time claims.

## Alpha.6 Fresh-Origin Beta Entry Result

One fresh owner-controlled temporary origin completed the from-scratch
deployment gate. All offered system and default-kernel updates were applied,
required reboots were completed, the host verifier passed, independently
verified Alpha.6 assets were deployed, and the origin and provider-fronted path
passed configuration, service, listener, TLS, fallback, edge, end-to-end SOCKS,
fail-closed, and post-test health checks.

On the spare owner-controlled macOS client, all five public artifact checks,
both product smoke checks, client configuration, and the SOCKS5 listener passed.
The first proxied page loaded 1 minute 44 seconds after the owner began the
guided run. Ordinary browsing was acceptable: control and search pages worked,
the previously affected news site and its embedded video worked, short-form
video played smoothly, and the lingering loading indicator was markedly
improved.

The major-video comparison then produced a narrower boundary. The current
Firefox profile, Firefox Troubleshoot Mode, and a clean Firefox profile all
reported `Video unavailable`; the clean profile's client-stop check proved that
it did not bypass Maverick. A new isolated Chrome profile also passed its
client-stop fail-closed check. While signed out, Chrome presented a
service-authentication challenge instead of ordinary playback. After the owner
authenticated inside that isolated temporary profile, the same test video
played smoothly at both 720p and 1080p, and seeking remained usable.
The planned player/media request-category Test E was not performed, so no
`403`, `429`, reset, timeout, or other request category was collected.

This establishes that the shared Maverick/provider-fronted path can carry the
service's high-definition video. It does not establish that the exit address is
the sole cause, that every data-center exit receives the same policy, or that
Firefox itself is defective. Exit reputation, service anti-abuse policy, and
browser/service interaction remain possible combined factors. No account
identifier, cookie, full URL, media hostname, or temporary profile path is
project evidence.

After the client slept for about 7 to 8 minutes, ordinary browsing and
short-form video resumed smoothly without a refresh. The fixed aggregate target
resolution and connection timeout/failure counters stayed at zero, the service
did not restart, and the retained journal contained no error, panic, or fatal
line. Aggregate H2 stream resets were observed, but without a target failure,
capacity stall, service restart, or matching user-visible failure they are not
by themselves evidence of a product defect.

The owner determined that this fresh-origin run satisfies the earlier
from-scratch installation, basic-browsing, applicable browser-diagnosis, and
sleep/resume gate and entered Maverick into the Beta development stage. The
result does not prove that BBR or the selected qdisc caused the improvement and
does not justify Stable, mature, production-ready, anonymity, broad
censorship-resistance, exact browser-equivalence, or provider-independent
claims.

## Historical Beta.2 Release Candidate Preparation

The source prepared for Draft PR #17 used `1.2.0-beta.2`. At that candidate
stage it was unmerged, untagged, and unpublished. This paragraph records that
past preparation only; the `Current Product Truth` above controls the present
fact that `v1.2.0-beta.2` is now the published and independently reverified Beta
prerelease. Repository-local tests, safe rejections, dependency checks, and
candidate-archive checks were quality controls, not a product or user result.

That candidate added `StoredClientProfile::stored_profile_schema_version` and
`StoredClientAuthProfile::channel_binding`. Downstream code using complete
struct literals or exhaustive field patterns for those public structs must be
updated. No public function signature or Serde trait implementation was
removed.

Stored profiles containing exactly the known Beta.1 flat JSON fields remain
readable, but migration requires the caller to choose a complete
channel-binding policy explicitly; the candidate did not infer the missing
legacy value. New writes use a schema-1 envelope that the Beta.1 reader rejects
instead of silently accepting with downgraded channel-binding metadata.
Canonical client and server YAML loading and top-level stored-profile JSON
loading now reject unknown mapping keys instead of ignoring them.
`FallbackConfig` is the explicit direct-generic-Serde exception: invalid or
unknown fields inside a fallback variant are now rejected, while the two legal
fallback shapes and their defaults are unchanged. A current stored profile
whose metadata is internally contradictory is reported as malformed and cannot
be serialized as a normal current envelope.

The candidate Rust packages used version `1.2.0-beta.2`. The Maverick protocol
version, config version, and stored-profile schema version remained `1`;
existing authentication and frame wire formats were unchanged.

## Beta.1 Release

The published GitHub prerelease is `v1.2.0-beta.1`, the first Beta prerelease.
It is neither a draft nor the repository's Latest release. Its Rust protocol
and config behavior are unchanged from the field-tested Alpha.6 build; protocol
and config versions remain `1`. The release combines the Beta-stage
documentation and version transition with the reviewed test-host persistence
correction described below.

The host gate now persists the already approved active `fq` or `fq_codel`
selection through a native `systemd-networkd` drop-in. It validates the
effective network file and its parent directory, creates no custom helper or
long-running service, and performs no live `tc` or `networkctl` mutation. A
reboot followed by `verify` remains the point at which the real default-route
qdisc must prove the persisted choice.

The scheduled parser-fuzz workflow no longer calls an archived script. It
checks both current fuzz binaries and runs the `frame_decode` and `auth_decode`
targets for 256 bounded iterations each with a pinned nightly compiler. The same
bounded run passes locally. The GitHub parser-fuzz, product, CodeQL, and
supply-chain checks passed on the final reviewed pull-request head. The merged
tree then passed the main-branch product and CodeQL checks.

The annotated `v1.2.0-beta.1` tag resolves to the reviewed merge commit. The
single release workflow re-ran the complete product gate, built the Apple
Silicon macOS and x86-64 Linux archives, verified their outer checksums, and
published exactly those two archives and their two checksum files. All four
public assets were then downloaded independently. Both checksum layers, exact
file lists, clean source revision, version, target, executable permissions, and
binary architectures passed verification. The downloaded Apple Silicon binary
also passed `version` and `user-smoke`, and the release assets passed the
private-string scan.

This release is still experimental prerelease software. It does not authorize
production deployment or support Stable, mature, anonymity, broad
censorship-resistance, exact browser-equivalence, native-ECH, or
provider-independent claims.

## Authorization Boundary

Repository-local work may build, test, and use `127.0.0.1` with OS-assigned
ephemeral ports. The following owner authorization applies only to the first
pilot and does not create standing authorization for later runs:

- person and client: the owner on one owner-controlled spare macOS laptop;
- client path: the privately identified, owner-controlled lawful restricted
  access network; a second access-network test is outside this run;
- duration and use: one 24-hour observation window, ordinary non-sensitive web
  use, and no recruited third party;
- client network changes: application-local proxy configuration only; no system
  proxy, DNS, route, firewall, VPN, interface, or network-service change;
- CDN trust: Cloudflare may terminate TLS for this run; the owner accepts that
  it can observe Maverick authentication information and tunnel traffic;
- CDN change scope: one new dedicated pilot hostname and DNS record, one
  seven-day origin certificate limited to that hostname, one hostname-only
  strict-origin TLS rule, and enablement of the zone's gRPC capability; do not
  modify existing DNS records or the zone-wide SSL mode;
- temporary CDN credential: at most one token expiring within 24 hours, limited
  to the selected zone and origin-certificate editing, with no DNS, account, or
  other-zone permission;
- Cloudflare spend: paid-product budget is `US$0`;
- origin: at most one small owner-controlled VPS, retained for at most seven
  days, with total pilot spend capped at `US$5`;
- excluded purchases: backups, additional disks, load balancers, and every
  other paid add-on; and
- stop rule: any additional resource, duration, person, network, trust change,
  or possible cost above these limits requires a new owner decision first.

The exact provider account or team, neutral resource name, region, containing
owner-controlled zone, dedicated pilot hostname, and access method were
confirmed privately. They remain private operational details and must not enter
the repository. No provider change beyond the envelope above is standing
authorization. No per-run hash approval is required.

The actual client run exceeded the authorized observation duration by 48 hours
18 minutes. This operational deviation does not erase the completed 24-hour
observation, does not count as a second pilot, and does not create broader or
standing authorization. The temporary origin remained inside the existing
seven-day retention and spending limits; no additional remote resource or paid
add-on was created.

The first pilot has ended and its temporary remote resources have been removed
after explicit owner approval. The temporary origin and dedicated provider DNS
record and hostname-only strict-origin rule were deleted, and the provider's
zone-wide gRPC capability was restored to its pre-pilot disabled state. The
zone-wide SSL mode was not changed, no unrelated provider setting was modified,
and the short-lived origin certificate may expire naturally.

The separately authorized `alpha.3` retest has also ended. Its dedicated
hostname-only strict-origin rule, dedicated DNS record, and single temporary
origin were deleted by exact resource identity. The provider's zone-wide gRPC
capability was restored to its disabled baseline. The existing ruleset
identities, unrelated DNS records observed immediately around cleanup, and
zone-wide SSL mode were unchanged by cleanup. The short-lived origin
certificate may expire naturally.

The separately authorized Alpha.6 repository publication is complete. The owner
has authorized continued privacy-safe repository-local development.

The separately authorized Alpha.5 owner retest has also ended. Its one temporary
origin, exact dedicated DNS record, hostname-only strict-origin rule, and
short-lived Origin CA certificate were removed or revoked by exact resource
identity. The zone-wide SSL mode and unrelated DNS records were not changed.
Under the owner's standing decision that the selected zone is dedicated to
Maverick testing, Cloudflare operations are API-first and the zone's gRPC
capability remains enabled instead of being repeatedly toggled between tests.
The dedicated hostname's hostname-only Full (strict) rule is a persistent test
setting rather than a per-run resource. A replacement origin updates the
dedicated DNS target and receives its own short-lived Origin CA certificate; a
retired origin's DNS target must not remain pointed at a released address.
Browser control is used only when the required capability has no documented
usable API. These standing operational settings do not authorize a new origin,
spend, provider change, or live-field run.

The first separately authorized Alpha.6 diagnostic origin passed package
integrity, local smoke, listener, and basic-connectivity checks, but its ordinary
browsing performance was too poor to support diagnosis. The observed major-video
failure is therefore inconclusive, not an Alpha.6 product failure.
Destination-free host measurements found no sustained resource exhaustion or
interface errors. After the diagnostic summaries were retained, that exact
origin was deleted with owner approval. One manually selected replacement
origin has now passed the ordinary host verifier: all offered package and
default-kernel updates were applied, required reboots were completed, stock
Ubuntu BBRv1 is active, and one of the two approved qdisc choices is both active
and persistent. The exact choice is not public project data, and this status
does not prefer `fq` or `fq_codel`.

The independently downloaded Alpha.6 release assets and their published and
inner checksums passed before deployment. The installed server passed
configuration validation, service, listener, direct TLS, static fallback,
fronting-provider edge, end-to-end SOCKS, client-stop fail-closed, and
post-test health checks. A new owner-only macOS handoff package was generated
outside the repository from the independently verified release asset and
passed its own checksum, configuration, version, and smoke checks. These
results first established deployment plumbing. The later owner field result
recorded above adds the ordinary-browsing baseline, browser comparison,
major-video boundary, and sleep/resume observation.

The owner separately authorized that exact manually selected replacement,
which has now passed both the ordinary-browsing baseline and host verifier, to
serve as a fixed reference origin for no more than 30 consecutive days from its
provider creation time. It may keep the origin-side address, operating system,
provider path, and host policy constant for any remaining authorized Beta
reference checks. It must not host unrelated work.
Before every authorized session, apply all offered package and default-kernel
updates, reboot when required, and pass the host verifier before Maverick
starts. Expiry, a failed baseline or verifier, unexplained configuration drift,
suspected compromise or credential exposure, or degraded routing or reputation
requires retirement and a new owner decision before replacement.

This authorization changes only the lifetime and diagnostic role of that one
replacement. It does not rewrite the completed first pilot's seven-day
boundary, authorize Codex to create the manually selected server, authorize a
second concurrent origin, a different provider or specification, paid add-ons,
unrelated users or networks, automatic renewal, production use, or a Stable
claim. The last exact total-spend ceiling remains `US$6`; stop before retention
could exceed it and obtain a new owner decision instead. The owner determined
that this same freshly provisioned clean replacement, its from-scratch
deployment, basic browsing, and applicable diagnostic checks satisfy the prior
Beta-entry requirement. Before Stable, fresh-origin validation must be repeated
for the Stable candidate. That requirement does not grant authority to create
a server.

The replacement's current origin certificate is deliberately short-lived and
does not authorize automatic renewal. If its validity cannot cover a later
authorized session, stop and obtain a separate owner decision before renewing
or replacing it. The replacement has passed the ordinary-browsing baseline and
is accepted as the fixed reference origin only within the recorded lifetime,
cost, certificate, person, network, and stop boundaries.

For the Alpha.6 reference trial, the owner also authorized and completed an
application-local comparison between a clean Firefox profile and one temporary
isolated Chrome profile. Chrome used its own new data directory, Maverick's
loopback-only SOCKS5 listener, no direct fallback, resolver containment, and a
client-stop fail-closed check. When the signed-out Chrome test surfaced a
service-authentication challenge, the owner chose to authenticate inside that
isolated temporary profile and the video played. This added authentication as
a test variable, so the result establishes path capability but does not by
itself attribute the Firefox presentation or the service policy to one cause.
No signed-in daily browser profile was reused. Safari and every macOS system
proxy, DNS, route, firewall, VPN, interface, or other network-service change
remained outside the comparison.

For future API-created Maverick test origins, the owner has established an
address gate: inspect the public IPv4 address before DNS, certificates, or
deployment; if its first octet is `64`, immediately delete that exact newly
created resource by provider ID and create a replacement within the same
approved team, region, specification, lifetime, and total-spend boundary. If
that boundary cannot produce a non-`64` address, stop and ask instead of
creating without limit. This is an owner-selected operational exclusion, not a
claim that the entire `64.0.0.0/8` network is technically defective. A server
the owner says they are creating manually remains on the separately
communicated manual path.

Beyond that one manual replacement, its approved 30-day reference trial, and
the completed browser-local comparison above, any new live-field run, remote
resource, provider change, spending, production or Stable claim, or native-ECH
implementation requires a new owner decision.
