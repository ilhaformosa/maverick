# Maverick Status

Date: 2026-10-27

This is Maverick's only active current-truth document. It answers what exists,
what is safe to claim, what is blocked, and what currently needs owner
participation. `ROADMAP.md` controls execution order. Git history, pull
requests, Actions runs, releases, archived documents, and the retired recovery
playbook preserve detail without becoming parallel status ledgers.

## At a Glance

| Area | Current truth |
|---|---|
| Development stage | **Beta**; experimental and not production-ready |
| Published release | Immutable `v1.2.0-rc.2` prerelease; not Latest; Beta.4 remains the fixed rollback partner |
| Dependency maintenance | Included in published RC.2; earlier immutable releases remain unchanged |
| Supported product route | Direct browser-like TLS 1.3 + HTTP/2 |
| Provider-fronted route | Implemented and Beta; not part of the first Stable support claim |
| H3/UDP product | Default-off; local authenticated H3/TCP proxy experiment only; no CLI/Auto H3 path or native Datagram |
| Future H3 direction | quiche only, subject to later qualification; Quinn product code is retired |
| Protocol/config/profile schema | Version `1`; existing authentication and frame wire formats unchanged |
| Current milestone | Local SOCKS → H3 → authenticated server → TCP forwarding implemented; owner field validation deferred |
| Stable readiness | **RED / owner-deferred**; exact-RC field use and owner rollback remain incomplete |

Progress means a real user-visible result. Tests, hashes, policy documents, and
candidate experiments are quality controls, not product progress by themselves.

## Product That Exists

- The Rust core, client, server, CLI, SDK, loopback integration suite, local
  configuration generator, and release-artifact tooling are implemented.
- The default supported route uses browser-like TLS 1.3 and HTTP/2. Local
  `user-smoke` proves that a correct credential relays data and a wrong
  credential does not establish a proxy flow.
- The provider-fronted H2 workaround has carried an owner-only field pilot. It
  is not native ECH or provider-independent privacy. The provider terminates
  TLS and can observe authentication information and tunnel traffic.
- The older WebSocket carrier remains a compatibility path.
- `v1.2.0-beta.4` is the earlier public prerelease and fixed rollback partner.
  Its Apple Silicon and x86-64 Linux archives, checksums, and target-aware SBOMs
  were published and independently reverified.
- The owner completed a fresh-origin install and an owner-only real-network
  observation. The install path beat five minutes in later trials, and the
  observation ran for 72 hours 18 minutes. This is one pilot, not proof of
  anonymity, maturity, broad censorship resistance, or universal reliability.
- The 2026-07-21 independent security audit reported no open findings for its
  exact historical revision. Later revisions and a future RC require their own
  review and do not inherit that result.

## Claims Maverick Does Not Make

Maverick does not claim production readiness, anonymity, exact browser
fingerprint equivalence, provider independence, native ECH, native QUIC
Datagram support, broad censorship resistance, or safe use by at-risk third
parties. Beta.4 and its field evidence do not automatically qualify a later RC.

## RC.2 Dependency Security Maintenance

The current source resolves RUSTSEC-2026-0346 through RUSTSEC-2026-0349,
RUSTSEC-2026-0381, RUSTSEC-2026-0382, and the RUSTSEC-2026-0386 soundness warning
with rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots 1.0.10, and Tokio
1.53.3. Direct dependency minimums exclude the older affected versions;
rustls-webpki is fixed in the product lockfile. The isolated H3 proxy fixture also resolves fixed versions of these
dependencies. No advisory is ignored or suppressed.

The default browser TLS certificate decompressor also had the large-window
behavior described by RUSTSEC-2026-0348. It now uses strict RFC 7932 decoding,
retains the caller's output bound, and rejects incomplete or trailing data.
Four focused regression tests pass; the large-window rejection test failed
against the old callback. The Linux-only TUN test harness uses Tokio's explicit
registration API with the existing owned-file lifetime preserved.

Browser TLS also applies the eight compromised public keys from the locked
WebPKI distrust set to its verified certificate chain, including trusted
anchors and leaf certificates. Existing CA, signature, validity, and hostname
failures remain failures; platform and custom trust stores are not modified.
Version detection and migration preview no longer reject non-finite-looking
text before a declared string field is read. Numeric/version validation and
finite resource-ratio checks remain enforced. The release note records the
other YAML acceptance changes introduced since RC.1.

`security-dependency-inventory.sh`, `user-smoke.sh`, `local-harness.sh`, and the
supported no-default CLI/SDK/test-target build pass locally. The modified Linux
registration module passes a Linux-target Clippy check; no TUN device was run.
The complete no-default relay suite now passes 62 of 62 tests. The private-mode
success test is restricted to its required browser-TLS build, and both build
variants explicitly test rejection of a private client using the rustls
fingerprint. The configuration safety rule is unchanged; CI now runs the
complete no-default relay suite instead of only two selected tests.

These fixes are included in the immutable public RC.2 artifacts. Earlier
releases do not acquire the fixes retroactively. No field or Stable result
follows from publication. The owner has
authorized completing the compatibility fix, repository integration, and the
subsequent release work autonomously. This does not authorize a field task,
provider resource, spending, or changes to this machine's network settings.

## Completed Release: Direct-H2 RC.2

The Direct-H2-only `v1.2.0-rc.2` prerelease is published, containing the
maintenance above and the configuration-parser changes merged after RC.1. The immutable RC.1 release remains historical evidence for its own
commit and bytes; it cannot qualify the changed RC.2 source or dependencies.
H3 product adoption, native Datagram, auth v3, runnable Config v2, Auto H3,
TUN migration, and new provider work remain paused.

RC.2 passed its local/public checks, independent source/file review,
Apple/Linux artifact and SBOM verification, and native Beta.4 rollback drills.
The recorded publication decision was **GO** for commit
`966d29966d05287bc2eef6401c6297582db605f6` and the six files from attempt-1
main qualification run `40364048961` only. Linux artifact `12669763505` has
ZIP SHA-256 `d66104ddca1cd978c70b28d53eb1934747b7dda9fa57e66f3d64083b485276ee`;
macOS artifact `12669659863` has ZIP SHA-256
`f7e096a840642fcdfc7e15e5dd70111a8945d3ab4ca192ad4e6e00172d8c0d1b`.
The source note and exact files were independently reviewed, and downloaded
copies were reverified locally. Only the release-page CONFIG link was changed
from relative to the same destination at the immutable RC.2 tag; the reviewed
source note and all artifact bytes are unchanged.
Attempt-1 release run `40369570802` published immutable Release
`v1.2.0-rc.2` as prerelease/non-Latest. All six public files were downloaded
and matched the independently reviewed files byte for byte. The description
link normalization was read back and verified as the only description change.
The owner explicitly deferred field validation on 2026-10-27. Stable therefore
remains blocked; no deployment or field result is claimed.

### RC/Stable Gate Board

This board concerns RC.2 only. RC.1's prior qualification is not carried over.

| Gate | State |
|---|---|
| Exact RC commit, package version, release note, and candidate scope | **GREEN — `966d299`, package/note `1.2.0-rc.2`, and Direct-H2 scope agree** |
| Direct-H2-only route and v1 compatibility matrix | **GREEN — 65 default and 62 rustls relay tests plus both native artifact drills pass** |
| Local `user-smoke` and `local-harness` on exact candidate | **GREEN on the RC.2 candidate source** |
| Dependency, advisory, license, source, and first-party `unsafe` review | **GREEN locally — fresh advisory/policy checks pass for 307 locked dependencies with no advisory exceptions** |
| Apple/Linux archives, checksums, native/static verification, and SBOMs | **GREEN — exact main-run artifacts above; independent file checks pass; runtime SBOMs contain 184 Linux / 182 macOS components** |
| Exact-head public CI and CodeQL | **GREEN — attempt-1 main runs `40364048961` and `40364047199`; PR supply-chain run `40360237756` and fresh local main inventory also pass** |
| Independent exact-RC security review; no unresolved Critical/High | **GREEN — exact-source and exact-file review approved; all reported candidate issues closed** |
| Fresh-origin Direct-H2 field run and 72-hour owner use | **DEFERRED by owner on 2026-10-27 — not performed** |
| Native RC-to-Beta.4 rollback on Apple Silicon and x86-64 Linux | **GREEN for qualification — native Apple/Linux RC.2 drills pass; owner field rollback is deferred** |
| RC.2 prerelease/non-Latest publication | **GREEN — immutable RC.2 published by run `40369570802`; all six public assets match the reviewed bytes** |
| Stable publication and Latest classification | **BLOCKED** |

The full release safety contract remains
`docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`. It is a gate reference, not a second
roadmap.

## Completed Recovery and Architecture Decisions

- The v1.3 cumulative experiment was preserved through immutable archive refs,
  a one-time merge inventory, an exact-head Draft CI baseline, and an accepted
  convergence decision. The 77-commit experimental tree was not merged as a
  giant product change.
- Phase 3 and every renamed recovery/certification continuation are retired.
- Config-v1 experimental Quinn H3 fails closed, and the unpublished
  Quinn/hyperium-H3 product implementation and dependencies were removed.
- quiche is the only possible future H3/UDP product direction. This is a
  direction decision, not adoption evidence.
- The Datagram semantic contract is accepted. A private fake-adapter prototype
  deterministically proved that receive can progress while send remains
  blocked, with bounded cleanup. No public Datagram API, consumer migration,
  CONNECT-UDP, native QUIC Datagram, or product result follows from that proof.
- Release tag and artifact verifiers accept canonical positive Beta/RC inputs
  while deliberately rejecting Stable. They do not create an RC candidate or
  authorize publication.

## Incomplete Backend Qualification

### B-001 — quiche qualification

**RED.** The neutral local-only observation contract and bounded parser exist,
but equal quiche and Chrome adapters do not. No complete TLS/QUIC/H3,
fingerprint, weak-network, exporter, CONNECT, Datagram, maintenance, platform,
or supply-chain comparison exists. A failed qualification leaves H3 disabled.

### B-002 — old quiche patch dispositions

**PARTIAL / RED.** Historical source reconstruction, the byte-only verifier,
the candidate dependency boundary, Linux/macOS candidate tests, logging tests,
and one narrow peer-push patch candidate were completed. They are candidate
evidence only.

P1, P2, and P3 remain `UNRESOLVED`. Missing work includes selected-candidate
dispositions, replay, upstream route or a still-valid exception where
required, exact product-shaped qualification, shared-Boring security review,
supported-target product closure/SBOM/final artifact evidence, security-update
response proof, and independent final-delta review. No private quiche patch or
runtime may enter the product until the applicable fork budget passes.

### Bounded local quiche experiment

`backend-capture-lab quiche-loopback`, built with the default-off
`quiche-candidate` feature, now makes a certificate- and hostname-validated
connection and exchanges one complete H3 POST/response over real loopback UDP.
The bodies contain 25 request bytes and 26 response bytes. Both endpoints use
OS-assigned ports, fixed packet/stream/body limits, and a five-second network
deadline. The server receives the clean H3 close before both connections,
sockets, and temporary owner-only credentials are released.

Four focused tests pass locally: the valid exchange, wrong trust anchor,
wrong hostname, and expired deadline. They check socket and temporary-file
release on success and failure. The existing in-memory candidate tests remain
separate. The executable uses pristine quiche 0.29.3 and the existing single
Boring 5.1.0 closure, without a private patch or dependency change. Both native
CI jobs run the focused tests and executable. The normal CLI still has no
quiche dependency; an ordinary lab build rejects this command before setup.

### Upstream TLS and authentication integration

The isolated `crates/maverick-tests/fixtures/quiche-tls-auth` package verifies
the maintained upstream TLS API with quiche 0.30.0, boring 5.2.0, and one
boring-sys 5.3.0 native dependency. It uses `with_boring_ssl_ctx_builder` and
`SslRef` directly, with no private TLS bridge, Cargo patch, or first-party
unsafe code. Its own lockfile leaves the shipping H2 dependencies and the
earlier 0.29.3 candidate unchanged.

The fixture compiles the actual client TLS settings and certificate distrust
callback, and reuses the existing UDP loopback driver. The H2 settings and
strict Brotli decoder were moved into a private shared module without changing
their values or behavior. Both endpoints derive the existing TLS exporter
binding and exchange the existing authentication v1/v2 Hello encodings over
H3. Valid authentication succeeds; wrong credentials, either peer omitting
required binding, and client or server authentication bound to another TLS
connection are rejected.
Untrusted certificates, wrong hostnames, and a rejecting verification callback
also fail the handshake.

The original 21 TLS/authentication tests remain covered. Browser fingerprint
equivalence is not established by these tests.

### Local authenticated H3 TCP proxy

The isolated package now has an explicit `proxy` feature and an executable
`h3-proxy-smoke`. It connects a real local SOCKS5 client through H3 over UDP to
the actual Maverick server credential lookup, authentication v1/v2, replay
cache, connection/admission limits, per-user flow policy, and target connector.
The client reuses its normal credential selection, Hello validation, OpenTcp,
and SOCKS relay. The server's optional H3 session handles TCP frames with the
existing egress policy, rate limiter, padding, and cover-traffic settings.

One H3 request carries one TCP flow. Bounded frame channels and partial H3
writes permit transfers larger than the 8 KiB stream window. Eleven focused
tests include 512 KiB each way for auth v1 and v2, a response after client
half-close, credential and disabled-user rejection, epoch and required-binding
checks, shared replay detection, per-user concurrent-flow rejection, and egress
rejection before contacting the origin. The local executable exercises both
positive flows. TLS fixtures and sockets are released when the run ends.

Integration also exposed a client negotiation mismatch: `channel_binding.require`
was not enforced on the received ServerHello. The shared client handshake now
rejects an unbound reply when binding is required, for both authentication
versions; optional binding remains compatible. This applies to H2/WS as well.

All new endpoints require the default-off `experimental-h3` Cargo feature.
The actual quiche driver remains in the isolated package, using the upstream
Boring integration and one native Boring dependency. The shipping dependency
versions, CLI transport selector, config-v1 H3 rejection, and default H2 route
remain unchanged. Both native CI jobs run the proxy tests and smoke.

Local verification passes: the 32 isolated TLS/proxy tests, executable smoke,
workspace Clippy with and without the opt-in endpoints, `local-harness`
(including the H2 product smoke), the 62-test rustls relay suite, and dependency
advisory/license/source checks. Three pre-existing workspace tests remain
explicitly ignored; no new test is ignored.

**Product adoption remains NO-GO.** This is a working local TCP proxy slice,
not a deployable H3 listener, multiplexed connection pool, UDP carrier, Auto
route, or public release. B-001/B-002 and P1/P2/P3 still need dispositions for
the concrete upstream carrier before adoption. Field work remains deferred.

## Execution Model

- Exactly one primary user-visible milestone may be active.
- One observable outcome normally uses one PR containing implementation,
  focused tests, and any needed STATUS/ROADMAP update.
- A separate authorization PR or post-merge truth PR is not required for
  ordinary reversible work.
- Verification is proportional to risk:
  - documentation-only: diff and privacy checks;
  - ordinary product change: focused tests, `user-smoke`, and public CI;
  - auth, wire, config, dependency, release, or rollback boundary:
    `local-harness`, independent review, and the applicable exact-candidate
    gate.
- Exact hashes and multi-host supply-chain proofs are reserved for releases,
  vendored/upstream source, dependencies, security-sensitive evidence, and
  artifacts where byte identity matters.
- If work takes more than three days without a runnable result, creates more
  than three prerequisite tasks, needs a new coordination framework, or
  produces more management machinery than product value, stop and either
  shrink or defer it.

## Safety and Privacy Boundaries

- Never change this Mac's system proxy, DNS, routes, firewall, VPN, or network
  interfaces. Local work uses `127.0.0.1` and OS-assigned ephemeral ports.
- Never commit real endpoints, credentials, private paths, identities,
  infrastructure names, packet captures, key logs, or environment-specific
  output.
- Authentication, trust-route, target admission, resource budgets, and failure
  behavior remain fail closed. No failure may silently retry, replay, dual-send,
  cross a trust route, or move partial application data to another carrier.
- No queue, task, socket, target map, or association may be unbounded.
- A release, real-network task, provider resource, paid action, destructive
  cleanup, or Stable claim requires its own exact prerequisites and recorded
  go/no-go decision.

## Authorization and Owner Participation

The owner has delegated ordinary technical prioritization and repository-local
execution to Codex. That delegation does not turn missing evidence green or
authorize network-setting changes, spending, destructive actions, or personal
attestations. The owner's latest instruction delegates completion of the
security fixes, compatibility-test repair, commits, pushes, integration, and
release decisions.
Codex has selected RC.2 as the narrowly scoped maintenance candidate. That
authorization permits prerelease/non-Latest publication only after the exact
candidate gates pass and the final go/no-go is recorded. It does not authorize
Stable/Latest, a provider resource, spending, or a field task.

Local RC preparation and publication are complete. The owner has explicitly
deferred the exact-RC install, ordinary-use/72-hour field task, and field
rollback experience. Autonomous work may continue on the bounded local
development; resuming field use still requires the owner and a named authorized
environment. Personal or legal attestations remain the owner's responsibility. If a new
paid/provider resource is actually required, the exact team, resource, region,
lifetime, cost cap, and cleanup must be confirmed before creation or
modification. Full-access provider tokens stay in macOS Keychain and are never
printed or stored in repository configuration.

## Evidence and History

Detailed historical timelines belong to Git commits, merged pull requests,
GitHub Actions, release records, and `docs/archive/`. They are not copied into
this file. When current truth changes, update the affected paragraph in the
same PR instead of appending another chronological evidence block.
