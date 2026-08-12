# Maverick Status

Date: 2026-08-12

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
- Workspace source, current published Beta prerelease, and last independently
  reverified public artifact: `v1.2.0-beta.4`. PR #27 merged the reviewed
  candidate as main commit
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
- H3/UDP backend direction (owner decision, 2026-08-12): Maverick will not build
  a Quinn product path. The single intended H3/UDP product backend is quiche.
  Current main's unpublished Quinn feature is retained temporarily only to
  extract backend-neutral semantic and test oracles; immutable archives
  preserve its permanent history, and current-main Quinn code is then removed
  in a separate reversible slice. This supersedes the conditional B-003
  choice in the convergence ADR without making quiche usable or ready. B-001
  still must qualify quiche against the neutral Chrome reference and the fixed
  objective matrix, and B-002 remains **RED**: the preserved fork has no
  passing patch dispositions, required upstream routes or still-valid written
  cannot-upstream exceptions, clean rebase/replay proof, demonstrated
  security-update SLA response, or independent delta
  review. No private fork or delta may be restored until the complete fork
  budget passes. A pure-upstream quiche
  candidate may omit all three old private patches only after an evidence-backed
  `DROP / not required` disposition and dependency, security, and SBOM gates
  pass. H3 product runtime and native Datagram claims remain blocked in either
  case by their other objective gates. A failed qualification leaves product H3
  disabled; it does not revive Quinn. The two unpublished Quinn-specific
  work-in-progress slices for B-001 relay qualification and D-004 adaptation
  are stopped and must not be committed. This decision does not change v1.2
  Direct H2, does not place H3 in Auto, and does not count reliable H3 DATA
  framing as native UDP.
- QRET-1 is merged current truth at `main` commit
  `be5f3ae532037468edbb1d619731a223284164c5` (2026-08-13):
  `advanced.experimental_h3=true` fails closed with the fixed root error
  `advanced.experimental_h3=true is retired for config version 1` before DNS,
  bind, file or referenced secret-store reads, local I/O, fallback, or cooldown
  work. The field,
  default/explicit `false`, Serde/URI/SDK shapes, and H2 behavior and bytes stay
  unchanged. Direct public legacy H3 connection is also retired. Quinn code,
  dependencies, and its local loopback test remain temporarily as a test-only
  oracle for QRET-2; this slice adds no quiche runtime, Product Config v2, Auto
  H3, wire change, or UDP product claim. Retired Quinn product tests duplicated
  existing H2 relay, padding, auth, malformed/replay, DNS, SOCKS UDP, and
  concurrency semantics; the one Quinn reverse-proxy available-body detail
  remains an immutable-archive semantic oracle until it can be re-expressed
  backend-neutrally.
- B-002-S1 document-only policy contract: it assigns explicit
  protocol-safety, privacy-logging, and dependency-security responsibilities;
  freezes patch-specific `DROP`/`RETAIN`, upstream/rebase, and fail-closed H3
  rules; and records the S1 point-in-time observation that an official quiche
  0.29.3 archive matched its public checksum, upstream revision, and license
  hash. The replay
  contract now requires reviewed fixed task-specific verifier constants, a
  repository-external `0700` temporary workspace, byte-only non-executing
  reconstruction, and separate
  historical patched-source reconstruction, separate curated-delta byte
  accounting, and selected-candidate runs followed by exact-hash
  qualification. Unclassified advisories fail closed as Critical, and ordinary
  releases require a decision within 14 calendar days. Any policy disable event
  — including unknown/Critical/High risk, an ordinary-release decision miss,
  Medium/Low overdue point, exception expiry, or any required-gate invalidation
  — rejects new H3 work, invalidates idle pools and resumption, and terminates
  affected existing H3 carriers without sending or replaying application data
  to H2. This is **PARTIAL / RED** policy evidence
  only. No patch was applied or resolved, no upstream contact or independent
  delta review occurred, and the official package's Boring 4.x requirement is
  still incompatible with the required proof of one Boring 5.x closure for the
  real H3 product feature, dependency/link graph, target SBOM, and final
  artifact on both supported release targets. A shared-Boring risk must open a
  separate Train A exact-candidate H2 impact gate; this slice neither changes H2
  nor exempts it. B-002, quiche adoption, H3 runtime, security, supply-chain,
  product, release, and real-network gates remain RED.
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
- A new paid third-party formal audit remains optional. The owner-approved
  v1.2 RC/Stable contract instead requires an independent security review bound
  to the exact RC, supply-chain checks, and no unresolved Critical or High
  finding. Neither the 2026-07-21 audit nor Beta.4 field/artifact evidence is
  inherited by a later RC. Open-source users remain responsible for deciding
  whether the software and its threat model fit their use.
- v1.2 RC/Stable release policy (owner-approved 2026-08-12): the first Stable
  support claim is Direct H2 only, while provider-fronted H2 remains Beta. RC
  must be a prerelease and non-Latest; Stable must be a non-prerelease and
  Latest. Immutable `v1.2.0-beta.4` is the exact rollback partner. The full
  contract and still-closed gates are recorded in
  `docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`. This policy does not make an RC or
  Stable candidate exist. RLC-001b is merged as bounded repository tooling; it
  does not authorize a tag, publication, a field run, a server, spending, a paid
  audit, or a Stable claim.
- RLC-001 is merged current truth at `main` commit
  `9423bff57818da199c9b1141edfeb89e03c801a1`. The release-tag verifier accepts
  only canonical positive `v1.2.0-beta.N` and `v1.2.0-rc.N` annotated tags while
  retaining Stable, Alpha, other version-line, zero/leading-zero sequence,
  tag-shape, exact-SHA, ancestry, and missing-history rejection. This replaces
  the stale pre-merge candidate wording and completes only the bounded
  tag-verifier slice; it did not create or authorize an RC tag, artifact, or
  publication.
- RLC-001b is merged current truth at `main` commit
  `7632d86361a7ddc74884d224e6ce5c6706a2ee78` (2026-08-12). Its deterministic
  RED used an otherwise-valid `1.2.0-rc.1` archive whose filename, source
  metadata, version metadata, inner and outer digests, target, architecture,
  and native binary output agreed, and the former Beta-only artifact-version
  gate rejected it. The merged verifier accepts only canonical positive
  `1.2.0-beta.N` and `1.2.0-rc.N` artifact versions and keeps Stable, Alpha,
  foreign version lines, zero, and leading-zero sequences fail-closed. It
  statically locks the unchanged publication workflow's prerelease/non-Latest
  classification and final tag, six-file, checksum, digest, and release-note
  rechecks before its sole release-create command. Static and current-host
  native RC-fixture verification, independent exact-hash and privacy review,
  exact-head public checks, and merge passed for this bounded tool only. No
  exact-RC package version, release note, archive, SBOM, tag, or publication
  input exists; candidate preparation, security, supply-chain, compatibility,
  Beta.4 rollback, field, artifact, and publication gates remain RED.
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
`fq` or `fq_codel`. Config-v1 H3 has no host-policy exception: its retired flag
fails before any QUIC/UDP socket or H3-to-H2 fallback. DNS and SOCKS UDP relay
remain separate inner functions, not H3 or native-Datagram evidence. The
server-sent half of all three modes'
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

On 2026-08-12, the owner authorized strict execution of the dated Maverick
v1.3 recovery playbook, ratified OD-01 through OD-09, approved v1.2 release
decisions R1 through R4, and then delegated every remaining project and task
decision in this thread to Codex. Codex must use the playbook's recommended
option when one exists; otherwise it must choose the smallest safe,
failure-driven option and record the decision and reason. A further owner
selection or approval is not required. This standing delegation covers placing
the remaining playbook work into the `ROADMAP.md` queue and its ordinary local,
public-repository, review, and required public-CI workflow. RLC-001 and RLC-001b
are merged; future v1.2 work follows the current `ROADMAP.md` and its exact task
gates rather than inheriting authorization from either tool slice.

The delegation is decision authority, not evidence. It does not turn a RED or
UNKNOWN gate green, inherit evidence from another commit or route, waive
independent review or privacy checks, or override the non-negotiable host-network
boundary in `AGENTS.md`. Codex may approve a later release, field run, provider
resource, paid action, or destructive cleanup only after the exact task,
target, objective prerequisites, cost/lifetime cap, and rollback or cleanup are
recorded and independently checkable; uncertainty defaults to no action. A step
that requires the owner to physically use a device, supply unavailable access,
or make a legal/personal attestation will be reported as required participation,
not returned as a technical project decision.

The same authorization covered the one-time remote recovery controls now
completed: protect and create the five exact `archive/v1.3-*` branches, open one
exact-head Draft `DO NOT MERGE` baseline PR, let its normal checks run once,
record the results, and close it without a rerun. It does not authorize changing
an archive ref, synchronizing or merging the cumulative 77-commit branch,
silently bypassing a failed gate, or treating governance evidence as a product
result. A rebuilt small PR may merge only after its own task gates, independent
review, and privacy gate pass. The owner has now fixed quiche as the sole H3/UDP
backend direction, but product adoption, config/wire/public-API changes, tags,
releases, field runs, provider resources, paid audits, spending, and destructive
actions remain separate recorded tasks with their own objective gates. They no
longer require another owner choice, but they are not authorized merely because
a direction or an earlier task completed. Host-network changes remain prohibited
by `AGENTS.md`.

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
  or possible cost above these limits requires a new separately recorded Codex
  go/no-go decision under the standing delegation above, with exact boundaries
  and cleanup; it is not inherited from this first-pilot authorization.

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
requires retirement. A replacement requires a separate recorded Codex go/no-go
decision with an exact target, need, lifetime, cost cap, and cleanup plan.

This authorization changes only the lifetime and diagnostic role of that one
replacement. It does not rewrite the completed first pilot's seven-day
boundary, authorize Codex to create the manually selected server, authorize a
second concurrent origin, a different provider or specification, paid add-ons,
unrelated users or networks, automatic renewal, production use, or a Stable
claim. The last exact total-spend ceiling remains `US$6`; stop before retention
could exceed it and record a new bounded Codex go/no-go decision instead. The
owner determined that this same freshly provisioned clean replacement, its
from-scratch deployment, basic browsing, and applicable diagnostic checks satisfy the prior
Beta-entry requirement. Before Stable, fresh-origin validation must be repeated
for the Stable candidate. That requirement does not grant authority to create
a server.

The replacement's current origin certificate is deliberately short-lived and
does not authorize automatic renewal. If its validity cannot cover a later
authorized session, stop and record a separate Codex go/no-go decision with the
exact hostname, validity, access, cost, and revocation or expiry plan before
renewing or replacing it. The replacement has passed the ordinary-browsing
baseline and is accepted as the fixed reference origin only within the recorded
lifetime, cost, certificate, person, network, and stop boundaries.

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
implementation is a new task. It requires a separate recorded Codex go/no-go
decision under the standing delegation, after its exact objective prerequisites,
scope, target, privacy boundary, cost/lifetime cap, and cleanup are checkable.
