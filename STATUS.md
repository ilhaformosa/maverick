# Maverick Status

Date: 2026-07-26

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
install path was attempted by the owner from the published prerelease. The
first successful proxied page load occurred after 5 minutes 18 seconds, so the
path worked but missed the strict target by 18 seconds.

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

- Workspace version: `1.2.0-alpha.3`.
- Protocol version: `1` (unchanged).
- Config version: `1` (unchanged).
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
  page in 5 minutes 18 seconds.
- First timed-install artifact: `v1.2.0-alpha.2`. The earlier
  `v1.2.0-alpha.1` artifact is superseded because it lacks the live-provider H2
  request fix. The shorter `alpha.3` fast-start path has passed local checks but
  has not yet been timed by a person.
- Python coordination/validation tooling: frozen under `scripts/archive/python/`.
- Former remote/evidence shell orchestration: frozen under
  `scripts/archive/legacy/`.
- Non-current documents and machine-readable production ledgers: archived under
  `docs/archive/`.
- Real install by the owner on the spare laptop: demonstrated, but the strict
  five-minute target was missed by 18 seconds.
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
- Production, anonymity, censorship-resistance, and exact browser-equivalence
  claims: not made.

## First Pilot Result

General web browsing was smooth during the owner-only real-network pilot.
Three usability exceptions remain open:

- one major video service loaded its interface and supported most non-playback
  actions, but video playback did not work;
- some images on one news site loaded extremely slowly or appeared not to
  finish; and
- during weaker connectivity, some pages continued to show an active loading
  indicator after their visible content appeared complete.

These are observed symptoms, not established causes. Current evidence does not
show whether they came from provider TLS termination, Maverick's H2 carrier,
the destination services, browser behavior, or the underlying network.
Reconciled server-side service logs show authenticated activity across the run
without a service restart or error-like line in the retained journal, but those
logs are not detailed enough to diagnose the three symptoms. All three
observations came from the Firefox instance configured to use Maverick; Chrome
was not used during the pilot.

The planned 24-hour observation remains valid product evidence. The North-Star
milestone did not pass because the timed setup exceeded five minutes by 18
seconds, and the usability findings above remain unresolved. The result does
not support production, anonymity, broad censorship-resistance, or exact
browser-equivalence claims.

## Alpha.3 Reliability Hardening

The `1.2.0-alpha.3` workspace is a locally verified hardening candidate, not a
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

This proves the reproduced code defects are fixed locally. It does not prove
that video playback, slow images, or the lingering Firefox loading indicator
are fixed in a real provider path. It also does not prove that the shorter
install path beats five minutes for a person. Those questions require a later,
separately authorized owner retest using a published `alpha.3` artifact.

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

The next legal actions are privacy-safe local diagnosis of the observed setup
and usability failures. Any new live-field run, remote resource, provider
change, spending, or native-ECH implementation requires a new owner decision.
