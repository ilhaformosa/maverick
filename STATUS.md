# Maverick Status

Date: 2026-07-23

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
install path is not yet validated by a fresh user.

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

- Workspace version: `1.2.0-alpha.2`.
- Protocol version: `1` (unchanged).
- Config version: `1` (unchanged).
- Rust product core and loopback relay path: implemented.
- Browser-like TLS backend: default build path on supported targets.
- Generated client profile: browser-like TLS/H2 by default on supported targets.
- Handshake-hiding primary implementation: browser-like TLS over CDN-fronted H2
  is implemented and loopback-verified. The first live-provider deployment
  check exposed and fixed missing HTTP/2 scheme and authority metadata. After
  that fix, one authenticated end-to-end proxy request through the single
  temporary provider route succeeded from an operator-controlled setup machine.
  This is deployment-path validation only; it does not validate the spare-laptop
  install or the 24-hour restricted-network pilot. TLS exporter channel binding
  remains disabled across provider termination because the two TLS connections
  cannot share an exporter. The owner has accepted Cloudflare TLS termination
  only for this owner-only 24-hour pilot and understands that Cloudflare can
  observe Maverick authentication information and tunnel traffic. The older
  WebSocket carrier remains a rustls compatibility path.
- Local correct-credential relay and wrong-credential rejection: covered by
  `./scripts/user-smoke.sh`.
- Single-binary owner-pilot folder and shareable archive: generated locally by
  `./scripts/build-pilot.sh`; version tags publish equivalent GitHub prerelease
  assets for the supported pilot targets. Fresh-user timing remains untested.
- Timed-install artifact: `v1.2.0-alpha.2` or later. The earlier
  `v1.2.0-alpha.1` artifact is superseded because it lacks the live-provider H2
  request fix.
- Python coordination/validation tooling: frozen under `scripts/archive/python/`.
- Former remote/evidence shell orchestration: frozen under
  `scripts/archive/legacy/`.
- Non-current documents and machine-readable production ledgers: archived under
  `docs/archive/`.
- Real five-minute install by the owner on the spare laptop: not yet
  demonstrated.
- Owner-only, 24-hour real-network pilot: authorized and route-prepared, but not
  started.
- Owner-confirmed audit checkpoint (2026-07-21): the latest formal independent
  security audit of the then-current repository code completed with no open
  findings reported. This is a point-in-time result, not a warranty,
  certification, or claim that later changes inherit the same review.
- Future formal audits are optional and are not a pilot, release, or progress
  requirement. Open-source users remain responsible for deciding whether the
  software and its threat model fit their use.
- Production, anonymity, censorship-resistance, and exact browser-equivalence
  claims: not made.

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

The next legal actions are to publish the corrected prerelease, let the owner
perform the five-minute install attempt on the spare laptop, and, if that
succeeds, begin the 24-hour real-network pilot. Neither deployment-path
validation nor rehearsal counts as the North-Star Result.
