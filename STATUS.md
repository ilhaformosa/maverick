# Maverick Status

Date: 2026-07-21

This is the only active current-truth document. Archived plans, manifests,
evidence records, and release notes do not override it.

## Direction Decision

Phase 3 and every recovery alias are terminally retired. The incomplete result
remains `No-Go`; no product result was produced, no server is active, and no
lease or run is active. This user-first direction is a new product-learning
track, not an amendment, completion, or relabeling of Phase 3.

Progress now means:

> A real person uses the real product to complete a real task.

Passing tests, safe rejection, hashes, manifests, and evidence tooling are
quality controls. They do not count as product progress on their own.

## One-Page Pilot Strategy

### 1. Who is the first user?

The first user is the project owner on an owner-controlled desktop. No friend,
journalist, activist, or otherwise at-risk third party is recruited for the
first pilot. The task is ordinary web use through Maverick for one workday.

### 2. What is the first adversary?

The first adversary model is the access-network observer on the selected pilot
path. It may block endpoints using TLS metadata or traffic fingerprints and may
actively probe the public server. No claim is made about a named country,
firewall, or censorship system until the owner names a lawful pilot environment
and the test actually runs there.

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
2. the owner uses it for one normal workday on a named, lawful real-network path;
3. the default client uses the browser-like TLS/H2 path;
4. ordinary browsing works well enough to finish the day;
5. the record contains no Maverick-specific active-probe response and no
   observed block attributable to the tested Maverick fingerprint;
6. failures and unknowns are recorded plainly.

This result would still be one pilot, not proof of anonymity, broad
censorship resistance, production readiness, or browser identity.

## Current Product Truth

- Workspace version: `1.2.0-alpha.1`.
- Protocol version: `1` (unchanged).
- Config version: `1` (unchanged).
- Rust product core and loopback relay path: implemented.
- Browser-like TLS backend: default build path on supported targets.
- Generated client profile: browser-like TLS/H2 by default on supported targets.
- Handshake-hiding primary implementation: browser-like TLS over CDN-fronted H2
  is implemented and loopback-verified. TLS exporter channel binding is
  disabled across provider termination because the two TLS connections cannot
  share an exporter. A real provider path and its trust decision remain
  unvalidated; the older WebSocket carrier remains a rustls compatibility path.
- Local correct-credential relay and wrong-credential rejection: covered by
  `./scripts/user-smoke.sh`.
- Single-binary owner-pilot folder and shareable archive: generated locally by
  `./scripts/build-pilot.sh`; version tags publish equivalent GitHub prerelease
  assets for the supported pilot targets. Fresh-user timing remains untested.
- Python coordination/validation tooling: frozen under `scripts/archive/python/`.
- Former remote/evidence shell orchestration: frozen under
  `scripts/archive/legacy/`.
- Non-current documents and machine-readable production ledgers: archived under
  `docs/archive/`.
- Real five-minute install by a fresh user: not yet demonstrated.
- One-person, one-day real-network pilot: not started.
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
ephemeral ports. Nothing in this status authorizes provider access, spending,
SSH, a public endpoint, contacting another person, or changing any machine's
system proxy, DNS, routes, firewall, VPN, or network services.

The first envelope already fixes the pilot person as the owner, the duration as
one normal workday, and allowed network changes as application-local proxy
configuration only. The owner still must name the lawful client environment,
accept or reject TLS termination at the proposed Cloudflare edge, and set the
maximum spend for the owner-controlled origin. It must not require per-run hash
approval. Until those three decisions exist, the legal next actions are local
artifact work and local verification only.
