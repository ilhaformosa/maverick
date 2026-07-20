# Handshake And Fallback Architecture Decision

Status: accepted post-v1 decision. M6 long-haul, impairment, and failure
evidence closed without changing the comparison or its assumptions. This
document does not authorize a runtime handshake change.

## Decision

Maverick will use three clearly separated tracks:

1. Keep direct TLS 1.3 plus H2 with application-layer fallback as the mandatory
   v1.x compatibility path and ordinary default.
2. Keep CDN-fronted WebSocket as an explicit, default-off deployment option
   that fully trusts the TLS-terminating provider.
3. Study handshake-layer forwarding or a REALITY/ShadowTLS-like split only as
   an isolated v2 research track. Do not merge it into v1.x and do not replace
   the current default until its security, compatibility, and operational gates
   pass.

This is a sequencing decision, not a claim that application fallback is
perfectly indistinguishable or that a future handshake-layer design will be
safe.

## Context

The current default path has several useful properties:

- TLS 1.3 and H2 use normal certificate validation;
- Auth v1/v2, replay protection, resource bounds, and fallback behavior are
  implemented and tested;
- direct rustls and browser-TLS H2 can bind authentication to TLS exporter
  material;
- one runtime-scoped H2 connection can carry multiple request streams without
  changing the frozen frame or authentication formats;
- active-probe tests compare 13 deterministic response shapes;
- the H2/TLS path has local, failure-injection, and approved-host evidence.

It also has known limits:

- the server still terminates its own recognizable TLS stack;
- browser-TLS evidence still differs from the pinned browser on ALPS and newer
  signature algorithms;
- application fallback can reduce protocol-specific responses but cannot make
  TLS, timing, admission behavior, and every origin behavior identical;
- the explicit CDN path changes the trust model because the provider
  terminates client-facing TLS;
- current evidence is not a censorship-resistance, anonymity, or perfect
  indistinguishability result.

The official REALITY project describes a custom TLS-handshake path with
temporary authenticated certificates and forwarding to a selected target for
rejected or ordinary clients. The official ShadowTLS project exposes a real TLS
handshake from a selected site and then carries a separate encrypted proxy
behind that handshake. These are architectural references only. Maverick has
not selected their wire formats, code, trust assumptions, or deployment model.

Primary references:

- <https://github.com/XTLS/REALITY>
- <https://github.com/ihciah/shadow-tls>

## Options

### A. Direct TLS/H2 With Application Fallback

Trust:

- the client trusts the configured Maverick server and certificate authority;
- the operator owns or provisions the server certificate and fallback origin;
- there is no mandatory third-party TLS terminator.

Channel binding and replay:

- direct supported TLS carriers can bind Auth v1/v2 to TLS exporter material;
- existing timestamp, nonce, epoch, and replay-cache behavior remains intact;
- no new pre-auth negotiation endpoint is required.

Active probing:

- ordinary, malformed, wrong-auth, and rate-limited requests can be sent through
  the configured fallback;
- the current response-shape baseline is mechanically testable;
- TLS fingerprint, timing, admission exhaustion, WebSocket upgrade behavior,
  and origin-specific details can still differ.

Operations and compatibility:

- lowest deployment complexity of the three options;
- normal certificates, direct origin reachability, and current configs apply;
- fully compatible with the frozen v1 frame and auth formats;
- preserves the best-understood rollback path.

### B. Trusted CDN-Fronted WebSocket

Trust:

- the client and origin trust the CDN as a TLS-terminating reverse proxy;
- the CDN can observe origin request metadata, auth frames, and tunnel payload;
- this mode does not protect the client from the fronting provider.

Certificate ownership and channel binding:

- the CDN controls the client-facing certificate and handshake;
- the origin separately controls or provisions the edge-to-origin certificate;
- current end-to-end TLS exporter binding cannot span the terminating provider;
- this path must not claim direct client-to-origin TLS channel binding.

Replay and active probing:

- Maverick auth and replay checks still run at the origin;
- the provider sees and can influence the connection before origin auth;
- the public edge can provide ordinary ECH and WebSocket behavior;
- wrong-path WebSocket behavior and provider-specific responses remain
  measurable differences.

Operations and compatibility:

- requires DNS, provider configuration, origin reachability, WebSocket support,
  and a documented provider trust decision;
- keeps current Maverick frame and auth formats but uses a separate carrier;
- remains explicit, default-off, and rejected by stable mode;
- is useful for controlled deployments, not a provider-independent default.

### C. Handshake-Layer Forwarding Or Split

Trust and identity:

- certificate and identity behavior depends on the chosen design;
- a target site, forwarding component, temporary credential, or new key type
  may enter the trust boundary;
- target selection can create legal, operational, availability, and
  fingerprinting risks;
- copying a design name without its full threat model is unacceptable.

Channel binding and replay:

- the current TLS exporter contract cannot be assumed to survive a split or
  forwarded handshake;
- a new transcript-binding and downgrade story would be required;
- pre-auth routing keys, time windows, retries, and rejected-client forwarding
  need separately bounded replay and abuse controls;
- no custom cryptography may be introduced without focused review and vectors.

Active probing:

- this family can structurally move rejection behavior closer to a real TLS
  target instead of synthesizing an application response;
- it can still expose implementation, target-selection, timing, retry, record
  size, or post-handshake differences;
- the benefit must be measured against direct target behavior, not assumed.

Operations and compatibility:

- highest implementation, deployment, debugging, and incident-response cost;
- changes certificate, handshake, routing, or authentication semantics;
- requires a new protocol/version track and migration plan;
- cannot be a silent v1.x change.

## Comparison

| Dimension | Application fallback | CDN WebSocket | Handshake-layer research |
| --- | --- | --- | --- |
| v1 frame/auth compatibility | yes | yes, separate carrier | not assumed |
| New mandatory trust party | no | TLS-terminating CDN | design-dependent |
| Direct TLS exporter binding | supported on direct carriers | unavailable end to end | must be redesigned |
| Own certificate required | normally yes | provider edge plus origin policy | design-dependent |
| Pre-auth origin similarity | bounded application comparison | provider edge behavior | potentially structural |
| Current runtime evidence | strongest | one approved-host smoke plus local tests | none |
| Deployment complexity | low | medium/high | high |
| Default status | mandatory | explicit and off | research only |
| Version track | v1.x | compatible experimental carrier | unscheduled incompatible release |

## Why This Decision

Replacing the default now would discard the path with the strongest
compatibility, auth, replay, rollback, and operational evidence. Promoting the
CDN path would silently make a third party part of every user's confidentiality
boundary. Implementing a handshake-layer design immediately would create a new
security protocol before Maverick has an independently reviewed threat model or
evidence harness for it.

The conservative choice preserves a usable v1.x baseline while allowing the
most promising structural idea to be studied without misleading users or
destabilizing the current protocol.

## v2 Research Entry Gate

Handshake-layer work may begin only as an isolated research prototype after all
of these are written and reviewed:

- a threat model naming passive observers, active probes, malicious targets,
  malicious forwarding components, compromised providers, and replay actors;
- a certificate and server-identity model;
- an authentication transcript and channel-binding design;
- replay, downgrade, retry, resource, and abuse bounds;
- target-selection and target-failure policy;
- a migration and rollback plan that leaves direct H2/TLS available;
- deterministic parser/conformance vectors for every new pre-auth field;
- direct-target differential tests for accepted, rejected, malformed, replayed,
  delayed, and overloaded connections;
- two-host and impairment evidence on explicitly approved test systems;
- dependency, license, unsafe-code, and independent security review.

The first prototype must be build-gated, runtime-gated, default-off, excluded
from stable claims, and unable to modify the existing v1 path silently.

## Rejection Conditions

Do not promote a handshake-layer design if it:

- requires unreviewed custom cryptography;
- cannot authenticate the intended Maverick endpoint without trusting an
  unrelated target;
- makes replay or resource use unbounded before authentication;
- depends on a target whose behavior cannot be reproduced or legally operated;
- creates a unique failure signal that is easier to probe than the current
  fallback;
- cannot fail closed without exposing credentials or silently downgrading;
- removes the tested direct H2/TLS rollback path;
- lacks an independent review route.

## Consequences

Near term:

- no runtime or config change is authorized by this decision;
- v1.x work stays focused on measured browser TLS, fallback, connection reuse,
  shaping, and real network evidence;
- CDN-fronted WebSocket keeps its explicit provider-trust acknowledgement;
- M6 evidence remains valid because this decision changes documentation only.

Long term:

- v2 has a concrete research entry gate instead of an open-ended protocol idea;
- a successful handshake-layer prototype can be compared with the direct and
  CDN tracks using the same evidence discipline;
- failure to pass the gate leaves the current v1.x architecture intact.

## Finalization Record

This decision became accepted after:

- M6 long-haul, impairment, and failure evidence was accepted for tested source
  commit `b3a1793`;
- the evidence revealed no blocker that changes the comparison above;
- documentation and claim-hygiene checks passed;
- the decision remained linked from the active plan and documentation index.

The redacted evidence record is
`docs/history/evidence/APPROVED_HOST_POST_V1_M6_EVIDENCE_2026_07_11.md`.
