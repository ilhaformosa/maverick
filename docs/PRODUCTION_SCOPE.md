# Narrow Production Scope Candidate

Status: frozen and parked scope definition for `v1.2.0`. Phase 3 closed
incomplete with a final `NO_GO` decision. This document defines the smallest
production claim Maverick had tried to earn; it does not say that the claim was
earned.

## Candidate Name

`maverick-linux-h2-ipv4-v1`

## Included Scope

The candidate contains only:

- the `maverick` CLI-managed server using TLS 1.3 plus HTTP/2;
- the `maverick-reference-client` Debian package;
- Ubuntu 26.04 LTS on `amd64` for both installed service evidence and support;
- IPv4 traffic only;
- Auth v1 by default, with the existing explicit Auth v2 option;
- config version 1 and the existing v1 frame format;
- connection-bound capture through the packaged Linux service and helper;
- package install, upgrade, rollback, purge, monitoring, incident response, and
  credential rotation only when their exact candidate gates pass.

The release may describe only the exact package, operating-system version,
architecture, carrier, address family, and operations path that were frozen,
tested, independently audited, and accepted.

Formal platform evidence must come from a source-bound disposable Ubuntu 26.04
LTS `amd64` VM or fixture whose image and package hashes are recorded. Evidence
from a physical host running another operating-system release may help test the
harness or host-isolation boundary, but it cannot satisfy the Ubuntu 26.04
support gate and cannot be relabeled as target-platform evidence.

## Excluded Scope And Non-Claims

The candidate does not include or claim:

- IPv6 support;
- macOS, Windows, mobile, GUI, container, router, or other Linux-distribution
  support;
- production H3/QUIC, WebSocket fronting, native ECH, experimental TUN runtime,
  shaping, padding, or experimental cryptography;
- anonymity, censorship resistance, browser-fingerprint equivalence, perfect
  fallback indistinguishability, or strong traffic-analysis resistance;
- safe operation on a compromised client, server, root account, signing system,
  or package repository;
- a support SLA, high availability, DDoS protection, or multi-region failover;
- production readiness merely because code, tests, evidence, packaging, or an
  audit package exists.

## Five Separate Questions

Maverick keeps these decisions separate:

1. **Code-complete:** is the frozen source implemented and locally verified?
2. **Evidence-complete:** did the frozen artifacts pass the accepted Phase 3-A
   runtime and lifecycle matrices?
3. **Audit-complete:** did a qualified independent reviewer complete and report
   the audit of the frozen candidate?
4. **Deployable:** can the exact signed package be installed, monitored,
   upgraded, rolled back, recovered, and removed on the named platform?
5. **Production-ready:** are all four earlier questions complete, are audit
   findings closed or explicitly accepted, and is there a final recorded Go
   decision?

Passing one question never changes another question automatically.

## Current Result

The candidate is frozen and the Phase 3-B input is accepted. Exact-source
post-freeze release-candidate CI also passed, but Phase 3 closed without an
accepted Phase 3-A input. Deployability and a formal independent production
audit are still missing. The final Phase 3 result is therefore **No-Go** and the
candidate is parked.

The last bounded engineering rehearsal stopped at a controller readiness race
before client package installation. It did not complete positive traffic,
expected rejection, restart recovery, or purge. This is not a demonstrated
protocol/package failure and is not product acceptance. Any return to server
work requires a separate project-level decision; see
`PHASE3_CLOSEOUT_AND_RECOVERY.md`.

The separate recovery route's readiness component later passed, but its first
whole execution package was rejected locally before external action because
real stage executables were missing. A corrected executable revision now
passes local tool checks, but its one authorized integration run stopped during
read-only provider preflight before resource creation because a truncated
response escaped the adapter's safe GET-retry path. It ran no product, created
no host, spent no money, and does not change this result. Any future server run
requires a new project-level decision and cannot retroactively complete Phase
3. A separately established transport-recovery package then passed a local
real-response-read regression and all inherited tool gates. Its single
authorized run stopped during read-only provider plan preflight after both
bounded GET attempts failed with the broad class `transport`; the precise
exception was not persisted. It created no resource, ran no product, spent no
money, and has no authorized successor. This is not product evidence.

The frozen first-stage identity is release train `1.2.0`, tag
`v1.2.0-alpha.1`, Maverick and reference-client software
`1.2.0-alpha.1`, and Debian package `1.2.0~alpha.1-1`. The machine-readable
ledger binds those names to exact commits and the package hash; it does not
turn the remaining evidence or approval questions into passes.

`production-readiness.json` is the machine-readable source for these states.
Run `python3 scripts/check-production-readiness.py` after every change to the
scope, gate inputs, release stages, or final decision.
