# Narrow Production Scope Candidate

Status: pre-freeze scope definition for `v1.2.0`. This document defines the
smallest production claim Maverick may try to earn. It does not say that the
claim has been earned.

## Candidate Name

`maverick-linux-h2-ipv4-v1`

## Included Scope

The candidate contains only:

- the `maverick` CLI-managed server using TLS 1.3 plus HTTP/2;
- the `maverick-reference-client` Debian package;
- Ubuntu 24.04 LTS on `amd64` for both installed service evidence and support;
- IPv4 traffic only;
- Auth v1 by default, with the existing explicit Auth v2 option;
- config version 1 and the existing v1 frame format;
- connection-bound capture through the packaged Linux service and helper;
- package install, upgrade, rollback, purge, monitoring, incident response, and
  credential rotation only when their exact candidate gates pass.

The release may describe only the exact package, operating-system version,
architecture, carrier, address family, and operations path that were frozen,
tested, independently audited, and accepted.

Formal platform evidence must come from a source-bound disposable Ubuntu 24.04
LTS `amd64` VM or fixture whose image and package hashes are recorded. Evidence
from a physical host running another operating-system release may help test the
harness or host-isolation boundary, but it cannot satisfy the Ubuntu 24.04
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

The candidate is not frozen. Phase 3-A and Phase 3-B inputs are missing, and no
formal independent production audit is complete. The current result is
therefore **No-Go**.

`production-readiness.json` is the machine-readable source for these states.
Run `python3 scripts/check-production-readiness.py` after every change to the
scope, gate inputs, release stages, or final decision.
