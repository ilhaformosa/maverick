# Independent Production Audit Package

Status: pre-freeze package preparation. No independent production audit has
started or completed.

This package tells an outside reviewer what to inspect after the coordinator
freezes one exact candidate. A Codex review, AI review, maintainer review, local
harness run, or earlier scoped review is useful input but is not the independent
production audit required here.

## Audit Subject

The audit is limited to `maverick-linux-h2-ipv4-v1` from
`docs/PRODUCTION_SCOPE.md`:

- the frozen Maverick server and SDK source;
- the frozen `maverick-reference-client` source and signed Debian package;
- Ubuntu 24.04 LTS `amd64`, IPv4, TLS 1.3 plus HTTP/2;
- authentication, replay, fallback, parser, resource, logging, and credential
  behavior;
- privileged helper IPC, TUN ownership, route isolation, private DNS, journaled
  rollback, process recovery, and package scripts;
- credential-root, package-signing, APT-publication, monitoring, incident,
  upgrade, rollback, recovery, and removal boundaries;
- the machine-readable production ledger and its release-decision rules.

Everything listed as a non-claim in `docs/PRODUCTION_SCOPE.md` is outside the
production claim. The reviewer should still report an excluded feature that can
accidentally enter the default path or weaken the included scope.

## Independence Requirement

The final auditor must:

- be outside the maintainer and implementation decision path;
- disclose material financial, employment, authorship, or operational conflicts;
- control the audit method and finding language;
- receive the exact frozen source and artifact hashes directly from the
  coordinator record;
- be able to publish or sign a scope-and-result statement that the maintainer
  cannot silently rewrite.

An auditor may use automation or AI as one tool. The independent human or
organization remains responsible for the method, findings, severity, and final
report.

## Frozen Intake Record

Do not start the formal audit until every value below is present and verified:

| field | required value |
| --- | --- |
| Maverick source | full public commit hash |
| Maverick SDK source | full commit hash pinned by the reference client |
| reference-client source | full public commit hash |
| server/CLI artifact | name, target, size, SHA-256, signature result |
| reference package | package name, version, architecture, size, SHA-256, signature result |
| release versions | software, protocol, Auth v1, Auth v2, config, IPC, journal/recovery |
| evidence tools | runner, collector, analyzer, cleanup, verifier hashes |
| public CI | accepted PR gate plus exact release-candidate run identity and control commit |
| Phase 3-A input | coordinator-accepted manifest SHA-256 and redacted summaries |
| Phase 3-B input | coordinator-accepted candidate manifest SHA-256 and redacted summaries |
| known risks | open blockers, accepted residual risks, excluded features |

A mismatch stops the audit. Evidence from another commit or rebuilt package may
not be relabeled.

The target-platform runtime gates must use a source-bound disposable Ubuntu
24.04 LTS `amd64` VM or fixture. Evidence collected on a physical host with a
different operating-system release cannot be used as Ubuntu support evidence.

## Reviewer Instructions

1. Verify the frozen source, dependency locks, artifacts, signatures, and input
   manifests before reviewing behavior.
   Confirm that the public release-candidate run built the ledger's release
   commit rather than the newer control-record commit.
2. Review the two threat models and build one combined attack-path list for the
   server, client, privileged helper, package, credential root, and repository.
3. Reproduce local and loopback gates from clean checkouts. Do not change the
   reviewer's everyday machine proxy, DNS, routes, firewall, VPN, or interfaces.
4. Run privileged, power-loss, package-manager, route, DNS, or TUN tests only in
   auditor-controlled disposable fixtures with collection-before-cleanup and an
   independent residue check.
5. Inspect default behavior first. Confirm that experimental H3, ECH, shaping,
   crypto, SDK TUN, GUI, IPv6, and fronted paths cannot enter the production
   claim accidentally.
6. Test malformed, concurrent, interrupted, replayed, downgraded, stale, and
   partial states. Include resource exhaustion and recovery failure.
7. Keep raw logs, host details, credentials, packet contents, and exploit steps
   private. Public material uses neutral descriptions, hashes, and redacted
   conclusions.
8. Send findings through `docs/SECURITY_DISCLOSURE_WORKFLOW.md` and assign impact
   under `docs/AUDIT_REMEDIATION_POLICY.md`.
9. Recheck affected layers after fixes. Do not accept a new candidate under the
   old report without a written impact decision.
10. Produce the deliverables below even when the result is No-Go.

## Required Deliverables

The final package must include:

- auditor identity, independence statement, dates, method, tools, and limits;
- exact source, artifact, package, and evidence-manifest hashes;
- included and excluded scope;
- every finding with severity, affected component, reproduction boundary,
  impact, and remediation status;
- a clear list of tests not performed and claims not established;
- retest results tied to the remediation commit and rebuilt artifact hashes;
- residual-risk decisions with owner and expiry;
- final report SHA-256 and, when available, auditor signature;
- a simple conclusion: audit complete for the named scope, audit incomplete, or
  candidate rejected.

An audit can be complete while the product remains No-Go. Audit completion is
only one of the five readiness questions.

## Completion Rule

Phase 3-C may set `audit_complete` after the coordinator verifies the auditor's
independence, frozen bindings, complete report, and report hash. It sets audit
remediation complete only after finding closure. RC and production Go require
both states. Critical or high findings cannot be open, and any accepted
lower-risk finding must follow the documented residual-risk policy.
