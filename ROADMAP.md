# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Planning Input Rule

Design drafts and reconciliation notes are non-authoritative planning inputs.
When they conflict, `STATUS.md` alone controls current truth and authorization,
while `ROADMAP.md` controls execution order. Only a minimal slice placed here
enters execution; every other proposal remains deferred, neither automatically
adopted nor automatically rejected.

## Current Repository-Local Queue

### T011a-1 — Enforce the strict Profile URI v1 query boundary

This repository-local slice is not bound to a release version.

- **User result:** A mistyped or ambiguous Profile URI v1 query fails safely
  instead of silently dropping a field or choosing one of two conflicting
  values.
- **Scope:** Before reading individual fields, inspect every decoded v1 query
  pair once. Accept only the ten existing v1 keys and reject any unknown or
  repeated key with one fixed privacy-safe error. Preserve legal field order,
  serialization order, defaults, secret handling, and materialization behavior.
- **Acceptance:** Unknown and percent-encoded unknown keys fail closed; every
  recognized required, optional, secret, pin, and boolean key fails when
  repeated, including percent-encoded duplicates. Rejection occurs before
  secret parsing or file creation and never echoes untrusted query content.
  Legal v1 round trips, imports, QR and clipboard safety, overwrite protection,
  and explicit v2 rejection remain unchanged.
- **Out of scope:** Profile URI v2, a core codec, stored-profile migration,
  complete config v2, a client-role envelope or readiness API, runtime consumer,
  public API or schema changes, dependencies, server behavior, and real network
  work.
- **Stop conditions:** Stop if implementation requires a fourth file,
  `STATUS.md`, Cargo or lockfile changes, a dependency, public API or schema
  expansion, a core, SDK, client, or server change, a real network, or any
  system-network mutation.

## Execution Order

1. **Fix only reproduced Beta failures.** After Beta.2, use the smallest local
   reproduction and repair for a failure that a Beta user or an authorized
   field run actually observes. Preserve destination-free diagnostics and the
   existing privacy boundaries. Do not add speculative transports, tuning,
   orchestration, or connection-health machinery merely because Beta has
   started. A product-binary change requires a new reviewed Beta artifact; a
   documentation-only clarification must not pretend to be a product fix.
2. **Validate the Stable candidate on a fresh origin.** Before any Stable
   decision, obtain separate authorization for one freshly provisioned clean
   temporary origin and repeat artifact verification, from-scratch installation,
   ordinary browsing, and the applicable reliability and compatibility checks
   using the exact Stable-candidate artifact. The origin must pass the current
   host policy and every recorded stop rule. A retained reference origin or
   Beta result cannot replace this clean-origin gate, and this roadmap item does
   not itself authorize a server, provider change, spending, network change, or
   Stable claim.
3. **Track native server-side ECH upstream.** Keep the current provider-fronted
   path labeled as a workaround, not ECH. Do not fork rustls or vendor an
   unmerged ECH patch in the current plan.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work without a reproduced Beta need and an explicit
  compatibility and security decision.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No rustls fork or vendored unmerged server-ECH patch in the current execution
  plan.
- No remote, paid, privileged, or host-network action outside the current
  authorization recorded in `STATUS.md`.

## Failure-Driven Follow-Up

Use the shortest failure-driven next step:

- install failed -> simplify the artifact;
- daily use failed -> fix reliability/usability;
- TLS fingerprint was blocked -> improve the default TLS/handshake path;
- active probe distinguished the server -> harden handshake/fallback behavior;
- Beta baseline passed -> accept privacy-safe feedback, but do not recruit
  another user or widen platform, protocol, packaging, or governance scope
  without a separate owner decision.

The Maverick protocol version, config version, and stored-profile schema
version remain `1` for the published Beta.2 release; existing authentication
and frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
