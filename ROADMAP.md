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

No new product-code slice is queued. The current release-only slice is limited
to making the unmerged `1.2.0-beta.2` publication path fail closed:

- one shared offline verifier checks the exact seven-entry pilot archive,
  checksums, bound public content, USTAR metadata, architecture, source
  revision, version, and privacy rules;
- each repository-contents-read-only build job performs native verification,
  copies only the approved archive and checksum into private staging, performs
  a final static reverification, and uploads only those two staged paths;
- the publish job executes neither downloaded binary. It accepts exactly two
  archives plus two checksums, copies them into separate private staging,
  statically reverifies the exact bytes selected for publication, and gives
  only those four named paths to the final release command;
- a release tag must be annotated, directly target the exact event commit, and
  that commit must already be an ancestor of the freshly read current `main`;
  and
- ordinary public PR/main CI builds the Linux archive with GNU tar on
  `ubuntu-24.04`, performs native verification before any write-capable release
  context exists, and runs the same local negative gate tests.

Native verification means the binary ran successfully on a matching host; it is
not a sandbox or proof that an untrusted binary is safe to execute. Linux CI is
repository quality evidence only, not a product, user, live-network, release,
or publication result. Local verification and safe rejection do not change the
product facts in `STATUS.md`.

The implementation stage stops after local validation and a bounded commit for
independent review. Only after that review may the commit be pushed and the
existing Draft PR receive updated notes; it remains Draft. This queue does not
authorize marking the PR ready, merging, creating or moving a tag, running the
release workflow, uploading an Actions or public release asset, releasing,
deploying, or changing any live, remote, or system-network state.

## Execution Order

1. **Fix only reproduced Beta failures.** After Beta.1, use the smallest local
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
version remain `1` for both the published Beta.1 release and the unmerged
Beta.2 candidate; existing authentication and frame wire formats are unchanged.
Any future version or wire-format change requires an explicit compatibility
decision based on observed user need.
