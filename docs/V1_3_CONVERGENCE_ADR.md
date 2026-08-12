# Maverick v1.3 Convergence Decision Record

Date: 2026-08-12
Status: **Accepted and amended — OD-01 through OD-09 ratified; B-003 direction superseded on 2026-08-12**

## Authority and claim boundary

This record turns the recovery playbook into one reviewable decision surface.
It is not a second status ledger, a completion record, a release authorization,
or permission for real-network, paid, privileged, or host-network work.

- `AGENTS.md` remains the safety boundary.
- `STATUS.md` remains the only current product truth and authorization source.
- `ROADMAP.md` remains the execution order after the owner approves a slice.
- The dated master design, reconciliation, and recovery playbook remain design
  inputs. They do not make future architecture current product fact.

This record freezes only the decisions named below. Each implementation still
requires the smallest approved `ROADMAP.md` slice and its own deterministic
evidence.

## Exact evidence baselines

| Item | Exact fact |
|---|---|
| Public main | `da69e15a6b9a6a70b55ab7697465c4d113edbc57` |
| Published Beta.4 source | annotated `v1.2.0-beta.4` directly targets `5109d89bdddc23a2830eda2c0c56a954d3b214a9` |
| Cumulative experimental head | `40b0aa7b630c0decc411c0983795828d15252bda` |
| Topology | experimental head is 77 commits ahead, 0 behind; merge base is public main; the range contains 0 merge commits |
| Recovery | five immutable `archive/v1.3-*` branches preserve the playbook recovery points |
| Remote baseline | Historical Draft PR [#29](https://github.com/ilhaformosa/maverick/pull/29) ran exact-head gates once, recorded five passing check names and one CI/reproducibility failure, and was closed without rerun or merge |

The cumulative branch remains unmerged and unreleased experimental source. It
is publicly visible only as recovery and baseline source. Local tests, remote
checks, archive refs, hashes, and this record are quality or recovery controls;
none is a human-user, real-network, product, release, audit, native Datagram,
or production-readiness result.

## Evidence corrections learned during recovery

These corrections narrow wording without changing the playbook's direction.

1. Config schema 3 is no longer purely pre-runtime. The cumulative head has
   feature-gated, loopback-only runtime consumers for a one-shot client role
   and a server role. It is still not the normal CLI, SDK, `start_client`,
   long-running, non-loopback, or published product path. Schema-3 retirement
   therefore has compatibility cost and must not be treated as deleting an
   unused draft.
2. The borrowed legacy-H3 split cannot be moved into two independent
   `'static` tasks, but one owning actor task can poll both borrowed halves.
   The precise root cause is the current `DatagramFlow`/consumer ownership and
   inline-await model, not borrowed splitting alone.
3. T025f proves one finite, three-frame scheduling shape. It does not provide
   an explicit fairness budget or a deterministic proof for continuous input.
   Its test uses timing windows, so it is not the D-003 causal RED.
4. The current v1.2 release verifier accepts Beta tags only, and the release
   workflow always publishes a prerelease. RC/Stable publication therefore
   needs a separately approved, deterministic release-contract slice before
   any RC or Stable tag can be created.
5. Exact-head PR #29 passed CodeQL Actions, CodeQL Rust, aggregated CodeQL,
   `public-pr-gate`, and `macos-sbom-gate`. Its `dependency-inventory` job
   failed only in the later focused CycloneDX test; the preceding locked
   dependency/deny/unsafe inventory script passed. The cumulative branch adds
   the gated quiche/Boring closure but retains the old component-count
   expectations: generated counts are Linux 185 and macOS 184, while the test
   expects 177 and 176. A local diagnostic changed only those expectations and
   then passed both target checks plus all 55 negative checks. This is a
   recorded CI/reproducibility red, not a dependency-vulnerability finding or
   a remote green result. No check was rerun and the frozen head was not changed.

## Owner decisions

| ID | Decision | Accepted owner decision |
|---|---|---|
| OD-01 | Stop automatic micro-fixes after T025f | **Yes.** Stop at T025f and move to an ownership-level slice. |
| OD-02 | Count the current legacy-H3 duplex path as native UDP | **No.** It is reliable H3 DATA duplex UDP framing only. |
| OD-03 | Authorize a Datagram public/internal API redesign | **Yes.** Private owned-handle prototype first; public design only after evidence. |
| OD-04 | Allow Quinn and quiche product stacks to coexist long term | **No.** Measure both, then retain at most one product backend. |
| OD-05 | Accept long-term maintenance of a private QUIC/TLS fork | **No by default.** An exception must pass the complete fork budget. |
| OD-06 | Keep config v2 permanently policy-only and create v3 separately | **No. Plan A is accepted:** one complete, runnable, migratable Product Config v2. Current schema 3 does not become the product config; a distinct provisioning file, if needed, uses its own `provisioning_schema` domain. |
| OD-07 | Squash or merge all 77 commits as a whole | **No.** Preserve them, classify them, and rebuild reviewable slices. |
| OD-08 | Let Auto use H3 immediately | **No.** H3 remains outside Auto until every architecture, security, fingerprint, and weak-network gate passes. |
| OD-09 | Keep separate v1.2 H2 and v1.3 release trains | **Yes.** Neither train silently authorizes a release or field run. |

## 2026-08-12 amendment — quiche is the single H3/UDP direction

After the decisions above were recorded, the owner recalled and explicitly
reaffirmed an earlier project decision: Maverick is to abandon Quinn for the
H3/UDP product path and continue only toward quiche. This amendment preserves
the table above as the historical OD-01 through OD-09 answer and supersedes
only its later conditional B-003 selection procedure.

The repository facts supporting recovery scope are narrower than a claim that
all 23 historical heads are quiche implementations:

- the six `codex/t027c2d-*` through `codex/t027c2i-*` heads terminate in the
  direct-v3 quiche runtime sequence;
- the 17 `codex/t024*` and `codex/t025*` heads terminate in Quinn legacy-H3
  reliable DATA/UDP semantic work, although the single linear chain means
  their ancestry also contains the earlier quiche foundation;
- `archive/v1.3-direct-foundation-7f6158d` is the preferred quiche source
  oracle. The later `7f6158d..40b0aa7` range did not change the quiche
  foundation/runtime/vendor paths or Cargo dependency files, so later Quinn
  heads add no newer quiche implementation to recover.

This is a direction choice, not acceptance evidence. B-001 becomes a
single-subject qualification of quiche against a neutral Chrome reference and
the same fixed objective matrix. B-002 remains **RED**. Any retained private
delta must pass every named-owner, upstream/rebase, security-SLA, and
independent-delta fork-budget gate. A pure-upstream candidate may omit the old
patches only after evidence-backed `DROP / not required` dispositions plus its
dependency, security, and target-aware SBOM gates pass. Privacy, fingerprint,
resource, and platform gates remain mandatory in either case. No quiche patch
may be enlarged merely to improve a qualification result. If quiche fails, H3
remains outside the product; Quinn is not a fallback.

The stopped Quinn-specific B-001 relay qualification and D-004 implementation
work-in-progress are not to be committed. Existing Quinn product code is
removed later in one separate, reviewable, reversible slice so deletion cannot
hide quiche adoption risk. Immutable archives remain available as semantic and
test oracles; they are not current product code. Recovery should extract
contracts and tests from the quiche oracle, not copy dependency downgrades or
adopt the preserved private fork by default.

Compatibility is unchanged for the v1.2 H2 train. Auto still does not use H3,
and reliable H3 DATA framing still does not become native UDP. Rollback of this
document amendment restores planning text only; it cannot silently restore a
second product backend or count archived code as current implementation.

## Frozen stop boundaries

The following stop rules remain active after acceptance:

- do not create T025g or another scheduling probe;
- do not call legacy H3 DATA framing native Datagram;
- do not change public API, config schema, auth wire, frame wire, or Auto;
- do not add Quinn H3 functionality or restore quiche before its gates pass;
- do not expand the vendored quiche delta;
- do not squash, merge, delete, or force-update the cumulative branches;
- do not tag, publish, deploy, spend, or perform a new field run;
- do not turn `STATUS.md` into a commit diary or this ADR into a registry.

## Frozen outcomes

### Datagram ownership

The product direction is one authoritative association owner with separately
owned send, receive, and control handles. Queues, bytes, tasks, targets,
sockets, and lifetimes are bounded. Exact Rust names, queue sizes, and public
API remain unfrozen until D-001 through D-003 produce deterministic evidence.

### Product configuration

The target is a complete Product Config v2, not a permanent policy-only v2.
The existing v2 policy logic and schema-3 validators may be reused, but schema
3 is not renumbered in place and v1 Mode meanings do not change. A runnable v2
still requires separate decisions about schema-3 compatibility, the first H2
TrustRoute/auth support matrix, YAML migration scope, and single-endpoint
forward shape.

### H3 backend

The dated amendment selects quiche as the only intended H3/UDP product
direction. B-001 must qualify quiche against the neutral Chrome reference using
the same observable workload where comparison is technically meaningful, and
B-002 must resolve every old private patch through either a complete retained-
fork budget or an evidence-backed DROP disposition before adoption. B-003 therefore
records a fixed direction, not a technical PASS. If quiche does not pass its
objective gates, v1.3 remains H2-only; Quinn is not restored as a product
candidate.

### Release trains

- Train A: narrow, honest v1.2 H2 RC/Stable convergence.
- Train B: v1.3 architecture Alpha, with one backend, persistent session,
  owned Datagram semantics, and later standard CONNECT-UDP/QUIC DATAGRAM.

Train A does not wait for native H3 Datagram. Train B cannot borrow old field,
audit, artifact, or release evidence as proof for new source.

## Recorded repository-local next steps

`STATUS.md` records the authorization boundary; `ROADMAP.md` controls the
execution order. This decision record identifies the matching architecture
outcomes:

- G-001 immutable recovery points;
- G-002 one-time 77-commit merge manifest;
- G-003 Draft exact-head remote baseline, with no rerun or merge;
- D-001 semantic contract, D-003 old-API RED, D-002 private actor prototype,
  and D-003 GREEN implementation;
- B-001 quiche-only qualification planning and B-002 fork-delta closure;
- read-only v1.2 RC/Stable release-gap analysis.

Config/wire/public API changes beyond a separately approved smallest slice,
quiche product adoption, Auto, publication, and real-network work remain
stopped. Quinn removal is a separate reversible code slice, not part of this
document amendment.

## Recorded and delegated technical gates

1. Before C-001 implementation, Codex records the schema-3 compatibility
   treatment and the first runnable v2 TrustRoute/auth matrix under the owner's
   standing delegation; this is an objective migration gate, not an owner
   choice.
2. R1 through R4 already fix the v1.2 release policy: Direct H2 only for first
   Stable, RC prerelease/non-Latest, Stable non-prerelease/Latest, Beta.4 exact
   rollback, and exact-RC independent security plus supply-chain review with no
   unresolved Critical or High finding. Candidate evidence is still required.
3. No backend choice remains open. B-001/B-002 determine whether the fixed
   quiche direction is admissible; failure keeps product H3 disabled.

## Supersession rule

A later design change must name the evidence that changed, the affected
decision IDs, compatibility and rollback impact, and the replacing dated
record. Routine implementation results stay in code, tests, pull requests,
`STATUS.md`, or `ROADMAP.md` according to their roles.
