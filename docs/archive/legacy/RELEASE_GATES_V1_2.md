# v1.2.0 Release Gates

Status: active pre-freeze gate map. No tag is authorized or created by this
document.

All stages use the narrow scope in `docs/PRODUCTION_SCOPE.md`. Every tag requires
coordinator approval, a clean exact commit, local verification, artifact privacy,
and versions not previously used in the private history.

Every stage also follows `docs/CI_AND_RELEASE_GATES.md`:

- the exact change passes local preflight and `public-pr-ci / public-pr-gate`;
- after freeze, the coordinator dispatches `release-candidate-ci` with the full
  `maverick_release_commit` and exact stage;
- the accepted run identity and checksums enter the coordinator record before
  the stage is marked passed;
- the workflow does not tag, publish, or replace private reference-client or
  target-fixture evidence.

## `v1.2.0-alpha.1`

Purpose: first public frozen-source and package candidate.

Required:

- the ledger records release train `1.2.0`, release tag
  `v1.2.0-alpha.1`, Maverick and reference-client software
  `1.2.0-alpha.1`, and Debian package `1.2.0~alpha.1-1` as separate fields;
- the ledger scope and formal fixture policy both name Ubuntu 26.04 LTS
  `amd64`; an Ubuntu 24.04 Actions result is CI input only and cannot satisfy
  the target-platform gate;
- coordinator records the exact frozen Maverick release, Maverick SDK, and
  reference-client commits, and verifies the reference-client SDK pin against
  the Phase 3-B accepted public summary;
- `code_complete` is complete in `production-readiness.json`;
- both local harnesses, dependency/source/license/unsafe gates, package build,
  checksum, signature, privacy, and smoke checks pass for exact artifacts;
- public PR CI and exact-commit release-candidate CI pass;
- the scope, non-claims, compatibility, migration, and known blockers are in the
  release notes;
- release is marked Pre-release and not Latest.

Phase 3-A evidence and an independent audit may still be incomplete. The alpha
must say so and cannot carry a deployment or production claim.

## `v1.2.0-beta.1`

Purpose: evidence-complete candidate for the named platform.

Required:

- every alpha requirement still passes for the exact beta candidate;
- Phase 3-A and Phase 3-B inputs are coordinator-accepted and
  `evidence_complete` is complete;
- sustained/daily, transition, process-recovery, power-loss, credential-root,
  package lifecycle/publication, cleanup, and residue results required by the
  scope are accepted; excluded gates remain explicit non-claims;
- no critical or high finding is open;
- release remains Pre-release and not Latest.

The independent production audit may be in progress. Beta is not production
approval.

## `v1.2.0-rc.1`

Purpose: audit-complete, deployable stable candidate.

Required:

- all beta requirements pass for the exact RC candidate;
- `audit_complete` and `deployable` are complete;
- the independent report binds the exact RC source and artifacts;
- all critical/high findings are closed and every accepted medium risk follows
  `docs/AUDIT_REMEDIATION_POLICY.md`;
- monitoring, incident response, key recovery, support, compatibility, upgrade,
  rollback, removal, and package-publication instructions are rehearsed;
- release remains Pre-release and not Latest.

Any affected runtime change after RC requires a new RC and targeted evidence and
audit retest.

## `v1.2.0`

Purpose: first public stable release for the named narrow production scope.

Required:

- all RC requirements pass for the exact stable candidate;
- stable release-candidate CI passes while the final production decision is
  still No-Go; the owner uses that accepted result as an input to the final
  ledger transition;
- every published RC artifact is re-downloaded and independently verified;
- all five readiness dimensions are complete;
- the final record based on `docs/PRODUCTION_GO_NO_GO_TEMPLATE.md` says `GO` and
  the ledger checker agrees;
- stable artifacts and repository metadata are signed and independently
  verified;
- release notes state the exact platform and every non-claim;
- coordinator separately approves tag, publication, and release creation.

Stable does not expand the scope. It does not create anonymity, censorship-
resistance, browser-equivalence, IPv6, cross-platform, H3, or support-SLA claims.

## Change After A Gate

| change | action |
| --- | --- |
| prose only, no procedure or claim effect | docs/privacy gates and impact note |
| build, package, dependency, checker, or evidence-tool change | rebuild and rerun affected local/evidence layers |
| server, SDK, helper, credential, route, DNS, recovery, or package-script change | new candidate binding and affected formal/audit retest |
| platform, architecture, carrier, address family, or default-path change | new scope and full matching gate plan |

No stage passes because time elapsed. It passes only because its exact evidence
exists and is accepted.
