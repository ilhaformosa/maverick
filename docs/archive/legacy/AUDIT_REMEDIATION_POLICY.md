# Audit Finding Remediation And Impact Policy

Status: active pre-freeze policy. It defines release impact; it does not claim
that an audit occurred.

## Severity

| severity | meaning | release effect |
| --- | --- | --- |
| critical | likely compromise of code execution, credentials, signatures, package trust, or broad host network state with practical impact | blocks every candidate and release until fixed and independently retested |
| high | major authentication, isolation, replay, route/DNS, recovery, secret, or package-integrity failure | blocks beta, RC, stable, deployment, and production Go until fixed and independently retested |
| medium | bounded security failure needing meaningful preconditions or limited impact | blocks RC/stable unless fixed or explicitly accepted under the rule below |
| low | defense-in-depth, hardening, or low-impact disclosure gap | may be scheduled with an owner and deadline when the production scope stays accurate |
| informational | no demonstrated security impact | track when useful; does not alone block a release |

Severity considers exploitability, required access, affected assets, scope,
detectability, recovery, and whether default behavior is affected. A numeric
score may support the decision but does not replace the written impact.

## Required Finding Record

Each accepted finding records:

- private finding ID and public advisory ID when one exists;
- affected source, artifact, package, platform, and configuration;
- severity and written impact;
- default/optional path and required attacker access;
- fix commit and rebuilt artifact hashes;
- unit, regression, formal-evidence, and audit retests required;
- disclosure state and user mitigation;
- closure reviewer and date.

## Candidate Impact

A runtime, helper, credential, package, signing, route, DNS, recovery, or evidence
tool fix creates an impact decision. Reuse is allowed only for an unaffected
layer with written reasoning. A fix that changes the frozen source or artifact
creates a new candidate binding even when its wire and config versions stay the
same.

Rejected or partial runs remain rejected. Passing evidence from different source
revisions cannot be combined to present one complete candidate.

## Residual-Risk Acceptance

Critical and high findings cannot be accepted for the production Go decision.
A medium finding may be accepted only when all of these are recorded:

- why the included production scope remains safe enough;
- exact affected and unaffected boundaries;
- practical operator mitigation;
- named maintainer owner and expiry date;
- auditor response to the proposed acceptance;
- a public, redacted statement in the release notes and production ledger
  evidence.

Expired acceptance returns the finding to open. Low findings require an owner
and review date when deferred. Silence, lack of time, or release pressure is not
risk acceptance.

## Closure

A finding closes only after the original reproduction fails for the expected
reason, regression tests pass, affected formal evidence is accepted, release
artifacts are rebound, documentation matches the result, and the required
independent retest is recorded. A maintainer-authored fix is not its own
independent verification.
