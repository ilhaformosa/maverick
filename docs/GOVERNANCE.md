# Governance

Status: active lightweight maintainer governance for `v1.1.x` maintenance and
`v1.2.0` development.

Governance should keep Maverick changes reviewable, security-conscious, and
compatible with the project's privacy and anti-abuse boundaries.

## Roles

- Maintainer: reviews and merges changes.
- Security reviewer: reviews auth, crypto, fallback, logging, and parser
  changes.
- Implementer: builds compatible clients, servers, SDKs, or tooling.
- Operator: deploys private instances and reports operational issues.

## Decision Areas

Wire-affecting changes require:

- spec update;
- conformance vector update;
- compatibility note;
- security review.

Experimental feature promotion requires:

- feature-gate history;
- passing tests;
- risk register update;
- explicit migration plan;
- no default enablement until reviewed.

## Security Reports

Security reports should avoid public exploit details until triaged. The project
must maintain a private intake path before a public repository is opened or a
wider deployment claim is made.

External review planning is tracked in `docs/SECURITY_REVIEW_PLAN.md`. A plan
is not an audit result; release notes must distinguish planned, in-progress,
and completed review status.

## Release Labels

- `experimental`: feature or design work outside the stable scope.
- `candidate`: spec candidate with conformance vectors.
- `reviewed`: scoped external review completed; this does not mean a formal
  audit unless the release evidence says so.
- `stable`: a narrow engineering scope with operational evidence and
  compatibility discipline; it is not a production-readiness claim.

## Community Boundaries

This project is for legal privacy, secure communication, connectivity research,
and protocol engineering. It does not accept malware, credential theft,
intrusion, scanning, spam, or abuse-enablement contributions.
