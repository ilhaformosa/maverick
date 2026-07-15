# Public Feedback Process

Status: standing public intake and privacy process. It is not an execution
plan, support SLA, security-audit process, stable-release promise, or
production-readiness claim. `docs/PLAN_POST_V1.md` owns prioritization.

Maverick accepts public feedback only within the repository's experimental
scope. Feedback should help improve the source prototype, documentation,
release hygiene, compatibility notes, local harnesses, and carefully scoped
runtime behavior.

## Intake

Use public GitHub issues for:

- reproducible non-security bugs;
- documentation gaps or confusing release boundaries;
- compatibility or migration questions;
- loopback-only harness failures;
- scoped feature requests that preserve the experimental status.

Do not use public issues for:

- vulnerabilities with working exploit details;
- real server addresses, real private hostnames, access tokens, generated
  credentials, private keys, HMAC tags, or payload data;
- operator logs that reveal private infrastructure, account names, cloud
  resources, certificate paths, or local filesystem paths;
- requests that require changing a developer workstation's system proxy, DNS,
  route table, firewall, VPN, or other network-service settings.

Security reports should use private vulnerability reporting or another private
maintainer channel.

## First Triage

For each public issue, first classify it as one of:

- `security-private`: move out of public discussion and ask for private
  reporting if sensitive details are involved;
- `release-blocker`: breaks a supported release, default local harness, release
  artifact generation, dependency advisory gate, or documented compatibility
  boundary;
- `active-milestone-candidate`: useful, aligned with
  `docs/PLAN_POST_V1.md`, scoped, and verifiable without expanding public
  claims;
- `beta-candidate` and `rc-candidate`: historical v1-train labels retained for
  old issues only; new work maps to `active-milestone-candidate`;
- `docs-clarification`: wording, examples, non-claims, or operator guidance;
- `future-track`: valid but outside the active post-v1 milestone;
- `out-of-scope`: contradicts the safety boundary or asks for unsupported
  product scope.

Before reproducing an issue, scrub any supplied material for secrets and
private environment details. Prefer reproduction cases that use `127.0.0.1`,
OS-assigned ephemeral ports, generated placeholder credentials, and neutral
host placeholders such as `REPLACE_WITH_TEST_HOSTNAME`.

## Active Milestone Selection

An item is a good active-milestone candidate when it:

- improves public feedback handling, release hygiene, privacy hygiene,
  compatibility policy, operator docs, examples, conformance, benchmark
  evidence, or long-haul evidence;
- is small enough to review and verify without changing the project claim;
- keeps protocol version and config version unchanged unless the release notes,
  compatibility policy, and migration notes are explicitly updated;
- can be tested with loopback-only commands or separately approved hosts;
- does not require native server-side ECH, GUI/App work, TUN system apply on a
  workstation, or a production-readiness claim unless the active milestone
  explicitly includes and gates that work.

If there are no open public issues or pull requests at a release-planning
snapshot, record that plainly. Do not claim public feedback was handled unless
matching issues, pull requests, or private reports are recorded.

Defer items that need a protocol freeze, formal security review, broad platform
packaging, native ECH runtime support, or stronger anonymity/censorship
resistance evidence unless the current phase explicitly includes that work.

## Release Note Capture

For every accepted release item, record:

- user-visible change;
- compatibility or migration impact;
- security/privacy impact;
- verification command;
- whether approved-host evidence is required;
- whether release notes must repeat any non-claim.

Every release should include:

- the correct GitHub release type for the version policy;
- release notes with exact verification commands and commit hash;
- artifacts generated from the exact tagged commit, if artifacts are attached;
- explicit statements that may cite evidence or review input only when
  accurate, and that the release is not audited or production-ready;
- the Native ECH boundary and Cloudflare-fronted workaround boundary when ECH
  is mentioned.

## Stable-Scope Feedback

Feedback that targets `maverick-tls-h2-cli-v1` should be evaluated against
the frozen compatibility policy, `docs/STABLE_SCOPE_CANDIDATE.md`, and the
active post-v1 milestone. A maintenance or post-v1 release must preserve the
documented stable scope or provide an explicit migration and version decision.
