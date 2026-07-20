# Security Disclosure Workflow

Status: active process for private reports and audit findings. Response targets
are best effort, not a support SLA.

## Intake

Use GitHub private vulnerability reporting when available. If it is unavailable,
open a public issue containing only a short coordination request and no exploit,
host, credential, path, packet, or log detail. Follow `SECURITY.md`.

The maintainer should acknowledge ordinary security coordination within seven
calendar days when possible. A report that appears to permit unauthenticated
code execution, credential theft, broad route/DNS escape, signature bypass, or
silent package compromise should be acknowledged as soon as practical.

## Workflow States

1. `received`: preserve the original private report and assign a private ID.
2. `triaging`: confirm scope, affected commit/package, preconditions, and impact.
3. `accepted`: record severity, affected releases, owner, and disclosure plan.
4. `fixing`: prepare the smallest fix and identify evidence that must be rerun.
5. `retesting`: reproduce the original issue and affected regression gates.
6. `release_ready`: prepare signed artifacts, upgrade guidance, and advisory.
7. `disclosed`: publish enough detail for users to act without exposing private
   reporter or infrastructure data.
8. `closed`: verify update availability and record remaining risk.

A rejected report records a coarse reason privately. It must not expose a
reporter's identity or reproduction details.

## Coordination Roles

- The maintainer owns intake, user communication, and release decisions.
- The reporter controls whether their name is credited.
- An independent auditor controls their finding language and audit conclusion.
- A fix implementer does not independently close their own critical or high
  finding; another reviewer must reproduce the fix result.

## Disclosure Timing

Coordinate disclosure around a usable signed update. Earlier disclosure is
appropriate when exploitation is already public, users face immediate harm, or
the maintainer cannot provide a safe update in a reasonable period. Delaying
disclosure only to protect project reputation is not acceptable.

When practical, a public advisory should include affected versions, impact,
preconditions, fixed version, upgrade/rollback guidance, workarounds, credit,
and the limits of the investigation. Working exploit details may remain private
until users have a reasonable update window.

## Data Hygiene

Private reports may contain sensitive material, but retained evidence should be
minimized. Do not copy real credentials, packet contents, private hostnames,
addresses, provider data, account names, or raw logs into public commits,
release notes, or ordinary issues. Use hashes and neutral reproductions when
possible.

## Release Effect

Finding severity, candidate invalidation, residual-risk acceptance, and required
retests follow `docs/AUDIT_REMEDIATION_POLICY.md`. An open critical or high
finding keeps the production decision at No-Go.
