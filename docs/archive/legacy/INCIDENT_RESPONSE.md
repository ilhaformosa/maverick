# Incident Response

Status: pre-release operating process for the narrow production candidate. It
does not create a support SLA or production-ready claim.

## Priorities

1. Protect users, credentials, package trust, and host network state.
2. Stop new harm without destroying evidence needed to understand it.
3. Restore a known-good signed version or fail closed.
4. Communicate privately first when public detail would increase risk.
5. Record what happened, what was not proven, and what must be retested.

## Severity

- `SEV-0`: signing/archive-key compromise, unauthenticated code execution,
  credential disclosure, malicious package, or broad silent route/DNS escape.
- `SEV-1`: major authentication, isolation, fallback, recovery, or package
  integrity failure with practical impact.
- `SEV-2`: bounded service/security degradation with a workaround and no known
  broad compromise.
- `SEV-3`: low-impact hardening, documentation, or monitoring defect.

Security finding severity and release effect follow
`docs/AUDIT_REMEDIATION_POLICY.md`.

## First Response

- Assign an incident ID and UTC start time.
- Record the exact release tag, Maverick software, reference-client software,
  Debian package, config, protocol, and artifact hashes.
- Stop publication and promotion when package or signing trust may be affected.
- Preserve minimal redacted logs, metrics, package metadata, and configuration
  hashes before cleanup or rollback.
- Do not paste credentials, private keys, packet contents, addresses, hostnames,
  provider data, private paths, or raw logs into a public issue.
- Choose containment: disable one credential, stop one service, remove one
  repository snapshot, or roll back to one verified artifact. Avoid broad
  unmeasured changes.
- Open a private security report when the incident may be a product flaw.

## Playbooks

### User credential suspected compromised

1. Disable the affected user or credential on the server.
2. Preserve only redacted authentication and rate-limit evidence.
3. Generate a new high-entropy credential offline.
4. Apply the bounded overlap sequence in `docs/CREDENTIAL_ROTATION.md` only when
   the old credential can remain temporarily safe; otherwise revoke first.
5. Verify old authentication fails and new authentication succeeds.
6. Remove expired material and check logs for accidental disclosure.

### TLS server key or certificate compromised

1. Stop accepting new service traffic when continued use would expose users.
2. Revoke/replace the certificate through the operator's CA process.
3. Protect the new private key, update certificate pins when used, and validate
   hostname/chain/pin behavior from a clean client.
4. Restart the service, verify H2 health, and retire the old key and pin.

### Release or APT signing key suspected compromised

1. Stop tags, releases, package publication, and repository metadata updates.
2. Record the last known-good signed commit, tag, artifact manifest, and APT
   snapshot.
3. Rotate the affected key without reusing the OpenSSH artifact key as the APT
   archive key.
4. Publish the new public key/fingerprint through a reviewed project channel.
5. Rebuild and reverify affected artifacts; issue an advisory and replacement
   release when trust was lost.
6. Keep old public keys only for historical verification and mark the affected
   interval clearly.

### Route, DNS, TUN, or capture leak

1. Stop new captured applications and fail closed.
2. Preserve the journal and exact typed state before any manual cleanup.
3. Use the package's verified recovery/rollback path.
4. Compare TUN, policy rules, route tables, resolver state, processes, sockets,
   services, and package files with the recorded baseline.
5. Do not delete an object that cannot be proven run-owned.
6. Require a fresh-session independent zero-residue check before reuse.

### Package upgrade, install, or purge failure

1. Stop automatic retry and record package-manager state.
2. Confirm services are inactive or known-good and host network state is clean.
3. Preserve operator data and the recovery journal.
4. Retry only with the same or higher verified package allowed by the package
   gate, or restore the previous verified snapshot through the documented
   transactional path.
5. Purge only after the exact rollback and residue checks pass.

### Overload or probing spike

1. Check connection, pre-auth, auth-rate-limit, fallback-overload, flow-limit,
   process, memory, descriptor, and restart signals.
2. Keep authentication and fallback behavior fail-closed and redacted.
3. Apply ordinary provider or host protections outside Maverick without
   weakening egress or listener boundaries.
4. Treat the controls as load bounds, not DDoS protection.

## Recovery Gate

Recovery is complete only when the known-good signed artifact is running, the
intended credential/certificate/signing state is active, expected probes pass,
monitoring is normal for the recorded observation window, rollback residue is
absent, and user-facing guidance is ready.

Any source or package change made during response creates an evidence-impact
decision. Re-run only the affected layers, but never reuse evidence across an
unrecorded candidate change.

## Closeout

Record a redacted timeline, root cause, affected versions, containment, recovery,
finding IDs, evidence reruns, user communication, and follow-up owner/deadline.
Public disclosure follows `docs/SECURITY_DISCLOSURE_WORKFLOW.md`.
