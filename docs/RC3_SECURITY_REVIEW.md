# RC.3 independent security review

Date: 2026-11-10

The reviewed candidate is `2aeaaf98b3f400e9cbd0a4b30896e8e8d7b93796`, compared
with immutable published RC.2 `966d29966d05287bc2eef6401c6297582db605f6`.
Five fresh-context model reviewers, independent from implementation, reviewed
69 changed source/tool files and 35 additional test/fixture/lock files. A separate
fresh-context architecture review mapped actual trust and resource consumers.
The implementing parent checked the remaining 20 documentation/deployment files,
reconciled findings and reproduced the two retained issues on loopback.

This is a source-backed model review, not a paid human audit or an exhaustive
audit of third-party dependency implementations. Daybreak was unavailable;
ordinary models were used as authorized. Existing successful tests were treated
as supporting evidence, not a substitute for this review.

| Finding at RC.3 | Severity | Correction in RC.4 |
|---|---|---|
| Shared connection limits were enforced after QUIC TLS while H2 reserved them before TLS | Medium | Reserve the existing shared allowance before QUIC allocation and keep it through transport completion |
| Canceling reliable UDP close could detach its background task and retain the H2 stream | Low | Retain task ownership across the existing close await so cancellation invokes Drop cleanup |

The first issue was bounded by existing pre-authentication admission, local H3
limits and handshake deadlines; it was not unbounded admission or authentication
bypass. The second required delayed completion and caller cancellation; it did
not establish credential disclosure or arbitrary exhaustion scale. Neither
finding was rated Critical or High.

Actual product regressions failed at those controls on unchanged RC.3 runtime
code. The UDP reproduction used the public SDK, a normal authenticated server,
and an opaque transport stall. Shared-limit tests use real dual listeners and
QUIC handshakes; the fixed cases cover both arrival orders and independently
exercise global/source bounds and capacity recovery. Successful forwarding,
normal close and close-timeout behavior remain controls.

No source-backed authentication, origin-protection, egress, security-downgrade,
configuration-export or package/rollback bypass survived the reviewed paths.
The intentional public certificate SHA-256 output remains distinct from secret
logging. This absence of additional findings is bounded by the inspected change
set and supporting code, not a proof that the product has no vulnerabilities.

The immutable scan bundle retains its RC.3 findings and exact red/green evidence;
it must not be relabeled as a review of modified source. Replacement qualification
uses a separate independent patch review, applicable local/CI checks and exact
archive/SBOM/rollback records. Git/PR records and SOURCE.txt bind those results to
the replacement candidate. No scan rule or required quality check is removed.

Field validation, actual deployment and release remain deferred. Independent
pin distribution, origin-key custody, real intermediary streaming, ordinary
network use, 72-hour observation and field rollback still require their own
evidence before Stable qualification.
