# Phase 3-B Frozen Candidate Summary

Status: coordinator-accepted redacted summary for the frozen
`v1.2.0-alpha.1` candidate. This file contains no raw logs, credentials,
private paths, host details, addresses, or provider details.

## Exact identity

- Maverick release and SDK commit:
  `3b3f0c4836c2ab619002e953ff574fbbcf224f56`.
- Reference-client commit:
  `054956fa4e14e2df3e9b1d9c7f4f0628074a83a1`.
- Reference-client SDK pin:
  `3b3f0c4836c2ab619002e953ff574fbbcf224f56`; the pin matches the Maverick
  SDK commit.
- Release train and tag: `1.2.0` and `v1.2.0-alpha.1`.
- Maverick and reference-client software: `1.2.0-alpha.1`.
- Debian package: `maverick-reference-client` version
  `1.2.0~alpha.1-1`, Ubuntu 26.04 LTS `amd64`.
- Protocol `1`, Auth v1 `1`, Auth v2 `2`, config `1`, helper IPC `1`,
  recovery journal `2`, and platform plan `3` remain separate versions.

## Accepted build and signing conclusions

- Debian package SHA-256:
  `2fccf32953fb0b93c569c9c74fbb58ae4bee0c7ca1e9a33b494c25fc7b95388a`.
- Two independent package builds produced byte-identical package, BUILDINFO,
  and server bytes. Accepted pair-result SHA-256:
  `e943e5d37a744676653a9848c9b38a7ae74436bdaa262f1ce53c93ee1be9e046`.
- Server binary SHA-256:
  `4c3477787e9800b7d3368050ca906468c26caee47a7b53b83e58986d3856d590`.
- The detached OpenSSH package-set signature and public signer identity were
  accepted. Signature SHA-256:
  `60bcc9a333c6303f09dc9cd40ff949b7a0459ff923015e82e7b07c9f1c7a824f`;
  public fingerprint:
  `SHA256:XUecjxlGXpdqieNDN1haGSmeRFwEutb8lDi5+zLR6pQ`.
- The deterministic APT snapshot uses an accepted signed `InRelease`. It does
  not claim that a detached `Release.gpg` exists and no package repository has
  been published.

## Accepted gates and frozen inputs

- Both local harnesses, dependency/source/license/unsafe checks, package
  reproducibility, privacy, current-source T2, cleanup, and independent zero
  residue were accepted for the exact identities above.
- Current-source T2 accepted-manifest SHA-256:
  `032e7d32a55d11c1ac619f8b5d81e42b027779afa59c08d33195f9b6a76751ce`.
- The coordinator re-hashed 38 frozen artifacts and 10 frozen tools. Frozen
  input-tree manifest SHA-256:
  `a45704bea46e49be2ff49df2b3e8b8d32353fb224db4c1999d4f854871d8e6b3`.
- Phase 3-B recommendation SHA-256:
  `51fdd2e3a5f57b5fc035f664441a22ecab947cba843d5043b672ef4657e24c62`;
  it had no unresolved pre-freeze blocker.
- Coordinator freeze-record SHA-256:
  `309a02809b45c4969a5c1725e87f9e1b62af1584d3d4f4ca049918b203955923`.

## Boundary

This closes the Phase 3-B frozen-candidate input and the code-complete question
only. Post-freeze public release-candidate CI, formal Phase 3-A evidence,
independent audit, deployability, publication, and final Go approval are still
missing. The current decision remains No-Go.
