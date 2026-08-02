# quiche 0.29.3 provenance

This directory is Maverick's repository-maintained, library-only copy of
`quiche` 0.29.3. The unmodified source archive is the crates.io `.crate` with
SHA-256 `61166d27591eb7cb1310eec2b8fc6ae0e0686e9e4ed742a3ffc6317171175e7d`.
Its `.cargo_vcs_info.json` identifies upstream commit
`09b125d4cfc16e78d73d8382c93926f3aba063d4`. The source was adopted on
2026-08-03.

`COPYING` is retained byte for byte under BSD-2-Clause and has SHA-256
`2ef4b5abfce387a83933bda738e72467a79d15c1c17679143ec55011dae66b84`.
Maverick maintainers own review, rebasing, and security maintenance of this
copy. An upstream-version change requires a new source, license, dependency,
and maintained-delta review.

The retained runtime source is byte-identical to the `.crate` except for the
three H3 files changed by the patches in `PATCHES/`. The first patch is the
reviewed strict peer-push gate, with SHA-256
`74e9078d2e6c244b4fba2dbad185a8eb1adba6762d32286540ed645122be04fa`.
The adoption review patch has SHA-256
`873ba92b498ba260ae097c47474d51ee79d6f94ac87efa3ba53337ca57404512`;
it narrows one helper's visibility and makes the setter documentation enumerate
its exact boundary.
The H3 trace privacy patch has SHA-256
`923c9ce876e76c7758ecebe8d9126572a245ea98019b467b66d5acc228ad2ee0`.
Relative to the accepted T026b-1 tree, it changes exactly `src/h3/mod.rs`,
`src/h3/stream.rs`, and `src/h3/qpack/decoder.rs`: a configuration value is
copied into each H3 connection, all H3 frame and stream trace calls check it
before formatting, and the QPACK decoder checks its connection-derived copy
before formatting header names, values, or indexes. Its default is `false`, so
quiche 0.29.3 callers that do not opt in retain the existing trace behavior.
Maverick's private shared H3 builder opts in for both connection roles while
keeping the independent strict peer-push gate enabled.
The vendor-local `.gitattributes` disables Git whitespace diagnostics only for
the three byte-exact unified-diff artifacts and `src/recovery/mod.rs`, which has
one upstream trailing-space line. This preserves those upstream/provenance
bytes without weakening whitespace checks elsewhere in the repository.
The Cargo manifest is intentionally curated to a library target and only the
`boringssl-boring-crate` runtime feature plus the unstable `internal` test
support used by Maverick's focused regression test. Other upstream optional
features are not offered by this copy; qlog remains disabled.

The H3 trace privacy setting does not cover qlog or outer QUIC transport logs.
qlog is absent from the current curated manifest and dependency graph; offering
or enabling it later would reopen a separate privacy-review boundary.

`src/ffi.rs`, `src/h3/ffi.rs`, and `src/tests.rs` are retained byte for byte
only because `cargo fmt --all` resolves conditional modules while formatting.
The curated manifest does not offer FFI, and the excluded path package is not
an upstream test workspace, so these tooling-only files are not built. The
vendor-local rustfmt configuration preserves the exact upstream formatting
instead of rewriting the archive into a large unrelated maintained delta.

Deliberately omitted from the `.crate`:

- `examples/**`, including all sample certificates and `examples/cert.key`;
- `include/quiche.h`, `quiche.svg`, `README.md`, and upstream `AGENTS.md` files;
- the upstream package `Cargo.lock` and workspace-only `Cargo.toml.orig`.

The copy does not implement Maverick authentication, CONNECT, target or DNS
handling, relay data, user-visible H3, or a Datagram admission gate.
