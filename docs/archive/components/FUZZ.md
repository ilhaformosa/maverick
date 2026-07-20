# Maverick Fuzzing

Maverick fuzz targets are parser-only and require no network listeners.

Seed inputs are declared in `seed-manifest.json`. Run the smoke harness to
materialize cargo-fuzz corpus files from checked-in conformance vectors and
compile the targets:

```sh
./scripts/fuzz-smoke.sh
```

To run a bounded fuzz pass when `cargo-fuzz` is installed:

```sh
MAVERICK_RUN_CARGO_FUZZ=1 MAVERICK_FUZZ_RUNS=256 ./scripts/fuzz-smoke.sh
```

Generated corpus, artifacts, and coverage output stay out of git.
