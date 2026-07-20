# Benchmark Baseline

Maverick benchmark results are local diagnostics, not performance guarantees.
They run on `127.0.0.1` with ephemeral ports and do not change system proxy,
DNS, route, firewall, VPN, or other network-service settings.

## Command

```sh
./scripts/benchmark-baseline.sh
```

By default this runs release-mode loopback payloads at 64 KiB, 1 MiB, and
10 MiB with concurrency levels 1 and 4. For a quick non-baseline local smoke
run:

```sh
MAVERICK_BENCH_PROFILE=dev MAVERICK_BENCH_CONCURRENCY=1 ./scripts/benchmark-baseline.sh 65536
```

Generate a markdown dashboard with:

```sh
./scripts/benchmark-dashboard.sh
```

Compile the Criterion parser-regression benchmark without running timed
measurements:

```sh
./scripts/criterion-regression.sh smoke
```

Save or compare a local Criterion baseline with bounded sample settings:

```sh
./scripts/criterion-regression.sh baseline
./scripts/criterion-regression.sh compare
```

Criterion results live under `target/criterion/` and are local diagnostics only.
They are useful for parser regression triage, not production performance
claims.

## Current Baseline

Sample run:

- date UTC: 2026-06-26T09:11:13Z;
- git commit: `f2834fb`;
- command: `./scripts/benchmark-baseline.sh 65536`;
- cargo profile: dev;
- concurrency: 1;
- payload bytes: `65536`;
- direct TCP roundtrip: `0.930 ms`;
- Maverick SOCKS roundtrip: `0.938 ms`;
- overhead ratio: `1.009`.

## Interpretation

Use this baseline to catch large regressions, not to compare against other
machines or networks. Loopback timings can vary across CPU load, thermal state,
payload size, and concurrency. Compare release-mode baselines with release-mode
baselines.
