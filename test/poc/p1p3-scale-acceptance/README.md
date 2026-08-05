# P1-P3 scale acceptance

This harness verifies the retained, disposable 34,184-package SOW V2 scale
baseline. It uses exactly these existing lab roots and never reads or writes
the production repository:

- `/Users/vonng/repo/sow-v2-scale-portable.OnL4IO` (17 workspaces, 31,811 objects)
- `/Users/vonng/repo/sow-v2-scale-supplement-portable.Jjt2ma` (one workspace, 2,373 objects)

`prepare.sh` rebuilds replacement disposable baselines with the current
checkout. Its 17 primary input selections are read from retained manifests
whose package paths are all under `/Users/vonng/pgsty/repo2`; the 2,373-package
supplement selection likewise validates every current repo2 path and byte
size before ingestion. It creates new `sow-v2-scale-portable.*` roots and
never edits either repo2 or the retained source manifests. After a successful
preparation, update the two frozen roots in `run.sh` to the printed paths.

The combined immutable package facts must be exactly 34,184 objects and
53,879,777,230 bytes (50.179452850 GiB). The harness builds one frozen Darwin
arm64 and one Linux arm64 binary from the current checkout, converges all 18
workspaces, then performs one Docker-guest-cache-cold and two host-warm forced
metadata rebuilds per workspace. For each cold run it copies the read-only
host workspace into a uniquely labelled, run-owned Docker native volume,
drops the Linux guest page cache, runs the Linux build and full check on that
native filesystem, then verifies both labels before deleting only that volume.
This avoids treating Docker Desktop's macOS bind filesystem, which does not
provide the required non-empty directory exchange, as a supported Linux
publication filesystem. Each forced rebuild changes only a non-matching
policy marker, so membership and package bytes remain unchanged while every
Dist is actually rendered and a new physical Generation is committed. Every
retained run must complete within 120 seconds.

Finally it runs full `check` and `changes 0` on every workspace and records
timing, maximum RSS, source/binary identities, SQLite counts, disk usage and
all JSON results. Docker's privileged cache drop clears the Linux VM page
cache; it cannot prove that macOS APFS host caches are cold, so the report
labels this boundary explicitly.

Run from the project root:

```bash
test/poc/p1p3-scale-acceptance/run.sh
```

Evidence is retained under a new
`/Users/vonng/repo/sow-v2-scale-final.*` directory. The package workspaces are
the already-disposable baseline above; the new directory contains only logs,
binaries and manifests.
