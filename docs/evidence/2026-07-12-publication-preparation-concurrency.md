# Default publication preparation concurrency evidence

Date: 2026-07-12

The ordinary beta/latest/stable path—not only snapshot materialization—builds
one independent task per asset repo, APT repo, and YUM repo/OS/architecture
leaf. Source-tree scans use the same scheduler. Tasks are sorted before launch
and results/output are consumed in that stable order.

The scheduler divides one caller-provided worker budget between outer tasks and
their inner hashing/index pools. With budget 4 and eight tasks, four tasks must
be concurrently blocked while each receives one inner worker; a fifth task is
forbidden until capacity is released. With one task, that task receives all
four workers. The race detector repeats this barrier proof ten times:

```sh
go test -race ./internal/cli \
  -run '^TestRunBoundedOrderedSharesWorkerBudgetAndSorts$' -count=10
```

Observed:

```text
ok  github.com/pgsty/sow/internal/cli  6.446s
```

The production multi-repository path was then exercised with real DEB/RPM
parsers, APT/YUM signing and both metadata engines under the race detector:

```sh
go test -race ./internal/cli \
  -run 'TestPublishCLIUploadsRealAPTAndYUMGenerationClosures|TestRunBoundedOrderedSharesWorkerBudgetAndSorts' \
  -count=1
```

Observed:

```text
ok  github.com/pgsty/sow/internal/cli  4.364s
```

This evidence covers the default publication scheduler and global bound. The
separate APT/YUM/materialize 50k records remain the throughput and bounded-memory
evidence; this small barrier test does not substitute for those scale runs.
