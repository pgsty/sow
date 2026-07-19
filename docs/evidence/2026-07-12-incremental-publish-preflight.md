# Incremental publish no-change preflight evidence

Date: 2026-07-12 (Asia/Shanghai)

The ordinary view publication path now validates the provider checkpoint and
immutable generation control plane, the canonical configuration digest, and
the selected ref commit vector before package materialization or serving-tree
scans. An exact match returns `status=unchanged preflight=ref-vector`. A changed
or missing ref, configuration change, interrupted generation/lock, control
drift, or expired retained snapshot falls back to the complete publication
transaction; the optimization never turns those conditions into success.

The protocol-level CLI regression publishes a real asset generation through
the production R2/Cloudflare client, repeats the same command, and asserts:

- the second output contains the preflight marker and no `materialized view=`;
- PUT, CDN purge, and CDN verification counts do not increase;
- the remote ref still equals the canonical desired ref;
- no incomplete local transaction remains.

```bash
go test -count=1 ./internal/cli \
  -run '^TestPublishCLIUsesRealProviderProtocolAndAdvancesRemoteRefLast$'
```

```text
ok  github.com/pgsty/sow/internal/cli  1.262s
```

A scale fixture commits a canonical asset view containing 50,000 sorted
entries, then executes the production ref-vector comparison 100 times. The
measurement starts after fixture creation, so it isolates the no-change gate
and proves it does not open or stream the large view blob.

```bash
go test -tags perf -count=1 -v ./internal/cli \
  -run '^TestIncrementalPublishPreflightFiftyThousandEntriesDoesNotReadView$'
```

```text
incremental-preflight entries=50000 iterations=100 elapsed=9.129625ms retained_heap_growth=-941048
--- PASS: TestIncrementalPublishPreflightFiftyThousandEntriesDoesNotReadView (0.10s)
ok github.com/pgsty/sow/internal/cli 0.807s
```

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
重跑为 `elapsed=10.697959ms retained_heap_growth=-941160`，package 0.613s，PASS。

The test gate allows at most one second and 4 MiB retained-heap growth. Changed
publications still use the separately measured streaming 50k manifest diff and
bounded repo/component/architecture preparation scheduler; this evidence is
specifically for the dominant no-change path.
