# Current-source MVP and Cloudflare bootstrap readiness

Date: 2026-07-29

Host: `vonng-m5max.vonng-rognet`, macOS 26.5.2 arm64

Revision: clean `22d3bd7` before this evidence-only edit

## Result

The current source contains a usable local MVP rather than a command skeleton:

- one CGO-free Go CLI exposes `init`, `fsck`, `add`, `rm`, `sync`, `publish`,
  `gc`, `verify`, `promote`, `materialize`, and `compatibility`;
- a real CLI adopts APT and YUM content, materializes it, verifies it, and runs
  `fsck`;
- the publication package passes its race suite and a real disposable MinIO
  S3-compatible transaction;
- current source produces static Linux/macOS amd64/arm64 binaries;
- the owner-authorized nonproduction Cloudflare bootstrap plan and deployment
  registry can be reproduced byte-for-byte from current source without cloud
  credentials or network mutation.

This is an MVP/current-source readiness result, not completion of the full PRD.
Real Cloudflare Worker/route/purge/cache behavior, Cloudflare provider logs,
COS/EdgeOne, and production migration remain separate evidence layers.

> Superseded bootstrap identity: the Workers Paid provider-attestation
> correction changed the auth Worker bundle after this clean-revision run.
> Plan `12c7410a…025c`, auth bundle `85389273…fa0c`, and registry
> `78f400b8…cab0` below are historical evidence only and must not be used.
> Current hashes and corrected tests are recorded in
> [the follow-up evidence](2026-07-29-cloudflare-workers-paid-provider-attestation.md).

## Reproducible checks

All cloud credentials were removed from these invocations. Real-cloud,
real-edge, real-upstream, and Docker compatibility opt-ins were disabled unless
the check explicitly says otherwise. No command targeted
`/Users/vonng/pgsty/repo`, a production bucket, a production repository, or a
production CDN namespace.

### CLI and local repository lifecycle

```bash
./sow version
./sow help

env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 SOW_RUN_DOCKER_COMPAT=0 \
  go test -race -timeout 15m -count=1 ./internal/cli \
  -run '^TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK$'
```

Result:

- `sow 0.1.0-dev darwin/arm64 go1.26.5`;
- the help output contains the complete command surface and documented exit
  codes 0–7;
- real APT+YUM adoption/materialize/verify/fsck E2E: PASS, package `15.282s`.

The checked-in arm64 binary SHA-256 was
`bd3629797c59fa9fa4f2020d2b2ec6aa912fb407269f56e405421cc825f267ec`.

### Publication transaction and real local S3 protocol

```bash
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 SOW_RUN_DOCKER_COMPAT=0 \
  go test -race -timeout 15m -count=1 ./internal/publish

env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_MINIO_TEST=1 go test -timeout 10m -count=1 -v \
  ./internal/publish -run '^TestMinIOS3Compatibility$'
```

Result:

- publication race suite: PASS, package `10.912s`;
- disposable fixed-image MinIO SigV4/conditional mutation/replay test: PASS,
  test `1.04s`, package `1.636s`.

MinIO is real S3-compatible protocol evidence, not R2 or COS provider evidence.
The latest real R2 storage/publication/fsck evidence remains V-85.

### Four static targets

```bash
CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -o /tmp/sow-linux-amd64  ./cmd/sow
CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -o /tmp/sow-linux-arm64  ./cmd/sow
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o /tmp/sow-darwin-amd64 ./cmd/sow
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o /tmp/sow-darwin-arm64 ./cmd/sow
shasum -a 256 /tmp/sow-{linux,darwin}-{amd64,arm64}
```

Result:

| Target | SHA-256 |
|---|---|
| linux/amd64 | `4d46248a59011a4e1e1ded597ddc773307985b20822691aa7b5d063cbc3aeaad` |
| linux/arm64 | `6e52b1693fa4e6895bfb05043bf77697782399e21c34bc85af426099692e431b` |
| darwin/amd64 | `841059a1aae93a959e2474bfd9b52b3fcba40598e07a467b9e98ada5b807bdef` |
| darwin/arm64 | `bd3629797c59fa9fa4f2020d2b2ec6aa912fb407269f56e405421cc825f267ec` |

### Cloudflare bootstrap offline closure

```bash
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 SOW_RUN_DOCKER_COMPAT=0 \
  go test -timeout 20m -count=1 ./test/compat \
  -run 'CloudflareBootstrap|ProviderReadiness'
```

Result: PASS, package `0.965s`.

The bootstrap candidate was regenerated into a new create-only directory from
the current source, private bootstrap descriptor, signer, entitlements, and Go
to JavaScript edge contract. It compared byte-for-byte with the independently
prepared candidate:

- plan SHA-256:
  `12c7410aff0a4a3a3f27e12604038f0096fc31a1aa78b14e95587f8eaaed025c`;
- readiness resource SHA-256:
  `0af5c47472a59b2c677889d8f2039d469d88ce05f3642b43d54389405aa78a2d`;
- auth Worker bundle SHA-256:
  `85389273136e7b67b58ef0a57afbadac34dcca4fad7181506ad2239e0c9fea0c`;
- origin Worker bundle SHA-256:
  `54f9dfe5d124b59cd4c81feb5980f9f8a30f95adb85c8c0f786b27915a646923`;
- deployment registry SHA-256:
  `78f400b82ad3c2986ab0ca33ee512e0f6c127ab8dc04e0aa929d73ebb07fcab0`.

The first deliberate replay into an existing output directory failed closed,
confirming create-only candidate generation. A second run into a nonexistent
child directory passed and matched the prior plan and registry exactly. This
stage performed no Cloudflare API call and no object mutation.

## Remaining external gates

The prepared one-day Cloudflare token is intentionally scoped to the exact
owner-authorized test account/zone and omits production resources. It has not
yet been created, so the following claims remain open:

1. deploy the two test Workers, bind only the exact test routes, publish a
   canary, exercise token/Basic paths, prove MISS/HIT and minimal purge, capture
   the deployment receipt, then roll back;
2. capture provider Workers Trace Events. The corrected contract uses the
   account-scoped `workers_trace_events` dataset available on Workers Paid,
   rather than Enterprise-only HTTP Requests. Creating/updating the exact task
   still requires account `Logs Edit` plus dedicated R2 writer, reader, and
   lease-control identities. The prepared bootstrap token deliberately lacks
   that separate permission; see the
   [follow-up evidence](2026-07-29-cloudflare-workers-paid-provider-attestation.md);
3. execute the equivalent COS/EdgeOne acceptance with separate nonproduction
   credentials/resources;
4. execute production migration/cutover evidence only under a separately
   authorized migration run. It is not authorized by this MVP check.

EL8 is not a blocker: its freeze point is `v5.0.0`, while apt older than 1.2 is
outside the compatibility floor. Those decisions are already frozen in the
product contracts and compatibility tests.

## Follow-up: shipped clean-room local MVP closure

The first literal clean-room replay of the README found three documentation
gaps rather than a CLI implementation failure:

1. `sow.example.yaml` declares three service directories, so an empty root must
   create those directories before `init`;
2. `L2` is remote-target coverage and must fail closed when `targets: {}` is
   used; the credential-free local smoke path is `L1`;
3. an explicit materialization target is directly hostable, so its real
   ancestor chain must be symlink-free and Nginx-worker traversable.

The README now contains an exact no-cloud/no-credential asset lifecycle whose
CLI phase performs no network operation, and
`TestShippedExampleSupportsCleanRoomLocalMVP` builds the production binary,
copies the shipped example, initializes an empty tree, adds an asset, executes
L1, promotes beta to latest, materializes a directly hostable export, runs
`fsck`, and byte-compares the exported asset. The clean-delivery builder runs
that test again from the extracted source archive rather than merely compiling
the archive.

Current-source results before this evidence edit:

| Check | Result |
|---|---|
| focused clean-room ordinary | PASS, package `8.011s` |
| focused clean-room race | PASS, package `7.999s` |
| full compat ordinary | PASS, package `17.852s` |
| full compat race | PASS, package `22.931s` |
| clean-delivery policy race | PASS, package `37.193s` |
| extracted-tree clean delivery, empty module/cache roots | PASS |

The default Go module endpoints were unreachable from this host. Clean delivery
therefore gained explicit `SOW_CLEAN_GOSUMDB` alongside the existing
`SOW_CLEAN_GOPROXY`; it still rejects `off`, clears private/no-sum bypasses, and
verifies every module. The successful isolated run used
`https://goproxy.cn,direct` plus `sum.golang.google.cn`. Its archive identity was
a pre-evidence observation and is intentionally not recorded as the final
delivery identity; V-14 still requires the post-document identities outside the
self-referential delivery root.

All repository mutations in this follow-up were below disposable
`/private/tmp/sow-compat-hostable-*` roots. Cloud credentials and real-cloud
opt-ins were absent. No Cloudflare API, R2 object, COS/CO resource, production
repository, or `/Users/vonng/pgsty/repo` write path was used.

## Follow-up: actual-process interruption recovery

The archive-enforced clean-room test now also proves the operator recovery
claim with the production executable. It starts one actual CLI add containing
1,024 unique assets, watches only the durable on-disk projection/selection
fences, sends `SIGSTOP` followed by `SIGKILL` as soon as a fence becomes
visible, and waits for the child to die. It does not install or call an
in-process fault hook.

The test then:

1. runs plain `fsck` and requires a nonzero diagnostic containing the recovery
   action;
2. deletes the entire original input directory;
3. executes the documented inputless
   `sow add --recover --config ... --root ...`;
4. requires a durable recovery receipt, L1 pass, full clean `fsck`, exact
   recovered sample bytes, and absence of both durable residue files.

The final 1,024-file fixture passed three consecutive ordinary runs in
`55.409s` total and two consecutive race-harness runs in `39.042s` total. Full
compat then passed ordinary/race in `40.601s`/`46.151s`; clean-delivery policy
race passed in `40.364s`; vet, Staticcheck, and diff checks were clean. The
recovered beta view contains the original smoke asset plus all 1,024
interrupted assets. This evidence strengthens FR-28/NFR-09 and clean-environment
operability; it does not upgrade any real-cloud or production-migration row.

All child processes and repository writes stayed below disposable
`/private/tmp/sow-compat-hostable-*`. Cloud credentials and all real-provider
opt-ins were absent, and no production or cloud resource was accessed.
