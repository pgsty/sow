# Nginx exact repository-route compatibility evidence (2026-07-14)

## Claim

One POSIX serving tree can preserve both the configured package-repository
leaves and the object-store contract in which exact object `/pkg` coexists
with independently owned `/pkg/pig/`, without granting generic `/apt/`,
`/yum/`, `/_sow/`, or `/pkg/` capabilities. The same projection remains fail
closed in the standalone Basic Auth fallback.

## Product paths

- `asset/bootstrap/pkg` is served only by exact location `/pkg` (or
  `/pro/v1/basic/pkg`).
- `pkg/pig/` is served only by prefix location `/pkg/pig/` (or
  `/pro/v1/basic/pkg/pig/`).
- package locations are emitted for concrete configured leaves such as
  `apt/test/` and `yum/test/x86_64/`, not their parent namespaces;
- one exact mirrorlist and one generation route constrained to its literal
  repo leaf are emitted for each configured YUM channel;
- `/pkg/`, a real unowned `pkg/child/` canary, `.sow`, `.pool`, operator files,
  unknown roots, and real `apt/unowned-secret`, `yum/unowned-secret`,
  `_sow/unowned-secret`, and unowned generation canaries are denied by the
  default location.
- Basic responses require authentication and successful content responses are
  `Cache-Control: private, no-store`.

## Reproduction

All cloud credentials were removed, every real-cloud/edge switch was forced to
zero, outbound proxies were pointed at a closed loopback port, and `GOPROXY`
was disabled. The test starts only a temporary local Nginx process and sends
HTTP requests to `127.0.0.1`.

```sh
SOW_RUN_REAL_CLOUD=0 \
SOW_RUN_REAL_EDGE_EVIDENCE=0 \
SOW_REAL_CLOUD_PURGE_WATCHER_HELPER=0 \
SOW_COMPAT_NGINX=1 \
GOPROXY=off \
go test ./test/compat \
  -run '^(TestBasicNginxExampleAssetProjectionContract|TestNginxRepositoryAllowlist|TestBasicNginxRepositoryAllowlist)$' \
  -count=1
```

Observed result:

```text
ok  github.com/pgsty/sow/test/compat  10.821s
```

This is local Nginx compatibility evidence. It is not a production URL,
Cloudflare, CO/COS, CDN, or production-cutover result; production resources are
prohibited for testing.
