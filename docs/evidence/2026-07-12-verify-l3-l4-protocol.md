# L3/L4 publication and package-protocol verification evidence (2026-07-12)

## Scope and result

`sow verify` now executes remote checks rather than treating L3/L4 as an
unconfigured adapter surface:

- L3 loads the last canonical `remotes/<target>/plan.json`, requires its full
  `objects` to `verify` closure, checks the committed checkpoint/generation
  identity, and streams every expected byte through the configured CDN.
- L4 implements bounded pure-Go APT and DNF-compatible protocol probes. The
  APT chain is `InRelease -> Release SHA256 -> by-hash Packages -> DEB`; the
  YUM chain is `mirrorlist -> repomd.xml + .asc -> primary/filelists/other ->
  RPM` for both EL8 gzip and EL9/10 zstd metadata.
- A successful L4 finding contains protocol/version, metadata and installed
  object counts, package identity/version/SHA256, and a redacted transcript
  digest. A boolean-only adapter result is rejected as incomplete coverage.
- Stable checks use Basic Auth by default. `--pro-token-file` selects the
  token-in-path route at runtime. The token file must be a regular non-symlink
  with no group/other permissions and contain one 22-256 character base64url
  path segment. The token rewrites only in-memory request URLs and dynamic
  mirrorlist expectations; canonical plans retain `/pro/v1/basic/` and reports
  retain only non-secret labels.

Network/auth failures map to CLI exit 5, verified byte/signature drift maps to
exit 4, and missing committed plan/package coverage fails closed rather than
passing an empty layer.

## Reproducible local evidence

Executed from the repository root on macOS/arm64 with Go 1.26.4:

```text
go test ./internal/verify ./internal/cli \
  -run 'TestHTTPCheck|TestAPTProtocol|TestYUMProtocol|TestVerifyCLI|TestVerificationHeaders|TestProVerificationToken' \
  -count=1 -v

PASS internal/verify (0.863s)
PASS internal/cli    (4.244s)

go test ./internal/verify ./internal/cli -count=1
PASS internal/verify (3.757s)
PASS internal/cli    (42.496s)

go test -race ./internal/verify ./internal/cli \
  -run 'TestHTTPCheck|TestAPTProtocol|TestYUMProtocol|TestVerifyCLI|TestVerificationHeaders|TestProVerificationToken' \
  -count=1
PASS internal/verify (2.178s)
PASS internal/cli    (5.618s)

go vet ./...
PASS

go test ./... -count=1
PASS (all packages; internal/cli 48.208s, internal/verify 10.699s)
```

The tests exercise:

- real SOW APT generation, OpenPGP signing, TLS CDN serving, by-hash fetch,
  full Packages parse, exact DEB download/hash and DEB control parsing;
- real SOW YUM generation and detached signing, TLS mirrorlist serving, EL8
  gzip and EL10 zstd metadata, cross-file identity/count closure, exact RPM
  download/hash and RPM header parsing;
- publish -> canonical plan/checkpoint -> independent L3 -> independent L4
  CLI flows for APT and YUM;
- stable token-in-path L3/L4 and JSON output, plus Basic fallback, while
  proving the canonical plan is byte-identical before/after and contains no
  runtime token; token-mode probes also pass with the CDN Basic/API secret
  environment variable removed after publication;
- bad InRelease/repomd signatures, missing DEB/RPM, cross-origin mirror and
  redirect rejection, unsafe/noncanonical URL rejection, missing Basic auth,
  missing plan coverage, byte drift (exit 4), and transport outage (exit 5).

## Evidence boundary

These tests use real generated repository bytes and real HTTP/TLS protocol
paths; they are not in-memory repository mocks. They do **not** claim that a
system `apt` or `dnf` binary accepted the output, nor that Cloudflare or EdgeOne
was exercised. The disposable Linux client matrix and paid-provider PoCs remain
separate required evidence before FR-31/FR-32 or the overall Goal can be marked
complete.
