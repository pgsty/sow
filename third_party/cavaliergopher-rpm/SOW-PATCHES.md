# SOW compatibility patch

This directory is a source snapshot of
`github.com/cavaliergopher/rpm@v1.3.0`, retained under its original MIT
license.

Upstream module checksum:
`h1:UHX46sasX8MesUXXQ+UbkFLUX4eUWTlEcX8jcnRBIgI=`. The tag, checksum and this
patch ledger are the review anchors for future refreshes.

SOW narrows the copied module to its production use: bounded RPM header and
metadata parsing. The upstream `GPGCheck` helpers depended on the abandoned
`golang.org/x/crypto/openpgp` package (GO-2026-5932) and are not used by SOW, so
they are removed instead of silently substituting a verifier that cannot parse
legacy v3 RPM signatures. `GPGSignature.String` retains bounded metadata
display without making a verification claim; embedded signature bytes remain
unchanged and real `rpm -K`/DNF clients provide package-level validation.

This deliberately removes the unused GPG-checking API from the local module.
The general RPM parser API used by SOW is unchanged; the local snapshot adds
the narrow `ReadSignatureHeader` entry point described below. Repository
metadata signing and verification continue to use ProtonMail go-crypto in SOW
proper.

The snapshot also hardens the untrusted header boundary without changing valid
tag semantics:

- the lead and both RPM headers require canonical type/magic/version/reserved
  bytes, including the header-signature lead type used by modern RPM;
- fixed header/index reads use `io.ReadFull`;
- index count, per-tag ranges, aggregate decoded bytes and aggregate element
  counts are checked in a complete preflight before tag allocation;
- strings must be NUL terminated even at non-zero offsets;
- negative installed/archive sizes never wrap into `uint64`.

`ReadSignatureHeader` stops before the main RPM header and payload and applies
a separate 2 MiB raw signature-header, 256-index and bounded decoded-value
budget. Provenance inspection uses this entry point so a large untrusted main
header is never materialized once per concurrent sync worker merely to inspect
embedded signature evidence. This strict signature-only path also rejects
duplicate tag IDs instead of inheriting the general parser's historical
last-value-wins map projection.

`sow_hardening_test.go` carries allocation-bomb, malformed descriptor,
unterminated string, signed-size and fuzz regressions. `verify-upstream.sh`
checks the pinned module sum and rejects drift outside the explicit patch-file
allowlist; CI also scans this nested module independently with `govulncheck`.

When updating the upstream snapshot, run `verify-upstream.sh`, diff all patched files against the tagged source,
reapply this parser-only patch, run this module's tests, run SOW's RPM tests and
real DNF compatibility suite, and rerun `govulncheck ./...`.
