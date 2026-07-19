# Digest-bound external builder handoff evidence (2026-07-17)

## Result

SOW now admits external builder output through the normal `add` command while
binding each positional file to a caller-provided
`sha256:<lowercase-64-hex>:<size>` identity. The implementation reuses the
authenticated expected-object path already used by upstream sync for DEB/RPM,
and applies the same check before asset CAS import.

Focused integration run:

```text
$ go test -timeout 10m -count=1 -run '^TestBuilderHandoff' ./internal/cli
ok github.com/pgsty/sow/internal/cli 4.237s
```

The run covered:

- strict one-to-one/order parsing, including count, algorithm, case, size and
  duplicate-input negatives;
- an asset digest mismatch that returned exit 4 with canonical HEAD and CAS
  byte-for-byte unchanged;
- successful asset admission and hardlink materialization;
- a real DEB fixture through package inspection, APT metadata generation and
  repository signing;
- a real embedded-signature RPM fixture through package-keyring verification,
  YUM metadata generation and repository signing;
- successful receipt output only after the complete add path returned success.

All inputs and state were disposable temporary files. No production tree,
Cloudflare, CO/COS, remote origin or external package-building tool was read or
written by this gate.

## Boundary

This closes the generic local executable handoff mechanism. The later
[shared ROOT canonical builder](2026-07-17-root-shared-canonical-builder-handoff.md)
uses this exact boundary to replace the historical `.io/.cc` split with four
deterministic bodies. Neither result proves production URL/cutover: the builder
receipt, SOW receipt/canonical commit and eventual provider evidence must still
be archived together.
