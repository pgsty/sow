#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly allowlist="$root/test/compat/deadcode-binary-allowlist.txt"

cd "$root"
diff -u "$allowlist" <(
  # Pin the release analysis platform so the exact allowlist is identical on
  # Darwin developer hosts and Linux CI runners.
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 deadcode ./... |
    sed -E 's/^([^:]+):[0-9]+:[0-9]+: unreachable func: /\1: /' |
    LC_ALL=C sort
)
