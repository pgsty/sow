#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT_DIR=${1:-"${TMPDIR:-/tmp}/sow-clean-delivery"}

command -v go >/dev/null 2>&1 || {
  echo "required tool is unavailable: go" >&2
  exit 1
}

cd "$ROOT"
exec go run ./test/compat/cleandelivery --root "$ROOT" --out "$OUT_DIR"
