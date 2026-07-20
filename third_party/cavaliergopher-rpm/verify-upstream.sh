#!/usr/bin/env bash
set -euo pipefail

readonly module='github.com/cavaliergopher/rpm'
readonly version='v1.3.0'
readonly expected_sum='h1:UHX46sasX8MesUXXQ+UbkFLUX4eUWTlEcX8jcnRBIgI='
readonly local_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly upstream_cache="$(mktemp -d "${TMPDIR:-/tmp}/sow-rpm-upstream.XXXXXX")"

cleanup() {
  chmod -R u+w "$upstream_cache" 2>/dev/null || true
  rm -rf -- "$upstream_cache"
}
trap cleanup EXIT

# The pinned h1 sum below is the provenance authority for this hermetic gate.
# A fresh extraction prevents a mutable reused module directory from becoming
# a second, unauthenticated source of truth. Disable the network checksum
# service so a local read-only module proxy can reproduce the comparison; the
# downloaded zip must still match the fixed h1 before bytewise verification.
metadata="$(GOWORK=off GOSUMDB=off GOMODCACHE="$upstream_cache" go mod download -json "${module}@${version}")"
upstream_root="$(printf '%s\n' "$metadata" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
actual_sum="$(printf '%s\n' "$metadata" | sed -n 's/^[[:space:]]*"Sum": "\(.*\)",$/\1/p')"
if [[ -z "$upstream_root" || ! -d "$upstream_root" ]]; then
  echo 'unable to locate pinned upstream module' >&2
  exit 1
fi
if [[ "$actual_sum" != "$expected_sum" ]]; then
  echo "upstream module sum drift: got $actual_sum want $expected_sum" >&2
  exit 1
fi

allowed_patch() {
  case "$1" in
    README.md|doc.go|go.mod|go.sum|header.go|lead.go|package.go|signature.go|signature_test.go|SOW-PATCHES.md|sow_hardening_test.go|verify-upstream.sh)
      return 0
      ;;
  esac
  return 1
}

while IFS= read -r -d '' upstream_file; do
  relative="${upstream_file#"$upstream_root"/}"
  if allowed_patch "$relative"; then
    continue
  fi
  local_file="$local_root/$relative"
  if [[ ! -f "$local_file" ]] || ! cmp -s "$upstream_file" "$local_file"; then
    echo "unapproved rpm fork drift: $relative" >&2
    exit 1
  fi
done < <(find "$upstream_root" -type f -print0)

while IFS= read -r -d '' local_file; do
  relative="${local_file#"$local_root"/}"
  if [[ -f "$upstream_root/$relative" ]] || allowed_patch "$relative"; then
    continue
  fi
  echo "unapproved file added to rpm fork: $relative" >&2
  exit 1
done < <(find "$local_root" -type f -print0)

echo "rpm fork upstream=${version} sum=${actual_sum} drift=allowlisted"
