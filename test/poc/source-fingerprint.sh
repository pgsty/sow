#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT=${1:?project root is required}
OUTPUT_MANIFEST=${2:-}
PROJECT_ROOT=$(cd -- "$PROJECT_ROOT" && pwd -P)

PATH_LIST=$(mktemp "${TMPDIR:-/tmp}/sow-source-inputs.XXXXXX")
HASH_LIST=$(mktemp "${TMPDIR:-/tmp}/sow-source-hashes.XXXXXX")
cleanup() {
  rm -f -- "$PATH_LIST" "$HASH_LIST"
}
trap cleanup EXIT

(
  cd -- "$PROJECT_ROOT"
  {
    printf '%s\n' go.mod go.sum test/poc/source-fingerprint.sh
    GOWORK=off go list -deps -f '{{.Dir}}' ./cmd/sow |
      while IFS= read -r dependency_dir; do
        case "$dependency_dir" in
          "$PROJECT_ROOT")
            printf '.\n'
            ;;
          "$PROJECT_ROOT"/*)
            relative_dir=${dependency_dir#"$PROJECT_ROOT"/}
            find "$relative_dir" -type f ! -path '*/.git/*' -print
            ;;
        esac
      done
  } | LC_ALL=C sort -u >"$PATH_LIST"

  while IFS= read -r source_file; do
    if [[ "$source_file" == "." || ! -f "$source_file" ]]; then
      printf 'invalid build input path: %s\n' "$source_file" >&2
      exit 1
    fi
    digest=$(shasum -a 256 -- "$source_file" | awk '{print $1}')
    printf '%s  %s\n' "$digest" "$source_file"
  done <"$PATH_LIST" >"$HASH_LIST"
)

if [[ -n "$OUTPUT_MANIFEST" ]]; then
  install -m 0644 "$HASH_LIST" "$OUTPUT_MANIFEST"
fi
shasum -a 256 "$HASH_LIST" | awk '{print $1}'
