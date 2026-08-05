#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_IMAGE='almalinux:9@sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743'
readonly IMAGE="${IMAGE:-$DEFAULT_IMAGE}"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sow-yum-relative-pool.XXXXXX")"

cleanup() {
  if [[ "${KEEP_WORK:-0}" == 1 ]]; then
    printf 'keeping work directory: %s\n' "$WORK_DIR"
  else
    rm -rf -- "$WORK_DIR"
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || {
  printf 'error: docker is required\n' >&2
  exit 1
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull --platform linux/amd64 "$IMAGE"

printf 'host image reference: %s\n' "$IMAGE"
printf 'host image id: %s\n' "$(docker image inspect "$IMAGE" --format '{{.Id}}')"
printf 'host work directory: %s\n' "$WORK_DIR"

docker run --rm --platform linux/amd64 \
  --mount "type=bind,src=$SCRIPT_DIR,dst=/fixture,readonly" \
  --mount "type=bind,src=$WORK_DIR,dst=/work" \
  "$IMAGE" bash /fixture/run-in-container.sh
