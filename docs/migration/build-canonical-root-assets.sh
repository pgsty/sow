#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
TEMPLATE=${SCRIPT_DIR}/root-assets/canonical-bootstrap.sh.in
SOURCE_ROOT=${1:-}
OUTPUT_ROOT=${2:-}

fail() {
    printf 'canonical root asset builder: %s\n' "$*" >&2
    exit 1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail 'sha256sum or shasum is required'
    fi
}

[[ ${SOURCE_ROOT} == /* && ${OUTPUT_ROOT} == /* ]] || fail 'source and output must be absolute paths'
[[ -d ${SOURCE_ROOT} && ! -L ${SOURCE_ROOT} ]] || fail 'source must be a non-symlink directory'
CANONICAL_SOURCE=$(cd "${SOURCE_ROOT}" && pwd -P)
[[ ${CANONICAL_SOURCE} == "${SOURCE_ROOT}" ]] || fail 'source path must already be canonical'
OUTPUT_PARENT=$(dirname "${OUTPUT_ROOT}")
OUTPUT_NAME=$(basename "${OUTPUT_ROOT}")
[[ ${OUTPUT_NAME} != . && ${OUTPUT_NAME} != .. && -d ${OUTPUT_PARENT} ]] || fail 'output parent must already exist'
CANONICAL_OUTPUT_PARENT=$(cd "${OUTPUT_PARENT}" && pwd -P)
OUTPUT_ROOT=${CANONICAL_OUTPUT_PARENT}/${OUTPUT_NAME}
case "${OUTPUT_ROOT}/" in
    "${CANONICAL_SOURCE}/"*) fail 'output must not resolve inside the read-only source tree' ;;
esac
[[ ! -e ${OUTPUT_ROOT} && ! -L ${OUTPUT_ROOT} ]] || fail 'output path must not already exist'
[[ -f ${TEMPLATE} && ! -L ${TEMPLATE} ]] || fail 'canonical template is absent or unsafe'

readonly SOURCE_BASELINE=$(cat <<'EOF'
get.io 5923 90515397a3df973cf5e32f3ce29bcef73d0ede3e93819f61b5b1c8b28758f0ea
get.cc 5893 a275f2580dbbb6b21cbe228185093cf962919a085d321d2efbc17657269caca7
pig.io 5850 e933f78cd166d94f7e04ceaea5afde9f728b518c31560a972e4181b40e2a869d
pig.cc 5858 0a0dc543219ec82fbe52933fae67805b815fc9d5919eb7d0f0112544f6f037bc
pkg.io 6185 32fa7243837ea99d491ed5cf257eded8f177104914dc97099fb5f60ac27aa989
pkg.cc 6158 201a8d889b77f98894eb6a942da7042f275ccbb565492692c8e4fff2b0f94075
beta.io 5929 93599b50588c18947fc130ea156cf70264301b0988f46caeac28324d80fdee1e
beta.cc 5881 07072039c6b6a3e2ccef1a19b4b76c24c6bb55fd3c8d44b45903b40d8e0a9eb3
EOF
)

verify_sources() {
    local name expected_size expected_sha path actual_size actual_sha
    while read -r name expected_size expected_sha; do
        path=${SOURCE_ROOT}/bin/${name}
        [[ -f ${path} && ! -L ${path} ]] || fail "source ${name} is absent or unsafe"
        actual_size=$(wc -c <"${path}" | tr -d '[:space:]')
        actual_sha=$(sha256_file "${path}")
        [[ ${actual_size} == "${expected_size}" && ${actual_sha} == "${expected_sha}" ]] ||
            fail "source ${name} drifted from the reviewed ${expected_size}/${expected_sha} baseline"
    done <<<"${SOURCE_BASELINE}"
}

verify_sources
umask 077
mkdir -m 0700 "${OUTPUT_ROOT}"
[[ $(cd "${OUTPUT_ROOT}" && pwd -P) == "${OUTPUT_ROOT}" ]] || fail 'created output resolved to an unexpected directory'
STAGE=$(mktemp -d "${OUTPUT_ROOT}/.build.XXXXXX")
cleanup() {
    rm -rf "${STAGE}"
}
trap cleanup EXIT HUP INT TERM

for kind in beta get pig pkg; do
    output=${STAGE}/${kind}
    sed "s/@ASSET_KIND@/${kind}/g" "${TEMPLATE}" >"${output}"
    grep -q '@ASSET_KIND@' "${output}" && fail "template token remained in ${kind}"
    bash -n "${output}" || fail "generated ${kind} is not valid Bash"
    chmod 0755 "${output}"
done

verify_sources
for kind in beta get pig pkg; do
    mv "${STAGE}/${kind}" "${OUTPUT_ROOT}/${kind}"
done
rmdir "${STAGE}"
trap - EXIT HUP INT TERM

for kind in beta get pig pkg; do
    size=$(wc -c <"${OUTPUT_ROOT}/${kind}" | tr -d '[:space:]')
    digest=$(sha256_file "${OUTPUT_ROOT}/${kind}")
    printf 'CANONICAL_ROOT_ASSET kind=%s size=%s sha256=%s\n' "${kind}" "${size}" "${digest}"
done
