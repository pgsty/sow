#!/bin/sh
# Hermetic positive and fail-closed tests for the complete physical migration
# config/ledger. This script reads checked-in fixtures and temporary copies
# only. It never reads a legacy checkout, invokes Make, or contacts any network,
# object-storage, CDN, CO/COS, or Cloudflare resource.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CONFIG=$SCRIPT_DIR/fixtures/pigsty-v1.yaml
SYNTHETIC=$SCRIPT_DIR/fixtures/pigsty-v1-synthetic.yaml
SELECTOR=$SCRIPT_DIR/fixtures/selector-matrix.yaml
TOPOLOGY=$SCRIPT_DIR/fixtures/legacy-physical-topology.tsv
LEDGER=$SCRIPT_DIR/fixtures/pigsty-v1-migration-ledger.tsv

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
unset AWS_CONTAINER_CREDENTIALS_FULL_URI CLOUDFLARE_API_TOKEN CLOUDFLARE_API_KEY CF_API_TOKEN
unset TENCENT_SECRET_ID TENCENT_SECRET_KEY TENCENTCLOUD_SECRET_ID TENCENTCLOUD_SECRET_KEY
unset TENCENTCLOUD_SESSION_TOKEN SOW_REAL_CF_STORAGE_JSON SOW_REAL_CF_CDN_JSON
unset SOW_REAL_COS_STORAGE_JSON SOW_REAL_COS_CDN_JSON SOW_REAL_CF_LOG_STORAGE_JSON
unset SOW_REAL_COS_LOG_STORAGE_JSON SOW_REAL_CF_LOG_WRITER_JSON SOW_REAL_COS_LOG_WRITER_JSON
export AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null
export SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0
export SOW_REAL_CLOUD_PURGE_WATCHER_HELPER=0
export HTTP_PROXY=http://127.0.0.1:1 HTTPS_PROXY=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1
export NO_PROXY=127.0.0.1,localhost GOPROXY=off

go_test() {
	if [ "${SOW_PHYSICAL_MIGRATION_RACE:-0}" = 1 ]; then
		go test -race -count=1 "$@"
	else
		go test -count=1 "$@"
	fi
}

umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-physical-migration-config.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

run_contract() {
	config=$1
	topology=$2
	ledger=$3
	SOW_PHYSICAL_MIGRATION_CONFIG=$config \
	SOW_PHYSICAL_MIGRATION_TOPOLOGY=$topology \
	SOW_PHYSICAL_MIGRATION_LEDGER=$ledger \
		go_test ./internal/config -run '^TestPigstyV1PhysicalMigrationContract$'
}

expect_fail() {
	name=$1
	expected=$2
	config=$3
	topology=$4
	ledger=$5
	if run_contract "$config" "$topology" "$ledger" > "$TMP/$name.out" 2> "$TMP/$name.err"; then
		echo "expected fail-closed physical migration contract: $name" >&2
		exit 1
	fi
	if ! grep -Eq "$expected" "$TMP/$name.out" "$TMP/$name.err"; then
		echo "physical migration contract failed for the wrong reason: $name (expected /$expected/)" >&2
		cat "$TMP/$name.out" "$TMP/$name.err" >&2
		exit 1
	fi
	printf 'PASS %s\n' "$name"
}

cd "$PROJECT_ROOT"
run_contract "$CONFIG" "$TOPOLOGY" "$LEDGER"
printf 'PASS exact-physical-contract\n'

# The old 12-repo subset and 33-repo selector matrix are useful tests, but they
# must never satisfy the physical migration gate.
expect_fail synthetic-12-cannot-claim-physical 'explicit non-claim|differs|want=98|no ledger disposition' "$SYNTHETIC" "$TOPOLOGY" "$LEDGER"
expect_fail synthetic-33-cannot-claim-physical 'must not contain a cloud target|differs|want=98' "$SELECTOR" "$TOPOLOGY" "$LEDGER"

awk '!removed && $1 == "apt-index" { removed=1; next } { print }' "$TOPOLOGY" > "$TMP/missing-apt.tsv"
expect_fail missing-apt-index 'APT physical index closure differs' "$CONFIG" "$TMP/missing-apt.tsv" "$LEDGER"

awk '!changed && /active-policy-unverified/ { sub(/active-policy-unverified/, "active"); changed=1 } { print }' "$LEDGER" > "$TMP/false-lifecycle.tsv"
expect_fail lifecycle-cannot-be-overclaimed 'unknown lifecycle_evidence' "$CONFIG" "$TOPOLOGY" "$TMP/false-lifecycle.tsv"

awk '!changed && /yum-nested/ { sub(/quarantine-overlap/, "mapped-review-required"); changed=1 } { print }' "$LEDGER" > "$TMP/nested-not-quarantined.tsv"
expect_fail nested-child-must-remain-quarantined 'nested PGDG quarantine contract changed' "$CONFIG" "$TOPOLOGY" "$TMP/nested-not-quarantined.tsv"

awk '!changed && /id: yum-percona-el10/ { sub(/noarch_mode: separate/, "noarch_mode: replicate"); changed=1 } { print }' "$CONFIG" > "$TMP/percona-replicate.yaml"
expect_fail percona-noarch-must-remain-separate 'Percona noarch leaf is not separately indexed' "$TMP/percona-replicate.yaml" "$TOPOLOGY" "$LEDGER"

awk '!changed && /^  yum-pgsql:/ { sub(/\[/, "[yum-infra-legacy-compat, "); changed=1 } { print }' "$CONFIG" > "$TMP/infra-in-group.yaml"
expect_fail infra-carrier-cannot-enter-group 'quarantined YUM infra carrier entered repo group' "$TMP/infra-in-group.yaml" "$TOPOLOGY" "$LEDGER"

awk '!changed && $1 == "root-key" && $3 == "beta" { sub(/cf,cos$/, "cos"); changed=1 } { print }' "$LEDGER" > "$TMP/root-target-drift.tsv"
expect_fail root-target-affinity-is-exact 'root key target affinity beta' "$CONFIG" "$TOPOLOGY" "$TMP/root-target-drift.tsv"

go_test ./internal/cli -run '^TestPhysicalMigrationCompatibilityCarrierIsNotCLISelectable$'
printf 'PASS inactive-migration-carrier-cli-gate\n'
printf 'physical migration config hermetic suite: PASS\n'
