#!/usr/bin/env bash
# Local-only executable closure for the 44 legacy operation families.
#
# The contract test binds every family to either real CLI/filesystem/parser
# evidence or an explicit retire/policy/handoff/migration disposition. The Go
# evidence uses temporary roots plus in-memory or loopback provider/upstream
# protocols; this script forces GOPROXY=off and never reads a production cloud
# credential or invokes a legacy Make recipe. The final binary-level adoption
# and rollback test also operates entirely below a fresh temporary directory.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CONTRACT=$SCRIPT_DIR/fixtures/family-e2e.tsv
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-family-e2e.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' HUP INT TERM

if [[ ! -f "$CONTRACT" ]]; then
	echo "missing family E2E contract: $CONTRACT" >&2
	exit 1
fi

family_count=$(awk -F $'\t' 'NR > 2 && $1 ~ /^[RAYD][0-9][0-9]$/ { count++ } END { print count+0 }' "$CONTRACT")
if [[ "$family_count" != 44 ]]; then
	echo "family E2E contract has $family_count rows, want 44" >&2
	exit 1
fi

awk -F $'\t' '
	NR > 2 {
		n=split($4, evidence, ",")
		for (i=1; i<=n; i++) if (evidence[i] ~ /^Test/) print evidence[i]
	}
' "$CONTRACT" | LC_ALL=C sort -u > "$TMP/expected-tests"

(
	cd "$PROJECT_ROOT"
	GOPROXY=off go test -count=1 ./internal/cli \
		-run '^(TestLegacyMigrationFixturesUseCanonical33RepoUniverse|TestLegacyMigrationFamilyE2EContract|TestLegacyMigrationMapClosesFamiliesAndSelectors)$'
	GOPROXY=off go test ./internal/cli -list '^Test' | LC_ALL=C sort -u > "$TMP/available-tests"
)

expect_contract_reject() {
	local label=$1
	local fixture=$2
	if (
		cd "$PROJECT_ROOT"
		GOPROXY=off SOW_MIGRATION_FAMILY_CONTRACT="$fixture" \
			go test -count=1 ./internal/cli -run '^TestLegacyMigrationFamilyE2EContract$'
	) > "$TMP/negative-$label.log" 2>&1; then
		echo "family E2E contract accepted invalid fixture: $label" >&2
		cat "$TMP/negative-$label.log" >&2
		exit 1
	fi
	echo "PASS family-contract-$label"
}

awk -F $'\t' 'BEGIN { OFS=FS } $1 != "D07" { print }' "$CONTRACT" > "$TMP/missing-family.tsv"
awk -F $'\t' 'BEGIN { OFS=FS } $1 == "R03" { $4="TestHelpAndUsageCodes" } { print }' "$CONTRACT" > "$TMP/help-evidence.tsv"
awk -F $'\t' 'BEGIN { OFS=FS } $1 == "D01" { $4="contract:policy-reject" } { print }' "$CONTRACT" > "$TMP/wrong-disposition.tsv"
awk -F $'\t' 'BEGIN { OFS=FS } $1 == "R03" { $3="local-cli" } { print }' "$CONTRACT" > "$TMP/missing-provider.tsv"

expect_contract_reject missing-family "$TMP/missing-family.tsv"
expect_contract_reject help-as-business-evidence "$TMP/help-evidence.tsv"
expect_contract_reject wrong-disposition "$TMP/wrong-disposition.tsv"
expect_contract_reject publish-without-provider "$TMP/missing-provider.tsv"

if ! comm -23 "$TMP/expected-tests" "$TMP/available-tests" > "$TMP/missing-tests"; then
	exit 1
fi
if [[ -s "$TMP/missing-tests" ]]; then
	echo "family E2E contract references missing tests:" >&2
	cat "$TMP/missing-tests" >&2
	exit 1
fi

test_regex=$(paste -sd '|' "$TMP/expected-tests")
if [[ -z "$test_regex" ]]; then
	echo "family E2E contract contains no executable CLI evidence" >&2
	exit 1
fi
(
	cd "$PROJECT_ROOT"
	GOPROXY=off go test -count=1 -v ./internal/cli -run "^(${test_regex})$"
) | tee "$TMP/go-evidence.log"

while IFS= read -r test_name; do
	if ! grep -Eq "^--- PASS: ${test_name}( |$)" "$TMP/go-evidence.log"; then
		echo "family E2E evidence did not execute successfully: $test_name" >&2
		exit 1
	fi
done < "$TMP/expected-tests"

GOPROXY=off "$SCRIPT_DIR/test-local-adoption-rollback.sh" | tee "$TMP/binary-rollback.log"
grep -Fq 'zero_byte_adoption=pass' "$TMP/binary-rollback.log"
grep -Fq 'local_symlink_rollback_replay=pass' "$TMP/binary-rollback.log"

echo "migration_family_contract=pass families=$family_count"
echo "migration_family_negative_contracts=pass cases=4"
echo "migration_family_cli_evidence=pass tests=$(wc -l < "$TMP/expected-tests" | tr -d ' ')"
echo "migration_family_external_network=disabled goproxy=off provider_scope=memory_or_loopback"
echo "migration_family_production_mutation=none temp_roots_only=true"
