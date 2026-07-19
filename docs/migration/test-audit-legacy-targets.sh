#!/bin/sh
# Reproducible negative tests for audit-legacy-targets.sh.
# The default path synthesizes an inert source fixture from the frozen migration
# ledger. No production checkout is read, and no Make recipe or remote operation
# is executed. An explicit first argument may select another non-production
# fixture when separately authorized.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
AUDIT=$SCRIPT_DIR/audit-legacy-targets.sh
MAP=$SCRIPT_DIR/make-target-map.md
umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-legacy-audit-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' HUP INT TERM
SOURCE_ROOT=${1:-$TMP/source}
FINGERPRINTS=$TMP/source-fingerprints.txt
export SOW_MIGRATION_AUDIT_FIXTURE_MODE=1

if command -v sha256sum >/dev/null 2>&1; then
	hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
	hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

if [ "$#" -eq 0 ]; then
	mkdir -p "$SOURCE_ROOT/apt/list" "$SOURCE_ROOT/yum" "$SOURCE_ROOT/docker"
	for source in ROOT APT YUM DKR; do
		case "$source" in
			ROOT) output=$SOURCE_ROOT/Makefile ;;
			APT) output=$SOURCE_ROOT/apt/Makefile ;;
			YUM) output=$SOURCE_ROOT/yum/Makefile ;;
			DKR) output=$SOURCE_ROOT/docker/Makefile ;;
		esac
		awk -F '|' -v wanted="$source" '
			function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
			$2 ~ "^[[:space:]]*" wanted "-[0-9]+[[:space:]]*$" {
				target=trim($3); gsub(/`/, "", target); print target ":"
			}
		' "$MAP" > "$output"
	done
	printf '%s\n' '.PHONE: build-extra' >> "$SOURCE_ROOT/yum/Makefile"
	printf '%s\n' 'inert apt list generator fixture' > "$SOURCE_ROOT/apt/list/gen"
	printf '%s\n' 'inert yum build helper fixture' > "$SOURCE_ROOT/yum/build"
	printf '%s\n' 'FROM scratch' > "$SOURCE_ROOT/docker/Dockerfile"
fi

for file in \
	Makefile \
	apt/Makefile apt/list/gen \
	yum/Makefile yum/build \
	docker/Makefile docker/Dockerfile
do
	if [ ! -f "$SOURCE_ROOT/$file" ]; then
		echo "missing legacy fixture source: $SOURCE_ROOT/$file" >&2
		exit 1
	fi
	printf '%s  %s\n' "$(hash_file "$SOURCE_ROOT/$file")" "$file" >> "$FINGERPRINTS"
done

mkdir -p "$TMP/legacy/apt/list" "$TMP/legacy/yum" "$TMP/legacy/docker"

for file in \
	Makefile \
	apt/Makefile apt/list/gen \
	yum/Makefile yum/build \
	docker/Makefile docker/Dockerfile
do
	cp "$SOURCE_ROOT/$file" "$TMP/legacy/$file"
done

SOW_BIN=$TMP/sow
(cd "$PROJECT_ROOT" && go build -trimpath -o "$SOW_BIN" ./cmd/sow)

pass() { printf 'PASS %s\n' "$1"; }

expect_fail() {
	name=$1
	expected=$2
	shift 2
	if "$@" > "$TMP/$name.out" 2> "$TMP/$name.err"; then
		echo "expected fail-closed audit: $name" >&2
		exit 1
	fi
	if ! grep -Eq "$expected" "$TMP/$name.out" "$TMP/$name.err"; then
		echo "audit failed for the wrong reason: $name (expected /$expected/)" >&2
		cat "$TMP/$name.out" "$TMP/$name.err" >&2
		exit 1
	fi
	pass "$name"
}

MACHINE_MAP=$TMP/machine-map.tsv
"$AUDIT" --legacy-root "$TMP/legacy" --map "$MAP" --sow-bin "$SOW_BIN" \
	--source-fingerprints "$FINGERPRINTS" --emit-tsv "$MACHINE_MAP" > "$TMP/baseline.out"
[ "$(wc -l < "$MACHINE_MAP" | tr -d ' ')" = 177 ]
grep -Fq 'ledger coverage: exact' "$TMP/baseline.out"
grep -Fq 'operation_families=44 partition=exact' "$TMP/baseline.out"
grep -Fq 'disposition closure: exact' "$TMP/baseline.out"
grep -Fq 'cli surface/enums: current' "$TMP/baseline.out"
grep -Fq 'cli semantic equivalence: not asserted' "$TMP/baseline.out"
grep -Fq 'source_fingerprint_baseline=hermetic-fixture' "$TMP/baseline.out"
pass baseline-and-machine-map

if SOW_MIGRATION_AUDIT_FIXTURE_MODE=0 "$AUDIT" \
	--legacy-root "$TMP/legacy" --map "$MAP" --sow-bin "$SOW_BIN" \
	--source-fingerprints "$FINGERPRINTS" \
	> "$TMP/fixture-mode-guard.out" 2> "$TMP/fixture-mode-guard.err"; then
	echo "audit accepted a fixture fingerprint baseline outside explicit fixture mode" >&2
	exit 1
fi
grep -Fq -- '--source-fingerprints is restricted to explicit hermetic fixture mode' \
	"$TMP/fixture-mode-guard.err"
pass fixture-fingerprint-mode-guard

# Inject a competing creator in the exact interval between the early output
# check and hard-link publication.  The audit must fail closed without replacing
# the competing evidence.  PATH interception avoids a timing-sensitive test.
RACE_MAP=$TMP/machine-map-race.tsv
REAL_LN=$(command -v ln)
mkdir "$TMP/race-bin"
cat > "$TMP/race-bin/ln" <<'EOF'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$2" = "$SOW_RACE_DEST" ] && [ ! -e "$2" ]; then
	printf 'competing-machine-map\n' > "$2"
fi
exec "$REAL_LN" "$@"
EOF
chmod +x "$TMP/race-bin/ln"
if PATH="$TMP/race-bin:$PATH" REAL_LN="$REAL_LN" SOW_RACE_DEST="$RACE_MAP" \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$MAP" --sow-bin "$SOW_BIN" \
	--source-fingerprints "$FINGERPRINTS" --emit-tsv "$RACE_MAP" \
	> "$TMP/emit-race.out" 2> "$TMP/emit-race.err"; then
	echo "audit replaced a concurrently created machine map" >&2
	exit 1
fi
grep -Fq 'refusing to publish emitted TSV because output appeared during the audit' "$TMP/emit-race.err"
printf 'competing-machine-map\n' > "$TMP/emit-race.expected"
cmp "$TMP/emit-race.expected" "$RACE_MAP"
pass emitted-tsv-output-race

awk '
	!changed && /^\| R01 \|/ { sub(/copy-auth/, "copy-bin"); changed=1 }
	{ print }
' "$MAP" > "$TMP/family-drift.md"
expect_fail operation-family-partition-drift \
	'44-family partition differs' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/family-drift.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

awk '
	!changed && /^\| R01 \|/ { sub(/\| R01 \|/, "| R99 |"); changed=1 }
	{ print }
' "$MAP" > "$TMP/family-id-drift.md"
expect_fail operation-family-id-drift \
	'expected operation family id' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/family-id-drift.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

cf_yum_replacement=$(awk -F '|' '$2 ~ /^[[:space:]]*ROOT-46[[:space:]]*$/ { print $8 }' "$MAP")
case "$cf_yum_replacement" in
	*'sow publish --target cf --repo yum-pgsql'*) ;;
	*) echo "ROOT-46 no longer expands to the corrected YUM-only selector" >&2; exit 1 ;;
esac
case "$cf_yum_replacement" in
	*'apt-'*) echo "ROOT-46 regressed to an APT selector" >&2; exit 1 ;;
esac
case "$cf_yum_replacement" in
	*'--repo yum-infra'*) echo "ROOT-46 regressed to an ordinary mixed-EL infra selector" >&2; exit 1 ;;
esac
pass cf-yum-selector-regression

disposition_for() {
	id=$1
	awk -F '|' -v wanted="$id" '
		function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
		trim($2) == wanted { print trim($9); found=1; exit }
		END { if (!found) exit 1 }
	' "$MAP"
}
for id in ROOT-02 ROOT-03; do
	[ "$(disposition_for "$id")" = external-handoff ] || {
		echo "$id must remain an explicit target-specific asset handoff" >&2
		exit 1
	}
done
for id in APT-18 APT-19 APT-20 APT-21 APT-22 APT-23 APT-24 APT-25 DKR-01 DKR-02 DKR-15 DKR-16; do
	[ "$(disposition_for "$id")" = retire ] || {
		echo "$id must remain retired instead of claiming non-equivalent CLI coverage" >&2
		exit 1
	}
done
grep -Fq '同一 key' "$MAP"
grep -Fq '不宣称输出等价' "$MAP"
grep -Fq '不宣称等价于容器状态' "$MAP"
pass semantic-non-equivalence-dispositions

# A recipe/source edit with the same target names must invalidate the reviewed
# semantic mapping through the pinned fingerprint gate.
printf '\n# audit drift fixture\n' >> "$TMP/legacy/apt/Makefile"
expect_fail source-fingerprint-drift \
	'legacy source fingerprint changed' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$MAP" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"
cp "$SOURCE_ROOT/apt/Makefile" "$TMP/legacy/apt/Makefile"

# Removing one target row must fail both sequential-ID and exact inventory
# checks. The awk rewrite is portable across BSD and GNU userlands.
awk '$0 !~ /^\| ROOT-52 \|/' "$MAP" > "$TMP/missing-row.md"
expect_fail missing-ledger-row \
	'expected sequential id|legacy target inventory differs' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/missing-row.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

cp "$MAP" "$TMP/unparsed-row.md"
printf '%s\n' '| ROOOT-01 | `rogue` | x | x | x | x | `sow fsck` | unresolved | RB-X |' >> "$TMP/unparsed-row.md"
expect_fail unparsed-ledger-row \
	'unparsed target-ledger row' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/unparsed-row.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

# The disposition enum is closed; typo/new states require an explicit schema
# decision instead of silently passing the retirement gate.
awk '
	!changed && /^\| ROOT-02 \|/ { sub(/\| external-handoff \|/, "| unresolved |"); changed=1 }
	{ print }
' "$MAP" > "$TMP/unknown-disposition.md"
expect_fail unknown-disposition \
	'unknown disposition|unresolved legacy status' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/unknown-disposition.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

# A different but valid disposition is also semantic drift. Structural enum
# validation alone would accept it; the reviewed normalized-map digest must not.
awk '
	!changed && /^\| ROOT-02 \|/ { sub(/\| external-handoff \|/, "| retire |"); changed=1 }
	{ print }
' "$MAP" > "$TMP/known-disposition-drift.md"
expect_fail reviewed-disposition-drift \
	'reviewed machine map digest changed' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/known-disposition-drift.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

# Command templates are checked against the actual binary. A stale or invented
# flag therefore fails before anyone can treat the mapping as executable.
awk '
	!changed && /^\| APT-01 \|/ { sub(/--repo/, "--definitely-not-a-sow-flag"); changed=1 }
	{ print }
' "$MAP" > "$TMP/stale-cli.md"
expect_fail stale-cli-flag \
	'references undefined .* flag' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/stale-cli.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

awk '
	!changed && /^\| ROOT-19 \|/ { sub(/--target cf,cos/, "--target cf,moon"); changed=1 }
	{ print }
' "$MAP" > "$TMP/invalid-enum.md"
expect_fail invalid-cli-enum \
	'invalid publish --target value moon' \
	"$AUDIT" --legacy-root "$TMP/legacy" --map "$TMP/invalid-enum.md" --sow-bin "$SOW_BIN" --source-fingerprints "$FINGERPRINTS"

(cd "$PROJECT_ROOT" && go test -count=1 ./internal/cli -run '^TestLegacyMigrationMapClosesFamiliesAndSelectors$')
pass physical-selector-golden-all-targets-and-aliases

echo 'legacy migration audit negative suite: PASS'
