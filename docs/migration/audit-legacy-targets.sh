#!/bin/sh
# Read-only, fail-closed audit for the legacy Make target migration ledger.
#
# The script never invokes a Make recipe or contacts a remote service. It
# verifies the exact legacy source fingerprints and target inventory, validates
# every machine disposition in make-target-map.md, and probes every referenced
# SOW verb/flag plus the closed target/view/layer/type values against the current
# binary contract. It intentionally does not claim command-level business
# equivalence; that remains an E2E migration gate. A normalized TSV can be
# emitted only after all structural gates pass.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
LEGACY_ROOT=/Users/vonng/pgsty/repo
MAP=$SCRIPT_DIR/make-target-map.md
SOW_BIN=${SOW_BIN:-}
EMIT_TSV=
SOURCE_FINGERPRINTS=
POSITIONALS=0

usage() {
	cat >&2 <<'EOF'
usage: audit-legacy-targets.sh [LEGACY_ROOT [MAP]] [options]

options:
  --legacy-root DIR  legacy repo checkout (default /Users/vonng/pgsty/repo)
  --map FILE         migration ledger (default adjacent make-target-map.md)
  --sow-bin FILE     current SOW binary; otherwise build a temporary binary
  --emit-tsv FILE    write normalized machine map after every gate passes
  --source-fingerprints FILE
                     expected source hashes; hermetic tests only and requires
                     SOW_MIGRATION_AUDIT_FIXTURE_MODE=1 (default is the frozen
                     2026-07-12 production-source baseline)
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--legacy-root)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			LEGACY_ROOT=$2
			shift 2
			;;
		--map)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			MAP=$2
			shift 2
			;;
		--sow-bin)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			SOW_BIN=$2
			shift 2
			;;
		--emit-tsv)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			EMIT_TSV=$2
			shift 2
			;;
		--source-fingerprints)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			SOURCE_FINGERPRINTS=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		--*)
			echo "unknown option: $1" >&2
			usage
			exit 2
			;;
		*)
			POSITIONALS=$((POSITIONALS + 1))
			case "$POSITIONALS" in
				1) LEGACY_ROOT=$1 ;;
				2) MAP=$1 ;;
				*) echo "too many positional arguments" >&2; usage; exit 2 ;;
			esac
			shift
			;;
	esac
done

umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-legacy-audit.XXXXXX")
EMIT_TMP=
cleanup() {
	rm -rf "$TMP"
	if [ -n "$EMIT_TMP" ]; then
		rm -f "$EMIT_TMP"
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_file() {
	if [ ! -f "$1" ]; then
		echo "missing required audit input: $1" >&2
		exit 1
	fi
}

require_file "$MAP"
require_file "$LEGACY_ROOT/Makefile"
require_file "$LEGACY_ROOT/apt/Makefile"
require_file "$LEGACY_ROOT/apt/list/gen"
require_file "$LEGACY_ROOT/yum/Makefile"
require_file "$LEGACY_ROOT/yum/build"
require_file "$LEGACY_ROOT/docker/Makefile"
require_file "$LEGACY_ROOT/docker/Dockerfile"

if command -v sha256sum >/dev/null 2>&1; then
	hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
	hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

# Extract only ordinary, named targets. Special .PHONY declarations are not
# user operations. The misspelled .PHONE rule is audited separately.
extract_make_targets() {
	prefix=$1
	file=$2
	awk -v prefix="$prefix" '
		/^[^#[:space:]][^=]*:/ {
			if ($0 ~ /^[^#[:space:]][^:]*[:+?]?=/) next
			lhs=$0
			sub(/:.*/, "", lhs)
			n=split(lhs, names, /[[:space:]]+/)
			for (i=1; i<=n; i++) {
				if (names[i] != "" && names[i] !~ /^\./) print prefix "\t" names[i]
			}
		}
	' "$file" | LC_ALL=C sort -u
}

extract_make_targets ROOT "$LEGACY_ROOT/Makefile" > "$TMP/root"
extract_make_targets APT "$LEGACY_ROOT/apt/Makefile" > "$TMP/apt"
extract_make_targets YUM "$LEGACY_ROOT/yum/Makefile" > "$TMP/yum"
extract_make_targets DKR "$LEGACY_ROOT/docker/Makefile" > "$TMP/docker"
cat "$TMP/root" "$TMP/apt" "$TMP/yum" "$TMP/docker" | LC_ALL=C sort > "$TMP/actual"
status=0

# The prose summary's 44 operation families are an executable partition, not a
# decorative count. Every legacy target must appear exactly once across the
# family rows; a duplicate and a compensating omission must still fail.
family_count=$(awk -F '|' -v output="$TMP/family-targets" '
	function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
	$2 ~ /^[[:space:]]*(R|A|Y|D)[0-9][0-9][[:space:]]*$/ {
		family=trim($2); cell=trim($3); gsub(/`/, "", cell)
		prefix=substr(family, 1, 1)
		expected=sprintf("%s%02d", prefix, ++family_counts[prefix])
		if (family != expected) { print "expected operation family id " expected ", got " family > "/dev/stderr"; bad=1 }
		if (seen_family[family]++) { print "duplicate operation family id " family > "/dev/stderr"; bad=1 }
		n=split(cell, words, /[[:space:]]+/)
		if (n < 2) { print "family " family " has no targets" > "/dev/stderr"; bad=1; next }
		for (i=2; i<=n; i++) if (words[i] != "") print words[1] "\t" words[i] > output
		families++
	}
	END { print families+0; exit bad ? 1 : 0 }
' "$MAP") || status=1
if [ "$family_count" != 44 ]; then
	echo "unexpected operation family count: $family_count" >&2
	status=1
fi
if [ -f "$TMP/family-targets" ]; then
	LC_ALL=C sort "$TMP/family-targets" -o "$TMP/family-targets"
	if ! cmp -s "$TMP/actual" "$TMP/family-targets"; then
		echo "44-family partition differs from the exact legacy target inventory:" >&2
		comm -3 "$TMP/actual" "$TMP/family-targets" >&2 || true
		status=1
	fi
fi

if ! awk -F '|' -v documented="$TMP/documented" -v normalized="$TMP/normalized" '
	function trim(value) {
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
		return value
	}
	function fail(message) {
		print "ledger schema error line " NR ": " message > "/dev/stderr"
		bad=1
	}
	$0 ~ /^\|/ && NF >= 10 && $2 !~ /^[[:space:]]*(ROOT|APT|YUM|DKR)-[0-9]+[[:space:]]*$/ {
		candidate=trim($2)
		if (candidate != "ID" && candidate !~ /^---/) fail("unparsed target-ledger row with id " candidate)
	}
	$2 ~ /^[[:space:]]*(ROOT|APT|YUM|DKR)-[0-9]+[[:space:]]*$/ {
		id=trim($2)
		target=trim($3)
		gsub(/`/, "", target)
		replacement=trim($8)
		disposition=trim($9)
		rollback=trim($10)
		split(id, id_parts, "-")
		prefix=id_parts[1]
		expected=sprintf("%s-%02d", prefix, ++counts[prefix])
		if (id != expected) fail("expected sequential id " expected ", got " id)
		if (target == "") fail(id " has an empty target")
		if (replacement == "") fail(id " has an empty replacement")
		if (index(id, "\t") || index(target, "\t") || index(replacement, "\t") ||
		    index(disposition, "\t") || index(rollback, "\t")) fail(id " contains a tab that would corrupt TSV output")
		if (disposition != "sow-cli" && disposition != "retire" &&
		    disposition != "policy-reject" && disposition != "external-handoff" &&
		    disposition != "migration-only") fail(id " has unknown disposition " disposition)
		if (disposition == "sow-cli" && replacement !~ /`sow /) fail(id " sow-cli replacement has no executable inline command")
		if (rollback !~ /^RB-[ARPLXB](、RB-[ARPLXB])*(；[^|]+)?$/) fail(id " has an invalid rollback code list")
		key=prefix SUBSEP target
		if (seen_target[key]++) fail("duplicate source/target " prefix "/" target)
		if (seen_id[id]++) fail("duplicate id " id)
		print prefix "\t" target > documented
		print prefix "\t" id "\t" target "\t" disposition "\t" replacement "\t" rollback > normalized
	}
	END {
		if (counts["ROOT"] != 52 || counts["APT"] != 70 || counts["YUM"] != 14 || counts["DKR"] != 40) {
			fail("unexpected row counts root=" counts["ROOT"] " apt=" counts["APT"] " yum=" counts["YUM"] " docker=" counts["DKR"])
		}
		exit bad ? 1 : 0
	}
' "$MAP"; then
	status=1
fi

if [ -f "$TMP/documented" ]; then
	LC_ALL=C sort -u "$TMP/documented" -o "$TMP/documented"
	if ! cmp -s "$TMP/actual" "$TMP/documented"; then
		echo "legacy target inventory differs from the migration ledger:" >&2
		comm -3 "$TMP/actual" "$TMP/documented" >&2 || true
		status=1
	fi
fi

root_count=$(wc -l < "$TMP/root" | tr -d ' ')
apt_count=$(wc -l < "$TMP/apt" | tr -d ' ')
yum_count=$(wc -l < "$TMP/yum" | tr -d ' ')
docker_count=$(wc -l < "$TMP/docker" | tr -d ' ')
total_count=$(wc -l < "$TMP/actual" | tr -d ' ')
if [ "$root_count:$apt_count:$yum_count:$docker_count:$total_count" != "52:70:14:40:176" ]; then
	echo "unexpected target counts: root=$root_count apt=$apt_count yum=$yum_count docker=$docker_count total=$total_count" >&2
	status=1
fi

if ! grep -Fq '.PHONE:' "$LEGACY_ROOT/yum/Makefile" || ! grep -Fq 'build-extra' "$LEGACY_ROOT/yum/Makefile"; then
	echo "expected YUM .PHONE/build-extra defect changed; re-audit it" >&2
	status=1
fi

# Any recipe/source drift invalidates the semantic mapping even when the target
# names remain unchanged. Normal audits use the reviewed 2026-07-12 baseline.
# Hermetic tests may pass an explicit, closed seven-file fixture baseline; this
# avoids reading a production checkout while preserving the same fail-closed
# fingerprint comparison and source-drift negative test.
check_fingerprint() {
	relative=$1
	expected=$2
	actual=$(hash_file "$LEGACY_ROOT/$relative")
	printf '%s  %s\n' "$actual" "$relative" >> "$TMP/fingerprints"
	if [ "$actual" != "$expected" ]; then
		echo "legacy source fingerprint changed: $relative expected=$expected actual=$actual" >&2
		status=1
	fi
}

: > "$TMP/fingerprints"
if [ -n "$SOURCE_FINGERPRINTS" ]; then
	if [ "${SOW_MIGRATION_AUDIT_FIXTURE_MODE:-0}" != 1 ]; then
		echo "--source-fingerprints is restricted to explicit hermetic fixture mode" >&2
		exit 2
	fi
	require_file "$SOURCE_FINGERPRINTS"
	awk '
		BEGIN {
			expected["Makefile"]=1
			expected["apt/Makefile"]=1
			expected["apt/list/gen"]=1
			expected["yum/Makefile"]=1
			expected["yum/build"]=1
			expected["docker/Makefile"]=1
			expected["docker/Dockerfile"]=1
		}
		{
			if (NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || !($2 in expected) || seen[$2]++) {
				print "invalid source fingerprint fixture line " NR > "/dev/stderr"
				bad=1
			}
		}
		END {
			for (path in expected) if (!seen[path]) {
				print "missing source fingerprint fixture path: " path > "/dev/stderr"
				bad=1
			}
			exit bad ? 1 : 0
		}
	' "$SOURCE_FINGERPRINTS" || exit 2
	while read -r expected relative; do
		check_fingerprint "$relative" "$expected"
	done < "$SOURCE_FINGERPRINTS"
	SOURCE_FINGERPRINT_BASELINE=hermetic-fixture
else
	check_fingerprint Makefile 434851089902ebc3f0ab402c81a3b407a420a4f4ec9c8368a10494f21d4c1a8c
	check_fingerprint apt/Makefile 1077efce002f193466351f16424841a9d7eecc4e8ca61382cf4ba7b5635c8945
	check_fingerprint apt/list/gen d1f89aea35e672c10b0e0e0151035f34f2ed3d2be039d61dee10ad65393a118c
	check_fingerprint yum/Makefile 32a7800a577213e4b257a4116f75986a95a55e8b8909baa8bc54f475cb4953f3
	check_fingerprint yum/build e7837003d1498dd80d1ab7aded299c5b577399b37a8257c7e81c5427f795c27a
	check_fingerprint docker/Makefile 1629076293514cadb1fcaf8b2e734ff1b715bd9af4a086f56c3a4284e38bfd2e
	check_fingerprint docker/Dockerfile f9d821210669b82132e3232581e3aa69d98256c2e1257b30ed59ddb8f7ba4966
	SOURCE_FINGERPRINT_BASELINE=frozen-production-2026-07-12
fi

if grep -Eq '未迁移/未验证|范围缺口/未验证|待退役/未验证|策略禁止/未验证|\|[[:space:]]*unresolved[[:space:]]*\|' "$MAP"; then
	echo "migration ledger still contains an unresolved legacy status" >&2
	status=1
fi

# Freeze the reviewed semantic mapping, not just its row count. This catches a
# known-enum disposition or selector being changed while every structural gate
# still passes. Updating this digest requires an explicit re-review of all 176
# normalized rows and the evidence record.
EXPECTED_MACHINE_MAP_SHA256=54b9e81b837c4010bb16e8a25339375d57043232428a22a8019bb8703253c6ac
MACHINE_MAP_SHA256=
if [ -f "$TMP/normalized" ]; then
	{
		printf 'source\tid\ttarget\tdisposition\treplacement\trollback\n'
		cat "$TMP/normalized"
	} > "$TMP/machine-map.tsv"
	MACHINE_MAP_SHA256=$(hash_file "$TMP/machine-map.tsv")
	if [ "$MACHINE_MAP_SHA256" != "$EXPECTED_MACHINE_MAP_SHA256" ]; then
		echo "reviewed machine map digest changed: expected=$EXPECTED_MACHINE_MAP_SHA256 actual=$MACHINE_MAP_SHA256" >&2
		status=1
	fi
fi

if [ -z "$SOW_BIN" ]; then
	if ! command -v go >/dev/null 2>&1; then
		echo "go is required to validate the current SOW CLI surface (or pass --sow-bin)" >&2
		exit 1
	fi
	SOW_BIN=$TMP/sow
	if ! (cd "$PROJECT_ROOT" && go build -trimpath -o "$SOW_BIN" ./cmd/sow); then
		echo "failed to build current SOW CLI" >&2
		exit 1
	fi
else
	require_file "$SOW_BIN"
fi

if ! "$SOW_BIN" help > "$TMP/sow-help" 2> "$TMP/sow-help.err"; then
	echo "current SOW help failed" >&2
	status=1
fi
if ! CLI_IDENTITY=$("$SOW_BIN" version 2> "$TMP/sow-version.err"); then
	echo "current SOW version failed" >&2
	status=1
	CLI_IDENTITY=unavailable
fi
for verb in init add rm sync publish gc verify promote materialize fsck compatibility; do
	if ! grep -Eq "^[[:space:]]+$verb[[:space:]]" "$TMP/sow-help"; then
		echo "mapped SOW verb missing from top-level help: $verb" >&2
		status=1
	fi
	if ! "$SOW_BIN" "$verb" --help > "$TMP/sow-$verb-help.out" 2> "$TMP/sow-$verb-help.err"; then
		echo "current SOW $verb help failed" >&2
		status=1
	fi
	cat "$TMP/sow-$verb-help.out" "$TMP/sow-$verb-help.err" > "$TMP/sow-$verb-help"
done
for compatibility_verb in yum-adopt yum-candidate yum-freeze yum-cutover yum-rollback; do
	if ! "$SOW_BIN" compatibility "$compatibility_verb" --help > "$TMP/sow-compatibility-$compatibility_verb-help.out" 2> "$TMP/sow-compatibility-$compatibility_verb-help.err"; then
		echo "current SOW compatibility $compatibility_verb help failed" >&2
		status=1
	fi
	cat "$TMP/sow-compatibility-$compatibility_verb-help.out" "$TMP/sow-compatibility-$compatibility_verb-help.err" > "$TMP/sow-compatibility-$compatibility_verb-help"
done

# Extract inline command templates only from target rows. This makes the
# Markdown table both human-readable and mechanically executable as an audit
# contract without ever running a mutating command.
awk -F '|' '
	function trim(value) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value }
	$2 ~ /^[[:space:]]*(ROOT|APT|YUM|DKR)-[0-9]+[[:space:]]*$/ {
		id=trim($2); disposition=trim($9); n=split($8, parts, "`")
		for (i=2; i<=n; i+=2) if (parts[i] ~ /^sow /) print id "\t" disposition "\t" parts[i]
	}
' "$MAP" > "$TMP/commands"

TAB=$(printf '\t')
while IFS="$TAB" read -r id disposition command; do
	[ -n "$command" ] || continue
	case "$command" in
		sow\ --help) continue ;;
	esac
	verb=$(printf '%s\n' "$command" | awk '{print $2}')
	case "$verb" in
		init|add|rm|sync|publish|gc|verify|promote|materialize|fsck) ;;
		compatibility)
			compatibility_verb=$(printf '%s\n' "$command" | awk '{print $3}')
			case "$compatibility_verb" in
				yum-adopt|yum-candidate|yum-freeze|yum-cutover|yum-rollback) ;;
				*) echo "$id references unknown SOW compatibility verb in: $command" >&2; status=1; continue ;;
			esac
			;;
		*) echo "$id references unknown SOW verb in: $command" >&2; status=1; continue ;;
	esac
	if [ "$disposition" = "sow-cli" ]; then
		case "$verb" in
			add|rm|promote|materialize)
				third=$(printf '%s\n' "$command" | awk '{print $3}')
				case "$third" in ''|--*) echo "$id has incomplete positional command: $command" >&2; status=1 ;; esac
				;;
		esac
	fi
	# The generated subcommand help is the exact FlagSet surface. Inspect it
	# directly instead of combining an arbitrary flag with --help: help must
	# short-circuit before parsing/configuration even when an earlier flag is
	# unknown, so that older probe technique could no longer distinguish a stale
	# mapping from a valid no-side-effect help request.
	printf '%s\n' "$command" | tr ' ' '\n' | sed -n 's/^\(--[A-Za-z0-9-]*\).*$/\1/p' | LC_ALL=C sort -u > "$TMP/flags"
	help_file=$TMP/sow-$verb-help
	if [ "$verb" = compatibility ]; then
		help_file=$TMP/sow-compatibility-$compatibility_verb-help
	fi
	while IFS= read -r flag; do
		[ -n "$flag" ] || continue
		flag_name=${flag#--}
		if ! grep -Eq "^[[:space:]]*-$flag_name([[:space:]]|$)" "$help_file"; then
			echo "$id references undefined $verb flag $flag in: $command" >&2
			status=1
		fi
	done < "$TMP/flags"
	for enum_flag in target view layer type; do
		printf '%s\n' "$command" | awk -v wanted="--$enum_flag" '
			{
				for (i=1; i<=NF; i++) {
					if ($i == wanted && i < NF) print $(i+1)
					else if (index($i, wanted "=") == 1) print substr($i, length(wanted)+2)
				}
			}
		' > "$TMP/enum-values"
		while IFS= read -r enum_value; do
			[ -n "$enum_value" ] || continue
			old_ifs=$IFS
			IFS=,
			for enum_item in $enum_value; do
				case "$enum_flag:$verb:$enum_item" in
					target:*:cf|target:*:cos) ;;
					layer:verify:L1|layer:verify:L2|layer:verify:L3|layer:verify:L4|layer:verify:all) ;;
					type:add:auto|type:add:asset|type:add:rpm|type:add:deb) ;;
					view:init:latest|view:init:stable|view:rm:beta|view:rm:latest|view:publish:beta|view:publish:latest|view:publish:stable|view:verify:beta|view:verify:latest|view:verify:stable) ;;
					*) echo "$id references invalid $verb --$enum_flag value $enum_item in: $command" >&2; status=1 ;;
				esac
			done
			IFS=$old_ifs
		done < "$TMP/enum-values"
	done
done < "$TMP/commands"

echo "targets root=$root_count apt=$apt_count yum=$yum_count docker=$docker_count total=$total_count"
echo "operation_families=$family_count partition=exact"
echo "cli_identity=$CLI_IDENTITY"
echo "dot-rule yum=.PHONE dangling-prerequisite=build-extra (excluded from the 176 user-operation targets)"
echo "source_fingerprint_baseline=$SOURCE_FINGERPRINT_BASELINE"
if [ -f "$TMP/normalized" ]; then
	awk -F '\t' '{counts[$4]++} END {
		printf "dispositions"
		printf " sow-cli=%d", counts["sow-cli"]+0
		printf " retire=%d", counts["retire"]+0
		printf " policy-reject=%d", counts["policy-reject"]+0
		printf " external-handoff=%d", counts["external-handoff"]+0
		printf " migration-only=%d\n", counts["migration-only"]+0
	}' "$TMP/normalized"
fi
if [ -n "$MACHINE_MAP_SHA256" ]; then
	echo "machine_map_sha256=$MACHINE_MAP_SHA256"
fi
echo "source fingerprints:"
cat "$TMP/fingerprints"

if [ "$status" -ne 0 ]; then
	exit "$status"
fi

if [ -n "$EMIT_TSV" ]; then
	case "$EMIT_TSV" in
		/*) ;;
		*) echo "--emit-tsv requires an absolute output path" >&2; exit 2 ;;
	esac
	if [ -e "$EMIT_TSV" ] || [ -L "$EMIT_TSV" ]; then
		echo "refusing to overwrite emitted TSV: $EMIT_TSV" >&2
		exit 2
	fi
	EMIT_TMP=$(mktemp "$EMIT_TSV.tmp.XXXXXX")
	cp "$TMP/machine-map.tsv" "$EMIT_TMP"
	# Do not let a concurrent auditor replace another completed result between
	# the existence check above and publication.  The temp file is in the output
	# directory, so a hard link is an atomic no-clobber publish operation.
	if ! ln "$EMIT_TMP" "$EMIT_TSV"; then
		echo "refusing to publish emitted TSV because output appeared during the audit: $EMIT_TSV" >&2
		exit 1
	fi
	rm -f "$EMIT_TMP"
	EMIT_TMP=
	echo "machine_map=$EMIT_TSV rows=$total_count"
fi

echo "ledger coverage: exact"
echo "disposition closure: exact"
echo "cli surface/enums: current"
echo "cli semantic equivalence: not asserted; requires per-operation E2E"
