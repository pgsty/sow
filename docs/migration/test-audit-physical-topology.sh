#!/bin/sh
# Hermetic positive and fail-closed tests for audit-physical-topology.sh.
# All mutations happen in fresh temporary trees. No legacy checkout, Make
# recipe, network endpoint, or cloud resource is used.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AUDIT=$SCRIPT_DIR/audit-physical-topology.sh
SNAPSHOT=$SCRIPT_DIR/fixtures/physical-topology-hermetic.tsv
umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-physical-topology-test.XXXXXX")
cleanup() { chmod -R u+rwX "$TMP" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

write_text() {
	path=$1
	shift
	mkdir -p "$(dirname -- "$path")"
	printf '%s\n' "$@" > "$path"
}

build_fixture() {
	root=$1
	mkdir -p "$root"
	write_text "$root/Makefile" \
		'fixture-root-make-v1' \
		'rclone copyto bin/fileauth.txt $(CO)/fileauth.txt' \
		'rclone copyto bin/get.io $(CF)/get' \
		'rclone copyto bin/get.cc $(CO)/get' \
		'rclone copyto bin/ray $(CO)/ray' \
		'rclone sync src/ $(CF)/src/' \
		'rclone sync pkg/pig/ $(CO)/pkg/pig/'
	write_text "$root/apt/Makefile" 'fixture-apt-make-v1'
	write_text "$root/apt/list/gen" 'fixture-apt-list-gen-v1'
	write_text "$root/yum/Makefile" 'fixture-yum-make-v1'
	write_text "$root/yum/build" 'fixture-yum-build-v1'
	write_text "$root/docker/Makefile" 'fixture-docker-make-v1'
	write_text "$root/docker/Dockerfile" 'fixture-dockerfile-v1'

	write_text "$root/apt/demo/dists/stable/main/binary-amd64/Packages" 'fixture apt stable'
	write_text "$root/apt/demo/dists/testing/main/binary-arm64/Packages" 'fixture apt testing'
	write_text "$root/yum/pgdg/17/redhat/rhel-10-aarch64/repodata/repomd.xml" '<repomd>parent</repomd>'
	write_text "$root/yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64/repodata/repomd.xml" '<repomd>nested</repomd>'

	write_text "$root/bin/get.io" 'fixture get io'
	write_text "$root/bin/get.cc" 'fixture get cc'
	write_text "$root/bin/ray" 'fixture ray'
	write_text "$root/bin/fileauth.txt" 'synthetic do-not-read marker'
	mkdir -p "$root/src" "$root/pkg/pig"
	write_text "$root/pro/a.tgz" 'gated-a'
	write_text "$root/pro/b.tgz" 'gated-bb'
}

pass() { printf 'PASS %s\n' "$1"; }

expect_fail() {
	name=$1
	expected=$2
	shift 2
	if "$@" > "$TMP/$name.out" 2> "$TMP/$name.err"; then
		echo "expected fail-closed physical topology audit: $name" >&2
		exit 1
	fi
	if ! grep -Eq "$expected" "$TMP/$name.out" "$TMP/$name.err"; then
		echo "physical topology audit failed for the wrong reason: $name (expected /$expected/)" >&2
		cat "$TMP/$name.out" "$TMP/$name.err" >&2
		exit 1
	fi
	pass "$name"
}

BASE=$TMP/baseline
build_fixture "$BASE"

if [ "${SOW_PRINT_PHYSICAL_TOPOLOGY_MINI:-0}" = 1 ]; then
	"$AUDIT" --legacy-root "$BASE" --print-actual
	exit 0
fi

# The audit must neither require nor read the synthetic fileauth marker or pro
# content. Metadata stat remains possible with mode 000.
chmod 000 "$BASE/bin/fileauth.txt" "$BASE/pro/a.tgz" "$BASE/pro/b.tgz"
"$AUDIT" --legacy-root "$BASE" --snapshot "$SNAPSHOT" > "$TMP/baseline.out"
grep -Fq 'legacy physical topology audit: PASS' "$TMP/baseline.out"
grep -Fq 'migration-equivalence=not-asserted cloud-validation=not-performed' "$TMP/baseline.out"
pass hermetic-baseline-and-no-secret-read

COUNT_ROOT=$TMP/count-drift
build_fixture "$COUNT_ROOT"
write_text "$COUNT_ROOT/apt/demo/dists/extra/main/binary-amd64/Packages" 'fixture apt extra'
expect_fail count-drift \
	'physical topology count mismatch for apt-index: expected=2 actual=3' \
	"$AUDIT" --legacy-root "$COUNT_ROOT" --snapshot "$SNAPSHOT"

PATH_ROOT=$TMP/path-drift
build_fixture "$PATH_ROOT"
mkdir -p "$PATH_ROOT/apt/demo/dists/stable/main/binary-arm64"
mv "$PATH_ROOT/apt/demo/dists/stable/main/binary-amd64/Packages" \
	"$PATH_ROOT/apt/demo/dists/stable/main/binary-arm64/Packages"
expect_fail path-drift \
	'physical topology inventory differs from the reviewed snapshot' \
	"$AUDIT" --legacy-root "$PATH_ROOT" --snapshot "$SNAPSHOT"

HASH_ROOT=$TMP/hash-drift
build_fixture "$HASH_ROOT"
printf '%s\n' '# same topology, changed reviewed source' >> "$HASH_ROOT/Makefile"
expect_fail reviewed-source-hash-drift \
	'physical topology inventory differs from the reviewed snapshot' \
	"$AUDIT" --legacy-root "$HASH_ROOT" --snapshot "$SNAPSHOT"

INDEX_HASH_ROOT=$TMP/index-hash-drift
build_fixture "$INDEX_HASH_ROOT"
printf '%s\n' 'changed public index bytes' >> \
	"$INDEX_HASH_ROOT/apt/demo/dists/stable/main/binary-amd64/Packages"
expect_fail public-index-hash-drift \
	'physical topology inventory differs from the reviewed snapshot' \
	"$AUDIT" --legacy-root "$INDEX_HASH_ROOT" --snapshot "$SNAPSHOT"

UNREVIEWED_ROOT=$TMP/unreviewed-root-source
build_fixture "$UNREVIEWED_ROOT"
write_text "$UNREVIEWED_ROOT/bin/unreviewed" 'synthetic must-not-be-read marker'
chmod 000 "$UNREVIEWED_ROOT/bin/unreviewed"
printf '%s\n' 'rclone copyto bin/unreviewed $(CO)/unreviewed' >> "$UNREVIEWED_ROOT/Makefile"
expect_fail unreviewed-root-source \
	'unreviewed root exact-key source \(refusing to read it\): bin/unreviewed' \
	"$AUDIT" --legacy-root "$UNREVIEWED_ROOT" --snapshot "$SNAPSHOT"

PRO_TYPE_ROOT=$TMP/pro-type-drift
build_fixture "$PRO_TYPE_ROOT"
ln -s a.tgz "$PRO_TYPE_ROOT/pro/alias.tgz"
expect_fail gated-pro-type-drift \
	'unexpected non-regular gated pro inventory entry' \
	"$AUDIT" --legacy-root "$PRO_TYPE_ROOT" --snapshot "$SNAPSHOT"

echo 'legacy physical topology hermetic suite: PASS'
