#!/bin/sh
# Read-only, local-only audit of the legacy repository's physical topology.
#
# This script never invokes make, never contacts a network/cloud endpoint, and
# never opens bin/fileauth.txt.  It hashes only reviewed public source/index
# files.  Gated pro artifacts are represented by path and stat size only.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEGACY_ROOT=/Users/vonng/pgsty/repo
DEFAULT_SNAPSHOT=$SCRIPT_DIR/fixtures/legacy-physical-topology.tsv
SNAPSHOT=$DEFAULT_SNAPSHOT
PRINT_ACTUAL=0

usage() {
	cat >&2 <<'EOF'
usage: audit-physical-topology.sh [options]

options:
  --legacy-root DIR  local legacy repository root
                     (default /Users/vonng/pgsty/repo)
  --snapshot FILE    expected machine-readable TSV snapshot
  --print-actual     print normalized local inventory instead of comparing
  -h, --help         show this help

The command is read-only. It does not run Make recipes, read bin/fileauth.txt,
or access CO/COS/Cloudflare (or any other network or cloud resource).
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--legacy-root)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			LEGACY_ROOT=$2
			shift 2
			;;
		--snapshot)
			[ "$#" -ge 2 ] || { usage; exit 2; }
			SNAPSHOT=$2
			shift 2
			;;
		--print-actual)
			PRINT_ACTUAL=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage
			exit 2
			;;
	esac
done

case "$LEGACY_ROOT" in
	/*) ;;
	*) echo "legacy root must be an absolute local path: $LEGACY_ROOT" >&2; exit 2 ;;
esac

if [ ! -d "$LEGACY_ROOT" ] || [ -L "$LEGACY_ROOT" ]; then
	echo "legacy root is not a physical directory: $LEGACY_ROOT" >&2
	exit 1
fi

umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-physical-topology.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if command -v sha256sum >/dev/null 2>&1; then
	hash_public_file() { sha256sum "$1" | awk '{print $1}'; }
else
	hash_public_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

file_size() {
	if stat -f '%z' "$1" >/dev/null 2>&1; then
		stat -f '%z' "$1"
	else
		stat -c '%s' "$1"
	fi
}

require_public_file() {
	if [ ! -f "$1" ] || [ -L "$1" ]; then
		echo "missing or non-physical reviewed public file: $1" >&2
		exit 1
	fi
}

require_directory() {
	if [ ! -d "$1" ] || [ -L "$1" ]; then
		echo "missing or non-physical directory: $1" >&2
		exit 1
	fi
}

record() {
	# kind, logical path, physical path, scope/family, bytes, sha256
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$TMP/actual.unsorted"
}

: > "$TMP/actual.unsorted"

# These are reviewed public build sources.  fileauth.txt is intentionally not
# in this list and is never passed to stat or a hashing command.
for rel in \
	Makefile \
	apt/Makefile apt/list/gen \
	yum/Makefile yum/build \
	docker/Makefile docker/Dockerfile
do
	file=$LEGACY_ROOT/$rel
	require_public_file "$file"
	record source "$rel" "$rel" reviewed-public-source "$(file_size "$file")" "$(hash_public_file "$file")"
done

# An APT physical leaf is evidenced by its uncompressed Packages file.  The
# index is public metadata and therefore safe to fingerprint.
require_directory "$LEGACY_ROOT/apt"
find "$LEGACY_ROOT/apt" -type f -name Packages -print | LC_ALL=C sort > "$TMP/apt-files"
while IFS= read -r file; do
	case "$file" in
		"$LEGACY_ROOT"/apt/*/binary-*/Packages) ;;
		*) echo "unexpected APT Packages path: $file" >&2; exit 1 ;;
	esac
	rel=${file#"$LEGACY_ROOT"/}
	leaf=${rel%/Packages}
	family=${rel#apt/}
	family=${family%%/*}
	record apt-index "$leaf" "$rel" "$family" "$(file_size "$file")" "$(hash_public_file "$file")"
done < "$TMP/apt-files"

# Enumerate every repomd.xml and classify a leaf as nested when an ancestor is
# itself another repomd leaf.  This finds the PGDG rhel-10.0-aarch64 child
# without baking its path into the enumerator.
require_directory "$LEGACY_ROOT/yum"
find "$LEGACY_ROOT/yum" -type f -path '*/repodata/repomd.xml' -print | LC_ALL=C sort > "$TMP/yum-absolute-files"
: > "$TMP/yum-files"
while IFS= read -r file; do
	printf '%s\n' "${file#"$LEGACY_ROOT"/}" >> "$TMP/yum-files"
done < "$TMP/yum-absolute-files"
while IFS= read -r rel; do
	file=$LEGACY_ROOT/$rel
	leaf=${rel%/repodata/repomd.xml}
	family=${rel#yum/}
	family=${family%%/*}
	kind=yum-repomd
	ancestor=${leaf%/*}
	while [ "$ancestor" != "$leaf" ] && [ "$ancestor" != yum ]; do
		if grep -Fqx "$ancestor/repodata/repomd.xml" "$TMP/yum-files"; then
			kind=yum-repomd-nested
			break
		fi
		leaf=$ancestor
		ancestor=${leaf%/*}
	done
	record "$kind" "${rel%/repodata/repomd.xml}" "$rel" "$family" "$(file_size "$file")" "$(hash_public_file "$file")"
done < "$TMP/yum-files"

# Parse root exact-object ownership from the reviewed Makefile without running
# it.  Only this closed allowlist may be hashed.  The legacy credential file is
# skipped before any filesystem operation.
awk '
	$1 == "rclone" && $2 == "copyto" {
		source=$3; dest=$4
		if (source == "bin/fileauth.txt") next
		if (index(dest, "$(CF)/") == 1) { scope="cf"; logical=substr(dest, 7) }
		else if (index(dest, "$(CO)/") == 1) { scope="co"; logical=substr(dest, 7) }
		else next
		if (logical != "" && index(logical, "/") == 0) print "/" logical "\t" source "\t" scope
	}
' "$LEGACY_ROOT/Makefile" | LC_ALL=C sort -u > "$TMP/root-key-sources"
while IFS="$(printf '\t')" read -r logical source scope; do
	case "$source" in
		bin/get.io|bin/get.cc|bin/pig.io|bin/pig.cc|bin/pkg.io|bin/pkg.cc|bin/beta.io|bin/beta.cc|bin/claude|bin/ray) ;;
		*) echo "unreviewed root exact-key source (refusing to read it): $source" >&2; exit 1 ;;
	esac
	file=$LEGACY_ROOT/$source
	require_public_file "$file"
	record root-key-source "$logical" "$source" "$scope" "$(file_size "$file")" "$(hash_public_file "$file")"
done < "$TMP/root-key-sources"

# Root directory-prefix ownership is also extracted from upload recipes.  A
# remote operand must occur after the local operand, which excludes co-pro-get.
awk '
	$1 == "rclone" && ($2 == "copy" || $2 == "sync") {
		local=""; remote=""; local_i=0; remote_i=0
		for (i=3; i<=NF; i++) {
			if (remote == "" && (index($i, "$(CF)/") == 1 || index($i, "$(CO)/") == 1)) {
				remote=$i; remote_i=i
			} else if (local == "" && $i !~ /^-/ && $i ~ /\/$/ && index($i, "$(") != 1) {
				local=$i; local_i=i
			}
		}
		if (local == "" || remote == "" || local_i >= remote_i) next
		if (index(remote, "$(CF)/") == 1) { scope="cf"; logical=substr(remote, 7) }
		else { scope="co"; logical=substr(remote, 7) }
		if (logical !~ /\/$/) next
		top=logical; sub(/\/.*/, "", top)
		if (top == "apt" || top == "yum" || top == "pro") next
		print "/" logical "\t" local "\t" scope
	}
' "$LEGACY_ROOT/Makefile" | LC_ALL=C sort -u > "$TMP/root-prefix-sources"
while IFS="$(printf '\t')" read -r logical source scope; do
	case "$source" in
		img/|ext/|src/|pkg/pig/|pkg/claude/|pkg/ray/|etc/|dba/) ;;
		*) echo "unreviewed root directory-prefix source: $source" >&2; exit 1 ;;
	esac
	require_directory "$LEGACY_ROOT/${source%/}"
	record root-prefix-source "$logical" "$source" "$scope" - -
done < "$TMP/root-prefix-sources"

# Pro artifacts are gated inventory.  Record only path and stat size: do not
# open or hash their contents.
require_directory "$LEGACY_ROOT/pro"
find "$LEGACY_ROOT/pro" -mindepth 1 ! -type f -print | LC_ALL=C sort > "$TMP/pro-non-files"
if [ -s "$TMP/pro-non-files" ]; then
	echo 'unexpected non-regular gated pro inventory entry:' >&2
	sed -n '1,20p' "$TMP/pro-non-files" >&2
	exit 1
fi
find "$LEGACY_ROOT/pro" -type f -print | LC_ALL=C sort > "$TMP/pro-files"
while IFS= read -r file; do
	rel=${file#"$LEGACY_ROOT"/}
	record pro-file "/$rel" "$rel" gated-metadata-only "$(file_size "$file")" -
done < "$TMP/pro-files"

if grep -Fq 'fileauth.txt' "$TMP/actual.unsorted"; then
	echo 'internal error: forbidden credential path entered the inventory' >&2
	exit 1
fi

LC_ALL=C sort "$TMP/actual.unsorted" > "$TMP/actual"

if [ "$PRINT_ACTUAL" -eq 1 ]; then
	cat "$TMP/actual"
	exit 0
fi

if [ ! -f "$SNAPSHOT" ] || [ -L "$SNAPSHOT" ]; then
	echo "missing or non-physical topology snapshot: $SNAPSHOT" >&2
	exit 1
fi

awk '
	/^#/ || /^[[:space:]]*$/ { next }
	BEGIN { FS="\t" }
	NF != 6 { print "invalid snapshot row at line " NR ": expected 6 tab-separated fields" > "/dev/stderr"; bad=1 }
	{ print }
	END { exit bad ? 1 : 0 }
' "$SNAPSHOT" > "$TMP/expected.unsorted"
LC_ALL=C sort "$TMP/expected.unsorted" > "$TMP/expected"
if ! cmp -s "$TMP/expected.unsorted" "$TMP/expected"; then
	echo "snapshot data rows are not in canonical C-locale order: $SNAPSHOT" >&2
	exit 1
fi

count_inventory() {
	file=$1
	category=$2
	case "$category" in
		apt-index)
			awk -F '\t' '$1 == "apt-index" { n++ } END { print n+0 }' "$file"
			;;
		yum-repomd-total)
			awk -F '\t' '$1 == "yum-repomd" || $1 == "yum-repomd-nested" { n++ } END { print n+0 }' "$file"
			;;
		yum-repomd-nested)
			awk -F '\t' '$1 == "yum-repomd-nested" { n++ } END { print n+0 }' "$file"
			;;
		root-exact-key)
			awk -F '\t' '$1 == "root-key-source" { print $2 }' "$file" | LC_ALL=C sort -u | awk 'END { print NR+0 }'
			;;
		root-directory-prefix)
			awk -F '\t' '$1 == "root-prefix-source" { print $2 }' "$file" | LC_ALL=C sort -u | awk 'END { print NR+0 }'
			;;
		pro-file)
			awk -F '\t' '$1 == "pro-file" { n++ } END { print n+0 }' "$file"
			;;
		*) echo "unknown snapshot count category: $category" >&2; exit 1 ;;
	esac
}

for category in apt-index yum-repomd-total yum-repomd-nested root-exact-key root-directory-prefix pro-file; do
	expected_count=$(awk -v wanted="$category" '$1 == "#" && $2 == "count" && $3 == wanted { print $4; n++ } END { if (n != 1) exit 1 }' "$SNAPSHOT") || {
		echo "snapshot must contain exactly one '# count $category N' directive" >&2
		exit 1
	}
	case "$expected_count" in *[!0-9]*|'') echo "invalid count for $category: $expected_count" >&2; exit 1 ;; esac
	snapshot_count=$(count_inventory "$TMP/expected" "$category")
	actual_count=$(count_inventory "$TMP/actual" "$category")
	if [ "$snapshot_count" != "$expected_count" ]; then
		echo "snapshot count mismatch for $category: directive=$expected_count rows=$snapshot_count" >&2
		exit 1
	fi
	if [ "$actual_count" != "$expected_count" ]; then
		echo "physical topology count mismatch for $category: expected=$expected_count actual=$actual_count" >&2
		exit 1
	fi
done

# The checked-in canonical fixture is the reviewed 2026-07-14 source contract.
# Custom snapshots are supported for hermetic tests, but cannot weaken these
# exact production-source inventory facts.
if [ "$SNAPSHOT" = "$DEFAULT_SNAPSHOT" ]; then
	[ "$(count_inventory "$TMP/actual" apt-index)" = 74 ] || exit 1
	[ "$(count_inventory "$TMP/actual" yum-repomd-total)" = 131 ] || exit 1
	[ "$(count_inventory "$TMP/actual" yum-repomd-nested)" = 1 ] || exit 1
	[ "$(count_inventory "$TMP/actual" root-exact-key)" = 7 ] || exit 1
	[ "$(count_inventory "$TMP/actual" root-directory-prefix)" = 8 ] || exit 1
	[ "$(count_inventory "$TMP/actual" pro-file)" = 16 ] || exit 1

	awk -F '\t' '$1 == "apt-index" { print $4 }' "$TMP/actual" | LC_ALL=C sort | uniq -c | awk '{ print $2 "=" $1 }' > "$TMP/apt-family"
	printf '%s\n' infra=2 mssql=6 percona=12 pgdg=40 pgsql=14 > "$TMP/apt-family.expected"
	LC_ALL=C sort "$TMP/apt-family.expected" -o "$TMP/apt-family.expected"
	cmp -s "$TMP/apt-family.expected" "$TMP/apt-family" || { echo 'canonical APT family distribution changed' >&2; exit 1; }

	awk -F '\t' '$1 == "yum-repomd" || $1 == "yum-repomd-nested" { print $4 }' "$TMP/actual" | LC_ALL=C sort | uniq -c | awk '{ print $2 "=" $1 }' > "$TMP/yum-family"
	printf '%s\n' gpsql=3 infra=2 mssql=5 percona=9 pgdg=105 pgsql=7 > "$TMP/yum-family.expected"
	LC_ALL=C sort "$TMP/yum-family.expected" -o "$TMP/yum-family.expected"
	cmp -s "$TMP/yum-family.expected" "$TMP/yum-family" || { echo 'canonical YUM family distribution changed' >&2; exit 1; }

	awk -F '\t' '$1 == "yum-repomd-nested" { print $2 }' "$TMP/actual" > "$TMP/nested"
	printf '%s\n' 'yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64' > "$TMP/nested.expected"
	cmp -s "$TMP/nested.expected" "$TMP/nested" || { echo 'canonical PGDG nested child changed' >&2; exit 1; }

	awk -F '\t' '$1 == "root-key-source" { print $2 }' "$TMP/actual" | LC_ALL=C sort -u > "$TMP/root-keys"
	printf '%s\n' /beta /cc /claude /get /pig /pkg /ray | LC_ALL=C sort > "$TMP/root-keys.expected"
	cmp -s "$TMP/root-keys.expected" "$TMP/root-keys" || { echo 'canonical root exact-key set changed' >&2; exit 1; }

	awk -F '\t' '$1 == "root-prefix-source" { print $2 }' "$TMP/actual" | LC_ALL=C sort -u > "$TMP/root-prefixes"
	printf '%s\n' /dba/ /etc/ /ext/ /img/ /pkg/claude/ /pkg/pig/ /pkg/ray/ /src/ | LC_ALL=C sort > "$TMP/root-prefixes.expected"
	cmp -s "$TMP/root-prefixes.expected" "$TMP/root-prefixes" || { echo 'canonical root directory-prefix set changed' >&2; exit 1; }
fi

if ! cmp -s "$TMP/expected" "$TMP/actual"; then
	echo 'physical topology inventory differs from the reviewed snapshot:' >&2
	diff -u "$TMP/expected" "$TMP/actual" >&2 || true
	exit 1
fi

echo 'legacy physical topology audit: PASS'
echo "apt_indices=$(count_inventory "$TMP/actual" apt-index) yum_repodata=$(count_inventory "$TMP/actual" yum-repomd-total) yum_nested=$(count_inventory "$TMP/actual" yum-repomd-nested)"
echo "root_exact_keys=$(count_inventory "$TMP/actual" root-exact-key) root_directory_prefixes=$(count_inventory "$TMP/actual" root-directory-prefix) pro_files=$(count_inventory "$TMP/actual" pro-file)"
echo 'scope=current-local-source-inventory migration-equivalence=not-asserted cloud-validation=not-performed'
