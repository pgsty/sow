#!/usr/bin/env bash
# Produce a deterministic SHA-256 inventory of serving bytes without modifying
# the repository. Reviewed secret-bearing files are omitted without opening or
# hashing them; suspicious unreviewed names fail before the byte scan starts.
# Paths containing newlines are rejected to keep the TSV exact.
# The caller must freeze all writers for the entire scan: per-file size guards
# detect common concurrent writes but cannot make a multi-file tree snapshot
# atomic or detect every same-size rewrite outside the hash interval.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 ROOT OUTPUT.tsv [ADDITIONAL-SENSITIVE-PATHS]" >&2
	exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$1
OUTPUT=$2
DEFAULT_SENSITIVE_PATHS=$SCRIPT_DIR/fixtures/legacy-sensitive-paths.txt
ADDITIONAL_SENSITIVE_PATHS=${3:-}
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P)
case "$OUTPUT" in
	/*) ;;
	*)
		echo "output must be an absolute path outside the repository root" >&2
		exit 2
		;;
esac
OUT_DIR=$(dirname -- "$OUTPUT")
if [[ ! -d "$OUT_DIR" ]]; then
	echo "output directory must already exist: $OUT_DIR" >&2
	exit 2
fi
OUT_DIR=$(CDPATH= cd -- "$OUT_DIR" && pwd -P)
OUT_NAME=$(basename -- "$OUTPUT")
if [[ "$OUT_NAME" == "." || "$OUT_NAME" == ".." || "$OUT_NAME" == *$'\n'* ]]; then
	echo "unsafe output filename" >&2
	exit 2
fi
OUTPUT=$OUT_DIR/$OUT_NAME
if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
	echo "refusing to overwrite output: $OUTPUT" >&2
	exit 2
fi
case "$OUTPUT" in
	"$ROOT"|"$ROOT"/*)
		echo "output must be outside the repository root" >&2
		exit 2
		;;
esac

validate_sensitive_list() {
	local list=$1
	if [[ ! -f "$list" || -L "$list" ]]; then
		echo "sensitive-path list must be a regular non-symlink file: $list" >&2
		exit 2
	fi
	if [[ $(wc -c < "$list" | tr -d ' ') -gt 1048576 ]]; then
		echo "sensitive-path list exceeds 1 MiB: $list" >&2
		exit 2
	fi
}
validate_sensitive_list "$DEFAULT_SENSITIVE_PATHS"
if [[ -n "$ADDITIONAL_SENSITIVE_PATHS" ]]; then
	validate_sensitive_list "$ADDITIONAL_SENSITIVE_PATHS"
fi

if command -v sha256sum >/dev/null 2>&1; then
	hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
	hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

umask 077
SENSITIVE_RAW=$(mktemp "$OUTPUT.sensitive.XXXXXX")
SENSITIVE_SORTED=$(mktemp "$OUTPUT.sensitive-sorted.XXXXXX")
TMP=
SORTED=
cleanup() {
	if [[ -n "$TMP" ]]; then rm -f "$TMP"; fi
	if [[ -n "$SORTED" ]]; then rm -f "$SORTED"; fi
	rm -f "$SENSITIVE_RAW" "$SENSITIVE_SORTED"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

append_sensitive_paths() {
	local list=$1 line
	while IFS= read -r line || [[ -n "$line" ]]; do
		case "$line" in
			''|'#'*) continue ;;
		esac
		if [[ "$line" != "${line#${line%%[![:space:]]*}}" || "$line" != "${line%${line##*[![:space:]]}}" ]]; then
			echo "sensitive path has surrounding whitespace: $list" >&2
			exit 2
		fi
		case "$line" in
			/*|.|..|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*$'\t'*|*$'\r'*)
				echo "unsafe repository-relative sensitive path in $list: $line" >&2
				exit 2
				;;
		esac
		printf '%s\n' "$line" >> "$SENSITIVE_RAW"
	done < "$list"
}

append_sensitive_paths "$DEFAULT_SENSITIVE_PATHS"
if [[ -n "$ADDITIONAL_SENSITIVE_PATHS" ]]; then
	append_sensitive_paths "$ADDITIONAL_SENSITIVE_PATHS"
fi
LC_ALL=C sort -u "$SENSITIVE_RAW" > "$SENSITIVE_SORTED"
if [[ $(wc -l < "$SENSITIVE_SORTED" | tr -d ' ') -gt 4096 ]]; then
	echo "sensitive-path closure exceeds 4096 entries" >&2
	exit 2
fi

SENSITIVE_PATHS=()
while IFS= read -r path; do
	SENSITIVE_PATHS+=("$path")
done < "$SENSITIVE_SORTED"

is_sensitive_path() {
	local candidate=$1 reviewed
	for reviewed in "${SENSITIVE_PATHS[@]}"; do
		if [[ "$candidate" == "$reviewed" ]]; then
			return 0
		fi
	done
	return 1
}

looks_sensitive() {
	local base=${1##*/}
	case "$base" in
		key|private.asc|private.gpg|private.pgp|fileauth.txt|credentials|credentials.json|credentials.yaml|credentials.yml|secrets.json|secrets.yaml|secrets.yml|.env|.env.*|.netrc|.npmrc|.pypirc|.htpasswd|id_rsa|id_ed25519|*.pem|*.key)
			return 0
			;;
	esac
	return 1
}

# A byte inventory that silently omits symlinks, devices, sockets, or FIFOs is
# not a migration baseline. Adoption rejects those entries too, so fail before
# producing an apparently complete TSV.
unsupported=$(find "$ROOT" \
	\( -path "$ROOT/.sow" -o -path "$ROOT/.sow/*" \
	   -o -path "$ROOT/.pool" -o -path "$ROOT/.pool/*" \
	   -o -path "$ROOT/.git" -o -path "$ROOT/.git/*" \) -prune \
	-o ! -type d ! -type f -print -quit)
if [[ -n "$unsupported" ]]; then
	echo "repository contains an unsupported non-regular entry: $unsupported" >&2
	exit 1
fi

# Fail before hashing any ordinary file when the tree contains a suspicious
# path that has not been explicitly reviewed. This prevents a typo or newly
# introduced credential filename from silently becoming a digest oracle.
find "$ROOT" \
	\( -path "$ROOT/.sow" -o -path "$ROOT/.sow/*" \
	   -o -path "$ROOT/.pool" -o -path "$ROOT/.pool/*" \
	   -o -path "$ROOT/.git" -o -path "$ROOT/.git/*" \) -prune \
	-o -type f -print0 |
while IFS= read -r -d '' file; do
	rel=${file#"$ROOT"/}
	if looks_sensitive "$rel" && ! is_sensitive_path "$rel"; then
		echo "sensitive-looking path is not in the reviewed exclusion list: $rel" >&2
		exit 1
	fi
done

TMP=$(mktemp "$OUTPUT.tmp.XXXXXX")
SORTED=$(mktemp "$OUTPUT.sorted.XXXXXX")

find "$ROOT" \
	\( -path "$ROOT/.sow" -o -path "$ROOT/.sow/*" \
	   -o -path "$ROOT/.pool" -o -path "$ROOT/.pool/*" \
	   -o -path "$ROOT/.git" -o -path "$ROOT/.git/*" \) -prune \
	-o -type f -print0 |
while IFS= read -r -d '' file; do
	if [[ "$file" == *$'\n'* || "$file" == *$'\t'* ]]; then
		echo "repository contains a tab/newline in a path; cannot encode exact TSV" >&2
		exit 1
	fi
	rel=${file#"$ROOT"/}
	# A reviewed sensitive path contributes no bytes or metadata to migration
	# evidence. Candidate trees intentionally omit these non-serving files, so
	# before/after comparisons remain about the public serving namespace.
	if is_sensitive_path "$rel"; then
		continue
	fi
	size_before=$(wc -c < "$file" | tr -d ' ')
	digest=$(hash_file "$file")
	size_after=$(wc -c < "$file" | tr -d ' ')
	if [[ "$size_before" != "$size_after" ]]; then
		echo "repository file changed size while hashing: $file" >&2
		exit 1
	fi
	printf '%s\t%s\t%s\n' "$rel" "$size_after" "$digest" >> "$TMP"
done

LC_ALL=C sort "$TMP" > "$SORTED"
# Publish with one no-clobber filesystem operation.  A second writer may create
# OUTPUT after the early existence check; rename(2) would silently replace that
# evidence.  SORTED is deliberately created beside OUTPUT so hard-linking is
# atomic, cannot cross filesystems, and fails when any path already exists.
if ! ln "$SORTED" "$OUTPUT"; then
	echo "refusing to publish snapshot because output appeared during the scan: $OUTPUT" >&2
	exit 1
fi
rm -f "$SORTED"
SORTED=
echo "snapshot=$OUTPUT files=$(wc -l < "$OUTPUT" | tr -d ' ')"
