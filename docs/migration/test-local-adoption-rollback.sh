#!/usr/bin/env bash
# Non-destructive local migration fixture proving:
#   1. init --adopt-content is byte-for-byte zero rewrite;
#   2. materialize can build an isolated candidate tree;
#   3. a serving-root symlink can be switched back to the untouched legacy tree.
#
# This is not a production Nginx/cloud rollback test. Everything lives under a
# fresh temporary directory and no remote service is contacted.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
# Materialize persists an Nginx route receipt and therefore intentionally
# rejects roots hidden below macOS's per-user 0700 TMPDIR. Use a public,
# worker-traversable system temp parent while keeping the unique fixture local.
case "$(uname -s)" in
	Darwin) TMP_PARENT=/private/tmp ;;
	*) TMP_PARENT=/tmp ;;
esac
TMP=$(mktemp -d "$TMP_PARENT/sow-local-rollback.XXXXXX")
TMP=$(CDPATH= cd -- "$TMP" && pwd -P)
chmod 0755 "$TMP"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' HUP INT TERM

LEGACY=$TMP/legacy
# Explicit --target directories must be ordinary, dedicated children of the
# repository root.  The CLI-owned .sow control tree is intentionally reserved;
# use a migration-only sibling namespace that the origin allowlist denies.
STAGED=$LEGACY/.sow-migration-staging/rollback-candidate
CURRENT=$TMP/current
CONFIG=$TMP/sow.yaml
SOW_BIN=$TMP/sow
mkdir -p "$LEGACY/pkg/pig"
mkdir -p "$STAGED"
chmod 0755 "$LEGACY" "$LEGACY/.sow-migration-staging" "$STAGED"
printf '4.0.0\n' > "$LEGACY/pkg/pig/latest"
printf 'release-bytes-v4\n' > "$LEGACY/pkg/pig/pigsty-pkg-v4.0.0.tgz"
# A real legacy checkout contains local credentials/signing material beside the
# serving tree. The baseline and SOW adoption must not open it. Mode 000 makes
# an accidental hash/read deterministic instead of relying on access times.
printf 'synthetic-secret-must-never-be-read\n' > "$LEGACY/key"
chmod 000 "$LEGACY/key"

sensitive_stat() {
	case "$(uname -s)" in
		Darwin) stat -f '%i:%m:%p' "$1" ;;
		*) stat -c '%i:%Y:%f' "$1" ;;
	esac
}
SENSITIVE_BEFORE=$(sensitive_stat "$LEGACY/key")

cat > "$CONFIG" <<'YAML'
schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: release, mutable_paths: [pig/latest]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://migration-fixture}
YAML

(cd "$PROJECT_ROOT" && go build -trimpath -o "$SOW_BIN" ./cmd/sow)

"$SCRIPT_DIR/snapshot-serving-tree.sh" "$LEGACY" "$TMP/serving-before.tsv" >/dev/null
if grep -Fq $'key\t' "$TMP/serving-before.tsv"; then
	echo "snapshot persisted excluded sensitive-path evidence" >&2
	exit 1
fi
"$SOW_BIN" init --adopt-content \
	--config "$CONFIG" --root "$LEGACY" --repo assets --view latest --workers 2 \
	> "$TMP/adopt-first.out"
grep -Fq 'serving_tree_rewritten=false' "$TMP/adopt-first.out"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$LEGACY" "$TMP/serving-after-adopt.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-after-adopt.tsv"
test "$(sensitive_stat "$LEGACY/key")" = "$SENSITIVE_BEFORE"

"$SOW_BIN" init --adopt-content \
	--config "$CONFIG" --root "$LEGACY" --repo assets --view latest --workers 2 \
	> "$TMP/adopt-replay.out"
grep -Fq 'changed=false' "$TMP/adopt-replay.out"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$LEGACY" "$TMP/serving-after-replay.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-after-replay.tsv"
test "$(sensitive_stat "$LEGACY/key")" = "$SENSITIVE_BEFORE"
"$SOW_BIN" fsck --config "$CONFIG" --root "$LEGACY" --repo assets > "$TMP/fsck.out"

"$SOW_BIN" materialize latest \
	--config "$CONFIG" --root "$LEGACY" --repo assets --target "$STAGED" --workers 2 \
	> "$TMP/materialize.out"
"$SOW_BIN" verify --layer L1 \
	--config "$CONFIG" --root "$LEGACY" --repo assets --view latest \
	> "$TMP/verify.out"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$STAGED" "$TMP/serving-staged.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-staged.tsv"

atomic_replace_link() {
	target=$1
	link=$2
	next=$link.next
	rm -f "$next"
	ln -s "$target" "$next"
	case "$(uname -s)" in
		Darwin) mv -h -f "$next" "$link" ;;
		*) mv -T -f "$next" "$link" ;;
	esac
}

ln -s "$LEGACY" "$CURRENT"
atomic_replace_link "$STAGED" "$CURRENT"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$CURRENT" "$TMP/serving-after-switch.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-after-switch.tsv"

# Simulate a bad post-switch candidate without mutating the hardlinked CAS
# object. Detection uses the same deterministic serving-byte inventory as the
# production runbook, then rollback replaces only the external root link; the
# untouched legacy tree is never copied over.
rm "$STAGED/pkg/pig/latest"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$CURRENT" "$TMP/serving-bad-candidate.tsv" >/dev/null
if cmp -s "$TMP/serving-before.tsv" "$TMP/serving-bad-candidate.tsv"; then
	echo "corrupt candidate was not detected" >&2
	exit 1
fi
atomic_replace_link "$LEGACY" "$CURRENT"
# Preserve the failed candidate for diagnosis, but move the migration-only
# namespace outside the active legacy origin before claiming a whole-tree byte
# match.  Keeping it below LEGACY would make the baseline comparison dishonest
# even when the public allowlist denied it.
mv "$LEGACY/.sow-migration-staging" "$TMP/failed-candidate-evidence"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$CURRENT" "$TMP/serving-after-rollback.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-after-rollback.tsv"
atomic_replace_link "$LEGACY" "$CURRENT"
"$SCRIPT_DIR/snapshot-serving-tree.sh" "$CURRENT" "$TMP/serving-after-rollback-replay.tsv" >/dev/null
cmp "$TMP/serving-before.tsv" "$TMP/serving-after-rollback-replay.tsv"

mkdir "$TMP/unsafe-tree"
printf 'target\n' > "$TMP/unsafe-tree/target"
ln -s target "$TMP/unsafe-tree/link"
if "$SCRIPT_DIR/snapshot-serving-tree.sh" "$TMP/unsafe-tree" "$TMP/unsafe.tsv" > "$TMP/unsafe.out" 2> "$TMP/unsafe.err"; then
	echo "snapshot silently ignored a symlink" >&2
	exit 1
fi
grep -Fq 'unsupported non-regular entry' "$TMP/unsafe.err"

# A suspicious name that is not in the reviewed list fails before byte hashing.
# An explicit path-only review can then exclude it without persisting its path,
# size, digest, or contents in the serving evidence.
mkdir "$TMP/unreviewed-secret-tree"
printf 'synthetic-unreviewed-secret\n' > "$TMP/unreviewed-secret-tree/credentials.json"
chmod 000 "$TMP/unreviewed-secret-tree/credentials.json"
if "$SCRIPT_DIR/snapshot-serving-tree.sh" \
	"$TMP/unreviewed-secret-tree" "$TMP/unreviewed-secret.tsv" \
	> "$TMP/unreviewed-secret.out" 2> "$TMP/unreviewed-secret.err"; then
	echo "snapshot accepted an unreviewed sensitive-looking path" >&2
	exit 1
fi
grep -Fq 'sensitive-looking path is not in the reviewed exclusion list' "$TMP/unreviewed-secret.err"
printf 'credentials.json\n' > "$TMP/additional-sensitive-paths.txt"
"$SCRIPT_DIR/snapshot-serving-tree.sh" \
	"$TMP/unreviewed-secret-tree" "$TMP/reviewed-secret.tsv" \
	"$TMP/additional-sensitive-paths.txt" >/dev/null
if grep -Fq 'credentials.json' "$TMP/reviewed-secret.tsv"; then
	echo "snapshot persisted an explicitly excluded sensitive path" >&2
	exit 1
fi

# Deterministically create a competing output after the script's initial
# existence check but immediately before its no-clobber hard-link publication.
# The competing evidence must survive byte-for-byte and the snapshot must fail.
RACE_OUTPUT=$TMP/snapshot-race.tsv
REAL_LN=$(command -v ln)
mkdir "$TMP/race-bin"
cat > "$TMP/race-bin/ln" <<'EOF'
#!/bin/sh
if [ "$#" -eq 2 ] && [ "$2" = "$SOW_RACE_DEST" ] && [ ! -e "$2" ]; then
	printf 'competing-snapshot\n' > "$2"
fi
exec "$REAL_LN" "$@"
EOF
chmod +x "$TMP/race-bin/ln"
if PATH="$TMP/race-bin:$PATH" REAL_LN="$REAL_LN" SOW_RACE_DEST="$RACE_OUTPUT" \
	"$SCRIPT_DIR/snapshot-serving-tree.sh" "$LEGACY" "$RACE_OUTPUT" \
	> "$TMP/snapshot-race.out" 2> "$TMP/snapshot-race.err"; then
	echo "snapshot replaced a concurrently created output" >&2
	exit 1
fi
grep -Fq 'refusing to publish snapshot because output appeared during the scan' "$TMP/snapshot-race.err"
printf 'competing-snapshot\n' > "$TMP/snapshot-race.expected"
cmp "$TMP/snapshot-race.expected" "$RACE_OUTPUT"

echo 'zero_byte_adoption=pass serving_tree_rewritten=false replay_changed=false replay_bytes_unchanged=true'
echo 'isolated_materialize=pass candidate_bytes=exact'
echo 'canonical_l1=pass legacy_fsck=pass'
echo 'local_symlink_rollback=pass legacy_bytes_restored=true'
echo 'local_symlink_rollback_replay=pass'
echo 'failed_candidate_preserved_outside_origin=true'
echo 'snapshot_nonregular_guard=pass'
echo 'snapshot_sensitive_path_guard=pass secret_bytes_opened=false digest_persisted=false'
echo 'snapshot_output_race_guard=pass competing_bytes_preserved=true'
