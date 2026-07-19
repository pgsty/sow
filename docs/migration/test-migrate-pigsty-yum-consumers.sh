#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
MIGRATE=$SCRIPT_DIR/migrate-pigsty-yum-consumers.sh
FILES=$SCRIPT_DIR/yum-consumer-files.tsv
SOURCE_ROOT=${PIGSTY_ROOT:-/Users/vonng/pgsty/pigsty}

[ -x "$MIGRATE" ] || { echo "migration script is not executable: $MIGRATE" >&2; exit 1; }
[ -d "$SOURCE_ROOT" ] || { echo "Pigsty source root is missing: $SOURCE_ROOT" >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-pigsty-yum-consumers.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

COPY=$TMP/pigsty
PLAN=$TMP/plan
REPLAY_PLAN=$TMP/replay-plan
EVIDENCE=$TMP/evidence
mkdir "$COPY"

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

: > "$TMP/source.tsv"
while IFS="$(printf '\t')" read -r relative expected kind; do
	case "$relative" in ''|'#'*) continue ;; esac
	[ -f "$SOURCE_ROOT/$relative" ] && [ ! -L "$SOURCE_ROOT/$relative" ] || {
		echo "unsafe source fixture: $relative" >&2
		exit 1
	}
	mkdir -p "$(dirname -- "$COPY/$relative")"
	cp -p "$SOURCE_ROOT/$relative" "$COPY/$relative"
	printf '%s\t%s\n' "$relative" "$(hash_file "$SOURCE_ROOT/$relative")" >> "$TMP/source.tsv"
done < "$FILES"

"$MIGRATE" audit --pigsty-root "$COPY" > "$TMP/audit.txt"
"$MIGRATE" stage --pigsty-root "$COPY" --output "$PLAN" > "$TMP/stage.txt"
digest=$(awk -F= '$1 == "plan_sha256" {print $2}' "$TMP/stage.txt")
[ -n "$digest" ] || { echo "stage did not emit a plan digest" >&2; exit 1; }
grep -Fxq 'changed=true' "$TMP/stage.txt"

"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/apply.txt"
grep -Fxq 'changed=true' "$TMP/apply.txt"
"$MIGRATE" verify --pigsty-root "$COPY" > "$TMP/verify.txt"

"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/apply-replay.txt"
grep -Fxq 'changed=false' "$TMP/apply-replay.txt"

"$MIGRATE" stage --pigsty-root "$COPY" --output "$REPLAY_PLAN" > "$TMP/stage-replay.txt"
grep -Fxq 'changed=false' "$TMP/stage-replay.txt"

# Rollback must reject a file that no longer matches either reviewed state.
printf '\n# foreign-drift\n' >> "$COPY/conf/demo/el.yml"
if "$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-drift.txt" 2>&1; then
	echo 'rollback accepted foreign drift' >&2
	exit 1
fi
grep -Fq 'foreign drift in conf/demo/el.yml' "$TMP/rollback-drift.txt"
cp -p "$PLAN/conf/demo/el.yml" "$COPY/conf/demo/el.yml"

"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback.txt"
grep -Fxq 'changed=true' "$TMP/rollback.txt"
"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-replay.txt"
grep -Fxq 'changed=false' "$TMP/rollback-replay.txt"

# A process death can leave either direction mixed. Existing evidence must let
# the exact plan finish without reconstructing or overwriting foreign bytes.
cp -p "$PLAN/roles/node/tasks/pkg.yml" "$COPY/roles/node/tasks/pkg.yml"
"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/apply-mixed-replay.txt"
grep -Fxq 'changed=true' "$TMP/apply-mixed-replay.txt"
"$MIGRATE" verify --pigsty-root "$COPY" > "$TMP/verify-mixed-replay.txt"
cp -p "$EVIDENCE/original/conf/build/dev.yml" "$COPY/conf/build/dev.yml"
"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-mixed-replay.txt"
grep -Fxq 'changed=true' "$TMP/rollback-mixed-replay.txt"
"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-final-replay.txt"
grep -Fxq 'changed=false' "$TMP/rollback-final-replay.txt"

while IFS="$(printf '\t')" read -r relative expected; do
	[ "$(hash_file "$COPY/$relative")" = "$expected" ] || {
		echo "rollback did not restore $relative byte-for-byte" >&2
		exit 1
	}
	[ "$(hash_file "$SOURCE_ROOT/$relative")" = "$expected" ] || {
		echo "source tree changed during isolated migration test: $relative" >&2
		exit 1
	}
done < "$TMP/source.tsv"

echo 'pigsty_yum_consumer_audit=pass mapped_definitions=28'
echo 'pigsty_yum_consumer_stage=pass source_unchanged=true'
echo 'pigsty_yum_consumer_apply=pass replay_idempotent=true mixed_state_recovered=true'
echo 'pigsty_yum_consumer_rollback=pass foreign_drift_rejected=true exact_bytes_restored=true replay_idempotent=true mixed_state_recovered=true'
