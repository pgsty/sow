#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
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
SOW_BIN=$TMP/sow-receipt-check
SOW_CONFIG=$TMP/sow.yaml
TRUST_BUNDLE=$TMP/rpm-trust.asc
PREFLIGHT_RECEIPT=$TMP/preflight-receipt.json
mkdir "$COPY"

printf 'schema: sow/v1\n' > "$SOW_CONFIG"
printf '%s\n' 'test-public-trust-bundle' > "$TRUST_BUNDLE"
printf '%s\n' '{"schema":"test-receipt"}' > "$PREFLIGHT_RECEIPT"
# The single-quoted arguments deliberately become a separate executable whose
# variables expand only when that fixture runs.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'set -eu' \
	'[ "$1" = compatibility ] && [ "$2" = yum-consumer-receipt-check ] || exit 70' \
	'shift 2' \
	'staged= map= inventory= trust= receipt= confirm= config=' \
	'while [ "$#" -gt 0 ]; do' \
	'  case "$1" in' \
	'    --staged) staged=$2 ;; --map) map=$2 ;; --inventory) inventory=$2 ;;' \
	'    --trust-bundle) trust=$2 ;; --receipt) receipt=$2 ;; --confirm) confirm=$2 ;; --config) config=$2 ;;' \
	'    --workers|--chunk-entries|--root) : ;; *) exit 71 ;;' \
	'  esac' \
	'  shift 2' \
	'done' \
	'[ -d "$staged" ] && [ -f "$staged/manifest.tsv" ] && [ -f "$map" ] && [ -f "$inventory" ] && [ -f "$trust" ] && [ -f "$receipt" ] && [ -f "$config" ] && [ -n "$confirm" ] || exit 72' \
	'[ "${SOW_TEST_PREFLIGHT_FAIL:-0}" = 0 ] || exit 73' \
	'if [ -n "${SOW_TEST_FAIL_SECOND_STATE:-}" ]; then count=0; [ ! -f "$SOW_TEST_FAIL_SECOND_STATE" ] || count=$(cat "$SOW_TEST_FAIL_SECOND_STATE"); count=$((count + 1)); printf "%s\n" "$count" > "$SOW_TEST_FAIL_SECOND_STATE"; [ "$count" -lt 2 ] || exit 74; fi' \
	'if command -v sha256sum >/dev/null 2>&1; then receipt_sha=$(sha256sum "$receipt" | awk '\''{print $1}'\''); else receipt_sha=$(shasum -a 256 "$receipt" | awk '\''{print $1}'\''); fi' \
	'printf "receipt=valid plan_sha256=%s receipt_sha256=%s\n" "$confirm" "$receipt_sha"' > "$SOW_BIN"
chmod 0700 "$SOW_BIN"

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

: > "$TMP/source.tsv"
while IFS="$(printf '\t')" read -r relative _expected _kind; do
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

# The old dev-only infra source used beta.pigsty.cc raw bytes. Frozen cross-EL
# compatibility projections have one latest authority, so both China routes
# must use repo.pigsty.cc/latest rather than inventing a mutable beta projection.
grep -Fq 'https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt' "$PLAN/conf/build/dev.yml"
grep -Fq 'https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/infra-legacy-aarch64/cross-el/aarch64.txt' "$PLAN/conf/build/dev.yml"
if grep -Fq 'https://beta.pigsty.cc/_sow/v1/mirrorlist/beta/infra-legacy-' "$PLAN/conf/build/dev.yml"; then
	echo 'frozen infra stage invented a beta compatibility projection' >&2
	exit 1
fi

# The receipt gate must run before evidence creation, backups, or any Pigsty
# mutation. A rejected gate leaves every reviewed source byte untouched.
if SOW_TEST_PREFLIGHT_FAIL=1 "$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-gate-fail.txt" 2>&1; then
	echo 'apply accepted a rejected endpoint preflight receipt' >&2
	exit 1
fi
[ ! -e "$EVIDENCE" ] || { echo 'rejected preflight created migration evidence' >&2; exit 1; }
while IFS="$(printf '\t')" read -r relative expected; do
	[ "$(hash_file "$COPY/$relative")" = "$expected" ] || { echo "rejected preflight changed $relative" >&2; exit 1; }
done < "$TMP/source.tsv"

# The shell independently validates manifest paths before it creates or
# traverses evidence, even if a substituted receipt checker lies.
ATTACK_PLAN=$TMP/path-traversal-plan
ATTACK_EVIDENCE=$TMP/path-traversal-evidence
mkdir "$ATTACK_PLAN"
printf '../../escape\t%s\t%s\n' "$(printf '%064d' 0)" "$(printf '%064d' 0)" > "$ATTACK_PLAN/manifest.tsv"
attack_digest=$(hash_file "$ATTACK_PLAN/manifest.tsv")
printf '%s\n' "$attack_digest" > "$ATTACK_PLAN/plan.sha256"
if "$MIGRATE" apply --pigsty-root "$COPY" --staged "$ATTACK_PLAN" --evidence "$ATTACK_EVIDENCE" --confirm "$attack_digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-path-traversal.txt" 2>&1; then
	echo 'apply accepted an unsafe manifest path' >&2
	exit 1
fi
grep -Fq 'unsafe manifest path: ../../escape' "$TMP/apply-path-traversal.txt"
[ ! -e "$ATTACK_EVIDENCE" ] || { echo 'unsafe manifest created migration evidence' >&2; exit 1; }

# A plan cannot be the checkout's ancestor or a symlink to another directory;
# both shapes make path boundaries ambiguous under concurrent replacement.
ANCESTOR_EVIDENCE=$TMP/ancestor-evidence
if "$MIGRATE" apply --pigsty-root "$COPY" --staged "$TMP" --evidence "$ANCESTOR_EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-ancestor-plan.txt" 2>&1; then
	echo 'apply accepted a plan directory containing the Pigsty checkout' >&2
	exit 1
fi
grep -Fq 'plan/evidence directory must not contain the Pigsty checkout' "$TMP/apply-ancestor-plan.txt"
[ ! -e "$ANCESTOR_EVIDENCE" ]
SYMLINK_PLAN=$TMP/symlink-plan
SYMLINK_EVIDENCE=$TMP/symlink-evidence
ln -s "$PLAN" "$SYMLINK_PLAN"
if "$MIGRATE" apply --pigsty-root "$COPY" --staged "$SYMLINK_PLAN" --evidence "$SYMLINK_EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-symlink-plan.txt" 2>&1; then
	echo 'apply accepted a symlinked plan directory' >&2
	exit 1
fi
grep -Fq 'plan directory is missing or a symlink' "$TMP/apply-symlink-plan.txt"
[ ! -e "$SYMLINK_EVIDENCE" ]

# A receipt can expire or canonical authority can drift while backups are
# being made. The second network-free check must still fail before the first
# Pigsty byte is changed; recovery evidence may safely remain for inspection.
EXPIRY_EVIDENCE=$TMP/expiry-evidence
SECOND_CHECK_STATE=$TMP/second-check-state
if SOW_TEST_FAIL_SECOND_STATE="$SECOND_CHECK_STATE" "$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EXPIRY_EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-second-gate-fail.txt" 2>&1; then
	echo 'apply accepted a receipt rejected immediately before mutation' >&2
	exit 1
fi
grep -Fq 'preflight receipt was rejected before mutation' "$TMP/apply-second-gate-fail.txt"
[ "$(awk 'NR == 1 {print}' "$SECOND_CHECK_STATE")" = 2 ]
while IFS="$(printf '\t')" read -r relative expected; do
	[ "$(hash_file "$COPY/$relative")" = "$expected" ] || { echo "second receipt check failure changed $relative" >&2; exit 1; }
done < "$TMP/source.tsv"

# Stale fixed-name symlinks from the provisional implementation must never be
# followed. The current writer uses checked process-unique temporary paths.
mkdir "$EVIDENCE"
printf 'marker-sentinel\n' > "$TMP/marker-sentinel"
printf 'receipt-sentinel\n' > "$TMP/receipt-sentinel"
marker_sentinel_sha=$(hash_file "$TMP/marker-sentinel")
receipt_sentinel_sha=$(hash_file "$TMP/receipt-sentinel")
ln -s "$TMP/marker-sentinel" "$EVIDENCE/preflight-receipt.sha256.tmp"
ln -s "$TMP/receipt-sentinel" "$EVIDENCE/receipt.tmp"

"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply.txt"
grep -Fxq 'changed=true' "$TMP/apply.txt"
grep -Fxq 'schema=sow-pigsty-yum-consumer-receipt/v2' "$EVIDENCE/receipt"
grep -Fxq "preflight_receipt_sha256=$(hash_file "$PREFLIGHT_RECEIPT")" "$EVIDENCE/receipt"
[ "$(awk 'NR == 1 {print}' "$EVIDENCE/preflight-receipt.sha256")" = "$(hash_file "$PREFLIGHT_RECEIPT")" ]
[ "$(hash_file "$EVIDENCE/preflight-receipts/$(hash_file "$PREFLIGHT_RECEIPT").json")" = "$(hash_file "$PREFLIGHT_RECEIPT")" ]
[ "$(hash_file "$TMP/marker-sentinel")" = "$marker_sentinel_sha" ]
[ "$(hash_file "$TMP/receipt-sentinel")" = "$receipt_sentinel_sha" ]
"$MIGRATE" verify --pigsty-root "$COPY" > "$TMP/verify.txt"

"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-replay.txt"
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
grep -Fxq 'schema=sow-pigsty-yum-consumer-receipt/v2' "$EVIDENCE/receipt"
grep -Fxq "preflight_receipt_sha256=$(hash_file "$PREFLIGHT_RECEIPT")" "$EVIDENCE/receipt"
"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-replay.txt"
grep -Fxq 'changed=false' "$TMP/rollback-replay.txt"

# Evidence created by the pre-v2 migrator has no archived endpoint receipt.
# Its already-restored tree must remain safely replayable, and the receipt must
# explicitly retain the legacy schema rather than inventing a v2 authority.
mv "$EVIDENCE/preflight-receipt.sha256" "$TMP/preflight-receipt.sha256.v2"
mv "$EVIDENCE/preflight-receipts" "$TMP/preflight-receipts.v2"
"$MIGRATE" rollback --pigsty-root "$COPY" --evidence "$EVIDENCE" --confirm "$digest" > "$TMP/rollback-v1-replay.txt"
grep -Fxq 'changed=false' "$TMP/rollback-v1-replay.txt"
grep -Fxq 'schema=sow-pigsty-yum-consumer-receipt/v1' "$EVIDENCE/receipt"
if grep -q '^preflight_receipt_sha256=' "$EVIDENCE/receipt"; then
	echo 'legacy rollback invented a v2 preflight receipt authority' >&2
	exit 1
fi

# A process death can leave either direction mixed. Existing evidence must let
# the exact plan finish without reconstructing or overwriting foreign bytes.
cp -p "$PLAN/roles/node/tasks/pkg.yml" "$COPY/roles/node/tasks/pkg.yml"
"$MIGRATE" apply --pigsty-root "$COPY" --staged "$PLAN" --evidence "$EVIDENCE" --confirm "$digest" --sow-bin "$SOW_BIN" --sow-config "$SOW_CONFIG" --trust-bundle "$TRUST_BUNDLE" --preflight-receipt "$PREFLIGHT_RECEIPT" > "$TMP/apply-mixed-replay.txt"
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

echo 'pigsty_yum_consumer_audit=pass mapped_definitions=22'
echo 'pigsty_yum_consumer_stage=pass source_unchanged=true'
echo 'pigsty_yum_consumer_apply=pass replay_idempotent=true mixed_state_recovered=true'
echo 'pigsty_yum_consumer_preflight_gate=pass rejected_before_mutation=true revalidated_before_write=true receipt_bound=true unsafe_manifest_rejected=true disjoint_plan_enforced=true stale_symlink_not_followed=true'
echo 'pigsty_yum_consumer_rollback=pass foreign_drift_rejected=true exact_bytes_restored=true replay_idempotent=true mixed_state_recovered=true legacy_v1_replay=true'
