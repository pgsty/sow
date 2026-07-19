#!/bin/sh
# Fail-closed migration for Pigsty's SOW-hosted YUM consumers.
#
# The source tree is never edited by `audit` or `stage`. `apply` requires the
# exact reviewed plan digest, keeps byte-identical originals outside the
# Pigsty tree, and is crash-replayable. `rollback` refuses foreign drift and
# restores those original bytes. Before any Pigsty byte is changed, apply asks
# the Go CLI to validate a short-lived, canonical endpoint preflight receipt.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
MAP=$SCRIPT_DIR/yum-consumer-map.tsv
FILES=$SCRIPT_DIR/yum-consumer-files.tsv
MARKER='sow-yum-mirrorlist/v2'
PIGSTY_ROOT=
OUTPUT=
STAGED=
EVIDENCE=
CONFIRM=
SOW_BIN=
SOW_CONFIG=
SOW_ROOT=
TRUST_BUNDLE=
PREFLIGHT_RECEIPT=

usage() {
	cat >&2 <<'EOF'
usage:
  migrate-pigsty-yum-consumers.sh audit    --pigsty-root DIR
  migrate-pigsty-yum-consumers.sh stage    --pigsty-root DIR --output DIR
  migrate-pigsty-yum-consumers.sh verify   --pigsty-root DIR
  migrate-pigsty-yum-consumers.sh apply    --pigsty-root DIR --staged DIR --evidence DIR --confirm SHA256 \
    --sow-bin FILE --sow-config FILE [--sow-root DIR] --trust-bundle FILE --preflight-receipt FILE
  migrate-pigsty-yum-consumers.sh rollback --pigsty-root DIR --evidence DIR --confirm SHA256

The stage and evidence directories must be outside the Pigsty checkout. The
apply confirmation is the plan digest printed by `stage`; rollback uses the
same digest. `apply` refuses to create backups or edit Pigsty until the Go CLI
proves that every exact generation-pinned route and the aggregate public-only
rpm-trust.asc bundle are current, target-owned, and covered by an unexpired
receipt. The receipt is produced by `sow compatibility yum-consumer-preflight`.
EOF
}

die() {
	echo "pigsty YUM consumer migration: $*" >&2
	exit 1
}

[ "$#" -ge 1 ] || { usage; exit 2; }
COMMAND=$1
shift
case "$COMMAND" in
	audit|stage|verify|apply|rollback) ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
esac

while [ "$#" -gt 0 ]; do
	case "$1" in
		--pigsty-root) [ "$#" -ge 2 ] || { usage; exit 2; }; PIGSTY_ROOT=$2; shift 2 ;;
		--output) [ "$#" -ge 2 ] || { usage; exit 2; }; OUTPUT=$2; shift 2 ;;
		--staged) [ "$#" -ge 2 ] || { usage; exit 2; }; STAGED=$2; shift 2 ;;
		--evidence) [ "$#" -ge 2 ] || { usage; exit 2; }; EVIDENCE=$2; shift 2 ;;
		--confirm) [ "$#" -ge 2 ] || { usage; exit 2; }; CONFIRM=$2; shift 2 ;;
		--sow-bin) [ "$#" -ge 2 ] || { usage; exit 2; }; SOW_BIN=$2; shift 2 ;;
		--sow-config) [ "$#" -ge 2 ] || { usage; exit 2; }; SOW_CONFIG=$2; shift 2 ;;
		--sow-root) [ "$#" -ge 2 ] || { usage; exit 2; }; SOW_ROOT=$2; shift 2 ;;
		--trust-bundle) [ "$#" -ge 2 ] || { usage; exit 2; }; TRUST_BUNDLE=$2; shift 2 ;;
		--preflight-receipt) [ "$#" -ge 2 ] || { usage; exit 2; }; PREFLIGHT_RECEIPT=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage; exit 2 ;;
	esac
done

[ -f "$MAP" ] || die "missing map $MAP"
[ -f "$FILES" ] || die "missing file inventory $FILES"
[ -n "$PIGSTY_ROOT" ] || die "--pigsty-root is required"
[ -d "$PIGSTY_ROOT" ] || die "Pigsty root is not a directory: $PIGSTY_ROOT"
PIGSTY_ROOT=$(CDPATH='' cd -- "$PIGSTY_ROOT" && pwd -P)

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

valid_sha256() {
	printf '%s\n' "$1" | LC_ALL=C awk 'NR == 1 && length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid=1 } NR > 1 { valid=0 } END { exit valid ? 0 : 1 }'
}

canonical_existing_dir() {
	(CDPATH='' cd -- "$1" && pwd -P)
}

require_outside_root() {
	candidate=$1
	label=$2
	case "$candidate/" in
		"$PIGSTY_ROOT/"*) die "$label must be outside the Pigsty checkout" ;;
	esac
}

require_disjoint_root() {
	candidate=$1
	label=$2
	require_outside_root "$candidate" "$label"
	case "$PIGSTY_ROOT/" in
		"$candidate/"*) die "$label must not contain the Pigsty checkout" ;;
	esac
}

require_regular_inventory() {
	while IFS="$(printf '\t')" read -r relative _expected kind; do
		case "$relative" in ''|'#'*) continue ;; esac
		file=$PIGSTY_ROOT/$relative
		[ -f "$file" ] || die "missing inventory file $relative"
		[ ! -L "$file" ] || die "inventory file is a symlink: $relative"
		case "$kind" in renderer|consumer) ;; *) die "invalid inventory kind for $relative: $kind" ;; esac
	done < "$FILES"
}

# Validate the exact 28 reviewed definitions. Other SOW-hosted raw default
# URLs fail closed instead of being silently omitted from the migration map.
audit_consumer_inventory() {
	set --
	while IFS="$(printf '\t')" read -r relative _expected kind; do
		case "$relative" in ''|'#'*) continue ;; esac
		[ "$kind" = consumer ] || continue
		set -- "$@" "$PIGSTY_ROOT/$relative"
	done < "$FILES"
	awk -v map="$MAP" -v files="$FILES" '
		BEGIN {
			FS="\t"
			while ((getline < map) > 0) {
				if ($0 == "" || substr($0,1,1) == "#") continue
				name[$1]=$2; expected_name[$1]=$4+0
			}
			close(map)
			while ((getline < files) > 0) {
				if ($0 == "" || substr($0,1,1) == "#" || $3 != "consumer") continue
				expected_file[$1]=$2+0
			}
			close(files)
		}
		{
			rel=FILENAME
			sub(/^.*\/conf\//, "conf/", rel)
			if (rel == FILENAME) sub(/^.*\/roles\//, "roles/", rel)
			matched=""
			for (n in name) {
				if (index($0, "name: " n) && index($0, "repo.pigsty.io/yum/")) {
					if (matched != "") { print "ambiguous mapped definition: " FILENAME ":" FNR > "/dev/stderr"; bad=1 }
					matched=n
				}
			}
			if (matched != "") {
				count_name[matched]++; count_file[rel]++
				if (index($0, "mirrorlist:") != 0) migrated++
				total++
			} else if (index($0, "repo.pigsty.io/yum/")) {
				print "unmapped SOW-hosted YUM default: " FILENAME ":" FNR > "/dev/stderr"; bad=1
			}
		}
		END {
			for (n in expected_name) if (count_name[n] != expected_name[n]) {
				print "definition count for " n " is " count_name[n] ", expected " expected_name[n] > "/dev/stderr"; bad=1
			}
			for (f in expected_file) if (count_file[f] != expected_file[f]) {
				print "definition count for " f " is " count_file[f] ", expected " expected_file[f] > "/dev/stderr"; bad=1
			}
			if (total != 28) { print "mapped definition total is " total ", expected 28" > "/dev/stderr"; bad=1 }
			print "mapped_definitions=" total " already_migrated=" migrated
			exit bad ? 1 : 0
		}
	' "$@" || die "consumer inventory differs from the reviewed contract"
}

audit_renderer_inventory() {
	for relative in roles/node/tasks/pkg.yml roles/repo/tasks/build.yml; do
		file=$PIGSTY_ROOT/$relative
		markers=$(grep -F -c "$MARKER" "$file" || true)
		old=$(grep -F -c "{% if region in repo.baseurl and repo.baseurl[region] != '' %}" "$file" || true)
		if [ "$markers" -eq 0 ]; then
			[ "$old" -eq 2 ] || die "$relative no longer has the reviewed RPM+APT baseurl blocks"
		else
			[ "$markers" -eq 1 ] || die "$relative has an invalid migration marker count"
			grep -Fq 'repo.mirrorlist is defined' "$file" || die "$relative marker has no mirrorlist renderer"
			grep -Fq 'repo.gpgkey is defined' "$file" || die "$relative marker has no gpgkey renderer"
		fi
	done
}

audit_source() {
	require_regular_inventory
	audit_consumer_inventory
	audit_renderer_inventory
}

transform_renderer() {
	source=$1
	target=$2
	if grep -Fq "$MARKER" "$source"; then
		cp -p "$source" "$target"
		return
	fi
	body=$target.body.$$
	awk -v marker="$MARKER" '
		BEGIN { replacing=0; replaced=0; inserted=0 }
		replacing {
			if (index($0, "{% endif %}")) replacing=0
			next
		}
		replaced == 0 && index($0, "{% if region in repo.baseurl") {
			indent=$0; sub(/\{% if.*/, "", indent)
			print indent "# " marker
			print indent "{% if repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is mapping and os_arch in repo.mirrorlist[region] %}"
			print indent "mirrorlist = {{ repo.mirrorlist[region][os_arch] | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% elif repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is string and repo.mirrorlist[region] != \"\" %}"
			print indent "mirrorlist = {{ repo.mirrorlist[region] | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% elif repo.baseurl is defined and region in repo.baseurl and repo.baseurl[region] != \"\" %}"
			print indent "baseurl = {{ repo.baseurl[region] | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% elif repo.mirrorlist is defined and \"default\" in repo.mirrorlist and repo.mirrorlist.default is mapping and os_arch in repo.mirrorlist.default %}"
			print indent "mirrorlist = {{ repo.mirrorlist.default[os_arch] | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% elif repo.mirrorlist is defined and \"default\" in repo.mirrorlist and repo.mirrorlist.default is string and repo.mirrorlist.default != \"\" %}"
			print indent "mirrorlist = {{ repo.mirrorlist.default | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% else %}"
			print indent "baseurl = {{ repo.baseurl.default | replace(\"${admin_ip}\", admin_ip) | replace(\"$releasever\", target_version|string) }}"
			print indent "{% endif %}"
			replacing=1; replaced++
			next
		}
		{
			print
			if (replaced == 1 && inserted == 0 && index($0, "{% if repo.meta is defined %}{% set repo_opts = repo_opts | combine(repo.meta) %}{% endif %}")) {
				indent=$0; sub(/\{% if.*/, "", indent)
				print indent "{% if repo.gpgkey is defined %}"
				print indent "{% if region in repo.gpgkey and repo.gpgkey[region] != \"\" %}"
				print indent "{% set repo_opts = repo_opts | combine({\"gpgkey\": repo.gpgkey[region]}) %}"
				print indent "{% else %}"
				print indent "{% set repo_opts = repo_opts | combine({\"gpgkey\": repo.gpgkey.default}) %}"
				print indent "{% endif %}"
				print indent "{% endif %}"
				inserted++
			}
		}
		END { if (replacing || replaced != 1 || inserted != 1) exit 42 }
	' "$source" > "$body" || { code=$?; rm -f "$body"; die "cannot transform renderer $source (code $code)"; }
	cp -p "$source" "$target"
	cp "$body" "$target"
	rm -f "$body"
}

transform_consumer() {
	source=$1
	target=$2
	body=$target.body.$$
	awk -v map="$MAP" '
		BEGIN {
			FS="\t"
			while ((getline < map) > 0) {
				if ($0 == "" || substr($0,1,1) == "#") continue
				repo_x86[$1]=$2; repo_arm[$1]=$3
			}
			close(map)
		}
		function append_before_last_brace(line, extra,    i) {
			for (i=length(line); i>0; i--) if (substr(line,i,1) == "}") return substr(line,1,i-1) extra " " substr(line,i)
			return ""
		}
		{
			matched=""
			for (name in repo_x86) if (index($0, "name: " name) && index($0, "repo.pigsty.io/yum/")) matched=name
			if (matched == "" || index($0, "mirrorlist:") != 0) { print; next }
			if (index($0, "gpgkey:") || index($0, "gpgcheck:") || index($0, "repo_gpgcheck:")) {
				print "unreviewed partial trust configuration: " FILENAME ":" FNR > "/dev/stderr"
				exit 44
			}
			china_host="repo.pigsty.cc"; china_view="latest"
			# ADR-0021 freezes the cross-EL infra projections in latest. The
			# historical dev definition used beta.pigsty.cc as a raw byte source,
			# but there is deliberately no mutable beta compatibility projection.
			if (matched != "pigsty-infra" && index($0, "beta.pigsty.cc/yum/")) { china_host="beta.pigsty.cc"; china_view="beta" }
			coordinate_x86=repo_x86[matched] ".txt"
			coordinate_arm=repo_arm[matched] ".txt"
			extra=" ,mirrorlist: { default: { x86_64: '\''https://repo.pigsty.io/_sow/v1/mirrorlist/latest/" coordinate_x86 "'\'' ,aarch64: '\''https://repo.pigsty.io/_sow/v1/mirrorlist/latest/" coordinate_arm "'\'' }"
			extra=extra " ,china: { x86_64: '\''https://" china_host "/_sow/v1/mirrorlist/" china_view "/" coordinate_x86 "'\'' ,aarch64: '\''https://" china_host "/_sow/v1/mirrorlist/" china_view "/" coordinate_arm "'\'' } }"
			extra=extra " ,gpgkey: { default: '\''https://repo.pigsty.io/pkg/keys/rpm-trust.asc'\'' ,china: '\''https://" china_host "/pkg/keys/rpm-trust.asc'\'' }"
			line=$0
			if (line ~ /,meta:[[:space:]]*\{/) {
			sub(/,meta:[[:space:]]*\{/, extra " ,meta: { gpgcheck: 1 ,repo_gpgcheck: 1 ,", line)
			} else {
				line=append_before_last_brace(line, extra " ,meta: { gpgcheck: 1 ,repo_gpgcheck: 1 }")
				if (line == "") exit 43
			}
			print line
		}
	' "$source" > "$body" || { code=$?; rm -f "$body"; die "cannot transform consumer $source (code $code)"; }
	cp -p "$source" "$target"
	cp "$body" "$target"
	rm -f "$body"
}

verify_migrated_contract() {
	root=$1
	for relative in roles/node/tasks/pkg.yml roles/repo/tasks/build.yml; do
		file=$root/$relative
		[ "$(grep -F -c "$MARKER" "$file" || true)" -eq 1 ] || die "$relative is not the reviewed mirrorlist renderer"
		grep -Fq 'mirrorlist = {{ repo.mirrorlist[region][os_arch]' "$file" || die "$relative lacks architecture-specific regional mirrorlist rendering"
		grep -Fq '"gpgkey": repo.gpgkey[region]' "$file" || die "$relative lacks regional gpgkey rendering"
	done
	set --
	while IFS="$(printf '\t')" read -r relative _expected kind; do
		case "$relative" in ''|'#'*) continue ;; esac
		[ "$kind" = consumer ] || continue
		set -- "$@" "$root/$relative"
	done < "$FILES"
	awk -v map="$MAP" '
		BEGIN {
			FS="\t"
			while ((getline < map) > 0) {
				if ($0 == "" || substr($0,1,1) == "#") continue
				repo_x86[$1]=$2; repo_arm[$1]=$3; expected[$1]=$4+0
			}
			close(map)
		}
		{
			for (name in repo_x86) if (index($0, "name: " name) && index($0, "repo.pigsty.io/yum/")) {
				count[name]++; total++
				coordinate_x86="/_sow/v1/mirrorlist/latest/" repo_x86[name] ".txt"
				coordinate_arm="/_sow/v1/mirrorlist/latest/" repo_arm[name] ".txt"
				if (!index($0, coordinate_x86) || !index($0, coordinate_arm) || !index($0, "mirrorlist:") || !index($0, "x86_64:") || !index($0, "aarch64:") || !index($0, ",meta: { gpgcheck: 1 ,repo_gpgcheck: 1") || !index($0, "gpgkey:") || !index($0, "/pkg/keys/rpm-trust.asc")) {
					print "incomplete migrated definition: " FILENAME ":" FNR > "/dev/stderr"; bad=1
				}
				if (name != "pigsty-infra" && index($0, "beta.pigsty.cc/yum/") && !index($0, "https://beta.pigsty.cc/_sow/v1/mirrorlist/beta/")) {
					print "beta consumer did not map to beta mirrorlist: " FILENAME ":" FNR > "/dev/stderr"; bad=1
				}
				if (name == "pigsty-infra" && (!index($0, "https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/" repo_x86[name] ".txt") || !index($0, "https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/" repo_arm[name] ".txt") || index($0, "https://beta.pigsty.cc/_sow/v1/mirrorlist/beta/"))) {
					print "frozen infra consumer did not map China to latest compatibility projections: " FILENAME ":" FNR > "/dev/stderr"; bad=1
				}
				if (index($0, "repo.pigsty.cc/yum/") && (!index($0, "https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/" repo_x86[name] ".txt") || !index($0, "https://repo.pigsty.cc/_sow/v1/mirrorlist/latest/" repo_arm[name] ".txt"))) {
					print "China latest consumer did not map to its exact mirrorlist: " FILENAME ":" FNR > "/dev/stderr"; bad=1
				}
			}
		}
		END {
			for (name in expected) if (count[name] != expected[name]) { print "migrated count mismatch for " name > "/dev/stderr"; bad=1 }
			if (total != 28) { print "migrated definition total is " total ", expected 28" > "/dev/stderr"; bad=1 }
			exit bad ? 1 : 0
		}
	' "$@" || die "migrated consumer contract is incomplete"
}

stage_tree() {
	[ -n "$OUTPUT" ] || die "stage requires --output"
	[ ! -e "$OUTPUT" ] || die "stage output already exists: $OUTPUT"
	parent=$(dirname -- "$OUTPUT")
	[ -d "$parent" ] || die "stage output parent does not exist: $parent"
	parent=$(canonical_existing_dir "$parent")
	require_outside_root "$parent" "stage output"
	umask 077
	mkdir "$OUTPUT"
	OUTPUT=$(canonical_existing_dir "$OUTPUT")
	require_disjoint_root "$OUTPUT" "stage output"
	manifest_tmp=$OUTPUT/manifest.tsv.tmp
	: > "$manifest_tmp"
	stage_changed=false
	while IFS="$(printf '\t')" read -r relative _expected kind; do
		case "$relative" in ''|'#'*) continue ;; esac
		source=$PIGSTY_ROOT/$relative
		target=$OUTPUT/$relative
		mkdir -p "$(dirname -- "$target")"
		case "$kind" in
			renderer) transform_renderer "$source" "$target" ;;
			consumer) transform_consumer "$source" "$target" ;;
		esac
		before=$(hash_file "$source")
		after=$(hash_file "$target")
		[ "$before" = "$after" ] || stage_changed=true
		printf '%s\t%s\t%s\n' "$relative" "$before" "$after" >> "$manifest_tmp"
	done < "$FILES"
	mv "$manifest_tmp" "$OUTPUT/manifest.tsv"
	verify_migrated_contract "$OUTPUT"
	digest=$(hash_file "$OUTPUT/manifest.tsv")
	printf '%s\n' "$digest" > "$OUTPUT/plan.sha256"
	echo "stage=$OUTPUT"
	echo "plan_sha256=$digest"
	echo "changed=$stage_changed"
}

load_plan() {
	dir=$1
	[ -d "$dir" ] && [ ! -L "$dir" ] || die "plan directory is missing or a symlink: $dir"
	dir=$(canonical_existing_dir "$dir")
	require_disjoint_root "$dir" "plan/evidence directory"
	[ -f "$dir/manifest.tsv" ] && [ ! -L "$dir/manifest.tsv" ] || die "plan manifest is missing or unsafe"
	[ -f "$dir/plan.sha256" ] && [ ! -L "$dir/plan.sha256" ] || die "plan digest is missing or unsafe"
	digest=$(hash_file "$dir/manifest.tsv")
	recorded=$(awk 'NR==1 {print $1; exit}' "$dir/plan.sha256")
	[ "$digest" = "$recorded" ] || die "plan manifest digest differs from plan.sha256"
	[ -n "$CONFIRM" ] && [ "$CONFIRM" = "$digest" ] || die "--confirm must equal plan digest $digest"
	printf '%s\t%s\n' "$dir" "$digest"
}

validate_preflight_receipt() {
	expected_plan_digest=$1
	quiet=${2:-}
	if [ -n "$SOW_ROOT" ]; then
		if ! receipt_check_output=$("$SOW_BIN" compatibility yum-consumer-receipt-check --config "$SOW_CONFIG" --root "$SOW_ROOT" --staged "$STAGED" --map "$MAP" --inventory "$FILES" --trust-bundle "$TRUST_BUNDLE" --receipt "$PREFLIGHT_RECEIPT" --confirm "$expected_plan_digest"); then
			die "YUM consumer preflight receipt was rejected before mutation"
		fi
	else
		if ! receipt_check_output=$("$SOW_BIN" compatibility yum-consumer-receipt-check --config "$SOW_CONFIG" --staged "$STAGED" --map "$MAP" --inventory "$FILES" --trust-bundle "$TRUST_BUNDLE" --receipt "$PREFLIGHT_RECEIPT" --confirm "$expected_plan_digest"); then
			die "YUM consumer preflight receipt was rejected before mutation"
		fi
	fi
	[ "$quiet" = quiet ] || printf '%s\n' "$receipt_check_output"
	validated_preflight_sha256=$(printf '%s\n' "$receipt_check_output" | awk '
		{ for (i=1; i<=NF; i++) if ($i ~ /^receipt_sha256=/) { sub(/^receipt_sha256=/, "", $i); if (length($i) == 64 && $i !~ /[^0-9a-f]/) { print $i; found++ } } }
		END { if (found != 1) exit 1 }
	') || die "YUM consumer receipt-check did not emit one canonical receipt digest"
	preflight_receipt_sha256=$(hash_file "$PREFLIGHT_RECEIPT")
	[ "$preflight_receipt_sha256" = "$validated_preflight_sha256" ] || die "YUM consumer preflight receipt changed after validation"
}

preflight_manifest() {
	manifest=$1
	backup_root=$2
	staged_root=${3:-}
	while IFS="$(printf '\t')" read -r relative before after; do
		[ -n "$relative" ] || die "empty manifest path"
		case "$relative" in /*|../*|*/../*|*/..|./*|*/./*|*//*|*\\*|*"$(printf '\t')"*) die "unsafe manifest path: $relative" ;; esac
		require_evidence_parent "$PIGSTY_ROOT" "$relative" "current source"
		current=$PIGSTY_ROOT/$relative
		[ -f "$current" ] && [ ! -L "$current" ] || die "unsafe current file: $relative"
		observed=$(hash_file "$current")
		[ "$observed" = "$before" ] || [ "$observed" = "$after" ] || die "foreign drift in $relative"
		if [ -n "$backup_root" ]; then
			require_evidence_parent "$backup_root" "$relative" "original backup"
			backup=$backup_root/$relative
			[ -f "$backup" ] && [ ! -L "$backup" ] || die "missing safe backup for $relative"
			[ "$(hash_file "$backup")" = "$before" ] || die "backup digest mismatch for $relative"
		fi
		if [ -n "$staged_root" ]; then
			require_evidence_parent "$staged_root" "$relative" "staged plan"
			staged_file=$staged_root/$relative
			[ -f "$staged_file" ] && [ ! -L "$staged_file" ] || die "missing safe staged file for $relative"
			[ "$(hash_file "$staged_file")" = "$after" ] || die "staged digest mismatch for $relative"
		fi
	done < "$manifest"
}

require_evidence_parent() {
	root=$1
	relative=$2
	label=$3
	remaining=$(dirname -- "$relative")
	[ "$remaining" != . ] || return 0
	directory=$root
	while :; do
		segment=${remaining%%/*}
		[ -n "$segment" ] && [ "$segment" != . ] && [ "$segment" != .. ] || die "unsafe $label parent for $relative"
		directory=$directory/$segment
		[ ! -L "$directory" ] && [ -d "$directory" ] || die "$label parent is missing, non-directory, or a symlink for $relative"
		[ "$remaining" = "$segment" ] && break
		remaining=${remaining#*/}
	done
}

ensure_evidence_parent() {
	root=$1
	relative=$2
	remaining=$(dirname -- "$relative")
	[ "$remaining" != . ] || return 0
	directory=$root
	while :; do
		segment=${remaining%%/*}
		[ -n "$segment" ] && [ "$segment" != . ] && [ "$segment" != .. ] || die "unsafe evidence parent for $relative"
		directory=$directory/$segment
		[ ! -L "$directory" ] || die "evidence parent is a symlink for $relative"
		if [ -e "$directory" ]; then
			[ -d "$directory" ] || die "evidence parent is not a directory for $relative"
		else
			mkdir "$directory"
		fi
		[ "$remaining" = "$segment" ] && break
		remaining=${remaining#*/}
	done
}

apply_plan() {
	[ -n "$STAGED" ] && [ -n "$EVIDENCE" ] || die "apply requires --staged and --evidence"
	plan_data=$(load_plan "$STAGED")
	STAGED=$(printf '%s\n' "$plan_data" | awk -F '\t' 'NR==1 {print $1}')
	digest=$(printf '%s\n' "$plan_data" | awk -F '\t' 'NR==1 {print $2}')
	[ -n "$SOW_BIN" ] && [ -f "$SOW_BIN" ] && [ ! -L "$SOW_BIN" ] && [ -x "$SOW_BIN" ] || die "apply requires a real executable --sow-bin"
	[ -n "$SOW_CONFIG" ] && [ -f "$SOW_CONFIG" ] && [ ! -L "$SOW_CONFIG" ] || die "apply requires a safe --sow-config"
	[ -n "$TRUST_BUNDLE" ] && [ -f "$TRUST_BUNDLE" ] && [ ! -L "$TRUST_BUNDLE" ] || die "apply requires a safe --trust-bundle"
	[ -n "$PREFLIGHT_RECEIPT" ] && [ -f "$PREFLIGHT_RECEIPT" ] && [ ! -L "$PREFLIGHT_RECEIPT" ] || die "apply requires a safe --preflight-receipt"
	validate_preflight_receipt "$digest"
	initial_preflight_receipt_sha256=$preflight_receipt_sha256
	# Validate every relative path and before/after byte identity before an
	# operator-controlled evidence path is created or traversed.
	preflight_manifest "$STAGED/manifest.tsv" "" "$STAGED"
	umask 077
	if [ -e "$EVIDENCE" ]; then
		[ -d "$EVIDENCE" ] && [ ! -L "$EVIDENCE" ] || die "evidence path is not a directory or is a symlink"
		EVIDENCE=$(canonical_existing_dir "$EVIDENCE")
	else
		parent=$(dirname -- "$EVIDENCE")
		[ -d "$parent" ] || die "evidence parent does not exist"
		parent=$(canonical_existing_dir "$parent")
		require_outside_root "$parent" "evidence"
		mkdir "$EVIDENCE"
		EVIDENCE=$(canonical_existing_dir "$EVIDENCE")
	fi
	require_disjoint_root "$EVIDENCE" "evidence"
	receipt_archive=$EVIDENCE/preflight-receipts
	if [ -e "$receipt_archive" ]; then
		[ -d "$receipt_archive" ] && [ ! -L "$receipt_archive" ] || die "preflight receipt archive is unsafe"
	else
		mkdir "$receipt_archive"
	fi
	archived_receipt=$receipt_archive/$preflight_receipt_sha256.json
	if [ -e "$archived_receipt" ]; then
		[ -f "$archived_receipt" ] && [ ! -L "$archived_receipt" ] && [ "$(hash_file "$archived_receipt")" = "$preflight_receipt_sha256" ] || die "archived preflight receipt is unsafe or drifted"
	else
		archived_tmp=$receipt_archive/.receipt.$$
		[ ! -e "$archived_tmp" ] || die "preflight receipt archive temporary path exists"
		cp "$PREFLIGHT_RECEIPT" "$archived_tmp"
		[ "$(hash_file "$archived_tmp")" = "$preflight_receipt_sha256" ] || die "preflight receipt changed while archiving"
		mv "$archived_tmp" "$archived_receipt"
	fi
	marker_tmp=$EVIDENCE/.preflight-receipt.sha256.$$
	[ ! -e "$marker_tmp" ] && [ ! -L "$marker_tmp" ] || die "preflight receipt marker temporary path exists"
	printf '%s\n' "$preflight_receipt_sha256" > "$marker_tmp"
	[ -f "$marker_tmp" ] && [ ! -L "$marker_tmp" ] || die "preflight receipt marker temporary path is unsafe"
	mv "$marker_tmp" "$EVIDENCE/preflight-receipt.sha256"
	for evidence_name in manifest.tsv plan.sha256; do
		evidence_file=$EVIDENCE/$evidence_name
		[ ! -L "$evidence_file" ] || die "evidence $evidence_name is a symlink"
		if [ -e "$evidence_file" ]; then
			[ -f "$evidence_file" ] || die "evidence $evidence_name is not a regular file"
		else
			evidence_tmp=$EVIDENCE/.$evidence_name.$$
			[ ! -e "$evidence_tmp" ] && [ ! -L "$evidence_tmp" ] || die "evidence $evidence_name temporary path exists"
			cp "$STAGED/$evidence_name" "$evidence_tmp"
			[ -f "$evidence_tmp" ] && [ ! -L "$evidence_tmp" ] || die "evidence $evidence_name temporary path is unsafe"
			mv "$evidence_tmp" "$evidence_file"
		fi
	done
	[ "$(hash_file "$EVIDENCE/manifest.tsv")" = "$digest" ] || die "evidence belongs to another plan"
	[ "$(awk 'NR == 1 { print; next } { exit 1 }' "$EVIDENCE/plan.sha256")" = "$digest" ] || die "evidence plan digest differs"
	[ ! -L "$EVIDENCE/original" ] || die "evidence original directory is a symlink"
	if [ -e "$EVIDENCE/original" ]; then
		[ -d "$EVIDENCE/original" ] || die "evidence original path is not a directory"
	else
		mkdir "$EVIDENCE/original"
	fi
	while IFS="$(printf '\t')" read -r relative before after; do
		backup=$EVIDENCE/original/$relative
		[ ! -L "$backup" ] || die "original backup is a symlink for $relative"
		if [ -e "$backup" ]; then
			[ -f "$backup" ] || die "original backup is not a regular file for $relative"
			continue
		fi
		[ "$(hash_file "$PIGSTY_ROOT/$relative")" = "$before" ] || die "cannot reconstruct missing original backup for $relative"
		ensure_evidence_parent "$EVIDENCE/original" "$relative"
		backup_tmp=$(dirname -- "$backup")/.sow-yum-original.$$
		[ ! -e "$backup_tmp" ] && [ ! -L "$backup_tmp" ] || die "original backup temporary path exists for $relative"
		cp -p "$PIGSTY_ROOT/$relative" "$backup_tmp"
		[ -f "$backup_tmp" ] && [ ! -L "$backup_tmp" ] && [ "$(hash_file "$backup_tmp")" = "$before" ] || die "original backup temporary digest mismatch for $relative"
		mv "$backup_tmp" "$backup"
	done < "$STAGED/manifest.tsv"
	preflight_manifest "$STAGED/manifest.tsv" "$EVIDENCE/original" "$STAGED"
	# Backups are intentionally allowed after the first gate, but the actual
	# Pigsty mutation starts only after a second network-free validity check.
	# This closes expiry/config/state drift during a slow backup phase.
	validate_preflight_receipt "$digest" quiet
	[ "$preflight_receipt_sha256" = "$initial_preflight_receipt_sha256" ] || die "YUM consumer preflight receipt identity changed before apply"
	changed=false
	while IFS="$(printf '\t')" read -r relative before after; do
		current=$PIGSTY_ROOT/$relative
		observed=$(hash_file "$current")
		[ "$observed" = "$after" ] && continue
		[ "$observed" = "$before" ] || die "foreign drift appeared before apply for $relative"
		temp=$(dirname -- "$current")/.sow-yum-migration.$$
		[ ! -e "$temp" ] && [ ! -L "$temp" ] || die "temporary path already exists for $relative"
		cp -p "$STAGED/$relative" "$temp"
		[ -f "$temp" ] && [ ! -L "$temp" ] && [ "$(hash_file "$temp")" = "$after" ] || die "temporary digest mismatch for $relative"
		[ "$(hash_file "$current")" = "$before" ] || die "foreign drift appeared while applying $relative"
		mv "$temp" "$current"
		changed=true
	done < "$STAGED/manifest.tsv"
	verify_migrated_contract "$PIGSTY_ROOT"
	receipt_tmp=$EVIDENCE/.receipt.$$
	[ ! -e "$receipt_tmp" ] && [ ! -L "$receipt_tmp" ] || die "apply receipt temporary path exists"
	printf 'schema=sow-pigsty-yum-consumer-receipt/v2\nstate=applied\nplan_sha256=%s\npreflight_receipt_sha256=%s\n' "$digest" "$preflight_receipt_sha256" > "$receipt_tmp"
	mv "$receipt_tmp" "$EVIDENCE/receipt"
	echo "plan_sha256=$digest"
	echo "changed=$changed"
	echo 'state=applied'
}

rollback_plan() {
	[ -n "$EVIDENCE" ] || die "rollback requires --evidence"
	plan_data=$(load_plan "$EVIDENCE")
	EVIDENCE=$(printf '%s\n' "$plan_data" | awk -F '\t' 'NR==1 {print $1}')
	digest=$(printf '%s\n' "$plan_data" | awk -F '\t' 'NR==1 {print $2}')
	[ -d "$EVIDENCE/original" ] && [ ! -L "$EVIDENCE/original" ] || die "evidence original directory is missing or unsafe"
	rollback_preflight_sha256=
	if [ -e "$EVIDENCE/preflight-receipt.sha256" ]; then
		[ -f "$EVIDENCE/preflight-receipt.sha256" ] && [ ! -L "$EVIDENCE/preflight-receipt.sha256" ] || die "preflight receipt authority is unsafe"
		rollback_preflight_sha256=$(awk 'NR == 1 { print; next } { exit 1 }' "$EVIDENCE/preflight-receipt.sha256") || die "preflight receipt authority is malformed"
		valid_sha256 "$rollback_preflight_sha256" || die "preflight receipt authority is not a SHA-256"
		[ -d "$EVIDENCE/preflight-receipts" ] && [ ! -L "$EVIDENCE/preflight-receipts" ] || die "preflight receipt archive directory is unsafe"
		rollback_archive=$EVIDENCE/preflight-receipts/$rollback_preflight_sha256.json
		[ -f "$rollback_archive" ] && [ ! -L "$rollback_archive" ] && [ "$(hash_file "$rollback_archive")" = "$rollback_preflight_sha256" ] || die "preflight receipt archive authority is missing or drifted"
	fi
	preflight_manifest "$EVIDENCE/manifest.tsv" "$EVIDENCE/original" ""
	changed=false
	while IFS="$(printf '\t')" read -r relative before after; do
		current=$PIGSTY_ROOT/$relative
		observed=$(hash_file "$current")
		[ "$observed" = "$before" ] && continue
		[ "$observed" = "$after" ] || die "foreign drift appeared before rollback for $relative"
		temp=$(dirname -- "$current")/.sow-yum-rollback.$$
		[ ! -e "$temp" ] && [ ! -L "$temp" ] || die "temporary rollback path already exists for $relative"
		cp -p "$EVIDENCE/original/$relative" "$temp"
		[ -f "$temp" ] && [ ! -L "$temp" ] && [ "$(hash_file "$temp")" = "$before" ] || die "temporary rollback digest mismatch for $relative"
		[ "$(hash_file "$current")" = "$after" ] || die "foreign drift appeared while rolling back $relative"
		mv "$temp" "$current"
		changed=true
	done < "$EVIDENCE/manifest.tsv"
	audit_source >/dev/null
	receipt_tmp=$EVIDENCE/.receipt.$$
	[ ! -e "$receipt_tmp" ] && [ ! -L "$receipt_tmp" ] || die "rollback receipt temporary path exists"
	if [ -n "$rollback_preflight_sha256" ]; then
		printf 'schema=sow-pigsty-yum-consumer-receipt/v2\nstate=rolled-back\nplan_sha256=%s\npreflight_receipt_sha256=%s\n' "$digest" "$rollback_preflight_sha256" > "$receipt_tmp"
	else
		# Backward-compatible rollback for evidence produced by the pre-v2
		# migration script, which had no endpoint-receipt authority to retain.
		printf 'schema=sow-pigsty-yum-consumer-receipt/v1\nstate=rolled-back\nplan_sha256=%s\n' "$digest" > "$receipt_tmp"
	fi
	mv "$receipt_tmp" "$EVIDENCE/receipt"
	echo "plan_sha256=$digest"
	echo "changed=$changed"
	echo 'state=rolled-back'
}

case "$COMMAND" in
	audit) audit_source; echo 'audit=pass' ;;
	stage) audit_source; stage_tree ;;
	verify) audit_source >/dev/null; verify_migrated_contract "$PIGSTY_ROOT"; echo 'verify=pass' ;;
	apply) audit_source >/dev/null; apply_plan ;;
	rollback) rollback_plan ;;
esac
