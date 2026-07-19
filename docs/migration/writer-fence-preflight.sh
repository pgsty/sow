#!/usr/bin/env bash
# Read-only, fail-closed preflight for retiring the legacy Pigsty-v1 writers.
#
# This proves only the effective user's access, explicitly labelled live or
# supplied probes, and a reviewed operator attestation. It does not contact
# cloud IAM and must not be described as independent proof that provider
# credentials were revoked.
set -euo pipefail

LEGACY_ROOT=
ATTESTATION=
OUTPUT=
PROCESS_SNAPSHOT=
CONTAINER_SNAPSHOT=
MOUNT_SNAPSHOT=

usage() {
	cat >&2 <<'EOF'
usage: writer-fence-preflight.sh --legacy-root DIR --attestation FILE --output FILE [options]

options:
  --process-snapshot FILE    normalized process probe; otherwise probe live ps
  --container-snapshot FILE  normalized container mounts; otherwise probe Docker
  --mount-snapshot FILE      normalized mount probe; otherwise probe live mounts

The output must be a new absolute path outside LEGACY_ROOT. Supplied snapshots
must use the schemas emitted by this script's live probes. They are digest-bound
offline evidence, never current-host proof; only three live probes produce
production_current_host_preflight=pass. No writer is stopped and no permission
or cloud state is changed by this command.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--legacy-root)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			LEGACY_ROOT=$2
			shift 2
			;;
		--attestation)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			ATTESTATION=$2
			shift 2
			;;
		--output)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			OUTPUT=$2
			shift 2
			;;
		--process-snapshot)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			PROCESS_SNAPSHOT=$2
			shift 2
			;;
		--container-snapshot)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			CONTAINER_SNAPSHOT=$2
			shift 2
			;;
		--mount-snapshot)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			MOUNT_SNAPSHOT=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown or positional argument: $1" >&2
			usage
			exit 2
			;;
	esac
done

if [[ -z "$LEGACY_ROOT" || -z "$ATTESTATION" || -z "$OUTPUT" ]]; then
	usage
	exit 2
fi
if [[ ! -d "$LEGACY_ROOT" ]]; then
	echo "legacy root is not a directory: $LEGACY_ROOT" >&2
	exit 2
fi
LEGACY_ROOT=$(CDPATH= cd -- "$LEGACY_ROOT" && pwd -P)
if [[ "$LEGACY_ROOT" == *$'\n'* || "$LEGACY_ROOT" == *$'\t'* ]]; then
	echo "legacy root must not contain a newline or tab" >&2
	exit 2
fi

case "$OUTPUT" in
	/*) ;;
	*) echo "output must be an absolute path outside the legacy root" >&2; exit 2 ;;
esac
OUTPUT_DIR=$(dirname -- "$OUTPUT")
OUTPUT_NAME=$(basename -- "$OUTPUT")
if [[ ! -d "$OUTPUT_DIR" ]]; then
	echo "output directory must already exist: $OUTPUT_DIR" >&2
	exit 2
fi
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd -P)
if [[ "$OUTPUT_NAME" == "." || "$OUTPUT_NAME" == ".." || "$OUTPUT_NAME" == *$'\n'* ]]; then
	echo "unsafe output filename" >&2
	exit 2
fi
OUTPUT=$OUTPUT_DIR/$OUTPUT_NAME
if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
	echo "refusing to overwrite output: $OUTPUT" >&2
	exit 2
fi
case "$OUTPUT" in
	"$LEGACY_ROOT"|"$LEGACY_ROOT"/*)
		echo "output must be outside the legacy root" >&2
		exit 2
		;;
esac

canonical_input() {
	local path=$1 label=$2 dir base
	if [[ ! -f "$path" || -L "$path" ]]; then
		echo "$label must be a regular, non-symlink file: $path" >&2
		exit 2
	fi
	dir=$(dirname -- "$path")
	base=$(basename -- "$path")
	dir=$(CDPATH= cd -- "$dir" && pwd -P)
	path=$dir/$base
	case "$path" in
		"$LEGACY_ROOT"|"$LEGACY_ROOT"/*)
			echo "$label must be outside the legacy root" >&2
			exit 2
			;;
	esac
	printf '%s\n' "$path"
}

ATTESTATION=$(canonical_input "$ATTESTATION" attestation)

umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-writer-fence.XXXXXX")
OUTPUT_TMP=
cleanup() {
	rm -rf "$TMP"
	if [[ -n "$OUTPUT_TMP" ]]; then rm -f "$OUTPUT_TMP"; fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Bind every externally reviewed input to this invocation before validation.
# The report hashes these private copies, so a concurrent edit cannot make the
# validated bytes differ from the durable evidence digest.
ATTESTATION_SOURCE=$ATTESTATION
ATTESTATION=$TMP/attestation
if ! cp "$ATTESTATION_SOURCE" "$ATTESTATION"; then
	echo "failed to bind attestation input" >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
	hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

if LEGACY_STAT_PROBE=$(stat -f '%d:%i' "$LEGACY_ROOT" 2>/dev/null) && [[ "$LEGACY_STAT_PROBE" =~ ^[0-9]+:[0-9]+$ ]]; then
	LEGACY_STAT_STYLE=bsd
else
	LEGACY_STAT_STYLE=gnu
fi

file_identity() {
	local path=$1
	if [[ "$LEGACY_STAT_STYLE" == bsd ]]; then
		stat -L -f '%d:%i' "$path" 2>/dev/null
	else
		stat -Lc '%d:%i' -- "$path" 2>/dev/null
	fi
}

make_legacy_inode_snapshot() {
	local destination=$1 unsorted
	unsorted=$destination.unsorted
	if [[ "$LEGACY_STAT_STYLE" == bsd ]]; then
		if ! find "$LEGACY_ROOT" -type f -exec stat -f '%d:%i' {} + > "$unsorted"; then
			echo "failed to inventory legacy file identities" >&2
			exit 1
		fi
	else
		if ! find "$LEGACY_ROOT" -type f -exec stat -Lc '%d:%i' -- {} + > "$unsorted"; then
			echo "failed to inventory legacy file identities" >&2
			exit 1
		fi
	fi
	if ! LC_ALL=C sort -u "$unsorted" > "$destination"; then
		echo "failed to normalize legacy file identities" >&2
		exit 1
	fi
}

# The schema is deliberately closed. Unknown fields could accidentally turn a
# secret-bearing operator note into durable evidence, so they fail validation.
if ! awk -F= '
	BEGIN {
		allowed["schema"]=1
		allowed["scheduler_writers_disabled"]=1
		allowed["legacy_cloud_credentials_revoked"]=1
		allowed["legacy_containers_stopped"]=1
		allowed["legacy_make_writers_archived"]=1
		allowed["sow_exclusive_writer"]=1
		allowed["approved_change"]=1
		allowed["approved_at"]=1
	}
	NF < 2 { print "invalid empty/malformed attestation line " NR > "/dev/stderr"; bad=1; next }
	{
		key=$1
		if (!allowed[key]) { print "unknown attestation field: " key > "/dev/stderr"; bad=1 }
		if (seen[key]++) { print "duplicate attestation field: " key > "/dev/stderr"; bad=1 }
	}
	END {
		for (key in allowed) if (!seen[key]) {
			print "missing attestation field: " key > "/dev/stderr"
			bad=1
		}
		exit bad ? 1 : 0
	}
' "$ATTESTATION"; then
	exit 1
fi
for required in \
	'schema=sow-writer-revocation/v1' \
	'scheduler_writers_disabled=true' \
	'legacy_cloud_credentials_revoked=true' \
	'legacy_containers_stopped=true' \
	'legacy_make_writers_archived=true' \
	'sow_exclusive_writer=true'
do
	if ! grep -Fqx "$required" "$ATTESTATION"; then
		echo "attestation is not approved: $required" >&2
		exit 1
	fi
done
if ! grep -Eq '^approved_change=[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$' "$ATTESTATION"; then
	echo "attestation approved_change must be a non-secret change identifier" >&2
	exit 1
fi
APPROVED_AT=$(sed -n 's/^approved_at=//p' "$ATTESTATION")
if ! grep -Eq '^approved_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' "$ATTESTATION" ||
	! awk -v value="$APPROVED_AT" '
		BEGIN {
			year=substr(value,1,4)+0
			month=substr(value,6,2)+0
			day=substr(value,9,2)+0
			hour=substr(value,12,2)+0
			minute=substr(value,15,2)+0
			second=substr(value,18,2)+0
			leap=(year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
			days[1]=31; days[2]=(leap ? 29 : 28); days[3]=31; days[4]=30
			days[5]=31; days[6]=30; days[7]=31; days[8]=31
			days[9]=30; days[10]=31; days[11]=30; days[12]=31
			exit !(year >= 1 && month >= 1 && month <= 12 &&
			       day >= 1 && day <= days[month] &&
			       hour <= 23 && minute <= 59 && second <= 59)
		}
	' </dev/null
then
	echo "attestation approved_at must be an RFC3339 UTC timestamp" >&2
	exit 1
fi

make_process_snapshot() {
	local destination=$1 pid class explicit cwd process_count
	printf 'schema=sow-process-probe/v2\n' > "$destination"
	printf 'scope\tknown-processes-and-effective-user-writable-fds\n' >> "$destination"
	if ! ps -axo pid=,command= > "$TMP/process-raw"; then
		echo "live process probe failed" >&2
		exit 1
	fi
	if ! awk -v root="$LEGACY_ROOT" '
		BEGIN { OFS="\t"; count=0 }
		{
			pid=$1
			sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
			command=$0
			count++
			class=""
			if (command ~ /(^|[[:space:]\/])make([[:space:]]|$)/) class="make"
			else if (command ~ /(^|[[:space:]\/])(rclone|rsync|reprepro|createrepo|createrepo_c)([[:space:]]|$)/) class="repo-writer"
			else if (command ~ /(^|[[:space:]\/])rpm[[:space:]].*(--addsign|--resign)/) class="rpm-signer"
			else if (command ~ /(^|[[:space:]\/])sow[[:space:]]+(init|add|rm|sync|promote|publish|materialize)([[:space:]]|$)/) class="sow-writer"
			else if (command ~ /(^|[[:space:]\/])docker[[:space:]]+(run|exec|compose)([[:space:]]|$)/) class="docker-writer"
			if (class != "") print pid, class, (index(command, root) != 0 ? 1 : 0)
		}
		END { print count > count_file }
	' count_file="$TMP/process-total" "$TMP/process-raw" > "$TMP/process-candidates"; then
		echo "live process probe failed" >&2
		exit 1
	fi
	process_count=$(cat "$TMP/process-total")
	while IFS=$'\t' read -r pid class explicit; do
		[[ -n "$pid" ]] || continue
		if [[ "$explicit" == 1 ]]; then
			printf 'writer\t%s\t%s\n' "$pid" "$class" >> "$destination"
			continue
		fi
		if ! cwd=$(live_process_cwd "$pid"); then
			# A process that exited after the atomic ps snapshot is no longer a
			# writer. An active candidate whose cwd cannot be inspected makes the
			# current-host probe incomplete and therefore fails closed.
			if ps -p "$pid" -o pid= >/dev/null 2>&1; then
				echo "cannot inspect cwd of active writer candidate pid=$pid class=$class" >&2
				exit 1
			fi
			continue
		fi
		case "$cwd" in
			"$LEGACY_ROOT"|"$LEGACY_ROOT"/*)
				printf 'writer\t%s\t%s\n' "$pid" "$class" >> "$destination"
				;;
		esac
	done < "$TMP/process-candidates"
	make_writable_fd_snapshot "$destination"
	printf 'probe\tcomplete\t%s\n' "$process_count" >> "$destination"
}

# Permissions on a pathname do not revoke an already-open writable file
# descriptor. Inspect every descriptor owned by the effective user and bind
# this closure into the same process snapshot as the known-writer scan. Linux
# uses procfs directly; macOS and other supported hosts use the system lsof.
make_writable_fd_snapshot() {
	local destination=$1
	: > "$TMP/fd-writers"
	if [[ -d /proc/self/fd && -r /proc/self/status ]]; then
		make_proc_writable_fd_snapshot
	else
		make_lsof_writable_fd_snapshot
	fi
	LC_ALL=C sort -u "$TMP/fd-writers" >> "$destination"
	IFS=$'\t' read -r FD_PROCESS_COUNT FD_COUNT < "$TMP/fd-total"
	printf 'fd-probe\tcomplete\t%s\t%s\n' "$FD_PROCESS_COUNT" "$FD_COUNT" >> "$destination"
}

make_proc_writable_fd_snapshot() {
	local effective_uid pid_dir pid owner fd flags access target identity matched
	local processes=0 descriptors=0
	effective_uid=$(id -u)
	for pid_dir in /proc/[0-9]*; do
		[[ -d "$pid_dir" ]] || continue
		pid=${pid_dir##*/}
		if ! owner=$(awk '$1 == "Uid:" { print $2; found=1; exit } END { exit found ? 0 : 1 }' "$pid_dir/status" 2>/dev/null); then
			if [[ -d "$pid_dir" ]] && ps -p "$pid" -o pid= >/dev/null 2>&1; then
				echo "cannot inspect owner of active process pid=$pid" >&2
				exit 1
			fi
			continue
		fi
		[[ "$owner" == "$effective_uid" ]] || continue
		processes=$((processes + 1))
		if [[ ! -d "$pid_dir/fd" || ! -r "$pid_dir/fd" ]]; then
			if ps -p "$pid" -o pid= >/dev/null 2>&1; then
				echo "cannot inspect descriptors of active effective-user process pid=$pid" >&2
				exit 1
			fi
			continue
		fi
		for fd in "$pid_dir"/fd/*; do
			[[ -L "$fd" ]] || continue
			if ! flags=$(awk '$1 == "flags:" { print $2; found=1; exit } END { exit found ? 0 : 1 }' "$pid_dir/fdinfo/${fd##*/}" 2>/dev/null); then
				if [[ -L "$fd" ]] && ps -p "$pid" -o pid= >/dev/null 2>&1; then
					echo "cannot inspect descriptor flags of active process pid=$pid fd=${fd##*/}" >&2
					exit 1
				fi
				continue
			fi
			descriptors=$((descriptors + 1))
			access=${flags: -1}
			[[ "$access" == 1 || "$access" == 2 ]] || continue
			if ! target=$(readlink "$fd" 2>/dev/null); then
				if [[ -L "$fd" ]] && ps -p "$pid" -o pid= >/dev/null 2>&1; then
					echo "cannot inspect writable descriptor target of active process pid=$pid fd=${fd##*/}" >&2
					exit 1
				fi
				continue
			fi
				target=${target%" (deleted)"}
				matched=0
				case "$target" in
					"$LEGACY_ROOT"|"$LEGACY_ROOT"/*)
						matched=1
						;;
				esac
				if identity=$(file_identity "$fd"); then
					if grep -Fqx "$identity" "$TMP/legacy-inodes.before"; then matched=1; fi
				elif [[ -L "$fd" ]] && ps -p "$pid" -o pid= >/dev/null 2>&1; then
					echo "cannot inspect writable descriptor identity of active process pid=$pid fd=${fd##*/}" >&2
					exit 1
				fi
				if [[ "$matched" == 1 ]]; then
					printf 'writer\t%s\twritable-fd\n' "$pid" >> "$TMP/fd-writers"
				fi
			done
	done
	printf '%s\t%s\n' "$processes" "$descriptors" > "$TMP/fd-total"
}

make_lsof_writable_fd_snapshot() {
	local effective_uid pid device inode decimal_device identity
	effective_uid=$(id -u)
	if ! command -v lsof >/dev/null 2>&1; then
		echo "live writable-descriptor probe requires procfs or lsof" >&2
		exit 1
	fi
	if ! lsof -nP -u "$effective_uid" -F pfaDtin > "$TMP/lsof-raw" 2> "$TMP/lsof-error"; then
		echo "live writable-descriptor lsof probe failed" >&2
		exit 1
	fi
	if [[ -s "$TMP/lsof-error" ]]; then
		echo "live writable-descriptor lsof probe was incomplete" >&2
		exit 1
	fi
	: > "$TMP/lsof-writable-identities"
	if ! awk -v root="$LEGACY_ROOT" -v writers="$TMP/fd-writers" -v candidates="$TMP/lsof-writable-identities" -v totals="$TMP/fd-total" '
		function within(name, root) { return name == root || index(name, root "/") == 1 }
		substr($0,1,1) == "p" { pid=substr($0,2); processes[pid]=1; access=""; device=""; type=""; inode=""; next }
		substr($0,1,1) == "f" { access=""; device=""; type=""; inode=""; next }
		substr($0,1,1) == "a" { access=substr($0,2); next }
		substr($0,1,1) == "D" { device=substr($0,2); next }
		substr($0,1,1) == "t" { type=substr($0,2); next }
		substr($0,1,1) == "i" { inode=substr($0,2); next }
		substr($0,1,1) == "n" {
			name=substr($0,2)
			sub(/ \(deleted\)$/, "", name)
			descriptors++
			if (access == "w" || access == "u") {
				if (within(name, root)) print "writer\t" pid "\twritable-fd" >> writers
				if (type == "REG" || type == "VREG") {
					if (device !~ /^(0x[0-9A-Fa-f]+|[0-9]+)$/ || inode !~ /^[0-9]+$/) bad=1
					else print pid "\t" device "\t" inode >> candidates
				}
			}
			next
		}
		END {
			for (pid in processes) process_count++
			print process_count+0 "\t" descriptors+0 > totals
			exit bad ? 1 : 0
		}
		' "$TMP/lsof-raw"; then
		echo "live writable-descriptor lsof output is invalid" >&2
		exit 1
	fi
	while IFS=$'\t' read -r pid device inode; do
		[[ -n "$pid" ]] || continue
		if [[ "$device" == 0x* ]]; then
			if ! printf -v decimal_device '%d' "$device" 2>/dev/null; then
				echo "live writable-descriptor lsof device is invalid: $device" >&2
				exit 1
			fi
		else
			decimal_device=$device
		fi
		identity=$decimal_device:$inode
		if grep -Fqx "$identity" "$TMP/legacy-inodes.before"; then
			printf 'writer\t%s\twritable-fd\n' "$pid" >> "$TMP/fd-writers"
		fi
	done < "$TMP/lsof-writable-identities"
}

live_process_cwd() {
	local pid=$1 value
	if [[ -L "/proc/$pid/cwd" ]]; then
		readlink "/proc/$pid/cwd"
		return
	fi
	if command -v lsof >/dev/null 2>&1; then
		value=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | awk 'substr($0,1,1)=="n" { print substr($0,2); found=1; exit } END { exit found ? 0 : 1 }') || return 1
		[[ "$value" == /* && "$value" != *$'\n'* && "$value" != *$'\t'* ]] || return 1
		printf '%s\n' "$value"
		return
	fi
	return 1
}

make_container_snapshot() {
	local destination=$1 ids id
	printf 'schema=sow-container-mount-probe/v1\n' > "$destination"
	if ! command -v docker >/dev/null 2>&1; then
		printf 'runtime\tabsent\n' >> "$destination"
		return
	fi
	if ! ids=$(docker ps -q 2>/dev/null); then
		echo "Docker is installed but the live container probe is unavailable" >&2
		exit 1
	fi
	printf 'runtime\tdocker\n' >> "$destination"
	for id in $ids; do
		if ! docker inspect --format '{{range .Mounts}}{{printf "%s\\t%s\\t%t\\n" .Source .Destination .RW}}{{end}}' "$id" 2>/dev/null |
			awk -v id="$id" -F '\t' 'BEGIN { OFS="\t" } NF == 3 { print "container", id, $1, $2, ($3 == "true" ? "rw" : "ro") } NF != 3 { bad=1 } END { exit bad ? 1 : 0 }' >> "$destination"
		then
			echo "failed to inspect running container: $id" >&2
			exit 1
		fi
	done
}

make_mount_snapshot() {
	local destination=$1
	printf 'schema=sow-mount-probe/v1\n' > "$destination"
	if ! mount | awk '
		BEGIN { OFS="\t"; count=0 }
		{
			line=$0
			marker=index(line, " on ")
			if (!marker) { bad=1; next }
			rest=substr(line, marker+4)
			target=rest
			sub(/[[:space:]]+type[[:space:]].*$/, "", target)
			sub(/[[:space:]]+\(.*/, "", target)
			mode=(line ~ /\(([^)]*,)?(ro|read-only)(,[^)]*)?\)/ || line ~ /,[[:space:]]*read-only([,\)])/ ? "ro" : "rw")
			if (target == "" || index(target, "\t")) { bad=1; next }
			print "mount", target, mode
			count++
		}
		END {
			print "probe", "complete", count
			exit bad ? 1 : 0
		}
	' >> "$destination"; then
		echo "live mount probe failed" >&2
		exit 1
	fi
}

# Bind the complete regular-file device/inode set before inspecting live
# descriptors. This catches writers that opened an external hard-link alias,
# whose reported pathname is outside LEGACY_ROOT but whose inode is still part
# of the legacy repository.
make_legacy_inode_snapshot "$TMP/legacy-inodes.before"

if [[ -n "$PROCESS_SNAPSHOT" ]]; then
	PROCESS_PROBE_SOURCE=supplied-snapshot
	PROCESS_SOURCE=$(canonical_input "$PROCESS_SNAPSHOT" process-snapshot)
	PROCESS_SNAPSHOT=$TMP/process.tsv
	if ! cp "$PROCESS_SOURCE" "$PROCESS_SNAPSHOT"; then
		echo "failed to bind process snapshot" >&2
		exit 1
	fi
else
	PROCESS_PROBE_SOURCE=live-current-host
	PROCESS_SNAPSHOT=$TMP/process.tsv
	make_process_snapshot "$PROCESS_SNAPSHOT"
fi
if [[ -n "$CONTAINER_SNAPSHOT" ]]; then
	CONTAINER_PROBE_SOURCE=supplied-snapshot
	CONTAINER_SOURCE=$(canonical_input "$CONTAINER_SNAPSHOT" container-snapshot)
	CONTAINER_SNAPSHOT=$TMP/container.tsv
	if ! cp "$CONTAINER_SOURCE" "$CONTAINER_SNAPSHOT"; then
		echo "failed to bind container snapshot" >&2
		exit 1
	fi
else
	CONTAINER_PROBE_SOURCE=live-current-host
	CONTAINER_SNAPSHOT=$TMP/container.tsv
	make_container_snapshot "$CONTAINER_SNAPSHOT"
fi
if [[ -n "$MOUNT_SNAPSHOT" ]]; then
	MOUNT_PROBE_SOURCE=supplied-snapshot
	MOUNT_SOURCE=$(canonical_input "$MOUNT_SNAPSHOT" mount-snapshot)
	MOUNT_SNAPSHOT=$TMP/mount.tsv
	if ! cp "$MOUNT_SOURCE" "$MOUNT_SNAPSHOT"; then
		echo "failed to bind mount snapshot" >&2
		exit 1
	fi
else
	MOUNT_PROBE_SOURCE=live-current-host
	MOUNT_SNAPSHOT=$TMP/mount.tsv
	make_mount_snapshot "$MOUNT_SNAPSHOT"
fi

if ! awk -F '\t' '
	NR == 1 { if ($0 != "schema=sow-process-probe/v2") bad=1; next }
	$1 == "scope" && NF == 2 && $2 == "known-processes-and-effective-user-writable-fds" { scope++; next }
	$1 == "writer" && NF == 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^(make|repo-writer|rpm-signer|sow-writer|docker-writer|writable-fd)$/ { writers++; next }
	$1 == "fd-probe" && $2 == "complete" && NF == 4 && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ { fd_complete++; fd_processes=$3; descriptors=$4; next }
	$1 == "probe" && $2 == "complete" && NF == 3 && $3 ~ /^[0-9]+$/ { complete++; next }
	{ bad=1 }
	END {
		if (scope != 1 || complete != 1 || fd_complete != 1) bad=1
		print writers+0 "\t" fd_processes+0 "\t" descriptors+0
		exit bad ? 1 : 0
	}
' "$PROCESS_SNAPSHOT" > "$TMP/process-count"; then
	echo "invalid or incomplete process snapshot" >&2
	exit 1
fi
IFS=$'\t' read -r SUSPICIOUS_PROCESSES FD_PROCESS_COUNT FD_COUNT < "$TMP/process-count"
if [[ "$SUSPICIOUS_PROCESSES" != 0 ]]; then
	echo "process probe found $SUSPICIOUS_PROCESSES legacy writer process(es)" >&2
	exit 1
fi

if ! awk -F '\t' -v root="$LEGACY_ROOT" '
	function overlaps(source, root) {
		while (length(source) > 1 && substr(source, length(source), 1) == "/") source=substr(source, 1, length(source)-1)
		while (length(root) > 1 && substr(root, length(root), 1) == "/") root=substr(root, 1, length(root)-1)
		if (source == "/") return 1
		return source == root || index(root, source "/") == 1 || index(source, root "/") == 1
	}
	NR == 1 { if ($0 != "schema=sow-container-mount-probe/v1") bad=1; next }
	$1 == "runtime" && NF == 2 && ($2 == "absent" || $2 == "docker") { runtime++; next }
	$1 == "container" && NF == 5 && $5 ~ /^(rw|ro)$/ {
		mounts++
		if ($5 == "rw" && overlaps($3, root)) risky++
		next
	}
	{ bad=1 }
	END {
		if (runtime != 1) bad=1
		print risky+0 "\t" mounts+0
		exit bad ? 1 : 0
	}
' "$CONTAINER_SNAPSHOT" > "$TMP/container-count"; then
	echo "invalid or incomplete container snapshot" >&2
	exit 1
fi
IFS=$'\t' read -r RISKY_CONTAINERS CONTAINER_MOUNTS < "$TMP/container-count"
if [[ "$RISKY_CONTAINERS" != 0 ]]; then
	echo "container probe found $RISKY_CONTAINERS writable mount(s) overlapping the legacy root" >&2
	exit 1
fi

if ! awk -F '\t' -v root="$LEGACY_ROOT" '
	NR == 1 { if ($0 != "schema=sow-mount-probe/v1") bad=1; next }
	$1 == "mount" && NF == 3 && $3 ~ /^(rw|ro)$/ {
		mounts++
		if ($3 == "rw" && ($2 == root || index($2, root "/") == 1)) risky++
		next
	}
	$1 == "probe" && $2 == "complete" && NF == 3 && $3 ~ /^[0-9]+$/ { complete++; next }
	{ bad=1 }
	END {
		if (complete != 1) bad=1
		print risky+0 "\t" mounts+0
		exit bad ? 1 : 0
	}
' "$MOUNT_SNAPSHOT" > "$TMP/mount-count"; then
	echo "invalid or incomplete mount snapshot" >&2
	exit 1
fi
IFS=$'\t' read -r RISKY_MOUNTS MOUNT_COUNT < "$TMP/mount-count"
if [[ "$RISKY_MOUNTS" != 0 ]]; then
	echo "mount probe found $RISKY_MOUNTS writable mount(s) at or below the legacy root" >&2
	exit 1
fi

for required in Makefile apt/Makefile yum/Makefile docker/Makefile; do
	if [[ ! -f "$LEGACY_ROOT/$required" || -L "$LEGACY_ROOT/$required" ]]; then
		echo "missing regular legacy Makefile: $required" >&2
		exit 1
	fi
done

ENTRY_COUNT=0
WRITABLE_COUNT=0
FIRST_WRITABLE=
if ! UNSUPPORTED=$(find "$LEGACY_ROOT" ! -type d ! -type f -print -quit); then
	echo "failed to inspect legacy entry types" >&2
	exit 1
fi
if [[ -n "$UNSUPPORTED" ]]; then
	echo "legacy tree contains an unsupported non-regular entry: $UNSUPPORTED" >&2
	exit 1
fi
if ! find "$LEGACY_ROOT" \( -type d -o -type f \) -print0 > "$TMP/legacy-entries"; then
	echo "failed to enumerate the complete legacy tree" >&2
	exit 1
fi
while IFS= read -r -d '' entry; do
	ENTRY_COUNT=$((ENTRY_COUNT + 1))
	if [[ -w "$entry" ]]; then
		WRITABLE_COUNT=$((WRITABLE_COUNT + 1))
		if [[ -z "$FIRST_WRITABLE" ]]; then FIRST_WRITABLE=$entry; fi
	fi
done < "$TMP/legacy-entries"
make_legacy_inode_snapshot "$TMP/legacy-inodes.after"
if ! cmp -s "$TMP/legacy-inodes.before" "$TMP/legacy-inodes.after"; then
	echo "legacy file identity inventory changed during preflight" >&2
	exit 1
fi
LEGACY_FILE_INODES=$(wc -l < "$TMP/legacy-inodes.before" | tr -d ' ')
if [[ "$WRITABLE_COUNT" != 0 ]]; then
	echo "effective user can still write $WRITABLE_COUNT legacy entries; first: $FIRST_WRITABLE" >&2
	exit 1
fi

LIVE_PROBE_COUNT=0
for source in "$PROCESS_PROBE_SOURCE" "$CONTAINER_PROBE_SOURCE" "$MOUNT_PROBE_SOURCE"; do
	if [[ "$source" == live-current-host ]]; then LIVE_PROBE_COUNT=$((LIVE_PROBE_COUNT + 1)); fi
done
case "$LIVE_PROBE_COUNT" in
	3)
		CURRENT_HOST_PROBE_COVERAGE=complete
		PROBE_EVIDENCE_MODE=live-current-host
		PRODUCTION_CURRENT_HOST_PREFLIGHT=pass
		EVIDENCE_SCOPE=effective-user-plus-current-host-live-probes-plus-operator-attestation
		;;
	0)
		CURRENT_HOST_PROBE_COVERAGE=none
		PROBE_EVIDENCE_MODE=supplied-snapshots
		PRODUCTION_CURRENT_HOST_PREFLIGHT=not-proven
		EVIDENCE_SCOPE=effective-user-plus-supplied-snapshots-plus-operator-attestation
		;;
	*)
		CURRENT_HOST_PROBE_COVERAGE=partial
		PROBE_EVIDENCE_MODE=mixed-live-and-supplied
		PRODUCTION_CURRENT_HOST_PREFLIGHT=not-proven
		EVIDENCE_SCOPE=effective-user-plus-mixed-live-and-supplied-probes-plus-operator-attestation
		;;
esac

OUTPUT_TMP=$(mktemp "$OUTPUT.tmp.XXXXXX")
{
	printf 'schema=sow-writer-fence-report/v4\n'
	printf 'legacy_root=%s\n' "$LEGACY_ROOT"
	printf 'attestation_sha256=%s\n' "$(hash_file "$ATTESTATION")"
	printf 'process_snapshot_sha256=%s\n' "$(hash_file "$PROCESS_SNAPSHOT")"
	printf 'container_snapshot_sha256=%s\n' "$(hash_file "$CONTAINER_SNAPSHOT")"
	printf 'mount_snapshot_sha256=%s\n' "$(hash_file "$MOUNT_SNAPSHOT")"
	printf 'process_probe_source=%s\n' "$PROCESS_PROBE_SOURCE"
	printf 'container_probe_source=%s\n' "$CONTAINER_PROBE_SOURCE"
	printf 'mount_probe_source=%s\n' "$MOUNT_PROBE_SOURCE"
	printf 'probe_evidence_mode=%s\n' "$PROBE_EVIDENCE_MODE"
	printf 'current_host_probe_coverage=%s\n' "$CURRENT_HOST_PROBE_COVERAGE"
	printf 'production_current_host_preflight=%s\n' "$PRODUCTION_CURRENT_HOST_PREFLIGHT"
	printf 'legacy_entries=%s\n' "$ENTRY_COUNT"
	printf 'legacy_file_inodes=%s\n' "$LEGACY_FILE_INODES"
	printf 'legacy_file_inode_snapshot_sha256=%s\n' "$(hash_file "$TMP/legacy-inodes.before")"
	printf 'writable_entries=0\n'
	printf 'suspicious_processes=0\n'
	printf 'effective_user_processes_inspected=%s\n' "$FD_PROCESS_COUNT"
	printf 'open_descriptors_inspected=%s\n' "$FD_COUNT"
	printf 'legacy_writable_open_descriptors=0\n'
	printf 'container_mounts=%s\n' "$CONTAINER_MOUNTS"
	printf 'legacy_rw_container_mounts=0\n'
	printf 'mounts=%s\n' "$MOUNT_COUNT"
	printf 'legacy_rw_submounts=0\n'
	printf 'evidence_scope=%s\n' "$EVIDENCE_SCOPE"
	printf 'writer_revoke_preflight=pass\n'
} > "$OUTPUT_TMP"
if ! ln "$OUTPUT_TMP" "$OUTPUT"; then
	echo "refusing to replace output created during preflight: $OUTPUT" >&2
	exit 1
fi
rm -f "$OUTPUT_TMP"
OUTPUT_TMP=
printf 'writer_revoke_preflight=pass report=%s entries=%s current_host=%s\n' "$OUTPUT" "$ENTRY_COUNT" "$PRODUCTION_CURRENT_HOST_PREFLIGHT"
