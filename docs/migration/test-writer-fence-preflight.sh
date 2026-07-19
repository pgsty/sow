#!/usr/bin/env bash
# Deterministic positive and negative tests for writer-fence-preflight.sh.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFLIGHT=$SCRIPT_DIR/writer-fence-preflight.sh
umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/sow-writer-fence-test.XXXXXX")
cleanup() {
	if [[ -n "${WRITER_PID:-}" ]]; then kill "$WRITER_PID" 2>/dev/null || true; wait "$WRITER_PID" 2>/dev/null || true; fi
	if [[ -n "${ROOT:-}" ]]; then chmod u+rwx "$ROOT" "$ROOT/pkg" 2>/dev/null || true; fi
	chmod -R u+w "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

ROOT=$TMP/legacy
INPUT=$TMP/input
mkdir -p "$ROOT/apt" "$ROOT/yum" "$ROOT/docker" "$ROOT/pkg" "$INPUT"
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P)
for file in Makefile apt/Makefile yum/Makefile docker/Makefile pkg/pig.tar.gz; do
	printf 'legacy fixture %s\n' "$file" > "$ROOT/$file"
done

write_attestation() {
	local destination=$1 cloud=${2:-true} approved_at=${3:-2026-07-12T12:00:00Z}
	cat > "$destination" <<EOF
schema=sow-writer-revocation/v1
scheduler_writers_disabled=true
legacy_cloud_credentials_revoked=$cloud
legacy_containers_stopped=true
legacy_make_writers_archived=true
sow_exclusive_writer=true
approved_change=CHG-2026-0712
approved_at=$approved_at
EOF
}

write_attestation "$INPUT/attestation"
cat > "$INPUT/process.tsv" <<'EOF'
schema=sow-process-probe/v2
scope	known-processes-and-effective-user-writable-fds
fd-probe	complete	17	51
probe	complete	17
EOF
cat > "$INPUT/container.tsv" <<'EOF'
schema=sow-container-mount-probe/v1
runtime	docker
container	unrelated	/tmp/cache	/cache	rw
EOF
cat > "$INPUT/mount.tsv" <<'EOF'
schema=sow-mount-probe/v1
mount	/	rw
probe	complete	1
EOF

chmod -R a-w "$ROOT"

pass() { printf 'PASS %s\n' "$1"; }
expect_fail() {
	local name=$1 expected=$2
	shift 2
	if "$@" > "$TMP/$name.out" 2> "$TMP/$name.err"; then
		echo "expected fail-closed preflight: $name" >&2
		exit 1
	fi
	if ! grep -Eq "$expected" "$TMP/$name.out" "$TMP/$name.err"; then
		echo "preflight failed for the wrong reason: $name (expected /$expected/)" >&2
		cat "$TMP/$name.out" "$TMP/$name.err" >&2
		exit 1
	fi
	pass "$name"
}

run_preflight() {
	local output=$1
	shift
	"$PREFLIGHT" \
		--legacy-root "$ROOT" \
		--attestation "$INPUT/attestation" \
		--process-snapshot "$INPUT/process.tsv" \
		--container-snapshot "$INPUT/container.tsv" \
		--mount-snapshot "$INPUT/mount.tsv" \
		--output "$output" "$@"
}

run_preflight "$TMP/report-1.txt" > "$TMP/pass.out"
run_preflight "$TMP/report-2.txt" >> "$TMP/pass.out"
cmp "$TMP/report-1.txt" "$TMP/report-2.txt"
grep -Fqx 'writer_revoke_preflight=pass' "$TMP/report-1.txt"
grep -Fqx 'writable_entries=0' "$TMP/report-1.txt"
grep -Fqx 'legacy_rw_container_mounts=0' "$TMP/report-1.txt"
grep -Fqx 'legacy_rw_submounts=0' "$TMP/report-1.txt"
grep -Fqx 'schema=sow-writer-fence-report/v4' "$TMP/report-1.txt"
grep -Eq '^legacy_file_inodes=[0-9]+$' "$TMP/report-1.txt"
grep -Eq '^legacy_file_inode_snapshot_sha256=[0-9a-f]{64}$' "$TMP/report-1.txt"
grep -Fqx 'legacy_writable_open_descriptors=0' "$TMP/report-1.txt"
grep -Fqx 'probe_evidence_mode=supplied-snapshots' "$TMP/report-1.txt"
grep -Fqx 'current_host_probe_coverage=none' "$TMP/report-1.txt"
grep -Fqx 'production_current_host_preflight=not-proven' "$TMP/report-1.txt"
pass deterministic-read-only-baseline

"$PREFLIGHT" \
	--legacy-root "$ROOT" \
	--attestation "$INPUT/attestation" \
	--container-snapshot "$INPUT/container.tsv" \
	--output "$TMP/live-host-probes.txt" > "$TMP/live-host-probes.out"
grep -Fqx 'writer_revoke_preflight=pass' "$TMP/live-host-probes.txt"
grep -Fqx 'probe_evidence_mode=mixed-live-and-supplied' "$TMP/live-host-probes.txt"
grep -Fqx 'current_host_probe_coverage=partial' "$TMP/live-host-probes.txt"
grep -Fqx 'production_current_host_preflight=not-proven' "$TMP/live-host-probes.txt"
pass live-process-and-mount-probes

run_live_process_preflight() {
	local output=$1
	"$PREFLIGHT" \
		--legacy-root "$ROOT" \
		--attestation "$INPUT/attestation" \
		--container-snapshot "$INPUT/container.tsv" \
		--mount-snapshot "$INPUT/mount.tsv" \
		--output "$output"
}

# The lsof fallback must reject any writable descriptor record whose device or
# inode identity is absent. Otherwise an external hard-link alias could be
# silently omitted from identity matching. Linux exercises the independent
# procfs implementation below; this mutation targets hosts that use lsof.
if [[ ! -d /proc/self/fd || ! -r /proc/self/status ]]; then
	REAL_LSOF=$(command -v lsof)
	mkdir -p "$INPUT/lsof-shim"
	cat > "$INPUT/lsof-shim/lsof" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" -u "* ]]; then
	printf 'p999999\nf9\nau\ntREG\nn/tmp/sow-malformed-external-alias\n'
	exit 0
fi
exec "$SOW_TEST_REAL_LSOF" "$@"
EOF
	chmod 700 "$INPUT/lsof-shim/lsof"
	run_malformed_lsof_preflight() (
		export PATH="$INPUT/lsof-shim:$PATH"
		export SOW_TEST_REAL_LSOF="$REAL_LSOF"
		run_live_process_preflight "$1"
	)
	expect_fail malformed-lsof-identity 'lsof output is invalid' run_malformed_lsof_preflight "$TMP/malformed-lsof-report.txt"
fi
ln -s "$(command -v sleep)" "$INPUT/make"
(
	cd "$ROOT"
	exec "$INPUT/make" 30
) &
WRITER_PID=$!
sleep 0.2
expect_fail relative-cwd-writer 'legacy writer process' run_live_process_preflight "$TMP/relative-cwd-report.txt"
kill "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
WRITER_PID=
pass relative-cwd-live-process-probe

# A process can keep writing through a descriptor opened before chmod. Its
# command and cwd are deliberately unrelated to the legacy root.
chmod u+w "$ROOT/pkg/pig.tar.gz"
(
	exec 9<> "$ROOT/pkg/pig.tar.gz"
	printf 'ready\n' > "$INPUT/fd-writer-ready"
	while :; do sleep 0.05; done
) &
WRITER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[[ -f "$INPUT/fd-writer-ready" ]] && break
	sleep 0.05
done
[[ -f "$INPUT/fd-writer-ready" ]] || { echo 'writable-fd fixture did not start' >&2; exit 1; }
chmod a-w "$ROOT/pkg/pig.tar.gz"
expect_fail arbitrary-open-writable-fd 'legacy writer process' run_live_process_preflight "$TMP/open-fd-report.txt"
kill "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
WRITER_PID=
pass arbitrary-open-writable-fd-live-probe

# Opening an external hard-link alias still grants writes to the legacy inode.
# Path-only descriptor checks miss this; the live probe must compare device and
# inode identities against the complete legacy regular-file set.
rm -f "$INPUT/fd-writer-ready"
chmod u+w "$ROOT/pkg/pig.tar.gz"
ln "$ROOT/pkg/pig.tar.gz" "$INPUT/pig-hardlink-alias"
(
	exec 9<> "$INPUT/pig-hardlink-alias"
	printf 'ready\n' > "$INPUT/fd-writer-ready"
	while :; do sleep 0.05; done
) &
WRITER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[[ -f "$INPUT/fd-writer-ready" ]] && break
	sleep 0.05
done
[[ -f "$INPUT/fd-writer-ready" ]] || { echo 'hardlink writable-fd fixture did not start' >&2; exit 1; }
chmod a-w "$ROOT/pkg/pig.tar.gz"
expect_fail hardlink-alias-open-writable-fd 'legacy writer process' run_live_process_preflight "$TMP/hardlink-open-fd-report.txt"
kill "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
WRITER_PID=
rm -f "$INPUT/pig-hardlink-alias" "$INPUT/fd-writer-ready"
pass hardlink-alias-open-writable-fd-live-probe

cat > "$INPUT/process-bad.tsv" <<'EOF'
schema=sow-process-probe/v2
scope	known-processes-and-effective-user-writable-fds
writer	42	make
fd-probe	complete	18	52
probe	complete	18
EOF
mv "$INPUT/process.tsv" "$INPUT/process-good.tsv"
cp "$INPUT/process-bad.tsv" "$INPUT/process.tsv"
expect_fail suspicious-process 'legacy writer process' run_preflight "$TMP/process-bad-report.txt"
mv "$INPUT/process-good.tsv" "$INPUT/process.tsv"

cat > "$INPUT/container-bad.tsv" <<EOF
schema=sow-container-mount-probe/v1
runtime	docker
container	legacy-writer	$ROOT	/repo	rw
EOF
mv "$INPUT/container.tsv" "$INPUT/container-good.tsv"
cp "$INPUT/container-bad.tsv" "$INPUT/container.tsv"
expect_fail writable-container 'writable mount.*legacy root' run_preflight "$TMP/container-bad-report.txt"
mv "$INPUT/container-good.tsv" "$INPUT/container.tsv"

cat > "$INPUT/container-root.tsv" <<'EOF'
schema=sow-container-mount-probe/v1
runtime	docker
container	root-writer	/	/host	rw
EOF
mv "$INPUT/container.tsv" "$INPUT/container-good.tsv"
cp "$INPUT/container-root.tsv" "$INPUT/container.tsv"
expect_fail writable-container-ancestor 'writable mount.*legacy root' run_preflight "$TMP/container-root-report.txt"
mv "$INPUT/container-good.tsv" "$INPUT/container.tsv"

cat > "$INPUT/mount-bad.tsv" <<EOF
schema=sow-mount-probe/v1
mount	$ROOT/pkg	rw
probe	complete	2
EOF
mv "$INPUT/mount.tsv" "$INPUT/mount-good.tsv"
cp "$INPUT/mount-bad.tsv" "$INPUT/mount.tsv"
expect_fail writable-submount 'writable mount.*at or below' run_preflight "$TMP/mount-bad-report.txt"
mv "$INPUT/mount-good.tsv" "$INPUT/mount.tsv"

write_attestation "$INPUT/attestation-bad" false
mv "$INPUT/attestation" "$INPUT/attestation-good"
cp "$INPUT/attestation-bad" "$INPUT/attestation"
expect_fail incomplete-attestation 'legacy_cloud_credentials_revoked=true' run_preflight "$TMP/attestation-bad-report.txt"
mv "$INPUT/attestation-good" "$INPUT/attestation"

write_attestation "$INPUT/attestation-bad-time" true 2026-02-31T12:00:00Z
mv "$INPUT/attestation" "$INPUT/attestation-good"
cp "$INPUT/attestation-bad-time" "$INPUT/attestation"
expect_fail impossible-approved-at 'RFC3339 UTC timestamp' run_preflight "$TMP/attestation-bad-time-report.txt"
mv "$INPUT/attestation-good" "$INPUT/attestation"

chmod u+w "$ROOT/Makefile"
expect_fail writable-legacy-entry 'can still write' run_preflight "$TMP/writable-report.txt"
chmod a-w "$ROOT/Makefile"

chmod 000 "$ROOT/pkg"
expect_fail incomplete-tree-enumeration 'failed to inventory legacy file identities|failed to inspect legacy entry types|failed to enumerate the complete legacy tree' run_preflight "$TMP/unreadable-report.txt"
chmod 555 "$ROOT/pkg"

chmod u+w "$ROOT/pkg"
ln -s "$INPUT" "$ROOT/pkg/external-link"
chmod a-w "$ROOT/pkg"
expect_fail nonregular-legacy-entry 'unsupported non-regular entry' run_preflight "$TMP/nonregular-report.txt"
chmod u+w "$ROOT/pkg"
rm "$ROOT/pkg/external-link"
chmod a-w "$ROOT/pkg"

expect_fail no-overwrite 'refusing to overwrite' run_preflight "$TMP/report-1.txt"
expect_fail output-inside-root 'outside the legacy root' run_preflight "$ROOT/report.txt"

cat > "$INPUT/process-malformed.tsv" <<'EOF'
schema=sow-process-probe/v2
scope	known-processes-and-effective-user-writable-fds
EOF
mv "$INPUT/process.tsv" "$INPUT/process-good.tsv"
cp "$INPUT/process-malformed.tsv" "$INPUT/process.tsv"
expect_fail incomplete-probe 'invalid or incomplete process snapshot' run_preflight "$TMP/incomplete-report.txt"
mv "$INPUT/process-good.tsv" "$INPUT/process.tsv"

echo 'writer fence preflight suite: PASS'
