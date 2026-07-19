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
	local destination=$1 cloud=${2:-true}
	cat > "$destination" <<EOF
schema=sow-writer-revocation/v1
scheduler_writers_disabled=true
legacy_cloud_credentials_revoked=$cloud
legacy_containers_stopped=true
legacy_make_writers_archived=true
sow_exclusive_writer=true
approved_change=CHG-2026-0712
approved_at=2026-07-12T12:00:00Z
EOF
}

write_attestation "$INPUT/attestation"
cat > "$INPUT/process.tsv" <<'EOF'
schema=sow-process-probe/v1
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
grep -Fqx 'schema=sow-writer-fence-report/v2' "$TMP/report-1.txt"
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

cat > "$INPUT/process-bad.tsv" <<'EOF'
schema=sow-process-probe/v1
writer	42	make
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

chmod u+w "$ROOT/Makefile"
expect_fail writable-legacy-entry 'can still write' run_preflight "$TMP/writable-report.txt"
chmod a-w "$ROOT/Makefile"

chmod 000 "$ROOT/pkg"
expect_fail incomplete-tree-enumeration 'failed to inspect legacy entry types|failed to enumerate the complete legacy tree' run_preflight "$TMP/unreadable-report.txt"
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
schema=sow-process-probe/v1
EOF
mv "$INPUT/process.tsv" "$INPUT/process-good.tsv"
cp "$INPUT/process-malformed.tsv" "$INPUT/process.tsv"
expect_fail incomplete-probe 'invalid or incomplete process snapshot' run_preflight "$TMP/incomplete-report.txt"
mv "$INPUT/process-good.tsv" "$INPUT/process.tsv"

echo 'writer fence preflight suite: PASS'
