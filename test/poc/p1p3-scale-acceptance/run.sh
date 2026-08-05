#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)
BASELINE_ROOT=/Users/vonng/repo/sow-v2-scale-portable.OnL4IO
SUPPLEMENT_ROOT=/Users/vonng/repo/sow-v2-scale-supplement-portable.Jjt2ma
EXPECTED_OBJECTS=34184
EXPECTED_BYTES=53879777230
MAX_REBUILD_SECONDS=120
JOBS=${JOBS:-8}
DOCKER_IMAGE=${DOCKER_IMAGE:-alpine:3.22}

for required in "$BASELINE_ROOT" "$SUPPLEMENT_ROOT"; do
  [[ -d "$required" && ! -L "$required" ]] || {
    printf 'required retained scale lab is missing or unsafe: %s\n' "$required" >&2
    exit 2
  }
done
if [[ -z "${LAB_ROOT:-}" ]]; then
  LAB_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-scale-final.XXXXXX)
else
  LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
  if find "$LAB_ROOT" -mindepth 1 -print -quit | grep -q .; then
    printf 'refusing non-empty LAB_ROOT: %s\n' "$LAB_ROOT" >&2
    exit 2
  fi
fi
LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
case "$LAB_ROOT" in
  /Users/vonng/repo/sow-v2-scale-final.*) ;;
  *)
    printf 'refusing LAB_ROOT outside the dedicated prefix: %s\n' "$LAB_ROOT" >&2
    exit 2
    ;;
esac
LAB_TOKEN=${LAB_ROOT##*.}
[[ "$LAB_TOKEN" =~ ^[A-Za-z0-9]+$ ]] || {
  printf 'unsafe scale lab token: %s\n' "$LAB_TOKEN" >&2
  exit 2
}
case "$LAB_ROOT" in
  /Users/vonng/pgsty/repo*)
    printf 'production repository is forbidden: %s\n' "$LAB_ROOT" >&2
    exit 2
    ;;
esac
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || {
  printf 'JOBS must be a positive integer: %s\n' "$JOBS" >&2
  exit 2
}

for tool in docker go python3 shasum sqlite3 stat /usr/bin/time; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'required tool is unavailable: %s\n' "$tool" >&2
    exit 2
  }
done

mkdir -p "$LAB_ROOT/bin" "$LAB_ROOT/evidence/build" "$LAB_ROOT/evidence/check" \
  "$LAB_ROOT/evidence/changes" "$LAB_ROOT/evidence/timing"
exec > >(tee "$LAB_ROOT/run.log") 2>&1

ACTIVE_VOLUME=
ACTIVE_VOLUME_SLUG=
cleanup_active_volume() {
  local volume=${ACTIVE_VOLUME:-}
  [[ -n "$volume" ]] || return 0
  [[ "$volume" =~ ^sow-v2-scale-[A-Za-z0-9]+-[a-z0-9][a-z0-9._-]*$ ]] || {
    printf 'refusing unsafe scale volume name: %s\n' "$volume" >&2
    return 1
  }
  if ! docker volume inspect "$volume" >/dev/null 2>&1; then
    ACTIVE_VOLUME=
    return 0
  fi
  local actual_token actual_slug
  actual_token=$(docker volume inspect "$volume" \
    --format '{{ index .Labels "com.pgsty.sow.scale-token" }}')
  actual_slug=$(docker volume inspect "$volume" \
    --format '{{ index .Labels "com.pgsty.sow.scale-slug" }}')
  if [[ "$actual_token" != "$LAB_TOKEN" || "$actual_slug" != "$ACTIVE_VOLUME_SLUG" ]]; then
    printf 'refusing scale volume with wrong labels: %s token=%s slug=%s\n' \
      "$volume" "$actual_token" "$actual_slug" >&2
    return 1
  fi
  docker volume rm "$volume"
  ACTIVE_VOLUME=
  ACTIVE_VOLUME_SLUG=
}
trap cleanup_active_volume EXIT

create_scale_volume() {
  local slug=$1
  [[ "$slug" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    printf 'unsafe workspace slug for scale volume: %s\n' "$slug" >&2
    return 1
  }
  [[ -z "$ACTIVE_VOLUME" ]] || {
    printf 'previous scale volume is still active: %s\n' "$ACTIVE_VOLUME" >&2
    return 1
  }
  local volume="sow-v2-scale-$LAB_TOKEN-$slug"
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    printf 'refusing pre-existing scale volume: %s\n' "$volume" >&2
    return 1
  fi
  local created
  created=$(docker volume create \
    --label "com.pgsty.sow.scale-token=$LAB_TOKEN" \
    --label "com.pgsty.sow.scale-slug=$slug" \
    "$volume")
  [[ "$created" == "$volume" ]] || {
    printf 'unexpected scale volume identity: got=%s want=%s\n' "$created" "$volume" >&2
    return 1
  }
  ACTIVE_VOLUME=$volume
  ACTIVE_VOLUME_SLUG=$slug
}

printf 'SOW V2 P1-P3 scale acceptance\n'
printf 'utc_started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'project_root=%s\n' "$PROJECT_ROOT"
printf 'baseline_root=%s\n' "$BASELINE_ROOT"
printf 'supplement_root=%s\n' "$SUPPLEMENT_ROOT"
printf 'lab_root=%s\n' "$LAB_ROOT"
printf 'git_head=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
printf 'host_arch=%s\n' "$(uname -m)"
printf 'host_os=%s\n' "$(sw_vers -productVersion)"
printf 'host_cpu=%s\n' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || printf unknown)"
printf 'host_memory_bytes=%s\n' "$(sysctl -n hw.memsize)"
printf 'go_version=%s\n' "$(go version)"
printf 'docker_server=%s\n' "$(docker version --format '{{.Server.Version}}')"
printf 'jobs=%s\n' "$JOBS"

SOURCE_FINGERPRINT=$(
  "$PROJECT_ROOT/test/poc/source-fingerprint.sh" \
    "$PROJECT_ROOT" "$LAB_ROOT/evidence/sow-build-inputs.sha256"
)
printf 'source_fingerprint=%s\n' "$SOURCE_FINGERPRINT"
printf 'harness_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/run.sh" | awk '{print $1}')"

printf '\n== build frozen current-checkout binaries ==\n'
(
  cd -- "$PROJECT_ROOT"
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOWORK=off \
    go build -trimpath -o "$LAB_ROOT/bin/sow-darwin-arm64" ./cmd/sow
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off \
    go build -trimpath -o "$LAB_ROOT/bin/sow-linux-arm64" ./cmd/sow
)
chmod 0755 "$LAB_ROOT/bin/sow-darwin-arm64" "$LAB_ROOT/bin/sow-linux-arm64"
HOST_SOW=$LAB_ROOT/bin/sow-darwin-arm64
LINUX_SOW=$LAB_ROOT/bin/sow-linux-arm64
printf 'sow_darwin_arm64_sha256=%s\n' "$(shasum -a 256 "$HOST_SOW" | awk '{print $1}')"
printf 'sow_linux_arm64_sha256=%s\n' "$(shasum -a 256 "$LINUX_SOW" | awk '{print $1}')"
"$HOST_SOW" version

printf '\n== enumerate exact retained workspaces ==\n'
WORKSPACE_LIST=$LAB_ROOT/evidence/workspaces.tsv
: >"$WORKSPACE_LIST"
while IFS= read -r workspace; do
  slug=${workspace##*/}
  [[ "$slug" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    printf 'unsafe workspace slug: %s\n' "$slug" >&2
    exit 1
  }
  printf '%s\t%s\n' "$slug" "$workspace" >>"$WORKSPACE_LIST"
done < <(find "$BASELINE_ROOT/workspaces" -mindepth 1 -maxdepth 1 -type d -print | LC_ALL=C sort)
printf 'supplement\t%s\n' "$SUPPLEMENT_ROOT/workspace" >>"$WORKSPACE_LIST"
if [[ $(wc -l <"$WORKSPACE_LIST") -ne 18 ]]; then
  printf 'unexpected workspace count: %s\n' "$(wc -l <"$WORKSPACE_LIST")" >&2
  exit 1
fi

resolve_repo() {
  local workspace=$1
  local databases=()
  shopt -s nullglob
  databases=("$workspace"/.sow/*.db)
  shopt -u nullglob
  [[ ${#databases[@]} -eq 1 && -f "${databases[0]}" && ! -L "${databases[0]}" ]] || {
    printf 'workspace must contain exactly one safe repository database: %s\n' "$workspace" >&2
    return 1
  }
  local repo=${databases[0]##*/}
  repo=${repo%.db}
  [[ "$repo" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    printf 'unsafe repository name derived from %s: %s\n' "${databases[0]}" "$repo" >&2
    return 1
  }
  printf '%s\n' "$repo"
}

OBJECTS_TSV=$LAB_ROOT/evidence/package-objects.tsv
: >"$OBJECTS_TSV"
while IFS=$'\t' read -r slug workspace; do
  case "$workspace" in
    "$BASELINE_ROOT"/workspaces/*|"$SUPPLEMENT_ROOT"/workspace) ;;
    *)
      printf 'unsafe workspace path: %s\n' "$workspace" >&2
      exit 1
      ;;
  esac
  [[ -f "$workspace/sow.yml" && ! -L "$workspace/sow.yml" ]] || {
    printf 'missing or unsafe workspace config: %s\n' "$workspace" >&2
    exit 1
  }
  repo=$(resolve_repo "$workspace")
  row=$(sqlite3 -batch -noheader "$workspace/.sow/$repo.db" \
    'SELECT count(*), COALESCE(sum(size), 0) FROM package_objects;')
  count=${row%%|*}
  bytes=${row##*|}
  [[ "$count" =~ ^[0-9]+$ && "$bytes" =~ ^[0-9]+$ ]] || {
    printf 'invalid package object count for %s: %s\n' "$workspace" "$row" >&2
    exit 1
  }
  printf '%s\t%s\t%s\t%s\t%s\n' "$slug" "$workspace" "$repo" "$count" "$bytes" >>"$OBJECTS_TSV"
done <"$WORKSPACE_LIST"
read -r TOTAL_OBJECTS TOTAL_BYTES < <(
  awk -F '\t' '{objects += $4; bytes += $5} END {printf "%.0f %.0f\n", objects, bytes}' "$OBJECTS_TSV"
)
printf 'workspace_count=18\n'
printf 'package_objects=%s\n' "$TOTAL_OBJECTS"
printf 'package_bytes=%s\n' "$TOTAL_BYTES"
python3 - "$TOTAL_BYTES" <<'PY'
import sys
print(f"package_gib={int(sys.argv[1]) / 1073741824:.9f}")
PY
if [[ "$TOTAL_OBJECTS" -ne "$EXPECTED_OBJECTS" || "$TOTAL_BYTES" -ne "$EXPECTED_BYTES" ]]; then
  printf 'scale identity mismatch: got objects=%s bytes=%s want objects=%s bytes=%s\n' \
    "$TOTAL_OBJECTS" "$TOTAL_BYTES" "$EXPECTED_OBJECTS" "$EXPECTED_BYTES" >&2
  exit 1
fi
du -sk "$BASELINE_ROOT" "$SUPPLEMENT_ROOT" | tee "$LAB_ROOT/evidence/disk-before.tsv"
df -k "$BASELINE_ROOT" | tee "$LAB_ROOT/evidence/filesystem-before.txt"

validate_build_json() {
  local json_path=$1 require_physical=$2
  python3 - "$json_path" "$require_physical" <<'PY'
import json, sys
with open(sys.argv[1], "rb") as stream:
    doc = json.load(stream)
if doc.get("schema") != "sow.cli/v1" or doc.get("command") != "build" or doc.get("ok") is not True or doc.get("errors") != []:
    raise SystemExit(f"invalid successful build envelope: {doc!r}")
result = doc.get("result") or {}
if not isinstance(result.get("built_generation"), int) or result["built_generation"] < 1:
    raise SystemExit(f"invalid build generation: {result!r}")
if sys.argv[2] == "yes" and result.get("noop") is not False:
    raise SystemExit(f"forced rebuild was not physical: {result!r}")
PY
}

toggle_policy_marker() {
  local config_path=$1 token=$2
  python3 - "$config_path" "$token" <<'PY'
import os, re, stat, sys, tempfile
path, token = sys.argv[1:]
st = os.lstat(path)
if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
    raise SystemExit(f"unsafe config: {path}")
with open(path, "r", encoding="utf-8") as stream:
    data = stream.read()
pattern = re.compile(r"__sow_scale_(?:no_match|probe)_[A-Za-z0-9_.-]+__")
matches = pattern.findall(data)
if len(matches) != 1:
    raise SystemExit(f"expected exactly one scale marker in {path}, found {matches!r}")
updated = pattern.sub(token, data, count=1)
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".sow-scale-config-", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(updated)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, stat.S_IMODE(st.st_mode))
    os.replace(temporary, path)
    dirfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

printf '\n== converge schema, recovery and current renderer contract ==\n'
while IFS=$'\t' read -r slug workspace repo count bytes; do
  printf 'converge %s objects=%s bytes=%s\n' "$slug" "$count" "$bytes"
  "$HOST_SOW" build -C "$workspace" -r "$repo" -j "$JOBS" --json \
    >"$LAB_ROOT/evidence/build/$slug.converge.json"
  validate_build_json "$LAB_ROOT/evidence/build/$slug.converge.json" no
done <"$OBJECTS_TSV"

TIMINGS_TSV=$LAB_ROOT/evidence/rebuild-timings.tsv
printf 'condition\tround\tworkspace\tseconds\tmax_rss_kib\tobjects\tbytes\n' >"$TIMINGS_TSV"

parse_linux_time() {
  local timing=$1
  python3 - "$timing" <<'PY'
import re, sys
data = open(sys.argv[1], encoding="utf-8", errors="replace").read()
elapsed = re.search(r"Elapsed \(wall clock\) time .*?:\s*(?:(\d+)m )?([0-9.]+)s", data)
rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", data)
if not elapsed or not rss:
    raise SystemExit(f"cannot parse Linux timing: {data}")
seconds = int(elapsed.group(1) or 0) * 60 + float(elapsed.group(2))
print(f"{seconds:.6f} {rss.group(1)}")
PY
}

parse_darwin_time() {
  local timing=$1
  python3 - "$timing" <<'PY'
import re, sys
data = open(sys.argv[1], encoding="utf-8", errors="replace").read()
elapsed = re.search(r"^real\s+([0-9.]+)$", data, re.MULTILINE)
rss = re.search(r"^\s*(\d+)\s+maximum resident set size$", data, re.MULTILINE)
if not elapsed or not rss:
    raise SystemExit(f"cannot parse Darwin timing: {data}")
print(f"{float(elapsed.group(1)):.6f} {int(rss.group(1)) // 1024}")
PY
}

printf '\n== Docker guest-cache-cold full rebuilds ==\n'
docker image inspect "$DOCKER_IMAGE" --format '{{index .RepoTags 0}} id={{.Id}} arch={{.Architecture}} os={{.Os}}' \
  | tee "$LAB_ROOT/evidence/docker-image.txt"
while IFS=$'\t' read -r slug workspace repo count bytes; do
  toggle_policy_marker "$workspace/sow.yml" "__sow_scale_probe_${LAB_TOKEN}_${slug}_cold_1__"
  output=$LAB_ROOT/evidence/build/$slug.cold-1.json
  timing=$LAB_ROOT/evidence/timing/$slug.cold-1.txt
  printf 'cold rebuild %s objects=%s bytes=%s\n' "$slug" "$count" "$bytes"
  create_scale_volume "$slug"
  docker run --rm --pull never --platform linux/arm64 \
    -v "$workspace:/source:ro" -v "$ACTIVE_VOLUME:/workspace" \
    "$DOCKER_IMAGE" sh -ec 'cd /source; tar cf - . | tar xpf - -C /workspace'
  docker run --rm --pull never --privileged --platform linux/arm64 \
    -v "$LINUX_SOW:/sow:ro" -v "$ACTIVE_VOLUME:/workspace" \
    "$DOCKER_IMAGE" sh -c '
      sync
      echo 3 >/proc/sys/vm/drop_caches
      exec /usr/bin/time -v /sow build -C /workspace -r "$1" -j "$2" --json
    ' sh "$repo" "$JOBS" >"$output" 2>"$timing"
  validate_build_json "$output" yes
  read -r seconds rss < <(parse_linux_time "$timing")
  printf 'guest-cold\t1\t%s\t%s\t%s\t%s\t%s\n' "$slug" "$seconds" "$rss" "$count" "$bytes" >>"$TIMINGS_TSV"
  docker run --rm --pull never --platform linux/arm64 \
    -v "$LINUX_SOW:/sow:ro" -v "$ACTIVE_VOLUME:/workspace" \
    "$DOCKER_IMAGE" /sow check -C /workspace -r "$repo" -j "$JOBS" --json \
    >"$LAB_ROOT/evidence/check/$slug.guest-cold.json"
  python3 - "$LAB_ROOT/evidence/check/$slug.guest-cold.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], "rb"))
result = doc.get("result") or {}
if doc.get("ok") is not True or result.get("status") != "clean" or result.get("ready_to_copy") is not True:
    raise SystemExit(f"guest-cold repository is not clean and ready: {doc!r}")
PY
  cleanup_active_volume
done <"$OBJECTS_TSV"

printf '\n== host-warm full rebuilds ==\n'
for round in 1 2; do
  while IFS=$'\t' read -r slug workspace repo count bytes; do
    toggle_policy_marker "$workspace/sow.yml" "__sow_scale_probe_${LAB_TOKEN}_${slug}_warm_${round}__"
    output=$LAB_ROOT/evidence/build/$slug.warm-$round.json
    timing=$LAB_ROOT/evidence/timing/$slug.warm-$round.txt
    printf 'warm rebuild round=%s %s objects=%s bytes=%s\n' "$round" "$slug" "$count" "$bytes"
    /usr/bin/time -l -p -o "$timing" \
      "$HOST_SOW" build -C "$workspace" -r "$repo" -j "$JOBS" --json >"$output"
    validate_build_json "$output" yes
    read -r seconds rss < <(parse_darwin_time "$timing")
    printf 'host-warm\t%s\t%s\t%s\t%s\t%s\t%s\n' "$round" "$slug" "$seconds" "$rss" "$count" "$bytes" >>"$TIMINGS_TSV"
  done <"$OBJECTS_TSV"
done

printf '\n== timing threshold and summary ==\n'
python3 - "$TIMINGS_TSV" "$MAX_REBUILD_SECONDS" >"$LAB_ROOT/evidence/rebuild-summary.json" <<'PY'
import csv, json, statistics, sys
path, limit = sys.argv[1], float(sys.argv[2])
with open(path, newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
if len(rows) != 54:
    raise SystemExit(f"expected 54 retained rebuild runs, got {len(rows)}")
seconds = [float(row["seconds"]) for row in rows]
rss = [int(row["max_rss_kib"]) for row in rows]
summary = {
    "runs": len(rows),
    "median_seconds": statistics.median(seconds),
    "worst_seconds": max(seconds),
    "peak_rss_kib": max(rss),
    "limit_seconds": limit,
    "all_within_limit": max(seconds) <= limit,
    "conditions": {},
}
for condition in sorted({row["condition"] for row in rows}):
    values = [float(row["seconds"]) for row in rows if row["condition"] == condition]
    summary["conditions"][condition] = {
        "runs": len(values), "median_seconds": statistics.median(values), "worst_seconds": max(values)
    }
print(json.dumps(summary, sort_keys=True, indent=2))
if not summary["all_within_limit"]:
    raise SystemExit(f"rebuild threshold exceeded: worst={summary['worst_seconds']} limit={limit}")
PY
cat "$LAB_ROOT/evidence/rebuild-summary.json"

printf '\n== full current-checkout check and changes 0 ==\n'
while IFS=$'\t' read -r slug workspace repo count bytes; do
  printf 'check and changes %s\n' "$slug"
  "$HOST_SOW" check -C "$workspace" -r "$repo" -j "$JOBS" --json \
    >"$LAB_ROOT/evidence/check/$slug.json"
  python3 - "$LAB_ROOT/evidence/check/$slug.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], "rb"))
result = doc.get("result") or {}
if doc.get("ok") is not True or result.get("status") != "clean" or result.get("ready_to_copy") is not True:
    raise SystemExit(f"repository is not clean and ready: {doc!r}")
PY
  "$HOST_SOW" changes 0 -C "$workspace" -r "$repo" --json \
    >"$LAB_ROOT/evidence/changes/$slug.json"
  python3 - "$LAB_ROOT/evidence/changes/$slug.json" "$workspace/$repo" <<'PY'
import hashlib, json, os, stat, sys
from pathlib import Path, PurePosixPath

changes_path, repository = Path(sys.argv[1]), Path(sys.argv[2])
doc = json.loads(changes_path.read_text(encoding="utf-8"))
result = doc.get("result") or {}
if (
    doc.get("schema") != "sow.cli/v1"
    or doc.get("command") != "changes"
    or doc.get("ok") is not True
    or doc.get("errors") != []
    or result.get("base") != 0
    or result.get("dirty") is not False
    or not isinstance(result.get("generation"), int)
    or result["generation"] < 1
):
    raise SystemExit(f"invalid changes 0 envelope: {doc!r}")

phase_rank = {"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
declared = {}
previous_rank = -1
for change in result.get("changes") or []:
    value = change.get("path")
    relative = PurePosixPath(value) if isinstance(value, str) else None
    if (
        relative is None
        or not value
        or relative.is_absolute()
        or ".." in relative.parts
        or str(relative) != value
        or value in declared
    ):
        raise SystemExit(f"unsafe or duplicate changes path: {value!r}")
    rank = phase_rank.get(change.get("phase"))
    if rank is None or rank < previous_rank:
        raise SystemExit(f"changes are not in phase order at: {value!r}")
    previous_rank = rank
    if change.get("op") != "add":
        raise SystemExit(f"changes 0 must contain only add operations: {change!r}")
    size, sha256 = change.get("size"), change.get("sha256")
    if not isinstance(size, int) or size < 0 or not isinstance(sha256, str) or len(sha256) != 64:
        raise SystemExit(f"invalid changes identity: {change!r}")
    declared[value] = (size, sha256)

observed = {}
digest_cache = {}
for top in ("pool", "dists"):
    base = repository / top
    if not base.is_dir():
        raise SystemExit(f"missing public directory: {base}")
    for current, directories, files in os.walk(base, followlinks=False):
        current_path = Path(current)
        for name in directories:
            node = current_path / name
            if not stat.S_ISDIR(node.lstat().st_mode):
                raise SystemExit(f"non-directory public node: {node}")
        for name in files:
            path = current_path / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise SystemExit(f"non-regular public file: {path}")
            cache_key = (info.st_dev, info.st_ino, info.st_size)
            identity = digest_cache.get(cache_key)
            if identity is None:
                hasher = hashlib.sha256()
                size = 0
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        hasher.update(chunk)
                identity = (size, hasher.hexdigest())
                digest_cache[cache_key] = identity
            observed[path.relative_to(repository).as_posix()] = identity

if observed != declared:
    missing = sorted(observed.keys() - declared.keys())
    extra = sorted(declared.keys() - observed.keys())
    changed = sorted(path for path in observed.keys() & declared.keys() if observed[path] != declared[path])
    raise SystemExit(
        f"changes 0 differs from public tree: missing={missing[:5]} extra={extra[:5]} changed={changed[:5]}"
    )
print(
    json.dumps(
        {
            "base": result["base"],
            "generation": result["generation"],
            "files": len(observed),
            "unique_inodes": len(digest_cache),
            "exact_public_tree": True,
        },
        sort_keys=True,
    )
)
PY
done <"$OBJECTS_TSV"

du -sk "$BASELINE_ROOT" "$SUPPLEMENT_ROOT" | tee "$LAB_ROOT/evidence/disk-after.tsv"
df -k "$BASELINE_ROOT" | tee "$LAB_ROOT/evidence/filesystem-after.txt"
FINAL_SOURCE_FINGERPRINT=$("$PROJECT_ROOT/test/poc/source-fingerprint.sh" "$PROJECT_ROOT")
printf 'final_source_fingerprint=%s\n' "$FINAL_SOURCE_FINGERPRINT"
if [[ "$FINAL_SOURCE_FINGERPRINT" != "$SOURCE_FINGERPRINT" ]]; then
  printf 'project source changed during scale acceptance: before=%s after=%s\n' \
    "$SOURCE_FINGERPRINT" "$FINAL_SOURCE_FINGERPRINT" >&2
  exit 1
fi

printf 'utc_finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'SOW_V2_P1P3_SCALE_ACCEPTANCE=PASS\n'
printf 'retained_lab=%s\n' "$LAB_ROOT"
