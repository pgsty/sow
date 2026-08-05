#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)
REPO2_ROOT=/Users/vonng/pgsty/repo2
SELECTION_ROOT=/Users/vonng/repo/sow-v2-scale.uD9pC2
SUPPLEMENT_SELECTION=/Users/vonng/repo/sow-v2-scale-supplement.jUtMwE/evidence/selection-size-path.tsv
JOBS=${JOBS:-8}
EXPECTED_BASE_OBJECTS=31811
EXPECTED_BASE_BYTES=47264180286
EXPECTED_SUPPLEMENT_OBJECTS=2373
EXPECTED_SUPPLEMENT_BYTES=6615596944

for tool in go python3 sqlite3 stat; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'required tool is unavailable: %s\n' "$tool" >&2
    exit 2
  }
done
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || {
  printf 'JOBS must be a positive integer: %s\n' "$JOBS" >&2
  exit 2
}
[[ -d "$REPO2_ROOT" && ! -L "$REPO2_ROOT" ]] || {
  printf 'repo2 input root is missing or unsafe: %s\n' "$REPO2_ROOT" >&2
  exit 2
}
[[ -d "$SELECTION_ROOT/evidence" && ! -L "$SELECTION_ROOT" ]] || {
  printf 'retained repo2 selection evidence is missing or unsafe: %s\n' "$SELECTION_ROOT" >&2
  exit 2
}
[[ -f "$SUPPLEMENT_SELECTION" && ! -L "$SUPPLEMENT_SELECTION" ]] || {
  printf 'supplement repo2 selection is missing or unsafe: %s\n' "$SUPPLEMENT_SELECTION" >&2
  exit 2
}

BASELINE_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-scale-portable.XXXXXX)
SUPPLEMENT_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-scale-supplement-portable.XXXXXX)
for created in "$BASELINE_ROOT" "$SUPPLEMENT_ROOT"; do
  created=$(cd -- "$created" && pwd -P)
  case "$created" in
    /Users/vonng/repo/sow-v2-scale-portable.*|/Users/vonng/repo/sow-v2-scale-supplement-portable.*) ;;
    *)
      printf 'unsafe generated scale root: %s\n' "$created" >&2
      exit 2
      ;;
  esac
  case "$created" in
    /Users/vonng/pgsty/repo*)
      printf 'production repository is forbidden: %s\n' "$created" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$BASELINE_ROOT/bin" "$BASELINE_ROOT/evidence" "$BASELINE_ROOT/workspaces" \
  "$SUPPLEMENT_ROOT/evidence" "$SUPPLEMENT_ROOT/workspace"
exec > >(tee "$BASELINE_ROOT/prepare.log") 2>&1

printf 'SOW V2 portable scale baseline preparation\n'
printf 'utc_started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'project_root=%s\n' "$PROJECT_ROOT"
printf 'repo2_root=%s\n' "$REPO2_ROOT"
printf 'baseline_root=%s\n' "$BASELINE_ROOT"
printf 'supplement_root=%s\n' "$SUPPLEMENT_ROOT"
printf 'git_head=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
SOURCE_FINGERPRINT=$(
  "$PROJECT_ROOT/test/poc/source-fingerprint.sh" \
    "$PROJECT_ROOT" "$BASELINE_ROOT/evidence/sow-build-inputs.sha256"
)
printf 'source_fingerprint=%s\n' "$SOURCE_FINGERPRINT"
printf 'harness_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/prepare.sh" | awk '{print $1}')"

(
  cd -- "$PROJECT_ROOT"
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOWORK=off \
    go build -trimpath -o "$BASELINE_ROOT/bin/sow" ./cmd/sow
)
chmod 0755 "$BASELINE_ROOT/bin/sow"
SOW=$BASELINE_ROOT/bin/sow
printf 'sow_sha256=%s\n' "$(shasum -a 256 "$SOW" | awk '{print $1}')"

write_config() {
  local workspace=$1 repo=$2 dist=$3 format=$4 architecture=$5
  python3 - "$workspace/sow.yml" "$repo" "$dist" "$format" "$architecture" <<'PY'
import os, sys
path, repo, dist, fmt, arch = sys.argv[1:]
dist_arch = f"\n        architectures: [{arch}]" if arch else ""
data = f"""schema: sow/v2
architectures:
  - x86_64
  - aarch64
repos:
  {repo}:
    signing:
      rpm:
        packages:
          mode: never
    dists:
      {dist}:
        format: {fmt}{dist_arch}
        exclude:
          - name: [__sow_scale_no_match_portable__]
"""
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
PY
}

ADD_SEQUENCE=0
add_batch() {
  local workspace=$1 repo=$2 dist=$3 slug=$4
  shift 4
  ((ADD_SEQUENCE += 1))
  local output
  output=$(printf '%s/evidence/%s.add.%04d.json' "$BASELINE_ROOT" "$slug" "$ADD_SEQUENCE")
  "$SOW" add "$@" --skip -C "$workspace" -r "$repo" -d "$dist" -j "$JOBS" --json >"$output"
  python3 - "$output" "$#" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], "rb"))
result = doc.get("result") or {}
want = int(sys.argv[2])
if doc.get("ok") is not True or result.get("accepted") != want or result.get("failed") != 0:
    raise SystemExit(f"invalid add batch: want={want} document={doc!r}")
PY
}

add_json_selection() {
  local workspace=$1 repo=$2 dist=$3 slug=$4 manifest=$5
  local -a batch=()
  while IFS= read -r -d '' package; do
    case "$package" in
      "$REPO2_ROOT"/*.rpm|"$REPO2_ROOT"/*.deb) ;;
      *)
        printf 'selection escaped repo2: %s\n' "$package" >&2
        return 1
        ;;
    esac
    [[ -f "$package" && ! -L "$package" ]] || {
      printf 'selected repo2 package is missing or unsafe: %s\n' "$package" >&2
      return 1
    }
    batch+=("$package")
    if [[ ${#batch[@]} -eq 128 ]]; then
      add_batch "$workspace" "$repo" "$dist" "$slug" "${batch[@]}"
      batch=()
    fi
  done < <(python3 - "$manifest" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1], "rb"))
items = (doc.get("result") or {}).get("items") or []
paths = [item.get("input") for item in items if item.get("status") in {"accepted", "reused"}]
if len(paths) != (doc.get("result") or {}).get("accepted"):
    raise SystemExit("selection manifest does not contain the complete accepted set")
for path in paths:
    os.write(1, os.fsencode(path) + b"\0")
PY
)
  if [[ ${#batch[@]} -ne 0 ]]; then
    add_batch "$workspace" "$repo" "$dist" "$slug" "${batch[@]}"
  fi
}

build_and_check() {
  local workspace=$1 repo=$2 slug=$3
  "$SOW" build -C "$workspace" -r "$repo" -j "$JOBS" --json >"$BASELINE_ROOT/evidence/$slug.build.json"
  "$SOW" check -C "$workspace" -r "$repo" -j "$JOBS" --json >"$BASELINE_ROOT/evidence/$slug.check.json"
  python3 - "$BASELINE_ROOT/evidence/$slug.check.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], "rb"))
result = doc.get("result") or {}
if doc.get("ok") is not True or result.get("status") != "clean" or result.get("ready_to_copy") is not True:
    raise SystemExit(f"prepared workspace is not clean: {doc!r}")
PY
}

while IFS=$'\t' read -r slug format architecture; do
  workspace=$BASELINE_ROOT/workspaces/$slug
  mkdir -p "$workspace"
  write_config "$workspace" repo dist "$format" "$architecture"
  manifest=$SELECTION_ROOT/evidence/$slug.add.json
  [[ -f "$manifest" && ! -L "$manifest" ]] || {
    printf 'selection manifest is missing or unsafe: %s\n' "$manifest" >&2
    exit 2
  }
  printf 'prepare %s format=%s architecture=%s\n' "$slug" "$format" "${architecture:-all}"
  "$SOW" init "$workspace" --json >"$BASELINE_ROOT/evidence/$slug.init.json"
  add_json_selection "$workspace" repo dist "$slug" "$manifest"
  build_and_check "$workspace" repo "$slug"
done <<'EOF'
apt-infra	deb
apt-pgsql-bookworm	deb
apt-pgsql-bullseye	deb
apt-pgsql-focal	deb
apt-pgsql-jammy	deb
apt-pgsql-noble	deb
apt-pgsql-resolute	deb
apt-pgsql-trixie	deb
rpm-infra-aarch64	rpm	aarch64
rpm-infra-x86_64	rpm	x86_64
rpm-pgsql-el10-aarch64	rpm	aarch64
rpm-pgsql-el10-x86_64	rpm	x86_64
rpm-pgsql-el7-x86_64	rpm	x86_64
rpm-pgsql-el8-aarch64	rpm	aarch64
rpm-pgsql-el8-x86_64	rpm	x86_64
rpm-pgsql-el9-aarch64	rpm	aarch64
rpm-pgsql-el9-x86_64	rpm	x86_64
EOF

printf 'prepare supplement\n'
SUPPLEMENT_WORKSPACE=$SUPPLEMENT_ROOT/workspace
write_config "$SUPPLEMENT_WORKSPACE" local pgdg deb ""
"$SOW" init "$SUPPLEMENT_WORKSPACE" --json >"$SUPPLEMENT_ROOT/evidence/init.json"
batch=()
supplement_sequence=0
while IFS=' ' read -r expected_size package; do
  [[ "$expected_size" =~ ^[0-9]+$ ]] || {
    printf 'invalid supplement size: %s\n' "$expected_size" >&2
    exit 2
  }
  case "$package" in
    "$REPO2_ROOT"/*.deb) ;;
    *)
      printf 'supplement selection escaped repo2: %s\n' "$package" >&2
      exit 2
      ;;
  esac
  [[ -f "$package" && ! -L "$package" && "$(stat -f %z "$package")" -eq "$expected_size" ]] || {
    printf 'supplement repo2 package identity changed: %s\n' "$package" >&2
    exit 2
  }
  batch+=("$package")
  if [[ ${#batch[@]} -eq 128 ]]; then
    ((supplement_sequence += 1))
    output=$(printf '%s/evidence/add.%04d.json' "$SUPPLEMENT_ROOT" "$supplement_sequence")
    "$SOW" add "${batch[@]}" --skip -C "$SUPPLEMENT_WORKSPACE" -r local -d pgdg -j "$JOBS" --json >"$output"
    batch=()
  fi
done <"$SUPPLEMENT_SELECTION"
if [[ ${#batch[@]} -ne 0 ]]; then
  ((supplement_sequence += 1))
  output=$(printf '%s/evidence/add.%04d.json' "$SUPPLEMENT_ROOT" "$supplement_sequence")
  "$SOW" add "${batch[@]}" --skip -C "$SUPPLEMENT_WORKSPACE" -r local -d pgdg -j "$JOBS" --json >"$output"
fi
"$SOW" build -C "$SUPPLEMENT_WORKSPACE" -r local -j "$JOBS" --json >"$SUPPLEMENT_ROOT/evidence/build.json"
"$SOW" check -C "$SUPPLEMENT_WORKSPACE" -r local -j "$JOBS" --json >"$SUPPLEMENT_ROOT/evidence/check.json"

read -r base_objects base_bytes < <(python3 - "$BASELINE_ROOT/workspaces" <<'PY'
import glob, sqlite3, sys
objects = size = 0
databases = sorted(glob.glob(sys.argv[1] + "/*/.sow/*.db"))
if len(databases) != 17:
    raise SystemExit(f"expected 17 primary databases, got {len(databases)}")
for path in databases:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        count, total = db.execute("SELECT count(*), COALESCE(sum(size),0) FROM package_objects").fetchone()
        upper = db.execute("SELECT count(*) FROM package_objects WHERE substr(pool_path,6,instr(substr(pool_path,6),'/')-1) != lower(substr(pool_path,6,instr(substr(pool_path,6),'/')-1))").fetchone()[0]
        collisions = db.execute("SELECT count(*) FROM (SELECT lower(pool_path) FROM package_objects GROUP BY lower(pool_path) HAVING count(*) > 1)").fetchone()[0]
        if upper or collisions:
            raise SystemExit(f"non-portable Pool paths in {path}: upper={upper} collisions={collisions}")
    objects += count
    size += total
print(objects, size)
PY
)
supplement_db=$SUPPLEMENT_WORKSPACE/.sow/local.db
IFS='|' read -r supplement_objects supplement_bytes < <(
  sqlite3 -batch -noheader "$supplement_db" 'SELECT count(*), COALESCE(sum(size),0) FROM package_objects;'
)
printf 'base_objects=%s base_bytes=%s\n' "$base_objects" "$base_bytes"
printf 'supplement_objects=%s supplement_bytes=%s\n' "$supplement_objects" "$supplement_bytes"
if [[ "$base_objects" -ne "$EXPECTED_BASE_OBJECTS" || "$base_bytes" -ne "$EXPECTED_BASE_BYTES" ||
      "$supplement_objects" -ne "$EXPECTED_SUPPLEMENT_OBJECTS" || "$supplement_bytes" -ne "$EXPECTED_SUPPLEMENT_BYTES" ]]; then
  printf 'prepared scale identity differs from the frozen baseline\n' >&2
  exit 1
fi

FINAL_SOURCE_FINGERPRINT=$("$PROJECT_ROOT/test/poc/source-fingerprint.sh" "$PROJECT_ROOT")
printf 'final_source_fingerprint=%s\n' "$FINAL_SOURCE_FINGERPRINT"
if [[ "$FINAL_SOURCE_FINGERPRINT" != "$SOURCE_FINGERPRINT" ]]; then
  printf 'project source changed during baseline preparation\n' >&2
  exit 1
fi
printf 'utc_finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'SOW_V2_P1P3_SCALE_PREPARE=PASS\n'
printf 'BASELINE_ROOT=%s\n' "$BASELINE_ROOT"
printf 'SUPPLEMENT_ROOT=%s\n' "$SUPPLEMENT_ROOT"
