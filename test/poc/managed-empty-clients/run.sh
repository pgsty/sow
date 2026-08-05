#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)
RPM_IMAGE=${RPM_IMAGE:-pgsty/el9:build}
DEB_IMAGE=${DEB_IMAGE:-pgsty/u24:latest}
HTTP_IMAGE=${HTTP_IMAGE:-pgsty/u24a:build}

if [[ -z "${LAB_ROOT:-}" ]]; then
  LAB_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-managed-empty.XXXXXX)
fi
LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
case "$LAB_ROOT" in
  /Users/vonng/repo/sow-v2-managed-empty.*) ;;
  *)
    printf 'refusing LAB_ROOT outside the dedicated test prefix: %s\n' "$LAB_ROOT" >&2
    exit 2
    ;;
esac
if [[ "$LAB_ROOT" == /Users/vonng/pgsty/repo* ]]; then
  printf 'production repository is forbidden: %s\n' "$LAB_ROOT" >&2
  exit 2
fi
LAB_TOKEN=${LAB_ROOT##*.}
[[ "$LAB_TOKEN" =~ ^[A-Za-z0-9]+$ ]] || {
  printf 'unsafe managed-empty lab token: %s\n' "$LAB_TOKEN" >&2
  exit 2
}
NETWORK_NAME="sow-managed-empty-net-$LAB_TOKEN"
SERVER_NAME="sow-managed-empty-http-$LAB_TOKEN"
[[ "$NETWORK_NAME" =~ ^sow-managed-empty-net-[A-Za-z0-9]+$ ]] || exit 2
[[ "$SERVER_NAME" =~ ^sow-managed-empty-http-[A-Za-z0-9]+$ ]] || exit 2

cleanup_docker() {
  local actual_token
  if docker container inspect "$SERVER_NAME" >/dev/null 2>&1; then
    actual_token=$(docker container inspect "$SERVER_NAME" \
      --format '{{ index .Config.Labels "com.pgsty.sow.managed-empty-token" }}')
    if [[ "$actual_token" != "$LAB_TOKEN" ]]; then
      printf 'refusing container with wrong managed-empty label: %s\n' "$SERVER_NAME" >&2
      return 1
    fi
    docker container rm -f "$SERVER_NAME" >/dev/null
  fi
  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    actual_token=$(docker network inspect "$NETWORK_NAME" \
      --format '{{ index .Labels "com.pgsty.sow.managed-empty-token" }}')
    if [[ "$actual_token" != "$LAB_TOKEN" ]]; then
      printf 'refusing network with wrong managed-empty label: %s\n' "$NETWORK_NAME" >&2
      return 1
    fi
    docker network rm "$NETWORK_NAME" >/dev/null
  fi
}
trap cleanup_docker EXIT

exec > >(tee "$LAB_ROOT/run.log") 2>&1
printf 'SOW V2 P1 managed empty real-client PoC\n'
printf 'utc_started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'project_root=%s\n' "$PROJECT_ROOT"
printf 'lab_root=%s\n' "$LAB_ROOT"
printf 'git_head=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
printf 'go_version=%s\n' "$(go version)"
printf 'docker_server=%s\n' "$(docker version --format '{{.Server.Version}}')"
SOURCE_FINGERPRINT=$(
  "$PROJECT_ROOT/test/poc/source-fingerprint.sh" \
    "$PROJECT_ROOT" "$LAB_ROOT/sow-build-inputs.sha256"
)
printf 'v2_source_fingerprint=%s\n' "$SOURCE_FINGERPRINT"
printf 'v2_source_manifest=%s\n' "$LAB_ROOT/sow-build-inputs.sha256"
printf 'fingerprint_script_sha256=%s\n' "$(shasum -a 256 "$PROJECT_ROOT/test/poc/source-fingerprint.sh" | awk '{print $1}')"
printf 'harness_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/run.sh" | awk '{print $1}')"

mkdir -p "$LAB_ROOT/bin" "$LAB_ROOT/workspace"
chmod 0755 "$LAB_ROOT" "$LAB_ROOT/bin" "$LAB_ROOT/workspace"

printf '\n== immutable client images ==\n'
docker image inspect "$RPM_IMAGE" "$DEB_IMAGE" "$HTTP_IMAGE" \
  --format '{{index .RepoTags 0}} id={{.Id}} arch={{.Architecture}} os={{.Os}}' \
  | LC_ALL=C sort -u

printf '\n== build and exercise the public V2 CLI ==\n'
(
  cd "$PROJECT_ROOT"
  CGO_ENABLED=0 go build -trimpath -o "$LAB_ROOT/bin/sow" ./cmd/sow
)
SOW="$LAB_ROOT/bin/sow"
printf 'sow_binary_sha256=%s\n' "$(shasum -a 256 "$SOW" | awk '{print $1}')"
"$SOW" init "$LAB_ROOT/workspace" --json | tee "$LAB_ROOT/init.json"
"$SOW" repo new local -C "$LAB_ROOT/workspace" --json | tee "$LAB_ROOT/repo-new.json"
"$SOW" dist new el9 --format rpm -C "$LAB_ROOT/workspace" -r local --json | tee "$LAB_ROOT/dist-rpm.json"
"$SOW" dist new noble --format deb -C "$LAB_ROOT/workspace" -r local --json | tee "$LAB_ROOT/dist-deb.json"
"$SOW" config check -C "$LAB_ROOT/workspace" --json | tee "$LAB_ROOT/config-check.json"
"$SOW" dist ls -C "$LAB_ROOT/workspace" -r local --json | tee "$LAB_ROOT/dist-list.json"

python3 - "$LAB_ROOT" <<'PY'
import gzip
import json
import pathlib
import sys

lab = pathlib.Path(sys.argv[1])
documents = {}
for name in ("init", "repo-new", "dist-rpm", "dist-deb", "config-check", "dist-list"):
    data = json.loads((lab / f"{name}.json").read_text(encoding="utf-8"))
    assert data["schema"] == "sow.cli/v1", (name, data)
    assert data["ok"] is True and data["errors"] == [], (name, data)
    documents[name] = data

workspace = str(lab / "workspace")
assert documents["init"]["command"] == "init", documents["init"]
assert documents["init"]["repository"] is None, documents["init"]
assert documents["init"]["result"] == {
    "workspace": workspace,
    "config_created": True,
    "repositories_initialized": 0,
    "dists_initialized": 0,
    "existing": [],
}, documents["init"]

repo = documents["repo-new"]
assert repo["command"] == "repo new" and repo["repository"] == "local", repo
assert repo["result"]["name"] == "local", repo
assert repo["result"]["path"] == str(lab / "workspace" / "local"), repo
assert repo["result"]["status"] == "clean", repo
assert repo["result"]["packages"] == 0 and repo["result"]["memberships"] == 0, repo

expected_arches = {
    "dist-rpm": (
        "el9",
        "rpm",
        [
            {"family": "x86_64", "ecosystem_arch": "x86_64"},
            {"family": "aarch64", "ecosystem_arch": "aarch64"},
        ],
    ),
    "dist-deb": (
        "noble",
        "deb",
        [
            {"family": "x86_64", "ecosystem_arch": "amd64"},
            {"family": "aarch64", "ecosystem_arch": "arm64"},
        ],
    ),
}
for document, (dist_name, dist_format, arches) in expected_arches.items():
    data = documents[document]
    assert data["command"] == "dist new" and data["repository"] == "local", data
    assert data["result"]["name"] == dist_name, data
    assert data["result"]["format"] == dist_format, data
    assert data["result"]["architectures"] == arches, data
    assert data["result"]["status"] == "clean" and data["result"]["dirty"] is False, data

check = documents["config-check"]
assert check["command"] == "config check" and check["repository"] is None, check
assert check["result"] == {"workspace": workspace, "repositories": 1, "dists": 2}, check

listing = documents["dist-list"]
assert listing["command"] == "dist ls" and listing["repository"] == "local", listing
assert [(item["name"], item["format"]) for item in listing["result"]["dists"]] == [
    ("el9", "rpm"),
    ("noble", "deb"),
], listing

root = lab / "workspace" / "local" / "dists"
for arch in ("x86_64", "aarch64"):
    repodata = root / "el9" / arch / "repodata"
    assert (repodata / "repomd.xml").is_file(), repodata
    assert not (repodata / "repomd.xml.asc").exists(), repodata
for arch in ("amd64", "arm64"):
    binary = root / "noble" / "main" / f"binary-{arch}"
    assert (binary / "Packages").is_file(), binary
    assert (binary / "Packages.gz").is_file(), binary
    assert (binary / "Packages").read_bytes() == b"", binary
    assert gzip.decompress((binary / "Packages.gz").read_bytes()) == b"", binary
assert (root / "noble" / "Release").is_file()
assert not (root / "noble" / "InRelease").exists()
assert not (root / "noble" / "Release.gpg").exists()
assert (lab / "workspace" / ".sow" / "local.db").is_file()
print("managed JSON and layout assertions: PASS")
PY

printf '\n== DNF and YUM consume both empty RPM architecture views ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/workspace/local:/repo:ro" "$RPM_IMAGE" bash -euxo pipefail -c '
    dnf --version
    yum --version
    cat >/etc/yum.repos.d/sow-empty.repo <<"REPO"
[sow-empty-x86]
name=SOW empty x86_64
baseurl=file:///repo/dists/el9/x86_64
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0

[sow-empty-arm]
name=SOW empty aarch64
baseurl=file:///repo/dists/el9/aarch64
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
REPO
    dnf -y clean all
    dnf -y --disablerepo="*" --enablerepo=sow-empty-x86 makecache
    yum -y --disablerepo="*" --enablerepo=sow-empty-x86 makecache
    dnf -q --disablerepo="*" --enablerepo=sow-empty-x86 repoquery > /tmp/x86-packages
    test ! -s /tmp/x86-packages
    dnf -y --disablerepo="*" --enablerepo=sow-empty-arm makecache
    yum -y --disablerepo="*" --enablerepo=sow-empty-arm makecache
    dnf -q --disablerepo="*" --enablerepo=sow-empty-arm repoquery > /tmp/arm-packages
    test ! -s /tmp/arm-packages
    mkdir -p /tmp/reposync
    dnf -y reposync --repo=sow-empty-x86 --download-path=/tmp/reposync/x86
    dnf -y reposync --repo=sow-empty-arm --download-path=/tmp/reposync/arm
    test "$(find /tmp/reposync -type f -name "*.rpm" | wc -l)" -eq 0
  '

printf '\n== APT consumes both empty DEB architecture indexes ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/workspace/local:/repo:ro" "$DEB_IMAGE" bash -euxo pipefail -c '
    apt-get --version
    dpkg --add-architecture arm64
    printf "deb [trusted=yes arch=amd64,arm64] file:/repo noble main\n" >/etc/apt/sources.list.d/sow-empty.list
    apt-get \
      -o Dir::Etc::sourcelist="sources.list.d/sow-empty.list" \
      -o Dir::Etc::sourceparts="-" \
      -o APT::Get::List-Cleanup="0" update
    apt-cache \
      -o Dir::Etc::sourcelist="sources.list.d/sow-empty.list" \
      -o Dir::Etc::sourceparts="-" dumpavail > /tmp/available
    test ! -s /tmp/available
    grep -q "Architectures: amd64 arm64" /repo/dists/noble/Release
    grep -q "main/binary-amd64/Packages" /repo/dists/noble/Release
    grep -q "main/binary-arm64/Packages" /repo/dists/noble/Release
  '

printf '\n== HTTP serves both empty RPM and DEB architecture views ==\n'
if docker container inspect "$SERVER_NAME" >/dev/null 2>&1 || \
   docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  printf 'refusing pre-existing managed-empty Docker resource\n' >&2
  exit 2
fi
docker network create \
  --label "com.pgsty.sow.managed-empty-token=$LAB_TOKEN" \
  "$NETWORK_NAME" >/dev/null
docker run -d --pull never --platform linux/arm64 \
  --name "$SERVER_NAME" --network "$NETWORK_NAME" \
  --label "com.pgsty.sow.managed-empty-token=$LAB_TOKEN" \
  -v "$LAB_ROOT/workspace/local:/srv:ro" \
  "$HTTP_IMAGE" python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv >/dev/null
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if docker exec "$SERVER_NAME" python3 -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/dists/noble/Release", timeout=1).read(1)' \
    >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 10 ]]; then
    printf 'managed-empty HTTP server did not become ready\n' >&2
    exit 1
  fi
  sleep 0.2
done

docker run --rm --pull never --platform linux/amd64 --network "$NETWORK_NAME" \
  "$RPM_IMAGE" bash -euxo pipefail -c "
    cat >/etc/yum.repos.d/sow-empty.repo <<'REPO'
[sow-empty-x86]
name=SOW empty x86_64 HTTP
baseurl=http://$SERVER_NAME:8080/dists/el9/x86_64
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0

[sow-empty-arm]
name=SOW empty aarch64 HTTP
baseurl=http://$SERVER_NAME:8080/dists/el9/aarch64
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
REPO
    dnf -y clean all
    for repo in sow-empty-x86 sow-empty-arm; do
      dnf -y --disablerepo='*' --enablerepo=\"\$repo\" makecache
      dnf -q --disablerepo='*' --enablerepo=\"\$repo\" repoquery >\"/tmp/\$repo-packages\"
      test ! -s \"/tmp/\$repo-packages\"
      mkdir -p \"/tmp/\$repo-reposync\"
      dnf -y reposync --repo=\"\$repo\" --download-path=\"/tmp/\$repo-reposync\"
      test \"\$(find \"/tmp/\$repo-reposync\" -type f -name '*.rpm' | wc -l)\" -eq 0
    done
  "

docker run --rm --pull never --platform linux/amd64 --network "$NETWORK_NAME" \
  "$DEB_IMAGE" bash -euxo pipefail -c "
    dpkg --add-architecture arm64
    printf 'deb [trusted=yes arch=amd64,arm64] http://$SERVER_NAME:8080 noble main\\n' \
      >/etc/apt/sources.list.d/sow-empty.list
    apt-get -o Dir::Etc::sourcelist='sources.list.d/sow-empty.list' \
      -o Dir::Etc::sourceparts='-' -o APT::Get::List-Cleanup='0' update
    apt-cache -o Dir::Etc::sourcelist='sources.list.d/sow-empty.list' \
      -o Dir::Etc::sourceparts='-' dumpavail >/tmp/available
    test ! -s /tmp/available
  "

printf '\nPASS: public SOW V2 CLI created empty RPM/DEB Dists consumed over file and HTTP.\n'
printf 'This is local source/client evidence only; nothing was signed or published.\n'
printf 'artifacts=%s\n' "$LAB_ROOT"
printf 'utc_finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
