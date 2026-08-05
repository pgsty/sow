#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)
SOURCE_ROOT=${SOURCE_ROOT:-/Users/vonng/pgsty/repo2}
RPM_BUILD_IMAGE=${RPM_BUILD_IMAGE:-pgsty/el9:build}
RPM_SIGN_IMAGE=${RPM_SIGN_IMAGE:-dnfupdate:latest}
RPM_AMD64_IMAGE=${RPM_AMD64_IMAGE:-pgsty/el9:build}
RPM_ARM64_IMAGE=${RPM_ARM64_IMAGE:-pgsty/el9a:build}
DEB_BUILD_IMAGE=${DEB_BUILD_IMAGE:-pgsty/u24:build}
DEB_AMD64_IMAGE=${DEB_AMD64_IMAGE:-pgsty/u24:build}
DEB_ARM64_IMAGE=${DEB_ARM64_IMAGE:-pgsty/u24a:build}
HTTP_IMAGE=${HTTP_IMAGE:-pgsty/u24a:build}

SOURCE_ROOT=$(cd -- "$SOURCE_ROOT" && pwd -P)
if [[ "$SOURCE_ROOT" != /Users/vonng/pgsty/repo2 ]]; then
  printf 'refusing source other than the dedicated repo2 tree: %s\n' "$SOURCE_ROOT" >&2
  exit 2
fi
if [[ -z "${LAB_ROOT:-}" ]]; then
  LAB_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-repo2-ordinary.XXXXXX)
else
  LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
  if find "$LAB_ROOT" -mindepth 1 -print -quit | grep -q .; then
    printf 'refusing non-empty LAB_ROOT: %s\n' "$LAB_ROOT" >&2
    exit 2
  fi
fi
LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
case "$LAB_ROOT" in
  /Users/vonng/repo/sow-v2-repo2-ordinary.*) ;;
  *)
    printf 'refusing LAB_ROOT outside the dedicated prefix: %s\n' "$LAB_ROOT" >&2
    exit 2
    ;;
esac
if [[ "$LAB_ROOT" == /Users/vonng/pgsty/repo* ]]; then
  printf 'production repository is forbidden: %s\n' "$LAB_ROOT" >&2
  exit 2
fi

for tool in docker go gpg gpgconf python3 shasum; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'required tool is unavailable: %s\n' "$tool" >&2
    exit 2
  }
done

mkdir -p "$LAB_ROOT/evidence" "$LAB_ROOT/bin" "$LAB_ROOT/lists"
exec > >(tee "$LAB_ROOT/run.log") 2>&1

printf 'SOW V2 repo2 ordinary repository acceptance\n'
printf 'utc_started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'project_root=%s\n' "$PROJECT_ROOT"
printf 'source_root=%s (read-only input)\n' "$SOURCE_ROOT"
printf 'lab_root=%s\n' "$LAB_ROOT"
printf 'git_head=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
printf 'go_version=%s\n' "$(go version)"
printf 'docker_server=%s\n' "$(docker version --format '{{.Server.Version}}')"

SOURCE_FINGERPRINT=$(
  "$PROJECT_ROOT/test/poc/source-fingerprint.sh" \
    "$PROJECT_ROOT" "$LAB_ROOT/evidence/sow-build-inputs.sha256"
)
printf 'source_fingerprint=%s\n' "$SOURCE_FINGERPRINT"
printf 'fingerprint_script_sha256=%s\n' "$(shasum -a 256 "$PROJECT_ROOT/test/poc/source-fingerprint.sh" | awk '{print $1}')"
printf 'harness_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/run.sh" | awk '{print $1}')"
printf 'comparison_script_sha256=%s\n' "$(shasum -a 256 "$PROJECT_ROOT/test/poc/plain-clients/compare_offline_metadata.py" | awk '{print $1}')"
printf 'changes_consumer_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/apply_changes.py" | awk '{print $1}')"

printf '\n== immutable container images ==\n'
docker image inspect \
  "$RPM_BUILD_IMAGE" "$RPM_SIGN_IMAGE" "$RPM_AMD64_IMAGE" "$RPM_ARM64_IMAGE" \
  "$DEB_BUILD_IMAGE" "$DEB_AMD64_IMAGE" "$DEB_ARM64_IMAGE" "$HTTP_IMAGE" \
  --format '{{index .RepoTags 0}} id={{.Id}} arch={{.Architecture}} os={{.Os}}' \
  | LC_ALL=C sort -u | tee "$LAB_ROOT/evidence/images.txt"

(
  cd -- "$SOURCE_ROOT"
  find yum/infra/x86_64 -maxdepth 1 -type f -name '*.rpm' -print \
    | LC_ALL=C sort >"$LAB_ROOT/lists/rpm-x86_64.paths"
  find apt/infra/pool -type f -name '*.deb' -print \
    | LC_ALL=C sort >"$LAB_ROOT/lists/deb-infra.paths"
)
cat >"$LAB_ROOT/lists/managed.paths" <<'PATHS'
yum/infra/x86_64/asciinema-3.2.1-1.x86_64.rpm
yum/infra/aarch64/asciinema-3.2.1-1.aarch64.rpm
yum/infra/x86_64/pev2-1.22.0-1.noarch.rpm
apt/infra/pool/main/a/asciinema/asciinema_3.2.1-1_amd64.deb
apt/infra/pool/main/a/asciinema/asciinema_3.2.1-1_arm64.deb
apt/infra/pool/main/p/pev2/pev2_1.22.0_all.deb
PATHS
cat >"$LAB_ROOT/lists/p0-sign.paths" <<'PATHS'
yum/infra/x86_64/dblab-0.43.0-1.x86_64.rpm
PATHS

if [[ $(wc -l <"$LAB_ROOT/lists/rpm-x86_64.paths") -ne 87 ]]; then
  printf 'unexpected current repo2 RPM count (want 87): %s\n' "$(wc -l <"$LAB_ROOT/lists/rpm-x86_64.paths")" >&2
  exit 1
fi
if [[ $(wc -l <"$LAB_ROOT/lists/deb-infra.paths") -ne 181 ]]; then
  printf 'unexpected current repo2 DEB count (want 181): %s\n' "$(wc -l <"$LAB_ROOT/lists/deb-infra.paths")" >&2
  exit 1
fi

make_source_manifest() {
  local output=$1
  (
    cd -- "$SOURCE_ROOT"
    cat "$LAB_ROOT/lists/rpm-x86_64.paths" \
      "$LAB_ROOT/lists/deb-infra.paths" \
      "$LAB_ROOT/lists/managed.paths" \
      "$LAB_ROOT/lists/p0-sign.paths" \
      | LC_ALL=C sort -u \
      | while IFS= read -r source_file; do
          [[ -f "$source_file" && ! -L "$source_file" ]] || {
            printf 'missing or unsafe repo2 input: %s\n' "$source_file" >&2
            exit 1
          }
          digest=$(shasum -a 256 -- "$source_file" | awk '{print $1}')
          size=$(stat -f '%z' "$source_file")
          printf '%s  %s  %s\n' "$digest" "$size" "$source_file"
        done
  ) >"$output"
}

printf '\n== bind read-only repo2 inputs ==\n'
make_source_manifest "$LAB_ROOT/evidence/repo2-input-before.sha256"
printf 'repo2_input_files=%s\n' "$(wc -l <"$LAB_ROOT/evidence/repo2-input-before.sha256")"
awk '{bytes += $2} END {printf "repo2_input_bytes=%.0f repo2_input_gib=%.6f\n", bytes, bytes/1073741824}' \
  "$LAB_ROOT/evidence/repo2-input-before.sha256"
printf 'repo2_input_manifest_sha256=%s\n' "$(shasum -a 256 "$LAB_ROOT/evidence/repo2-input-before.sha256" | awk '{print $1}')"

clone_file() {
  local source=$1 target=$2
  [[ "$source" == "$SOURCE_ROOT"/* || "$source" == "$LAB_ROOT"/* ]] || {
    printf 'unsafe clone source: %s\n' "$source" >&2
    return 1
  }
  [[ "$target" == "$LAB_ROOT"/* && ! -e "$target" && ! -L "$target" ]] || {
    printf 'unsafe clone target: %s\n' "$target" >&2
    return 1
  }
  if ! cp -c -p -- "$source" "$target" 2>/dev/null; then
    if [[ -e "$target" || -L "$target" ]]; then
      [[ "$target" == "$LAB_ROOT"/* ]] || return 1
      rm -f -- "$target"
    fi
    cp -p -- "$source" "$target"
  fi
}

printf '\n== clone ordinary repo2 sets into the retained lab ==\n'
for family in el9 u24; do
  mkdir -p "$LAB_ROOT/plain/$family/sow" "$LAB_ROOT/plain/$family/traditional"
done
while IFS= read -r relative; do
  basename=${relative##*/}
  clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/plain/el9/sow/$basename"
  clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/plain/el9/traditional/$basename"
done <"$LAB_ROOT/lists/rpm-x86_64.paths"
while IFS= read -r relative; do
  basename=${relative##*/}
  clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/plain/u24/sow/$basename"
  clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/plain/u24/traditional/$basename"
done <"$LAB_ROOT/lists/deb-infra.paths"

printf '\n== build current-checkout Darwin and Linux binaries ==\n'
(
  cd -- "$PROJECT_ROOT"
  GOWORK=off go build -trimpath -o "$LAB_ROOT/bin/sow-darwin" ./cmd/sow
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off \
    go build -trimpath -o "$LAB_ROOT/bin/sow-linux-amd64" ./cmd/sow
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off \
    go build -trimpath -o "$LAB_ROOT/bin/sow-linux-arm64" ./cmd/sow
)
chmod 0755 "$LAB_ROOT/bin/sow-darwin" "$LAB_ROOT/bin/sow-linux-amd64" \
  "$LAB_ROOT/bin/sow-linux-arm64"
printf 'sow_darwin_sha256=%s\n' "$(shasum -a 256 "$LAB_ROOT/bin/sow-darwin" | awk '{print $1}')"
printf 'sow_linux_amd64_sha256=%s\n' "$(shasum -a 256 "$LAB_ROOT/bin/sow-linux-amd64" | awk '{print $1}')"
printf 'sow_linux_arm64_sha256=%s\n' "$(shasum -a 256 "$LAB_ROOT/bin/sow-linux-arm64" | awk '{print $1}')"
"$LAB_ROOT/bin/sow-darwin" version

printf '\n== SOW Plain versus traditional metadata on repo2 infra sets ==\n'
"$LAB_ROOT/bin/sow-darwin" create "$LAB_ROOT/plain/el9/sow" -j 8 --json \
  | tee "$LAB_ROOT/evidence/plain-rpm-create.json"
"$LAB_ROOT/bin/sow-darwin" create "$LAB_ROOT/plain/u24/sow" -j 8 --json \
  | tee "$LAB_ROOT/evidence/plain-deb-create.json"
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/plain/el9/traditional:/repo:rw" "$RPM_BUILD_IMAGE" \
  createrepo_c --no-database --changelog-limit 10 /repo
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/plain/u24/traditional:/repo:rw" "$DEB_BUILD_IMAGE" bash -euxo pipefail -c '
    cd /repo
    dpkg-scanpackages --multiversion . /dev/null >Packages
    gzip -n -9 -c Packages >Packages.gz
  '
python3 "$PROJECT_ROOT/test/poc/plain-clients/compare_offline_metadata.py" "$LAB_ROOT/plain" \
  | tee "$LAB_ROOT/evidence/traditional-comparison.json"

printf '\n== generate disposable acceptance signing identity ==\n'
mkdir -p "$LAB_ROOT/gnupg" "$LAB_ROOT/home" "$LAB_ROOT/tools" "$LAB_ROOT/workspace/keys" \
  "$LAB_ROOT/managed-inputs/rpm" "$LAB_ROOT/managed-inputs/deb" "$LAB_ROOT/p0-sign"
chmod 0700 "$LAB_ROOT/gnupg" "$LAB_ROOT/home" "$LAB_ROOT/tools" "$LAB_ROOT/workspace/keys"

clear_lab_gpg_sockets() {
  local socket
  gpgconf --homedir "$LAB_ROOT/gnupg" --kill all >/dev/null 2>&1 || true
  while IFS= read -r socket; do
    [[ "$socket" == "$LAB_ROOT/gnupg/"S.* ]] || {
      printf 'unsafe GPG socket path: %s\n' "$socket" >&2
      return 1
    }
    printf 'remove stale lab GPG socket: %s\n' "$socket"
  done < <(find "$LAB_ROOT/gnupg" -maxdepth 1 -type s -print)
  find "$LAB_ROOT/gnupg" -maxdepth 1 -type s -delete
}

GNUPGHOME="$LAB_ROOT/gnupg" gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-gen-key 'SOW repo2 acceptance <sow-repo2@example.invalid>' rsa2048 sign 1d
SIGNING_FINGERPRINT=$(
  GNUPGHOME="$LAB_ROOT/gnupg" gpg --batch --with-colons --fingerprint --list-secret-keys \
    | awk -F: '$1 == "fpr" {print $10; exit}'
)
printf '%s\n' "$SIGNING_FINGERPRINT" >"$LAB_ROOT/evidence/signing-fingerprint.txt"
GNUPGHOME="$LAB_ROOT/gnupg" gpg --batch --armor --export "$SIGNING_FINGERPRINT" \
  >"$LAB_ROOT/workspace/keys/repo-public.asc"
GNUPGHOME="$LAB_ROOT/gnupg" gpg --batch --armor --export-secret-keys "$SIGNING_FINGERPRINT" \
  >"$LAB_ROOT/workspace/keys/repo-private.asc"
SIGNING_FINGERPRINT=$(tr -d '\r\n' <"$LAB_ROOT/evidence/signing-fingerprint.txt")
if [[ ! "$SIGNING_FINGERPRINT" =~ ^[0-9A-F]{40}$ ]]; then
  printf 'invalid generated fingerprint: %s\n' "$SIGNING_FINGERPRINT" >&2
  exit 1
fi
cat >"$LAB_ROOT/home/.rpmmacros" <<MACROS
%_signature gpg
%_gpg_name $SIGNING_FINGERPRINT
%_gpg_path /gnupg
%_gpgbin /usr/bin/gpg2
%_gpg_digest_algo sha256
MACROS
chmod 0600 "$LAB_ROOT/home/.rpmmacros"
clear_lab_gpg_sockets

cat >"$LAB_ROOT/tools/rpm" <<'RPM_WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail

: "${SOW_TEST_LAB_ROOT:?}"
: "${SOW_TEST_GNUPGHOME:?}"
: "${SOW_TEST_RPM_HOME:?}"
: "${SOW_TEST_RPM_IMAGE:?}"
case "$SOW_TEST_LAB_ROOT" in
  /Users/vonng/repo/sow-v2-repo2-ordinary.*) ;;
  *) printf 'unsafe signing lab root: %s\n' "$SOW_TEST_LAB_ROOT" >&2; exit 2 ;;
esac
[[ "$SOW_TEST_GNUPGHOME" == "$SOW_TEST_LAB_ROOT/gnupg" ]] || exit 2
[[ "$SOW_TEST_RPM_HOME" == "$SOW_TEST_LAB_ROOT/home" ]] || exit 2

ARGS=("$@")
if (( ${#ARGS[@]} == 0 )); then
  printf 'missing rpm arguments\n' >&2
  exit 2
fi
TARGET_INDEX=$((${#ARGS[@]} - 1))
TARGET=${ARGS[$TARGET_INDEX]}
case "$TARGET" in
  /*)
    [[ "$TARGET" == "$SOW_TEST_LAB_ROOT"/* && -f "$TARGET" && ! -L "$TARGET" ]] || {
      printf 'unsafe absolute signing target: %s\n' "$TARGET" >&2
      exit 2
    }
    STAGE_ROOT=$(cd -- "$(dirname -- "$TARGET")" && /bin/pwd -P)
    TARGET_NAME=$(basename -- "$TARGET")
    [[ "$TARGET" == "$STAGE_ROOT/$TARGET_NAME" ]] || exit 2
    ARGS[$TARGET_INDEX]="/work/$TARGET_NAME"
    ;;
  */*)
    printf 'unsafe relative signing target: %s\n' "$TARGET" >&2
    exit 2
    ;;
  *)
    TARGET_NAME=$TARGET
    [[ -n "$TARGET_NAME" && "$TARGET_NAME" != . && "$TARGET_NAME" != .. ]] || exit 2
    STAGE_ROOT=$(/bin/pwd -P)
    [[ -f "$STAGE_ROOT/$TARGET_NAME" && ! -L "$STAGE_ROOT/$TARGET_NAME" ]] || exit 2
    ;;
esac
case "$STAGE_ROOT" in
  "$SOW_TEST_LAB_ROOT"/*) ;;
  *) printf 'unsafe signing stage: %s\n' "$STAGE_ROOT" >&2; exit 2 ;;
esac

clear_sockets() {
  local socket
  gpgconf --homedir "$SOW_TEST_GNUPGHOME" --kill all >/dev/null 2>&1 || true
  while IFS= read -r socket; do
    [[ "$socket" == "$SOW_TEST_GNUPGHOME/"S.* ]] || exit 2
  done < <(find "$SOW_TEST_GNUPGHOME" -maxdepth 1 -type s -print)
  find "$SOW_TEST_GNUPGHOME" -maxdepth 1 -type s -delete
}

clear_sockets
set +e
docker run --rm --pull never --platform linux/arm64 \
  -e HOME=/home -e GNUPGHOME=/gnupg \
  -v "$STAGE_ROOT:/work:rw" \
  -v "$SOW_TEST_GNUPGHOME:/gnupg:rw" \
  -v "$SOW_TEST_RPM_HOME:/home:ro" \
  -w /work "$SOW_TEST_RPM_IMAGE" rpm "${ARGS[@]}"
STATUS=$?
set -e
clear_sockets
exit "$STATUS"
RPM_WRAPPER
chmod 0700 "$LAB_ROOT/tools/rpm"

while IFS= read -r relative; do
  basename=${relative##*/}
  case "$relative" in
    *.rpm) clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/managed-inputs/rpm/$basename" ;;
    *.deb) clone_file "$SOURCE_ROOT/$relative" "$LAB_ROOT/managed-inputs/deb/$basename" ;;
    *) printf 'unexpected managed input: %s\n' "$relative" >&2; exit 1 ;;
  esac
done <"$LAB_ROOT/lists/managed.paths"
P0_RELATIVE=$(cat "$LAB_ROOT/lists/p0-sign.paths")
clone_file "$SOURCE_ROOT/$P0_RELATIVE" "$LAB_ROOT/p0-sign/${P0_RELATIVE##*/}"

cat >"$LAB_ROOT/workspace/sow.yml" <<'YAML'
schema: sow/v2
architectures: [x86_64, aarch64]
repos:
  local:
    signing:
      rpm:
        packages:
          mode: always
          key: file://keys/repo-private.asc
        metadata:
          key: file://keys/repo-private.asc
      deb:
        metadata:
          key: file://keys/repo-private.asc
    dists:
      el9:
        format: rpm
      noble:
        format: deb
YAML

printf '\n== Plain RPM --sign-with/--overwrite and signed Managed build ==\n'
export PATH="$LAB_ROOT/tools:$PATH"
export GNUPGHOME="$LAB_ROOT/gnupg"
export SOW_TEST_LAB_ROOT="$LAB_ROOT"
export SOW_TEST_GNUPGHOME="$LAB_ROOT/gnupg"
export SOW_TEST_RPM_HOME="$LAB_ROOT/home"
export SOW_TEST_RPM_IMAGE="$RPM_SIGN_IMAGE"
"$LAB_ROOT/bin/sow-darwin" create "$LAB_ROOT/p0-sign" \
  --sign-with "$SIGNING_FINGERPRINT" --overwrite --json \
  | tee "$LAB_ROOT/evidence/p0-signed-create.json"
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/p0-sign:/repo:ro" \
  -v "$LAB_ROOT/workspace/keys/repo-public.asc:/key.asc:ro" \
  "$RPM_BUILD_IMAGE" bash -euxo pipefail -c '
    rpmkeys --import /key.asc
    rpm --checksig /repo/*.rpm
  '

"$LAB_ROOT/bin/sow-darwin" init "$LAB_ROOT/workspace" --json \
  | tee "$LAB_ROOT/evidence/managed-init.json"
"$LAB_ROOT/bin/sow-darwin" add "$LAB_ROOT"/managed-inputs/rpm/*.rpm \
  -C "$LAB_ROOT/workspace" -r local -d el9 -j 1 --json \
  | tee "$LAB_ROOT/evidence/managed-add-rpm.json"
"$LAB_ROOT/bin/sow-darwin" add "$LAB_ROOT"/managed-inputs/deb/*.deb \
  -C "$LAB_ROOT/workspace" -r local -d noble -j 4 --json \
  | tee "$LAB_ROOT/evidence/managed-add-deb.json"
"$LAB_ROOT/bin/sow-darwin" status -C "$LAB_ROOT/workspace" -r local --json \
  | tee "$LAB_ROOT/evidence/managed-status.json"
"$LAB_ROOT/bin/sow-darwin" check -C "$LAB_ROOT/workspace" -r local -j 4 --json \
  | tee "$LAB_ROOT/evidence/managed-check.json"
"$LAB_ROOT/bin/sow-darwin" changes 0 -C "$LAB_ROOT/workspace" -r local --json \
  | tee "$LAB_ROOT/evidence/changes-0.json"
"$LAB_ROOT/bin/sow-darwin" log export "$LAB_ROOT/evidence/log-before-prune.jsonl" \
  -C "$LAB_ROOT/workspace" -r local

printf '\n== verify package and metadata signatures independently ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/workspace:/workspace:ro" "$RPM_BUILD_IMAGE" bash -euxo pipefail -c '
    export GNUPGHOME=/tmp/verify-gnupg
    mkdir -m 0700 "$GNUPGHOME"
    gpg --batch --import /workspace/keys/repo-public.asc
    rpmkeys --import /workspace/keys/repo-public.asc
    find /workspace/local/pool -type f -name "*.rpm" -print -exec rpm --checksig "{}" ";"
    for repomd in /workspace/local/dists/el9/*/repodata/repomd.xml; do
      gpg --batch --verify "$repomd.asc" "$repomd"
    done
    gpg --batch --verify /workspace/local/dists/noble/Release.gpg \
      /workspace/local/dists/noble/Release
    gpg --batch --verify /workspace/local/dists/noble/InRelease
  '

printf '\n== changes 0 external phase-ordered consumer ==\n'
mkdir -p "$LAB_ROOT/handoff"
python3 "$SCRIPT_DIR/apply_changes.py" \
  --source "$LAB_ROOT/workspace/local" \
  --target "$LAB_ROOT/handoff" \
  --changes "$LAB_ROOT/evidence/changes-0.json" \
  | tee "$LAB_ROOT/evidence/handoff.json"

NETWORK_NAME="sow-repo2-net-$$"
SERVER_NAME="sow-repo2-http-$$"
if [[ ! "$NETWORK_NAME" =~ ^sow-repo2-net-[0-9]+$ || ! "$SERVER_NAME" =~ ^sow-repo2-http-[0-9]+$ ]]; then
  printf 'unsafe Docker resource name\n' >&2
  exit 1
fi
cleanup_docker() {
  if [[ "$SERVER_NAME" =~ ^sow-repo2-http-[0-9]+$ ]]; then
    docker rm -f "$SERVER_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "$NETWORK_NAME" =~ ^sow-repo2-net-[0-9]+$ ]]; then
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup_docker EXIT
docker network create "$NETWORK_NAME" >/dev/null
docker run -d --pull never --platform linux/arm64 --name "$SERVER_NAME" \
  --network "$NETWORK_NAME" -v "$LAB_ROOT/workspace/local:/srv:ro" \
  "$HTTP_IMAGE" python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv >/dev/null
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if docker exec "$SERVER_NAME" python3 -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/dists/noble/Release", timeout=1).read(1)' \
    >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 10 ]]; then
    printf 'HTTP repository server did not become ready\n' >&2
    exit 1
  fi
  sleep 0.2
done

run_dnf_client() {
  local platform=$1 image=$2 arch=$3 transport=$4 baseurl=$5
  docker run --rm --pull never --platform "$platform" --network "$NETWORK_NAME" \
    -v "$LAB_ROOT/workspace/local:/repo:ro" \
    -v "$LAB_ROOT/workspace/keys/repo-public.asc:/key.asc:ro" \
    "$image" bash -euxo pipefail -c "
      cat >/etc/yum.repos.d/sow-managed.repo <<'REPO'
[sow-managed]
name=SOW Managed repo2 $arch $transport
baseurl=$baseurl
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///key.asc
metadata_expire=0
module_hotfixes=1
REPO
      dnf -y clean all
      dnf -y --disablerepo='*' --enablerepo=sow-managed makecache
      dnf -q --disablerepo='*' --enablerepo=sow-managed repoquery --location asciinema pev2
      mkdir -p /tmp/download /tmp/reposync
      dnf -y --disablerepo='*' --enablerepo=sow-managed install \
        --downloadonly --downloaddir=/tmp/download asciinema pev2
      test \"\$(find /tmp/download -maxdepth 1 -type f -name '*.rpm' | wc -l)\" -eq 2
      dnf -y --disablerepo='*' --enablerepo=sow-managed install asciinema pev2
      rpm -q asciinema pev2
      dnf -y reposync --repo=sow-managed --download-path=/tmp/reposync
      test \"\$(find /tmp/reposync -type f -name '*.rpm' | wc -l)\" -eq 2
    "
}

run_apt_client() {
  local platform=$1 image=$2 arch=$3 transport=$4 uri=$5
  docker run --rm --pull never --platform "$platform" --network "$NETWORK_NAME" \
    -v "$LAB_ROOT/workspace/local:/repo:ro" \
    -v "$LAB_ROOT/workspace/keys/repo-public.asc:/key.asc:ro" \
    "$image" bash -euxo pipefail -c "
      gpg --batch --dearmor --output /usr/share/keyrings/sow-managed.gpg /key.asc
      printf 'deb [signed-by=/usr/share/keyrings/sow-managed.gpg arch=$arch] $uri noble main\\n' \
        >/etc/apt/sources.list.d/sow-managed.list
      apt-get -o Dir::Etc::sourcelist='sources.list.d/sow-managed.list' \
        -o Dir::Etc::sourceparts='-' -o APT::Get::List-Cleanup='0' update
      apt-cache -o Dir::Etc::sourcelist='sources.list.d/sow-managed.list' \
        -o Dir::Etc::sourceparts='-' show asciinema pev2 >/tmp/show
      grep -q '^Package: asciinema$' /tmp/show
      grep -q '^Package: pev2$' /tmp/show
      cd /tmp
      apt-get -o Dir::Etc::sourcelist='sources.list.d/sow-managed.list' \
        -o Dir::Etc::sourceparts='-' download asciinema pev2
      test \"\$(find /tmp -maxdepth 1 -type f -name '*.deb' | wc -l)\" -eq 2
      apt-get -y -o Dir::Etc::sourcelist='sources.list.d/sow-managed.list' \
        -o Dir::Etc::sourceparts='-' install asciinema pev2
      dpkg-query -W asciinema pev2
    "
}

printf '\n== real amd64/arm64 clients over file and HTTP ==\n'
run_dnf_client linux/amd64 "$RPM_AMD64_IMAGE" x86_64 file file:///repo/dists/el9/x86_64
run_dnf_client linux/arm64 "$RPM_ARM64_IMAGE" aarch64 file file:///repo/dists/el9/aarch64
run_dnf_client linux/amd64 "$RPM_AMD64_IMAGE" x86_64 http http://$SERVER_NAME:8080/dists/el9/x86_64
run_dnf_client linux/arm64 "$RPM_ARM64_IMAGE" aarch64 http http://$SERVER_NAME:8080/dists/el9/aarch64
run_apt_client linux/amd64 "$DEB_AMD64_IMAGE" amd64 file file:/repo
run_apt_client linux/arm64 "$DEB_ARM64_IMAGE" arm64 file file:/repo
run_apt_client linux/amd64 "$DEB_AMD64_IMAGE" amd64 http http://$SERVER_NAME:8080
run_apt_client linux/arm64 "$DEB_ARM64_IMAGE" arm64 http http://$SERVER_NAME:8080

printf '\n== failed audit, log prune, and post-prune invariants ==\n'
printf 'not an rpm\n' >"$LAB_ROOT/invalid.rpm"
clear_lab_gpg_sockets
set +e
"$LAB_ROOT/bin/sow-darwin" add "$LAB_ROOT/invalid.rpm" \
  -C "$LAB_ROOT/workspace" -r local -d el9 --json \
  >"$LAB_ROOT/evidence/expected-invalid-add.json"
INVALID_EXIT=$?
set -e
if [[ $INVALID_EXIT -ne 6 ]]; then
  printf 'invalid add exit=%s, want 6\n' "$INVALID_EXIT" >&2
  exit 1
fi
clear_lab_gpg_sockets
"$LAB_ROOT/bin/sow-darwin" log export "$LAB_ROOT/evidence/log-with-failure.jsonl" \
  -C "$LAB_ROOT/workspace" -r local
"$LAB_ROOT/bin/sow-darwin" log prune 2100-01-01T00:00:00Z \
  -C "$LAB_ROOT/workspace" -r local --json | tee "$LAB_ROOT/evidence/log-prune.json"
"$LAB_ROOT/bin/sow-darwin" check -C "$LAB_ROOT/workspace" -r local -j 4 --json \
  | tee "$LAB_ROOT/evidence/check-after-prune.json"
"$LAB_ROOT/bin/sow-darwin" changes 0 -C "$LAB_ROOT/workspace" -r local --json \
  | tee "$LAB_ROOT/evidence/changes-after-prune.json"
mkdir -p "$LAB_ROOT/handoff-after-prune"
python3 "$SCRIPT_DIR/apply_changes.py" \
  --source "$LAB_ROOT/workspace/local" \
  --target "$LAB_ROOT/handoff-after-prune" \
  --changes "$LAB_ROOT/evidence/changes-after-prune.json" \
  | tee "$LAB_ROOT/evidence/handoff-after-prune.json"

printf '\n== prove repo2 source remained byte-identical ==\n'
make_source_manifest "$LAB_ROOT/evidence/repo2-input-after.sha256"
cmp "$LAB_ROOT/evidence/repo2-input-before.sha256" "$LAB_ROOT/evidence/repo2-input-after.sha256"
printf 'repo2_readonly_identity=PASS\n'

printf '\nPASS: repo2 traditional metadata, signed Plain/Managed repositories, clients, handoff, and prune.\n'
printf 'No production repository, remote endpoint, or publication path was modified.\n'
printf 'artifacts=%s\n' "$LAB_ROOT"
printf 'utc_finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
