#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT=/work/repo
readonly DIST_ROOT="$REPO_ROOT/dists/el9"
readonly POOL_ROOT="$REPO_ROOT/pool/s/sow-yum-relative"
readonly X86_VIEW="$DIST_ROOT/x86_64"
readonly ARM_VIEW="$DIST_ROOT/aarch64"
readonly LOCATION_PREFIX='../../../'

run() {
  printf '\n+ '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

assert_file() {
  [[ -f "$1" ]] || {
    printf 'missing expected file: %s\n' "$1" >&2
    exit 1
  }
}

assert_primary_locations() {
  local view=$1
  shift
  local primary
  primary=$(find "$view/repodata" -maxdepth 1 -type f -name '*-primary.xml.gz' -print -quit)
  assert_file "$primary"

  local actual
  actual=$(gzip -dc "$primary" | sed -n 's/.*<location href="\([^"]*\)".*/\1/p' | sort)
  printf '%s\n' "$actual"

  local expected
  expected=$(printf '%s\n' "$@" | sort)
  [[ "$actual" == "$expected" ]] || {
    printf 'unexpected package locations in %s\nexpected:\n%s\nactual:\n%s\n' \
      "$view" "$expected" "$actual" >&2
    exit 1
  }
  if grep -Eq '(^|[[:space:]"])(https?://|file://|/)' <<<"$actual"; then
    printf 'absolute URL/path found in package locations for %s\n' "$view" >&2
    exit 1
  fi
}

printf '=== client identity ===\n'
run uname -a
run uname -m
run sh -c '. /etc/os-release; printf "%s %s (%s)\\n" "$NAME" "$VERSION_ID" "$PRETTY_NAME"'

printf '\n=== install fixture tooling ===\n'
run dnf -y -q install rpm-build createrepo_c dnf-plugins-core
run dnf --version
run createrepo_c --version
run rpm --version

printf '\n=== build minimal native and noarch RPMs ===\n'
run mkdir -p /work/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
run cp /fixture/specs/sow-yum-relative-native.spec /work/rpmbuild/SPECS/
run cp /fixture/specs/sow-yum-relative-neutral.spec /work/rpmbuild/SPECS/
run rpmbuild -bb --define '_topdir /work/rpmbuild' /work/rpmbuild/SPECS/sow-yum-relative-native.spec
run rpmbuild -bb --define '_topdir /work/rpmbuild' /work/rpmbuild/SPECS/sow-yum-relative-neutral.spec

native_rpm=$(find /work/rpmbuild/RPMS/x86_64 -maxdepth 1 -type f -name 'sow-yum-relative-native-*.rpm' -print -quit)
neutral_rpm=$(find /work/rpmbuild/RPMS/noarch -maxdepth 1 -type f -name 'sow-yum-relative-neutral-*.rpm' -print -quit)
assert_file "$native_rpm"
assert_file "$neutral_rpm"
run rpm -qp --qf '%{NAME} %{EVR} %{ARCH}\n' "$native_rpm" "$neutral_rpm"

run mkdir -p "$POOL_ROOT" "$X86_VIEW" "$ARM_VIEW"
run cp "$native_rpm" "$neutral_rpm" "$POOL_ROOT/"
native_name=$(basename "$native_rpm")
neutral_name=$(basename "$neutral_rpm")
native_href="${LOCATION_PREFIX}pool/s/sow-yum-relative/$native_name"
neutral_href="${LOCATION_PREFIX}pool/s/sow-yum-relative/$neutral_name"

printf 'pool package sha256:\n'
run sha256sum "$POOL_ROOT/$native_name" "$POOL_ROOT/$neutral_name"

printf '\n=== render two architecture views with relative pool locations ===\n'
printf 'pool/s/sow-yum-relative/%s\n' "$native_name" > /work/x86.pkglist
printf 'pool/s/sow-yum-relative/%s\n' "$neutral_name" >> /work/x86.pkglist
printf 'pool/s/sow-yum-relative/%s\n' "$neutral_name" > /work/arm.pkglist

run createrepo_c --quiet --general-compress-type=gz \
  --pkglist /work/x86.pkglist --location-prefix "$LOCATION_PREFIX" \
  --outputdir "$X86_VIEW" "$REPO_ROOT"
run createrepo_c --quiet --general-compress-type=gz \
  --pkglist /work/arm.pkglist --location-prefix "$LOCATION_PREFIX" \
  --outputdir "$ARM_VIEW" "$REPO_ROOT"

printf 'x86_64 primary locations:\n'
assert_primary_locations "$X86_VIEW" "$native_href" "$neutral_href"
printf 'aarch64 primary locations:\n'
assert_primary_locations "$ARM_VIEW" "$neutral_href"

cat > /etc/yum.repos.d/sow-relative-poc.repo <<'EOF'
[sow-relative-x86]
name=SOW relative pool x86_64 view
baseurl=file:///work/repo/dists/el9/x86_64
enabled=0
gpgcheck=0
metadata_expire=0

[sow-relative-arm]
name=SOW relative pool aarch64 view
baseurl=file:///work/repo/dists/el9/aarch64
enabled=0
gpgcheck=0
metadata_expire=0
EOF

printf '\n=== x86_64 client: makecache, locate, download-only, install ===\n'
run dnf -q clean all
run dnf -v --disablerepo='*' --enablerepo=sow-relative-x86 makecache
run dnf -q --disablerepo='*' --enablerepo=sow-relative-x86 repoquery \
  --qf '%{name} %{arch} %{location}' sow-yum-relative-native sow-yum-relative-neutral
run mkdir -p /work/download-x86
run dnf -y --disablerepo='*' --enablerepo=sow-relative-x86 download \
  --destdir=/work/download-x86 sow-yum-relative-native sow-yum-relative-neutral
assert_file "/work/download-x86/$native_name"
assert_file "/work/download-x86/$neutral_name"
run sha256sum "/work/download-x86/$native_name" "/work/download-x86/$neutral_name"
run dnf -y --disablerepo='*' --enablerepo=sow-relative-x86 install \
  sow-yum-relative-native sow-yum-relative-neutral
run rpm -q sow-yum-relative-native sow-yum-relative-neutral
run test "$(</usr/share/sow-yum-relative/native.txt)" = 'native x86_64 payload'
run test "$(</usr/share/sow-yum-relative/neutral.txt)" = 'neutral noarch payload'
run dnf -y remove sow-yum-relative-native sow-yum-relative-neutral

printf '\n=== aarch64 client view: makecache, locate, download, install noarch ===\n'
run dnf -q clean all
run dnf -v --forcearch=aarch64 --disablerepo='*' --enablerepo=sow-relative-arm makecache
arm_query=$(dnf -q --forcearch=aarch64 --disablerepo='*' --enablerepo=sow-relative-arm repoquery \
  --qf '%{name} %{arch} %{location}' sow-yum-relative-neutral)
printf '%s\n' "$arm_query"
grep -Fq 'sow-yum-relative-neutral noarch ' <<<"$arm_query"
native_arm_query=$(dnf -q --forcearch=aarch64 --disablerepo='*' --enablerepo=sow-relative-arm repoquery \
  --qf '%{name}' sow-yum-relative-native)
[[ -z "$native_arm_query" ]] || {
  printf 'x86_64 native package leaked into aarch64 view: %s\n' "$native_arm_query" >&2
  exit 1
}
run mkdir -p /work/download-arm
run dnf -y --forcearch=aarch64 --disablerepo='*' --enablerepo=sow-relative-arm download \
  --destdir=/work/download-arm sow-yum-relative-neutral
assert_file "/work/download-arm/$neutral_name"
run sha256sum "/work/download-arm/$neutral_name"
run dnf -y --forcearch=aarch64 --disablerepo='*' --enablerepo=sow-relative-arm install \
  sow-yum-relative-neutral
run rpm -q sow-yum-relative-neutral
run test "$(</usr/share/sow-yum-relative/neutral.txt)" = 'neutral noarch payload'
run dnf -y remove sow-yum-relative-neutral

printf '\n=== reposync from both views ===\n'
run mkdir -p /work/reposync-x86 /work/reposync-arm
set +e
run dnf -q reposync --repoid=sow-relative-x86 --download-path=/work/reposync-x86 \
  --arch=x86_64 --arch=noarch
x86_reposync_status=$?
run dnf -q --forcearch=aarch64 reposync --repoid=sow-relative-arm \
  --download-path=/work/reposync-arm --arch=aarch64 --arch=noarch
arm_reposync_status=$?
set -e
printf 'reposync exit status: x86_64=%d aarch64=%d\n' \
  "$x86_reposync_status" "$arm_reposync_status"
if (( x86_reposync_status != 0 && arm_reposync_status != 0 )); then
  printf '\nEXPECTED REJECTION: DNF consumes ../../../pool/... but reposync rejects both views.\n'
  original_rejection_status=0
else
  printf '\nUNEXPECTED RESULT: original reposync must reject both parent-traversing views.\n' >&2
  original_rejection_status=1
fi
if (( x86_reposync_status == 0 && arm_reposync_status == 0 )); then
  run find /work/reposync-x86 /work/reposync-arm -type f -name '*.rpm' -print -exec sha256sum '{}' ';'

  x86_synced_native=$(find /work/reposync-x86 -type f -name "$native_name" -print -quit)
  x86_synced_neutral=$(find /work/reposync-x86 -type f -name "$neutral_name" -print -quit)
  arm_synced_neutral=$(find /work/reposync-arm -type f -name "$neutral_name" -print -quit)
  assert_file "$x86_synced_native"
  assert_file "$x86_synced_neutral"
  assert_file "$arm_synced_neutral"
  if find /work/reposync-arm -type f -name "$native_name" -print -quit | grep -q .; then
    printf 'reposync copied x86_64 native package from aarch64 view\n' >&2
    exit 1
  fi
  run cmp "$POOL_ROOT/$native_name" "$x86_synced_native"
  run cmp "$POOL_ROOT/$neutral_name" "$x86_synced_neutral"
  run cmp "$POOL_ROOT/$neutral_name" "$arm_synced_neutral"
fi

run bash /fixture/redesign-in-container.sh "$POOL_ROOT" "$native_name" "$neutral_name"

if (( original_rejection_status != 0 )); then
  printf '\nPOC HARNESS FAIL: original rejection contract was not observed.\n' >&2
  exit 1
fi
printf '\nPOC HARNESS PASS: parent-traversal rejected; C2 shared-pool hardlink projection is adoptable.\n'
