#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE_POOL=${1:?source pool path is required}
readonly NATIVE_NAME=${2:?native RPM filename is required}
readonly NEUTRAL_NAME=${3:?noarch RPM filename is required}
readonly MATRIX_ROOT=/work/redesign
matrix_failed=0

run() {
  printf '\n+ '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

assert_file() {
  [[ -f "$1" ]] || {
    printf 'missing expected file: %s\n' "$1" >&2
    return 1
  }
}

primary_file() {
  find "$1/repodata" -maxdepth 1 -type f -name '*-primary.xml.gz' -print -quit
}

show_locations() {
  local primary
  primary=$(primary_file "$1")
  gzip -dc "$primary" | sed -n 's/.*\(<location[^>]*>\).*/\1/p'
}

write_repo() {
  local repoid=$1
  local baseurl=$2
  cat >> /etc/yum.repos.d/sow-relative-redesign.repo <<EOF
[$repoid]
name=$repoid
baseurl=file://$baseurl
enabled=0
gpgcheck=0
metadata_expire=0

EOF
}

render_from_root() {
  local repo=$1
  local view=$2
  local pkglist=$3
  shift 3
  run createrepo_c --quiet --general-compress-type=gz \
    --pkglist "$pkglist" "$@" --outputdir "$view" "$repo"
}

prepare_pool() {
  local repo=$1
  run mkdir -p "$repo/pool/s/sow-yum-relative"
  run cp "$SOURCE_POOL/$NATIVE_NAME" "$SOURCE_POOL/$NEUTRAL_NAME" \
    "$repo/pool/s/sow-yum-relative/"
}

write_lists() {
  local prefix=$1
  printf 'pool/s/sow-yum-relative/%s\n' "$NATIVE_NAME" > "$prefix-x86.pkglist"
  printf 'pool/s/sow-yum-relative/%s\n' "$NEUTRAL_NAME" >> "$prefix-x86.pkglist"
  printf 'pool/s/sow-yum-relative/%s\n' "$NEUTRAL_NAME" > "$prefix-arm.pkglist"
}

build_a_xml_base() {
  local repo="$MATRIX_ROOT/a-xml-base/repo"
  local x86="$repo/dists/el9/x86_64"
  local arm="$repo/dists/el9/aarch64"
  prepare_pool "$repo"
  run mkdir -p "$x86" "$arm"
  write_lists /work/a
  render_from_root "$repo" "$x86" /work/a-x86.pkglist --baseurl ../../../
  render_from_root "$repo" "$arm" /work/a-arm.pkglist --baseurl ../../../
  printf '\nA x86_64 primary location elements:\n'
  show_locations "$x86"
  printf 'A aarch64 primary location elements:\n'
  show_locations "$arm"
  write_repo redesign-a-x86 "$x86"
  write_repo redesign-a-arm "$arm"
  run cp -a "$repo" "$MATRIX_ROOT/a-xml-base/copied-repo"
  printf 'LAYOUT_FACT candidate=A shared_pool=yes regular_tree=yes metadata_parent_escape=yes symlink=no\n'
}

build_b_symlink() {
  local repo="$MATRIX_ROOT/b-symlink/repo"
  local x86="$repo/dists/el9/x86_64"
  local arm="$repo/dists/el9/aarch64"
  prepare_pool "$repo"
  run mkdir -p "$x86" "$arm"
  run ln -s ../../../pool "$x86/pool"
  run ln -s ../../../pool "$arm/pool"
  write_lists /work/b
  render_from_root "$repo" "$x86" /work/b-x86.pkglist
  render_from_root "$repo" "$arm" /work/b-arm.pkglist
  printf '\nB x86_64 primary location elements:\n'
  show_locations "$x86"
  printf 'B aarch64 primary location elements:\n'
  show_locations "$arm"
  run readlink "$x86/pool"
  run readlink "$arm/pool"
  write_repo redesign-b-x86 "$x86"
  write_repo redesign-b-arm "$arm"
  run cp -a "$repo" "$MATRIX_ROOT/b-symlink/copied-repo"
  run test -f "$MATRIX_ROOT/b-symlink/copied-repo/dists/el9/x86_64/pool/s/sow-yum-relative/$NATIVE_NAME"
  printf 'LAYOUT_FACT candidate=B shared_pool=yes posix_copy_with_symlinks=yes controlled_symlink=yes\n'
}

build_c_hardlink() {
  local repo="$MATRIX_ROOT/c-hardlink/repo"
  local x86="$repo/dists/el9/x86_64"
  local arm="$repo/dists/el9/aarch64"
  prepare_pool "$repo"
  run mkdir -p "$x86/Packages" "$arm/Packages"
  run ln "$repo/pool/s/sow-yum-relative/$NATIVE_NAME" "$x86/Packages/$NATIVE_NAME"
  run ln "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" "$x86/Packages/$NEUTRAL_NAME"
  run ln "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" "$arm/Packages/$NEUTRAL_NAME"
  printf 'Packages/%s\n' "$NATIVE_NAME" > /work/c-x86.pkglist
  printf 'Packages/%s\n' "$NEUTRAL_NAME" >> /work/c-x86.pkglist
  printf 'Packages/%s\n' "$NEUTRAL_NAME" > /work/c-arm.pkglist
  render_from_root "$x86" "$x86" /work/c-x86.pkglist
  render_from_root "$arm" "$arm" /work/c-arm.pkglist
  printf '\nC x86_64 primary location elements:\n'
  show_locations "$x86"
  printf 'C aarch64 primary location elements:\n'
  show_locations "$arm"
  run stat -c '%d:%i links=%h %n' \
    "$repo/pool/s/sow-yum-relative/$NATIVE_NAME" \
    "$x86/Packages/$NATIVE_NAME" \
    "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$x86/Packages/$NEUTRAL_NAME" \
    "$arm/Packages/$NEUTRAL_NAME"
  write_repo redesign-c-x86 "$x86"
  write_repo redesign-c-arm "$arm"
  run cp -a "$repo" "$MATRIX_ROOT/c-hardlink/copied-repo"
  run test -f "$MATRIX_ROOT/c-hardlink/copied-repo/dists/el9/x86_64/Packages/$NATIVE_NAME"
  run test -f "$MATRIX_ROOT/c-hardlink/copied-repo/dists/el9/aarch64/Packages/$NEUTRAL_NAME"
  printf 'LAYOUT_FACT candidate=C shared_inode=yes regular_tree=yes symlink=no metadata_parent_escape=no\n'
}

build_c2_view_pool_hardlink() {
  local repo="$MATRIX_ROOT/c2-view-pool-hardlink/repo"
  local x86="$repo/dists/el9/x86_64"
  local arm="$repo/dists/el9/aarch64"
  local copy="$MATRIX_ROOT/c2-view-pool-hardlink/copied-repo"
  local unlink_test="$MATRIX_ROOT/c2-view-pool-hardlink/unlink-test-repo"
  prepare_pool "$repo"
  run mkdir -p \
    "$x86/pool/s/sow-yum-relative" \
    "$arm/pool/s/sow-yum-relative"

  # Hardlink failure is fatal: this candidate never falls back to copying.
  run ln "$repo/pool/s/sow-yum-relative/$NATIVE_NAME" \
    "$x86/pool/s/sow-yum-relative/$NATIVE_NAME"
  run ln "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$x86/pool/s/sow-yum-relative/$NEUTRAL_NAME"
  run ln "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$arm/pool/s/sow-yum-relative/$NEUTRAL_NAME"

  write_lists /work/c2
  render_from_root "$x86" "$x86" /work/c2-x86.pkglist
  render_from_root "$arm" "$arm" /work/c2-arm.pkglist
  printf '\nC2 x86_64 primary location elements:\n'
  show_locations "$x86"
  printf 'C2 aarch64 primary location elements:\n'
  show_locations "$arm"
  run stat -c '%d:%i links=%h %n' \
    "$repo/pool/s/sow-yum-relative/$NATIVE_NAME" \
    "$x86/pool/s/sow-yum-relative/$NATIVE_NAME" \
    "$repo/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$x86/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$arm/pool/s/sow-yum-relative/$NEUTRAL_NAME"

  write_repo redesign-c2-x86 "$x86"
  write_repo redesign-c2-arm "$arm"

  # A dist removal unlinks aliases only; the canonical root-pool object remains.
  run cp -a "$repo" "$unlink_test"
  run rm -rf "$unlink_test/dists/el9/aarch64"
  run test -f "$unlink_test/pool/s/sow-yum-relative/$NEUTRAL_NAME"
  run test -f "$unlink_test/dists/el9/x86_64/pool/s/sow-yum-relative/$NEUTRAL_NAME"
  run stat -c 'after-dist-rm %d:%i links=%h %n' \
    "$unlink_test/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$unlink_test/dists/el9/x86_64/pool/s/sow-yum-relative/$NEUTRAL_NAME"

  # Model a copier that preserves regular files but not hardlink identity.
  run cp -R --no-preserve=links "$repo" "$copy"
  run test -f "$copy/pool/s/sow-yum-relative/$NATIVE_NAME"
  run test -f "$copy/dists/el9/x86_64/pool/s/sow-yum-relative/$NATIVE_NAME"
  run test -f "$copy/dists/el9/aarch64/pool/s/sow-yum-relative/$NEUTRAL_NAME"
  local copied_root_inode copied_x86_inode copied_arm_inode
  copied_root_inode=$(stat -c '%d:%i' "$copy/pool/s/sow-yum-relative/$NEUTRAL_NAME")
  copied_x86_inode=$(stat -c '%d:%i' "$copy/dists/el9/x86_64/pool/s/sow-yum-relative/$NEUTRAL_NAME")
  copied_arm_inode=$(stat -c '%d:%i' "$copy/dists/el9/aarch64/pool/s/sow-yum-relative/$NEUTRAL_NAME")
  [[ "$copied_root_inode" != "$copied_x86_inode" ]]
  [[ "$copied_root_inode" != "$copied_arm_inode" ]]
  [[ "$copied_x86_inode" != "$copied_arm_inode" ]]
  run stat -c 'nonpreserving-copy %d:%i links=%h %n' \
    "$copy/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$copy/dists/el9/x86_64/pool/s/sow-yum-relative/$NEUTRAL_NAME" \
    "$copy/dists/el9/aarch64/pool/s/sow-yum-relative/$NEUTRAL_NAME"

  write_repo redesign-c2copy-x86 "$copy/dists/el9/x86_64"
  write_repo redesign-c2copy-arm "$copy/dists/el9/aarch64"
  printf 'LAYOUT_FACT candidate=C2 root_pool_owner=canonical view_alias=regular_hardlink href=pool/... symlink=no parent_escape=no copy_without_links=functional_pending_client_matrix\n'
}

test_view() {
  local label=$1
  local repoid=$2
  local forcearch=$3
  local expected_native=$4
  local expected_result=$5
  local download_dir="$MATRIX_ROOT/download-$label"
  local reposync_dir="$MATRIX_ROOT/reposync-$label"
  local makecache_status=0
  local query_status=0
  local download_status=0
  local install_status=0
  local reposync_status=0
  local -a arch_args=()
  local -a sync_arch=(--arch=noarch)
  local -a packages=(sow-yum-relative-neutral)
  if [[ -n "$forcearch" ]]; then
    arch_args=(--forcearch="$forcearch")
  fi
  if [[ "$expected_native" == yes ]]; then
    packages=(sow-yum-relative-native sow-yum-relative-neutral)
    sync_arch+=(--arch=x86_64)
  else
    sync_arch+=(--arch=aarch64)
  fi

  printf '\n--- client matrix: %s ---\n' "$label"
  run dnf -q clean all
  if run dnf -v "${arch_args[@]}" --disablerepo='*' --enablerepo="$repoid" makecache; then
    :
  else
    makecache_status=$?
  fi
  if run dnf -q "${arch_args[@]}" --disablerepo='*' --enablerepo="$repoid" \
    repoquery --qf '%{name} %{arch} %{location}' "${packages[@]}"; then
    :
  else
    query_status=$?
  fi
  if [[ "$expected_native" == no ]]; then
    local native_query
    native_query=$(dnf -q "${arch_args[@]}" --disablerepo='*' --enablerepo="$repoid" \
      repoquery --qf '%{name}' sow-yum-relative-native)
    [[ -z "$native_query" ]]
  fi
  run mkdir -p "$download_dir"
  if run dnf -y "${arch_args[@]}" --disablerepo='*' --enablerepo="$repoid" \
    download --destdir="$download_dir" "${packages[@]}"; then
    :
  else
    download_status=$?
  fi
  if (( download_status == 0 )); then
    assert_file "$download_dir/$NEUTRAL_NAME"
    run cmp "$SOURCE_POOL/$NEUTRAL_NAME" "$download_dir/$NEUTRAL_NAME"
    if [[ "$expected_native" == yes ]]; then
      assert_file "$download_dir/$NATIVE_NAME"
      run cmp "$SOURCE_POOL/$NATIVE_NAME" "$download_dir/$NATIVE_NAME"
    fi
  fi
  if run dnf -y "${arch_args[@]}" --disablerepo='*' --enablerepo="$repoid" \
    install "${packages[@]}"; then
    :
  else
    install_status=$?
  fi
  if (( install_status == 0 )); then
    run rpm -q "${packages[@]}"
    run test "$(</usr/share/sow-yum-relative/neutral.txt)" = 'neutral noarch payload'
    if [[ "$expected_native" == yes ]]; then
      run test "$(</usr/share/sow-yum-relative/native.txt)" = 'native x86_64 payload'
    fi
    run dnf -y remove "${packages[@]}"
  fi

  run mkdir -p "$reposync_dir"
  if run dnf -q "${arch_args[@]}" reposync --repoid="$repoid" \
    --download-path="$reposync_dir" "${sync_arch[@]}"; then
    :
  else
    reposync_status=$?
  fi
  if (( reposync_status == 0 )); then
    local synced_neutral
    synced_neutral=$(find "$reposync_dir" -type f -name "$NEUTRAL_NAME" -print -quit)
    assert_file "$synced_neutral"
    printf 'REPOSYNC_PATH candidate=%s package=noarch path=%s\n' "$label" "$synced_neutral"
    run cmp "$SOURCE_POOL/$NEUTRAL_NAME" "$synced_neutral"
    if [[ "$expected_native" == yes ]]; then
      local synced_native
      synced_native=$(find "$reposync_dir" -type f -name "$NATIVE_NAME" -print -quit)
      assert_file "$synced_native"
      printf 'REPOSYNC_PATH candidate=%s package=native path=%s\n' "$label" "$synced_native"
      run cmp "$SOURCE_POOL/$NATIVE_NAME" "$synced_native"
    elif find "$reposync_dir" -type f -name "$NATIVE_NAME" -print -quit | grep -q .; then
      printf 'native RPM leaked into %s reposync output\n' "$label" >&2
      reposync_status=1
    fi
  fi
  printf 'REDESIGN_RESULT candidate=%s makecache=%d query=%d download=%d install=%d reposync=%d\n' \
    "$label" "$makecache_status" "$query_status" "$download_status" \
    "$install_status" "$reposync_status"
  results+=("$label makecache=$makecache_status query=$query_status download=$download_status install=$install_status reposync=$reposync_status")
  if [[ "$expected_result" == reject ]]; then
    if (( makecache_status != 0 || query_status != 0 || download_status == 0 || install_status == 0 || reposync_status == 0 )); then
      printf 'unexpected Candidate A result for %s\n' "$label" >&2
      matrix_failed=1
    fi
  elif (( makecache_status != 0 || query_status != 0 || download_status != 0 || install_status != 0 || reposync_status != 0 )); then
    printf 'unexpected redesign failure for %s\n' "$label" >&2
    matrix_failed=1
  fi
}

printf '\n=== redesign candidates ===\n'
rm -f /etc/yum.repos.d/sow-relative-redesign.repo
build_a_xml_base
build_b_symlink
build_c_hardlink
build_c2_view_pool_hardlink

declare -a results=()
for row in \
  'a-x86 redesign-a-x86 none yes reject' \
  'a-arm redesign-a-arm aarch64 no reject' \
  'b-x86 redesign-b-x86 none yes pass' \
  'b-arm redesign-b-arm aarch64 no pass' \
  'c-x86 redesign-c-x86 none yes pass' \
  'c-arm redesign-c-arm aarch64 no pass' \
  'c2-x86 redesign-c2-x86 none yes pass' \
  'c2-arm redesign-c2-arm aarch64 no pass' \
  'c2copy-x86 redesign-c2copy-x86 none yes pass' \
  'c2copy-arm redesign-c2copy-arm aarch64 no pass'; do
  read -r label repoid forcearch expected_native expected_result <<<"$row"
  [[ "$forcearch" == none ]] && forcearch=''
  test_view "$label" "$repoid" "$forcearch" "$expected_native" "$expected_result"
done

printf '\n=== redesign result matrix ===\n'
printf '%s\n' "${results[@]}"
if (( matrix_failed != 0 )); then
  printf 'REDESIGN HARNESS FAIL: observed matrix differs from expected rejection/pass contract.\n' >&2
  exit 1
fi
printf 'REDESIGN HARNESS PASS: A rejected; B/C/C2 and non-hardlink C2 copy passed.\n'
