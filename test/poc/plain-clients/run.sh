#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)
RPM_IMAGE=${RPM_IMAGE:-pgsty/el9:build}
DEB_IMAGE=${DEB_IMAGE:-pgsty/u24:latest}

if [[ -z "${LAB_ROOT:-}" ]]; then
  LAB_ROOT=$(mktemp -d /Users/vonng/repo/sow-v2-plain-clients.XXXXXX)
fi
LAB_ROOT=$(cd -- "$LAB_ROOT" && pwd -P)
case "$LAB_ROOT" in
  /Users/vonng/repo/sow-v2-plain-clients.*) ;;
  *)
    printf 'refusing LAB_ROOT outside the dedicated test prefix: %s\n' "$LAB_ROOT" >&2
    exit 2
    ;;
esac
if [[ "$LAB_ROOT" == /Users/vonng/pgsty/repo* ]]; then
  printf 'production repository is forbidden: %s\n' "$LAB_ROOT" >&2
  exit 2
fi

exec > >(tee "$LAB_ROOT/run.log") 2>&1
printf 'SOW P0 plain real-client PoC\n'
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
printf 'plain_source_fingerprint=%s\n' "$SOURCE_FINGERPRINT"
printf 'plain_source_manifest=%s\n' "$LAB_ROOT/sow-build-inputs.sha256"
printf 'fingerprint_script_sha256=%s\n' "$(shasum -a 256 "$PROJECT_ROOT/test/poc/source-fingerprint.sh" | awk '{print $1}')"
printf 'harness_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/run.sh" | awk '{print $1}')"

mkdir -p "$LAB_ROOT/packages/rpm" "$LAB_ROOT/packages/deb" "$LAB_ROOT/bin" "$LAB_ROOT/evidence"
mkdir -p "$LAB_ROOT/repos/rpm-only" "$LAB_ROOT/repos/deb-only" "$LAB_ROOT/repos/mixed"
chmod 0755 "$LAB_ROOT" "$LAB_ROOT/packages" "$LAB_ROOT/packages/rpm" "$LAB_ROOT/packages/deb" \
  "$LAB_ROOT/repos" "$LAB_ROOT/repos/rpm-only" "$LAB_ROOT/repos/deb-only" "$LAB_ROOT/repos/mixed"

printf '\n== build current-checkout sow binary ==\n'
SOW_BIN="$LAB_ROOT/bin/sow"
(
  cd "$PROJECT_ROOT"
  go build -trimpath -o "$SOW_BIN" ./cmd/sow
)
chmod 0755 "$SOW_BIN"
printf 'sow_binary=%s\n' "$SOW_BIN"
printf 'sow_binary_sha256=%s\n' "$(shasum -a 256 "$SOW_BIN" | awk '{print $1}')"
printf 'sow_version=%s\n' "$($SOW_BIN version)"

printf '\n== immutable client images ==\n'
docker image inspect "$RPM_IMAGE" "$DEB_IMAGE" \
  --format '{{index .RepoTags 0}} id={{.Id}} arch={{.Architecture}} os={{.Os}}'

printf '\n== build installable RPM fixtures ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT:/lab" "$RPM_IMAGE" bash -euxo pipefail -c '
    top=/tmp/rpmbuild
    mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    cat >"$top/SPECS/sow-plain-native.spec" <<"SPEC"
Name: sow-plain-native
Version: 1.0.0
Release: 1%{?dist}
Summary: SOW plain native client fixture
License: MIT
BuildArch: x86_64

%description
Installable native fixture for the SOW plain repository client proof.

%install
mkdir -p %{buildroot}/usr/share/sow-plain
printf "native rpm fixture\n" > %{buildroot}/usr/share/sow-plain/native-rpm.txt

%files
/usr/share/sow-plain/native-rpm.txt
SPEC
    cat >"$top/SPECS/sow-plain-neutral.spec" <<"SPEC"
Name: sow-plain-neutral
Version: 1.0.0
Release: 1%{?dist}
Summary: SOW plain noarch client fixture
License: MIT
BuildArch: noarch

%description
Installable noarch fixture for the SOW plain repository client proof.

%install
mkdir -p %{buildroot}/usr/share/sow-plain
printf "neutral rpm fixture\n" > %{buildroot}/usr/share/sow-plain/neutral-rpm.txt

%files
/usr/share/sow-plain/neutral-rpm.txt
SPEC
    rpmbuild --define "_topdir $top" -bb "$top/SPECS/sow-plain-native.spec"
    rpmbuild --define "_topdir $top" -bb "$top/SPECS/sow-plain-neutral.spec"
    cp "$top"/RPMS/x86_64/sow-plain-native-*.rpm /lab/packages/rpm/
    cp "$top"/RPMS/noarch/sow-plain-neutral-*.rpm /lab/packages/rpm/
    rpm -qpi /lab/packages/rpm/*.rpm
  '

printf '\n== build installable DEB fixtures ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT:/lab" "$DEB_IMAGE" bash -euxo pipefail -c '
    make_deb() {
      name=$1
      arch=$2
      payload=$3
      root="/tmp/${name}"
      mkdir -p "$root/DEBIAN" "$root/usr/share/sow-plain"
      cat >"$root/DEBIAN/control" <<CONTROL
Package: $name
Version: 1.0.0-1
Section: misc
Priority: optional
Architecture: $arch
Maintainer: SOW Test <sow@example.invalid>
Description: Installable SOW plain repository client fixture
CONTROL
      printf "%s\n" "$payload" >"$root/usr/share/sow-plain/${name}.txt"
      dpkg-deb --root-owner-group --build "$root" "/lab/packages/deb/${name}_1.0.0-1_${arch}.deb"
    }
    make_deb sow-plain-deb-native amd64 "native deb fixture"
    make_deb sow-plain-deb-neutral all "neutral deb fixture"
    for package in /lab/packages/deb/*.deb; do
      dpkg-deb --info "$package"
    done
  '

cp "$LAB_ROOT"/packages/rpm/*.rpm "$LAB_ROOT/repos/rpm-only/"
cp "$LAB_ROOT"/packages/deb/*.deb "$LAB_ROOT/repos/deb-only/"
cp "$LAB_ROOT"/packages/rpm/*.rpm "$LAB_ROOT/repos/mixed/"
cp "$LAB_ROOT"/packages/deb/*.deb "$LAB_ROOT/repos/mixed/"

printf '\n== invoke current-checkout cmd/sow binary with public JSON API ==\n'
"$SOW_BIN" create "$LAB_ROOT/repos/rpm-only" -j 2 --json | tee "$LAB_ROOT/evidence/create-rpm-only.json"
"$SOW_BIN" create "$LAB_ROOT/repos/deb-only" -j 2 --json | tee "$LAB_ROOT/evidence/create-deb-only.json"
"$SOW_BIN" create "$LAB_ROOT/repos/mixed" -j 2 --json | tee "$LAB_ROOT/evidence/create-mixed.json"
python3 - "$LAB_ROOT" <<'PY'
import json
import pathlib
import sys

lab = pathlib.Path(sys.argv[1])
expected = {"rpm-only": (2, 0), "deb-only": (0, 2), "mixed": (2, 2)}
for name, counts in expected.items():
    envelope = json.loads((lab / "evidence" / f"create-{name}.json").read_text())
    assert envelope["schema"] == "sow.cli/v1", envelope
    assert envelope["command"] == "create" and envelope["ok"] is True, envelope
    assert envelope["repository"] is None and envelope["operation"] is None, envelope
    assert envelope["errors"] == [], envelope
    result = envelope["result"]
    assert (result["rpm"], result["deb"]) == counts, (name, result)
    assert result["marker"] is False and result["removed"] in (None, []), result
    print(f"{name}: json rpm={result['rpm']} deb={result['deb']} marker={result['marker']}")
PY
if find "$LAB_ROOT/repos" \( -name repo_complete -o -name '*.db' -o -name '*.sqlite' \) -print -quit | grep -q .; then
  printf 'unexpected marker or database in default Plain output\n' >&2
  exit 1
fi
if find "$LAB_ROOT/repos" -iname '*modulemd*' -print -quit | grep -q .; then
  printf 'unexpected modulemd output in Plain repository\n' >&2
  exit 1
fi

printf '\n== inspect flat metadata locations ==\n'
python3 - "$LAB_ROOT" <<'PY'
import gzip
import pathlib
import sys
import xml.etree.ElementTree as ET

lab = pathlib.Path(sys.argv[1])
for repo_name in ("rpm-only", "mixed"):
    repo = lab / "repos" / repo_name
    repomd = ET.parse(repo / "repodata" / "repomd.xml")
    ns = {"r": "http://linux.duke.edu/metadata/repo"}
    primary_href = None
    for data in repomd.findall("r:data", ns):
        if data.attrib.get("type") == "primary":
            primary_href = data.find("r:location", ns).attrib["href"]
            break
    assert primary_href and primary_href.startswith("repodata/")
    with gzip.open(repo / primary_href, "rb") as stream:
        primary = ET.parse(stream)
    locations = sorted(node.attrib["href"] for node in primary.iter("{http://linux.duke.edu/metadata/common}location"))
    expected = sorted(path.name for path in repo.glob("*.rpm"))
    assert locations == expected, (repo_name, locations, expected)
    print(f"{repo_name}: rpm locations={locations}")

for repo_name in ("deb-only", "mixed"):
    repo = lab / "repos" / repo_name
    text = (repo / "Packages").read_text()
    filenames = sorted(line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("Filename: "))
    expected = sorted("./" + path.name for path in repo.glob("*.deb"))
    assert filenames == expected, (repo_name, filenames, expected)
    with gzip.open(repo / "Packages.gz", "rt") as stream:
        assert stream.read() == text
    print(f"{repo_name}: deb filenames={filenames}")
PY

printf '\n== DNF and YUM consume RPM-only flat repository ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/repos/rpm-only:/repo:ro" "$RPM_IMAGE" bash -euxo pipefail -c '
    dnf --version
    yum --version
    cat >/etc/yum.repos.d/sow-plain.repo <<"REPO"
[sow-plain]
name=SOW Plain fixture
baseurl=file:///repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
REPO
    dnf -y clean all
    dnf -y --disablerepo="*" --enablerepo=sow-plain makecache
    yum -y --disablerepo="*" --enablerepo=sow-plain makecache
    dnf -q --disablerepo="*" --enablerepo=sow-plain repoquery --location sow-plain-native sow-plain-neutral
    mkdir -p /tmp/downloads
    dnf -y --disablerepo="*" --enablerepo=sow-plain install --downloadonly --downloaddir=/tmp/downloads sow-plain-native sow-plain-neutral
    test "$(find /tmp/downloads -maxdepth 1 -name "*.rpm" | wc -l)" -eq 2
    dnf -y --disablerepo="*" --enablerepo=sow-plain install sow-plain-native sow-plain-neutral
    rpm -q sow-plain-native sow-plain-neutral
    test -f /usr/share/sow-plain/native-rpm.txt
    test -f /usr/share/sow-plain/neutral-rpm.txt
  '

printf '\n== DNF consumes RPM side of mixed flat repository ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/repos/mixed:/repo:ro" "$RPM_IMAGE" bash -euxo pipefail -c '
    cat >/etc/yum.repos.d/sow-plain.repo <<"REPO"
[sow-plain]
name=SOW Plain mixed fixture
baseurl=file:///repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
    dnf -y --disablerepo="*" --enablerepo=sow-plain makecache
    dnf -q --disablerepo="*" --enablerepo=sow-plain repoquery sow-plain-native sow-plain-neutral
  '

printf '\n== APT consumes DEB-only flat repository ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/repos/deb-only:/repo:ro" "$DEB_IMAGE" bash -euxo pipefail -c '
    apt-get --version
    printf "deb [trusted=yes] file:/repo ./\n" >/etc/apt/sources.list.d/sow-plain.list
    apt-get -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" update
    apt-cache -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" policy sow-plain-deb-native sow-plain-deb-neutral
    cd /tmp
    apt-get -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" download sow-plain-deb-native sow-plain-deb-neutral
    test "$(find /tmp -maxdepth 1 -name "sow-plain-deb-*.deb" | wc -l)" -eq 2
    apt-get -y -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" --download-only install sow-plain-deb-native sow-plain-deb-neutral
    apt-get -y -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" install sow-plain-deb-native sow-plain-deb-neutral
    dpkg-query -W sow-plain-deb-native sow-plain-deb-neutral
    test -f /usr/share/sow-plain/sow-plain-deb-native.txt
    test -f /usr/share/sow-plain/sow-plain-deb-neutral.txt
  '

printf '\n== APT consumes DEB side of mixed flat repository ==\n'
docker run --rm --pull never --platform linux/amd64 \
  -v "$LAB_ROOT/repos/mixed:/repo:ro" "$DEB_IMAGE" bash -euxo pipefail -c '
    printf "deb [trusted=yes] file:/repo ./\n" >/etc/apt/sources.list.d/sow-plain.list
    apt-get -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" update
    apt-cache -o Dir::Etc::sourcelist="sources.list.d/sow-plain.list" -o Dir::Etc::sourceparts="-" show sow-plain-deb-native sow-plain-deb-neutral >/tmp/packages.txt
    grep -q "Package: sow-plain-deb-native" /tmp/packages.txt
    grep -q "Package: sow-plain-deb-neutral" /tmp/packages.txt
  '

printf '\nPASS: P0 plain RPM-only, DEB-only, and mixed repositories were consumed by real Linux clients.\n'
printf 'This is local source/client evidence only; nothing was published.\n'
printf 'artifacts=%s\n' "$LAB_ROOT"
printf 'utc_finished=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
