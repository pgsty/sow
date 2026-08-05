#!/usr/bin/env python3
"""Compare SOW Plain metadata with createrepo_c/dpkg-scanpackages output.

The input directory must contain:

  el9/sow, el9/traditional, u24/sow, u24/traditional

This comparison intentionally treats MD5sum and SHA1 as traditional-tool
extras. SOW V2's integrity contract is SHA-256 based.
"""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


COMMON = "{http://linux.duke.edu/metadata/common}"
RPM = "{http://linux.duke.edu/metadata/rpm}"
FILELISTS = "{http://linux.duke.edu/metadata/filelists}"
OTHER = "{http://linux.duke.edu/metadata/other}"
REPO = "{http://linux.duke.edu/metadata/repo}"


def xml_tree(repo: Path, kind: str) -> ET.Element:
    repomd = ET.parse(repo / "repodata" / "repomd.xml").getroot()
    locations = [
        data.find(REPO + "location").attrib["href"]
        for data in repomd.findall(REPO + "data")
        if data.attrib.get("type") == kind and data.find(REPO + "location") is not None
    ]
    if len(locations) != 1:
        raise AssertionError(
            f"expected repomd.xml to reference one {kind} document in {repo}, "
            f"got {locations}"
        )
    with gzip.open(repo / locations[0], "rb") as stream:
        return ET.parse(stream).getroot()


def primary_key(package: ET.Element) -> tuple[str, ...]:
    version = package.find(COMMON + "version")
    assert version is not None
    return (
        package.findtext(COMMON + "name", ""),
        version.attrib.get("epoch", "0"),
        version.attrib["ver"],
        version.attrib["rel"],
        package.findtext(COMMON + "arch", ""),
    )


def dependency_entries(
    package: ET.Element, group: str, include_pre: bool = True
) -> set[tuple[str, ...]]:
    entries: set[tuple[str, ...]] = set()
    for entry in package.findall(f"{COMMON}format/{RPM}{group}/{RPM}entry"):
        value = (
            entry.attrib.get("name", ""),
            entry.attrib.get("flags", ""),
            entry.attrib.get("epoch", ""),
            entry.attrib.get("ver", ""),
            entry.attrib.get("rel", ""),
        )
        if include_pre:
            value += (entry.attrib.get("pre", ""),)
        entries.add(value)
    return entries


def normalized_primary(package: ET.Element) -> tuple[tuple[object, ...], ...]:
    """Return the complete primary package semantics in wire order.

    File mtime is intentionally deterministic in SOW and host-derived in
    createrepo_c, so it is not a package fact. Dependency entries are compared
    separately as semantic sets by dependency_entries(); this also ignores
    duplicate entries emitted by some createrepo_c/rpm combinations.
    """

    rows: list[tuple[object, ...]] = []

    def walk(element: ET.Element, prefix: str = "") -> None:
        for child in element:
            name = child.tag.rsplit("}", 1)[-1]
            current = f"{prefix}/{name}"
            if name == "entry":
                continue
            attributes = dict(child.attrib)
            if name == "time":
                attributes.pop("file", None)
            rows.append(
                (current, tuple(sorted(attributes.items())), child.text or "")
            )
            walk(child, current)

    walk(package)
    return tuple(rows)


def parse_packages(path: Path) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    paragraph: dict[str, str] = {}
    last: str | None = None
    for line in path.read_text().splitlines():
        if not line:
            if paragraph:
                paragraphs.append(paragraph)
            paragraph, last = {}, None
        elif line[0] in " \t":
            assert last is not None
            paragraph[last] += "\n" + line
        else:
            name, value = line.split(":", 1)
            last = name.lower()
            paragraph[last] = value.lstrip()
    if paragraph:
        paragraphs.append(paragraph)
    return paragraphs


def compare_rpm(
    root: Path,
    sow_repo: Path | None = None,
    traditional_repo: Path | None = None,
    exact_locations: bool = False,
) -> dict[str, object]:
    sow_repo = sow_repo or root / "el9" / "sow"
    traditional_repo = traditional_repo or root / "el9" / "traditional"
    sow = {primary_key(p): p for p in xml_tree(sow_repo, "primary")}
    traditional = {
        primary_key(p): p for p in xml_tree(traditional_repo, "primary")
    }
    result: dict[str, object] = {
        "sow_packages": len(sow),
        "traditional_packages": len(traditional),
        "only_sow": len(sow.keys() - traditional.keys()),
        "only_traditional": len(traditional.keys() - sow.keys()),
    }

    dependency_differences: dict[str, object] = {}
    for group in (
        "provides",
        "requires",
        "conflicts",
        "obsoletes",
        "suggests",
        "enhances",
        "recommends",
        "supplements",
    ):
        missing = extra = missing_without_pre = extra_without_pre = 0
        sow_count = traditional_count = 0
        for key in sow.keys() & traditional.keys():
            sow_entries = dependency_entries(sow[key], group)
            traditional_entries = dependency_entries(traditional[key], group)
            sow_count += len(sow_entries)
            traditional_count += len(traditional_entries)
            missing += len(traditional_entries - sow_entries)
            extra += len(sow_entries - traditional_entries)
            sow_without_pre = dependency_entries(sow[key], group, False)
            traditional_without_pre = dependency_entries(
                traditional[key], group, False
            )
            missing_without_pre += len(traditional_without_pre - sow_without_pre)
            extra_without_pre += len(sow_without_pre - traditional_without_pre)
        dependency_differences[group] = {
            "sow_entries": sow_count,
            "traditional_entries": traditional_count,
            "missing_from_sow": missing,
            "extra_in_sow": extra,
            "missing_from_sow_without_pre": missing_without_pre,
            "extra_in_sow_without_pre": extra_without_pre,
        }
    result["dependencies"] = dependency_differences

    location_mismatches = checksum_mismatches = 0
    for key in sow.keys() & traditional.keys():
        sow_location = sow[key].find(COMMON + "location")
        traditional_location = traditional[key].find(COMMON + "location")
        assert sow_location is not None and traditional_location is not None
        sow_href = sow_location.attrib["href"]
        traditional_href = traditional_location.attrib["href"]
        if exact_locations:
            same_location = sow_href == traditional_href
        else:
            same_location = Path(sow_href).name == Path(traditional_href).name
        if not same_location:
            location_mismatches += 1
        if sow[key].findtext(COMMON + "checksum") != traditional[key].findtext(
            COMMON + "checksum"
        ):
            checksum_mismatches += 1
    result[
        "location_mismatches" if exact_locations else "location_basename_mismatches"
    ] = location_mismatches
    result["checksum_mismatches"] = checksum_mismatches
    result["primary_semantics"] = {
        "packages_different": sum(
            normalized_primary(sow[key]) != normalized_primary(traditional[key])
            for key in sow.keys() & traditional.keys()
        ),
        "ignored_host_or_version_fields": ["time.file", "entry.pre"],
    }
    result["primary_file_entries"] = {
        "sow": sum(
            len(package.findall(f"{COMMON}format/{COMMON}file"))
            for package in sow.values()
        ),
        "traditional": sum(
            len(package.findall(f"{COMMON}format/{COMMON}file"))
            for package in traditional.values()
        ),
    }

    def filelist_key(package: ET.Element) -> tuple[str, ...]:
        version = package.find(FILELISTS + "version")
        assert version is not None
        return (
            package.attrib["name"],
            version.attrib.get("epoch", "0"),
            version.attrib["ver"],
            version.attrib["rel"],
            package.attrib["arch"],
        )

    sow_files = {filelist_key(p): p for p in xml_tree(sow_repo, "filelists")}
    traditional_files = {
        filelist_key(p): p for p in xml_tree(traditional_repo, "filelists")
    }
    packages_different = typed_different = 0
    kinds: Counter[tuple[str | None, str | None]] = Counter()
    for key in sow_files.keys() & traditional_files.keys():
        sow_map = {
            entry.text: entry.attrib.get("type", "file")
            for entry in sow_files[key].findall(FILELISTS + "file")
        }
        traditional_map = {
            entry.text: entry.attrib.get("type", "file")
            for entry in traditional_files[key].findall(FILELISTS + "file")
        }
        changes = [
            (sow_map.get(path), traditional_map.get(path))
            for path in sow_map.keys() | traditional_map.keys()
            if sow_map.get(path) != traditional_map.get(path)
        ]
        if changes:
            packages_different += 1
            typed_different += len(changes)
            kinds.update(changes)
    result["filelists"] = {
        "packages_different": packages_different,
        "entries_different": typed_different,
        "difference_kinds": {
            f"{left!s}->{right!s}": count
            for (left, right), count in sorted(kinds.items(), key=str)
        },
    }

    def other_key(package: ET.Element) -> tuple[str, ...]:
        version = package.find(OTHER + "version")
        assert version is not None
        return (
            package.attrib["name"],
            version.attrib.get("epoch", "0"),
            version.attrib["ver"],
            version.attrib["rel"],
            package.attrib["arch"],
        )

    def changelogs(package: ET.Element) -> list[tuple[str, str, str]]:
        return [
            (
                entry.attrib.get("author", ""),
                entry.attrib.get("date", ""),
                entry.text or "",
            )
            for entry in package.findall(OTHER + "changelog")
        ]

    sow_other = {other_key(p): p for p in xml_tree(sow_repo, "other")}
    traditional_other = {
        other_key(p): p for p in xml_tree(traditional_repo, "other")
    }
    other_differences = [
        key
        for key in sow_other.keys() & traditional_other.keys()
        if sow_other[key].attrib.get("pkgid")
        != traditional_other[key].attrib.get("pkgid")
        or changelogs(sow_other[key]) != changelogs(traditional_other[key])
    ]
    result["other"] = {
        "sow_packages": len(sow_other),
        "traditional_packages": len(traditional_other),
        "only_sow": len(sow_other.keys() - traditional_other.keys()),
        "only_traditional": len(traditional_other.keys() - sow_other.keys()),
        "packages_different": len(other_differences),
        "entries_sow": sum(len(changelogs(p)) for p in sow_other.values()),
        "entries_traditional": sum(
            len(changelogs(p)) for p in traditional_other.values()
        ),
    }
    return result


def compare_deb(
    root: Path,
    sow_packages_path: Path | None = None,
    traditional_packages_path: Path | None = None,
) -> dict[str, object]:
    sow_repo = root / "u24" / "sow"
    sow_packages_path = sow_packages_path or sow_repo / "Packages"
    traditional_packages_path = (
        traditional_packages_path or root / "u24" / "traditional" / "Packages"
    )
    sow_packages = parse_packages(sow_packages_path)
    traditional_packages = parse_packages(traditional_packages_path)
    key = lambda p: (p.get("package"), p.get("version"), p.get("architecture"))
    sow = {key(p): p for p in sow_packages}
    traditional = {key(p): p for p in traditional_packages}
    fields = (
        "filename",
        "size",
        "sha256",
        "package",
        "version",
        "architecture",
        "depends",
        "pre-depends",
        "recommends",
        "suggests",
        "enhances",
        "provides",
        "conflicts",
        "breaks",
        "replaces",
        "multi-arch",
        "essential",
        "section",
        "priority",
        "description",
    )
    differences = {
        field: sum(
            sow[item].get(field) != traditional[item].get(field)
            for item in sow.keys() & traditional.keys()
        )
        for field in fields
    }
    percent_names = (
        sorted(path.name for path in sow_repo.glob("*%3[aA]*.deb"))
        if sow_packages_path == sow_repo / "Packages"
        else []
    )
    indexed_percent_names = sorted(
        Path(package["filename"]).name
        for package in sow_packages
        if "%3a" in package.get("filename", "").lower()
    )
    return {
        "sow_packages": len(sow),
        "traditional_packages": len(traditional),
        "only_sow": len(sow.keys() - traditional.keys()),
        "only_traditional": len(traditional.keys() - sow.keys()),
        "field_differences": differences,
        "percent3a_files": len(percent_names),
        "percent3a_indexed": len(indexed_percent_names),
        "percent3a_missing_from_index": sorted(
            set(percent_names) - set(indexed_percent_names)
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--rpm-sow", type=Path)
    parser.add_argument("--rpm-traditional", type=Path)
    parser.add_argument("--rpm-exact-locations", action="store_true")
    parser.add_argument("--deb-sow-packages", type=Path)
    parser.add_argument("--deb-traditional-packages", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    report = {
        "root": str(root),
        "rpm": compare_rpm(
            root,
            args.rpm_sow,
            args.rpm_traditional,
            args.rpm_exact_locations,
        ),
        "deb": compare_deb(
            root, args.deb_sow_packages, args.deb_traditional_packages
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    rpm = report["rpm"]
    deb = report["deb"]
    assert isinstance(rpm, dict) and isinstance(deb, dict)
    failures = []
    for family, data in (("rpm", rpm), ("deb", deb)):
        if data["only_sow"] or data["only_traditional"]:
            failures.append(f"{family}: package identity mismatch")
    for group, data in rpm["dependencies"].items():
        # EL9's createrepo_c 0.20.1 marks PREREQ/SCRIPT_PRE/SCRIPT_POST as
        # pre. Current upstream additionally marks PRETRANS/POSTTRANS, which
        # is the projection SOW implements. Compare requirement identity
        # separately from this versioned annotation; every other group must
        # match exactly.
        if group == "requires":
            mismatched = (
                data["missing_from_sow_without_pre"]
                or data["extra_in_sow_without_pre"]
            )
        else:
            mismatched = data["missing_from_sow"] or data["extra_in_sow"]
        if mismatched:
            failures.append(f"rpm: {group} mismatch")
    location_key = (
        "location_mismatches"
        if args.rpm_exact_locations
        else "location_basename_mismatches"
    )
    if rpm[location_key] or rpm["checksum_mismatches"]:
        failures.append("rpm: location/checksum mismatch")
    if rpm["primary_semantics"]["packages_different"]:
        failures.append("rpm: primary package semantics mismatch")
    if rpm["filelists"]["entries_different"]:
        failures.append("rpm: filelists mismatch")
    if (
        rpm["other"]["only_sow"]
        or rpm["other"]["only_traditional"]
        or rpm["other"]["packages_different"]
    ):
        failures.append("rpm: other/changelog mismatch")
    if rpm["primary_file_entries"]["sow"] != rpm["primary_file_entries"]["traditional"]:
        failures.append("rpm: primary file projection mismatch")
    for field, count in deb["field_differences"].items():
        if count:
            failures.append(f"deb: {field} mismatch")
    if deb["percent3a_files"] != deb["percent3a_indexed"]:
        failures.append("deb: literal %3a files missing from index")
    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1
    print(
        "PASS: SOW metadata matches traditional generators for compared fields.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
