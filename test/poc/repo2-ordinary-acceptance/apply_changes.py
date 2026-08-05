#!/usr/bin/env python3
"""Apply a SOW `changes` JSON envelope and verify the exact public tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


PHASE_RANK = {"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}


def digest(path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            hasher.update(chunk)
    return size, hasher.hexdigest()


def safe_relative(value: str) -> Path:
    posix = PurePosixPath(value)
    if not value or posix.is_absolute() or ".." in posix.parts or str(posix) != value:
        raise AssertionError(f"unsafe changes path: {value!r}")
    return Path(*posix.parts)


def public_files(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for top in ("pool", "dists"):
        base = root / top
        if not base.is_dir():
            raise AssertionError(f"missing public directory: {base}")
        for current, directories, files in os.walk(base, followlinks=False):
            current_path = Path(current)
            for name in directories:
                mode = (current_path / name).lstat().st_mode
                if not stat.S_ISDIR(mode):
                    raise AssertionError(f"non-directory public node: {current_path / name}")
            for name in files:
                path = current_path / name
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise AssertionError(f"non-regular public file: {path}")
                result[path.relative_to(root).as_posix()] = digest(path)
    return dict(sorted(result.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--changes", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    target = args.target.resolve(strict=True)
    envelope = json.loads(args.changes.read_text(encoding="utf-8"))
    if envelope.get("schema") != "sow.cli/v1" or not envelope.get("ok"):
        raise AssertionError("changes file is not a successful sow.cli/v1 envelope")
    result = envelope["result"]
    changes = result["changes"]
    previous_rank = -1
    phases: list[str] = []

    for change in changes:
        phase = change["phase"]
        rank = PHASE_RANK.get(phase)
        if rank is None or rank < previous_rank:
            raise AssertionError("changes are not in executable phase order")
        previous_rank = rank
        phases.append(phase)
        relative = safe_relative(change["path"])
        source_file = source / relative
        target_file = target / relative
        operation = change["op"]
        if operation == "delete":
            target_file.unlink()
            continue
        if operation not in ("add", "update"):
            raise AssertionError(f"unsupported operation: {operation!r}")
        if not stat.S_ISREG(source_file.lstat().st_mode):
            raise AssertionError(f"source is not a regular file: {relative.as_posix()}")
        source_size, source_sha = digest(source_file)
        if source_size != change["size"] or source_sha != change["sha256"]:
            raise AssertionError(f"source identity mismatch: {relative.as_posix()}")
        target_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        temporary = target_file.with_name(target_file.name + ".handoff-tmp")
        with source_file.open("rb") as incoming, temporary.open("xb") as outgoing:
            while chunk := incoming.read(1024 * 1024):
                outgoing.write(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        temporary.chmod(0o644)
        temporary.replace(target_file)

    expected = public_files(source)
    observed = public_files(target)
    if observed != expected:
        missing = sorted(expected.keys() - observed.keys())
        extra = sorted(observed.keys() - expected.keys())
        changed = sorted(
            path for path in expected.keys() & observed.keys() if expected[path] != observed[path]
        )
        raise AssertionError(
            f"handoff tree differs: missing={missing[:5]} extra={extra[:5]} changed={changed[:5]}"
        )
    print(
        json.dumps(
            {
                "base": result["base"],
                "generation": result["generation"],
                "changes": len(changes),
                "files": len(expected),
                "phases": sorted(set(phases), key=PHASE_RANK.__getitem__),
                "tree_sha256": hashlib.sha256(
                    "".join(
                        f"{path}\0{size}\0{sha}\n"
                        for path, (size, sha) in expected.items()
                    ).encode()
                ).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
