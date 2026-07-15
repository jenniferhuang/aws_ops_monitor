#!/usr/bin/env python3
"""Print a deterministic SHA-256 for a release directory.

The revision and hash marker files are excluded because they are generated
after the Git archive is unpacked. Symlinks and non-regular files are rejected.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import sys


EXCLUDED = frozenset({"REVISION", "TREE_SHA256"})


def tree_hash(root: Path) -> str:
    root = root.resolve(strict=True)
    digest = sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if relative.as_posix() in EXCLUDED:
            continue
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"release contains a symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"release contains a non-regular file: {relative}")
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{metadata.st_mode & 0o777:o}".encode("ascii"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} <release-directory>", file=sys.stderr)
        return os.EX_USAGE
    try:
        print(tree_hash(Path(sys.argv[1])))
    except (OSError, ValueError) as error:
        print(f"Unable to hash release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
