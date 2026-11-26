"""Verify installed Astranyx application files against a wheel."""

import argparse
import hashlib
import stat
import sys
import sysconfig
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unsafe_link(path):
    if path.is_symlink():
        return True

    attributes = getattr(path.lstat(), "st_file_attributes", 0)

    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_point and attributes & reparse_point)


def verify_runtime(wheel, site):
    site = site.resolve(strict=True)
    root = site / "astranyx"

    require(root.is_dir(), "Application directory missing")
    require(not unsafe_link(root), "Unsafe application directory")

    expected = {}
    casefolded = set()

    with ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue

            name = entry.filename

            if not name.startswith("astranyx/"):
                continue

            relative = PurePosixPath(name)

            require(
                not relative.is_absolute()
                and ".." not in relative.parts
                and "\\" not in name
                and ":" not in name
                and relative.as_posix() == name,
                f"Unsafe archive path: {name}",
            )

            require(
                not stat.S_ISLNK(entry.external_attr >> 16),
                f"Archive symlink: {name}",
            )

            require(
                name.casefold() not in casefolded,
                f"Duplicate archive entry: {name}",
            )

            casefolded.add(name.casefold())

            with archive.open(entry) as stream:
                expected[name] = hashlib.file_digest(stream, "sha256").hexdigest()

    require(bool(expected), "Empty application inventory")

    observed = set()

    for path in root.rglob("*"):
        require(
            not unsafe_link(path),
            f"Unsafe installed entry: {path}",
        )

        require(
            path.resolve().is_relative_to(root),
            f"Installed path escapes application root: {path}",
        )

        if path.is_dir():
            continue

        require(path.is_file(), f"Unexpected file type: {path}")

        name = path.relative_to(site).as_posix()

        if "__pycache__" in path.parts and path.suffix == ".pyc":
            continue

        require(name in expected, f"Unexpected installed file: {name}")

        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()

        require(
            digest == expected[name],
            f"Installed content mismatch: {name}",
        )

        observed.add(name)

    missing = set(expected) - observed

    require(
        not missing,
        f"Missing application files: {sorted(missing)}",
    )

    return len(observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    args = parser.parse_args()

    try:
        site = Path(sysconfig.get_path("purelib"))
        count = verify_runtime(args.wheel, site)
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Platform: {sys.platform}")
    print(f"Verified application files: {count}")
    print("Runtime application integrity: PASSED")


if __name__ == "__main__":
    main()
