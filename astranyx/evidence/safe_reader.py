"""Bounded, symlink-resistant evidence file reading on POSIX systems."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SafeReadError(ValueError):
    """Unsafe path or unsupported evidence object."""


class SizeLimitExceeded(SafeReadError):
    """Evidence exceeds the permitted size."""


def read_bounded(root: Path, relative: str, limit: int) -> bytes:
    """Read a regular evidence file without following symlinks.

    On POSIX, open each path component relative to a directory
    descriptor. Limit the number of bytes read and reject files
    that exceed the limit.

    Windows is intentionally unsupported until a secure
    platform-specific implementation is available.
    """
    if os.name != "posix":
        raise SafeReadError("secure evidence reading requires POSIX")

    if not isinstance(relative, str) or not relative:
        raise SafeReadError("invalid evidence path")

    if (
        relative.startswith("/")
        or "\\" in relative
        or any(component in {"", ".", ".."} for component in relative.split("/"))
    ):
        raise SafeReadError("unsafe evidence path")

    path = Path(relative)

    if not path.parts or path.is_absolute():
        raise SafeReadError("unsafe evidence path")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise SafeReadError("invalid size limit")

    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )

    directory_fd = os.open(root, directory_flags)

    try:
        for component in path.parts[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )

            os.close(directory_fd)
            directory_fd = next_fd

        file_fd = os.open(
            path.parts[-1],
            file_flags,
            dir_fd=directory_fd,
        )

        try:
            info = os.fstat(file_fd)

            if not stat.S_ISREG(info.st_mode):
                raise SafeReadError("evidence object is not a regular file")

            if info.st_size > limit:
                raise SizeLimitExceeded("evidence file exceeds size limit")

            chunks = []
            remaining = limit + 1

            while remaining > 0:
                chunk = os.read(
                    file_fd,
                    min(remaining, 65536),
                )

                if not chunk:
                    break

                chunks.append(chunk)
                remaining -= len(chunk)

            data = b"".join(chunks)

            if len(data) > limit:
                raise SizeLimitExceeded("evidence file exceeds size limit")

            return data

        finally:
            os.close(file_fd)

    finally:
        os.close(directory_fd)
