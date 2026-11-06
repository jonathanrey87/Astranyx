"""Windows file reads with reparse-point checks and pinned directories."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class _FileTime(ctypes.Structure):
    _fields_ = [
        ("low", wintypes.DWORD),
        ("high", wintypes.DWORD),
    ]


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("created", _FileTime),
        ("accessed", _FileTime),
        ("written", _FileTime),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


def read_regular_windows(path: Path, *, root: Path | None = None) -> bytes:
    """Read a file while holding checked directory handles open."""
    if os.name != "nt":
        raise OSError("Windows file handles are required")

    import msvcrt

    path = Path(path).absolute()
    root = Path(root).absolute() if root is not None else path.parent

    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise OSError("file is outside the trusted root") from exc

    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise OSError("invalid relative file path")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE

    get_info = kernel32.GetFileInformationByHandle
    get_info.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FileInformation),
    ]
    get_info.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    OPEN_EXISTING = 3
    FILE_READ_ATTRIBUTES = 0x00000080
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ_WRITE = 0x00000003
    FILE_SHARE_ALL = 0x00000007
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

    flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    invalid_handle = ctypes.c_void_p(-1).value

    def open_checked(target: Path, access: int, share: int) -> tuple[int, int]:
        handle = create_file(
            str(target),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        if handle == invalid_handle:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            info = _FileInformation()
            if not get_info(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            return handle, info.attributes
        except BaseException:
            close_handle(handle)
            raise

    directories = [root]
    current = root

    for component in relative.parts[:-1]:
        current = current / component
        directories.append(current)

    held_handles = []

    try:
        for directory in directories:
            handle, attributes = open_checked(
                directory,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ_WRITE,
            )
            held_handles.append(handle)

            if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise OSError("directory reparse point is not permitted")

            if not attributes & FILE_ATTRIBUTE_DIRECTORY:
                raise OSError("intermediate path is not a directory")

        file_handle, attributes = open_checked(
            path,
            GENERIC_READ,
            FILE_SHARE_ALL,
        )

        try:
            if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY):
                raise OSError("reparse point or directory is not permitted")

            fd = msvcrt.open_osfhandle(
                file_handle,
                os.O_RDONLY | os.O_BINARY,
            )
            file_handle = None

            with os.fdopen(fd, "rb") as stream:
                return stream.read()

        finally:
            if file_handle is not None:
                close_handle(file_handle)

    finally:
        for handle in reversed(held_handles):
            close_handle(handle)
