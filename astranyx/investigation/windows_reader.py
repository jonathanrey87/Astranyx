"""Windows file reads using handle-relative, no-reparse traversal."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


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


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", wintypes.LPVOID),
        ("security_quality_of_service", wintypes.LPVOID),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("status", wintypes.LPVOID), ("information", ctypes.c_size_t)]


def _handle_attributes(get_info, handle: int) -> int:
    """Return attributes for an open handle (separate for race regressions)."""
    info = _FileInformation()
    if not get_info(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.attributes


def read_regular_windows(path: Path, *, root: Path | None = None) -> bytes:
    """Read a regular file without following untrusted reparse points.

    The trusted root is opened once by absolute path. Each remaining component
    is then resolved relative to the checked parent handle with ``NtCreateFile``
    and ``OBJ_DONT_REPARSE``. All directory handles stay open through the read.

    Windows does not publish an atomic snapshot guarantee for concurrent
    namespace mutation or third-party filesystem filters. A concurrent change
    may therefore make verification fail, but this traversal does not reopen a
    previously checked intermediate directory by pathname.
    """
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
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

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
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
    get_info.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    nt_create_file.restype = wintypes.LONG

    rtl_status_to_dos_error = ntdll.RtlNtStatusToDosError
    rtl_status_to_dos_error.argtypes = [wintypes.LONG]
    rtl_status_to_dos_error.restype = wintypes.ULONG

    OPEN_EXISTING = 3
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_TRAVERSE = 0x00000020
    SYNCHRONIZE = 0x00100000
    GENERIC_READ = 0x80000000
    FILE_SHARE_ALL = 0x00000007
    FILE_OPEN = 1
    FILE_DIRECTORY_FILE = 0x00000001
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    FILE_NON_DIRECTORY_FILE = 0x00000040
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    OBJ_CASE_INSENSITIVE = 0x00000040
    OBJ_DONT_REPARSE = 0x00001000
    invalid_handle = ctypes.c_void_p(-1).value

    def open_root() -> tuple[int, int]:
        handle = create_file(
            str(root),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == invalid_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return handle, _handle_attributes(get_info, handle)
        except BaseException:
            close_handle(handle)
            raise

    def open_relative(
        parent: int, component: str, *, directory: bool
    ) -> tuple[int, int]:
        name_buffer = ctypes.create_unicode_buffer(component)
        name = _UnicodeString(
            len(component.encode("utf-16-le")),
            ctypes.sizeof(name_buffer),
            ctypes.cast(name_buffer, wintypes.LPWSTR),
        )
        object_attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes),
            parent,
            ctypes.pointer(name),
            OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            None,
            None,
        )
        io_status = _IoStatusBlock()
        handle = wintypes.HANDLE()
        desired_access = SYNCHRONIZE | (
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES if directory else GENERIC_READ
        )
        create_options = FILE_SYNCHRONOUS_IO_NONALERT | (
            FILE_DIRECTORY_FILE if directory else FILE_NON_DIRECTORY_FILE
        )
        status = nt_create_file(
            ctypes.byref(handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            None,
            0,
            FILE_SHARE_ALL,
            FILE_OPEN,
            create_options,
            None,
            0,
        )
        if status < 0:
            raise ctypes.WinError(rtl_status_to_dos_error(status))

        value = handle.value
        try:
            return value, _handle_attributes(get_info, value)
        except BaseException:
            close_handle(value)
            raise

    held_handles: list[int] = []
    file_handle: int | None = None
    try:
        root_handle, attributes = open_root()
        held_handles.append(root_handle)
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("trusted root reparse point is not permitted")
        if not attributes & FILE_ATTRIBUTE_DIRECTORY:
            raise OSError("trusted root is not a directory")

        parent_handle = root_handle
        for component in relative.parts[:-1]:
            directory_handle, attributes = open_relative(
                parent_handle, component, directory=True
            )
            held_handles.append(directory_handle)
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise OSError("directory reparse point is not permitted")
            if not attributes & FILE_ATTRIBUTE_DIRECTORY:
                raise OSError("intermediate path is not a directory")
            parent_handle = directory_handle

        file_handle, attributes = open_relative(
            parent_handle, relative.parts[-1], directory=False
        )
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY):
            raise OSError("reparse point or directory is not permitted")

        fd = msvcrt.open_osfhandle(file_handle, os.O_RDONLY | os.O_BINARY)
        file_handle = None
        with os.fdopen(fd, "rb") as stream:
            return stream.read()
    finally:
        if file_handle is not None:
            close_handle(file_handle)
        for handle in reversed(held_handles):
            close_handle(handle)
