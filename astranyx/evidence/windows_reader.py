"""Windows-only bounded no-reparse-point reads using NT handle-relative opens.

This is an experimental implementation that must pass Windows regression tests
and a security review before release. No fallback to ordinary path.open() exists.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

# Importing this module is only permitted on Windows.
if os.name != "nt":
    raise ImportError("Windows reader is Windows-only")

# These values are defined by the Windows NT I/O API.
OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000
FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_READ_ATTRIBUTES = 0x0080
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x00000001
FILE_OPEN = 0x00000001
FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    # The first field is a union of NTSTATUS and pointer; pointer-sized storage.
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_NtCreateFile = _ntdll.NtCreateFile
_NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.ULONG,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
]
_NtCreateFile.restype = ctypes.c_long
_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL
_GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
_GetFileInformationByHandleEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
]
_GetFileInformationByHandleEx.restype = wintypes.BOOL
_GetFileSizeEx = _kernel32.GetFileSizeEx
_GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
_GetFileSizeEx.restype = wintypes.BOOL
_ReadFile = _kernel32.ReadFile
_ReadFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
_ReadFile.restype = wintypes.BOOL


def _check_not_reparse(handle: wintypes.HANDLE) -> None:
    info = FILE_ATTRIBUTE_TAG_INFO()
    if not _GetFileInformationByHandleEx(
        handle, FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError("reparse points are not permitted in evidence paths")


def _open_nt(
    name: str, parent: wintypes.HANDLE | None, directory: bool
) -> wintypes.HANDLE:
    # Keep name storage and all pointers alive until the call returns.
    buf = ctypes.create_unicode_buffer(name)
    unicode_name = UNICODE_STRING(
        len(name.encode("utf-16-le")),
        ctypes.sizeof(buf),
        ctypes.cast(buf, wintypes.LPWSTR),
    )
    attributes = OBJECT_ATTRIBUTES(
        ctypes.sizeof(OBJECT_ATTRIBUTES),
        parent if parent is not None else wintypes.HANDLE(),
        ctypes.pointer(unicode_name),
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        None,
        None,
    )
    io_status = IO_STATUS_BLOCK()
    result = wintypes.HANDLE()
    options = (
        FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | (FILE_DIRECTORY_FILE if directory else FILE_NON_DIRECTORY_FILE)
    )
    access = (
        (FILE_LIST_DIRECTORY if directory else FILE_READ_DATA)
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
    )
    status = _NtCreateFile(
        ctypes.byref(result),
        access,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        options,
        None,
        0,
    )
    if status < 0:
        raise OSError(
            f"Windows secure open denied (NTSTATUS 0x{status & 0xffffffff:08X})"
        )
    try:
        _check_not_reparse(result)
        return result
    except BaseException:
        _CloseHandle(result)
        raise


def read_windows(root: Path, relative: str, limit: int) -> bytes:
    """Use anchored, per-component NT opens; reject reparse points at every level."""
    # Common input validation occurs in safe_reader.read_bounded before calling us.
    from astranyx.evidence.safe_reader import SizeLimitExceeded

    path = str(root.expanduser().absolute())
    path = path.removeprefix("\\\\?\\")
    if not (len(path) >= 3 and path[1:3] == ":\\"):
        raise OSError("unsupported Windows evidence root path")
    root_handle = _open_nt("\\??\\" + path, None, True)
    handles = [root_handle]
    try:
        parent = root_handle
        components = relative.split("/")
        for part in components[:-1]:
            parent = _open_nt(part, parent, True)
            handles.append(parent)
        file_handle = _open_nt(components[-1], parent, False)
        handles.append(file_handle)
        size = ctypes.c_longlong()
        if not _GetFileSizeEx(file_handle, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if size.value > limit:
            raise SizeLimitExceeded("evidence file exceeds size limit")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            count = min(remaining, 65536)
            buffer = ctypes.create_string_buffer(count)
            got = wintypes.DWORD()
            if not _ReadFile(file_handle, buffer, count, ctypes.byref(got), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if not got.value:
                break
            chunks.append(buffer.raw[: got.value])
            remaining -= got.value
        data = b"".join(chunks)
        if len(data) > limit:
            raise SizeLimitExceeded("evidence file exceeds size limit")
        return data
    finally:
        for handle in reversed(handles):
            _CloseHandle(handle)
