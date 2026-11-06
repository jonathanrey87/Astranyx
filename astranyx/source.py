"""Bounded, root-confined reading for untrusted source trees."""

from __future__ import annotations

from pathlib import Path

from astranyx.evidence.safe_reader import SafeReadError, read_bounded

MAX_SOURCE_BYTES = 10 * 1024 * 1024


class SourceReadError(ValueError):
    """Source path is unsafe, unsupported, or too large."""


def read_source_bytes(root: Path, path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes:
    """Read raw source bytes once, bounded and confined to the analysis root."""
    resolved_root = root.expanduser().resolve()
    absolute_path = path.expanduser().absolute()
    try:
        relative = absolute_path.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise SourceReadError("source path is outside the analysis root") from exc

    try:
        data = read_bounded(resolved_root, relative, limit)
    except (OSError, SafeReadError) as exc:
        raise SourceReadError(f"unsafe source path: {relative}") from exc

    return data


def read_source_text(root: Path, path: Path, limit: int = MAX_SOURCE_BYTES) -> str:
    """Read and decode one confined source snapshot."""
    return read_source_bytes(root, path, limit).decode("utf-8", errors="ignore")
