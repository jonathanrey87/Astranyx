"""Integrity verification for sealed Astranyx investigations."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


class IntegrityError(RuntimeError):
    """Raised when an investigation manifest cannot be evaluated."""


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"unable to read investigation manifest: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        raise IntegrityError("invalid investigation manifest: artifacts must be a list")
    return payload


def _safe_artifact(root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    relative = Path(value)
    if not relative.parts:
        return None
    candidate = root

    for component in relative.parts:
        if component in {".", ".."}:
            return None
        candidate = candidate / component
        if candidate.is_symlink():
            return None

    resolved = candidate.resolve()
    try:
        if not resolved.relative_to(root).parts:
            return None
    except ValueError:
        return None
    return resolved


def _read_artifact_nofollow(root: Path, relative: Path) -> bytes:
    """Read through directory handles, never following symlinks on POSIX."""
    if os.name != "posix":
        # Windows does not support this POSIX dir_fd/O_NOFOLLOW strategy.
        return (root / relative).read_bytes()

    # O_PATH avoids requiring directory-listing permission on Linux.
    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        artifact_fd = os.open(relative.parts[-1], file_flags, dir_fd=fd)
        try:
            if not stat.S_ISREG(os.fstat(artifact_fd).st_mode):
                raise OSError("artifact is not a regular file")
            with os.fdopen(artifact_fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(artifact_fd)
    finally:
        os.close(fd)


def verify(workspace: str | Path) -> dict[str, Any]:
    """Verify every artifact recorded in an investigation manifest."""
    root = Path(workspace).expanduser().resolve()
    manifest = _load_manifest(root / "manifest.json")
    failures: list[dict[str, Any]] = []
    checked = 0
    seen: set[str] = set()

    for index, record in enumerate(manifest["artifacts"]):
        if not isinstance(record, dict):
            failures.append({"index": index, "reason": "invalid artifact record"})
            continue

        relative = record.get("path")
        artifact = _safe_artifact(root, relative)
        if artifact is None:
            failures.append(
                {"index": index, "path": relative, "reason": "unsafe artifact path"}
            )
            continue
        normalized = artifact.relative_to(root).as_posix()
        if normalized in seen:
            failures.append(
                {"index": index, "path": relative, "reason": "duplicate artifact path"}
            )
            continue
        seen.add(normalized)

        try:
            content = _read_artifact_nofollow(root, artifact.relative_to(root))
        except OSError as exc:
            failures.append(
                {"index": index, "path": relative, "reason": f"unreadable: {exc}"}
            )
            continue

        checked += 1
        actual_size = len(content)
        actual_digest = hashlib.sha256(content).hexdigest()
        if record.get("size_bytes") != actual_size:
            failures.append(
                {
                    "index": index,
                    "path": relative,
                    "reason": "size mismatch",
                    "expected": record.get("size_bytes"),
                    "actual": actual_size,
                }
            )
        if record.get("sha256") != actual_digest:
            failures.append(
                {
                    "index": index,
                    "path": relative,
                    "reason": "SHA-256 mismatch",
                    "expected": record.get("sha256"),
                    "actual": actual_digest,
                }
            )

    investigation = manifest.get("investigation")
    investigation_id = (
        investigation.get("id") if isinstance(investigation, dict) else None
    )
    return {
        "workspace": str(root),
        "investigation_id": investigation_id,
        "artifacts_recorded": len(manifest["artifacts"]),
        "artifacts_checked": checked,
        "valid": not failures,
        "failures": failures,
    }
