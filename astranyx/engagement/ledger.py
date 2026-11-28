"""Tamper-evident, privacy-aware engagement action ledger."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "api-key",
        "apikey",
        "access-key",
        "cookie",
        "credential",
        "password",
        "proxy-authorization",
        "secret",
        "set-cookie",
        "token",
    }
)


class LedgerError(ValueError):
    """Raised when a ledger is malformed or fails integrity verification."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def redact_url(value: str) -> str:
    """Remove credentials, query values, and fragments from a URL."""
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return value
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    try:
        port = parsed.port
    except ValueError:
        port = None
        host = f"{host}:[INVALID-PORT]"
    if port and port != default_port:
        host = f"{host}:{port}"
    query = REDACTED if parsed.query else ""
    return urlunsplit((parsed.scheme, host, parsed.path, query, ""))


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact common credential fields and URL query values."""
    normalized_key = key.casefold().replace("_", "-")
    if any(marker in normalized_key for marker in SENSITIVE_KEYS):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(item): redact(content, str(item)) for item, content in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str) and key.casefold() in {"url", "location", "final_url"}:
        return redact_url(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    records: int
    head_hash: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "records": self.records,
            "head_hash": self.head_hash,
            "error": self.error,
        }


def _secure_windows_file(descriptor: int, path: Path) -> None:
    """Tighten and verify the same NTFS file through a checked native handle.

    Experimental: security review still required for hostile directory races.
    """
    import msvcrt

    try:
        import win32api
        import win32con
        import win32file
        import win32security

        original = msvcrt.get_osfhandle(descriptor)
        original_info = win32file.GetFileInformationByHandle(original)
        if original_info[0] & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            raise LedgerError("Windows ledger reparse point is forbidden")
        if path.is_symlink():
            raise LedgerError("Windows ledger symlink is forbidden")

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
        system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
        rights = win32con.READ_CONTROL | win32con.WRITE_DAC
        sharing = (
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE
        )
        native = win32file.CreateFile(
            str(path),
            rights,
            sharing,
            None,
            win32con.OPEN_EXISTING,
            0x00200000,
            None,  # FILE_FLAG_OPEN_REPARSE_POINT
        )
        try:
            actual = win32file.GetFileInformationByHandle(native)
            # Volume serial and file index are identity fields on Windows.
            identity = lambda info: (info[4], info[8], info[9])
            if (actual[0] & 0x400) or identity(actual) != identity(original_info):
                raise LedgerError("Windows ledger file changed or is a reparse point")
            current = win32security.GetSecurityInfo(
                native,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = current.GetSecurityDescriptorOwner()
            if owner not in (user_sid, admin_sid):
                raise LedgerError("Windows ledger file owner is unsafe")

            dacl = win32security.ACL()
            for sid in (user_sid, system_sid, admin_sid):
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x1F01FF, sid)
            win32security.SetSecurityInfo(
                native,
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None,
            )
            verified = win32security.GetSecurityInfo(
                original,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            control, _ = verified.GetSecurityDescriptorControl()
            if not (control & 0x1000):  # SE_DACL_PROTECTED
                raise LedgerError("Windows ledger DACL is not protected")
            current_dacl = verified.GetSecurityDescriptorDacl()
            if current_dacl is None or current_dacl.GetAceCount() != 3:
                raise LedgerError("Windows ledger DACL was not restricted")
            expected_sids = {
                win32security.ConvertSidToStringSid(sid)
                for sid in (user_sid, system_sid, admin_sid)
            }
            actual_sids = set()
            for index in range(current_dacl.GetAceCount()):
                ace = current_dacl.GetAce(index)
                if ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
                    raise LedgerError("Windows ledger DACL contains unsafe ACE")
                if ace[1] != 0x1F01FF:
                    raise LedgerError("Windows ledger ACE permissions are unsafe")
                if ace[0][1] & 0x10:  # INHERITED_ACE
                    raise LedgerError("Windows ledger DACL contains inherited ACE")
                actual_sids.add(win32security.ConvertSidToStringSid(ace[2]))
            if actual_sids != expected_sids:
                raise LedgerError("Windows ledger ACL grants unexpected access")
        finally:
            native.Close()
    except (ImportError, OSError) as exc:
        raise LedgerError("Windows ledger ACL enforcement failed") from exc


def _validate_windows_file(descriptor: int, path: Path) -> None:
    """Validate a Windows file through read-only, identity-checked handles."""
    import msvcrt

    try:
        import win32api
        import win32con
        import win32file
        import win32security

        original = msvcrt.get_osfhandle(descriptor)
        original_info = win32file.GetFileInformationByHandle(original)
        if original_info[0] & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            raise LedgerError("Windows ledger reparse point is forbidden")
        if path.is_symlink():
            raise LedgerError("Windows ledger symlink is forbidden")

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
        sharing = (
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE
        )
        native = win32file.CreateFile(
            str(path),
            win32con.READ_CONTROL,
            sharing,
            None,
            win32con.OPEN_EXISTING,
            0x00200000,
            None,  # FILE_FLAG_OPEN_REPARSE_POINT
        )
        try:
            actual = win32file.GetFileInformationByHandle(native)
            # Volume serial and file index are identity fields on Windows.
            identity = lambda info: (info[4], info[8], info[9])
            if (actual[0] & 0x400) or identity(actual) != identity(original_info):
                raise LedgerError("Windows ledger file changed or is a reparse point")
            current = win32security.GetSecurityInfo(
                native,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION,
            )
            owner = current.GetSecurityDescriptorOwner()
            if owner not in (user_sid, admin_sid):
                raise LedgerError("Windows ledger file owner is unsafe")
        finally:
            native.Close()
    except (ImportError, OSError) as exc:
        raise LedgerError("Windows ledger file validation failed") from exc


def _secure_file_mode(descriptor: int, path: Path) -> None:
    if os.name == "nt":
        _secure_windows_file(descriptor, path)
    else:
        os.fchmod(descriptor, 0o600)


class AuditLedger:
    """Append-only JSONL ledger chained with SHA-256 hashes."""

    schema_version = 1

    EVENT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

    def __init__(
        self,
        path: str | Path,
        engagement_id: str,
        *,
        max_bytes: int = 67_108_864,
        max_record_bytes: int = 1_048_576,
    ):
        self.path = Path(path).expanduser()
        self.engagement_id = engagement_id
        self._thread_lock = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._head_path = self.path.with_name(self.path.name + ".head")
        if max_bytes < 1 or max_record_bytes < 1 or max_record_bytes > max_bytes:
            raise LedgerError("invalid ledger size bounds")
        self.max_bytes = max_bytes
        self.max_record_bytes = max_record_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise LedgerError("ledger path must not be a symbolic link")
        result = self.verify()
        if not result.valid:
            raise LedgerError(result.error)

    @contextmanager
    def _exclusive_lock(self):
        flags = getattr(os, "O_BINARY", 0) | os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._lock_path, flags, 0o600)
        locked = False
        try:
            if os.name == "nt":
                import msvcrt

                _validate_windows_file(descriptor, self._lock_path)
                # Windows can lock past EOF. Writing a marker before locking
                # can collide with another process that already locked byte 0.
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                locked = True
                # SetSecurityInfo on the shared lock file must not race with
                # another process doing the same work before serialization.
                _secure_file_mode(descriptor, self._lock_path)
            else:
                import fcntl

                _secure_file_mode(descriptor, self._lock_path)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
            yield
        finally:
            try:
                if locked:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _read_locked(self) -> str:
        if not self.path.exists():
            return ""
        flags = getattr(os, "O_BINARY", 0) | os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags)
        try:
            _secure_file_mode(descriptor, self.path)
            if os.fstat(descriptor).st_size > self.max_bytes:
                raise LedgerError("ledger exceeds configured size bound")
            chunks = []
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LedgerError("ledger is not valid UTF-8") from exc

    def _read_head_locked(self) -> dict[str, Any] | None:
        if not self._head_path.exists():
            return None
        flags = getattr(os, "O_BINARY", 0) | os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._head_path, flags)
        try:
            _secure_file_mode(descriptor, self._head_path)
            payload = os.read(descriptor, 16_384)
            if os.read(descriptor, 1):
                raise LedgerError("ledger head checkpoint is too large")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LedgerError("invalid ledger head checkpoint") from exc
        if not isinstance(value, dict):
            raise LedgerError("invalid ledger head checkpoint")
        return value

    def _write_head_locked(self, verification: VerificationResult) -> None:
        payload = (
            _canonical(
                {
                    "schema_version": self.schema_version,
                    "engagement_id": self.engagement_id,
                    "records": verification.records,
                    "head_hash": verification.head_hash,
                }
            )
            + b"\n"
        )
        temporary = self._head_path.with_name(
            f"{self._head_path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        flags = getattr(os, "O_BINARY", 0) | os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            _secure_file_mode(descriptor, temporary)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise LedgerError("ledger head write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, self._head_path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _verify_content(
        self, content: str, checkpoint: dict[str, Any] | None
    ) -> VerificationResult:
        previous = "0" * 64
        count = 0
        lines = content.splitlines()
        for expected_index, line in enumerate(lines, start=1):
            if not line.strip():
                return VerificationResult(False, count, previous, "blank ledger record")
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return VerificationResult(False, count, previous, "invalid JSON record")
            digest = record.pop("hash", None)
            if record.get("index") != expected_index:
                return VerificationResult(
                    False, count, previous, "non-sequential index"
                )
            if record.get("previous_hash") != previous:
                return VerificationResult(
                    False, count, previous, "hash-chain discontinuity"
                )
            if record.get("engagement_id") != self.engagement_id:
                return VerificationResult(False, count, previous, "engagement mismatch")
            calculated = _hash(record)
            if digest != calculated:
                return VerificationResult(
                    False, count, previous, "record hash mismatch"
                )
            previous = calculated
            count += 1
        if checkpoint is None:
            if count:
                return VerificationResult(
                    False, count, previous, "missing ledger head checkpoint"
                )
        elif (
            checkpoint.get("schema_version") != self.schema_version
            or checkpoint.get("engagement_id") != self.engagement_id
            or checkpoint.get("records") != count
            or checkpoint.get("head_hash") != previous
        ):
            return VerificationResult(
                False, count, previous, "ledger head checkpoint mismatch"
            )
        return VerificationResult(True, count, previous)

    def verify(self) -> VerificationResult:
        try:
            with self._thread_lock, self._exclusive_lock():
                return self._verify_content(
                    self._read_locked(), self._read_head_locked()
                )
        except (OSError, LedgerError) as exc:
            return VerificationResult(False, 0, "0" * 64, str(exc))

    def append(
        self,
        event: str,
        data: dict[str, Any],
        *,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        if not isinstance(event, str) or not self.EVENT_PATTERN.fullmatch(event):
            raise LedgerError("event must be a bounded lowercase identifier")
        with self._thread_lock, self._exclusive_lock():
            content = self._read_locked()
            verification = self._verify_content(content, self._read_head_locked())
            if not verification.valid:
                raise LedgerError(verification.error)
            moment = (timestamp or datetime.now(UTC)).astimezone(UTC)
            record = {
                "schema_version": self.schema_version,
                "index": verification.records + 1,
                "timestamp": moment.isoformat(),
                "engagement_id": self.engagement_id,
                "event": event,
                "data": redact(data),
                "previous_hash": verification.head_hash,
            }
            digest = _hash(record)
            sealed = {**record, "hash": digest}
            encoded = _canonical(sealed) + b"\n"
            if len(encoded) > self.max_record_bytes:
                raise LedgerError("ledger record exceeds configured size bound")
            if len(content.encode("utf-8")) + len(encoded) > self.max_bytes:
                raise LedgerError("ledger exceeds configured size bound")
            flags = getattr(os, "O_BINARY", 0) | os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            try:
                _secure_file_mode(descriptor, self.path)
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise LedgerError("ledger write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._write_head_locked(
                VerificationResult(True, verification.records + 1, digest)
            )
            return sealed
