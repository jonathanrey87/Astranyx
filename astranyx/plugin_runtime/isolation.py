"""Fail-closed Bubblewrap runtime for untrusted Astranyx plugins."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 1_048_576
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class PluginError(RuntimeError):
    """Raised when a plugin cannot be validated or isolated safely."""


@dataclass(frozen=True, slots=True)
class PluginManifest:
    name: str
    version: str
    entrypoint: str
    entrypoint_sha256: str
    read_inputs: bool = False
    write_output: bool = False
    network: bool = False
    timeout_seconds: int = 30
    cpu_seconds: int = 20
    memory_mib: int = 256
    max_output_bytes: int = 1_048_576
    publisher_key_id: str = ""
    signature_algorithm: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not all(
            type(value) is bool
            for value in (self.read_inputs, self.write_output, self.network)
        ):
            raise PluginError("plugin capabilities must be JSON booleans")
        if not all(
            type(value) is int
            for value in (
                self.timeout_seconds,
                self.cpu_seconds,
                self.memory_mib,
                self.max_output_bytes,
            )
        ):
            raise PluginError("plugin resource limits must be JSON integers")
        if not NAME_PATTERN.fullmatch(self.name):
            raise PluginError("plugin name must be a bounded lowercase identifier")
        if (
            not self.version
            or len(self.version) > 64
            or any(ord(item) < 32 for item in self.version)
        ):
            raise PluginError("plugin version must be a bounded printable value")
        signature_values = (
            self.publisher_key_id,
            self.signature_algorithm,
            self.signature,
        )
        if any(signature_values):
            if not all(signature_values):
                raise PluginError(
                    "signed plugin manifests require all signature fields"
                )
            if not NAME_PATTERN.fullmatch(self.publisher_key_id):
                raise PluginError(
                    "publisher key ID must be a bounded lowercase identifier"
                )
            if self.signature_algorithm != "ed25519":
                raise PluginError("only Ed25519 plugin signatures are supported")
            try:
                decoded = base64.b64decode(self.signature, validate=True)
            except (ValueError, TypeError) as exc:
                raise PluginError("plugin signature must be valid base64") from exc
            if len(decoded) != 64:
                raise PluginError("Ed25519 plugin signatures must be 64 bytes")
        entrypoint = Path(self.entrypoint)
        if (
            entrypoint.is_absolute()
            or ".." in entrypoint.parts
            or entrypoint.suffix != ".py"
        ):
            raise PluginError("plugin entrypoint must be a relative Python file")
        if not re.fullmatch(r"[0-9a-f]{64}", self.entrypoint_sha256):
            raise PluginError("entrypoint_sha256 must be a lowercase SHA-256 digest")
        if self.network:
            raise PluginError("third-party plugin network access is not supported")
        if not 1 <= self.timeout_seconds <= 300:
            raise PluginError("plugin timeout must be between 1 and 300 seconds")
        if not 1 <= self.cpu_seconds <= self.timeout_seconds:
            raise PluginError(
                "plugin CPU limit must be positive and no greater than timeout"
            )
        if not 32 <= self.memory_mib <= 1_024:
            raise PluginError("plugin memory limit must be between 32 and 1024 MiB")
        if not 1_024 <= self.max_output_bytes <= 10_485_760:
            raise PluginError("plugin output limit must be between 1 KiB and 10 MiB")

    @classmethod
    def load(cls, plugin_dir: str | Path) -> tuple[PluginManifest, Path]:
        root = Path(plugin_dir).expanduser().resolve()
        manifest_path = root / "plugin.json"
        try:
            if (
                manifest_path.is_symlink()
                or manifest_path.stat().st_size > MAX_MANIFEST_BYTES
            ):
                raise PluginError("plugin manifest is unsafe or exceeds 1 MiB")
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
        except PluginError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PluginError(f"unable to load plugin manifest: {exc}") from exc
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise PluginError("unsupported or malformed plugin manifest")
        allowed = {
            "schema_version",
            "name",
            "version",
            "entrypoint",
            "entrypoint_sha256",
            "read_inputs",
            "write_output",
            "network",
            "timeout_seconds",
            "cpu_seconds",
            "memory_mib",
            "max_output_bytes",
            "publisher_key_id",
            "signature_algorithm",
            "signature",
        }
        unknown = set(document) - allowed
        if unknown:
            raise PluginError(f"unknown plugin manifest field: {min(unknown)}")
        values = {
            key: value for key, value in document.items() if key != "schema_version"
        }
        try:
            manifest = cls(**values)
        except TypeError as exc:
            raise PluginError("plugin manifest fields are missing or invalid") from exc
        entrypoint = root / manifest.entrypoint
        try:
            entrypoint.resolve().relative_to(root)
        except ValueError as exc:
            raise PluginError(
                "plugin entrypoint resolves outside the plugin directory"
            ) from exc
        if entrypoint.is_symlink() or not entrypoint.is_file():
            raise PluginError("plugin entrypoint must be a regular non-symlink file")
        if (
            hashlib.sha256(entrypoint.read_bytes()).hexdigest()
            != manifest.entrypoint_sha256
        ):
            raise PluginError("plugin entrypoint digest mismatch")
        return manifest, root

    def summary(self) -> dict[str, Any]:
        return asdict(self)

    def signed_payload(self) -> bytes:
        document = {"schema_version": 1, **asdict(self)}
        document.pop("signature")
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@contextmanager
def _hold_windows_key_acl(path: Path, *, directory: bool = False):
    """Fail closed for unexpected owners, ACEs, and Windows reparse points.

    Inspect the opened object, not a separately resolved pathname. This check
    does not grant access, mutate ACLs, or authorize execution of a plugin.
    """
    validated = False
    try:
        import win32api
        import win32con
        import win32file
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        system = win32security.ConvertStringSidToSid("S-1-5-18")
        admins = win32security.ConvertStringSidToSid("S-1-5-32-544")
        owner_rights = win32security.ConvertStringSidToSid("S-1-3-4")
        trusted = (user, system, admins, owner_rights)

        # FILE_FLAG_OPEN_REPARSE_POINT is not exported by every pywin32 build.
        flags = 0x00200000
        if directory:
            flags |= 0x02000000  # FILE_FLAG_BACKUP_SEMANTICS
        handle = win32file.CreateFile(
            str(path),
            win32con.READ_CONTROL | 0x0080,
            win32con.FILE_SHARE_READ,
            None,
            win32con.OPEN_EXISTING,
            flags,
            None,
        )
        try:
            info = win32file.GetFileInformationByHandle(handle)
            if info[0] & 0x00000400:  # FILE_ATTRIBUTE_REPARSE_POINT
                raise PluginError("plugin key path must not be a reparse point")
            descriptor = win32security.GetSecurityInfo(
                handle,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = descriptor.GetSecurityDescriptorOwner()
            dacl = descriptor.GetSecurityDescriptorDacl()
            if owner not in (user, admins) or dacl is None:
                raise PluginError("plugin key owner or ACL is unsafe")
            owner_access = False
            for index in range(dacl.GetAceCount()):
                ace = dacl.GetAce(index)
                ace_type = ace[0][0]
                sid = ace[2]
                if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                    if sid not in trusted:
                        raise PluginError("plugin key ACL grants untrusted access")
                    if sid in (user, owner_rights):
                        owner_access = True
                elif ace_type != win32security.ACCESS_DENIED_ACE_TYPE:
                    raise PluginError("plugin key ACL has unsupported ACE type")
            if not owner_access:
                raise PluginError("plugin key ACL lacks owner access")
            # Keep this validated handle open across the OpenSSL subprocess.
            # No FILE_SHARE_DELETE or FILE_SHARE_WRITE: block path replacement
            # and in-place modification while the key is consumed.
            validated = True
            yield
        finally:
            handle.Close()
    except PluginError:
        raise
    except Exception as exc:
        if validated:
            raise
        raise PluginError("Windows plugin key ACL verification failed") from exc


def _verify_windows_key_acl(path: Path, *, directory: bool = False) -> None:
    """Validate a Windows key/path ACL and close its handle immediately."""
    with _hold_windows_key_acl(path, directory=directory):
        pass


def verify_signature(
    manifest: PluginManifest,
    keyring: str | Path,
    *,
    openssl: str | None = None,
) -> None:
    """Verify a manifest against an explicitly trusted Ed25519 publisher key."""
    if not manifest.signature:
        raise PluginError("isolated execution requires a signed plugin manifest")
    executable = openssl or shutil.which("openssl") or ""
    if not executable:
        raise PluginError("OpenSSL is required for plugin signature verification")
    root = Path(keyring).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise PluginError("publisher keyring must be a non-symlink directory")
    if os.name == "nt":
        _verify_windows_key_acl(root, directory=True)
    elif root.stat().st_mode & 0o022:
        raise PluginError("publisher keyring must not be group- or world-writable")
    public_key = root / f"{manifest.publisher_key_id}.pem"
    if (
        public_key.is_symlink()
        or not public_key.is_file()
        or public_key.stat().st_size > 65_536
        or (os.name != "nt" and public_key.stat().st_mode & 0o022)
    ):
        raise PluginError("trusted publisher key is missing or unsafe")
    signature = base64.b64decode(manifest.signature, validate=True)
    with tempfile.TemporaryDirectory() as temporary:
        payload_path = Path(temporary) / "manifest.bin"
        signature_path = Path(temporary) / "manifest.sig"
        payload_path.write_bytes(manifest.signed_payload())
        signature_path.write_bytes(signature)
        guard = _hold_windows_key_acl(public_key) if os.name == "nt" else nullcontext()
        with guard:
            result = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
    if result.returncode != 0:
        raise PluginError("plugin manifest signature verification failed")


def sign_manifest(
    plugin_dir: str | Path,
    private_key: str | Path,
    publisher_key_id: str,
    *,
    openssl: str | None = None,
) -> PluginManifest:
    """Sign a validated manifest with an Ed25519 private key, replacing no files silently."""
    if not NAME_PATTERN.fullmatch(publisher_key_id):
        raise PluginError("publisher key ID must be a bounded lowercase identifier")
    executable = openssl or shutil.which("openssl") or ""
    if not executable:
        raise PluginError("OpenSSL is required for plugin signing")
    key = Path(private_key).expanduser()
    if (
        key.is_symlink()
        or not key.is_file()
        or key.stat().st_size > 65_536
        or (os.name != "nt" and key.stat().st_mode & 0o077)
    ):
        raise PluginError("private signing key must be a restricted regular file")
    manifest, root = PluginManifest.load(plugin_dir)
    document = {
        "schema_version": 1,
        **asdict(manifest),
        "publisher_key_id": publisher_key_id,
        "signature_algorithm": "ed25519",
        "signature": "",
    }
    document.pop("signature")
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as temporary:
        payload_path = Path(temporary) / "manifest.bin"
        signature_path = Path(temporary) / "manifest.sig"
        payload_path.write_bytes(payload)
        guard = _hold_windows_key_acl(key) if os.name == "nt" else nullcontext()
        with guard:
            result = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(key),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-out",
                    str(signature_path),
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
        if result.returncode != 0:
            raise PluginError("plugin manifest signing failed")
        signature = base64.b64encode(signature_path.read_bytes()).decode("ascii")
    signed_document = {**document, "signature": signature}
    encoded = json.dumps(signed_document, indent=2, sort_keys=True).encode() + b"\n"
    manifest_path = root / "plugin.json"
    temporary_path = root / f".plugin.json.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary_path, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PluginError("signed manifest write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary_path, manifest_path)
    return PluginManifest.load(root)[0]


class IsolatedPluginRunner:
    """Run a validated plugin only when a network namespace is enforceable."""

    def __init__(
        self,
        bubblewrap: str | None = None,
        *,
        keyring: str | Path | None = None,
    ):
        self.bubblewrap = bubblewrap or shutil.which("bwrap") or ""
        self.prlimit = shutil.which("prlimit") or ""
        self.keyring = Path(keyring).expanduser() if keyring is not None else None

    def doctor(self) -> dict[str, Any]:
        if not self.bubblewrap:
            return {
                "ready": False,
                "backend": "bubblewrap",
                "reason": "bwrap is not installed",
            }
        if not self.prlimit:
            return {
                "ready": False,
                "backend": "bubblewrap",
                "reason": "prlimit is not installed",
            }
        command = self._base_command() + [
            "--",
            "/usr/bin/python3",
            "-c",
            "print('ready')",
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ready": False, "backend": "bubblewrap", "reason": str(exc)[:500]}
        return {
            "ready": result.returncode == 0 and result.stdout.strip() == "ready",
            "backend": "bubblewrap",
            "reason": "" if result.returncode == 0 else result.stderr.strip()[:500],
        }

    def _base_command(self) -> list[str]:
        command = [
            self.bubblewrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--ro-bind",
            "/usr",
            "/usr",
        ]
        for library in ("/lib", "/lib64"):
            if Path(library).exists():
                command += ["--ro-bind", library, library]
        return command + [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/work",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/work",
            "--chdir",
            "/work",
        ]

    def _limited_command(
        self, command: list[str], manifest: PluginManifest
    ) -> list[str]:
        if not self.prlimit:
            raise PluginError("prlimit is required for plugin resource enforcement")
        return [
            self.prlimit,
            f"--cpu={manifest.cpu_seconds}",
            f"--as={manifest.memory_mib * 1_048_576}",
            f"--fsize={manifest.max_output_bytes}",
            "--nofile=64",
            "--nproc=32",
            "--",
            *command,
        ]

    def build_command(
        self,
        manifest: PluginManifest,
        plugin_root: Path,
        inputs: list[str | Path],
        output: str | Path | None,
    ) -> tuple[list[str], dict[str, str]]:
        if inputs and not manifest.read_inputs:
            raise PluginError("plugin did not declare read_inputs capability")
        if output is not None and not manifest.write_output:
            raise PluginError("plugin did not declare write_output capability")
        command = self._base_command() + ["--ro-bind", str(plugin_root), "/plugin"]
        input_map = {}
        seen = set()
        for index, value in enumerate(inputs):
            source = Path(value).expanduser()
            if source.is_symlink() or not source.exists():
                raise PluginError("plugin inputs must be existing non-symlink paths")
            resolved = source.resolve()
            if resolved in seen:
                raise PluginError("duplicate plugin input")
            seen.add(resolved)
            target = f"/inputs/{index:04d}"
            command += ["--ro-bind", str(resolved), target]
            input_map[str(value)] = target
        output_target = None
        if output is not None:
            destination = Path(output).expanduser()
            if destination.is_symlink() or not destination.is_dir():
                raise PluginError(
                    "plugin output must be an existing non-symlink directory"
                )
            if any(destination.iterdir()):
                raise PluginError("plugin output directory must be empty")
            output_target = "/output"
            command += ["--bind", str(destination.resolve()), output_target]
        command += ["--", "/usr/bin/python3", f"/plugin/{manifest.entrypoint}"]
        invocation = {"inputs": list(input_map.values()), "output": output_target}
        return command, invocation

    def run(
        self,
        plugin_dir: str | Path,
        *,
        inputs: list[str | Path] | None = None,
        output: str | Path | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        manifest, root = PluginManifest.load(plugin_dir)
        if self.keyring is None:
            raise PluginError("a trusted publisher keyring is required")
        verify_signature(manifest, self.keyring)
        readiness = self.doctor()
        if not readiness["ready"]:
            raise PluginError(f"isolation backend unavailable: {readiness['reason']}")
        command, invocation = self.build_command(manifest, root, inputs or [], output)
        command = self._limited_command(command, manifest)
        try:
            request = json.dumps(
                {**invocation, "parameters": parameters or {}}, separators=(",", ":")
            ).encode()
        except (TypeError, ValueError) as exc:
            raise PluginError("plugin parameters must be JSON-serializable") from exc
        if len(request) > 1_048_576:
            raise PluginError("plugin invocation exceeds 1 MiB")
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                    env={},
                )
                process.communicate(request, timeout=manifest.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise PluginError("plugin execution timed out") from exc
            except OSError as exc:
                raise PluginError(f"unable to start isolated plugin: {exc}") from exc
            stdout.seek(0, os.SEEK_END)
            stdout_size = stdout.tell()
            stderr.seek(0, os.SEEK_END)
            stderr_size = stderr.tell()
            if (
                stdout_size > manifest.max_output_bytes
                or stderr_size > manifest.max_output_bytes
            ):
                raise PluginError("plugin output exceeded its declared limit")
            stdout.seek(0)
            stderr.seek(0)
            output_text = stdout.read().decode("utf-8", errors="replace")
            error_text = stderr.read().decode("utf-8", errors="replace")
        if process.returncode != 0:
            raise PluginError(
                f"plugin exited with status {process.returncode}: {error_text[:1000]}"
            )
        try:
            result = json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise PluginError("plugin stdout must contain one JSON document") from exc
        if not isinstance(result, dict):
            raise PluginError("plugin result must be a JSON object")
        return {"plugin": manifest.name, "version": manifest.version, "result": result}
