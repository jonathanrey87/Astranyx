import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from astranyx.cli import main
from astranyx.plugin_runtime import (
    IsolatedPluginRunner,
    PluginError,
    PluginManifest,
    sign_manifest,
    verify_signature,
)


def write_plugin(tmp_path, **overrides):
    root = tmp_path / "plugin"
    root.mkdir()
    entrypoint = root / "main.py"
    entrypoint.write_text(
        'import json, sys\nrequest=json.load(sys.stdin)\nprint(json.dumps({"inputs": request["inputs"]}))\n'
    )
    manifest = {
        "schema_version": 1,
        "name": "test-plugin",
        "version": "1.0.0",
        "entrypoint": "main.py",
        "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
        "read_inputs": False,
        "write_output": False,
        "network": False,
        "timeout_seconds": 10,
        "cpu_seconds": 5,
        "memory_mib": 64,
        "max_output_bytes": 4096,
    }
    manifest.update(overrides)
    (root / "plugin.json").write_text(json.dumps(manifest))
    return root


def write_keys(tmp_path, key_id="publisher"):
    openssl = shutil.which("openssl")
    if openssl is None and os.name == "nt":
        git = shutil.which("git")
        if git is not None:
            bundled_openssl = Path(git).resolve().parent.parent / "usr/bin/openssl.exe"
            if bundled_openssl.is_file():
                openssl = str(bundled_openssl)
                os.environ["PATH"] = (
                    str(bundled_openssl.parent)
                    + os.pathsep
                    + os.environ.get("PATH", "")
                )
    if openssl is None:
        pytest.fail("OpenSSL is required to generate plugin signing test keys")

    private = tmp_path / "private.pem"
    keyring = tmp_path / "keyring"
    keyring.mkdir(parents=True)
    os.chmod(keyring, 0o700)
    public = keyring / f"{key_id}.pem"
    subprocess.run(
        [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    os.chmod(private, 0o600)
    subprocess.run(
        [openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    os.chmod(public, 0o644)
    return private, keyring


def test_manifest_validates_entrypoint_digest_and_capabilities(tmp_path):
    root = write_plugin(tmp_path)
    manifest, resolved = PluginManifest.load(root)
    assert manifest.name == "test-plugin"
    assert resolved == root.resolve()
    (root / "main.py").write_text("tampered")
    with pytest.raises(PluginError, match="digest mismatch"):
        PluginManifest.load(root)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"network": True}, "network access"),
        ({"entrypoint": "../escape.py"}, "relative Python"),
        ({"timeout_seconds": 301}, "timeout"),
        ({"memory_mib": 16}, "memory"),
        ({"unexpected": True}, "unknown"),
        ({"read_inputs": "false"}, "JSON booleans"),
        ({"memory_mib": "64"}, "JSON integers"),
    ],
)
def test_manifest_rejects_unsafe_declarations(tmp_path, overrides, message):
    root = write_plugin(tmp_path, **overrides)
    with pytest.raises(PluginError, match=message):
        PluginManifest.load(root)


def test_command_mounts_only_declared_inputs_and_output(tmp_path):
    root = write_plugin(tmp_path, read_inputs=True, write_output=True)
    manifest, plugin_root = PluginManifest.load(root)
    source = tmp_path / "input.txt"
    source.write_text("input")
    output = tmp_path / "output"
    output.mkdir()
    command, invocation = IsolatedPluginRunner("/usr/bin/bwrap").build_command(
        manifest, plugin_root, [source], output
    )
    assert "--unshare-all" in command
    assert [str(source.resolve()), "/inputs/0000"] == command[
        command.index(str(source.resolve())) : command.index(str(source.resolve())) + 2
    ]
    assert invocation == {"inputs": ["/inputs/0000"], "output": "/output"}


def test_capability_mismatch_is_denied_before_execution(tmp_path):
    root = write_plugin(tmp_path)
    manifest, plugin_root = PluginManifest.load(root)
    source = tmp_path / "input.txt"
    source.write_text("input")
    with pytest.raises(PluginError, match="read_inputs"):
        IsolatedPluginRunner("/usr/bin/bwrap").build_command(
            manifest, plugin_root, [source], None
        )


def test_backend_failure_is_fail_closed(tmp_path, monkeypatch):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    sign_manifest(root, private, "publisher")
    runner = IsolatedPluginRunner("/missing/bwrap", keyring=keyring)
    with pytest.raises(PluginError, match="backend unavailable"):
        runner.run(root)


def test_signed_manifest_verifies_against_trusted_publisher(tmp_path):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    manifest = sign_manifest(root, private, "publisher")
    verify_signature(manifest, keyring)
    assert manifest.signature_algorithm == "ed25519"
    assert manifest.publisher_key_id == "publisher"


def test_signature_rejects_manifest_tampering_and_untrusted_key(tmp_path):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    sign_manifest(root, private, "publisher")
    document = json.loads((root / "plugin.json").read_text())
    document["timeout_seconds"] = 11
    (root / "plugin.json").write_text(json.dumps(document))
    manifest, _ = PluginManifest.load(root)
    with pytest.raises(PluginError, match="verification failed"):
        verify_signature(manifest, keyring)

    other_private, other_keyring = write_keys(tmp_path / "other")
    assert other_private.exists()
    with pytest.raises(PluginError, match="verification failed"):
        verify_signature(sign_manifest(root, private, "publisher"), other_keyring)


def test_runner_requires_trusted_keyring_before_isolation(tmp_path):
    root = write_plugin(tmp_path)
    with pytest.raises(PluginError, match="keyring"):
        IsolatedPluginRunner("/missing/bwrap").run(root)


def test_cli_validates_plugin_without_executing_it(tmp_path, monkeypatch, capsys):
    root = write_plugin(tmp_path)
    monkeypatch.setattr(sys, "argv", ["astranyx", "plugin", "validate", str(root)])
    main()
    assert json.loads(capsys.readouterr().out)["name"] == "test-plugin"


@pytest.mark.skipif(os.name != "nt", reason="Windows NTFS ACL regression")
def test_windows_signing_rejects_world_access(tmp_path):
    import win32security

    root = write_plugin(tmp_path)
    private, _ = write_keys(tmp_path)
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    descriptor = win32security.GetNamedSecurityInfo(
        str(private),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    assert dacl is not None
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x00020000, everyone)
    win32security.SetNamedSecurityInfo(
        str(private),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
    with pytest.raises(PluginError, match="untrusted access"):
        sign_manifest(root, private, "publisher")


@pytest.mark.skipif(os.name != "nt", reason="Windows NTFS ACL regression")
def test_windows_keyring_rejects_world_access(tmp_path):
    import win32security

    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    sign_manifest(root, private, "publisher")
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    descriptor = win32security.GetNamedSecurityInfo(
        str(keyring),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    assert dacl is not None
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x00020000, everyone)
    win32security.SetNamedSecurityInfo(
        str(keyring),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
    manifest = PluginManifest.load(root)[0]
    with pytest.raises(PluginError, match="untrusted access"):
        verify_signature(manifest, keyring)


@pytest.mark.skipif(os.name != "nt", reason="Windows plugin key replacement regression")
def test_windows_signing_resists_key_path_replacement(tmp_path, monkeypatch):
    """Signatures must come from the validated original key, not a swapped path."""
    import importlib

    isolation = importlib.import_module("astranyx.plugin_runtime.isolation")
    plugin = write_plugin(tmp_path)
    original_private, original_keyring = write_keys(tmp_path)
    alternate_private, _ = write_keys(tmp_path / "alternate")
    real_run = subprocess.run
    replacement_attempts = []

    def substitute_before_openssl(args, *positional, **keywords):
        if "pkeyutl" in args and "-sign" in args:
            try:
                # Simulate directory-entry replacement after ACL validation.
                os.replace(alternate_private, original_private)
            except PermissionError:
                replacement_attempts.append("blocked")
            else:
                replacement_attempts.append("replaced")
        return real_run(args, *positional, **keywords)

    monkeypatch.setattr(isolation.subprocess, "run", substitute_before_openssl)
    signed = sign_manifest(plugin, original_private, "publisher")
    assert replacement_attempts, "test did not reach the signing subprocess"
    # Secure implementations must either block replacement while signing or
    # sign from a protected snapshot of the originally validated key bytes.
    verify_signature(signed, original_keyring)


@pytest.mark.skipif(os.name != "nt", reason="Windows keyring substitution test")
def test_windows_rejects_keyring_swapped_after_acl_check(tmp_path, monkeypatch):
    import importlib

    isolation = importlib.import_module("astranyx.plugin_runtime.isolation")
    plugin = write_plugin(tmp_path)
    _, trusted_keyring = write_keys(tmp_path / "trusted")
    attacker_private, attacker_keyring = write_keys(tmp_path / "attacker")
    manifest = sign_manifest(plugin, attacker_private, "publisher")
    with pytest.raises(PluginError):
        verify_signature(manifest, trusted_keyring)

    from contextlib import contextmanager

    original_hold = isolation._hold_windows_key_acl
    attempts = []

    @contextmanager
    def attempt_swap_while_held(path, *, directory=False):
        with original_hold(path, directory=directory) as handle:
            if directory and path == trusted_keyring:
                try:
                    os.rename(
                        trusted_keyring, trusted_keyring.with_name("keyring.saved")
                    )
                except OSError:
                    attempts.append("blocked")
                else:
                    attempts.append("replaced")
                    os.rename(attacker_keyring, trusted_keyring)
            yield handle

    monkeypatch.setattr(isolation, "_hold_windows_key_acl", attempt_swap_while_held)
    with pytest.raises(PluginError):
        verify_signature(manifest, trusted_keyring)
    assert attempts, "keyring substitution was not attempted"


@pytest.mark.skipif(os.name != "nt", reason="Windows post-validation keyring swap")
def test_windows_verification_uses_validated_key_after_directory_swap(
    tmp_path, monkeypatch
):
    import importlib

    isolation = importlib.import_module("astranyx.plugin_runtime.isolation")
    plugin = write_plugin(tmp_path)
    _, trusted_keyring = write_keys(tmp_path / "trusted")
    attacker_private, attacker_keyring = write_keys(tmp_path / "attacker")
    manifest = sign_manifest(plugin, attacker_private, "publisher")
    real_run = subprocess.run
    attempts = []

    def swap_keyring_before_openssl(args, *positional, **keywords):
        if "pkeyutl" in args and "-verify" in args:
            try:
                os.rename(trusted_keyring, trusted_keyring.with_name("keyring.saved"))
            except PermissionError:
                attempts.append("blocked")
            else:
                attempts.append("replaced")
                os.rename(attacker_keyring, trusted_keyring)
        return real_run(args, *positional, **keywords)

    monkeypatch.setattr(isolation.subprocess, "run", swap_keyring_before_openssl)
    with pytest.raises(PluginError, match="verification failed"):
        verify_signature(manifest, trusted_keyring)
    assert attempts == ["blocked"]


@pytest.mark.skipif(os.name != "nt", reason="Windows post-validation signing-key swap")
def test_windows_signing_uses_validated_key_after_directory_swap(tmp_path, monkeypatch):
    import importlib

    isolation = importlib.import_module("astranyx.plugin_runtime.isolation")
    plugin = write_plugin(tmp_path)
    original_root = tmp_path / "original"
    original_private, original_keyring = write_keys(original_root)
    attacker_root = tmp_path / "attacker"
    write_keys(attacker_root)
    saved_root = tmp_path / "original.saved"
    real_run = subprocess.run
    attempts = []

    def swap_key_directory_before_openssl(args, *positional, **keywords):
        if "pkeyutl" in args and "-sign" in args:
            try:
                os.rename(original_root, saved_root)
            except PermissionError:
                attempts.append("blocked")
            else:
                attempts.append("replaced")
                os.rename(attacker_root, original_root)
        return real_run(args, *positional, **keywords)

    monkeypatch.setattr(isolation.subprocess, "run", swap_key_directory_before_openssl)
    signed = sign_manifest(plugin, original_private, "publisher")
    assert attempts == ["blocked"]
    verify_signature(signed, original_keyring)
