"""Regression tests for runtime integrity verification."""

import importlib.util
import stat
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "verify_runtime.py"
)

SPEC = importlib.util.spec_from_file_location("verify_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def runtime(tmp_path):
    site = tmp_path / "site-packages"
    root = site / "astranyx"
    root.mkdir(parents=True)

    payload = root / "__init__.py"
    payload.write_bytes(b"original")

    wheel = tmp_path / "test.whl"

    with ZipFile(wheel, "w") as archive:
        archive.writestr("astranyx/__init__.py", b"original")

    return wheel, site, payload


def test_valid_runtime(runtime):
    wheel, site, _ = runtime
    assert MODULE.verify_runtime(wheel, site) == 1


@pytest.mark.parametrize(
    "scenario",
    [
        "modified",
        "missing",
        "unexpected",
        "empty-wheel",
        "traversal",
        "duplicate",
        "case-collision",
        "archive-symlink",
        "backslash",
        "noncanonical",
        "alternate-stream",
    ],
)
def test_rejects_invalid_runtime(runtime, scenario):
    wheel, site, payload = runtime

    if scenario == "modified":
        payload.write_bytes(b"modified")

    elif scenario == "missing":
        payload.unlink()

    elif scenario == "unexpected":
        (payload.parent / "extra.py").write_bytes(b"extra")

    elif scenario == "empty-wheel":
        with ZipFile(wheel, "w"):
            pass

    else:
        names = {
            "traversal": "astranyx/../escape.py",
            "duplicate": "astranyx/__init__.py",
            "case-collision": "astranyx/__INIT__.py",
            "archive-symlink": "astranyx/link.py",
            "backslash": "astranyx/sub\\file.py",
            "noncanonical": "astranyx/./file.py",
            "alternate-stream": "astranyx/file.py:stream",
        }

        entry = ZipInfo(names[scenario])

        if scenario == "archive-symlink":
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16

        with ZipFile(wheel, "a") as archive:
            if scenario == "duplicate":
                with pytest.warns(UserWarning):
                    archive.writestr(entry, b"invalid")
            else:
                archive.writestr(entry, b"invalid")

    with pytest.raises(ValueError):
        MODULE.verify_runtime(wheel, site)


def test_rejects_installed_symlink(runtime):
    wheel, site, payload = runtime
    target = site / "external.py"
    target.write_bytes(b"original")
    payload.unlink()

    try:
        payload.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation unavailable")

    with pytest.raises(ValueError):
        MODULE.verify_runtime(wheel, site)


def test_rejects_missing_application_root(runtime):
    wheel, site, payload = runtime
    payload.unlink()
    payload.parent.rmdir()

    with pytest.raises(ValueError):
        MODULE.verify_runtime(wheel, site)
