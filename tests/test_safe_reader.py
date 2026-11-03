import pytest

from astranyx.evidence.safe_reader import (
    SafeReadError,
    SizeLimitExceeded,
    read_bounded,
)


def test_reads_normal_file(tmp_path):
    (tmp_path / "evidence.txt").write_bytes(b"evidence")

    assert read_bounded(tmp_path, "evidence.txt", 100) == b"evidence"


def test_rejects_symlink(tmp_path):
    (tmp_path / "original.txt").write_bytes(b"secret")
    (tmp_path / "alias.txt").symlink_to(tmp_path / "original.txt")

    with pytest.raises(OSError):
        read_bounded(tmp_path, "alias.txt", 100)


def test_rejects_oversized_file(tmp_path):
    (tmp_path / "large.bin").write_bytes(b"A" * 1024)

    with pytest.raises(SizeLimitExceeded):
        read_bounded(tmp_path, "large.bin", 100)


def test_rejects_directory(tmp_path):
    (tmp_path / "directory").mkdir()

    with pytest.raises((SafeReadError, OSError)):
        read_bounded(tmp_path, "directory", 100)


def test_rejects_parent_traversal(tmp_path):
    with pytest.raises(SafeReadError):
        read_bounded(tmp_path, "../secret.txt", 100)


def test_rejects_replaced_file_symlink(tmp_path):
    original = tmp_path / "evidence.txt"
    target = tmp_path / "secret.txt"

    original.write_bytes(b"evidence")
    target.write_bytes(b"secret")

    # Simulate replacement after an earlier path check.
    original.unlink()
    original.symlink_to(target)

    with pytest.raises(OSError):
        read_bounded(tmp_path, "evidence.txt", 100)


def test_rejects_intermediate_directory_symlink(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "evidence.txt").write_bytes(b"evidence")

    (tmp_path / "linked").symlink_to(
        real_dir,
        target_is_directory=True,
    )

    with pytest.raises(OSError):
        read_bounded(tmp_path, "linked/evidence.txt", 100)


def test_read_bounded_rejects_unsafe_path_forms(tmp_path):
    import pytest

    from astranyx.evidence.safe_reader import SafeReadError, read_bounded

    (tmp_path / "evidence.txt").write_bytes(b"safe")

    unsafe_paths = [
        "",
        ".",
        "./",
        "./evidence.txt",
        "evidence.txt/.",
        "sub/../evidence.txt",
        "../evidence.txt",
        "/etc/passwd",
        "sub//evidence.txt",
        "evidence.txt/",
        r"sub\file.txt",
    ]

    for relative in unsafe_paths:
        with pytest.raises(SafeReadError):
            read_bounded(tmp_path, relative, 1024)


def test_read_bounded_enforces_size_limit(tmp_path):
    import pytest

    from astranyx.evidence.safe_reader import SizeLimitExceeded, read_bounded

    (tmp_path / "evidence.txt").write_bytes(b"123456")

    with pytest.raises(SizeLimitExceeded):
        read_bounded(tmp_path, "evidence.txt", 5)

    assert read_bounded(tmp_path, "evidence.txt", 6) == b"123456"
