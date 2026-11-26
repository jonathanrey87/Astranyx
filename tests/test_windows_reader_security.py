import os

import pytest

from astranyx.evidence.safe_reader import read_bounded

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows only")


def test_native_volume_nested_read(tmp_path):
    nested = tmp_path / "first" / "second"
    nested.mkdir(parents=True)
    (nested / "proof.txt").write_bytes(b"verified")

    assert read_bounded(tmp_path, "first/second/proof.txt", 1024) == b"verified"


def test_rejects_alternate_data_stream(tmp_path):
    original = tmp_path / "proof.txt"
    original.write_bytes(b"public")

    stream = tmp_path / "proof.txt:hidden"
    stream.write_bytes(b"private")

    with pytest.raises(OSError):
        read_bounded(tmp_path, "proof.txt:hidden", 1024)


def test_rejects_missing_root(tmp_path):
    with pytest.raises(OSError):
        read_bounded(tmp_path / "missing", "proof.txt", 1024)


def test_rejects_missing_intermediate_directory(tmp_path):
    with pytest.raises(OSError):
        read_bounded(tmp_path, "missing/proof.txt", 1024)


def test_rejects_unsupported_device_mapping(tmp_path, monkeypatch):
    from astranyx.evidence import windows_reader as reader

    def fake_query(drive, buffer, length):
        buffer.value = r"\Device\Mup"
        return len(buffer.value) + 1

    def unexpected_open(*args):
        pytest.fail("Unsupported device must not be opened")

    monkeypatch.setattr(reader._kernel32, "QueryDosDeviceW", fake_query)
    monkeypatch.setattr(reader, "_open_nt", unexpected_open)

    with pytest.raises(OSError, match="unsupported Windows volume"):
        read_bounded(tmp_path, "proof.txt", 1024)


def test_closes_handles_after_failed_traversal(tmp_path, monkeypatch):
    from astranyx.evidence import windows_reader as reader

    opened = []
    closed = []
    original_open = reader._open_nt
    original_close = reader._CloseHandle

    def tracked_open(*args):
        handle = original_open(*args)
        opened.append(handle.value)
        return handle

    def tracked_close(handle):
        closed.append(handle.value)
        return original_close(handle)

    monkeypatch.setattr(reader, "_open_nt", tracked_open)
    monkeypatch.setattr(reader, "_CloseHandle", tracked_close)

    with pytest.raises(OSError):
        read_bounded(tmp_path, "missing/proof.txt", 1024)

    assert opened
    assert closed == list(reversed(opened))
