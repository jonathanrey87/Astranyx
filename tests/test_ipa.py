import struct
import zipfile
from argparse import Namespace

import pytest

from astranyx.plugins import ipa


def _write_ipa(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in members:
            archive.writestr(name, content)


def _corrupt_member(path, member_name):
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(member_name)
        header_offset = member.header_offset

    data = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from("<HH", data, header_offset + 26)
    content_offset = header_offset + 30 + name_length + extra_length
    data[content_offset] ^= 0xFF
    path.write_bytes(data)


def test_run_accepts_valid_ipa_and_removes_temporary_files(
    tmp_path, monkeypatch, capsys
):
    archive = tmp_path / "valid.ipa"
    extraction_root = tmp_path / "extracted"
    _write_ipa(
        archive,
        [
            ("Payload/Example.app/Info.plist", b"<plist><dict></dict></plist>"),
            ("Payload/Example.app/Example", b"binary"),
        ],
    )
    monkeypatch.setattr(ipa.tempfile, "mkdtemp", lambda **_kwargs: str(extraction_root))

    assert ipa.run(Namespace(file=str(archive))) == 0
    assert "ASTRANYX IPA ANALYSIS" in capsys.readouterr().out
    assert not extraction_root.exists()


def test_extract_ipa_rejects_expanded_size_before_writing(tmp_path, monkeypatch):
    archive = tmp_path / "oversized.ipa"
    extraction_root = tmp_path / "extracted"
    _write_ipa(archive, [("Payload/Example.app/large.bin", b"12345")])
    monkeypatch.setattr(ipa, "MAX_ARCHIVE_EXPANDED_BYTES", 4)
    monkeypatch.setattr(ipa.tempfile, "mkdtemp", lambda **_kwargs: str(extraction_root))

    with pytest.raises(ValueError, match="expanded size limit"):
        ipa.extract_ipa(archive)

    assert not extraction_root.exists()


def test_extract_ipa_removes_partial_output_after_corrupt_member(tmp_path, monkeypatch):
    archive = tmp_path / "corrupt.ipa"
    extraction_root = tmp_path / "extracted"
    _write_ipa(
        archive,
        [
            ("Payload/Example.app/first.bin", b"first"),
            ("Payload/Example.app/corrupt.bin", b"second"),
        ],
    )
    _corrupt_member(archive, "Payload/Example.app/corrupt.bin")
    monkeypatch.setattr(ipa.tempfile, "mkdtemp", lambda **_kwargs: str(extraction_root))

    with pytest.raises(zipfile.BadZipFile, match="Bad CRC-32"):
        ipa.extract_ipa(archive)

    assert not extraction_root.exists()


@pytest.mark.parametrize(
    "member_name",
    [
        "../outside",
        "/absolute",
        "Payload\\outside",
        "C:/outside",
        "Payload//x",
        "D:outside.txt",
        "Payload/D:/outside.txt",
        "Payload/C:secret.txt",
        "Payload/Example.app/D:payload",
    ],
)
def test_extract_ipa_rejects_unsafe_paths(tmp_path, monkeypatch, member_name):
    archive = tmp_path / "unsafe.ipa"
    extraction_root = tmp_path / "extracted"
    _write_ipa(archive, [(member_name, b"content")])
    monkeypatch.setattr(ipa.tempfile, "mkdtemp", lambda **_kwargs: str(extraction_root))

    with pytest.raises(ValueError, match="unsafe path"):
        ipa.extract_ipa(archive)

    assert not extraction_root.exists()


@pytest.mark.parametrize(
    "members",
    [
        [
            ("Payload/App.app/cache", b"file"),
            ("Payload/App.app/cache/data.bin", b"data"),
        ],
        [
            ("Payload/App.app/cache/data.bin", b"data"),
            ("Payload/App.app/cache", b"file"),
        ],
    ],
)
def test_extract_ipa_rejects_file_directory_conflicts(tmp_path, members):
    archive = tmp_path / "conflict.ipa"
    _write_ipa(archive, members)

    with pytest.raises(ValueError, match="path conflict"):
        ipa.extract_ipa(archive)


def test_extract_ipa_rejects_symlinks(tmp_path):
    import stat

    archive = tmp_path / "symlink.ipa"
    info = zipfile.ZipInfo("Payload/App.app/linked")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16

    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(info, "../../outside")

    with pytest.raises(ValueError, match="unsupported entry type"):
        ipa.extract_ipa(archive)


def test_extract_ipa_rejects_duplicate_paths(tmp_path):
    archive = tmp_path / "duplicate.ipa"

    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("Payload/App.app/file", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            output.writestr("Payload/App.app/file", b"second")

    with pytest.raises(ValueError, match="duplicate path"):
        ipa.extract_ipa(archive)


def test_extract_ipa_rejects_member_limit(tmp_path, monkeypatch):
    archive = tmp_path / "large-member.ipa"
    _write_ipa(archive, [("Payload/App.app/file", b"12345")])
    monkeypatch.setattr(ipa, "MAX_ARCHIVE_MEMBER_BYTES", 4)

    with pytest.raises(ValueError, match="size limit"):
        ipa.extract_ipa(archive)


def test_extract_ipa_rejects_member_count(tmp_path, monkeypatch):
    archive = tmp_path / "many-members.ipa"
    _write_ipa(
        archive,
        [
            ("Payload/App.app/one", b"1"),
            ("Payload/App.app/two", b"2"),
        ],
    )
    monkeypatch.setattr(ipa, "MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(ValueError, match="too many entries"):
        ipa.extract_ipa(archive)
