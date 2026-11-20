import os
import subprocess

import pytest

from astranyx.evidence.safe_reader import read_bounded


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_rejects_junction_root(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "proof.txt").write_text("JUNCTION_TEST", encoding="utf-8")
    link = tmp_path / "root-link"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("Junction creation unavailable")
    with pytest.raises(OSError):
        read_bounded(link, "proof.txt", 1024)


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_rejects_root_swapped_before_native_open(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "proof.txt").write_text("OUTSIDE_DATA", encoding="utf-8")
    from astranyx.evidence import windows_reader

    original_open = windows_reader._open_nt
    swapped = [False]

    def swap_then_open(name, parent, directory):
        if parent is None and not swapped[0]:
            root.rmdir()
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(root), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            swapped[0] = True
        return original_open(name, parent, directory)

    monkeypatch.setattr(windows_reader, "_open_nt", swap_then_open)
    with pytest.raises(OSError):
        read_bounded(root, "proof.txt", 1024)
    assert swapped[0]
