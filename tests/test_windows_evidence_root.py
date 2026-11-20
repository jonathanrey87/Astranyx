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
