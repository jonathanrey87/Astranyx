import os
from argparse import Namespace
from pathlib import Path

from astranyx.plugins import evidence


def test_create_workspace(tmp_path):
    old_cwd = Path.cwd()
    os.chdir(tmp_path)

    try:
        args = Namespace(
            evidence_command="create",
            name="Test Investigation",
        )

        result = evidence.run(args)

        workspace = tmp_path / "evidence" / "Test_Investigation"

        assert result == 0
        assert workspace.exists()
        assert (workspace / "README.md").exists()
        assert (workspace / "notes.md").exists()
        assert (workspace / "timeline.md").exists()
        assert (workspace / "screenshots").exists()
        assert (workspace / "requests").exists()
        assert (workspace / "responses").exists()

    finally:
        os.chdir(old_cwd)
